// C4 (2026-09-18). ROUND-TOWARD-ZERO FLOAT -> INTEGER ON THE LLVM ARM.
//
// `vfcvt.rtz.x.f.v` / `vfcvt.rtz.xu.f.v`, same width. The contract is `softfp::cvt_to_int_width`
// (rv32_softfp.h) -- the VECTOR reference uses the exact softfloat core unconditionally -- and this
// file compares against that function directly rather than against a restatement of it.
//
// WHY A STRUCTURAL CHECK WOULD BE THE WRONG INSTRUMENT AGAIN. The interesting part of this lowering
// is a set of boundary rules: NaN yields `sat_max` in BOTH directions; infinity is sign-directed;
// `-2^(W-1)` is IN range for signed while `+2^(W-1)` is not; and for unsigned a negative value that
// truncates to magnitude zero (`-0.5`) is IN range and yields 0 with NX, while `-1.0` is invalid.
// Every one of those is a one-constant difference that leaves the IR's shape untouched. So:
//
//   [3] THE VALUE ORACLE. The unit's source load is replaced by a crafted constant vector; the
//       function is folded; the constrained conversion -- which cannot fold -- is replaced by the
//       truncation the hardware would produce for its (already neutralised, hence in-range)
//       constant operand; the function is folded again; and the value the unit stores is compared
//       lane by lane against `softfp::cvt_to_int_width`.
//   [4] THE FLAG ORACLE. After the same folding, the `fcsr` update collapses to either
//       `or(fcsr, NV)` or `or(fcsr, 0)`. That is compared against whether the contract raises NV
//       for any lane of the same input. NX is NOT asserted here: it is delegated to the hardware
//       conversion of the in-range lanes, which is exactly why the invalid lanes are neutralised to
//       +0.0 first -- section 2 asserts that neutralisation instead.
//   [2] THE NEUTRALISATION ITSELF: a select feeding the conversion, so no NaN or out-of-range lane
//       is ever converted. This is the assertion behind "no poison, and no stray host NV".
//   [1] Frame shape, and [5] the frm-rounded pair and the widening/narrowing/masked forms refused.
//
// Every emitted module is checked with `verifyModule` AND a forced type walk; the module is built in
// `g_llvm_ctx`, which is the context `LLVMGenCtx` actually uses.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_softfp.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace testcompat = dbt::qir::testcompat;

namespace
{
namespace rvv32 = dbt::rv32;

unsigned g_fail = 0;
#define CHECK(c)                                                                                   \
	do {                                                                                       \
		if (!(c)) {                                                                        \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                      \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)
#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto x_ = (long long)(a);                                                          \
		auto y_ = (long long)(b);                                                          \
		if (x_ != y_) {                                                                    \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, x_, y_);                                                        \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

// The generator ignores the module it is handed and builds everything in this context
// (llvmgen.cpp:61). Using it is what makes verifyModule meaningful here.
llvm::LLVMContext &g_ctx = g_llvm_ctx;

constexpr u32 OpVfcvt(u32 sub, u32 vs2, u32 vd, bool unmasked = true)
{
	return (18u << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) | (1u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 10u, kVs2 = 8u;
constexpr u32 kSubRtzXu = 6u, kSubRtzX = 7u;
constexpr u32 kSubFrmXu = 0u, kSubFrmX = 1u;
// sub-opcode for (rounding arm, signedness): 0/1 round by frm, 6/7 truncate.
constexpr u32 SubFor(bool rtz, bool is_signed)
{
	return rtz ? (is_signed ? kSubRtzX : kSubRtzXu) : (is_signed ? kSubFrmX : kSubFrmXu);
}
// The diagnostics must name the ROUNDING ARM as well as the signedness: both arms drive the same
// patterns, and a message that says only "x.f" cannot tell the reader which one disagreed.
constexpr char const *ArmName(bool rtz, bool is_signed)
{
	return rtz ? (is_signed ? "rtz.x.f " : "rtz.xu.f") : (is_signed ? "x.f     " : "xu.f    ");
}

u32 VRegOff(u32 reg) { return (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg) +
				   reg * rvv32::VLEN_MAX_BYTES); }

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c4ftoi", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_fcvt_ftoi = on;
	// Reset the widening knob too -- a flag one section sets and another never clears produces
	// false refusal rows (that leak was found in the float-width test).
	config::rvv_llvm_fcvt_ftoi_widen = false;
	config::rvv_llvm_fcvt_partial_vl = false;
	// C5-MASK-FP, reset for the SAME reason the two above are: `[C4FI-5]` asserts that the
	// masked form keeps the helper, and it would pass or fail depending on what the previous
	// section happened to leave behind. A section must not be able to leak an admission into
	// the one after it.
	config::rvv_llvm_fp_cvt_masked = false;
	config::rvv_llvm_fp_dynamic_frm = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
}

void Translate(Built &b)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

void CheckModuleIsWellFormed(Built &b, char const *what)
{
	std::string err;
	llvm::raw_string_ostream es(err);
	if (llvm::verifyModule(b.module, &es)) {
		printf("  FAIL %s: verifyModule rejected the emitted module:\n%s\n", what, err.c_str());
		++g_fail;
	}
	llvm::raw_null_ostream null_os; // drives llvm::TypeFinder over every referenced type
	b.module.print(null_os, nullptr);
}

struct Qir {
	unsigned frames = 0, units = 0, hcalls = 0, brackets = 0;
	int guard_kind = -1, is_signed = -1, rtz = -1;
	u32 vtype = 0, vlmax = 0; // C6-FRM: needed to pin the frame guard's state loads
	unsigned sew = 0, bytes = 0, src_sew = 0;
	std::vector<u32> src_offs, dst_offs;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				q.vtype = static_cast<InstRVVTypedChunkBegin *>(&ins)->vtype;
				q.vlmax = static_cast<InstRVVTypedChunkBegin *>(&ins)->vlmax;
				break;
			case Op::_vchunkftoi: {
				auto *n = static_cast<InstVChunkFToI *>(&ins);
				++q.units;
				q.is_signed = n->is_signed ? 1 : 0;
				q.rtz = n->rtz ? 1 : 0;
				q.sew = n->sew;
				q.bytes = n->bytes;
				q.src_sew = n->src_sew;
				q.src_offs.push_back(n->rs);
				q.dst_offs.push_back(n->rd);
				break;
			}
			case Op::_rvvqcgfpbegin:
				++q.brackets;
				break;
			case Op::_hcall:
				++q.hcalls;
				break;
			default:
				break;
			}
		}
	return q;
}

llvm::Value *StripToBase(llvm::Value *p)
{
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p))
		p = g->getPointerOperand();
	return p;
}

u32 StateOffset(llvm::Value *p, llvm::Value *state)
{
	if (StripToBase(p) != state || p == state)
		return ~0u;
	auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	if (!g)
		return ~0u;
	llvm::APInt ap(64, 0);
	if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
		return ~0u;
	return (u32)ap.getZExtValue();
}

void FoldToFixpoint(llvm::Function *fn)
{
	auto const &DL = fn->getParent()->getDataLayout();
	for (bool again = true; again;) {
		again = false;
		for (auto &bb : *fn)
			for (auto it = bb.begin(); it != bb.end();) {
				llvm::Instruction &I = *it++;
				if (I.isTerminator() || I.mayHaveSideEffects() || I.use_empty())
					continue;
				if (auto *c = llvm::ConstantFoldInstruction(&I, DL)) {
					I.replaceAllUsesWith(c);
					again = true;
				}
			}
	}
}

// What the hardware conversion produces for an operand that is already NEUTRALISED -- every lane is
// either +0.0 or genuinely in range -- so a plain C++ truncation is well defined here.
u64 TruncateInRange(double v, bool is_signed, u32 bits)
{
	double const t = std::trunc(v);
	u64 const all = bits == 64 ? ~0ull : ((1ull << bits) - 1u);
	if (is_signed)
		return (u64)(long long)t & all;
	if (t <= 0.0) // only -0.0 / values truncating to zero survive neutralisation here
		return 0;
	return (u64)(unsigned long long)t & all;
}

struct Folded {
	bool ok = false;
	std::vector<u64> lanes;
	u32 flags = 0; // the constant the unit ORs into fcsr: NV and, on the frm arm, NX
};

Folded FoldUnit(Built &b, u32 rs_off, u32 rd_off, std::vector<u64> const &pattern, u32 sew,
		u32 lanes, bool is_signed, bool rtz)
{
	Folded out;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	u32 const bits = 8u * sew;

	// [step 1] the unit's source load, matched structurally (types are uniqued per context).
	llvm::LoadInst *src = nullptr;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || vt->getNumElements() != lanes ||
			    !vt->getElementType()->isFloatingPointTy() ||
			    vt->getScalarSizeInBits() != bits)
				continue;
			if (StateOffset(l->getPointerOperand(), state) != rs_off)
				continue;
			src = l;
			break;
		}
		if (src)
			break;
	}
	if (!src)
		return out;
	auto *fty = llvm::cast<llvm::FixedVectorType>(src->getType());
	llvm::SmallVector<llvm::Constant *, 64> in;
	for (u32 i = 0; i < lanes; ++i) {
		u64 const bitsv = pattern[i % pattern.size()];
		llvm::APInt ap(bits, bitsv);
		in.push_back(llvm::ConstantFP::get(
		    fty->getElementType(),
		    sew == 4 ? llvm::APFloat(llvm::APFloat::IEEEsingle(), ap)
			     : llvm::APFloat(llvm::APFloat::IEEEdouble(), ap)));
	}
	src->replaceAllUsesWith(llvm::ConstantVector::get(in));
	FoldToFixpoint(fn);

	// The frm arm rounds first, and `constrained.nearbyint` cannot constant-fold either. Replace
	// it with round-to-nearest-even of its (already neutralised) constant operand -- RNE because
	// the frame guard pins `frm == RNE`, which is the only mode this route admits.
	if (!rtz) {
		llvm::IntrinsicInst *rnd = nullptr;
		for (auto &bb : *fn)
			for (auto &ins : bb)
				if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
					if (ii->getIntrinsicID() ==
					    llvm::Intrinsic::experimental_constrained_nearbyint) {
						rnd = ii;
						break;
					}
		if (!rnd)
			return out;
		auto *rop = llvm::dyn_cast<llvm::Constant>(rnd->getArgOperand(0));
		if (!rop)
			return out;
		auto *rfty = llvm::cast<llvm::FixedVectorType>(rnd->getType());
		llvm::SmallVector<llvm::Constant *, 64> rv;
		for (u32 i = 0; i < lanes; ++i) {
			auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(rop->getAggregateElement(i));
			if (!cf)
				return out;
			double const x = cf->getValueAPF().convertToDouble();
			double const r = std::nearbyint(x); // default FE_TONEAREST == RNE
			rv.push_back(sew == 4 ? llvm::ConstantFP::get(rfty->getElementType(),
								      (double)(float)r)
					      : llvm::ConstantFP::get(rfty->getElementType(), r));
		}
		rnd->replaceAllUsesWith(llvm::ConstantVector::get(rv));
		FoldToFixpoint(fn);
	}

	// [step 2] the constrained conversion cannot fold; replace it with the truncation of its now
	// constant -- and already neutralised -- operand.
	llvm::IntrinsicInst *conv = nullptr;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				auto const id = ii->getIntrinsicID();
				if (id == llvm::Intrinsic::experimental_constrained_fptosi ||
				    id == llvm::Intrinsic::experimental_constrained_fptoui) {
					conv = ii;
					break;
				}
			}
	if (!conv)
		return out;
	auto *op = llvm::dyn_cast<llvm::Constant>(conv->getArgOperand(0));
	if (!op)
		return out; // the neutralisation did not fold: the operand is not constant
	auto *ity = llvm::cast<llvm::FixedVectorType>(conv->getType());
	llvm::SmallVector<llvm::Constant *, 64> cv;
	for (u32 i = 0; i < lanes; ++i) {
		auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(op->getAggregateElement(i));
		if (!cf)
			return out;
		double const v = cf->getValueAPF().convertToDouble();
		cv.push_back(llvm::ConstantInt::get(ity->getElementType(),
						    TruncateInRange(v, is_signed, bits)));
	}
	conv->replaceAllUsesWith(llvm::ConstantVector::get(cv));
	FoldToFixpoint(fn);

	// [step 3] read the unit's destination store and the fcsr update.
	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st)
				continue;
			u32 const off = StateOffset(st->getPointerOperand(), state);
			if (off == rd_off) {
				if (auto *c = llvm::dyn_cast<llvm::Constant>(st->getValueOperand())) {
					out.lanes.clear();
					for (u32 i = 0; i < lanes; ++i)
						if (auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(
							c->getAggregateElement(i)))
							out.lanes.push_back(ci->getZExtValue());
					out.ok = out.lanes.size() == lanes;
				}
			} else if (off == fcsr_off) {
				// folds to `or(<fcsr load>, <constant flag mask>)`
				if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(
					st->getValueOperand()))
					if (bo->getOpcode() == llvm::Instruction::Or)
						if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(
							bo->getOperand(1)))
							out.flags = (u32)ci->getZExtValue();
			}
		}
	return out;
}

// One representative of every boundary the contract distinguishes, per width.
struct Pat { char const *name; u32 p32; u64 p64; };
constexpr Pat kPats[] = {
    {"+0.0",           0x00000000u, 0x0000000000000000ull},
    {"-0.0",           0x80000000u, 0x8000000000000000ull},
    {"+1.5 (inexact)", 0x3fc00000u, 0x3ff8000000000000ull},
    {"-1.5 (inexact)", 0xbfc00000u, 0xbff8000000000000ull},
    {"+2.0 (exact)",   0x40000000u, 0x4000000000000000ull},
    {"-0.5 (unsigned in range!)", 0xbf000000u, 0xbfe0000000000000ull},
    // -0.75 is THE discriminator for "range test on the ROUNDED value": RNE(-0.75) = -1.0, which is
    // out of range for unsigned (NV), while the ORIGINAL -0.75 has magnitude < 1 and would test as
    // in range. Without this input a mutation that range-tests the original bits passes. It is the
    // only boundary in the same-width envelope where rounding can move a value across a limit --
    // every other limit sits at an exponent where the format's ulp is already >= 1, so values there
    // are integers and rounding cannot move them.
    {"-0.75 (RNE -> -1.0)",       0xbf400000u, 0xbfe8000000000000ull},
    {"+0.75 (RNE -> +1.0)",       0x3f400000u, 0x3fe8000000000000ull},
    {"-1.0 (unsigned invalid)",   0xbf800000u, 0xbff0000000000000ull},
    {"+inf",           0x7f800000u, 0x7ff0000000000000ull},
    {"-inf",           0xff800000u, 0xfff0000000000000ull},
    {"qNaN",           0x7fc00000u, 0x7ff8000000000000ull},
    {"sNaN",           0x7f800001u, 0x7ff0000000000001ull},
    {"-qNaN",          0xffc00000u, 0xfff8000000000000ull},
    // the signed boundaries: -2^(W-1) is IN range, +2^(W-1) is not
    {"-2^(W-1)",       0xcf000000u, 0xc3e0000000000000ull},
    {"+2^(W-1)",       0x4f000000u, 0x43e0000000000000ull},
    {"+2^(W-1) - ulp", 0x4effffffu, 0x43dfffffffffffffull},
    {"+2^W (unsigned oor)", 0x4f800000u, 0x43f0000000000000ull},
    {"+2^W - ulp",     0x4f7fffffu, 0x43efffffffffffffull},
    {"+huge",          0x7f7fffffu, 0x7fefffffffffffffull},
};
constexpr size_t kNP = sizeof(kPats) / sizeof(kPats[0]);

void SectionOracle()
{
	printf("[C4FI-3,4] value + NV oracle vs softfp::cvt_to_int_width\n");
	unsigned checked = 0;
	bool seen[kNP] = {};
	for (u32 vlen : {256u, 1024u})
	  for (int arm = 0; arm < 2; ++arm)
		for (int sgn = 0; sgn < 2; ++sgn)
			for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
				bool const rtz = arm == 1;
				u32 const sew = vt == kVT_E64M1 ? 8u : 4u;
				u32 const bytes = vlen / 8u < 64u ? vlen / 8u : 64u;
				u32 const lanes = bytes / sew;
				bool const is_signed = sgn == 1;
				u32 const rm = rtz ? rvv32::FRM_RTZ : rvv32::FRM_RNE;
				auto const &fmt = sew == 4 ? rvv32::softfp::FMT32
							   : rvv32::softfp::FMT64;
				for (size_t start = 0; start < kNP; start += lanes) {
					Configure(vlen, /*on=*/true);
					Built b({Vsetvli(vt), OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd),
						 kJalr});
					Translate(b);
					Qir q = ScanQir(b.region);
					if (!q.frames)
						break;
					std::vector<u64> pattern;
					for (u32 i = 0; i < lanes; ++i) {
						size_t const k = (start + i) % kNP;
						pattern.push_back(sew == 4 ? (u64)kPats[k].p32
									   : kPats[k].p64);
					}
					Folded f = FoldUnit(b, VRegOff(kVs2), VRegOff(kVd), pattern,
							    sew, lanes, is_signed, rtz);
					if (!f.ok) {
						printf("  FAIL vlen=%u sew=%u %s start=%zu: the unit "
						       "did not fold to a constant\n", vlen, sew,
						       is_signed ? "signed" : "unsigned", start);
						++g_fail;
						continue;
					}
					bool want_nv = false;
					for (u32 i = 0; i < lanes; ++i) {
						size_t const k = (start + i) % kNP;
						u32 fl = 0;
						u64 const want = rvv32::softfp::cvt_to_int_width(
						    pattern[i], is_signed, fmt, rm, 8u * sew, fl);
						if (fl & rvv32::FFLAG_NV)
							want_nv = true;
						++checked;
						seen[k] = true;
						if (f.lanes[i] != want) {
							printf("  FAIL vlen=%u sew=%u %-26s %s "
							       "in=0x%llx emitted=0x%llx "
							       "reference=0x%llx\n", vlen, sew,
							       kPats[k].name,
							       ArmName(rtz, is_signed),
							       (unsigned long long)pattern[i],
							       (unsigned long long)f.lanes[i],
							       (unsigned long long)want);
							++g_fail;
						}
					}
					if (((f.flags & rvv32::FFLAG_NV) != 0) != want_nv) {
						printf("  FAIL vlen=%u sew=%u %s start=%zu: NV "
						       "emitted=%d contract=%d\n", vlen, sew,
						       ArmName(rtz, is_signed), start,
						       (int)((f.flags & rvv32::FFLAG_NV) != 0),
						       (int)want_nv);
						++g_fail;
					}
				}
			}
	printf("       %u lanes compared against the reference converter\n", checked);
	CHECK(checked > 0);
	for (size_t k = 0; k < kNP; ++k)
		if (!seen[k]) {
			printf("  FAIL pattern '%s' was never compared -- the oracle has a gap\n",
			       kPats[k].name);
			++g_fail;
		}
}

void SectionShapeAndNeutralisation()
{
	printf("[C4FI-1,2] frame shape, and the conversion's operand IS a neutralising select\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 sub : {kSubRtzX, kSubRtzXu, kSubFrmX, kSubFrmXu})
			for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
				bool const rtz = sub >= 6u;
				Configure(vlen, /*on=*/true);
				Built b({Vsetvli(vt), OpVfcvt(sub, kVs2, kVd), kJalr});
				Translate(b);
				Qir q = ScanQir(b.region);
				if (!q.frames)
					continue;
				++admitted;
				CheckModuleIsWellFormed(b, "float-to-int");
				CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
				CHECK_EQ(q.rtz, rtz ? 1 : 0);
				CHECK_EQ(q.is_signed, (sub & 1u) != 0u ? 1 : 0);
				CHECK_EQ(q.brackets, 1u);

				unsigned convs = 0, neutralised = 0, plain = 0;
				unsigned nearby = 0, rints = 0;
				for (auto &bb : *b.fn)
					for (auto &ins : bb) {
						if (llvm::isa<llvm::FPToSIInst>(&ins) ||
						    llvm::isa<llvm::FPToUIInst>(&ins))
							++plain;
						auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
						if (!ii)
							continue;
						auto const id = ii->getIntrinsicID();
						if (id == llvm::Intrinsic::
							      experimental_constrained_nearbyint)
							++nearby;
						if (id == llvm::Intrinsic::
							      experimental_constrained_rint)
							++rints;
						if (id != llvm::Intrinsic::
							      experimental_constrained_fptosi &&
						    id != llvm::Intrinsic::
							      experimental_constrained_fptoui)
							continue;
						++convs;
						// THE ASSERTION: the operand is a select, i.e. the
						// invalid lanes were replaced BEFORE the conversion.
						if (llvm::isa<llvm::SelectInst>(
							ii->getArgOperand(0)))
							++neutralised;
					}
				CHECK_EQ(convs, q.units);
				CHECK_EQ(neutralised, q.units);
				CHECK_EQ(plain, 0u);
				// THE ROUNDING INTRINSIC MUST BE `nearbyint`, NEVER `rint`. Measured on
				// LLVM 20.1.8: `nearbyint` -> `vrndscaleps $12` (uses MXCSR.RC and
				// SUPPRESSES the precision exception); `rint` -> `$4` (raises it). This
				// route derives NX itself, so a host NX from `rint` would be counted
				// twice. The test cannot observe host MXCSR, so this structural check is
				// the instrument for that -- stated rather than implied.
				CHECK_EQ(rints, 0u);
				CHECK_EQ(nearby, rtz ? 0u : q.units);
			}
	CHECK(admitted > 0);
}

// [C4FI-7] PER-LANE FLAG ISOLATION, and it exists because the chunk-level check was not enough.
//
// The two subtlest rules in the contract are ones where the emitted RESULT is correct either way and
// only the FLAG differs:
//   * signed `-2^(W-1)` is IN range -- treating it as out of range still yields `sat_min`, which is
//     the same value, but raises a spurious NV;
//   * unsigned `-0.5` is IN range (the rule is `a.sign && ip != 0`, not "is negative") -- treating
//     any negative as invalid still yields 0, the same value, but raises NV instead of NX.
// Mutations of exactly those two shapes PASSED the first version of this file. The value oracle
// cannot see them, and the NV oracle could not either, because it compared NV per CHUNK: any other
// invalid lane in the same chunk -- an infinity, a NaN -- already forced `want_nv` true and masked
// the change.
//
// So each pattern is placed in lane 0 with every other lane holding `+2.0`, which is exact and in
// range for both directions and therefore raises nothing. The chunk's NV then reflects THAT PATTERN
// ALONE and is compared against the contract's flags for it.
void SectionPerLaneFlags()
{
	printf("[C4FI-7] per-lane NV isolation (filler lanes raise nothing)\n");
	unsigned checked = 0;
	for (u32 vlen : {256u, 1024u})
	  for (int arm = 0; arm < 2; ++arm)
		for (int sgn = 0; sgn < 2; ++sgn)
			for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
				bool const rtz = arm == 1;
				u32 const sew = vt == kVT_E64M1 ? 8u : 4u;
				u32 const bytes = vlen / 8u < 64u ? vlen / 8u : 64u;
				u32 const lanes = bytes / sew;
				bool const is_signed = sgn == 1;
				u32 const rm = rtz ? rvv32::FRM_RTZ : rvv32::FRM_RNE;
				auto const &fmt = sew == 4 ? rvv32::softfp::FMT32
							   : rvv32::softfp::FMT64;
				// +2.0: exact, in range for x.f and xu.f alike, raises nothing.
				u64 const filler = sew == 4 ? 0x40000000ull : 0x4000000000000000ull;
				for (size_t k = 0; k < kNP; ++k) {
					Configure(vlen, /*on=*/true);
					Built b({Vsetvli(vt), OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd),
						 kJalr});
					Translate(b);
					if (!ScanQir(b.region).frames)
						break;
					std::vector<u64> pattern(lanes, filler);
					pattern[0] = sew == 4 ? (u64)kPats[k].p32 : kPats[k].p64;
					Folded f = FoldUnit(b, VRegOff(kVs2), VRegOff(kVd), pattern,
							    sew, lanes, is_signed, rtz);
					if (!f.ok) {
						printf("  FAIL vlen=%u sew=%u %s '%s': did not fold\n",
						       vlen, sew, ArmName(rtz, is_signed),
						       kPats[k].name);
						++g_fail;
						continue;
					}
					u32 fl = 0;
					u64 const want = rvv32::softfp::cvt_to_int_width(
					    pattern[0], is_signed, fmt, rm, 8u * sew, fl);
					bool const want_nv = (fl & rvv32::FFLAG_NV) != 0;
					bool const want_nx = (fl & rvv32::FFLAG_NX) != 0;
					++checked;
					if (f.lanes[0] != want) {
						printf("  FAIL vlen=%u sew=%u %-26s %s value "
						       "emitted=0x%llx reference=0x%llx\n", vlen, sew,
						       kPats[k].name, ArmName(rtz, is_signed),
						       (unsigned long long)f.lanes[0],
						       (unsigned long long)want);
						++g_fail;
					}
					bool const got_nv = (f.flags & rvv32::FFLAG_NV) != 0;
					if (got_nv != want_nv) {
						printf("  FAIL vlen=%u sew=%u %-26s %s NV emitted=%d "
						       "contract=%d  (this lane alone decides it)\n",
						       vlen, sew, kPats[k].name,
						       ArmName(rtz, is_signed), (int)got_nv,
						       (int)want_nv);
						++g_fail;
					}
					// NX is DERIVED on the frm arm (`nearbyint` suppresses the host
					// precision exception and the truncating convert of an integral
					// value raises nothing), so it is checkable here. On the rtz arm
					// NX is left to the hardware and is deliberately not asserted.
					if (!rtz) {
						bool const got_nx = (f.flags & rvv32::FFLAG_NX) != 0;
						if (got_nx != want_nx) {
							printf("  FAIL vlen=%u sew=%u %-26s %s NX "
							       "emitted=%d contract=%d\n", vlen, sew,
							       kPats[k].name,
							       ArmName(rtz, is_signed),
							       (int)got_nx, (int)want_nx);
							++g_fail;
						}
					}
				}
			}
	printf("       %u isolated lanes compared (value, NV, and NX on the frm arm)\n", checked);
	CHECK(checked > 0);
}

// The widening fold: source is `<lanes x float>` and destination `<lanes x i64>`, so the two type
// searches differ. Everything else -- the rounding substitution on the frm arm, the truncation of
// the already-neutralised operand, the store and fcsr reads -- is the same-width helper's logic.
Folded FoldUnitW(Built &b, u32 rs_off, u32 rd_off, std::vector<u64> const &pattern, u32 lanes,
		 bool is_signed, bool rtz)
{
	Folded out;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);

	llvm::LoadInst *src = nullptr;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || vt->getNumElements() != lanes || !vt->getElementType()->isFloatTy())
				continue;
			if (StateOffset(l->getPointerOperand(), state) != rs_off)
				continue;
			src = l;
			break;
		}
		if (src)
			break;
	}
	if (!src)
		return out;
	auto *sfty = llvm::cast<llvm::FixedVectorType>(src->getType());
	llvm::SmallVector<llvm::Constant *, 64> in;
	for (u32 i = 0; i < lanes; ++i)
		in.push_back(llvm::ConstantFP::get(
		    sfty->getElementType(),
		    llvm::APFloat(llvm::APFloat::IEEEsingle(),
				  llvm::APInt(32, (u32)pattern[i % pattern.size()]))));
	src->replaceAllUsesWith(llvm::ConstantVector::get(in));
	FoldToFixpoint(fn);

	if (!rtz) {
		llvm::IntrinsicInst *rnd = nullptr;
		for (auto &bb : *fn)
			for (auto &ins : bb)
				if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
					if (ii->getIntrinsicID() ==
					    llvm::Intrinsic::experimental_constrained_nearbyint) {
						rnd = ii;
						break;
					}
		if (!rnd)
			return out;
		auto *rop = llvm::dyn_cast<llvm::Constant>(rnd->getArgOperand(0));
		if (!rop)
			return out;
		auto *rfty = llvm::cast<llvm::FixedVectorType>(rnd->getType());
		llvm::SmallVector<llvm::Constant *, 64> rv;
		for (u32 i = 0; i < lanes; ++i) {
			auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(rop->getAggregateElement(i));
			if (!cf)
				return out;
			double const x = cf->getValueAPF().convertToDouble();
			rv.push_back(llvm::ConstantFP::get(rfty->getElementType(),
							   (double)(float)std::nearbyint(x)));
		}
		rnd->replaceAllUsesWith(llvm::ConstantVector::get(rv));
		FoldToFixpoint(fn);
	}

	llvm::IntrinsicInst *conv = nullptr;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				auto const id = ii->getIntrinsicID();
				if (id == llvm::Intrinsic::experimental_constrained_fptosi ||
				    id == llvm::Intrinsic::experimental_constrained_fptoui) {
					conv = ii;
					break;
				}
			}
	if (!conv)
		return out;
	auto *op = llvm::dyn_cast<llvm::Constant>(conv->getArgOperand(0));
	if (!op)
		return out;
	auto *ity = llvm::cast<llvm::FixedVectorType>(conv->getType());
	llvm::SmallVector<llvm::Constant *, 64> cv;
	for (u32 i = 0; i < lanes; ++i) {
		auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(op->getAggregateElement(i));
		if (!cf)
			return out;
		cv.push_back(llvm::ConstantInt::get(
		    ity->getElementType(),
		    TruncateInRange(cf->getValueAPF().convertToDouble(), is_signed, 64u)));
	}
	conv->replaceAllUsesWith(llvm::ConstantVector::get(cv));
	FoldToFixpoint(fn);

	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st)
				continue;
			u32 const off = StateOffset(st->getPointerOperand(), state);
			if (off == rd_off) {
				if (auto *c = llvm::dyn_cast<llvm::Constant>(st->getValueOperand())) {
					out.lanes.clear();
					for (u32 i = 0; i < lanes; ++i)
						if (auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(
							c->getAggregateElement(i)))
							out.lanes.push_back(ci->getZExtValue());
					out.ok = out.lanes.size() == lanes;
				}
			} else if (off == fcsr_off) {
				if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(
					st->getValueOperand()))
					if (bo->getOpcode() == llvm::Instruction::Or)
						if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(
							bo->getOperand(1)))
							out.flags = (u32)ci->getZExtValue();
			}
		}
	return out;
}

// ---------------------------------------------------------------------------------------------
// [C4FIW] WIDENING float -> integer: `vfwcvt.{x,xu}.f.v` and the `.rtz` pair, f32 -> i64.
//
// The semantics are this file's own, reused; what has to be proved here is that the TWO WIDTHS are
// kept apart -- bit-layout constants in the SOURCE format, saturation values and range bounds in the
// DESTINATION integer. The oracle is the same `cvt_to_int_width` comparison with a destination width
// of 64, run over patterns chosen for the f32 -> i64 boundaries.
constexpr u32 kSubWFrmXu = 8u, kSubWFrmX = 9u, kSubWRtzXu = 14u, kSubWRtzX = 15u;
constexpr u32 SubForW(bool rtz, bool is_signed)
{
	return rtz ? (is_signed ? kSubWRtzX : kSubWRtzXu) : (is_signed ? kSubWFrmX : kSubWFrmXu);
}

// f32 patterns whose i64 behaviour is the interesting part.
struct PatW { char const *name; u32 bits; };
constexpr PatW kPatsW[] = {
    {"+0.0",              0x00000000u},
    {"-0.0",              0x80000000u},
    {"+2.5 (inexact)",    0x40200000u},
    {"-2.5 (inexact)",    0xc0200000u},
    {"-0.5 (unsigned in range!)", 0xbf000000u},
    {"-0.75 (RNE -> -1)", 0xbf400000u},
    {"+2^31 (fits i64)",  0x4f000000u},
    {"+2^62",             0x5e800000u},
    {"-2^63 (in range)",  0xdf000000u},
    {"+2^63 (oor)",       0x5f000000u},
    {"+2^64 (oor)",       0x5f800000u},
    {"+inf",              0x7f800000u},
    {"-inf",              0xff800000u},
    {"qNaN",              0x7fc00000u},
    {"sNaN",              0x7f800001u},
};
constexpr size_t kNPW = sizeof(kPatsW) / sizeof(kPatsW[0]);

void SectionWiden()
{
	printf("[C4FIW] widening f32->i64: source/destination widths kept apart, value+flag oracle\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned checked = 0, admitted = 0;
	bool seen[kNPW] = {};
	constexpr u32 kFillerW = 0x40000000u; // +2.0: exact, in range for both directions
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (int arm = 0; arm < 2; ++arm)
			for (int sgn = 0; sgn < 2; ++sgn) {
				bool const rtz = arm == 1, is_signed = sgn == 1;
				u32 const rm = rtz ? rvv32::FRM_RTZ : rvv32::FRM_RNE;
				for (size_t k = 0; k < kNPW; ++k) {
					Configure(vlen, /*on=*/false);
					config::rvv_llvm_fcvt_ftoi_widen = true;
					Built b({Vsetvli(kVT_E32M1),
						 OpVfcvt(SubForW(rtz, is_signed), kVs2, kVd), kJalr});
					Translate(b);
					Qir q = ScanQir(b.region);
					if (!q.frames)
						break;
					if (k == 0) {
						++admitted;
						CheckModuleIsWellFormed(b, "vfwcvt float-to-int");
						CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
						CHECK_EQ(q.sew, 8u);	 // destination i64
						CHECK_EQ(q.src_sew, 4u); // source f32
						CHECK_EQ(q.rtz, rtz ? 1 : 0);
						CHECK_EQ(q.is_signed, is_signed ? 1 : 0);
						u32 const rb = vlen / 8u;
						u32 const lanes2 = q.bytes / 8u;
						auto win = [&](u32 reg, u32 e, u32 esz) {
							u32 const byte = e * esz;
							return VRegOff(reg) +
							       byte / rb * rvv32::VLEN_MAX_BYTES +
							       byte % rb;
						};
						for (size_t u = 0; u < q.dst_offs.size(); ++u) {
							CHECK_EQ(q.dst_offs[u],
								 win(kVd, (u32)u * lanes2, 8u));
							CHECK_EQ(q.src_offs[u],
								 win(kVs2, (u32)u * lanes2, 4u));
						}
					}
					u32 const lanes = q.bytes / 8u;
					std::vector<u64> pattern(lanes, kFillerW);
					pattern[0] = kPatsW[k].bits;
					Folded f = FoldUnitW(b, VRegOff(kVs2), VRegOff(kVd), pattern,
							     lanes, is_signed, rtz);
					if (!f.ok) {
						printf("  FAIL vlen=%u %s '%s': did not fold\n", vlen,
						       ArmName(rtz, is_signed), kPatsW[k].name);
						++g_fail;
						continue;
					}
					u32 fl = 0;
					u64 const want = rvv32::softfp::cvt_to_int_width(
					    kPatsW[k].bits, is_signed, rvv32::softfp::FMT32, rm, 64u,
					    fl);
					++checked;
					seen[k] = true;
					if (f.lanes[0] != want) {
						printf("  FAIL vlen=%u %s %-26s value emitted=0x%016llx "
						       "reference=0x%016llx\n", vlen,
						       ArmName(rtz, is_signed), kPatsW[k].name,
						       (unsigned long long)f.lanes[0],
						       (unsigned long long)want);
						++g_fail;
					}
					bool const want_nv = (fl & rvv32::FFLAG_NV) != 0;
					if (((f.flags & rvv32::FFLAG_NV) != 0) != want_nv) {
						printf("  FAIL vlen=%u %s %-26s NV emitted=%d "
						       "contract=%d\n", vlen, ArmName(rtz, is_signed),
						       kPatsW[k].name,
						       (int)((f.flags & rvv32::FFLAG_NV) != 0),
						       (int)want_nv);
						++g_fail;
					}
					if (!rtz) {
						bool const want_nx = (fl & rvv32::FFLAG_NX) != 0;
						bool const got_nx = (f.flags & rvv32::FFLAG_NX) != 0;
						if (got_nx != want_nx) {
							printf("  FAIL vlen=%u %s %-26s NX emitted=%d "
							       "contract=%d\n", vlen,
							       ArmName(rtz, is_signed),
							       kPatsW[k].name, (int)got_nx,
							       (int)want_nx);
							++g_fail;
						}
					}
				}
			}
	printf("       %u isolated lanes compared (value, NV, NX on the frm arm)\n", checked);
	CHECK(checked > 0);
	CHECK(admitted > 0);
	for (size_t k = 0; k < kNPW; ++k)
		if (!seen[k]) {
			printf("  FAIL widening pattern '%s' was never compared\n", kPatsW[k].name);
			++g_fail;
		}
	// Only vtype SEW 32 is in the admitted pair; SEW 16 and 64 keep the helper.
	for (u32 bad_vt : {0xc8u, kVT_E64M1}) {
		Configure(1024u, /*on=*/false);
		config::rvv_llvm_fcvt_ftoi_widen = true;
		Built b({Vsetvli(bad_vt), OpVfcvt(kSubWRtzX, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.units, 0u);
		CHECK(q.hcalls > 0u);
	}
}

// ---------------------------------------------------------------------------------------------
// [C4FP] PARTIAL VL for the float-SOURCE conversions, and the one check that actually settles the
// composition question: an architecturally INVALID value sitting in an INACTIVE lane must raise
// NOTHING.
//
// Every other check here could pass with the two suppression reasons conflated. This one cannot:
// it folds `vec.vl` to a constant as well as the operand, so the whole unit -- mask, neutralisation,
// conversion, flag derivation -- collapses to constants, and the `fcsr` OR is then read directly.
// The same NaN is placed once in an active lane (NV must appear) and once in an inactive lane (NV
// must NOT appear).
struct PartialFold {
	bool ok{false};
	u32 flags{0};
	std::vector<std::vector<u64>> unit_masks;
	bool masked_store{false}, plain_store{false};
};

// `v0_bits` is the ARCHITECTURAL MASK, one bit per ELEMENT, and it defaults to all-active so
// every pre-existing caller is unaffected -- an unmasked instruction emits no v0 load at all,
// so the pinning below is a no-op for them.
PartialFold FoldPartial(Built &b, u32 rs_off, u32 rd_off, std::vector<u64> const &pattern,
			u32 lanes, bool is_signed, bool rtz, u32 vl_value,
			u64 v0_bits = ~(u64)0)
{
	PartialFold out;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	u32 const vl_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
	u32 const v0_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));

	// vl becomes a constant, which is what lets the active mask fold.
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins))
				if (StateOffset(l->getPointerOperand(), state) == vl_off)
					l->replaceAllUsesWith(
					    llvm::ConstantInt::get(l->getType(), vl_value));
	// THE ARCHITECTURAL MASK. `RvvArchMaskForUnit` loads v0 as a 16-bit group at
	// `vreg_base + element_base/8`, so the i16 at byte `k` carries elements [k*8, k*8+16).
	// Serving it per-window rather than pinning one constant everywhere is what lets a
	// multi-unit frame be checked: a single constant would make every unit's mask identical
	// and hide a unit that read the wrong window.
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l || !l->getType()->isIntegerTy(16))
				continue;
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o == ~0u || o < v0_off || o >= v0_off + rvv32::VLEN_MAX_BYTES)
				continue;
			u32 const first = (o - v0_off) * 8u;
			u16 w = 0;
			for (u32 i = 0; i < 16u && first + i < 64u; ++i)
				if (v0_bits & ((u64)1 << (first + i)))
					w |= (u16)(1u << i);
			l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), w));
		}
	llvm::LoadInst *src = nullptr;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || vt->getNumElements() != lanes || !vt->getElementType()->isFloatTy())
				continue;
			if (StateOffset(l->getPointerOperand(), state) != rs_off)
				continue;
			src = l;
			break;
		}
		if (src)
			break;
	}
	if (!src)
		return out;
	auto *sfty = llvm::cast<llvm::FixedVectorType>(src->getType());
	llvm::SmallVector<llvm::Constant *, 64> in;
	for (u32 i = 0; i < lanes; ++i)
		in.push_back(llvm::ConstantFP::get(
		    sfty->getElementType(),
		    llvm::APFloat(llvm::APFloat::IEEEsingle(),
				  llvm::APInt(32, (u32)pattern[i % pattern.size()]))));
	src->replaceAllUsesWith(llvm::ConstantVector::get(in));
	FoldToFixpoint(fn);

	if (!rtz) {
		for (auto &bb : *fn)
			for (auto &ins : bb)
				if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
					if (ii->getIntrinsicID() ==
					    llvm::Intrinsic::experimental_constrained_nearbyint) {
						auto *rop = llvm::dyn_cast<llvm::Constant>(
						    ii->getArgOperand(0));
						if (!rop)
							return out;
						auto *rt = llvm::cast<llvm::FixedVectorType>(
						    ii->getType());
						llvm::SmallVector<llvm::Constant *, 64> rv;
						for (u32 i = 0; i < lanes; ++i) {
							auto *cf = llvm::dyn_cast_or_null<
							    llvm::ConstantFP>(
							    rop->getAggregateElement(i));
							if (!cf)
								return out;
							rv.push_back(llvm::ConstantFP::get(
							    rt->getElementType(),
							    (double)(float)std::nearbyint(
								cf->getValueAPF()
								    .convertToDouble())));
						}
						ii->replaceAllUsesWith(
						    llvm::ConstantVector::get(rv));
						break;
					}
		FoldToFixpoint(fn);
	}
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				auto const id = ii->getIntrinsicID();
				if (id != llvm::Intrinsic::experimental_constrained_fptosi &&
				    id != llvm::Intrinsic::experimental_constrained_fptoui)
					continue;
				auto *op = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
				if (!op)
					return out;
				auto *it = llvm::cast<llvm::FixedVectorType>(ii->getType());
				llvm::SmallVector<llvm::Constant *, 64> cv;
				for (u32 i = 0; i < lanes; ++i) {
					auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(
					    op->getAggregateElement(i));
					if (!cf)
						return out;
					cv.push_back(llvm::ConstantInt::get(
					    it->getElementType(),
					    TruncateInRange(cf->getValueAPF().convertToDouble(),
							    is_signed,
							    it->getScalarSizeInBits())));
				}
				ii->replaceAllUsesWith(llvm::ConstantVector::get(cv));
				break;
			}
	FoldToFixpoint(fn);

	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
					// EVERY unit's mask, in emission order -- not just unit 0's.
					// With `vl` folded the mask is a constant i1 vector, so what is
					// read here is the ACTIVE SET itself, which is a stronger check
					// than the index vector: a unit whose mask was built from lane 0
					// instead of its own element base shows up as the wrong set.
					if (StateOffset(ii->getArgOperand(1), state) == rd_off)
						out.masked_store = true;
					if (auto *cv = llvm::dyn_cast<llvm::Constant>(
						testcompat::MaskedStoreMask(ii))) {
						std::vector<u64> m;
						for (u32 i = 0; i < lanes; ++i)
							if (auto *ci =
								llvm::dyn_cast_or_null<llvm::ConstantInt>(
								    cv->getAggregateElement(i)))
								m.push_back(ci->getZExtValue());
						out.unit_masks.push_back(m);
					}
					continue;
				}
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st)
				continue;
			u32 const off = StateOffset(st->getPointerOperand(), state);
			if (off == rd_off)
				out.plain_store = true;
			else if (off == fcsr_off)
				if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(
					st->getValueOperand()))
					if (bo->getOpcode() == llvm::Instruction::Or)
						if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(
							bo->getOperand(1))) {
							out.flags = (u32)ci->getZExtValue();
							out.ok = true;
						}
		}
	return out;
}

void SectionPartialVlFloatSource()
{
	printf("[C4FP] float-source partial VL: an invalid value in an INACTIVE lane raises nothing\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	constexpr u32 kQNaN = 0x7fc00000u, kBenign = 0x40000000u; // +2.0: exact, in range
	unsigned cases = 0;
	for (u32 vlen : {256u, 1024u})
		for (int arm = 0; arm < 2; ++arm)
			for (int sgn = 0; sgn < 2; ++sgn) {
				bool const rtz = arm == 1, is_signed = sgn == 1;
				// Build once to learn the shape.
				Configure(vlen, /*on=*/true);
				config::rvv_llvm_fcvt_partial_vl = true;
				Built probe({Vsetvli(kVT_E32M1),
					     OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd), kJalr});
				Translate(probe);
				Qir q = ScanQir(probe.region);
				if (!q.frames)
					continue;
				CHECK_EQ(q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
				CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
				u32 const lanes = q.bytes / q.sew;
				if (lanes < 2)
					continue;
				u32 const vl = 1u; // only element 0 is active

				// (a) the NaN in the ACTIVE lane 0 -> NV must appear.
				{
					Configure(vlen, true);
					config::rvv_llvm_fcvt_partial_vl = true;
					Built b({Vsetvli(kVT_E32M1),
						 OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd), kJalr});
					Translate(b);
					std::vector<u64> pat(lanes, kBenign);
					pat[0] = kQNaN;
					PartialFold f = FoldPartial(b, VRegOff(kVs2), VRegOff(kVd), pat,
								    lanes, is_signed, rtz, vl);
					CHECK(f.ok);
					CHECK(f.masked_store);
					CHECK(!f.plain_store);
					// THE MASK BASE, checked as the resulting ACTIVE SET: unit `u`
					// covers elements [u*lanes, (u+1)*lanes), so with vl = 1 only
					// unit 0 lane 0 is active and every later unit's mask is empty.
					// A mask built from lane 0 for every unit would make unit 1's
					// lane 0 active too, and that is what this catches.
					CHECK(!f.unit_masks.empty());
					for (size_t u = 0; u < f.unit_masks.size(); ++u) {
						CHECK_EQ(f.unit_masks[u].size(), lanes);
						for (u32 i = 0; i < f.unit_masks[u].size(); ++i) {
							u64 const want =
							    ((u32)u * lanes + i) < vl ? 1u : 0u;
							CHECK_EQ(f.unit_masks[u][i], want);
						}
					}
					if ((f.flags & rvv32::FFLAG_NV) == 0) {
						printf("  FAIL %s vlen=%u: an ACTIVE NaN raised no NV "
						       "(flags=0x%x)\n", ArmName(rtz, is_signed), vlen,
						       f.flags);
						++g_fail;
					}
					++cases;
				}
				// (a2) an INEXACT BUT VALID value in an inactive lane -> NX must NOT
				// appear. The NaN cases above cannot exercise this: a NaN is invalid,
				// so `inexact && !invalid` is false for it whatever the gating does.
				// Only a value that WOULD legitimately raise NX if it were active can
				// tell a gated derivation from an ungated one.
				if (!rtz) {
					Configure(vlen, true);
					config::rvv_llvm_fcvt_partial_vl = true;
					Built b({Vsetvli(kVT_E32M1),
						 OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd), kJalr});
					Translate(b);
					std::vector<u64> pat(lanes, kBenign);
					pat[lanes - 1u] = 0x40200000u; // +2.5 -> inexact when converted
					PartialFold f = FoldPartial(b, VRegOff(kVs2), VRegOff(kVd), pat,
								    lanes, is_signed, rtz, vl);
					CHECK(f.ok);
					if ((f.flags & rvv32::FFLAG_NX) != 0) {
						printf("  FAIL %s vlen=%u: an INACTIVE inexact value "
						       "raised NX (flags=0x%x)\n",
						       ArmName(rtz, is_signed), vlen, f.flags);
						++g_fail;
					}
					++cases;
					// ... and the same value ACTIVE must raise it, so the check
					// above is not passing merely because NX is never derived.
					Configure(vlen, true);
					config::rvv_llvm_fcvt_partial_vl = true;
					Built b2({Vsetvli(kVT_E32M1),
						  OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd), kJalr});
					Translate(b2);
					std::vector<u64> pat2(lanes, kBenign);
					pat2[0] = 0x40200000u;
					PartialFold f2 = FoldPartial(b2, VRegOff(kVs2), VRegOff(kVd),
								     pat2, lanes, is_signed, rtz, vl);
					CHECK(f2.ok);
					if ((f2.flags & rvv32::FFLAG_NX) == 0) {
						printf("  FAIL %s vlen=%u: an ACTIVE inexact value "
						       "raised no NX (flags=0x%x)\n",
						       ArmName(rtz, is_signed), vlen, f2.flags);
						++g_fail;
					}
					++cases;
				}
				// (b) the SAME NaN in an INACTIVE lane -> NV must NOT appear.
				{
					Configure(vlen, true);
					config::rvv_llvm_fcvt_partial_vl = true;
					Built b({Vsetvli(kVT_E32M1),
						 OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd), kJalr});
					Translate(b);
					std::vector<u64> pat(lanes, kBenign);
					pat[lanes - 1u] = kQNaN; // element lanes-1 >= vl = 1
					PartialFold f = FoldPartial(b, VRegOff(kVs2), VRegOff(kVd), pat,
								    lanes, is_signed, rtz, vl);
					CHECK(f.ok);
					if ((f.flags & rvv32::FFLAG_NV) != 0) {
						printf("  FAIL %s vlen=%u: an INACTIVE NaN raised NV "
						       "(flags=0x%x) -- the inactive predicate and the "
						       "invalid-lane neutralisation are conflated\n",
						       ArmName(rtz, is_signed), vlen, f.flags);
						++g_fail;
					}
					++cases;
				}
			}
	printf("       %u active/inactive flag-ownership cases checked\n", cases);
	CHECK(cases > 0);

	// STRUCTURAL PROXY, and it is labelled as one. Whether an inactive lane actually reaches the
	// host rounding/conversion instruction is a HOST FLAG question, and this test folds IR -- it
	// cannot observe MXCSR any more than it can observe OF/UF/NX. What it CAN check is that the
	// suppression condition feeding each of those two operations mentions the active mask at all:
	// a `select` whose condition is an `or` with a `not` of an `icmp` against the live `vl`.
	// Mutations that drop the inactive term from either site are invisible to the value/flag
	// oracle above and visible here, which is exactly why both kinds of check are present.
	printf("[C4FP-b] the rounding and conversion operands are suppressed on INACTIVE lanes too\n");
	unsigned structural = 0;
	for (u32 vlen : {256u, 1024u})
		for (int arm = 0; arm < 2; ++arm) {
			bool const rtz = arm == 1;
			Configure(vlen, true);
			config::rvv_llvm_fcvt_partial_vl = true;
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(rtz, true), kVs2, kVd), kJalr});
			Translate(b);
			if (!ScanQir(b.region).frames)
				continue;
			auto mentions_inactive = [&](llvm::Value *cond) {
				auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(cond);
				if (!bo || bo->getOpcode() != llvm::Instruction::Or)
					return false;
				for (unsigned k = 0; k < 2; ++k) {
					auto *x = bo->getOperand(k);
					// `not(active)` is emitted as `xor(active, true)`.
					auto *xb = llvm::dyn_cast<llvm::BinaryOperator>(x);
					if (xb && xb->getOpcode() == llvm::Instruction::Xor)
						return true;
				}
				return false;
			};
			unsigned convs = 0, rnds = 0, conv_ok = 0, rnd_ok = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii)
						continue;
					auto const id = ii->getIntrinsicID();
					bool const is_conv =
					    id == llvm::Intrinsic::experimental_constrained_fptosi ||
					    id == llvm::Intrinsic::experimental_constrained_fptoui;
					bool const is_rnd =
					    id == llvm::Intrinsic::experimental_constrained_nearbyint;
					if (!is_conv && !is_rnd)
						continue;
					auto *sel = llvm::dyn_cast<llvm::SelectInst>(
					    ii->getArgOperand(0));
					if (is_conv) {
						++convs;
						if (sel && mentions_inactive(sel->getCondition()))
							++conv_ok;
					} else {
						++rnds;
						if (sel && mentions_inactive(sel->getCondition()))
							++rnd_ok;
					}
				}
			CHECK(convs > 0);
			CHECK_EQ(conv_ok, convs);
			if (!rtz) {
				CHECK(rnds > 0);
				CHECK_EQ(rnd_ok, rnds);
			}
			++structural;
		}
	printf("       %u structural suppression cells checked\n", structural);
	CHECK(structural > 0);
}

// [C5FP] THE ARCHITECTURAL MASK, and the reason it is a semantic change rather than an admission
// widening. The destination needs no new code -- an inactive element is simply not stored, and the
// masked store already carried the predicate for partial VL. THE STICKY FLAG DOES: `fcsr`
// accumulates by OR and has no second chance to be corrected, so a NaN sitting in a lane that `v0`
// masks OFF must raise NOTHING. That is the one property this section exists to pin, and it is
// checked the same way the partial-VL section checks it -- by placing the NaN in an inactive lane
// and asserting NV is absent -- with `v0` doing the deactivating instead of `vl`.
void SectionMaskedFloatSource()
{
	printf("[C5FP] architectural mask: an invalid value in a v0-INACTIVE lane raises nothing\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	constexpr u32 kQNaN = 0x7fc00000u, kBenign = 0x40000000u;
	unsigned cases = 0, isolating = 0;
	for (u32 vlen : {256u, 1024u})
		for (int arm = 0; arm < 2; ++arm)
			for (int sgn = 0; sgn < 2; ++sgn) {
				bool const rtz = arm == 1, is_signed = sgn == 1;
				Configure(vlen, /*on=*/true);
				config::rvv_llvm_fp_cvt_masked = true;
				Built probe({Vsetvli(kVT_E32M1),
					     OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd,
						     /*unmasked=*/false),
					     kJalr});
				Translate(probe);
				Qir q = ScanQir(probe.region);
				CHECK(q.frames != 0); // the masked form must be ADMITTED
				u32 const lanes = q.bytes / q.sew;
				if (lanes < 2)
					continue;

				// vl covers EVERY element, so `vl` cannot be what deactivates the
				// lane -- only `v0` can. Without this the section would pass with the
				// architectural mask entirely absent.
				u32 const vl = lanes * (u32)q.units;
				u64 const v0 = ~(u64)1; // element 0 INACTIVE, all others active

				Configure(vlen, true);
				config::rvv_llvm_fp_cvt_masked = true;
				Built b({Vsetvli(kVT_E32M1),
					 OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd,
						 /*unmasked=*/false),
					 kJalr});
				Translate(b);
				std::vector<u64> pat(lanes, kBenign);
				pat[0] = kQNaN; // the NaN is in the ONE lane v0 masks off
				PartialFold f = FoldPartial(b, VRegOff(kVs2), VRegOff(kVd), pat, lanes,
							    is_signed, rtz, vl, v0);
				CHECK(f.ok);
				CHECK(f.masked_store);
				CHECK(!f.plain_store);
				// (a) THE FLAG. An inactive NaN raises nothing.
				CHECK_EQ(f.flags & rvv32::FFLAG_NV, 0u);
				++isolating;
				// (b) THE DESTINATION. The store predicate is `(e < vl) && v0[e]`,
				// and with vl at full width that is exactly v0.
				CHECK(!f.unit_masks.empty());
				for (size_t u = 0; u < f.unit_masks.size(); ++u) {
					CHECK_EQ(f.unit_masks[u].size(), lanes);
					for (u32 i = 0; i < lanes; ++i) {
						u32 const e = (u32)u * lanes + i;
						u64 const want =
						    (e < vl && (v0 & ((u64)1 << e))) ? 1u : 0u;
						CHECK_EQ(f.unit_masks[u][i], want);
					}
				}
				++cases;

				// (c) THE CONTROL, and the section is worth little without it: the SAME
				// NaN in the SAME lane, now ACTIVE in v0, MUST raise NV. Without this a
				// lowering that never raises NV at all would pass (a).
				Configure(vlen, true);
				config::rvv_llvm_fp_cvt_masked = true;
				Built c({Vsetvli(kVT_E32M1),
					 OpVfcvt(SubFor(rtz, is_signed), kVs2, kVd,
						 /*unmasked=*/false),
					 kJalr});
				Translate(c);
				PartialFold g = FoldPartial(c, VRegOff(kVs2), VRegOff(kVd), pat, lanes,
							    is_signed, rtz, vl, ~(u64)0);
				CHECK(g.ok);
				CHECK_EQ(g.flags & rvv32::FFLAG_NV, (u32)rvv32::FFLAG_NV);
			}
	printf("       %u masked cells, %u with the flag isolated by v0 alone\n", cases, isolating);
	CHECK(cases != 0);
}

// [C5FP-R] The masked form must be REFUSED when the switch is off, and when the destination is v0.
void SectionMaskedRefusals()
{
	printf("[C5FP-R] masked refusals: switch off, and vd == v0\n");
	unsigned refused = 0;
	for (u32 vlen : {256u, 1024u}) {
		// (a) switch OFF -> the masked form is not admitted, and the route is INERT.
		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = false;
		Built off({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, kVd,
						       /*unmasked=*/false),
			   kJalr});
		Translate(off);
		CHECK_EQ(ScanQir(off.region).frames, 0u);
		++refused;

		// (b) switch ON but vd == v0 -- RVV 1.0 5.3 forbids it.
		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built v0d({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, /*vd=*/0u,
						       /*unmasked=*/false),
			   kJalr});
		Translate(v0d);
		CHECK_EQ(ScanQir(v0d.region).frames, 0u);
		++refused;

		// (c) THE SOURCE SIDE, which is a DIFFERENT rule from (b) and was found missing by
		// the mutation gate. `vs2 == v0` is refused for a masked instruction by the
		// one-EEW-per-register rule, and it is enforced ONLY by `convert_registers_legal`
		// -- the route's own `rd == 0` check cannot see it. Without this cell, reverting
		// the route to the hardcoded `/*vm=*/true` it used to pass changed nothing that any
		// test could observe.
		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built v0s({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), /*vs2=*/0u, kVd,
						       /*unmasked=*/false),
			   kJalr});
		Translate(v0s);
		CHECK_EQ(ScanQir(v0s.region).frames, 0u);
		++refused;

		// (d) the UNMASKED form must still be admitted with the switch off: this change must
		// not have narrowed the route it extends.
		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = false;
		Built um({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, kVd), kJalr});
		Translate(um);
		CHECK(ScanQir(um.region).frames != 0);
	}
	printf("       %u refusals, and the unmasked form still admitted\n", refused);
	CHECK_EQ(refused, 6u);
}

// [C6FRM] THE FRAME'S ROUNDING-MODE ADMISSION.
//
// The FP conversion frame guarded on `frm == RNE`. The frame's bracket already installs the live
// guest `frm` into MXCSR.RC and every lane operation is a `round.dynamic` constrained intrinsic,
// so RNE/RTZ/RDN/RUP all execute in the mode the guest asked for -- the guard was simply refusing
// three of them. On official ACT4 that cost 1,480 admitted-then-rejected instances across seven
// ELFs, because the official tests sweep rounding modes.
//
// THE ASSERTION THAT MATTERS IS THE ONE ABOUT RMM. Widening this guard is only correct if
// `frm == 4` STILL FALLS BACK: x86 has no round-to-nearest-ties-away mode, and the bracket's
// frm -> MXCSR.RC select maps RMM onto RNE, which is a WRONG RESULT, not a slow one. A lowering
// that simply deleted the rounding test would satisfy every other check in this section and fail
// [b] -- which is the whole reason [b] sweeps all eight encodings rather than just the four.
void SectionDynamicFrmGuard()
{
	printf("[C6FRM] the conversion frame admits frm <= RUP, and STILL refuses RMM\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	u32 const vlenb_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vlenb));
	u32 const vtype_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vtype));
	u32 const vl_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
	u32 const vstart_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));

	// Fold the guard with every state value matching and `frm` set to `frm_val`; report which
	// arm the conditional branch resolves to. Returns 1 fast, 0 fallback, -1 did not fold.
	auto arm_taken = [&](Built &b, u32 vlen, u32 vtype, u32 vlmax, u32 frm_val) -> int {
		llvm::Value *state = b.fn->getArg(0);
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
				if (!l)
					continue;
				u32 const o = StateOffset(l->getPointerOperand(), state);
				u64 v;
				if (o == vlenb_off) v = vlen / 8u;
				else if (o == vtype_off) v = vtype;
				else if (o == vl_off) v = vlmax;
				else if (o == vstart_off) v = 0;
				else if (o == fcsr_off) v = (u64)frm_val << 5;
				else continue;
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), v));
			}
		FoldToFixpoint(b.fn);
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *br = llvm::dyn_cast<llvm::BranchInst>(&ins);
				if (!br || !br->isConditional())
					continue;
				auto *c = llvm::dyn_cast<llvm::ConstantInt>(br->getCondition());
				if (!c)
					continue;
				llvm::BasicBlock *t = br->getSuccessor(c->isOne() ? 0 : 1);
				if (t->getName().starts_with("rvv.tchunk.direct"))
					return 1;
				if (t->getName().starts_with("rvv.tchunk.fallback"))
					return 0;
			}
		return -1;
	};

	unsigned checked = 0, rmm_refused = 0;
	for (u32 vlen : {256u, 1024u})
		for (int partial = 0; partial < 2; ++partial) {
			// (a) THE KIND ITSELF. Off must be byte-for-byte the old behaviour.
			Configure(vlen, /*on=*/true);
			config::rvv_llvm_fcvt_partial_vl = partial != 0;
			config::rvv_llvm_fp_dynamic_frm = false;
			Built off({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, kVd), kJalr});
			Translate(off);
			Qir qo = ScanQir(off.region);
			if (!qo.frames)
				continue;
			CHECK_EQ(qo.guard_kind, (int)(partial ? GK::VTypePartialVlVstartFrmRNE
							      : GK::VTypeVlVstartFrmRNE));

			Configure(vlen, /*on=*/true);
			config::rvv_llvm_fcvt_partial_vl = partial != 0;
			config::rvv_llvm_fp_dynamic_frm = true;
			Built on({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, kVd), kJalr});
			Translate(on);
			Qir qn = ScanQir(on.region);
			CHECK(qn.frames != 0);
			CHECK_EQ(qn.guard_kind, (int)(partial ? GK::VTypePartialVlVstartFrmHostRound
							      : GK::VTypeVlVstartFrmHostRound));

			// (b) THE ADMITTED SET, one rebuild per encoding because folding consumes it.
			for (u32 frm = 0; frm < 8; ++frm) {
				Configure(vlen, /*on=*/true);
				config::rvv_llvm_fcvt_partial_vl = partial != 0;
				config::rvv_llvm_fp_dynamic_frm = true;
				Built b({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, kVd),
					 kJalr});
				Translate(b);
				Qir q = ScanQir(b.region);
				if (!q.frames)
					continue;
				int const got = arm_taken(b, vlen, q.vtype, q.vlmax, frm);
				// RNE(0) RTZ(1) RDN(2) RUP(3) are the four MXCSR can express.
				int const want = frm <= 3u ? 1 : 0;
				if (got != want) {
					printf("  FAIL vlen=%u partial=%d frm=%u: arm=%d want=%d\n",
					       vlen, partial, frm, got, want);
					++g_fail;
				}
				if (frm == 4u && got == 0)
					++rmm_refused; // the RMM refusal, counted explicitly
				++checked;
			}

			// (c) THE OLD KIND IS UNMOVED: with the switch off, only RNE is admitted.
			for (u32 frm : {0u, 1u, 3u}) {
				Configure(vlen, /*on=*/true);
				config::rvv_llvm_fcvt_partial_vl = partial != 0;
				config::rvv_llvm_fp_dynamic_frm = false;
				Built b({Vsetvli(kVT_E32M1), OpVfcvt(SubFor(false, true), kVs2, kVd),
					 kJalr});
				Translate(b);
				Qir q = ScanQir(b.region);
				if (!q.frames)
					continue;
				int const got = arm_taken(b, vlen, q.vtype, q.vlmax, frm);
				int const want = frm == 0u ? 1 : 0;
				if (got != want) {
					printf("  FAIL switch-off vlen=%u frm=%u: arm=%d want=%d\n",
					       vlen, frm, got, want);
					++g_fail;
				}
			}
		}
	printf("       %u frm encodings resolved, %u of them the RMM refusal\n", checked,
	       rmm_refused);
	CHECK(checked != 0);
	CHECK(rmm_refused != 0); // a vacuous RMM check would defeat the section's purpose
}

void SectionRefusals()
{
	printf("[C4FI-5] widening, narrowing and masked forms keep the helper\n");
	struct R { char const *name; u32 sub; bool unmasked; };
	R const rows[] = {
	    {"vfwcvt.rtz.x.f.v (widening, sub 15)", 15u, true},
	    {"vfncvt.rtz.x.f.w (narrowing, sub 23)", 23u, true},
	    {"vfcvt.rtz.x.f.v MASKED", kSubRtzX, false},
	};
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			Configure(vlen, /*on=*/true);
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(r.sub, kVs2, kVd, r.unmasked), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (q.units != 0) {
				printf("  FAIL %s was admitted at vlen=%u; this route is rtz "
				       "same-width unmasked only\n", r.name, vlen);
				++g_fail;
			}
			CHECK(q.hcalls > 0u);
		}
}

void SectionOffIsInert()
{
	printf("[C4FI-6] switch off: no frame, the instruction reaches the helper\n");
	for (u32 vlen : {256u, 1024u})
		for (u32 sub : {kSubRtzX, kSubRtzXu}) {
			Configure(vlen, /*on=*/false);
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			CHECK_EQ(q.units, 0u);
			CHECK(q.hcalls > 0u);
		}
}

void DumpIR()
{
	char const *path = getenv("C4FI_DUMP_IR");
	if (!path)
		return;
	if (char const *wp = getenv("C4FIW_DUMP_IR")) {
		Configure(1024u, false);
		config::rvv_llvm_fcvt_ftoi_widen = true;
		Built wb({Vsetvli(kVT_E32M1), OpVfcvt(kSubWRtzX, kVs2, kVd), kJalr});
		Translate(wb);
		std::error_code wec;
		llvm::raw_fd_ostream wos(wp, wec);
		if (!wec)
			wb.module.print(wos, nullptr);
		printf("  (widening IR dumped to %s)\n", wp);
	}
	// The frm arm at e32/VLEN 1024: the dump then shows the rounding step, both neutralisations
	// and the derived NV|NX, which is the shape that differs from the rtz arm.
	Configure(1024u, true);
	Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubFrmX, kVs2, kVd), kJalr});
	Translate(b);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

} // namespace

int main()
{
	printf("rvv_llvm_fcvt_ftoi_test\n");
	SectionShapeAndNeutralisation();
	SectionOracle();
	SectionPerLaneFlags();
	SectionWiden();
	SectionPartialVlFloatSource();
	SectionDynamicFrmGuard();
	SectionMaskedFloatSource();
	SectionMaskedRefusals();
	SectionRefusals();
	SectionOffIsInert();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
