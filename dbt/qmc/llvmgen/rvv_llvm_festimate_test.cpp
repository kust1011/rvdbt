// ORDER ITEM 4 (2026-09-19): THE 7-BIT ESTIMATES `vfrsqrt7.v` / `vfrec7.v` ON THE LLVM ARM.
//
// WHY A DIFFERENTIAL AND NOT A STRUCTURAL CHECK. These are not IEEE operations: RVV 1.0 specifies
// them by an EXACT 128-entry lookup table, so a transcription error in the table, an index built
// from six bits instead of seven, a normalisation off by one, or a special-value arm in the wrong
// order all produce IR of exactly the right SHAPE with the wrong VALUES. The only instrument that
// sees those is a comparison against the reference itself. `rvv_ref::vfrsqrt7_elem` and
// `vfrec7_elem` are the functions the helper arm calls, so folding the emitted unit to constants
// and comparing it to them, element by element and flag by flag, is the check.
//
// SECTIONS:
//   [E1] Admission, frame shape and inertness: one `_vchunkfestimate` per unit, guard kind
//        `VTypeIntegerNoRestart` (so `vstart == 0` is the GUARD's, which this body needs because it
//        has no prestart term), nothing at all with the switch off.
//   [E2] NO FP MACHINERY: zero constrained intrinsics and zero `x86_sse_{ld,st}mxcsr`. This is the
//        assertion behind "an OPFVV instruction can be an integer body" -- and it is the one that
//        would fail if the route had been written by copying the `vfsqrt` arm, which is exactly the
//        mistake the plan's withdrawn framing was heading towards.
//   [E3] THE DIFFERENTIAL, both instructions, SEW 32 and 64, with the pattern window ROTATED so
//        every crafted pattern reaches a lane at every width (the `vfclass` test records that its
//        first version silently never classified two of its patterns).
//   [E4] `vfrec7` AT EVERY ROUNDING MODE. Its subnormal-overflow arm is the one place an estimate
//        depends on `frm`, and the body reads it from `fcsr` rather than pinning it at the guard.
//        A test at RNE alone would never exercise the `to_inf` select.
//   [E5] A pseudo-random sweep, same differential.
//   [E6] The emitted table is compared byte for byte against the reference's own array -- an
//        independent check of the one thing [E3] could in principle agree with for the wrong
//        reason, if both the emitter and the oracle read a table this file had copied.
//   [E7] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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

llvm::LLVMContext &g_ctx = dbt::qir::g_llvm_ctx;

// VFUNARY1 (funct6 19), OPFVV (funct3 1). sub 4 = vfrsqrt7.v, 5 = vfrec7.v.
constexpr u32 OpVfest(u32 sub, u32 vs2, u32 vd, bool unmasked = true)
{
	return (19u << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) | (1u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVs2 = 8u, kVd = 10u;
constexpr u32 kSubRsqrt = 4u, kSubRec = 5u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4est", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_festimate = on;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_llvm_masked = false;
	config::rvv_llvm_restart = false;
	// C5-MASK-FP, reset so one section cannot leak a masked admission into the next.
	config::rvv_llvm_fp_cvt_masked = false;
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

struct Qir {
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0;
	int guard_kind = -1;
	std::vector<u32> bases;
	bool sqrt_flag = false;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vchunkfestimate) {
				auto *n = static_cast<InstVChunkFEstimate *>(&ins);
				++q.nodes;
				q.bases.push_back(n->base);
				q.finishes += n->finish;
				q.sqrt_flag = n->sqrt;
			} else if (ins.GetOpcode() == Op::_hcall) {
				++q.hcalls;
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

constexpr u32 kVregOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
constexpr u32 kFcsrOff = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
u32 VRegOff(u32 r) { return kVregOff + r * rvv32::VLEN_MAX_BYTES; }

struct Folded {
	bool ok = false;
	std::vector<u64> lanes;
	u32 fflags = 0;
	// C5-MASK-FP: the store's PREDICATE, not just its value. The value alone cannot show which
	// elements were actually published, which is half of what an architectural mask decides.
	std::vector<u64> store_mask;
};

// Replace the unit's source load and every `fcsr` load with constants, fold, and read back the
// published lane values and the flag word.
// `v0_bits` is the ARCHITECTURAL MASK, one bit per ELEMENT. It defaults to all-active, and an
// unmasked instruction emits no v0 load at all, so every pre-existing caller is unaffected.
Folded FoldUnit(Built &b, u32 sew, u32 lanes, std::vector<u64> const &pattern, u32 frm,
		u64 v0_bits = ~(u64)0)
{
	Folded out;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	auto const &DL = fn->getParent()->getDataLayout();
	u32 const fcsr_in = (frm & 7u) << 5;
	u32 const vl_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
	// PIN `vec.vl` TO VLMAX. The published lane values do not depend on it, but the FLAG
	// reduction does -- every predicate is ANDed with the active mask before it is reduced -- so
	// without this the flag word stays symbolic and the fflags comparison silently reads 0. That
	// is what the first run of this file did: every lane value matched and every flag cell failed.
	u32 const vlmax = config::vlen_bits / (8u * sew);

	llvm::LoadInst *src = nullptr;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o == vl_off) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vlmax));
				continue;
			}
			if (o == kFcsrOff) {
				// BOTH `fcsr` reads are pinned: the `frm` extraction in the `vfrec7`
				// arm, and the accumulate-and-store read. Pinning the second one to a
				// known value is what lets the stored word be read as `frm | fflags`.
				l->replaceAllUsesWith(
				    llvm::ConstantInt::get(l->getType(), fcsr_in));
				continue;
			}
			// THE ARCHITECTURAL MASK. `RvvArchMaskForUnit` loads v0 as a 16-bit group
			// at `vreg_base + element_base/8`, so the i16 at byte `k` carries elements
			// [k*8, k*8+16). Served per-window rather than as one constant so a unit
			// that read the WRONG window cannot pass.
			if (l->getType()->isIntegerTy(16)) {
				u32 const v0b = VRegOff(0);
				if (o != ~0u && o >= v0b && o < v0b + rvv32::VLEN_MAX_BYTES) {
					u32 const first = (o - v0b) * 8u;
					u16 w = 0;
					for (u32 i = 0; i < 16u && first + i < 64u; ++i)
						if (v0_bits & ((u64)1 << (first + i)))
							w |= (u16)(1u << i);
					l->replaceAllUsesWith(
					    llvm::ConstantInt::get(l->getType(), w));
					continue;
				}
			}
			if (src)
				continue;
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || vt->getNumElements() != lanes ||
			    vt->getScalarSizeInBits() != 8u * sew)
				continue;
			if (o != VRegOff(kVs2))
				continue;
			src = l;
		}
	if (!src)
		return out;
	auto *ety = llvm::cast<llvm::FixedVectorType>(src->getType())->getElementType();
	llvm::SmallVector<llvm::Constant *, 64> cv;
	for (u32 i = 0; i < lanes; ++i)
		cv.push_back(llvm::ConstantInt::get(ety, pattern[i % pattern.size()]));
	src->replaceAllUsesWith(llvm::ConstantVector::get(cv));

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
					continue;
				}
				// `bitcast <N x i1> to iN` is not folded by LLVM (the element type is
				// not byte-sized), and the flag reduction is built on exactly that.
				auto *bc = llvm::dyn_cast<llvm::BitCastInst>(&I);
				if (!bc || !bc->getType()->isIntegerTy())
					continue;
				auto *st = llvm::dyn_cast<llvm::FixedVectorType>(
				    bc->getOperand(0)->getType());
				if (!st || !st->getElementType()->isIntegerTy(1))
					continue;
				auto *c0 = llvm::dyn_cast<llvm::Constant>(bc->getOperand(0));
				if (!c0)
					continue;
				llvm::APInt acc(st->getNumElements(), 0);
				bool all = true;
				for (unsigned k = 0; k < st->getNumElements(); ++k) {
					auto *el = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    c0->getAggregateElement(k));
					if (!el) { all = false; break; }
					if (el->isOne())
						acc.setBit(k);
				}
				if (!all)
					continue;
				bc->replaceAllUsesWith(llvm::ConstantInt::get(bc->getType(), acc));
				again = true;
			}
	}

	llvm::Constant *pub = nullptr;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store)
					if (StateOffset(ii->getArgOperand(1), state) == VRegOff(kVd)) {
						pub = llvm::dyn_cast<llvm::Constant>(
						    ii->getArgOperand(0));
						if (auto *mk = llvm::dyn_cast<llvm::Constant>(
							testcompat::MaskedStoreMask(ii)))
							for (u32 i = 0; i < lanes; ++i)
								if (auto *b1 = llvm::dyn_cast_or_null<
									llvm::ConstantInt>(
									mk->getAggregateElement(i)))
									out.store_mask.push_back(
									    b1->getZExtValue());
					}
			auto *st2 = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st2 || StateOffset(st2->getPointerOperand(), state) != kFcsrOff)
				continue;
			if (auto *c = llvm::dyn_cast<llvm::ConstantInt>(st2->getValueOperand()))
				out.fflags |= (u32)c->getZExtValue() & 0x1fu;
		}
	if (!pub)
		return out;
	for (u32 i = 0; i < lanes; ++i) {
		auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(pub->getAggregateElement(i));
		if (!ci)
			return out;
		out.lanes.push_back(ci->getZExtValue());
	}
	out.ok = true;
	return out;
}

// THE REFERENCE. These are the functions `rvv_lower::vfunary1` calls for these two sub-encodings.
u64 RefElem(bool sqrt, u64 bits, u32 sew, u32 frm, u32 *fl)
{
	rvv32::FPUState fs{};
	fs.set_frm(frm);
	u64 const r = sqrt ? rvv32::rvv_ref::vfrsqrt7_elem(fs, bits, sew)
			   : rvv32::rvv_ref::vfrec7_elem(fs, bits, sew, frm);
	if (fl)
		*fl |= fs.fflags();
	return r;
}

struct Pat { char const *name; u32 p32; u64 p64; };
Pat const kPats[] = {
    {"+0", 0x00000000u, 0x0000000000000000ull},
    {"-0", 0x80000000u, 0x8000000000000000ull},
    {"+1.0", 0x3f800000u, 0x3ff0000000000000ull},
    {"-1.0", 0xbf800000u, 0xbff0000000000000ull},
    {"+2.0", 0x40000000u, 0x4000000000000000ull},
    {"+0.5", 0x3f000000u, 0x3fe0000000000000ull},
    {"+min normal", 0x00800000u, 0x0010000000000000ull},
    {"-min normal", 0x80800000u, 0x8010000000000000ull},
    {"+max normal", 0x7f7fffffu, 0x7fefffffffffffffull},
    {"+max subnormal", 0x007fffffu, 0x000fffffffffffffull},
    {"-max subnormal", 0x807fffffu, 0x800fffffffffffffull},
    // The two subnormal shapes `vfrec7` distinguishes: `lead == 0` (top bit set), `lead == 1`, and
    // `lead > 1` (the overflow arm). A test without all three never reaches `to_inf`.
    {"sub lead=0", 0x00400000u, 0x0008000000000000ull},
    {"sub lead=1", 0x00200000u, 0x0004000000000000ull},
    {"sub lead=2", 0x00100000u, 0x0002000000000000ull},
    {"-sub lead=2", 0x80100000u, 0x8002000000000000ull},
    {"+min subnormal", 0x00000001u, 0x0000000000000001ull},
    {"-min subnormal", 0x80000001u, 0x8000000000000001ull},
    {"+inf", 0x7f800000u, 0x7ff0000000000000ull},
    {"-inf", 0xff800000u, 0xfff0000000000000ull},
    {"qNaN", 0x7fc00000u, 0x7ff8000000000000ull},
    {"sNaN", 0x7f800001u, 0x7ff0000000000001ull},
    {"-sNaN", 0xff800001u, 0xfff0000000000001ull},
    {"-qNaN", 0xffc00000u, 0xfff8000000000000ull},
};
constexpr size_t kNPats = sizeof(kPats) / sizeof(kPats[0]);

void SectionAdmission()
{
	printf("[E1] admission, frame shape and inertness\n");
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1})
			for (u32 sub : {kSubRsqrt, kSubRec}) {
				Configure(vlen, true);
				Built b({Vsetvli(vt), OpVfest(sub, kVs2, kVd), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind,
					 (int)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
				CHECK_EQ(q.finishes, 1u); // exactly one unit clears vstart
				CHECK_EQ((int)q.sqrt_flag, (int)(sub == kSubRsqrt));
				// Unit bases ascend from 0 by the unit's own element count.
				u32 const sew = vt == kVT_E64M1 ? 8u : 4u;
				u32 const bytes = std::min(vlen / 8u, 64u);
				for (u32 c = 0; c < q.bases.size(); ++c)
					CHECK_EQ(q.bases[c], c * (bytes / sew));
				Configure(vlen, false);
				Built o({Vsetvli(vt), OpVfest(sub, kVs2, kVd), kJalr});
				Translate(o);
				Qir const qo = ScanQir(o.region);
				CHECK_EQ(qo.nodes, 0u);
				CHECK(qo.hcalls >= 1u);
			}
	printf("       %u admitted route/width/SEW cells\n", admitted);
	CHECK(admitted > 0);
}

void SectionNoFpMachinery()
{
	printf("[E2] no constrained intrinsic and no MXCSR bracket anywhere in the module\n");
	for (u32 vlen : {256u, 1024u})
		for (u32 sub : {kSubRsqrt, kSubRec}) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpVfest(sub, kVs2, kVd), kJalr});
			Translate(b);
			if (!b.fn || !ScanQir(b.region).nodes)
				continue;
			unsigned bad = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb)
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						llvm::StringRef n = llvm::Intrinsic::getBaseName(
						    ii->getIntrinsicID());
						if (n.contains("experimental.constrained") ||
						    n.contains("x86.sse.ldmxcsr") ||
						    n.contains("x86.sse.stmxcsr"))
							++bad;
					}
			CHECK_EQ(bad, 0u);
		}
}

// The shared differential: rotate the pattern window so every pattern reaches a lane.
// `single >= 0` fills EVERY lane with one pattern. That mode exists because the flag word is a
// per-UNIT OR: with a mixed unit, a flag raised for the wrong lane is invisible whenever any other
// lane in the same unit raises it too. A mutation that moved `vfrsqrt7`'s NV from -inf to +inf
// survived this file until this mode was added, for exactly that reason.
void Differential(char const *label, bool sqrt, u32 frm, std::vector<u64> const *sweep,
		  unsigned *cells, bool *seen, int single = -1)
{
	size_t const n = sweep ? sweep->size() : kNPats;
	for (u32 vlen : {256u, 1024u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
			u32 const sew = vt == kVT_E64M1 ? 8u : 4u;
			u32 const bytes = std::min(vlen / 8u, 64u);
			u32 const lanes = bytes / sew;
			for (size_t start = 0; start < (single >= 0 ? 1u : n); start += lanes) {
				Configure(vlen, true);
				Built b({Vsetvli(vt),
					 OpVfest(sqrt ? kSubRsqrt : kSubRec, kVs2, kVd), kJalr});
				Translate(b);
				if (!ScanQir(b.region).nodes)
					break;
				std::vector<u64> pattern;
				std::vector<size_t> which;
				for (u32 i = 0; i < lanes; ++i) {
					size_t const k =
					    single >= 0 ? (size_t)single : (start + i) % n;
					which.push_back(k);
					pattern.push_back(sweep ? (*sweep)[k]
								: (sew == 4 ? (u64)kPats[k].p32
									    : kPats[k].p64));
				}
				Folded const f = FoldUnit(b, sew, lanes, pattern, frm);
				if (!f.ok) {
					printf("  FAIL %s vlen=%u sew=%u start=%zu: the unit did not "
					       "fold to constants\n", label, vlen, sew, start);
					++g_fail;
					continue;
				}
				u32 want_fl = 0;
				for (u32 i = 0; i < lanes; ++i) {
					u64 const in = pattern[i];
					u64 const want = RefElem(sqrt, in, sew, frm, &want_fl);
					if (f.lanes[i] != want) {
						printf("  FAIL %s vlen=%u sew=%u lane %u in=0x%llx: "
						       "emitted 0x%llx, reference 0x%llx\n",
						       label, vlen, sew, i,
						       (unsigned long long)in,
						       (unsigned long long)f.lanes[i],
						       (unsigned long long)want);
						++g_fail;
					}
					if (seen && !sweep)
						seen[which[i]] = true;
					++*cells;
				}
				if ((f.fflags & 0x1fu) != (want_fl & 0x1fu)) {
					printf("  FAIL %s vlen=%u sew=%u start=%zu: fflags 0x%x, "
					       "reference 0x%x\n", label, vlen, sew, start,
					       f.fflags & 0x1fu, want_fl & 0x1fu);
					++g_fail;
				}
			}
		}
}

void SectionOracle()
{
	printf("[E3] differential vs vfrsqrt7_elem / vfrec7_elem, SEW 32 and 64\n");
	unsigned cells = 0;
	bool seen_s[kNPats] = {}, seen_r[kNPats] = {};
	Differential("vfrsqrt7", true, rvv32::FRM_RNE, nullptr, &cells, seen_s);
	Differential("vfrec7", false, rvv32::FRM_RNE, nullptr, &cells, seen_r);
	// EVERY PATTERN MUST HAVE REACHED A LANE, or the rotation silently skipped it.
	for (size_t k = 0; k < kNPats; ++k) {
		if (!seen_s[k]) {
			printf("  FAIL pattern '%s' never reached a vfrsqrt7 lane\n", kPats[k].name);
			++g_fail;
		}
		if (!seen_r[k]) {
			printf("  FAIL pattern '%s' never reached a vfrec7 lane\n", kPats[k].name);
			++g_fail;
		}
	}
	printf("       %u elements compared against the reference\n", cells);
	CHECK(cells > 0);
}

void SectionRoundingModes()
{
	printf("[E4] vfrec7 at every rounding mode -- its subnormal-overflow arm reads frm\n");
	unsigned cells = 0;
	for (u32 frm : {rvv32::FRM_RNE, rvv32::FRM_RTZ, rvv32::FRM_RDN, rvv32::FRM_RUP,
			rvv32::FRM_RMM})
		Differential("vfrec7/frm", false, frm, nullptr, &cells, nullptr);
	printf("       %u elements compared across 5 rounding modes\n", cells);
	CHECK(cells > 0);
}

void SectionSweep()
{
	printf("[E5] pseudo-random sweep, same differential\n");
	unsigned cells = 0;
	u64 x = 0x9E3779B97F4A7C15ull;
	for (unsigned round = 0; round < 40; ++round) {
		std::vector<u64> pat;
		for (unsigned i = 0; i < 32; ++i) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			pat.push_back(x);
		}
		Differential("sweep", round & 1, rvv32::FRM_RNE, &pat, &cells, nullptr);
	}
	printf("       %u elements compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [E8] ONE PATTERN PER UNIT, so the flag word is attributable to a single operand value.
void SectionPerValueFlags()
{
	printf("[E8] per-VALUE flags: every lane of the unit holds the same operand\n");
	unsigned cells = 0;
	for (size_t k = 0; k < kNPats; ++k) {
		Differential("vfrsqrt7/one", true, rvv32::FRM_RNE, nullptr, &cells, nullptr, (int)k);
		for (u32 frm : {rvv32::FRM_RNE, rvv32::FRM_RTZ, rvv32::FRM_RDN, rvv32::FRM_RUP,
				rvv32::FRM_RMM})
			Differential("vfrec7/one", false, frm, nullptr, &cells, nullptr, (int)k);
	}
	printf("       %u elements compared with a single-value unit\n", cells);
	CHECK(cells > 0);
}

void SectionTable()
{
	printf("[E6] the emitted table equals the reference table, entry for entry\n");
	for (u32 sub : {kSubRsqrt, kSubRec}) {
		Configure(512u, true);
		Built b({Vsetvli(kVT_E32M1), OpVfest(sub, kVs2, kVd), kJalr});
		Translate(b);
		if (!ScanQir(b.region).nodes) { CHECK(false); continue; }
		u8 const *ref = sub == kSubRsqrt ? rvv32::rvv_ref::VFRSQRT7_TAB
						 : rvv32::rvv_ref::VFREC7_TAB;
		unsigned found = 0;
		for (auto &gv : b.module.globals()) {
			if (!gv.isConstant() || !gv.hasInitializer())
				continue;
			auto *cda = llvm::dyn_cast<llvm::ConstantDataArray>(gv.getInitializer());
			if (!cda || cda->getNumElements() != 128 ||
			    cda->getElementByteSize() != 1)
				continue;
			++found;
			for (unsigned k = 0; k < 128; ++k)
				if ((u8)cda->getElementAsInteger(k) != ref[k]) {
					printf("  FAIL sub=%u table[%u] = %u, reference %u\n", sub,
					       k, (unsigned)cda->getElementAsInteger(k),
					       (unsigned)ref[k]);
					++g_fail;
				}
		}
		// EXACTLY ONE table per module: two would mean the other instruction's table had
		// been emitted as well, i.e. the selector is not doing its job.
		CHECK_EQ(found, 1u);
	}
}

// [E9] THE ARCHITECTURAL MASK. `vfrsqrt7` of a NEGATIVE raises NV, which makes this family able to
// state the mask's real obligation: a negative sitting in a lane `v0` masks OFF must raise NOTHING.
// `vl` is pinned to VLMAX by `FoldUnit`, so `v0` is the ONLY thing that can deactivate the lane --
// a section that leaned on a short `vl` would pass with the architectural mask entirely absent.
void SectionMaskedArchMask()
{
	printf("[E9] architectural mask: a negative in a v0-INACTIVE lane raises no NV\n");
	constexpr u32 kNegOne = 0xbf800000u, kPosOne = 0x3f800000u;
	unsigned cells = 0;
	for (u32 vlen : {256u, 512u}) {
		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built probe({Vsetvli(kVT_E32M1), OpVfest(kSubRsqrt, kVs2, kVd, /*unmasked=*/false),
			     kJalr});
		Translate(probe);
		CHECK(ScanQir(probe.region).nodes != 0); // the masked form must be ADMITTED
		u32 const lanes = vlen / 32u > 16u ? 16u : vlen / 32u;
		if (lanes < 2)
			continue;
		std::vector<u64> pat(lanes, kPosOne);
		pat[0] = kNegOne; // the ONE lane v0 will mask off

		// (a) lane 0 INACTIVE -> its NV must not appear.
		Configure(vlen, true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built a({Vsetvli(kVT_E32M1), OpVfest(kSubRsqrt, kVs2, kVd, /*unmasked=*/false),
			 kJalr});
		Translate(a);
		Folded fa = FoldUnit(a, 4u, lanes, pat, rvv32::FRM_RNE, ~(u64)1);
		CHECK(fa.ok);
		CHECK_EQ(fa.fflags & 0x10u, 0u); // NV is bit 4
		// the store predicate is v0 itself, vl being VLMAX
		CHECK_EQ(fa.store_mask.size(), lanes);
		for (u32 i = 0; i < lanes; ++i)
			CHECK_EQ(fa.store_mask[i], i == 0 ? 0u : 1u);
		++cells;

		// (b) THE CONTROL. Same value, same lane, now ACTIVE -> NV MUST appear. Without
		// this a lowering that never raises NV at all would satisfy (a).
		Configure(vlen, true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built c({Vsetvli(kVT_E32M1), OpVfest(kSubRsqrt, kVs2, kVd, /*unmasked=*/false),
			 kJalr});
		Translate(c);
		Folded fc = FoldUnit(c, 4u, lanes, pat, rvv32::FRM_RNE, ~(u64)0);
		CHECK(fc.ok);
		CHECK_EQ(fc.fflags & 0x10u, 0x10u);

		// (c) REFUSALS: the switch off, and vd == v0.
		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = false;
		Built off({Vsetvli(kVT_E32M1), OpVfest(kSubRsqrt, kVs2, kVd, /*unmasked=*/false),
			   kJalr});
		Translate(off);
		CHECK_EQ(ScanQir(off.region).nodes, 0u);

		Configure(vlen, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built v0d({Vsetvli(kVT_E32M1), OpVfest(kSubRsqrt, kVs2, /*vd=*/0u,
						       /*unmasked=*/false),
			   kJalr});
		Translate(v0d);
		CHECK_EQ(ScanQir(v0d.region).nodes, 0u);
	}
	printf("       %u masked cells, each with its NV-must-appear control\n", cells);
	CHECK(cells != 0);
}

void SectionVerify()
{
	printf("[E7] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1})
			for (u32 sub : {kSubRsqrt, kSubRec}) {
				Configure(vlen, true);
				Built b({Vsetvli(vt), OpVfest(sub, kVs2, kVd), kJalr});
				Translate(b);
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL vlen=%u vt=%u sub=%u: %s\n", vlen, vt, sub,
					       err.c_str());
					++g_fail;
				}
			}
}

} // namespace

int main()
{
	printf("rvv_llvm_festimate_test: order item 4, vfrsqrt7.v / vfrec7.v in integer IR\n");
	SectionAdmission();
	SectionNoFpMachinery();
	SectionOracle();
	SectionRoundingModes();
	SectionSweep();
	SectionPerValueFlags();
	SectionTable();
	SectionMaskedArchMask();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
