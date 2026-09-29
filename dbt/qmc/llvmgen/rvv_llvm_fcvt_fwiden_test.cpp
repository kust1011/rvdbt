// C4 (2026-09-19). WIDENING FLOAT -> FLOAT ON THE LLVM ARM: `vfwcvt.f.f.v` (f32 -> f64).
//
// THE ASSERTION THIS FILE EXISTS FOR is that a bare `fpext` is not a correct lowering. "Widening a
// finite float is exact" is true and is not the contract. `softfp::cvt_fmt` (rv32_softfp.h:443):
//
//     sNaN -> NV, result = the TARGET format's CANONICAL quiet NaN
//     qNaN -> no flag, result = ALSO the canonical quiet NaN (the payload is NOT carried across)
//
// while x86's `vcvtps2pd` quiets a signalling NaN while PRESERVING its payload and passes a quiet
// NaN through unchanged. So every NaN input is a wrong-bits case for `fpext` alone, and a
// payload-carrying NaN is exactly what a structural check would not notice.
//
// The oracle is therefore a VALUE oracle against `cvt_fmt`, run over inputs that include NaNs with
// distinctive payloads in both quiet and signalling flavours -- a canonical-NaN result and a
// payload-preserved result have the same shape and differ only in bits.
//
// NV is DERIVED by the route (an integer bit test for "NaN and quiet bit clear"), so it folds to a
// constant and is checkable here per isolated lane, which is what makes the sNaN-vs-qNaN
// distinction testable without observing host MXCSR.
//
// Every emitted module is checked with `verifyModule` and a forced type walk, in `g_llvm_ctx`.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_softfp.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

llvm::LLVMContext &g_ctx = g_llvm_ctx;

constexpr u32 OpVfcvt(u32 sub, u32 vs2, u32 vd, bool unmasked = true)
{
	return (18u << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) | (1u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;
// `vfwcvt` doubles the destination EMUL, so vd must be an even register at LMUL 1 and must not
// overlap the source in a way RVV forbids.
constexpr u32 kVd = 10u, kVs2 = 8u;
constexpr u32 kSubWidenFF = 12u; // widening block (8) + kind 4 (f.f)

u32 VRegOff(u32 reg) { return (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg) +
				   reg * rvv32::VLEN_MAX_BYTES); }

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c4fw", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	// BOTH direction flags are reset here. They were not, and the narrowing sections' setting
	// leaked into the widening refusal rows, which then reported `vfncvt.f.f.w` as wrongly
	// admitted by the WIDENING route. A per-test knob that one section sets and another never
	// clears is a false result waiting to happen.
	config::rvv_llvm_fcvt_fwiden = on;
	config::rvv_llvm_fcvt_fnarrow = false;
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
	llvm::raw_null_ostream null_os;
	b.module.print(null_os, nullptr);
}

struct Qir {
	unsigned frames = 0, units = 0, hcalls = 0, brackets = 0;
	int guard_kind = -1;
	unsigned sew = 0, bytes = 0;
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
				break;
			case Op::_vchunkftof: {
				auto *n = static_cast<InstVChunkFToF *>(&ins);
				++q.units;
				q.sew = n->sew;
				q.bytes = n->bytes;
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

struct Folded {
	bool ok = false;
	std::vector<u64> lanes;
	u32 flags = 0;
};

// The bits x86 `vcvtps2pd` would produce: a plain IEEE widening, quieting a signalling NaN and
// PRESERVING its payload. That is deliberately NOT the architectural answer -- it is what the
// hardware does, and substituting it here is what lets the oracle prove the route corrects it.
u64 HostWiden(u32 b)
{
	u32 const absb = b & 0x7fffffffu;
	if (absb > 0x7f800000u) { // NaN: quiet it, carry the payload into the f64 significand
		u64 const sign = (u64)(b >> 31) << 63;
		u64 const payload = (u64)(b & 0x007fffffu) << 29;
		return sign | 0x7ff0000000000000ull | (1ull << 51) | payload;
	}
	float f;
	std::memcpy(&f, &b, 4);
	double const d = (double)f;
	u64 out;
	std::memcpy(&out, &d, 8);
	return out;
}

Folded FoldUnit(Built &b, u32 rs_off, u32 rd_off, std::vector<u32> const &pattern, u32 lanes)
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
			if (!vt || vt->getNumElements() != lanes ||
			    !vt->getElementType()->isFloatTy())
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
		    llvm::APFloat(llvm::APFloat::IEEEsingle(), llvm::APInt(32, pattern[i % pattern.size()]))));
	src->replaceAllUsesWith(llvm::ConstantVector::get(in));
	FoldToFixpoint(fn);

	// `constrained.fpext` cannot fold; substitute what the HOST would produce, so that anything
	// the route does to correct it is what the comparison then measures.
	llvm::IntrinsicInst *ext = nullptr;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() ==
				    llvm::Intrinsic::experimental_constrained_fpext) {
					ext = ii;
					break;
				}
	if (!ext)
		return out;
	auto *dfty = llvm::cast<llvm::FixedVectorType>(ext->getType());
	llvm::SmallVector<llvm::Constant *, 64> ev;
	for (u32 i = 0; i < lanes; ++i)
		ev.push_back(llvm::ConstantFP::get(
		    dfty->getElementType(),
		    llvm::APFloat(llvm::APFloat::IEEEdouble(),
				  llvm::APInt(64, HostWiden(pattern[i % pattern.size()])))));
	ext->replaceAllUsesWith(llvm::ConstantVector::get(ev));
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
						else if (auto *cf =
							     llvm::dyn_cast_or_null<llvm::ConstantFP>(
								 c->getAggregateElement(i)))
							out.lanes.push_back(
							    cf->getValueAPF().bitcastToAPInt()
								.getZExtValue());
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

struct Pat { char const *name; u32 bits; };
constexpr Pat kPats[] = {
    {"+0.0",                 0x00000000u},
    {"-0.0",                 0x80000000u},
    {"+1.0",                 0x3f800000u},
    {"-2.5",                 0xc0200000u},
    {"+min subnormal",       0x00000001u},
    {"-max subnormal",       0x807fffffu},
    {"+max normal",          0x7f7fffffu},
    {"+inf",                 0x7f800000u},
    {"-inf",                 0xff800000u},
    // THE CASES A BARE fpext GETS WRONG. A payload-preserving widening and a canonicalising one
    // have the same shape and differ only in bits, which is why these carry distinctive payloads.
    {"qNaN (canonical)",     0x7fc00000u},
    {"qNaN payload",         0x7feaaaaau},
    {"-qNaN payload",        0xffd55555u},
    {"sNaN payload 0x1",     0x7f800001u},
    {"sNaN payload 0x2aaaaa",0x7faaaaaau},
    {"-sNaN payload",        0xff955555u},
};
constexpr size_t kNP = sizeof(kPats) / sizeof(kPats[0]);

void SectionOracle()
{
	printf("[C4FW-2] value + NV oracle vs softfp::cvt_fmt (isolated lanes)\n");
	unsigned checked = 0;
	bool seen[kNP] = {};
	// +1.0 raises nothing and is exact, so a chunk's derived NV reflects the lane under test.
	constexpr u32 kFiller = 0x3f800000u;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (size_t k = 0; k < kNP; ++k) {
			Configure(vlen, /*on=*/true);
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubWidenFF, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				break;
			u32 const lanes = q.bytes / 8u;
			std::vector<u32> pattern(lanes, kFiller);
			pattern[0] = kPats[k].bits;
			Folded f = FoldUnit(b, VRegOff(kVs2), VRegOff(kVd), pattern, lanes);
			if (!f.ok) {
				printf("  FAIL vlen=%u '%s': the unit did not fold to a constant\n",
				       vlen, kPats[k].name);
				++g_fail;
				continue;
			}
			u32 fl = 0;
			u64 const want = rvv32::softfp::cvt_fmt(kPats[k].bits, rvv32::softfp::FMT32,
								rvv32::softfp::FMT64,
								rvv32::FRM_RNE, fl);
			bool const want_nv = (fl & rvv32::FFLAG_NV) != 0;
			bool const got_nv = (f.flags & rvv32::FFLAG_NV) != 0;
			++checked;
			seen[k] = true;
			if (f.lanes[0] != want) {
				printf("  FAIL vlen=%u %-24s value emitted=0x%016llx "
				       "reference=0x%016llx\n", vlen, kPats[k].name,
				       (unsigned long long)f.lanes[0], (unsigned long long)want);
				++g_fail;
			}
			if (got_nv != want_nv) {
				printf("  FAIL vlen=%u %-24s NV emitted=%d contract=%d\n", vlen,
				       kPats[k].name, (int)got_nv, (int)want_nv);
				++g_fail;
			}
			// The filler lanes must be untouched by the NaN handling.
			for (u32 i = 1; i < lanes; ++i) {
				u32 f2 = 0;
				u64 const w2 = rvv32::softfp::cvt_fmt(kFiller, rvv32::softfp::FMT32,
								      rvv32::softfp::FMT64,
								      rvv32::FRM_RNE, f2);
				if (f.lanes[i] != w2) {
					printf("  FAIL vlen=%u %-24s filler lane %u corrupted\n",
					       vlen, kPats[k].name, i);
					++g_fail;
					break;
				}
			}
		}
	printf("       %u isolated lanes compared (value AND NV)\n", checked);
	CHECK(checked > 0);
	for (size_t k = 0; k < kNP; ++k)
		if (!seen[k]) {
			printf("  FAIL pattern '%s' was never compared\n", kPats[k].name);
			++g_fail;
		}
}

void SectionShape()
{
	printf("[C4FW-1] frame shape, widening geometry, constrained fpext, canonical-NaN select\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		Configure(vlen, /*on=*/true);
		Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubWidenFF, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		if (!q.frames)
			continue;
		++admitted;
		CheckModuleIsWellFormed(b, "vfwcvt.f.f");
		CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		CHECK_EQ(q.brackets, 1u);
		CHECK_EQ(q.sew, 8u); // the node's sew is the DESTINATION width
		u32 const lanes = q.bytes / 8u;
		// THE WIDENING GEOMETRY, derived from first principles rather than from the emitter's
		// formula: unit `c` covers elements `[c*lanes, (c+1)*lanes)` of BOTH groups, and element
		// `e` of a group lives in register `base + (e*esize)/rb` at byte `(e*esize)%rb`. The
		// destination element is 8 bytes and the source element is 4, so the two windows advance
		// at DIFFERENT rates -- one stride for both would read the wrong half of the source
		// group. Note the offsets are not simply `bytes` apart: crossing into the next register
		// jumps by the CPUState register slot (VLEN_MAX_BYTES), which is what the first version
		// of this assertion got wrong.
		u32 const rb = vlen / 8u;
		auto win = [&](u32 base_reg, u32 elem, u32 esize) {
			u32 const byte = elem * esize;
			return VRegOff(base_reg) + byte / rb * rvv32::VLEN_MAX_BYTES + byte % rb;
		};
		for (size_t c = 0; c < q.dst_offs.size(); ++c) {
			CHECK_EQ(q.dst_offs[c], win(kVd, (u32)c * lanes, 8u));
			CHECK_EQ(q.src_offs[c], win(kVs2, (u32)c * lanes, 4u));
		}
		unsigned exts = 0, canon_selects = 0, plain = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				if (llvm::isa<llvm::FPExtInst>(&ins))
					++plain;
				if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
					auto *t = llvm::dyn_cast<llvm::Constant>(sel->getTrueValue());
					auto *sp = t ? t->getSplatValue() : nullptr;
					auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(sp);
					if (ci && ci->getZExtValue() == rvv32::F64_CANONICAL_NAN)
						++canon_selects;
				}
				auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
				if (ii && ii->getIntrinsicID() ==
					      llvm::Intrinsic::experimental_constrained_fpext)
					++exts;
			}
		CHECK_EQ(exts, q.units);
		// One canonical-NaN select per unit: the assertion that a bare fpext is not what ships.
		CHECK_EQ(canon_selects, q.units);
		CHECK_EQ(plain, 0u);
	}
	CHECK(admitted > 0);
}

// ---------------------------------------------------------------------------------------------
// NARROWING (`vfncvt.f.f.w`, f64 -> f32). NOT the mirror of the widening direction: it rounds, so
// it can raise NX, OF|NX and UF|NX. Those three come from the hardware and this test CANNOT observe
// host MXCSR, so it does not assert them -- it asserts the VALUES (where rounding, overflow
// saturation and the NaN canonicalisation are all visible) and the one flag the route derives
// itself, NV for signalling NaNs. That limit is stated rather than papered over; the structural
// check that the conversion really is the CONSTRAINED `fptrunc` with `round.dynamic` +
// `fpexcept.strict` is what stands behind the delegated flags.
constexpr u32 kSubNarrowFF = 20u; // narrowing block (16) + kind 4 (f.f)
constexpr u32 kSubNarrowROD = 21u;

struct PatD { char const *name; u64 bits; };
constexpr PatD kPatsD[] = {
    {"+0.0",               0x0000000000000000ull},
    {"-0.0",               0x8000000000000000ull},
    {"+1.0",               0x3ff0000000000000ull},
    {"-2.5",               0xc004000000000000ull},
    {"inexact -> NX",      0x3ff000001ad7f29bull},
    {"f32 max normal",     0x47efffffe0000000ull},
    {"overflow -> OF|NX",  0x48078287f49c4a1dull},
    {"underflow -> UF|NX", 0x3696d601ad376ab9ull},
    {"f32 min normal",     0x3810000000000000ull},
    {"+inf",               0x7ff0000000000000ull},
    {"-inf",               0xfff0000000000000ull},
    {"qNaN (canonical)",   0x7ff8000000000000ull},
    {"qNaN payload",       0x7ffaaaaaaaaaaaaaull},
    {"-qNaN payload",      0xfffd555555555555ull},
    {"sNaN payload 0x1",   0x7ff0000000000001ull},
    {"sNaN payload big",   0x7ff4aaaaaaaaaaaaull},
    {"-sNaN payload",      0xfff2555555555555ull},
};
constexpr size_t kNPD = sizeof(kPatsD) / sizeof(kPatsD[0]);

// What x86 `vcvtpd2ps` produces under round-to-nearest: an IEEE narrowing that quiets a signalling
// NaN and carries the TOP of its payload across. Deliberately not the architectural answer -- it is
// the thing the route has to correct, and substituting it is what lets the oracle prove it does.
u32 HostNarrow(u64 b)
{
	u64 const absb = b & 0x7fffffffffffffffull;
	if (absb > 0x7ff0000000000000ull) {
		u32 const sign = (u32)(b >> 63) << 31;
		u32 const payload = (u32)((b >> 29) & 0x003fffffu);
		return sign | 0x7f800000u | 0x00400000u | payload;
	}
	double d;
	std::memcpy(&d, &b, 8);
	float const f = (float)d;
	u32 out;
	std::memcpy(&out, &f, 4);
	return out;
}

Folded FoldUnitNarrow(Built &b, u32 rs_off, u32 rd_off, std::vector<u64> const &pattern, u32 lanes)
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
			if (!vt || vt->getNumElements() != lanes || !vt->getElementType()->isDoubleTy())
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
		    llvm::APFloat(llvm::APFloat::IEEEdouble(),
				  llvm::APInt(64, pattern[i % pattern.size()]))));
	src->replaceAllUsesWith(llvm::ConstantVector::get(in));
	FoldToFixpoint(fn);

	llvm::IntrinsicInst *tr = nullptr;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() ==
				    llvm::Intrinsic::experimental_constrained_fptrunc) {
					tr = ii;
					break;
				}
	if (!tr)
		return out;
	auto *dfty = llvm::cast<llvm::FixedVectorType>(tr->getType());
	llvm::SmallVector<llvm::Constant *, 64> tv;
	for (u32 i = 0; i < lanes; ++i)
		tv.push_back(llvm::ConstantFP::get(
		    dfty->getElementType(),
		    llvm::APFloat(llvm::APFloat::IEEEsingle(),
				  llvm::APInt(32, HostNarrow(pattern[i % pattern.size()])))));
	tr->replaceAllUsesWith(llvm::ConstantVector::get(tv));
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
					for (u32 i = 0; i < lanes; ++i) {
						auto *e = c->getAggregateElement(i);
						if (auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(e))
							out.lanes.push_back(ci->getZExtValue());
						else if (auto *cf =
							     llvm::dyn_cast_or_null<llvm::ConstantFP>(e))
							out.lanes.push_back(
							    cf->getValueAPF().bitcastToAPInt()
								.getZExtValue());
					}
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

void SectionNarrowOracle()
{
	printf("[C4FN-1] narrowing: value oracle vs softfp::cvt_fmt, and the derived NV\n");
	unsigned checked = 0;
	bool seen[kNPD] = {};
	constexpr u64 kFillerD = 0x3ff0000000000000ull; // +1.0: exact, raises nothing
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (size_t k = 0; k < kNPD; ++k) {
			Configure(vlen, /*on=*/false);
			config::rvv_llvm_fcvt_fnarrow = true;
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubNarrowFF, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				break;
			u32 const lanes = q.bytes / 4u;
			std::vector<u64> pattern(lanes, kFillerD);
			pattern[0] = kPatsD[k].bits;
			Folded f = FoldUnitNarrow(b, VRegOff(kVs2), VRegOff(kVd), pattern, lanes);
			if (!f.ok) {
				printf("  FAIL vlen=%u '%s': the unit did not fold to a constant\n",
				       vlen, kPatsD[k].name);
				++g_fail;
				continue;
			}
			u32 fl = 0;
			u64 const want = rvv32::softfp::cvt_fmt(kPatsD[k].bits, rvv32::softfp::FMT64,
								rvv32::softfp::FMT32,
								rvv32::FRM_RNE, fl);
			++checked;
			seen[k] = true;
			if (f.lanes[0] != want) {
				printf("  FAIL vlen=%u %-22s value emitted=0x%08llx "
				       "reference=0x%08llx\n", vlen, kPatsD[k].name,
				       (unsigned long long)f.lanes[0], (unsigned long long)want);
				++g_fail;
			}
			bool const want_nv = (fl & rvv32::FFLAG_NV) != 0;
			bool const got_nv = (f.flags & rvv32::FFLAG_NV) != 0;
			if (got_nv != want_nv) {
				printf("  FAIL vlen=%u %-22s NV emitted=%d contract=%d\n", vlen,
				       kPatsD[k].name, (int)got_nv, (int)want_nv);
				++g_fail;
			}
			// OF / UF / NX are delegated to the hardware and are NOT asserted here; the
			// route emits no constant for them, so the derived mask must carry ONLY NV.
			CHECK_EQ(f.flags & ~(u32)rvv32::FFLAG_NV, 0u);
		}
	printf("       %u isolated lanes compared (value AND the derived NV)\n", checked);
	CHECK(checked > 0);
	for (size_t k = 0; k < kNPD; ++k)
		if (!seen[k]) {
			printf("  FAIL narrowing pattern '%s' was never compared\n", kPatsD[k].name);
			++g_fail;
		}
}

void SectionNarrowShape()
{
	printf("[C4FN-2] narrowing: constrained fptrunc with round.dynamic, geometry, rod refused\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		Configure(vlen, /*on=*/false);
		config::rvv_llvm_fcvt_fnarrow = true;
		Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubNarrowFF, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		if (!q.frames)
			continue;
		++admitted;
		CheckModuleIsWellFormed(b, "vfncvt.f.f");
		CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		CHECK_EQ(q.sew, 4u); // destination width
		u32 const lanes = q.bytes / 4u;
		u32 const rb = vlen / 8u;
		// The SOURCE window is the wider one here -- the opposite of the widening direction.
		auto win = [&](u32 base_reg, u32 elem, u32 esize) {
			u32 const byte = elem * esize;
			return VRegOff(base_reg) + byte / rb * rvv32::VLEN_MAX_BYTES + byte % rb;
		};
		for (size_t c = 0; c < q.dst_offs.size(); ++c) {
			CHECK_EQ(q.dst_offs[c], win(kVd, (u32)c * lanes, 4u));
			CHECK_EQ(q.src_offs[c], win(kVs2, (u32)c * lanes, 8u));
		}
		unsigned trs = 0, rounded = 0, strict = 0, canon_selects = 0, plain = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				if (llvm::isa<llvm::FPTruncInst>(&ins))
					++plain;
				if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
					auto *t = llvm::dyn_cast<llvm::Constant>(sel->getTrueValue());
					auto *sp = t ? t->getSplatValue() : nullptr;
					auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(sp);
					if (ci && ci->getZExtValue() == rvv32::F32_CANONICAL_NAN)
						++canon_selects;
				}
				auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
				if (!ii || ii->getIntrinsicID() !=
					       llvm::Intrinsic::experimental_constrained_fptrunc)
					continue;
				++trs;
				for (unsigned a = 1; a < ii->arg_size(); ++a)
					if (auto *mv = llvm::dyn_cast<llvm::MetadataAsValue>(
						ii->getArgOperand(a)))
						if (auto *ms = llvm::dyn_cast<llvm::MDString>(
							mv->getMetadata())) {
							if (ms->getString() == "round.dynamic")
								++rounded;
							if (ms->getString() == "fpexcept.strict")
								++strict;
						}
			}
		CHECK_EQ(trs, q.units);
		// The delegated OF/UF/NX only exist because the call is strict AND rounds by MXCSR.
		CHECK_EQ(rounded, q.units);
		CHECK_EQ(strict, q.units);
		CHECK_EQ(canon_selects, q.units);
		CHECK_EQ(plain, 0u);
	}
	CHECK(admitted > 0);

	// round-to-odd stays on the helper: it is not an architectural rounding mode.
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, /*on=*/false);
		config::rvv_llvm_fcvt_fnarrow = true;
		Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubNarrowROD, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.units, 0u);
		CHECK(q.hcalls > 0u);
	}
}

void SectionRefusals()
{
	printf("[C4FW-3] narrowing, round-to-odd, same-width and masked forms keep the helper\n");
	struct R { char const *name; u32 sub; bool unmasked; };
	R const rows[] = {
	    {"vfncvt.f.f.w (narrowing, sub 20)", 20u, true},
	    {"vfncvt.rod.f.f.w (sub 21)", 21u, true},
	    {"vfwcvt.f.x.v (widening int->float, sub 11)", 11u, true},
	    {"vfwcvt.rtz.x.f.v (widening float->int, sub 15)", 15u, true},
	    {"vfwcvt.f.f.v MASKED", kSubWidenFF, false},
	};
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			Configure(vlen, /*on=*/true);
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(r.sub, kVs2, kVd, r.unmasked), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (q.units != 0) {
				printf("  FAIL %s was admitted at vlen=%u; this route is unmasked "
				       "widening f.f only\n", r.name, vlen);
				++g_fail;
			}
			CHECK(q.hcalls > 0u);
		}
}

void SectionOffIsInert()
{
	printf("[C4FW-4] switch off: no frame, the instruction reaches the helper\n");
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, /*on=*/false);
		Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubWidenFF, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.units, 0u);
		CHECK(q.hcalls > 0u);
	}
}

void DumpIR()
{
	char const *path = getenv("C4FW_DUMP_IR");
	if (!path)
		return;
	Configure(1024u, true);
	Built b({Vsetvli(kVT_E32M1), OpVfcvt(kSubWidenFF, kVs2, kVd), kJalr});
	Translate(b);
	// The narrowing direction goes to a second file, so both shapes are on record.
	if (char const *np = getenv("C4FN_DUMP_IR")) {
		Configure(1024u, false);
		config::rvv_llvm_fcvt_fnarrow = true;
		Built nb({Vsetvli(kVT_E32M1), OpVfcvt(kSubNarrowFF, kVs2, kVd), kJalr});
		Translate(nb);
		std::error_code nec;
		llvm::raw_fd_ostream nos(np, nec);
		if (!nec)
			nb.module.print(nos, nullptr);
		printf("  (narrowing IR dumped to %s)\n", np);
	}
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

} // namespace

int main()
{
	printf("rvv_llvm_fcvt_fwiden_test\n");
	SectionShape();
	SectionOracle();
	SectionNarrowShape();
	SectionNarrowOracle();
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
