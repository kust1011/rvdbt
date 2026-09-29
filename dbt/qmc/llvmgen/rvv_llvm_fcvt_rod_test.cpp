// ORDER ITEM 4 (2026-09-19): `vfncvt.rod.f.f.w` -- ROUND-TO-ODD narrowing, f64 -> f32.
//
// WHAT THE ROUTE IS, AND WHY IT IS NOT A HOST CONVERSION. Round-to-odd is "truncate toward zero,
// then force the low significand bit whenever anything was discarded". It is not one of the five
// architectural rounding modes and cannot be requested through `frm`. The obvious LLVM design --
// a constrained `fptrunc` carrying `round.towardzero` -- is WRONG ON THIS TARGET, measured on the
// installed LLVM 20.1.8:
//
//     constrained.fptrunc <8 x double> ... round.towardzero -> vcvtpd2ps
//     constrained.fptrunc <8 x double> ... round.dynamic    -> vcvtpd2ps
//     constrained.fadd    double       ... round.upward     -> vaddsd
//
// byte-identical code and no MXCSR write, so codegen would use whatever MXCSR.RC holds -- inside
// this frame's bracket, the GUEST's `frm`. The body is therefore INTEGER IR with no host
// floating-point operation at all.
//
// THE CENTRAL CHECK IS A DIFFERENTIAL AGAINST THE REPOSITORY'S OWN REFERENCE, not against a
// hand-written expectation table. `dbt::rv32::softfp::cvt_fmt(bits, FMT64, FMT32, FRM_ROD, fl)` is the exact
// function the helper arm calls, so folding the route's own emitted IR to constants and comparing
// both the RESULT BITS and the DERIVED FLAGS against it, value by value, is the strongest evidence
// this file can produce without executing. A hand table would encode my reading of the spec twice.
//
// SECTIONS:
//   [R1] Admission: the kind-5 encoding takes the frame under the switch and keeps the unchanged
//        helper without it; kind 4 (the ordinary rounding narrow) is unaffected in both positions.
//   [R2] NO host FP operation is emitted in the ROD body -- no constrained intrinsic at all. If one
//        appeared, the whole argument above would be void and the result would depend on `frm`.
//   [R3] THE DIFFERENTIAL: named boundary values, every one of which the reference fixes and each
//        of which is a plausible off-by-one -- the overflow threshold (E >= 128, not 127), the
//        impossibility of underflowing to zero, the f64-subnormal source, the exact cases, both
//        signs, both NaN kinds and both infinities.
//   [R4] THE SAME DIFFERENTIAL over a pseudo-random sweep of bit patterns, which is what turns [R3]
//        from "the cases I thought of" into coverage.
//   [R5] Flags, compared against the reference's own accumulated `fl` for the same lanes.
//   [R6] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_rvv_contract.h"
#include "dbt/guest/rv32_softfp.h"
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
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
namespace rvv32 = dbt::rv32;
namespace ctr = dbt::rv32::rvvcontract;

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

// VFUNARY0 (funct6 18), OPFVV (funct3 1). `sub` 20 is `vfncvt.f.f.w`, 21 is `vfncvt.rod.f.f.w`.
constexpr u32 OpVfncvt(u32 sub, u32 vs2, u32 vd)
{
	return (18u << 26) | (1u << 25) | (vs2 << 20) | (sub << 15) | (1u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVs2 = 8u, kVd = 10u;
constexpr u32 kSubFF = 20u, kSubROD = 21u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4rod", g_ctx) {}
};

void Configure(u32 vlen, bool rod)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_fcvt_fnarrow = true;
	config::rvv_llvm_fcvt_rod = rod;
	config::rvv_llvm_fcvt_partial_vl = false;
	config::rvv_llvm_masked = false;
	config::rvv_llvm_restart = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = true;
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

unsigned CountFtoF(Region *r, bool *rod_out)
{
	unsigned n = 0;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_vchunkftof) {
				++n;
				if (rod_out)
					*rod_out = static_cast<InstVChunkFToF *>(&ins)->rod;
			}
	return n;
}

unsigned CountHcalls(Region *r)
{
	unsigned n = 0;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_hcall)
				++n;
	return n;
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
					continue;
				}
				// LLVM's constant folder does not fold `bitcast <N x i1> to iN` -- the
				// element type is not byte-sized -- so the flag reduction
				// (`icmp ne (bitcast mask to iN), 0`) stays symbolic and the whole
				// `fcsr` expression with it. Folding it here is a TEST-SIDE gap being
				// closed, not a change to what is emitted: the backend lowers that
				// bitcast to a `kmov` perfectly well.
				auto *bc = llvm::dyn_cast<llvm::BitCastInst>(&I);
				if (!bc || !bc->getType()->isIntegerTy())
					continue;
				auto *src_ty =
				    llvm::dyn_cast<llvm::FixedVectorType>(bc->getOperand(0)->getType());
				if (!src_ty || !src_ty->getElementType()->isIntegerTy(1))
					continue;
				auto *cv = llvm::dyn_cast<llvm::Constant>(bc->getOperand(0));
				if (!cv)
					continue;
				llvm::APInt acc(src_ty->getNumElements(), 0);
				bool all = true;
				for (unsigned k = 0; k < src_ty->getNumElements(); ++k) {
					auto *el = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    cv->getAggregateElement(k));
					if (!el) {
						all = false;
						break;
					}
					if (el->isOne())
						acc.setBit(k); // little-endian: element k is bit k
				}
				if (!all)
					continue;
				bc->replaceAllUsesWith(llvm::ConstantInt::get(bc->getType(), acc));
				again = true;
			}
	}
}

constexpr u32 kVregOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
constexpr u32 kFcsrOff = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
u32 VRegOff(u32 r) { return kVregOff + r * rvv32::VLEN_MAX_BYTES; }

struct Folded {
	bool ok = false;
	int why = 0;
	std::vector<u32> results; // one per destination element, in element order
	u32 flags = 0;
};

// Fold one frame with the source elements set to `pattern` (repeating), and read back the stored
// destination words and the flag word ORed into `fcsr`.
Folded FoldRod(Built &b, u32 lanes, std::vector<u64> const &pattern)
{
	Folded out;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	// Every source chunk load becomes a constant vector. Chunk `c` covers elements
	// [c*lanes, (c+1)*lanes), and its CPUState offset identifies which.
	// THE SOURCE GROUP SPANS TWO REGISTERS, and that is the whole difference from a same-width
	// route. A narrowing convert reads f64 at EMUL 2 while writing f32 at EMUL 1, so `vs2`'s
	// elements continue into `vs2 + 1`; a filter that looked only inside `vs2`'s own 512-byte slot
	// found the first chunk's load and missed the second, and the half of the body fed by the
	// missed load stayed symbolic. The element windows are therefore taken from the SHARED
	// CONTRACT -- the same `ElementStateOffset` the route itself used to place them -- rather than
	// from a range test.
	u32 const vlen = config::vlen_bits;
	u32 const vmax = vlen / 32u;
	std::vector<std::pair<u32, llvm::LoadInst *>> loads;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || !vt->getElementType()->isDoubleTy())
				continue;
			u32 const o = StateOffset(l->getPointerOperand(), state);
			for (u32 e = 0; e < vmax; e += lanes)
				if (ctr::ElementStateOffset(vlen, kVs2, e, 8) == o) {
					loads.emplace_back(e, l);
					break;
				}
		}
	if (loads.empty()) { out.why=1; return out; }
	for (auto const &pr : loads) {
		u32 const first = pr.first;
		auto *vt = llvm::cast<llvm::FixedVectorType>(pr.second->getType());
		llvm::SmallVector<llvm::Constant *, 16> cv;
		for (u32 i = 0; i < vt->getNumElements(); ++i)
			cv.push_back(llvm::ConstantFP::get(
			    vt->getElementType(),
			    llvm::APFloat(llvm::APFloat::IEEEdouble(),
					  llvm::APInt(64, pattern[(first + i) % pattern.size()]))));
		pr.second->replaceAllUsesWith(llvm::ConstantVector::get(cv));
	}
	FoldToFixpoint(fn);

	// Destination words, by element index.
	std::vector<std::pair<u32, llvm::Constant *>> dst;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st)
				continue;
			u32 const o = StateOffset(st->getPointerOperand(), state);
			bool is_dst = false;
			u32 dst_e = 0;
			for (u32 e = 0; e < vmax; e += lanes)
				if (ctr::ElementStateOffset(vlen, kVd, e, 4) == o) {
					is_dst = true;
					dst_e = e;
					break;
				}
			if (is_dst) {
				auto *c = llvm::dyn_cast<llvm::Constant>(st->getValueOperand());
				if (!c) { out.why=2; return out; }
				dst.emplace_back(dst_e, c);
				continue;
			}
			if (o != kFcsrOff)
				continue;
			// TWO DIFFERENT STORES REACH `fcsr` IN THIS FUNCTION and only one of them is
			// this body's. The FP bracket's close (`rvvqcgfpend`) ORs the HOST's MXCSR
			// sticky bits in, and that operand is symbolic by construction -- it is read
			// at run time. The ROD body's own store ORs a value that folds to a constant.
			// So a non-constant operand here is SKIPPED rather than treated as a folding
			// failure; an earlier version of this loop bailed on the bracket's store and
			// reported the whole body as unfoldable.
			//
			// (The bracket contributes nothing for this route in any case: its open masks
			// MXCSR with 0xFFFF9FC0, clearing the six sticky bits, and the ROD body
			// performs no host floating-point operation that could set them again.)
			auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(st->getValueOperand());
			if (!bo || bo->getOpcode() != llvm::Instruction::Or)
				continue;
			auto *c0 = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(0));
			auto *c1 = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(1));
			if (!c0 && !c1)
				continue;
			out.flags |= (u32)(c0 ? c0->getZExtValue() : c1->getZExtValue());
		}
	if (dst.empty()) { out.why=3; return out; }
	u32 max_e = 0;
	for (auto const &d : dst) {
		auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(d.second->getType());
		if (!vt) { out.why=4; return out; }
		max_e = std::max(max_e, d.first + (u32)vt->getNumElements());
	}
	out.results.assign(max_e, 0);
	for (auto const &d : dst) {
		auto *vt = llvm::cast<llvm::FixedVectorType>(d.second->getType());
		for (u32 i = 0; i < vt->getNumElements(); ++i) {
			auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
			    d.second->getAggregateElement(i));
			if (!e) { out.why=5; return out; }
			out.results[d.first + i] = (u32)e->getZExtValue();
		}
	}
	out.ok = true;
	return out;
}

// THE REFERENCE. `dbt::rv32::softfp::cvt_fmt` with FRM_ROD is exactly what `rvv_lower::vfcvt` calls for this
// sub-encoding, so this is the helper arm's own function and not a second reading of the spec.
u32 RefRod(u64 bits, u32 *fl)
{
	u32 f = 0;
	u64 const r = dbt::rv32::softfp::cvt_fmt(bits, dbt::rv32::softfp::FMT64, dbt::rv32::softfp::FMT32, rvv32::FRM_ROD, f);
	if (fl)
		*fl |= f;
	return (u32)r;
}

std::vector<u64> const &BoundaryPatterns()
{
	static std::vector<u64> p = {
	    0x0000000000000000ull, // +0
	    0x8000000000000000ull, // -0
	    0x7FF0000000000000ull, // +inf
	    0xFFF0000000000000ull, // -inf
	    0x7FF8000000000000ull, // qNaN
	    0x7FF0000000000001ull, // sNaN
	    0xFFF4000000000000ull, // negative sNaN
	    0x3FF0000000000000ull, // 1.0, exact
	    0x3FF0000000000001ull, // 1.0 + 1ulp(f64): inexact, odd bit forced
	    0xBFF0000000000001ull, // the same, negative
	    0x47EFFFFFE0000000ull, // FLT_MAX as a double, exact
	    0x47EFFFFFE0000001ull, // just above FLT_MAX: still E == 127, NOT an overflow
	    0x47F0000000000000ull, // 2^128: the first real overflow
	    0xC7F0000000000000ull, // -2^128
	    0x7FE0000000000000ull, // 1e300-ish: far overflow
	    0x3810000000000000ull, // 2^-126: the smallest f32 NORMAL, exact
	    0x3800000000000000ull, // 2^-127: f32 subnormal, exact
	    0x36A0000000000000ull, // 2^-149: the smallest f32 subnormal, exact
	    0x3690000000000000ull, // 2^-150: underflows -- ROD gives the smallest subnormal, NOT 0
	    0xB690000000000000ull, // the same, negative
	    0x0000000000000001ull, // the smallest f64 subnormal
	    0x8000000000000001ull, // negative
	    0x000FFFFFFFFFFFFFull, // the largest f64 subnormal
	    0x3FF5555555555555ull, // an ordinary inexact value
	    0x4005555555555555ull,
	    0xC005555555555555ull,
	};
	return p;
}

void SectionAdmission()
{
	printf("[R1] the kind-5 encoding takes the frame under the switch, helper without it\n");
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		Configure(vlen, true);
		Built on({Vsetvli(kVT_E32M1), OpVfncvt(kSubROD, kVs2, kVd), kJalr});
		Translate(on);
		bool rod = false;
		unsigned const n = CountFtoF(on.region, &rod);
		if (!n)
			continue;
		++admitted;
		CHECK(rod);
		Configure(vlen, false);
		Built off({Vsetvli(kVT_E32M1), OpVfncvt(kSubROD, kVs2, kVd), kJalr});
		Translate(off);
		CHECK_EQ(CountFtoF(off.region, nullptr), 0u);
		CHECK(CountHcalls(off.region) >= 1u);
		// The ORDINARY narrowing form is unaffected by this switch in both positions.
		for (bool sw : {false, true}) {
			Configure(vlen, sw);
			Built ff({Vsetvli(kVT_E32M1), OpVfncvt(kSubFF, kVs2, kVd), kJalr});
			Translate(ff);
			bool r2 = true;
			CHECK(CountFtoF(ff.region, &r2) == n);
			CHECK(!r2);
		}
	}
	printf("       %u admitted widths\n", admitted);
	CHECK(admitted > 0);
}

void SectionNoHostFp()
{
	printf("[R2] the ROD body emits NO constrained FP intrinsic -- the result cannot depend on frm\n");
	for (u32 vlen : {128u, 512u, 2048u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpVfncvt(kSubROD, kVs2, kVd), kJalr});
		Translate(b);
		if (!b.fn || !CountFtoF(b.region, nullptr))
			continue;
		unsigned constrained = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb)
				if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
					llvm::StringRef n =
					    llvm::Intrinsic::getBaseName(ii->getIntrinsicID());
					if (n.contains("experimental.constrained"))
						++constrained;
				}
		CHECK_EQ(constrained, 0u);
		// And the ordinary narrowing form DOES emit one, so the check above is not vacuous.
		Built ff({Vsetvli(kVT_E32M1), OpVfncvt(kSubFF, kVs2, kVd), kJalr});
		Translate(ff);
		unsigned c2 = 0;
		if (ff.fn)
			for (auto &bb : *ff.fn)
				for (auto &ins : bb)
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						llvm::StringRef n = llvm::Intrinsic::getBaseName(
						    ii->getIntrinsicID());
						if (n.contains("experimental.constrained"))
							++c2;
					}
		CHECK(c2 > 0);
	}
}

// The shared differential body: fold one frame over `pattern` and compare every element and the
// accumulated flags against `dbt::rv32::softfp::cvt_fmt(..., FRM_ROD, ...)`.
unsigned Differential(char const *label, std::vector<u64> const &pattern, unsigned *cells)
{
	unsigned bad = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpVfncvt(kSubROD, kVs2, kVd), kJalr});
		Translate(b);
		if (!b.fn || !CountFtoF(b.region, nullptr))
			continue;
		u32 const vmax = vlen / 32u;
		u32 const lanes = std::min(vlen / 8u, 64u) / 8u;
		Folded const f = FoldRod(b, lanes, pattern);
		if (!f.ok) {
			printf("  FAIL %s vlen=%u: the ROD body did not fold to constants (why=%d)\n", label,
			       vlen, f.why);
			++g_fail;
			++bad;
			continue;
		}
		u32 want_flags = 0;
		for (u32 e = 0; e < vmax && e < f.results.size(); ++e) {
			u64 const in = pattern[e % pattern.size()];
			u32 const want = RefRod(in, &want_flags);
			if (f.results[e] != want) {
				printf("  FAIL %s vlen=%u e=%u in=0x%016llx: emitted 0x%08x, "
				       "softfp 0x%08x\n",
				       label, vlen, e, (unsigned long long)in, f.results[e], want);
				++g_fail;
				++bad;
			}
			++*cells;
		}
		// THE FLAGS, against the reference's own accumulation over the same elements. The
		// emitted value is the OR over the whole unit, which is what `fcsr` accumulates.
		u32 const mask = rvv32::FFLAG_NV | rvv32::FFLAG_OF | rvv32::FFLAG_UF | rvv32::FFLAG_NX;
		if ((f.flags & mask) != (want_flags & mask)) {
			printf("  FAIL %s vlen=%u: flags 0x%x, softfp 0x%x\n", label, vlen,
			       f.flags & mask, want_flags & mask);
			++g_fail;
			++bad;
		}
	}
	return bad;
}

void SectionBoundaries()
{
	printf("[R3/R5] named boundary values, results and flags vs dbt::rv32::softfp::cvt_fmt(FRM_ROD)\n");
	unsigned cells = 0;
	Differential("boundary", BoundaryPatterns(), &cells);
	printf("       %u elements compared against the reference\n", cells);
	CHECK(cells > 0);
}

void SectionSweep()
{
	printf("[R4] pseudo-random bit-pattern sweep, same differential\n");
	unsigned cells = 0;
	u64 x = 0x243F6A8885A308D3ull;
	for (unsigned round = 0; round < 160; ++round) {
		std::vector<u64> pat;
		for (unsigned i = 0; i < 64; ++i) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			u64 v = x;
			// Bias a third of the draws into the narrow exponent band where the three
			// interesting boundaries live, so the sweep is not almost entirely
			// overflow/underflow-to-subnormal.
			if ((i % 3) == 0)
				v = (v & 0x800FFFFFFFFFFFFFull) |
				    ((u64)(0x380u + (x % 0x100u)) << 52);
			pat.push_back(v);
		}
		Differential("sweep", pat, &cells);
	}
	printf("       %u elements compared against the reference\n", cells);
	CHECK(cells > 0);
}

void SectionVerify()
{
	printf("[R6] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpVfncvt(kSubROD, kVs2, kVd), kJalr});
		Translate(b);
		std::string err;
		llvm::raw_string_ostream es(err);
		if (llvm::verifyModule(b.module, &es)) {
			printf("  FAIL vlen=%u: %s\n", vlen, err.c_str());
			++g_fail;
		}
	}
}

void SectionNarrowStoreAlignment()
{
	printf("[R7] VLEN-128 narrowing stores do not claim 16-byte alignment at +8\n");
	for (u32 sub : {kSubFF, kSubROD}) {
		Configure(128, true);
		Built b({Vsetvli(kVT_E32M1), OpVfncvt(sub, kVs2, kVd), kJalr});
		Translate(b);
		unsigned aligned8 = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
					if (store->getAlign() == llvm::Align(8))
						++aligned8;
				} else if (auto *intr = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
					if (intr->getIntrinsicID() == llvm::Intrinsic::masked_store &&
					    llvm::cast<llvm::ConstantInt>(intr->getArgOperand(2))->getZExtValue() == 8)
						++aligned8;
				}
			}
		CHECK(aligned8 > 0);
	}
}

} // namespace

int main()
{
	printf("rvv_llvm_fcvt_rod_test: order item 4, vfncvt.rod.f.f.w in integer IR\n");
	SectionAdmission();
	SectionNoHostFp();
	SectionBoundaries();
	SectionSweep();
	SectionVerify();
	SectionNarrowStoreAlignment();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
