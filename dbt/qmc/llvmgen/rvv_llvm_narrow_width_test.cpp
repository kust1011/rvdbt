// P4: the LLVM/AOT `vadd.vv` typed-chunk route at every host vector width.
//
// WHAT P4 CHANGED. Until P4 the LLVM arm of `vadd.vv` refused any chunk narrower than 64 bytes --
// RvvVaddChunkShape carried an explicit `aot_use_llvm && bytes != max_chunk` refusal, and llvmgen
// had no narrow chunk type at all (MakeType/MakePtrType Panicked on V128/V256). So VLEN 128 and 256
// took the `rv32_vialu` helper for every guest `vadd.vv`, which P3 measured directly: 262144 and
// 131072 helper calls at REPS=1 and not one packed-add instruction anywhere in the artifact.
//
// P4 removes the refusal and DERIVES the type instead of branching on it:
//   * MakeType / MakePtrType -> <VTypeToSize(t)/8 x i64>, one expression for V128/V256/V512;
//   * TChunkAluLower         -> <VTypeToSize(t)/sew x i32>, one expression for every lane count;
//   * vstatechunkload/store  -> the node's own ins->Bytes(), the rule QEmit has used since M2C.
// There is no per-width body anywhere and no new helper.
//
// HOW THIS FILE OBSERVES IT. Through the same seam the sibling route tests use --
// `qir::CompilerGenRegionIR`, which runs the real decoder and the real `RV32Translator::Translate`
// and nothing else (no QSel, no QRegAlloc, no QEmit, no guest memory, no execution). The admission
// DECISION is therefore observed on a real encoded instruction pair at a real config::vlen_bits,
// rather than by calling a predicate directly -- which is also why it works with those predicates
// private.
//
// WHAT IT CHECKS:
//   1. type / lane / chunk derivation at all four widths: the frame exists, carries 4*count typed
//      ops, and every chunk value's QIR VType, byte width and i32 lane count equal what this file
//      recomputes from VLEN alone -- so the file is not comparing the implementation with itself;
//   2. 512 and 1024 keep exactly their pre-P4 shape ({64,1} and {64,2}), so a regression there
//      cannot pass silently;
//   3. fail-closed: --rvv-vector-ssa off, --rvv-verify, SEW != 32, a partial-chunk VLEN, a VLEN
//      below 128, and a VLEN above the UNCHANGED upper bound must all fall back to the helper;
//   4. the widening is `vadd.vv` ONLY -- `vsub.vv` still falls back at 128/256 on the LLVM arm,
//      with a 512 control proving that refusal is a width property and not a broken build.
//
// It never generates or executes code, never runs a guest and times nothing.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (long long)(a);                                                                    \
		auto _b = (long long)(b);                                                                    \
		if (_a != _b) {                                                                              \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, _a, _b);                                                                 \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// The same instruction pair the accepted vadd.vv route test uses (see that file for provenance).
constexpr u32 INSN_VSETVLI = 0x09057557u; // vsetvli a0, a0, e32, m1, tu, ma
constexpr u32 INSN_VADD_VV = 0x021101d7u; // vadd.vv v3, v1, v2
constexpr u32 INSN_VSUB_VV = 0x0a1101d7u; // vsub.vv v3, v1, v2
// vsetvli encodings built from the vtype fields, verbatim from the accepted vadd.vv route test, so
// the SEW row below tests a real e64 configuration rather than a hand-typed word.
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 INSN_VSETVLI_E64 = EncodeVsetvli(Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1));

// The expected shape, derived from VLEN alone -- NOT by calling the predicate under test.
struct Expect {
	u32 bytes, count, lanes;
	VType vtype;
};
Expect ExpectFor(u32 vlen)
{
	u32 const reg_bytes = vlen / 8;
	u32 const bytes = reg_bytes < 64 ? reg_bytes : 64;
	VType const vt = bytes == 16 ? VType::V128 : bytes == 32 ? VType::V256 : VType::V512;
	return Expect{bytes, reg_bytes / bytes, bytes / 4, vt};
}

// One region containing the translated pair, on the LLVM arm at one VLEN. No force-emit switch is
// used or needed: the LLVM arm has no host-CPUID row (rv32_qir.cpp says so explicitly -- LLVM
// legalises the vector add for whatever subtarget the artifact is compiled for), so this file's
// result does not depend on the machine it runs on.
Region *TranslateLLVM(MemArena &arena, u32 words[2], u32 vlen_bits, bool ssa = true,
		      bool verify = false, bool sub_switch = false)
{
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_verify = verify;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false; // the LLVM arm must not borrow the QCG switch
	// vsub.vv's LLVM route has its OWN per-opcode switch, checked BEFORE RvvSSAEnabled()
	// (rv32_qir.cpp RvvLLVMSubChunkAdmit). Section 4 must set it, or vsub's refusal would be
	// attributable to the switch being off rather than to the width -- which is what an earlier
	// draft of this file did, making its 128/256 assertions pass for the wrong reason.
	config::rvv_qcg_typed_chunk_sub = sub_switch;
	config::vlen_bits = vlen_bits;

	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

struct Group {
	unsigned n_begin = 0, n_end = 0;
	std::vector<Inst *> body;
};

Group FindGroup(Region *region)
{
	Group g;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				++g.n_begin;
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				++g.n_end;
				open = false;
				continue;
			}
			if (open) {
				g.body.push_back(&ins);
			}
		}
	}
	return g;
}

// True iff the region routed vadd.vv directly (a typed frame exists) rather than falling back.
bool Routed(Region *region) { return FindGroup(region).n_begin == 1; }

// ---------------------------------------------------------------------------------------------
void Section1_Derivation()
{
	printf("1. type / lane / chunk derivation at every width, LLVM arm\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		Expect const e = ExpectFor(vlen);
		MemArena arena(1u << 20);
		u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
		Group g = FindGroup(TranslateLLVM(arena, words, vlen));

		if (g.n_begin != 1) {
			fprintf(stderr, "  FAIL vlen=%u: LLVM vadd.vv did NOT route (frames=%u)\n", vlen,
				g.n_begin);
			++g_failures;
			continue;
		}
		CHECK_EQ(g.n_end, 1u);
		// load, load, add, store per chunk -- the shape every typed frame has.
		CHECK_EQ(g.body.size(), 4u * e.count);

		unsigned loads = 0, adds = 0, stores = 0, typed_vals = 0;
		for (Inst *ins : g.body) {
			switch (ins->GetOpcode()) {
			case Op::_vstatechunkload:
				++loads;
				break;
			case Op::_vchunkadd:
				++adds;
				break;
			case Op::_vstatechunkstore:
				++stores;
				break;
			default:
				CHECK(!"unexpected opcode inside the typed frame");
			}
			// EVERY chunk value in the frame must carry the width this VLEN derives.
			auto outs = ins->outputs();
			for (u8 k = 0; k < outs.size(); ++k) {
				VOperand const &o = outs[k];
				if (o.IsVGPR() || o.IsVVPR()) {
					CHECK(o.GetType() == e.vtype);
					CHECK_EQ(VTypeToSize(o.GetType()), e.bytes);
					CHECK_EQ(VTypeToSize(o.GetType()) / 4, e.lanes);
					++typed_vals;
				}
			}
		}
		CHECK_EQ(loads, 2u * e.count);
		CHECK_EQ(adds, e.count);
		CHECK_EQ(stores, e.count);
		CHECK(typed_vals >= 3u * e.count);
		// One guest register is exactly count chunks with no tail.
		CHECK_EQ(e.bytes * e.count, vlen / 8);
		CHECK(e.count <= dbt::rv32::rvvrun::kMaxChunks);
		printf("   vlen=%-5u chunk=%2u bytes  count=%u  i32 lanes=%2u  vtype=V%u  frame ops=%zu\n",
		       vlen, e.bytes, e.count, e.lanes, e.bytes * 8, g.body.size());
	}
}

// ---------------------------------------------------------------------------------------------
void Section2_NoRegression()
{
	printf("2. 512 and 1024 keep their pre-P4 shape\n");
	struct {
		u32 vlen, count;
	} const cases[2] = {{512u, 1u}, {1024u, 2u}};
	for (auto c : cases) {
		MemArena arena(1u << 20);
		u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
		Group g = FindGroup(TranslateLLVM(arena, words, c.vlen));
		CHECK_EQ(g.n_begin, 1u);
		CHECK_EQ(g.body.size(), 4u * c.count);
		for (Inst *ins : g.body) {
			auto outs = ins->outputs();
			for (u8 k = 0; k < outs.size(); ++k) {
				VOperand const &o = outs[k];
				if (o.IsVGPR() || o.IsVVPR()) {
					CHECK(o.GetType() == VType::V512);
				}
			}
		}
		printf("   vlen=%-5u -> {64,%u}, all chunk values V512 (unchanged)\n", c.vlen, c.count);
	}
}

// ---------------------------------------------------------------------------------------------
void Section3_FailClosed()
{
	printf("3. fail-closed matrix\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		{ // the route's own switch off
			MemArena a(1u << 20);
			u32 w[2] = {INSN_VSETVLI, INSN_VADD_VV};
			CHECK(!Routed(TranslateLLVM(a, w, vlen, /*ssa=*/false)));
		}
		{ // --rvv-verify
			MemArena a(1u << 20);
			u32 w[2] = {INSN_VSETVLI, INSN_VADD_VV};
			CHECK(!Routed(TranslateLLVM(a, w, vlen, true, /*verify=*/true)));
		}
	}
	// SEW != 32: an e64 vsetvli in front of the same vadd.vv.
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI_E64, INSN_VADD_VV};
		CHECK(!Routed(TranslateLLVM(a, w, vlen)));
	}
	// A VLEN that is not a whole number of chunks and one below the smallest register. Both are
	// geometry refusals and neither moved: 384 bytes-per-register is 48, which is not one of the
	// three host vector widths, and 64 is below the minimum.
	//
	// W5 (2026-09-17) TOOK 2048 AND 4096 OUT OF THIS LOOP, and they are asserted as ROUTED below
	// instead. P4's upper bound was `config::vlen_bits > 1024` written into
	// RvvQcgTypedChunkGatesOpen; W5 replaced it with the geometry's own bound (`count <=
	// kMaxChunks`), under which a 2048-bit register is four 64-byte chunks and a 4096-bit one is
	// eight. Deleting the rows rather than moving them would have left the new upper bound
	// unasserted.
	for (u32 vlen : {384u, 64u}) {
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI, INSN_VADD_VV};
		CHECK(!Routed(TranslateLLVM(a, w, vlen)));
	}
	for (u32 vlen : {2048u, 4096u}) {
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI, INSN_VADD_VV};
		CHECK(Routed(TranslateLLVM(a, w, vlen)));
	}
	printf("   ssa-off, verify, e64, VLEN 384/64 fall back; 2048/4096 route\n");
}

// ---------------------------------------------------------------------------------------------
// W5 (2026-09-17) INVERTED THIS SECTION'S CLAIM, which is the honest way to record what changed.
//
// It read "the widening is vadd.vv ONLY", and that was true of P4: vadd.vv reached
// RvvQcgTypedChunkGatesOpen(llvm_any_width=true) while every other LLVM route ended in
// RvvGenericChunkShapeAdmit, whose `vlen < 512` row refused 128/256 regardless of the gate. W5
// removed that asymmetry by making RvvRouteChunkShape the one width authority for the LLVM arm, so
// vsub.vv now routes at 128/256 for the same reason vadd.vv did.
//
// WHAT THE SECTION STILL HAS TO SHOW is that the width and the per-opcode switch are INDEPENDENT
// reasons to refuse -- that is what it was really protecting, and deleting it would have lost it.
void Section4_FamilyWidening()
{
	printf("4. the widening is the whole .vv family, not vadd.vv alone\n");
	for (u32 vlen : {128u, 256u}) {
		// vsub's own switch ON: W5 means the width no longer refuses it either.
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI, INSN_VSUB_VV};
		CHECK(Routed(TranslateLLVM(a, w, vlen, true, false, /*sub_switch=*/true)));
		MemArena b(1u << 20);
		u32 wa[2] = {INSN_VSETVLI, INSN_VADD_VV};
		CHECK(Routed(TranslateLLVM(b, wa, vlen)));
	}
	// The same route at 512, unchanged, so a build in which vsub is broken outright would not pass
	// the rows above by accident.
	{
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI, INSN_VSUB_VV};
		CHECK(Routed(TranslateLLVM(a, w, 512u, true, false, /*sub_switch=*/true)));
	}
	// AND THE PER-OPCODE SWITCH STILL REFUSES AT A NARROW WIDTH TOO, which is the half of the old
	// section that has to survive: if W5 had widened the family by dropping a switch rather than a
	// width rule, this would route.
	for (u32 vlen : {128u, 256u}) {
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI, INSN_VSUB_VV};
		CHECK(!Routed(TranslateLLVM(a, w, vlen, true, false, /*sub_switch=*/false)));
	}
	// And the second, independent reason vsub can refuse, asserted separately so the two are never
	// confused: its per-opcode switch OFF refuses even at 512, where the width is fine.
	{
		MemArena a(1u << 20);
		u32 w[2] = {INSN_VSETVLI, INSN_VSUB_VV};
		CHECK(!Routed(TranslateLLVM(a, w, 512u, true, false, /*sub_switch=*/false)));
	}
	printf("   vsub.vv (own switch on) routes at 128/256/512; switch off refuses at 128/256/512\n");
}

} // namespace

int main()
{
	printf("RVV_LLVM_NARROW_WIDTH: typed-chunk route geometry at 128/256/512/1024 (+W5: 2048/4096)\n");
	Section1_Derivation();
	Section2_NoRegression();
	Section3_FailClosed();
	Section4_FamilyWidening();
	if (g_failures) {
		fprintf(stderr, "RVV_LLVM_NARROW_WIDTH: %d check(s) FAILED\n", g_failures);
		return 1;
	}
	printf("RVV_LLVM_NARROW_WIDTH: OK: all checks passed\n");
	return 0;
}
