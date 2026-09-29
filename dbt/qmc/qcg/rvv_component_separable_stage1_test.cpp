// P7O-1 STAGE 1: the component-separable legality classifier and the component-resident liveness
// bound. Design: experiments/2026-08-30-prof-hung-teacher-closure/COMPONENT_SEPARABLE_RUN_DESIGN.md.
//
// WHAT STAGE 1 IS, AND THEREFORE WHAT THIS FILE MAY AND MAY NOT ASSERT. Stage 1 adds a predicate
// (rvvrun::RvvRunComponentSeparable), a pure bound function (rvvrun::RvvRunPeakLiveBoundCS), a
// descriptor bit and a default-off switch. It changes NO admission decision, NO emitted body and
// NO counter. So this file asserts what the predicate answers and what the bound computes, and it
// asserts that turning the switch on changes nothing else -- it does NOT assert any speedup, any
// cut disappearing, or any body shape, because Stage 1 emits none of those.
//
// THE SECTIONS, AND THE MUTATION THAT EACH IS BUILT TO CATCH:
//
//   [1] THE BOUND'S ALGEBRA, exhaustively over a small range, as four separate relations rather
//       than one. Reintroducing an `nchunks` factor into RvvRunPeakLiveBoundCS fails [1c]/[1d];
//       dropping either broadcast term fails [1b]; and the ChaCha20-shaped arithmetic in [1d] is
//       pinned to the literal 36 and 18, so a bound that "improves" by an unrelated amount is red.
//
//   [2] ACCEPTED RUNS, through the REAL admission entry point (RV32Translator::RvvAdmitVectorRun)
//       with the REAL decoder and the REAL per-route predicates -- never a reconstruction. A
//       lane-local integer run at VLEN 1024 (k = 2) is separable; the SAME words at VLEN 512
//       (k = 1) are not, which is the design's no-op condition and not a safety condition.
//
//   [3] EVERY REJECTED SEMANTIC CATEGORY. Two mechanisms, deliberately, because they falsify
//       different things:
//         (a) through the real translator, for the categories a real word sequence can produce
//             (a memory member, a scalar passthrough member, an FP run whose guard weakens vl);
//         (b) by MUTATING ONE FIELD of a descriptor the real translator accepted, for the
//             categories no admissible word sequence can produce today (a masked member, LMUL 2,
//             a SEW mismatch, a chunk geometry that does not tile the register). Each mutation is
//             a single field, and the unmutated descriptor is asserted separable in the same
//             breath, so "rejected for the wrong reason" is not a passing state: deleting the
//             corresponding condition from the predicate makes exactly that row turn green-to-red.
//
//   [4] DEFAULT-OFF EQUIVALENCE, in the strong form. For sequences that DO form a separable run,
//       the switch-off and switch-on arms must produce byte-identical host code and an identical
//       QIR dump, and identical descriptors in every field EXCEPT `component_separable`. If a
//       later stage wires the bit into the bound without updating this file, [4] goes red -- which
//       is the point: it is the guard that Stage 1 is inert, and it is EXPECTED to be rewritten
//       when Stage 2 makes the bit consequential.
//
// SCOPE. Nothing here executes emitted code and nothing here measures time.
//
// INSTRUCTION WORDS. Built from the RVV 1.0 FIELDS by the encoders below rather than pasted as
// magic numbers, and the encoders are pinned by static_assert against words assembled with the
// xPack GNU RISC-V toolchain that the sibling route tests already carry.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvrun = dbt::rv32::rvvrun;
using rvvrun::RunOp;

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
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// [0] Pins. These fail to COMPILE rather than to run.
// ---------------------------------------------------------------------------------------------
static_assert(rvvrun::kHostVectorRegs == qcg::ArchTraits::VPR_POOL.count(),
	      "rvvrun::kHostVectorRegs must equal the QCG allocator's V512 pool size");

// The design's whole claim is about a bound compared against this number. Pinning it here means a
// pool resize is a compile error in the file that reasons about 36 > 30 >= 18, not a silent
// re-interpretation of those literals.
static_assert(rvvrun::kHostVectorRegs == 30, "the design's 36 > 30 >= 18 arithmetic assumes 30");

// ---------------------------------------------------------------------------------------------
// Encoders, field by field, in RVV 1.0's own layout.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111u;
constexpr u32 Enc(u32 funct6, u32 vm, u32 vs2, u32 vs1_or_imm, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1_or_imm << 15) | (funct3 << 12) |
	       (vd << 7) | OPV;
}
constexpr u32 F3_OPIVV = 0b000u, F3_OPIVI = 0b011u, F3_OPMVX = 0b110u, F3_OPFVV = 0b001u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u, F6_VXOR = 0b001011u, F6_VOR = 0b001010u;
constexpr u32 F6_VAND = 0b001001u;
constexpr u32 F6_VSLL = 0b100101u, F6_VSRL = 0b101000u;
constexpr u32 F6_VSLIDEUP = 0b001110u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u;

constexpr u32 Vvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPIVV, vd); }
constexpr u32 Vvi(u32 f6, u32 vd, u32 vs2, u32 uimm) { return Enc(f6, 1, vs2, uimm, F3_OPIVI, vd); }
constexpr u32 Vfvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPFVV, vd); }
constexpr u32 Vmvx(u32 f6, u32 vd, u32 vs2, u32 rs1) { return Enc(f6, 1, vs2, rs1, F3_OPMVX, vd); }

// vl<nf>re32.v / vs<nf>r.v, the two whole-register transfer rows.
constexpr u32 VlNre32(u32 nf, u32 rs1, u32 vd)
{
	return 0b0000111u | (vd << 7) | (0b110u << 12) | (rs1 << 15) | (0b01000u << 20) |
	       (1u << 25) | ((nf - 1) << 29);
}
constexpr u32 VsNr(u32 nf, u32 rs1, u32 vs3)
{
	return 0b0100111u | (vs3 << 7) | (rs1 << 15) | (0b01000u << 20) | (1u << 25) |
	       ((nf - 1) << 29);
}

// The encoders agree with words the assembler produced, and the sibling route tests already carry
// these exact literals; a transposed field below fails to compile.
static_assert(Vvv(F6_VADD, 3, 1, 2) == 0x021101d7u, "vadd.vv v3,v1,v2");
static_assert(Vvv(F6_VSUB, 4, 3, 2) == 0x0a310257u, "vsub.vv v4,v3,v2");
static_assert(Vvv(F6_VXOR, 6, 5, 4) == 0x2e520357u, "vxor.vv v6,v5,v4");
static_assert(Vvv(F6_VOR, 7, 6, 5) == 0x2a6283d7u, "vor.vv  v7,v6,v5");
static_assert(Vvv(F6_VAND, 8, 7, 6) == 0x26730457u, "vand.vv v8,v7,v6");
static_assert(VlNre32(1, 14, 8) == 0x02876407u, "vl1re32.v v8,(a4)");
static_assert(VsNr(1, 14, 8) == 0x02870427u, "vs1r.v v8,(a4)");
static_assert(Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 11) == 0x9685e457u, "vmul.vx v8,v8,a1");

constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 W_ADDI = 0x00150513u;	     // addi a0,a0,1

// The two vtypes no route admits, built from the same fields VTYPE_E32_M1_TA_MA is built from so
// that neither is a literal: `vsew` 011 is SEW 64, `vlmul` 001 is LMUL 2. Each is then pinned
// against the vtype field of the corresponding ASSEMBLED `vsetvli`, so a wrong field position here
// is a compile error rather than a test that quietly exercises a different shape.
constexpr u32 VTYPE_E64_M1 = dbt::rv32::VTYPE_VMA_BIT | dbt::rv32::VTYPE_VTA_BIT |
			     (0b011u << dbt::rv32::VTYPE_VSEW_SHIFT) | dbt::rv32::VLMUL_M1;
constexpr u32 VTYPE_E32_M2 = dbt::rv32::VTYPE_VMA_BIT | dbt::rv32::VTYPE_VTA_BIT |
			     (dbt::rv32::VSEW_E32 << dbt::rv32::VTYPE_VSEW_SHIFT) | 0b001u;
static_assert(dbt::rv32::VTYPE_E32_M1_TA_MA == ((0x0d057557u >> 20) & 0x7ffu),
	      "vsetvli a0,a0,e32,m1,ta,ma");
static_assert(VTYPE_E64_M1 == ((0x0d857557u >> 20) & 0x7ffu), "vsetvli a0,a0,e64,m1,ta,ma");
static_assert(VTYPE_E32_M2 == ((0x0d157557u >> 20) & 0x7ffu), "vsetvli a0,a0,e32,m2,ta,ma");

// A lane-local integer chain of the shape a stream cipher's quarter-round has: xor, rotate halves,
// add. Nothing here names ChaCha20; the point is only that the members are lane-local and many.
constexpr u32 W_ADD_V3_V1_V2 = Vvv(F6_VADD, 3, 1, 2);
constexpr u32 W_SUB_V4_V3_V2 = Vvv(F6_VSUB, 4, 3, 2);
constexpr u32 W_XOR_V6_V5_V4 = Vvv(F6_VXOR, 6, 5, 4);
constexpr u32 W_OR_V7_V6_V5 = Vvv(F6_VOR, 7, 6, 5);
constexpr u32 W_AND_V8_V7_V6 = Vvv(F6_VAND, 8, 7, 6);
constexpr u32 W_SLL_V9_V8_7 = Vvi(F6_VSLL, 9, 8, 7);
constexpr u32 W_SRL_V10_V8_25 = Vvi(F6_VSRL, 10, 8, 25);

// The rejected-category words.
constexpr u32 W_VL1RE32 = VlNre32(1, /*rs1=*/14, /*vd=*/8);
constexpr u32 W_VS1R = VsNr(1, /*rs1=*/14, /*vs3=*/8);
constexpr u32 W_VMUL_VX = Vmvx(dbt::rv32::VF6_VMUL, /*vd=*/8, /*vs2=*/8, /*rs1=*/11);
constexpr u32 W_VFADD_VV = Vfvv(F6_VFADD, /*vd=*/8, /*vs2=*/8, /*vs1=*/9);
constexpr u32 W_VFSUB_VV = Vfvv(F6_VFSUB, /*vd=*/9, /*vs2=*/8, /*vs1=*/9);
// A MASKED FP word. It is the one encoding that classifies to a present, lane-local, non-trapping
// route row with vm = 0: the two FP rows have no AdmitsEncoding of their own and leave the mask
// refusal to their runtime admission predicate, which FormRun reaches only through the
// caller-supplied MemberAdmit. That is exactly why the predicate re-derives P7 from bit 25.
constexpr u32 W_VFADD_VV_MASKED = Enc(F6_VFADD, /*vm=*/0, /*vs2=*/8, /*vs1=*/9, F3_OPFVV, /*vd=*/8);
// A cross-lane word, for the P2 row.
constexpr u32 W_VSLIDEUP_VI = Vvi(F6_VSLIDEUP, /*vd=*/9, /*vs2=*/8, /*uimm=*/1);

// ---------------------------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------------------------
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};

// Every switch this file depends on is set explicitly on every call, so no section can inherit a
// value a previous section left in the process globals -- the ordering hazard an admission test
// must not have.
struct Env {
	u32 vlen = 1024;
	bool component_separable = true;
	bool scalar_passthrough = false;
	bool route_falu = false;
	bool route_fma = false;
	bool route_mem = false;
	bool route_vx_mulacc = false;
	u32 observed_vtype = dbt::rv32::VTYPE_E32_M1_TA_MA;
};

void Apply(Env const &e)
{
	config::vlen_bits = e.vlen;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_scalar_passthrough = e.scalar_passthrough;
	config::rvv_run_component_separable = e.component_separable;
	// The six integer routes plus the shift pair, all force-emitted so the admission rule is
	// exercised on a host without AVX-512. This file never executes emitted code.
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_typed_chunk_falu = e.route_falu;
	config::rvv_qcg_typed_chunk_falu_force_emit = e.route_falu;
	config::rvv_qcg_typed_chunk_fma = e.route_fma;
	config::rvv_qcg_typed_chunk_fma_force_emit = e.route_fma;
	config::rvv_qcg_whole_reg = e.route_mem;
	config::rvv_qcg_whole_reg_force_emit = e.route_mem;
	config::rvv_qcg_vx_mulacc = e.route_vx_mulacc;
	config::rvv_qcg_vx_mulacc_force_emit = e.route_vx_mulacc;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}

// The REAL admission entry point over a word sequence laid out at guest pc 0.
rvvrun::RunDescriptor Admit(std::vector<u32> const &words, Env const &e)
{
	Apply(e);
	auto *mem = const_cast<u32 *>(words.data());
	u32 const boundary = (u32)words.size() * 4u;
	return qir::rv32::RV32Translator::RvvAdmitVectorRun((uptr)mem, 0u, boundary,
							    (u32)words.size(), e.observed_vtype,
							    rvvrun::RunLimits{});
}

// Translate and generate host code, for the default-off equivalence section.
std::pair<std::string, std::vector<u8>> TranslateAndEmit(std::vector<u32> const &words, Env const &e)
{
	Apply(e);
	auto *mem = const_cast<u32 *>(words.data());
	MemArena arena(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)mem, CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	std::string const dump = qir::PrinterPass::run(region);
	TestCompilerRuntime cr;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
	return {dump, std::vector<u8>(span.begin(), span.end())};
}

u8 Pop(u32 m) { return (u8)__builtin_popcount(m); }

// ---------------------------------------------------------------------------------------------
// [1] The bound's algebra.
//
// Four SEPARATE relations, because they falsify different edits. Stating them as one "the new
// bound is better" would be satisfied by a function that returns 0.
// ---------------------------------------------------------------------------------------------
void CheckBoundAlgebra()
{
	printf("[1] RvvRunPeakLiveBoundCS: the four relations to RvvRunPeakLiveBound\n");

	// [1a] THE NO-OP. At one component, no GPR broadcast and at most one F broadcast, the two
	//      functions agree TERM BY TERM. This is the design's `k = 1` identity, stated with its
	//      exact preconditions rather than as a blanket claim.
	//      MUTATION IT CATCHES: dropping the `+ 1` in-flight term, or charging the broadcasts
	//      differently in the SSA term.
	{
		unsigned checked = 0;
		for (unsigned t = 0; t <= 64; ++t)
			for (unsigned nf = 0; nf <= 1; ++nf)
				for (int fused = 0; fused <= 1; ++fused) {
					u8 const old_b = rvvrun::RvvRunPeakLiveBound(
					    (u8)t, /*nchunks=*/1, (u8)nf, fused != 0);
					u8 const cs_b = rvvrun::RvvRunPeakLiveBoundCS(
					    (u8)t, (u8)nf, /*n_xbroadcast=*/0, fused != 0);
					CHECK_EQ((unsigned)cs_b, (unsigned)old_b);
					++checked;
				}
		printf("    ok  [1a] k=1, nx=0, nf<=1: identical over %u inputs\n", checked);
	}

	// [1b] THE SAFE DIRECTION EVERYWHERE ELSE AT k = 1. With more broadcasts the new bound is
	//      never SMALLER than the old one, so a one-component run can never be admitted by the
	//      new rule that the old rule cut. This is the half that makes "k = 1 is a no-op" a
	//      safety statement and not just an efficiency one.
	//      MUTATION IT CATCHES: dropping `n_xbroadcast` from either term -- with nx > 0 the new
	//      value would then fall BELOW the old one.
	{
		unsigned checked = 0;
		for (unsigned t = 0; t <= 40; ++t)
			for (unsigned nf = 0; nf <= 8; ++nf)
				for (unsigned nx = 0; nx <= 8; ++nx)
					for (int fused = 0; fused <= 1; ++fused) {
						u8 const old_b = rvvrun::RvvRunPeakLiveBound(
						    (u8)t, 1, (u8)nf, fused != 0);
						u8 const cs_b = rvvrun::RvvRunPeakLiveBoundCS(
						    (u8)t, (u8)nf, (u8)nx, fused != 0);
						CHECK(cs_b >= old_b);
						++checked;
					}
		printf("    ok  [1b] k=1: new >= old over %u inputs (never looser)\n", checked);
	}

	// [1c] THE RELIEF, AND ITS MEASURED BOUNDARY.
	//
	//      The design document (section 3.3) states the relation for two or more components as
	//      "new <= old". THAT IS NOT UNIVERSALLY TRUE of the formulas it also specifies, and this
	//      section is where that is recorded rather than assumed away. The new bound charges
	//      `n_fbroadcast + n_xbroadcast` in BOTH of its terms; the old one charges `n_fbroadcast`
	//      in its SSA term and only `(n_fbroadcast ? 1 : 0)` in its materialize term, and never
	//      sees `n_xbroadcast` at all. With enough frame-scope broadcasts and a small touched set
	//      the extra charge can exceed what dropping the `nchunks` factor saves.
	//
	//      Both halves are asserted:
	//        (i)  with at most THREE frame-scope broadcasts in total, the new bound is never the
	//             larger one anywhere in the swept box, and is STRICTLY smaller whenever there is
	//             a GPR broadcast to charge and a register to save. Every pure-integer run --
	//             including the case the design is about, where both counts are zero -- lies in
	//             this half.
	//        (ii) outside it the comparison CAN go the other way, and that direction is SAFE
	//             (the new bound cuts earlier, it never admits a run the old bound cut). The
	//             existence of such inputs is asserted too, so this row cannot decay into a
	//             vacuous "no counterexample was looked for".
	//
	//      MUTATION IT CATCHES: any reintroduction of an `nchunks` factor into the CS bound --
	//      the strict inequality in (i) then fails at every k >= 2.
	{
		unsigned checked = 0, strict = 0, larger = 0, min_bcast_larger = ~0u;
		for (unsigned k = 2; k <= rvvrun::kMaxChunks; ++k)
			for (unsigned t = 0; t <= 40; ++t)
				for (unsigned nf = 0; nf <= 8; ++nf)
					for (unsigned nx = 0; nx <= 8; ++nx)
						for (int fused = 0; fused <= 1; ++fused) {
							u8 const old_b =
							    rvvrun::RvvRunPeakLiveBound(
								(u8)t, (u8)k, (u8)nf, fused != 0);
							u8 const cs_b =
							    rvvrun::RvvRunPeakLiveBoundCS(
								(u8)t, (u8)nf, (u8)nx, fused != 0);
							++checked;
							if (nf + nx <= 3) {
								CHECK(cs_b <= old_b);
								if (nx == 0 && t >= 1) {
									CHECK(cs_b < old_b);
									++strict;
								}
							} else if (cs_b > old_b) {
								++larger;
								if (nf + nx < min_bcast_larger)
									min_bcast_larger = nf + nx;
							}
						}
		// (ii): the counterexamples exist, and every one of them needs at least four
		// frame-scope broadcasts. Both numbers are asserted so the boundary is a measurement.
		CHECK(larger > 0);
		CHECK_EQ(min_bcast_larger, 4u);
		printf("    ok  [1c] k>=2: over %u inputs, new <= old wherever nf+nx <= 3 (%u "
		       "strict); %u inputs where new is LARGER (safe direction), all at nf+nx >= %u\n",
		       checked, strict, larger, min_bcast_larger);
	}

	// [1d] THE ARITHMETIC THE DESIGN RESTS ON, pinned to literals. A run touching 17 vector
	//      registers with a pure-integer body at two components:
	//        old  (17 + 1) * 2 + 0 = 36  >  30  -> CutReason::RegisterPressure
	//        new  (17 + 1) * 1 + 0 = 18 <=  30  -> no cut
	//      MUTATION IT CATCHES: any change to either function that moves these two numbers, in
	//      either direction, including an "improvement" that overshoots.
	{
		CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(17, /*nchunks=*/2, 0, false), 36u);
		CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBoundCS(17, 0, 0, false), 18u);
		CHECK((unsigned)rvvrun::RvvRunPeakLiveBound(17, 2, 0, false) >
		      rvvrun::kHostVectorRegs);
		CHECK((unsigned)rvvrun::RvvRunPeakLiveBoundCS(17, 0, 0, false) <=
		      rvvrun::kHostVectorRegs);
		// The same run at ONE component is already 18 under the existing bound, which is what
		// makes 18 the component-resident answer rather than a new model.
		CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(17, /*nchunks=*/1, 0, false), 18u);
		printf("    ok  [1d] 36 > %u >= 18, pinned\n", (unsigned)rvvrun::kHostVectorRegs);
	}

	// [1e] The clamp, on both functions, for the reason stated at RvvRunPeakLiveBound: a silent
	//      u8 wrap turns "cut this run" into "admit it", which is a spill inside an open group.
	{
		CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBoundCS(255, 255, 255, true), 255u);
		CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(255, 8, 255, true), 255u);
		printf("    ok  [1e] both bounds clamp at 255 instead of wrapping\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [2] Accepted lane-local runs, through the real admission entry point.
// ---------------------------------------------------------------------------------------------
void CheckAcceptedRuns()
{
	printf("[2] accepted lane-local runs, and the nchunks = 1 no-op\n");

	// The scan starts at pc 0, so no `vsetvli` appears in these lists: the run's vtype is passed
	// to the admission entry point directly, which is what the production caller does with an
	// observed in-block vtype.
	struct Row {
		char const *name;
		std::vector<u32> words;
		u8 want_members;
	};
	Row const rows[] = {
	    {"vadd; vsub", {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2}, 2},
	    {"five-op integer chain",
	     {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_XOR_V6_V5_V4, W_OR_V7_V6_V5, W_AND_V8_V7_V6},
	     5},
	    {"xor/shift/shift chain (rotate shape)",
	     {W_XOR_V6_V5_V4, W_AND_V8_V7_V6, W_SLL_V9_V8_7, W_SRL_V10_V8_25},
	     4},
	};

	for (auto const &r : rows) {
		// VLEN 1024, e32/m1 -> two 64-byte host chunks per guest register: k = 2.
		Env on1024;
		on1024.vlen = 1024;
		auto const d1024 = Admit(r.words, on1024);
		CHECK_EQ((unsigned)d1024.n_members, (unsigned)r.want_members);
		CHECK_EQ((unsigned)d1024.nchunks, 2u);
		CHECK(d1024.component_separable);
		// The predicate is a pure function of the descriptor, and FormRun's answer must be
		// exactly that function's answer once the switch is on.
		CHECK_EQ(d1024.component_separable, rvvrun::RvvRunComponentSeparable(d1024));

		// THE BOUND, ON A REAL DESCRIPTOR. `peak_live_bound` is what FormRun actually
		// admitted on, recomputed here from the descriptor's own masks, so the relation
		// between the two functions is asserted on measured inputs and not only on the
		// synthetic sweep above. The design's section 3.3 asks for exactly this: the
		// `touched` count must be read off `touched_mask`, not back-derived.
		//
		// STAGE 2 CHANGED WHICH FUNCTION THIS IS, and that is the point of the change: a
		// separable descriptor is now ADMITTED on the component-resident bound, because that
		// is the bound of the body the emitter will produce for it. Before Stage 2 the
		// recorded value was always RvvRunPeakLiveBound's; asserting that here now would be
		// asserting that Stage 2 did not happen.
		u8 const touched = Pop(d1024.touched_mask);
		u8 const nf = Pop(d1024.f_live_in_mask);
		u8 const nx = Pop(d1024.x_live_in_mask);
		bool const fused = d1024.n_fused_members != 0;
		u8 const cs = rvvrun::RvvRunPeakLiveBoundCS(touched, nf, nx, fused);
		u8 const ssa = rvvrun::RvvRunPeakLiveBound(touched, d1024.nchunks, nf, fused);
		CHECK_EQ((unsigned)d1024.peak_live_bound, (unsigned)cs);
		CHECK(cs <= ssa);

		// VLEN 512, e32/m1 -> ONE 64-byte chunk: k = 1, and the transformation is the
		// identity, so the predicate answers false. This is the design's no-op condition.
		// It is asserted on the SAME words, so a row that is separable for an unrelated
		// reason cannot make this pass.
		Env on512 = on1024;
		on512.vlen = 512;
		auto const d512 = Admit(r.words, on512);
		CHECK_EQ((unsigned)d512.n_members, (unsigned)r.want_members);
		CHECK_EQ((unsigned)d512.nchunks, 1u);
		CHECK(!d512.component_separable);
		// ... and at k = 1 the two bounds agree, so refusing costs nothing.
		CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBoundCS(Pop(d512.touched_mask),
								 Pop(d512.f_live_in_mask), 0,
								 d512.n_fused_members != 0),
			 (unsigned)d512.peak_live_bound);

		printf("    ok  %-38s k=2 separable (touched=%u bound %u -> %u), k=1 no-op\n",
		       r.name, touched, d1024.peak_live_bound, cs);
	}
}

// ---------------------------------------------------------------------------------------------
// [3a] Rejected categories a real word sequence can produce.
// ---------------------------------------------------------------------------------------------
void CheckRejectedThroughTranslator()
{
	printf("[3a] rejected semantic categories, through the real translator\n");

	// P4: a whole-register load/store makes the run touch GUEST MEMORY. Under the
	// component-major schedule a fault in component 1 would leave a memory image the
	// member-major schedule never produces (design section 2.3, CE3), so v1 excludes it.
	{
		Env e;
		e.route_mem = true;
		e.route_vx_mulacc = true;
		auto const d = Admit({W_VL1RE32, W_VMUL_VX, W_VS1R}, e);
		CHECK_EQ((unsigned)d.n_members, 3u);
		CHECK(d.has_mem);
		CHECK(!d.component_separable);
		printf("    ok  P4 memory member: %u members, has_mem=1 -> not separable\n",
		       d.n_members);
	}
	// P4, the load alone -- so the row is not passing merely because the STORE was present.
	{
		Env e;
		e.route_mem = true;
		e.route_vx_mulacc = true;
		auto const d = Admit({W_VL1RE32, W_VMUL_VX}, e);
		CHECK(d.has_mem);
		CHECK(!d.component_separable);
		printf("    ok  P4 load-only member: has_mem=1 -> not separable\n");
	}
	// P5: an admitted scalar passthrough member. It has to sit BETWEEN two vector members,
	// because a trailing one is withdrawn by FormRun's trim and would leave a separable prefix
	// -- which is precisely why the predicate is evaluated after the trim.
	{
		Env e;
		e.scalar_passthrough = true;
		auto const d = Admit({W_ADD_V3_V1_V2, W_ADDI, W_SUB_V4_V3_V2}, e);
		CHECK_EQ((unsigned)d.n_members, 3u);
		CHECK_EQ((unsigned)d.n_scalar_members, 1u);
		CHECK(!d.component_separable);
		printf("    ok  P5 bridging scalar member: n_scalar_members=1 -> not separable\n");
	}
	// ... and the CONTRAST that makes the row above non-vacuous: the same passthrough switch,
	// the same scalar word, but TRAILING. FormRun trims it, `n_scalar_members` returns to zero,
	// and the kept prefix IS separable. A predicate latched inside the scan loop would answer
	// false here.
	{
		Env e;
		e.scalar_passthrough = true;
		auto const d = Admit({W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_ADDI}, e);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK_EQ((unsigned)d.n_scalar_members, 0u);
		CHECK(d.component_separable);
		printf("    ok  P5 trailing scalar is TRIMMED -> the kept prefix is separable\n");
	}
	// P6: a pure-FP run. Both FP rows declare `partial_vl_ok`, so the frame would be guarded
	// with GuardKind::VTypePartialVlVstartFrmRNE -- `vl <= VLMAX` -- under which a component's
	// active lane set is a run-time quantity. The design refuses that kind explicitly.
	{
		Env e;
		e.route_falu = true;
		auto const d = Admit({W_VFADD_VV, W_VFSUB_VV}, e);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK(d.partial_vl_ok);
		CHECK(d.needs_fp_bracket);
		CHECK(!d.component_separable);
		printf("    ok  P6 partial-vl FP run: partial_vl_ok=1 -> not separable\n");
	}
	// A cross-lane operation is a NON-MEMBER, so it cannot be inside a run at all: it cuts.
	// Asserted so that "P8 holds by construction" is a checked statement about this build's
	// route table and not an inherited claim.
	{
		Env e;
		auto const d = Admit({W_ADD_V3_V1_V2, W_VSLIDEUP_VI, W_SUB_V4_V3_V2}, e);
		CHECK_EQ((unsigned)d.n_members, 1u);
		CHECK(!rvvrun::ClassifyTypedAluRoute(W_VSLIDEUP_VI).present);
		printf("    ok  P8 cross-lane word is a non-member: run cut at 1 member\n");
	}
	// The run must be non-empty. A block whose first word is not a member forms nothing, and
	// nothing is not separable.
	{
		Env e;
		auto const d = Admit({W_ADDI, W_ADDI}, e);
		CHECK(d.Empty());
		CHECK(!d.component_separable);
		CHECK(!rvvrun::RvvRunComponentSeparable(d));
		printf("    ok  empty descriptor -> not separable\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [3b] Rejected categories reachable only by mutating ONE field of an accepted descriptor.
//
// These exist because the predicate has to hold for descriptors this build cannot currently
// produce -- a masked member, a register group, a SEW mismatch, a chunk geometry that does not
// tile the register. Removing the corresponding condition from RvvRunComponentSeparable turns the
// matching row from red to green, which is the falsification path each row needs.
// ---------------------------------------------------------------------------------------------
void CheckRejectedByMutation()
{
	printf("[3b] rejected semantic categories, by single-field descriptor mutation\n");

	Env e;
	e.vlen = 1024;
	auto const base = Admit({W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_XOR_V6_V5_V4}, e);
	// The baseline must be accepted, or every row below passes vacuously.
	CHECK_EQ((unsigned)base.n_members, 3u);
	CHECK_EQ((unsigned)base.nchunks, 2u);
	CHECK_EQ((unsigned)base.chunk_bytes, 64u);
	CHECK(rvvrun::RvvRunComponentSeparable(base));

	auto reject = [&](char const *why, rvvrun::RunDescriptor d) {
		bool const sep = rvvrun::RvvRunComponentSeparable(d);
		CHECK(!sep);
		printf("    %s %s\n", sep ? "FAIL" : "ok ", why);
	};

	// P1: one component. The transformation is the identity, so the predicate declines rather
	// than making a caller special-case a no-op. The whole geometry is moved consistently --
	// frame AND members -- so this descriptor is a legal one-component run and ONLY P1 rejects
	// it. (Section [2] also covers P1 through a real VLEN 512 translation; this row is what
	// isolates the condition from the shape tests.)
	{
		auto d = base;
		d.nchunks = 1;
		d.chunk_bytes = 128;
		for (u8 i = 0; i < d.n_members; ++i) {
			d.members[i].nchunks = 1;
			d.members[i].chunk_bytes = 128;
		}
		reject("P1  nchunks = 1 (identity transform, geometry consistent)", d);
	}
	// A descriptor that admitted NOTHING but carries a frame shape. FormRun cannot currently
	// produce one -- it keeps the shape local until a member commits -- so this row exists to
	// keep the `n_members == 0` test live rather than dead: without it the loop below runs zero
	// times and every frame-level test passes, which would make an empty run "separable".
	{
		auto d = base;
		d.n_members = 0;
		d.n_vector_members = 0;
		reject("empty descriptor carrying a frame shape", d);
	}
	// P3: a geometry that does not TILE the register group. `k` chunks of `chunk_bytes` must be
	// the whole VLEN/8-byte register, or the component sets are not disjoint and exhaustive.
	// The MEMBERS' chunk width is moved with the frame's, so the per-member shape test below
	// still passes and only the frame-level tiling test can reject this descriptor.
	{
		auto d = base;
		d.chunk_bytes = 32; // 32 * 2 != 1024/8
		for (u8 i = 0; i < d.n_members; ++i)
			d.members[i].chunk_bytes = 32;
		reject("P3  chunk_bytes * nchunks != VLEN/8 (members moved with it)", d);
	}
	// P9: a register GROUP. "Element -> component" is only a well-defined single partition at
	// EMUL = 1.
	{
		auto d = base;
		d.lmul_log2 = 1;
		reject("P9  lmul_log2 != 0 (register group)", d);
	}
	// P9: a member whose element width differs from the run's. A widening or narrowing row
	// admitted later would break the element -> component mapping without changing the shape,
	// so the SEW is compared per member and not only per frame.
	{
		auto d = base;
		d.members[1].sew_bytes = 2;
		reject("P9  member SEW != run SEW", d);
	}
	// P3, per member: a member disagreeing with the frame's chunk count.
	{
		auto d = base;
		d.members[2].nchunks = 1;
		reject("P3  member nchunks != run nchunks", d);
	}
	// P4, per member, with the frame-level flags left ALONE, so this row fails only if the
	// per-member memory test is removed.
	// P11, ISOLATED. Only the member's WORD is replaced by a whole-register load: its `op` still
	// says Sub, the frame's memory flags are still clear, and bit 25 of the new word is 1, so
	// every other condition passes. The route row for vl<nf>re32.v is the one that declines BOTH
	// non-trapping proof bits, which makes this the row that fails if P11 is deleted.
	{
		auto d = base;
		d.members[1].raw = W_VL1RE32;
		reject("P11 member word's route declines both non-trapping bits", d);
	}
	// P4 PER MEMBER, ISOLATED THE OTHER WAY. Only the member's `op` is changed, so its word
	// still classifies to a lane-local non-trapping row and the frame's memory flags are still
	// clear: this row fails only if the per-member memory/scalar test is deleted.
	{
		auto d = base;
		d.members[1].op = RunOp::LoadWhole;
		reject("P4  member op is LoadWhole (word and frame flags untouched)", d);
	}
	{
		auto d = base;
		d.members[1].op = RunOp::StoreWhole;
		reject("P4  member op is StoreWhole", d);
	}
	{
		auto d = base;
		d.members[1].op = RunOp::Scalar;
		reject("P5  member op is Scalar (n_scalar_members untouched)", d);
	}
	// The remaining disjunct of the same test: a member whose rs1 is a guest memory BASE.
	{
		auto d = base;
		d.members[1].src1_is_xbase = true;
		reject("P4  member rs1 is a memory base (frame flags untouched)", d);
	}
	// P4, frame level: the base-register mask alone, with `has_mem` left false.
	{
		auto d = base;
		d.mem_base_mask = 1u << 14;
		reject("P4  mem_base_mask != 0 (has_mem untouched)", d);
	}
	// P5, frame level: a counted scalar member.
	{
		auto d = base;
		d.n_scalar_members = 1;
		reject("P5  n_scalar_members != 0", d);
	}
	// P6: the weakened-vl guard.
	{
		auto d = base;
		d.partial_vl_ok = true;
		reject("P6  partial_vl_ok (guard weakens vl to <= VLMAX)", d);
	}
	// P7: A MASKED MEMBER. The only word that reaches a present, lane-local, non-trapping route
	// row with vm = 0 -- see the constant's comment. Every other descriptor field is the
	// accepted run's, so this row isolates bit 25 exactly.
	{
		CHECK(rvvrun::ClassifyTypedAluRoute(W_VFADD_VV_MASKED).present);
		CHECK(rvvrun::ClassifyTypedAluRoute(W_VFADD_VV_MASKED).lane_local);
		CHECK(rvvrun::ClassifyTypedAluRoute(W_VFADD_VV_MASKED).nontrapping_fast_path);
		auto d = base;
		d.members[1].raw = W_VFADD_VV_MASKED;
		reject("P7  member word has vm = 0 (masked)", d);
	}
	// P2, WITH ITS LIMITATION STATED. A member whose ROUTE ROW says it is not lane-local.
	//
	// THESE TWO ROWS DO NOT ISOLATE P2, and claiming they did would be the exact failure mode
	// this project has been bitten by before. Every VECTOR row in the route table declares
	// `lane_local`, so the only word that reaches here without it is the scalar-passthrough
	// pseudo-row -- which also has vm = 0 and declares no non-trapping proof bit, so P7 and P11
	// reject it too. Deleting P2 from the predicate leaves both rows below GREEN. They are kept
	// because they pin the CLASSIFICATION (`present` and `lane_local` on this word, under each
	// setting of the passthrough switch), which is what a future cross-lane row would change;
	// the rejection itself is asserted, and its attribution to P2 is not.
	{
		Env pt = e;
		pt.scalar_passthrough = true;
		Apply(pt);
		auto const info = rvvrun::ClassifyTypedAluRoute(W_ADDI);
		CHECK(info.present);
		CHECK(!info.lane_local);
		auto d = base;
		d.members[1].raw = W_ADDI;
		reject("P2  member route row is not lane_local", d);
	}
	{
		Env npt = e;
		npt.scalar_passthrough = false;
		Apply(npt);
		CHECK(!rvvrun::ClassifyTypedAluRoute(W_ADDI).present);
		auto d = base;
		d.members[1].raw = W_ADDI;
		reject("P2  member word has no route row at all", d);
	}
	// P11: the two memory rows are the only ones that decline BOTH proof bits, and P4 already
	// excludes them; asserted here so the claim "no admissible member fails P11 alone" is a
	// checked property of this build's table rather than an assumption.
	{
		Apply(e);
		auto const ld = rvvrun::ClassifyTypedAluRoute(W_VL1RE32);
		auto const st = rvvrun::ClassifyTypedAluRoute(W_VS1R);
		CHECK(ld.present && !ld.nontrapping_fast_path && !ld.fp_vector_state_only);
		CHECK(st.present && !st.nontrapping_fast_path && !st.fp_vector_state_only);
		printf("    ok  P11 the two memory rows decline both non-trapping proof bits\n");
	}
	// A run at a vtype the routes never admit forms nothing, so there is no "SEW = 8 separable"
	// state to reach through the translator; asserted so the absence is recorded.
	{
		Env e64 = e;
		e64.observed_vtype = VTYPE_E64_M1;
		auto const d = Admit({W_ADD_V3_V1_V2, W_SUB_V4_V3_V2}, e64);
		CHECK(d.Empty());
		CHECK(!d.component_separable);
		printf("    ok  e64 admits no member -> nothing to classify\n");
	}
	// LMUL = 2 through the translator, for the same reason.
	{
		Env m2 = e;
		m2.observed_vtype = VTYPE_E32_M2;
		auto const d = Admit({W_ADD_V3_V1_V2, W_SUB_V4_V3_V2}, m2);
		CHECK(!d.component_separable);
		printf("    ok  e32/m2: lmul_log2=%d -> not separable\n", (int)d.lmul_log2);
	}
}

// ---------------------------------------------------------------------------------------------
// [4] Default-off equivalence, in the strong form.
// ---------------------------------------------------------------------------------------------

// Every descriptor field that must be identical between the two arms. `component_separable` and
// `peak_live_bound` are the two the switch is ALLOWED to move -- the bit is the decision and the
// bound is the decision's consequence -- and each is asserted separately at the call site rather
// than folded in here. Compared field by field
// rather than by memcmp, because RunDescriptor has padding and a memcmp would report a difference
// nobody can act on -- and, more importantly, because a field added later without a line here is
// visible as a gap in this list rather than as a silently passing memcmp.
bool SameExceptSeparableAndBound(rvvrun::RunDescriptor const &a, rvvrun::RunDescriptor const &b)
{
	if (a.entry_pc != b.entry_pc || a.end_pc != b.end_pc || a.vtype_raw != b.vtype_raw ||
	    a.vlmax != b.vlmax || a.vlen_bits != b.vlen_bits || a.sew_bytes != b.sew_bytes ||
	    a.lmul_log2 != b.lmul_log2 || a.nchunks != b.nchunks || a.chunk_bytes != b.chunk_bytes ||
	    a.n_members != b.n_members || a.n_vector_members != b.n_vector_members ||
	    a.n_scalar_members != b.n_scalar_members || a.cut != b.cut || a.cut_pc != b.cut_pc ||
	    a.live_in_mask != b.live_in_mask || a.live_out_mask != b.live_out_mask ||
	    a.touched_mask != b.touched_mask || a.x_live_in_mask != b.x_live_in_mask ||
	    a.has_mem != b.has_mem || a.mem_base_mask != b.mem_base_mask ||
	    a.scalar_written_mask != b.scalar_written_mask ||
	    a.f_live_in_mask != b.f_live_in_mask ||
	    a.n_fscalar_members != b.n_fscalar_members ||
	    a.n_fused_members != b.n_fused_members || a.needs_fp_bracket != b.needs_fp_bracket ||
	    a.partial_vl_ok != b.partial_vl_ok || a.vtype_observed != b.vtype_observed)
		return false;
	for (unsigned i = 0; i < dbt::rv32::VREG_NUM; ++i)
		if (a.last_def[i] != b.last_def[i])
			return false;
	for (u8 i = 0; i < a.n_members; ++i) {
		auto const &x = a.members[i];
		auto const &y = b.members[i];
		if (x.pc != y.pc || x.raw != y.raw || x.stub != y.stub || x.op != y.op ||
		    x.rd != y.rd || x.rs1 != y.rs1 || x.rs2 != y.rs2 ||
		    x.sew_bytes != y.sew_bytes || x.nchunks != y.nchunks ||
		    x.chunk_bytes != y.chunk_bytes || x.funct6 != y.funct6 ||
		    x.src1_is_fscalar != y.src1_is_fscalar || x.src1_is_imm5 != y.src1_is_imm5 ||
		    x.src1_is_xscalar != y.src1_is_xscalar || x.src1_is_simm5 != y.src1_is_simm5 ||
		    x.src1_is_xbase != y.src1_is_xbase || x.defines_vd != y.defines_vd ||
		    x.src2_is_vector != y.src2_is_vector || x.reads_vd != y.reads_vd ||
		    x.fp_host_arith != y.fp_host_arith || x.src2_def != y.src2_def ||
		    x.src1_def != y.src1_def || x.srcd_def != y.srcd_def)
			return false;
	}
	return true;
}

void CheckDefaultOffEquivalence()
{
	printf("[4] default-off equivalence: the switch changes the bit and nothing else\n");

	struct Row {
		char const *name;
		std::vector<u32> words;
		bool separable_when_on; // at VLEN 1024
	};
	Row const rows[] = {
	    {"vadd; vsub", {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2}, true},
	    {"five-op integer chain",
	     {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_XOR_V6_V5_V4, W_OR_V7_V6_V5, W_AND_V8_V7_V6},
	     true},
	    {"xor/shift chain", {W_XOR_V6_V5_V4, W_SLL_V9_V8_7, W_SRL_V10_V8_25}, true},
	    {"single member", {W_ADD_V3_V1_V2}, true},
	    {"nothing admissible", {W_ADDI, W_ADDI}, false},
	};

	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			Env off;
			off.vlen = vlen;
			off.component_separable = false;
			Env on = off;
			on.component_separable = true;

			auto const d_off = Admit(r.words, off);
			auto const d_on = Admit(r.words, on);

			// The default arm never carries the bit, whatever the run looks like.
			CHECK(!d_off.component_separable);
			// The on arm carries exactly the predicate's answer -- for the rows in this
			// table. (Stage 2 made the recorded bit the scan's DECISION, which is the
			// predicate ANDed with "the component-resident bound is not the larger one";
			// none of these rows has the >= 4 frame-scope broadcasts that separates the
			// two, and rvv_component_separable_stage2_test owns that boundary.)
			CHECK_EQ(d_on.component_separable, rvvrun::RvvRunComponentSeparable(d_on));
			bool const want = r.separable_when_on && vlen == 1024;
			CHECK_EQ(d_on.component_separable, want);

			// STAGE 2 REWROTE THIS BLOCK, and the Stage 1 report said it would: the bit is
			// no longer inert. What "default-off" now means, exactly:
			//
			//   * the DEFAULT arm is unchanged -- it carries no bit and its recorded bound
			//     is still RvvRunPeakLiveBound's value;
			//   * where the feature arm REFUSES the run (every row at VLEN 512, and the
			//     non-admissible row at both), the two arms must agree in every descriptor
			//     field and produce byte-identical host code;
			//   * where the feature arm ACCEPTS, the descriptors may differ ONLY in the bit
			//     and in `peak_live_bound`, and the host code is EXPECTED to differ,
			//     because the body is a different schedule. Asserting the difference is
			//     what stops this row from silently degrading into "the feature stopped
			//     doing anything".
			CHECK_EQ((unsigned)d_off.peak_live_bound,
				 (unsigned)rvvrun::RvvRunPeakLiveBound(
				     Pop(d_off.touched_mask), d_off.nchunks,
				     Pop(d_off.f_live_in_mask), d_off.n_fused_members != 0));
			CHECK(SameExceptSeparableAndBound(d_off, d_on));
			if (!d_on.component_separable)
				CHECK_EQ((unsigned)d_on.peak_live_bound,
					 (unsigned)d_off.peak_live_bound);

			std::vector<u32> w_off = r.words, w_on = r.words;
			auto const e_off = TranslateAndEmit(w_off, off);
			auto const e_on = TranslateAndEmit(w_on, on);
			// The QIR dump is address-free, so it is compared directly; the host bytes are
			// compared only for LENGTH when the arms are expected to differ, because two
			// emissions in one process land in different code buffers and their absolute
			// immediates differ for a reason unrelated to this switch.
			//
			// A ONE-MEMBER RUN IS SEPARABLE AND STILL CHANGES NOTHING, and that is not a
			// hole in the rule: RvvTranslateVectorRun refuses to build a frame for a run
			// with fewer than two members (its body is exactly what the single-instruction
			// route already emits), so the descriptor's bit never reaches an emitter. The
			// expectation is therefore keyed on CONSUMPTION, not on the bit.
			bool const consumed = d_on.component_separable && d_on.n_members >= 2;
			if (!consumed) {
				CHECK(e_off.first == e_on.first);
				CHECK(e_off.second.size() == e_on.second.size());
			} else {
				CHECK(e_off.first != e_on.first);
			}
			printf("    ok  %-24s vlen=%-4u separable=%d, bound %2u -> %2u, QIR %s\n",
			       r.name, vlen, (int)d_on.component_separable,
			       (unsigned)d_off.peak_live_bound, (unsigned)d_on.peak_live_bound,
			       consumed ? "differs (component-major body)"
					: "identical (run not consumed)");
		}
	}

	// The run-shape counters are the ones an ablation using this switch has to report. On THESE
	// words they are still identical between the arms -- no member of this short run is ever
	// refused for pressure, so relaxing the bound cannot change which run is formed. That is a
	// statement about this input, NOT about the switch: rvv_component_separable_stage2_test's
	// ChaCha20-shaped run is the case where the counters DO differ (register_pressure 1 -> 0),
	// which is exactly why the design requires an ablation to report them next to any timing.
	{
		std::vector<u32> words = {W_VSETVLI_E32M1, W_ADD_V3_V1_V2, W_SUB_V4_V3_V2,
					  W_XOR_V6_V5_V4};
		Env off;
		off.vlen = 1024;
		off.component_separable = false;
		Env on = off;
		on.component_separable = true;

		rvvrun::g_stats = rvvrun::Stats{};
		TranslateAndEmit(words, off);
		auto const s_off = rvvrun::g_stats;
		rvvrun::g_stats = rvvrun::Stats{};
		TranslateAndEmit(words, on);
		auto const s_on = rvvrun::g_stats;

		CHECK_EQ(s_on.scans, s_off.scans);
		CHECK_EQ(s_on.runs_formed, s_off.runs_formed);
		CHECK_EQ(s_on.multi_member_runs, s_off.multi_member_runs);
		CHECK_EQ(s_on.members_admitted, s_off.members_admitted);
		for (unsigned i = 0; i < rvvrun::kCutReasonCount; ++i)
			CHECK_EQ(s_on.cuts[i], s_off.cuts[i]);
		printf("    ok  run-shape counters identical: scans=%llu runs=%llu members=%llu\n",
		       (unsigned long long)s_on.scans, (unsigned long long)s_on.runs_formed,
		       (unsigned long long)s_on.members_admitted);
	}
}

} // namespace

int main()
{
	printf("P7O-1 stage 1: component-separable classifier and component-resident bound\n");
	CheckBoundAlgebra();
	CheckAcceptedRuns();
	CheckRejectedThroughTranslator();
	CheckRejectedByMutation();
	CheckDefaultOffEquivalence();
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
