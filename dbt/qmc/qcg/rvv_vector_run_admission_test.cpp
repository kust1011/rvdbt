// R1A.3a: the vector-run (VRUN) descriptor and its translation-time admission/cut rule, verified
// against the REAL per-route admission predicates, the REAL shared decoder, and the REAL
// translator -- not against a copy of any of them.
//
// WHAT THIS FILE HAS TO PROVE, AND WHY EACH PART EXISTS
//
//   1. THE RULE IS NOT AN OPCODE PAIR. Section [2] forms a two-member run for EVERY one of the 36
//      ordered pairs over the six accepted typed integer ALU routes, at both VLENs, and asserts the
//      descriptors are identical in every field that is not the operation itself. If the substrate
//      contained a hardcoded `vadd+vsub` (or any other pair), 34 of those 36 would fail. Section
//      [1] additionally pins three named pairs -- add->sub, mul->xor, or->and -- to the exact
//      descriptor contents, so a rule that merely "forms something" for all pairs is not enough.
//
//   2. MEMBERSHIP IS THE DECODER'S OWN ROUTING RULE. Section [3] sweeps the ENTIRE OP-V funct3 x
//      funct6 x vm encoding space (1024 words) and asserts a word is admitted as a run member iff
//      the shared `insn::Decoder` routes it to one of the six ops. That is what makes "masked
//      vadd.vv", "vadd.vx", the mask/cross-lane/reduction/permutation families and every FP vector
//      op non-members WITHOUT this file, or the substrate, naming any of them.
//
//   3. A1 GOES THROUGH THE ROUTE'S OWN PREDICATE. Section [4] turns each route's OWN switch off in
//      turn and asserts the run truncates at exactly that member; it also drives --rvv-direct,
//      --rvv-verify, the LLVM backend gate and unsupported shapes (SEW=64, LMUL=2, VLEN=256). If
//      admission were re-implemented inside the run substrate, a route could be off and still be
//      admitted into a run.
//
//   4. BARRIERS CUT. Section [5] puts each barrier class between two otherwise-admissible members
//      and asserts the run stops before it, with the expected reason: `vset{i}vl{i}` (guard state),
//      vector load/store (memory), helper-only/mask/cross-lane/reduction/permutation OP-V
//      (unsupported), branch/jump (block boundary), `ecall` and an illegal word (trap), scalar ALU,
//      and scalar FP memory.
//
//   5. PEAK LIVENESS IS NOT "DISTINCT GUEST REGISTERS". Section [7] contains an INDEPENDENT
//      simulator of the fast body's schedule and asserts the production bound never falls below the
//      simulated peak, over a matrix that includes every architecturally legal operand overlap. It
//      also asserts a case where the simulated peak EXCEEDS distinct_registers * k, which is
//      exactly the quantity R1A.2b section 5 forbids using -- so replacing the bound with that
//      quantity fails here.
//
//   6. THE FLAG'S EFFECT HAS AN EXACT BOUNDARY. Section [9] translates real word sequences with the
//      switch off and on. Where NO two-member run can be admitted -- a barrier between the members,
//      an unadmitted vtype, a scalar-only block -- the QIR dump and the emitted host bytes must be
//      byte-identical. Where a run IS admitted, R1A.3b's code generator makes them differ, and the
//      difference must be exactly a multi-member frame. Both directions are asserted, so the
//      section fails either if the flag leaks into a sequence it must not touch or if it stops
//      taking effect on one it must.
//
// SCOPE. Nothing here executes emitted code and nothing here measures time. This file is about the
// ADMISSION rule only; R1A.3b's consumer of the descriptor -- the single guard, the SSA-preserving
// fast body and the ordered whole-run fallback -- is verified in
// qmc/qcg/rvv_vector_run_codegen_test.cpp, and section [9] below is the seam between the two.
//
// INSTRUCTION WORDS. Every constant below was produced by assembling the mnemonic with the xPack
// GNU RISC-V toolchain (`riscv-none-elf-gcc 14.2.0`, `-march=rv32imafdv`) and reading the encoding
// back out of `objdump -d`; the listings are preserved under the checkpoint's raw/ directory. They
// are not hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvrun = dbt::rv32::rvvrun;
using rvvrun::CutReason;
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
// [0] The host vector register budget is PINNED to the backend's own pool.
//
// rvvrun::kHostVectorRegs is restated in rv32_vrun.h rather than included from arch_traits.h,
// which drags asmjit into the guest translator. This assertion is what stops the two from drifting:
// if the QCG allocator's V512 pool ever changes size, this file fails to COMPILE.
// ---------------------------------------------------------------------------------------------
static_assert(rvvrun::kHostVectorRegs == qcg::ArchTraits::VPR_POOL.count(),
	      "rvvrun::kHostVectorRegs must equal the QCG allocator's V512 pool size");

// ---------------------------------------------------------------------------------------------
// Instruction words -- see the file header for provenance.
// ---------------------------------------------------------------------------------------------
constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u;  // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 W_VSETVLI_E64M1 = 0x0d857557u;  // vsetvli a0,a0,e64,m1,ta,ma
constexpr u32 W_VSETVLI_E32M2 = 0x0d157557u;  // vsetvli a0,a0,e32,m2,ta,ma
constexpr u32 W_VSETVL = 0x80b57557u;	      // vsetvl   a0,a0,a1
constexpr u32 W_VSETIVLI = 0xcd027557u;	      // vsetivli a0,4,e32,m1,ta,ma

constexpr u32 W_VADD_V3_V1_V2 = 0x021101d7u; // vadd.vv v3,v1,v2
constexpr u32 W_VSUB_V4_V3_V2 = 0x0a310257u; // vsub.vv v4,v3,v2
constexpr u32 W_VMUL_V5_V3_V4 = 0x963222d7u; // vmul.vv v5,v3,v4
constexpr u32 W_VXOR_V6_V5_V4 = 0x2e520357u; // vxor.vv v6,v5,v4
constexpr u32 W_VOR_V7_V6_V5 = 0x2a6283d7u;  // vor.vv  v7,v6,v5
constexpr u32 W_VAND_V8_V7_V6 = 0x26730457u; // vand.vv v8,v7,v6

constexpr u32 W_VADD_V3_V3_V2 = 0x023101d7u; // vadd.vv v3,v3,v2   (vd == vs2)
constexpr u32 W_VSUB_V3_V3_V2 = 0x0a3101d7u; // vsub.vv v3,v3,v2   (vd == vs2)
constexpr u32 W_VADD_V1_V2_V3 = 0x022180d7u; // vadd.vv v1,v2,v3
constexpr u32 W_VSUB_V4_V5_V6 = 0x0a530257u; // vsub.vv v4,v5,v6
constexpr u32 W_VADD_V3_V1_V3 = 0x021181d7u; // vadd.vv v3,v1,v3   (vd == vs1)
constexpr u32 W_VADD_V3_V3_V3 = 0x023181d7u; // vadd.vv v3,v3,v3   (vd == vs1 == vs2)
constexpr u32 W_VADD_V3_V1_V1 = 0x021081d7u; // vadd.vv v3,v1,v1   (vs1 == vs2)
constexpr u32 W_VADD_MASKED = 0x001101d7u;   // vadd.vv v3,v1,v2,v0.t

// Six distinct-register members, used by the pressure section.
constexpr u32 W_VADD_V3_V1_V2b = 0x021101d7u;	// vadd.vv v3,v1,v2
constexpr u32 W_VSUB_V6_V4_V5 = 0x0a428357u;	// vsub.vv v6,v4,v5
constexpr u32 W_VMUL_V9_V7_V8 = 0x967424d7u;	// vmul.vv v9,v7,v8
constexpr u32 W_VXOR_V12_V10_V11 = 0x2ea58657u; // vxor.vv v12,v10,v11

// The one-operand-shape word for each of the six routes, all writing v3 from v1/v2. Used wherever
// the test needs "the same instruction shape, a different operation".
constexpr u32 W_OP_ADD = 0x021101d7u; // vadd.vv v3,v1,v2
constexpr u32 W_OP_SUB = 0x0a1101d7u; // vsub.vv v3,v1,v2
constexpr u32 W_OP_MUL = 0x961121d7u; // vmul.vv v3,v1,v2
constexpr u32 W_OP_XOR = 0x2e1101d7u; // vxor.vv v3,v1,v2
constexpr u32 W_OP_OR = 0x2a1101d7u;  // vor.vv  v3,v1,v2
constexpr u32 W_OP_AND = 0x261101d7u; // vand.vv v3,v1,v2

constexpr u32 W_VLE32 = 0x0205e087u;	 // vle32.v  v1,(a1)
constexpr u32 W_VSE32 = 0x0205e0a7u;	 // vse32.v  v1,(a1)
constexpr u32 W_VRGATHER = 0x321101d7u;	 // vrgather.vv v3,v1,v2
constexpr u32 W_VSLIDEUP = 0x3a10b1d7u;	 // vslideup.vi v3,v1,1
constexpr u32 W_VREDSUM = 0x021121d7u;	 // vredsum.vs  v3,v1,v2
constexpr u32 W_VMAND = 0x661121d7u;	 // vmand.mm    v3,v1,v2
constexpr u32 W_VFREDUSUM = 0x061111d7u; // vfredusum.vs v3,v1,v2
constexpr u32 W_ADDI = 0x00150513u;	 // addi a0,a0,1
constexpr u32 W_BEQ = 0x00b50063u;	 // beq  a0,a1,.
constexpr u32 W_JAL = 0x000000efu;	 // jal  ra,.
constexpr u32 W_ECALL = 0x00000073u;	 // ecall
constexpr u32 W_FLW = 0x0005a007u;	 // flw  ft0,0(a1)
constexpr u32 W_ILL = 0x00000000u;	 // not a valid encoding -> Op::_ill

// ---------------------------------------------------------------------------------------------
// Config harness. Every knob any admission predicate reads is set on EVERY call, so no case can
// inherit another's global state. The base typed-chunk switch enables its production umbrella
// (six integer routes plus FP ALU/FMA); independently switched route families remain off.
// ---------------------------------------------------------------------------------------------
struct AdmitConfig {
	bool vector_run = true;
	bool rvv_direct = true;
	bool rvv_verify = false;
	bool aot_use_llvm = false;
	bool rvv_vector_ssa = false;
	bool route_add = true;
	bool route_sub = true;
	bool route_mul = true;
	bool route_xor = true;
	bool route_or = true;
	bool route_and = true;
	// The dedicated FP switches are pinned off, but the base typed-chunk switch above is the
	// production umbrella and therefore still enables FP ALU/FMA admission. Section [3] checks
	// that exact CLI contract. The dedicated switches remain explicit here so no test inherits
	// process-global state.
	bool route_falu = false;
	bool route_fma = false;
	// Admission sweeps must be host-independent.  These bypass only the AVX-512 feature probe;
	// they do not enable either dedicated route (the umbrella contract is tested separately).
	bool fp_force_emit = true;
	// The six QCG routes each carry a host AVX-512F probe. This test never executes emitted code
	// -- it never even emits any, except in section [9] -- so the probes are bypassed and the
	// admission rule is exercised on hosts without AVX-512.
	bool force_emit = true;
	u32 vlen_bits = 512;
	u32 observed_vtype = dbt::rv32::VTYPE_E32_M1_TA_MA;
	// The MEMBERSHIP-rule ablation factor, pinned ON for the same reason the FP route switches
	// above are pinned OFF: section [5]'s `addi` row asserts that a scalar bump between two
	// vector members is BRIDGED, which is a statement about the on-arm rule. Leaving it to
	// whatever the shipped default or a previous section put in the process globals would make
	// this file's result depend on execution order. The off-arm is driven explicitly by
	// rvv_lmul2_run_test.cpp.
	bool scalar_passthrough = true;
	// C2l. THE BODY SELECTOR, carried here so section [11] can vary it and every other section
	// pins it OFF explicitly rather than inheriting whatever a previous section left in the
	// process globals -- the reason stated for the FP route switches above.
	bool body_materialize = false;
	// C2l. The four routes section [11] needs and no other section does. Off by default, and set
	// explicitly in ApplyConfig for the same determinism reason.
	bool route_shift = false;
	bool route_vmv = false;
	bool route_whole_reg = false;
	bool route_vx_mulacc = false;
	rvvrun::RunLimits limits{};
};

void ApplyConfig(AdmitConfig const &c)
{
	config::rvv_vector_run = c.vector_run;
	config::rvv_direct = c.rvv_direct;
	config::rvv_verify = c.rvv_verify;
	config::aot_use_llvm = c.aot_use_llvm;
	config::rvv_vector_ssa = c.rvv_vector_ssa;
	config::vlen_bits = c.vlen_bits;
	config::rvv_qcg_typed_chunk = c.route_add;
	config::rvv_qcg_typed_chunk_sub = c.route_sub;
	config::rvv_qcg_typed_chunk_mul = c.route_mul;
	config::rvv_qcg_typed_chunk_xor = c.route_xor;
	config::rvv_qcg_typed_chunk_or = c.route_or;
	config::rvv_qcg_typed_chunk_and = c.route_and;
	config::rvv_qcg_typed_chunk_force_emit = c.force_emit;
	config::rvv_qcg_typed_chunk_sub_force_emit = c.force_emit;
	config::rvv_qcg_typed_chunk_mul_force_emit = c.force_emit;
	config::rvv_qcg_typed_chunk_xor_force_emit = c.force_emit;
	config::rvv_qcg_typed_chunk_or_force_emit = c.force_emit;
	config::rvv_qcg_typed_chunk_and_force_emit = c.force_emit;
	config::rvv_qcg_typed_chunk_falu = c.route_falu;
	config::rvv_qcg_typed_chunk_falu_force_emit = c.fp_force_emit;
	config::rvv_qcg_typed_chunk_fma = c.route_fma;
	config::rvv_qcg_typed_chunk_fma_force_emit = c.fp_force_emit;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_run_scalar_passthrough = c.scalar_passthrough;
	config::rvv_run_body_materialize = c.body_materialize;
	config::rvv_qcg_typed_chunk_shift = c.route_shift;
	config::rvv_qcg_typed_chunk_shift_force_emit = c.route_shift && c.force_emit;
	config::rvv_qcg_typed_chunk_vmv = c.route_vmv;
	config::rvv_qcg_typed_chunk_vmv_force_emit = c.route_vmv && c.force_emit;
	config::rvv_qcg_whole_reg = c.route_whole_reg;
	config::rvv_qcg_whole_reg_force_emit = c.route_whole_reg && c.force_emit;
	config::rvv_qcg_vx_mulacc = c.route_vx_mulacc;
	config::rvv_qcg_vx_mulacc_force_emit = c.route_vx_mulacc && c.force_emit;
}

// Run the REAL admission entry point over a word sequence laid out at guest pc 0.
rvvrun::RunDescriptor Admit(std::vector<u32> const &words, AdmitConfig const &c)
{
	ApplyConfig(c);
	// The words vector is the guest memory image; guest pc P reads words[P/4].
	auto *mem = const_cast<u32 *>(words.data());
	u32 const boundary = (u32)words.size() * 4u;
	return qir::rv32::RV32Translator::RvvAdmitVectorRun((uptr)mem, 0u, boundary,
							    (u32)words.size(), c.observed_vtype,
							    c.limits);
}

// ---------------------------------------------------------------------------------------------
// [1] Three named pairs, pinned field by field.
// ---------------------------------------------------------------------------------------------

struct ExpectMember {
	u32 pc;
	u32 raw;
	RunOp op;
	RuntimeStubId stub;
	u8 rd, rs1, rs2;
	i8 src2_def, src1_def;
};

void CheckMember(char const *tag, unsigned idx, rvvrun::RunMember const &m, ExpectMember const &e,
		 u8 want_nchunks)
{
	if (m.pc != e.pc || m.raw != e.raw || m.op != e.op || m.stub != e.stub || m.rd != e.rd ||
	    m.rs1 != e.rs1 || m.rs2 != e.rs2 || m.src2_def != e.src2_def ||
	    m.src1_def != e.src1_def || m.nchunks != want_nchunks) {
		fprintf(stderr,
			"  FAIL %s member %u: pc=%08x raw=%08x op=%s stub=%u v%u,v%u,v%u "
			"def(%d,%d) k=%u\n",
			tag, idx, m.pc, m.raw, rvvrun::RunOpName(m.op), (unsigned)m.stub, m.rd, m.rs2,
			m.rs1, m.src2_def, m.src1_def, m.nchunks);
		fprintf(stderr,
			"       want: pc=%08x raw=%08x op=%s stub=%u v%u,v%u,v%u def(%d,%d) k=%u\n",
			e.pc, e.raw, rvvrun::RunOpName(e.op), (unsigned)e.stub, e.rd, e.rs2, e.rs1,
			e.src2_def, e.src1_def, want_nchunks);
		++g_failures;
	}
}

void CheckNamedPairs()
{
	printf("[1] three named two-instruction pairs, pinned field by field\n");

	struct Case {
		char const *name;
		u32 w0, w1;
		ExpectMember m0, m1;
		u32 live_in, live_out, touched;
	};
	// Each pair chains: the second member's vs2 is the first member's destination, so `src2_def`
	// must be 0 and that register must NOT be a live-in. `vs1` is a run live-in in all three.
	Case const cases[] = {
	    {"add->sub (v3=v1+v2; v4=v3-v2)",
	     W_VADD_V3_V1_V2,
	     W_VSUB_V4_V3_V2,
	     {0, W_VADD_V3_V1_V2, RunOp::Add, RuntimeStubId::id_rv32_vadd_vv, 3, 2, 1, -1, -1},
	     {4, W_VSUB_V4_V3_V2, RunOp::Sub, RuntimeStubId::id_rv32_vialu, 4, 2, 3, 0, -1},
	     (1u << 1) | (1u << 2),
	     (1u << 3) | (1u << 4),
	     (1u << 1) | (1u << 2) | (1u << 3) | (1u << 4)},
	    {"mul->xor (v5=v3*v4; v6=v5^v4)",
	     W_VMUL_V5_V3_V4,
	     W_VXOR_V6_V5_V4,
	     {0, W_VMUL_V5_V3_V4, RunOp::Mul, RuntimeStubId::id_rv32_vimul, 5, 4, 3, -1, -1},
	     {4, W_VXOR_V6_V5_V4, RunOp::Xor, RuntimeStubId::id_rv32_vialu, 6, 4, 5, 0, -1},
	     (1u << 3) | (1u << 4),
	     (1u << 5) | (1u << 6),
	     (1u << 3) | (1u << 4) | (1u << 5) | (1u << 6)},
	    {"or->and (v7=v6|v5; v8=v7&v6)",
	     W_VOR_V7_V6_V5,
	     W_VAND_V8_V7_V6,
	     {0, W_VOR_V7_V6_V5, RunOp::Or, RuntimeStubId::id_rv32_vialu, 7, 5, 6, -1, -1},
	     {4, W_VAND_V8_V7_V6, RunOp::And, RuntimeStubId::id_rv32_vialu, 8, 6, 7, 0, -1},
	     (1u << 5) | (1u << 6),
	     (1u << 7) | (1u << 8),
	     (1u << 5) | (1u << 6) | (1u << 7) | (1u << 8)},
	};

	for (auto const &cs : cases) {
		for (u32 vlen : {512u, 1024u}) {
			AdmitConfig c;
			c.vlen_bits = vlen;
			u8 const k = (u8)(vlen / 512);
			auto const d = Admit({cs.w0, cs.w1}, c);

			CHECK_EQ((unsigned)d.n_members, 2u);
			if (d.n_members != 2) {
				fprintf(stderr, "  (%s vlen=%u cut=%s)\n", cs.name, vlen,
					rvvrun::CutReasonName(d.cut));
				continue;
			}
			CheckMember(cs.name, 0, d.members[0], cs.m0, k);
			CheckMember(cs.name, 1, d.members[1], cs.m1, k);
			CHECK_EQ(d.entry_pc, 0u);
			CHECK_EQ(d.end_pc, 8u);
			CHECK_EQ(d.vtype_raw, dbt::rv32::VTYPE_E32_M1_TA_MA);
			CHECK_EQ(d.vlmax, vlen / 32u);
			CHECK_EQ((unsigned)d.sew_bytes, 4u);
			CHECK_EQ((unsigned)d.nchunks, (unsigned)k);
			CHECK_EQ(d.live_in_mask, cs.live_in);
			CHECK_EQ(d.live_out_mask, cs.live_out);
			CHECK_EQ(d.touched_mask, cs.touched);
			CHECK_EQ((unsigned)d.last_def[cs.m0.rd], 0u);
			CHECK_EQ((unsigned)d.last_def[cs.m1.rd], 1u);
			// Four touched registers, so the bound is (4+1)*k. Stated as the literal
			// expected number rather than by calling the production function, so a
			// change to that function does not silently change what is asserted.
			CHECK_EQ((unsigned)d.peak_live_bound, 5u * k);
			// M2E: the prototype two-member cap is gone, so this two-word stream now
			// stops because the SUPPLIED instructions ran out (the harness passes
			// words.size() as the block budget), not because a member limit was hit.
			CHECK_EQ(d.cut, CutReason::InsnBudget);
			printf("    ok  %-32s vlen=%u k=%u live_in=%#x live_out=%#x peak<=%u\n",
			       cs.name, vlen, k, d.live_in_mask, d.live_out_mask,
			       (unsigned)d.peak_live_bound);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [2] ALL 36 ordered pairs over the six routes obey ONE rule.
// ---------------------------------------------------------------------------------------------

struct RouteRow {
	char const *name;
	u32 word; // writes v3 from vs2=v1, vs1=v2
	RunOp op;
	RuntimeStubId stub;
};

constexpr RouteRow kRoutes[] = {
    {"vadd.vv", W_OP_ADD, RunOp::Add, RuntimeStubId::id_rv32_vadd_vv},
    {"vsub.vv", W_OP_SUB, RunOp::Sub, RuntimeStubId::id_rv32_vialu},
    {"vmul.vv", W_OP_MUL, RunOp::Mul, RuntimeStubId::id_rv32_vimul},
    {"vxor.vv", W_OP_XOR, RunOp::Xor, RuntimeStubId::id_rv32_vialu},
    {"vor.vv", W_OP_OR, RunOp::Or, RuntimeStubId::id_rv32_vialu},
    {"vand.vv", W_OP_AND, RunOp::And, RuntimeStubId::id_rv32_vialu},
};

void CheckAllOrderedPairs()
{
	printf("[2] all 36 ordered pairs over the six routes form the same two-member run\n");
	unsigned ok = 0;
	for (auto const &a : kRoutes) {
		for (auto const &b : kRoutes) {
			for (u32 vlen : {512u, 1024u}) {
				AdmitConfig c;
				c.vlen_bits = vlen;
				u8 const k = (u8)(vlen / 512);
				auto const d = Admit({a.word, b.word}, c);
				bool good = d.n_members == 2 && d.members[0].op == a.op &&
					    d.members[1].op == b.op && d.members[0].stub == a.stub &&
					    d.members[1].stub == b.stub && d.nchunks == k &&
					    // Both members are `v3 = v1 op v2`, so member 1 reads the
					    // value member 0 defined: vs2 == v1 is a live-in, vs1 == v2
					    // is a live-in, and v3 is written twice.
					    d.live_in_mask == ((1u << 1) | (1u << 2)) &&
					    d.live_out_mask == (1u << 3) && d.last_def[3] == 1 &&
					    d.members[0].src2_def == -1 && d.members[1].src2_def == -1 &&
					    d.peak_live_bound == 4u * k;
				if (!good) {
					fprintf(stderr,
						"  FAIL pair %s -> %s vlen=%u: n=%u cut=%s "
						"live_in=%#x live_out=%#x\n",
						a.name, b.name, vlen, (unsigned)d.n_members,
						rvvrun::CutReasonName(d.cut), d.live_in_mask,
						d.live_out_mask);
					++g_failures;
				} else {
					++ok;
				}
			}
		}
	}
	printf("    ok  %u/72 (36 ordered pairs x 2 VLENs) formed an identical-shaped run\n", ok);
	CHECK_EQ(ok, 72u);
}

// ---------------------------------------------------------------------------------------------
// [3] Membership IS the shared decoder's routing decision -- swept over the whole OP-V space.
// ---------------------------------------------------------------------------------------------

// Minimal Decoder Provider whose `_##name` members are the Op enum values, so Decode returns the
// decoded opcode directly. Same trick the six route tests use; it exercises the REAL decoder.
struct OpProvider {
#define OP(name, format_, flags_) static constexpr dbt::rv32::insn::Op _##name = dbt::rv32::insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

dbt::rv32::insn::Op DecodeWord(u32 word)
{
	u32 w = word;
	return dbt::rv32::insn::Decoder<OpProvider>::Decode(&w);
}

bool IsUmbrellaRoutedOp(dbt::rv32::insn::Op op)
{
	using Op32 = dbt::rv32::insn::Op;
	return op == Op32::_vadd_vv || op == Op32::_vsub_vv || op == Op32::_vmul_vv ||
	       op == Op32::_vxor_vv || op == Op32::_vor_vv || op == Op32::_vand_vv ||
	       op == Op32::_vfalu || op == Op32::_vfma;
}

void CheckDecoderIsTheRule()
{
	printf("[3] OP-V sweep: admitted IFF the shared decoder reaches an umbrella-enabled route\n");
	// Fixed operand fields vd=v3, vs1=v2, vs2=v1; funct3 and funct6 and vm swept exhaustively.
	// 0x1010111 is the OP-V major opcode.
	unsigned n_member = 0, n_reject = 0, mismatches = 0;
	for (u32 f6 = 0; f6 < 64; ++f6) {
		for (u32 f3 = 0; f3 < 8; ++f3) {
			for (u32 vm = 0; vm < 2; ++vm) {
				u32 const word = (f6 << 26) | (vm << 25) | (1u << 20) | (2u << 15) |
						 (f3 << 12) | (3u << 7) | 0b1010111u;
				AdmitConfig c;
				auto const d = Admit({word}, c);
				// The base typed-chunk switch is the production umbrella for the six integer
				// routes and the FP ALU/FMA routes.  The latter are decode classes whose exact
				// legal funct6/form set is already decided by the shared decoder.  Shift, move,
				// whole-register and .vx routes have independent switches and remain off here.
				bool const want = vm == 1u && IsUmbrellaRoutedOp(DecodeWord(word));
				bool const got = d.n_members == 1;
				if (want != got) {
					fprintf(stderr,
						"  FAIL word %08x (f6=%02x f3=%u vm=%u): decoder says "
						"%s, run says %s (cut=%s)\n",
						word, f6, f3, vm, want ? "member" : "not",
						got ? "member" : "not", rvvrun::CutReasonName(d.cut));
					++mismatches;
					++g_failures;
				}
				want ? ++n_member : ++n_reject;
			}
		}
	}
	printf("    ok  1024 OP-V encodings swept: %u members, %u non-members, %u mismatches\n",
	       n_member, n_reject, mismatches);
	// Six integer .vv encodings plus every legal unmasked FP ALU/FMA encoding admitted
	// by the shared decoder at the pinned e32,m1 shape.
	CHECK_EQ(n_member, 42u);
	CHECK_EQ(mismatches, 0u);
}

// ---------------------------------------------------------------------------------------------
// [4] A1 is the route's OWN predicate: flags, backend and shape.
// ---------------------------------------------------------------------------------------------

void SetRouteFlag(AdmitConfig &c, RunOp op, bool on)
{
	switch (op) {
	case RunOp::Add:
		c.route_add = on;
		break;
	case RunOp::Sub:
		c.route_sub = on;
		break;
	case RunOp::Mul:
		c.route_mul = on;
		break;
	case RunOp::Xor:
		c.route_xor = on;
		break;
	case RunOp::Or:
		c.route_or = on;
		break;
	case RunOp::And:
		c.route_and = on;
		break;
	case RunOp::None:
	default:
		break;
	}
}

void CheckRouteOwnPredicate()
{
	printf("[4] A1 goes through each route's own predicate\n");

	// (a) Turning OFF the SECOND member's route truncates the run to one member, at that member,
	//     with RouteNotAdmitted -- for every one of the six, and with every other route left on.
	for (auto const &second : kRoutes) {
		for (auto const &first : kRoutes) {
			if (first.op == second.op)
				continue; // covered by (b)
			AdmitConfig c;
			SetRouteFlag(c, second.op, false);
			auto const d = Admit({first.word, second.word}, c);
			CHECK_EQ((unsigned)d.n_members, 1u);
			CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
			CHECK_EQ(d.cut_pc, 4u);
			CHECK_EQ(d.end_pc, 4u);
		}
	}
	printf("    ok  each route's own switch off -> run truncates at that member (30 pairs)\n");

	// (b) Turning off a route with BOTH members using it forms no run at all.
	for (auto const &r : kRoutes) {
		AdmitConfig c;
		SetRouteFlag(c, r.op, false);
		auto const d = Admit({r.word, r.word}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
	}
	printf("    ok  each route's own switch off, both members -> no run (6 routes)\n");

	// (c) The translator-level gates.
	{
		AdmitConfig c;
		c.vector_run = false;
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::Disabled);
	}
	{
		AdmitConfig c;
		c.rvv_direct = false;
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::Disabled);
	}
	{
		AdmitConfig c;
		c.rvv_verify = true;
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::Disabled);
	}
	printf("    ok  --rvv-vector-run/--rvv-direct/--rvv-verify gates\n");

	// (d) BACKEND. Under the LLVM backend EVERY route in kRoutes now admits only with
	//     --rvv-vector-ssa, and none is QCG-only any more. This is not a rule this file states: it
	//     is what those routes' own predicates do, observed through the run.
	//
	//     T1b MOVED vmul.vv OUT OF THE QCG-ONLY GROUP, T1d vxor.vv, T1e vor.vv and T1f vand.vv --
	//     which empties it. This file changed each time only because those predicates changed, and
	//     the section is kept rather than deleted because it now asserts the OTHER direction: that
	//     --rvv-vector-ssa is still REQUIRED by all six, so a later edit cannot make one of them
	//     admit without it. RvvRunMemberChunks calls each opcode's own single-instruction
	//     admission predicate verbatim, so when T1b gave vmul.vv an LLVM gate the run's view of it
	//     followed automatically -- which is exactly the property this section exists to observe. It
	//     does NOT change what a CONSUMED run does at any setting: RvvTranslateVectorRun refuses
	//     every run while config::aot_use_llvm is set, which is precisely when an LLVM gate can be
	//     non-zero, so the descriptors below are formed and counted but never lowered.
	{
		AdmitConfig c;
		c.aot_use_llvm = true;
		c.rvv_vector_ssa = false;
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
	}
	{
		AdmitConfig c;
		c.aot_use_llvm = true;
		c.rvv_vector_ssa = true;
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK_EQ(d.members[0].op, RunOp::Add);
		CHECK_EQ(d.members[1].op, RunOp::Sub);
	}
	// T1b gave vmul.vv an LLVM gate and T1d gave vxor.vv one, so under this backend both now behave
	// like add and sub -- closed without --rvv-vector-ssa, open with it. BOTH polarities are checked
	// for each, so a row fails either if its gate were dropped or if it stopped requiring the
	// vector-SSA switch. kRoutes[2] is vmul.vv, [3] vxor.vv, [4] vor.vv and [5] vand.vv.
	// T1e adds kRoutes[4] (vor.vv) and T1f kRoutes[5] (vand.vv), which completes the set: every
	// route in kRoutes now behaves the same way under this backend.
	for (auto const &r : {kRoutes[2], kRoutes[3], kRoutes[4], kRoutes[5]}) {
		{
			AdmitConfig c;
			c.aot_use_llvm = true;
			c.rvv_vector_ssa = false;
			auto const d = Admit({r.word, r.word}, c);
			CHECK_EQ((unsigned)d.n_members, 0u);
			CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
		}
		{
			AdmitConfig c;
			c.aot_use_llvm = true;
			c.rvv_vector_ssa = true;
			auto const d = Admit({r.word, r.word}, c);
			CHECK_EQ((unsigned)d.n_members, 2u);
			CHECK_EQ(d.members[0].op, r.op);
			CHECK_EQ(d.members[1].op, r.op);
		}
	}
	printf("    ok  LLVM backend: all six routes follow --rvv-vector-ssa; none stays QCG-only\n");

	// (e) SHAPE. Every axis the routes' shared shape rule closes.
	{
		// SEW=64: supported vtype, LMUL=1, but no route admits sew_bytes != 4.
		AdmitConfig c;
		c.observed_vtype = 0b011u << 3; // e64, m1, tu, mu -- vsew=011, vlmul=000
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
	}
	{
		// LMUL=2 reaches the route, then fails the aligned-register-group rule (v3 is odd).
		AdmitConfig c;
		c.observed_vtype = (0b010u << 3) | 0b001u; // e32, m2
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, CutReason::RegGroupIllegal);
	}
	{
		// VLEN=256. M2C made the vadd route width-correct, so vadd IS admitted here as ONE
		// 32-byte chunk -- and vsub, which is still 512-bit-chunk-only, is not. The run
		// therefore admits the add and cuts at the sub. This is the asymmetry the shape
		// carries: two routes can both be "admitted at k=1" and still disagree about width.
		AdmitConfig c;
		c.vlen_bits = 256;
		auto const d = Admit({W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 1u);
		CHECK_EQ((unsigned)d.nchunks, 1u);
		CHECK_EQ((unsigned)d.chunk_bytes, 32u);
		CHECK_EQ((unsigned)d.members[0].chunk_bytes, 32u);
		CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
	}
	printf("    ok  SEW=64 / integer LMUL=2 route refused; VLEN=256 admits the width-correct add only\n");
	config::vlen_bits = 512;
}

// ---------------------------------------------------------------------------------------------
// [5] Barriers cut, each with its own reason.
// ---------------------------------------------------------------------------------------------

void CheckBarriers()
{
	printf("[5] barrier negatives: [member, barrier, member] -> one member\n");
	struct Row {
		char const *name;
		u32 word;
		CutReason want;
	};
	Row const rows[] = {
	    // Guard state: all three vset forms write vtype/vl, which the run's single guard compares.
	    {"vsetvli", W_VSETVLI_E32M1, CutReason::GuardStateWrite},
	    {"vsetvl", W_VSETVL, CutReason::GuardStateWrite},
	    {"vsetivli", W_VSETIVLI, CutReason::GuardStateWrite},
	    // Vector memory: can really trap, and touches guest memory.
	    {"vle32.v", W_VLE32, CutReason::VectorMemory},
	    {"vse32.v", W_VSE32, CutReason::VectorMemory},
	    // Helper-only / non-lane-separable OP-V.
	    {"vadd.vv masked", W_VADD_MASKED, CutReason::UnsupportedVector},
	    {"vrgather.vv (permutation)", W_VRGATHER, CutReason::UnsupportedVector},
	    {"vslideup.vi (cross-lane)", W_VSLIDEUP, CutReason::UnsupportedVector},
	    {"vredsum.vs (reduction)", W_VREDSUM, CutReason::UnsupportedVector},
	    {"vmand.mm (mask)", W_VMAND, CutReason::UnsupportedVector},
	    // P7M-A: `vfredusum.vs` is an FP REDUCTION -- it has no typed chunk route in any build,
	    // so it is still reached through the classifier's default "not a member" arm.
	    {"vfredusum.vs (fp reduction)", W_VFREDUSUM, CutReason::UnsupportedVector},
	    // Control flow and traps: a run must not cross a QIR block boundary.
	    {"beq", W_BEQ, CutReason::ControlFlow},
	    {"jal", W_JAL, CutReason::ControlFlow},
	    {"ecall", W_ECALL, CutReason::TrapInsn},
	    {"illegal word", W_ILL, CutReason::TrapInsn},
	    // Scalar.
	    {"addi", W_ADDI, CutReason::ScalarInsn},
	    {"flw", W_FLW, CutReason::ScalarFpMemory},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			AdmitConfig c;
			c.vlen_bits = vlen;
			auto const d = Admit({W_VADD_V3_V1_V2, r.word, W_VSUB_V4_V3_V2}, c);
			if (r.word == W_ADDI) {
				CHECK_EQ((unsigned)d.n_members, 3u);
				CHECK_EQ((unsigned)d.n_vector_members, 2u);
				CHECK_EQ((unsigned)d.n_scalar_members, 1u);
				CHECK_EQ(d.end_pc, 12u);
			} else {
				CHECK_EQ((unsigned)d.n_members, 1u);
				CHECK_EQ(d.cut, r.want);
				CHECK_EQ(d.cut_pc, 4u);
				CHECK_EQ(d.end_pc, 4u);
				// The barrier must not have leaked into the run's dataflow.
				CHECK_EQ(d.live_out_mask, 1u << 3);
			}
		}
		printf("    ok  %-28s -> %s\n", r.name, rvvrun::CutReasonName(r.want));
	}

	// A barrier at the very FIRST position forms no run at all -- the same rule, with nothing
	// admitted before it.
	for (auto const &r : rows) {
		AdmitConfig c;
		auto const d = Admit({r.word, W_VADD_V3_V1_V2}, c);
		CHECK_EQ((unsigned)d.n_members, 0u);
		CHECK_EQ(d.cut, r.want);
		CHECK_EQ(d.cut_pc, 0u);
	}
	printf("    ok  every barrier at position 0 -> no run (%zu classes)\n",
	       sizeof(rows) / sizeof(rows[0]));
}

// ---------------------------------------------------------------------------------------------
// [6] Length, boundary and budget cuts.
// ---------------------------------------------------------------------------------------------

void CheckLengthAndBoundary()
{
	printf("[6] max members, region boundary and instruction budget\n");
	std::vector<u32> const four = {W_OP_ADD, W_OP_SUB, W_OP_MUL, W_OP_XOR};

	{
		// M2E: no prototype cap any more. All four legal members are admitted and the run
		// stops on the block budget the harness supplied.
		AdmitConfig c;
		auto const d = Admit(four, c);
		CHECK_EQ((unsigned)d.n_members, 4u);
		CHECK_EQ(d.cut, CutReason::InsnBudget);
		CHECK_EQ(d.end_pc, 16u);
		CHECK_EQ(d.cut_pc, 16u);
	}
	{
		// The limit is a parameter of the substrate, not a rule baked into it: raising it
		// admits exactly the members that were already legal, in order.
		AdmitConfig c;
		c.limits.max_members = 4;
		auto const d = Admit(four, c);
		CHECK_EQ((unsigned)d.n_members, 4u);
		CHECK_EQ(d.members[0].op, RunOp::Add);
		CHECK_EQ(d.members[1].op, RunOp::Sub);
		CHECK_EQ(d.members[2].op, RunOp::Mul);
		CHECK_EQ(d.members[3].op, RunOp::Xor);
		// The length limit is checked before the range boundary, so a run that exactly fills
		// its budget reports the limit.
		CHECK_EQ(d.cut, CutReason::MaxMembers);
		CHECK_EQ(d.end_pc, 16u);
		// v3 is written by all four; the last write is member 3.
		CHECK_EQ(d.live_out_mask, 1u << 3);
		CHECK_EQ((unsigned)d.last_def[3], 3u);
	}
	{
		// With length and budget both to spare, the same four members stop at the ip range's
		// end instead -- so the three limits are three separate rules, not one.
		ApplyConfig(AdmitConfig{});
		std::vector<u32> words = four;
		auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		    (uptr)words.data(), 0u, 16u, 64u, dbt::rv32::VTYPE_E32_M1_TA_MA,
		    rvvrun::RunLimits{rvvrun::kMaxDescriptorMembers, rvvrun::kHostVectorRegs});
		CHECK_EQ((unsigned)d.n_members, 4u);
		CHECK_EQ(d.cut, CutReason::RegionBoundary);
		CHECK_EQ(d.cut_pc, 16u);
		CHECK_EQ(d.end_pc, 16u);
	}
	{
		// Region boundary at 4 bytes: only the first word is inside the ip range.
		ApplyConfig(AdmitConfig{});
		std::vector<u32> words = four;
		auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		    (uptr)words.data(), 0u, 4u, 64u, dbt::rv32::VTYPE_E32_M1_TA_MA,
		    rvvrun::RunLimits{4, rvvrun::kHostVectorRegs});
		CHECK_EQ((unsigned)d.n_members, 1u);
		CHECK_EQ(d.cut, CutReason::RegionBoundary);
	}
	{
		// Translation-block instruction budget of 1.
		ApplyConfig(AdmitConfig{});
		std::vector<u32> words = four;
		auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		    (uptr)words.data(), 0u, 16u, 1u, dbt::rv32::VTYPE_E32_M1_TA_MA,
		    rvvrun::RunLimits{4, rvvrun::kHostVectorRegs});
		CHECK_EQ((unsigned)d.n_members, 1u);
		CHECK_EQ(d.cut, CutReason::InsnBudget);
	}
	printf("    ok  max_members / region boundary / insn budget\n");
}

// ---------------------------------------------------------------------------------------------
// [7] PEAK SSA LIVENESS -- the production bound versus an independent simulation.
// ---------------------------------------------------------------------------------------------

// An INDEPENDENT simulation of the fast body's schedule, written from the R1A.2 section 3.4/3.5
// description rather than from the production code. It counts, at every program point, how many
// distinct component values are simultaneously live:
//
//   * a source read binds the register's CURRENT value, loading it if the run has not produced it;
//   * a destination definition is live SIMULTANEOUSLY with the sources of the same operation --
//     it cannot be given a register that one of its own inputs still occupies unless that input
//     dies there, which the allocator is not required to arrange;
//   * a value stops being live when its register's current value is replaced.
//
// This is what "peak SSA liveness" means for this body, and it is the quantity R1A.2b section 5
// says must NOT be approximated by the number of distinct guest registers.
unsigned SimulatePeakLive(rvvrun::RunDescriptor const &d)
{
	unsigned const k = d.nchunks;
	// live[reg][chunk] -- 1 when the register's current value for that chunk is materialized as
	// a host vector register inside the run.
	bool live[dbt::rv32::VREG_NUM][rvvrun::kMaxChunks] = {};
	auto count = [&]() {
		unsigned n = 0;
		for (auto const &r : live)
			for (unsigned c = 0; c < k; ++c)
				n += r[c] ? 1u : 0u;
		return n;
	};
	unsigned peak = 0;
	for (unsigned i = 0; i < d.n_members; ++i) {
		auto const &m = d.members[i];
		// pass 1: both sources of every chunk, before any destination is written.
		for (unsigned c = 0; c < k; ++c) {
			live[m.rs2][c] = true;
			live[m.rs1][c] = true;
			peak = std::max(peak, count());
		}
		// pass 2: each destination, live at the same point as its own two sources.
		for (unsigned c = 0; c < k; ++c) {
			bool const overwrites = live[m.rd][c];
			// The destination is a NEW value; if the register already had one, both are
			// live at this point.
			peak = std::max(peak, count() + (overwrites ? 1u : 0u));
			live[m.rd][c] = true;
			peak = std::max(peak, count());
		}
	}
	return peak;
}

unsigned DistinctRegisterCount(rvvrun::RunDescriptor const &d)
{
	return (unsigned)__builtin_popcount(d.touched_mask);
}

void CheckPeakLiveness()
{
	printf("[7] peak-liveness bound vs an independent schedule simulation\n");
	struct Row {
		char const *name;
		std::vector<u32> words;
	};
	Row const rows[] = {
	    {"disjoint single", {W_VADD_V3_V1_V2}},
	    {"vd==vs2 single", {W_VADD_V3_V3_V2}},
	    {"vd==vs1 single", {W_VADD_V3_V1_V3}},
	    {"vd==vs1==vs2 single", {W_VADD_V3_V3_V3}},
	    {"vs1==vs2 single", {W_VADD_V3_V1_V1}},
	    {"chained pair", {W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}},
	    {"overlapping chained pair", {W_VADD_V3_V3_V2, W_VSUB_V3_V3_V2}},
	    {"independent pair", {W_VADD_V1_V2_V3, W_VSUB_V4_V5_V6}},
	    {"six distinct registers", {W_VADD_V3_V1_V2b, W_VSUB_V6_V4_V5}},
	    {"same op twice", {W_OP_ADD, W_OP_ADD}},
	};
	unsigned strict_cases = 0;
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			AdmitConfig c;
			c.vlen_bits = vlen;
			auto const d = Admit(r.words, c);
			CHECK_EQ((unsigned)d.n_members, (unsigned)r.words.size());
			if (d.n_members != r.words.size())
				continue;
			unsigned const sim = SimulatePeakLive(d);
			unsigned const distinct = DistinctRegisterCount(d) * d.nchunks;
			// THE OBLIGATION: the admission bound must never be BELOW the real peak, or a
			// run would be admitted that the allocator has to spill -- and a spill inside
			// an open typed chunk group is a Panic, not a slowdown.
			CHECK(d.peak_live_bound >= sim);
			if (d.peak_live_bound < sim) {
				fprintf(stderr, "  (%s vlen=%u: bound=%u sim=%u)\n", r.name, vlen,
					(unsigned)d.peak_live_bound, sim);
			}
			// THE FORBIDDEN FORMULATION: `distinct guest registers * k`. Count the cases
			// where it is strictly smaller than the real peak; the assertion below
			// requires there to be some, which is what makes this section fail if the
			// production bound is replaced by that quantity.
			if (sim > distinct)
				++strict_cases;
			printf("    ok  %-28s vlen=%u bound=%2u sim=%2u distinct*k=%2u\n", r.name,
			       vlen, (unsigned)d.peak_live_bound, sim, distinct);
		}
	}
	// Every legal operand overlap produces a program point where a destination and the source it
	// overwrites are both live, so `distinct * k` is not a bound. If this ever reaches zero, the
	// simulation stopped modelling the def/source overlap and the section proves nothing.
	CHECK(strict_cases > 0);
	printf("    ok  %u/%zu configurations have peak > distinct_registers*k\n", strict_cases,
	       2 * (sizeof(rows) / sizeof(rows[0])));

	// The production bound is, by construction, strictly greater than the forbidden quantity for
	// every non-empty run. Stated directly so a change to the formula that keeps the tests above
	// passing by luck still fails here.
	for (unsigned touched = 1; touched <= 24; ++touched) {
		for (u8 k : {(u8)1, (u8)2}) {
			CHECK(rvvrun::RvvRunPeakLiveBound((u8)touched, k) > touched * k);
		}
	}
	printf("    ok  bound is strictly above the forbidden touched*k quantity\n");

	// R1A.3d. THE BOUND NOW COVERS BOTH BODIES, and which one it takes must not depend on the
	// body mode -- if it did, arms B and C could form different runs and the ablation would have
	// two factors instead of one.
	//
	//   ssa body          peak <= (touched + 1) * k
	//   materialize body  peak <= 3 * k, because every member reads BOTH sources of every chunk
	//                     before defining any destination, independently of `touched`
	//
	// so the production bound is the max. The second term binds exactly when `touched <= 1`.
	for (unsigned touched = 1; touched <= 24; ++touched) {
		for (u8 k : {(u8)1, (u8)2, (u8)4, (u8)8}) {
			unsigned const want = std::max((touched + 1u) * k, 3u * k);
			CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound((u8)touched, k), want);
		}
	}
	// The crossover is real and executed, not an unreachable line: at touched == 1 the
	// materialize term is strictly larger, and at touched >= 2 the SSA term is at least as large.
	CHECK(rvvrun::RvvRunPeakLiveBound(1, 4) == 12);  // 3k = 12 > (1+1)k = 8
	CHECK(rvvrun::RvvRunPeakLiveBound(2, 4) == 12);  // (2+1)k = 12 == 3k
	CHECK(rvvrun::RvvRunPeakLiveBound(3, 4) == 16);  // (3+1)k = 16 > 3k
	// AND IT CHANGES NOTHING AT ANY SUPPORTED SHAPE, which is the reason it is safe to land in
	// the same checkpoint that measures with it: the bound only cuts a run above
	// kHostVectorRegs, and with k <= 2 the new term is at most 6.
	for (unsigned touched = 0; touched <= 31; ++touched) {
		for (u8 k : {(u8)1, (u8)2}) {
			bool const cut_new = rvvrun::RvvRunPeakLiveBound((u8)touched, k) >
					     rvvrun::kHostVectorRegs;
			bool const cut_old = (touched + 1u) * k > rvvrun::kHostVectorRegs;
			CHECK(cut_new == cut_old);
		}
	}
	printf("    ok  bound is max((touched+1)*k, 3*k); the new term binds at touched<=1 and cuts "
	       "no run at any supported VLEN\n");
}

// ---------------------------------------------------------------------------------------------
// [8] The register-pressure cut.
// ---------------------------------------------------------------------------------------------

void CheckPressure()
{
	printf("[8] register-pressure cut at its exact boundary\n");
	// Two members touching six distinct registers: bound = (6+1)*k.
	std::vector<u32> const six = {W_VADD_V3_V1_V2b, W_VSUB_V6_V4_V5};
	for (u32 vlen : {512u, 1024u}) {
		u8 const k = (u8)(vlen / 512);
		u8 const need = (u8)(7u * k);
		{
			AdmitConfig c;
			c.vlen_bits = vlen;
			c.limits.host_vector_regs = need;
			auto const d = Admit(six, c);
			CHECK_EQ((unsigned)d.n_members, 2u);
			CHECK_EQ((unsigned)d.peak_live_bound, (unsigned)need);
		}
		{
			AdmitConfig c;
			c.vlen_bits = vlen;
			c.limits.host_vector_regs = (u8)(need - 1);
			auto const d = Admit(six, c);
			// One member fits ((3+1)*k) and the second does not; the run stops BEFORE the
			// member rather than admitting it and leaving the allocator to spill.
			CHECK_EQ((unsigned)d.n_members, 1u);
			CHECK_EQ(d.cut, CutReason::RegisterPressure);
			CHECK_EQ(d.cut_pc, 4u);
			CHECK_EQ((unsigned)d.peak_live_bound, 4u * k);
		}
		{
			// Too tight even for the first member: no run at all, no member half-recorded.
			AdmitConfig c;
			c.vlen_bits = vlen;
			c.limits.host_vector_regs = (u8)(4u * k - 1u);
			auto const d = Admit(six, c);
			CHECK_EQ((unsigned)d.n_members, 0u);
			CHECK_EQ(d.cut, CutReason::RegisterPressure);
			CHECK_EQ((unsigned)d.peak_live_bound, 0u);
			CHECK_EQ(d.live_in_mask, 0u);
			CHECK_EQ(d.live_out_mask, 0u);
		}
		printf("    ok  vlen=%u: admits at %u host vector regs, cuts at %u\n", vlen, need,
		       need - 1);
	}
	// At the production budget the prototype's two-member runs always fit, which is why the
	// boundary above is exercised with an explicit budget rather than by constructing a run long
	// enough to exhaust 30 registers. Recorded, not hidden: the pressure rule is real code on a
	// path this checkpoint's PROTOTYPE SCOPE does not reach.
	{
		AdmitConfig c;
		auto const d = Admit(six, c);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK(d.peak_live_bound <= rvvrun::kHostVectorRegs);
	}
	printf("    ok  at the production budget (%u) a two-member run is never cut for pressure\n",
	       (unsigned)rvvrun::kHostVectorRegs);

	// The rule is not scope-limited, though, and this is where that is shown: four members over
	// twelve distinct registers at VLEN=1024 need (12+1)*2 = 26, which fits the real 30-register
	// pool -- while a 25-register budget cuts the run at its fourth member, after three members
	// whose own bound was (9+1)*2 = 20. Same rule, same code path, at the production budget's
	// order of magnitude.
	{
		std::vector<u32> const twelve = {W_VADD_V3_V1_V2b, W_VSUB_V6_V4_V5, W_VMUL_V9_V7_V8,
						 W_VXOR_V12_V10_V11};
		AdmitConfig c;
		c.vlen_bits = 1024;
		c.limits.max_members = 4;
		auto const d = Admit(twelve, c);
		CHECK_EQ((unsigned)d.n_members, 4u);
		CHECK_EQ((unsigned)d.peak_live_bound, 26u);
		CHECK(d.peak_live_bound <= rvvrun::kHostVectorRegs);
		CHECK(SimulatePeakLive(d) <= d.peak_live_bound);

		AdmitConfig c2 = c;
		c2.limits.host_vector_regs = 25;
		auto const d2 = Admit(twelve, c2);
		CHECK_EQ((unsigned)d2.n_members, 3u);
		CHECK_EQ(d2.cut, CutReason::RegisterPressure);
		CHECK_EQ((unsigned)d2.peak_live_bound, 20u);
		printf("    ok  four members / twelve registers at VLEN=1024: 26 needed, cut at 25\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [9] The existing single-instruction route is bit-identical with the switch off and on.
// ---------------------------------------------------------------------------------------------

// C4e (2026-09-14). ONE FIXED CODE BUFFER FOR EVERY ARM, AND THAT IS WHAT MAKES [9]'s
// "identical where no run forms" MEAN ANYTHING.
//
// This runtime used to hand back a per-call `std::vector`'s data pointer, so the two arms of [9]
// were emitted at two different heap addresses. QEmit embeds ABSOLUTE addresses (the helper stub
// table, and intra-blob references computed from the address the runtime returned), so the two
// arms' bytes then differ in exactly those immediates for a reason that has nothing to do with the
// switch under test. It passed only as long as the allocator happened to reuse one address: adding
// a single byte to InstRVVTypedChunkBegin elsewhere in the tree was enough to separate them, and
// the failure was TWO BYTES of one immediate inside a guest program of three `addi` -- a row with
// no vector instruction in it at all.
//
// The same reasoning and the same fix are already recorded in
// qmc/qcg/rvv_component_separable_stage2_test.cpp, which measured 62 differing bytes out of 2552
// while the QIR dump was identical. The buffer is reused, so each arm's bytes must be COPIED OUT
// before the next emission -- which is what TranslateAndEmit already does.
alignas(64) inline u8 g_fixed_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		if (sz > sizeof(g_fixed_code_buf))
			Panic("run-admission test: code buffer too small");
		return g_fixed_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
};

// Translate `words` through the REAL translator and return (QIR dump, emitted host bytes).
std::pair<std::string, std::vector<u8>> TranslateAndEmit(std::vector<u32> &words, bool vector_run,
							u32 vlen_bits)
{
	AdmitConfig c;
	c.vector_run = vector_run;
	c.vlen_bits = vlen_bits;
	ApplyConfig(c);

	MemArena arena(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	std::string const dump = qir::PrinterPass::run(region);

	TestCompilerRuntime cr;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
	return {dump, std::vector<u8>(span.begin(), span.end())};
}

// The number of typed chunk frames that cover more than one guest instruction.
unsigned CountRunFrames(Region *region)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
				n += static_cast<InstRVVTypedChunkBegin *>(&ins)->n_members > 1;
	return n;
}

void CheckRouteInvariance()
{
	printf("[9] the switch's exact boundary: identical where no run forms, a run frame where one does\n");
	struct Row {
		char const *name;
		std::vector<u32> words;
		unsigned want_runs; // multi-member frames expected with the switch ON
	};
	Row const rows[] = {
	    // A run IS admitted: R1A.3b consumes both members into one guarded frame.
	    {"vsetvli; vadd; vsub", {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, 1},
	    // M2E: one MAXIMAL run of six, not three prototype-capped pairs.
	    {"vsetvli; six-op mixed run",
	     {W_VSETVLI_E32M1, W_OP_ADD, W_OP_SUB, W_OP_MUL, W_OP_XOR, W_OP_OR, W_OP_AND}, 1},
	    {"no vsetvli; vadd; vsub", {W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, 1},
	    // No run can be admitted, so the switch must change nothing at all.
	    {"vsetvli; vadd; vle; vadd", {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VLE32, W_OP_ADD}, 0},
	    {"vsetvli e64; vadd; vsub", {W_VSETVLI_E64M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, 0},
	    {"vsetvli e32,m2; vadd; vsub", {W_VSETVLI_E32M2, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, 0},
	    {"scalar only", {W_ADDI, W_ADDI, W_ADDI}, 0},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			std::vector<u32> w_off = r.words;
			std::vector<u32> w_on = r.words;
			MemArena arena_off(1u << 20), arena_on(1u << 20);
			auto const off = TranslateAndEmit(w_off, false, vlen);
			auto const on = TranslateAndEmit(w_on, true, vlen);
			bool const same_ir = off.first == on.first;
			bool const same_code = off.second == on.second;

			// With the switch OFF no frame may ever cover more than one instruction --
			// that is the "accepted single-instruction route is untouched" half, and it
			// holds for every row including the ones a run would otherwise be built from.
			{
				MemArena arena(1u << 20);
				std::vector<u32> w = r.words;
				ApplyConfig(AdmitConfig{});
				config::rvv_vector_run = false;
				config::vlen_bits = vlen;
				CompilerJob::IpRangesSet ranges = {{0u, (u32)w.size() * 4u}};
				CompilerJob job(nullptr, (uptr)w.data(), CodeSegment(0u, 0x1000u),
						std::move(ranges));
				CHECK_EQ(CountRunFrames(CompilerGenRegionIR(&arena, job)), 0u);
			}
			// With the switch ON, exactly the expected number of run frames.
			{
				MemArena arena(1u << 20);
				std::vector<u32> w = r.words;
				ApplyConfig(AdmitConfig{});
				config::rvv_vector_run = true;
				config::vlen_bits = vlen;
				CompilerJob::IpRangesSet ranges = {{0u, (u32)w.size() * 4u}};
				CompilerJob job(nullptr, (uptr)w.data(), CodeSegment(0u, 0x1000u),
						std::move(ranges));
				CHECK_EQ(CountRunFrames(CompilerGenRegionIR(&arena, job)),
					 r.want_runs);
			}

			if (r.want_runs == 0) {
				CHECK(same_ir);
				CHECK(same_code);
				if (!same_ir) {
					fprintf(stderr,
						"  (%s vlen=%u) QIR differs:\n--- off ---\n%s\n--- on "
						"---\n%s\n",
						r.name, vlen, off.first.c_str(), on.first.c_str());
				}
				printf("    ok  %-30s vlen=%-4u no run admitted -> identical (%zu "
				       "host bytes)\n",
				       r.name, vlen, on.second.size());
			} else {
				// A run was built, so the two must NOT be identical. Asserting the
				// difference is what keeps this row from silently degrading into a
				// vacuous "they happen to match" if consumption ever stopped working.
				CHECK(!same_ir);
				CHECK(!same_code);
				printf("    ok  %-30s vlen=%-4u %u run frame(s) -> %zu vs %zu host "
				       "bytes\n",
				       r.name, vlen, r.want_runs, off.second.size(),
				       on.second.size());
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [11] C2l: THE BODY SELECTOR IS INVISIBLE TO ADMISSION.
//
// `config.h` has claimed since R1A.3d that "rvv_vector_run_admission_test.cpp asserts that" the
// body selector never reaches FormRun, any admission predicate or the descriptor. C2i found that
// no such assertion existed, and C2j found the claim to be FALSE: RvvRunMemberChunks refused the
// move, the OPMVX pair and the whole-register pair whenever `--rvv-run-body=materialize` was set,
// because the materialize arm had no body for them. The two arms therefore formed different runs
// from the same guest code, which is precisely what the R1A.3d ablation cannot tolerate and why
// C2j's G5 gate ("runs_formed / multi_member_runs / members_admitted equal cell by cell") could
// not be evaluated.
//
// This section is the missing assertion, and it is written against the REAL admission entry point
// rather than against emitted code, so it constrains the descriptor itself. FAILURE PATH: restore
// any `config::rvv_run_body_materialize` disjunct in RvvRunMemberChunks and the row covering that
// route fails on `n_members` immediately.
// ---------------------------------------------------------------------------------------------

// vsll.vi / vsrl.vi, the two shift-immediate rows.
constexpr u32 W_VSLL_V4_V3_3 = 0x9601b257u; // vsll.vi v4,v3,3
constexpr u32 W_VSRL_V5_V4_7 = 0xa243b2d7u; // vsrl.vi v5,v4,7
// The four unmasked move forms (funct6 010111, vm = 1, vs2 = 0).
constexpr u32 W_VMV_V_I_V3_5 = 0x5e02b1d7u; // vmv.v.i  v3,5
constexpr u32 W_VMV_V_X_V4_A1 = 0x5e05c257u; // vmv.v.x  v4,a1
constexpr u32 W_VFMV_V_F_V5_FA2 = 0x5e0652d7u; // vfmv.v.f v5,fa2
constexpr u32 W_VMV_V_V_V6_V5 = 0x5e028357u; // vmv.v.v  v6,v5
// The OPMVX multiply/accumulate pair and the whole-register transfer pair.
constexpr u32 W_VMUL_VX_V3_V1_A1 = 0x9615e1d7u;  // vmul.vx  v3,v1,a1
constexpr u32 W_VMACC_VX_V4_A1_V3 = 0xb635e257u; // vmacc.vx v4,a1,v3
constexpr u32 W_VL1RE32_V1_A4 = 0x02876087u;     // vl1re32.v v1,(a4)
constexpr u32 W_VS1R_V3_A4 = 0x028700a7u;        // vs1r.v    v1,(a4)

void CheckBodySelectorInvisibleToAdmission()
{
	printf("[11] the --rvv-run-body selector does not reach admission or the descriptor\n");
	struct Row {
		char const *name;
		std::vector<u32> words;
		unsigned want_members;
		AdmitConfig cfg;
	};
	AdmitConfig base{};
	base.scalar_passthrough = false; // this section is about ROUTES, not about the bridge rule
	AdmitConfig shifts = base;
	shifts.route_shift = true;
	AdmitConfig moves = base;
	moves.route_vmv = true;
	AdmitConfig vx = base;
	vx.route_vx_mulacc = true;
	AdmitConfig mem = base;
	mem.route_vx_mulacc = true;
	mem.route_whole_reg = true;

	// NO LEADING vsetvli: `Admit` scans from guest pc 0 and an OPCFG instruction is a barrier,
	// so the run's vtype comes from `AdmitConfig::observed_vtype` exactly as it does in the
	// pinned-descriptor sections above.
	Row const rows[] = {
	    // The baseline: the six integer rows have always been admitted identically in both arms.
	    {"int .vv pair", {W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, 2, base},
	    {"shift .vi pair", {W_VADD_V3_V1_V2, W_VSLL_V4_V3_3, W_VSRL_V5_V4_7}, 3, shifts},
	    // The three families C2j found refused under materialize.
	    {"move forms",
	     {W_VMV_V_I_V3_5, W_VMV_V_X_V4_A1, W_VFMV_V_F_V5_FA2, W_VMV_V_V_V6_V5}, 4, moves},
	    {"vmul.vx + vmacc.vx", {W_VMUL_VX_V3_V1_A1, W_VMACC_VX_V4_A1_V3}, 2, vx},
	    {"whole-register load/store around a .vx multiply",
	     {W_VL1RE32_V1_A4, W_VMUL_VX_V3_V1_A1, W_VS1R_V3_A4}, 3, mem},
	};

	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			AdmitConfig off = r.cfg, on = r.cfg;
			off.vlen_bits = on.vlen_bits = vlen;
			off.body_materialize = false;
			on.body_materialize = true;
			auto const d_off = Admit(r.words, off);
			auto const d_on = Admit(r.words, on);
			// The member count first: it is what C2j's G5 gate compares and the first
			// thing a body-conditional refusal changes.
			CHECK_EQ((unsigned)d_off.n_members, r.want_members);
			CHECK_EQ((unsigned)d_on.n_members, (unsigned)d_off.n_members);
			// ... and then the whole descriptor, so a selector that changed a dataflow
			// field, a mask or the pressure bound instead of the member count is caught
			// too. The two arms may differ ONLY below RvvEmitVectorRunGroup.
			CHECK_EQ(d_on.entry_pc, d_off.entry_pc);
			CHECK_EQ(d_on.end_pc, d_off.end_pc);
			CHECK_EQ(d_on.vtype_raw, d_off.vtype_raw);
			CHECK_EQ(d_on.vlmax, d_off.vlmax);
			CHECK_EQ((unsigned)d_on.nchunks, (unsigned)d_off.nchunks);
			CHECK_EQ((unsigned)d_on.chunk_bytes, (unsigned)d_off.chunk_bytes);
			CHECK_EQ((unsigned)d_on.n_vector_members, (unsigned)d_off.n_vector_members);
			CHECK_EQ((unsigned)d_on.n_scalar_members, (unsigned)d_off.n_scalar_members);
			CHECK_EQ(d_on.cut_pc, d_off.cut_pc);
			CHECK_EQ(d_on.live_in_mask, d_off.live_in_mask);
			CHECK_EQ(d_on.live_out_mask, d_off.live_out_mask);
			CHECK_EQ(d_on.touched_mask, d_off.touched_mask);
			CHECK_EQ(d_on.x_live_in_mask, d_off.x_live_in_mask);
			CHECK_EQ(d_on.f_live_in_mask, d_off.f_live_in_mask);
			CHECK_EQ(d_on.mem_base_mask, d_off.mem_base_mask);
			CHECK_EQ(d_on.has_mem, d_off.has_mem);
			CHECK_EQ((unsigned)d_on.n_fused_members, (unsigned)d_off.n_fused_members);
			CHECK_EQ((unsigned)d_on.n_fscalar_members,
				 (unsigned)d_off.n_fscalar_members);
			CHECK_EQ(d_on.needs_fp_bracket, d_off.needs_fp_bracket);
			CHECK_EQ((unsigned)d_on.peak_live_bound, (unsigned)d_off.peak_live_bound);
			CHECK_EQ(d_on.component_separable, d_off.component_separable);
			if (d_on.n_members != d_off.n_members)
				continue;
			for (u8 i = 0; i < d_off.n_members; ++i) {
				auto const &a = d_off.members[i];
				auto const &b = d_on.members[i];
				CHECK_EQ(a.pc, b.pc);
				CHECK_EQ(a.raw, b.raw);
				CHECK_EQ((unsigned)a.op, (unsigned)b.op);
				CHECK_EQ((unsigned)a.rd, (unsigned)b.rd);
				CHECK_EQ((unsigned)a.rs1, (unsigned)b.rs1);
				CHECK_EQ((unsigned)a.rs2, (unsigned)b.rs2);
				CHECK_EQ((int)a.src1_def, (int)b.src1_def);
				CHECK_EQ((int)a.src2_def, (int)b.src2_def);
				CHECK_EQ((int)a.srcd_def, (int)b.srcd_def);
			}
			printf("    ok  %-45s vlen=%-4u %u members in both arms\n", r.name, vlen,
			       (unsigned)d_off.n_members);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [10] The translator's own scan hook records runs during a real translation.
// ---------------------------------------------------------------------------------------------

void CheckTranslatorHook()
{
	printf("[10] the translator's scan hook records maximal, non-overlapping runs\n");
	// vsetvli pins e32/m1; then six routed ALU ops in a row. M2E: the scan must record ONE
	// maximal six-member run, not six overlapping ones and not three prototype-capped pairs.
	std::vector<u32> words = {W_VSETVLI_E32M1, W_OP_ADD, W_OP_SUB, W_OP_MUL,
				  W_OP_XOR,	   W_OP_OR,  W_OP_AND};
	rvvrun::g_stats = rvvrun::Stats{};
	auto const on = TranslateAndEmit(words, true, 512);
	CHECK(!on.second.empty());
	// Seven instructions, and a scan starts at every pc not already covered by a formed run:
	// vsetvli (no run), then ONE six-member run that covers the rest.
	CHECK_EQ(rvvrun::g_stats.multi_member_runs, 1ull);
	CHECK_EQ(rvvrun::g_stats.members_admitted, 6ull);
	CHECK_EQ(rvvrun::g_stats.runs_formed, 1ull);
	CHECK_EQ(rvvrun::g_stats.scans, 2ull);
	CHECK_EQ(rvvrun::g_stats.cuts[(unsigned)CutReason::GuardStateWrite], 1ull);
	printf("    ok  scans=%llu runs=%llu multi=%llu members=%llu\n",
	       (unsigned long long)rvvrun::g_stats.scans,
	       (unsigned long long)rvvrun::g_stats.runs_formed,
	       (unsigned long long)rvvrun::g_stats.multi_member_runs,
	       (unsigned long long)rvvrun::g_stats.members_admitted);

	// With the switch off the hook is not called at all: no counter moves.
	rvvrun::g_stats = rvvrun::Stats{};
	auto const off = TranslateAndEmit(words, false, 512);
	CHECK(!off.second.empty());
	CHECK_EQ(rvvrun::g_stats.scans, 0ull);
	CHECK_EQ(rvvrun::g_stats.runs_formed, 0ull);
	printf("    ok  switch off: the scan is not reached (scans=0)\n");
}

} // namespace

int main()
{
	printf("R1A.3a vector-run descriptor and admission substrate\n");
	CheckNamedPairs();
	CheckAllOrderedPairs();
	CheckDecoderIsTheRule();
	CheckRouteOwnPredicate();
	CheckBarriers();
	CheckLengthAndBoundary();
	CheckPeakLiveness();
	CheckPressure();
	CheckRouteInvariance();
	CheckTranslatorHook();
	CheckBodySelectorInvisibleToAdmission();

	if (g_failures) {
		fprintf(stderr, "\nFAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("\nALL CHECKS PASSED\n");
	return 0;
}
