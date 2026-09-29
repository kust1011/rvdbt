#include "dbt/guest/rv32_vrun.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_decode.h"

#include <deque>
#include <type_traits>

namespace dbt::rv32::rvvrun
{

Stats g_stats;

// P7M-E. A `deque`, not a `vector`, and that is load-bearing rather than a style choice: emitted
// code holds `&entry->count` as an absolute 64-bit immediate, so an entry's address must survive
// every later allocation. `std::deque` never relocates existing elements on `push_back`;
// `std::vector` would, and the first reallocation would leave every already-emitted frame
// incrementing freed memory. `tcache::edge_slot_arena` is the same idiom for the same reason.
static std::deque<FrameCensusEntry> g_frame_census;

FrameCensusEntry *FrameCensusAlloc(u32 tb_pc, u16 frame_index, u8 n_members, u8 k)
{
	if (!config::rvv_run_frame_census)
		return nullptr;
	g_frame_census.push_back(FrameCensusEntry{tb_pc, frame_index, n_members, k, 0});
	return &g_frame_census.back();
}

void FrameCensusForEach(void (*fn)(FrameCensusEntry const &, void *), void *ctx)
{
	for (auto const &e : g_frame_census)
		fn(e, ctx);
}

char const *RunOpName(RunOp op)
{
	switch (op) {
	case RunOp::None:
		return "none";
	case RunOp::Scalar:
		return "scalar";
	case RunOp::Add:
		return "add";
	case RunOp::Sub:
		return "sub";
	case RunOp::Mul:
		return "mul";
	case RunOp::Xor:
		return "xor";
	case RunOp::Or:
		return "or";
	case RunOp::And:
		return "and";
	case RunOp::FAlu:
		return "falu";
	case RunOp::FMA:
		return "fma";
	// C2l: the three rows this table was missing. Their absence fell through to the trailing "?",
	// which is what the C2j census printed as `ops=?,falu,falu,...` -- a diagnostic gap that made
	// a shift member indistinguishable from a move member in the only output that named them.
	case RunOp::Sll:
		return "sll_vi";
	case RunOp::Srl:
		return "srl_vi";
	case RunOp::Mov:
		return "mov";
	case RunOp::MulX:
		return "mul_vx";
	case RunOp::MAccX:
		return "macc_vx";
	case RunOp::LoadWhole:
		return "vlNre";
	case RunOp::StoreWhole:
		return "vsNr";
	}
	return "?";
}

char const *CutReasonName(CutReason r)
{
	switch (r) {
	case CutReason::None:
		return "none";
	case CutReason::Disabled:
		return "disabled";
	case CutReason::RunVTypeUnusable:
		return "run_vtype_unusable";
	case CutReason::MaxMembers:
		return "max_members";
	case CutReason::InsnBudget:
		return "insn_budget";
	case CutReason::RegionBoundary:
		return "region_boundary";
	case CutReason::ControlFlow:
		return "control_flow";
	case CutReason::TrapInsn:
		return "trap_insn";
	case CutReason::GuardStateWrite:
		return "guard_state_write";
	case CutReason::VectorMemory:
		return "vector_memory";
	case CutReason::ScalarFpMemory:
		return "scalar_fp_memory";
	case CutReason::UnsupportedVector:
		return "unsupported_vector";
	case CutReason::ScalarInsn:
		return "scalar_insn";
	case CutReason::RouteNotAdmitted:
		return "route_not_admitted";
	case CutReason::RegGroupIllegal:
		return "reg_group_illegal";
	case CutReason::ChunkShapeMismatch:
		return "chunk_shape_mismatch";
	case CutReason::TypedOpCapacity:
		return "typed_op_capacity";
	case CutReason::RegisterPressure:
		return "register_pressure";
	case CutReason::MemBaseMismatch:
		return "mem_base_mismatch";
	case CutReason::UnobservedVType:
		return "unobserved_vtype";
	}
	return "?";
}

namespace
{

// ---------------------------------------------------------------------------------------------
// A2/A3/A5 METADATA. One row per decode class that has an accepted typed chunk route.
//
// The primary template is the answer for EVERY other decode class in RV32_OPCODE_LIST, which is
// what makes every non-member -- vector memory, helper-only vector ops, mask/cross-lane/reduction/
// permutation ops, `vset{i}vl{i}`, branches, traps, and all scalar instructions -- cut the run
// without being named anywhere. Adding an opcode to the family is one row here plus one row in
// RV32Translator::RvvRunMemberChunks (which routes A1 to that opcode's OWN predicate); no rule in
// this file changes.
//
// What a row asserts, and where each assertion was established:
//
//   A2 lane-separable      -- the route lowers to one independent per-chunk host operation with no
//                             cross-lane and no cross-chunk def-use (the six routes' accepted
//                             checkpoints: C2/C3 add, P3.5a mul, S2.1 sub, S2.2 xor, S2.3 or,
//                             S2.4 and; S3.9's audit found the six agree on this by construction).
//   A3 writes only vreg[]  -- RvvEmitTypedAluChunkGroupCore and the three remaining per-op
//                             builders emit only vstatechunkload / vchunk<op> / vstatechunkstore
//                             at offsets inside CPUState::vec.vreg[]. No guard field, no guest
//                             memory, no GPR.
//   A5 single (state, raw) helper -- `stub` below is the SAME RuntimeStubId the single-instruction
//                             route passes to Create_rvvtypedchunkbegin/end for this opcode. It is
//                             a pre-existing architectural helper that re-derives funct6/funct3/vm
//                             from the raw word, so an ordered fallback arm reproduces the guest
//                             sequence exactly.
//
// A1 is NOT here. It depends on flags, backend and host, so it is asked per compile, of the
// route's own predicate, through MemberAdmit.
// ---------------------------------------------------------------------------------------------
struct Candidate; // G1: the encoding hooks below take one by reference; defined further down

template <typename IType>
struct TypedAluRoute {
	static constexpr bool present = false;
	static constexpr RunOp op = RunOp::None;
	static constexpr RuntimeStubId stub = RuntimeStubId::Count;
	static constexpr bool lane_local = false;
	static constexpr bool vector_state_only = false;
	static constexpr bool fp_vector_state_only = false;
	static constexpr bool nontrapping_fast_path = false;
	static constexpr bool chunk_ssa_present = false;
	static constexpr bool overlap_snapshot_proven = false;
	// P7M-A shape facts. The primary template answers "no" to all of them for the same reason it
	// answers `present = false`: a decode class that has not established a property does not have
	// it, and nothing has to be listed for that to be true.
	static constexpr bool fp_host_arith = false;
	static constexpr bool requires_observed_vtype = false;
	static constexpr bool reads_vd = false;
	static constexpr bool partial_vl_ok = false;
	static constexpr bool opfvf_scalar_src1 = false;
	static constexpr bool opivi_imm_src1 = false;
	// G1. TWO ENCODING HOOKS, and the primary template answers both with "nothing to say" for the
	// same reason it answers `present = false`. They exist because a decode class can cover more
	// encodings than its route admits (`vimul` is the whole OPMVV/OPMVX multiply family) and
	// because a row's operand kinds can be encoding-derived rather than constant (vmul.vx does
	// not read vd, vmacc.vx does). Keeping them here rather than in ClassifyOne preserves the
	// property that the classifier body has no per-opcode logic.
};

#define TYPED_ALU_PROOFS                                                                                      \
	static constexpr bool lane_local = true;                                                               \
	static constexpr bool vector_state_only = true;                                                        \
	static constexpr bool fp_vector_state_only = false;                                                    \
	static constexpr bool nontrapping_fast_path = true;                                                    \
	static constexpr bool chunk_ssa_present = true;                                                        \
	static constexpr bool overlap_snapshot_proven = true;                                                  \
	static constexpr bool fp_host_arith = false;                                                           \
	static constexpr bool requires_observed_vtype = false;                                                 \
	static constexpr bool reads_vd = false;                                                                \
	/* the integer chunk ops are UNMASKED full-width host operations; their frames guard */                \
	/* vl == VLMAX exactly and their bodies are written for nothing else */                                \
	static constexpr bool partial_vl_ok = false;                                                           \
	static constexpr bool opfvf_scalar_src1 = false;                                                       \
	/* P7N-B: the six integer `.vv` rows have no OPIVI form, so this is false for all of them */          \
	static constexpr bool opivi_imm_src1 = false

template <>
struct TypedAluRoute<insn::Insn_vadd_vv> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Add;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vadd_vv;
	TYPED_ALU_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vsub_vv> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Sub;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vialu;
	TYPED_ALU_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vmul_vv> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Mul;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vimul;
	TYPED_ALU_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vxor_vv> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Xor;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vialu;
	TYPED_ALU_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vor_vv> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Or;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vialu;
	TYPED_ALU_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vand_vv> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::And;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vialu;
	TYPED_ALU_PROOFS;
};

// P7N-B. The two LOGICAL shift-immediate rows.
//
// THEY CARRY THE SAME SIX PROOF BITS AS THE INTEGER `.vv` ROWS, and each one is true for the same
// reason: the operation is element-wise on a lane's own bits (`lane_local`), touches only vector
// state (`vector_state_only`), cannot trap on the fast path (`nontrapping_fast_path`), has a chunk
// SSA form (`chunk_ssa_present`), and reads its source before writing its destination so vd == vs2
// is safe (`overlap_snapshot_proven` -- the one-source body's pass 1 reads every chunk before pass
// 3 writes any).
//
// WHAT IS NEW IS `opivi_imm_src1`. It says: for this decode class, an encoding in the OPIVI group
// has a 5-bit IMMEDIATE in the rs1 field rather than a register number. Like `opfvf_scalar_src1`,
// it is a CAPABILITY on the row and the ENCODING decides whether it applies -- a class with no
// OPIVI form leaves it false and is unaffected without being mentioned.
//
// THE STUB IS rv32_vialu, the same one every non-admitted shift encoding uses. No new stub.
#define TYPED_SHIFT_PROOFS                                                                            \
	static constexpr bool lane_local = true;                                                      \
	static constexpr bool vector_state_only = true;                                               \
	static constexpr bool fp_vector_state_only = false;                                           \
	static constexpr bool nontrapping_fast_path = true;                                           \
	static constexpr bool chunk_ssa_present = true;                                               \
	/* the one-source body's pass 1 reads every chunk before pass 3 writes any, so vd == vs2 */   \
	/* reads the pre-instruction bytes -- the same argument the two-source bodies make */         \
	static constexpr bool overlap_snapshot_proven = true;                                         \
	static constexpr bool fp_host_arith = false;                                                  \
	static constexpr bool requires_observed_vtype = false;                                        \
	static constexpr bool reads_vd = false;                                                       \
	static constexpr bool partial_vl_ok = false;                                                  \
	static constexpr bool opfvf_scalar_src1 = false;                                              \
	/* THE ONE NEW BIT. Spelled out rather than taken from TYPED_ALU_PROOFS precisely so that */  \
	/* the difference between these rows and the six `.vv` rows is visible in one place. */       \
	static constexpr bool opivi_imm_src1 = true

template <>
struct TypedAluRoute<insn::Insn_vsll_vi> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Sll;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vialu;
	TYPED_SHIFT_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vsrl_vi> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Srl;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vialu;
	TYPED_SHIFT_PROOFS;
};

// ---------------------------------------------------------------------------------------------
// P7M-A. THE TWO FP LANE ROUTES.
//
// SCOPE, AND HOW IT IS BOUNDED WITHOUT NAMING ANYTHING. These are the `vfalu` and `vfma` DECODE
// CLASSES, one row each, exactly as the six integer rows are decode classes. WHICH encodings
// inside a class are admitted is not decided here and is not restated here: A1 goes to
// `RvvQcgTypedFaluAdmit` / `RvvQcgTypedFmaAdmit` through MemberAdmit, and those are the same
// predicates the single-instruction translators call. So the admitted FP set inside a run is,
// by construction, the P7K-C2 set -- the forms P7J-A and P7K-C1 differenced against hardware and
// QEMU -- and it narrows or widens with those predicates rather than with a list in this file.
//
// WHAT EACH PROOF BIT MEANS HERE, since three of them do NOT mean what they mean above.
//
//   lane_local              -- established: `Emit_vchunkfalu` / `Emit_vchunkfma` emit ONE packed
//                              host FP operation per chunk with a per-chunk lane mask derived
//                              from `chunk * lanes` and the live vl. No cross-lane and no
//                              cross-chunk def-use, at any admitted VLEN.
//   vector_state_only       -- FALSE. See rv32_vrun.h: these routes touch host FP control state
//                              and CPUState::fpu, so the integer sentence is not true of them and
//                              is not borrowed. Consumers that read this bit get UNKNOWN.
//   fp_vector_state_only    -- established, and it is the restated A3 (rv32_vrun.h states it in
//                              full, including the sticky-fflags argument for a frame-scope
//                              bracket).
//   nontrapping_fast_path   -- established: the guard proves vtype/vl/vstart/frm, the bracket
//                              MASKS every host FP exception (Emit_rvvqcgfpbegin retains the
//                              exception masks and only clears the accrued flag bits), and RVV FP
//                              arithmetic raises no architectural trap -- it accrues fflags. The
//                              ONE architectural helper per member remains the fallback arm.
//   chunk_ssa_present       -- established: every operand is an ordinary QIR V512 value with
//                              real def-use, which is what lets a run keep it out of CPUState.
//   overlap_snapshot_proven -- established: both FP frames are LOAD-MAJOR (every
//                              vstatechunkload before any vstatechunkstore), which is exactly
//                              the property a run generalizes by binding all of a member's
//                              sources from `cur[][]` before publishing its destination.
//
// AND THE THREE SHAPE FACTS THAT ARE NEW WITH THESE ROWS:
//
//   fp_host_arith           -- the frame needs ONE host FP control/exception bracket and a guard
//                              that proves frm == RNE.
//   requires_observed_vtype -- a run must not bet these routes on an unobserved vtype; see
//                              rv32_vrun.h for why that is a shape error and not a coverage
//                              choice.
//   opfvf_scalar_src1       -- both classes have an OPFVF form in which the rs1 FIELD names an F
//                              register. Whether a given instruction IS that form is decided from
//                              its funct3 by the classifier below, never from a funct6 list.
//   reads_vd                -- vfma only: RVV's fused forms take vd as a multiplicand or an
//                              addend, so vd is read before it is written.
//   partial_vl_ok           -- both FP frames guard `vl <= VLMAX` and mask every lane operation
//                              from the live vl, so a run made only of them may do the same.
// ---------------------------------------------------------------------------------------------
#define FP_LANE_PROOFS                                                                                        \
	static constexpr bool lane_local = true;                                                               \
	static constexpr bool vector_state_only = false;                                                       \
	static constexpr bool fp_vector_state_only = true;                                                     \
	static constexpr bool nontrapping_fast_path = true;                                                    \
	static constexpr bool chunk_ssa_present = true;                                                        \
	static constexpr bool overlap_snapshot_proven = true;                                                  \
	static constexpr bool fp_host_arith = true;                                                            \
	static constexpr bool requires_observed_vtype = true;                                                  \
	static constexpr bool partial_vl_ok = true;                                                            \
	static constexpr bool opfvf_scalar_src1 = true;                                                        \
	/* P7N-B: the FP classes have no OPIVI form either */                                                 \
	static constexpr bool opivi_imm_src1 = false

template <>
struct TypedAluRoute<insn::Insn_vfalu> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::FAlu;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vfalu;
	static constexpr bool reads_vd = false;
	FP_LANE_PROOFS;
};
template <>
struct TypedAluRoute<insn::Insn_vfma> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::FMA;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vfma;
	static constexpr bool reads_vd = true;
	FP_LANE_PROOFS;
};

#undef FP_LANE_PROOFS
#undef TYPED_ALU_PROOFS

// Why a non-member cut the run. Purely diagnostic; the decision was already made by the absence of
// a TypedAluRoute row. Derived from generic instruction properties -- the shared Flags the opcode
// table already carries and the encoding's own major/funct3 fields -- rather than from a list of
// rejected opcodes, so a newly decoded instruction is classified without editing this function.
CutReason ClassifyNonMember(u32 raw, u32 flags)
{
	if (flags & insn::Flags::Branch)
		return CutReason::ControlFlow;
	if (flags & insn::Flags::Trap)
		return CutReason::TrapInsn;

	u32 const major = raw & 0x7f;
	if (major == 0b1010111) { // OP-V
		// OPCFG (funct3 == 0b111) is the whole `vset{i}vl{i}` group: it writes vtype and vl,
		// which are two of the three fields the run's single guard compares. R1A.2 3.3's
		// stability argument is only valid because these cannot occur inside a run.
		if (((raw >> 12) & 0b111) == 0b111)
			return CutReason::GuardStateWrite;
		return CutReason::UnsupportedVector;
	}
	// LOAD-FP / STORE-FP carry BOTH the vector unit-stride/strided/indexed/segment memory
	// encodings and the scalar flw/fld/fsw/fsd. The width field separates them: 0b010 and 0b011
	// are the scalar 32/64-bit forms, and every other value is a vector element width. Both cut;
	// they are distinguished only so the counters say which barrier was hit.
	if (major == 0b0000111 || major == 0b0100111) {
		u32 const width = (raw >> 12) & 0b111;
		if (width == 0b010 || width == 0b011)
			return CutReason::ScalarFpMemory;
		return CutReason::VectorMemory;
	}
	return CutReason::ScalarInsn;
}

// The candidate one decode step produced.
struct Candidate {
	bool member = false;
	bool scalar_passthrough = false;
	RunOp op = RunOp::None;
	RuntimeStubId stub = RuntimeStubId::Count;
	u8 rd = 0, rs1 = 0, rs2 = 0;
	bool lane_local = false;
	bool vector_state_only = false;
	bool fp_vector_state_only = false;
	bool nontrapping_fast_path = false;
	bool chunk_ssa_present = false;
	bool overlap_snapshot_proven = false;
	bool fp_host_arith = false;
	bool requires_observed_vtype = false;
	bool reads_vd = false;
	bool partial_vl_ok = false;
	bool src1_is_fscalar = false;
	bool src1_is_imm5 = false;
	// G1. The three operand-kind facts a memory or OPMVX row needs; see RunMember for what each
	// one means to the scanner and to the body.
	bool src1_is_xscalar = false;
	bool src1_is_simm5 = false;
	bool src1_is_xbase = false;
	bool defines_vd = true;
	bool src2_is_vector = true;
	u8 funct6 = 0;
	CutReason cut = CutReason::None;
};

// ---------------------------------------------------------------------------------------------
// G1. THE FOUR ROWS THAT CLOSE A LOAD -> .vx MULTIPLY/ACCUMULATE -> STORE DATAFLOW.
//
// Everything here is derived from the ENCODING and from the routes that already exist for these
// opcodes as single instructions; no guest pc, workload name or iteration count appears.
//
//   vmul.vx / vmacc.vx   OPMVX (funct3 110), vm = 1, funct6 in {VMUL, VMACC}. The rs1 field names
//                        a GPR whose word is broadcast once per frame -- the same scalar the
//                        single-instruction vx-mul/acc route broadcasts. vmacc READS vd.
//   vl<nf>re<eew>.v      nf = 1 register, width = e32 this round, so one whole register is moved
//                        at the run's own SEW and the chunk stream is exact.
//   vs<nf>r.v            nf = 1 register. Its vector SOURCE is encoded in the vs3 field, which the
//                        shared decoder puts in `rd`; the row moves it to `rs2` so the scanner's
//                        one dataflow rule resolves it, and clears `defines_vd`.
//
// THE TWO MEMORY ROWS DO NOT CLAIM `vector_state_only` OR `nontrapping_fast_path`. They move guest
// memory and a load can fault, so a run that contains one is guarded like the memory frames (base
// range) and the certificate table version is bumped rather than reusing the ALU proof macro.
// ---------------------------------------------------------------------------------------------
#define TYPED_MEM_PROOFS                                                                                      \
	static constexpr bool lane_local = true;                                                               \
	static constexpr bool vector_state_only = false;                                                       \
	static constexpr bool fp_vector_state_only = false;                                                    \
	static constexpr bool nontrapping_fast_path = false;                                                   \
	static constexpr bool chunk_ssa_present = true;                                                        \
	static constexpr bool overlap_snapshot_proven = true;                                                  \
	static constexpr bool fp_host_arith = false;                                                           \
	static constexpr bool requires_observed_vtype = true;                                                  \
	static constexpr bool reads_vd = false;                                                                \
	static constexpr bool partial_vl_ok = false;                                                           \
	static constexpr bool opfvf_scalar_src1 = false;                                                       \
	static constexpr bool opivi_imm_src1 = false

template <>
struct TypedAluRoute<insn::Insn_vimul> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::MulX; // refined to MAccX by funct6
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vimul;
	// The ALU proof macro is out of scope here, so the six bits are spelled out. They hold for
	// the same reasons the `.vv` multiply row states: lane-local, vector-state-only, cannot trap
	// on the fast path, has a chunk SSA form, and reads its sources before writing vd.
	static constexpr bool lane_local = true;
	static constexpr bool vector_state_only = true;
	static constexpr bool fp_vector_state_only = false;
	static constexpr bool nontrapping_fast_path = true;
	static constexpr bool chunk_ssa_present = true;
	static constexpr bool overlap_snapshot_proven = true;
	static constexpr bool fp_host_arith = false;
	static constexpr bool requires_observed_vtype = true;
	static constexpr bool reads_vd = false; // refined per encoding
	static constexpr bool partial_vl_ok = false;
	static constexpr bool opfvf_scalar_src1 = false;
	static constexpr bool opivi_imm_src1 = false;
	static constexpr bool AdmitsEncoding(u32 raw)
	{
		u32 const f6 = (raw >> 26) & 0x3fu;
		return ((raw >> 12) & 0b111u) == 0b110u && ((raw >> 25) & 1u) == 1u &&
		       (f6 == VF6_VMUL || f6 == VF6_VMACC);
	}
	static constexpr void Refine(Candidate &out, u32 raw)
	{
		bool const macc = ((raw >> 26) & 0x3fu) == VF6_VMACC;
		out.op = macc ? RunOp::MAccX : RunOp::MulX;
		out.reads_vd = macc;
		out.src1_is_xscalar = true;
	}
};

// G3. THE MOVE / BROADCAST ROWS: vmv.v.v, vmv.v.x, vmv.v.i and vfmv.v.f.
//
// RVV 1.0 encodes all four as funct6 010111 with vm = 1 and the vs2 field fixed to zero -- the form
// that has NO second vector operand and therefore is not a merge. The four differ only in what
// source 1 is, and that is the funct3 group: OPIVV a vector register, OPIVX a GPR, OPIVI a 5-bit
// SIGNED immediate, OPFVF an F register. `Refine` reads exactly those fields, so the rows carry no
// opcode-specific logic and nothing outside the encoding.
//
// FAIL-CLOSED ON THE MERGE FORM. vm = 0 is vmerge.v?m / vfmerge.vfm, which READS vs2 and v0 as
// operands; `AdmitsEncoding` refuses it, so it keeps its existing single-instruction path unchanged.
// A non-zero vs2 with vm = 1 is a reserved encoding and is refused for the same reason.
//
// `reads_vd` is false and `defines_vd` true: a move writes vd and reads nothing else, so the run's
// dataflow gives it the source component directly and no CPUState traffic is created for it.
#define TYPED_MOVE_PROOFS                                                                                     \
	static constexpr bool lane_local = true;                                                               \
	static constexpr bool vector_state_only = true;                                                        \
	static constexpr bool fp_vector_state_only = false;                                                    \
	static constexpr bool nontrapping_fast_path = true;                                                    \
	static constexpr bool chunk_ssa_present = true;                                                        \
	static constexpr bool overlap_snapshot_proven = true;                                                  \
	static constexpr bool fp_host_arith = false;                                                           \
	static constexpr bool requires_observed_vtype = true;                                                  \
	static constexpr bool reads_vd = false;                                                                \
	static constexpr bool partial_vl_ok = false;                                                           \
	static constexpr bool opfvf_scalar_src1 = false;                                                       \
	static constexpr bool opivi_imm_src1 = false;                                                          \
	static constexpr bool MoveEncoding(u32 raw)                                                            \
	{                                                                                                      \
		return ((raw >> 25) & 1u) == 1u && ((raw >> 20) & 0x1fu) == 0u;                                \
	}

template <>
struct TypedAluRoute<insn::Insn_vmerge> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Mov;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vmerge;
	TYPED_MOVE_PROOFS;
	static constexpr bool AdmitsEncoding(u32 raw)
	{
		u32 const f3 = (raw >> 12) & 0b111u;
		return MoveEncoding(raw) && (f3 == 0b000u || f3 == 0b100u || f3 == 0b011u);
	}
	static constexpr void Refine(Candidate &out, u32 raw)
	{
		u32 const f3 = (raw >> 12) & 0b111u;
		out.src1_is_xscalar = f3 == 0b100u; // vmv.v.x: x[rs1]
		out.src1_is_simm5 = f3 == 0b011u;   // vmv.v.i: the rs1 FIELD is a signed imm5
		out.src2_is_vector = false;	    // the vs2 field is fixed to zero and never read
	}
};

template <>
struct TypedAluRoute<insn::Insn_vfmerge> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::Mov;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vfmerge;
	TYPED_MOVE_PROOFS;
	static constexpr bool AdmitsEncoding(u32 raw)
	{
		return MoveEncoding(raw) && ((raw >> 12) & 0b111u) == 0b101u; // OPFVF: vfmv.v.f
	}
	static constexpr void Refine(Candidate &out, u32)
	{
		out.src1_is_fscalar = true; // f[rs1], broadcast once per frame
		out.src2_is_vector = false;
	}
};

template <>
struct TypedAluRoute<insn::Insn_vlNre> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::LoadWhole;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vlNre;
	TYPED_MEM_PROOFS;
	static constexpr bool AdmitsEncoding(u32) { return true; }
	static constexpr void Refine(Candidate &out, u32)
	{
		out.src1_is_xbase = true;   // rs1 is the guest base address, not a vector source
		out.src2_is_vector = false; // the rs2 FIELD is lumop 01000
	}
};

template <>
struct TypedAluRoute<insn::Insn_vsNr> {
	static constexpr bool present = true;
	static constexpr RunOp op = RunOp::StoreWhole;
	static constexpr RuntimeStubId stub = RuntimeStubId::id_rv32_vsNr;
	TYPED_MEM_PROOFS;
	static constexpr bool AdmitsEncoding(u32) { return true; }
	static constexpr void Refine(Candidate &out, u32)
	{
		out.rs2 = out.rd;	  // the vs3 field is this member's vector SOURCE
		out.defines_vd = false;	  // ... and it writes no vector register
		out.src1_is_xbase = true; // rs1 is the guest base address
	}
};

// A Decoder<> provider that CLASSIFIES instead of translating, in exactly the way RV32Analyser is
// a Decoder<> provider that analyses instead of translating. Using the shared decoder rather than
// re-testing funct3/funct6/vm here is the point: the run can only ever see the same routing
// decision the translator sees, so it cannot admit an encoding the single-instruction route would
// have sent to a helper (nor miss one it would have routed).
struct RunClassifier {
#define OP(name, format_, flags_)                                                                            \
	void H_##name(void *insn);                                                                           \
	static constexpr auto _##name = &RunClassifier::H_##name;
	RV32_OPCODE_LIST()
#undef OP

	Candidate out{};

	template <typename IType>
	void ClassifyOne(IType i)
	{
		using Route = TypedAluRoute<IType>;
		if constexpr (Route::present) {
			// G1. A row may cover more encodings than its route admits. The refusal is a
			// route refusal, not a decode surprise, so it cuts with RouteNotAdmitted --
			// the same reason MemberAdmit's own "no" produces.
			if constexpr (requires { Route::AdmitsEncoding(i.raw); }) {
				if (!Route::AdmitsEncoding(i.raw)) {
					out.member = false;
					out.cut = CutReason::RouteNotAdmitted;
					return;
				}
			}
			out.member = true;
			out.op = Route::op;
			out.stub = Route::stub;
			out.rd = (u8)i.rd();
			out.rs1 = (u8)i.rs1();
			out.rs2 = (u8)i.rs2();
			out.lane_local = Route::lane_local;
			out.vector_state_only = Route::vector_state_only;
			out.fp_vector_state_only = Route::fp_vector_state_only;
			out.nontrapping_fast_path = Route::nontrapping_fast_path;
			out.chunk_ssa_present = Route::chunk_ssa_present;
			out.overlap_snapshot_proven = Route::overlap_snapshot_proven;
			out.fp_host_arith = Route::fp_host_arith;
			out.requires_observed_vtype = Route::requires_observed_vtype;
			out.reads_vd = Route::reads_vd;
			out.partial_vl_ok = Route::partial_vl_ok;
			out.funct6 = (u8)(i.raw >> 26);
			// P7M-A. THE OPERAND-KIND ANSWER, derived from the ENCODING and gated by the
			// ROW. funct3 == 0b101 is OP-V's OPFVF group, in which the rs1 field names a
			// scalar F register rather than a vector register group -- that is the RVV 1.0
			// encoding, not a property of any particular opcode. A decode class that has no
			// OPFVF form leaves `opfvf_scalar_src1` false and can never reach the true arm,
			// so the six integer rows are unaffected without being mentioned.
			out.src1_is_fscalar =
			    Route::opfvf_scalar_src1 && ((i.raw >> 12) & 0b111u) == 0b101u;
			// P7N-B. THE SAME DEVICE FOR THE OPIVI GROUP. funct3 == 0b011 is OP-V's
			// OPIVI group, in which the rs1 FIELD is a 5-bit unsigned immediate rather
			// than a register number -- that is the RVV 1.0 encoding, not a property of
			// any particular opcode. A decode class with no OPIVI form leaves
			// `opivi_imm_src1` false and can never reach the true arm, so the seven
			// earlier rows are unaffected without being mentioned. The two are mutually
			// exclusive because 0b011 and 0b101 are different funct3 values.
			out.src1_is_imm5 =
			    Route::opivi_imm_src1 && ((i.raw >> 12) & 0b111u) == 0b011u;
			// G1. The row's own encoding-derived refinement, applied last so it sees the
			// fields the generic code above has already filled (the store row moves `rd`
			// into `rs2`). The primary template's Refine is empty, so every earlier row is
			// unaffected without being mentioned.
			if constexpr (requires { Route::Refine(out, i.raw); })
				Route::Refine(out, i.raw);
		} else if constexpr (std::is_same_v<IType, insn::Insn_add> ||
				     std::is_same_v<IType, insn::Insn_addi> ||
				     std::is_same_v<IType, insn::Insn_sub>) {
			// Scalar address/counter maintenance commonly sits inside vector loops. These three
			// RV32 integer ALU forms cannot trap or change control flow, so they may be carried
			// through a vector run without materializing vector state. This is an ISA semantic
			// class, not a guest-PC or workload allow-list.
			//
			// THE ABLATION SWITCH IS READ HERE AND NOWHERE ELSE, so that "off" is not a
			// weaker version of the rule but the ABSENCE of the rule: the three forms fall
			// through to the same ClassifyNonMember call the final `else` arm makes, which
			// returns CutReason::ScalarInsn for them exactly as it does for every other
			// scalar instruction. Nothing downstream needs a second test -- with the switch
			// off no candidate ever carries `scalar_passthrough`, so FormRun's passthrough
			// admission arm, its trailing-scalar trim, `n_scalar_members`, the frame's
			// `rvvrunscalar` ops and the fallback arm's scalar members are all unreachable
			// rather than merely unused. See config.h for why this switch, unlike every
			// other `rvv_run_*` one, is deliberately an ADMISSION-side switch.
			if (!config::rvv_run_scalar_passthrough) {
				out.member = false;
				out.cut = ClassifyNonMember(i.raw, IType::flags);
				return;
			}
			out.member = true;
			out.scalar_passthrough = true;
			out.op = RunOp::Scalar;
			out.rd = (u8)i.rd();
			out.rs1 = (u8)i.rs1();
			if constexpr (std::is_same_v<IType, insn::Insn_addi>)
				out.rs2 = 0;
			else
				out.rs2 = (u8)i.rs2();
		} else {
			out.member = false;
			out.cut = ClassifyNonMember(i.raw, IType::flags);
		}
	}
};

// One generic handler body for every decode class. There is no per-opcode logic here at all: the
// only thing that varies is the Insn type, and everything the type contributes comes from its
// TypedAluRoute<> row and its shared Flags.
#define OP(name, format_, flags_)                                                                            \
	void RunClassifier::H_##name(void *insn)                                                             \
	{                                                                                                    \
		ClassifyOne(insn::Insn_##name{*(u32 *)insn});                                                \
	}
RV32_OPCODE_LIST()
#undef OP

Candidate Classify(u32 raw)
{
	RunClassifier c;
	u32 word = raw;
	using decoder = insn::Decoder<RunClassifier>;
	(c.*decoder::Decode(&word))(&word);
	return c.out;
}

} // namespace

TypedAluRouteInfo ClassifyTypedAluRoute(u32 raw)
{
	Candidate const c = Classify(raw);
	if (!c.member)
		return {};
	// Written as named assignments rather than a positional braced list: the struct now carries
	// eleven booleans, and a positional list is one inserted field away from silently shifting
	// every proof bit by one.
	TypedAluRouteInfo out;
	out.present = true;
	out.op = c.op;
	out.stub = c.stub;
	out.rd = c.rd;
	out.rs1 = c.rs1;
	out.rs2 = c.rs2;
	out.lane_local = c.lane_local;
	out.vector_state_only = c.vector_state_only;
	out.fp_vector_state_only = c.fp_vector_state_only;
	out.nontrapping_fast_path = c.nontrapping_fast_path;
	out.chunk_ssa_present = c.chunk_ssa_present;
	out.overlap_snapshot_proven = c.overlap_snapshot_proven;
	out.fp_host_arith = c.fp_host_arith;
	out.requires_observed_vtype = c.requires_observed_vtype;
	out.reads_vd = c.reads_vd;
	out.partial_vl_ok = c.partial_vl_ok;
	out.src1_is_fscalar = c.src1_is_fscalar;
	out.src1_is_imm5 = c.src1_is_imm5;
	out.src1_is_xscalar = c.src1_is_xscalar;
	out.src1_is_simm5 = c.src1_is_simm5;
	out.src1_is_xbase = c.src1_is_xbase;
	out.src2_is_vector = c.src2_is_vector;
	out.funct6 = c.funct6;
	return out;
}

// ---------------------------------------------------------------------------------------------
// P7O-1 STAGE 1. THE COMPONENT-SEPARABLE LEGALITY PREDICATE (design document section 1).
//
// Each of the eleven conditions is answered below from a field the descriptor ALREADY carries or
// from the route table's OWN proof bits, re-read through ClassifyTypedAluRoute so that no second
// opcode allow-list exists. Nothing here is a new route row, and nothing here relaxes an existing
// cut: this predicate can only ever refuse.
//
// THE THREE CONDITIONS THAT ARE DISCHARGED BY CONSTRUCTION rather than by a test, stated so that
// their absence below is a recorded argument and not an omission:
//
//   P8 (no cross-lane member). Reduction, permutation, slide, gather and compress have NO row in
//      the route table above, so they are non-members and CUT the run before it can contain one.
//      A future row for one of them would have to set `lane_local = false`, which P2 then catches;
//      a row that set `lane_local = true` for a cross-lane operation would be a false entry in the
//      table itself, which is the thing the table's own header forbids.
//   P10 (no CSR/GPR architectural side effect). Every CSR access and every scalar instruction is a
//      non-member (CutReason::ScalarInsn), so the only way a run can write a GPR is an admitted
//      RunOp::Scalar passthrough member, which P5 excludes; the only way it can write guest memory
//      is a whole-register store, which P4 excludes. The `.vx` rows READ a GPR and write none. The
//      accrued FP flags are the documented exception and are handled by the frame-scope bracket,
//      whose scope this design does not change: RVV fflags are sticky and OR-accumulated, and OR
//      is commutative and associative, so reordering lane work cannot change the frame's accrued
//      value (rv32_vrun.h, the `fp_vector_state_only` paragraph).
//   P6's vstart half. The three guard kinds a descriptor satisfying P4 and P6's `partial_vl` half
//      can reach -- VTypeVlVstart, VTypeIntegerTwoArm and VTypeVlVstartFrmRNE -- all enter the
//      full body only after testing `vl` against VLMAX and `vstart` against zero (qmc/qcg/
//      qemit.cpp, Emit_rvvtypedchunkbegin: the two-arm kind branches to its restart-aware partial
//      arm instead of falling through). The kinds the design refuses -- VTypePartialVlVstartFrmRNE
//      and the `VTypeInteger` family, which weaken `vl` to `<=` -- are reachable only with
//      `partial_vl_ok` true or through a single-instruction frame, never through a run this
//      predicate accepts.
// ---------------------------------------------------------------------------------------------
// P7O-1 STAGE 2 SPLIT THE PREDICATE IN TWO, and the reason is not tidiness. `FormRun` has to
// answer it for the run AS IT WOULD BE with a candidate included, BEFORE the candidate is
// committed and therefore before there is a RunMember or a descriptor to ask about. A second copy
// of the eleven conditions inside the scan is exactly the drift this file's route table exists to
// prevent, so the conditions live here once and both callers -- the scan, per candidate, and
// RvvRunComponentSeparable, per formed descriptor -- go through the same two functions.
bool RvvRunMemberSeparable(MemberSeparableFacts const &m, u8 run_sew_bytes, u8 run_nchunks,
			   u16 run_chunk_bytes)
{
	TypedAluRouteInfo const info = ClassifyTypedAluRoute(m.raw);
	// P2, AND AN HONEST NOTE ABOUT ITS CURRENT FALSIFIABILITY. The route's OWN lane-locality bit
	// is the premise the whole correctness argument rests on: `vd[e]` depends only on element
	// `e` of its sources. `present` is tested with it because a word with no route row yields a
	// default-constructed TypedAluRouteInfo, on which every proof bit is already false -- the
	// two cannot be separated by any input, so they are one condition rather than two branches,
	// one of which no test could reach.
	//
	// NEITHER HALF IS INDEPENDENTLY FALSIFIABLE IN THIS BUILD, and that is recorded rather than
	// papered over: every row in the route table declares `lane_local`, so the only member word
	// that can fail this test today is one that fails P7 (vm) or P11 as well. It is kept because
	// it is the condition a FUTURE row would trip -- a cross-lane row must declare
	// `lane_local = false`, and nothing else here would notice. The Stage 1 mutation sweep
	// reports it as surviving for exactly this reason; see COMPONENT_SEPARABLE_STAGE1.md.
	if (!info.present || !info.lane_local)
		return false;
	// P11. The fast path cannot trap. `nontrapping_fast_path` is the integer rows' statement;
	// the two FP rows state the same property in their own weaker wording
	// (`fp_vector_state_only`), and the design accepts either. Both are false on the two memory
	// rows, which P4 has already excluded -- so this test is reached, and can be made to fail,
	// only by a member whose WORD is a memory transfer while the frame's memory flags say
	// otherwise, which is what the focused test constructs.
	if (!info.nontrapping_fast_path && !info.fp_vector_state_only)
		return false;
	// P4/P5, per member, so that the frame-level tests are not the only thing standing between a
	// memory or GPR-writing member and an accepted run.
	if (m.src1_is_xbase || m.op == RunOp::Scalar || m.op == RunOp::LoadWhole ||
	    m.op == RunOp::StoreWhole)
		return false;
	// P7. UNMASKED. Read off bit 25 of the word -- the `vm` field of the OP-V encoding -- and
	// not off an opcode list. It is checked rather than inherited because the route table does
	// not refuse `vm = 0` uniformly: the move rows and the OPMVX multiply row refuse it in their
	// own `AdmitsEncoding`, but the two FP rows have none and rely on their runtime admission
	// predicate, which FormRun reaches through a caller-supplied MemberAdmit. Under a mask, v0's
	// bit-per-element layout is not the data operands' element layout, and mask synthesis is a
	// frame-scope resource.
	if (((m.raw >> 25) & 1u) != 1u)
		return false;
	// P9's member half, and P3's. The element -> component mapping must be the same one on every
	// operand of every member: same element width, same number of chunks, same chunk width.
	// FormRun already cuts a shape mismatch; a widening or narrowing row admitted later would
	// break the mapping without changing the shape, which is what the SEW comparison catches.
	if (m.sew_bytes != run_sew_bytes || m.nchunks != run_nchunks ||
	    m.chunk_bytes != run_chunk_bytes)
		return false;
	return true;
}

bool RvvRunFrameSeparable(FrameSeparableFacts const &f)
{
	// An empty descriptor admitted nothing; there is no run to separate.
	if (f.n_members == 0)
		return false;
	// P1. Below two components the transformation is the IDENTITY, so the predicate answers
	// false and no caller has to special-case a no-op. RvvRunPeakLiveBoundCS is written so that
	// this is a statement about pointlessness, not about safety -- see its comment for the exact
	// k = 1 agreement.
	if (f.nchunks < 2)
		return false;
	// P9's frame half. C4k GENERALIZES IT FROM "EMUL = 1" TO "AN INTEGRAL REGISTER GROUP THE
	// CALLER'S BODY ACTUALLY ADDRESSES". The two tests below refuse for DIFFERENT reasons and are
	// therefore separate conditions rather than one.
	//
	// FRACTIONAL EMUL IS STILL REFUSED OUTRIGHT, and not for tidiness. `emul_group_regs` reports
	// ONE register for every `emul_log2 <= 0`, so at a fractional EMUL several distinct groups
	// share one architectural register. The run substrate keys ALL of its dataflow on the group's
	// BASE REGISTER NUMBER -- `cur_def[]`, `touched_mask`, `live_in_mask`/`live_out_mask` here,
	// and the code generator's `cur[r][c]` -- and that key is EXACT only while any two groups of
	// the run's single EMUL are either equal or disjoint. At an integral EMUL `reg_group_legal`
	// (rv32_vector.h) guarantees exactly that -- every group is EMUL-aligned and EMUL-wide -- and
	// the scan applies it to every field that names a vector register. At a fractional EMUL it
	// does not, so the keying would alias two different groups onto one entry.
	//
	// An out-of-range EMUL is refused through the SAME helper the ISA rule uses, so this function
	// and `reg_group_legal` cannot disagree about which group widths exist.
	if (f.lmul_log2 < 0 || !emul_in_range(f.lmul_log2))
		return false;
	// AN INTEGRAL GROUP WIDER THAN ONE REGISTER NEEDS THE CALLER'S PERMISSION. The
	// element -> component map is well defined for it (see GroupAddressing in the header), but a
	// caller whose body tiles a SINGLE register would build `k` components of the wrong register.
	// The permission is the caller's, which is what keeps the pre-C4k callers' answers unchanged.
	if (f.lmul_log2 != 0 && f.group_addressing != GroupAddressing::RegisterGroup)
		return false;
	// P3. ONE chunk shape, and C4k makes it THREE facts about that shape rather than one, because
	// at EMUL > 1 the single equality no longer implies the other two.
	//
	//   (a) the register's live width must be describable by CPUState at all. VLEN_MAX_BYTES is
	//       the per-register storage reservation (rv32_vector.h, rv32_cpu.h), so a wider fact is
	//       not a shape this substrate can address -- and bounding it here is also what keeps the
	//       group-bytes product below inside its u32.
	//   (b) a chunk must not STRADDLE a register boundary. `group_chunk_location` places chunk c
	//       at byte `(c*chunk_bytes) % reg_bytes` of register `base + (c*chunk_bytes)/reg_bytes`,
	//       and each architectural register occupies its OWN VLEN_MAX_BYTES slot, so a chunk
	//       wider than the live register would run into that slot's padding instead of into the
	//       next register. At EMUL = 1 this is IMPLIED by (c); at EMUL > 1 it is not, which is
	//       why it is written rather than inherited.
	//   (c) `k` chunks of `chunk_bytes` are the whole register GROUP and nothing else -- the same
	//       `stride * k == group_bytes` fact RvvEmitVectorRunGroup Panics on (guest/rv32_qir.cpp),
	//       checked here rather than assumed, because it is what makes the `k` component sets
	//       DISJOINT and EXHAUSTIVE. The register count comes from `emul_group_regs`, the SAME
	//       helper `reg_group_legal` uses for the alignment rule, so the two cannot disagree
	//       about the group's size.
	//
	// AT EMUL = 1 THE ANSWER IS UNCHANGED ON EVERY INPUT. `emul_group_regs(0)` is 1, so (c) is the
	// pre-C4k equality character for character; (b) follows from it, because
	// `chunk_bytes * nchunks == reg_bytes` implies `chunk_bytes` divides `reg_bytes`; and (a)
	// could only refuse a fact whose register is wider than the storage reservation, which (c)
	// would then require `chunk_bytes * nchunks` to equal -- a shape no route admits and the
	// per-chunk arrays could not hold.
	u32 const reg_bytes = f.vlen_bits / 8u;
	if (reg_bytes == 0 || reg_bytes > VLEN_MAX_BYTES)
		return false;
	if (f.chunk_bytes == 0 || reg_bytes % (u32)f.chunk_bytes != 0)
		return false;
	if ((u32)f.chunk_bytes * (u32)f.nchunks != reg_bytes * emul_group_regs(f.lmul_log2))
		return false;
	// The descriptor's and the code generator's per-chunk arrays are sized `kMaxChunks`. The run's
	// MemberAdmit already clamps there (guest/rv32_qir.cpp), but this predicate takes FACTS from
	// its caller and must not rest on one caller's clamp: a component index past those arrays is
	// an out-of-bounds write, not a refused run. Unreachable at EMUL = 1 for the reason (a) gives.
	if (f.nchunks > kMaxChunks)
		return false;
	// P4. No guest memory. The v1 exclusion, not a semantic necessity: a whole-register store
	// faulting in component 1 would leave a memory image the member-major schedule never
	// produces (design section 2.3, CE3). The design deliberately does not rest on rvdbt's
	// user-mode fault being a termination rather than a rebuilt guest vector trap.
	if (f.has_mem || f.mem_base_mask != 0)
		return false;
	// P5. No scalar passthrough member. A GPR broadcast is taken once at frame entry, so a
	// member that WRITES a GPR the frame also reads is order-sensitive across components. The
	// existing `scalar_written_mask` cut already refuses the observable form of that; this is
	// the second, blunter exclusion the design asks for.
	if (f.n_scalar_members != 0 || f.n_vector_members != f.n_members)
		return false;
	// P6's vl half. `partial_vl_ok` true is exactly the frame that would be guarded with
	// GuardKind::VTypePartialVlVstartFrmRNE -- `vl <= VLMAX` -- under which a component's lane
	// set is a run-time quantity rather than the full chunk. Refuse it; see the block comment
	// above for why the remaining kinds are sound.
	if (f.partial_vl_ok)
		return false;
	return true;
}

// C4e. See the header for why P6's vl half is discharged here rather than inherited.
// C4k. See the header for why this is the one caller that addresses a register GROUP.
bool RvvRunGroupedComponentMajor(RunDescriptor const &d)
{
	// Every condition EXCEPT P6's vl half, evaluated through the same two functions. The
	// `partial_vl_ok` field is passed as `false` -- "answer every other condition" -- because
	// passing `d.partial_vl_ok` would make this call answer exactly the question this function
	// exists to answer differently, and the discharge is stated in the header rather than hidden
	// in an argument.
	//
	// C4k. `group_addressing` is the second argument this call STATES rather than forwards, and
	// for the mirror-image reason: it is a fact about THIS caller's body, not about the run. The
	// grouped body emits `for c: maskset(c); loads(c); members(c); stores(c)` with every CPUState
	// access going through `group_chunk_state_offset` (guest/rv32_qir.cpp), which is
	// `group_chunk_location` -- the group's logical-byte addressing. So this caller can address a
	// register group, and says so here; the predicate still decides whether the group's geometry
	// is one it accepts.
	if (!RvvRunFrameSeparable(FrameSeparableFacts{d.nchunks, d.chunk_bytes, d.vlen_bits,
						      d.lmul_log2, d.has_mem, d.mem_base_mask,
						      d.n_scalar_members, d.n_vector_members,
						      d.n_members, /*partial_vl_ok=*/false,
						      GroupAddressing::RegisterGroup}))
		return false;
	for (u8 i = 0; i < d.n_members; ++i) {
		RunMember const &m = d.members[i];
		if (!RvvRunMemberSeparable(MemberSeparableFacts{m.raw, m.op, m.src1_is_xbase,
							       m.sew_bytes, m.nchunks,
							       m.chunk_bytes},
					   d.sew_bytes, d.nchunks, d.chunk_bytes))
			return false;
	}
	// A one-member run is lowered by the single-instruction route's own frame, and a run with no
	// second member has nothing to group.
	if (d.n_members < 2)
		return false;
	return true;
}

// C4k does NOT touch this predicate's admitted set. It keeps the default `GroupAddressing::
// SingleRegister` -- its body is P7O-1's, which tiles one register -- so it still answers false on
// every EMUL != 1 descriptor, and P7O-1's own condition stays separately falsifiable.
bool RvvRunComponentSeparable(RunDescriptor const &d)
{
	if (!RvvRunFrameSeparable(FrameSeparableFacts{d.nchunks, d.chunk_bytes, d.vlen_bits,
						      d.lmul_log2, d.has_mem, d.mem_base_mask,
						      d.n_scalar_members, d.n_vector_members,
						      d.n_members, d.partial_vl_ok}))
		return false;
	for (u8 i = 0; i < d.n_members; ++i) {
		RunMember const &m = d.members[i];
		if (!RvvRunMemberSeparable(MemberSeparableFacts{m.raw, m.op, m.src1_is_xbase,
							       m.sew_bytes, m.nchunks,
							       m.chunk_bytes},
					   d.sew_bytes, d.nchunks, d.chunk_bytes))
			return false;
	}
	return true;
}

RunDescriptor FormRun(uptr vmem_base, u32 entry_pc, u32 boundary_pc, u32 insn_budget, RunVType vtype,
		      RunBackendCaps caps, u32 vlen_bits, RunLimits limits, MemberAdmit admit)
{
	RunDescriptor d;
	d.entry_pc = entry_pc;
	d.end_pc = entry_pc;
	d.vtype_raw = vtype.raw;
	d.vtype_observed = vtype.observed;
	d.vlen_bits = vlen_bits;

	VType const vt{vtype.raw};
	// The run's vtype has to satisfy, ONCE for the whole run, what each single-instruction
	// Fractional groups are not represented by this cross-instruction dataflow. Integral groups
	// are allowed here; each member's own admission predicate below still decides whether its
	// lowering supports that group width.
	if (!vtype_supported(vt, vlen_bits) || vt.lmul_log2() < 0) {
		d.cut = CutReason::RunVTypeUnusable;
		return d;
	}
	d.lmul_log2 = (i8)vt.lmul_log2();
	d.sew_bytes = (u8)(vt.sew() / 8);
	d.vlmax = compute_vlmax(vt, vlen_bits);

	// cur_def[r] is the member index whose result is guest vector register r's current value
	// inside the run, or -1 when the run has not written r. It is what turns a guest register
	// name back into a component SSA value, and it is the reason live-in is "read before any
	// member wrote it" rather than "read at all".
	i8 cur_def[VREG_NUM];
	for (auto &e : cur_def)
		e = -1;

	// P7M-A. Accumulators for the four frame-scope facts a member can contribute. All of them
	// are evaluated on the run AS IT WOULD BE with the candidate included, exactly like
	// `touched_with` and the two live masks, so a candidate that is examined and then refused
	// leaves nothing behind. `partial_vl` starts TRUE and is ANDed: it is a property EVERY
	// member must have, and an empty run has no member that lacks it.
	u32 f_live_in = 0;
	u8 n_fscalar = 0;
	u8 n_fused = 0;
	bool needs_bracket = false;
	bool partial_vl = true;
	// F1 GUARD. The member half of the store-masked partial-vl argument (rv32_vrun.h,
	// `partial_vl_store_masked_ok`): ANDed like `partial_vl`, cleared by a scalar member, and
	// snapshot at the last vector commit so the trailing-scalar trim can restore it.
	bool store_masked_vl = true;
	bool store_masked_vl_at_vector = false;

	// P7O-1 STAGE 2. The AND over the per-member component-separability conditions of everything
	// committed so far, starting TRUE for the same reason `partial_vl` does: an empty run has no
	// member that lacks the property. Only VECTOR commits update it, because a scalar
	// passthrough member is refused by the FRAME half (`n_scalar_members != 0`) and is withdrawn
	// by the trailing trim -- latching this on a member the trim removes would answer false for
	// a kept prefix that is in fact separable.
	bool sep_members = true;
	// Did any committed member fit ONLY because the component-resident bound was used? The
	// invariant this exists to police is stated and asserted at the end of the scan.
	bool relaxed_used = false;

	// THE LAST COMMITTED VECTOR MEMBER, and the frame-scope facts as they stood when it was
	// committed. A scalar passthrough member is admitted only to BRIDGE vector members, so the
	// run must end at a vector member; the trailing scalar members are withdrawn after the scan
	// (see the trim below) and every fact they contributed has to be withdrawn with them.
	//
	// The facts are SNAPSHOT rather than recomputed because neither is invertible from the
	// descriptor alone: `partial_vl` is an AND whose per-member term is not stored on a
	// RunMember, and `scalar_written` is an OR in which two members can contribute the same bit.
	// Both are monotone in scan order, so the value at the last vector commit is exactly the
	// value the kept prefix would have produced. The initial values are the ones an EMPTY
	// descriptor carries, so the trim is correct even in the (unreachable) case where no vector
	// member was ever committed.
	i8 last_vector_idx = -1;
	u32 end_pc_at_vector = entry_pc;
	u32 scalar_written_at_vector = 0;
	u8 n_scalar_at_vector = 0;
	bool partial_vl_at_vector = false;
	// P7O-1 STAGE 2. The DECISION (not the legality) as it stood at the last vector commit: did
	// that member's admission use the component-resident bound? It is snapshot for exactly the
	// reason the two facts above are -- the trim can withdraw trailing scalar members, and the
	// decision that admitted the last vector member is the one the emitted body must match.
	bool separable_at_vector = false;
	u8 batch_at_vector = 0;

	u32 pc = entry_pc;
	u32 budget = insn_budget;
	// The run's chunk SHAPE, established by the first COMMITTED member. Kept local so a
	// candidate that is examined and then refused (pressure, capacity, shape mismatch) cannot
	// leave a shape on a descriptor that admitted nothing.
	MemberShape run_shape{};
	while (true) {
		// The pc the scan stopped at, whatever stopped it -- including the limits below, which
		// stop it without examining a word.
		d.cut_pc = pc;
		if (d.n_members >= limits.max_members || d.n_members >= kMaxDescriptorMembers) {
			d.cut = CutReason::MaxMembers;
			break;
		}
		if (budget == 0) {
			d.cut = CutReason::InsnBudget;
			break;
		}
		if (pc >= boundary_pc) {
			d.cut = CutReason::RegionBoundary;
			break;
		}

		u32 const raw = *(u32 *)(vmem_base + pc);
		Candidate const c = Classify(raw);
		if (!c.member) {
			d.cut = c.cut;
			break;
		}
		if (c.scalar_passthrough) {
			// A scalar prefix is not a vector island. Passthrough exists only to bridge vector
			// producers/consumers already seen in this run.
			if (d.n_vector_members == 0) {
				d.cut = CutReason::ScalarInsn;
				break;
			}
			if (RvvRunTypedOpCount((u8)__builtin_popcount(d.live_in_mask),
					       (u8)__builtin_popcount(d.live_out_mask), d.n_vector_members,
					       run_shape.nchunks, (u8)__builtin_popcount(f_live_in),
					       n_fscalar, n_fused, needs_bracket,
					       (u8)(d.n_scalar_members + 1)) > kMaxTypedOpsPerFrame) {
				d.cut = CutReason::TypedOpCapacity;
				break;
			}
			u8 const idx = d.n_members;
			RunMember &m = d.members[idx];
			m.pc = pc;
			m.raw = raw;
			m.op = RunOp::Scalar;
			m.rd = c.rd;
			m.rs1 = c.rs1;
			m.rs2 = c.rs2;
			d.n_members = idx + 1;
			d.n_scalar_members++;
			if (c.rd)
				d.scalar_written_mask |= 1u << c.rd;
			d.partial_vl_ok = false;
			partial_vl = false;
			d.partial_vl_store_masked_ok = false;
			store_masked_vl = false;
			d.end_pc = pc + 4;
			pc += 4;
			budget -= 1;
			continue;
		}
		// P7M-A. A ROUTE MAY REFUSE TO BET ON AN UNOBSERVED SHAPE, and this is applied before
		// the route's predicate is consulted -- the predicate would be asked about the RUN's
		// candidate vtype and would answer about that, not about the shape it would itself
		// have proposed for an unobserved block. See rv32_vrun.h for why that mismatch is a
		// shape error rather than a coverage choice.
		//
		// R1 (2026-09-17). THE REFUSAL IS (ROUTE, BACKEND), NOT ROUTE ALONE. The row stays
		// exactly as it is -- `requires_observed_vtype` is still true for vfalu/vfma, for the
		// memory rows, for vimul and for the move rows -- and the ONE thing that can relax it
		// is a backend that has no second candidate of its own to disagree with the run's.
		// `RunBackendCaps::fp_candidate_vtype_ok` is that statement, made by the caller from
		// its live configuration and never recorded on the route table, so no QCG consumer of
		// ClassifyTypedAluRoute sees a different answer than it saw before. With the default
		// `caps` -- every field false -- this expression is the line it replaced, bit for bit.
		bool const needs_observed =
		    c.requires_observed_vtype && !(c.fp_host_arith && caps.fp_candidate_vtype_ok);
		if (needs_observed && !vtype.observed) {
			d.cut = CutReason::UnobservedVType;
			break;
		}
		// A4's register-group half, at the run's single LMUL. Same test, same arguments, as
		// every single-instruction entry makes before calling its own admission predicate.
		//
		// P7M-A: rs1 is checked ONLY when it names a vector register group. In an OPFVF form
		// it names one of the 32 scalar F registers, which have no group-alignment rule at any
		// LMUL. `RvvQcgTypedFaluAdmit` makes exactly the same distinction (it guards its rs1
		// check with `vv &&`), so checking it unconditionally here would be a second and
		// STRICTER copy of that route's rule.
		// P7N-B adds the second exemption for the same reason: an OPIVI rs1 is a 5-bit
		// immediate, and running a shift AMOUNT through a register-group legality test would
		// refuse legal shifts for a reason that has nothing to do with registers.
		// G1. Only the fields that NAME a vector register are asked for register-group
		// legality: a memory member's rs1 is a guest base address, its rs2 field is lumop,
		// and an OPMVX rs1 is a GPR. `vector_src1` is the one place that distinction is
		// computed; everything below reuses it.
		bool const vector_src1 = !c.src1_is_fscalar && !c.src1_is_imm5 && !c.src1_is_xscalar &&
					 !c.src1_is_simm5 && !c.src1_is_xbase;
		if (!reg_group_legal(c.rd, d.lmul_log2) ||
		    (c.src2_is_vector && !reg_group_legal(c.rs2, d.lmul_log2)) ||
		    (vector_src1 && !reg_group_legal(c.rs1, d.lmul_log2))) {
			d.cut = CutReason::RegGroupIllegal;
			break;
		}
		// A memory member contributes its base to the frame-wide guard set. x0 is refused for
		// the same reason the single-instruction direct route refuses it: x0 has no tracked
		// CPUState slot for the generated indirect memory node.
		if (c.src1_is_xbase) {
			if (d.scalar_written_mask & (1u << c.rs1)) {
				d.cut = CutReason::ScalarInsn;
				break;
			}
			if (c.rs1 == 0) {
				d.cut = CutReason::RouteNotAdmitted;
				break;
			}
		}
		if (c.src1_is_xscalar && (d.scalar_written_mask & (1u << c.rs1))) {
			d.cut = CutReason::ScalarInsn;
			break;
		}
		// A1. The route's OWN predicate, with the run's SEW -- and, for routes that need
		// them, the raw word and the run's vtype. Everything a route refuses -- its flag
		// being off, the wrong backend, an unsupported VLEN or SEW, an unadmitted
		// funct3/funct6, a masked encoding, a missing host feature, a soft-float build,
		// --rvv-verify -- refuses the member here, with no second copy of any of it.
		MemberShape const shape = admit(MemberQuery{c.op, d.sew_bytes, raw, vtype.raw});
		if (!shape) {
			d.cut = CutReason::RouteNotAdmitted;
			break;
		}
		// M2E: the whole SHAPE must match, not just the count. Since M2C the vadd route's
		// chunk width follows VLEN, so two routes can agree on `nchunks` and still disagree
		// on how wide a chunk is; a run carrying one number would then build a body at the
		// wrong width. Cut rather than assume: which shapes exist is other files' business.
		if (d.n_members != 0 && !(shape == run_shape)) {
			d.cut = CutReason::ChunkShapeMismatch;
			break;
		}

		// Pressure, decided BEFORE the member is committed. The bound is computed on the run
		// as it WOULD be with this member included; if it does not fit, the run ends here and
		// the member starts a later scan instead.
		//
		// P7M-A: `touched` counts VECTOR registers only, so an OPFVF rs1 does NOT enter it --
		// putting an F-register NUMBER into a mask of vector registers would both overstate
		// pressure and, worse, alias with a real vector register that the run genuinely
		// touches. The broadcast values it does cost are charged separately, one per DISTINCT
		// F register, because that is how many the frame creates.
		// P7N-B: an OPIVI rs1 is an IMMEDIATE, so it must not enter this mask either, and
		// for a sharper version of the OPFVF reason -- a shift amount of 12 would alias with
		// vector register v12, overstating pressure AND silently claiming the run touches a
		// register it never names.
		u32 touched_with = d.touched_mask | (1u << c.rd);
		if (c.src2_is_vector)
			touched_with |= 1u << c.rs2;
		if (vector_src1)
			touched_with |= 1u << c.rs1;
		u32 const f_live_in_with =
		    c.src1_is_fscalar ? (f_live_in | (1u << c.rs1)) : f_live_in;
		u8 const n_fbcast_with = (u8)__builtin_popcount(f_live_in_with);
		bool const any_fused_with = n_fused != 0 || c.reads_vd;
		u8 const bound_ssa = RvvRunPeakLiveBound((u8)__builtin_popcount(touched_with),
							shape.nchunks, n_fbcast_with, any_fused_with);

		// P7O-1 STAGE 2. THE BOUND SELECTION, AND IT IS ALSO THE BODY SELECTION.
		//
		// `use_cs_with` is not "this run is legally separable"; it is "this frame WILL emit the
		// component-major body". The two must be the same decision, made here and recorded on
		// the descriptor, because the bound that admits a member has to bound the body that is
		// actually emitted. Splitting them is the hole: a run can be legally separable while
		// RvvRunPeakLiveBoundCS is the LARGER of the two bounds (the Stage 1 sweep measured 747
		// such inputs, all at n_fbcast + n_xbcast >= 4), and admitting it on the SSA bound while
		// emitting the component body would put a peak the allocator never budgeted for inside
		// an open group -- QEmit::Emit_mov's Panic.
		//
		// So the CS bound is taken only when all four hold:
		//   * the switch is on;
		//   * every committed member AND this candidate satisfies the per-member conditions;
		//   * the frame conditions hold for the run WITH this candidate (which subsumes
		//     P1's `nchunks >= 2` -- at one component the transform is the identity);
		//   * the CS bound is not the larger one, so turning the feature on can never cut a run
		//     the default arm admits.
		// The chosen bound is then checked against the real pool exactly as before; nothing
		// about `limits.host_vector_regs` changes.
		// AN HONEST NOTE ON `member_sep_with`'s FALSIFIABILITY AT THIS CALL SITE. Through
		// FormRun it is currently SUBSUMED by `frame_sep_with`: every per-member condition a
		// candidate this build can admit could fail also shows up in the frame facts -- a
		// memory member sets `has_mem`, a scalar member is handled by the passthrough arm and
		// counted in `n_scalar_members`, a masked encoding is refused by the route's own
		// admission predicate before it reaches here, and a shape mismatch is already a cut.
		// Deleting this conjunct therefore changes no admitted run today, and the Stage 2
		// mutation sweep reports it as surviving. It is kept because (a) the conditions
		// themselves ARE falsified, through the same function, by the Stage 1 descriptor
		// mutations, and (b) it is what a future route row -- a widening form, a cross-lane
		// form, a row that admits `vm = 0` -- would trip, and nothing else here would notice.
		u32 const x_live_in_with =
		    c.src1_is_xscalar ? (d.x_live_in_mask | (1u << c.rs1)) : d.x_live_in_mask;
		bool const member_sep_with =
		    sep_members &&
		    RvvRunMemberSeparable(MemberSeparableFacts{raw, c.op, c.src1_is_xbase, d.sew_bytes,
							       shape.nchunks, shape.chunk_bytes},
					  d.sew_bytes, shape.nchunks, shape.chunk_bytes);
		bool const frame_sep_with = RvvRunFrameSeparable(FrameSeparableFacts{
		    shape.nchunks, shape.chunk_bytes, vlen_bits, d.lmul_log2,
		    d.has_mem || c.src1_is_xbase,
		    d.mem_base_mask | (c.src1_is_xbase ? (1u << c.rs1) : 0u), d.n_scalar_members,
		    (u8)(d.n_vector_members + 1), (u8)(d.n_members + 1),
		    partial_vl && c.partial_vl_ok});
		u8 const bound_cs = RvvRunPeakLiveBoundCS((u8)__builtin_popcount(touched_with),
							  n_fbcast_with,
							  (u8)__builtin_popcount(x_live_in_with),
							  any_fused_with);
		bool const use_cs_with = config::rvv_run_component_separable && member_sep_with &&
					 frame_sep_with && bound_cs <= bound_ssa;
		// Mixed lane-local members use the existing masked-publication proof.
		// Their inactive results remain private; only active lanes reach guest state.
		bool const masked_publication_with = store_masked_vl &&
		    (c.partial_vl_ok || (c.lane_local && c.nontrapping_fast_path && c.vector_state_only));
		bool const partial_batch_with = (partial_vl && c.partial_vl_ok) ||
		    (config::rvv_run_fp_store_masked_partial_vl && masked_publication_with);
		bool const batch_legal = config::rvv_run_bounded_batches && !config::aot_use_llvm &&
		    !config::rvv_run_body_materialize && !config::rvv_run_component_separable &&
		    !config::rvv_run_live_range_split && !config::rvv_run_order_chunk_major &&
		    !config::rvv_run_dep_probe_depth && config::rvv_qcg_fp_shared_mask &&
		    member_sep_with && partial_batch_with && (needs_bracket || c.fp_host_arith) &&
		    x_live_in_with == 0 &&
		    RvvRunFrameSeparable(FrameSeparableFacts{
		        shape.nchunks, shape.chunk_bytes, vlen_bits, d.lmul_log2,
		        d.has_mem || c.src1_is_xbase, d.mem_base_mask, d.n_scalar_members,
		        (u8)(d.n_vector_members + 1), (u8)(d.n_members + 1), false,
		        GroupAddressing::RegisterGroup});
		u8 const batch_width = batch_legal ? RvvRunBatchWidth(shape.nchunks,
		    (u8)__builtin_popcount(touched_with), n_fbcast_with, any_fused_with,
		    limits.host_vector_regs, config::rvv_qcg_fp_shared_mask_max_chunks) : 0;
		u8 const use_batch = batch_width && batch_width < shape.nchunks ? batch_width : 0;
		u8 const bound = use_batch ? RvvRunPeakLiveBound((u8)__builtin_popcount(touched_with),
		    use_batch, n_fbcast_with, any_fused_with) : use_cs_with ? bound_cs : bound_ssa;
		// THE LIMIT DEPENDS ON WHICH BODY WILL LOWER THIS RUN, not on whether the splitting
		// switch is set. `has_mem_with` is the same fact the frame-separability call above
		// evaluates, and it is one of the two conditions that disqualify the splitting body;
		// the other, the materialize body, is a global switch. A run this scan admits under the
		// relaxed limit but that the splitting body then refuses would be lowered with nothing
		// bounding its residency -- see RunLimits::host_vector_regs_split.
		//
		// Exceeding the applicable limit CUTS the run here; it does not refuse it. The next
		// scan resumes at `d.end_pc`, so the remaining guest instructions form the next run and
		// every member still goes through its own direct typed-chunk route.
		bool const has_mem_with = d.has_mem || c.src1_is_xbase;
		bool const splittable_with = !config::rvv_run_body_materialize && !has_mem_with;
		u8 const cap = (splittable_with && limits.host_vector_regs_split)
				   ? limits.host_vector_regs_split
				   : limits.host_vector_regs;
		if (bound > cap) {
			d.cut = CutReason::RegisterPressure;
			break;
		}

		// M2E: the QIR node's typed-op capacity, computed on the run as it WOULD be with this
		// member, by the SAME function the code generator uses. Both live masks are evaluated
		// with the member included, because a new live-in appears exactly when a member reads
		// a register the run has not written.
		//
		// P7M-A adds the THIRD source. A fused member reads its old vd, so an unwritten vd is
		// a live-in exactly as an unwritten vs1/vs2 is; omitting it would make the frame emit
		// no load for a component the body then reads, and `cur[rd][c].IsBad()` in the
		// emitter would Panic. An OPFVF rs1 contributes to the SCALAR-F mask instead, never
		// to `live_in_mask`.
		u32 live_in_with = d.live_in_mask;
		if (c.src2_is_vector && cur_def[c.rs2] < 0)
			live_in_with |= 1u << c.rs2;
		// P7N-B: an immediate source contributes NO live-in. It is not a register.
		if (vector_src1 && cur_def[c.rs1] < 0)
			live_in_with |= 1u << c.rs1;
		if (c.reads_vd && cur_def[c.rd] < 0)
			live_in_with |= 1u << c.rd;
		u32 const live_out_with = c.defines_vd ? (d.live_out_mask | (1u << c.rd))
						       : d.live_out_mask;
		u8 const n_fscalar_with = (u8)(n_fscalar + (c.src1_is_fscalar ? 1u : 0u));
		u8 const n_fused_with = (u8)(n_fused + (c.reads_vd ? 1u : 0u));
		bool const bracket_with = needs_bracket || c.fp_host_arith;
		if (RvvRunTypedOpCount((u8)__builtin_popcount(live_in_with),
				       (u8)__builtin_popcount(live_out_with), (u8)(d.n_vector_members + 1),
				       shape.nchunks, n_fbcast_with, n_fscalar_with, n_fused_with,
				       bracket_with, d.n_scalar_members) > kMaxTypedOpsPerFrame) {
			d.cut = CutReason::TypedOpCapacity;
			break;
		}

		u8 const idx = d.n_members;
		RunMember &m = d.members[idx];
		m.pc = pc;
		m.raw = raw;
		m.stub = c.stub;
		m.op = c.op;
		m.rd = c.rd;
		m.rs1 = c.rs1;
		m.rs2 = c.rs2;
		m.sew_bytes = d.sew_bytes;
		m.nchunks = shape.nchunks;
		m.chunk_bytes = shape.chunk_bytes;
		m.funct6 = c.funct6;
		m.src1_is_fscalar = c.src1_is_fscalar;
		m.src1_is_imm5 = c.src1_is_imm5;
		m.src1_is_xscalar = c.src1_is_xscalar;
		m.src1_is_simm5 = c.src1_is_simm5;
		m.src1_is_xbase = c.src1_is_xbase;
		m.defines_vd = c.defines_vd;
		m.src2_is_vector = c.src2_is_vector;
		m.reads_vd = c.reads_vd;
		m.fp_host_arith = c.fp_host_arith;
		// Sources are resolved against the state BEFORE this member's definition, which is
		// what makes every architecturally legal overlap (vd==vs2, vd==vs1, vd==vs1==vs2,
		// and P7M-A's fused vd==vs2) come out right: the destination replaces the register's
		// current value only after ALL of the sources have been bound.
		m.src2_def = c.src2_is_vector ? cur_def[c.rs2] : (i8)-1;
		m.src1_def = vector_src1 ? cur_def[c.rs1] : (i8)-1;
		m.srcd_def = c.reads_vd ? cur_def[c.rd] : (i8)-1;
		if (c.src2_is_vector && m.src2_def < 0)
			d.live_in_mask |= 1u << c.rs2;
		if (vector_src1 && m.src1_def < 0)
			d.live_in_mask |= 1u << c.rs1;
		if (c.reads_vd && m.srcd_def < 0)
			d.live_in_mask |= 1u << c.rd;
		// G1. A GPR read as a scalar operand is a frame-scope broadcast, and a memory base is
		// read by the memory node itself; neither is vector dataflow.
		if (c.src1_is_xscalar)
			d.x_live_in_mask |= 1u << c.rs1;
		if (c.src1_is_xbase) {
			d.has_mem = true;
			d.mem_base_mask |= 1u << c.rs1;
		}

		if (c.defines_vd) {
			cur_def[c.rd] = (i8)idx;
			d.last_def[c.rd] = (i8)idx;
			d.live_out_mask |= 1u << c.rd;
		}
		d.touched_mask = touched_with;
		f_live_in = f_live_in_with;
		n_fscalar = n_fscalar_with;
		n_fused = n_fused_with;
		needs_bracket = bracket_with;
		partial_vl = partial_vl && c.partial_vl_ok;
		store_masked_vl = store_masked_vl &&
				  (c.partial_vl_ok ||
				   (c.lane_local && c.nontrapping_fast_path && c.vector_state_only));
		d.partial_vl_store_masked_ok = store_masked_vl;
		d.f_live_in_mask = f_live_in;
		d.n_fscalar_members = n_fscalar;
		d.n_fused_members = n_fused;
		d.needs_fp_bracket = needs_bracket;
		d.partial_vl_ok = partial_vl;
		d.peak_live_bound = bound;
		// P7O-1 STAGE 2. Committed together with the bound they justify.
		sep_members = member_sep_with;
		relaxed_used = relaxed_used || bound_ssa > limits.host_vector_regs;
		run_shape = shape;
		d.nchunks = shape.nchunks;
		d.chunk_bytes = shape.chunk_bytes;
		d.n_members = idx + 1;
		d.n_vector_members++;
		d.end_pc = pc + 4;

		last_vector_idx = (i8)idx;
		end_pc_at_vector = d.end_pc;
		scalar_written_at_vector = d.scalar_written_mask;
		n_scalar_at_vector = d.n_scalar_members;
		partial_vl_at_vector = d.partial_vl_ok;
		store_masked_vl_at_vector = d.partial_vl_store_masked_ok;
		separable_at_vector = use_cs_with;
		batch_at_vector = use_batch;

		pc += 4;
		budget -= 1;
	}

	// TRAILING SCALAR MEMBERS ARE NOT PART OF THE RUN.
	//
	// The admission arm above carries a scalar instruction through a run for exactly one reason:
	// to BRIDGE two vector members, so that address/counter maintenance sitting between them
	// does not cut the vector island. A scalar member after the LAST vector member bridges
	// nothing. Keeping it is not neutral -- it is lowered as an `rvvrunscalar` op INSIDE the
	// guarded body, so it is re-executed by the ordered fallback arm on every guard miss, it
	// forces `partial_vl_ok` off for a frame that has no scalar work left in it, and it advances
	// `end_pc` past instructions the run has no reason to own.
	//
	// The trimmed instructions are not lost. Runs are maximal and non-overlapping and the
	// caller advances its scan window to `end_pc`, so each trimmed instruction is translated
	// immediately afterwards by its own ordinary single-instruction path.
	//
	// `cut` / `cut_pc` are deliberately NOT rewritten: they are the scan's diagnostic for why it
	// stopped extending, which the trim does not change.
	u8 const keep = (u8)(last_vector_idx + 1);
	if (d.n_members > keep) {
		for (u8 i = keep; i < d.n_members; ++i)
			d.members[i] = RunMember{};
		d.n_members = keep;
		d.n_scalar_members = n_scalar_at_vector;
		d.end_pc = end_pc_at_vector;
		d.scalar_written_mask = scalar_written_at_vector;
		d.partial_vl_ok = partial_vl_at_vector;
		d.partial_vl_store_masked_ok = store_masked_vl_at_vector;
	}

	// P7O-1. THE COMPONENT-SEPARABLE BIT: the scan's DECISION, taken after the trim.
	//
	// AFTER THE TRIM, NOT INSIDE THE SCAN LOOP, and that placement is load-bearing: a run of
	// {vadd, vadd, addi} withdraws its trailing `addi`, restoring `n_scalar_members` to zero and
	// `partial_vl_ok` to the value the last vector member left, and the kept prefix IS separable.
	// `separable_at_vector` is the decision as it stood at that last vector commit, which is
	// exactly the decision whose bound admitted the descriptor that survives the trim.
	//
	// With the switch off it is false on every descriptor: not a weaker rule, the ABSENCE of the
	// rule, so `use_cs_with` above is constant false, the bound is the unchanged SSA bound, and
	// the emitter's component-major arm is unreachable rather than merely unused.
	d.component_separable = separable_at_vector;
	d.batch_chunks = batch_at_vector;

	// THE TWO FAIL-CLOSED INVARIANTS THIS DECISION HAS TO SATISFY are asserted in the CONSUMER
	// (RV32Translator::RvvEmitVectorRunGroup), not here, for two reasons: that is where a
	// violation would actually produce wrong code, and this translation unit is linked WITHOUT
	// dbt::Panic by the minimal analysis-only test targets (see dbt/CMakeLists.txt on
	// rvv_lane_region_certificate_test). Both are restated at the assertion site.
	//
	// (2) is worth recording where the decision is made, because it holds for a REASON rather
	// than by a second test. "A later illegal member must stop before entering the run":
	// RvvRunPeakLiveBound is MONOTONE NON-DECREASING across commits (`touched`, `n_fbroadcast`
	// and `any_fused` only grow, and `nchunks` is fixed after the first member by
	// CutReason::ChunkShapeMismatch). So if some commit had `bound_ssa > host_vector_regs`,
	// every later candidate has it too; a candidate that breaks separability takes the SSA bound
	// and is therefore CUT rather than admitted. A trailing scalar member is withdrawn by the
	// trim above, and a scalar member followed by a vector member is exactly that "later
	// candidate" case. `relaxed_used` exists to name the premise; the emitter checks the
	// conclusion.
	(void)relaxed_used;
	return d;
}

// P7N-G. See the Stats block in rv32_vrun.h for what each counter separates and why.
void RecordSplitCost(u32 load_first, u32 reload, u32 store_dead, u32 spill_live, u32 store_final,
		     u32 peak_resident)
{
	g_stats.split_frames++;
	g_stats.split_load_first += load_first;
	g_stats.split_reload += reload;
	g_stats.split_store_dead += store_dead;
	g_stats.split_spill_live += spill_live;
	g_stats.split_store_final += store_final;
	if (peak_resident > g_stats.split_peak_resident)
		g_stats.split_peak_resident = peak_resident;
}

void RecordStats(RunDescriptor const &d)
{
	g_stats.scans += 1;
	if (d.n_members > 0) {
		g_stats.runs_formed += 1;
		g_stats.members_admitted += d.n_members;
		if (d.n_members > 1)
			g_stats.multi_member_runs += 1;
	}
	// P7M-C1: the member-count histogram, over the SAME descriptors the counters above summarize.
	// `n_members` is a u8 that FormRun never lets exceed kMaxRunMembers, but the bound is checked
	// rather than assumed: a diagnostic that can write past its array would be a worse bug than
	// the one it exists to measure.
	if (d.n_members < sizeof(g_stats.members_hist) / sizeof(g_stats.members_hist[0]))
		g_stats.members_hist[d.n_members] += 1;

	unsigned const r = (unsigned)d.cut;
	if (r < sizeof(g_stats.cuts) / sizeof(g_stats.cuts[0]))
		g_stats.cuts[r] += 1;
}

std::optional<CutReason> EmptyScanCut(uptr vmem_base, u32 entry_pc, u32 boundary_pc, u32 insn_budget,
				      RunVType vtype, u32 vlen_bits, RunLimits limits)
{
	// FormRun's pre-loop check.
	VType const vt{vtype.raw};
	if (!vtype_supported(vt, vlen_bits) || vt.lmul_log2() < 0)
		return CutReason::RunVTypeUnusable;
	// FormRun's first loop iteration, with n_members == 0 and pc == entry_pc, in its order.
	if (limits.max_members == 0 || kMaxDescriptorMembers == 0)
		return CutReason::MaxMembers;
	if (insn_budget == 0)
		return CutReason::InsnBudget;
	if (entry_pc >= boundary_pc)
		return CutReason::RegionBoundary;
	u32 const raw = *(u32 *)(vmem_base + entry_pc);
	Candidate const c = Classify(raw);
	if (!c.member)
		return c.cut;
	if (c.scalar_passthrough)
		return CutReason::ScalarInsn; // FormRun: a scalar prefix is refused while n_vector_members == 0
	return std::nullopt;
}

void RecordEmptyScan(CutReason cut)
{
	// Exactly RecordStats(d) for d.n_members == 0 and d.cut == cut.
	g_stats.scans += 1;
	g_stats.members_hist[0] += 1;
	unsigned const r = (unsigned)cut;
	if (r < sizeof(g_stats.cuts) / sizeof(g_stats.cuts[0]))
		g_stats.cuts[r] += 1;
}

} // namespace dbt::rv32::rvvrun
