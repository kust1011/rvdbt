#pragma once

// R1A.3a: the VECTOR RUN (VRUN) descriptor and the translation-time admission/cut substrate.
//
// WHAT THIS FILE IS, AND WHAT IT IS NOT.
//
// R1A.0 measured that the accepted direct typed RVV ALU route materializes every guest vector
// register back to CPUState at every guest instruction boundary: a two-operation chain costs
// 5 CPUState chunk loads and 4 chunk stores at VLEN=512 and twice that at VLEN=1024, with zero
// spills, zero shuffles and no taken helper. R1A.1 then proved that the obvious repairs are
// ILLEGAL as the backend is built today -- QIR has no miss edge and no phi, so the fast body's
// SSA results are simply undefined on the guard-miss path, and neither "delete the commit" nor
// "commit selectively before the miss" can be made to hold. R1A.2 chose the one remaining legal
// shape: put ONE guard around a RUN of consecutive members, keep component SSA inside the run,
// and let the run's single exit be the only place where the two arms have to agree on authority.
// R1A.2b closed that design's last blocker (precise IP) and unlocked a minimal implementation.
//
// This file is the FIRST step of that implementation and deliberately only the first: it decides
// WHICH consecutive guest instructions could form a run and records everything a later code
// generator would need about them. It generates NO code. Nothing here changes what any existing
// route emits, at any flag setting, and with `config::rvv_vector_run` off nothing here even runs.
// A descriptor produced by this file is a translation-time OBSERVATION, not a lowering decision.
//
// THE ADMISSION RULE IS A SEMANTIC PREDICATE, NOT AN OPCODE PAIR.
//
// R1A.2 states membership as five conditions (A1-A5). This file implements them as follows:
//
//   A1 (the member already has an admitted typed chunk route at this shape) -- evaluated by
//      CALLING THE ROUTE'S OWN admission predicate through MemberAdmit below. There is no second
//      copy of any route's flag, backend gate, host-feature probe, VLEN set or SEW rule here, so
//      a run can never admit a shape the single-instruction route would have refused.
//   A2 (lane-separable: output lane i depends only on input lane i) and
//   A3 (the emitted fast path writes only CPUState::vec.vreg[] -- no guard field, no guest
//      memory, no GPR) and
//   A5 (the fallback is ONE architectural helper callable as (state, raw)) -- properties of a
//      route, established by that route's own accepted checkpoint, recorded once per decode class
//      in the TypedAluRoute<> metadata rows in rv32_vrun.cpp. They are not re-derived per
//      run and not restated per opcode.
//   A4 (unmasked, EMUL=1, SEW equal to the run's vtype, vstart==0 proven by the guard) -- the
//      unmasked part is guaranteed by the DECODER (only vm=1 encodings reach these ops at all);
//      LMUL=1 and register-group legality are checked here against the run's single vtype, which
//      is the same check the single-instruction translators make.
//
// Consequently the substrate has no notion of "vadd" or of a pair of opcodes. Every instruction
// that is not a member cuts the run, and the six accepted typed integer ALU routes are members
// because -- and only for as long as -- their own predicates admit them.
//
// CUT RULES ARE FAIL-CLOSED BY CONSTRUCTION. The classifier's DEFAULT for every one of the ~110
// decode classes in RV32_OPCODE_LIST is "not a member". Vector memory, helper-only vector ops,
// mask/cross-lane/reduction/permutation ops, `vset{i}vl{i}`, branches, traps and every scalar
// instruction therefore cut without being enumerated anywhere. The CutReason values below are
// diagnostics that name WHY; they are not the decision.
//
// M2E REPLACED THE PROTOTYPE BOUND. `RunLimits::max_members` was 2, a correctness-scope
// restriction that existed only to bound how much of the R1A.2 design had a code generator. The
// code generator is now general in `m`, so the bound is derived from the three places a run is
// actually representable-limited, and from nothing else:
//
//   1. THE TRANSLATION BLOCK. A run lives inside one ip range of one block, so it can never have
//      more members than a block has instructions: `TB_MAX_INSNS`. `kMaxRunMembers` is that
//      number, pinned to it by a static_assert in rv32_qir.cpp (this header must not include
//      rv32_cpu.h). The scan already stops earlier than this on the block's own remaining budget
//      (CutReason::InsnBudget) and on the ip range end (RegionBoundary); the constant only sizes
//      the arrays.
//   2. THE QIR NODE. The run must be DESCRIBABLE by the frame nodes, in two independent respects,
//      and M2E deliberately sized both so that neither is what actually binds a run today.
//      `InstRVVTypedChunkBegin::n_typed` is a u16 (M2E widened it from u8) against a capacity of
//      kMaxTypedOpsPerFrame; the widest body limits 1 and 3 can admit is 4 * 64 * 8 = 2048 ops,
//      so the field represents every run the other two limits allow. The member count is bounded
//      by `qir::RVV_RUN_MAX_MEMBERS`, which rv32_qir.cpp static_asserts equal to kMaxRunMembers,
//      so it is limit 1's number restated on the backend side rather than a second cap. The
//      member list is NOT an inline array: `InstRVVTypedChunkEnd` BORROWS an array allocated from
//      the region arena (qir::Builder::CreateRunMembers) and holds one inline slot for the
//      single-member frame, the ownership InstCCRFComputeRegion::operations already uses.
//      What still has to be decided during the scan is the typed-op COUNT, because it is a
//      function of the run's own dataflow and chunk shape (RvvRunTypedOpCount below) and not of
//      its member count. Hence CutReason::TypedOpCapacity: a fail-closed check made while
//      scanning, so a body that would not fit cuts the run instead of Panicking at emit time.
//   3. THE HOST REGISTER FILE. Unchanged: RvvRunPeakLiveBound against kHostVectorRegs, because a
//      spill inside an open group is QEmit::Emit_mov's Panic.
//
// None of the three mentions a workload, a guest PC, or a member count chosen to make some kernel
// come out a particular way.

#include "dbt/guest/rv32_insn.h"
#include <optional>
#include "dbt/guest/rv32_lowering_decision.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/runtime_stubs.h"

namespace dbt::rv32::rvvrun
{

// The element-wise lane operations that have an accepted direct chunk route. This is the run's
// view of "which operation", ONE VALUE PER ACCEPTED ROUTE -- not per opcode; it is NOT a list of
// things a run may contain in some fixed order, and it carries no ordering, no pairing and no
// precedence.
//
// P7M-A ADDED TWO VALUES, AND THEY ARE ROUTES RATHER THAN OPCODES. `FAlu` is the whole `vfalu`
// decode class and `FMA` the whole `vfma` decode class: which funct6/funct3/SEW combinations
// inside each class are actually admitted is decided, as for every other row, by THAT ROUTE'S OWN
// admission predicate through MemberAdmit. No funct6 value, guest PC or workload constant appears
// in this file or in rv32_vrun.cpp because of them.
enum class RunOp : u8 {
	None = 0,
	// A non-trapping scalar integer update carried through a vector SSA island. It has no
	// vector chunks; its raw instruction is lowered against CPUState in guest order.
	Scalar,
	Add,
	Sub,
	Mul,
	Xor,
	Or,
	And,
	FAlu, // P7M-A: the vfalu decode class (OPFVV/OPFVF element-wise FP ALU)
	FMA,  // P7M-A: the vfma decode class (fused multiply-add; vd is also a SOURCE)
	// P7N-B: the two LOGICAL shift-immediate forms. One vector source and a translation-time
	// immediate, which is why they are values here and not expressible through the two-input
	// integer dispatch.
	Sll,
	Srl,
	// A MOVE (copy/broadcast) with no lane arithmetic: `vd <- source 1`. Two producers now:
	// the single-instruction vmv.v.{x,i,v} frame's one-member descriptor for the A3 partial arm,
	// and (G3) the run rows for the unmasked vmv.v.v / vmv.v.x / vmv.v.i / vfmv.v.f encodings.
	// It never reaches the lane-operation dispatch in either case: the component-SSA body
	// republishes the source's values, and the partial arm has its own Kind::Mov node.
	// G9: the SPLIT body has its own move arm with the same republish semantics, so a move is
	// now admitted with --rvv-run-live-range-split on too; residency there is accounted by value
	// identity because a republished component is an ALIAS, not a second register.
	// C2l CORRECTED THIS PARAGRAPH. It used to end "the materialize body and the chunk-major
	// order still refuse it", and BOTH halves were already false when written: no line in the
	// tree implemented a chunk-major refusal (P6C-R had removed it), and the materialize refusal
	// lived in RvvRunMemberChunks -- an ADMISSION predicate -- rather than in a body. The
	// materialize body now lowers all four move forms through RvvEmitTypedVmvChunkBody, the
	// single-instruction frame's own body, so no body refuses a move.
	Mov,
	// G1. The two OPMVX integer rows whose scalar operand is a GPR word: vmul.vx (vd = vs2 * x)
	// and vmacc.vx (vd += vs2 * x). Separate values rather than `Mul` plus a flag because vmacc
	// READS vd and vmul does not, and the run's dataflow resolution is keyed on that.
	MulX,
	MAccX,
	// G1. The whole-register transfer pair vl<nf>re<eew>.v / vs<nf>r.v as run members. They are
	// the only members that touch GUEST MEMORY, which is why they carry their own proof bits
	// (not vector_state_only, not nontrapping_fast_path) and why a run containing one is guarded
	// with the memory frames' base-range kind. LoadWhole DEFINES its vd from memory; StoreWhole
	// defines no vector register and reads the vector register named in its vs3 field.
	LoadWhole,
	StoreWhole,
};

// Increment whenever the semantic route table changes.  Downstream analysis certificates record
// this value so a cached certificate cannot silently survive a route-table widening or semantic
// reclassification.
//
// P7M-A: 1 -> 2. The table gained two rows and five new proof bits, and a certificate produced
// against version 1 asserted "the six rows are integer, lane-local, vector-state-only" -- a
// statement that is no longer true of the table as a whole.
//
// P7N-B: 2 -> 3. The table gained two more rows and a new proof bit (`opivi_imm_src1`), and a
// certificate produced against version 2 asserted that every row's rs1 field names either a vector
// register or an F register -- a statement that is no longer true, because the two shift rows'
// rs1 field is a 5-bit immediate.
// G1: 3 -> 4. The table gained four rows -- vmul.vx, vmacc.vx and the whole-register transfer pair
// -- and the last two are the first members that touch GUEST MEMORY. A certificate produced
// against version 3 asserted that every row is vector-state-only and non-trapping on the fast
// path; that is no longer true of the table as a whole.
// C2l: WIDENING THIS TABLE IS ALSO A CODE-GENERATION CHANGE, and one `static_assert` makes that
// unavoidable rather than remembered. RV32Translator::RvvMaterializeRunMember pins this exact
// value, so a new route row forces whoever adds it to give that row a materialize body and an
// exact typed-op count -- the two things C2j found missing for nine of the fifteen member shapes
// the table can already produce.
static constexpr u32 kTypedAluRouteTableVersion = 4;

// Public, decode-derived view of the exact typed ALU route table.  This is deliberately only a
// classifier: it does not run a route's runtime/backend admission predicate.  Region analyses use
// it together with their caller-supplied result of that predicate, preventing a second opcode
// allow-list from drifting away from FormRun's table.
struct TypedAluRouteInfo {
	bool present{};
	RunOp op{RunOp::None};
	RuntimeStubId stub{RuntimeStubId::Count};
	u8 rd{}, rs1{}, rs2{};
	// Semantic/QIR proof carried by the same default-absent table as membership.  These are
	// consumed by the T7g real-candidate bridge; a future route row that does not explicitly
	// establish one of them therefore leaves that detector fact UNKNOWN rather than safe.
	bool lane_local{};
	// A3, AS THE SIX INTEGER ROWS ESTABLISHED IT AND ONLY AS THEY ESTABLISHED IT: the emitted
	// fast path writes NOTHING but CPUState::vec.vreg[] -- no guest memory, no GPR, no CSR, no
	// scalar register, no FP state, no control transfer.
	//
	// *** P7M-A: THIS BIT IS FALSE ON THE TWO FP ROWS, AND THAT IS DELIBERATE. ***
	//
	// The FP frames do NOT satisfy the sentence above. `Emit_rvvqcgfpbegin`/`Emit_rvvqcgfpend`
	// (qmc/qcg/qemit.cpp) save and restore the host MXCSR through three CPUState::fpu scratch
	// fields and OR the accrued host exception flags into CPUState::fpu.fcsr, and the `.vf`
	// forms READ CPUState::fpu.f[rs1]. Reusing the integer sentence for them would have made
	// the T7g bridge assert `fp_or_fflags_effect == No` for an instruction whose entire purpose
	// is an FP effect. Instead the FP rows leave this bit FALSE -- which makes the bridge's
	// derived facts UNKNOWN rather than wrongly safe, exactly as this block's header promises --
	// and state their own, weaker, separately-worded property below.
	bool vector_state_only{};
	// P7M-A. A3 FOR AN FP LANE ROUTE, restated rather than inherited. The emitted fast path:
	//   * writes guest architectural state ONLY in CPUState::vec.vreg[] and in the ACCRUED
	//     exception bits of CPUState::fpu.fcsr (RVV fflags are sticky: they are OR-accumulated
	//     and never cleared by an arithmetic instruction, so accruing the UNION of a whole
	//     frame's members once at the frame's end is bit-identical to accruing each member's
	//     separately -- nothing between two members can read fcsr, because every instruction
	//     that could (a CSR access, `frflags`, a scalar FP op) is a non-member and CUTS the run);
	//   * reads CPUState::fpu.f[rs1] for the `.vf` forms and never writes any F register;
	//   * writes the three CPUState::fpu MXCSR bracket scratch fields, which are host control
	//     state private to this translator and not guest architectural state;
	//   * touches no guest memory, no GPR, no vtype/vl/vstart field and no control transfer.
	bool fp_vector_state_only{};
	bool nontrapping_fast_path{};
	bool chunk_ssa_present{};
	bool overlap_snapshot_proven{};

	// -----------------------------------------------------------------------------------------
	// P7M-A SHAPE FACTS. Each is either a property of the ROUTE (recorded once in its table row)
	// or derived from the ENCODING by the shared decoder -- never from an opcode list here.
	// -----------------------------------------------------------------------------------------
	// The route computes in HOST floating point and therefore needs (a) the frame-scope MXCSR
	// bracket and (b) a guard that proves the guest rounding mode is RNE.
	bool fp_host_arith{};
	// The route must not be admitted into a run formed under a vtype the block never observed.
	// A run proposes ONE candidate vtype for all its members; the vfalu route's own unobserved
	// -vtype candidate is a DIFFERENT shape (a hard-coded e32/e64 m2 pair), so admitting it
	// against the run's candidate would build a body whose chunk count does not tile the run's
	// register at all. Fail closed instead: the members get their own single-instruction frames.
	bool requires_observed_vtype{};
	// vd is a SOURCE as well as the destination (the fused forms' multiplicand/accumulator).
	// A run's live-in rule is "read before any member wrote it", so missing this loses a live-in
	// and the frame would read an undefined component.
	bool reads_vd{};
	// The route's single-instruction guard permits vl < VLMAX (the FP frames mask every lane
	// operation from the live vl). False means the route's body is written for full VL only, so
	// a run containing it must guard vl == VLMAX.
	bool partial_vl_ok{};
	// DERIVED FROM THE ENCODING, not from the row: this instruction's rs1 field names an F
	// register (OPFVF) rather than a vector register group. The row only says whether the decode
	// class HAS such a form.
	bool src1_is_fscalar{};
	// P7N-B. Also derived from the ENCODING: this instruction's rs1 field is a 5-bit unsigned
	// IMMEDIATE (the OPIVI group) rather than a register number of any kind. Mutually exclusive
	// with `src1_is_fscalar` -- 0b011 and 0b101 are different funct3 groups.
	bool src1_is_imm5{};
	bool src1_is_xscalar{};
	bool src1_is_simm5{};
	bool src1_is_xbase{};
	bool src2_is_vector{true};
	// funct6, carried through so the lane-operation dispatch does not re-decode the word.
	u8 funct6{};
};

TypedAluRouteInfo ClassifyTypedAluRoute(u32 raw);

// The VECTOR registers this instruction reads, as a mask, derived from the route's operand kinds
// rather than from `(1 << rs1) | (1 << rs2)`. The run substrate, bridge and lane-region detector
// must agree: scalar/immediate rs1 and non-vector rs2 fields are not vector uses; a fused form's
// old vd is one.
constexpr u32 RouteVectorUses(TypedAluRouteInfo const &r)
{
	u32 uses = r.src2_is_vector ? 1u << r.rs2 : 0u;
	if (!r.src1_is_fscalar && !r.src1_is_imm5 && !r.src1_is_xscalar &&
	    !r.src1_is_simm5 && !r.src1_is_xbase)
		uses |= 1u << r.rs1;
	if (r.reads_vd)
		uses |= 1u << r.rd;
	return uses;
}

// The F registers this instruction reads, as a mask over the 32 scalar FP registers.
constexpr u32 RouteScalarFUses(TypedAluRouteInfo const &r)
{
	return r.src1_is_fscalar ? (1u << r.rs1) : 0u;
}

// The destination register when it is ALSO read (read-before-write), zero otherwise.
constexpr u32 RouteOldDestination(TypedAluRouteInfo const &r)
{
	return r.reads_vd ? (1u << r.rd) : 0u;
}

char const *RunOpName(RunOp op);

// Why the scan stopped extending the run. Diagnostic only -- the DECISION is always the same
// ("this instruction is not part of the run"), and every reason below except MaxMembers,
// RegisterPressure and Disabled is reached through the classifier's default "not a member" arm.
enum class CutReason : u8 {
	None = 0,	  // scan has not stopped yet (never stored in a finished descriptor)
	Disabled,	  // config::rvv_vector_run is off: no run is formed at all
	RunVTypeUnusable, // the run's own vtype is unsupported/fractional-LMUL/LMUL>1: no run at all
	MaxMembers,	  // RunLimits::max_members reached (kMaxRunMembers == TB_MAX_INSNS)
	InsnBudget,	  // the translation block's remaining instruction budget reached
	RegionBoundary,	  // next pc is at or past the ip-range boundary
	ControlFlow,	  // Flags::Branch -- a run must not cross a QIR block boundary (QIR has no phi)
	TrapInsn,	  // Flags::Trap (ill/ecall/ebreak) -- an architectural trap edge
	GuardStateWrite,  // OP-V OPCFG: vsetvli/vsetivli/vsetvl write vtype/vl and break guard stability
	VectorMemory,	  // vector load/store: can really trap, and touches guest memory
	ScalarFpMemory,	  // flw/fld/fsw/fsd share the LOAD-FP/STORE-FP majors with vector memory
	UnsupportedVector, // an OP-V encoding with no typed chunk route (helper, mask, cross-lane, ...)
	ScalarInsn,	   // any non-vector instruction
	RouteNotAdmitted,  // a typed route exists but ITS OWN predicate refused this shape/flags/host
	RegGroupIllegal,   // vd/vs1/vs2 is not a legal register group at the run's LMUL
	ChunkShapeMismatch, // the member's admitted chunk SHAPE -- count AND width -- differs
	RegisterPressure,   // adding the member would exceed the host vector register budget
	TypedOpCapacity,    // the frame's typed-op count would not fit InstRVVTypedChunkBegin::n_typed
	UnobservedVType,    // P7M-A: the route refuses a run vtype the block never observed
	MemBaseMismatch,    // G1: a second memory member names a different base register
};

// One past the last CutReason, so the diagnostic counter array below cannot be sized against a
// value that a later edit moves. Adding a reason after this line is a compile-time no-op here.
static constexpr unsigned kCutReasonCount = (unsigned)CutReason::MemBaseMismatch + 1;

} // namespace dbt::rv32::rvvrun

// WHAT A RUN CUT MEANS FOR LOWERING, on the shared axes (dbt/guest/rv32_lowering_decision.h).
//
// The projection lives here, next to the enum, for the reason the other two do: a reason added to
// `CutReason` without a lowering meaning must be a change in THIS file, not a silent hole
// elsewhere. rvv_lowering_decision_test.cpp section [2] enumerates the domain and requires one.
//
// CUTTING A RUN IS NOT ITSELF A LOWERING DEFICIENCY, and most values say so by projecting onto the
// empty set: `InsnBudget`, `RegionBoundary`, `MaxMembers`, `ControlFlow`, `TrapInsn`, `ScalarInsn`
// and `RegisterPressure` are all properties of the SCAN or of the neighbouring instruction, and
// the instruction that was cut still gets its own single-instruction frame with its own decision.
// Only the values that describe THIS instruction's own shape carry an axis.
namespace dbt::rv32::rvvlower
{

constexpr ConstraintSet ConstraintsFor(rvvrun::CutReason r)
{
	using C = rvvrun::CutReason;
	switch (r) {
	case C::Disabled:
		return Set(Constraint::Disabled);
	// The run's vtype is unsupported, fractional-LMUL, or LMUL > 1.
	case C::RunVTypeUnusable:
		return Set(Constraint::Sew, Constraint::Lmul);
	// An OP-V encoding with no typed chunk route at all.
	case C::UnsupportedVector:
		return Set(Constraint::MissingLowering);
	// A route exists and its own predicate refused this shape, flags or host. The cut does not
	// record WHICH clause refused; the frame that instruction does get records its own axes.
	case C::RouteNotAdmitted:
		return Set(Constraint::MissingLowering);
	case C::RegGroupIllegal:
		return Set(Constraint::Lmul, Constraint::Overlap);
	case C::ChunkShapeMismatch:
		return Set(Constraint::Sew, Constraint::Lmul);
	case C::UnobservedVType:
		return Set(Constraint::Sew, Constraint::Lmul);
	// Vector memory can really trap and touches guest memory; the scalar FP forms share its
	// majors. `MemBaseMismatch` is the run's own address-protocol term.
	case C::VectorMemory:
	case C::ScalarFpMemory:
	case C::MemBaseMismatch:
		return Set(Constraint::MemoryProtocol);
	// vsetvli/vsetivli/vsetvl write vtype/vl: the guard the next member would carry is no
	// longer stable across the boundary.
	case C::GuardStateWrite:
		return Set(Constraint::Sew, Constraint::Lmul, Constraint::VlVstart);
	// The frame's typed-op count would not fit InstRVVTypedChunkBegin::n_typed -- a limit of
	// rvdbt's own encoding, not of the host.
	case C::TypedOpCapacity:
		return Set(Constraint::MissingLowering);
	// Properties of the SCAN or of the NEXT instruction; see the block comment above.
	case C::None:
	case C::MaxMembers:
	case C::InsnBudget:
	case C::RegionBoundary:
	case C::ControlFlow:
	case C::TrapInsn:
	case C::ScalarInsn:
	case C::RegisterPressure:
		return Set();
	}
	return Set();
}

} // namespace dbt::rv32::rvvlower

namespace dbt::rv32::rvvrun
{

char const *CutReasonName(CutReason r);

// The maximum number of 512-bit host chunks one guest vector register can occupy in the shapes any
// accepted route admits. Used only to size fixed arrays -- the descriptor's, and the shared typed
// ALU body's per-chunk value arrays in rv32_qir.cpp.
//
// HM.2a raised this from 2 to 8. It is `VLEN_MAX_BITS / 512`, i.e. the widest register the storage
// reservation permits divided by the host chunk width, and it is derived from those two rather
// than written as a literal so that a future change to either cannot leave a stack array sized for
// a narrower register than a route may admit. It is an UPPER BOUND on what routes may admit, not a
// statement that any route admits it: which VLENs are admitted is the admission predicates' own
// business. T6b put the six typed ALU routes and the vsetvli/vle32.v/vse32.v trio on the same
// generic whole-chunk rule `vmul.vv` had used since HM.2a, so on the pure-QCG path all nine reach
// k=8; the LLVM/AOT gates still refuse anything above VLEN=1024 through RvvSSAEnabled(), and the
// diagnostic and whole-register routes keep their own narrower VLEN sets.
//
// `qir::MAX_REG_CHUNKS` (dbt/qmc/qir.h) is the same derivation on the QIR-node side, and
// rv32_qir.cpp static_asserts the two agree.
static constexpr u8 kMaxChunks = (u8)(VLEN_MAX_BITS / 512);
static_assert(kMaxChunks >= 2, "the accepted VLEN=1024 shape must still fit");

// M2E: the TRANSLATION-BLOCK limit (header item 1). A run is a contiguous stretch of one block's
// ip range, so `TB_MAX_INSNS` guest instructions is the most it can ever contain. Written here as
// its value and pinned to rv32_cpu.h's definition by a static_assert in rv32_qir.cpp, the same
// discipline kHostVectorRegs uses for the backend's register pool: this header is included by the
// decode/analysis side and must not pull in the CPU state header.
static constexpr u8 kMaxRunMembers = 64;

// Descriptor arrays are sized to the bound itself. There is no longer a prototype limit below it
// for them to be generously sized against.
static constexpr u8 kMaxDescriptorMembers = kMaxRunMembers;
static_assert(kMaxRunMembers <= kMaxDescriptorMembers);

// The host vector register budget the pressure rule is measured against.
//
// WHY THERE IS A BUDGET AT ALL (R1A.2 3.6, corrected by R1A.2b 5): QEmit::Emit_mov PANICS while a
// typed chunk group is open, because an allocator-inserted move inside the group would be skipped
// by the guard-miss arm that branches over the body. A run is one such group, so a run must not
// contain a spill -- and "does not spill" has to be decided at TRANSLATION time, because the
// alternative is a Panic rather than a slowdown.
//
// WHY THIS NUMBER: it is the size of the QCG allocator's own V512 pool, ArchTraits::VPR_POOL --
// the whole zmm file minus the two hardcoded scratch registers. It is restated here rather than
// included because arch_traits.h pulls in asmjit and belongs to the backend, and it is PINNED to
// the backend's own value by a static_assert in qmc/qcg/rvv_vector_run_admission_test.cpp, so the
// two cannot drift apart silently. The LLVM backend has no such register file and no such Panic;
// applying the QCG number to both is the conservative direction.
static constexpr u8 kHostVectorRegs = 30;

struct RunLimits {
	u8 max_members = kMaxRunMembers;

	// The STRICT limit: the pool a body that manages no residency of its own must fit inside.
	u8 host_vector_regs = kHostVectorRegs;

	// The RELAXED limit, usable ONLY while the run is one the live-range-splitting body will
	// actually lower. Splitting evicts and reloads to keep its own residency inside the pool, so
	// a run it lowers may have a peak-live bound above `host_vector_regs`; a run it does NOT
	// lower may not.
	//
	// WHY THIS IS A SEPARATE FIELD RATHER THAN ONE RAISED LIMIT. The splitting body is selected
	// by `rvv_run_live_range_split && !materialize && !d.has_mem` (guest/rv32_qir.cpp). Raising
	// the single limit whenever the SWITCH is on relaxed admission for runs that predicate
	// rejects too -- and a run containing a memory member is exactly such a run. It was then
	// lowered by the fixed-placement body with nothing bounding its residency, which reached
	// QRegAlloc as `vector spill inside a typed chunk group (VPR pool=30, 30 live, 30 resident)`:
	// the whole pool live inside a window where the allocator may not spill, because the
	// guard-miss arm branches over the body (QEmit::Emit_mov Panics).
	//
	// ZERO MEANS UNSET, and unset means "use host_vector_regs". Defaulting it to kHostVectorRegs
	// instead would be a footgun: a caller that tightens only `host_vector_regs` -- which every
	// existing test does -- would silently keep the loose 30 for non-memory runs and stop
	// exercising its own limit. With 0 the relaxation is strictly opt-in and every existing
	// caller is bit-for-bit unchanged.
	u8 host_vector_regs_split = 0;
};

// One admitted member. Everything a code generator needs about it is recorded here, because the
// scan is the only place that has both the decoded instruction and the run's dataflow context.
struct RunMember {
	u32 pc{};    // guest PC. R1A.2b: the ordered fallback arm MUST write this to state->ip
		     // immediately before this member's helper call, or that helper's trap reports
		     // the wrong PC. The fast arm writes only the LAST member's pc, at the exit.
	u32 raw{};   // raw guest instruction word: the helper's second argument, unchanged
	RuntimeStubId stub{}; // the SAME fallback stub this instruction's single-instruction route
			      // uses. No new stub, no new semantics.
	RunOp op{RunOp::None};
	u8 rd{}, rs1{}, rs2{};
	u8 sew_bytes{};
	u8 nchunks{};	  // host chunks per guest vector register, from the route's predicate
	u16 chunk_bytes{}; // M2E: the width of one of those chunks

	// P7M-A. The member's SHAPE, copied from its route row / its encoding at admission so the
	// code generator never re-decodes the word and cannot disagree with what was admitted.
	u8 funct6{};
	bool src1_is_fscalar{}; // rs1 names an F register, broadcast once per run (a frame live-in)
	// P7N-B. rs1 is a 5-bit UNSIGNED IMMEDIATE, not a register of any kind. When this is set,
	// `rs1` carries the shift amount, there is no vector source 1, `src1_def` is meaningless and
	// stays -1, and the member contributes NOTHING to the run's vector live-in set through rs1.
	// Mutually exclusive with `src1_is_fscalar` by construction: OPIVI and OPFVF are different
	// funct3 groups.
	bool src1_is_imm5{};
	// A6. Two more SOURCE-1 KINDS.
	//   src1_is_xscalar : rs1 names a GPR whose CPUState word is broadcast ONCE per frame.
	//   src1_is_simm5   : the rs1 FIELD is a 5-bit SIGNED immediate value, broadcast once.
	// C2l CORRECTED THIS PARAGRAPH. It used to read "set ONLY by the single-instruction
	// vadd.vx / vadd.vi frames ... FormRun never sets them; every run body may therefore keep
	// treating a member with both false as a vector source." That was already false: the G1
	// `vimul` row sets `src1_is_xscalar` on every vmul.vx / vmacc.vx member (rv32_vrun.cpp's
	// TypedAluRoute<Insn_vimul>::Refine) and the G3 move rows set `src1_is_xscalar` /
	// `src1_is_simm5` on vmv.v.x / vmv.v.i. A body that assumed the old sentence read VECTOR
	// REGISTER #rs1 for a GPR number -- structurally perfect, wrong-valued code -- which is the
	// second defect the C2j abort was hiding. Every body must derive the source-1 kind from
	// these flags; RvvMaterializeRunMember does it in one place for the materialize body.
	bool src1_is_xscalar{};
	bool src1_is_simm5{};
	// G1. rs1 names a GPR holding a guest BASE ADDRESS (the whole-register transfer pair). It is
	// neither a vector source nor a broadcast: the memory node reads the CPUState word itself,
	// exactly as the single-instruction route does, so it contributes to no live-in set.
	bool src1_is_xbase{};
	// G1. false for a member that writes no vector register (StoreWhole). The scanner must not
	// record a definition for it and the body must not update the run's current-value map.
	bool defines_vd{true};
	// G1. false when the rs2 FIELD is not a vector register number (LoadWhole encodes lumop
	// there). Such a member has no vector source 2 and adds nothing to the live-in set.
	bool src2_is_vector{true};
	bool reads_vd{};	// vd is read BEFORE it is written (the fused forms)
	bool fp_host_arith{};	// this member needs the frame's host FP control/exception bracket

	// Dataflow resolution, decided at admission because it cannot be recovered later without
	// redoing the scan: for each source, WHICH member's result is its current value, or -1 for
	// "read from CPUState as a run live-in". This is what lets the fast arm keep a component in
	// SSA across a guest instruction boundary instead of storing and reloading it.
	//
	// `src1_def` is meaningless when `src1_is_fscalar` -- an F register is not part of the
	// vector dataflow at all, it is a frame-scope broadcast -- and is left at -1 there.
	// `srcd_def` exists only for `reads_vd` members and resolves the OLD vd, bound BEFORE this
	// member's own definition replaces it.
	i8 src2_def{-1};
	i8 src1_def{-1};
	i8 srcd_def{-1};
};

// A maximal run starting at `entry_pc` under the current translation-time configuration.
//
// n_members == 0 means no run was formed. n_members == 1 is a run whose body is exactly what the
// existing single-instruction route already emits; it is recorded rather than discarded so the
// consumer, not the scanner, decides whether a one-member run is worth a frame.
//
// INVARIANT ON THE MEMBER LIST: members[0] and members[n_members - 1] are both VECTOR members. The
// first because a scalar passthrough is refused until the run has a vector member, the last because
// FormRun trims trailing scalar members before returning. A scalar passthrough member therefore
// always sits strictly BETWEEN two vector members, which is the only position its admission rule
// justifies -- it exists to bridge a vector producer to a vector consumer, not to absorb the scalar
// tail that follows the island. `end_pc` is consequently the pc after the last VECTOR member, so a
// caller that resumes scanning there re-offers the trimmed instructions to their own routes.
struct RunDescriptor {
	u32 entry_pc{};	 // pc of member 0
	u32 end_pc{};	 // pc immediately after the last member (== entry_pc when empty)
	u32 vtype_raw{}; // the single vtype the run's one guard will compare against
	u32 vlmax{};	 // compute_vlmax(vtype, vlen_bits) -- the guard's vl constant
	u32 vlen_bits{};
	u8 sew_bytes{};
	i8 lmul_log2{}; // the logical register-group width shared by every admitted member
	u8 nchunks{};	  // uniform across members; a member admitting a different shape cuts the run
	u16 chunk_bytes{}; // M2E: uniform across members, for the same reason
	u8 n_members{};
	u8 n_vector_members{};
	u8 n_scalar_members{};
	CutReason cut{CutReason::None};
	u32 cut_pc{}; // pc of the instruction that ended the run, when one was examined

	RunMember members[kMaxDescriptorMembers]{};

	// Dataflow over the whole run, in guest vector register numbers.
	u32 live_in_mask{};  // read by some member before any member wrote it -> load once, at entry
	u32 live_out_mask{}; // written by some member -> store once, at the exit
	u32 touched_mask{};  // appears as a VECTOR operand of any member (never an F register)

	// G1. GPR-sourced frame-scope facts, both in guest x-register numbers.
	//   x_live_in_mask : every rs1 read as a SCALAR OPERAND (vmul.vx / vmacc.vx). One broadcast
	//                    per register at frame entry, exactly as f_live_in_mask does for OPFVF.
	//   mem_base_mask  : every GPR used as a memory base. The run guard checks all of them before
	//                    entering the direct body; each memory member still names its own base.
	u32 x_live_in_mask{};
	bool has_mem{};
	u32 mem_base_mask{};
	// GPRs written by admitted scalar passthrough members. A later memory/base or scalar-vector
	// use of one of these registers cuts the run because frame-entry guards/broadcasts would see
	// the pre-update value.
	u32 scalar_written_mask{};

	// P7M-A. THE SCALAR-F LIVE-IN SET, and why it is a SEPARATE mask rather than more bits in
	// `live_in_mask`.
	//
	// An OPFVF member's rs1 names one of the 32 scalar F registers, a different register file
	// from the 32 vector registers; the two masks would collide bit for bit. The value is
	// broadcast ONCE per distinct F register, at frame entry, and stays live for the frame.
	//
	// WHY ONE BROADCAST PER RUN IS SOUND, stated as an argument rather than assumed: no member
	// of a run can write an F register. The only RVV instruction that writes one is `vfmv.f.s`,
	// which has no typed chunk route and therefore has no row in the table below, so it is a
	// non-member and CUTS the run; every scalar instruction (including every scalar FP op and
	// every CSR access) cuts the run through CutReason::ScalarInsn. So f[rs1] is loop-invariant
	// across the whole frame by construction, not by inspection of any particular workload.
	u32 f_live_in_mask{};
	// Members whose rs1 is an F-register broadcast, and members that read their old vd. Counted
	// during the scan because the typed-op capacity rule (below) needs both, and it must be
	// evaluated BEFORE the member is committed.
	u8 n_fscalar_members{};
	u8 n_fused_members{};
	// Any member needs the host FP control/exception bracket -> the frame emits ONE, and its
	// guard additionally proves frm == RNE.
	bool needs_fp_bracket{};
	// Every member's route permits vl < VLMAX. False (the integer routes' answer) makes the
	// frame guard vl == VLMAX exactly, which is what those routes' bodies are written for.
	bool partial_vl_ok{};
	// F1 GUARD (2026-09-23). Every VECTOR member either permits vl < VLMAX itself
	// (`partial_vl_ok`) or is lane-local, non-trapping and touches vector state only -- and the
	// run has NO scalar passthrough member. Such a run computes every ACTIVE lane [0, vl) exactly
	// with unmasked bodies, because no member moves data across lanes; its inactive lanes may hold
	// any value, and they are harmless provided (a) no FP member computes on them (FP lane ops
	// are masked by the live vl) and (b) no store writes them back. The translator supplies (b)
	// by masking every live-out store with the live-vl lane mask, and only then may it guard the
	// FP frame with `vl <= VLMAX`. This bit states the member half of that argument; the
	// translator (rv32_qir.cpp, `fp_store_masked_partial`) states the body half.
	bool partial_vl_store_masked_ok{};
	// The run's vtype came from an in-block `vsetvli` rather than from the fallback candidate.
	bool vtype_observed{};
	// For each live-out register, the member whose result is its FINAL value. Only entries whose
	// bit is set in live_out_mask are meaningful; the rest stay -1 so a caller that reads one
	// anyway gets "no member", not member 0. The constructor below is what guarantees that on
	// EVERY descriptor, including the ones returned before the scan starts.
	i8 last_def[rv32::VREG_NUM];

	RunDescriptor()
	{
		for (auto &e : last_def)
			e = -1;
	}

	// Conservative upper bound on the number of host vector registers simultaneously live inside
	// the run's fast body. See RvvRunPeakLiveBound() for the model and its proof obligation.
	u8 peak_live_bound{};

	// P7O-1 STAGE 1. Does this run satisfy the component-separable predicate P1-P11?
	//
	// FormRun sets it, at the very end of the scan (AFTER the trailing-scalar trim, because two
	// of the eleven conditions are read off fields the trim rewrites), to
	//
	//     config::rvv_run_component_separable && RvvRunComponentSeparable(*this)
	//
	// so with the switch off it is false on every descriptor and no consumer of it can be
	// reached. Stage 1 has NO consumer: nothing selects a bound, an emission order or a body arm
	// from this bit yet. It exists so that the classifier and its tests can land separately from
	// the bound change that will use it.
	bool component_separable{};
	u8 batch_chunks{}; // Zero: existing layout; otherwise maximal resource-bounded batch.

	bool Empty() const { return n_members == 0; }
	bool IsMultiMember() const { return n_members > 1; }
};

// The conservative peak-liveness bound, stated once so the rule and its argument stay together.
//
// R1A.2b 5 corrected R1A.2 3.6 on exactly this point: counting DISTINCT GUEST REGISTERS is NOT a
// bound on peak liveness, because the fast body's per-member destination is live at the same time
// as the sources that define it. Whenever a member overwrites one of its own sources (`vd == vs2`,
// the overlap form the frozen workload actually contains), the true peak is strictly greater than
// distinct_registers * k, so admitting on that quantity would let a run through that the allocator
// must spill -- and a spill inside a group is a Panic, not a slowdown.
//
// THE MODEL. The fast body under R1A.2 3.4/3.5 keeps, at any point, at most one live value per
// (touched guest register, chunk) pair -- a source read is the register's current value, and a
// destination definition replaces it -- plus the destinations of the pass currently in flight,
// which is at most one per chunk. Hence
//
//     peak_live <= touched_registers * k + k = (touched_registers + 1) * k
//
// The `+ k` term is exactly the def/source overlap the distinct-register formulation drops. The
// bound is deliberately loose in the other direction (it charges the overlap for every chunk even
// though a load-major schedule retires each destination as it is defined); a loose bound cuts runs
// earlier, which is the safe direction. The focused test simulates the schedule directly and
// asserts this bound is never below the simulated peak, and its mutation gate proves that
// replacing it with `touched * k` is caught.
//
// R1A.3d ADDS THE SECOND TERM, and it is a correctness fix rather than a tightening.
//
// `(touched + 1) * k` was derived for the COMPONENT-SSA body alone. The materialize body
// (config::rvv_run_body_materialize) emits, per member, the single-instruction route's own
// load-major passes: both sources of every chunk are live before any destination is defined, so
// its peak is `2k` sources plus `k` destinations = `3k`, INDEPENDENT of how many distinct guest
// registers the run touches. When a run touches at most one register -- `vadd v1,v1,v1` followed
// by another `vadd v1,v1,v1` is the smallest case -- the SSA formula gives `2k < 3k` and stops
// being an upper bound at all.
//
// That matters because a spill inside an open group is QEmit::Emit_mov's Panic, not a slowdown.
// The bound must therefore cover WHICHEVER body will be emitted, and the ADMISSION DECISION MUST
// NOT DEPEND ON THE BODY MODE: if it did, arms B and C could form different runs and the R1A.3d
// ablation would no longer have a single factor. Taking the max of the two models gives one
// body-independent bound and keeps both arms on exactly the same descriptor.
//
// AT EVERY SUPPORTED SHAPE THIS CHANGES NOTHING, and that is provable rather than hoped: the bound
// only cuts a run when it exceeds kHostVectorRegs = 30. With `k <= 2` the new term is at most 6,
// so it can never cut; and the old term first exceeds 30 at `touched >= 14` with `k = 2`, which
// the max leaves untouched. Every run any accepted route can form today is admitted exactly as
// before. The focused test exercises the two terms' crossover at a larger `k` so this is not an
// unexecuted line.
//
// (The bound itself is RvvRunPeakLiveBound, defined after the typed-op rule below.)

// M2E: the QIR-NODE capacity rule (header item 2), stated once so the scan and the code generator
// cannot disagree about how many typed ops a frame will contain.
//
// `InstRVVTypedChunkBegin::n_typed` is a u16 and `Emit_rvvtypedchunkend` Panics unless the emitter
// saw exactly that many typed body ops, so a run whose body does not fit must be CUT during the
// scan, not discovered at emit time.
//
// Body-independent for the same reason RvvRunPeakLiveBound is: admission must not depend on which
// body mode is configured, or the R1A.3d ablation arms would form different runs and stop being a
// single-factor comparison. The two bodies are
//
//   ssa          (|live_in| + |live_out| + m) * k
//   materialize  4 * m * k
//
// and the rule takes the larger. Returns a u32 deliberately -- the caller compares it against
// kMaxTypedOpsPerFrame below, and computing in the field's own width would wrap exactly at the
// values that must be refused.
// P7M-A EXTENDED IT WITH THREE TERMS AND ONE FLAG, all defaulted to the pre-P7M-A values so an
// integer-only run's number is bit-for-bit what it was:
//
//   n_fbroadcast       distinct F registers broadcast once at frame entry (SSA body only -- the
//                      materialize body re-broadcasts inside every member that needs one)
//   n_fscalar_members  members that carry their own broadcast in the materialize body
//   n_fused_members    members that also LOAD their old vd; in the materialize body that is one
//                      extra load pass, i.e. `k` more typed ops than the 4*k this rule charges
//   fp_bracket         the frame's `rvvqcgfpbegin` / `rvvqcgfpend` pair, which QEmit accounts as
//                      two typed body ops and which `Emit_rvvtypedchunkend` therefore requires to
//                      be inside the declared count
//
// It stays an UPPER BOUND on either body and stays body-independent, for the reason above. The
// emitter computes the EXACT count for the body it actually writes and asserts it against this
// one, so a shape that outgrows the bound is a loud translation failure rather than a frame whose
// guard-miss arm branches over the wrong number of bytes.
constexpr u32 RvvRunTypedOpCount(u8 n_live_in, u8 n_live_out, u8 n_vector_members, u8 nchunks,
				 u8 n_fbroadcast = 0, u8 n_fscalar_members = 0,
				 u8 n_fused_members = 0, bool fp_bracket = false,
				 u8 n_scalar_members = 0)
{
	u32 const bracket = fp_bracket ? 2u : 0u;
	u32 const ssa_body =
	    ((u32)n_live_in + n_live_out + n_vector_members) * nchunks + n_fbroadcast +
	    bracket + n_scalar_members;
	u32 const materialize_body =
	    4u * n_vector_members * nchunks + (u32)n_fused_members * nchunks +
	    n_fscalar_members + bracket + n_scalar_members;
	return ssa_body > materialize_body ? ssa_body : materialize_body;
}

// The capacity that count must fit: InstRVVTypedChunkBegin::n_typed, which M2E widened to u16
// precisely so that the NODE is not the binding constraint. With the other two limits at
// kMaxRunMembers = 64 members and kMaxChunks = 8, the largest body any admitted run can ask for is
// 4 * 64 * 8 = 2048, so this bound is REACHABLE ONLY IF one of those grows -- which is the point.
// The scan still checks it, so growing one of them cuts runs rather than overflowing the field.
static constexpr u32 kMaxTypedOpsPerFrame = 65535;

// P7M-A ADDS THE SCALAR-F AND FUSED TERMS, both defaulted off so every integer-only answer is
// unchanged.
//
//   * `n_fbroadcast` broadcast values are created at frame entry and are live for the WHOLE SSA
//     body, so they add to the peak directly. The materialize body creates at most one at a time,
//     hence the `+ 1` rather than `+ n` on that side.
//   * a fused member's materialize body holds THREE source passes before defining a destination
//     (vs2, old vd, and the broadcast) instead of two, so its term is 4k+1 rather than 3k. On the
//     SSA side nothing changes: the old vd is `cur[rd][c]`, already charged by `touched`.
//
// The result is clamped rather than truncated. The incremental check in FormRun means the value
// can never reach 255 on an admitted run -- the previous member already satisfied `<= 30` and one
// member adds at most three registers -- but a silent u8 wrap would turn "cut this run" into
// "admit it", i.e. a spill inside an open group, which is QEmit::Emit_mov's Panic.
constexpr u8 RvvRunPeakLiveBound(u8 touched_registers, u8 nchunks, u8 n_fbroadcast = 0,
				 bool any_fused = false)
{
	u32 const ssa_body = (touched_registers + 1u) * nchunks + n_fbroadcast;
	u32 const materialize_body =
	    (any_fused ? 4u : 3u) * nchunks + (n_fbroadcast ? 1u : 0u);
	u32 const v = ssa_body > materialize_body ? ssa_body : materialize_body;
	return v > 255u ? (u8)255u : (u8)v;
}

// P7O-1 STAGE 1. THE SAME MODEL FOR A COMPONENT-RESIDENT SCHEDULE, and the one term that differs.
//
// THE SCHEDULE IT BOUNDS (not emitted yet; Stage 3's business) is
//
//     for c in 0 .. k-1 { pass1(c); pass2(all members, component c); pass3(c) }
//
// instead of today's `pass1(all c); pass2(all members, all c); pass3(all c)`. Under the P1-P11
// predicate that RvvRunComponentSeparable() decides, no member reads a lane belonging to a
// component other than its own, so component `c`'s values are dead once its pass 3 has stored
// them, and at most ONE component's working set is live at any point. That is the whole content
// of this function: `nchunks` disappears from the per-component term.
//
// WHY THE TWO BROADCAST COUNTS ARE BOTH CHARGED HERE WHEN RvvRunPeakLiveBound CHARGES ONLY ONE.
// A frame-scope broadcast is created once at frame entry and stays live for the whole frame, so
// it does NOT shrink with the component loop and has to be added on top of the resident component.
// RvvRunPeakLiveBound is passed only `popcount(f_live_in)` at its call site in FormRun and never
// sees the GPR broadcasts of the `.vx` rows (`RunDescriptor::x_live_in_mask`), even though the
// live-range-splitting body's own budget does subtract both (guest/rv32_qir.cpp, `budget =
// kHostVectorRegs - n_fbcast - n_xbcast`). This function does not inherit that asymmetry: it takes
// both counts, so its answer is never lower than the values it must bound for that reason.
//
// THE RELATION TO THE EXISTING BOUND, stated exactly rather than as "identical at k = 1":
//
//   * at `nchunks == 1` AND `n_xbroadcast == 0` AND `n_fbroadcast <= 1` the two functions agree
//     TERM BY TERM, so the transformation is a no-op on a one-component run and cannot make its
//     admission looser. (`n_fbroadcast >= 2` is the only remaining gap: this function's
//     materialize term adds `n_fbroadcast`, the old one adds 1. That direction is STRICTER, so it
//     still cannot admit a run the old bound cut.)
//   * for ANY arguments, `RvvRunPeakLiveBoundCS(t, nf, nx, f) >= RvvRunPeakLiveBound(t, 1, nf, f)`:
//     both terms are monotone in the broadcast counts and `nf >= (nf ? 1 : 0)`.
//   * for `nchunks >= 2` the new bound is the SMALLER one exactly while `nx <= t + 1`, which is
//     where the design claims relief; the function does not assume it, the caller compares.
//
// The clamp is the same one and is there for the same reason: a u8 wrap would turn "cut this run"
// into "admit it", i.e. a spill inside an open group, which is QEmit::Emit_mov's Panic.
constexpr u8 RvvRunPeakLiveBoundCS(u8 touched_registers, u8 n_fbroadcast = 0, u8 n_xbroadcast = 0,
				   bool any_fused = false)
{
	u32 const broadcasts = (u32)n_fbroadcast + (u32)n_xbroadcast;
	u32 const ssa_body = (touched_registers + 1u) + broadcasts;
	u32 const materialize_body = (any_fused ? 4u : 3u) + broadcasts;
	u32 const v = ssa_body > materialize_body ? ssa_body : materialize_body;
	return v > 255u ? (u8)255u : (u8)v;
}

constexpr u8 RvvRunBatchWidth(u8 chunks, u8 touched, u8 broadcasts, bool fused,
			     u8 registers, u8 masks)
{
	for (u8 n = chunks < masks ? chunks : masks; n; --n)
		if (RvvRunPeakLiveBound(touched, n, broadcasts, fused) <= registers) {
			// Keep the minimum number of batches, without leaving a small final batch
			// with fewer independent chains (eight chunks, capacity six: four + four).
			u8 const batches = (chunks + n - 1) / n;
			return (chunks + batches - 1) / batches;
		}
	return 0;
}

// A1's evaluation hook. `ctx` is opaque to this module; in production it is the RV32Translator,
// whose implementation calls the SAME per-route admission predicate the single-instruction
// translator for that opcode calls, and nothing else. A function pointer rather than a virtual
// interface or std::function because the scan runs inside translation and must not allocate.
// M2E: a route's admission answer is a SHAPE, not just a count. `chunk_bytes` is the width of one
// host chunk and `nchunks` how many cover a guest vector register; `nchunks == 0` means refused.
// The pair travels together because only the pair is meaningful -- M2C made the single-instruction
// vadd route emit 16/32/64-byte chunks according to VLEN, and a run that carried only the count
// would build a 64-byte body for a 16-byte value.
struct MemberShape {
	u8 nchunks{};
	u16 chunk_bytes{};

	explicit operator bool() const { return nchunks != 0; }
	bool operator==(MemberShape const &o) const
	{
		return nchunks == o.nchunks && chunk_bytes == o.chunk_bytes;
	}
};

// P7M-A. WHAT A1 HAS TO BE ASKED, and why it is now a struct.
//
// The six integer routes' predicates are functions of the SEW alone, so `(op, sew_bytes)` was a
// complete question for them. The two FP routes' predicates are not: `RvvQcgTypedFaluAdmit` and
// `RvvQcgTypedFmaAdmit` take `(raw, vtype)` and decide on funct3/funct6/vm/register-group
// legality/LMUL as well. Passing them less than they take would have forced a SECOND copy of
// their rules into the run substrate -- exactly what routing A1 through MemberAdmit exists to
// prevent. So the query carries everything a route may need, and every route still answers with
// its own predicate and nothing else.
struct MemberQuery {
	RunOp op{RunOp::None};
	u32 sew_bytes{}; // the RUN's SEW, from its single vtype
	u32 raw{};	 // the candidate's raw guest word
	u32 vtype_raw{}; // the run's vtype -- always a concrete vtype, never the ~0u "unobserved"
};

struct MemberAdmit {
	MemberShape (*fn)(void *ctx, MemberQuery const &q){};
	void *ctx{};

	MemberShape operator()(MemberQuery const &q) const { return fn(ctx, q); }
};

// The run's vtype AND whether it was actually observed. A single u32 could not carry the second
// fact, and a bare `bool` parameter next to five other integers would convert silently from any
// of them; a distinct aggregate type makes an un-updated call site a compile error.
struct RunVType {
	u32 raw{};
	bool observed{};
};

// R1 (2026-09-17). WHAT THE BACKEND COMPILING THIS RUN CAN DO, asked once per scan.
//
// It exists so that a route row's `requires_observed_vtype` can stay a property of the ROUTE while
// the decision it feeds becomes a property of (route, backend). The alternative -- making
// ClassifyTypedAluRoute answer differently depending on `config::aot_use_llvm` -- would change what
// a shared, backend-agnostic classifier means for every QCG consumer of the same table, including
// the ones that never form a run.
//
// NOT stored on a descriptor, not carried into a cache, not part of any artifact key: it is read
// from the translator's live configuration at the call and discarded with the scan.
struct RunBackendCaps {
	// May a route whose row says `requires_observed_vtype` still be admitted into a run formed
	// under an UNOBSERVED candidate vtype?
	//
	// TRUE ONLY FOR THE HOST-FP LANE ROUTES (`fp_host_arith`) ON THE LLVM BACKEND, and the
	// asymmetry is the whole content of this field. The row's recorded reason (see
	// `requires_observed_vtype` above) is that the FP route has its OWN unobserved-vtype
	// candidate of a different shape -- the hard-coded e32/e64 m2 pair that
	// RvvEmitTypedFaluChunkGroup's QCG arm guards -- so a run's candidate and the route's
	// candidate would disagree about how the register tiles. That second candidate exists only
	// on the QCG arm: RvvLLVMFaluChunkAdmit / RvvLLVMFmaChunkAdmit refuse `vt.raw == ~0u`
	// outright and derive every shape fact (LMUL group, chunk count, chunk width, the LLVM lane
	// type) from the vtype they are HANDED, so on that backend there is no second candidate for
	// the run's to disagree with and the conjunct is vacuous.
	//
	// WHAT MAKES A WRONG CANDIDATE SAFE IS NOT THIS FLAG. It is the frame's guard, which is
	// unchanged: an LLVM FP run always takes GuardKind::VTypeVlVstartFrmRNE
	// (`llvm_fp_full_vl` in RvvEmitVectorRunGroup), proving vtype-equal, vl == VLMAX,
	// vstart == 0 and frm == RNE against the candidate before the body runs, with the ordered
	// per-member fallback to the same already-verified helpers when it does not hold. This is
	// the rule the memory and integer routes have used for an unobserved block since C3.1f.
	bool fp_candidate_vtype_ok{};
};

// P7O-1 STAGE 1. THE COMPONENT-SEPARABLE LEGALITY PREDICATE, as a PURE FUNCTION OF A FORMED
// DESCRIPTOR. See COMPONENT_SEPARABLE_RUN_DESIGN.md section 1 for the eleven conditions and
// section 2 for the correctness argument each of them discharges.
//
// It is a free function rather than a member, and it re-derives each member's route facts from
// `RunMember::raw` through ClassifyTypedAluRoute() rather than from a second opcode list, for the
// same two reasons that function exists at all: there must be exactly ONE table of what a route
// proves, and a predicate that takes only a descriptor can be tested against a descriptor without
// a translator, a guest program or a config global.
//
// IT READS NO config SWITCH. Whether the answer is USED is FormRun's business (and, from Stage 2,
// the bound selection's); whether it is TRUE is a property of the run. Keeping the two apart is
// what lets the switch's "off" arm mean the absence of the rule rather than a weaker rule.
//
// CONSERVATIVE IN ONE DIRECTION ONLY. Every condition can refuse a run that would in fact have
// been separable (the design's section 2.3 lists which, and what would have to be proved to relax
// P4 and P5); none can accept one that is not. An empty descriptor is not separable.
bool RvvRunComponentSeparable(RunDescriptor const &d);

// P7O-2, design section 5.4. THE ONE PRECONDITION DEMAND PLACEMENT NEEDS THAT NOTHING ELSE DOES.
//
// Rule S uses `last_def[r]` as an EMISSION POSITION -- the store of live-out `r` is emitted after
// member `last_def[r]` has finished the component -- so that index has to name a member the frame
// will actually emit. Every other consumer of `last_def` reads it as dataflow, where a stale index
// is at worst a wrong answer to a question nobody asks.
//
// TODAY THIS HOLDS BY COINCIDENCE, WHICH IS THE REASON IT IS A FUNCTION. FormRun's trailing-scalar
// trim rewrites `n_members` and does NOT rewrite `last_def[]` or `live_out_mask`; that is safe only
// because the trim drops SCALAR members, whose commit path never writes either field, and because
// P5 excludes any run that has a scalar member from being component-separable at all. If the trim
// ever learns to drop a vector member, Rule S would anchor a store to a member that no longer
// exists -- and the failure mode is a frame that stores nothing for that live-out, not a
// translation error. So the emitter asks this before it places anything.
//
// It is stated over `live_out_mask` only: the other entries stay -1 by RunDescriptor's constructor
// and are never read as positions.
inline bool RvvRunDemandStoreAnchorsValid(RunDescriptor const &d)
{
	for (u32 r = 0; r < rv32::VREG_NUM; ++r) {
		if (!(d.live_out_mask & (1u << r)))
			continue;
		if (d.last_def[r] < 0 || (u32)d.last_def[r] >= (u32)d.n_members)
			return false;
	}
	return true;
}

// P7O-1 STAGE 2. THE SAME PREDICATE, SPLIT SO THE SCAN CAN ASK IT ABOUT A CANDIDATE.
//
// The pressure bound has to be chosen BEFORE a member is committed -- that is what makes the cut
// "this member does not fit" rather than "the run the allocator cannot colour". At that moment
// there is no RunMember and no descriptor, only the classifier's answer and the route's admitted
// shape. These two aggregates are what the scan has, and they are the SAME inputs
// RvvRunComponentSeparable feeds from a formed descriptor, so there is exactly one implementation
// of each condition. Aggregates rather than long parameter lists because both carry several
// same-typed fields, and a positional list is one inserted field away from silently transposing
// two of them.
struct MemberSeparableFacts {
	u32 raw{};
	RunOp op{RunOp::None};
	bool src1_is_xbase{};
	u8 sew_bytes{};
	u8 nchunks{};
	u16 chunk_bytes{};
};

// C4k. WHICH REGISTER-GROUP WIDTH THE CALLER'S BODY CAN ADDRESS.
//
// This is a PERMISSION THE CALLER GRANTS, not a property of the run, and it is a distinct enum
// rather than a `bool` for two reasons. It sits next to `bool partial_vl_ok` in a POSITIONAL
// aggregate, which is exactly the "one inserted field away from silently transposing two of them"
// hazard the comment above names -- a distinct type makes a transposition a compile error rather
// than a wrong answer. And its default is the REFUSING value, so a caller that is not updated
// keeps its pre-C4k answer on every input.
//
//   SingleRegister  the caller's body tiles ONE architectural vector register, so the
//                   element -> component partition it reasons about is only defined at EMUL = 1.
//                   This is what every pre-C4k caller meant and what they keep meaning.
//   RegisterGroup   the caller's body addresses the whole register GROUP through rv32_vector.h's
//                   `group_chunk_location`, which places component c at the group's logical byte
//                   `c * chunk_bytes` and therefore crosses a register boundary by moving to the
//                   next VLEN_MAX_BYTES slot IN ELEMENT ORDER. Only such a caller may be told
//                   about an integral EMUL > 1.
//
// It licenses NOTHING else. Fractional EMUL, guest memory, scalar passthrough, cross-lane members
// and the per-member conditions are refused for their own reasons, with or without it.
enum class GroupAddressing : u8 {
	SingleRegister,
	RegisterGroup,
};

struct FrameSeparableFacts {
	u8 nchunks{};
	u16 chunk_bytes{};
	u32 vlen_bits{};
	i8 lmul_log2{};
	bool has_mem{};
	u32 mem_base_mask{};
	u8 n_scalar_members{};
	u8 n_vector_members{};
	u8 n_members{};
	bool partial_vl_ok{};
	// C4k. Appended LAST and defaulted to the refusing value so that every pre-C4k positional
	// initializer -- the scan's, and RvvRunComponentSeparable's -- is unchanged and still means
	// "one register".
	GroupAddressing group_addressing{GroupAddressing::SingleRegister};
};

// P2, P4, P5, P7, and the per-member halves of P3 and P9.
bool RvvRunMemberSeparable(MemberSeparableFacts const &m, u8 run_sew_bytes, u8 run_nchunks,
			   u16 run_chunk_bytes);
// P1, P4, P5, P6, and the frame halves of P3 and P9.
bool RvvRunFrameSeparable(FrameSeparableFacts const &f);

// C4e. MAY THIS RUN'S BODY BE EMITTED AS `nchunks` CONTIGUOUS COMPONENT SLICES?
//
// It is `RvvRunComponentSeparable` with ONE condition answered differently -- P6's vl half -- and
// it is a separate function rather than a parameter on that one because the two answer questions
// with different scopes: `RvvRunComponentSeparable` is an ADMISSION decision that also selects a
// different pressure bound, while this is an EMISSION decision taken after the run is already
// formed. Both go through the same `RvvRunMemberSeparable` / `RvvRunFrameSeparable` pair, so no
// second copy of any condition exists.
//
// WHY P6's vl HALF IS DISCHARGED RATHER THAN INHERITED. P6 refuses `partial_vl_ok` because under
// `vl <= VLMAX` a component's active lane set is a run-time quantity rather than the whole chunk.
// The transformation this predicate licenses is a PERMUTATION of the k component slices, and a
// component's active lane set is a pure function of (vl, vstart, c) -- the same function in either
// order, rebuilt per component from CPUState by the lane op or by the frame's per-chunk mask node.
// Under P2 (lane locality) member i's component-c result depends only on component-c inputs, so
// both orders are linear extensions of the SAME SSA value graph whatever `vl` is. No condition
// below relies on a component's lane set being the full chunk.
//
// C4k. AND WHY THIS IS ALSO THE ONE CALLER THAT ADDRESSES A REGISTER GROUP.
//
// C4e refused EMUL > 1 here and recorded the reason: relaxing two of P7O-1's conditions in one
// change would make neither separately falsifiable. That is why it is a SECOND change and why it
// is stated as a caller's permission (`GroupAddressing`, see FrameSeparableFacts) rather than as a
// weaker condition -- `RvvRunComponentSeparable` keeps the refusing default, so P7O-1's EMUL == 1
// condition is still exactly as falsifiable as it was.
//
// THE DISCHARGE, for an INTEGRAL EMUL only. A component is the group's logical byte interval
// `[c*chunk_bytes, (c+1)*chunk_bytes)`, and `group_chunk_location` (rv32_vector.h) maps it to
// register `base + (c*chunk_bytes)/reg_bytes`, byte `(c*chunk_bytes) % reg_bytes`. Component c's
// first element is `e(c) = c*chunk_bytes/sew`, and RVV 1.0 places group element `e` in register
// `base + e/(reg_bytes/sew)`; substituting gives `e(c)/(reg_bytes/sew) == c*chunk_bytes/reg_bytes`,
// the SAME register displacement. So the element order, and with it:
//
//   * the SUFFIX property -- `e(c)` is strictly increasing in c, so `vl <= e(c)` implies every
//     later component is inactive too;
//   * the UNIQUENESS of the element -> component map -- a run has ONE vtype, so one map;
//   * the DISJOINTNESS of the k component dataflows -- `c |-> c*chunk_bytes` is injective on
//     `[0, group_bytes)`, so crossing a register boundary changes only WHICH register a slice's
//     loads and stores name, never which values a slice owns;
//
// all hold across a register boundary exactly as they hold inside one register. What does NOT
// follow from the old geometry test, and is therefore written as its own condition in the
// predicate, is that a chunk must not STRADDLE a register boundary.
//
// The remaining conditions are UNCHANGED and are what keep the class the same one: fractional
// EMUL, guest memory, scalar passthrough, masked encodings, cross-lane rows and a member of
// another shape are all still refused, so no memory, reduction, permutation or whole-register
// family becomes reachable through this.
bool RvvRunGroupedComponentMajor(RunDescriptor const &d);

// Form the maximal run starting at `entry_pc`.
//
//   vmem_base    guest memory base; instruction words are read as *(u32 *)(vmem_base + pc)
//   entry_pc     first candidate member's pc
//   boundary_pc  the ip range's exclusive end; the scan never reads a word at or past it
//   insn_budget  how many more instructions this translation block may still contain
//   vtype        the single vtype the run is formed under -- an observed in-block `vsetvli`
//                constant, or the candidate shape the single-instruction routes propose when
//                nothing was observed, plus WHICH of the two it is. The emitted guard proves the
//                value at run time either way; the flag exists because a route may legitimately
//                refuse to bet on a shape nobody observed (TypedAluRouteInfo::
//                requires_observed_vtype).
//   caps         what the backend compiling this run can lower; the ONE thing it currently
//                decides is whether the `requires_observed_vtype` refusal above applies to the
//                host-FP lane routes. See RunBackendCaps.
//   vlen_bits    config::vlen_bits at translation time
//
// Returns a descriptor; `Empty()` when nothing was admitted, with `cut` naming why.
RunDescriptor FormRun(uptr vmem_base, u32 entry_pc, u32 boundary_pc, u32 insn_budget, RunVType vtype,
		      RunBackendCaps caps, u32 vlen_bits, RunLimits limits, MemberAdmit admit);

// Translation-time diagnostics. Counters only; nothing here participates in a decision, and
// nothing here is on an execution path. Not synchronized -- like the other translator-side Stats
// blocks in rv32_qir.h, it is a compile-time diagnostic, not a measurement instrument.
struct Stats {
	u64 scans = 0;		    // FormRun calls from the translator
	u64 runs_formed = 0;	    // scans that admitted at least one member
	u64 multi_member_runs = 0;  // scans that admitted two or more
	u64 members_admitted = 0;   // total admitted members
	u64 cuts[kCutReasonCount] = {};
	// P7M-C1: the MEMBER-COUNT HISTOGRAM. `multi_member_runs` says how many runs had two or more
	// members; on a real application the interesting question is how many had two, how many
	// three, and so on, because that distribution is what decides how much of the workload a
	// cross-operation lowering can reach. Index i counts runs that admitted exactly i members;
	// index 0 counts scans that admitted none. Bounded by kMaxRunMembers by construction --
	// FormRun cannot commit more.
	u64 members_hist[kMaxRunMembers + 1] = {};
	// P7N-G. WHAT LIVE-RANGE SPLITTING COST, separated into the ops that REPLACE one the fixed
	// placement would have emitted anyway and the ops that are genuinely new. Reporting only a
	// total would hide the cost inside a number that also went down.
	//
	//   split_load_first   a live-in component's FIRST load        (replaces a pass-1 load)
	//   split_reload       a later load of the same component      -- EXTRA
	//   split_store_dead   store of an already-dead component      (replaces a pass-3 store)
	//   split_spill_live   store of a component still to be used   -- EXTRA
	//   split_store_final  the closing loop's store                (replaces a pass-3 store)
	//   split_peak_resident  the largest resident set any frame held
	u64 split_frames = 0;
	u64 split_load_first = 0;
	u64 split_reload = 0;
	u64 split_store_dead = 0;
	u64 split_spill_live = 0;
	u64 split_store_final = 0;
	u64 split_peak_resident = 0;
};
extern Stats g_stats;

// P7M-E. THE PER-FRAME **DYNAMIC** EXECUTION CENSUS (`--rvv-run-frame-census`, default off).
//
// WHY IT EXISTS AND WHY NOTHING ABOVE CAN REPLACE IT. Everything in `Stats` is a TRANSLATION-TIME
// formation count: `members_admitted` says how many members were admitted while translating, not
// how many were ever executed, and `members_hist` says how the formed runs were shaped, not which
// of them lie on a hot path. `COMPONENT_INDEPENDENCE_CAUSAL_SYNTHESIS.md` section 16 showed that
// this is exactly the gap that makes a D=1 power estimate impossible for the accepted workloads:
// the stored artifacts bound the member executions from ABOVE (every admitted member, assumed hot)
// while a power argument needs a bound from BELOW. `CPUState::rvv_direct_hits` cannot close it
// either -- it is one `inc` at the join of EVERY typed frame, so it cannot separate a multi-member
// run frame from a single-instruction one, and it is a single global with no per-frame identity.
//
// WHAT AN ENTRY IS. One emitted multi-member run frame. `count` is incremented by EMITTED code at
// that frame's fast-arm join -- the same site and the same reasoning as `EmitRvvHitCount`, so a
// guard MISS (which leaves through the fallback label) is never counted. The identity is fixed at
// translation time and never changes afterwards.
//
// A REGION MAY BE TRANSLATED MORE THAN ONCE. Each translation allocates its own entries, so a
// retranslated region contributes several rows with the same `tb_pc`/`frame_index`; the consumer
// sums them. Recording it this way rather than reusing a slot is deliberate: two translations can
// legitimately produce different frame shapes, and silently merging them would hide that.
//
// IT IS NOT A TIMING INSTRUMENT. Arming it changes the emitted bytes of every multi-member run
// frame, so it must never be enabled on an arm that is being timed. It answers a COUNTING
// question, which is all section 16.4 asked for.
struct FrameCensusEntry {
	u32 tb_pc;	 // region entry guest PC this frame was emitted under
	u16 frame_index; // emission order of the frame within that translation of that region
	u8 n_members;	 // static admitted members (>= 2; single-member runs are not registered)
	u8 k;		 // host components per guest vector register (RunDescriptor::nchunks)
	u64 count;	 // dynamic fast-arm executions, incremented by emitted code
};

// Allocates one entry and returns a pointer whose address is STABLE for the process lifetime --
// emitted code holds `&entry->count` as an absolute immediate, so a reallocating container would
// leave live code pointing at freed memory. Returns nullptr when the switch is off, which is what
// makes "off" mean "no slot, therefore no emitted increment" in one place.
FrameCensusEntry *FrameCensusAlloc(u32 tb_pc, u16 frame_index, u8 n_members, u8 k);
// Iteration for the exit dump, in allocation (translation) order.
void FrameCensusForEach(void (*fn)(FrameCensusEntry const &, void *), void *ctx);

void RecordStats(RunDescriptor const &d);

// F1 SCAN FAST-REJECT (2026-09-23). FormRun's answer for a scan that CANNOT admit a first member,
// computed without forming a descriptor; std::nullopt when FormRun must run.
//
// A run's first member must be a VECTOR member: a scalar-passthrough candidate is refused while
// n_vector_members == 0 (FormRun's ScalarInsn arm), and a non-member cuts at once. Every check
// FormRun makes BEFORE that first classification -- vtype usability, the member cap, the budget,
// the region boundary -- also ends the scan with zero members. This function evaluates exactly
// those checks, in FormRun's order, on FormRun's inputs, and returns the cut FormRun would record;
// it returns nullopt as soon as the first instruction is a vector-member candidate, so it never
// decides anything FormRun's admission predicates, shape or pressure rules decide. The equivalence
// (value => FormRun forms zero members with this exact cut) is pinned differentially by
// rvv_run_scan_fast_reject_test against the unchanged FormRun.
std::optional<CutReason> EmptyScanCut(uptr vmem_base, u32 entry_pc, u32 boundary_pc, u32 insn_budget,
				      RunVType vtype, u32 vlen_bits, RunLimits limits);
// RecordStats for a zero-member descriptor whose cut is `cut`, without the descriptor.
void RecordEmptyScan(CutReason cut);
// P7N-G. Translation-time diagnostic, called once per emitted splitting frame.
void RecordSplitCost(u32 load_first, u32 reload, u32 store_dead, u32 spill_live, u32 store_final,
		     u32 peak_resident);

} // namespace dbt::rv32::rvvrun
