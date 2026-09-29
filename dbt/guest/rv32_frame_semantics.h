#pragma once

// P1b. THE COMMON FRAME FINALIZER FOR TYPED-CHUNK FRAMES.
//
// WHAT THIS FILE IS. The one place that closes a typed-chunk frame. At finalization it DERIVES the
// frame's active-suffix semantics from the QIR body the producer actually emitted, DECIDES legality
// and the policy class, INSERTS each bound immediately before its unit, updates `n_typed`,
// RELOCATES the `vec.vstart = 0` write when a bound makes the last body node skippable, and creates
// the frame's end node. The ten producers no longer do any of that.
//
// WHY FINALIZATION AND NOT `Create_rvvtypedchunkbegin` (P1 revision C2, now load-bearing). A begin
// builder cannot inspect nodes that do not exist yet: `n_typed` must be complete at begin (QEmit
// reads it in Emit_rvvtypedchunkbegin and Panics at Emit_rvvtypedchunkend on a mismatch), a bound
// must precede the unit it guards, and the body is created only after begin returns. The first
// moment the whole body is visible is just before the end node, and `n_typed` has no reader before
// QEmit, so it can be completed here.
//
// ONE CLASSIFIER, NOT TWO. The decision itself is still `rvvplan::ActiveChunkPlan` -- P1b moves its
// CALLERS from the ten producers into this file, it does not add a second predicate. `ClassifyNode`
// below is the derivation table (QIR opcode + node fields, never a guest opcode name); the checks
// in `FinalizeFrame` are this finalizer's own post-conditions on what it derived, which is the only
// semantic checking left after P1a's transitional duplicate was removed.
//
// WHAT THE PRODUCER STILL STATES, AND WHY EACH ONE CANNOT BE DERIVED BEFORE THE BODY EXISTS:
//
//   * `policy_enabled` -- which of the three cost-profile ablation switches this frame's work unit
//     belongs to. That is a POLICY fact (a config switch), not a semantic one.
//   * `units`, `unit_dest_bytes`, `dest_element_bytes` -- the producer's own tiling arithmetic,
//     which it must do anyway because each body node carries its element base. The finalizer
//     re-derives the unit count and every base FROM THE NODES and refuses a disagreement, so these
//     are checked, not trusted, and the bound's immediate is COPIED from the node it guards rather
//     than recomputed -- the two cannot drift by construction.
//   * `static_full_vl_proved` -- W21's block-scoped tracker answer, external to the frame.
//   * `vstart_owner` and `per_unit_mask` -- both ARE derived and cross-checked here; they are
//     stated because `WillBound` must answer before the body exists for the two FP routes whose
//     BODY LAYOUT depends on the answer (batch size and mask-node placement).
//
// `guard_kind` and `suffix_is_body_tail` are no longer stated by anyone: the finalizer reads them off the
// begin node.
//
// FAIL CLOSED MEANS PANIC HERE. Every refusal below is a disagreement between what a producer built
// and what its own nodes say, i.e. a translator bug; there is no "carry on unbounded" that is safe
// once the frame has been laid out for one answer.

#include "dbt/config.h"
#include "dbt/guest/rv32_active_chunk_plan.h"
#include "dbt/guest/rv32_lowering_decision.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <vector>

namespace dbt::rv32::rvvfinal
{

// P1 design section 2.1. A per-unit architectural effect is classified by WHETHER THE EMITTED CODE
// ALREADY MASKS THE UNIT'S CONTRIBUTION, never by whether the effect "sounds sticky".
//
//   Omissible         with the unit's active mask empty the effect is already a no-op in the
//                     emitted code (a k1-masked store writes no byte; a mask-destination
//                     read-modify-write stores back the value it read).
//   IdentityReducible the effect accumulates into an accumulator with an identity element, the
//                     unit's contribution is ALREADY AND-ed with its active mask, and the
//                     accumulator's fold point (if it has one) lies on the early-exit path.
//   Forbidding        anything else.
enum class EffectClass : u8 { Omissible = 0, IdentityReducible = 1, Forbidding = 2 };

// The role a node plays in its frame. `Anchor` is the node that performs one unit's lane operation
// and is the node a bound must guard; `MaskSet` is the FP families' per-unit mask node, which when
// present is the FIRST node of its unit and therefore where the bound goes.
enum class NodeRole : u8 { Anchor, Bound, MaskSet, Support, Unclassified };

// P1c. WHY A FRAME IS NOT A CANDIDATE FOR ACTIVE-SUFFIX ELIMINATION. Every typed-chunk frame in
// rv32_qir.cpp closes through the common entry and carries exactly one of these; `Unclassified` is
// never legal for a producer to declare and fails closed.
//
//   None                      the ten element-wise destination-indexed families the planner decides
//   MultiMember               a vector run: an early exit would jump past LATER guest instructions
//   WholeRegisterEvl          EVL = nregs*VLEN/EEW, independent of vl and legal under vill, so a
//                             `vec.vl` exit would be WRONG rather than merely unprofitable
//   ScalarResult              the destination is element 0 or a scalar register, so dropping a
//                             trailing input unit changes the RESULT, not just the work
//   IsaCrossLane              destination element i is not a function of source element i alone
//   MemoryOrProtocol          guest memory access, or the two-arm/partial-arm frame protocol whose
//                             single `vstart` write has no placement inside a bounded region
//   LoweringNotDecomposed     the lowering presents no contiguous per-unit region: one node covers
//                             the whole register group, or per-chunk nodes are emitted batch-major
//   EligibleShapeNotEnrolled  shape-eligible but deliberately NOT wired to the planner (mask logic;
//                             P1 open question O3). Recorded so it is visible rather than silent.
enum class Ineligibility : u8 {
	None = 0,
	MultiMember,
	WholeRegisterEvl,
	ScalarResult,
	IsaCrossLane,
	MemoryOrProtocol,
	LoweringNotDecomposed,
	EligibleShapeNotEnrolled,
	Unclassified,
};

inline char const *ReasonName(Ineligibility r)
{
	switch (r) {
	case Ineligibility::None: return "none";
	case Ineligibility::MultiMember: return "multi-member";
	case Ineligibility::WholeRegisterEvl: return "whole-register-EVL";
	case Ineligibility::ScalarResult: return "scalar-result";
	case Ineligibility::IsaCrossLane: return "ISA-cross-lane";
	case Ineligibility::MemoryOrProtocol: return "memory/protocol";
	case Ineligibility::LoweringNotDecomposed: return "lowering-not-decomposed";
	case Ineligibility::EligibleShapeNotEnrolled: return "eligible-shape-not-enrolled";
	default: return "unclassified";
	}
}

} // namespace dbt::rv32::rvvfinal

// ---------------------------------------------------------------------------------------------
// THE TWO PROJECTIONS THIS FILE OWNS. Both live here, next to the enums they read, so that adding
// a reason or a guard kind and forgetting its lowering meaning is a change in ONE file rather than
// a silent hole in another. `rvv_lowering_decision_test.cpp` section [2] enumerates both domains
// and requires a projection for every value.
namespace dbt::rv32::rvvlower
{

// `Ineligibility` answers "why can this frame not drop its inactive suffix". That is NOT a
// lowering-quality question, and most values project onto axes that say nothing about parallelism
// -- which is exactly why this projection must never be folded into a `Decision` unconditionally.
//
// THE RULE THE ONE CALLER FOLLOWS (CloseFrame, below): fold this in ONLY when the frame's own
// nodes already say the frame scalarized. Then, and only then, the declared reason is also the
// lowering reason -- a `_vmemorynative` frame is an element loop BECAUSE of the memory protocol, a
// `_vgathernative` element loop BECAUSE the access is cross-lane, a `_vfestimate` frame BECAUSE
// its lowering was never decomposed. On a packed frame the same values mean something else
// entirely (every full-VL `vadd.vv` frame declares `MemoryOrProtocol`, and it is pure packed SIMD),
// so folding them there would manufacture a reason for a lowering that has no deficiency.
constexpr ConstraintSet ConstraintsFor(rvvfinal::Ineligibility r)
{
	switch (r) {
	case rvvfinal::Ineligibility::None:
		return Set();
	// A run: the frame holds several guest instructions. Nothing about lane parallelism.
	case rvvfinal::Ineligibility::MultiMember:
		return Set();
	// EVL is nregs*VLEN/EEW, independent of vl and legal under vill.
	case rvvfinal::Ineligibility::WholeRegisterEvl:
		return Set(Constraint::VlVstart);
	// The destination is element 0 or a scalar register.
	case rvvfinal::Ineligibility::ScalarResult:
		return Set(Constraint::CrossLane);
	case rvvfinal::Ineligibility::IsaCrossLane:
		return Set(Constraint::CrossLane);
	case rvvfinal::Ineligibility::MemoryOrProtocol:
		return Set(Constraint::MemoryProtocol);
	// One node covers the whole register group, or the units are emitted batch-major. On a
	// SCALARIZING frame that is the definition of an unwritten packed lowering.
	case rvvfinal::Ineligibility::LoweringNotDecomposed:
		return Set(Constraint::MissingLowering);
	case rvvfinal::Ineligibility::EligibleShapeNotEnrolled:
		return Set(Constraint::MissingLowering);
	default: // Unclassified: a frame that reached the close without a classification
		return Set(Constraint::MissingLowering);
	}
}

// WHAT A FRAME'S EMITTED GUARD RE-TESTS AT RUN TIME, on the shared axes. A miss on any of them
// leaves the emitted body through the fallback edge and runs the helper, so this set IS the
// "conditional direct" property, read off the one field that decides the emitted guard.
//
// Derived from the two predicates qir.h already exports plus the facts the kind names carry, so
// this cannot drift from the guard QEmit emits:
//   * every `VType*` kind compares `vec.vtype` for exact equality, which pins SEW and LMUL;
//   * `GuardProvesFullVl` adds `vl == VLMAX && vstart == 0`; the `*NoRestart` kinds and the
//     `Vlenb*` kinds test `vstart == 0` without pinning vl;
//   * a `Frm` kind tests the guest rounding mode; a `Base`/`BaseMask` kind tests a guest address
//     range, which is a memory-protocol term rather than a vtype term.
// VLEN is not on the axis list on purpose: `vlenb` is a build constant of this rvdbt, not a
// property of the guest instruction, so the `Vlenb*` kinds contribute only their vstart term.
constexpr ConstraintSet ConstraintsFor(qir::InstRVVTypedChunkBegin::GuardKind k)
{
	using G = qir::InstRVVTypedChunkBegin::GuardKind;
	ConstraintSet s = Set();
	bool const vlenb_kind = k == G::VlenbVstart || k == G::VlenbVstartBaseLimit ||
				k == G::VlenbRestartable;
	if (!vlenb_kind)
		s |= Set(Constraint::Sew, Constraint::Lmul); // the exact vec.vtype compare
	if (qir::InstRVVTypedChunkBegin::GuardProvesFullVl(k))
		s |= Set(Constraint::VlVstart);
	switch (k) {
	case G::VlenbVstart:
	case G::VlenbVstartBaseLimit:
	case G::VTypeIntegerNoRestart:
	case G::VTypeFpNoRestart:
	case G::VTypeFpAnyRMNoRestart:
	case G::VTypePartialVlVstartFrmRNE:
	case G::VTypeE32OrE64M2PartialVlVstartFrmRNE:
	case G::VTypePartialVlVstartFrmHost:
	case G::VTypePartialVlVstartFrmHostRound:
	case G::VTypeVlOrPartialVstart:
	case G::VTypeVlOrPartialVstartBaseLimit:
		s |= Set(Constraint::VlVstart); // vstart == 0 without pinning vl to VLMAX
		break;
	default:
		break;
	}
	switch (k) {
	case G::VTypePartialVlVstartFrmRNE:
	case G::VTypeE32OrE64M2PartialVlVstartFrmRNE:
	case G::VTypeVlVstartFrmRNE:
	case G::VTypeVlVstartFrmHostRound:
	case G::VTypePartialVlVstartFrmHostRound:
	case G::VTypePartialVlVstartFrmHost:
	case G::VTypeVlVstartFrmRNEBaseMask:
	case G::VTypeFpNoRestart:
		s |= Set(Constraint::Rounding);
		break;
	default:
		break;
	}
	switch (k) {
	case G::VTypeVlVstartBaseLimit:
	case G::VlenbVstartBaseLimit:
	case G::VTypeVlOrPartialVstartBaseLimit:
	case G::VTypeVlVstartFrmRNEBaseMask:
	case G::VTypeVlVstartBaseMask:
		s |= Set(Constraint::MemoryProtocol); // a guest address-range term
		break;
	default:
		break;
	}
	return s;
}

} // namespace dbt::rv32::rvvlower

namespace dbt::rv32::rvvfinal
{

struct NodeFacts {
	NodeRole role = NodeRole::Unclassified;
	bool has_base = false;	 // carries an architectural element index
	u32 base = 0;
	bool has_ordinal = false; // carries a host work-unit ordinal
	u32 ordinal = 0;
	bool has_finish = false; // participates in the LastChunkNode vstart convention
	bool finish = false;
	u32 lanes = 0;		    // MaskSet only: elements this unit covers
	EffectClass worst = EffectClass::Omissible;
	bool accrues_fp_exceptions = false; // needs an FP bracket fold on the early-exit path
	// P1c: the reason THIS NODE TYPE puts on its frame, or `None` when the node says nothing
	// about eligibility (a load into CPUState, a broadcast, a mask node, the FP bracket).
	Ineligibility reason = Ineligibility::None;
	bool guest_memory = false;
	// THE SHAPE OF THE HOST CODE THIS NODE'S EMITTER PRODUCES, and why it is not packed.
	//
	// Derived the same way every other field on this struct is -- from the QIR opcode plus the
	// node's OWN fields, never from a guest mnemonic -- and cross-checked against
	// `dbt/qmc/qcg/qemit.cpp` row by row by rvv_lowering_decision_test.cpp section [3]. The
	// default is `PackedSIMD`, which is the honest default: all but a handful of QCG emitters
	// emit one host instruction per chunk, and a node whose emitter does not is listed
	// explicitly below with the axis that forces it.
	//
	// THIS IS A QCG STATEMENT. Under `config::aot_use_llvm` the same nodes lower through
	// llvmgen, so the one caller that reads this field refuses to record under that switch.
	rvvlower::Codegen codegen = rvvlower::Codegen::PackedSIMD;
	rvvlower::ConstraintSet codegen_why = 0; // empty iff `codegen == PackedSIMD`
};

// Does this `_vchunkpartialalu` kind, at this element width, take Emit_vchunkpartialalu's SCALAR
// LANE ARM?
//
// THE MIRROR OF ONE LINE OF THE EMITTER, and it has to be exact. qemit.cpp:3732 reads
//
//     if (divide || ((high_multiply || fractional) && ins->sew_bytes == 8))
//
// and its own comment states why: "AVX-512 has neither packed integer divide nor 64x64 high-
// product. Emit exact host scalar operations for active lanes, without a C++ helper call." That
// arm emits, per lane, a `bt`/`jnc` pair, a scalar load, a sign normalisation, an `idiv`/`div` or
// `imul`/`mul`, and a scalar store -- fully unrolled at translation time. It is native code and it
// has no lane parallelism at all, which is the distinction this whole header exists to record.
//
// The two operands of that expression are node FIELDS (`op`, `sew_bytes`), so this is decidable
// here and cannot drift by construction; the test enumerates all 52 kinds x 4 widths against an
// independently written copy of the emitter's condition.
constexpr bool PartialAluScalarizesLanes(u8 op, u8 sew_bytes)
{
	using Kind = qir::InstVChunkPartialAlu::Kind;
	auto const k = (Kind)op;
	bool const divide = k == Kind::DivU || k == Kind::DivS || k == Kind::RemU || k == Kind::RemS;
	bool const high_multiply = k == Kind::MulHU || k == Kind::MulH || k == Kind::MulHSU;
	bool const fractional = k == Kind::FracMul;
	return divide || ((high_multiply || fractional) && sew_bytes == 8);
}

// Does this `_vchunkpartialalu` kind accrue the sticky `vxsat`?
//
// Derived from the emitter, not guessed: the four `or [vec.vxsat], ...` sites in QEmit all live in
// Emit_vchunkpartialalu -- the saturating add/sub arm, the two clip arms and the fractional-multiply
// scalar lane loop. Three AND the contribution with the live body mask before the OR; the fourth
// (`or [vec.vxsat], 1` in the fractional path) sits inside a `bt rdi, lane; jnc skip` per-lane loop
// and is unreachable when the mask is empty. All four therefore contribute the OR identity 0 for an
// entirely inactive unit, which is what makes them IdentityReducible rather than Forbidding.
inline bool PartialAluAccruesVxsat(u8 op)
{
	using Kind = qir::InstVChunkPartialAlu::Kind;
	auto const k = (Kind)op;
	return k == Kind::SatAddU || k == Kind::SatAddS || k == Kind::SatSubU || k == Kind::SatSubS ||
	       k == Kind::ClipU || k == Kind::ClipS || k == Kind::FracMul;
}

// The per-node-type derivation table. It reads ONLY the node's own fields.
inline NodeFacts ClassifyNode(qir::Inst *ins)
{
	NodeFacts f;
	switch (ins->GetOpcode()) {
	case qir::Op::_vchunkactive: {
		auto *n = static_cast<qir::InstVChunkActive *>(ins);
		f.role = NodeRole::Bound;
		f.has_base = true;
		f.base = n->element_base;
		f.has_ordinal = true;
		f.ordinal = n->chunk;
		return f;
	}
	case qir::Op::_vchunkmaskset: {
		auto *n = static_cast<qir::InstVChunkMaskSet *>(ins);
		f.role = NodeRole::MaskSet;
		f.has_ordinal = true;
		f.ordinal = n->chunk;
		f.lanes = n->lanes;
		return f;
	}
	case qir::Op::_vchunkpartialalu: {
		auto *n = static_cast<qir::InstVChunkPartialAlu *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->element_base;
		f.has_ordinal = true;
		f.ordinal = n->chunk;
		f.has_finish = true;
		f.finish = n->finish_instruction;
		// A node that derives its own lane mask inside its own region is the per-unit mask
		// placement; the legacy form consumes the frame's k(1+chunk) and cannot be bounded.
		f.worst = n->architectural_mask
			      ? (PartialAluAccruesVxsat(n->op) ? EffectClass::IdentityReducible
							      : EffectClass::Omissible)
			      : EffectClass::Forbidding;
		if (PartialAluScalarizesLanes(n->op, n->sew_bytes)) {
			// The one QCG lane node whose shape depends on its own fields rather than on
			// its opcode. `HostIsa` and nothing else: there is no packed x86 form to
			// write, so this scalarization is necessary rather than unfinished work.
			f.codegen = rvvlower::Codegen::NativeScalar;
			f.codegen_why = rvvlower::Set(rvvlower::Constraint::HostIsa);
		}
		return f;
	}
	case qir::Op::_vchunknarrowshift: {
		auto *n = static_cast<qir::InstVChunkNarrowShift *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f; // vnsrl/vnsra set no sticky flag; only the vnclip arm above does
	}
	// Order item 4: the narrowing CLIP. Same Anchor shape as the narrowing shift -- it owns a
	// chunk of the destination and carries `finish` -- and unlike it, this one DOES set `vxsat`.
	// That is a property of the operation, not of the unit structure, so it does not change the
	// role; what it changes is that dropping a trailing unit would drop that unit's contribution
	// to a sticky flag, which is why the frame it lives in plans no active bound.
	case qir::Op::_vchunknarrowclip: {
		auto *n = static_cast<qir::InstVChunkNarrowClip *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f;
	}
	case qir::Op::_vchunkwiden: {
		auto *n = static_cast<qir::InstVChunkWiden *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f;
	}
	case qir::Op::_vchunkextend: {
		auto *n = static_cast<qir::InstVChunkExtend *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f;
	}
	case qir::Op::_vchunkindex: {
		auto *n = static_cast<qir::InstVChunkIndex *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f;
	}
	case qir::Op::_vchunkfclass: {
		auto *n = static_cast<qir::InstVChunkFClass *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f; // RVV 1.0: vfclass raises no FP exception
	}
	// ORDER ITEM 4: the 7-bit estimates. Same shape as `vfclass` -- one anchor per unit, its own
	// element base, a `finish` flag -- and the SAME classification, because the difference between
	// them is not visible to the planner: these two DO raise flags (DZ, NV, and for `vfrec7` also
	// OF|NX), but they raise them by an explicit OR into `fcsr` computed from the operand bits, not
	// by a host FP instruction inside a bracket. A frame's classification is about its work-unit
	// structure, not about what its units compute.
	case qir::Op::_vchunkfestimate: {
		auto *n = static_cast<qir::InstVChunkFEstimate *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f;
	}
	// Order item 4: one unit of `vfmerge.vfm` / `vfmv.v.f`. Same unit structure again; it raises
	// no FP exception at all (it is a typed SELECT, not an arithmetic operation).
	case qir::Op::_vchunkfmerge: {
		auto *n = static_cast<qir::InstVChunkFMerge *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		return f;
	}
	case qir::Op::_vchunkftoi: {
		auto *n = static_cast<qir::InstVChunkFToI *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.accrues_fp_exceptions = true;
		f.worst = EffectClass::IdentityReducible;
		return f;
	}
	case qir::Op::_vchunkitof: {
		auto *n = static_cast<qir::InstVChunkIToF *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.accrues_fp_exceptions = true;
		f.worst = EffectClass::IdentityReducible;
		return f;
	}
	case qir::Op::_vchunkftof: {
		auto *n = static_cast<qir::InstVChunkFToF *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.accrues_fp_exceptions = true;
		f.worst = EffectClass::IdentityReducible;
		return f;
	}
	// The two FP arithmetic nodes carry a work-unit ORDINAL but no element base. That asymmetry is
	// why this file takes those frames' element stride from the unit's own `_vchunkmaskset::lanes`.
	// No FP node field is added, because the source proves one is not needed here.
	case qir::Op::_vchunkfalu: {
		auto *n = static_cast<qir::InstVChunkFALU *>(ins);
		f.role = NodeRole::Anchor;
		f.has_ordinal = true;
		f.ordinal = n->chunk;
		f.accrues_fp_exceptions = true;
		f.worst = EffectClass::IdentityReducible;
		return f;
	}
	case qir::Op::_vchunkfma: {
		auto *n = static_cast<qir::InstVChunkFMA *>(ins);
		f.role = NodeRole::Anchor;
		f.has_ordinal = true;
		f.ordinal = n->chunk;
		f.accrues_fp_exceptions = true;
		f.worst = EffectClass::IdentityReducible;
		return f;
	}
	// Support nodes: no per-unit architectural effect an empty active mask could leave behind,
	// and nothing to say about eligibility either way.
	case qir::Op::_vstatechunkload:
	case qir::Op::_vstatechunkstore:
	case qir::Op::_vchunkfbroadcast:
	case qir::Op::_vchunkbroadcast:
	case qir::Op::_vchunkdep:
	case qir::Op::_rvvqcgfpbegin:
	case qir::Op::_rvvqcgfpend:
	// C5 (2026-09-17): the INTEGER lane operations, on the same row and for the same reason the
	// row already states. Unlike `_vchunkfalu`/`_vchunkfma` above they are Support rather than
	// Anchor, and that is a property of the nodes rather than a convenience:
	//
	//   * they carry NO chunk index (InstVChunkAdd and its siblings are pure two-input SSA value
	//     ops -- compare InstVChunkFALU, which carries `chunk`), so they cannot state a unit
	//     ordinal and a producer cannot be checked against one;
	//   * they have NO architectural effect at all. The value is committed by the frame's
	//     `_vstatechunkstore`, which is on this row already; an empty active mask leaves nothing
	//     behind for them either.
	//
	// EXISTING FRAMES ARE UNAFFECTED, and that is checkable rather than asserted: this row sets
	// `reason = Ineligibility::None`, whose slot the derivation chain never consults (`None` is
	// index 0 and no `else if` tests it), so every frame that reaches an earlier row -- which is
	// every frame containing these nodes today, all of which derive `MemoryOrProtocol` from the
	// `GuardProvesFullVl` arm -- derives exactly what it derived before. What the row enables is
	// the ONE shape that could not be closed at all before: a frame whose guard does not prove
	// full VL, which previously hit "unclassified node inside a finalized frame".
	// C3: the two immediate-shift lane operations, on this row for the same two reasons as the
	// integer ALU ops -- InstVChunkSll/InstVChunkSrl carry no chunk index, and the value is
	// committed by the frame's `_vstatechunkstore`, not by them.
	case qir::Op::_vchunksll:
	case qir::Op::_vchunksrl:
	case qir::Op::_vchunkadd:
	case qir::Op::_vchunksub:
	case qir::Op::_vchunkmul:
	case qir::Op::_vchunkand:
	case qir::Op::_vchunkor:
	case qir::Op::_vchunkxor:
	// Order item 4: the saturating add/sub family. SAME ROW as the ordinary lane ops and for the
	// same reason C5 gives for them: these nodes carry NO chunk index -- they are two-input SSA
	// value ops -- so there is no anchor-delimited work unit for a bound to retire. That they
	// write `vec.vxsat` is a property of the OPERATION, not of the frame's unit structure, which
	// is what this classification describes.
	case qir::Op::_vchunksatadd:
	// Order item 4: the carry/borrow family, same row and same reason.
	case qir::Op::_vchunkadc:
	// Order item 4: the averaging family, same row and same reason. It READS `vec.vxrm`, which
	// no more delimits a work unit than reading an operand does.
	case qir::Op::_vchunkavg:
	// Order item 4: the fractional multiply, same row. Like `vchunksatadd` it writes `vxsat`,
	// which is a property of the OPERATION and not of the frame's unit structure.
	case qir::Op::_vchunkfracmul:
		f.role = NodeRole::Support;
		return f;

	// -------- P1c: the node types the other 27 producer bodies emit. Each carries the ISA or
	// -------- lowering fact that keeps its frame out of active-suffix elimination.

	// The destination is element 0 or a scalar register: dropping a trailing input unit changes
	// the RESULT, not merely the work.
	case qir::Op::_vreducenative:
	case qir::Op::_vmaskscalar:
		// Both ARE packed: Emit_vreducenative tree-reduces with vshufi64x2/vpshufd and
		// Emit_vmaskscalar folds 64 mask lanes per GPR popcnt/bsf. Only their DESTINATION is
		// scalar, which is what `ScalarResult` says -- and why this row keeps the default.
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::ScalarResult;
		return f;

	// Emit_vfreducenative (qemit.cpp:3368) is an element loop over [0, vl): one vmovss/vmovsd
	// plus one vaddss/vaddsd or vucomiss/vucomisd PER ELEMENT, for every FP reduction form and
	// not only for the architecturally ordered vfredosum.
	case qir::Op::_vfreducenative: {
		auto *n = static_cast<qir::InstVFReduce *>(ins);
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::ScalarResult;
		f.codegen = rvvlower::Codegen::NativeScalar;
		// op 0 is the SUM, and FP addition does not reassociate: a tree fold would change the
		// result of vfredosum. op 1/2 are min/max, which DO reassociate -- the integer
		// reduction node next door proves the tree shape exists -- so their sequential fold is
		// unwritten work, not an ISA consequence. The node's own field separates them.
		f.codegen_why = n->op == 0 ? rvvlower::Set(rvvlower::Constraint::Rounding)
					   : rvvlower::Set(rvvlower::Constraint::MissingLowering);
		return f;
	}

	// Emit_vscalarmove (qemit.cpp:3543) is a single scalar mov. There is nothing to parallelise:
	// the architectural operation touches exactly one element, which is what `CrossLane` records
	// here -- it is a shape statement, not a deficiency.
	case qir::Op::_vscalarmove:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::ScalarResult;
		f.codegen = rvvlower::Codegen::NativeScalar;
		f.codegen_why = rvvlower::Set(rvvlower::Constraint::CrossLane);
		return f;

	// Destination element i is not a function of source element i alone: a slide/gather reads
	// element j != i, a compress's landing place depends on the mask population, and the mask
	// scan families have a left-to-right sequential dependency.
	//
	// Emit_vcompressnative is nevertheless PACKED (vpcompressb/w/d/q under a pdep-built mask) and
	// Emit_vmaskprefix folds 64 mask lanes per GPR instruction, so only the two rows below carry
	// a scalarizing shape.
	case qir::Op::_vcompressnative:
	case qir::Op::_vmaskprefix:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::IsaCrossLane;
		return f;

	// Emit_vgathernative's AVX-512 arm is guarded by `!slide && mode == 0 && sew >= 4`
	// (qemit.cpp:2911) and emits one k-masked vpgatherdd/vpgatherqq per chunk; everything else --
	// every slide form, every .vx/.vi gather, and .vv at SEW 1 or 2 -- runs the element loop at
	// qemit.cpp:2981. All three operands of that condition are node fields, so the split is
	// decidable here and mirrors the emitter exactly.
	case qir::Op::_vgathernative: {
		auto *n = static_cast<qir::InstVGather *>(ins);
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::IsaCrossLane;
		if (!(n->slide == 0 && n->mode == 0 && n->sew >= 4)) {
			f.codegen = rvvlower::Codegen::NativeScalar;
			f.codegen_why = rvvlower::Set(rvvlower::Constraint::CrossLane);
		}
		return f;
	}

	// Emit_vmaskiota (qemit.cpp:3585) is a PER-BIT loop -- bt/jnc, bzhi, popcnt, an offset
	// recomputation and a scalar element store for every set lane. Unlike its three mask
	// siblings it does not fold a whole mask word per instruction.
	case qir::Op::_vmaskiota:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::IsaCrossLane;
		f.codegen = rvvlower::Codegen::NativeScalar;
		f.codegen_why = rvvlower::Set(rvvlower::Constraint::CrossLane);
		return f;

	// EVL = nregs * VLEN / EEW, independent of vl and of vtype and legal even under vill.
	// Emit_vwholemove (qemit.cpp:3235) is a byte-offset loop with a 64-byte vmovdqu64 arm and a
	// single-BYTE arm; the byte arm is reached whenever `vstart << log2(SEW)` is not width
	// aligned, so the restart index is what forces the scalar arm to exist.
	case qir::Op::_vwholemove:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::WholeRegisterEvl;
		f.codegen = rvvlower::Codegen::NativeScalar;
		f.codegen_why = rvvlower::Set(rvvlower::Constraint::VlVstart);
		return f;

	// Guest memory. An omitted unit's skipped work would include a skipped guest access, and the
	// frame's address bound is whole-group.
	//
	// `_vchunkload`/`_vchunkstore` are the PACKED memory nodes (one vmovdqu64 per chunk, the
	// dedicated vle/vse chunk routes). `_vmemorynative` is the generic route and is
	// Emit_vmemorynative's element loop (qemit.cpp:3154): per element an offset recomputation, a
	// scalar mov and a vstart publication, and a BYTE-BY-BYTE assembly when the address wraps.
	case qir::Op::_vmemorynative:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::MemoryOrProtocol;
		f.guest_memory = true;
		f.codegen = rvvlower::Codegen::NativeScalar;
		f.codegen_why = rvvlower::Set(rvvlower::Constraint::MemoryProtocol);
		return f;

	case qir::Op::_vchunkload:
	case qir::Op::_vchunkstore:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::MemoryOrProtocol;
		f.guest_memory = true;
		return f;

	// The lowering presents no contiguous per-unit region: one node covers the whole register
	// group (the FP estimates, the LLVM wide add), or the per-chunk nodes are emitted batch-major
	// with separate load / operate / store passes (vfsqrt, the FP compare, FP widening).
	//
	// Of these five only `_vfestimate` SCALARIZES: Emit_vfestimate (qemit.cpp:3275) is a
	// whole-register element loop that does per element a scalar normalisation, a byte table
	// lookup and a scalar store, and uses no vector register at all. The other four are
	// batch-major packed bodies (vsqrtps/pd, vcmpps/pd, vcvtps2pd), so they keep the default.
	case qir::Op::_vfestimate:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::LoweringNotDecomposed;
		f.codegen = rvvlower::Codegen::NativeScalar;
		// Nothing in x86 forbids a packed 7-bit estimate (the table is a permute away); this
		// one is unwritten work, and the `MissingLowering` bucket is what measures that.
		f.codegen_why = rvvlower::Set(rvvlower::Constraint::MissingLowering);
		return f;

	case qir::Op::_vchunkfsqrt:
	case qir::Op::_vchunkfcmpstate:
	case qir::Op::_vchunkfwidencvt:
	case qir::Op::_vwideaddssa:
		f.role = NodeRole::Support;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::LoweringNotDecomposed;
		return f;

	case qir::Op::_vmasklogic: {
		auto *n = static_cast<qir::InstVMaskLogic *>(ins);
		f.role = NodeRole::Anchor;
		f.has_base = true;
		f.base = n->base;
		f.has_finish = true;
		f.finish = n->finish;
		// Empty body masks preserve the destination word; no guest memory or flags.
		return f;
	}

	default:
		f.role = NodeRole::Unclassified;
		f.worst = EffectClass::Forbidding;
		f.reason = Ineligibility::Unclassified;
		return f;
	}
}

// ---------------------------------------------------------------------------------------------

struct InstructionWorkScope {
	qir::InstVChunkPartialAlu *last = nullptr;
	u32 units = 0;
};

// A suffix exit belongs to one architectural instruction, not necessarily its
// enclosing frame. Only contiguous, independently masked, ordered units qualify.
template <typename Iterator>
inline InstructionWorkScope PlanInstructionWorkScope(Iterator it, Iterator end)
{
	if (it == end || it->GetOpcode() != qir::Op::_vchunkpartialalu)
		return {};
	auto const *first = static_cast<qir::InstVChunkPartialAlu *>(&*it);
	if (first->element_base != 0 || first->chunk != 0)
		return {};
	u32 units = 0;
	for (; it != end; ++it) {
		if (it->GetOpcode() != qir::Op::_vchunkpartialalu)
			return {};
		auto *n = static_cast<qir::InstVChunkPartialAlu *>(&*it);
		auto const facts = ClassifyNode(n);
		if (facts.worst == EffectClass::Forbidding || !n->architectural_mask ||
		    n->op != first->op || n->sew_bytes != first->sew_bytes ||
		    n->chunk_bytes != first->chunk_bytes || n->masked != first->masked ||
		    n->src1_kind != first->src1_kind || n->imm != first->imm ||
		    n->chunk != units ||
		    n->element_base != units * (n->chunk_bytes / n->sew_bytes))
			return {};
		++units;
		if (n->finish_instruction)
			return {n, units};
	}
	return {};
}

// The `vec.vstart = 0` ownership convention, re-exported from the planner so a producer names one
// namespace and the two cannot drift apart.
using VStartOwner = rvvplan::VStartOwner;

// The frame's geometry and policy class. See the header comment for why each field is here.
struct FrameGeometry {
	bool policy_enabled = false;
	u32 units = 0;
	u32 unit_dest_bytes = 0;
	u32 dest_element_bytes = 0;
	bool static_full_vl_proved = false;
	bool per_unit_mask = true;
	VStartOwner vstart_owner = VStartOwner::LastChunkNode;
	// ORDER ITEM 3 (2026-09-19), RESTART. Does this frame's EPILOGUE owe an explicit
	// `vec.vstart = 0` write?
	//
	// Every frame before this one answered NO for the same reason, and it was a property of the
	// GUARD rather than of the frame: their guard kinds prove `vstart == 0`, so the architectural
	// post-state already holds and there is nothing to write. A frame that ADMITS a nonzero
	// `vstart` has to write it, and no existing mechanism carries that fact -- `frame_clears_vstart`
	// on the end node is derived from `plan.frame_clears_vstart()`, which is
	// `bounded_ && LastChunkNode`, a QCG active-bound concept that is false for every LLVM frame by
	// construction. So this is a SEPARATE declaration ORed into the same end-node field, defaulted
	// false so every existing producer is unchanged without being edited.
	//
	// It is NOT the same question as `vstart_owner`. That says WHICH node would own the write if
	// one were needed (and every LLVM frame already says FrameEpilogue); this says whether one IS
	// needed. Conflating them would make every existing frame start emitting a store of 0 over a
	// value the guard already proved to be 0.
	bool epilogue_clears_vstart = false;
	u32 dest_element_bits = 0;
};

// The decision, built the one way it is built anywhere: the shared planner, with the two fields the
// frame's own begin node already carries read off it rather than restated by a producer.
inline rvvplan::ActiveChunkPlan BuildPlan(qir::InstRVVTypedChunkBegin const *begin,
					  FrameGeometry const &g)
{
	return rvvplan::ActiveChunkPlan::Make({
	    .family_enabled = g.policy_enabled,
	    .units = g.units,
	    .unit_dest_bytes = g.unit_dest_bytes,
	    .dest_element_bytes = g.dest_element_bytes,
	    .guard_kind = begin->guard_kind,
	    .static_full_vl_proved = g.static_full_vl_proved,
	    // C4e. The two shapes whose body order makes the inactive units a tail, read off the SAME
	    // node the guard kind is read off so the translator's answer and the emitter's cannot
	    // drift. `body_component_major` is false on every node no producer sets it on, so every
	    // frame that existed before C4e answers exactly what `n_members == 1` answered.
	    .suffix_is_body_tail = begin->n_members == 1 || begin->body_component_major,
	    .per_chunk_active_mask = g.per_unit_mask,
	    .vstart_owner = g.vstart_owner,
	    .dest_element_bits = g.dest_element_bits,
	});
}

// Unit `c`'s first architectural element index. One expression, used by the producer for its body
// node's own field and by the finalizer only as a cross-check -- the bound's immediate is COPIED
// from the node it guards, never recomputed.
inline u32 ElementBase(FrameGeometry const &g, u32 c)
{
	return c * rvvplan::ElementsPerUnit(g.unit_dest_bytes, g.dest_element_bytes,
					  g.dest_element_bits);
}

// PRE-BODY ANSWER, FOR THE TWO ROUTES WHOSE BODY LAYOUT DEPENDS ON IT. The FP lane and fused
// multiply-add bodies choose their batch size and their mask-node placement from this, so they must
// ask before they emit. It is the same decision `FinalizeFrame` re-derives and requires to agree;
// no other producer calls it.
inline bool WillBound(qir::InstRVVTypedChunkBegin const *begin, FrameGeometry const &g)
{
	return BuildPlan(begin, g).bounded();
}

// P1c. EVERYTHING A TYPED-CHUNK FRAME NEEDS TO CLOSE, including the end node the old site built.
// `reason` is the producer's classification; the common close DERIVES the reason from the frame's
// own nodes and guard and refuses a disagreement, so a producer cannot silently opt out.
struct FrameClose {
	Ineligibility reason = Ineligibility::Unclassified;
	FrameGeometry geom{}; // meaningful only when `reason == None`
	u32 raw = 0;
	RuntimeStubId stub{};
	u16 whole_regbytes = 0;
	// The run form of the end node, for the frames that build one. `members == nullptr` selects
	// the single-instruction form, which is what every other site used.
	qir::RVVRunMember const *members = nullptr;
	u8 n_members = 1;
};

// THE ONE CLOSE for every typed-chunk frame in rv32_qir.cpp.
inline void CloseFrame(qir::Builder &qb, qir::Inst *begin_inst, FrameClose const &c)
{
	if (begin_inst == nullptr || begin_inst->GetOpcode() != qir::Op::_rvvtypedchunkbegin)
		Panic("rvv frame close: frame handle is not a chunk-begin node");
	auto *begin = static_cast<qir::InstRVVTypedChunkBegin *>(begin_inst);
	FrameGeometry const &g = c.geom;
	auto const plan = c.reason == Ineligibility::None ? BuildPlan(begin, g)
							  : rvvplan::ActiveChunkPlan{};

	// ---- derive from the completed body ----
	struct Unit {
		qir::Inst *first = nullptr; // where this unit's bound goes
		qir::Inst *anchor = nullptr;
		bool has_base = false;
		u32 base = 0;
		bool has_ordinal = false;
		u32 ordinal = 0;
		bool has_finish = false;
		bool finish = false;
		u32 lanes = 0; // from this unit's own mask node, when it has one
		// C4e. The unit's identity as its anchors state it, used only to decide whether the NEXT
		// anchor is a later member of this same unit or the first anchor of the next one.
		bool keyed = false;
		u32 key = 0;
	};
	std::vector<Unit> units;
	Unit pending;
	bool pending_open = false;
	bool any_forbidding = false, has_partial_arm = false, has_fp_bracket = false;
	// The frame's LOWERING SHAPE, accumulated from the same nodes the loop below already walks.
	// A frame is as parallel as its least parallel lane node, so `Worse` folds and never unfolds.
	auto frame_codegen = rvvlower::Codegen::PackedSIMD;
	rvvlower::ConstraintSet frame_why = 0;
	bool needs_fp_fold = false, saw_bound = false;
	u32 masksets = 0;
	bool node_reason[(int)Ineligibility::Unclassified + 1] = {};

	auto it = begin_inst->getIter();
	++it;
	for (; it != qb.GetIterator(); ++it) {
		qir::Inst *ins = &*it;
		auto const op = ins->GetOpcode();
		if (op == qir::Op::_rvvtypedchunkend)
			Panic("rvv frame finalizer: the frame is already closed");
		if (op == qir::Op::_rvvtypedchunkbegin)
			Panic("rvv frame finalizer: a second frame opened inside this one");
		if (op == qir::Op::_rvvtypedchunkpartial) {
			has_partial_arm = true;
			continue;
		}
		if (op == qir::Op::_rvvqcgfpbegin || op == qir::Op::_rvvqcgfpend)
			has_fp_bracket = true;

		NodeFacts f = ClassifyNode(ins);
		// A resident integer component has pure value nodes and no arithmetic
		// anchor. Its masked publication supplies the independently checkable
		// component identity. Do not reinterpret member-major state stores.
		if (begin->body_component_major && op == qir::Op::_vstatechunkstore) {
			auto *store = static_cast<qir::InstVStateChunkStore *>(ins);
			if (store->active_sew && store->kmask) {
				if (store->Bytes() != g.unit_dest_bytes ||
				    store->active_sew != g.dest_element_bytes ||
				    store->kmask != 1 + store->chunk % qir::RVV_FP_SHARED_MASK_MAX_CHUNKS)
					Panic("rvv component publication disagrees with its active-work geometry");
				f.role = NodeRole::Anchor;
				f.has_ordinal = true;
				f.ordinal = store->chunk;
			}
		}
		node_reason[(int)f.reason] = true;
		frame_codegen = rvvlower::Worse(frame_codegen, f.codegen);
		if (f.codegen != rvvlower::Codegen::PackedSIMD)
			frame_why |= f.codegen_why;
		if (f.role == NodeRole::Unclassified && c.reason == Ineligibility::None)
			Panic("rvv frame finalizer: unclassified node inside a finalized frame");
		any_forbidding = any_forbidding || f.worst == EffectClass::Forbidding;
		needs_fp_fold = needs_fp_fold || f.accrues_fp_exceptions;

		switch (f.role) {
		case NodeRole::Bound:
			// P1b: the finalizer is the only inserter. A producer that still emits its own
			// bound would double them.
			saw_bound = true;
			break;
		case NodeRole::MaskSet:
			++masksets;
			// C4e: a mask node after a unit's anchors starts the NEXT unit. Before C4e an
			// anchor always closed its unit, so `pending_open && pending.anchor` was
			// unreachable here and this is not a change to any existing frame; it is what
			// makes a component-major slice's leading mask node open its own slice.
			if (pending_open && pending.anchor != nullptr) {
				units.push_back(pending);
				pending_open = false;
			}
			if (!pending_open) {
				pending = Unit{};
				pending_open = true;
				pending.first = ins;
			}
			pending.lanes = f.lanes;
			break;
		case NodeRole::Anchor: {
			// C4e. AN ANCHOR CLOSES A UNIT ONLY WHEN THE NEXT ANCHOR NAMES A DIFFERENT ONE.
			//
			// Before C4e every anchor ended a unit, because every producer emitted exactly one
			// anchor per work unit. A component-major RUN slice holds one anchor PER MEMBER, all
			// naming the same unit, so "one anchor = one unit" would count a k-component m-member
			// frame as m*k units and the geometry check below would refuse it.
			//
			// The key is the unit's own identity as the node states it -- its element base where
			// the node type carries one, otherwise its ordinal -- and NOT a member index, a
			// position or a count. An anchor whose key equals the open unit's EXTENDS that unit;
			// any other key, and a unit opened by a mask node, starts a new one. For every
			// pre-C4e frame the keys are strictly increasing (the two Panics below already
			// required it), so `same` is never true there and this is the old rule exactly.
			u32 const key = f.has_base ? f.base : f.ordinal;
			bool const keyed = f.has_base || f.has_ordinal;
			bool const same = pending_open && pending.anchor != nullptr && keyed &&
					  pending.keyed && pending.key == key;
			if (pending_open && pending.anchor != nullptr && !same) {
				units.push_back(pending);
				pending_open = false;
			}
			if (!pending_open) {
				pending = Unit{};
				pending_open = true;
				pending.first = ins;
			}
			if (same) {
				// The slice's later members must agree with it about which unit this is;
				// a disagreement is a body that does not have the shape it claims.
				if (pending.has_base != f.has_base || pending.has_ordinal != f.has_ordinal ||
				    (f.has_base && pending.base != f.base) ||
				    (f.has_ordinal && pending.ordinal != f.ordinal))
					Panic("rvv frame finalizer: anchors in one work unit disagree about "
					      "which unit it is");
			}
			pending.anchor = ins;
			pending.has_base = f.has_base;
			pending.base = f.base;
			pending.has_ordinal = f.has_ordinal;
			pending.ordinal = f.ordinal;
			pending.keyed = keyed;
			pending.key = key;
			// The vstart write rides on ONE anchor; a slice in which several claim it is a
			// frame whose epilogue convention is ambiguous.
			pending.has_finish = pending.has_finish || f.has_finish;
			pending.finish = pending.finish || f.finish;
			break;
		}
		case NodeRole::Support:
			// A support node before this unit's anchor belongs to this unit only if the
			// unit has already started (its mask node opened it). Otherwise it is frame
			// prologue -- the FP bracket and the scalar broadcast -- and a bound must not
			// be placed before it.
			break;
		case NodeRole::Unclassified:
			break;
		}
	}
	// C4e. THE LAST UNIT IS CLOSED HERE, not by its anchor. Before C4e the anchor closed it and
	// this flush could not fire (a trailing mask node with no anchor was already refused by the
	// `a bounded unit has no mask node of its own` check below); now the last slice's anchors are
	// still open when the body ends.
	if (pending_open && pending.anchor != nullptr) {
		units.push_back(pending);
		pending_open = false;
	}

	// ---- P1c: derive the frame's classification from what the nodes and the guard say ----
	//
	// A member-major run is ineligible because early exit would skip later guest instructions;
	// component-major is checked against emitted units below. Whole-register EVL takes priority
	// over the node types it happens to use.
	Ineligibility derived = Ineligibility::None;
	// C4e. A multi-member frame outranks everything EXCEPT when its body is emitted
	// component-major, which is the one order in which an early exit skips only inactive work --
	// see `rvvplan::ActiveChunkInput::suffix_is_body_tail`. The claim is not taken on trust: the
	// unit derivation below refuses a frame whose emitted units do not match it (one unit per
	// component, strictly ascending, each with at least one anchor).
	if (begin->n_members != 1 && !begin->body_component_major)
		derived = Ineligibility::MultiMember;
	else if (!qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax(begin->guard_kind))
		derived = Ineligibility::WholeRegisterEvl;
	else if (node_reason[(int)Ineligibility::ScalarResult])
		derived = Ineligibility::ScalarResult;
	else if (node_reason[(int)Ineligibility::IsaCrossLane])
		derived = Ineligibility::IsaCrossLane;
	else if (node_reason[(int)Ineligibility::MemoryOrProtocol])
		derived = Ineligibility::MemoryOrProtocol;
	else if (node_reason[(int)Ineligibility::LoweringNotDecomposed])
		derived = Ineligibility::LoweringNotDecomposed;
	else if (has_partial_arm ||
		 qir::InstRVVTypedChunkBegin::GuardProvesFullVl(begin->guard_kind))
		derived = Ineligibility::MemoryOrProtocol;
	else if (node_reason[(int)Ineligibility::EligibleShapeNotEnrolled])
		derived = Ineligibility::EligibleShapeNotEnrolled;
	else if (node_reason[(int)Ineligibility::Unclassified])
		derived = Ineligibility::Unclassified;

	if (c.reason == Ineligibility::Unclassified)
		Panic("rvv frame close: a frame reached the common close without a classification");
	if (derived != c.reason)
		Panic("rvv frame close: the frame's nodes and guard do not support the declared reason");

	// THE LOWERING DECISION FOR THIS FRAME. One record, here, because this is the one place every
	// typed-chunk frame in rv32_qir.cpp passes through with its body complete -- which is exactly
	// what makes the remaining families migrate for free (see
	// QCG_RVV_LOWERING_ARCHITECTURE_20260921.md section 4). It reads only facts already derived
	// above; it changes no node, inserts nothing and emits nothing.
	//
	// QCG ONLY. `NodeFacts::codegen` is a statement about `dbt/qmc/qcg/qemit.cpp`. Under
	// `aot_use_llvm` the same nodes go to llvmgen, so recording there would attribute LLVM's
	// choices to QCG. Refuse rather than guess.
	//
	// WHEN THE DECLARED INELIGIBILITY BECOMES A LOWERING REASON: only on a frame whose nodes
	// already say it scalarized. See ConstraintsFor(Ineligibility) above for why folding it into
	// a packed frame would manufacture a deficiency that is not there.
	if (!config::aot_use_llvm) {
		rvvlower::Decision d;
		d.preferred = rvvlower::Codegen::PackedSIMD;
		d.emitted = frame_codegen;
		d.blocked = frame_codegen == rvvlower::Codegen::PackedSIMD
				? rvvlower::Set()
				: (frame_why | rvvlower::ConstraintsFor(c.reason));
		// Every typed frame has a guard and a fallback edge into the helper: that is the
		// invariant Emit_rvvtypedchunkbegin/Emit_rvvtypedchunkend enforce, and the reason no
		// RVV arithmetic or memory family is DIRECT_NATIVE on QCG.
		d.runtime_fallback = true;
		d.guarded = rvvlower::ConstraintsFor(begin->guard_kind);
		rvvlower::Note(c.raw, d);
	}

	if (c.reason != Ineligibility::None) {
		// An ineligible frame closes EXACTLY as it did before: nothing inserted, no node
		// modified, `n_typed` untouched. What changed is that its reason is now stated and
		// checked instead of being a silent absence.
		if (saw_bound)
			Panic("rvv frame close: an ineligible frame carries an active-vl bound");
		if (c.members != nullptr)
			qb.Create_rvvtypedchunkend(c.members, c.n_members);
		else
			qb.Create_rvvtypedchunkend(c.raw, c.stub, c.whole_regbytes);
		return;
	}

	// ---- post-conditions on what was derived ----
	if (saw_bound)
		Panic("rvv frame finalizer: the body already carries a bound");
	if (units.size() != g.units)
		Panic("rvv frame finalizer: the emitted work-unit count disagrees with the geometry");
	if (begin->n_members != 1 && plan.bounded() && !begin->body_component_major)
		Panic("rvv frame finalizer: a bounded frame is not a single-member frame");
	// C4e. THE COMPONENT-MAJOR CLAIM IS CHECKED AGAINST THE EMITTED BODY, and this is the one
	// place it can be. A producer that sets `body_component_major` but emits a member-major body
	// would otherwise get a bound whose early exit skips LIVE work -- wrong values, not a
	// translation failure. Two facts make the claim, and both are read off the units the loop
	// above derived rather than off the producer:
	//
	//   * every unit carries at least one anchor. A "unit" with none is a mask node the body
	//     never used, i.e. not a slice.
	//   * the units are ORDINAL-KEYED and ascending. That is checked one loop below for every
	//     frame; here it is additionally required to be PRESENT, because a component-major run
	//     slice's anchors are grouped BY ordinal and a body whose anchors carry no ordinal could
	//     not have been grouped at all -- it would have produced one unit per anchor.
	//
	// A single-member frame is not subject to either: it does not carry the claim.
	if (begin->body_component_major) {
		if (begin->n_members == 1)
			Panic("rvv frame finalizer: a single-member frame claims a component-major body");
		for (auto const &u : units) {
			if (u.anchor == nullptr)
				Panic("rvv frame finalizer: a component-major unit has no anchor");
			if (!u.has_ordinal)
				Panic("rvv frame finalizer: a component-major unit carries no ordinal");
		}
	}
	u32 finishes = 0;
	for (u32 c = 0; c < units.size(); ++c) {
		auto const &u = units[c];
		if (u.has_ordinal && u.ordinal != c)
			Panic("rvv frame finalizer: work units are not emitted in ascending ordinal order");
		if (u.has_base) {
			if (c && units[c - 1].has_base && u.base <= units[c - 1].base)
				Panic("rvv frame finalizer: unit element bases are not strictly increasing");
			if (plan.elements_per_unit() != 0 && u.base != ElementBase(g, c))
				Panic("rvv frame finalizer: a unit's element base disagrees with the geometry");
		}
		if (u.lanes != 0 && plan.elements_per_unit() != 0 && u.lanes != plan.elements_per_unit())
			Panic("rvv frame finalizer: a unit's mask width disagrees with the element stride");
		finishes += u.has_finish && u.finish;
	}
	// The producer emits the UNBOUNDED vstart convention: for a LastChunkNode frame exactly the
	// last unit carries the write, for a FrameEpilogue frame no unit does. Relocation below is
	// what a bound requires, and it happens here, not in any producer.
	if (g.vstart_owner == VStartOwner::LastChunkNode) {
		if (has_fp_bracket)
			Panic("rvv frame finalizer: a LastChunkNode frame carries an FP bracket");
		if (finishes != 1 || units.empty() || !units.back().has_finish || !units.back().finish)
			Panic("rvv frame finalizer: a LastChunkNode frame does not end with exactly one "
			      "vstart write");
	} else if (finishes != 0) {
		Panic("rvv frame finalizer: a FrameEpilogue frame carries a body-node vstart write");
	}
	if (plan.bounded()) {
		// The mask placement a bound depends on, checked from the nodes: either the frame has no
		// mask node at all (the integer families derive the mask inside the body node itself), or
		// every unit opened on its own one. An up-front block of mask nodes -- the unbounded FP
		// layout -- would leave later units with none, and this is where that is caught.
		if (masksets != 0) {
			if (masksets != units.size() || !g.per_unit_mask)
				Panic("rvv frame finalizer: a bounded frame's mask nodes are not one per unit");
			for (auto const &u : units)
				if (u.lanes == 0)
					Panic("rvv frame finalizer: a bounded unit has no mask node of its own");
		}
		if (any_forbidding)
			Panic("rvv frame finalizer: a bounded frame carries an effect that forbids "
			      "omitting an inactive unit");
		if (has_partial_arm)
			Panic("rvv frame finalizer: a bounded frame carries a partial arm");
		if (needs_fp_fold && !has_fp_bracket)
			Panic("rvv frame finalizer: a bounded frame accrues FP exceptions with no bracket "
			      "to fold them on the early-exit path");
	}

	// ---- insert, patch and relocate ----
	if (plan.bounded()) {
		u32 inserted = 0;
		for (u32 c = plan.first_bounded_unit(); c < units.size(); ++c) {
			auto const &u = units[c];
			// The bound's immediate is the unit's OWN element index wherever the unit
			// carries one; an FP arithmetic unit has no such field, so its own mask node's
			// width supplies the stride. Neither path recomputes the producer's arithmetic.
			u32 base;
			if (u.has_base) {
				base = u.base;
			} else if (u.lanes != 0) {
				base = c * u.lanes;
			} else {
				Panic("rvv frame finalizer: a boundable unit has neither an element base "
				      "nor a mask width");
			}
			// C4h. THE EVALUATION-ONLY PLACEBO, and this is the ONLY place it may be
			// applied. Weakening the comparison value to 0 keeps the node, its position,
			// its `chunk` index and the two host instructions QEmit emits for it, while
			// making the test `vl <= 0` -- true only for the architecturally empty vector,
			// which the real bound's own unit-0 immediate is already true for. A smaller
			// comparison value can only skip LESS (`vl <= 0` implies `vl <= base`), so this
			// arm's skipped set is a subset of the real arm's and the frame's values stay
			// correct. `base` itself is untouched above, so the guarded unit's own lane-mask
			// base -- the other user of the same element index -- does not move.
			u32 const imm = config::rvv_qcg_active_vl_bound_placebo ? 0u : base;
			qir::Builder ib(qb.GetBlock(), dbt::IListIterator<qir::Inst>(u.first));
			ib.Create_vchunkactive((u8)c, imm);
			++inserted;
		}
		if (inserted != plan.bound_nodes())
			Panic("rvv frame finalizer: inserted bound count disagrees with the plan");
		begin->n_typed = (u16)(begin->n_typed + inserted);
		if (plan.frame_clears_vstart()) {
			// Relocation: the last body node's write would be jumped past by an early exit,
			// so it moves to the frame epilogue below.
			auto *last = units.back().anchor;
			switch (last->GetOpcode()) {
			case qir::Op::_vchunkpartialalu:
				static_cast<qir::InstVChunkPartialAlu *>(last)->finish_instruction = false;
				break;
			case qir::Op::_vchunknarrowshift:
				static_cast<qir::InstVChunkNarrowShift *>(last)->finish = false;
				break;
			case qir::Op::_vchunknarrowclip:
				static_cast<qir::InstVChunkNarrowClip *>(last)->finish = false;
				break;
			case qir::Op::_vchunkwiden:
				static_cast<qir::InstVChunkWiden *>(last)->finish = false;
				break;
			case qir::Op::_vchunkextend:
				static_cast<qir::InstVChunkExtend *>(last)->finish = false;
				break;
			case qir::Op::_vmasklogic:
				static_cast<qir::InstVMaskLogic *>(last)->finish = false;
				break;
			case qir::Op::_vchunkindex:
				static_cast<qir::InstVChunkIndex *>(last)->finish = false;
				break;
			case qir::Op::_vchunkfclass:
				static_cast<qir::InstVChunkFClass *>(last)->finish = false;
				break;
			case qir::Op::_vchunkfestimate:
				static_cast<qir::InstVChunkFEstimate *>(last)->finish = false;
				break;
			case qir::Op::_vchunkfmerge:
				static_cast<qir::InstVChunkFMerge *>(last)->finish = false;
				break;
			default:
				Panic("rvv frame finalizer: the last unit cannot carry the vstart write");
			}
		}
	}

	// P2a. THE ONLY SOURCE OF THE CENSUS GEOMETRY, and it is the geometry this function already
	// derived and checked: `units.size()` is the unit count read off the emitted body (and refused
	// above if it disagrees with the producer's arithmetic), and `plan.bound_nodes()` is the number
	// of bounds this function just inserted (and refused above if the loop inserted a different
	// number). Their difference is the ALWAYS-EXECUTED PREFIX: the units carrying no bound. For an
	// unbounded frame `bound_nodes() == 0`, so the prefix is the whole frame and a policy-off
	// execution reaches every unit -- the switch-off invariant, by construction and not by a rule.
	//
	// No opcode, guest PC, VLEN threshold or eligibility test appears here; this arm of CloseFrame
	// is by definition the `reason == None` arm, so the population is exactly the planner-eligible
	// frames. The cap is InstVChunkActive's own 64-chunk limit restated as a u16 field width.
	u32 const census_units = (u32)units.size();
	u32 const census_prefix = census_units - plan.bound_nodes();
	if (census_units > 0xffffu)
		Panic("rvv frame finalizer: work-unit count does not fit the census field");
	// C4e. A RUN frame's `end` must carry the ordered member list -- QEmit builds the guard-miss
	// arm out of it, one helper call per member in guest order, and checks its length against
	// what `begin` declared. Before C4e no run reached this arm, so the single-instruction form
	// was the only one needed here; a component-major run needs BOTH halves and gets them from
	// the constructor that carries both. The single-instruction path below is byte-identical to
	// what it was.
	// ORDER ITEM 3: the planner's answer OR the frame's own declaration. The two can never both be
	// true: `plan.frame_clears_vstart()` requires `bounded_`, which requires `family_enabled`,
	// which is `policy_enabled` -- and the one producer that sets `epilogue_clears_vstart` is an
	// LLVM route whose `policy_enabled` is explicitly false. Stated as an OR rather than a
	// precedence so that neither can silently mask the other.
	bool const clears_vstart = plan.frame_clears_vstart() || c.geom.epilogue_clears_vstart;
	if (c.members != nullptr)
		qb.Create_rvvtypedchunkend(c.members, c.n_members, clears_vstart,
					   (u16)census_units, (u16)census_prefix);
	else
		qb.Create_rvvtypedchunkend(c.raw, c.stub, c.whole_regbytes,
					   clears_vstart, (u16)census_units,
					   (u16)census_prefix);
}

// A full-VL guard discharges the suffix bound before entering the body.
inline void FinalizeFrame(qir::Builder &qb, qir::Inst *begin_inst, FrameGeometry const &g, u32 raw,
			  RuntimeStubId stub, u16 whole_regbytes = 0)
{
	auto const *begin = static_cast<qir::InstRVVTypedChunkBegin *>(begin_inst);
	auto const reason = qir::InstRVVTypedChunkBegin::GuardProvesFullVl(begin->guard_kind)
	    ? Ineligibility::MemoryOrProtocol : Ineligibility::None;
	CloseFrame(qb, begin_inst, FrameClose{.reason = reason,
					      .geom = g,
					      .raw = raw,
					      .stub = stub,
					      .whole_regbytes = whole_regbytes});
}

} // namespace dbt::rv32::rvvfinal
