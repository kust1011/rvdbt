#pragma once

// W26. THE SHARED ACTIVE-CHUNK PLAN.
//
// WHAT THIS FILE IS. The single place that answers, for ONE typed-chunk frame, the two questions
// the S1-2A/S1-2D/S1-3A/S1-3W prototypes each answered in their own producer:
//
//   (1) may this frame carry active-VL bounds at all, and from which work-unit index up;
//   (2) what ELEMENT INDEX does work unit `c` start at -- the immediate a bound compares against
//       the live `vec.vl`, and the same immediate the unit's body node hands its own lane mask.
//
// Before this file those two answers existed three times: in the FP frames
// (RvvEmitTypedFaluChunkGroup / RvvEmitTypedFmaChunkGroup and the body they share), in the
// equal-width integer route, and in the widening integer route. The three agreed, but only because
// three hand-written conjunct lists and three hand-written `c * bytes / element` expressions
// happened to agree; nothing made them agree. This file makes them one expression evaluated once
// per frame, so a further family is a new `ActiveChunkInput`, not a fourth copy.
//
// W27 IS THAT FURTHER FAMILY, AND IT IS WHY THE GEOMETRY BELOW IS STATED IN DESTINATION BYTES.
// The integer NARROWING route (`vnsrl`/`vnsra`/`vnclipu`/`vnclip`) emits one body node per host
// SOURCE chunk: it reads `bytes` and writes `bytes/2`. W26's original input named the numerator
// "chunk_bytes", which on that route is the SOURCE span and would have doubled the element stride.
// The fix is not a narrowing special case -- it is naming the quantity that is the same question in
// every family: how many DESTINATION bytes one emitted work unit covers.
//
// WHAT THIS FILE IS NOT, AND THE RULE THAT KEEPS IT THAT WAY. Every input below is an ISA- or
// frame-SHAPE quantity: an architectural work-unit count, the unit's DESTINATION byte span, the
// DESTINATION element width, a guard kind, a block-scoped static proof, and two structural facts
// about who owns the frame's side effects. There is deliberately NO workload, NO guest PC, NO
// symbol, NO opcode, NO family tag, NO profile, NO observed AVL, NO VLEN special case and NO
// tunable threshold -- VLEN enters only through the `units` and `unit_dest_bytes` the caller
// already computed for its own tiling, exactly as it did before. A reviewer can check that claim
// by reading the struct: any field that could carry such a thing would have to be added here first.
//
// THIS CHECKPOINT IS BEHAVIOR-PRESERVING FOR THE THREE W26 FAMILIES. `units` is both the
// architectural and the emitted unit count; no unit is statically omitted. The W23 exact-short-VL
// omission (emit only `ceil(vl / elements_per_unit)` units) is a later checkpoint and is
// deliberately absent: it is the one change in this family that can produce WRONG VALUES rather
// than merely forfeit a saving, so it must not ride along with a refactor whose whole claim is
// that nothing moved.
//
// FAIL CLOSED, ALWAYS IN THE SAME DIRECTION. Every refusal below costs a frame its saving and can
// never cost it correctness: a frame that is not bounded is exactly the frame the switch-off arm
// builds. That asymmetry is why the refusals are silent here (no new Panic) while the two
// pre-existing shape Panics -- RvvEmitFpSharedMasks' "chunk width is not a whole number of lanes"
// and Emit_rvvtypedchunkend's "frame and body disagree about who clears vstart" -- stay exactly
// where they were.

#include "dbt/qmc/qir.h"

namespace dbt::rv32::rvvplan
{

// WHO PERFORMS THE FRAME'S ARCHITECTURAL `vec.vstart = 0` WRITE. This is the one input that is not
// about active elements at all, and it is here because it is what decides whether chunk 0 may be
// skipped -- which is a question about ARCHITECTURAL SIDE EFFECTS, not about lanes.
//
//   LastChunkNode  the write rides on the LAST chunk body node's `finish` flag (the integer
//                  routes: InstVChunkPartialAlu::finish_instruction, InstVChunkWiden::finish,
//                  InstVChunkNarrowShift::finish).
//                  An early exit jumps straight past it, so a bounded frame must move the write to
//                  its own epilogue (`frame_clears_vstart`) -- and it must never bound chunk 0,
//                  because a frame whose every chunk can be skipped has no body left to reach the
//                  epilogue's precondition (see Emit_rvvtypedchunkend's Panic, which states the
//                  same fact from the bounds QEmit actually saw).
//   FrameEpilogue  the frame already writes it unconditionally after the body-done label, inside
//                  its own epilogue: an FP frame binds that label in Emit_rvvqcgfpend, INSIDE the
//                  MXCSR bracket, so an early-exited body still accrues fflags, restores MXCSR and
//                  clears vstart. Nothing rides on a chunk node, so chunk 0 is boundable and the
//                  `vl == 0` case is handled by the same instruction as every other chunk.
enum class VStartOwner : u8 {
	LastChunkNode,
	FrameEpilogue,
};

// The largest number of chunks a bounded frame may contain, and it is a property of the NODE rather
// than of any route: InstVChunkActive carries `chunk` in a u8 and Panics at `chunk >= 64`
// (dbt/qmc/qir.h). qir.h derives the same 64 as "LMUL=8 registers times VLEN_MAX/512 host chunks",
// the cap both FP admission predicates already apply and the equal-width integer route restated as
// its own `chunks <= 64` conjunct. Restated here, once, so a frame is refused instead of Panicking.
static constexpr u32 kMaxBoundedChunks = 64;

// The frame's shape, as the ISA and the frame's own structure determine it.
//
// EVERY DEFAULT IS THE REFUSING VALUE, including the guard kind: `VlenbVstart` is a whole-register
// transfer whose EVL is `nregs * VLEN / EEW` and is independent of `vec.vl` entirely, so
// GuardBoundsVlByVlmax refuses it. No chunk-planning route builds that kind, which is exactly why
// it is the safe default -- a caller that forgets a field gets an unbounded plan, never a bound
// against a register its guard never validated.
struct ActiveChunkInput {
	// The family's own CLI switch. Read by the CALLER and passed in, because the three families
	// keep three separate switches on purpose (each family's full-VL cost must stay separately
	// ablatable) and this file must not know which one a frame belongs to.
	bool family_enabled = false;

	// The ARCHITECTURAL count of emitted WORK UNITS in the frame: how many body nodes the guest
	// register group tiles into, each of which may carry one bound. Also the emitted count in
	// this checkpoint. One work unit is one "chunk" in the node's vocabulary
	// (InstVChunkActive::chunk), and the two words are used interchangeably below.
	u32 units = 0;

	// THE GEOMETRY, AND IT IS STATED IN DESTINATION TERMS ONLY. `unit_dest_bytes` is how many
	// bytes of the DESTINATION register group ONE emitted work unit covers; `dest_element_bytes`
	// is the destination EEW. Their quotient is the unit's architectural ELEMENT count, which is
	// the element stride between consecutive units and therefore the whole of the "which element
	// does unit c start at" question.
	//
	// WHY THIS IS THE GENERAL SHAPE, AND WHY A HOST CHUNK WIDTH IS NOT. The three shapes this
	// substrate emits relate host work to destination bytes differently:
	//
	//   equal-width  one unit reads `bytes` and writes `bytes`   -> unit_dest_bytes = bytes
	//   widening     one unit reads `bytes/2` and writes `bytes`  -> unit_dest_bytes = bytes
	//   narrowing    one unit reads `bytes` and writes `bytes/2`  -> unit_dest_bytes = bytes/2
	//
	// A field called "host chunk width" therefore answers a different question in each family,
	// and using it as the numerator silently doubles the narrowing stride -- which would place
	// every bound above a full-VL execution's `vl` and skip LIVE units. The active set is a set
	// of ELEMENTS, so the only numerator that is the same question everywhere is the destination
	// byte span of the unit. Nothing here is an opcode, a family tag, a VLEN or a workload
	// constant: both numbers come from the route's own tiling arithmetic.
	//
	// WHY THE DESTINATION AND NEVER THE SOURCE. RVV 1.0 leaves ELEMENT INDEXING alone in both
	// width-changing families: destination element i is produced from source element i, and `vl`
	// counts elements, so the active set is ONE set, [vstart, vl), shared by both widths. The
	// destination side is the one whose bytes and EEW multiply out to that element count.
	u32 unit_dest_bytes = 0;
	u32 dest_element_bytes = 0;

	// The frame's guard kind, read through the SAME qir.h predicates QEmit consults
	// (GuardBoundsVlByVlmax, GuardProvesFullVl), so the translator's answer and the emitter's
	// cannot drift. The kind is passed rather than the two booleans for that reason.
	qir::InstRVVTypedChunkBegin::GuardKind guard_kind =
	    qir::InstRVVTypedChunkBegin::GuardKind::VlenbVstart;

	// W21. The block-scoped static proof that `vl == VLMAX` for this frame's vtype on every
	// execution of this block. `false` means "not proved" OR "this route does not consult the
	// proof", and the two are the same answer to this conjunct: an unknown vl and a provably
	// SHORT vl both keep the ladder, so only a positive proof changes anything here. That is why
	// a route which has not been extended to the proof passes `false` and keeps its exact
	// current shape -- W21's scope was the widening route and this refactor does not widen it.
	bool static_full_vl_proved = false;

	// C4e. Does this frame's BODY ORDER make its inactive work units a contiguous TAIL of the
	// body? The early exit leaves the WHOLE body, so a bound is a correct "skip the inactive
	// suffix" only when everything after unit c's first node is unit c..units-1's work and
	// nothing else.
	//
	// TWO WAYS TO BE TRUE, and they are the same statement about the body, not two policies:
	//
	//   single guest instruction  one member, units emitted in ascending order -> the tail
	//                             property holds by construction. This is the original W26
	//                             `single_member` conjunct, unchanged in meaning.
	//   component-major run       a multi-member run whose body is emitted as `units` contiguous
	//                             slices, slice c holding every member's unit-c work plus that
	//                             unit's own loads and stores. The inactive units are then the
	//                             body's tail for EVERY member at once, because a run has ONE
	//                             vtype and therefore ONE element -> unit map shared by all of its
	//                             members (rv32_vrun.h RunDescriptor: sew_bytes, nchunks and
	//                             chunk_bytes are uniform, a member of another shape cuts the run).
	//
	// A MEMBER-MAJOR multi-member run is false: there, unit c of member i is followed by unit 0 of
	// member i+1, which is LIVE, so the early exit would skip active work. Emit_vchunkactive
	// Panics on that shape; this is the translator's half of that fact, refused here rather than
	// hit as a Panic.
	bool suffix_is_body_tail = false;

	// Is the frame's active-lane mask for chunk c derived INSIDE chunk c's own guarded region?
	// The bound retires a chunk's mask derivation along with its loads, lane op and store, so a
	// frame whose masks are computed once up-front for the whole body cannot be bounded without
	// moving them. The integer routes derive the mask inside each chunk's own body node and are
	// therefore always true; the FP frames are true exactly when their shared per-chunk masks
	// are deferred into the body (`shared_mask_ops == nchunks`).
	bool per_chunk_active_mask = false;

	VStartOwner vstart_owner = VStartOwner::LastChunkNode;
	// Sub-byte elements (e.g. mask bits); zero retains the byte-based geometry.
	u32 dest_element_bits = 0;
};

inline u32 ElementsPerUnit(u32 unit_bytes, u32 element_bytes, u32 element_bits = 0)
{
	u64 const bits = element_bits ? element_bits : u64(element_bytes) * 8;
	u64 const span = u64(unit_bytes) * 8;
	return bits && span && span % bits == 0 && span / bits <= 0xffffffffu
	    ? u32(span / bits) : 0;
}

// The plan. Default-constructed it is the REFUSING plan (`bounded() == false`), which is what makes
// it usable as the default argument of a shared body emitter whose other caller -- a vector run in
// materialize mode -- must never be bounded.
class ActiveChunkPlan
{
public:
	ActiveChunkPlan() = default;

	static ActiveChunkPlan Make(ActiveChunkInput const &in)
	{
		ActiveChunkPlan p;
		p.units_ = in.units;
		p.vstart_owner_ = in.vstart_owner;
		// The element stride, and the whole of the "which element does unit c start at"
		// question. A destination span that is not a whole number of destination elements
		// leaves `elements_per_unit_ == 0`, and a plan with no element stride cannot be
		// bounded: its bound's immediate would not be an element index. `dest_element_bytes
		// == 0` is the same refusal and is the frame whose SEW is only resolved at run time.
		p.elements_per_unit_ = ElementsPerUnit(in.unit_dest_bytes, in.dest_element_bytes,
						in.dest_element_bits);
		p.first_bounded_unit_ = in.vstart_owner == VStartOwner::FrameEpilogue ? 0u : 1u;
		// The guard capability, both halves, from the node's own predicates:
		//   * it must already have compared `vec.vl` against the `vlmax` this frame's vtype
		//     implies, or the comparison is against a register the frame never validated;
		//   * it must NOT already prove `vl == VLMAX && vstart == 0`, because then every
		//     bound is a translation-time constant `false` and QEmit Panics on the
		//     contradiction rather than emitting dead code.
		bool const guard_ok =
		    qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax(in.guard_kind) &&
		    !qir::InstRVVTypedChunkBegin::GuardProvesFullVl(in.guard_kind);
		// `units > first_bounded_unit_` is the "a frame with no boundable unit is not a
		// bounded frame" rule, stated once for both conventions: it is `units >= 2` when the
		// last body node owns the vstart write and `units >= 1` when the epilogue does.
		p.bounded_ = in.family_enabled && in.suffix_is_body_tail && in.per_chunk_active_mask &&
			     guard_ok && !in.static_full_vl_proved && p.elements_per_unit_ != 0 &&
			     in.units > p.first_bounded_unit_ && in.units <= kMaxBoundedChunks;
		return p;
	}

	bool bounded() const { return bounded_; }

	// The architectural work-unit count, which in this checkpoint is also the emitted count.
	u32 units() const { return units_; }

	// Destination ELEMENTS one work unit covers, i.e. the element stride between units.
	u32 elements_per_unit() const { return elements_per_unit_; }

	// The lowest unit index a bound may guard: 0 or 1, per VStartOwner above.
	u32 first_bounded_unit() const { return first_bounded_unit_; }

	// Does unit `c` carry a bound? The one predicate every producer loop asks.
	bool bound_at(u32 c) const { return bounded_ && c >= first_bounded_unit_ && c < units_; }

	// How many InstVChunkActive nodes this frame contains -- the `n_typed` contribution the
	// frame's `begin` node must declare, and the number Emit_rvvtypedchunkend checks against
	// what QEmit actually saw.
	u32 bound_nodes() const { return bounded_ ? units_ - first_bounded_unit_ : 0; }

	// Unit `c`'s first architectural element index: the bound's immediate, and the same element
	// index the unit's body node hands its own lane mask. Both come from HERE so that "does the
	// bound agree with the body it guards" is one expression used twice rather than two
	// expressions that must be kept equal.
	u32 element_base(u32 c) const { return c * elements_per_unit_; }

	// Does the frame's epilogue own the `vstart = 0` write? True exactly when the write had to
	// move off the last body node because that node became skippable.
	bool frame_clears_vstart() const
	{
		return bounded_ && vstart_owner_ == VStartOwner::LastChunkNode;
	}

	// The `finish` flag for unit `c`'s body node. Meaningful only for the LastChunkNode
	// convention -- a FrameEpilogue family's body nodes have no such flag and never ask.
	bool unit_finishes(u32 c) const { return c + 1 == units_ && !frame_clears_vstart(); }

private:
	u32 units_ = 0;
	u32 elements_per_unit_ = 0;
	u32 first_bounded_unit_ = 1;
	bool bounded_ = false;
	VStartOwner vstart_owner_ = VStartOwner::LastChunkNode;
};

} // namespace dbt::rv32::rvvplan
