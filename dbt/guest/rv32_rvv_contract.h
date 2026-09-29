#pragma once

// RVV SHARED SEMANTIC CONTRACT (Strict Execution Order item 2, started 2026-09-19).
//
// WHY THIS FILE EXISTS. Every route delivered under C3/C4 re-derived the same handful of facts
// inline, and the re-derivations were not identical: the conversion routes each wrote their own
// `byte / rb * VLEN_MAX_BYTES + byte % rb`, their own lane count, and their own source/destination
// stride pair, and one of those (the first geometry assertion in the float-width test) was simply
// wrong. `RvvHostChunkGeometry` already learned this lesson for the same-width chunk tiling -- its
// comment records three copies of one formula being consolidated -- and this file continues it for
// the facts that tiling does not cover.
//
// SCOPE DISCIPLINE. This is a CONTRACT, not a rewrite. It is pure, header-only, reads no config and
// probes no host feature, so it is testable on its own and callable from both LLVM route families
// without either being restructured. Routes adopt it one at a time (order item 3); nothing here
// changes behaviour by existing.
//
// PIECES DELIVERED: (1) the physical-slot versus logical-geometry distinction; (2) the active
// predicate `(vstart <= e && e < vl) && architectural_mask` together with the obligation that
// whatever a body omits its guard must prove, and the whole-register / cross-element exemptions.
// (3) tail/mask policy: what an unwritten element must contain, and when a frame owes a policy at
// all. NOT yet here: source snapshots for legal overlap, owned state publication and vstart
// clearing, memory bounds/fault/restart, and guest rounding/sticky-flag ownership. They are
// listed so the file's current coverage is not mistaken for the whole contract.

#include "dbt/guest/rv32_cpu.h"

namespace dbt::rv32::rvvcontract
{

// THE DISTINCTION THIS PIECE EXISTS TO MAKE.
//
// A guest vector register occupies a FIXED PHYSICAL SLOT in CPUState -- `VLEN_MAX_BYTES` apart,
// sized for the largest VLEN this build admits -- while the LOGICAL layout of elements inside a
// register group depends on the live VLEN and the element width. The two are not the same stride,
// and conflating them is the error that produced the wrong first assertion in the float-width test:
// consecutive units of a frame are `unit_bytes` apart only WITHIN a register, and jump by
// `VLEN_MAX_BYTES` when they cross into the next one.
//
// `rb` below is the LOGICAL register size in bytes (VLEN/8); `VLEN_MAX_BYTES` is the PHYSICAL slot.
// Every function here takes `vlen_bits` explicitly rather than reading `config::vlen_bits`, so a
// test can pin the truth table at widths the current build is not compiled for.

// Bytes of one guest vector register at this VLEN. The logical size, never the slot size.
constexpr u32 RegisterBytes(u32 vlen_bits) { return vlen_bits / 8u; }

// Is this a geometry this contract is willing to describe at all? A register must be a whole number
// of bytes and elements, and the element width must be one this ISA has.
constexpr bool GeometryDescribable(u32 vlen_bits, u32 element_bytes)
{
	if (vlen_bits == 0 || vlen_bits % 8u != 0)
		return false;
	if (element_bytes != 1 && element_bytes != 2 && element_bytes != 4 && element_bytes != 8)
		return false;
	u32 const rb = RegisterBytes(vlen_bits);
	if (rb % element_bytes != 0)
		return false;
	// The physical slot has to be able to hold the logical register.
	return rb <= VLEN_MAX_BYTES;
}

// Elements of `element_bytes` that fit in ONE register at this VLEN.
constexpr u32 ElementsPerRegister(u32 vlen_bits, u32 element_bytes)
{
	return RegisterBytes(vlen_bits) / element_bytes;
}

// THE CENTRAL FUNCTION. Byte offset, from the start of `vec.vreg`, of element `element_index` of the
// group based at `base_reg`, for an element width of `element_bytes`.
//
// It crosses register boundaries by the PHYSICAL slot and advances within a register by the LOGICAL
// element size -- which is exactly the pair of facts a caller open-coding
// `byte / rb * VLEN_MAX_BYTES + byte % rb` is asserting, now in one place with a name.
constexpr u32 ElementSlotOffset(u32 vlen_bits, u32 base_reg, u32 element_index, u32 element_bytes)
{
	u32 const per_reg = ElementsPerRegister(vlen_bits, element_bytes);
	u32 const reg = base_reg + element_index / per_reg;
	u32 const within = (element_index % per_reg) * element_bytes;
	return reg * VLEN_MAX_BYTES + within;
}

// The same offset relative to CPUState rather than to `vec.vreg`.
inline u32 ElementStateOffset(u32 vlen_bits, u32 base_reg, u32 element_index, u32 element_bytes)
{
	return (u32)(offsetof(CPUState, vec) + offsetof(VectorState, vreg)) +
	       ElementSlotOffset(vlen_bits, base_reg, element_index, element_bytes);
}

// A TWO-WIDTH UNIT. A conversion frame processes `lanes` ELEMENTS per unit, and the source and
// destination element widths may differ. The unit is bounded by the WIDER of the two windows,
// because that is the one that first fills a host vector; using the narrower one produces a unit
// whose wide side overflows the host chunk (the mutation that crashed the widening
// integer-to-float node's own shape check).
//
// `host_chunk_bytes` is the emitter's widest comfortable vector width; 64 for this backend.
// Returns 0 when the shape is not describable, so callers fail closed rather than round.
constexpr u32 UnitLanes(u32 vlen_bits, u32 dst_element_bytes, u32 src_element_bytes,
			u32 host_chunk_bytes = 64u)
{
	if (!GeometryDescribable(vlen_bits, dst_element_bytes) ||
	    !GeometryDescribable(vlen_bits, src_element_bytes))
		return 0;
	u32 const rb = RegisterBytes(vlen_bits);
	u32 const window = rb < host_chunk_bytes ? rb : host_chunk_bytes;
	u32 const wider = dst_element_bytes > src_element_bytes ? dst_element_bytes : src_element_bytes;
	return window / wider;
}

// How many units cover `vlmax` elements at that lane count. Fails closed on a zero lane count.
constexpr u32 UnitCount(u32 lanes, u32 vlmax) { return lanes == 0 ? 0 : (vlmax + lanes - 1u) / lanes; }

// ---------------------------------------------------------------------------------------------
// PIECE 2: THE ACTIVE-ELEMENT PREDICATE.
//
// The architectural rule for an ELEMENT-WISE operation is one expression:
//
//     active(e) = (vstart <= e) && (e < vl) && architectural_mask(e)
//
// Every LLVM route delivered so far emits only the MIDDLE conjunct. That is not wrong, but it is
// only sound because the frame's guard proves the other two vacuous -- `vstart == 0` makes the floor
// always true, and refusing masked encodings makes the mask always true. The C4-FIX defect was
// exactly this pairing coming apart: three routes carried `GuardKind::VTypeInteger`, which does NOT
// prove `vstart == 0`, while their bodies had no floor term. So the contract below is not the
// predicate alone -- it is the predicate TOGETHER WITH the obligation that whatever a body omits,
// its guard proves.
//
// WHOLE-REGISTER AND CROSS-ELEMENT OPERATIONS DO NOT INHERIT THIS. `vmv<n>r.v` and the whole-register
// memory forms are defined without reference to `vl` or `vtype` at all (RVV 1.0 16.6), and a
// reduction's active set governs which elements CONTRIBUTE, not which destination elements are
// written -- its destination is element 0 of `vd`. Applying the element-wise predicate to either
// would be wrong in a way that looks like extra rigour, so the classification is explicit.

enum class ExecutionRule : u8 {
	ElementWise,	// active(e) as above
	WholeRegister,	// independent of vl and vtype; the unit is the whole register
	CrossElement,	// reductions/gather/compress: the ISA defines its own active set
};

// The architectural predicate for an element-wise operation.
constexpr bool ElementIsActive(u32 e, u32 vstart, u32 vl, bool mask_bit)
{
	return e >= vstart && e < vl && mask_bit;
}

// Which conjuncts a body's emitted predicate actually contains. Measured from the emitted IR, never
// declared: a route that reads `vec.vl` has the bound, one that reads `vec.vstart` in its lane
// predicate has the floor, one that reads `v0` has the mask.
struct PredicateTerms {
	bool vl_bound{false};
	bool vstart_floor{false};
	bool architectural_mask{false};
};

// What a body with those terms actually computes for one element.
constexpr bool PredicateComputes(PredicateTerms t, u32 e, u32 vstart, u32 vl, bool mask_bit)
{
	bool r = true;
	if (t.vl_bound)
		r = r && e < vl;
	if (t.vstart_floor)
		r = r && e >= vstart;
	if (t.architectural_mask)
		r = r && mask_bit;
	return r;
}

// What the frame's guard has already established before the body runs.
struct GuardProofs {
	bool vstart_is_zero{false};
	bool unmasked{false};
};

// THE OBLIGATION. A body may omit a conjunct only when the guard makes it vacuous. `vl_bound` can
// never be omitted: no guard kind in this backend bounds `vl` to the elements a single unit covers.
constexpr bool PredicateIsSound(PredicateTerms t, GuardProofs g)
{
	if (!t.vl_bound)
		return false;
	if (!t.vstart_floor && !g.vstart_is_zero)
		return false;
	if (!t.architectural_mask && !g.unmasked)
		return false;
	return true;
}

// PIECE 2b: WHERE THE ARCHITECTURAL MASK BIT ACTUALLY IS.
//
// Piece 2 names the `architectural_mask(e)` conjunct; this says how to FETCH it, because a route
// that emits the conjunct still has to read v0 and every backend was about to derive the addressing
// for itself. RVV 1.0 5.3: the mask always lives in v0, one BIT per element, element `e` at bit
// `e % 8` of byte `e / 8` -- independent of SEW, LMUL and VLEN. Both guest and host are
// little-endian, so a `w`-bit integer load of the containing aligned group has element `e` at bit
// position `e % w` of the loaded value.
//
// A UNIT WANTS `lanes` CONSECUTIVE BITS AT BIT `element_base`, and the only real question is
// whether they straddle the load. They do not, and the reason is arithmetic rather than luck: a
// frame's `element_base` is `unit * lanes` and `lanes` is a power of two no larger than the group,
// so `element_base % group_bits` is a multiple of `lanes` and adding `lanes` cannot pass
// `group_bits`. THIS FUNCTION DOES NOT ASSUME THAT -- it CHECKS it and returns `bits == 0` when it
// fails, so a future route with a ragged lane count fails closed instead of reading a neighbouring
// unit's bits as its own.
//
// QCG derives the same window inline in `QEmit::EmitRvvBodyMask` (a 64-bit load at `base / 8` then
// a shift by `base % 8`). That form is correct for its own emitter and is deliberately left alone;
// this one is stated in the units an LLVM `trunc`/`bitcast` to `<lanes x i1>` needs, and the
// contract test pins the two against the same architectural bit numbering.
struct MaskUnitWindow {
	u32 byte_offset{0}; // from the start of v0
	u32 bit_shift{0};   // right-shift applied to the loaded group
	u32 bits{0};	    // 0 = not describable; otherwise the load width in bits
};

constexpr MaskUnitWindow MaskWindowForUnit(u32 element_base, u32 lanes, u32 group_bits = 16u)
{
	if (lanes == 0 || lanes > group_bits || (lanes & (lanes - 1u)) != 0)
		return {};
	if (group_bits == 0 || group_bits % 8u != 0)
		return {};
	u32 const shift = element_base % group_bits;
	if (shift + lanes > group_bits)
		return {}; // the unit straddles two groups: fail closed rather than read half of it
	return {(element_base / group_bits) * (group_bits / 8u), shift, group_bits};
}

// The architectural bit numbering itself, so a test can state the rule independently of the window
// above and then check that the window agrees with it.
constexpr bool MaskBitOfElement(u8 const *v0, u32 e) { return (v0[e / 8u] >> (e % 8u)) & 1u; }

// ---------------------------------------------------------------------------------------------
// PIECE 3: TAIL AND MASK POLICY -- what an element the operation does NOT write must contain.
//
// RVV 1.0 gives two independent policies, both encoded in vtype:
//
//   vta = 1 (tail-agnostic)   elements at or above `vl` may be PRESERVED or set to all-ones
//   vta = 0 (tail-undisturbed) they must be PRESERVED
//   vma = 1 (mask-agnostic)   masked-off BODY elements may be PRESERVED or set to all-ones
//   vma = 0 (mask-undisturbed) they must be PRESERVED
//
// PRESERVING IS LEGAL UNDER ALL FOUR, which is why every LLVM route in this backend preserves and
// none of them reads `vta`/`vma` at all. That is a deliberate choice, not an omission, and stating
// it is the point: a route that started writing ones would need the policy bits, and would also
// stop being bit-comparable against the reference in the way described below.
//
// A DIFFERENTIAL CAVEAT THAT IS EASY TO TRIP OVER. The reference's own fast path is NOT always a
// preserving implementation: with `--rvv-tail-round` and `vta = 1` it rounds a unit's extent UP to
// the host tier width and writes the surplus lanes (`rv32_vector_fast.h`, `walk_extent_ta`). Both
// behaviours are architecturally legal under `vta`, so a BIT-EXACT differential of an LLVM route
// against the helper is only meaningful with that flag off, or restricted to `vtu`. This is a
// property of the oracle, not of either implementation.
//
// A FULL-VL FRAME HAS NO TAIL AT ALL. When the guard proves `vl == VLMAX` every element of every
// unit is a body element, so no tail policy applies and an unmasked full-width store is correct.
// `TailHandlingRequired` says exactly when a route owes a policy, so "this route has no tail
// handling" can be checked against "its guard proves full VL" rather than assumed benign.

enum class InactiveFill : u8 {
	Preserve, // legal under every policy
	Ones,	  // legal only under the matching agnostic policy
};

constexpr bool InactiveFillIsLegal(InactiveFill f, bool agnostic)
{
	return f == InactiveFill::Preserve || agnostic;
}

// Does this frame owe a tail/mask policy at all? Only if some element of some unit can be inactive.
constexpr bool TailHandlingRequired(bool guard_proves_full_vl, bool unmasked)
{
	return !(guard_proves_full_vl && unmasked);
}

// How a body publishes its destination, as measured from the emitted IR.
enum class DestinationWrite : u8 {
	FullWidthStore,	 // one unmasked store of the whole unit
	MaskedStore,	 // llvm.masked.store under the active-lane predicate
	MergedStore,	 // full-width store of select(active, computed, old destination)
	None,
};

constexpr bool DestinationWritePreserves(DestinationWrite w)
{
	return w == DestinationWrite::MaskedStore || w == DestinationWrite::MergedStore;
}

// THE OBLIGATION. A frame that owes a policy must publish through a preserving form; a frame that
// owes none may store the full width.
constexpr bool DestinationWriteIsSound(DestinationWrite w, bool guard_proves_full_vl, bool unmasked)
{
	if (w == DestinationWrite::None)
		return false;
	if (!TailHandlingRequired(guard_proves_full_vl, unmasked))
		return true;
	return DestinationWritePreserves(w);
}

// ---------------------------------------------------------------------------------------------
// PIECE 4: SOURCE SNAPSHOTS AND LEGAL OVERLAP.
//
// RVV 1.0 5.2 permits a destination group to overlap a source group in specific cases (equal EEW; a
// narrower destination over the lowest-numbered part; a wider destination over the highest-numbered
// part), and this repository's `convert_registers_legal` / `vext_supported` enforce exactly that.
// THE ISA RULE IS NOT THE WHOLE OBLIGATION. It says which overlaps a correct implementation must
// accept; it does not say that any particular emission order is correct for them.
//
// THE EMISSION OBLIGATION. A frame emits units in order. Unit `c` writes its destination window and
// later units read their source windows. If unit `c`'s WRITE lands on bytes a LATER unit still has
// to READ, the frame has destroyed its own input -- a read-after-write hazard created by the
// lowering, not by the guest. Within ONE unit reading before writing is fine, which is why the
// self-intersection is excluded below.
//
// This is computable from piece 1's geometry alone, and therefore checkable against what a route
// actually emits rather than argued from the register numbers.

struct ByteWindow {
	u32 begin{0};
	u32 size{0};
	constexpr u32 end() const { return begin + size; }
};

constexpr bool WindowsIntersect(ByteWindow a, ByteWindow b)
{
	return a.begin < b.end() && b.begin < a.end();
}

// Does unit `writer`'s destination clobber a byte unit `reader`'s source still needs?
// Only meaningful for `writer < reader`; a unit reading its own destination window is the ordinary
// read-then-write every lane operation performs.
constexpr bool UnitWriteClobbersLaterRead(ByteWindow write, ByteWindow later_read)
{
	return WindowsIntersect(write, later_read);
}

// ---------------------------------------------------------------------------------------------
// PIECE 5: OWNED STATE PUBLICATION AND vstart CLEARING.
//
// The strongest of the five, because it is a CLOSED-WORLD assertion rather than a property of one
// construct: a frame may write ONLY the state it owns, and every byte it does write must fall in a
// category it declared. The categories a conversion/lane frame is entitled to are exactly:
//
//   DestinationWindow  the `vreg` bytes of the units it emitted -- and NOT its source windows;
//   VStart             `vec.vstart`, cleared once, by the owner the frame's geometry declares;
//   FpFlags            `fpu.fcsr`, accrued by OR (never assigned);
//   FpBracket          `fpu.fround_run_open` / `fround_run_saved_mxcsr`, the bracket's own state;
//   GuestPc            the translator's per-instruction `ip` spill, which belongs to the
//                      instruction boundary rather than to the frame.
//
// Anything else is unowned. The value of stating it this way is that a NEW route cannot quietly
// write a field nobody reviewed: the check enumerates every CPUState store the function emits and
// fails on the first one that matches no category, naming the offset.

enum class StateCategory : u8 {
	DestinationWindow,
	SourceWindow, // readable, NEVER writable by the frame
	VStart,
	FpFlags,
	FpBracket,
	GuestPc,
	Unowned,
};

constexpr bool StateCategoryIsWritable(StateCategory c)
{
	switch (c) {
	case StateCategory::DestinationWindow:
	case StateCategory::VStart:
	case StateCategory::FpFlags:
	case StateCategory::FpBracket:
	case StateCategory::GuestPc:
		return true;
	default:
		return false;
	}
}

// `vstart` is cleared ONCE per frame. Which node owns that write is a property of the frame's
// geometry, not of any individual unit, and the two conventions are mutually exclusive.
enum class VStartOwnerRule : u8 {
	FrameEpilogue,	// the frame's own end node clears it
	LastChunkNode,	// the last unit carries a `finish` flag and clears it
};

constexpr bool VStartClearCountIsSound(VStartOwnerRule rule, u32 clears, u32 units)
{
	(void)units;
	// Either convention publishes exactly one clear on the taken path.
	return rule == VStartOwnerRule::FrameEpilogue ? clears == 1u : clears == 1u;
}

// ---------------------------------------------------------------------------------------------
// PIECE 7: GUEST ROUNDING AND STICKY-FLAG OWNERSHIP.
//
// Three components can affect the guest's FP state and they must not overlap:
//
//   THE BRACKET owns MXCSR.RC. `Emit_rvvfpbegin` / `Emit_rvvqcgfpbegin` installs the guest `frm`
//     once per frame and the close folds the host's sticky bits into `fcsr`. A body never sets RC.
//   THE BODY owns `round.dynamic`. A lane operation that rounds says so by carrying that metadata,
//     which is only meaningful BECAUSE the bracket installed RC -- so a rounding body without an
//     open bracket computes in whatever mode the host happened to be in. That pairing is the rule.
//   A BODY MAY ALSO DERIVE A FLAG ITSELF (`vfclass` derives none, the float-to-integer routes derive
//     NV, the frm arm derives NX). When it does, it must ensure the host cannot raise a
//     CONTRADICTORY one for the same lane -- which is what neutralising the invalid lanes achieves.
//     Deriving a flag while leaving the host free to raise a different one for the same element is
//     the failure this rule names.
//
// AT MOST ONE BRACKET PER FRAME. Two opens would save the host's MXCSR twice and restore a value
// the first open had already replaced.

struct FpOwnership {
	u32 brackets_opened{0};
	u32 rounding_bodies{0};	   // constrained calls carrying round.dynamic
	bool derives_flags{false};  // the body ORs a flag into fcsr itself
	bool neutralises_operands{false}; // ... and suppresses the host's view of those lanes
};

constexpr bool FpOwnershipIsSound(FpOwnership o)
{
	if (o.brackets_opened > 1u)
		return false;
	// A body that rounds by the guest mode needs the bracket that installed it.
	if (o.rounding_bodies > 0u && o.brackets_opened == 0u)
		return false;
	// A body that derives a flag must not leave the host free to contradict it.
	if (o.derives_flags && !o.neutralises_operands)
		return false;
	return true;
}

} // namespace dbt::rv32::rvvcontract
