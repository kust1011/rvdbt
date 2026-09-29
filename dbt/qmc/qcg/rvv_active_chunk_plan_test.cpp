// W26: the SHARED active-chunk plan (dbt/guest/rv32_active_chunk_plan.h), tested on its own.
//
// W27 EXTENDED IT: the input's geometry is now the work unit's DESTINATION byte span rather than a
// host chunk width, section [4b] is the narrowing family's geometry, and section [6] states the one
// decision that deliberately CHANGES (narrowing was unbounded at every switch position before W27).
//
// WHY THIS FILE IS SEPARATE FROM THE FOUR ROUTE SUITES. The existing suites
// (rvv_active_vl_bound_test, ..._stage2a, ..._stage2d_fma, ..._int_bound, ..._widen_bound,
// rvv_widen_static_fullvl_test) translate real guest instructions and inspect QIR and emitted host
// bytes; they are the ones that can say "the frame did not move". They cannot say anything about
// the DOMAIN of the decision, because a route only ever presents the shapes its own admission
// predicates produce. This file tests the decision function over shapes no accepted route reaches
// today -- the 64-chunk cap, a multi-member frame, a guard kind that does not bound `vec.vl`, a
// chunk that is not a whole number of elements -- which is exactly the surface a FOURTH family
// would arrive on.
//
// NOTHING HERE IS A BEHAVIOUR CHANGE, AND SECTION [6] IS WHY. That section re-implements the three
// pre-W26 decisions from the three producers, independently and from the reports rather than from
// the new header, and requires the planner to agree with each of them on every shape that producer
// can present. A refactor that quietly widened or narrowed any of the three fails there.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [1] SINGLE CHUNK. With the integer convention (the last chunk node owns `vstart = 0`) a
//       one-chunk frame is NOT bounded: chunk 0 is unboundable there, so a bounded one-chunk frame
//       would be a frame that emitted no bound while having moved the `vstart` write to its
//       epilogue -- the exact disagreement Emit_rvvtypedchunkend Panics on. With the FP convention
//       (the epilogue already owns the write) a one-chunk frame IS bounded, at chunk 0, which is
//       how the `vl == 0` case is covered by the same instruction as every other chunk. Failure in
//       either direction is a lost saving on one family and a translation-time Panic on the other.
//
//   [2] FULL VL. Two independent ways for a frame to be provably full, and both must yield the
//       OFF-arm frame exactly: W21's block-scoped static proof (`static_full_vl_proved`), and a
//       guard kind that already tests `vl == VLMAX && vstart == 0`. For the second, QEmit Panics if
//       a bound reaches such a frame at all, so a false positive here is a crash, not a slowdown.
//       Also checked: a full-VL plan's `unit_finishes(last)` is still true and
//       `frame_clears_vstart()` still false -- i.e. the frame really is the OFF-arm one, node flags
//       included, rather than a third shape.
//
//   [3] UNKNOWN / PARTIAL VL. The ladder is kept: `bound_nodes() == chunks - first_bounded_chunk`,
//       bounds are a contiguous suffix starting at `first_bounded_chunk`, element bases are
//       0, lanes, 2*lanes, ..., every chunk node's `finish` is clear and the frame owns the
//       `vstart` write. Failure = the refactor turned "not proved full" into "proved full" and
//       silently deleted the S1-3A/S1-3W benefit, which no correctness test could see.
//
//   [4] WIDENING USES DESTINATION LANES. At e16 widening the destination element is 4 bytes, not 2,
//       so a 64-byte chunk is 16 destination lanes and the ladder is 0, 16, 32, 48. The source-lane
//       answer (32 lanes/chunk, ladder 0, 32, 64, 96) is computed alongside and required to DIFFER
//       at chunk 1 -- so the check cannot pass if the stride is taken from the source width. That
//       mistake would place every bound above the live `vl` of a full-VL execution and skip live
//       chunks, i.e. wrong values, which is why it is checked positively AND negatively here.
//
//   [4b] NARROWING COVERS HALF A HOST CHUNK OF DESTINATION BYTES, and the two single-factor
//        mistakes are computed alongside and required to DIFFER: the unit's host SOURCE span, which
//        doubles the stride and is shown to FIRE on a full-VL execution and retire live units (a
//        wrong-value bug, not a lost saving), and the SOURCE element width, which halves it. Also
//        checked as an equality: a narrowing unit is geometrically an equal-width unit of half the
//        width, so the planner has no narrowing case at all -- which is what "no family tag" means
//        operationally.
//
//   [5] INELIGIBLE FRAMES. A multi-member run frame (the early exit would jump past later guest
//       instructions -- Emit_vchunkactive Panics), a `Vlenb*` guard kind (its EVL is
//       `nregs * VLEN / EEW` and is independent of `vec.vl`, so an early exit there is WRONG, and
//       Emit_vchunkactive Panics on it too), a frame with no per-chunk active mask, a frame whose
//       element width is not known at translation time (the two-vtype FP frame), a chunk that is
//       not a whole number of elements, more chunks than InstVChunkActive can index, and the switch
//       off. Every one must be unbounded. Failure of the first two is a Panic in QEmit; failure of
//       the rest is a bound whose immediate is not an element index.
//
//   [6] EQUIVALENCE WITH THE THREE PRE-W26 DECISIONS, over each producer's own reachable shape
//       domain (stated in the code). Plus the ONE deliberate difference and its direction: the FP
//       sites did not test GuardBoundsVlByVlmax for themselves, so the planner is STRICTLY more
//       conservative than the old FP expression on guard kinds no FP route builds. That is checked
//       as a difference rather than hidden.
//
//   [7] STRUCTURAL INVARIANTS the emitter relies on: element bases strictly increase with the chunk
//       index (so inactive chunks are always a SUFFIX and one forward branch can retire the rest of
//       the body), `element_base(0) == 0`, and `bound_at` is monotone. Failure = the "skip a suffix"
//       argument stops holding and a bound could retire live work.
//
// No QIR is built and no host byte is emitted here; this is a decision-function checkpoint.

#include "dbt/guest/rv32_active_chunk_plan.h"
#include "dbt/qmc/qir.h"
#include "dbt/util/common.h"

#include <cstdio>
#include <vector>

using namespace dbt;
using Guard = dbt::qir::InstRVVTypedChunkBegin::GuardKind;
using dbt::rv32::rvvplan::ActiveChunkInput;
using dbt::rv32::rvvplan::ActiveChunkPlan;
using dbt::rv32::rvvplan::kMaxBoundedChunks;
using dbt::rv32::rvvplan::VStartOwner;

namespace
{
int g_failures = 0;

#define CHECK(cond)                                                                                  \
	do {                                                                                         \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		long long _a = (long long)(a);                                                       \
		long long _b = (long long)(b);                                                       \
		if (_a != _b) {                                                                      \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, _a, _b);                                           \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// The FOUR producers' shapes, written the way each PRODUCER states them -- a host chunk width and
// the guest SEW -- and translated here into the planner's destination-side geometry, so a reader can
// check the mapping instead of taking it on trust. This is the whole of the W27 generalization:
//
//   family       one unit reads   one unit writes   dest element   -> unit_dest_bytes
//   equal-width  bytes            bytes             sew               bytes
//   widening     bytes/2          bytes             2*sew             bytes
//   narrowing    bytes            bytes/2           sew               bytes/2
//   FP           chunk_bytes      chunk_bytes       sew               chunk_bytes
//
// `chunk_bytes` here is always the HOST chunk width the route computes (`min(VLEN/8, 64)` on the
// integer routes), never the destination span: the point of the helpers is that the destination span
// is derived from it per family, in one visible place.
ActiveChunkInput IntegerFrame(u32 chunks, u32 chunk_bytes, u32 sew, bool on, bool static_full = false)
{
	return ActiveChunkInput{
	    .family_enabled = on,
	    .units = chunks,
	    .unit_dest_bytes = chunk_bytes,
	    .dest_element_bytes = sew,
	    .guard_kind = Guard::VTypeInteger,
	    .static_full_vl_proved = static_full,
	    .suffix_is_body_tail = true,
	    .per_chunk_active_mask = true,
	    .vstart_owner = VStartOwner::LastChunkNode,
	};
}

ActiveChunkInput WideningFrame(u32 chunks, u32 chunk_bytes, u32 sew, bool on, bool static_full = false)
{
	auto in = IntegerFrame(chunks, chunk_bytes, sew, on, static_full);
	in.dest_element_bytes = 2 * sew; // the destination element is twice the source's
	return in;
}

// The narrowing frame: the destination SPAN is halved, the destination ELEMENT is the vtype SEW
// (for a narrowing op the vtype SEW is the destination width and the source is 2*SEW). Both halves
// of that sentence are needed -- halving only the span, or only the element, gives a stride that is
// wrong by a factor of two in opposite directions.
ActiveChunkInput NarrowingFrame(u32 chunks, u32 chunk_bytes, u32 sew, bool on)
{
	auto in = IntegerFrame(chunks, chunk_bytes, sew, on);
	in.unit_dest_bytes = chunk_bytes / 2;
	return in;
}

ActiveChunkInput FpFrame(u32 chunks, u32 chunk_bytes, u32 sew, bool on, bool per_chunk_mask = true,
			 Guard kind = Guard::VTypePartialVlVstartFrmHost)
{
	return ActiveChunkInput{
	    .family_enabled = on,
	    .units = chunks,
	    .unit_dest_bytes = chunk_bytes,
	    .dest_element_bytes = sew,
	    .guard_kind = kind,
	    .static_full_vl_proved = false,
	    .suffix_is_body_tail = true,
	    .per_chunk_active_mask = per_chunk_mask,
	    .vstart_owner = VStartOwner::FrameEpilogue,
	};
}

// ---------------------------------------------------------------------------------------------
// [1] a single chunk
// ---------------------------------------------------------------------------------------------
void TestSingleChunk()
{
	// The integer convention: no boundable chunk, so not a bounded frame. The `vstart` write must
	// stay on the one chunk node, and the frame must NOT claim to own it.
	auto const one_int = ActiveChunkPlan::Make(IntegerFrame(1, 64, 4, /*on=*/true));
	CHECK(!one_int.bounded());
	CHECK_EQ(one_int.bound_nodes(), 0u);
	CHECK(!one_int.bound_at(0));
	CHECK(one_int.unit_finishes(0));
	CHECK(!one_int.frame_clears_vstart());

	// Two chunks is the smallest bounded integer frame, and its single bound is on chunk 1.
	auto const two_int = ActiveChunkPlan::Make(IntegerFrame(2, 64, 4, /*on=*/true));
	CHECK(two_int.bounded());
	CHECK_EQ(two_int.bound_nodes(), 1u);
	CHECK(!two_int.bound_at(0));
	CHECK(two_int.bound_at(1));
	CHECK(two_int.frame_clears_vstart());
	CHECK(!two_int.unit_finishes(1));

	// The FP convention: the epilogue already owns the write, so one chunk IS boundable and the
	// bound sits at chunk 0 with immediate 0 -- the `vl == 0` test.
	auto const one_fp = ActiveChunkPlan::Make(FpFrame(1, 64, 4, /*on=*/true));
	CHECK(one_fp.bounded());
	CHECK_EQ(one_fp.first_bounded_unit(), 0u);
	CHECK_EQ(one_fp.bound_nodes(), 1u);
	CHECK(one_fp.bound_at(0));
	CHECK_EQ(one_fp.element_base(0), 0u);
	// The FP frame never transfers the vstart write, bounded or not.
	CHECK(!one_fp.frame_clears_vstart());

	// Zero chunks is not a frame at all (no accepted route produces it: every FP and integer
	// producer is entered only after its admission predicate returned a non-zero count).
	CHECK(!ActiveChunkPlan::Make(FpFrame(0, 64, 4, /*on=*/true)).bounded());
	CHECK(!ActiveChunkPlan::Make(IntegerFrame(0, 64, 4, /*on=*/true)).bounded());
	printf("    single chunk: integer unbounded, FP bounded at chunk 0\n");
}

// ---------------------------------------------------------------------------------------------
// [2] provably full VL, two independent ways
// ---------------------------------------------------------------------------------------------
void TestFullVl()
{
	// W21's static proof, on the widening route that consults it.
	auto const proved =
	    ActiveChunkPlan::Make(WideningFrame(4, 64, 2, /*on=*/true, /*static_full=*/true));
	CHECK(!proved.bounded());
	CHECK_EQ(proved.bound_nodes(), 0u);
	// ... and the frame is the OFF-arm frame, flags included: last chunk still finishes, the
	// frame still does not own the vstart write.
	CHECK(proved.unit_finishes(3));
	CHECK(!proved.frame_clears_vstart());
	// The same shape WITHOUT the proof is bounded, so the check above cannot pass vacuously.
	CHECK(ActiveChunkPlan::Make(WideningFrame(4, 64, 2, /*on=*/true, /*static_full=*/false))
		  .bounded());

	// A guard kind that already proves `vl == VLMAX && vstart == 0`. Every such kind must be
	// refused: a bound inside one of those frames is a translation-time constant `false` and
	// QEmit Panics rather than emit it.
	for (Guard k : {Guard::VTypeVlVstart, Guard::VTypeVlVstartFrmRNE, Guard::VTypeVlVstartBaseLimit,
			Guard::VTypeVlVstartFrmRNEBaseMask, Guard::VTypeVlVstartBaseMask}) {
		CHECK(dbt::qir::InstRVVTypedChunkBegin::GuardProvesFullVl(k));
		auto in = IntegerFrame(4, 64, 4, /*on=*/true);
		in.guard_kind = k;
		CHECK(!ActiveChunkPlan::Make(in).bounded());
	}
	printf("    full VL: static proof and 5 full-VL guard kinds all give the OFF-arm frame\n");
}

// ---------------------------------------------------------------------------------------------
// [3] unknown / partial VL keeps the whole ladder
// ---------------------------------------------------------------------------------------------
void TestPartialVl()
{
	// Unknown vl and provably SHORT vl are the same answer to this conjunct: both are
	// `static_full_vl_proved == false`, and both must keep the ladder unchanged. (Statically
	// omitting the inactive suffix of a known-short frame is W23 and is NOT implemented.)
	auto const p = ActiveChunkPlan::Make(IntegerFrame(4, 64, 2, /*on=*/true));
	CHECK(p.bounded());
	CHECK_EQ(p.units(), 4u);
	CHECK_EQ(p.elements_per_unit(), 32u); // 64 bytes / e16
	CHECK_EQ(p.bound_nodes(), 3u);
	CHECK(!p.bound_at(0));
	for (u32 c = 1; c < 4; ++c) {
		CHECK(p.bound_at(c));
		CHECK_EQ(p.element_base(c), c * 32u);
		CHECK(!p.unit_finishes(c));
	}
	CHECK(p.frame_clears_vstart());

	// The FP convention on the same count: one bound per chunk, chunk 0 included.
	auto const f = ActiveChunkPlan::Make(FpFrame(4, 64, 8, /*on=*/true));
	CHECK(f.bounded());
	CHECK_EQ(f.elements_per_unit(), 8u); // 64 bytes / e64
	CHECK_EQ(f.bound_nodes(), 4u);
	for (u32 c = 0; c < 4; ++c) {
		CHECK(f.bound_at(c));
		CHECK_EQ(f.element_base(c), c * 8u);
	}
	printf("    partial/unknown VL: ladders are %u (integer) and %u (FP) bounds\n",
	       p.bound_nodes(), f.bound_nodes());
}

// ---------------------------------------------------------------------------------------------
// [4] the widening family's stride is the DESTINATION element's
// ---------------------------------------------------------------------------------------------
void TestWideningDestinationLanes()
{
	// e16 widening at a 64-byte host chunk: destination EEW is 32 bits, so 16 lanes per chunk.
	auto const w = ActiveChunkPlan::Make(WideningFrame(4, 64, 2, /*on=*/true));
	CHECK(w.bounded());
	CHECK_EQ(w.elements_per_unit(), 16u);
	u32 const want[4] = {0, 16, 32, 48};
	for (u32 c = 0; c < 4; ++c)
		CHECK_EQ(w.element_base(c), want[c]);

	// The source-lane answer, computed here so the assertion below cannot pass if the planner
	// ever took the source width: it is a DIFFERENT ladder at every chunk but 0, and it would
	// place bounds above the live vl of a full-VL execution -- skipping live chunks.
	auto const src = ActiveChunkPlan::Make(IntegerFrame(4, 64, 2, /*on=*/true)); // ds == ss == 2
	CHECK_EQ(src.elements_per_unit(), 32u);
	CHECK(src.element_base(1) != w.element_base(1));
	CHECK_EQ(src.element_base(1), 2u * w.element_base(1));

	// And the whole point of the shared field: the equal-width route at the DESTINATION width of
	// that widening op produces the identical ladder, because the ladder is a function of the
	// destination element width and nothing else.
	auto const same = ActiveChunkPlan::Make(IntegerFrame(4, 64, 4, /*on=*/true));
	for (u32 c = 0; c < 4; ++c)
		CHECK_EQ(same.element_base(c), w.element_base(c));
	printf("    widening: e16 -> 16 destination lanes/chunk, source answer (32) rejected\n");
}

// ---------------------------------------------------------------------------------------------
// [4b] the narrowing family's unit covers HALF a host chunk of destination bytes
// ---------------------------------------------------------------------------------------------
void TestNarrowingDestinationSpan()
{
	// e8 narrowing (`vnsrl.wv` at vtype SEW=8): one unit reads 64 source bytes of e16 elements
	// and writes 32 destination bytes of e8 elements, so it covers 32 architectural elements.
	auto const n = ActiveChunkPlan::Make(NarrowingFrame(4, 64, 1, /*on=*/true));
	CHECK(n.bounded());
	CHECK_EQ(n.elements_per_unit(), 32u);
	u32 const want[4] = {0, 32, 64, 96};
	for (u32 c = 0; c < 4; ++c)
		CHECK_EQ(n.element_base(c), want[c]);

	// THE MISTAKE W27 EXISTS TO PREVENT, computed here so the check above cannot pass with the
	// wrong numerator: using the unit's HOST SOURCE span (64) instead of its destination span
	// (32) doubles the stride. At a full-VL execution of this frame `vl == 4*32 == 128`, so the
	// wrong ladder's last bound is `vl <= 192` -- TRUE -- and it would skip two LIVE units.
	auto const src_span = ActiveChunkPlan::Make(IntegerFrame(4, 64, 1, /*on=*/true));
	CHECK_EQ(src_span.elements_per_unit(), 64u);
	CHECK(src_span.element_base(1) != n.element_base(1));
	CHECK_EQ(src_span.element_base(1), 2u * n.element_base(1));
	u32 const full_vl = 4u * n.elements_per_unit();
	CHECK(n.element_base(3) < full_vl);	   // the right ladder never fires at full VL
	CHECK(src_span.element_base(2) >= full_vl); // the wrong one fires and drops live units

	// The other single-factor mistake: keeping the destination span but taking the SOURCE element
	// width (2*SEW) halves the stride, which would leave the last unit's bound below the elements
	// it covers and retire nothing it should.
	auto wrong_elem = NarrowingFrame(4, 64, 1, /*on=*/true);
	wrong_elem.dest_element_bytes = 2;
	CHECK_EQ(ActiveChunkPlan::Make(wrong_elem).elements_per_unit(), 16u);
	CHECK(ActiveChunkPlan::Make(wrong_elem).element_base(1) != n.element_base(1));

	// THE GENERALIZATION, STATED AS AN EQUALITY. A narrowing unit whose destination span is
	// `bytes/2` has exactly the geometry of an equal-width unit of width `bytes/2` at the same
	// destination element width. The planner therefore has no narrowing case at all -- which is
	// what "no opcode, no family tag" means operationally.
	for (u32 bytes : {16u, 32u, 64u})
		for (u32 sew : {1u, 2u, 4u})
			for (u32 chunks : {1u, 2u, 4u, 8u}) {
				auto const a = ActiveChunkPlan::Make(NarrowingFrame(chunks, bytes, sew, true));
				auto const b = ActiveChunkPlan::Make(IntegerFrame(chunks, bytes / 2, sew, true));
				CHECK_EQ(a.bounded(), b.bounded());
				CHECK_EQ(a.elements_per_unit(), b.elements_per_unit());
				CHECK_EQ(a.bound_nodes(), b.bound_nodes());
				CHECK_EQ(a.frame_clears_vstart(), b.frame_clears_vstart());
				for (u32 c = 0; c < chunks; ++c) {
					CHECK_EQ(a.element_base(c), b.element_base(c));
					CHECK_EQ(a.bound_at(c), b.bound_at(c));
					CHECK_EQ(a.unit_finishes(c), b.unit_finishes(c));
				}
			}
	printf("    narrowing: e8 from e16 -> 32 dest elements/unit; source span (64) and source\n");
	printf("               element (16) both rejected; identical to an equal-width bytes/2 unit\n");
}

// ---------------------------------------------------------------------------------------------
// [5] the refusals
// ---------------------------------------------------------------------------------------------
void TestIneligible()
{
	// A multi-member run frame. The early exit leaves the WHOLE body, so in a run it would jump
	// past later guest instructions; Emit_vchunkactive Panics on `members != 1`.
	{
		auto in = FpFrame(4, 64, 8, /*on=*/true);
		in.suffix_is_body_tail = false;
		CHECK(!ActiveChunkPlan::Make(in).bounded());
		in.suffix_is_body_tail = true; // the control: the same frame IS bounded
		CHECK(ActiveChunkPlan::Make(in).bounded());
	}
	// A guard kind that does not bound `vec.vl` by `vlmax`: the whole-register transfers, whose
	// EVL is `nregs * VLEN / EEW` and is independent of vl and vtype entirely.
	for (Guard k : {Guard::VlenbVstart, Guard::VlenbVstartBaseLimit, Guard::VlenbRestartable}) {
		CHECK(!dbt::qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax(k));
		auto in = IntegerFrame(4, 64, 4, /*on=*/true);
		in.guard_kind = k;
		CHECK(!ActiveChunkPlan::Make(in).bounded());
	}
	// No per-chunk active mask: the FP frame whose shared masks were not deferred into the body.
	CHECK(!ActiveChunkPlan::Make(FpFrame(4, 64, 8, /*on=*/true, /*per_chunk_mask=*/false)).bounded());
	// The two-vtype FP frame: SEW is only resolved at run time, so there is no element stride and
	// the bound's immediate would not be an element index.
	CHECK(!ActiveChunkPlan::Make(FpFrame(4, 64, /*sew=*/0, /*on=*/true)).bounded());
	// A chunk that is not a whole number of destination elements. Refused (fail closed), which is
	// the direction that can only cost a saving.
	CHECK(!ActiveChunkPlan::Make(IntegerFrame(4, /*chunk_bytes=*/4, /*sew=*/8, /*on=*/true)).bounded());
	CHECK(!ActiveChunkPlan::Make(IntegerFrame(4, /*chunk_bytes=*/0, /*sew=*/8, /*on=*/true)).bounded());
	// InstVChunkActive indexes `chunk` in a u8 and Panics at >= 64, so 64 chunks is the last
	// admissible frame and 65 must be refused rather than reach the node's Panic.
	CHECK(ActiveChunkPlan::Make(IntegerFrame(kMaxBoundedChunks, 64, 4, /*on=*/true)).bounded());
	CHECK(!ActiveChunkPlan::Make(IntegerFrame(kMaxBoundedChunks + 1, 64, 4, /*on=*/true)).bounded());
	// And the switch, in all three families' shapes.
	CHECK(!ActiveChunkPlan::Make(IntegerFrame(4, 64, 4, /*on=*/false)).bounded());
	CHECK(!ActiveChunkPlan::Make(WideningFrame(4, 64, 2, /*on=*/false)).bounded());
	CHECK(!ActiveChunkPlan::Make(FpFrame(4, 64, 8, /*on=*/false)).bounded());
	printf("    refusals: multi-member, 3 vlenb guard kinds, no per-chunk mask, dynamic SEW,\n");
	printf("              non-tiling chunk, %u+1 chunks, and all three switches off\n",
	       kMaxBoundedChunks);
}

// ---------------------------------------------------------------------------------------------
// [6] equivalence with the three pre-W26 decisions
// ---------------------------------------------------------------------------------------------
//
// The three legacy expressions, transcribed from the S1-2A/S1-2D/S1-3A/S1-3W reports (not from the
// new header) and evaluated independently here. Each is compared against the planner over the
// shapes ITS producer can present; the domains are narrow on purpose, because outside them the
// comparison is meaningless rather than informative.
struct Legacy {
	bool bounded;
	u32 bound_nodes;
	u32 first_bound;
	bool frame_clears_vstart;
};

Legacy LegacyInteger(u32 chunks, bool on, Guard k, bool static_full, bool widening)
{
	bool const bounded = on && chunks >= 2 && chunks <= 64 &&
			     dbt::qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax(k) &&
			     !dbt::qir::InstRVVTypedChunkBegin::GuardProvesFullVl(k) &&
			     !(widening && static_full);
	return {bounded, bounded ? chunks - 1 : 0, 1, bounded};
}

Legacy LegacyFp(u32 nchunks, bool on, Guard k, bool shared_masks_are_per_chunk)
{
	bool const bounded = on && shared_masks_are_per_chunk &&
			     !dbt::qir::InstRVVTypedChunkBegin::GuardProvesFullVl(k);
	return {bounded, bounded ? nchunks : 0, 0, false};
}

// The legacy element stride, re-derived the way the three producers formed it: chunk c's immediate
// was the single expression `c * chunk_bytes / element_bytes`, which equals `c * (chunk_bytes /
// element_bytes)` only because the element width DIVIDES the chunk on every shape those routes
// admit (`chunk_bytes = min(VLEN/8, 32 or 64)` is a power of two and at least 16, since
// VLEN_MIN_BITS is 128, while the destination element is at most 8 bytes). That precondition is the
// reason the planner may hand out a per-chunk stride at all, so this suite refuses to compare on a
// shape where it does not hold rather than silently comparing two different formulas.
u32 LegacyStride(u32 chunk_bytes, u32 element_bytes)
{
	if (element_bytes == 0 || chunk_bytes % element_bytes != 0)
		Panic("rvv_active_chunk_plan_test: the legacy stride is only defined when the "
		      "element width divides the host chunk");
	return chunk_bytes / element_bytes;
}

void CheckAgainstLegacy(char const *what, ActiveChunkPlan const &p, Legacy const &l, u32 chunks,
			u32 chunk_bytes, u32 element_bytes)
{
	u32 const legacy_lanes = LegacyStride(chunk_bytes, element_bytes);
	CHECK_EQ(p.bounded(), l.bounded);
	CHECK_EQ(p.bound_nodes(), l.bound_nodes);
	CHECK_EQ(p.frame_clears_vstart(), l.frame_clears_vstart);
	if (!l.bounded)
		return;
	CHECK_EQ(p.first_bounded_unit(), l.first_bound);
	CHECK_EQ(p.elements_per_unit(), legacy_lanes);
	for (u32 c = 0; c < chunks; ++c) {
		// The legacy sites formed `c * chunk_bytes / element` and `(c + 1 == chunks) &&
		// !bounded`; both are re-formed here from the legacy quantities.
		CHECK_EQ(p.element_base(c), c * legacy_lanes);
		CHECK_EQ(p.bound_at(c), c >= l.first_bound);
		CHECK_EQ(p.unit_finishes(c), c + 1 == chunks && !l.frame_clears_vstart);
	}
	(void)what;
}

void TestLegacyEquivalence()
{
	u32 cells = 0;
	// EQUAL-WIDTH INTEGER (S1-3A). Domain: `bytes = min(VLEN/8, 32 or 64)` is a power of two and
	// at least 16 because VLEN_MIN_BITS is 128; SEW is 1, 2, 4 or 8 bytes; `chunks` reaches 128 at
	// VLEN 4096/LMUL 8 with a byte-width-widened op, so the sweep goes past the node's 64 cap.
	for (u32 bytes : {16u, 32u, 64u})
		for (u32 sew : {1u, 2u, 4u, 8u})
			for (u32 chunks : {0u, 1u, 2u, 3u, 4u, 8u, 63u, 64u, 65u, 128u})
				for (bool on : {false, true}) {
					auto const in = IntegerFrame(chunks, bytes, sew, on);
					CheckAgainstLegacy("int", ActiveChunkPlan::Make(in),
							   LegacyInteger(chunks, on, in.guard_kind,
									 false, false),
							   chunks, bytes, sew);
					++cells;
				}
	// WIDENING INTEGER (S1-3W + W21). Domain: the same chunk widths; SEW is 1, 2 or 4 bytes
	// because the destination is 2*SEW and must be a legal element width; `chunks` tops out at 64
	// (widening needs emul_in_range(lmul_log2 + 1), so LMUL <= 4). Both positions of W21's proof.
	for (u32 bytes : {16u, 32u, 64u})
		for (u32 ss : {1u, 2u, 4u})
			for (u32 chunks : {0u, 1u, 2u, 3u, 4u, 8u, 64u})
				for (bool on : {false, true})
					for (bool full : {false, true}) {
						auto const in =
						    WideningFrame(chunks, bytes, ss, on, full);
						CheckAgainstLegacy(
						    "widen", ActiveChunkPlan::Make(in),
						    LegacyInteger(chunks, on, in.guard_kind, full, true),
						    chunks, bytes, 2 * ss);
						++cells;
					}
	// FP (S1-2A/S1-2D). Domain: the chunk widths the generic width rule admits, SEW 4 or 8 (the FP
	// routes never admit another), `nchunks` in 1..8 (`rvvrun::kMaxChunks`, and the FP admission
	// predicates cap at 8 register groups times that), the three guard kinds the two routes build,
	// and both answers to `shared_mask_ops == nchunks`. The two-vtype frame's `sew == 0` is
	// covered in [5] instead, because the legacy expression reaches it only through
	// `shared_mask_ops == 0 != nchunks`.
	for (Guard k : {Guard::VTypePartialVlVstartFrmHost, Guard::VTypePartialVlVstartFrmRNE,
			Guard::VTypeE32OrE64M2PartialVlVstartFrmRNE})
		for (u32 bytes : {16u, 32u, 64u})
			for (u32 sew : {4u, 8u})
				for (u32 chunks : {1u, 2u, 4u, 8u})
					for (bool on : {false, true})
						for (bool per_chunk : {false, true}) {
							auto const in = FpFrame(chunks, bytes, sew, on,
										per_chunk, k);
							CheckAgainstLegacy(
							    "fp", ActiveChunkPlan::Make(in),
							    LegacyFp(chunks, on, k, per_chunk), chunks,
							    bytes, sew);
							++cells;
						}
	printf("    %u cells agree with the three pre-W26 decisions\n", cells);

	// NARROWING (W27) IS THE ONE FAMILY WHOSE DECISION CHANGES, AND THIS IS WHERE THAT IS STATED
	// RATHER THAN SMUGGLED. Before W27 the narrowing producer emitted no bound at any switch
	// position, so its legacy decision is the constant `unbounded`. What must still hold is the
	// OFF arm: with the integer policy switch clear the plan is byte-for-byte the legacy decision,
	// including `frame_clears_vstart == false` and `finish` on the architecturally last unit --
	// that is the inertness half. With the switch ON the plan is the equal-width ladder over the
	// narrowing geometry, which is the intended change.
	u32 off_cells = 0, on_cells = 0;
	for (u32 bytes : {16u, 32u, 64u})
		for (u32 sew : {1u, 2u, 4u})
			for (u32 chunks : {0u, 1u, 2u, 3u, 4u, 8u, 64u, 65u}) {
				auto const off = ActiveChunkPlan::Make(NarrowingFrame(chunks, bytes, sew, false));
				CHECK(!off.bounded());
				CHECK_EQ(off.bound_nodes(), 0u);
				CHECK(!off.frame_clears_vstart());
				if (chunks)
					CHECK(off.unit_finishes(chunks - 1));
				++off_cells;

				auto const on = ActiveChunkPlan::Make(NarrowingFrame(chunks, bytes, sew, true));
				bool const want = chunks >= 2 && chunks <= kMaxBoundedChunks;
				CHECK_EQ(on.bounded(), want);
				CHECK_EQ(on.bound_nodes(), want ? chunks - 1 : 0);
				CHECK_EQ(on.frame_clears_vstart(), want);
				if (want) {
					CHECK(!on.bound_at(0));
					for (u32 c = 1; c < chunks; ++c) {
						CHECK(on.bound_at(c));
						CHECK_EQ(on.element_base(c), c * (bytes / 2 / sew));
						CHECK(!on.unit_finishes(c));
					}
				}
				++on_cells;
			}
	printf("    narrowing: %u OFF cells are the legacy (unbounded) decision, %u ON cells are the\n",
	       off_cells, on_cells);
	printf("               equal-width ladder over the narrowing geometry -- W27's one change\n");

	// THE ONE DELIBERATE DIFFERENCE, AND ITS DIRECTION. The FP sites tested only
	// `!GuardProvesFullVl`; the planner also requires `GuardBoundsVlByVlmax`. On the three kinds
	// the FP routes actually build the two agree (checked above and static_asserted at the call
	// sites), so no FP frame moves. On a kind no FP route builds, the planner is strictly more
	// conservative -- it refuses where the old expression would have bounded.
	{
		auto in = FpFrame(4, 64, 8, /*on=*/true);
		in.guard_kind = Guard::VlenbRestartable;
		auto const l = LegacyFp(4, true, in.guard_kind, true);
		CHECK(l.bounded); // the old FP expression WOULD have bounded it
		CHECK(!ActiveChunkPlan::Make(in).bounded()); // the planner refuses
		printf("    and is strictly more conservative on vl-unguarded kinds no FP route builds\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [7] the invariants the early exit rests on
// ---------------------------------------------------------------------------------------------
void TestStructuralInvariants()
{
	for (u32 bytes : {16u, 32u, 64u})
		for (u32 sew : {1u, 2u, 4u, 8u})
			for (u32 chunks : {2u, 3u, 8u, 64u}) {
				auto const p = ActiveChunkPlan::Make(IntegerFrame(chunks, bytes, sew, true));
				CHECK(p.bounded());
				CHECK_EQ(p.element_base(0), 0u);
				bool seen_bound = false;
				for (u32 c = 1; c < chunks; ++c) {
					// Strictly increasing: this is what makes the inactive set a
					// SUFFIX, so `vl <= base_c` implies `vl <= base_{c+1}` and one
					// forward branch can retire the rest of the body.
					CHECK(p.element_base(c) > p.element_base(c - 1));
					// Monotone: once bounds start they never stop.
					if (p.bound_at(c))
						seen_bound = true;
					else
						CHECK(!seen_bound);
				}
				// The last chunk's base is below VLMAX for the group: the frame tiles
				// exactly, so base(chunks-1) + lanes == chunks * lanes.
				CHECK_EQ(p.element_base(chunks - 1) + p.elements_per_unit(),
					 chunks * p.elements_per_unit());
			}
	printf("    bases strictly increase, bounds are a suffix, tiling is exact\n");
}
} // namespace

int main()
{
	printf("[1] a single-chunk frame, both vstart-ownership conventions\n");
	TestSingleChunk();
	printf("[2] provably full VL, two independent ways\n");
	TestFullVl();
	printf("[3] unknown / partial VL keeps the whole ladder\n");
	TestPartialVl();
	printf("[4] widening counts DESTINATION lanes\n");
	TestWideningDestinationLanes();
	printf("[4b] narrowing covers HALF a host chunk of destination bytes\n");
	TestNarrowingDestinationSpan();
	printf("[5] ineligible frames are refused, fail-closed\n");
	TestIneligible();
	printf("[6] equivalence with the three pre-W26 decisions\n");
	TestLegacyEquivalence();
	printf("[7] the invariants the early exit rests on\n");
	TestStructuralInvariants();
	if (g_failures) {
		printf("FAIL rvv_active_chunk_plan_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_chunk_plan_test\n");
	return 0;
}
