#pragma once

// THE QCG RVV LOWERING DECISION MODEL. Phase 1: the model and its sink, nothing else.
//
// WHAT QUESTION THIS ANSWERS, AND WHY THE TREE DID NOT ALREADY ANSWER IT.
//
// rvdbt already has three vocabularies that each answer a DIFFERENT question about an RVV
// instruction, and none of them answers "what shape of host code did QCG actually produce":
//
//   rvvfinal::Ineligibility (rv32_frame_semantics.h)
//       "why can this typed frame not drop its inactive suffix?"  A property of a frame that WAS
//       built. A frame can be `MemoryOrProtocol`-ineligible and still be perfectly packed SIMD
//       (every full-VL vadd.vv frame is), so this enum cannot be read as a lowering-quality
//       statement.
//
//   rv32::vrun::CutReason (rv32_vrun.h)
//       "why did the vector-run scan stop extending the run?"  A property of a SCAN, about the
//       instruction AFTER the one being lowered as much as about this one.
//
//   route_census::Route (rv32_route_census.h)
//       a KEY, not a reason: which of sixteen named encodings a C++ handler entry belongs to. It
//       counts helper entries; it says nothing about what the non-helper executions did.
//
// This header adds ONE axis those three do not have -- the shape of the emitted code -- and a set
// of constraint axes to say why that shape is what it is. It deliberately does NOT restate any of
// the three above. Instead each of the three keeps its own enum, next to which its OWNER states a
// total projection onto this header's `Constraint` set:
//
//   rvvlower::ConstraintsFor(rvvfinal::Ineligibility)         in rv32_frame_semantics.h
//   rvvlower::ConstraintsFor(qir::...::GuardKind)             in rv32_frame_semantics.h
//   rvvlower::ConstraintsFor(rv32::vrun::CutReason)           in rv32_vrun.h
//
// so the vocabularies are JOINED rather than duplicated, and the joins are tested for totality
// (rvv_lowering_decision_test.cpp section [2]). A reason added to any of the three without a
// projection fails that test.
//
// WHAT THIS HEADER MUST NOT BECOME. It is not an opcode table and it is not a second admission
// predicate. Every `Decision` recorded by phase 1 is DERIVED, at the point the existing code has
// already decided, from data that code already computed (QIR node fields, the frame's guard kind,
// the producer's own declared classification). Nothing here re-decides anything, and nothing here
// names a guest mnemonic.
//
// PHASE 1 EMITS NOTHING. `Note` writes to this header's own globals and is called only from
// translation-time code. No host byte moves, no guest state is read or written, and no emitter is
// touched -- that is the phase-1 contract, and it is what makes the layer safe to land before the
// emitters are reorganised around it.
//
// SCALARIZATION IS NOT SIMD. `Codegen::NativeScalar` exists precisely so that a route which emits
// host code without calling a helper cannot be reported as parallel. The QCG inventory
// (QCG_RVV1_NATIVE_HELPER_INVENTORY_20260921.md) found fourteen such rows; recording them as
// `PackedSIMD` would be the single most misleading thing this layer could do.

#include "dbt/guest/rv32_route_census.h"
#include "dbt/util/common.h"

namespace dbt::rv32::rvvlower
{

// THE SHAPE OF THE HOST CODE A GUEST VECTOR INSTRUCTION RUNS AS. Four values, and the boundaries
// between them are observable rather than editorial:
//
//   PackedSIMD    at least one host instruction covers more than one guest element. (The mask
//                 families cover 64 mask lanes per 64-bit GPR instruction; they are packed by this
//                 definition and the inventory records the register-file caveat per row.)
//   NativeScalar  emitted host code, no hcall on this path, but one guest element per host
//                 sequence -- an element loop, or a translation-time-unrolled per-lane sequence.
//   Helper        the execution runs the C++ reference's `for (e = vstart; e < vl; ++e)`.
//   Unsupported   no implementation exists anywhere: no decoder op, no handler, no route.
//
// ORDERED BY PREFERENCE, best first. `Worse()` below relies on that order and nothing else does.
enum class Codegen : u8 {
	PackedSIMD = 0,
	NativeScalar = 1,
	Helper = 2,
	Unsupported = 3,
};

inline char const *CodegenName(Codegen c)
{
	switch (c) {
	case Codegen::PackedSIMD: return "packed-simd";
	case Codegen::NativeScalar: return "native-scalar";
	case Codegen::Helper: return "helper";
	default: return "unsupported";
	}
}

// The worse (less parallel) of two shapes. A frame's shape is the worst of its nodes': a frame
// that scalarizes one lane operation is a scalarizing frame even if its loads are packed.
constexpr Codegen Worse(Codegen a, Codegen b) { return (u8)a >= (u8)b ? a : b; }

// WHY A LOWERING IS NOT THE SHAPE IT COULD BE, on eleven axes. The axes are the ones the QCG
// admission predicates, the emitted guards and the helper fallbacks actually test -- each value
// below names a test that exists in the tree, not a category invented for symmetry.
//
//   HostIsa          the host instruction set has no packed form of this operation. THIS IS THE
//                    ONE VALUE THAT MEANS "NECESSARY": x86 has no packed integer divide and no
//                    packed 64x64 high product, so Emit_vchunkpartialalu's scalar arm is forced.
//                    Everything else on this list is a property of rvdbt, not of the host.
//   Sew              the admitted element width, or a guard's exact-vtype compare.
//   Lmul             the admitted register-group multiplier, or a guard's exact-vtype compare.
//   Mask             the vm bit / the v0 mask operand.
//   VlVstart         `vl == VLMAX`, `vl <= VLMAX`, or `vstart == 0`.
//   Overlap          the architectural source/destination register-group overlap rules.
//   Rounding         a guest rounding mode (frm, vxrm) with no host equivalent, or an ordering
//                    requirement that forbids reassociation.
//   CrossLane        destination element i is not a function of source element i alone, or the
//                    destination is a scalar / element 0.
//   MemoryProtocol   guest memory access, address wrap, restart/vstart publication, or fault
//                    delivery.
//   MissingLowering  NOT an ISA limit: a packed form is expressible on this host and rvdbt has not
//                    written it. This is the bucket that measures remaining work.
//   Disabled         a config switch is off.
enum class Constraint : u8 {
	HostIsa = 0,
	Sew,
	Lmul,
	Mask,
	VlVstart,
	Overlap,
	Rounding,
	CrossLane,
	MemoryProtocol,
	MissingLowering,
	Disabled,
};

static constexpr unsigned kConstraintCount = (unsigned)Constraint::Disabled + 1;

inline char const *ConstraintName(Constraint c)
{
	switch (c) {
	case Constraint::HostIsa: return "host-isa";
	case Constraint::Sew: return "sew";
	case Constraint::Lmul: return "lmul";
	case Constraint::Mask: return "mask";
	case Constraint::VlVstart: return "vl/vstart";
	case Constraint::Overlap: return "overlap";
	case Constraint::Rounding: return "rounding";
	case Constraint::CrossLane: return "cross-lane";
	case Constraint::MemoryProtocol: return "memory/protocol";
	case Constraint::MissingLowering: return "missing-lowering";
	default: return "disabled";
	}
}

// A set of axes. A single axis is rarely the whole story -- an exact-vtype guard pins SEW and LMUL
// at once -- so the model carries sets, never a single "the" reason.
using ConstraintSet = u16;
static_assert(kConstraintCount <= 16, "ConstraintSet must hold every Constraint");

constexpr ConstraintSet Set() { return 0; }
constexpr ConstraintSet Set(Constraint c) { return (ConstraintSet)(1u << (unsigned)c); }
constexpr ConstraintSet Set(Constraint a, Constraint b) { return Set(a) | Set(b); }
constexpr ConstraintSet Set(Constraint a, Constraint b, Constraint c)
{
	return Set(a) | Set(b) | Set(c);
}
constexpr bool Has(ConstraintSet s, Constraint c) { return (s & Set(c)) != 0; }

// ONE LOWERING DECISION.
//
//   preferred   the best shape this instruction form's lowering could have on this host. For every
//               element-wise vector operation that is `PackedSIMD`; a producer states something
//               else only when the ISA itself forbids parallelism.
//
//               `preferred == Codegen::Helper` IS THE LAYER'S "NOT YET CLASSIFIED" STATE, not a
//               claim that the helper is optimal. It is what a helper record carries when the
//               producer that fell back stated no reason -- which is the whole migration backlog
//               (QCG_RVV_LOWERING_ARCHITECTURE_20260921.md section 4), and is counted separately
//               in `Sink::helper_unstated` so the backlog is measurable rather than invisible.
//               Recording `PackedSIMD` there instead would claim a packed lowering is possible
//               for forms nobody has looked at, including the three OPCFG configuration
//               instructions, which have no lane work at all.
//   emitted     what this translation actually produced.
//   blocked     why `emitted` is not `preferred`. EMPTY IF AND ONLY IF THEY AGREE -- `Valid()`
//               enforces that, so "scalarized for no stated reason" cannot be recorded.
//   runtime_fallback  the emitted code carries a guard whose MISS arm runs the helper. This is the
//               inventory's CONDITIONAL_DIRECT_WITH_HELPER_FALLBACK class, and it is a separate
//               flag rather than "guarded is non-empty" on purpose: a whole-register frame's guard
//               tests only `vlenb`, which is a build constant of this rvdbt and therefore projects
//               onto NO guest-facing axis -- yet that frame absolutely does have a fallback edge.
//   guarded     WHICH guest-facing axes that guard re-tests. May be empty while
//               `runtime_fallback` is set, for exactly the reason above. Only emitted code carries
//               a guard: `Valid()` refuses a guarded or fallback-carrying Helper/Unsupported.
struct Decision {
	Codegen preferred = Codegen::PackedSIMD;
	Codegen emitted = Codegen::Helper;
	ConstraintSet blocked = 0;
	bool runtime_fallback = false;
	ConstraintSet guarded = 0;

	constexpr bool Valid() const
	{
		if ((emitted == preferred) != (blocked == 0))
			return false;
		if ((u8)emitted < (u8)preferred)
			return false; // a lowering cannot be better than its own best case
		bool const is_emitted_code =
		    emitted == Codegen::PackedSIMD || emitted == Codegen::NativeScalar;
		if (runtime_fallback && !is_emitted_code)
			return false;
		if (guarded != 0 && !runtime_fallback)
			return false;
		if (emitted == Codegen::Unsupported && preferred != Codegen::Unsupported)
			return false;
		return true;
	}

	// Does a guard miss on this decision run the helper?
	constexpr bool FallsBackToHelper() const { return runtime_fallback; }
};

// ---------------------------------------------------------------------------------------------
// IS THIS ENCODING A VECTOR INSTRUCTION?
//
// Derived from the RVV 1.0 encoding and nothing else, because the sink must not record a scalar
// `flw` as a vector helper entry. OP-V is one major opcode. LOAD-FP / STORE-FP are SHARED between
// scalar and vector: RVV 1.0 7.3 gives the vector forms width 0 (e8), 5 (e16), 6 (e32) and 7
// (e64), while the scalar flw/fld/fsw/fsd are width 2 and 3. So the funct3 field separates them
// exactly, with no stub name and no decoder table involved.
constexpr bool IsVectorEncoding(u32 raw)
{
	u32 const opcode = raw & 0x7fu, funct3 = (raw >> 12) & 0x7u;
	if (opcode == 0x57u)
		return true; // OP-V, including the three OPCFG forms
	if (opcode == 0x07u || opcode == 0x27u)
		return funct3 != 2u && funct3 != 3u;
	return false;
}

// ---------------------------------------------------------------------------------------------
// THE SINK.
//
// Translation-time only, and deliberately not gated on a config switch. `route_census::note` is
// gated because it sits in the interpreter's per-execution handler path; this runs once per guest
// instruction per TRANSLATION, so a gate would buy nothing and would make the record unavailable
// without a rebuild. It writes nothing but the globals below: no CPUState, no emitted byte.
//
// `g_route_emitted` is keyed by `route_census::Route`, REUSING that header's classifier rather
// than introducing a second key, so a route's helper-entry count and its lowering decision join on
// one index. Encodings the census does not name land in `R_other_vector`, which is why `g_last`
// carries the raw word as well -- a focused test on one instruction reads that, not the histogram.
struct Sink {
	Decision last{};
	u32 last_raw = 0;
	bool has_last = false;
	u64 emitted[4] = {};
	u64 blocked[kConstraintCount] = {};
	u64 guarded[kConstraintCount] = {};
	u64 route_emitted[route_census::R_COUNT][4] = {};
	u64 runtime_fallback = 0; // decisions whose emitted code can still reach the helper
	// Helper records whose producer stated no reason: `preferred == Codegen::Helper`. The
	// migration backlog, measured.
	u64 helper_unstated = 0;
};

inline Sink g_sink{};

inline void Reset() { g_sink = Sink{}; }

// Record one decision. Refuses an inconsistent one rather than storing it: a `Decision` that fails
// `Valid()` is a bug at the call site (a scalarization with no stated reason, or a guard on a
// helper), and silently counting it would make the layer's own evidence unreliable.
inline void Note(u32 raw, Decision const &d)
{
	if (!d.Valid())
		Panic("rvv lowering decision: inconsistent decision recorded");
	g_sink.last = d;
	g_sink.last_raw = raw;
	g_sink.has_last = true;
	++g_sink.emitted[(unsigned)d.emitted];
	++g_sink.route_emitted[route_census::classify(raw)][(unsigned)d.emitted];
	g_sink.runtime_fallback += d.runtime_fallback ? 1u : 0u;
	if (d.emitted == Codegen::Helper && d.preferred == Codegen::Helper)
		++g_sink.helper_unstated;
	for (unsigned c = 0; c < kConstraintCount; ++c) {
		if (Has(d.blocked, (Constraint)c))
			++g_sink.blocked[c];
		if (Has(d.guarded, (Constraint)c))
			++g_sink.guarded[c];
	}
}

} // namespace dbt::rv32::rvvlower
