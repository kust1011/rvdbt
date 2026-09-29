// PHASE 1 OF THE QCG RVV LOWERING DECISION LAYER, tested on its own.
//
// WHAT THE LAYER CLAIMS, AND WHAT THIS FILE HAS TO ESTABLISH.
//
// `dbt/guest/rv32_lowering_decision.h` adds one axis rvdbt did not have -- the SHAPE of the host
// code a guest vector instruction runs as -- and records it from the two points where the existing
// code has already decided: `rvvfinal::CloseFrame` (every typed-chunk frame in rv32_qir.cpp closes
// there) and `RV32Translator::TranslateHelper` (every vector instruction with no route ends there).
// Three claims need evidence, and the third is the one a careless layer would get wrong:
//
//   1. the model is internally consistent and cannot record a nonsense decision;
//   2. it JOINS the three existing vocabularies instead of duplicating them;
//   3. IT DOES NOT CALL SCALARIZATION SIMD, and it does not move a single emitted byte.
//
// SECTION MAP, AND WHAT EACH SECTION'S FAILURE LOOKS LIKE
//
//   [1] THE MODEL'S OWN INVARIANTS. `Decision::Valid()` is the gate `Note` refuses records on, so
//       every later section rests on it. Checked in both directions: the four consistent shapes
//       are accepted, and six specific inconsistencies are refused -- a scalarization with no
//       stated reason, a reason with no shape change, a guard on a helper record, a
//       `runtime_fallback` on a helper record, an `Unsupported` emitted from a `PackedSIMD`
//       preference, and an emitted shape BETTER than the preferred one. Failure = the layer would
//       happily store "native scalar, because nothing", which is exactly the kind of record that
//       makes a diagnostic lie. Also checked: `Worse` really is the fold the frame rule needs.
//
//   [2] TOTALITY OF THE THREE JOINS. Every `rvvfinal::Ineligibility`, every
//       `qir::InstRVVTypedChunkBegin::GuardKind` and every `rvvrun::CutReason` is enumerated here
//       and required to have a projection onto the shared axis set. This is the check that keeps
//       the new `Constraint` enum a REFINEMENT of the existing vocabularies rather than a fourth
//       one: a reason added to any of the three without a lowering meaning fails here, in this
//       file, rather than silently defaulting somewhere. Two specific projections are also pinned
//       because they are the ones a refactor would most plausibly get backwards: an exact-vtype
//       guard must pin SEW and LMUL, and a `Vlenb*` guard must NOT (its EVL does not read vtype).
//
//   [3] THE SCALAR-LANE PREDICATE, against an INDEPENDENTLY WRITTEN copy of the emitter's own
//       condition, over all 52 `InstVChunkPartialAlu::Kind` values x the four element widths --
//       208 cases. `rvvfinal::PartialAluScalarizesLanes` mirrors qemit.cpp:3732; if it drifts, the
//       layer reports `vdiv.vv` as packed SIMD while the emitter unrolls an `idiv` per lane, which
//       is the single most damaging error this checkpoint could ship. The independent copy is
//       written from the four Kind groups by NAME rather than by copying the expression, so a
//       shared typo cannot pass. Section [3b] additionally pins the SEW boundary: high multiply
//       scalarizes at SEW 8 and is packed at SEW 4, and divide scalarizes at every width.
//
//   [4] THE THREE REPRESENTATIVE PATHS, translated for real through `CompilerGenRegionIR`, one
//       region each. These are acceptance WITNESSES, not a per-opcode table -- the layer contains
//       no mention of any of the three:
//         vadd.vv  -> Codegen::PackedSIMD,    blocked empty
//         vdiv.vv  -> Codegen::NativeScalar,  blocked == {HostIsa}
//         vleff    -> Codegen::Helper,        blocked == {MemoryProtocol}, no runtime fallback
//       The guard projection recorded for each frame is compared against the guard kind read
//       INDEPENDENTLY off that frame's own begin node in the constructed Region, so a record that
//       belonged to some other frame, or that used a stale guard kind, fails. Failure of the vdiv
//       row is claim 3 broken.
//
//   [5] THE EMITTED CODE DID NOT MOVE. For each of the three witnesses the constructed QIR is
//       checked against the shape the tree produced before this checkpoint: vadd.vv still builds
//       one typed frame whose body is two `vstatechunkload`, one `vchunkadd` and one
//       `vstatechunkstore`; vdiv.vv still builds one typed frame whose body is `vchunkpartialalu`
//       with `op == Kind::DivS`; vleff still builds NO frame at all and exactly one `hcall`.
//       Failure = the decision layer changed a lowering, which phase 1 forbids outright. (The
//       byte-level goldens for these routes live in the existing route suites, which are run
//       alongside this file; this section is the structural half.)
//
//   [6] THE CENSUS JOIN. `Sink::route_emitted` is keyed by `route_census::classify`, reusing that
//       header's classifier rather than a second key, so a route's helper-entry count and its
//       lowering decision land on one index. Checked on `R_vadd_vv`, and checked NEGATIVELY: the
//       unstated-helper backlog counter must move for `vsetvli` (which has no stated reason) and
//       must not for `vleff` (which states one).
//
// NOTHING HERE EXECUTES HOST VECTOR CODE. Like the other route tests in this directory it stops
// after QIR construction: no QEmit, no QCodegen, no guest program. `rvv_qcg_typed_chunk_force_emit`
// is set so the admission predicates' `__builtin_cpu_supports` probes do not make the result depend
// on the development host, which is the same convention vaddvv_typedchunk_route_test.cpp uses.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_frame_semantics.h"
#include "dbt/guest/rv32_lowering_decision.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

using dbt::rv32::rvvlower::Codegen;
using dbt::rv32::rvvlower::Constraint;
using dbt::rv32::rvvlower::ConstraintSet;
using dbt::rv32::rvvlower::Decision;
using dbt::rv32::rvvlower::Has;
using dbt::rv32::rvvlower::Set;
using Guard = dbt::qir::InstRVVTypedChunkBegin::GuardKind;
using Inel = dbt::rv32::rvvfinal::Ineligibility;
using Cut = dbt::rv32::rvvrun::CutReason;
using PKind = dbt::qir::InstVChunkPartialAlu::Kind;

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
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// [1] the model's own invariants

// Braced initializers do not survive a function-like macro argument, so the five fields are named
// through this one constructor. It is deliberately positional in the struct's own field order.
constexpr Decision Dec(Codegen preferred, Codegen emitted, ConstraintSet blocked,
		       bool runtime_fallback, ConstraintSet guarded)
{
	return Decision{preferred, emitted, blocked, runtime_fallback, guarded};
}

void TestModelInvariants()
{
	// The four consistent shapes the two hooks can produce.
	CHECK(Dec(Codegen::PackedSIMD, Codegen::PackedSIMD, 0, true, Set(Constraint::Sew)).Valid());
	CHECK(Dec(Codegen::PackedSIMD, Codegen::NativeScalar, Set(Constraint::HostIsa), true,
		  Set(Constraint::Sew))
		  .Valid());
	CHECK(Dec(Codegen::PackedSIMD, Codegen::Helper, Set(Constraint::MemoryProtocol), false, 0)
		  .Valid());
	CHECK(Dec(Codegen::Helper, Codegen::Helper, 0, false, 0).Valid()); // the unstated state

	// A scalarization with no stated reason. This is the record that would let the layer report
	// "we scalarize here" while answering "why" with silence.
	CHECK(!Dec(Codegen::PackedSIMD, Codegen::NativeScalar, 0, true, 0).Valid());
	// A reason with no shape change: the reason would be unattributable.
	CHECK(!Dec(Codegen::PackedSIMD, Codegen::PackedSIMD, Set(Constraint::HostIsa), true, 0).Valid());
	// A helper record cannot carry a guard or a fallback edge: the helper IS the path.
	CHECK(!Dec(Codegen::PackedSIMD, Codegen::Helper, Set(Constraint::MemoryProtocol), false,
		   Set(Constraint::Sew))
		   .Valid());
	CHECK(!Dec(Codegen::PackedSIMD, Codegen::Helper, Set(Constraint::MemoryProtocol), true, 0)
		   .Valid());
	// `Unsupported` means nothing implements the form; it cannot be the outcome of a preference
	// for packed SIMD, because there would then be something to prefer.
	CHECK(!Dec(Codegen::PackedSIMD, Codegen::Unsupported, Set(Constraint::MissingLowering), false, 0)
		   .Valid());
	// A lowering cannot come out better than its own stated best case.
	CHECK(!Dec(Codegen::NativeScalar, Codegen::PackedSIMD, Set(Constraint::HostIsa), false, 0)
		   .Valid());

	// `Worse` is the fold CloseFrame uses over a frame's nodes: one scalar lane node makes the
	// whole frame a scalarizing frame, and the fold is order-independent.
	CHECK(dbt::rv32::rvvlower::Worse(Codegen::PackedSIMD, Codegen::NativeScalar) ==
	      Codegen::NativeScalar);
	CHECK(dbt::rv32::rvvlower::Worse(Codegen::NativeScalar, Codegen::PackedSIMD) ==
	      Codegen::NativeScalar);
	CHECK(dbt::rv32::rvvlower::Worse(Codegen::PackedSIMD, Codegen::PackedSIMD) ==
	      Codegen::PackedSIMD);
	CHECK(dbt::rv32::rvvlower::Worse(Codegen::Helper, Codegen::NativeScalar) == Codegen::Helper);

	// The encoding predicate that keeps a scalar flw out of the vector sink. RVV 1.0 7.3: the
	// vector LOAD-FP/STORE-FP widths are 0/5/6/7; the scalar flw/fld/fsw/fsd are 2 and 3.
	CHECK(dbt::rv32::rvvlower::IsVectorEncoding(0x021101d7u));  // vadd.vv, OP-V
	CHECK(dbt::rv32::rvvlower::IsVectorEncoding(0x09057557u));  // vsetvli, OP-V OPCFG
	CHECK(dbt::rv32::rvvlower::IsVectorEncoding(0x02056087u));  // vle32.v, width 6
	CHECK(!dbt::rv32::rvvlower::IsVectorEncoding(0x00052007u)); // flw, width 2
	CHECK(!dbt::rv32::rvvlower::IsVectorEncoding(0x00053007u)); // fld, width 3
	CHECK(!dbt::rv32::rvvlower::IsVectorEncoding(0x00052027u)); // fsw, width 2
	CHECK(!dbt::rv32::rvvlower::IsVectorEncoding(0x00000033u)); // add, not a vector major
	printf("    Valid() accepts 4 consistent shapes and refuses 6 inconsistent ones\n");
}

// ---------------------------------------------------------------------------------------------
// [2] the three joins are total

void TestProjectionTotality()
{
	namespace L = dbt::rv32::rvvlower;

	// Every Ineligibility. `None` is the only value allowed to project onto the empty set
	// together with `MultiMember`, which is about the frame holding several guest instructions
	// and says nothing about lane parallelism.
	Inel const inels[] = {Inel::None,	    Inel::MultiMember,
			      Inel::WholeRegisterEvl, Inel::ScalarResult,
			      Inel::IsaCrossLane,     Inel::MemoryOrProtocol,
			      Inel::LoweringNotDecomposed, Inel::EligibleShapeNotEnrolled,
			      Inel::Unclassified};
	CHECK_EQ((unsigned)(sizeof(inels) / sizeof(inels[0])), (unsigned)Inel::Unclassified + 1u);
	for (Inel r : inels) {
		ConstraintSet const s = L::ConstraintsFor(r);
		bool const may_be_empty = r == Inel::None || r == Inel::MultiMember;
		if (!may_be_empty)
			CHECK(s != 0);
		(void)s;
	}
	CHECK_EQ(L::ConstraintsFor(Inel::IsaCrossLane), Set(Constraint::CrossLane));
	CHECK_EQ(L::ConstraintsFor(Inel::MemoryOrProtocol), Set(Constraint::MemoryProtocol));
	CHECK_EQ(L::ConstraintsFor(Inel::LoweringNotDecomposed), Set(Constraint::MissingLowering));

	// Every GuardKind. The enum is sparse (17..20 are out of numeric order), so the values are
	// listed rather than iterated over a range.
	Guard const guards[] = {Guard::VTypeVlVstart,
				Guard::VlenbVstart,
				Guard::VTypePartialVlVstartFrmRNE,
				Guard::VTypeE32OrE64M2PartialVlVstartFrmRNE,
				Guard::VTypeVlVstartFrmRNE,
				Guard::VTypeVlOrPartialVstart,
				Guard::VTypeVlVstartBaseLimit,
				Guard::VlenbVstartBaseLimit,
				Guard::VTypeInteger,
				Guard::VTypeIntegerTwoArm,
				Guard::VTypeIntegerNoRestart,
				Guard::VTypePartialVlVstartFrmHost,
				Guard::VTypeFpNoRestart,
				Guard::VlenbRestartable,
				Guard::VTypeFpAnyRM,
				Guard::VTypeFpAnyRMNoRestart,
				Guard::VTypeVlOrPartialVstartBaseLimit,
				Guard::VTypeVlVstartFrmRNEBaseMask,
				Guard::VTypeVlVstartBaseMask,
				Guard::VTypeVlVstartFrmHostRound,
				Guard::VTypePartialVlVstartFrmHostRound};
	for (Guard k : guards) {
		ConstraintSet const s = L::ConstraintsFor(k);
		bool const vlenb = k == Guard::VlenbVstart || k == Guard::VlenbVstartBaseLimit ||
				   k == Guard::VlenbRestartable;
		// EVERY VType* GUARD COMPARES vec.vtype FOR EXACT EQUALITY, so it pins SEW and LMUL.
		// Getting this backwards would report a frame as unconditionally admitted for every
		// element width, which is the opposite of what its guard does.
		CHECK_EQ(Has(s, Constraint::Sew), !vlenb);
		CHECK_EQ(Has(s, Constraint::Lmul), !vlenb);
	}
	// A Vlenb* guard reads no vtype at all: its EVL is nregs*VLEN/EEW, legal even under vill.
	CHECK(!Has(L::ConstraintsFor(Guard::VlenbRestartable), Constraint::Sew));
	// The full-VL kinds add the vl/vstart term; VTypeInteger deliberately does not (its body
	// handles vstart and its vl is only bounded, not pinned).
	CHECK(Has(L::ConstraintsFor(Guard::VTypeVlVstart), Constraint::VlVstart));
	CHECK(!Has(L::ConstraintsFor(Guard::VTypeInteger), Constraint::VlVstart));
	// A rounding-mode guard, and a guest-address-range guard.
	CHECK(Has(L::ConstraintsFor(Guard::VTypeVlVstartFrmRNE), Constraint::Rounding));
	CHECK(Has(L::ConstraintsFor(Guard::VTypeVlVstartBaseLimit), Constraint::MemoryProtocol));

	// Every CutReason. Totality here means "the switch has a case", which the compiler already
	// enforces for a switch over a scoped enum with every enumerator listed; what this loop adds
	// is that the values which DO describe this instruction's own shape carry an axis.
	for (unsigned r = 0; r < dbt::rv32::rvvrun::kCutReasonCount; ++r) {
		Cut const c = (Cut)r;
		ConstraintSet const s = L::ConstraintsFor(c);
		bool const scan_property = c == Cut::None || c == Cut::MaxMembers ||
					   c == Cut::InsnBudget || c == Cut::RegionBoundary ||
					   c == Cut::ControlFlow || c == Cut::TrapInsn ||
					   c == Cut::ScalarInsn || c == Cut::RegisterPressure;
		CHECK_EQ(s == 0, scan_property);
	}
	CHECK_EQ(L::ConstraintsFor(Cut::Disabled), Set(Constraint::Disabled));
	CHECK_EQ(L::ConstraintsFor(Cut::UnsupportedVector), Set(Constraint::MissingLowering));
	CHECK_EQ(L::ConstraintsFor(Cut::VectorMemory), Set(Constraint::MemoryProtocol));
	printf("    %u ineligibilities, %u guard kinds, %u cut reasons all project\n",
	       (unsigned)(sizeof(inels) / sizeof(inels[0])),
	       (unsigned)(sizeof(guards) / sizeof(guards[0])),
	       dbt::rv32::rvvrun::kCutReasonCount);
}

// ---------------------------------------------------------------------------------------------
// [3] the scalar-lane predicate mirrors the emitter

// INDEPENDENTLY WRITTEN from `Emit_vchunkpartialalu`'s scalar arm (qemit.cpp:3732-3811), by naming
// the four Kind groups the emitter's three booleans cover rather than by copying the expression.
// The emitter's own comment is the specification:
//
//     "AVX-512 has neither packed integer divide nor 64x64 high-product. Emit exact host scalar
//      operations for active lanes, without a C++ helper call."
//
//   divide        DivU DivS RemU RemS       -- every width; there is no packed integer divide
//   high_multiply MulHU MulH MulHSU         -- only at SEW 8; below that the emitter widens and
//   fractional    FracMul                      uses vpmullw/vpmulld/vpmullq
bool ScalarArmReference(PKind k, u8 sew_bytes)
{
	switch (k) {
	case PKind::DivU:
	case PKind::DivS:
	case PKind::RemU:
	case PKind::RemS:
		return true;
	case PKind::MulHU:
	case PKind::MulH:
	case PKind::MulHSU:
	case PKind::FracMul:
		return sew_bytes == 8;
	default:
		return false;
	}
}

void TestScalarLanePredicate()
{
	unsigned scalar_cases = 0, checked = 0;
	for (unsigned op = 0; op <= (unsigned)PKind::FracMul; ++op) {
		for (u8 sew : {(u8)1, (u8)2, (u8)4, (u8)8}) {
			bool const got = dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)op, sew);
			bool const want = ScalarArmReference((PKind)op, sew);
			CHECK_EQ(got, want);
			scalar_cases += got ? 1u : 0u;
			++checked;
		}
	}
	// 4 divide kinds x 4 widths + 4 high/fractional kinds x 1 width.
	CHECK_EQ(checked, 208u);
	CHECK_EQ(scalar_cases, 20u);

	// [3b] the two boundaries the whole claim rests on, pinned positively AND negatively. If
	// either of these flipped, the layer would report vdiv.vv as packed SIMD.
	CHECK(dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::DivS, 4));
	CHECK(dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::RemU, 1));
	CHECK(dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::MulH, 8));
	CHECK(!dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::MulH, 4));
	CHECK(!dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::Mul, 4));
	CHECK(!dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::Add, 8));
	CHECK(!dbt::rv32::rvvfinal::PartialAluScalarizesLanes((u8)PKind::Macc, 8));
	printf("    %u kind x width cases agree with the emitter's arm; %u scalarize\n", checked,
	       scalar_cases);
}

// ---------------------------------------------------------------------------------------------
// [4] / [5] the three witnesses, translated for real

// vsetvli a0, a0, e32, m1, tu, ma -- the exact word the accepted vadd route test uses, so the
// vtype this file's frames are built on is the one that suite already pins.
constexpr u32 INSN_VSETVLI = 0x09057557u;
constexpr u32 INSN_VADD_VV = 0x021101d7u; // vadd.vv  v3, v1, v2   (funct6 0,  OPIVV, vm=1)
constexpr u32 INSN_VDIV_VV = 0x861121d7u; // vdiv.vv  v3, v1, v2   (funct6 33, OPMVV, vm=1)
constexpr u32 INSN_VLE32FF = 0x03056087u; // vle32ff.v v1, (a0)    (mop=00, lumop=10000)

Region *TranslateOne(MemArena &arena, u32 words[2], u32 vlen_bits)
{
	config::rvv_qcg_typed_chunk = true;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk_force_emit = true; // see the file header
	config::vlen_bits = vlen_bits;

	CompilerJob::IpRangesSet ranges = {{0u, 8u}}; // two 4-byte instructions at ip 0 and 4
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

struct Frames {
	unsigned n_frames = 0;
	unsigned n_hcall = 0;
	InstRVVTypedChunkBegin *begin = nullptr; // the LAST frame's begin node
	std::vector<Op> body;			 // the LAST frame's body, in construction order
	std::vector<InstVChunkPartialAlu *> partial_alu;
};

Frames Scan(Region *region)
{
	Frames f;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto const op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				++f.n_frames;
				f.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				f.body.clear();
				f.partial_alu.clear();
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				open = false;
				continue;
			}
			if (op == Op::_hcall)
				++f.n_hcall;
			if (!open)
				continue;
			f.body.push_back(op);
			if (op == Op::_vchunkpartialalu)
				f.partial_alu.push_back(static_cast<InstVChunkPartialAlu *>(&ins));
		}
	}
	return f;
}

// The decision the layer recorded for the SECOND instruction of the pair, plus the frame the
// translator actually built for it. Both come from the same translation, which is what lets the
// caller cross-check the record against the QIR rather than against itself.
struct Witness {
	Decision d;
	u32 raw = 0;
	Frames frames;
	bool has_last = false;
};

// THE ARENA IS THE CALLER'S, and it has to be: `Region`, its instruction lists and every `Inst *`
// this Witness carries are arena-allocated, so an arena local to this function would be destroyed
// before the caller read a single field.
Witness Run(MemArena &arena, u32 second, u32 vlen_bits)
{
	dbt::rv32::rvvlower::Reset();
	u32 words[2] = {INSN_VSETVLI, second};
	Region *r = TranslateOne(arena, words, vlen_bits);
	Witness w;
	w.d = dbt::rv32::rvvlower::g_sink.last;
	w.raw = dbt::rv32::rvvlower::g_sink.last_raw;
	w.has_last = dbt::rv32::rvvlower::g_sink.has_last;
	w.frames = Scan(r);
	return w;
}

void TestPackedSimdWitness()
{
	MemArena arena(1u << 20);
	Witness const w = Run(arena, INSN_VADD_VV, 512);
	CHECK(w.has_last);
	CHECK_EQ(w.raw, INSN_VADD_VV);
	CHECK(w.d.Valid());
	// The claim: an admitted vadd.vv chunk frame is packed SIMD, with nothing blocking it.
	CHECK(w.d.emitted == Codegen::PackedSIMD);
	CHECK(w.d.preferred == Codegen::PackedSIMD);
	CHECK_EQ(w.d.blocked, (ConstraintSet)0);
	// It is nevertheless a CONDITIONAL direct route: the frame carries a guard whose miss arm
	// calls the same helper. "Packed SIMD" and "always runs" are different statements.
	CHECK(w.d.runtime_fallback);
	CHECK(w.d.FallsBackToHelper());

	// [5] the frame the translator built, read independently, and the guard projection compared
	// against THAT frame's own kind rather than against a constant.
	CHECK_EQ(w.frames.n_frames, 1u);
	CHECK(w.frames.begin != nullptr);
	if (w.frames.begin != nullptr) {
		CHECK_EQ(w.d.guarded,
			 dbt::rv32::rvvlower::ConstraintsFor(w.frames.begin->guard_kind));
		CHECK(Has(w.d.guarded, Constraint::Sew));
		CHECK(Has(w.d.guarded, Constraint::Lmul));
	}
	// The unchanged body: load both source chunks, add, store. Any change here is a lowering
	// change, which phase 1 forbids.
	unsigned adds = 0, loads = 0, stores = 0;
	for (Op op : w.frames.body) {
		adds += op == Op::_vchunkadd;
		loads += op == Op::_vstatechunkload;
		stores += op == Op::_vstatechunkstore;
	}
	CHECK_EQ(adds, 1u);
	CHECK_EQ(loads, 2u);
	CHECK_EQ(stores, 1u);
	CHECK_EQ(w.frames.body.size(), 4u);
	printf("    vadd.vv: packed-simd, nothing blocked, guard %u, body unchanged (4 nodes)\n",
	       w.frames.begin ? (unsigned)w.frames.begin->guard_kind : 0u);
}

void TestNativeScalarWitness()
{
	MemArena arena(1u << 20);
	Witness const w = Run(arena, INSN_VDIV_VV, 512);
	CHECK(w.has_last);
	CHECK_EQ(w.raw, INSN_VDIV_VV);
	CHECK(w.d.Valid());
	// THE CLAIM THIS WHOLE CHECKPOINT EXISTS FOR. vdiv.vv takes a direct QCG route -- it builds
	// a typed frame and calls no helper on the hit path -- and the code inside that frame is a
	// translation-time-unrolled `idiv` per lane. It must NOT be reported as packed SIMD.
	CHECK(w.d.emitted == Codegen::NativeScalar);
	CHECK(w.d.preferred == Codegen::PackedSIMD);
	// And the reason must be the one that means NECESSARY: x86 has no packed integer divide.
	CHECK_EQ(w.d.blocked, Set(Constraint::HostIsa));
	CHECK(Has(w.d.blocked, Constraint::HostIsa));
	CHECK(!Has(w.d.blocked, Constraint::MissingLowering)); // not unfinished work
	CHECK(w.d.runtime_fallback);

	CHECK_EQ(w.frames.n_frames, 1u);
	CHECK(w.frames.begin != nullptr);
	if (w.frames.begin != nullptr) {
		CHECK_EQ(w.d.guarded,
			 dbt::rv32::rvvlower::ConstraintsFor(w.frames.begin->guard_kind));
		// The shared integer builder's frame: exact vtype, vl <= VLMAX, body handles
		// vstart. So SEW and LMUL are guarded and vl/vstart is NOT -- the contrast with
		// vadd.vv's full-VL guard above, read off the two frames rather than asserted.
		CHECK(Has(w.d.guarded, Constraint::Sew));
		CHECK(!Has(w.d.guarded, Constraint::VlVstart));
	}
	// [5] the unchanged body: one `vchunkpartialalu` carrying the divide kind.
	CHECK_EQ(w.frames.partial_alu.size(), 1u);
	if (!w.frames.partial_alu.empty()) {
		auto *n = w.frames.partial_alu[0];
		CHECK_EQ((unsigned)n->op, (unsigned)PKind::DivS);
		CHECK_EQ((unsigned)n->sew_bytes, 4u);
		CHECK(n->architectural_mask); // the scalar arm Panics without it
		// ...and the predicate that classified it agrees, from the node's own fields.
		CHECK(dbt::rv32::rvvfinal::PartialAluScalarizesLanes(n->op, n->sew_bytes));
	}
	printf("    vdiv.vv: NATIVE-SCALAR via a direct route, blocked by host-isa, 1 partial-alu\n");
}

void TestHelperWitness()
{
	MemArena arena(1u << 20);
	Witness const w = Run(arena, INSN_VLE32FF, 512);
	CHECK(w.has_last);
	CHECK_EQ(w.raw, INSN_VLE32FF);
	CHECK(w.d.Valid());
	CHECK(w.d.emitted == Codegen::Helper);
	// The producer stated a reason, so this is NOT the unstated state.
	CHECK(w.d.preferred == Codegen::PackedSIMD);
	CHECK_EQ(w.d.blocked, Set(Constraint::MemoryProtocol));
	// A helper-only lowering has no guard and no fallback edge: the helper is the path.
	CHECK(!w.d.runtime_fallback);
	CHECK(!w.d.FallsBackToHelper());
	CHECK_EQ(w.d.guarded, (ConstraintSet)0);

	// [5] no typed frame was built at all, and exactly two hcalls exist in the region -- the
	// vsetvli's (direct-setvl is off by default) and the vleff's.
	CHECK_EQ(w.frames.n_frames, 0u);
	CHECK_EQ(w.frames.n_hcall, 2u);
	printf("    vle32ff.v: helper-only, blocked by memory/protocol, no frame, 2 hcalls\n");
}

// ---------------------------------------------------------------------------------------------
// [6] the census join and the backlog counter

void TestCensusJoinAndBacklog()
{
	namespace RC = dbt::rv32::route_census;

	{
		MemArena arena(1u << 20);
		Witness const w = Run(arena, INSN_VADD_VV, 512);
		(void)w;
		auto const &s = dbt::rv32::rvvlower::g_sink;
		// The decision lands on the SAME index route_census would count a vadd.vv helper
		// entry on. One key, two facts.
		CHECK_EQ(s.route_emitted[RC::R_vadd_vv][(unsigned)Codegen::PackedSIMD], 1ull);
		CHECK_EQ(s.route_emitted[RC::R_vadd_vv][(unsigned)Codegen::Helper], 0ull);
		// The vsetvli in the same pair reached TranslateHelper with no stated reason, so it
		// is one unit of the migration backlog and is counted as such.
		CHECK_EQ(s.route_emitted[RC::R_vsetvli][(unsigned)Codegen::Helper], 1ull);
		CHECK_EQ(s.helper_unstated, 1ull);
		CHECK_EQ(s.emitted[(unsigned)Codegen::PackedSIMD], 1ull);
		CHECK_EQ(s.runtime_fallback, 1ull);
		CHECK_EQ(s.blocked[(unsigned)Constraint::HostIsa], 0ull);
	}
	{
		MemArena arena(1u << 20);
		Witness const w = Run(arena, INSN_VDIV_VV, 512);
		(void)w;
		auto const &s = dbt::rv32::rvvlower::g_sink;
		CHECK_EQ(s.emitted[(unsigned)Codegen::NativeScalar], 1ull);
		CHECK_EQ(s.emitted[(unsigned)Codegen::PackedSIMD], 0ull);
		CHECK_EQ(s.blocked[(unsigned)Constraint::HostIsa], 1ull);
		CHECK_EQ(s.helper_unstated, 1ull); // the vsetvli, again
	}
	{
		MemArena arena(1u << 20);
		Witness const w = Run(arena, INSN_VLE32FF, 512);
		(void)w;
		auto const &s = dbt::rv32::rvvlower::g_sink;
		// TWO helper records, but only ONE of them is unstated: vleff stated its reason and
		// vsetvli did not. A layer that recorded every helper identically would fail here.
		CHECK_EQ(s.emitted[(unsigned)Codegen::Helper], 2ull);
		CHECK_EQ(s.helper_unstated, 1ull);
		CHECK_EQ(s.blocked[(unsigned)Constraint::MemoryProtocol], 1ull);
		CHECK_EQ(s.runtime_fallback, 0ull);
	}
	printf("    decisions join route_census's key; the unstated backlog is separable\n");
}
} // namespace

int main()
{
	printf("[1] the model's own invariants\n");
	TestModelInvariants();
	printf("[2] the three existing vocabularies all project onto the shared axes\n");
	TestProjectionTotality();
	printf("[3] the scalar-lane predicate mirrors Emit_vchunkpartialalu's arm\n");
	TestScalarLanePredicate();
	printf("[4a] witness: vadd.vv is packed SIMD\n");
	TestPackedSimdWitness();
	printf("[4b] witness: vdiv.vv is NATIVE SCALAR, not SIMD\n");
	TestNativeScalarWitness();
	printf("[4c] witness: vle32ff.v is helper-only\n");
	TestHelperWitness();
	printf("[6] the census join and the migration backlog counter\n");
	TestCensusJoinAndBacklog();
	if (g_failures) {
		printf("FAIL rvv_lowering_decision_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_lowering_decision_test\n");
	return 0;
}
