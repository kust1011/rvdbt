// R1/R2 (2026-09-17). THE CANDIDATE-VTYPE ENTRY FOR THE LLVM FP RUN FRAME.
//
// WHY THIS FILE EXISTS
//
// F1-F5 gave the FP-ALU family a complete LLVM lowering, but only for an ip range that contains the
// guest's own `vsetvli`. `TranslateIPRange` resets `rvv_bb_vtype` to ~0u at the top of every range,
// and FormRun refused a route whose row carries `requires_observed_vtype` under an unobserved
// vtype, so a dependent FP chain longer than one translation block kept the helper from the second
// range onward. Measured shape of that on the frozen f32sub guest (256 consecutive `vfsub.vv`, one
// AOT region, five ip ranges): 50 guest instructions lowered natively, 206 on `rv32_vfalu`.
//
// R1 makes the `requires_observed_vtype` refusal a property of (route, BACKEND) instead of route
// alone, passed in through `rvvrun::RunBackendCaps` rather than baked into the shared
// ClassifyTypedAluRoute table -- so no pure-QCG consumer of that table sees a different answer.
// R2 gives the unobserved scan a better candidate than the hard-coded canonical one: the vtype some
// constant `vsetvli`/`vsetivli` of THIS REGION established.
//
// WHAT IS ASSERTED, AND WHAT MAKES EACH ROW FALSIFIABLE
//
//   [S1] UNKNOWN ENTRY. A region of two ip ranges whose SECOND range holds only FP instructions --
//        no `vsetvli` -- builds a full three-member frame in that second range too, with the
//        full-VL FP guard kind. Falsifiable by [S5] and [S6]: the same words build no such frame on
//        the QCG backend, or with either switch off.
//   [S2] THE CANDIDATE IS THE REGION'S, NOT A CONSTANT. Every row is run at four vtypes, three of
//        which are NOT `VTYPE_E32_M1_TA_MA`, including two at LMUL=2. The second range's frame must
//        carry the region's vtype and its vlmax, and the canonical constant must appear NOWHERE in
//        the emitted guard. A fix that simply deleted the refusal -- leaving the hard-coded
//        candidate in place -- passes [S1] and fails this.
//   [S3] NO CANDIDATE KEEPS THE CANONICAL RULE. A region with no constant `vsetvl` at all still
//        proposes `VTYPE_E32_M1_TA_MA`, exactly as before R2.
//   [S4] THE REGISTER-FORM `vsetvl` INVALIDATES IT. After a `vsetvl` whose vtype is a runtime GPR,
//        the region candidate is dropped and the scan falls back to the canonical proposal. Without
//        the invalidation this row would see the stale e64,m2 candidate, so the assertion is a
//        difference, not a restatement.
//   [S5] THE GUARD AND THE ORDERED FALLBACK ARE THE UNCHANGED ONES. The unknown-entry frame is
//        entered through a guard that tests the candidate vtype with `icmp eq`, tests `vl` with
//        `eq` (never `ule`), and tests `fcsr & 0xe0 == 0`; its fast arm contains no helper call and
//        exactly `3 * chunks` constrained-FP calls; its fallback arm replays all three members in
//        guest order, each preceded by a store of its own guest PC, and pays NO MXCSR bracket. A
//        candidate is only safe BECAUSE of this guard, so it is asserted directly rather than
//        assumed -- and the miss path's real cost (the guard's own CPUState loads and compares,
//        plus the frame-boundary state commit, but not a bracket) is pinned by the same rows.
//   [S6] QCG IS UNCHANGED. The same two-range region on the pure-QCG backend: the observed range
//        still builds its frame, the unobserved range still builds none, and the cut is still
//        CutReason::UnobservedVType. This is the row that proves `RunBackendCaps` gates rather
//        than removes.
//   [S9] THE FUSED FAMILY, WHICH THE SAME FLAG ADMITS. `RunBackendCaps::fp_candidate_vtype_ok` is
//        keyed on `fp_host_arith`, and that row is true for BOTH `vfalu` and `vfma`, so the
//        relaxation reaches the fused family too -- but [S1]..[S5] drive `.vv` FP-ALU only. This row
//        drives two more unknown-second-range fixtures, one all-`vfmacc`/`vfmadd` and one mixing
//        FP-ALU with a fused member in the SAME frame, at e32/m1 and e64/m2, and repeats the
//        guard/candidate/fallback assertions on them. Without it the fused half of the flag is
//        admitted by the code and covered by nothing.
//   [S8] THE QCG INTEGER RUN IS BIT-FOR-BIT INVARIANT TO THE REGION CANDIDATE. This row exists
//        because [S6] could not have caught the first version of R2. [S6] asks whether an FP run
//        FORMS on the QCG backend, and it does not -- but the six integer `.vv` rows carry
//        `requires_observed_vtype = false`, so a pure-QCG INTEGER run already forms under an
//        unobserved vtype and already carries a proposed vtype into its `rvvtypedchunkbegin`. The
//        first version of R2 consumed the region candidate unconditionally, which changed that
//        frame's guard constant and vlmax on QCG -- a route this checkpoint is not about, and one
//        no FP-only contrast can see. The row is an A/B in the FIRST range only (canonical vs
//        non-canonical `vsetvli`) with the SECOND range's frames required to be identical, so it
//        tests the invariance directly rather than a value that happens to look right. Its
//        positive control is the LLVM arm of the same A/B, where the candidate MUST come through.
//   [S10] W5C: THE SAME CAPABILITY AT FIVE WIDTHS. W5 moved the typed routes' width decision to
//        RvvRouteChunkShape, but the run scan's candidate/caps decision still asked
//        RvvSSAEnabled(), so at VLEN 128/256/2048 an unknown second range had a lowering for its
//        members and no proposal that would let them form a run. These rows drive the same
//        unknown-second-range fixture at 128/256/512/1024/2048, for FP-ALU, all-fused and mixed
//        runs, at e32/m1, e64/m1 and e32/m2, and assert the SAME properties [S1]-[S5] assert --
//        the candidate reaches the frame, the guard is still the full-VL/RNE one, the lane-op
//        count is the geometry's, and the ordered fallback is intact.
//   [S11] THE CANDIDATE'S SHAPE HAS TO BE EXPRESSIBLE, AND THAT IS WIDTH-DEPENDENT. An e32,m4
//        region candidate is four register groups: 4 x 1 = 4 chunks at VLEN 512 (within
//        `rvvrun::kMaxChunks`) and 4 x 4 = 16 at VLEN 2048 (past it). The same decoded `vsetvli`
//        is therefore proposable at one width and not at the other, and where it is not the scan
//        falls back to the canonical proposal rather than proposing a shape no member can admit.
//        Asserting BOTH sides of that at one candidate is what makes it a capacity row rather than
//        a restatement of [S10].
//   [S12] A WIDTH THE GEOMETRY REFUSES (384) still builds no frame in either range.
//   [S13] W5D: THE STANDALONE `.vv` FP-ALU FRAME, AND THE ORDER THAT KEEPS FAMILY A FIRST.
//        An ISOLATED `vfsub.vv` -- one FP instruction with no admitted neighbour, so no run can
//        form -- at each of the five widths. Where Family A admits (512/1024 at a shape its
//        `nregs * (VLEN/512) <= 4` row allows) the instruction must still take the RESIDENCY route
//        and build NO typed frame; where it does not (128/256/2048, and e32,m2 at 2048) it must
//        now build one, with the same guard kind, the geometry's chunk count and one ordered
//        fallback stub. Asserting BOTH sides is the point: a change that simply added a frame
//        everywhere would pass a one-sided check and would have replaced Family A's residency.
//   [S14] W5D: the standalone frame on an UNKNOWN range uses the shape-filtered candidate, and
//        falls back to the helper when there is no candidate to use.
//   [S16] W5E: THE SAME PROPOSAL FOR THE STANDALONE FUSED FRAME. An isolated `vfmacc.vv` at the
//        five widths, observed and unknown, plus the wrong-candidate and no-candidate rows and the
//        flags-off control. F4's arm is placed BEFORE Family A's fused arm by its own documented
//        decision, so unlike [S13] there is no "Family A keeps it" side here -- what must hold is
//        that an observed range is unchanged and an unknown one is now covered by the same frame.
//   [S17] W5E: Family A FP-ALU -> FMA frame -> Family A FP-ALU, with the commit between.
//   [S18] W5F: `vfsqrt.v`, the one-operand FP frame. Five widths, e32 and e64, observed and the
//        guarded candidate: one frame, `chunks` `vchunkfsqrt` nodes, the FULL-VL/RNE guard kind
//        (NOT the QCG `VTypePartialVlVstartFrmHost` its own emitter uses), `3n + 2` typed ops, one
//        ordered stub, and a `constrained.sqrt` per chunk in the emitted IR with the canonical-NaN
//        select after it.
//   [S19] W5F refusals, which are where the QCG/LLVM envelope difference is actually visible:
//        masked, the three other VFUNARY1 sub-opcodes (vfclass and the two 7-bit estimates), and
//        the switch off. Plus the QCG contrast: the same masked word that this backend refuses is
//        still admitted on the pure-QCG arm with ITS guard kind, so the envelope narrowed for one
//        backend only.
//   [S20] W5F: the state boundary and the legal `vd == vs2` overlap. A
//        Family-A-FMA/FMA-frame alternation does not exist: one switch
//        (`--rvv-qcg-typed-chunk-fma`) decides all eight fused funct6 at once and F4's arm runs
//        first, so the mixable neighbour is the FP-ALU residency route.
//   [S15] W5D: A MIXED FAMILY A / TYPED-FRAME SEQUENCE, and the commit boundary between them.
//        Family A leaves its result RESIDENT in the chunk-value cache; a typed frame is
//        state-backed. So a frame that follows a Family A instruction must be preceded by the
//        commit of that dirty group (`rvvwrite`), or it would read a stale CPUState word -- the
//        F4-FIX boundary, restated here for the arm W5D adds a caller to.
//   [S7] FLAG-OFF CONTROLS. With `--rvv-qcg-typed-chunk-falu` off, or `--rvv-vector-run` off, no
//        multi-member frame exists in either range.
//
// WHAT THIS FILE DOES NOT DO
//
//   * It never runs the code it builds. No object file is emitted and no PROT_EXEC page exists in
//     this process, so it needs no AVX-512 host and executes no vector instruction of any width.
//   * It asserts nothing about speed, and nothing here is a measurement.

#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <set>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

// `rv32` alone is ambiguous here (dbt::rv32 vs qir's own lookup once `using namespace dbt::qir`
// is in scope), so both namespaces are named once and used through these aliases.
namespace rvv32 = dbt::rv32;
namespace rvvrun = dbt::rv32::rvvrun;

unsigned g_fail = 0;

#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto va_ = (long long)(a);                                                         \
		auto vb_ = (long long)(b);                                                         \
		if (va_ != vb_) {                                                                  \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, va_, vb_);                                                      \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

llvm::LLVMContext g_llvm_ctx;

// ---------------------------------------------------------------------------------------------
// ENCODINGS, hand-built from the field layout rather than copied, so the fixture owns its input.
// V format, OP-V (opcode 0x57): funct6[31:26] vm[25] vs2[24:20] vs1[19:15] funct3[14:12] vd[11:7].
// ---------------------------------------------------------------------------------------------

constexpr u32 OpV(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) /*vm=1, unmasked*/ | (vs2 << 20) | (vs1 << 15) |
	       (0b001u << 12) /*OPFVV, the `.vv` form*/ | (vd << 7) | 0x57u;
}

// The INTEGER `.vv` form, OPIVV (funct3 000). Needed for [S8]: the six integer rows carry
// `requires_observed_vtype = false`, so a pure-QCG integer run ALREADY forms under an unobserved
// vtype, and the proposal this checkpoint changes is the RUN's, not the FP family's.
constexpr u32 OpIVV(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0b000u << 12) |
	       (vd << 7) | 0x57u;
}

// `vsetvli rd=x10, rs1=x10, zimm11`. Bit 31 clear is what makes it the CONSTANT form -- the same
// bit TranslateIPRange's ip-4 recovery tests.
constexpr u32 Vsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}

// `vsetvl rd=x10, rs1=x10, rs2=x11` -- the REGISTER form. vtype comes from x11 at run time, which
// is exactly why it must invalidate a translation-time candidate.
constexpr u32 kVsetvlReg = 0x80000000u | (11u << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;

constexpr u32 F6_VFADD = 0b000000u;
constexpr u32 F6_VFSUB = 0b000010u;
constexpr u32 F6_VFMUL = 0b100100u;

// The ODD-register triple, legal at LMUL=1 only. Shape copied from rvv_llvm_fp_run_test's fixture:
// member 2's `vd == vs2` is the legal overlap, member 3 is the NON-COMMUTATIVE subtract.
constexpr u32 kAddM1 = OpV(F6_VFADD, /*vs2=*/9, /*vs1=*/10, /*vd=*/8);
constexpr u32 kMulM1 = OpV(F6_VFMUL, /*vs2=*/8, /*vs1=*/11, /*vd=*/8);
constexpr u32 kSubM1 = OpV(F6_VFSUB, /*vs2=*/8, /*vs1=*/13, /*vd=*/12);

// The EVEN-register triple, legal at LMUL=1 and LMUL=2. `reg_group_legal` refuses an odd register
// at m2, so the LMUL rows need their own registers or they would be refused for a reason that has
// nothing to do with the candidate under test.
constexpr u32 kAddM2 = OpV(F6_VFADD, /*vs2=*/10, /*vs1=*/12, /*vd=*/8);
constexpr u32 kMulM2 = OpV(F6_VFMUL, /*vs2=*/8, /*vs1=*/14, /*vd=*/8);
constexpr u32 kSubM2 = OpV(F6_VFSUB, /*vs2=*/8, /*vs1=*/18, /*vd=*/16);

// The INTEGER pair for [S8]: two adjacent `vadd.vv`, the minimum a multi-member frame needs, the
// second consuming the first. BOTH are `vadd.vv` on purpose -- that row is the one the umbrella
// `--rvv-qcg-typed-chunk` switch (default on) opens, so the fixture needs no per-op switch that a
// future default change could silently close.
constexpr u32 F6_VADD = 0b000000u;
constexpr u32 kIAdd = OpIVV(F6_VADD, /*vs2=*/9, /*vs1=*/10, /*vd=*/8);
constexpr u32 kIAdd2 = OpIVV(F6_VADD, /*vs2=*/8, /*vs1=*/11, /*vd=*/12);

constexpr u32 kJalr = 0x00008067u;

// vtype words. 0xd0 is `rvv32::VTYPE_E32_M1_TA_MA`, the canonical candidate the unobserved scan has
// always proposed; the other three exist so "the candidate came from the region" is a DIFFERENCE.
constexpr u32 kVT_E32M1 = 0xd0u;
// e32, m1, TU, ma -- SEW 32 and LMUL 1 (which the integer typed-chunk route requires) but NOT the
// canonical word, so a leak of the region candidate into a QCG proposal is visible as a value.
constexpr u32 kVT_E32M1_TU = 0x90u;
constexpr u32 kVT_E32M2 = 0xd1u;
constexpr u32 kVT_E64M1 = 0xd8u;
constexpr u32 kVT_E64M2 = 0xd9u;

char const *VTName(u32 vt)
{
	switch (vt) {
	case kVT_E32M1: return "e32,m1";
	case kVT_E32M2: return "e32,m2";
	case kVT_E64M1: return "e64,m1";
	case kVT_E64M2: return "e64,m2";
	default: return "?";
	}
}

bool IsM2(u32 vt) { return vt == kVT_E32M2 || vt == kVT_E64M2; }

void ConfigureLLVM(u32 vlen, bool falu_on = true, bool run_on = true)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_vector_ssa = true;
	config::rvv_vector_run = run_on;
	config::rvv_qcg_typed_chunk_falu = falu_on;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_grouped_component_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_partial_vl = false;
}

// One multi-member typed frame, as the QIR carries it.
struct Frame {
	u32 vtype{};
	u32 vlmax{};
	unsigned n_members{};
	unsigned guard_kind{~0u};
};

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};

	explicit Built(std::vector<u32> w) : words(std::move(w)), module("fp_cand", g_llvm_ctx) {}
};

// Translate `b.words` as a region of `ranges` ip ranges through the REAL pipeline, collect every
// multi-member typed frame in block order, and (unless `run_backend` is false) lower it.
//
// `run_backend` is false only for the pure-QCG contrast: that path builds a frame whose guard kind
// this backend deliberately has no lowering for, so handing it to QIRToLLVM would abort the
// process -- which is the fail-closed behaviour, not a way to observe it.
std::vector<Frame> Build(Built &b, std::vector<std::pair<u32, u32>> const &ranges,
			 bool run_backend = true)
{
	CompilerJob::IpRangesSet rs;
	for (auto const &r : ranges)
		rs.push_back({r.first, r.second});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);
	std::vector<Frame> out;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_rvvtypedchunkbegin)
				continue;
			auto *begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
			if (begin->n_members < 2)
				continue;
			out.push_back(Frame{begin->vtype, begin->vlmax, begin->n_members,
					    (unsigned)begin->guard_kind});
		}
	}
	if (run_backend) {
		LLVMGenCtx ctx(&b.module);
		ctx.AddFunction(0u, b.segment);
		QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
		b.fn = gen.Run();
	}
	return out;
}

// The two-range fixture: [vsetvli, A, B, C] then [A, B, C, jalr]. The second range holds no
// `vsetvli`, so `rvv_bb_vtype` is ~0u throughout it -- that is the whole point.
std::vector<u32> TwoRangeWords(u32 vtype, bool insert_vsetvl_reg)
{
	bool const m2 = IsM2(vtype);
	u32 const a = m2 ? kAddM2 : kAddM1, m = m2 ? kMulM2 : kMulM1, s = m2 ? kSubM2 : kSubM1;
	std::vector<u32> w{Vsetvli(vtype), a, m, s};
	if (insert_vsetvl_reg)
		w.push_back(kVsetvlReg);
	w.insert(w.end(), {a, m, s, kJalr});
	return w;
}

std::vector<std::pair<u32, u32>> TwoRanges(std::vector<u32> const &w, u32 first_insns)
{
	u32 const cut = first_insns * 4u;
	return {{0u, cut}, {cut, (u32)(w.size() * 4u)}};
}

// Every integer constant this function compares for EQUALITY. The guard's vtype test is one of
// them, so "the canonical constant is not in this set" is a checkable statement about the emitted
// guard rather than about the QIR node alone.
std::set<u64> EqComparedConstants(llvm::Function *fn)
{
	std::set<u64> out;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *ic = llvm::dyn_cast<llvm::ICmpInst>(&ins);
			if (!ic || ic->getPredicate() != llvm::CmpInst::ICMP_EQ)
				continue;
			for (unsigned i = 0; i < 2; ++i)
				if (auto *c = llvm::dyn_cast<llvm::ConstantInt>(ic->getOperand(i)))
					out.insert(c->getZExtValue());
		}
	}
	return out;
}

bool IsHelperCall(llvm::Instruction &ins)
{
	auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
	return call && !llvm::isa<llvm::IntrinsicInst>(call);
}

unsigned CountConstrainedFP(llvm::BasicBlock *bb)
{
	unsigned n = 0;
	for (auto &ins : *bb)
		if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
			switch (ii->getIntrinsicID()) {
			case llvm::Intrinsic::experimental_constrained_fadd:
			case llvm::Intrinsic::experimental_constrained_fsub:
			case llvm::Intrinsic::experimental_constrained_fmul:
			case llvm::Intrinsic::experimental_constrained_fdiv:
			case llvm::Intrinsic::experimental_constrained_fma:
				++n;
				break;
			default:
				break;
			}
	return n;
}

// ---------------------------------------------------------------------------------------------
// [S1]+[S2]+[S5]. The unknown-entry frame, its candidate, its guard and its fallback.
// ---------------------------------------------------------------------------------------------
void CheckUnknownEntry(u32 vlen, u32 vtype)
{
	printf("[unknown-entry] VLEN=%u vtype=0x%02x (%s)\n", vlen, vtype, VTName(vtype));
	ConfigureLLVM(vlen);
	auto const words = TwoRangeWords(vtype, /*insert_vsetvl_reg=*/false);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4));

	// [S1] BOTH ranges build a three-member frame. Before R1 the second built none: its first
	// `vfadd.vv` cut the scan with CutReason::UnobservedVType and each instruction fell through
	// to `rv32_vfalu`.
	CHECK_EQ(frames.size(), 2u);
	if (frames.size() != 2)
		return;
	for (auto const &f : frames) {
		CHECK_EQ(f.n_members, 3u);
		// The guard kind is NOT relaxed for a candidate. An LLVM FP run takes the full-VL
		// kind whether or not its vtype was observed, because the body has no mask.
		CHECK_EQ(f.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
		    (InstRVVTypedChunkBegin::GuardKind)f.guard_kind));
	}

	// [S2] THE SECOND FRAME CARRIES THE REGION'S VTYPE, not the canonical proposal. At the three
	// non-canonical vtypes this is the assertion that separates R2 from "delete the refusal".
	CHECK_EQ(frames[0].vtype, vtype);
	CHECK_EQ(frames[1].vtype, vtype);
	CHECK_EQ(frames[1].vlmax, frames[0].vlmax);
	CHECK_EQ(frames[1].vlmax, rvv32::compute_vlmax(rvv32::VType{vtype}, vlen));

	CHECK(b.fn != nullptr);
	if (!b.fn)
		return;
	// NOTE: llvm::verifyFunction is NOT called here, and that is deliberate rather than an
	// omission. LLVMGenCtx builds the emitted function in its OWN llvm::LLVMContext, not the one
	// this fixture's `llvm::Module` was constructed with, so the verifier reports "Function
	// context does not match Module context" for every emitted function regardless of the IR. The
	// same reason rvv_llvm_fp_run_test reads the IR without verifying it.

	// [S2, emitted] The candidate reaches the EMITTED guard, and the canonical constant does not
	// appear anywhere the function compares for equality.
	auto const eqs = EqComparedConstants(b.fn);
	CHECK(eqs.count(vtype) == 1);
	if (vtype != kVT_E32M1)
		CHECK(eqs.count(kVT_E32M1) == 0);

	// [S5] THE GUARD IS THE UNCHANGED FULL-VL FP ONE, read off the emitted IR.
	//
	//   vl is compared with `eq` -- the partial kind would compare `ule`;
	//   vstart is compared against 0;
	//   the frm test is `fcsr & 0xe0 == 0`, i.e. an `and` by 0xe0 feeding an equality with 0.
	unsigned vl_ule = 0, and_e0 = 0;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			if (auto *ic = llvm::dyn_cast<llvm::ICmpInst>(&ins))
				if (ic->getPredicate() == llvm::CmpInst::ICMP_ULE)
					++vl_ule;
			if (ins.getOpcode() != llvm::Instruction::And)
				continue;
			auto *c = llvm::dyn_cast<llvm::ConstantInt>(ins.getOperand(1));
			if (c && c->getZExtValue() == 0xe0u)
				++and_e0;
		}
	}
	CHECK_EQ(vl_ule, 0u); // no `vl <= VLMAX` anywhere: both frames are full-VL
	CHECK_EQ(and_e0, 2u); // one frm-is-RNE test per frame
	CHECK(eqs.count(0u) == 1); // the vstart == 0 / frm == 0 comparisons

	// [S5] THE ARITHMETIC IS ALL OF IT, AND NONE OF IT IS A HELPER. Counted over the whole
	// function rather than over the `rvv.tchunk.direct` block alone: the emitter splits the fast
	// arm further (the FP bracket and the per-chunk bodies get their own blocks), so a per-block
	// count would be asserting the emitter's block layout instead of the property under test.
	//
	// `chunks` is the per-register host chunk count times the LMUL group width, which is the
	// frame's own geometry -- so an LMUL=2 candidate that was silently lowered as m1 fails here.
	unsigned const group_regs = IsM2(vtype) ? 2u : 1u;
	unsigned const chunks = group_regs * (vlen / 512u);
	unsigned total_fp = 0;
	unsigned fallback_helpers = 0, direct_helpers = 0, other_helper_blocks = 0;
	for (auto &bb : *b.fn) {
		total_fp += CountConstrainedFP(&bb);
		unsigned n = 0;
		for (auto &ins : bb)
			n += IsHelperCall(ins) ? 1 : 0;
		if (!n)
			continue;
		if (bb.getName().starts_with("rvv.tchunk.fallback")) {
			fallback_helpers += n;
		} else if (bb.getName().starts_with("rvv.tchunk.direct")) {
			direct_helpers += n;
		} else {
			// The only two remaining helper sites are NOT members of any frame and are
			// present with or without them: the guest `vsetvli` (its direct QCG route
			// refuses `aot_use_llvm`, so it takes `rv32_vsetvli`) and the region-exit
			// dispatch for the trailing `jalr`. The first is in a translator block (`bb.N`),
			// the second in the last frame's join block, which is where that guest block
			// continues. Every block a frame creates for its own body carries an `rvv.`
			// prefix other than `rvv.tchunk.done`, so a helper appearing in one of THOSE --
			// including a block the fast arm falls through to -- fails here.
			CHECK(bb.getName().starts_with("bb.") ||
			      bb.getName().starts_with("rvv.tchunk.done"));
			CHECK_EQ(CountConstrainedFP(&bb), 0u);
			++other_helper_blocks;
		}
	}
	// [S5] THE GUARD-MISS PATH PAYS NO FP BRACKET, and this is asserted rather than assumed
	// because it is the one part of the miss cost that is NOT obvious: `Emit_rvvtypedchunkbegin`
	// emits its conditional branch and only then sets the insert point to the fast arm, so the
	// MXCSR save / rounding-mode install / flags fold all sit inside the taken arm. A miss still
	// costs the guard's own CPUState loads and compares, the frame-boundary state commit that
	// RvvEmitTypedFaluChunkGroup performs before the guard, and then the same per-member helper
	// calls -- but not a bracket.
	unsigned mxcsr_in_fallback = 0, mxcsr_total = 0;
	for (auto &bb : *b.fn) {
		unsigned n = 0;
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::x86_sse_stmxcsr ||
				    ii->getIntrinsicID() == llvm::Intrinsic::x86_sse_ldmxcsr)
					++n;
		mxcsr_total += n;
		if (bb.getName().starts_with("rvv.tchunk.fallback"))
			mxcsr_in_fallback += n;
	}
	CHECK(mxcsr_total > 0); // the fast arms do have a bracket, so the zero below is not vacuous
	CHECK_EQ(mxcsr_in_fallback, 0u);

	// Three members, two frames, `chunks` host operations each.
	CHECK_EQ(total_fp, 6u * chunks);
	// The ordered replay, and nothing else: six helper calls across the two fallback arms and
	// none at all in either fast arm.
	CHECK_EQ(fallback_helpers, 6u);
	CHECK_EQ(direct_helpers, 0u);
	CHECK_EQ(other_helper_blocks, 2u);

	unsigned fast_blocks = 0, slow_blocks = 0;
	for (auto &bb : *b.fn) {
		if (bb.getName().starts_with("rvv.tchunk.direct"))
			++fast_blocks;
		if (bb.getName().starts_with("rvv.tchunk.fallback")) {
			++slow_blocks;
			// Three helper calls, in guest order, each preceded by a store of its own
			// guest PC. The PCs are read off the stores and must increase by 4.
			std::vector<u64> pcs;
			unsigned helpers = 0;
			u64 last_pc = ~0ull;
			for (auto &ins : bb) {
				if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
					if (auto *c = llvm::dyn_cast<llvm::ConstantInt>(
						st->getValueOperand()))
						last_pc = c->getZExtValue();
				if (!IsHelperCall(ins))
					continue;
				++helpers;
				pcs.push_back(last_pc);
			}
			CHECK_EQ(helpers, 3u);
			CHECK_EQ(CountConstrainedFP(&bb), 0u);
			CHECK_EQ(pcs.size(), 3u);
			if (pcs.size() == 3) {
				CHECK_EQ(pcs[1], pcs[0] + 4);
				CHECK_EQ(pcs[2], pcs[1] + 4);
			}
		}
	}
	CHECK_EQ(fast_blocks, 2u);
	CHECK_EQ(slow_blocks, 2u);
	printf("    ok  2 frames, vtype=0x%02x vlmax=%u, %u chunks/member, guard+fallback intact\n",
	       frames[1].vtype, frames[1].vlmax, chunks);
}

// ---------------------------------------------------------------------------------------------
// [S3] NO CONSTANT `vsetvl` ANYWHERE -> the canonical rule, unchanged.
// ---------------------------------------------------------------------------------------------
void CheckNoCandidate(u32 vlen)
{
	printf("[no-candidate] VLEN=%u\n", vlen);
	ConfigureLLVM(vlen);
	std::vector<u32> const words{kAddM1, kMulM1, kSubM1, kAddM1, kMulM1, kSubM1, kJalr};
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 3));
	CHECK_EQ(frames.size(), 2u);
	for (auto const &f : frames) {
		CHECK_EQ(f.n_members, 3u);
		// The pre-R2 proposal, and it must still be exactly this one.
		CHECK_EQ(f.vtype, (u32)rvv32::VTYPE_E32_M1_TA_MA);
		CHECK_EQ(f.vtype, kVT_E32M1);
	}
	printf("    ok  canonical VTYPE_E32_M1_TA_MA proposed in both ranges\n");
}

// ---------------------------------------------------------------------------------------------
// [S4] THE REGISTER-FORM `vsetvl` DROPS THE CANDIDATE.
// ---------------------------------------------------------------------------------------------
void CheckRegisterVsetvlInvalidates(u32 vlen)
{
	printf("[vsetvl-invalidates] VLEN=%u\n", vlen);
	ConfigureLLVM(vlen);
	// [vsetvli e64,m2, A, M, S] | [vsetvl(reg), A, M, S, jalr]
	auto const words = TwoRangeWords(kVT_E64M2, /*insert_vsetvl_reg=*/true);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4));
	CHECK_EQ(frames.size(), 2u);
	if (frames.size() != 2)
		return;
	// The observed range keeps the guest's own vtype ...
	CHECK_EQ(frames[0].vtype, kVT_E64M2);
	// ... and the range after the register-form write falls back to the canonical proposal. If
	// the invalidation were removed this would read 0xd9, so the row is a difference.
	CHECK_EQ(frames[1].vtype, (u32)rvv32::VTYPE_E32_M1_TA_MA);
	printf("    ok  candidate dropped: 0x%02x then 0x%02x\n", frames[0].vtype, frames[1].vtype);
}

// ---------------------------------------------------------------------------------------------
// [S6] THE PURE-QCG BACKEND IS UNCHANGED.
// ---------------------------------------------------------------------------------------------
void CheckQcgUnchanged(u32 vlen)
{
	printf("[qcg-unchanged] VLEN=%u\n", vlen);
	ConfigureLLVM(vlen);
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false; // QCG side-exit substrate, not the LLVM lowering gate
	// The QCG predicate probes the COMPILING host for AVX-512F/BMI2; this test must build the
	// same QIR on any host. Nothing is emitted or executed.
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	auto const words = TwoRangeWords(kVT_E32M1, /*insert_vsetvl_reg=*/false);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4), /*run_backend=*/false);
	config::rvv_qcg_typed_chunk_falu_force_emit = false;

	// EXACTLY ONE multi-member frame -- the OBSERVED range's. The unobserved range still refuses,
	// because `RunBackendCaps::fp_candidate_vtype_ok` is false without RvvSSAEnabled(). A
	// vacuous version of this check is excluded by asserting the observed frame exists and has
	// the QCG guard kind.
	CHECK_EQ(frames.size(), 1u);
	if (frames.size() != 1)
		return;
	CHECK_EQ(frames[0].n_members, 3u);
	CHECK_EQ(frames[0].vtype, kVT_E32M1);
	CHECK_EQ(frames[0].guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmRNE);

	// And the scan says so in its own words, through the route-table entry point the translator
	// uses. `~0u` is what an unobserved block hands it.
	rvvrun::RunLimits limits;
	auto const d = dbt::qir::rv32::RV32Translator::RvvAdmitVectorRun(
	    (uptr)words.data(), /*entry_pc=*/4u * 5u, /*boundary_pc=*/(u32)(words.size() * 4u),
	    /*insn_budget=*/8u, /*observed_vtype=*/~0u, limits);
	CHECK_EQ((unsigned)d.n_members, 0u);
	CHECK_EQ((int)d.cut, (int)rvvrun::CutReason::UnobservedVType);
	printf("    ok  1 frame (observed range only), unobserved range cut: %s\n",
	       rvvrun::CutReasonName(d.cut));
}

// ---------------------------------------------------------------------------------------------
// [S7] FLAG-OFF CONTROLS. Without these, every row above would still pass with the gate stuck on.
// ---------------------------------------------------------------------------------------------
void CheckFlagOff(u32 vlen, bool falu_on, bool run_on, char const *name)
{
	printf("[flag-off] VLEN=%u %s\n", vlen, name);
	ConfigureLLVM(vlen, falu_on, run_on);
	auto const words = TwoRangeWords(kVT_E32M1, /*insert_vsetvl_reg=*/false);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4));
	CHECK_EQ(frames.size(), 0u);
	printf("    ok  no multi-member FP frame in either range\n");
}

// ---------------------------------------------------------------------------------------------
// [S8] THE QCG INTEGER RUN DOES NOT SEE THE REGION CANDIDATE, and the LLVM one does.
// ---------------------------------------------------------------------------------------------

// The integer two-range fixture: [vsetvli(vt), vadd.vv, vand.vv] then [vadd.vv, vand.vv, jalr].
std::vector<u32> IntTwoRangeWords(u32 vtype)
{
	return {Vsetvli(vtype), kIAdd, kIAdd2, kIAdd, kIAdd2, kJalr};
}

// Every multi-member frame of a build, so two builds can be compared field by field.
std::vector<Frame> IntFrames(u32 vlen, u32 vtype, bool llvm_backend)
{
	ConfigureLLVM(vlen);
	if (!llvm_backend) {
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = false;
		// The QCG integer emitter writes a literal EVEX `vpaddd`, so its predicate probes the
		// COMPILING host for AVX-512F. This test must build the same QIR on any host, and
		// nothing is emitted or executed.
		config::rvv_qcg_typed_chunk_force_emit = true;
	}
	auto const words = IntTwoRangeWords(vtype);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 3), /*run_backend=*/llvm_backend);
	config::rvv_qcg_typed_chunk_force_emit = false;
	return frames;
}

void CheckQcgIntegerInvariance(u32 vlen)
{
	printf("[qcg-integer-invariance] VLEN=%u\n", vlen);
	auto const canon = IntFrames(vlen, kVT_E32M1, /*llvm_backend=*/false);
	auto const noncanon = IntFrames(vlen, kVT_E32M1_TU, /*llvm_backend=*/false);

	// The fixture has to actually build two frames per arm, or the invariance below is vacuous.
	CHECK_EQ(canon.size(), 2u);
	CHECK_EQ(noncanon.size(), 2u);
	if (canon.size() != 2 || noncanon.size() != 2)
		return;

	// The OBSERVED range differs, which is what proves the non-canonical vtype really reached the
	// translator and really is a shape this route admits. Without this the row below could pass
	// because the second arm built nothing interesting.
	CHECK_EQ(canon[0].vtype, kVT_E32M1);
	CHECK_EQ(noncanon[0].vtype, kVT_E32M1_TU);
	CHECK(canon[0].vtype != noncanon[0].vtype);

	// THE ROW. The UNOBSERVED range must be identical between the two arms, field for field: the
	// only difference between the inputs is a vtype word in a DIFFERENT ip range, and a pure-QCG
	// proposal must not be able to see it.
	CHECK_EQ(noncanon[1].vtype, canon[1].vtype);
	CHECK_EQ(noncanon[1].vlmax, canon[1].vlmax);
	CHECK_EQ(noncanon[1].n_members, canon[1].n_members);
	CHECK_EQ(noncanon[1].guard_kind, canon[1].guard_kind);
	// And the value it keeps is the pre-R2 canonical proposal, named rather than inferred.
	CHECK_EQ(canon[1].vtype, (u32)rvv32::VTYPE_E32_M1_TA_MA);

	// POSITIVE CONTROL. The same A/B on the LLVM substrate, where the candidate is exactly what
	// R2 exists to deliver. If this did not differ, the QCG row above would be asserting that a
	// mechanism nobody built is absent.
	auto const lcanon = IntFrames(vlen, kVT_E32M1, /*llvm_backend=*/true);
	auto const lnoncanon = IntFrames(vlen, kVT_E32M1_TU, /*llvm_backend=*/true);
	CHECK_EQ(lcanon.size(), 2u);
	CHECK_EQ(lnoncanon.size(), 2u);
	if (lcanon.size() != 2 || lnoncanon.size() != 2)
		return;
	CHECK_EQ(lcanon[1].vtype, kVT_E32M1);
	CHECK_EQ(lnoncanon[1].vtype, kVT_E32M1_TU);
	printf("    ok  QCG second range 0x%02x in both arms; LLVM second range 0x%02x vs 0x%02x\n",
	       canon[1].vtype, lcanon[1].vtype, lnoncanon[1].vtype);
}

// ---------------------------------------------------------------------------------------------
// [S9] THE FUSED FAMILY IN AN UNKNOWN SECOND RANGE.
// ---------------------------------------------------------------------------------------------

constexpr u32 F6_VFMADD = 0b101000u;
constexpr u32 F6_VFMACC = 0b101100u;

// ONE REGISTER PLAN FOR BOTH VTYPES: every vector register here is EVEN, so the same three words
// are legal at LMUL=1 and at LMUL=2 and the e64/m2 row is not refused by `reg_group_legal` for a
// reason that has nothing to do with the candidate.
//
// All-fused: v8 is the accumulator every member reads AND writes (`reads_vd`), which is the
// property that distinguishes this family from the FP-ALU one.
constexpr u32 kFmacc1 = OpV(F6_VFMACC, /*vs2=*/10, /*vs1=*/12, /*vd=*/8);
constexpr u32 kFmacc2 = OpV(F6_VFMACC, /*vs2=*/14, /*vs1=*/16, /*vd=*/8);
constexpr u32 kFmadd3 = OpV(F6_VFMADD, /*vs2=*/10, /*vs1=*/18, /*vd=*/8);
// Mixed: FP-ALU, then a fused member, then the NON-COMMUTATIVE subtract, all in one frame.
constexpr u32 kMixAdd = OpV(F6_VFADD, /*vs2=*/10, /*vs1=*/12, /*vd=*/8);
constexpr u32 kMixAcc = OpV(F6_VFMACC, /*vs2=*/14, /*vs1=*/16, /*vd=*/8);
constexpr u32 kMixSub = OpV(F6_VFSUB, /*vs2=*/8, /*vs1=*/10, /*vd=*/18);

enum class Fused { FmaOnly, AluFma };
char const *FusedName(Fused f) { return f == Fused::FmaOnly ? "fma-only" : "alu+fma"; }

std::vector<u32> FusedTwoRangeWords(u32 vtype, Fused kind)
{
	u32 const a = kind == Fused::FmaOnly ? kFmacc1 : kMixAdd;
	u32 const b = kind == Fused::FmaOnly ? kFmacc2 : kMixAcc;
	u32 const c = kind == Fused::FmaOnly ? kFmadd3 : kMixSub;
	return {Vsetvli(vtype), a, b, c, a, b, c, kJalr};
}

void CheckUnknownEntryFused(u32 vlen, u32 vtype, Fused kind)
{
	printf("[unknown-entry-fused] VLEN=%u vtype=0x%02x (%s) %s\n", vlen, vtype, VTName(vtype),
	       FusedName(kind));
	ConfigureLLVM(vlen);
	// The fused route's OWN switch. ConfigureLLVM holds it off so every FP-ALU row above runs with
	// the fused family unavailable; this row is the one that turns it on.
	config::rvv_qcg_typed_chunk_fma = true;
	auto const words = FusedTwoRangeWords(vtype, kind);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4));
	config::rvv_qcg_typed_chunk_fma = false;

	// Both ranges form a three-member frame; the second one had no `vsetvli`.
	CHECK_EQ(frames.size(), 2u);
	if (frames.size() != 2)
		return;
	for (auto const &f : frames) {
		CHECK_EQ(f.n_members, 3u);
		// THE UNCHANGED FULL-VL / RNE GUARD KIND. A fused member does not relax it.
		CHECK_EQ(f.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
		    (InstRVVTypedChunkBegin::GuardKind)f.guard_kind));
	}
	// THE CANDIDATE CONSTANT, on the range that observed nothing.
	CHECK_EQ(frames[0].vtype, vtype);
	CHECK_EQ(frames[1].vtype, vtype);
	CHECK_EQ(frames[1].vlmax, rvv32::compute_vlmax(rvv32::VType{vtype}, vlen));

	CHECK(b.fn != nullptr);
	if (!b.fn)
		return;
	auto const eqs = EqComparedConstants(b.fn);
	CHECK(eqs.count(vtype) == 1);
	if (vtype != kVT_E32M1)
		CHECK(eqs.count(kVT_E32M1) == 0);

	// vl is compared with `eq`, never `ule`; one `fcsr & 0xe0` RNE test per frame.
	unsigned vl_ule = 0, and_e0 = 0;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			if (auto *ic = llvm::dyn_cast<llvm::ICmpInst>(&ins))
				if (ic->getPredicate() == llvm::CmpInst::ICMP_ULE)
					++vl_ule;
			if (ins.getOpcode() != llvm::Instruction::And)
				continue;
			auto *c = llvm::dyn_cast<llvm::ConstantInt>(ins.getOperand(1));
			if (c && c->getZExtValue() == 0xe0u)
				++and_e0;
		}
	}
	CHECK_EQ(vl_ule, 0u);
	CHECK_EQ(and_e0, 2u);

	unsigned const group_regs = IsM2(vtype) ? 2u : 1u;
	unsigned const chunks = group_regs * (vlen / 512u);
	unsigned total_fp = 0, fused_calls = 0, slow_blocks = 0;
	for (auto &bb : *b.fn) {
		total_fp += CountConstrainedFP(&bb);
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() ==
				    llvm::Intrinsic::experimental_constrained_fma)
					++fused_calls;
		if (!bb.getName().starts_with("rvv.tchunk.fallback"))
			continue;
		++slow_blocks;
		// ORDERED HELPER FALLBACK, and NO FP ARITHMETIC ON THE COLD ARM. The second is the row
		// that would catch a body accidentally emitted outside the guard: a fused lane op in
		// the fallback block would be arithmetic the guard did not authorise.
		std::vector<u64> pcs;
		unsigned helpers = 0, mxcsr = 0;
		u64 last_pc = ~0ull;
		for (auto &ins : bb) {
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
				if (auto *c =
					llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand()))
					last_pc = c->getZExtValue();
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::x86_sse_stmxcsr ||
				    ii->getIntrinsicID() == llvm::Intrinsic::x86_sse_ldmxcsr)
					++mxcsr;
			if (!IsHelperCall(ins))
				continue;
			++helpers;
			pcs.push_back(last_pc);
		}
		CHECK_EQ(helpers, 3u);
		CHECK_EQ(CountConstrainedFP(&bb), 0u); // no cold-arm FP arithmetic
		CHECK_EQ(mxcsr, 0u);		       // and no bracket on the miss path
		CHECK_EQ(pcs.size(), 3u);
		if (pcs.size() == 3) {
			CHECK_EQ(pcs[1], pcs[0] + 4);
			CHECK_EQ(pcs[2], pcs[1] + 4);
		}
	}
	CHECK_EQ(slow_blocks, 2u);
	// Three members, two frames, `chunks` host operations each.
	CHECK_EQ(total_fp, 6u * chunks);
	// And the fused members really are fused: one `constrained.fma` per fused member per chunk,
	// never a separate multiply and add. Three fused members per frame in the all-fused fixture,
	// one in the mixed one.
	unsigned const fused_members = kind == Fused::FmaOnly ? 3u : 1u;
	CHECK_EQ(fused_calls, 2u * fused_members * chunks);
	printf("    ok  2 frames, vtype=0x%02x, %u chunks/member, %u constrained.fma\n",
	       frames[1].vtype, chunks, fused_calls);
}

// [S9] FLAG-OFF CONTROL, the fused counterpart of [S7]. `--rvv-qcg-typed-chunk-fma` is the fused
// route's OWN switch (RvvLLVMFmaChunkAdmit reads it alone, not the umbrella), and with it off the
// all-fused fixture must build no multi-member frame in EITHER range -- including the observed one.
// Without this row every assertion above would still pass if the route were stuck open.
void CheckFusedFlagOff(u32 vlen)
{
	printf("[flag-off-fused] VLEN=%u --rvv-qcg-typed-chunk-fma off\n", vlen);
	ConfigureLLVM(vlen);
	config::rvv_qcg_typed_chunk_fma = false;
	auto const words = FusedTwoRangeWords(kVT_E32M1, Fused::FmaOnly);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4));
	CHECK_EQ(frames.size(), 0u);
	printf("    ok  no multi-member fused frame in either range\n");
}

// ---------------------------------------------------------------------------------------------
// [S10]-[S12] W5C: the guarded run candidate at five widths.
// ---------------------------------------------------------------------------------------------

// The five widths this follow-up is about. 4096 is deliberately absent: a three-group run there is
// 3 x 8 = 24 chunk registers, which fits, but the checkpoint's scope is the five widths W5 admits.
constexpr u32 FIVE_WIDTHS[] = {128u, 256u, 512u, 1024u, 2048u};

// The geometry, recomputed from VLEN rather than copied, as in the five-width geometry test.
u32 ChunksPerGroup(u32 vlen, u32 sew_bytes)
{
	u32 const reg_bytes = vlen / 8u;
	u32 const w = reg_bytes < 64u ? reg_bytes : 64u;
	if ((w != 16u && w != 32u && w != 64u) || w % sew_bytes != 0 || reg_bytes % w != 0)
		return 0;
	return reg_bytes / w;
}

enum class FpKind { Alu, FmaOnly, Mixed };
char const *FpKindName(FpKind k)
{
	return k == FpKind::Alu ? "fp-alu" : k == FpKind::FmaOnly ? "fma-only" : "alu+fma";
}

// THREE REGISTER GROUPS, ALL EVEN. Even so the LMUL=2 rows are legal groups; three so the run's
// peak live chunk count is 3 * chunks, which is 24 at the widest width here and inside
// `rvvrun::kHostVectorRegs` (30). A width failure in these rows is then a width failure and not a
// register-pressure one -- the pressure bound has its own row in the geometry test.
std::vector<u32> FiveWidthWords(u32 vtype, FpKind kind)
{
	u32 a, m, c;
	switch (kind) {
	case FpKind::Alu:
		a = OpV(F6_VFADD, 10, 12, 8);
		m = OpV(F6_VFMUL, 8, 10, 8);
		c = OpV(F6_VFSUB, 8, 12, 8);
		break;
	case FpKind::FmaOnly:
		a = OpV(F6_VFMACC, 10, 12, 8);
		m = OpV(F6_VFMACC, 12, 10, 8);
		c = OpV(F6_VFMACC, 10, 12, 8);
		break;
	default:
		a = OpV(F6_VFADD, 10, 12, 8);
		m = OpV(F6_VFMACC, 10, 12, 8);
		c = OpV(F6_VFSUB, 8, 12, 8);
		break;
	}
	return {Vsetvli(vtype), a, m, c, a, m, c, kJalr};
}

struct Body {
	unsigned lane_ops = 0;	 // vchunkfalu + vchunkfma
	unsigned stubs = 0;	 // ordered fallback members declared by the end nodes
};

Body ScanBody(Region *region)
{
	Body b;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto const op = ins.GetOpcode();
			if (op == Op::_vchunkfalu || op == Op::_vchunkfma)
				++b.lane_ops;
			if (op == Op::_rvvtypedchunkend)
				b.stubs += static_cast<InstRVVTypedChunkEnd *>(&ins)->n_members;
		}
	}
	return b;
}

void CheckFiveWidthCandidate(u32 vlen, u32 vtype, FpKind kind)
{
	u32 const sew = (vtype == kVT_E64M1 || vtype == kVT_E64M2) ? 8u : 4u;
	u32 const groups = IsM2(vtype) ? 2u : 1u;
	u32 const chunks = groups * ChunksPerGroup(vlen, sew);
	printf("[S10] VLEN=%u vtype=0x%02x (%s) %s\n", vlen, vtype, VTName(vtype), FpKindName(kind));
	ConfigureLLVM(vlen);
	config::rvv_qcg_typed_chunk_fma = true; // the fused route's own switch; the ALU rows ignore it
	auto const words = FiveWidthWords(vtype, kind);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4));
	config::rvv_qcg_typed_chunk_fma = false;

	// Both ranges form a frame; the second one contains no `vsetvli`.
	CHECK_EQ(frames.size(), 2u);
	if (frames.size() != 2)
		return;
	for (auto const &f : frames) {
		CHECK_EQ(f.n_members, 3u);
		// The guard does not weaken with width, vtype or member family.
		CHECK_EQ(f.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
		    (InstRVVTypedChunkBegin::GuardKind)f.guard_kind));
	}
	// THE CANDIDATE REACHED THE UNOBSERVED RANGE'S FRAME, with the vlmax that vtype implies here.
	CHECK_EQ(frames[0].vtype, vtype);
	CHECK_EQ(frames[1].vtype, vtype);
	CHECK_EQ(frames[1].vlmax, rvv32::compute_vlmax(rvv32::VType{vtype}, vlen));
	// The body is the geometry's: three members per frame, `chunks` lane ops each.
	auto const body = ScanBody(b.region);
	CHECK(chunks != 0);
	CHECK_EQ(body.lane_ops, 6u * chunks);
	// Ordered fallback: three members replayed per frame.
	CHECK_EQ(body.stubs, 6u);
	CHECK(b.fn != nullptr);
	if (b.fn) {
		auto const eqs = EqComparedConstants(b.fn);
		CHECK(eqs.count(vtype) == 1);
		if (vtype != kVT_E32M1)
			CHECK(eqs.count(kVT_E32M1) == 0);
	}
	printf("    ok  2 frames, vtype=0x%02x vlmax=%u, %u lane ops/member\n", frames[1].vtype,
	       frames[1].vlmax, chunks);
}

// [S10b] LMUL=2 AT EVERY WIDTH, AND THE PEAK-LIVE BOUND THAT ENDS IT.
//
// A member's chunk count is `groups * chunks_per_group`, so an LMUL=2 member is EIGHT chunks at
// VLEN 2048 -- and a three-group run of them is 24 chunk values before the body's own scratch. That
// is past what `rvvrun::kHostVectorRegs` (30) allows, and the scan cuts the run with
// CutReason::RegisterPressure. It is the SAME bound that has always been there; what W5 changed is
// that a width can now reach it.
//
// THE ROW ASSERTS BOTH SIDES, because "no run at 2048" is only acceptable if coverage does not
// vanish with it:
//
//   * where the run fits, the candidate reaches the unobserved range's frame exactly as at LMUL 1;
//   * where it does not, the run is cut AND the fused members keep their single-instruction frames
//     (F4's standalone `.vv` route), so the instructions are still lowered natively;
//   * the FP-ALU `.vv` members do NOT, and that is a stated limitation rather than a defect: their
//     single-instruction path is Family A, which this checkpoint deliberately does not widen, so at
//     128/256/2048 a `.vv` FP-ALU instruction outside a run takes the helper.
void CheckLmul2Capacity(u32 vlen, unsigned *formed_at_512)
{
	printf("[S10b] VLEN=%u e32,m2: run where the pool allows, single frames where it does not\n",
	       vlen);
	u32 const per_member = 2u * ChunksPerGroup(vlen, 4u);
	for (auto kind : {FpKind::FmaOnly, FpKind::Alu}) {
		ConfigureLLVM(vlen);
		config::rvv_qcg_typed_chunk_fma = true;
		auto const words = FiveWidthWords(kVT_E32M2, kind);
		Built b(words);
		auto const frames = Build(b, TwoRanges(words, 4), /*run_backend=*/false);
		config::rvv_qcg_typed_chunk_fma = false;
		unsigned singles = 0;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_rvvtypedchunkbegin &&
				    static_cast<InstRVVTypedChunkBegin *>(&ins)->n_members == 1)
					++singles;
		// THE ASSERTION IS TWO-SIDED AND DOES NOT PREDICT THE CUT. Reproducing
		// RvvRunPeakLiveBound's arithmetic here would make this row a copy of the model rather
		// than a check on it -- and a wrong copy at that: a first draft used
		// `3 * per_member <= kHostVectorRegs` and was too loose, because the bound also carries
		// the body's scratch headroom. So the row states what must be true EITHER WAY.
		if (frames.size() == 2) {
			// A run formed: the candidate reached the unobserved range with this LMUL.
			CHECK_EQ(frames[1].vtype, kVT_E32M2);
			CHECK_EQ(frames[1].vlmax,
				 rvv32::compute_vlmax(rvv32::VType{kVT_E32M2}, vlen));
			CHECK_EQ(frames[1].n_members, 3u);
			if (vlen == 512u)
				++*formed_at_512;
			printf("    ok  %-8s %u chunks/member: run formed, candidate 0x%02x\n",
			       FpKindName(kind), per_member, frames[1].vtype);
		} else {
			// The run was cut in BOTH ranges, and BOTH families now keep a single-instruction
			// frame in each -- six, three per range. The count is asserted rather than "some
			// frames exist" because it is the history of this boundary:
			//
			//   * before W5D: zero for FP-ALU (Family A refuses e32,m2 at VLEN 2048 and there
			//     was no other `.vv` route) and three for fused (the observed range only, via
			//     F4's standalone frame, which required an OBSERVED vtype);
			//   * W5D gave FP-ALU the standalone `.vv` frame on an observed vtype OR the
			//     shape-filtered region candidate -> six;
			//   * W5E (2026-09-17) gave the fused arm the same proposal, through the same
			//     `RvvStandaloneFrameVType()` -> six. The 3-vs-6 asymmetry W5D recorded as a
			//     limitation is closed, and this line is where that is checked.
			CHECK_EQ(frames.size(), 0u);
			CHECK_EQ(singles, 6u);
			printf("    ok  %-8s %u chunks/member: run cut, %u single-member frame(s)\n",
			       FpKindName(kind), per_member, singles);
		}
	}
}

// [S11] e32,m4: expressible at VLEN 512 (4 chunks), not at VLEN 2048 (16, past kMaxChunks).
constexpr u32 kVT_E32M4 = 0xd2u;

void CheckCandidateCapacity()
{
	printf("[S11] e32,m4 candidate: expressible at 512, not at 2048\n");
	// LMUL=4 groups must be 4-aligned.
	u32 const a = OpV(F6_VFADD, 12, 16, 8);
	u32 const m = OpV(F6_VFMUL, 8, 12, 8);
	u32 const c = OpV(F6_VFSUB, 8, 16, 8);
	std::vector<u32> const words{Vsetvli(kVT_E32M4), a, m, c, a, m, c, kJalr};
	for (u32 vlen : {512u, 2048u}) {
		u32 const total = 4u * ChunksPerGroup(vlen, 4u);
		bool const fits = total <= rvv32::rvvrun::kMaxChunks;
		ConfigureLLVM(vlen);
		Built b(words);
		auto const frames = Build(b, TwoRanges(words, 4), /*run_backend=*/false);
		if (frames.size() < 2) {
			// At a width where the members themselves cannot be admitted there is no frame to
			// read; the row below is about the PROPOSAL, so say so rather than assert nothing.
			printf("    vlen=%-5u total=%u fits=%d -> %zu frame(s)\n", vlen, total,
			       (int)fits, frames.size());
			continue;
		}
		// The observed range carries the guest's own vtype either way.
		CHECK_EQ(frames[0].vtype, kVT_E32M4);
		// The UNOBSERVED range: the candidate where it is expressible, the canonical proposal
		// where it is not. Without the shape filter the second width would propose 0xd2 and the
		// members would refuse it, leaving no frame at all.
		CHECK_EQ(frames[1].vtype, fits ? kVT_E32M4 : (u32)rvv32::VTYPE_E32_M1_TA_MA);
		printf("    ok  vlen=%-5u total=%u -> second range proposes 0x%02x\n", vlen, total,
		       frames[1].vtype);
	}
}

// [S12] a width with no chunk shape at all.
void CheckCandidateRefusedWidth()
{
	printf("[S12] VLEN 384 has no host chunk shape: no frame in either range\n");
	ConfigureLLVM(384u);
	auto const words = FiveWidthWords(kVT_E32M1, FpKind::Alu);
	Built b(words);
	auto const frames = Build(b, TwoRanges(words, 4), /*run_backend=*/false);
	CHECK_EQ(frames.size(), 0u);
	printf("    ok  no multi-member frame\n");
}

// [S4]/[S7]/[S8] at the three widths those sections did not previously reach.
void CheckWidthExtras(u32 vlen)
{
	// Invalidation: a register-form `vsetvl` drops the candidate, at every width.
	{
		printf("[S4@%u] register-form vsetvl invalidates\n", vlen);
		ConfigureLLVM(vlen);
		// e64,m1 rather than the e64,m2 the 512/1024 row uses: this row is about the register-form
		// `vsetvl` dropping the candidate, and a two-register group would additionally hit the
		// peak-live bound at the widest width (see CheckLmul2Capacity), which would make a failure
		// here ambiguous between the two.
		auto const words = TwoRangeWords(kVT_E64M1, /*insert_vsetvl_reg=*/true);
		Built b(words);
		auto const frames = Build(b, TwoRanges(words, 4));
		CHECK_EQ(frames.size(), 2u);
		if (frames.size() == 2) {
			CHECK_EQ(frames[0].vtype, kVT_E64M1);
			CHECK_EQ(frames[1].vtype, (u32)rvv32::VTYPE_E32_M1_TA_MA);
		}
		printf("    ok  candidate dropped\n");
	}
	// Flags off: neither switch may leave a multi-member frame behind, at any width.
	for (int row = 0; row < 2; ++row) {
		bool const falu_on = row == 1, run_on = row == 0;
		printf("[S7@%u] %s off\n", vlen, row == 0 ? "--rvv-qcg-typed-chunk-falu" : "--rvv-vector-run");
		ConfigureLLVM(vlen, falu_on, run_on);
		auto const words = FiveWidthWords(kVT_E32M1, FpKind::Alu);
		Built b(words);
		CHECK_EQ(Build(b, TwoRanges(words, 4)).size(), 0u);
		printf("    ok  no multi-member frame in either range\n");
	}
	// QCG invariance: a non-canonical vsetvli in the FIRST range must not reach the pure-QCG
	// integer run in the second, at any width.
	{
		printf("[S8@%u] QCG integer run invariant to the region candidate\n", vlen);
		auto const canon = IntFrames(vlen, kVT_E32M1, /*llvm_backend=*/false);
		auto const noncanon = IntFrames(vlen, kVT_E32M1_TU, /*llvm_backend=*/false);
		CHECK_EQ(canon.size(), noncanon.size());
		if (canon.size() == 2 && noncanon.size() == 2) {
			CHECK_EQ(noncanon[1].vtype, canon[1].vtype);
			CHECK_EQ(noncanon[1].vlmax, canon[1].vlmax);
			CHECK_EQ(canon[1].vtype, (u32)rvv32::VTYPE_E32_M1_TA_MA);
			// And the observed range still differs, so the row is not vacuous.
			CHECK(canon[0].vtype != noncanon[0].vtype);
			printf("    ok  second range 0x%02x in both arms\n", canon[1].vtype);
		} else {
			// Below VLEN 512 the pure-QCG integer route has no shape at all
			// (RvvGenericChunkShapeAdmit), so there is no frame to be invariant about --
			// which is itself the QCG-unchanged statement at those widths.
			CHECK_EQ(canon.size(), 0u);
			CHECK_EQ(noncanon.size(), 0u);
			printf("    ok  pure-QCG builds no integer frame at this width (unchanged)\n");
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [S13]/[S14] W5D: standalone `.vv` FP-ALU coverage where Family A does not admit.
// ---------------------------------------------------------------------------------------------

// ONE FP INSTRUCTION, ISOLATED. Its neighbours are a `vsetvli` and a `jalr`, neither of which is an
// admitted run member, so `FormRun` cannot reach two members and the only thing that can lower this
// instruction is a single-instruction route. That is the situation W5D is about: "the neighbours are
// not there" was never a property of the instruction.
struct Lowering {
	unsigned family_a = 0;	  // Op::_rvvfalu -- the residency route
	unsigned frames = 0;	  // typed frames of any member count
	unsigned lane_ops = 0;	  // vchunkfalu
	unsigned stubs = 0;
	unsigned guard_kind = ~0u;
	u32 frame_vtype = 0;
};

Lowering ScanLowering(Region *region)
{
	Lowering l;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvfalu:
				++l.family_a;
				break;
			case Op::_rvvtypedchunkbegin: {
				auto *b = static_cast<InstRVVTypedChunkBegin *>(&ins);
				++l.frames;
				l.guard_kind = (unsigned)b->guard_kind;
				l.frame_vtype = b->vtype;
				break;
			}
			case Op::_vchunkfalu:
				++l.lane_ops;
				break;
			case Op::_rvvtypedchunkend:
				l.stubs += static_cast<InstRVVTypedChunkEnd *>(&ins)->n_members;
				break;
			default:
				break;
			}
		}
	}
	return l;
}

// Family A's own admission contract, restated from rv32_qir.cpp so the expectation below is derived
// rather than a width list: RvvSSAEnabled() (VLEN 512 or 1024) and RvvPVectorSSAShapeAdmit's
// `SEW in {4,8}` and `nregs * (VLEN/512) <= 4`.
bool FamilyAAdmits(u32 vlen, u32 vtype)
{
	if (vlen != 512u && vlen != 1024u)
		return false;
	u32 const sew = (vtype == kVT_E64M1 || vtype == kVT_E64M2) ? 8u : 4u;
	u32 const nregs = IsM2(vtype) ? 2u : 1u;
	return (sew == 4u || sew == 8u) && nregs * (vlen / 512u) <= 4u;
}

void CheckStandaloneVv(u32 vlen, u32 vtype)
{
	printf("[S13] VLEN=%u vtype=0x%02x (%s) isolated vfsub.vv\n", vlen, vtype, VTName(vtype));
	u32 const sew = (vtype == kVT_E64M1 || vtype == kVT_E64M2) ? 8u : 4u;
	u32 const chunks = (IsM2(vtype) ? 2u : 1u) * ChunksPerGroup(vlen, sew);
	ConfigureLLVM(vlen);
	// Even registers, legal at LMUL 1 and 2; non-commutative, so an operand swap would show.
	std::vector<u32> const words{Vsetvli(vtype), OpV(F6_VFSUB, 10, 12, 8), kJalr};
	Built b(words);
	CompilerJob::IpRangesSet rs;
	rs.push_back({0u, (u32)(words.size() * 4u)});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);
	auto const l = ScanLowering(b.region);

	if (FamilyAAdmits(vlen, vtype)) {
		// FAMILY A KEEPS IT. The residency route runs and no typed frame is built -- W5D must
		// not have moved an instruction with a residency route onto a per-instruction frame.
		CHECK_EQ(l.family_a, 1u);
		CHECK_EQ(l.frames, 0u);
		CHECK_EQ(l.lane_ops, 0u);
		printf("    ok  Family A residency route (no typed frame)\n");
		return;
	}
	// FAMILY A REFUSED, so the standalone typed frame picks it up. Before W5D this was the
	// unchanged `rv32_vfalu` helper and none of the counts below existed.
	CHECK_EQ(l.family_a, 0u);
	CHECK_EQ(l.frames, 1u);
	CHECK(chunks != 0);
	CHECK_EQ(l.lane_ops, chunks);
	// The guard is the unchanged full-VL/RNE one, and the frame carries this vtype.
	CHECK_EQ(l.guard_kind, (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
	    (InstRVVTypedChunkBegin::GuardKind)l.guard_kind));
	CHECK_EQ(l.frame_vtype, vtype);
	// One member, one ordered fallback stub to the same helper.
	CHECK_EQ(l.stubs, 1u);
	printf("    ok  standalone typed frame, %u lane op(s), vtype=0x%02x\n", chunks, l.frame_vtype);
}

// [S13b] REFUSALS STAY EXPLICIT. A masked encoding, a reverse form and an unsupported funct6 must
// keep the helper at every width -- W5D widened WHICH SITUATIONS reach the frame, not which
// encodings it admits.
void CheckStandaloneRefusals(u32 vlen)
{
	printf("[S13b] VLEN=%u unsupported encodings keep the helper\n", vlen);
	struct Row {
		char const *what;
		u32 word;
	};
	// vm = 0 is masked; VFMIN (funct6 0b000100) is not one of the four constrained-arithmetic
	// rows; VFRSUB (0b100111) is an OPFVF reverse form.
	Row const rows[] = {
	    {"masked vfsub.vv (vm=0)",
	     (F6_VFSUB << 26) | (0u << 25) | (10u << 20) | (12u << 15) | (0b001u << 12) | (8u << 7) | 0x57u},
	    {"vfmin.vv (not one IEEE arithmetic op)", OpV(0b000100u, 10, 12, 8)},
	    {"vfrsub.vf (reverse form)",
	     (0b100111u << 26) | (1u << 25) | (10u << 20) | (12u << 15) | (0b101u << 12) | (8u << 7) | 0x57u},
	};
	for (auto const &r : rows) {
		ConfigureLLVM(vlen);
		std::vector<u32> const words{Vsetvli(kVT_E32M1), r.word, kJalr};
		Built b(words);
		CompilerJob::IpRangesSet rs;
		rs.push_back({0u, (u32)(words.size() * 4u)});
		CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
		b.region = CompilerGenRegionIR(&b.arena, job);
		auto const l = ScanLowering(b.region);
		CHECK_EQ(l.frames, 0u);
		CHECK_EQ(l.lane_ops, 0u);
		CHECK_EQ(l.family_a, 0u);
	}
	printf("    ok  masked / vfmin / reverse-form all refused\n");
}

// [S14] The standalone frame on an UNKNOWN range: the shape-filtered candidate, or the helper.
void CheckStandaloneUnknownEntry(u32 vlen)
{
	printf("[S14] VLEN=%u isolated vfsub.vv in an unknown second range\n", vlen);
	u32 const sub = OpV(F6_VFSUB, 10, 12, 8);
	// Range 1 establishes e64,m1; range 2 has no vsetvli and one isolated FP instruction.
	{
		ConfigureLLVM(vlen);
		std::vector<u32> const words{Vsetvli(kVT_E64M1), sub, sub, kJalr};
		Built b(words);
		CompilerJob::IpRangesSet rs;
		rs.push_back({0u, 8u});
		rs.push_back({8u, (u32)(words.size() * 4u)});
		CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
		b.region = CompilerGenRegionIR(&b.arena, job);
		auto const l = ScanLowering(b.region);
		if (FamilyAAdmits(vlen, kVT_E64M1)) {
			// The observed range goes to Family A; the unknown one has no Family A route
			// (its vtype is ~0u) and takes the candidate frame.
			CHECK_EQ(l.family_a, 1u);
			CHECK_EQ(l.frames, 1u);
		} else {
			CHECK_EQ(l.family_a, 0u);
			CHECK_EQ(l.frames, 2u);
		}
		CHECK_EQ(l.frame_vtype, kVT_E64M1); // the candidate reached the unknown range
		printf("    ok  candidate frame in the unknown range (vtype=0x%02x)\n", l.frame_vtype);
	}
	// NO CANDIDATE AT ALL: a region whose first range decodes no constant vsetvl. The unknown
	// range then has neither an observation nor a candidate, and RvvStandaloneFrameVType returns
	// `~0u`, so the instruction keeps the helper -- the refusal is explicit, not a guess.
	{
		ConfigureLLVM(vlen);
		std::vector<u32> const words{sub, sub, kJalr};
		Built b(words);
		CompilerJob::IpRangesSet rs;
		rs.push_back({0u, 4u});
		rs.push_back({4u, (u32)(words.size() * 4u)});
		CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
		b.region = CompilerGenRegionIR(&b.arena, job);
		auto const l = ScanLowering(b.region);
		CHECK_EQ(l.frames, 0u);
		CHECK_EQ(l.family_a, 0u);
		printf("    ok  no candidate -> helper\n");
	}
}

// [S13c] FLAGS OFF AND QCG INVARIANCE for the new arm.
void CheckStandaloneFlagsAndQcg(u32 vlen)
{
	printf("[S13c] VLEN=%u standalone arm: flags off, and pure QCG unchanged\n", vlen);
	u32 const sub = OpV(F6_VFSUB, 10, 12, 8);
	std::vector<u32> const words{Vsetvli(kVT_E32M1), sub, kJalr};
	auto build = [&](bool falu_on, bool llvm_backend) {
		ConfigureLLVM(vlen, falu_on, /*run_on=*/true);
		if (!llvm_backend) {
			config::aot_use_llvm = false;
			config::rvv_vector_ssa = false;
		}
		auto *b = new Built(words);
		CompilerJob::IpRangesSet rs;
		rs.push_back({0u, (u32)(words.size() * 4u)});
		CompilerJob job(nullptr, (uptr)b->words.data(), b->segment, std::move(rs));
		b->region = CompilerGenRegionIR(&b->arena, job);
		auto const l = ScanLowering(b->region);
		delete b;
		return l;
	};
	// The route's own switch off: no frame, at any width. Without this the arm could be widened
	// by dropping a switch rather than by the Family-A-refused ordering.
	CHECK_EQ(build(/*falu_on=*/false, /*llvm_backend=*/true).frames, 0u);
	// PURE QCG: this arm requires RvvLLVMTypedSubstrate(), so it cannot exist there. The QCG FALU
	// route has its own predicate and its own switches, and W5D touched neither.
	auto const qcg = build(/*falu_on=*/true, /*llvm_backend=*/false);
	CHECK_EQ(qcg.family_a, 0u);
	printf("    ok  falu switch off -> no frame; pure QCG has no Family A node either way\n");
}

// [S15] Mixed Family A / typed-frame sequence, and the commit between them.
//
// A NOTE ON WHAT CANNOT BE MIXED, because it shapes the fixture. Within ONE vtype, Family A and the
// W5D frame admit exactly the same `.vv` encodings: both ask `vfalu_llvm_constrained_vv_supported`,
// both require `vm == 1` and `funct3 == 0b001`, and both apply `reg_group_legal` at the same LMUL.
// They differ only in their SHAPE rows -- `nregs * (VLEN/512) <= 4` versus
// `total <= kMaxChunks` -- and those are functions of vtype and VLEN, not of the instruction. So a
// sequence that alternates between them at one vtype does not exist, and the honest mixed fixture
// is Family A `.vv` -> a `.vf` frame (F5's arm, which Family A never has) -> Family A `.vv`.
void CheckMixedFamilyASequence(u32 vlen)
{
	if (!FamilyAAdmits(vlen, kVT_E32M1))
		return; // Family A is closed at this width; there is nothing to mix.
	printf("[S15] VLEN=%u Family A -> typed frame -> Family A, with the commit between\n", vlen);
	// `--rvv-vector-run` OFF: the three instructions below are adjacent and all admitted, so with
	// it on the run former consumes them into ONE frame and there is no single-instruction
	// sequence left to observe. This row is about the boundary between the two SINGLE-instruction
	// representations, which is exactly what the run frame removes.
	ConfigureLLVM(vlen, /*falu_on=*/true, /*run_on=*/false);
	// vfadd.vv v8, v10, v12  (Family A: leaves v8 resident)
	// vfmul.vf v14, v10, f2  (F5's standalone frame: state-backed, so v8 must be committed first)
	// vfsub.vv v16, v8, v12  (Family A again)
	u32 const vf_mul = (F6_VFMUL << 26) | (1u << 25) | (10u << 20) | (2u << 15) |
			   (0b101u << 12) | (14u << 7) | 0x57u;
	std::vector<u32> const words{Vsetvli(kVT_E32M1), OpV(F6_VFADD, 10, 12, 8), vf_mul,
				     OpV(F6_VFSUB, 8, 12, 16), kJalr};
	Built b(words);
	CompilerJob::IpRangesSet rs;
	rs.push_back({0u, (u32)(words.size() * 4u)});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);

	// Walk in order: the commit of the dirty group has to appear between the first Family A node
	// and the frame's begin. Asserting the ORDER is the point -- counting the nodes would pass on
	// a build that committed after the frame.
	unsigned family_a = 0, frames = 0, commits_before_frame = 0;
	bool seen_family_a = false, seen_frame = false;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvfalu:
				++family_a;
				seen_family_a = true;
				break;
			case Op::_rvvwrite:
				if (seen_family_a && !seen_frame)
					++commits_before_frame;
				break;
			case Op::_rvvtypedchunkbegin:
				++frames;
				seen_frame = true;
				break;
			default:
				break;
			}
		}
	}
	CHECK_EQ(family_a, 2u);
	CHECK_EQ(frames, 1u);
	CHECK(commits_before_frame >= 1u);
	printf("    ok  2 Family A nodes, 1 frame, %u commit(s) between them\n", commits_before_frame);
}

// ---------------------------------------------------------------------------------------------
// [S16]/[S17] W5E: the standalone fused frame on a guarded candidate vtype.
// ---------------------------------------------------------------------------------------------

struct FmaLowering {
	unsigned family_a_fma = 0;   // Op::_rvvfma  -- the P-vector-SSA fused arm
	unsigned family_a_alu = 0;   // Op::_rvvfalu -- used by the mixed-boundary row
	unsigned frames = 0;
	unsigned lane_ops = 0;	     // vchunkfma
	unsigned stubs = 0;
	unsigned guard_kind = ~0u;
	u32 frame_vtype = 0;
};

FmaLowering ScanFma(Region *region)
{
	FmaLowering l;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvfma:
				++l.family_a_fma;
				break;
			case Op::_rvvfalu:
				++l.family_a_alu;
				break;
			case Op::_rvvtypedchunkbegin: {
				auto *b = static_cast<InstRVVTypedChunkBegin *>(&ins);
				++l.frames;
				l.guard_kind = (unsigned)b->guard_kind;
				l.frame_vtype = b->vtype;
				break;
			}
			case Op::_vchunkfma:
				++l.lane_ops;
				break;
			case Op::_rvvtypedchunkend:
				l.stubs += static_cast<InstRVVTypedChunkEnd *>(&ins)->n_members;
				break;
			default:
				break;
			}
		}
	}
	return l;
}

// One region, `ranges` ip ranges, fused route on. The fused switch is default OFF, so every row
// here sets it explicitly -- which is also what makes the flags-off row meaningful.
FmaLowering BuildFma(std::vector<u32> const &words, std::vector<std::pair<u32, u32>> const &ranges,
		     u32 vlen, bool fma_on = true)
{
	ConfigureLLVM(vlen);
	config::rvv_qcg_typed_chunk_fma = fma_on;
	Built b(words);
	CompilerJob::IpRangesSet rs;
	for (auto const &r : ranges)
		rs.push_back({r.first, r.second});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);
	auto const l = ScanFma(b.region);
	config::rvv_qcg_typed_chunk_fma = false;
	return l;
}

// `vfmacc.vv v8, v10, v12` -- vd is read as the accumulator, which is what makes it fused.
u32 FmaccVV() { return OpV(F6_VFMACC, 10, 12, 8); }

void CheckStandaloneFma(u32 vlen, u32 vtype)
{
	printf("[S16] VLEN=%u vtype=0x%02x (%s) isolated vfmacc.vv\n", vlen, vtype, VTName(vtype));
	u32 const sew = (vtype == kVT_E64M1 || vtype == kVT_E64M2) ? 8u : 4u;
	u32 const chunks = (IsM2(vtype) ? 2u : 1u) * ChunksPerGroup(vlen, sew);
	// OBSERVED: unchanged by W5E -- RvvStandaloneFrameVType returns `rvv_bb_vtype` here.
	{
		std::vector<u32> const w{Vsetvli(vtype), FmaccVV(), kJalr};
		auto const l = BuildFma(w, {{0u, (u32)(w.size() * 4u)}}, vlen);
		CHECK_EQ(l.frames, 1u);
		CHECK_EQ(l.lane_ops, chunks);
		CHECK_EQ(l.frame_vtype, vtype);
		CHECK_EQ(l.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
		    (InstRVVTypedChunkBegin::GuardKind)l.guard_kind));
		CHECK_EQ(l.stubs, 1u);
		// F4's arm runs before Family A's fused arm, so no `rvvfma` node is built for it.
		CHECK_EQ(l.family_a_fma, 0u);
	}
	// UNKNOWN second range: the shape-filtered candidate. Before W5E this was the helper.
	{
		std::vector<u32> const w{Vsetvli(vtype), FmaccVV(), FmaccVV(), kJalr};
		auto const l = BuildFma(w, {{0u, 8u}, {8u, (u32)(w.size() * 4u)}}, vlen);
		CHECK_EQ(l.frames, 2u);
		CHECK_EQ(l.lane_ops, 2u * chunks);
		CHECK_EQ(l.frame_vtype, vtype); // the last frame seen is the unknown range's
		CHECK_EQ(l.stubs, 2u);
	}
	printf("    ok  observed and unknown both build a frame, %u lane op(s), vtype=0x%02x\n",
	       chunks, vtype);
}

// [S16b] NO CANDIDATE, and a candidate the shape contract refuses. Both must keep the helper: the
// refusal is explicit, not a guess at a shape.
void CheckStandaloneFmaNoCandidate(u32 vlen)
{
	printf("[S16b] VLEN=%u fused: no candidate, and a candidate no frame can be built from\n",
	       vlen);
	// (a) a region whose first range decodes no constant `vsetvl` at all.
	{
		std::vector<u32> const w{FmaccVV(), FmaccVV(), kJalr};
		auto const l = BuildFma(w, {{0u, 4u}, {4u, (u32)(w.size() * 4u)}}, vlen);
		// The first range is unknown too, so neither gets a proposal from a decoded vsetvl.
		// RvvFormVectorRunAt's canonical fallback is a RUN proposal and does not reach a
		// standalone frame, so both instructions keep the helper.
		CHECK_EQ(l.frames, 0u);
		CHECK_EQ(l.lane_ops, 0u);
	}
	// (b) a register-form `vsetvl` between the ranges invalidates the candidate.
	{
		std::vector<u32> const w{Vsetvli(kVT_E32M1), FmaccVV(), kVsetvlReg, FmaccVV(), kJalr};
		auto const l = BuildFma(w, {{0u, 8u}, {8u, (u32)(w.size() * 4u)}}, vlen);
		// Only the observed range's instruction is framed; the range after the register-form
		// write has no candidate left.
		CHECK_EQ(l.frames, 1u);
		CHECK_EQ(l.frame_vtype, kVT_E32M1);
	}
	printf("    ok  both keep the helper / only the observed range is framed\n");
}

// [S16c] FLAGS OFF and QCG. The fused route has its OWN switch; with it off nothing here exists,
// at any width. And this arm requires RvvLLVMTypedSubstrate(), so pure QCG is untouched.
void CheckStandaloneFmaFlags(u32 vlen)
{
	printf("[S16c] VLEN=%u fused: switch off, and pure QCG\n", vlen);
	std::vector<u32> const w{Vsetvli(kVT_E32M1), FmaccVV(), FmaccVV(), kJalr};
	auto const off = BuildFma(w, {{0u, 8u}, {8u, (u32)(w.size() * 4u)}}, vlen, /*fma_on=*/false);
	CHECK_EQ(off.frames, 0u);
	CHECK_EQ(off.lane_ops, 0u);
	{
		ConfigureLLVM(vlen);
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = false;
		config::rvv_qcg_typed_chunk_fma = true;
		Built b(w);
		CompilerJob::IpRangesSet rs;
		rs.push_back({0u, 8u});
		rs.push_back({8u, (u32)(w.size() * 4u)});
		CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
		b.region = CompilerGenRegionIR(&b.arena, job);
		auto const l = ScanFma(b.region);
		config::rvv_qcg_typed_chunk_fma = false;
		// The pure-QCG fused route is RvvQcgTypedFmaAdmit's, on its own terms; what this row
		// asserts is that the LLVM candidate arm contributed nothing -- the unknown range has no
		// frame there, because the candidate is consumed only under RvvLLVMTypedSubstrate().
		CHECK(l.frames <= 1u);
	}
	printf("    ok  switch off -> nothing; pure QCG unchanged by the candidate\n");
}

// [S17] Family A FP-ALU -> FMA frame -> Family A FP-ALU, and the commit between.
//
// WHY THE NEIGHBOURS ARE FP-ALU. A Family-A-FMA / FMA-frame alternation cannot be built: F4's arm
// runs before Family A's fused arm and `--rvv-qcg-typed-chunk-fma` decides all eight funct6 at
// once, so within one configuration every fused instruction goes to the same route. The FP-ALU
// residency route is the neighbour that CAN sit either side of a fused frame.
void CheckFmaMixedBoundary(u32 vlen)
{
	if (!FamilyAAdmits(vlen, kVT_E32M1))
		return; // Family A is closed at this width; nothing to mix.
	printf("[S17] VLEN=%u Family A -> FMA frame -> Family A, with the commit between\n", vlen);
	// Run off, or the three adjacent admitted instructions become one run frame and there is no
	// single-instruction boundary left to observe.
	ConfigureLLVM(vlen, /*falu_on=*/true, /*run_on=*/false);
	config::rvv_qcg_typed_chunk_fma = true;
	std::vector<u32> const words{Vsetvli(kVT_E32M1), OpV(F6_VFADD, 10, 12, 8), FmaccVV(),
				     OpV(F6_VFSUB, 8, 12, 16), kJalr};
	Built b(words);
	CompilerJob::IpRangesSet rs;
	rs.push_back({0u, (u32)(words.size() * 4u)});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);
	config::rvv_qcg_typed_chunk_fma = false;

	unsigned falu = 0, frames = 0, commits_before_frame = 0;
	bool seen_falu = false, seen_frame = false;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvfalu:
				++falu;
				seen_falu = true;
				break;
			case Op::_rvvwrite:
				if (seen_falu && !seen_frame)
					++commits_before_frame;
				break;
			case Op::_rvvtypedchunkbegin:
				++frames;
				seen_frame = true;
				break;
			default:
				break;
			}
		}
	}
	CHECK_EQ(falu, 2u);
	CHECK_EQ(frames, 1u);
	// The FMA frame is state-backed; the dirty Family A group must be committed before it, or the
	// frame would read a stale CPUState word. Asserted by ORDER, not by count.
	CHECK(commits_before_frame >= 1u);
	printf("    ok  2 Family A FP-ALU nodes, 1 FMA frame, %u commit(s) between\n",
	       commits_before_frame);
}

// ---------------------------------------------------------------------------------------------
// [S18]-[S20] W5F: native `vfsqrt.v`.
// ---------------------------------------------------------------------------------------------

// VFUNARY1 is OPFVV with the vs1 field used as an opcode extension: 00000 vfsqrt.v, 00100
// vfrsqrt7.v, 00101 vfrec7.v, 10000 vfclass.v. Only the first is a correctly-rounded IEEE square
// root; the estimates and the classify are different functions and must keep the helper.
constexpr u32 F6_VFUNARY1 = 0b010011u;
constexpr u32 VfunaryV(u32 sub, u32 vs2, u32 vd, bool unmasked = true)
{
	return (F6_VFUNARY1 << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) |
	       (0b001u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 SUB_VFSQRT = 0b00000u, SUB_VFRSQRT7 = 0b00100u, SUB_VFREC7 = 0b00101u,
	      SUB_VFCLASS = 0b10000u;

struct SqrtLowering {
	unsigned frames = 0, lane_ops = 0, stubs = 0, state_loads = 0, state_stores = 0;
	unsigned guard_kind = ~0u;
	unsigned n_typed = 0;
	u32 frame_vtype = 0;
	unsigned sqrt_calls = 0;     // llvm.experimental.constrained.sqrt in the emitted IR
	unsigned helper_calls = 0;   // non-intrinsic calls in the frame's FALLBACK arm
	unsigned fast_arm_calls = 0; // ... and in its fast arm, which must be none
};

SqrtLowering BuildSqrt(std::vector<u32> const &words,
		       std::vector<std::pair<u32, u32>> const &ranges, u32 vlen, bool fsqrt_on = true,
		       bool llvm_backend = true, bool run_backend = true)
{
	ConfigureLLVM(vlen);
	if (!llvm_backend) {
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = false;
		// The QCG sqrt emitter probes the compiling host for AVX-512F/BMI2; this file must build
		// the same QIR anywhere and emits nothing on that arm.
		config::rvv_qcg_typed_chunk_fsqrt_force_emit = true;
	}
	config::rvv_qcg_typed_chunk_fsqrt = fsqrt_on;
	Built b(words);
	CompilerJob::IpRangesSet rs;
	for (auto const &r : ranges)
		rs.push_back({r.first, r.second});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);
	SqrtLowering l;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: {
				auto *bg = static_cast<InstRVVTypedChunkBegin *>(&ins);
				++l.frames;
				l.guard_kind = (unsigned)bg->guard_kind;
				l.frame_vtype = bg->vtype;
				l.n_typed = bg->n_typed;
				break;
			}
			case Op::_vchunkfsqrt:
				++l.lane_ops;
				break;
			case Op::_vstatechunkload:
				++l.state_loads;
				break;
			case Op::_vstatechunkstore:
				++l.state_stores;
				break;
			case Op::_rvvtypedchunkend:
				l.stubs += static_cast<InstRVVTypedChunkEnd *>(&ins)->n_members;
				break;
			default:
				break;
			}
		}
	}
	if (llvm_backend && run_backend) {
		LLVMGenCtx ctx(&b.module);
		ctx.AddFunction(0u, b.segment);
		QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
		b.fn = gen.Run();
		if (b.fn) {
			for (auto &bb : *b.fn) {
				// Helper calls are counted per BLOCK CLASS, not per function: the guest
				// `vsetvli` and the region-exit dispatch for the trailing `jalr` are
				// non-intrinsic calls too, and they are not this frame's. What the row
				// below is about is that the FAST arm calls nothing and the FALLBACK arm
				// calls the one stub.
				bool const fast = bb.getName().starts_with("rvv.tchunk.direct");
				bool const slow = bb.getName().starts_with("rvv.tchunk.fallback");
				for (auto &ins : bb) {
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						if (ii->getIntrinsicID() ==
						    llvm::Intrinsic::experimental_constrained_sqrt)
							++l.sqrt_calls;
						continue;
					}
					if (!llvm::isa<llvm::CallInst>(&ins))
						continue;
					if (slow)
						++l.helper_calls;
					else if (fast)
						++l.fast_arm_calls;
				}
			}
		}
	}
	config::rvv_qcg_typed_chunk_fsqrt = false;
	config::rvv_qcg_typed_chunk_fsqrt_force_emit = false;
	return l;
}

void CheckSqrt(u32 vlen, u32 vtype)
{
	printf("[S18] VLEN=%u vtype=0x%02x (%s) vfsqrt.v\n", vlen, vtype, VTName(vtype));
	u32 const sew = (vtype == kVT_E64M1 || vtype == kVT_E64M2) ? 8u : 4u;
	u32 const chunks = (IsM2(vtype) ? 2u : 1u) * ChunksPerGroup(vlen, sew);
	// OBSERVED vtype.
	{
		std::vector<u32> const w{Vsetvli(vtype), VfunaryV(SUB_VFSQRT, 10, 8), kJalr};
		auto const l = BuildSqrt(w, {{0u, (u32)(w.size() * 4u)}}, vlen);
		CHECK_EQ(l.frames, 1u);
		CHECK(chunks != 0);
		CHECK_EQ(l.lane_ops, chunks);
		// One source load and one store per chunk -- the one-operand shape.
		CHECK_EQ(l.state_loads, chunks);
		CHECK_EQ(l.state_stores, chunks);
		// `3n + 2`, which Emit_rvvtypedchunkend checks exactly; reaching the end of Run() at all
		// is that assertion, and this is the QIR side of it.
		CHECK_EQ(l.n_typed, 3u * chunks + 2u);
		CHECK_EQ(l.frame_vtype, vtype);
		// THE GUARD KIND IS THE LLVM ONE, NOT THE QCG EMITTER'S OWN. This is the row that would
		// fail if the partial/masked/host-rounding guard were handed to the unmasked body.
		CHECK_EQ(l.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
		    (InstRVVTypedChunkBegin::GuardKind)l.guard_kind));
		CHECK_EQ(l.stubs, 1u);
		// The emitted IR: one constrained sqrt per chunk, nothing called on the fast arm, and
		// the one ordered-fallback stub on the miss arm.
		CHECK_EQ(l.sqrt_calls, chunks);
		CHECK_EQ(l.fast_arm_calls, 0u);
		CHECK_EQ(l.helper_calls, 1u);
	}
	// UNKNOWN second range: the guarded candidate, via RvvStandaloneFrameVType.
	{
		std::vector<u32> const w{Vsetvli(vtype), VfunaryV(SUB_VFSQRT, 10, 8),
					 VfunaryV(SUB_VFSQRT, 12, 14), kJalr};
		auto const l = BuildSqrt(w, {{0u, 8u}, {8u, (u32)(w.size() * 4u)}}, vlen);
		CHECK_EQ(l.frames, 2u);
		CHECK_EQ(l.lane_ops, 2u * chunks);
		CHECK_EQ(l.frame_vtype, vtype);
		CHECK_EQ(l.sqrt_calls, 2u * chunks);
	}
	printf("    ok  %u chunk(s), %u constrained.sqrt, full-VL/RNE guard, 3n+2 typed ops\n", chunks,
	       chunks);
}

// [S19] Refusals, and the QCG contrast that gives them meaning.
void CheckSqrtRefusals(u32 vlen)
{
	printf("[S19] VLEN=%u refusals and the QCG contrast\n", vlen);
	struct Row {
		char const *what;
		u32 word;
	};
	Row const rows[] = {
	    {"masked vfsqrt.v (vm=0)", VfunaryV(SUB_VFSQRT, 10, 8, /*unmasked=*/false)},
	    {"vfrsqrt7.v (7-bit estimate)", VfunaryV(SUB_VFRSQRT7, 10, 8)},
	    {"vfrec7.v (7-bit estimate)", VfunaryV(SUB_VFREC7, 10, 8)},
	    {"vfclass.v", VfunaryV(SUB_VFCLASS, 10, 8)},
	};
	for (auto const &r : rows) {
		std::vector<u32> const w{Vsetvli(kVT_E32M1), r.word, kJalr};
		auto const l = BuildSqrt(w, {{0u, (u32)(w.size() * 4u)}}, vlen);
		CHECK_EQ(l.frames, 0u);
		CHECK_EQ(l.lane_ops, 0u);
	}
	// The route's own switch off: nothing, at any width.
	{
		std::vector<u32> const w{Vsetvli(kVT_E32M1), VfunaryV(SUB_VFSQRT, 10, 8), kJalr};
		auto const l = BuildSqrt(w, {{0u, (u32)(w.size() * 4u)}}, vlen, /*fsqrt_on=*/false);
		CHECK_EQ(l.frames, 0u);
	}
	// THE QCG CONTRAST. The masked word this backend refuses is still admitted on the pure-QCG
	// arm, with ITS guard kind -- so W5F narrowed the envelope for ONE backend and left the other
	// alone. Without this row, "masked is refused" would also pass on a build where the whole
	// route had been broken.
	//
	// ONLY WHERE THE QCG ROUTE HAS A SHAPE AT ALL. Its width rule is RvvRouteChunkShape on the
	// pure-QCG path, i.e. RvvGenericChunkShapeAdmit (`VLEN % 512 == 0`) once the narrow switch is
	// off -- so at 128/256 the QCG arm builds nothing for a reason that predates W5F and has
	// nothing to do with masking. Asserting a frame there would be asserting the wrong thing.
	if (vlen % 512u == 0u) {
		std::vector<u32> const w{Vsetvli(kVT_E32M1),
					 VfunaryV(SUB_VFSQRT, 10, 8, /*unmasked=*/false), kJalr};
		auto const l = BuildSqrt(w, {{0u, (u32)(w.size() * 4u)}}, vlen, /*fsqrt_on=*/true,
					 /*llvm_backend=*/false, /*run_backend=*/false);
		CHECK_EQ(l.frames, 1u);
		CHECK_EQ(l.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost);
		CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl(
		    (InstRVVTypedChunkBegin::GuardKind)l.guard_kind));
	}
	printf("    ok  masked / estimates / vfclass / switch-off refused; QCG masked still admitted\n");
}

// [S20] The state boundary, and the legal `vd == vs2` overlap.
void CheckSqrtBoundary(u32 vlen)
{
	if (!FamilyAAdmits(vlen, kVT_E32M1))
		return;
	printf("[S20] VLEN=%u Family A -> sqrt frame, and vd == vs2\n", vlen);
	// The sqrt frame is state-backed, so a dirty Family A group must be committed before it reads
	// CPUState. Run off, or the two FP-ALU instructions would form a run frame instead.
	{
		ConfigureLLVM(vlen, /*falu_on=*/true, /*run_on=*/false);
		config::rvv_qcg_typed_chunk_fsqrt = true;
		std::vector<u32> const words{Vsetvli(kVT_E32M1), OpV(F6_VFADD, 10, 12, 8),
					     VfunaryV(SUB_VFSQRT, 8, 14), kJalr};
		Built b(words);
		CompilerJob::IpRangesSet rs;
		rs.push_back({0u, (u32)(words.size() * 4u)});
		CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
		b.region = CompilerGenRegionIR(&b.arena, job);
		config::rvv_qcg_typed_chunk_fsqrt = false;
		unsigned falu = 0, frames = 0, commits_before_frame = 0;
		bool seen_falu = false, seen_frame = false;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist) {
				if (ins.GetOpcode() == Op::_rvvfalu) { ++falu; seen_falu = true; }
				if (ins.GetOpcode() == Op::_rvvwrite && seen_falu && !seen_frame)
					++commits_before_frame;
				if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
					++frames;
					seen_frame = true;
				}
			}
		CHECK_EQ(falu, 1u);
		CHECK_EQ(frames, 1u);
		// The sqrt frame reads v8, which Family A left RESIDENT and dirty. Without the commit
		// this frame would read a stale CPUState word.
		CHECK(commits_before_frame >= 1u);
		printf("    ok  1 Family A node, 1 sqrt frame, %u commit(s) between\n",
		       commits_before_frame);
	}
	// `vd == vs2` is legal for vfsqrt.v and the frame is load-major, so it must still be admitted
	// and must still emit every load before any store.
	{
		std::vector<u32> const w{Vsetvli(kVT_E32M1), VfunaryV(SUB_VFSQRT, 8, 8), kJalr};
		auto const l = BuildSqrt(w, {{0u, (u32)(w.size() * 4u)}}, vlen);
		u32 const chunks = ChunksPerGroup(vlen, 4u);
		CHECK_EQ(l.frames, 1u);
		CHECK_EQ(l.lane_ops, chunks);
		CHECK_EQ(l.state_loads, chunks);
		CHECK_EQ(l.state_stores, chunks);
		printf("    ok  vd == vs2 admitted, %u load(s) then %u store(s)\n", chunks, chunks);
	}
}


// ---------------------------------------------------------------------------------------------
// [S22] W6: the ordered floating reduction.
constexpr u32 F6_VFREDUSUM = 1u, F6_VFREDOSUM = 3u, F6_VFREDMIN = 5u, F6_VFWREDOSUM = 51u;
constexpr u32 VRed(u32 f6, u32 vs2, u32 vs1, u32 vd, bool unmasked = true)
{
	return (f6 << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) |
	       (0b001u << 12) | (vd << 7) | 0x57u;
}

struct RedLowering {
	unsigned frames = 0, red_nodes = 0, fadds = 0, reduce_intrinsics = 0, helper_calls = 0;
	unsigned guard_kind = 0, n_typed = 0, node_vlmax = 0;
	bool node_masked = false, node_wide = false;
	unsigned node_op = 255;
	// THE ORDERING PROPERTY. Every constrained fadd except the first must take the PREVIOUS fadd
	// as an operand; if any fadd's operands are both non-fadd values, the chain has been split
	// into independent partial sums, which is precisely what an ordered reduction forbids.
	bool single_chain = true;
	unsigned chain_len = 0;
};

RedLowering BuildRed(std::vector<u32> const &words, u32 vlen, bool route_on = true,
		     bool llvm_backend = true)
{
	ConfigureLLVM(vlen);
	if (!llvm_backend) {
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = false;
	}
	config::rvv_qcg_typed_chunk_fredosum = route_on;
	Built b(words);
	CompilerJob::IpRangesSet rs;
	rs.push_back({0u, (u32)(words.size() * 4u)});
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(rs));
	b.region = CompilerGenRegionIR(&b.arena, job);
	RedLowering l;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				auto *bg = static_cast<InstRVVTypedChunkBegin *>(&ins);
				++l.frames;
				l.guard_kind = (unsigned)bg->guard_kind;
				l.n_typed = bg->n_typed;
			} else if (ins.GetOpcode() == Op::_vfreducenative) {
				auto *r = static_cast<InstVFReduce *>(&ins);
				++l.red_nodes;
				l.node_masked = r->masked;
				l.node_wide = r->wide;
				l.node_op = r->op;
				l.node_vlmax = r->vlmax;
			}
		}
	}
	if (llvm_backend) {
		LLVMGenCtx ctx(&b.module);
		ctx.AddFunction(0u, b.segment);
		QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
		b.fn = gen.Run();
		if (b.fn) {
			llvm::Value *prev = nullptr;
			for (auto &bb : *b.fn) {
				bool const slow = bb.getName().starts_with("rvv.tchunk.fallback");
				for (auto &ins : bb) {
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						auto const id = ii->getIntrinsicID();
						if (id == llvm::Intrinsic::vector_reduce_fadd) {
							++l.reduce_intrinsics;
						} else if (id == llvm::Intrinsic::
								 experimental_constrained_fadd) {
							++l.fadds;
							// operand 0 is the accumulator.
							if (prev != nullptr &&
							    ii->getArgOperand(0) != prev)
								l.single_chain = false;
							prev = ii;
							++l.chain_len;
						}
						continue;
					}
					if (slow && llvm::isa<llvm::CallInst>(&ins))
						++l.helper_calls;
				}
			}
		}
	}
	return l;
}

void CheckOrderedReduction(u32 vlen, u32 vtype)
{
	u32 const sew = (vtype == kVT_E64M1 || vtype == kVT_E64M2) ? 8u : 4u;
	u32 const lmul = IsM2(vtype) ? 2u : 1u;
	u32 const vlmax = vlen / 8u * lmul / sew;
	printf("[S22] VLEN=%u vtype=0x%02x (%s) vfredosum.vs, VLMAX=%u\n", vlen, vtype, VTName(vtype),
	       vlmax);
	// The real k3 shape: unmasked ordered sum, vd = vs1 = the accumulator register. vs2 is EVEN
	// so the source group is legal at LMUL=2 as well -- an odd group there is an architecturally
	// illegal encoding, not a lowering limit, and must not be mistaken for one.
	std::vector<u32> const w{Vsetvli(vtype), VRed(F6_VFREDOSUM, 8, 11, 11), kJalr};
	auto const l = BuildRed(w, vlen);
	CHECK_EQ(l.frames, 1u);
	CHECK_EQ(l.red_nodes, 1u);
	CHECK_EQ(l.n_typed, 3u);  // fp-bracket begin + the reduction + fp-bracket end
	CHECK(!l.node_masked && !l.node_wide);
	CHECK_EQ(l.node_op, 0u);
	CHECK_EQ(l.node_vlmax, vlmax);
	// The guard must be the strong LLVM kind: it is what proves vl == VLMAX, so that the fold
	// length below is the architectural one and a vl == 0 execution cannot reach this body.
	CHECK_EQ(l.guard_kind,
		 (unsigned)qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	// ONE constrained add per element, and NOT a reduce intrinsic (which could carry neither
	// round.dynamic nor fpexcept.strict, and whose unordered form is a different function).
	CHECK_EQ(l.fadds, vlmax);
	CHECK_EQ(l.reduce_intrinsics, 0u);
	// THE ORDERING ITSELF: seed -> e0 -> e1 -> ... as one dependence chain.
	CHECK(l.single_chain);
	CHECK_EQ(l.chain_len, vlmax);
	printf("    ok  %u ordered constrained.fadd in ONE chain, no reduce intrinsic\n", vlmax);
}

void CheckOrderedReductionRefusals(u32 vlen)
{
	printf("[S23] VLEN=%u refusals -- everything outside the envelope keeps the helper\n", vlen);
	struct Case { char const *what; u32 word; };
	Case const cases[] = {
	    {"masked vfredosum.vs (vm=0)", VRed(F6_VFREDOSUM, 9, 11, 11, /*unmasked=*/false)},
	    {"vfredmin.vs (a different function)", VRed(F6_VFREDMIN, 9, 11, 11)},
	    {"vfwredosum.vs (widening)", VRed(F6_VFWREDOSUM, 9, 11, 11)},
	};
	for (auto const &c : cases) {
		std::vector<u32> const w{Vsetvli(kVT_E32M1), c.word, kJalr};
		auto const l = BuildRed(w, vlen);
		printf("    case: %s\n", c.what);
		CHECK(l.frames == 0 && l.red_nodes == 0 && l.fadds == 0);
	}
	// The switch alone decides; an umbrella must not resurrect it.
	{
		std::vector<u32> const w{Vsetvli(kVT_E32M1), VRed(F6_VFREDOSUM, 9, 11, 11), kJalr};
		auto const l = BuildRed(w, vlen, /*route_on=*/false);
		// --rvv-qcg-typed-chunk-fredosum=0 leaves the route off.
		CHECK(l.frames == 0 && l.red_nodes == 0);
	}
	// vfredusum (funct6=1) is admitted too: an ordered fold is a legal implementation of it.
	{
		std::vector<u32> const w{Vsetvli(kVT_E32M1), VRed(F6_VFREDUSUM, 9, 11, 11), kJalr};
		auto const l = BuildRed(w, vlen);
		// vfredusum.vs is admitted too: an ordered fold is a legal implementation of it.
		CHECK(l.frames == 1 && l.red_nodes == 1);
	}
}

// ---------------------------------------------------------------------------------------------
// [S21] W5F AOT REACHABILITY, AT THE SOURCE LEVEL.
//
// Every [S18]-[S20] check above sets `config::rvv_qcg_typed_chunk_fsqrt` BY HAND, so all of them
// pass on a build in which no command line can ever set it -- which is exactly the build W5F
// shipped. A lowering plus a gate makes the route reachable IN THIS PROCESS; an ARTIFACT needs an
// `elfaot` option that sets the flag and a `kRvvRouteContract` row that carries the parent's value
// to every background builder. This is the check T1c added for `vsub.vv` after the same defect, and
// it is why the same defect could recur here: it was never extended to the FP routes.
//
// RvvLLVMSqrtChunkAdmit reads THIS switch and no umbrella (rv32_qir.cpp), so a missing elfaot
// option is not a wrong default that another flag could override -- it is an unreachable route.
// A per-section "ok" line is a CLAIM about the checks just above it. Printing it unconditionally
// puts a green line next to a red one, which is how a reader concludes a failed gate passed.
void SectionOk(unsigned fails_before, char const *what)
{
	if (g_fail == fails_before)
		printf("  %s\n", what);
}

std::string ReadSourceFile(char const *rel)
{
	std::string const path = std::string(DBT_SOURCE_ROOT) + "/" + rel;
	std::ifstream f(path);
	if (!f) {
		printf("  FAIL cannot open %s\n", path.c_str());
		++g_fail;
		return {};
	}
	std::ostringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

void CheckSqrtAotPlumbing()
{
	printf("[S21] W5F AOT reachability (source-level):\n");

	unsigned before = g_fail;
	std::string const aot = ReadSourceFile("dbt/elfaot.cpp");
	CHECK(aot.find("\"rvv-qcg-typed-chunk-fsqrt\"") != std::string::npos);
	CHECK(aot.find("dbt::config::rvv_qcg_typed_chunk_fsqrt = opts.rvv_qcg_typed_chunk_fsqrt;") !=
	      std::string::npos);
	// AUDIT-ONLY, AND NOT elfaot's. The force-emit switch bypasses the host AVX-512F/BMI2
	// admission check; an artifact built with it SIGILLs wherever those features are absent, so
	// elfaot must not offer it and no contract may hand it to a builder.
	CHECK(aot.find("\"rvv-qcg-typed-chunk-fsqrt-force-emit\"") == std::string::npos);
	SectionOk(before, "elfaot: --rvv-qcg-typed-chunk-fsqrt declared and assigned; force-emit absent");

	before = g_fail;
	std::string const boot = ReadSourceFile("dbt/aot/aot_boot.cpp");
	auto const tbl = boot.find("kRvvRouteContract[]");
	CHECK(tbl != std::string::npos);
	auto const tbl_end = boot.find("};", tbl);
	CHECK(tbl_end != std::string::npos);
	if (tbl != std::string::npos && tbl_end != std::string::npos) {
		std::string const body = boot.substr(tbl, tbl_end - tbl);
		CHECK(body.find("\"rvv-qcg-typed-chunk-fsqrt\"") != std::string::npos);
		CHECK(body.find("&config::rvv_qcg_typed_chunk_fsqrt") != std::string::npos);
		// The QUOTED spelling is a row; the bare one in the comment beside it is documentation
		// of why the bypass is excluded. Matching the bare form failed on that comment, which is
		// the G9e distinction ("a name in prose is not a second copy of the option") applied here.
		CHECK(body.find("\"rvv-qcg-typed-chunk-fsqrt-force-emit\"") == std::string::npos);
	}
	SectionOk(before, "aot_boot: kRvvRouteContract carries the flag to every spawn site");

	before = g_fail;
	std::string const audit = ReadSourceFile("scripts/vlen_propagation_audit.py");
	CHECK(audit.find("(\"rvv-qcg-typed-chunk-fsqrt\", \"rvv_qcg_typed_chunk_fsqrt\", \"Route\")") !=
	      std::string::npos);
	SectionOk(before, "vlen_propagation_audit.py: ROUTE_FLAGS mirror updated in lockstep");

	// The gate's own text, so a future edit that quietly adds an umbrella fallback -- which would
	// make `--rvv-qcg-typed-chunk-fsqrt=0` a no-op, the thing its comment says it must not be --
	// shows up here rather than as a route that cannot be turned off.
	before = g_fail;
	std::string const qir = ReadSourceFile("dbt/guest/rv32_qir.cpp");
	auto const admit = qir.find("RV32Translator::RvvLLVMSqrtChunkAdmit");
	CHECK(admit != std::string::npos);
	if (admit != std::string::npos) {
		std::string const body = qir.substr(admit, 2000);
		CHECK(body.find("if (!config::rvv_qcg_typed_chunk_fsqrt)") != std::string::npos);
		CHECK(body.find("config::rvv_qcg_typed_chunk ||") == std::string::npos);
	}
	SectionOk(before, "rv32_qir: the gate still reads its own switch alone, with no umbrella fallback");
}

} // namespace

int main()
{
	for (u32 vlen : {512u, 1024u}) {
		for (u32 vt : {kVT_E32M1, kVT_E32M2, kVT_E64M1, kVT_E64M2})
			CheckUnknownEntry(vlen, vt);
		CheckNoCandidate(vlen);
		CheckRegisterVsetvlInvalidates(vlen);
		CheckQcgUnchanged(vlen);
		CheckQcgIntegerInvariance(vlen);
		for (auto kind : {Fused::FmaOnly, Fused::AluFma})
			for (u32 vt : {kVT_E32M1, kVT_E64M2})
				CheckUnknownEntryFused(vlen, vt, kind);
		CheckFusedFlagOff(vlen);
		CheckFlagOff(vlen, /*falu_on=*/false, /*run_on=*/true, "--rvv-qcg-typed-chunk-falu off");
		CheckFlagOff(vlen, /*falu_on=*/true, /*run_on=*/false, "--rvv-vector-run off");
	}
	// W5C: the same capability across the five widths W5 admits.
	unsigned lmul2_formed = 0;
	for (u32 vlen : FIVE_WIDTHS) {
		for (auto kind : {FpKind::Alu, FpKind::FmaOnly, FpKind::Mixed})
			for (u32 vt : {kVT_E32M1, kVT_E64M1})
				CheckFiveWidthCandidate(vlen, vt, kind);
		CheckLmul2Capacity(vlen, &lmul2_formed);
		CheckWidthExtras(vlen);
	}
	// NON-VACUITY FOR [S10b]: its two-sided rows would all pass on a build that cut every LMUL=2
	// run. At VLEN 512 an e32,m2 member is two chunks and three groups is six, which no bound in
	// this substrate refuses, so both fixtures must have formed a run there.
	CHECK_EQ(lmul2_formed, 2u);
	// W5D: standalone `.vv` coverage where Family A does not admit.
	for (u32 vlen : FIVE_WIDTHS) {
		for (u32 vt : {kVT_E32M1, kVT_E64M1, kVT_E32M2})
			CheckStandaloneVv(vlen, vt);
		CheckStandaloneRefusals(vlen);
		CheckStandaloneUnknownEntry(vlen);
		CheckStandaloneFlagsAndQcg(vlen);
		CheckMixedFamilyASequence(vlen);
		for (u32 vt : {kVT_E32M1, kVT_E64M1, kVT_E32M2})
			CheckStandaloneFma(vlen, vt);
		CheckStandaloneFmaNoCandidate(vlen);
		CheckStandaloneFmaFlags(vlen);
		CheckFmaMixedBoundary(vlen);
		for (u32 vt : {kVT_E32M1, kVT_E64M1, kVT_E32M2})
			CheckSqrt(vlen, vt);
		CheckSqrtRefusals(vlen);
		CheckSqrtBoundary(vlen);
	}
	CheckCandidateCapacity();
	CheckCandidateRefusedWidth();
	for (u32 vlen : FIVE_WIDTHS) {
		for (u32 vt : {kVT_E32M1, kVT_E64M1, kVT_E32M2})
			CheckOrderedReduction(vlen, vt);
		CheckOrderedReductionRefusals(vlen);
	}
	CheckSqrtAotPlumbing();
	printf(g_fail ? "FAIL (%u failures)\n" : "PASS (%u failures)\n", g_fail);
	return g_fail ? 1 : 0;
}
