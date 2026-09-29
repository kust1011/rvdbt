// F1/F2 (2026-09-16). THE LLVM/AOT TYPED FP FRAME: what a full-VL, unmasked, register-only
// floating-point SEQUENCE actually lowers to, in BOTH operand forms -- `.vv` (OPFVV, F1) and
// `.vf` (OPFVF, F2).
//
// F2 exists because Livermore kernel 1's hot loop is `.vf`, not `.vv`: a loop-invariant scalar
// multiplied into a vector and added. The two forms are driven through the SAME three-member
// fixture shape so they differ in exactly one factor -- where source 1 comes from -- and every
// assertion below is evaluated for both, at e32 and e64, at VLEN 512 and 1024.
//
// WHY THIS FILE EXISTS, NEXT TO rvv_llvm_falu_family_test.cpp
//
// That file covers the P-vector-SSA family: one `InstRVVFALU` per guest instruction, each with its
// OWN runtime guard and its own helper fallback arm. It already establishes that the ARITHMETIC is
// right -- the four funct6 map to four distinct constrained intrinsics, carrying round.dynamic and
// fpexcept.strict, with canonical-NaN selects and the encoding's operand order.
//
// F1 does NOT change that arithmetic and does not claim to. What it adds is the FRAME: several
// admitted FP instructions inside ONE `rvvtypedchunkbegin`, so the vtype/vl/vstart/frm guard is
// tested ONCE for the whole sequence instead of once per instruction, and the guard-miss path is a
// single ordered fallback that replays every member. Keeping intermediate values in SSA is NOT the
// new property -- the P-vector-SSA family already does that through the translator's chunk-value
// cache -- so this file asserts the SHARED GUARD directly (exactly one frame, exactly one guard
// comparison set, exactly one FP bracket pair for three guest instructions) and does not pretend
// the residency is novel.
//
// WHAT IS ASSERTED
//
//   [1] THE FRAME. The three FP instructions form exactly ONE typed frame with n_members == 3, and
//       its guard kind is VTypeVlVstartFrmRNE -- the FULL-VL kind. This is the one that matters:
//       on QCG an all-FP run takes VTypePartialVlVstartFrmRNE (`vl <= VLMAX`), because the QCG FP
//       body masks every lane from the live vl. This backend's body has no mask at all, so the
//       frame must carry the stronger kind or the emitted code would compute tail elements.
//   [2] THE GUARD IS SHARED AND IS THE RIGHT ONE. The fast arm is reached by exactly one
//       conditional branch; the guard compares `vl` with `==` (never `<=`) and contains the
//       `fcsr & 0xe0 == 0` frm-is-RNE test.
//   [3] THE ARITHMETIC. `active_chunks * 3` constrained calls in the fast arm, one per member per
//       chunk, with the three intended -- and mutually distinct -- intrinsic IDs, matched by
//       `llvm::Intrinsic::ID` off the callee and never by parsing a name.
//   [4] THE FP ENVIRONMENT. Every constrained call carries `round.dynamic` + `fpexcept.strict` and
//       the `strictfp` call-site attribute; the enclosing function carries `strictfp`; exactly one
//       stmxcsr/ldmxcsr bracket pair surrounds the body (the conditional fold of an inherited
//       bracket adds a second close, which is asserted for separately in [8]); `vec.vstart` is
//       stored 0 exactly once on the fast path; a canonical-NaN select follows every member.
//   [5] OPERAND ORDER IS THE ENCODING'S. The sequence's third member is the non-commutative
//       subtract -- `vfsub.vv v12, v8, v13` or `vfsub.vf v12, v8, f13`. Its vs2 is the SSA value
//       the second member produced; its source 1 is a CPUState load (`.vv`) or the frame-scope
//       splat (`.vf`). A swapped pair flips both, which is checked directly -- and which a
//       commutative member could never reveal. This is also why admission refuses vfrsub/vfrdiv:
//       those ARE the reversed forms, and one operand-binding rule cannot serve both.
//   [6] NO HELPER IN THE FAST ARM, and the ORDERED fallback: three non-intrinsic calls in the
//       fallback block, in guest order, each preceded by a store of its own guest PC.
//   [7] QIR AND LLVM AGREE ON THE SHAPE. `n_typed` is consumed exactly (any mismatch is a Panic in
//       Emit_rvvtypedchunkend, so reaching the end of Run() at all is the assertion), and the
//       declared member count equals the number of fallback calls.
//   [8] THE INHERITED-BRACKET FOLD IS PRESENT. `fround_run_open` is shared state that a preceding
//       scalar-FP helper can leave true inside a translated block (nothing closes it there --
//       TbExitCloseOpenFroundRun is interpreter-only), so the frame's bracket opens with a
//       conditional close. Asserted as: the fast arm loads `fround_run_open` and branches on it
//       before the first stmxcsr.
//  [11] F2: THE FRAME-SCOPE BROADCASTS, COUNTED -- one per DISTINCT live-in F register (the
//       fixture uses three distinct ones so the count is not confusable with members x chunks),
//       and NONE at all in the `.vv` form.
//  [12] F2: THE e32 NaN-BOX -- `select (icmp eq i32 %hi, -1), %lo, 0x7fc00000` in every `.vf`
//       broadcast at SEW=32, and no such select at SEW=64, where the doubleword IS the operand.
//   [9] FALSIFIABILITY / FLAG-OFF. With `--rvv-qcg-typed-chunk-falu` off, and with
//       `--rvv-vector-run` off, the same guest words build NO multi-member FP frame at all and the
//       instructions keep their pre-F1 per-instruction route. Without this row, [1]..[8] would all
//       still pass if the gate were stuck on.
//
// [10] is asserted by construction rather than by a check: every Panic named in the F1 comments
//      (a masked member, a shared opmask, a partial-VL guard kind, a non-64-byte chunk) aborts the
//      process, so a build in which any of them were reachable from this fixture could not print
//      PASS.
//
// WHAT THIS FILE DOES NOT DO
//
//   * It changes no semantics and no admission predicate; it reads the IR the real translator and
//     the real backend produce.
//   * It never runs the code it builds. No object file is emitted and no PROT_EXEC page exists in
//     this process, so it needs no AVX-512 host and executes no vector instruction of any width.
//   * It times nothing and makes no performance claim, and it does not establish FP, RVV or
//     M1/M2 LLVM equivalence -- only that this one admitted shape lowers to what is described here.
//
// PIPELINE, and it is the real one:
//     guest words -> qir::CompilerGenRegionIR (dbt/qmc/compile.cpp, the real RV32Translator)
//                 -> qir::QIRToLLVM::Run     (dbt/qmc/llvmgen/llvmgen.cpp, the real backend)
// The IR inspected is what `QIRToLLVM` produced, before any LLVM optimisation pass.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector_lower.h" // VF6_* funct6 constants, shared with the semantics
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/CFG.h" // llvm::predecessors
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IntrinsicsX86.h" // x86_sse_{st,ld}mxcsr, the bracket's two intrinsics
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

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

// THE FIXTURE, HAND-ENCODED SO THE TEST OWNS ITS OWN INPUT.
//
//   [0] vsetvli a0, a0, e{32,64}, m1, ta, ma
//   [1] vfadd.vv v8,  v9, v10     -- vd is read by [2], so it is NOT a frame live-out of [1]
//   [2] vfmul.vv v8,  v8, v11     -- consumes [1]'s value; vd == vs2, a legal overlap
//   [3] vfsub.vv v12, v8, v13     -- NON-COMMUTATIVE, vs2 is [2]'s SSA value, vs1 a CPUState load
//   [4] jalr x0, x1, 0
//
// The register choice is not arbitrary. [2]'s `vd == vs2` exercises the overlap the frame's
// load-major/publish-after-read rule exists for, and [3] is the only member whose operand order is
// observable: `v12 = v8 - v13` and `v12 = v13 - v8` are different functions.
// F2 (2026-09-16) ADDS THE SECOND FORM, with the SAME three-member shape so the two runs differ in
// exactly one factor -- where source 1 comes from:
//
//   [1] vfadd.vf v8,  v9, f10
//   [2] vfmul.vf v8,  v8, f11     -- vd == vs2, the same legal overlap as the `.vv` fixture
//   [3] vfsub.vf v12, v8, f13     -- NON-COMMUTATIVE; vs2 is [2]'s SSA value, source 1 a SPLAT
//
// THREE DISTINCT F REGISTERS on purpose: the frame must emit one `vchunkfbroadcast` per DISTINCT
// live-in F register, so a lowering that emitted one per member (3, coincidentally equal here) or
// one per member per chunk (3*k, not equal at VLEN 1024) is separated by the counted assertion.
// Livermore k1's hot loop is exactly this shape -- `vfmul.vf` + `vfadd.vf` over a loop-invariant
// scalar -- which is why this form is the one being added.
constexpr u32 kVsetvliE32 = 0x0d057557u; // zimm = 0xd0: e32, m1, ta, ma
constexpr u32 kVsetvliE64 = 0x0d857557u; // zimm = 0xd8: e64, m1, ta, ma
constexpr u32 kVfaddVV = 0x02951457u;	 // funct3 001, funct6 000000, vm=1, vs2=9, vs1=10, vd=8
constexpr u32 kVfmulVV = 0x92859457u;	 // funct3 001, funct6 100100, vm=1, vs2=8, vs1=11, vd=8
constexpr u32 kVfsubVV = 0x0a869657u;	 // funct3 001, funct6 000010, vm=1, vs2=8, vs1=13, vd=12
constexpr u32 kVfaddVF = 0x02955457u;	 // funct3 101, funct6 000000, vm=1, vs2=9, rs1=f10, vd=8
constexpr u32 kVfmulVF = 0x9285d457u;	 // funct3 101, funct6 100100, vm=1, vs2=8, rs1=f11, vd=8
constexpr u32 kVfsubVF = 0x0a86d657u;	 // funct3 101, funct6 000010, vm=1, vs2=8, rs1=f13, vd=12
constexpr u32 kJalr = 0x00008067u;

// Which operand form a fixture drives. The ONLY thing it changes about the expected lowering is
// where source 1 comes from and how many frame-scope broadcasts exist.
enum class Form { VV, VF };
char const *FormName(Form f) { return f == Form::VV ? ".vv" : ".vf"; }

// The order the members must appear in, as intrinsic IDs. Distinctness is part of the assertion:
// a map that returned one intrinsic for all three would satisfy every structural check here.
llvm::Intrinsic::ID const kExpected[3] = {
    llvm::Intrinsic::experimental_constrained_fadd,
    llvm::Intrinsic::experimental_constrained_fmul,
    llvm::Intrinsic::experimental_constrained_fsub,
};

char const *MDStr(llvm::Value *v)
{
	auto *mav = llvm::dyn_cast<llvm::MetadataAsValue>(v);
	if (!mav)
		return "";
	auto *ms = llvm::dyn_cast<llvm::MDString>(mav->getMetadata());
	return ms ? ms->getString().data() : "";
}

void ConfigureCommon(u32 vlen, bool falu_on, bool run_on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_vector_ssa = true;
	config::rvv_vector_run = run_on;
	config::rvv_qcg_typed_chunk_falu = falu_on;
	// F3: the FUSED route's own switch, held OFF here so every FALU check runs with the fused
	// family unavailable and each FMA check turns it on for itself. The two are independently
	// ablatable by design -- neither reads the other, and neither reads the umbrella.
	config::rvv_qcg_typed_chunk_fma = false;
	// THE UMBRELLA IS DELIBERATELY LEFT ON, AND THAT IS AN ASSERTION RATHER THAN A DEFAULT.
	// `rvv_qcg_typed_chunk` is the generic typed-chunk base switch and it DEFAULTS TO TRUE
	// (config.h). The QCG FALU twin reads `rvv_qcg_typed_chunk || rvv_qcg_typed_chunk_falu`, which
	// would make `--rvv-qcg-typed-chunk-falu=0` a no-op; RvvLLVMFaluChunkAdmit deliberately reads
	// the per-route switch ALONE, exactly as every integer LLVM route reads only its own. Setting
	// the umbrella explicitly here means the `falu_on=false` rows below prove that independence
	// instead of merely not exercising it: if the gate ever grew an umbrella term, those rows
	// would start finding a frame and fail.
	config::rvv_qcg_typed_chunk = true;
	// Every body-mode and policy switch this route refuses, held at its default so the fixture
	// exercises the shipped arm. RvvTranslateVectorRun refuses an FP run if any of them is on,
	// which is a separate (and deliberately untested-here) behaviour.
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

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x1000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};

	Built(u32 vsetvli, Form form) : module("fp_run", g_llvm_ctx)
	{
		words = form == Form::VV
			    ? std::vector<u32>{vsetvli, kVfaddVV, kVfmulVV, kVfsubVV, kJalr}
			    : std::vector<u32>{vsetvli, kVfaddVF, kVfmulVF, kVfsubVF, kJalr};
	}
	// F2: the explicit-word form, for the encoding-level refusals and the mixed-form run below.
	Built(std::vector<u32> w) : words(std::move(w)), module("fp_run", g_llvm_ctx) {}
};

// One build of the fixture. Returns the frame's member count (0 if no multi-member FP frame was
// built) through `n_members`, and leaves the emitted function in `fn`.
//
// `run_backend` is false for the pure-QCG contrast below, which inspects the QIR only: that path
// builds a frame with a guard kind this backend deliberately has no lowering for, so handing it to
// QIRToLLVM would abort the process -- which is the fail-closed behaviour under test, not a way to
// observe it.
void Build(Built &b, unsigned &n_members, unsigned &frames, unsigned &guard_kind,
	   bool run_backend = true)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	frames = 0;
	n_members = 0;
	guard_kind = ~0u;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_rvvtypedchunkbegin)
				continue;
			auto *begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
			if (begin->n_members < 2)
				continue;
			++frames;
			n_members = begin->n_members;
			guard_kind = (unsigned)begin->guard_kind;
		}
	}
	if (!run_backend)
		return;
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

// [1-CONTRAST] THE SAME THREE GUEST INSTRUCTIONS ON THE PURE-QCG BACKEND, and this is what makes
// [1]'s guard-kind assertion falsifiable rather than a restatement of whatever the code happens to
// produce.
//
// An all-FP run is `partial_vl_ok` (FP_LANE_PROOFS, rv32_vrun.cpp), so on QCG it takes
// GuardKind::VTypePartialVlVstartFrmRNE -- `vl <= VLMAX` -- and its body masks every lane from the
// live vl. F1 adds ONE term at the guard-kind decision so the LLVM backend, whose body has no mask,
// gets the strictly stronger VTypeVlVstartFrmRNE instead. If that term were deleted, this function
// and CheckAdmitted would report the SAME kind, so the pair of them is the test: the difference is
// asserted to exist, not just the LLVM value.
//
// The host-feature probe is bypassed with the route's own force-emit switch, because the QCG
// predicate checks the COMPILING host's CPUID for AVX-512F/BMI2 and this test must run on any host.
// Nothing is emitted or executed here; only the constructed QIR is read.
void CheckQcgContrast(u32 vlen, u8 sew, Form form)
{
	printf("[qcg-contrast] VLEN=%u SEW=%u %s\n", vlen, sew * 8, FormName(form));
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false; // QCG side-exit substrate, not the LLVM lowering gate
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	Built b(sew == 4 ? kVsetvliE32 : kVsetvliE64, form);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind, /*run_backend=*/false);
	config::rvv_qcg_typed_chunk_falu_force_emit = false;
	CHECK_EQ(frames, 1);
	CHECK_EQ(n_members, 3);
	CHECK_EQ(guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmRNE);
	CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl(
	    (InstRVVTypedChunkBegin::GuardKind)guard_kind));
}

void CheckAdmitted(u32 vlen, u8 sew, Form form)
{
	printf("[admitted] VLEN=%u SEW=%u %s\n", vlen, sew * 8, FormName(form));
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	Built b(sew == 4 ? kVsetvliE32 : kVsetvliE64, form);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);

	// [1] one frame, three members, the FULL-VL FP guard kind.
	CHECK_EQ(frames, 1);
	CHECK_EQ(n_members, 3);
	CHECK_EQ(guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
	    (InstRVVTypedChunkBegin::GuardKind)guard_kind));
	if (frames != 1 || n_members != 3)
		return; // every check below reads that frame; stop rather than cascade

	unsigned const chunks = vlen / 512;
	auto *fast = (llvm::BasicBlock *)nullptr;
	auto *slow = (llvm::BasicBlock *)nullptr;
	for (auto &bb : *b.fn) {
		if (bb.getName() == "rvv.tchunk.direct")
			fast = &bb;
		if (bb.getName() == "rvv.tchunk.fallback")
			slow = &bb;
	}
	CHECK(fast != nullptr);
	CHECK(slow != nullptr);
	if (!fast || !slow)
		return;

	// [2] ONE conditional branch reaches the fast arm, and its guard has the right shape.
	// `vl` is compared with EQ, never ULE (that would be the partial-VL kind), and the
	// frm-is-RNE test -- `(fcsr & 0xe0) == 0` -- is present.
	unsigned preds = 0, ule_cmps = 0, frm_rne_tests = 0;
	for (auto *pred : llvm::predecessors(fast))
		++preds, (void)pred;
	CHECK_EQ(preds, 1);
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(&ins);
			if (!cmp)
				continue;
			ule_cmps += cmp->getPredicate() == llvm::ICmpInst::ICMP_ULE;
			if (cmp->getPredicate() != llvm::ICmpInst::ICMP_EQ)
				continue;
			auto *rhs = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
			auto *band = llvm::dyn_cast<llvm::BinaryOperator>(cmp->getOperand(0));
			if (!rhs || !rhs->isZero() || !band ||
			    band->getOpcode() != llvm::Instruction::And)
				continue;
			auto *mask = llvm::dyn_cast<llvm::ConstantInt>(band->getOperand(1));
			frm_rne_tests += mask && mask->getZExtValue() == 0xe0u;
		}
	}
	CHECK_EQ(ule_cmps, 0);
	CHECK_EQ(frm_rne_tests, 1);

	// [3]/[4]/[5]/[6]: walk the frame's OWN blocks. The body spans three of them, because the
	// bracket's inherited-fold is a real branch: `rvv.tchunk.direct` -> {`rvv.tchunk.fp.fold`,
	// `rvv.tchunk.fp.fresh`} -> the rest of the body. Selecting by name rather than by "everything
	// that is not the fallback" matters: the region also contains the vsetvli's helper call and
	// the terminating jalr's escape, and counting those as fast-arm helper calls would make [6]
	// meaningless. The expected count is asserted, so a body that grows a block fails here rather
	// than silently escaping the scan.
	auto is_frame_body = [](llvm::BasicBlock &bb) {
		auto n = bb.getName();
		return n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.");
	};
	unsigned body_blocks = 0;
	for (auto &bb : *b.fn)
		body_blocks += is_frame_body(bb);
	CHECK_EQ(body_blocks, 3);
	std::vector<llvm::CallInst *> constrained;
	unsigned fast_helper_calls = 0, stmxcsr = 0, ldmxcsr = 0, vstart_zero_stores = 0;
	unsigned nan_selects = 0, open_flag_loads = 0;
	bool func_strictfp = b.fn->hasFnAttribute(llvm::Attribute::StrictFP);
	u32 const vstart_off =
	    offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart);
	u32 const open_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_open);
	for (auto &bb : *b.fn) {
		if (!is_frame_body(bb))
			continue;
		for (auto &ins : bb) {
			if (auto *call = llvm::dyn_cast<llvm::CallInst>(&ins)) {
				auto *callee = call->getCalledFunction();
				if (!callee) {
					++fast_helper_calls; // indirect stub call
					continue;
				}
				auto id = callee->getIntrinsicID();
				if (id == llvm::Intrinsic::x86_sse_stmxcsr)
					++stmxcsr;
				else if (id == llvm::Intrinsic::x86_sse_ldmxcsr)
					++ldmxcsr;
				else if (id == llvm::Intrinsic::experimental_constrained_fadd ||
					 id == llvm::Intrinsic::experimental_constrained_fsub ||
					 id == llvm::Intrinsic::experimental_constrained_fmul ||
					 id == llvm::Intrinsic::experimental_constrained_fdiv)
					constrained.push_back(call);
				else if (!callee->isIntrinsic())
					++fast_helper_calls;
				continue;
			}
			if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
				// The canonical-NaN select: a vector select whose condition is an
				// unordered self-compare.
				auto *fc = llvm::dyn_cast<llvm::FCmpInst>(sel->getCondition());
				nan_selects += fc && fc->getPredicate() == llvm::FCmpInst::FCMP_UNO &&
					       fc->getOperand(0) == fc->getOperand(1);
				continue;
			}
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				auto *v = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand());
				auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(
				    st->getPointerOperand());
				if (!v || !v->isZero() || !gep || gep->getNumIndices() != 1)
					continue;
				auto *idx = llvm::dyn_cast<llvm::ConstantInt>(
				    gep->getOperand(gep->getNumOperands() - 1));
				vstart_zero_stores +=
				    idx && idx->getZExtValue() == vstart_off && v->getBitWidth() == 32;
				continue;
			}
			if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(
				    ld->getPointerOperand());
				if (!gep || gep->getNumIndices() != 1)
					continue;
				auto *idx = llvm::dyn_cast<llvm::ConstantInt>(
				    gep->getOperand(gep->getNumOperands() - 1));
				open_flag_loads += idx && idx->getZExtValue() == open_off;
			}
		}
	}

	// [3] one call per member per chunk, in guest order, with the three intended IDs.
	CHECK_EQ(constrained.size(), 3u * chunks);
	if (constrained.size() == 3u * chunks) {
		for (unsigned m = 0; m < 3; ++m)
			for (unsigned c = 0; c < chunks; ++c) {
				auto *call = constrained[m * chunks + c];
				CHECK_EQ((unsigned)call->getCalledFunction()->getIntrinsicID(),
					 (unsigned)kExpected[m]);
				// [4] the FP environment metadata and the strictfp call attribute.
				CHECK(std::string(MDStr(call->getArgOperand(2))) == "round.dynamic");
				CHECK(std::string(MDStr(call->getArgOperand(3))) ==
				      "fpexcept.strict");
				// THE CALL SITE'S OWN ATTRIBUTE, read off its AttributeList.
				// `CallBase::hasFnAttr` would be VACUOUS here: it falls back to
				// the CALLEE's attributes, and every constrained intrinsic
				// DECLARATION already carries `strictfp`, so it returns true
				// whether or not this backend set anything. Mutation-checked:
				// deleting the `addFnAttr` call passes with `hasFnAttr` and
				// fails with this.
				CHECK(call->getAttributes().hasFnAttr(llvm::Attribute::StrictFP));
				// the lane type follows SEW, not a literal
				auto *vty = llvm::dyn_cast<llvm::FixedVectorType>(call->getType());
				CHECK(vty != nullptr);
				if (vty) {
					CHECK_EQ(vty->getNumElements(), 64u / sew);
					CHECK(sew == 4 ? vty->getElementType()->isFloatTy()
						       : vty->getElementType()->isDoubleTy());
				}
			}
	}
	CHECK_EQ((unsigned)kExpected[0] != (unsigned)kExpected[1] &&
		     (unsigned)kExpected[1] != (unsigned)kExpected[2] &&
		     (unsigned)kExpected[0] != (unsigned)kExpected[2],
		 1);
	CHECK(func_strictfp);

	// [4] exactly one bracket pair around the body, plus the conditional fold's extra close.
	// open  : 1 stmxcsr + 1 ldmxcsr     (RvvFpBracketOpenBody)
	// fold  : 1 stmxcsr + 1 ldmxcsr     (RvvFpBracketCloseBody, on the inherited-bracket arm)
	// close : 1 stmxcsr + 1 ldmxcsr     (RvvFpBracketCloseBody, at the frame epilogue)
	CHECK_EQ(stmxcsr, 3);
	CHECK_EQ(ldmxcsr, 3);
	// [8] THE INHERITED-BRACKET FOLD, asserted as the exact test it must be rather than as "a
	// branch exists". The frame's bracket must open with `if (fround_run_open) <close>` -- see
	// Emit_rvvqcgfpbegin for why that is load-bearing and not defensive. Checked as: exactly one
	// LOAD of the `fround_run_open` byte in the body (the close body only STORES it), and that
	// load feeds an `icmp ne i8 %open, 0` whose true edge is the fold block.
	CHECK_EQ(open_flag_loads, 1);
	{
		unsigned folds = 0;
		for (auto &bb : *b.fn) {
			if (!is_frame_body(bb))
				continue;
			auto *br = llvm::dyn_cast<llvm::BranchInst>(bb.getTerminator());
			if (!br || !br->isConditional())
				continue;
			auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(br->getCondition());
			if (!cmp || cmp->getPredicate() != llvm::ICmpInst::ICMP_NE)
				continue;
			auto *lhs = llvm::dyn_cast<llvm::LoadInst>(cmp->getOperand(0));
			auto *rhs = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
			if (!lhs || !lhs->getType()->isIntegerTy(8) || !rhs || !rhs->isZero())
				continue;
			auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(lhs->getPointerOperand());
			if (!gep || gep->getNumIndices() != 1)
				continue;
			auto *idx = llvm::dyn_cast<llvm::ConstantInt>(
			    gep->getOperand(gep->getNumOperands() - 1));
			if (!idx || idx->getZExtValue() != open_off)
				continue;
			folds += br->getSuccessor(0)->getName() == "rvv.tchunk.fp.fold";
		}
		CHECK_EQ(folds, 1);
	}
	// [4] vstart is cleared once, by the frame epilogue.
	CHECK_EQ(vstart_zero_stores, 1);
	// [4] one canonical-NaN select per member per chunk.
	CHECK_EQ(nan_selects, 3u * chunks);
	// [6] no helper in the fast arm.
	CHECK_EQ(fast_helper_calls, 0);

	// [5] OPERAND ORDER on the NON-COMMUTATIVE member, in both forms.
	//
	//   `.vv`: `vfsub.vv v12, v8, v13` must call fsub(<v8 chunk>, <v13 chunk>). v8's chunk here is
	//          the vfmul's RESULT -- a value produced inside the frame -- while v13's is a fresh
	//          CPUState load. Argument 0 must NOT trace back to a LoadInst and argument 1 must.
	//   `.vf`: `vfsub.vf v12, v8, f13` must call fsub(<v8 chunk>, <splat of f13>), which is the
	//          SAME rule -- RVV defines `vfsub.vf` as `vd[i] = vs2[i] - f[rs1]`, not the reverse
	//          (that is `vfrsub.vf`, which admission refuses). Argument 1 must be the frame-scope
	//          SPLAT, i.e. a shufflevector, and argument 0 still the frame's own SSA value.
	//
	// A swap flips both operands in either form, so this is a real two-sided check and not a
	// property a commutative member could satisfy by accident.
	if (constrained.size() == 3u * chunks) {
		for (unsigned c = 0; c < chunks; ++c) {
			auto *sub = constrained[2 * chunks + c];
			auto *a = sub->getArgOperand(0), *bb_ = sub->getArgOperand(1);
			auto strip = [](llvm::Value *v) -> llvm::Value * {
				while (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(v))
					v = bc->getOperand(0);
				return v;
			};
			if (form == Form::VV)
				CHECK(llvm::isa<llvm::LoadInst>(strip(bb_))); // vs1 = v13, CPUState
			else
				CHECK(llvm::isa<llvm::ShuffleVectorInst>(strip(bb_))); // splat of f13
			CHECK(!llvm::isa<llvm::LoadInst>(strip(a)));	 // vs2 = v8, the frame's SSA
			CHECK(llvm::isa<llvm::SelectInst>(strip(a)));	 // ... the vfmul's canon select
		}
	}

	// [11] F2: THE FRAME-SCOPE BROADCASTS, COUNTED. One per DISTINCT live-in F register and not
	// one per member or per chunk -- the fixture uses three distinct F registers precisely so that
	// "3" here is not also the member count times anything at VLEN 1024 (where k == 2).
	//
	// Counted as `shufflevector` instructions in the frame body, which is what `CreateVectorSplat`
	// produces (insertelement into poison, then a zeroinitializer shuffle) and which nothing else
	// in this body emits. The `.vv` form must have NONE: a broadcast there would mean a scalar
	// read the encoding never asked for.
	{
		unsigned splats = 0;
		for (auto &bb : *b.fn) {
			if (!is_frame_body(bb))
				continue;
			for (auto &ins : bb)
				splats += llvm::isa<llvm::ShuffleVectorInst>(&ins);
		}
		CHECK_EQ(splats, form == Form::VV ? 0u : 3u);
	}

	// [12] F2: THE e32 NaN-BOX, AND ITS ABSENCE AT e64. An RV32D F register holds an f32 boxed in
	// the upper 32 bits; an unboxed value must read as the canonical quiet NaN. So at SEW=32 each
	// broadcast must contain `select (icmp eq i32 %hi, -1), %lo, 0x7fc00000`, and at SEW=64 there
	// must be no such select at all -- the doubleword IS the operand. Checked on the constant, so
	// a lowering that boxed with the wrong sentinel or substituted the wrong NaN fails.
	{
		unsigned boxes = 0;
		for (auto &bb : *b.fn) {
			if (!is_frame_body(bb))
				continue;
			for (auto &ins : bb) {
				auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins);
				if (!sel || !sel->getType()->isIntegerTy(32))
					continue;
				auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
				auto *fv = llvm::dyn_cast<llvm::ConstantInt>(sel->getFalseValue());
				if (!cmp || cmp->getPredicate() != llvm::ICmpInst::ICMP_EQ || !fv)
					continue;
				auto *sentinel = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
				boxes += sentinel && sentinel->getZExtValue() == 0xffffffffu &&
					 fv->getZExtValue() == rv32::F32_CANONICAL_NAN;
			}
		}
		CHECK_EQ(boxes, (form == Form::VF && sew == 4) ? 3u : 0u);
	}

	// [6]/[7] the ORDERED fallback: three helper calls, in guest order, each preceded by a store
	// of its own guest PC.
	unsigned fallback_calls = 0;
	llvm::ConstantInt *last_pc = nullptr;
	for (auto &ins : *slow) {
		if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
			if (auto *v = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand()))
				last_pc = v;
			continue;
		}
		auto *call = llvm::dyn_cast<llvm::CallBase>(&ins);
		if (!call)
			continue;
		auto *callee = call->getCalledFunction();
		if (callee && callee->isIntrinsic())
			continue;
		unsigned const member = fallback_calls++;
		if (member >= 3)
			continue;
		auto *raw = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
		CHECK(raw != nullptr);
		CHECK_EQ(raw ? raw->getZExtValue() : 0u, b.words[member + 1]);
		CHECK(last_pc != nullptr);
		CHECK_EQ(last_pc ? last_pc->getZExtValue() : ~0ull, 4ull * (member + 1));
	}
	CHECK_EQ(fallback_calls, 3);
	CHECK_EQ(fallback_calls, n_members);

	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// [9] THE FALSIFIABILITY ROW. Without it every assertion above would still pass in a build whose
// gate was stuck on, which is exactly the failure mode this project has recorded before.
void CheckRefused(u32 vlen, u8 sew, Form form, bool falu_on, bool run_on, char const *what)
{
	printf("[refused] VLEN=%u SEW=%u %s %s\n", vlen, sew * 8, FormName(form), what);
	ConfigureCommon(vlen, falu_on, run_on);
	Built b(sew == 4 ? kVsetvliE32 : kVsetvliE64, form);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	// No multi-member RUN frame: neither switch leaves one standing.
	CHECK_EQ(frames, 0);
	// F5 REFINED THIS ASSERTION, and the refinement is a real behaviour change rather than an
	// accommodation. It used to read `!hasFnAttribute(StrictFP)` unconditionally, on the argument
	// that with no F1 run frame the three instructions all reach the P-vector-SSA arm, whose calls
	// are built inline and never set the attribute. That argument is still exactly right for
	// `.vv`. It is NOT right for `.vf` with only `--rvv-vector-run` off: F5 gives every OPFVF
	// instruction a STANDALONE typed frame, which needs no run at all, so three of them are built
	// and the function legitimately carries `strictfp`.
	//
	// So the check now ties the attribute to what was actually built. It still says everything the
	// old one said -- in every configuration where NO typed frame exists the attribute is absent,
	// which is the "F1/F2/F3 changed nothing for the older family" claim -- and it additionally
	// pins F5's own effect: turning `--rvv-vector-run` off no longer disables the `.vf` route.
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
	printf("    typed_frames=%u strictfp=%d\n", typed_frames,
	       (int)b.fn->hasFnAttribute(llvm::Attribute::StrictFP));
	CHECK_EQ(b.fn->hasFnAttribute(llvm::Attribute::StrictFP), typed_frames != 0);
	// The one configuration F5 is expected to change, stated as a value rather than left implicit:
	// `.vf` with the route on and only the run former off still gets one standalone frame per
	// instruction; every other combination here gets none.
	CHECK_EQ(typed_frames, (form == Form::VF && falu_on && !run_on) ? 3u : 0u);
	// And no typed FP lane op reached the backend -- if one had, Emit_vchunkfalu's preconditions
	// would have run outside a full-VL frame. Verify the function anyway.
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// F2. THE ENCODINGS THIS ROUTE MUST NOT TAKE, and why each is a real hazard rather than a gap:
//
//   vfrsub.vf   the REVERSED subtract, `vd[i] = f[rs1] - vs2[i]`. The frame binds i(0) = vs2 and
//               i(1) = the broadcast for every member, so admitting it would emit the subtraction
//               BACKWARDS -- structurally perfect IR computing the wrong value. This is the single
//               most dangerous encoding in the OPFVF group and the reason the funct6 row is a
//               predicate rather than "everything vfalu_supported admits for is_vf".
//   masked .vf  vm == 0 needs v0 folded into a lane mask; this body has none, so an inactive lane
//               would be computed and stored.
//
// Asserted as "no multi-member FP frame is built", i.e. the members keep the routes they had.
constexpr u32 kVfrsubVF_A = 0x9e955457u; // funct6 100111, vm=1, vs2=9, rs1=f10, vd=8
constexpr u32 kVfrsubVF_B = 0x9e85d457u; // funct6 100111, vm=1, vs2=8, rs1=f11, vd=8
constexpr u32 kVfaddVFMasked = kVfaddVF & ~(1u << 25);
constexpr u32 kVfmulVFMasked = kVfmulVF & ~(1u << 25);

void CheckRefusedEncoding(u32 vlen, u8 sew, std::vector<u32> const &body, char const *what)
{
	printf("[refused-encoding] VLEN=%u SEW=%u %s\n", vlen, sew * 8, what);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	std::vector<u32> words = {sew == 4 ? kVsetvliE32 : kVsetvliE64};
	words.insert(words.end(), body.begin(), body.end());
	words.push_back(kJalr);
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// F2. A RUN MAY MIX THE TWO FORMS, because the gate decides per MEMBER and both are RunOp::FAlu.
// This is the shape a real loop body has -- Livermore k1 alternates a `.vf` scale with a `.vv`
// combine -- so it is checked rather than assumed. One distinct F register means exactly one
// frame-scope broadcast however many `.vf` members name it, which is the property [11] states and
// which a per-member broadcast would break here (two `.vf` members, one splat).
void CheckMixedForms(u32 vlen, u8 sew)
{
	printf("[mixed] VLEN=%u SEW=%u .vf + .vv + .vf, one shared F register\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    0x92955457u, // vfmul.vf v8,  v9, f10 : funct3 101, funct6 100100, vm=1, vs2=9,  vd=8
	    0x02859457u, // vfadd.vv v8,  v8, v11 : funct3 001, funct6 000000, vm=1, vs2=8,  vd=8
	    0x0a855657u, // vfsub.vf v12, v8, f10 : funct3 101, funct6 000010, vm=1, vs2=8,  vd=12
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 1);
	CHECK_EQ(n_members, 3);
	CHECK_EQ(guard_kind, (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	if (frames != 1)
		return;
	unsigned splats = 0, helper_calls = 0, constrained = 0;
	for (auto &bb : *b.fn) {
		auto n = bb.getName();
		if (!(n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.")))
			continue;
		for (auto &ins : bb) {
			splats += llvm::isa<llvm::ShuffleVectorInst>(&ins);
			auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
			if (!call)
				continue;
			auto *callee = call->getCalledFunction();
			if (!callee) {
				++helper_calls;
				continue;
			}
			auto id = callee->getIntrinsicID();
			constrained += id == llvm::Intrinsic::experimental_constrained_fadd ||
				       id == llvm::Intrinsic::experimental_constrained_fsub ||
				       id == llvm::Intrinsic::experimental_constrained_fmul ||
				       id == llvm::Intrinsic::experimental_constrained_fdiv;
			helper_calls += !callee->isIntrinsic();
		}
	}
	CHECK_EQ(splats, 1);			     // ONE distinct F register -> ONE broadcast
	CHECK_EQ(constrained, 3u * (vlen / 512));    // three members, one call each per chunk
	CHECK_EQ(helper_calls, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// ---------------------------------------------------------------------------------------------
// F3 (2026-09-16). THE FUSED FAMILY.
//
// Eight funct6 values, two operand-role groups, and a sign on the product and/or the addend. What
// makes this family worth its own section is that EVERY one of the eight produces structurally
// identical IR -- one `llvm.experimental.constrained.fma` over three chunk values -- and differs
// only in WHICH value is which argument and which arguments are negated. A wrong row is therefore
// invisible to any count-based check and produces a perfectly plausible number.
//
// So this section decodes the emitted call's three arguments back to (guest register, negated?) and
// compares the triple against the table below, which is the SEMANTICS as rv32_vector_lower.h's
// helper computes them -- the same table QEmit::Emit_vchunkfma carries. `b` is vs1 (`.vv`) or the
// frame-scope F broadcast (`.vf`); `a` is vs2; `d` is the OLD vd.
//
//   vfmadd   fma( d, b,  a)      vfmacc   fma( b, a,  d)
//   vfnmadd  fma(-d, b, -a)      vfnmacc  fma(-b, a, -d)
//   vfmsub   fma( d, b, -a)      vfmsac   fma( b, a, -d)
//   vfnmsub  fma(-d, b,  a)      vfnmsac  fma(-b, a,  d)
//
// ONE NUANCE, STATED SO THE ASSERTION IS NOT OVERSOLD: arguments 0 and 1 are the two
// MULTIPLICANDS, and multiplication commutes, so exchanging JUST those two within a row is not
// semantically observable -- this file would flag it, and flagging it is a shape assertion (the
// emitted form is pinned to QEmit's table) rather than a correctness one. Everything else it checks
// IS semantic: which value is the ADDEND (argument 2) separates the two operand-role groups, and
// each negation flag decides the sign of a product or of an addend.
//
// SINGLE ROUNDING is asserted directly and negatively: the frame must contain `constrained.fma`
// and NO `constrained.fmul`, `constrained.fadd`, `constrained.fsub` or `constrained.fmuladd`. A
// mul+add decomposition rounds twice and is a different function from the helper's `std::fma`;
// `.fmuladd` is excluded too because LLVM is explicitly permitted to split that one.

enum class Role : u8 { D, B, A }; // the OLD vd, source 1 (vs1 or the .vf scalar), vs2

struct FmaRow {
	u32 funct6;
	char const *name;
	Role role[3];	 // which value is argument 0, 1, 2 of constrained.fma
	bool negated[3]; // and whether it is negated
};

constexpr FmaRow kFmaRows[8] = {
    {rv32::VF6_VFMADD,  "vfmadd",  {Role::D, Role::B, Role::A}, {false, false, false}},
    {rv32::VF6_VFNMADD, "vfnmadd", {Role::D, Role::B, Role::A}, {true,  false, true }},
    {rv32::VF6_VFMSUB,  "vfmsub",  {Role::D, Role::B, Role::A}, {false, false, true }},
    {rv32::VF6_VFNMSUB, "vfnmsub", {Role::D, Role::B, Role::A}, {true,  false, false}},
    {rv32::VF6_VFMACC,  "vfmacc",  {Role::B, Role::A, Role::D}, {false, false, false}},
    {rv32::VF6_VFNMACC, "vfnmacc", {Role::B, Role::A, Role::D}, {true,  false, true }},
    {rv32::VF6_VFMSAC,  "vfmsac",  {Role::B, Role::A, Role::D}, {false, false, true }},
    {rv32::VF6_VFNMSAC, "vfnmsac", {Role::B, Role::A, Role::D}, {true,  false, false}},
};

// The encodings are BUILT from their fields rather than hand-written as 16 hex literals: a typo in
// one of sixteen constants is exactly the kind of error this file exists to catch, and a literal
// cannot be checked by reading it.
constexpr u32 EncFp(u32 f6, bool vf, u32 vs2, u32 s1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (s1 << 15) | ((vf ? 0b101u : 0b001u) << 12) |
	       (vd << 7) | 0b1010111u;
}

u32 VregStateOffset(u32 reg)
{
	return (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) +
		     reg * rv32::VLEN_MAX_BYTES);
}

// Strip bitcasts, then one optional fneg, reporting whether it was there.
llvm::Value *StripToSource(llvm::Value *v, bool &negated)
{
	auto strip_casts = [](llvm::Value *x) {
		while (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(x))
			x = bc->getOperand(0);
		return x;
	};
	v = strip_casts(v);
	negated = false;
	if (auto *fn = llvm::dyn_cast<llvm::UnaryOperator>(v);
	    fn && fn->getOpcode() == llvm::Instruction::FNeg) {
		negated = true;
		v = strip_casts(fn->getOperand(0));
	}
	return v;
}

// If `v` is a CPUState load, return the byte offset it reads; otherwise ~0u.
u32 StateLoadOffset(llvm::Value *v)
{
	auto *ld = llvm::dyn_cast<llvm::LoadInst>(v);
	if (!ld)
		return ~0u;
	auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(ld->getPointerOperand());
	if (!gep || gep->getNumIndices() != 1)
		return ~0u;
	auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(gep->getNumOperands() - 1));
	return idx ? (u32)idx->getZExtValue() : ~0u;
}

// One admitted FUSED frame, for one funct6 and one operand form.
//
//   [1] <funct6>  vd=v8, source1 = v9 / f9, vs2 = v10   -- v8 is read AND written: the old-vd read
//   [2] vfmacc.vv vd=v12, vs1 = v8, vs2 = v11           -- consumes [1]'s result, keeps the frame
//                                                          all-fused so the negative single-rounding
//                                                          assertion has nothing else to trip on
void CheckFmaForm(u32 vlen, u8 sew, Form form, FmaRow const &row)
{
	printf("[fma] VLEN=%u SEW=%u %s %-8s\n", vlen, sew * 8, FormName(form), row.name);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	bool const vf = form == Form::VF;
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(row.funct6, vf, /*vs2=*/10, /*s1=*/9, /*vd=*/8),
	    EncFp(rv32::VF6_VFMACC, /*vf=*/false, /*vs2=*/11, /*s1=*/8, /*vd=*/12),
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 1);
	CHECK_EQ(n_members, 2);
	CHECK_EQ(guard_kind, (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	if (frames != 1 || n_members != 2)
		return;

	unsigned const chunks = vlen / 512;
	auto is_frame_body = [](llvm::BasicBlock &bb) {
		auto n = bb.getName();
		return n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.");
	};
	std::vector<llvm::CallInst *> fmas;
	unsigned other_constrained = 0, helper_calls = 0, splats = 0, nan_selects = 0;
	llvm::BasicBlock *slow = nullptr;
	for (auto &bb : *b.fn) {
		if (bb.getName() == "rvv.tchunk.fallback")
			slow = &bb;
		if (!is_frame_body(bb))
			continue;
		for (auto &ins : bb) {
			splats += llvm::isa<llvm::ShuffleVectorInst>(&ins);
			if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
				auto *fc = llvm::dyn_cast<llvm::FCmpInst>(sel->getCondition());
				nan_selects += fc &&
					       fc->getPredicate() == llvm::FCmpInst::FCMP_UNO &&
					       fc->getOperand(0) == fc->getOperand(1);
			}
			auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
			if (!call)
				continue;
			auto *callee = call->getCalledFunction();
			if (!callee) {
				++helper_calls;
				continue;
			}
			switch (callee->getIntrinsicID()) {
			case llvm::Intrinsic::experimental_constrained_fma:
				fmas.push_back(call);
				break;
			// SINGLE ROUNDING, asserted negatively. `.fmuladd` is in this list on
			// purpose: LLVM is permitted to split it into a multiply and an add, which
			// is the very decomposition this route must not perform.
			case llvm::Intrinsic::experimental_constrained_fmul:
			case llvm::Intrinsic::experimental_constrained_fadd:
			case llvm::Intrinsic::experimental_constrained_fsub:
			case llvm::Intrinsic::experimental_constrained_fdiv:
			case llvm::Intrinsic::experimental_constrained_fmuladd:
				++other_constrained;
				break;
			default:
				if (!callee->isIntrinsic())
					++helper_calls;
				break;
			}
		}
	}
	CHECK_EQ(fmas.size(), 2u * chunks); // two fused members, one call each per chunk
	CHECK_EQ(other_constrained, 0);	    // no mul+add decomposition, no fmuladd
	CHECK_EQ(helper_calls, 0);
	CHECK_EQ(splats, vf ? 1u : 0u);	    // one broadcast for f9 in the .vf form, none in .vv
	// The fused result is canonicalised exactly like every other FP lane op's: the helper arm
	// writes the canonical quiet NaN through vf_write -> f{32,64}_canon, so the fast arm must too
	// or the two arms return different bits. One select per member per chunk.
	CHECK_EQ(nan_selects, 2u * chunks);
	CHECK(slow != nullptr);

	// [SIGN + OPERAND MAPPING] on the member under test: chunks 0..k-1 of `fmas` are member 0.
	u32 const off_d = VregStateOffset(8), off_b = VregStateOffset(9), off_a = VregStateOffset(10);
	if (fmas.size() == 2u * chunks) {
		for (unsigned c = 0; c < chunks; ++c) {
			auto *call = fmas[c];
			// round.dynamic / fpexcept.strict / strictfp, as for every other lane op.
			// OPERAND 3 OF A CONSTRAINED FMA IS ITS ROUNDING-MODE METADATA, and it is NOT
			// the masked-store operand index that moved in LLVM 22 -- a mechanical rewrite
			// during the xbd port confused the two and broke 300 cells there. The
			// constrained-FP signatures are unchanged: `fma(a, b, c, round, except)`.
			CHECK(std::string(MDStr(call->getArgOperand(3))) == "round.dynamic");
			CHECK(std::string(MDStr(call->getArgOperand(4))) == "fpexcept.strict");
			CHECK(call->getAttributes().hasFnAttr(llvm::Attribute::StrictFP));
			for (unsigned k = 0; k < 3; ++k) {
				bool neg = false;
				llvm::Value *src = StripToSource(call->getArgOperand(k), neg);
				CHECK_EQ(neg, row.negated[k]);
				u32 const off = StateLoadOffset(src);
				switch (row.role[k]) {
				case Role::D:
					// chunk c of v8. The OLD vd: a CPUState load in BOTH forms,
					// because v8 is read before this member writes it.
					CHECK_EQ(off, off_d + c * 64u);
					break;
				case Role::B:
					// source 1: chunk c of v9 (`.vv`) or the frame-scope splat of
					// f9 (`.vf`). The splat is one value for every chunk, so it is
					// NOT offset by c -- checking it as a shufflevector is the
					// whole difference between the two forms here.
					if (vf)
						CHECK(llvm::isa<llvm::ShuffleVectorInst>(src));
					else
						CHECK_EQ(off, off_b + c * 64u);
					break;
				case Role::A:
					CHECK_EQ(off, off_a + c * 64u); // chunk c of v10
					break;
				}
			}
		}
	}

	// [FALLBACK ORDER] two helper calls, in guest order, each preceded by its own guest PC.
	unsigned fallback_calls = 0;
	llvm::ConstantInt *last_pc = nullptr;
	for (auto &ins : *slow) {
		if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
			if (auto *v = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand()))
				last_pc = v;
			continue;
		}
		auto *call = llvm::dyn_cast<llvm::CallBase>(&ins);
		if (!call)
			continue;
		auto *callee = call->getCalledFunction();
		if (callee && callee->isIntrinsic())
			continue;
		unsigned const member = fallback_calls++;
		if (member >= 2)
			continue;
		auto *raw = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
		CHECK(raw != nullptr);
		CHECK_EQ(raw ? raw->getZExtValue() : 0u, words[member + 1]);
		CHECK(last_pc != nullptr);
		CHECK_EQ(last_pc ? last_pc->getZExtValue() : ~0ull, 4ull * (member + 1));
	}
	CHECK_EQ(fallback_calls, 2);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// THE ARCHITECTURALLY LEGAL OLD-vd OVERLAP, which only the fused family can express: `vd == vs2`
// makes the OLD vd and the addend/multiplicand `a` the SAME guest register. The run body binds all
// of a member's sources from `cur[][]` BEFORE publishing its destination, so both arguments must
// resolve to the IDENTICAL llvm::Value -- one load, used twice -- and never to a re-read that could
// see the member's own result.
void CheckFmaOldVdOverlap(u32 vlen, u8 sew)
{
	printf("[fma-overlap] VLEN=%u SEW=%u vfmacc.vv vd==vs2\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(rv32::VF6_VFMACC, false, /*vs2=*/8, /*s1=*/9, /*vd=*/8),   // vd == vs2 == v8
	    EncFp(rv32::VF6_VFMADD, false, /*vs2=*/10, /*s1=*/8, /*vd=*/12), // keeps the run alive
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 1);
	CHECK_EQ(n_members, 2);
	if (frames != 1)
		return;
	unsigned const chunks = vlen / 512;
	std::vector<llvm::CallInst *> fmas;
	for (auto &bb : *b.fn) {
		auto n = bb.getName();
		if (!(n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.")))
			continue;
		for (auto &ins : bb) {
			auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
			auto *callee = call ? call->getCalledFunction() : nullptr;
			if (callee &&
			    callee->getIntrinsicID() == llvm::Intrinsic::experimental_constrained_fma)
				fmas.push_back(call);
		}
	}
	CHECK_EQ(fmas.size(), 2u * chunks);
	if (fmas.size() != 2u * chunks)
		return;
	// vfmacc is fma(b, a, d): argument 1 is `a` (vs2 = v8) and argument 2 is `d` (old vd = v8).
	for (unsigned c = 0; c < chunks; ++c) {
		bool n1 = false, n2 = false;
		llvm::Value *a = StripToSource(fmas[c]->getArgOperand(1), n1);
		llvm::Value *d = StripToSource(fmas[c]->getArgOperand(2), n2);
		CHECK(!n1);
		CHECK(!n2);
		CHECK_EQ(StateLoadOffset(a), VregStateOffset(8) + c * 64u);
		CHECK(a == d); // ONE value, read once, used for both roles
	}
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// A LEGAL MIXED FP FRAME: an FP-ALU member and a FUSED member under ONE guard and ONE bracket.
// Both routes lower on this backend, share a guard kind, a bracket and an ordered fallback, so a
// frame holding both is the same frame with two kinds of lane op in it. Integer members are still
// refused (a separate rule in RvvTranslateVectorRun) and that is NOT what this checks.
void CheckFmaMixedWithFalu(u32 vlen, u8 sew)
{
	printf("[fma-mixed] VLEN=%u SEW=%u vfmul.vf + vfmacc.vv + vfsub.vv\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(rv32::VF6_VFMUL, /*vf=*/true, /*vs2=*/9, /*s1=*/10, /*vd=*/8),  // .vf ALU
	    EncFp(rv32::VF6_VFMACC, /*vf=*/false, /*vs2=*/11, /*s1=*/8, /*vd=*/12), // fused
	    EncFp(rv32::VF6_VFSUB, /*vf=*/false, /*vs2=*/12, /*s1=*/8, /*vd=*/13),  // .vv ALU
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 1);
	CHECK_EQ(n_members, 3);
	CHECK_EQ(guard_kind, (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	if (frames != 1)
		return;
	unsigned const chunks = vlen / 512;
	unsigned fma = 0, fmul = 0, fsub = 0, brackets = 0, helper_calls = 0;
	for (auto &bb : *b.fn) {
		auto n = bb.getName();
		if (!(n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.")))
			continue;
		for (auto &ins : bb) {
			auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
			if (!call)
				continue;
			auto *callee = call->getCalledFunction();
			if (!callee) {
				++helper_calls;
				continue;
			}
			switch (callee->getIntrinsicID()) {
			case llvm::Intrinsic::experimental_constrained_fma: ++fma; break;
			case llvm::Intrinsic::experimental_constrained_fmul: ++fmul; break;
			case llvm::Intrinsic::experimental_constrained_fsub: ++fsub; break;
			case llvm::Intrinsic::x86_sse_stmxcsr: ++brackets; break;
			default:
				if (!callee->isIntrinsic())
					++helper_calls;
				break;
			}
		}
	}
	CHECK_EQ(fma, chunks);
	CHECK_EQ(fmul, chunks);
	CHECK_EQ(fsub, chunks);
	CHECK_EQ(helper_calls, 0);
	// ONE bracket for the whole mixed frame: open, the inherited-bracket fold, and close.
	CHECK_EQ(brackets, 3);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// FLAG-OFF, and INDEPENDENTLY of the FALU switch. `--rvv-qcg-typed-chunk-fma` off must refuse the
// fused frame even with `--rvv-qcg-typed-chunk-falu` on and the generic umbrella on, which is what
// makes the two routes separately ablatable.
void CheckFmaFlagOff(u32 vlen, u8 sew, bool falu_on, char const *what)
{
	printf("[fma-off] VLEN=%u SEW=%u %s\n", vlen, sew * 8, what);
	ConfigureCommon(vlen, falu_on, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = false;
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(rv32::VF6_VFMADD, false, /*vs2=*/10, /*s1=*/9, /*vd=*/8),
	    EncFp(rv32::VF6_VFMACC, false, /*vs2=*/11, /*s1=*/8, /*vd=*/12),
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// ---------------------------------------------------------------------------------------------
// F4 (2026-09-16). THE STANDALONE FUSED FRAME -- ONE guest instruction, no run.
//
// WHY THIS SECTION IS SEPARATE FROM THE F3 ONE ABOVE. Every F3 fixture puts the fused instruction
// next to a second admitted FP member, because a run needs two. That is exactly the situation F4
// exists to handle the ABSENCE of: real LINPACK has `vfmadd.vf` separated from its neighbours by a
// load, a store or a branch, so no run forms and -- before F4 -- the instruction took the
// `rv32_vfma` helper forever. A test that left a second FP member beside it would therefore
// re-exercise the run path and prove nothing about the standalone one.
//
// So the fixtures here are constructed so that NO run can exist, in two independent ways, and
// `n_members == 1` is asserted directly in both:
//
//   [A] the FMA is the only vector instruction in the region at all;
//   [B] the FMA is bracketed by scalar integer `addi`s, which CUT a run
//       (CutReason::ScalarInsn -- `--rvv-run-scalar-passthrough` is off by default and is left off
//       by ConfigureCommon, so a scalar instruction is a non-member).
//
// WHAT IS ASSERTED, beyond what the F3 section already covers for the same eight rows:
//
//   * `n_members == 1`. This is THE anti-run assertion. If a run had formed, it would be 2+.
//   * The FALLBACK ARM IS A SINGLE-INSTRUCTION ONE: exactly one helper call carrying the FMA's own
//     raw word, and NO guest-PC store -- Emit_rvvtypedchunkend writes per-member PCs only when
//     `n_members > 1`, so their absence is a positive statement that this is not a run frame.
//   * The GUARD KIND is VTypeVlVstartFrmRNE, and the pure-QCG contrast shows the same instruction
//     takes VTypePartialVlVstartFrmHost there -- which is what makes the F4 guard-kind term
//     falsifiable rather than a restatement.
//   * THE ORDERING against the pre-existing P-vector-SSA `rvv.fma.direct` route is stated as a
//     check, not only in a comment: with `--rvv-qcg-typed-chunk-fma` OFF and
//     `rvv_vector_ssa_host_fma` ON, `vfmadd` still reaches that older arm and the other seven
//     forms still reach the helper.

constexpr u32 kAddi = 0x00128293u; // addi x5, x5, 1 -- a non-member that cuts any run

// The three ways a standalone fixture can be spelled. `Isolated` is the minimal one; `ScalarSep`
// is the realistic one; `FlagOff` reuses `Isolated`'s words with the route switched off.
enum class Iso : u8 { Alone, ScalarSep };

std::vector<u32> StandaloneWords(u8 sew, Iso iso, u32 fma_word)
{
	std::vector<u32> w = {sew == 4 ? kVsetvliE32 : kVsetvliE64};
	if (iso == Iso::ScalarSep)
		w.push_back(kAddi);
	w.push_back(fma_word);
	if (iso == Iso::ScalarSep)
		w.push_back(kAddi);
	w.push_back(kJalr);
	return w;
}

void CheckStandaloneFma(u32 vlen, u8 sew, Form form, FmaRow const &row, Iso iso)
{
	printf("[fma-standalone] VLEN=%u SEW=%u %s %-8s %s\n", vlen, sew * 8, FormName(form),
	       row.name, iso == Iso::Alone ? "alone" : "scalar-separated");
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	bool const vf = form == Form::VF;
	u32 const fma_word = EncFp(row.funct6, vf, /*vs2=*/10, /*s1=*/9, /*vd=*/8);
	std::vector<u32> const words = StandaloneWords(sew, iso, fma_word);
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	// `frames` counts multi-member frames only, so it is 0 here BY DESIGN; the standalone frame is
	// found by the scan below instead.
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 0); // no RUN was formed -- which is the whole point of this fixture

	// Find the ONE typed frame this region contains, whatever its member count.
	unsigned typed_frames = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++typed_frames;
				begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
			}
	CHECK_EQ(typed_frames, 1);
	if (typed_frames != 1)
		return;
	// THE ANTI-RUN ASSERTION.
	CHECK_EQ((unsigned)begin->n_members, 1u);
	CHECK_EQ((unsigned)begin->guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);

	unsigned const chunks = vlen / 512;
	auto is_frame_body = [](llvm::BasicBlock &bb) {
		auto n = bb.getName();
		return n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.");
	};
	std::vector<llvm::CallInst *> fmas;
	unsigned other_constrained = 0, helper_calls = 0, splats = 0, nan_selects = 0, boxes = 0;
	unsigned masked_stores = 0;
	llvm::BasicBlock *slow = nullptr;
	for (auto &bb : *b.fn) {
		if (bb.getName() == "rvv.tchunk.fallback")
			slow = &bb;
		if (!is_frame_body(bb))
			continue;
		for (auto &ins : bb) {
			splats += llvm::isa<llvm::ShuffleVectorInst>(&ins);
			if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
				auto *fc = llvm::dyn_cast<llvm::FCmpInst>(sel->getCondition());
				nan_selects += fc &&
					       fc->getPredicate() == llvm::FCmpInst::FCMP_UNO &&
					       fc->getOperand(0) == fc->getOperand(1);
				// the e32 NaN-box of the `.vf` scalar
				auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
				auto *fvv = llvm::dyn_cast<llvm::ConstantInt>(sel->getFalseValue());
				if (sel->getType()->isIntegerTy(32) && cmp && fvv &&
				    cmp->getPredicate() == llvm::ICmpInst::ICMP_EQ) {
					auto *sn = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
					boxes += sn && sn->getZExtValue() == 0xffffffffu &&
						 fvv->getZExtValue() == rv32::F32_CANONICAL_NAN;
				}
			}
			auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
			if (!call)
				continue;
			auto *callee = call->getCalledFunction();
			if (!callee) {
				++helper_calls;
				continue;
			}
			switch (callee->getIntrinsicID()) {
			case llvm::Intrinsic::experimental_constrained_fma:
				fmas.push_back(call);
				break;
			case llvm::Intrinsic::masked_store:
				++masked_stores;
				break;
			case llvm::Intrinsic::experimental_constrained_fmul:
			case llvm::Intrinsic::experimental_constrained_fadd:
			case llvm::Intrinsic::experimental_constrained_fsub:
			case llvm::Intrinsic::experimental_constrained_fdiv:
			case llvm::Intrinsic::experimental_constrained_fmuladd:
				++other_constrained;
				break;
			default:
				if (!callee->isIntrinsic())
					++helper_calls;
				break;
			}
		}
	}
	// ONE fused call per chunk for ONE guest instruction, and single-rounded.
	CHECK_EQ(fmas.size(), chunks);
	CHECK_EQ(other_constrained, 0);
	CHECK_EQ(helper_calls, 0);
	CHECK_EQ(nan_selects, chunks);
	// THE STANDALONE FRAME STORES THROUGH `llvm.masked.store`, AND A RUN FRAME DOES NOT. This is a
	// real, intended difference and is asserted rather than tolerated. The shared FP body
	// (RvvEmitTypedFpChunkBody) passes the frame's SEW as `vstatechunkstore`'s `active_sew`, so
	// Emit_vstatechunkstore takes its masked arm and builds `(chunk*lanes + i) < vec.vl` per lane;
	// a run's pass-3 stores pass 0 and take the whole-chunk arm. At FULL VL -- which this frame's
	// guard has proved -- every element index is below `vl`, so the mask is all-ones and the two
	// arms write the identical bytes; the masked form simply carries the architectural predicate
	// the shared body always attaches. One store per chunk.
	CHECK_EQ(masked_stores, chunks);
	// Each `CreateVectorSplat` is one shufflevector: the `.vf` scalar broadcast (once per frame)
	// plus the store mask's splat of `vec.vl` (once per chunk).
	CHECK_EQ(splats, (vf ? 1u : 0u) + chunks);
	CHECK_EQ(boxes, (vf && sew == 4) ? 1u : 0u);
	CHECK(slow != nullptr);
	if (!slow || fmas.size() != chunks)
		return;

	// SIGN + OPERAND MAPPING, the SAME table and the SAME decoder the run fixtures use -- which is
	// the direct evidence that F4 did not introduce a second semantics for these eight rows.
	u32 const off_d = VregStateOffset(8), off_b = VregStateOffset(9), off_a = VregStateOffset(10);
	for (unsigned c = 0; c < chunks; ++c) {
		auto *call = fmas[c];
		CHECK(std::string(MDStr(call->getArgOperand(3))) == "round.dynamic");
		CHECK(std::string(MDStr(call->getArgOperand(4))) == "fpexcept.strict");
		CHECK(call->getAttributes().hasFnAttr(llvm::Attribute::StrictFP));
		for (unsigned k = 0; k < 3; ++k) {
			bool neg = false;
			llvm::Value *src = StripToSource(call->getArgOperand(k), neg);
			CHECK_EQ(neg, row.negated[k]);
			u32 const off = StateLoadOffset(src);
			switch (row.role[k]) {
			case Role::D: // the OLD vd: an input, read from CPUState
				CHECK_EQ(off, off_d + c * 64u);
				break;
			case Role::B:
				if (vf)
					CHECK(llvm::isa<llvm::ShuffleVectorInst>(src));
				else
					CHECK_EQ(off, off_b + c * 64u);
				break;
			case Role::A:
				CHECK_EQ(off, off_a + c * 64u);
				break;
			}
		}
	}

	// THE SINGLE-INSTRUCTION FALLBACK ARM: one helper call with this instruction's raw word, and
	// NO guest-PC store (Emit_rvvtypedchunkend emits those only for n_members > 1).
	unsigned fallback_calls = 0, pc_stores = 0;
	for (auto &ins : *slow) {
		if (llvm::isa<llvm::StoreInst>(&ins)) {
			++pc_stores;
			continue;
		}
		auto *call = llvm::dyn_cast<llvm::CallBase>(&ins);
		if (!call)
			continue;
		auto *callee = call->getCalledFunction();
		if (callee && callee->isIntrinsic())
			continue;
		++fallback_calls;
		auto *raw = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
		CHECK(raw != nullptr);
		CHECK_EQ(raw ? raw->getZExtValue() : 0u, fma_word);
	}
	CHECK_EQ(fallback_calls, 1);
	CHECK_EQ(pc_stores, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// THE PURE-QCG CONTRAST for the standalone frame, which is what makes the F4 guard-kind term
// falsifiable: the SAME single instruction takes VTypePartialVlVstartFrmHost on the QCG backend
// (that body masks every lane from the live vl and needs no vstart or RNE proof) and
// VTypeVlVstartFrmRNE on this one. Delete the term and the two would report the same kind.
// QIR only -- handing a partial-VL-kind frame to QIRToLLVM is the fail-closed abort under test.
void CheckStandaloneQcgContrast(u32 vlen, u8 sew)
{
	printf("[fma-standalone-qcg] VLEN=%u SEW=%u\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk_fma_force_emit = true; // bypass the COMPILE host's CPUID probe
	std::vector<u32> const words =
	    StandaloneWords(sew, Iso::Alone, EncFp(rv32::VF6_VFMADD, false, 10, 9, 8));
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind, /*run_backend=*/false);
	config::rvv_qcg_typed_chunk_fma_force_emit = false;
	unsigned typed_frames = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++typed_frames;
				begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
			}
	CHECK_EQ(typed_frames, 1);
	if (typed_frames != 1)
		return;
	CHECK_EQ((unsigned)begin->n_members, 1u);
	CHECK_EQ((unsigned)begin->guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost);
	CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl(begin->guard_kind));
}

// FLAG-OFF, AND THE ORDERING IT REVEALS. With `--rvv-qcg-typed-chunk-fma` off no typed frame is
// built at all, and what the instruction reaches instead depends on the PRE-EXISTING
// P-vector-SSA route, which handles `vfmadd` only (and only with `rvv_vector_ssa_host_fma` on).
// Asserting both halves is what makes the ordering decision in TRANSLATOR(vfma) a checked fact.
void CheckStandaloneFlagOff(u32 vlen, u8 sew, FmaRow const &row)
{
	printf("[fma-standalone-off] VLEN=%u SEW=%u %-8s\n", vlen, sew * 8, row.name);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_vector_ssa_host_fma = true; // as elfaot sets it on an FMA-capable compile host
	std::vector<u32> const words =
	    StandaloneWords(sew, Iso::Alone, EncFp(row.funct6, false, 10, 9, 8));
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	config::rvv_vector_ssa_host_fma = false;
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
	CHECK_EQ(typed_frames, 0);
	// The older route's own block, present for vfmadd and absent for the other seven.
	bool family_a = false;
	for (auto &bb : *b.fn)
		family_a |= bb.getName() == "rvv.fma.direct";
	CHECK_EQ(family_a, row.funct6 == rv32::VF6_VFMADD);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// F4. `--rvv-qcg-fp-shared-mask` MUST REFUSE THE STANDALONE FRAME, and this is the row that makes
// that a checked fact rather than a comment. With the switch on, RvvEmitFpSharedMasks emits one
// `vchunkmaskset` per chunk and every FP lane op names it; that node is a host opmask register with
// no LLVM lowering. The RUN path refuses it in RvvTranslateVectorRun, but the standalone path goes
// straight from RvvLLVMFmaChunkAdmit to RvvEmitTypedFmaChunkGroup with no frame-level gate, so the
// refusal lives in the predicate. Without this check, deleting it from the predicate passes.
// F4. A MASKED (vm == 0) FUSED INSTRUCTION MUST NOT TAKE THIS ROUTE. The QCG twin ADMITS vm == 0
// and masks every lane from v0; this backend's body has no lane mask at all, so a masked member
// would compute and store inactive lanes. Checked positively -- no typed frame is built -- rather
// than left to the Emit_vchunkfma Panic, because the right outcome is the pre-F4 fallback, not an
// abort. Both operand forms, because the mask rule has nothing to do with where source 1 lives.
void CheckStandaloneMaskedRefused(u32 vlen, u8 sew, Form form, FmaRow const &row)
{
	printf("[fma-standalone-masked] VLEN=%u SEW=%u %s %-8s\n", vlen, sew * 8, FormName(form),
	       row.name);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	u32 const masked = EncFp(row.funct6, form == Form::VF, 10, 9, 8) & ~(1u << 25);
	Built b(StandaloneWords(sew, Iso::Alone, masked));
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
	CHECK_EQ(typed_frames, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// F4. AN UNOBSERVED VTYPE MUST NOT TAKE THIS ROUTE. A region with no `vsetvli` leaves
// `rvv_bb_vtype` at ~0u; the QCG falu route may propose a hard-coded candidate shape and let its
// guard prove or refute it, but a fused frame cannot (it also LOADS the old vd, so a wrong
// candidate picks the wrong element width for an operand), and this backend cannot at all -- an
// LLVM lane type is a translation-time `<N x float|double>` with no run-time arm to select.
// Driven by simply omitting the `vsetvli` from the fixture.
void CheckStandaloneUnobservedVtypeRefused(u32 vlen, Form form)
{
	printf("[fma-standalone-novtype] VLEN=%u %s (no vsetvli in the region)\n", vlen,
	       FormName(form));
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	std::vector<u32> const words = {
	    EncFp(rv32::VF6_VFMACC, form == Form::VF, /*vs2=*/10, /*s1=*/9, /*vd=*/8), kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
	CHECK_EQ(typed_frames, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

void CheckStandaloneSharedMaskRefused(u32 vlen, u8 sew)
{
	printf("[fma-standalone-sharedmask] VLEN=%u SEW=%u\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_fp_shared_mask = true;
	std::vector<u32> const words =
	    StandaloneWords(sew, Iso::Alone, EncFp(rv32::VF6_VFMACC, true, 10, 9, 8));
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	config::rvv_qcg_fp_shared_mask = false;
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
	CHECK_EQ(typed_frames, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// ---------------------------------------------------------------------------------------------
// F4-FIX (2026-09-16). THE CROSS-REPRESENTATION BOUNDARY.
//
// This is the regression test for a REAL wrong-value bug that every other check in this file
// missed: F4's standalone fused frame reached CPUState without taking the P-vector-SSA cache's
// write-back boundary. It was found on a frozen LINPACK artifact (VLEN 512, LP_HASH e9215a3d
// against the expected 229c43d4) and reduced to the three guest instructions below, which
// disagreed with QEMU at one output byte while stdout and the profile matched.
//
// WHY 328 EXISTING CHECKS AND A SMALL SCALAR-FMA ORACLE ALL PASSED. Every other fixture in this
// file puts the fused instruction either alone or next to another instruction that this backend
// ALSO lowers into the same typed frame. Neither situation leaves a guest vector register sitting
// in the OTHER representation. The bug needs exactly that: a preceding instruction handled by the
// P-vector-SSA arm (`Create_rvvfalu`), which keeps its result as a live LLVM value and deliberately
// does not write CPUState until a boundary.
//
//   [1] vfadd.vv v12, v12, v10   -- Family A: v12 becomes a DIRTY SSA value; CPUState still holds
//                                   the PRE-vfadd bytes
//   [2] addi t0, zero, 1         -- cuts any run. It carries neither Trap nor MayTrap, so the
//                                   TRANSLATOR macro does not even call PreSideeff, and nothing
//                                   commits
//   [3] vfmacc.vf v12, fa0, v8   -- the F4 standalone typed frame, which reads AND writes v12
//                                   through CPUState
//
// TWO INDEPENDENT FAILURES, and the two counts below are one for each:
//
//   STALE READ   [3]'s old-vd load read the pre-[1] bytes of v12.
//   LOST WRITE   [3] stored its result to CPUState and the block-end RvvCommit then wrote the
//                still-dirty cached v12 -- [1]'s result -- straight over it.
//
// WHAT IS ASSERTED, and each is a count that FLIPS across the fix rather than a shape that merely
// looks plausible:
//
//   * Family A really did handle [1] -- an `rvv.falu.direct` block exists. Without this the
//     fixture would not create the cross-representation situation at all and the rest would be
//     vacuous.
//   * `commit_stores` -- stores of v12's chunks to CPUState in a NON-frame block. The fix's
//     `RvvCommit` runs before `Create_rvvtypedchunkbegin`, so it lands in the block holding the
//     guard: one per chunk after the fix, ZERO before it.
//   * `post_frame_stores` -- stores of v12's chunks inside `rvv.tchunk.done`. Emit_rvvtypedchunkend
//     leaves the insert point there, so the block-end commit of a STILL-DIRTY v12 would land in
//     it: ZERO after the fix (RvvResetValues invalidated the entry), one per chunk before it.
//
// The `.vf` ALU route, when it lands, needs the same boundary for the same reason.
void CheckCrossRepresentationBoundary(u32 vlen, u8 sew)
{
	printf("[fma-residency] VLEN=%u SEW=%u vfadd.vv -> addi -> vfmacc.vf on the same vreg\n",
	       vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	// Family A's own switch, as elfaot sets it on an FMA-capable compile host. It gates the
	// `Create_rvvfma` arm; the `Create_rvvfalu` arm [1] takes needs only RvvSSAEnabled().
	config::rvv_vector_ssa_host_fma = true;
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(rv32::VF6_VFADD, /*vf=*/false, /*vs2=*/12, /*s1=*/10, /*vd=*/12),
	    0x00100293u, // addi t0, zero, 1  -- cuts the run, does not touch vtype
	    EncFp(rv32::VF6_VFMACC, /*vf=*/true, /*vs2=*/8, /*s1=*/10, /*vd=*/12),
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	config::rvv_vector_ssa_host_fma = false;

	// The fixture must really be the cross-representation one: [1] on Family A, [3] in a
	// one-member typed frame.
	bool family_a = false;
	llvm::BasicBlock *fast = nullptr, *done = nullptr;
	for (auto &bb : *b.fn) {
		if (bb.getName() == "rvv.falu.direct")
			family_a = true;
		if (bb.getName() == "rvv.tchunk.direct")
			fast = &bb;
		if (bb.getName() == "rvv.tchunk.done")
			done = &bb;
	}
	CHECK(family_a);
	CHECK(fast != nullptr);
	CHECK(done != nullptr);
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++typed_frames;
				CHECK_EQ((unsigned)static_cast<InstRVVTypedChunkBegin *>(&ins)->n_members,
					 1u);
			}
	CHECK_EQ(typed_frames, 1);
	if (!family_a || !fast || !done || typed_frames != 1)
		return;

	unsigned const chunks = vlen / 512;
	auto is_frame_block = [](llvm::BasicBlock &bb) {
		return bb.getName().starts_with("rvv.tchunk.");
	};
	auto stores_to_v12 = [&](llvm::BasicBlock &bb) {
		unsigned n = 0;
		for (auto &ins : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st)
				continue;
			auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(st->getPointerOperand());
			if (!gep || gep->getNumIndices() != 1)
				continue;
			auto *idx = llvm::dyn_cast<llvm::ConstantInt>(
			    gep->getOperand(gep->getNumOperands() - 1));
			if (!idx)
				continue;
			u32 const off = (u32)idx->getZExtValue();
			for (unsigned c = 0; c < chunks; ++c)
				n += off == VregStateOffset(12) + c * 64u;
		}
		return n;
	};

	// THE COMMIT IS COUNTED IN THE GUARD'S OWN BLOCK, not merely "somewhere before the frame".
	// `Emit_rvvtypedchunkbegin` branches to the fast arm from the block it was emitted into, so
	// that block has exactly one predecessor-of-`fast` identity and it is precisely where
	// RvvEmitTypedFmaChunkGroup's `RvvCommit` lands. Counting more loosely would also pick up
	// Family A's OWN fallback arm, which stores vs2 (= v12 here) to CPUState before calling the
	// helper -- a different, pre-existing store that has nothing to do with this boundary.
	llvm::BasicBlock *guard_block = nullptr;
	unsigned preds = 0;
	for (auto *pred : llvm::predecessors(fast)) {
		++preds;
		guard_block = pred;
	}
	CHECK_EQ(preds, 1);
	unsigned commit_stores = 0, post_frame_stores = 0;
	if (guard_block)
		commit_stores = stores_to_v12(*guard_block);
	post_frame_stores = stores_to_v12(*done);
	(void)is_frame_block;
	printf("    commit_stores=%u post_frame_stores=%u (chunks=%u)\n", commit_stores,
	       post_frame_stores, chunks);
	// STALE READ: the boundary now writes v12 out before the frame reads it. MEASURED to flip --
	// 0 without the fix, `chunks` with it, at both VLENs and both SEWs.
	CHECK_EQ(commit_stores, chunks);
	// `post_frame_stores` is REPORTED, NOT ASSERTED, and that is deliberate. It was measured at 0
	// both with and without the fix, so the block-end commit of a still-dirty v12 does not land in
	// `rvv.tchunk.done` in this fixture and an assertion on it would be vacuous -- exactly the kind
	// of check that looks like evidence and is not. The INVALIDATION half of the boundary is
	// covered by CheckPostFrameCacheInvalidated below instead, which does flip.
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// F4-FIX. THE OTHER HALF OF THE BOUNDARY: `RvvResetValues()`.
//
// `RvvCommit` alone would write v12 out but leave the cache entry VALID, so the NEXT Family A
// instruction that reads v12 would reuse the stale pre-frame SSA value instead of the bytes the
// frame just stored. The fixture adds one instruction to the reproducer to make that observable:
//
//   [1] vfadd.vv  v12, v12, v10    Family A -- v12 enters the SSA cache
//   [2] addi t0, zero, 1           cuts the run, commits nothing
//   [3] vfmacc.vf v12, fa0, v8     the typed frame -- writes v12 through CPUState
//   [4] addi t0, zero, 1           a SECOND cut: without it [3] and [4] are adjacent FP members
//                                  and the run former swallows them into one frame
//   [5] vfadd.vv  v14, v12, v10    Family A again -- MUST re-read v12 from CPUState
//
// Counted as LOADS of v12's chunk offsets outside the frame body. [1] contributes twice: once for
// its own vs2 read and once in its FALLBACK arm, which reloads vd after calling the helper. [5]
// contributes another `chunks` ONLY IF the cache was invalidated. The expected totals are therefore
// 3*chunks with the reset and 2*chunks without it; both numbers are printed so the log carries the
// measurement rather than only the verdict.
void CheckPostFrameCacheInvalidated(u32 vlen, u8 sew)
{
	printf("[fma-residency-reset] VLEN=%u SEW=%u vfadd.vv -> addi -> vfmacc.vf -> vfadd.vv\n",
	       vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_vector_ssa_host_fma = true;
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(rv32::VF6_VFADD, /*vf=*/false, /*vs2=*/12, /*s1=*/10, /*vd=*/12),
	    0x00100293u, // addi t0, zero, 1
	    EncFp(rv32::VF6_VFMACC, /*vf=*/true, /*vs2=*/8, /*s1=*/10, /*vd=*/12),
	    0x00100293u, // a SECOND addi: without it [3] and [4] are adjacent FP members and the run
			 // former consumes them into one frame, so there would be no standalone frame
			 // and no Family A instruction after it -- the situation this check needs
	    EncFp(rv32::VF6_VFADD, /*vf=*/false, /*vs2=*/12, /*s1=*/10, /*vd=*/14),
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	config::rvv_vector_ssa_host_fma = false;
	unsigned const chunks = vlen / 512;
	unsigned loads = 0;
	for (auto &bb : *b.fn) {
		if (bb.getName().starts_with("rvv.tchunk."))
			continue; // the frame's own operand loads are not what this counts
		for (auto &ins : bb) {
			auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!ld)
				continue;
			auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(ld->getPointerOperand());
			if (!gep || gep->getNumIndices() != 1)
				continue;
			auto *idx = llvm::dyn_cast<llvm::ConstantInt>(
			    gep->getOperand(gep->getNumOperands() - 1));
			if (!idx)
				continue;
			u32 const off = (u32)idx->getZExtValue();
			for (unsigned c = 0; c < chunks; ++c)
				loads += off == VregStateOffset(12) + c * 64u;
		}
	}
	printf("    v12 loads outside the frame=%u (chunks=%u)\n", loads, chunks);
	CHECK_EQ(loads, 3u * chunks);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// ---------------------------------------------------------------------------------------------
// F5 (2026-09-16). THE STANDALONE `.vf` FP-ALU FRAME -- ONE guest instruction, no run, no `.vv`.
//
// WHY IT IS A SEPARATE SECTION. Every `.vf` fixture above either sits in a run or is a FUSED
// instruction. F5 closes the remaining hole: a single `vfadd/vfsub/vfmul/vfdiv .vf` separated from
// its neighbours by memory or control forms no run, has no P-vector-SSA arm (that route requires
// `funct3 == 0b001`), and therefore took the `rv32_vfalu` helper forever.
//
// THE FIXTURE IS ONE `.vf` INSTRUCTION AND NOTHING ELSE VECTOR, so no run can exist and
// `n_members == 1` is asserted directly.
//
//   [0] vsetvli a0, a0, e{32,64}, m1, ta, ma
//   [1] <funct6>.vf v12, v8, f9
//   [2] jalr
//
// WHAT IS ASSERTED
//
//   * `n_members == 1` -- the anti-run assertion -- and the FULL-VL guard kind, with the pure-QCG
//     contrast showing the same instruction takes VTypePartialVlVstartFrmHost there.
//   * OPCODE: the four funct6 map to four DISTINCT constrained intrinsics, matched by
//     `llvm::Intrinsic::ID` off the callee and never by parsing a name.
//   * SOURCE and ORDER: argument 0 is the vs2 CHUNK LOAD and argument 1 is the frame-scope SPLAT of
//     f9. `vfsub.vf` is `vd = vs2 - f[rs1]` and `vfdiv.vf` is `vs2 / f[rs1]`, so for those two a
//     swap is a different function; the reversed forms vfrsub/vfrdiv are refused at admission,
//     which is why one binding rule can serve all four.
//   * SEW32 BOXING: `select (icmp eq i32 %hi, -1), %lo, 0x7fc00000` in the broadcast at SEW=32 and
//     no such select at SEW=64, where the doubleword IS the operand.
//   * OWN FLAG-OFF: `--rvv-qcg-typed-chunk-falu` off builds no frame; and `.vv` is unaffected in
//     BOTH settings, which is the "keep the existing cross-instruction SSA" requirement.
//   * SHARED-MASK REFUSAL in admission, not a Panic in the emitter.
//   * THE REPRESENTATION BOUNDARY: a preceding Family A instruction's dirty value is committed
//     before this frame reads CPUState -- the F4-FIX defect, checked for this route too.

struct FaluRow {
	u32 funct6;
	char const *name;
	llvm::Intrinsic::ID id;
};

FaluRow const kFaluRows[4] = {
    {rv32::VF6_VFADD, "vfadd", llvm::Intrinsic::experimental_constrained_fadd},
    {rv32::VF6_VFSUB, "vfsub", llvm::Intrinsic::experimental_constrained_fsub},
    {rv32::VF6_VFMUL, "vfmul", llvm::Intrinsic::experimental_constrained_fmul},
    {rv32::VF6_VFDIV, "vfdiv", llvm::Intrinsic::experimental_constrained_fdiv},
};

void CheckStandaloneFaluVf(u32 vlen, u8 sew, FaluRow const &row)
{
	printf("[falu-standalone] VLEN=%u SEW=%u %s.vf v12, v8, f9\n", vlen, sew * 8, row.name);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	u32 const word = EncFp(row.funct6, /*vf=*/true, /*vs2=*/8, /*s1=*/9, /*vd=*/12);
	std::vector<u32> const words = {sew == 4 ? kVsetvliE32 : kVsetvliE64, word, kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	CHECK_EQ(frames, 0); // no RUN -- `frames` counts multi-member frames only

	unsigned typed_frames = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++typed_frames;
				begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
			}
	CHECK_EQ(typed_frames, 1);
	if (typed_frames != 1)
		return;
	CHECK_EQ((unsigned)begin->n_members, 1u); // THE ANTI-RUN ASSERTION
	CHECK_EQ((unsigned)begin->guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);

	unsigned const chunks = vlen / 512;
	auto is_frame_body = [](llvm::BasicBlock &bb) {
		auto n = bb.getName();
		return n == "rvv.tchunk.direct" || n.starts_with("rvv.tchunk.fp.");
	};
	std::vector<llvm::CallInst *> ops;
	unsigned other_constrained = 0, helper_calls = 0, splats = 0, nan_selects = 0, boxes = 0;
	unsigned masked_stores = 0;
	llvm::BasicBlock *slow = nullptr;
	for (auto &bb : *b.fn) {
		if (bb.getName() == "rvv.tchunk.fallback")
			slow = &bb;
		if (!is_frame_body(bb))
			continue;
		for (auto &ins : bb) {
			splats += llvm::isa<llvm::ShuffleVectorInst>(&ins);
			if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
				auto *fc = llvm::dyn_cast<llvm::FCmpInst>(sel->getCondition());
				nan_selects += fc &&
					       fc->getPredicate() == llvm::FCmpInst::FCMP_UNO &&
					       fc->getOperand(0) == fc->getOperand(1);
				auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
				auto *fvv = llvm::dyn_cast<llvm::ConstantInt>(sel->getFalseValue());
				if (sel->getType()->isIntegerTy(32) && cmp && fvv &&
				    cmp->getPredicate() == llvm::ICmpInst::ICMP_EQ) {
					auto *sn = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
					boxes += sn && sn->getZExtValue() == 0xffffffffu &&
						 fvv->getZExtValue() == rv32::F32_CANONICAL_NAN;
				}
			}
			auto *call = llvm::dyn_cast<llvm::CallInst>(&ins);
			if (!call)
				continue;
			auto *callee = call->getCalledFunction();
			if (!callee) {
				++helper_calls;
				continue;
			}
			auto id = callee->getIntrinsicID();
			if (id == row.id)
				ops.push_back(call);
			else if (id == llvm::Intrinsic::masked_store)
				++masked_stores;
			else if (id == llvm::Intrinsic::experimental_constrained_fadd ||
				 id == llvm::Intrinsic::experimental_constrained_fsub ||
				 id == llvm::Intrinsic::experimental_constrained_fmul ||
				 id == llvm::Intrinsic::experimental_constrained_fdiv ||
				 id == llvm::Intrinsic::experimental_constrained_fma ||
				 id == llvm::Intrinsic::experimental_constrained_fmuladd)
				++other_constrained; // a DIFFERENT arithmetic op than this row's
			else if (!callee->isIntrinsic())
				++helper_calls;
		}
	}
	// OPCODE: exactly this row's intrinsic, once per chunk, and no other arithmetic at all. The
	// four rows carry four distinct IDs, so a map that returned one of them for every funct6 would
	// leave `other_constrained` non-zero on three of the four rows.
	CHECK_EQ(ops.size(), chunks);
	CHECK_EQ(other_constrained, 0);
	CHECK_EQ(helper_calls, 0);
	CHECK_EQ(nan_selects, chunks);
	CHECK_EQ(masked_stores, chunks);
	CHECK_EQ(splats, 1u + chunks); // the f9 broadcast, plus the store mask's splat of vec.vl
	// SEW32 BOXING, present at e32 and absent at e64.
	CHECK_EQ(boxes, sew == 4 ? 1u : 0u);
	CHECK(slow != nullptr);
	if (!slow || ops.size() != chunks)
		return;

	// SOURCE AND ORDER: arg0 = the vs2 chunk load (v8), arg1 = the frame-scope splat of f9.
	u32 const off_vs2 = VregStateOffset(8);
	for (unsigned c = 0; c < chunks; ++c) {
		auto *call = ops[c];
		CHECK(std::string(MDStr(call->getArgOperand(2))) == "round.dynamic");
		CHECK(std::string(MDStr(call->getArgOperand(3))) == "fpexcept.strict");
		CHECK(call->getAttributes().hasFnAttr(llvm::Attribute::StrictFP));
		bool n0 = false, n1 = false;
		llvm::Value *a = StripToSource(call->getArgOperand(0), n0);
		llvm::Value *bb_ = StripToSource(call->getArgOperand(1), n1);
		CHECK(!n0);
		CHECK(!n1); // no negation anywhere in this family
		CHECK_EQ(StateLoadOffset(a), off_vs2 + c * 64u);
		CHECK(llvm::isa<llvm::ShuffleVectorInst>(bb_));
	}

	// SINGLE-INSTRUCTION FALLBACK: one helper call with this instruction's raw word, no PC store.
	unsigned fallback_calls = 0, pc_stores = 0;
	for (auto &ins : *slow) {
		if (llvm::isa<llvm::StoreInst>(&ins)) {
			++pc_stores;
			continue;
		}
		auto *call = llvm::dyn_cast<llvm::CallBase>(&ins);
		if (!call)
			continue;
		auto *callee = call->getCalledFunction();
		if (callee && callee->isIntrinsic())
			continue;
		++fallback_calls;
		auto *raw = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
		CHECK(raw != nullptr);
		CHECK_EQ(raw ? raw->getZExtValue() : 0u, word);
	}
	CHECK_EQ(fallback_calls, 1);
	CHECK_EQ(pc_stores, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// THE PURE-QCG CONTRAST, which makes the F5 guard-kind term falsifiable: the same single `.vf`
// instruction takes VTypePartialVlVstartFrmHost on the QCG backend. QIR only -- handing a
// partial-VL-kind frame to QIRToLLVM is the fail-closed abort under test.
void CheckStandaloneFaluVfQcgContrast(u32 vlen, u8 sew)
{
	printf("[falu-standalone-qcg] VLEN=%u SEW=%u\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	std::vector<u32> const words = {sew == 4 ? kVsetvliE32 : kVsetvliE64,
					EncFp(rv32::VF6_VFMUL, true, 8, 9, 12), kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind, /*run_backend=*/false);
	config::rvv_qcg_typed_chunk_falu_force_emit = false;
	unsigned typed_frames = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++typed_frames;
				begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
			}
	CHECK_EQ(typed_frames, 1);
	if (typed_frames != 1)
		return;
	CHECK_EQ((unsigned)begin->guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost);
	CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl(begin->guard_kind));
}

// OWN FLAG-OFF, AND `.vv` UNAFFECTED IN BOTH SETTINGS. The second half is the requirement that F5
// must not cost the existing cross-instruction SSA: a standalone `.vv` must keep reaching the
// P-vector-SSA arm (`rvv.falu.direct`) and must NEVER build a typed frame, whether the route's
// switch is on or off.
void CheckStandaloneFaluGates(u32 vlen, u8 sew, bool falu_on)
{
	printf("[falu-standalone-gate] VLEN=%u SEW=%u --rvv-qcg-typed-chunk-falu=%d\n", vlen,
	       sew * 8, (int)falu_on);
	for (Form form : {Form::VF, Form::VV}) {
		ConfigureCommon(vlen, falu_on, /*run_on=*/true);
		std::vector<u32> const words = {
		    sew == 4 ? kVsetvliE32 : kVsetvliE64,
		    EncFp(rv32::VF6_VFMUL, form == Form::VF, /*vs2=*/8, /*s1=*/9, /*vd=*/12), kJalr};
		Built b(words);
		unsigned n_members = 0, frames = 0, guard_kind = ~0u;
		Build(b, n_members, frames, guard_kind);
		unsigned typed_frames = 0;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
		bool family_a = false;
		for (auto &bb : *b.fn)
			family_a |= bb.getName() == "rvv.falu.direct";
		// A typed frame appears for `.vf` and only when this route's own switch is on.
		CHECK_EQ(typed_frames, (form == Form::VF && falu_on) ? 1u : 0u);
		// `.vv` keeps the P-vector-SSA arm in BOTH settings -- F5 costs it nothing.
		CHECK_EQ(family_a, form == Form::VV);
		CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	}
}

// SHARED-MASK REFUSAL IN ADMISSION. With `--rvv-qcg-fp-shared-mask` on, RvvEmitFpSharedMasks would
// emit `vchunkmaskset` nodes that have no LLVM lowering. The standalone path has no frame-level
// gate, so the refusal lives in RvvLLVMFaluChunkAdmit and the instruction keeps its helper.
void CheckStandaloneFaluSharedMaskRefused(u32 vlen, u8 sew)
{
	printf("[falu-standalone-sharedmask] VLEN=%u SEW=%u\n", vlen, sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	config::rvv_qcg_fp_shared_mask = true;
	std::vector<u32> const words = {sew == 4 ? kVsetvliE32 : kVsetvliE64,
					EncFp(rv32::VF6_VFADD, true, 8, 9, 12), kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	config::rvv_qcg_fp_shared_mask = false;
	unsigned typed_frames = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			typed_frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
	CHECK_EQ(typed_frames, 0);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

// THE REPRESENTATION BOUNDARY, for this route. Same shape as the fused reproducer: a Family A `.vv`
// instruction leaves v12 as a dirty SSA value, a scalar cuts any run, and the standalone `.vf`
// frame then reads v12 through CPUState. Counted as commit stores of v12 in the guard's own block --
// 0 without the boundary, one per chunk with it.
void CheckStandaloneFaluBoundary(u32 vlen, u8 sew)
{
	printf("[falu-standalone-residency] VLEN=%u SEW=%u vfadd.vv -> addi -> vfmul.vf\n", vlen,
	       sew * 8);
	ConfigureCommon(vlen, /*falu_on=*/true, /*run_on=*/true);
	std::vector<u32> const words = {
	    sew == 4 ? kVsetvliE32 : kVsetvliE64,
	    EncFp(rv32::VF6_VFADD, /*vf=*/false, /*vs2=*/12, /*s1=*/10, /*vd=*/12),
	    0x00100293u, // addi t0, zero, 1 -- cuts the run; no Trap/MayTrap, so no PreSideeff either
	    EncFp(rv32::VF6_VFMUL, /*vf=*/true, /*vs2=*/12, /*s1=*/9, /*vd=*/12),
	    kJalr};
	Built b(words);
	unsigned n_members = 0, frames = 0, guard_kind = ~0u;
	Build(b, n_members, frames, guard_kind);
	bool family_a = false;
	llvm::BasicBlock *fast = nullptr;
	for (auto &bb : *b.fn) {
		if (bb.getName() == "rvv.falu.direct")
			family_a = true;
		if (bb.getName() == "rvv.tchunk.direct")
			fast = &bb;
	}
	CHECK(family_a);
	CHECK(fast != nullptr);
	if (!fast)
		return;
	llvm::BasicBlock *guard_block = nullptr;
	unsigned preds = 0;
	for (auto *pred : llvm::predecessors(fast)) {
		++preds;
		guard_block = pred;
	}
	CHECK_EQ(preds, 1);
	unsigned const chunks = vlen / 512;
	unsigned commit_stores = 0;
	if (guard_block)
		for (auto &ins : *guard_block) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st)
				continue;
			auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(st->getPointerOperand());
			if (!gep || gep->getNumIndices() != 1)
				continue;
			auto *idx = llvm::dyn_cast<llvm::ConstantInt>(
			    gep->getOperand(gep->getNumOperands() - 1));
			if (!idx)
				continue;
			for (unsigned c = 0; c < chunks; ++c)
				commit_stores += (u32)idx->getZExtValue() == VregStateOffset(12) + c * 64u;
		}
	printf("    commit_stores=%u (chunks=%u)\n", commit_stores, chunks);
	CHECK_EQ(commit_stores, chunks);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
}

} // namespace

int main()
{
	for (u32 vlen : {512u, 1024u}) {
		for (u8 sew : {(u8)4, (u8)8}) {
			for (auto const &row : kFmaRows)
				for (Form form : {Form::VV, Form::VF})
					CheckFmaForm(vlen, sew, form, row);
			// F4: the same eight rows, both forms, with NO second FP member beside them.
			for (auto const &row : kFmaRows)
				for (Form form : {Form::VV, Form::VF})
					CheckStandaloneFma(vlen, sew, form, row, Iso::Alone);
			// and the realistic spelling: a scalar instruction on each side, which cuts
			// any run that the adjacency scan might otherwise have started.
			for (auto const &row : kFmaRows)
				CheckStandaloneFma(vlen, sew, Form::VF, row, Iso::ScalarSep);
			for (auto const &row : kFaluRows)
				CheckStandaloneFaluVf(vlen, sew, row);
			CheckStandaloneFaluVfQcgContrast(vlen, sew);
			CheckStandaloneFaluGates(vlen, sew, /*falu_on=*/true);
			CheckStandaloneFaluGates(vlen, sew, /*falu_on=*/false);
			CheckStandaloneFaluSharedMaskRefused(vlen, sew);
			CheckStandaloneFaluBoundary(vlen, sew);
			CheckCrossRepresentationBoundary(vlen, sew);
			CheckPostFrameCacheInvalidated(vlen, sew);
			CheckStandaloneQcgContrast(vlen, sew);
			CheckStandaloneSharedMaskRefused(vlen, sew);
			if (sew == 4) // vtype-free: the SEW loop would only repeat it
				for (Form form : {Form::VV, Form::VF})
					CheckStandaloneUnobservedVtypeRefused(vlen, form);
			for (auto const &row : kFmaRows)
				for (Form form : {Form::VV, Form::VF})
					CheckStandaloneMaskedRefused(vlen, sew, form, row);
			for (auto const &row : kFmaRows)
				CheckStandaloneFlagOff(vlen, sew, row);
			CheckFmaOldVdOverlap(vlen, sew);
			CheckFmaMixedWithFalu(vlen, sew);
			CheckFmaFlagOff(vlen, sew, /*falu_on=*/true,
					"--rvv-qcg-typed-chunk-fma off, --falu ON");
			CheckFmaFlagOff(vlen, sew, /*falu_on=*/false,
					"--rvv-qcg-typed-chunk-fma off, --falu off");
			CheckMixedForms(vlen, sew);
			CheckRefusedEncoding(vlen, sew, {kVfrsubVF_A, kVfrsubVF_B},
					     "vfrsub.vf (the REVERSED subtract)");
			CheckRefusedEncoding(vlen, sew, {kVfaddVFMasked, kVfmulVFMasked},
					     "masked .vf (vm == 0)");
			for (Form form : {Form::VV, Form::VF}) {
				CheckAdmitted(vlen, sew, form);
				CheckQcgContrast(vlen, sew, form);
				CheckRefused(vlen, sew, form, /*falu_on=*/false, /*run_on=*/true,
					     "--rvv-qcg-typed-chunk-falu off");
				CheckRefused(vlen, sew, form, /*falu_on=*/true, /*run_on=*/false,
					     "--rvv-vector-run off");
			}
		}
	}
	printf("%s (%u failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
	return g_fail != 0;
}
