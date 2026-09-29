#include "dbt/aot/aot.h"
#include "dbt/aot/loop_tier.h"
#include "dbt/qmc/compile.h"
#include "dbt/tcache/objprof.h"
namespace dbt::brindedges { void Dump(char const *path); }

#include "dbt/util/fsmanager.h"
#include "dbt/execute.h"
#include "dbt/mmu.h"

#include <spawn.h>
extern "C" char **environ;
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>
extern "C" {
#include <dlfcn.h>
#include <time.h>
#include <fcntl.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/time.h>
#include <ucontext.h>

}

namespace dbt
{

// X4g1: absolute path to this source tree's in-run single-run/descent builder script, baked by
// dbt/CMakeLists.txt from ${PROJECT_SOURCE_DIR}. There is deliberately no default: a fallback would
// silently reintroduce the cross-worktree path this replaced.
#ifndef DBT_SR_BUILDER_SH
#error "DBT_SR_BUILDER_SH must be defined by the build (see dbt/CMakeLists.txt)"
#endif


// Returns true iff `so_handle`'s embedded identity matches this process: the CPUState layout
// signature AND (X4g2) the RVV VLEN the artifact was specialized for.
//
// Defined here (rather than inline at each call site) because FOUR separate entry points
// dlopen an artifact and all of them must gate -- the fourth is T5d2b1's loop-tier loader, which
// calls this declaration from dbt/aot/aot.h rather than growing a copy. Both checks live in THIS function for the same
// reason: BootAOTFile, BootOneArtifact, BootReuseArtifact and LoadAndValidateArtifact must not
// grow their own copies that
// can drift apart -- a per-entry check is how an artifact ends up gated on one path and ungated on
// another. Every check added here is inherited by all three at once.
//
// Fail-closed on all three outcomes: match accepts, mismatch refuses, and a MISSING symbol refuses
// too. Absence is not evidence of compatibility -- an artifact built before a gate existed made no
// promise about the thing that gate checks -- and refusing merely costs a JIT recompile, which is
// always correct.
// =============================================================================================
// S3.7: THE RVV DIRECT-ROUTE CONTRACT -- one table, one renderer, every builder.
//
// WHY THIS EXISTS AS A TABLE AND NOT AS FIVE MORE snprintf ARGUMENTS. `dbt::config` is
// per-process. Every option below defaults FALSE in a freshly exec'd `elfaot`, so a builder that
// is not told stays on the pre-existing helper lowering no matter what the parent elfrun was asked
// for -- it produces a VLEN-qualified artifact whose hot region is opaque helper calls. That is
// precisely the failure X4f, X4f-fix1 and C5.2a each hit by hand-editing one spawn site and
// missing another. There are NINE reachable contract sites (2 direct C++ elfaot executions, 1
// script handoff, and the 6 elfaot executions inside sr_builder.sh), so "remember to add the flag
// in each place" is not a contract, it is an invitation to drift.
//
// The rule this establishes instead: a route flag is added to `kRvvRouteContract` and to nothing
// else. Both renderers below walk the same array, all three C++ spawn sites call a renderer, and
// the script splices the rendered string verbatim into every elfaot call it makes. The table holds
// THIRTEEN entries today -- nine direct route options (S3.4/S3.5/S3.6/S3.10a/T1b/T1d/T1e/T1f and
// Native-3), the vector-SSA enable that permits typed RVV lowering at all (C5.2a; T5f gives it its
// own KIND, see below), and three diagnostic switches -- and adding a fourteenth is one row here;
// scripts/vlen_propagation_audit.py fails if any reachable site stops using the mechanism. T1b, T1c
// and Native-3 are the rows added since the rule was written, and adding each was in fact the one
// edit the rule promised: no spawn site changed any of the three times.
//
// T1c IS THE CASE THIS TABLE EXISTS FOR, and it is worth recording as a demonstration rather than a
// claim. S3.10a shipped `vsub.vv`'s LLVM lowering, its TChunkCheckBodyOp whitelist entry and its
// RvvLLVMSubChunkAdmit gate -- a complete, tested route -- and then added neither an elfaot option
// nor a row here. The result was a route no artifact could ever take, in either the offline or the
// same-run builder, because `config::rvv_qcg_typed_chunk_sub` defaults false in a freshly exec'd
// elfaot and nothing told it otherwise. That is precisely the "route flag added to the lowering but
// not to the contract" failure the paragraph above describes, and it went unnoticed until the T1a
// route audit read the two sides against each other.
//
// IT IS RENDERED UNCONDITIONALLY, INCLUDING THE OFF STATE, and that is load-bearing rather than
// verbose. `--rvv-qcg-typed-chunk-vse=0` and omitting the option are the same thing to elfaot
// TODAY, but only because its default happens to be false. Emitting the parent's actual value
// makes the child's configuration a function of the parent's rather than of elfaot's defaults, so
// a future default change cannot silently switch a route on in a background builder that the user
// did not ask for. It also makes the contract observable in a `ps` line and in a saved command
// log, which is how S3.7's evidence checks it without inferring from parent flags.
// =============================================================================================
// T5f: ...AND ONE ROW IN THIS TABLE IS NOT A POLICY THE PARENT MAY DECIDE FOR THE CHILD.
//
// Everything above is written as if every row meant the same kind of thing: "the parent was asked
// for this, so the child is told it". For the nine routes and the three diagnostics that is exactly
// right -- each names a guest instruction form or a counter, and either backend can honour it or
// not, independently. `--rvv-vector-ssa` is not of that kind, and T5e measured the consequence.
//
// THE SAME SPELLING NAMES TWO DIFFERENT BACKENDS' REPRESENTATION CHOICES:
//
//   in the PARENT (elfrun/QCG):  may a guest-observable vector value stay live in a HOST REGISTER
//                                across a guest instruction boundary? That is a QCG residency
//                                property, and it is a LEGALITY precondition for the loop tier's
//                                intra-region side exit: MakeGBr's in-region arm does not
//                                RvvCommit, so under vector-SSA a value the guest can observe could
//                                still be in a register at the latch. looptier::Arm() therefore
//                                refuses `side_exit_needs_committed_vector_state`.
//
//   in the CHILD (elfaot/LLVM):  may the LLVM backend use typed fixed-width vector SSA values as
//                                its lowering SUBSTRATE? Every elfaot typed-chunk route is gated on
//                                it; at 0 there is no substrate and every one of them falls back to
//                                the RVV helper, whatever the nine route rows say.
//
// Those are different questions about different code generators, and inheritance bound them to one
// live boolean. The loop tier is where that binding becomes unsatisfiable rather than merely
// awkward: its parent MUST run at 0 to arm at all, so its child could only ever be told 0, and
// T5e's published artifact was 166 bytes of four helper calls per iteration with zero ZMM operands
// -- from the same elfaot binary, on the same guest, whose offline compile at 1 produced 19/36 ZMM
// operands in 4 496/4 656 bytes.
//
// The fix is to give the row its KIND rather than to add a switch. `Substrate` rows are rendered
// from the spawning site's declared `RvvChildSubstrate` (aot.h); `Route` and `Diagnostic` rows are
// rendered from the parent's live value at every site, exactly as before. No option is emitted
// twice and no option is emitted conditionally: the table is still walked once, in order, and every
// row still produces exactly one `--flag=0/1`.
//
// WHY THE PARENT BEING 0 IS WHAT MAKES THE CHILD AT 1 SAFE, rather than a risk taken on top of one.
// With QCG vector-SSA off, every QCG RVV route completes its load/compute/store inside one guest
// instruction, so at the loop header the artifact is entered at, all guest-visible vector state is
// already in CPUState::VectorState. The artifact loads from and commits to that same memory. This
// is not a new pairing: T5e's offline arm ran exactly it -- an elfrun at 0 entering artifacts built
// at 1 -- across the whole campaign with correct digests.
//
// WHAT THIS ROW IS NOT: a way for a caller to ask for a different lowering. `LlvmPrerequisite` is
// not a tuning knob and takes no value from the user; it is the constant the LLVM backend requires
// in order to have any typed route at all. The two other C++ spawn sites keep `InheritParent`, and
// that is a decision rather than an oversight -- see each one's comment.
enum class RvvRouteKind {
	Route,      // a guest instruction form's direct lowering: cross-backend policy, parent's value
	Diagnostic, // emits counters; changes no admission and no lowering shape: parent's value
	Substrate,  // the LLVM child's typed-vector representation prerequisite: the SITE's value
};
struct RvvRouteFlag {
	char const *opt;   // elfaot/elfrun option spelling, without the leading "--"
	bool const *value; // the parent's live config field; read at spawn time, never cached
	RvvRouteKind kind; // T5f: what the row MEANS, and therefore where the child's value comes from
};
static RvvRouteFlag const kRvvRouteContract[] = {
    // C5.2a: typed RVV lowering at all -- and T5f: the ONE substrate row, not a route. See the
    // block above for why the parent's value is the wrong answer for an LLVM child.
    {"rvv-vector-ssa", &config::rvv_vector_ssa, RvvRouteKind::Substrate},
    // S3.4: exact vsetvli
    {"rvv-qcg-direct-setvl", &config::rvv_qcg_direct_setvl, RvvRouteKind::Route},
    // S3.5: exact unit-stride vle32.v
    {"rvv-qcg-typed-chunk-vle", &config::rvv_qcg_typed_chunk_vle, RvvRouteKind::Route},
    // S3.6: exact unit-stride vse32.v
    {"rvv-qcg-typed-chunk-vse", &config::rvv_qcg_typed_chunk_vse, RvvRouteKind::Route},
    // T1c: exact unmasked vsub.vv
    {"rvv-qcg-typed-chunk-sub", &config::rvv_qcg_typed_chunk_sub, RvvRouteKind::Route},
    // T1b: exact unmasked vmul.vv
    {"rvv-qcg-typed-chunk-mul", &config::rvv_qcg_typed_chunk_mul, RvvRouteKind::Route},
    // T1d: exact unmasked vxor.vv
    {"rvv-qcg-typed-chunk-xor", &config::rvv_qcg_typed_chunk_xor, RvvRouteKind::Route},
    // T1e: exact unmasked vor.vv
    {"rvv-qcg-typed-chunk-or", &config::rvv_qcg_typed_chunk_or, RvvRouteKind::Route},
    // T1f: exact unmasked vand.vv
    {"rvv-qcg-typed-chunk-and", &config::rvv_qcg_typed_chunk_and, RvvRouteKind::Route},
    // Native-3: unmasked e32/m1 vmul.vx and vmacc.vx. The NINTH route, and the first whose guest
    // form takes an operand from an integer register -- which changes nothing about this table's
    // rule. It is one row here and no spawn site changed, exactly as the rule promised for T1b/T1c.
    {"rvv-qcg-vx-mulacc", &config::rvv_qcg_vx_mulacc, RvvRouteKind::Route},
    // The LLVM child must explicitly receive sequence admission and partial-VL policy.
    {"rvv-vector-run", &config::rvv_vector_run, RvvRouteKind::Route},
    {"rvv-qcg-partial-vl", &config::rvv_qcg_partial_vl, RvvRouteKind::Route},
    {"rvv-qcg-typed-chunk-falu", &config::rvv_qcg_typed_chunk_falu, RvvRouteKind::Route},
    {"rvv-qcg-typed-chunk-fma", &config::rvv_qcg_typed_chunk_fma, RvvRouteKind::Route},
    // W5F: exact unmasked full-VL vfsqrt.v. THIS ROW IS THE T1c DEMONSTRATION REPEATING ITSELF,
    // and it was caught the same way -- by reading the two sides against each other rather than by
    // any test. W5F shipped the lowering (RvvEmitTypedSqrtChunkGroup), the gate
    // (RvvLLVMSqrtChunkAdmit) and its IR tests, and added neither an elfaot option nor a row here,
    // so `config::rvv_qcg_typed_chunk_fsqrt` was false in every freshly exec'd elfaot and the route
    // was unreachable from ANY artifact, offline or same-run. The gate deliberately reads only its
    // own switch (rv32_qir.cpp: "not the umbrella disjunction the QCG twin uses"), which makes the
    // missing option fatal rather than merely untidy: no other flag can turn the route on.
    //
    // The AUDIT-ONLY `--rvv-qcg-typed-chunk-fsqrt-force-emit` is NOT here and must not be: it
    // bypasses the host AVX-512F/BMI2 admission check, so emitted code SIGILLs on a host without
    // them. A parent may ask for it for itself; it is never a policy to hand a background builder.
    {"rvv-qcg-typed-chunk-fsqrt", &config::rvv_qcg_typed_chunk_fsqrt, RvvRouteKind::Route},
    // W6: exact unmasked full-VL ordered floating reduction. Same rule as every route row: one line
    // here, no spawn site changed. Its gate reads this switch alone, so a child that does not
    // receive it has no reduction route at all -- the T1c failure shape.
    {"rvv-qcg-typed-chunk-fredosum", &config::rvv_qcg_typed_chunk_fredosum, RvvRouteKind::Route},
    // W7. Without this row the online background `elfaot` never sees the switch and the route is
    // dead in every published artifact -- which is exactly what happened to the sqrt route once.
    {"rvv-qcg-typed-chunk-wholemove", &config::rvv_qcg_typed_chunk_wholemove, RvvRouteKind::Route},
    // C2a: the register-vtype vsetvl route.
    {"rvv-llvm-setvl-reg", &config::rvv_llvm_setvl_reg, RvvRouteKind::Route},
    // C2b: the scalar <-> vector element-0 transfer route.
    {"rvv-llvm-scalar-move", &config::rvv_llvm_scalar_move, RvvRouteKind::Route},
    // C5: partial-VL admission for the LLVM integer element-wise frame.
    {"rvv-llvm-partial-vl", &config::rvv_llvm_partial_vl, RvvRouteKind::Route},
    // C3: the immediate-shift family on the LLVM arm.
    {"rvv-llvm-shift", &config::rvv_llvm_shift, RvvRouteKind::Route},
    // C3: the integer extension family on the LLVM arm.
    {"rvv-llvm-extend", &config::rvv_llvm_extend, RvvRouteKind::Route},
    {"rvv-llvm-fclass", &config::rvv_llvm_fclass, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-itof", &config::rvv_llvm_fcvt_itof, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-ftoi", &config::rvv_llvm_fcvt_ftoi, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-fwiden", &config::rvv_llvm_fcvt_fwiden, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-fnarrow", &config::rvv_llvm_fcvt_fnarrow, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-itof-widen", &config::rvv_llvm_fcvt_itof_widen, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-ftoi-widen", &config::rvv_llvm_fcvt_ftoi_widen, RvvRouteKind::Route},
    {"rvv-llvm-fcvt-partial-vl", &config::rvv_llvm_fcvt_partial_vl, RvvRouteKind::Route},
    // Order item 3: architectural-mask support for the masked OPIVV integer element-wise family.
    {"rvv-llvm-masked", &config::rvv_llvm_masked, RvvRouteKind::Route},
    // Order item 3: FP predication for the typed FP lane family.
    {"rvv-llvm-fp-masked", &config::rvv_llvm_fp_masked, RvvRouteKind::Route},
    // Order item 3: nonzero vstart for the masked integer element-wise family.
    {"rvv-llvm-restart", &config::rvv_llvm_restart, RvvRouteKind::Route},
    // Order item 4: round-to-odd narrowing.
    {"rvv-llvm-fcvt-rod", &config::rvv_llvm_fcvt_rod, RvvRouteKind::Route},
    // Order item 4: the two 7-bit estimates.
    {"rvv-llvm-festimate", &config::rvv_llvm_festimate, RvvRouteKind::Route},
    // Order item 4: vfmerge.vfm / vfmv.v.f.
    {"rvv-llvm-fmerge", &config::rvv_llvm_fmerge, RvvRouteKind::Route},
    // Order item 4: the widening FP arithmetic family.
    {"rvv-llvm-fwiden", &config::rvv_llvm_fwiden, RvvRouteKind::Route},
    // Order item 4: the saturating integer add/sub family.
    {"rvv-llvm-satadd", &config::rvv_llvm_satadd, RvvRouteKind::Route},
    // Order item 4: the carry/borrow family.
    {"rvv-llvm-adc", &config::rvv_llvm_adc, RvvRouteKind::Route},
    {"rvv-llvm-avg", &config::rvv_llvm_avg, RvvRouteKind::Route},
    {"rvv-llvm-smul", &config::rvv_llvm_smul, RvvRouteKind::Route},
    {"rvv-llvm-nclip", &config::rvv_llvm_nclip, RvvRouteKind::Route},
    {"rvv-llvm-ired", &config::rvv_llvm_ired, RvvRouteKind::Route},
    {"rvv-llvm-mlogic", &config::rvv_llvm_mlogic, RvvRouteKind::Route},
    {"rvv-llvm-vid", &config::rvv_llvm_vid, RvvRouteKind::Route},
    {"rvv-llvm-mscalar", &config::rvv_llvm_mscalar, RvvRouteKind::Route},
    {"rvv-llvm-mprefix", &config::rvv_llvm_mprefix, RvvRouteKind::Route},
    {"rvv-llvm-viota", &config::rvv_llvm_viota, RvvRouteKind::Route},
    {"rvv-llvm-vcompress", &config::rvv_llvm_vcompress, RvvRouteKind::Route},
    {"rvv-llvm-vrgather", &config::rvv_llvm_vrgather, RvvRouteKind::Route},
    {"rvv-llvm-vslide", &config::rvv_llvm_vslide, RvvRouteKind::Route},
    {"rvv-llvm-vstrided", &config::rvv_llvm_vstrided, RvvRouteKind::Route},
    {"rvv-llvm-vindexed", &config::rvv_llvm_vindexed, RvvRouteKind::Route},
    {"rvv-llvm-fixed-masked", &config::rvv_llvm_fixed_masked, RvvRouteKind::Route},
    {"rvv-llvm-fp-cvt-masked", &config::rvv_llvm_fp_cvt_masked, RvvRouteKind::Route},
    {"rvv-llvm-fp-dynamic-frm", &config::rvv_llvm_fp_dynamic_frm, RvvRouteKind::Route},
    {"rvv-llvm-fwiden-partial-vl", &config::rvv_llvm_fwiden_partial_vl, RvvRouteKind::Route},
    {"rvv-llvm-fwiden-masked", &config::rvv_llvm_fwiden_masked, RvvRouteKind::Route},
    // C3: the widening integer family on the LLVM arm.
    {"rvv-llvm-widen", &config::rvv_llvm_widen, RvvRouteKind::Route},
    // C3: the narrowing shifts on the LLVM arm.
    {"rvv-llvm-narrow", &config::rvv_llvm_narrow, RvvRouteKind::Route},
    // C5-FP: partial VL for the LLVM FP lane family, via operand neutralisation.
    {"rvv-llvm-fp-partial-vl", &config::rvv_llvm_fp_partial_vl, RvvRouteKind::Route},
    {"rvv-qcg-typed-chunk-mem-e64", &config::rvv_qcg_typed_chunk_mem_e64, RvvRouteKind::Route},
    // DIAGNOSTIC, NOT A ROUTE. This one changes no admission and no lowering shape; it only makes
    // the backend emit the direct-hit/guard-miss counter increments. It is carried by the same
    // mechanism for one reason: without it a background-built artifact cannot report whether its
    // typed frames' taken path was actually taken, so the contract could not be checked by anything
    // stronger than reading the parent's own flags -- which is exactly the inference S3.7 must not
    // rely on. Listed after the routes and labelled so nobody mistakes it for a tenth: there are nine.
    {"rvv-vector-ssa-counters", &config::rvv_vector_ssa_counters, RvvRouteKind::Diagnostic},
    // T3b, ALSO DIAGNOSTIC AND ALSO NOT A ROUTE. `--aot-region-hit-count` makes the child emit
    // `CPUState::region_entry_hits[slot]++` at every admitted region's entry. It rides this
    // mechanism for the same reason the row above does: without it, a mid-run-promoted artifact can
    // be shown to EXIST and to have been dlopen'd, but not to have been ENTERED -- and "the
    // artifact loaded" is not the claim T3 bullet 2 has to support. With it, a nonzero slot at exit
    // (dumped by elfrun's --dump-region-hits) is the artifact reporting its own execution. There
    // are still nine routes; this is the second diagnostic.
    {"aot-region-hit-count", &config::aot_region_hit_count, RvvRouteKind::Diagnostic},
    // T5c-0, AND ALSO NOT A ROUTE. `--aot-loop-entry` decides whether the child gives the natural-loop
    // headers of the regions it admits their own entry symbols (no per-loop hotness gate; see
    // ModuleGraph::MarkLateEnterableLoopHeaders). It rides this mechanism for the same reason the two rows above
    // do, and for a sharper one: the flag is useless anywhere BUT a background build. Its whole
    // purpose is to make an artifact enterable at a loop that is already running by the time the
    // artifact lands, which is a situation only the same-run tier can be in. If the parent asked
    // for it and the contract did not carry it, the child would silently build the un-enterable
    // artifact and the tier would report a boot with zero AOT execution -- the exact failure this
    // flag exists to remove, reappearing as a missing handoff instead of a missing mechanism.
    // There are still nine routes; this is the third diagnostic.
    {"aot-loop-entry", &config::aot_loop_entry, RvvRouteKind::Diagnostic},
};
static constexpr size_t kRvvRouteContractN = sizeof(kRvvRouteContract) / sizeof(kRvvRouteContract[0]);

// T5f: THE ONE PLACE A ROW'S RENDERED VALUE IS DECIDED, so that both renderers below cannot differ
// about it and neither can grow a special case for the substrate row.
//
// It returns ONE bool per row and is called ONCE per row, which is the structural reason this fix
// cannot express itself as a duplicate option. The alternative shape -- render the whole table from
// the parent and then append `--rvv-vector-ssa=1` at the sites that need it -- would emit the option
// twice and rely on elfaot's last-value-wins parse. That is not a contract: it is a spelling whose
// meaning depends on the child's argument-parser policy, it makes a `ps` line ambiguous about what
// was actually asked for, and a reordering anywhere would silently invert it.
static bool RvvRouteRenderedValue(RvvRouteFlag const &row, RvvChildSubstrate substrate)
{
	switch (row.kind) {
	case RvvRouteKind::Substrate:
		// The site's declaration, not the parent's live value -- see the T5f block above.
		return substrate == RvvChildSubstrate::LlvmPrerequisite ? true : *row.value;
	case RvvRouteKind::Route:
	case RvvRouteKind::Diagnostic:
		// Unchanged at every site, including the loop tier's: S3.7's rule that a child's routes
		// are a function of the parent's configuration is about POLICY rows, and T5f does not
		// touch it. `substrate` is deliberately not consulted here.
		return *row.value;
	}
	Panic("aot_boot: RVV route contract row has no kind");
}

// Renderer 1: one space-joined string, for the two sites that build a shell command line
// (`system()` for the P1 build) and for the script handoff, which passes it as a single argument.
// Returns `buf`. Never emits a leading or trailing space, so it splices cleanly either side.
//
// T5f: takes the caller's `RvvChildSubstrate` for the same reason renderer 2 does, and both of this
// renderer's callers pass `InheritParent` -- documented at each. There is deliberately no default
// argument: a new spawn site must state which it is, because the failure this parameter exists to
// remove is exactly the one a default would let a new site inherit silently.
static char const *RvvRouteArgsJoined(char *buf, size_t n, RvvChildSubstrate substrate)
{
	size_t used = 0;
	buf[0] = '\0';
	for (size_t i = 0; i < kRvvRouteContractN; ++i) {
		int w = snprintf(buf + used, n - used, "%s--%s=%d", i ? " " : "",
				 kRvvRouteContract[i].opt,
				 (int)RvvRouteRenderedValue(kRvvRouteContract[i], substrate));
		if (w < 0 || (size_t)w >= n - used) {
			Panic("aot_boot: RVV route contract does not fit its argument buffer");
		}
		used += (size_t)w;
	}
	return buf;
}

// Renderer 2: one argv slot per flag, for the execv sites, which cannot take a joined string.
// `slots` must have kRvvRouteArgMax rows of at least 64 bytes; `out` receives the pointers, and the
// RETURN VALUE is how many were written. ORDER RELATIVE TO A CONDITIONAL argv SLOT IS THE CALLER'S
// PROBLEM and is documented at that call site: execv stops at the first nullptr, so these
// unconditional arguments must precede any optional one.
//
// T5d2a made this externally visible (declared in aot.h) so the loop tier's own spawn site renders
// the SAME table instead of growing a copy of it. Callers size their buffers by the bound rather
// than by the row count, so adding a row stays one edit here.
//
// T5f: `substrate` says where the ONE substrate row's value comes from; every other row is the
// parent's live value as before. One slot per row, in table order, at every value of the parameter.
static_assert(kRvvRouteContractN <= kRvvRouteArgMax,
	      "kRvvRouteArgMax must bound the route contract; raise it in aot.h when a row is added");
size_t RvvRouteArgv(char slots[kRvvRouteArgMax][64], char const *out[kRvvRouteArgMax],
		    RvvChildSubstrate substrate)
{
	for (size_t i = 0; i < kRvvRouteContractN; ++i) {
		snprintf(slots[i], 64, "--%s=%d", kRvvRouteContract[i].opt,
			 (int)RvvRouteRenderedValue(kRvvRouteContract[i], substrate));
		out[i] = slots[i];
	}
	return kRvvRouteContractN;
}

bool AotAbiCompatible(void *so_handle, char const *what)
{
	auto const *sig = (u64 const *)dlsym(so_handle, AOT_SYM_ABI);
	if (!sig) {
		log_dbt("%s: artifact has no %s symbol (built before the ABI gate); refusing it and "
			"falling back to JIT",
			what, AOT_SYM_ABI);
		fprintf(stderr, "AOT_ABI_REJECT %s reason=no_signature\n", what);
		return false;
	}
	u64 const want = rv32::CPUStateAbiSignature();
	if (*sig != want) {
		log_dbt("%s: artifact CPUState ABI %016llx != this build %016llx; refusing it and "
			"falling back to JIT",
			what, (unsigned long long)*sig, (unsigned long long)want);
		fprintf(stderr, "AOT_ABI_REJECT %s reason=mismatch artifact=%016llx build=%016llx\n", what,
			(unsigned long long)*sig, (unsigned long long)want);
		return false;
	}
	// X4g2 VLEN identity. Separate symbol and separate diagnostic from the layout check above, so
	// "wrong layout" and "wrong VLEN" never have to be told apart by guesswork.
	auto const *vlen = (u64 const *)dlsym(so_handle, AOT_SYM_VLEN);
	if (!vlen) {
		log_dbt("%s: artifact has no %s symbol (built before the VLEN gate); refusing it and "
			"falling back to JIT",
			what, AOT_SYM_VLEN);
		fprintf(stderr, "AOT_VLEN_REJECT %s reason=no_vlen_symbol\n", what);
		return false;
	}
	if (*vlen != (u64)config::vlen_bits) {
		log_dbt("%s: artifact RVV VLEN %llu != this process %u; refusing it and falling back to JIT",
			what, (unsigned long long)*vlen, config::vlen_bits);
		fprintf(stderr, "AOT_VLEN_REJECT %s reason=mismatch artifact=%llu process=%u\n", what,
			(unsigned long long)*vlen, config::vlen_bits);
		return false;
	}
	return true;
}

LOG_STREAM(aot)

static size_t get_vm_size() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("VmSize:", 0) == 0) {
            std::istringstream iss(line.substr(7)); // skip "VmSize:"
            size_t vm_kb;
            std::string unit;
            iss >> vm_kb >> unit;
            if (unit == "kB")
                return vm_kb;
        }
    }
    return 0;
}


void BootAOTFile()
{
	size_t vm_size_before = get_vm_size();
	void *so_handle;
	link_map *lmap;
	{
		DBT_FS_LOCK();
		auto aot_path = objprof::GetCachePath(AOT_SO_EXTENSION);
		log_dbt("profile name: %s", aot_path.c_str());

		if (so_handle = dlopen(aot_path.c_str(), RTLD_NOW); !so_handle) {
			log_dbt("failed to open %s: %s, skip aot boot", aot_path.c_str(), dlerror());
			return; // Round-17: actually skip (previously fell through to dlinfo(null) -> Panic)
		}
		if (dlinfo(so_handle, RTLD_DI_LINKMAP, (void *)&lmap) < 0) {
			Panic();
		}
	}

	auto l_addr = (u8 *)lmap->l_addr;

	// ABI gate. The cache path is keyed only by the guest ELF checksum, so an artifact built
	// against a DIFFERENT CPUState layout lives at the same path and would otherwise be loaded
	// with stale baked-in field offsets -- silent corruption. Refuse and fall back to the JIT,
	// which is always correct. A missing symbol means the artifact predates the gate, which is
	// exactly the case that must be refused.
	if (!AotAbiCompatible(so_handle, "aot boot")) {
		dlclose(so_handle);
		return;
	}

	auto aottab = (AOTTabHeader const *)dlsym(so_handle, AOT_SYM_AOTTAB);
	assert(aottab);

	auto announce = [l_addr](AOTSymbol const *sym) {
		auto tb = tcache::AllocateTBlock();
		if (tb == nullptr) {
			Panic();
		}
		tb->ip = sym->gip;
		tb->tcode = TBlock::TCode{l_addr + sym->aot_vaddr, 0};
		tcache::Insert(tb);
		tcache::CacheBr(tb); // todo: validate this if a brcc to llvm aot occurs.
		tcache::CacheBrind(tb);
		log_dbt("announce ip: %x", tb->ip);
	};

	for (u64 idx = 0; idx < aottab->n_sym; ++idx) {
		announce(&aottab->sym[idx]);
	}
	size_t vm_size = get_vm_size();
	log_dbt("aot size: %zu KB", vm_size - vm_size_before);
}

// Round-40: the artifact path the poll channel is currently waiting for. In sequence mode
// (inrun_seq_n>0) this is seq[idx] (the NEXT unbooted artifact); otherwise the legacy single path.
// 2026-07-14 skip-ahead: rungs may land out of pace (a later rung supersedes earlier ones). Boot the
// HIGHEST-index present artifact >= idx; lower rungs that land afterwards are stale and skipped forever.
static time_t g_top_booted_mtime = 0; // R7''-8: last-booted mtime of the TOP slot (re-boot support)
static int highest_present_seq()
{
	// R7''-8 TOP-SLOT RE-BOOT (2026-07-19, the seq-window bug that controlled the xalan fast/slow
	// bimodality ALL ALONG: the builder's k counter advances on every wake including dries, so a late
	// big build could land at rung_12/rung_13 -- OUTSIDE the parent's 12-slot path window -- and be
	// structurally unbootable; whether a run was fast was decided by counter-alignment luck. The
	// builder now caps its rung FILE index at the last slot (overwriting rung_11.so with newer
	// artifacts); the parent accepts a RE-boot of the top slot whenever its mtime advances past the
	// last boot. BootOneArtifact is idempotent/additive, so re-promotion is safe.)
	int top = config::inrun_seq_n - 1;
	if (top >= 0 && config::inrun_seq_idx > top && config::inrun_seq_paths[top]) {
		struct stat st_;
		if (stat(config::inrun_seq_paths[top], &st_) == 0 && st_.st_mtime > g_top_booted_mtime)
			return top;
	}
	for (int k = top; k >= config::inrun_seq_idx; k--)
		if (config::inrun_seq_paths[k] && access(config::inrun_seq_paths[k], F_OK) == 0)
			return k;
	return -1;
}


// R7''-6 shared census-flip walk (2026-07-19, unified-chain finding: the evaluator-tick site alone
// re-introduced xalan's bimodality -- 424.23 vs 1051.99 -- because time-driven doubling-paced walks
// are SPARSE late in the run, while round-4's slowpath-driven walks were event-driven: dispatch churn
// at a phase transition is exactly when the slowpath fires, so walks cluster at the moments that
// matter. BOTH sites now call this one helper sharing one pacing state: the slowpath site densifies
// walks under dispatch churn (xalan determinism), the evaluator site guarantees a floor for fully-
// L1-cached workloads with no slowpath traffic (leela liveness). Doubling pacing rate-limits the
// combined call stream identically to either site alone.)
// B-line round 10 (2026-07-22): factored out of CensusFlipWalk so an oracle trigger (fires the
// SAME actions at a precomputed, known-correct instant instead of via doubling-paced detection)
// can share the identical action code -- not a new/different action, a timing-source ablation.
// Per-action ablation flags (sr_cf_no_override/-regime/-wake, pre-existing) still gate each action
// independently and log a fire-count so which action(s) actually contribute can be measured.
static void FireCensusFlipActions(unsigned long long dq_c, unsigned long long da_c, char const *src)
{
	using namespace dbt::config;
	fprintf(stderr, "CENSUS_FLIP src=%s dq=%llu da=%llu\n", src, dq_c, da_c);
	esc_last_promo_window = 0;
	if (!sr_cf_no_override) {
		esc_census_override = true;
		config::esc_cf_action_override_fires++;
	}
	if (escalate_cache && !sr_cf_no_regime) {
		char rgp[4096];
		snprintf(rgp, sizeof rgp, "%s/regime", escalate_cache);
		FILE *rgf = fopen(rgp, "a");
		if (rgf) { fputc('R', rgf); fclose(rgf); }
		config::esc_cf_action_regime_fires++;
	}
	if (escalate_cache && !sr_cf_no_wake) {
		char wp2[4096];
		snprintf(wp2, sizeof wp2, "%s/want", escalate_cache);
		FILE *wf2 = fopen(wp2, "w");
		if (wf2) { fputc('1', wf2); fclose(wf2); }
		config::esc_cf_action_wake_fires++;
	}
}

static void CensusFlipWalk(bool from_slowpath)
{
	using namespace dbt::config;
	struct timespec ts_;
	clock_gettime(CLOCK_MONOTONIC, &ts_);
	unsigned long nowu = (unsigned long)(ts_.tv_sec * 1000000L + ts_.tv_nsec / 1000L);
	unsigned long *last = from_slowpath ? &esc_census_walk_last_us : &esc_census_walk2_last_us;
	unsigned long *gap = from_slowpath ? &esc_census_walk_gap_us : &esc_census_walk2_gap_us;
	if (*last != 0 && nowu - *last < *gap)
		return;
	*gap = *last ? (nowu - *last) * 2 : sr_cf_reset_gap_us;
	*last = nowu;
	unsigned long cen[4];
	tcache::TierCensus(cen);
	unsigned long long dq_c = cen[2] - esc_boot_census_q;
	unsigned long long da_c = cen[3] - esc_boot_census_a;
	bool flip_now = (dq_c > da_c);
	esc_census_walk_calls++;
	esc_census_walk_calls_postboot++;
	esc_last_dq_c = dq_c;
	esc_last_da_c = da_c;
	if (flip_now && !(sr_cf_once && esc_census_override)) {
		// R-FAMILY-6 (2026-07-19, termfix xalan_1: builder stuck in the DRY-doubling backoff after
		// t=33s -- its release signal (rip_head/pages doubling) is SAMPLER-produced and starves with
		// the sampler decay; the regime-file write releases one backoff episode, and round-4's
		// REPEATED per-flip regime writes -- the very "churn" the round-3 sticky latch was built to
		// eliminate -- were the load-bearing keep-alive for the builder. The latch stays (promotion
		// liveness needs it across calls) but the ACTIONS fire per WALK while the flip condition
		// holds: doubling pacing already bounds this to log-many writes, and each write releases the
		// builder if it has fallen into any evidence-starved sleep.)
		FireCensusFlipActions(dq_c, da_c, "detect");
	}
	esc_census_override = flip_now; // sticky latch (promotion side); cleared on counter-walk or at boot
}

// B-line round 10 oracle arm: fires the IDENTICAL actions once, at a precomputed wall-clock instant
// (--sr-oracle-flip-at-ms), instead of via CensusFlipWalk's doubling-paced detection. This isolates
// "detection latency" from "the action itself" -- an upper bound on what perfect-information timing
// could achieve for the SAME action, not a different/new mechanism.
static void OracleFlipCheck()
{
	using namespace dbt::config;
	if (sr_oracle_flip_at_ms <= 0 || esc_oracle_fired)
		return;
	struct timespec ts_;
	clock_gettime(CLOCK_MONOTONIC, &ts_);
	static long long t0_ms = -1;
	long long nowms = (long long)ts_.tv_sec * 1000 + ts_.tv_nsec / 1000000;
	if (t0_ms < 0)
		t0_ms = nowms;
	if (nowms - t0_ms < sr_oracle_flip_at_ms)
		return;
	esc_oracle_fired = true;
	unsigned long cen[4];
	tcache::TierCensus(cen);
	FireCensusFlipActions(cen[2] - esc_boot_census_q, cen[3] - esc_boot_census_a, "oracle");
}

static char const *current_inrun_path()
{
	if (config::inrun_seq_n > 0) {
		// decision-state gate: while a confirmed KEEP stands, higher rungs are NOT promoted (each swap
		// costs brind flush + relink churn -- measured -43pp on tight dispatch loops); a contradiction
		// re-open clears inrun_escalated and promotion resumes. Zero constants.
		// UNIFIED evidence gate (same sign test as decide/revise): promote the next rung only while the
		// CURRENT tier mix since the last swap is QCG-majority (artifact insufficient). If the current
		// artifact holds the time majority, promotion would be churn -- hold until evidence flips.
		if (config::inrun_seq_idx > 0 && config::escalate_time_census) {
			unsigned long bq = config::esc_qcg_samples - config::esc_boot_q;
			unsigned long ba = config::esc_aot_samples - config::esc_boot_a;
			// REGIME-FLIP RESET (phase_keep raw: promote-doubling inherited phase-1's 2.2s window ->
			// the phase-2 handler rung waited ~4.4s, landing at 7.1s of a 7.3s run). When the
			// post-boot majority sign FLIPS (artifact-winning -> QCG-winning), the old window
			// evidence belongs to the previous regime: reset the promotion window (same
			// reset-on-flip principle as verdict-stability rate control). Zero constants.
			static bool prev_aot_winning = false;
			bool aot_winning = (bq + ba > 0) && ba >= bq;
			if (config::sr_census_flip_check)
				if (config::sr_cf_site != 2)
					CensusFlipWalk(true); // event-driven site (ablatable)
			// Line-B activation invariant (LINEB_GATE_IMPLEMENTATION_PLAN.md): with --sr-activation-invariant,
			// the override may only fire once exec_instr_seen * Delta_machine > C_machine (pay-after-evidence;
			// both constants machine-measured, zero workload knobs). With the flag off (default), this clause
			// is always true and behavior is byte-identical to today.
			bool activation_ok = !config::sr_activation_invariant ||
					      ((double)CPUState::Current()->exec_instr_seen * config::kDeltaMachineNsPerInstr >
					       config::kCMachineNs);
			if (config::esc_census_override && !config::sr_cf_no_override && activation_ok)
				aot_winning = false; // R7''-sticky latch (set/cleared by the census walks)
			if (prev_aot_winning && !aot_winning) {
				// B-line reset-necessity ablation (2026-07-18 hourly review, front 5): two
				// independent flags isolate the parent-side anchor (esc_last_promo_window) from the
				// builder-side propagation (the $STG/regime file, which the builder reads to reset its
				// OWN anchors: DRY rip-head + built_mass/built_smass -- the 4th anchor found by the
				// timestamped-trace investigation). NO-RESET = both false. PARTIAL-RESET = parent-only
				// (reproduces the pre-4th-anchor-fix state: this is the exact bug FOURTH CROSS-REGIME
				// ANCHOR FOUND BY TIMESTAMPED BUILDER TRACE fixed). FULL-RESET = both true (default,
				// current shipped behavior).
				if (!config::sr_ablate_regime_reset_parent)
					config::esc_last_promo_window = 0; // regime flip: re-arm prompt promotion
				if (config::escalate_cache && !config::sr_ablate_regime_reset_builder) {
					char rgp[4096]; // propagate to the builder: its DRY/evidence anchors also belong
					// to the old regime (phase_keep raw: DRY-doubling inherited phase-1's rip_head,
					// ~6.5s to re-double)
					snprintf(rgp, sizeof rgp, "%s/regime", config::escalate_cache);
					FILE *rgf = fopen(rgp, "a");
					if (rgf) {
						fputc('R', rgf);
						fclose(rgf);
					}
					// R7''-4 (stickyON round-3: REALIZED no-gain at SATURATED share 91/91->92/92
					// idled the builder at t=12s; xalan's t=120s+ phase with 1.9B fresh mass was
					// never compiled because the only un-idle path -- the sampler-based REARM --
					// is starved. A census-detected flip IS the contradiction the reopen exists
					// for): the flip un-idles the builder directly.
					if (config::sr_census_flip_check) {
						char wp2[4096];
						snprintf(wp2, sizeof wp2, "%s/want", config::escalate_cache);
						FILE *wf2 = fopen(wp2, "w");
						if (wf2) { fputc('1', wf2); fclose(wf2); }
					}
				}
			}
			prev_aot_winning = aot_winning;
			// R7''-fix (2026-07-19, C_censusflip trace: 14 CENSUS_FLIP overrides fired, builder
			// re-armed 8-9 builds, yet SEQ_BOOTED stayed 4): this no-churn return originally
			// re-evaluated the RAW sampler condition, silently ignoring the census override that
			// aot_winning carries -- the flip's side effects (window reset, builder regime file)
			// all fired while the actual promotion path stayed blocked. Use aot_winning itself.
			if (aot_winning)
				return nullptr; // current tier mix winning: no churn (aot_winning already implies samples exist)
			// promote-evidence-doubling: each successive swap needs a window with at least DOUBLE the
			// samples that justified the previous swap (short runs cap at 1-2 swaps structurally; long
			// runs accrue samples ~linearly so doubling is met promptly). Zero constants.
			if (!config::sr_ablate_promote && config::esc_last_promo_window > 0 &&
			    bq + ba < 2 * config::esc_last_promo_window)
				return nullptr;
		}
		int k = highest_present_seq();
		return k >= 0 ? config::inrun_seq_paths[k] : nullptr;
	}
	return config::inrun_artifact_path;
}

// Round-17 BCT: cheap artifact-presence check callable from the brind slowpath (no allocation, one access()).
extern "C" {
}
bool dbt_inrun_artifact_present_impl()
{
	char const *p = current_inrun_path();
	if (!p)
		return false;
	return access(p, F_OK) == 0;
}

// Round-40: dlopen + promote every AOT symbol in one artifact (InsertOrReplace so QCG-translated ips migrate;
// RelinkTo migrates direct-link chains). Idempotent for ips already promoted by an earlier swap; additive for new
// ones. Returns symbol count promoted, or -1 on failure.
static long BootOneArtifact(char const *path)
{
	void *so_handle;
	link_map *lmap;
	if (!path || access(path, F_OK) != 0)
		return -1;
	if (so_handle = dlopen(path, RTLD_NOW); !so_handle) {
		log_dbt("inrun boot: dlopen failed: %s", dlerror());
		return -1;
	}
	if (dlinfo(so_handle, RTLD_DI_LINKMAP, (void *)&lmap) < 0)
		return -1;
	if (!AotAbiCompatible(so_handle, "inrun boot")) {
		dlclose(so_handle);
		return -1;
	}
	auto l_addr = (u8 *)lmap->l_addr;
	auto aottab = (AOTTabHeader const *)dlsym(so_handle, AOT_SYM_AOTTAB);
	if (!aottab)
		return -1;
	for (u64 idx = 0; idx < aottab->n_sym; ++idx) {
		auto const *sym = &aottab->sym[idx];
		auto tb = tcache::AllocateTBlock();
		if (tb == nullptr)
			return -1;
		tb->ip = sym->gip;
		tb->tcode = TBlock::TCode{l_addr + sym->aot_vaddr, 0};
		{ // time-census: widen the AOT code range to cover this artifact's symbols
			auto a = (unsigned long long)tb->tcode.ptr;
			if (!config::esc_aot_lo || a < config::esc_aot_lo)
				config::esc_aot_lo = a;
			if (a + 4096 > config::esc_aot_hi)
				config::esc_aot_hi = a + 4096; // page-granular upper pad (symbol sizes unknown here)
		}
		// C5d: ONE promotion primitive, not four hand-spelled calls. This is the sequence this
		// function used to spell (InsertOrReplace + CacheBr + CacheBrind + RelinkTo) extracted
		// verbatim into `tcache::PromoteTarget`, plus the inline-cache unpatch it was MISSING --
		// a blob patched before this boot would otherwise keep jumping straight into the
		// pre-promotion QCG code. The loop tier's installer now calls the same function, which is
		// the whole point: the wiring cannot drift between the two promoters because there is only
		// one copy of it.
		auto const pc = tcache::PromoteTarget(tb);
		config::inrun_relinked += pc.relinked; // v2: migrate direct-link chains
		config::inrun_ic_unpatched += pc.ic_unpatched;
	}
	return (long)aottab->n_sym;
}

// Round-17 BCT (Round-40 generalized): mid-run boot. Tolerates a missing artifact (returns false). In sequence mode,
// boots seq[idx], advances idx, and latches inrun_booted only after the LAST entry -- the poll channel stays open
// across swaps (small-hot -> full, or per-shard chunks). Length-1 / legacy single-artifact path is identical.
// 2026-07-07 time-census sampler: async-signal-safe two-range classify + increment.
static void esc_prof_handler(int, siginfo_t *, void *uc)
{
	auto *ctx = (ucontext_t *)uc;
	auto rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];
	if (config::sr_sampled_edges)
		config::edge_capture_due = true; // one-shot: next slowpath visit records ONE edge
	if (config::esc_rip_ring) {
		config::esc_rip_ring[config::esc_rip_head & (config::kRipRingSlots - 1)] = rip;
		config::esc_rip_head = config::esc_rip_head + 1;
	}
	if (rip >= config::esc_aot_lo && rip < config::esc_aot_hi)
		config::esc_aot_samples = config::esc_aot_samples + 1;
	else if (rip >= config::esc_qcg_lo && rip < config::esc_qcg_hi)
		config::esc_qcg_samples = config::esc_qcg_samples + 1;
}

// 2026-08-17 SUBSTRATE FIX (PM correction, cycle-1 invalidation): the builder CPU was chosen as
// (sched_getcpu() + 1) % _SC_NPROCESSORS_ONLN. Under a cpuset (the project's own
// rvdbt-bench-isolation run-pair grants CPUs 2-3 out of 0-5 online) that arithmetic routinely
// names a CPU the process is NOT allowed to use, `taskset`/sched_setaffinity then fails with
// EINVAL, and the builder never runs -- while the caller still reported a successful spawn.
// Select from the process's ACTUAL allowed mask instead, preferring a CPU other than the guest's.
// Returns -1 when the mask has no usable CPU, so callers can FAIL CLOSED instead of silently
// continuing and mislabelling a dead builder as an abstention.
//
// T5d2a: the rule itself now lives in looptier::SelectDistinctCpu/PickBuilderCpu (loop_tier.cpp),
// which is this function's former body verbatim, so the loop tier and the two sites here cannot
// drift into disagreeing about what "a distinct allowed CPU" means. The split also makes the
// no-distinct-CPU case constructible in a test instead of only reachable on a one-core cpuset.
static int dbt_pick_builder_cpu()
{
	return looptier::PickBuilderCpu();
}

bool BootAOTFileInRun()
{
	char const *path = current_inrun_path();
	long n_sym = BootOneArtifact(path);
	{
		struct timespec tsn;
		clock_gettime(CLOCK_MONOTONIC, &tsn);
		long ms = tsn.tv_sec * 1000L + tsn.tv_nsec / 1000000L - config::inrun_start_ms;
		if (n_sym < 0)
			fprintf(stderr, "INRUN_EVENT BOOT_FAILED t_ms=%ld path=%s\n", ms, path ? path : "(null)");
		else
			fprintf(stderr, "INRUN_EVENT BOOTED t_ms=%ld n_sym=%ld relinked=%lu path=%s\n",
				ms, n_sym, config::inrun_relinked, path ? path : "(null)");
		// T3b PROMOTION BOUNDARY. Everything the guest executed up to this instant ran as QCG
		// code; everything the promoted region executes after it runs as AOT code. Snapshotting
		// the two counters HERE is what makes "QCG work before / AOT work after" a measured split
		// rather than an inference from the end-of-run totals: region_entry_hits is emitted only
		// by AOT-generated code, so its value at this line is the before-picture and must be 0.
		if (config::inrun_evidence_gate && n_sym >= 0) {
			auto *st = CPUState::Current();
			unsigned long long hits_now = 0;
			if (st) {
				for (unsigned i = 0; i < CPUState::REGION_HIT_SLOTS; ++i)
					hits_now += st->region_entry_hits[i];
			}
			fprintf(stderr,
				"INRUN_EVENT PROMOTED t_ms=%ld qcg_hottest_at_promote=%llu "
				"qcg_typed_frames_at_promote=%llu aot_region_hits_at_promote=%llu\n",
				ms, (unsigned long long)config::inrun_evidence_hottest,
				(unsigned long long)(st ? st->rvv_direct_hits : 0), hits_now);
		}
	}
	if (n_sym < 0)
		return false;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	long off = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L - config::inrun_start_ms;
	config::inrun_boot_ms = off; // last-swap offset (back-compat); per-swap recorded below
	{
		unsigned long wq = config::esc_qcg_samples - config::esc_boot_q;
		unsigned long wa = config::esc_aot_samples - config::esc_boot_a;
		if (config::inrun_seq_idx > 1) // windows exist only after the first swap
			config::esc_last_promo_window = wq + wa;
	}
	config::esc_boot_q = config::esc_qcg_samples; // promotion-gate window restarts at each swap
	config::esc_boot_a = config::esc_aot_samples;
	config::esc_census_override = false; // R7''-sticky: a boot resolves the flip; next walk re-judges
	if (config::sr_census_flip_check) { // R7'': census baseline restarts with the sample window
		unsigned long cen[4];
		tcache::TierCensus(cen);
		config::esc_boot_census_q = cen[2];
		config::esc_boot_census_a = cen[3];
		config::esc_census_walk_last_us = 0; // next walk re-paces from this swap
		config::esc_census_walk_gap_us = 0;
		config::esc_census_walk2_last_us = 0;
		config::esc_census_walk2_gap_us = 0;
		config::esc_census_walk_calls_postboot = 0; // diagnostic: count calls since THIS boot specifically
	}
	{ // realized-benefit bookkeeping: remember the pre-swap window share and its evidence size
		unsigned long pq = config::esc_boot_q - config::esc_prev_boot_q, pa = config::esc_boot_a - config::esc_prev_boot_a;
		config::esc_pre_share_num = pa;
		config::esc_pre_share_den = pa + pq;
		config::esc_prev_boot_q = config::esc_boot_q;
		config::esc_prev_boot_a = config::esc_boot_a;
		config::esc_benefit_pending = true;
	}
	if (config::inrun_seq_n > 0) {
		int hk = highest_present_seq(); // the rung we just booted (path resolved through the same scan)
		if (hk == config::inrun_seq_n - 1 && config::inrun_seq_paths[hk]) { // R7''-8: top-slot mtime
			struct stat st_;
			if (stat(config::inrun_seq_paths[hk], &st_) == 0)
				g_top_booted_mtime = st_.st_mtime;
		}
		if (hk >= config::inrun_seq_idx)
			config::inrun_seq_idx = hk; // skip-ahead: supersede unlanded lower rungs
		if (config::inrun_seq_idx < config::kInrunSeqMax)
			config::inrun_seq_boot_ms[config::inrun_seq_idx] = off;
		config::inrun_seq_idx++;
		if (config::inrun_seq_idx >= config::inrun_seq_n) {
			// auto-escalate: while the decision is pending, keep the channel OPEN (booted=false keeps the
			// brind dirty-list maintained -> periodic flush -> slowpath escapes -> the evaluator actually
			// ticks). KEEP closes it below; ESCALATE appends seq[n] and the channel serves the next swap.
			// R-FAMILY-7: with census-flip on, the top slot is re-bootable whenever its mtime advances,
			// so the channel must stay open for the run's lifetime.
			if (!(config::inrun_auto_escalate && !config::inrun_escalated) &&
			    !(config::sr_census_flip_check && !config::sr_cf_no_reboot))
				config::inrun_booted = true; // all swaps applied -> close the channel
		}
	} else {
		config::inrun_booted = true;
	}
	if (config::inrun_seq_idx == 1 && config::esc_first_land_ms < 0)
		config::esc_first_land_ms = off; // price calibration: first build wall ~= land - fire
	if (config::escalate_time_census && config::inrun_seq_idx == 1) {
		// quality proxy baseline: samples accumulated SINCE PROCESS START (armed in elfrun) are all-QCG
		// (AOT range was empty pre-boot); pair them with the census QCG entry count at this instant.
		unsigned long c0[4];
		tcache::TierCensus(c0);
		config::esc_pre_q_samples = config::esc_qcg_samples;
		config::esc_pre_q_entries = c0[2];
		tcache::CodePoolBounds(const_cast<unsigned long long *>(&config::esc_qcg_lo),
				       const_cast<unsigned long long *>(&config::esc_qcg_hi));
		struct sigaction sa{};
		sa.sa_sigaction = esc_prof_handler;
		sa.sa_flags = SA_SIGINFO | SA_RESTART;
		sigaction(SIGPROF, &sa, nullptr);
		if (config::esc_sample_us <= 0)
			config::esc_sample_us = config::inrun_flush_ms * 1000L; // coarse start: keeper tick (substrate bound)
		struct itimerval tv{};
		tv.it_interval.tv_usec = config::esc_sample_us % 1000000L;
		tv.it_interval.tv_sec = config::esc_sample_us / 1000000L;
		tv.it_value = tv.it_interval;
		setitimer(ITIMER_PROF, &tv, nullptr);
	}
	log_dbt("inrun boot: %ld AOT symbols promoted mid-run (seq %d/%d)", n_sym, config::inrun_seq_idx,
		config::inrun_seq_n);
	fprintf(stderr, "INRUN_BOOT seq=%d/%d off_ms=%ld syms=%ld\n", config::inrun_seq_idx, config::inrun_seq_n, off, n_sym);
	return true;
}

// ---------------------------------------------------------------------------------------------
// P1 (2026-07-23, Workflow B): in-run indirect-target promotion (self-healing exile).
// Host stack ONLY (tcache_map walk, file I/O, synchronous child build). One-shot per run.
// Reuses the BCT substrate end to end: the keeper flush (elfrun p1_alarm_handler) keeps the
// slowpath escape channel open, and the landed artifact is applied through the SAME
// BootOneArtifact (InsertOrReplace + CacheBr/CacheBrind l1 swap + RelinkTo) as every existing
// mid-run swap. Ledger note (why this is NOT the killed same-core BCT-from-cold scenario): the
// baseline is a FROZEN stale artifact that never recompiles and drags the exiled span in QCG
// for the whole run; P1 spends one measured, fully-counted synchronous compile to recover that
// steady-state gap for the remainder of the SAME invocation. See FEASIBILITY_P1.md.
void P1ScanAndMaybePromote()
{
	using namespace dbt::config;
	if (p1_fired)
		return;
	// doubling-paced evidence walk (CensusFlipWalk pacing idiom): unchanged evidence doubles
	// the gap, growth resets it -- bounds the O(tcache_map) walk to log-many per stable phase.
	static unsigned long last_us = 0, gap_us = 0;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	unsigned long nowu = (unsigned long)(ts.tv_sec * 1000000L + ts.tv_nsec / 1000L);
	if (last_us != 0 && nowu - last_us < gap_us)
		return;
	unsigned long c = tcache::CountExiledHot(p1_threshold);
	p1_scans++;
	static unsigned long prev_c = 0;
	static unsigned dry = 0;
	bool grew = (c != prev_c);
	if (!grew && c > 0)
		dry++; // stable nonempty candidate set: one dry observation
	else
		dry = 0;
	prev_c = c;
	p1_crossed = c;
	gap_us = (grew || last_us == 0) ? 1 : (nowu - last_us) * 2;
	last_us = nowu;
	// FIRE RULE (zero new constants): candidates crossed the pipeline's OWN admission threshold
	// (p1_threshold = the elfaot --threshold of this pipeline) and the set is dry for 2
	// consecutive scans (epochs_dry k=2 idiom) -> the exiled hot span has stabilized; batch it
	// into ONE build instead of paying the LLVM fixed cost per late-crossing target.
	if (c == 0 || dry < 2)
		return;
	p1_fired = true; // latch before the slow work (the tick handler tests this)
	p1_crossed_at_fire = c;
	if (!p1_staging || !p1_elf || !p1_elfaot || !p1_run_cache) {
		fprintf(stderr, "P1_FIRE observation-only (staging/elf/elfaot missing) candidates=%lu\n", c);
		return;
	}
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	p1_fire_ms = t0.tv_sec * 1000L + t0.tv_nsec / 1000000L - p1_start_ms;
	// Export THIS run's realized evidence. GROW-ONLY MAX merge is mandatory: artifact-served
	// regions report ~0 exec in an aot run (native code does not self-count), so an overwriting
	// update would clobber the a-profile; MAX keeps a-counts and adds the exiled span's
	// re-enabled in-run counts (objprof.cpp:202-208).
	bool merge_save = aot_profile_merge;
	aot_profile_merge = true;
	objprof::UpdateProfile();
	aot_profile_merge = merge_save;
	// SYNCHRONOUS b-inclusive rebuild in the staging dir. Staging is mandatory: this process
	// holds an EXCLUSIVE flock on the run cache's .prof (fsmanager Task_OpenCacheFile), so a
	// builder pointed at the run cache would fail its shared lock; cp is lock-oblivious (the
	// sr_builder precedent). The guest is paused here -- the build wall lands INSIDE this
	// invocation's measurement, which is exactly the corrected P1 ledger.
	// X4g1 VLEN propagation: dbt::config is per-process, so this child's --vlen defaults to 128
	// (elfaot.cpp) unless told -- same reason --sr-activation-invariant is forwarded explicitly at
	// the escalation builder below. Without it the child compiles a VLEN-128 specialization no
	// matter what VLEN this elfrun is executing at, and publishes it as p1.so.
	// X4g3 publish selector: pick the ACTIVE-VLEN qualified artifact by name, not `ls *.aot.so |
	// head -1`. Now that artifacts are VLEN-qualified (objprof::GetCachePath), a staging directory
	// can legitimately hold more than one specialization, and `head -1` would publish whichever
	// sorted first -- possibly a stale build for a VLEN this process is not running at. The child
	// was just told `--vlen=%u`, so the name it produces is known exactly; select that one and let
	// the step fail if it is absent rather than substituting a different specialization.
	// S3.7: the whole RVV direct-route contract, rendered from kRvvRouteContract rather than
	// spelled out here -- see that table for why a per-site literal is the drift this forbids.
	// T5f: `InheritParent`, DELIBERATELY. This builder's parent is not barred from carrying the
	// substrate: an operator who wants a vector-lowered P1 artifact runs elfrun with
	// `--rvv-vector-ssa 1` and inheritance delivers it. That is the whole asymmetry with the loop
	// tier, whose Arm() refuses to arm at all under that flag. T5f changes the site that CANNOT ask
	// and leaves the two that can, so no behaviour measured before this checkpoint moves.
	char rvvargs[512];
	RvvRouteArgsJoined(rvvargs, sizeof rvvargs, RvvChildSubstrate::InheritParent);
	char cmd[8192];
	snprintf(cmd, sizeof cmd,
		 "cp %s/*.prof %s/ && %s --elf=%s --cache=%s --llvm=1 --vlen=%u %s "
		 "--threshold=%llu "
		 ">%s/p1_build.log 2>&1 && so=$(ls %s/*.v%u.aot.so 2>/dev/null | head -1) && "
		 "[ -n \"$so\" ] && mv \"$so\" %s/p1.so",
		 p1_run_cache, p1_staging, p1_elfaot, p1_elf, p1_staging, config::vlen_bits,
		 rvvargs,
		 (unsigned long long)p1_threshold, p1_staging, p1_staging, config::vlen_bits, p1_staging);
	int rc = system(cmd); // research substrate: synchronous build+publish, wall counted in-run
	if (rc != 0) {
		fprintf(stderr, "P1_BUILD failed rc=%d (see %s/p1_build.log)\n", rc, p1_staging);
		return;
	}
	char so_path[4096];
	snprintf(so_path, sizeof so_path, "%s/p1.so", p1_staging);
	long n = BootOneArtifact(so_path); // BCT substrate: InsertOrReplace + l1 swap + RelinkTo
	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	p1_land_ms = t1.tv_sec * 1000L + t1.tv_nsec / 1000000L - p1_start_ms;
	if (n < 0) {
		fprintf(stderr, "P1_BOOT failed (artifact unloadable) candidates=%lu\n", c);
		return;
	}
	p1_booted = true; // keeper stops; the b-inclusive artifact now serves the exiled span
	p1_boots++;
	fprintf(stderr, "P1_PROMOTED candidates=%lu syms=%ld fire_ms=%ld land_ms=%ld build_ms=%ld\n",
		c, n, p1_fire_ms, p1_land_ms, p1_land_ms - p1_fire_ms);
}

// AARS byte-identity filter: read the reuse ELF's .text (guest vaddr -> bytes) so we can verify, per region, that the
// CURRENT binary's guest bytes are identical before serving the reuse artifact's AOT for that gip.
struct ReuseText {
	std::vector<u8> buf; // .text bytes
	u32 vaddr = 0;
	bool ok() const { return !buf.empty(); }
	bool same(u32 gip, u32 n) const // current mmu bytes [gip,gip+n) == reuse .text bytes?
	{
		if (gip < vaddr || (u64)gip + n > (u64)vaddr + buf.size())
			return false;
		return memcmp((const void *)((uptr)mmu::base + gip), &buf[gip - vaddr], n) == 0;
	}
};
static ReuseText LoadReuseText(char const *elf_path)
{
	ReuseText rt;
	std::ifstream f(elf_path, std::ios::binary);
	if (!f)
		return rt;
	std::vector<u8> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	if (d.size() < 0x34)
		return rt;
	auto rd16 = [&](u32 o) { return (u32)d[o] | ((u32)d[o + 1] << 8); };
	auto rd32 = [&](u32 o) { return (u32)d[o] | ((u32)d[o + 1] << 8) | ((u32)d[o + 2] << 16) | ((u32)d[o + 3] << 24); };
	u32 shoff = rd32(0x20), she = rd16(0x2e), shn = rd16(0x30), shstr = rd16(0x32);
	u32 stroff = rd32(shoff + shstr * she + 0x10);
	for (u32 i = 0; i < shn; ++i) {
		u32 e = shoff + i * she;
		u32 noff = rd32(e + 0), addr = rd32(e + 0xc), off = rd32(e + 0x10), sz = rd32(e + 0x14);
		const char *nm = (const char *)&d[stroff + noff];
		if (strcmp(nm, ".text") == 0) {
			rt.vaddr = addr;
			rt.buf.assign(d.begin() + off, d.begin() + off + sz);
			break;
		}
	}
	return rt;
}

// 2026-06-19 AARS: boot ANOTHER binary's .aot.so by gip (cross-program reuse). The loader keys by gip (no binary
// checksum). When config::aot_reuse_elf is set, each gip is served AOT ONLY if the current binary's region bytes
// [gip,next_gip) are byte-identical to the reuse ELF's -> correct by construction; unmatched gips fall back to QCG.
long BootReuseArtifact(char const *path)
{
	void *so_handle;
	link_map *lmap;
	if (!path || access(path, F_OK) != 0)
		return -1;
	if (so_handle = dlopen(path, RTLD_NOW); !so_handle) {
		log_dbt("aars reuse: dlopen failed: %s", dlerror());
		return -1;
	}
	if (dlinfo(so_handle, RTLD_DI_LINKMAP, (void *)&lmap) < 0)
		return -1;
	if (!AotAbiCompatible(so_handle, "aars reuse")) {
		dlclose(so_handle);
		return -1;
	}
	auto l_addr = (u8 *)lmap->l_addr;
	auto aottab = (AOTTabHeader const *)dlsym(so_handle, AOT_SYM_AOTTAB);
	if (!aottab)
		return -1;
	ReuseText rt;
	bool filter = config::aot_reuse_elf != nullptr && config::aot_reuse_elf[0] != '\0';
	if (filter) {
		rt = LoadReuseText(config::aot_reuse_elf);
		if (!rt.ok()) {
			log_dbt("aars reuse: cannot read reuse-elf .text %s; serving UNFILTERED", config::aot_reuse_elf);
			filter = false;
		}
	}
	// SAFETY GATE (all-or-nothing): the reuse artifact is a CLOSED AOT graph -- its functions musttail each other by
	// MakeAotSymbol(gip) intra-.so. Serving a SUBSET is unsafe: a served region can branch into a non-served (byte-
	// DIFFERENT) region's code. So we serve the artifact ONLY if EVERY region is byte-identical in the current binary
	// over its EXACT guest extent (sym->gsize = max ip_end - entry, recorded at build) -- no over-reach into adjacent
	// excluded regions, no magic window. Otherwise ABSTAIN entirely -> the binary runs its own Wendell/QCG (no
	// regression, no wrong code). This is the no-op-safety guarantee for unrelated binaries.
	if (filter) {
		for (u64 idx = 0; idx < aottab->n_sym; ++idx) {
			u32 gsz = aottab->sym[idx].gsize ? aottab->sym[idx].gsize : 4; // >=1 insn
			if (!rt.same(aottab->sym[idx].gip, gsz)) {
				log_dbt("aars reuse: ABSTAIN (gip %08x differs over %u bytes; closed graph not present)", aottab->sym[idx].gip, gsz);
				if (getenv("AARS_TRACE")) // env-gated audit trace (default-off: no env -> silent, no behavior change)
					fprintf(stderr, "AARS_TRACE ABSTAIN gip=%08x bytes=%u (closed graph not present)\n", aottab->sym[idx].gip, gsz);
				return 0; // not a family match -> do not reuse; fall back to own Wendell/QCG
			}
		}
	}
	long served = 0;
	for (u64 idx = 0; idx < aottab->n_sym; ++idx) {
		auto const *sym = &aottab->sym[idx];
		auto tb = tcache::AllocateTBlock();
		if (tb == nullptr)
			return -1;
		tb->ip = sym->gip;
		tb->tcode = TBlock::TCode{l_addr + sym->aot_vaddr, 0};
		// C5d: the same promotion, and therefore the same primitive. This site was a verbatim
		// copy of BootOneArtifact's four calls, so it inherited the missing inline-cache unpatch
		// too; both are fixed by there being one implementation.
		auto const pc = tcache::PromoteTarget(tb);
		config::inrun_relinked += pc.relinked;
		config::inrun_ic_unpatched += pc.ic_unpatched;
		served++;
	}
	log_dbt("aars reuse: served %ld / %llu regions (filter=%d)", served, (unsigned long long)aottab->n_sym, filter);
	if (getenv("AARS_TRACE")) // env-gated audit trace (default-off: no env -> silent, no behavior change)
		fprintf(stderr, "AARS_TRACE SERVED %ld/%llu filter=%d\n", served, (unsigned long long)aottab->n_sym, filter);
	return served;
}

// 2026-07-05 in-process closed-loop escalation (B-line). Host stack only (census walks a std::map; fork
// requires the verified single-thread run path). Rule = the SAME v2 majority sign test, evaluated on the
// census DELTA since the first artifact booted (post-chunk execution only). Zero constants. One-shot.
static inline unsigned long now_us()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long)(ts.tv_sec * 1000000L + ts.tv_nsec / 1000L);
}
static inline unsigned long now_cpu_us()
{
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return (unsigned long)(ts.tv_sec * 1000000L + ts.tv_nsec / 1000L);
}
struct EvalTimer { // pre-NONE cost trace: cumulative evaluator foreground time
	unsigned long t0, tc0;
	EvalTimer() : t0(now_us()), tc0(now_cpu_us()) {}
	~EvalTimer()
	{
		dbt::config::esc_us_eval += now_us() - t0;
		dbt::config::esc_us_eval_cpu += now_cpu_us() - tc0; // V151 diagnostic, see config.h
	}
};
void EvaluateAndMaybeEscalate()
{
	EvalTimer _evt;
	config::esc_eval_count++; // starvation detector: the keeper flushes only while we are NOT running
	using namespace dbt::config;
	// R7''-6: evaluator-tick site = liveness floor for workloads with no slowpath traffic (leela).
	if (inrun_auto_escalate && sr_census_flip_check && escalate_time_census && inrun_seq_idx > 0 && sr_cf_site != 1)
		CensusFlipWalk(false);
	if (inrun_auto_escalate && sr_oracle_flip_at_ms > 0)
		OracleFlipCheck();
	if (inrun_auto_escalate && esc_benefit_pending && esc_pre_share_den > 0 && !sr_ablate_realized) {
		unsigned long q = esc_qcg_samples - esc_prev_boot_q, a = esc_aot_samples - esc_prev_boot_a;
		if (q + a >= esc_pre_share_den) { // equal evidence accumulated
			esc_benefit_pending = false;
			// realized benefit: post-swap AOT share vs pre-swap (cross-multiplied, integer-safe)
			bool gained = (unsigned long long)a * esc_pre_share_den >
				      (unsigned long long)esc_pre_share_num * (a + q);
			// sqlite-mode vs xerces-mode discrimination (SQATTR: builds/boots = ~6pp on sqlite while
			// every landed swap shows ZERO realized AOT share): a==0 means the landed artifact is not
			// observed executing AT ALL -- climbing cannot help until the profile shifts. Two
			// consecutive zero-share landed swaps (independent confirmations, doubling-family) beat
			// the live-majority suppression; contradiction growth re-open still re-arms (idle != stop).
			if (a == 0)
				esc_zero_share_swaps++;
			else
				esc_zero_share_swaps = 0;
			// prefix-trap guard (instance #4 lesson): a single swap's verdict must not override the
			// LIVE majority state -- while QCG still holds the time majority, more benefit is provably
			// available (the ladder is mid-climb); idle only when there is ALSO nothing left to gain.
			if (!gained && a <= q && esc_zero_share_swaps < 2)
				gained = true; // suppress idle: live majority says keep climbing
			// R6' PENDING-MASS CROSS-CHECK (2026-07-18, leela race root cause; opt-in
			// --sr-realized-pend-check): zero realized share proves the LANDED artifact is not
			// executing -- it does NOT prove there is nothing worth building. Leela raw (two
			// independent 1800s runs + one recovered 40s run): the first two rungs land 24KB of
			// non-hot code, the zero-share verdict fires at ~0.65s, and the builder -- whose own
			// dry-run sees 20-29M pending admissible mass at the very next rung -- is idled
			// PERMANENTLY (the contradiction reopen is page-growth-gated and leela's pages
			// plateau early). Whether the run completes is decided by a RACE between the
			// builder's next dry-wake and this verdict. Fix: before idling, consult the
			// builder's own R4 currency (pend_c vs built_mass, published in $STG/pend); if the
			// builder holds doubling-worthy pending mass, the correct reading is "artifact TOO
			// SMALL so far", not "nothing to gain" -- do not idle. Termination is unaffected:
			// builds stay bounded by the builder's own per-channel doubling gate (R4), which is
			// exactly why no new constant is needed here.
			if (!gained && config::sr_realized_pend_check && escalate_cache) {
				char pp[4096];
				snprintf(pp, sizeof pp, "%s/pend", escalate_cache);
				FILE *pf = fopen(pp, "r");
				if (pf) {
					unsigned long long pend_c = 0, built_m = 0;
					if (fscanf(pf, "%llu %llu", &pend_c, &built_m) == 2 && pend_c > 0 &&
					    pend_c >= built_m) {
						gained = true; // builder has evidence-justified work: not idle
						fprintf(stderr,
							"REALIZED no-gain OVERRIDDEN by pending mass %llu >= built %llu\n",
							pend_c, built_m);
					}
					fclose(pf);
				}
			}
			// R6'' census idle-guard (2026-07-19, leela_full regression: the pend file is STALE at
			// verdict time -- the builder had just consumed its pending set, so pend_c=65K < built=24.9M
			// and the override stayed silent; with no in-flight build to land, the gain-revive half
			// never fired either -- the exact "no-in-flight-build geometry" flagged un-exercised in the
			// R6' doc. 4th instance of the same defect family). The exec-count census is neither stale
			// nor sampler-dependent: if QCG execution since the last boot dwarfs AOT execution, there is
			// PROVABLY massive unserved work regardless of what the tiny landed artifact's share says --
			// idling the builder now would orphan that work. Same fix class as R6'/R7'': cross-check the
			// starving signal against an independent free evidence stream.
			if (!gained && config::sr_realized_pend_check) {
				unsigned long cen2[4];
				tcache::TierCensus(cen2);
				if (cen2[2] > cen2[3]) {
					gained = true;
					fprintf(stderr, "REALIZED no-gain OVERRIDDEN by census qcg=%lu > aot=%lu\n",
						cen2[2], cen2[3]);
				}
			}
			if (!gained && escalate_cache) {
				char wp[4096];
				snprintf(wp, sizeof wp, "%s/want", escalate_cache);
				FILE *wf = fopen(wp, "w");
				if (wf) { fputc('0', wf); fclose(wf); }
				esc_last_keep = true; // hold promotions too; contradiction resumes both
				fprintf(stderr, "REALIZED no-gain: idling builder (pre %lu/%lu post %lu/%lu)\n",
					esc_pre_share_num, esc_pre_share_den, a, a + q);
			} else if (gained) {
				// ONE-WAY-IDLE FIX (same flag): a later realized GAIN is direct evidence the
				// builder's output pays -- un-idle it (found: the recovered leela run reached
				// 45/45 AOT share with want still 0 from an earlier no-gain; nothing ever
				// rewrites want=1 on the gain path, only the page-growth-gated reopen does).
				if (config::sr_realized_pend_check && escalate_cache) {
					char wp[4096];
					snprintf(wp, sizeof wp, "%s/want", escalate_cache);
					FILE *wf = fopen(wp, "w");
					if (wf) { fputc('1', wf); fclose(wf); }
				}
				fprintf(stderr, "REALIZED gain (pre %lu/%lu post %lu/%lu)\n",
					esc_pre_share_num, esc_pre_share_den, a, a + q);
			}
		}
	}
	if (escalate_time_census && esc_rip_head > 0) {
		// verdict-stability rate control (v2, closed-loop, zero constants): the sampler exists to serve
		// the census DECISION, so its rate follows decision uncertainty, not raw sample count. Start
		// COARSE at the keeper tick (substrate bound; v1's fixed 1ms start burned its tax across entire
		// short runs -- sqlite obs-only +5.8 median, SQ5 raw). Each time evidence doubles, compare the
		// census majority sign now vs at half evidence (self-similar stability test, no p-value
		// constant): same sign -> stable -> halve frequency (cap keeper tick); flipped -> unstable ->
		// double frequency (floor 1ms = itimer resolution). Losers stay coarse for the whole run
		// (tax -> 0); winners refine exactly while the verdict is in motion.
		if (esc_rate_anchor == 0) {
			esc_rate_anchor = esc_rip_head;
			esc_anchor_sign = (esc_qcg_samples >= esc_aot_samples);
		} else if (esc_rip_head >= 2 * esc_rate_anchor) {
			bool sign_now = (esc_qcg_samples >= esc_aot_samples);
			long want = esc_sample_us;
			if (sign_now == esc_anchor_sign && esc_sample_us < inrun_flush_ms * 1000L)
				want = esc_sample_us * 2; // stable: coarsen
			else if (sign_now != esc_anchor_sign && esc_sample_us > 1000L)
				want = esc_sample_us / 2; // verdict in motion: refine
			esc_rate_anchor = esc_rip_head;
			esc_anchor_sign = sign_now;
			if (want != esc_sample_us) {
				if (config::sr_log_ratecontrol) {
					struct timespec ts;
					clock_gettime(CLOCK_MONOTONIC, &ts);
					fprintf(stderr, "RATECTL t_ms=%lld %s %ld->%ld sign=%d rip_head=%lu\n",
						(long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000,
						want > esc_sample_us ? "COARSEN" : "REFINE", esc_sample_us, want,
						(int)sign_now, esc_rip_head);
				}
				esc_sample_us = want;
				struct itimerval tvr{};
				tvr.it_interval.tv_usec = esc_sample_us % 1000000L;
				tvr.it_interval.tv_sec = esc_sample_us / 1000000L;
				tvr.it_value = tvr.it_interval;
				setitimer(ITIMER_PROF, &tvr, nullptr);
			}
		}
	}
	if (inrun_single_run && inrun_builder_pid > 0 && !sr_ablate_updprof) {
		// DEMAND-DRIVEN profile maintenance (SQATTR raw: unconditional per-tick UpdateProfile+dumps =
		// ~8pp of sqlite's regression, the dominant marginal obs tax; rate-control attribution to SIGPROF
		// frequency was REFUTED by RC2). The builder consumes the profile exactly once per rung (its cp at
		// iteration start): it requests freshness via $STG/wantprof; the parent honors on the next tick and
		// unlinks as ack -> log-many updates total instead of one per 50ms tick. evid export stays per-tick
		// (two counters, no map walk) or the builder's DRY doubling gate would starve and stall the ladder.
		if (escalate_cache) {
			char wp[4096];
			snprintf(wp, sizeof wp, "%s/wantprof", escalate_cache);
			if (access(wp, F_OK) == 0) {
				unsigned long ack0 = now_us();
				objprof::UpdateProfile();
				char tp[4096];
				snprintf(tp, sizeof tp, "%s/tbmap.txt", escalate_cache);
				tcache::DumpTBMap(tp);
				if (profile_brind_edges || sr_sampled_edges) {
					char ep[4096];
					snprintf(ep, sizeof ep, "%s/edges.txt", escalate_cache);
					brindedges::Dump(ep);
				}
				if (escalate_run_cache)
					utimensat(AT_FDCWD, escalate_run_cache, nullptr, 0);
				unlink(wp); // ack: builder proceeds with its cp
				esc_us_acks += now_us() - ack0;
				esc_n_acks++;
			}
			char tp2[4096];
			snprintf(tp2, sizeof tp2, "%s/evid", escalate_cache);
			FILE *ef = fopen(tp2, "w");
			if (ef) {
				fprintf(ef, "%lu %lu\n", (unsigned long)esc_rip_head,
					(unsigned long)objprof::GetProfile().size());
				fclose(ef);
			}
		}
	}
	if (dvet_enable && escalate_cache && inrun_seq_idx > 0) {
		// DVET epoch trial (docs/DVET_DESIGN.md): when the builder publishes trial_P.so/trial_S.so
		// (equal work-counter instrumentation), alternate P/S epochs of equal in-pair length (length
		// doubles across pairs), compare work-rate (region entries per us), and keep/rollback on two
		// CONSECUTIVE pair wins (doubling-family confirmation). All costs bounded: 2 swaps per pair,
		// counter overhead equal in both variants, rollback = boot the pre-trial artifact.
		char tp_p[4096], tp_s[4096];
		snprintf(tp_p, sizeof tp_p, "%s/trial_P.so", escalate_cache);
		snprintf(tp_s, sizeof tp_s, "%s/trial_S.so", escalate_cache);
		auto now_us_l = []() {
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			return (unsigned long)(ts.tv_sec * 1000000L + ts.tv_nsec / 1000L);
		};
		CPUState *st = CPUState::Current();
		config::g_gbrind_exec_mirror = st->gbrind_counter; // A-line surface (a) exit mirror
		// RIPE gate (majority principle): the WHETHER question is live only once dispatch has MOVED
		// into AOT code (census AOT-majority). In the early selective phase the L1 brind cache serves
		// dispatch and trials measure parity by construction (DVET_LOCAL3: all rates equal). Signal
		// the builder via dvet_ripe so the trial pair is built from the AOT-majority working set.
		if (esc_aot_samples >= esc_qcg_samples && esc_aot_samples > 0) {
			esc_dvet_ripe = true; // arms the edge estimator (pay-after-evidence: no consumer before ripe)
			char rp2[4096];
			snprintf(rp2, sizeof rp2, "%s/dvet_ripe", escalate_cache);
			if (access(rp2, F_OK) != 0) {
				FILE *rf2 = fopen(rp2, "w");
				if (rf2)
					fclose(rf2);
			}
		}
		// ORDER COUNTERBALANCING (DVET_NLP raw: second variant inherits warmed caches/relinked state ->
		// systematic bias): even pairs run P->S, odd pairs S->P; verdict still needs 2 CONSECUTIVE pair
		// wins, so a pure order artifact (which flips with the order) can never win twice in a row.
		// SETTLE TICK: the epoch's first tick absorbs boot/relink churn; counting starts one tick later
		// (dvet_phase 3 = settling; work0/us0 re-snapshot when it ends).
		bool p_first = (dvet_pair % 2) == 0;
		if (dvet_phase == 0 && dvet_verdict == 0 && access(tp_p, F_OK) == 0 && access(tp_s, F_OK) == 0) {
			if (BootOneArtifact(p_first ? tp_p : tp_s) > 0) {
				dvet_phase = 3; // settle, then measure first epoch
				dvet_epoch_ticks = 0;
				fprintf(stderr, "DVET START pair=%d len=%lu order=%s\n", dvet_pair, dvet_epoch_len,
					p_first ? "PS" : "SP");
			}
		} else if (dvet_phase == 3 || dvet_phase == 4) { // settle tick after a boot
			dvet_phase -= 2; // 3->1 (first epoch), 4->2 (second epoch)
			dvet_epoch_ticks = 0;
			dvet_work0 = st->work_counter;
			dvet_us0 = now_us_l();
		} else if (dvet_phase > 0 && ++dvet_epoch_ticks >= dvet_epoch_len) {
			unsigned long dus = now_us_l() - dvet_us0;
			double rate = dus ? (double)(st->work_counter - dvet_work0) / (double)dus : 0.0;
			if (dvet_phase == 1) {
				if (p_first)
					dvet_rate_p = rate;
				else
					dvet_rate_s = rate;
				if (BootOneArtifact(p_first ? tp_s : tp_p) > 0) {
					dvet_phase = 4; // settle, then second epoch
					dvet_epoch_ticks = 0;
				}
			} else {
				if (p_first)
					dvet_rate_s = rate;
				else
					dvet_rate_p = rate;
				dvet_pair++;
				bool s_won = dvet_rate_s > dvet_rate_p;
				if (s_won) { dvet_s_wins++; dvet_p_wins = 0; }
				else { dvet_p_wins++; dvet_s_wins = 0; }
				fprintf(stderr, "DVET PAIR %d rate_p=%.3f rate_s=%.3f len=%lu %s\n",
					dvet_pair, dvet_rate_p, dvet_rate_s, dvet_epoch_len, s_won ? "S" : "P");
				if (dvet_s_wins >= 2 || dvet_p_wins >= 2) {
					dvet_verdict = dvet_s_wins >= 2 ? 'S' : 'P';
					dvet_phase = 0;
					// final boot: winner側 uninstrumented -- P = the pre-trial landed artifact
					// (highest seq rung), S = trial_S itself for now (instrumented; the uninstru-
					// mented S rebuild is a builder follow-up published as the next rung)
					if (dvet_verdict == 'P') {
						int k = highest_present_seq();
						if (k >= 0)
							BootOneArtifact(inrun_seq_paths[k]);
					} else {
						char rq[4096]; // winner realization: builder publishes uninstrumented S
						snprintf(rq, sizeof rq, "%s/dvet_wantS", escalate_cache);
						FILE *rf = fopen(rq, "w");
						if (rf)
							fclose(rf);
					}
					fprintf(stderr, "DVET VERDICT %c pairs=%d\n", dvet_verdict, dvet_pair);
				} else {
					dvet_epoch_len *= 2; // next pair: doubled epochs
					if (BootOneArtifact(tp_p) > 0) {
						dvet_phase = 1;
						dvet_epoch_ticks = 0;
						dvet_work0 = st->work_counter;
						dvet_us0 = now_us_l();
					}
				}
			}
		}
	}
	if (inrun_auto_escalate && inrun_escalated && esc_pages_at_decision && escalate_contradiction) {
		// CONTRADICTION rule (zero constants): a KEEP is a hypothesis. Apply the SAME time-majority sign
		// test to the post-decision window; if QCG time now outweighs AOT time since the KEEP, the
		// decision is contradicted by its own evidence standard -> re-open once. (Page-growth staleness
		// was falsified: miniz's code pages are all seen early -- what shifts is where TIME goes.)
		unsigned long pdq = esc_qcg_samples - esc_census0_q, pda = esc_aot_samples - esc_census0_a;
		if (pdq + pda > 0 && pdq > pda) {
			objprof::UpdateProfile();
			unsigned long now_pages = (unsigned long)objprof::GetProfile().size();
			if (now_pages > esc_pages_at_last_build) { // TERMINATION: rebuild only on grown evidence
				esc_rearmed = true;
				esc_reopen_count++;
				if (escalate_cache) {
					char wp[4096];
					snprintf(wp, sizeof wp, "%s/want", escalate_cache);
					FILE *wf = fopen(wp, "w");
					if (wf) { fputc('1', wf); fclose(wf); }
				}
				inrun_escalated = false;
				inrun_census0_taken = false;
				inrun_booted = false;
				fprintf(stderr, "AUTOESC REARM #%lu pdQ=%lu pdA=%lu pages %lu->%lu\n",
					esc_reopen_count, pdq, pda, esc_pages_at_last_build, now_pages);
			} else {
				esc_census0_q = esc_qcg_samples; // contradiction noted but evidence unchanged:
				esc_census0_a = esc_aot_samples; // reset window, no wasted rebuild
			}
		}
	}
	if (!inrun_auto_escalate || inrun_escalated)
		return;
	// TRUE SINGLE-RUN first rung: at the first tick, snapshot the run's OWN profile (host stack; grow-only
	// mmap update) and fork the Wendell-default selective build. The existing poll channel swaps it in and
	// the census loop takes over. No run-1 anywhere.
	if (inrun_single_run && !sr_first_fired) {
		// ablation: census-off = pure descent, no decision layer (evaluator still fires the builder once)

		// T3b RUNTIME-EVIDENCE GATE (config::inrun_evidence_gate, default OFF).
		//
		// WHAT IT REPLACES AND WHY. Without it this block fires on the FIRST evaluator tick, and
		// the evaluator is armed by a fixed-cadence SIGALRM (--inrun-flush-ms). That makes the
		// build trigger a function of WALL TIME, not of anything the guest did, so calling it
		// hot-region detection would be false -- and the closure checklist's T3 bullet 4 forbids
		// exactly that description. The first-tick behaviour is real lifecycle plumbing (it gets
		// an artifact built, shipped and booted mid-run); it is only the DETECTION claim that it
		// cannot support.
		//
		// THE BAR IS NOT A NEW CONSTANT. It is `sr_chunk_threshold` -- the very number this
		// function is about to hand the builder as elfaot's `--threshold`, i.e. the count at
		// which the offline compiler itself decides a region is worth compiling. So the gate
		// reads: fire only once the run's OWN accumulated execution evidence has made some region
		// admissible BY THE BUILDER'S OWN ADMISSION DEFINITION. Nothing here was chosen to make a
		// particular workload pass; a workload that never gets hot never fires, which is the
		// correct behaviour and is exercised as a negative control.
		//
		// THE EVIDENCE IS THE PROFILE THE BUILDER WILL CONSUME. `objprof::UpdateProfile()` folds
		// every TB's `flags.exec_count` into the per-page profile; the maximum over that profile is
		// the hottest region's execution count. Same array, same counts, same threshold the child
		// elfaot will apply -- there is no second, private notion of hotness introduced here.
		//
		// THE ONE-SHOT IS NOT CONSUMED WHILE WAITING. `sr_first_fired` is set only once the bar is
		// met; a below-bar evaluation returns without burning the single fire.
		if (config::inrun_evidence_gate) {
			objprof::UpdateProfile();
			u64 hottest = 0;
			for (auto const &pd : objprof::GetProfile()) {
				for (u64 c : pd.exec_count) {
					if (c > hottest)
						hottest = c;
				}
			}
			config::inrun_evidence_hottest = hottest;
			config::inrun_evidence_polls++;
			if (hottest < (u64)sr_chunk_threshold) {
				fprintf(stderr,
					"INRUN_EVENT EVIDENCE_WAIT t_ms=%ld hottest=%llu threshold=%ld poll=%lu\n",
					(long)(now_us() / 1000) - config::inrun_start_ms,
					(unsigned long long)hottest, sr_chunk_threshold,
					config::inrun_evidence_polls);
				return; // one-shot deliberately NOT consumed
			}
			fprintf(stderr,
				"INRUN_EVENT EVIDENCE_MET t_ms=%ld hottest=%llu threshold=%ld polls=%lu\n",
				(long)(now_us() / 1000) - config::inrun_start_ms,
				(unsigned long long)hottest, sr_chunk_threshold,
				config::inrun_evidence_polls);
		}

		sr_first_fired = true;
		unsigned long ff0 = now_us();
		if (!escalate_elfaot || !escalate_cache || !escalate_elf || !escalate_run_cache)
			return;
		objprof::UpdateProfile();
		static char first_path[4096];
		snprintf(first_path, sizeof first_path, "%s/first.so", escalate_cache);
		// COW-TWIN ELIMINATION (nlp wasm3 raw: AE delta = 40-50ms on a 0.17s run on an IDLE 20-core
		// machine with ZERO builds and 2.4ms evaluator -- the old fork()+system() child stayed a FULL
		// COPY of elfrun for the builder's entire life, so the parent paid a copy-on-write fault on
		// every page it wrote, all run long; +20ms user +20ms sys matched). posix_spawn execs bash
		// immediately: no twin, no CoW. Affinity moves into the command line (taskset); process group
		// via spawnattr so kill-on-exit semantics stay identical.
		int sp2 = dbt_pick_builder_cpu();
		int gcpu = sched_getcpu();
		if (config::inrun_observe_only) {
			// CAUSAL CONTROL: everything above this point has already run (profile
			// snapshot, evaluator state). Refuse to build, fail closed, and record it.
			fprintf(stderr, "INRUN_EVENT BUILD_SUPPRESSED reason=observe_only t_ms=%ld\n",
				(long)(now_us() / 1000) - config::inrun_start_ms);
			return;
		}
		fprintf(stderr, "INRUN_EVENT FIRE t_ms=%ld guest_cpu=%d builder_cpu=%d\n",
			(long)(now_us() / 1000) - config::inrun_start_ms, gcpu, sp2);
		if (sp2 < 0) {
			// FAIL CLOSED: no distinct allowed CPU for a background builder.
			fprintf(stderr, "INRUN_EVENT BUILDER_ABORT reason=no_distinct_allowed_cpu guest_cpu=%d\n",
				gcpu);
			return;
		}
		pid_t pid = -1;
		{
			char cmd[8192];
			// GEOMETRIC THRESHOLD DESCENT, rent-paced: rung k builds at threshold T/2^k with a FRESH
			// profile copy; each rung's cost is MEASURED (not extrapolated); the next rung starts only
			// once elapsed run time >= total compile seconds spent (installment ski: the run has
			// re-earned every second we spent). Publishes rung_k.so; parent pre-armed the seq paths.
			// Terminates at threshold 0 (full) or at process death (kill-on-exit) -- whichever first.
			// X4g1: the script path is baked from THIS source tree (DBT_SR_BUILDER_SH, set in
			// dbt/CMakeLists.txt). It was previously a hardcoded absolute path into a DIFFERENT
			// working copy, so a branch that edited its own sr_builder.sh changed nothing about what
			// actually ran, and no checkout could reproduce its own builder behaviour.
			//
			// X4g1 VLEN propagation: the script receives the active VLEN as its 7th positional
			// argument and forwards it to every elfaot call it makes. The argument count here and
			// the `VLEN=$7` in the script header are one contract: change either alone and $VLEN
			// expands empty into `--vlen=`, at sites whose output goes to /dev/null.
			//
			// C5.2a typed-RVV propagation: --vlen alone tells the child WHICH width to specialize
			// for, not that it may use typed RVV lowering at all. config::rvv_vector_ssa defaults
			// false in every fresh process, so without this 8th argument the child compiles the
			// guest's vector work as opaque RVV helper calls no matter what the parent was asked
			// for -- a VLEN-qualified artifact that is not actually a wide-vector artifact.
			// S3.7: the 8th positional argument is now the WHOLE rendered route contract, not
			// one boolean. Passing the rendered string keeps the script agnostic to how many
			// contract entries exist -- another one is a row in kRvvRouteContract and zero
			// script edits -- and it keeps the caller arity at 8, so the one-contract rule is
			// unchanged. It is single-quoted because it contains spaces and must arrive as ONE
			// argument; the rendered text is only `--flag=0/1` tokens, so it can carry no quote
			// of its own.
			// T5f: `InheritParent`, for the same reason the P1 builder above states -- this
			// parent may carry the substrate itself, so nothing here is unsatisfiable.
			char rvvargs[512];
			RvvRouteArgsJoined(rvvargs, sizeof rvvargs, RvvChildSubstrate::InheritParent);
			snprintf(cmd, sizeof cmd,
				 "taskset -c %d bash %s %s %s %s %s %ld %d %u '%s'",
				 sp2,
				 DBT_SR_BUILDER_SH,
				 escalate_elfaot, escalate_elf, escalate_cache, escalate_run_cache,
				 sr_chunk_threshold, (int)(!sr_descent), config::vlen_bits,
				 rvvargs);
			posix_spawnattr_t sa;
			posix_spawnattr_init(&sa);
			posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETPGROUP);
			posix_spawnattr_setpgroup(&sa, 0);
			char *argv_sp[] = {(char *)"/bin/sh", (char *)"-c", cmd, nullptr};
			if (posix_spawn(&pid, "/bin/sh", nullptr, &sa, argv_sp, ::environ) != 0)
				pid = -1;
			posix_spawnattr_destroy(&sa);
		}
		inrun_builder_pid = pid;
		if (pid < 0)
			fprintf(stderr, "INRUN_EVENT BUILDER_SPAWN_FAILED\n");
		else
			fprintf(stderr, "INRUN_EVENT BUILDER_SPAWNED pid=%d cpu=%d\n", (int)pid, sp2);
		// NOTE: this only means the shell process was created. The builder's real
		// disposition is INRUN_EVENT BUILDER_EXIT rc=..., emitted after waitpid.
		config::esc_ms_firstfire = (now_us() - ff0) / 1000;
		for (int k = 0; k < 12 && inrun_seq_n < kInrunSeqMax; k++) { // covers T0/2^k down to 0 (log2(262144/512)+2)
			char *rp = (char *)malloc(4096);
			snprintf(rp, 4096, "%s/rung_%d.so", escalate_cache, k);
			inrun_seq_paths[inrun_seq_n++] = rp;
		}
		{ // dual-channel: MAP_SHARED RIP ring + tbmap for the builder's sample resolution
			char rp[4096];
			snprintf(rp, sizeof rp, "%s/ring.bin", escalate_cache);
			int rfd = open(rp, O_RDWR | O_CREAT, 0644);
			if (rfd >= 0 && ftruncate(rfd, kRipRingSlots * 8) == 0) {
				void *rm = mmap(nullptr, kRipRingSlots * 8, PROT_READ | PROT_WRITE, MAP_SHARED, rfd, 0);
				if (rm != MAP_FAILED)
					esc_rip_ring = (volatile unsigned long long *)rm;
			}
			if (rfd >= 0)
				close(rfd);
			snprintf(rp, sizeof rp, "%s/tbmap.txt", escalate_cache);
			tcache::DumpTBMap(rp);
			if (escalate_time_census && !esc_qcg_lo) {
				tcache::CodePoolBounds(const_cast<unsigned long long *>(&esc_qcg_lo),
						       const_cast<unsigned long long *>(&esc_qcg_hi));
				struct sigaction sa2{};
				sa2.sa_sigaction = esc_prof_handler;
				sa2.sa_flags = SA_SIGINFO | SA_RESTART;
				sigaction(SIGPROF, &sa2, nullptr);
				if (esc_sample_us <= 0)
					esc_sample_us = inrun_flush_ms * 1000L; // coarse start: keeper tick
				struct itimerval tv2{};
				tv2.it_interval.tv_usec = esc_sample_us % 1000000L;
				tv2.it_interval.tv_sec = esc_sample_us / 1000000L;
				tv2.it_value = tv2.it_interval;
				setitimer(ITIMER_PROF, &tv2, nullptr);
			}
		}
		esc_pages_at_first_fire = (unsigned long)objprof::GetProfile().size();
		esc_pages_at_last_build = esc_pages_at_first_fire;
		struct timespec ts0;
		clock_gettime(CLOCK_MONOTONIC, &ts0);
		esc_first_fire_ms = ts0.tv_sec * 1000L + ts0.tv_nsec / 1000000L - inrun_start_ms;
		fprintf(stderr, "SR_FIRST_FIRE t_ms=%ld pid=%d\n",
			ts0.tv_sec * 1000L + ts0.tv_nsec / 1000000L - inrun_start_ms, (int)pid);
		return;
	}
	if (inrun_seq_idx == 0)
		return;
	if (!sr_census)
		return; // ablation: descent-only (no decision layer)
	// LAZY exec census (pre-NONE cost trace: TierCensus walks the whole tcache_map -- sqlite 10k TBs =
	// 3.8ms/eval x 41 evals = 154ms foreground, the measured local floor). In time-census mode the sign
	// test runs on SAMPLES; the exec census is needed only for (a) the census0 snapshot, (b) the
	// quality proxy (default-off), (c) the env-gated trace. Walk the map only in those cases.
	unsigned long c[4] = {0, 0, 0, 0};
	bool have_c = false;
	if (!inrun_census0_taken) { // first tick after the swap: baseline snapshot
		tcache::TierCensus(c);
		for (int i = 0; i < 4; ++i)
			inrun_census0[i] = c[i];
		inrun_census0_taken = true;
		return;
	}
	if (!escalate_time_census || escalate_quality_proxy || getenv("AUTOESC_TRACE")) {
		tcache::TierCensus(c);
		have_c = true;
	}
	unsigned long dq = have_c ? c[2] - inrun_census0[2] : 0;
	unsigned long da = have_c ? c[3] - inrun_census0[3] : 0;
	if (escalate_time_census) {
		unsigned long sq = esc_qcg_samples, sa2 = esc_aot_samples;
		unsigned long tdq = sq - esc_census0_q, tda = sa2 - esc_census0_a;
		if (!inrun_census0_taken) {
			esc_census0_q = sq;
			esc_census0_a = sa2;
		} else if (tdq + tda > 0) {
			// QUALITY PROXY (same-window, zero constants): over the post-swap window, compare
			// samples-per-entry of AOT code vs QCG code. If AOT time-per-entry >= QCG's IN THE SAME
			// WINDOW, the chunk's code buys no speed over QCG on what it covers -> quality deficit.
			unsigned long edq = c[2] - inrun_census0[2], eda = c[3] - inrun_census0[3];
			double aot_rate = eda ? (double)tda / (double)eda : 0.0;
			double qcg_rate = edq ? (double)tdq / (double)edq : 0.0;
			if (getenv("AUTOESC_PROXY"))
				fprintf(stderr, "AUTOESC_PROXY aot_rate=%.6f qcg_rate=%.6f tda=%lu eda=%lu tdq=%lu edq=%lu\n",
					aot_rate, qcg_rate, tda, eda, tdq, edq);
			if (escalate_quality_proxy && eda && edq && aot_rate >= qcg_rate) {
				dq = 1; // force the escalate branch: chunk code proven no faster per entry than QCG
				da = 0;
			} else {
				dq = tdq; // TIME evidence replaces ENTRY evidence in the same sign test
				da = tda;
			}
		}
	}
	if (getenv("AUTOESC_TRACE")) { // env-gated delta trajectory (diagnostic only)
		struct timespec dts;
		clock_gettime(CLOCK_MONOTONIC, &dts);
		fprintf(stderr, "AUTOESC_TRACE t_ms=%ld dQ=%lu dA=%lu totQ=%lu totA=%lu\n",
			dts.tv_sec * 1000L + dts.tv_nsec / 1000000L - inrun_start_ms, dq, da, c[2], c[3]);
	}
	if (dq + da == 0)
		return; // no evidence yet
	if (dq <= da) { // chunk (AOT) is the majority of post-swap execution -> KEEP_CHUNK
		inrun_escalated = true;
		objprof::UpdateProfile();
		esc_pages_at_decision = (unsigned long)objprof::GetProfile().size();
		esc_census0_q = esc_qcg_samples; // post-decision contradiction window starts now
		esc_census0_a = esc_aot_samples;
		if (esc_rearmed && escalate_time_census)
			setitimer(ITIMER_PROF, nullptr, nullptr); // second decision is final
		// keep the channel OPEN while a re-arm is still possible (the growth check runs on slowpath
		// escapes; closing the channel here was the round-3 latch bug class all over again)
		if (esc_rearmed)
			inrun_booted = true; // final decision: close the promotion channel
		esc_last_keep = true;
		if (escalate_cache) { // evidence-gated BUILD: builder idles while the KEEP stands
			char wp[4096];
			snprintf(wp, sizeof wp, "%s/want", escalate_cache);
			FILE *wf = fopen(wp, "w");
			if (wf) { fputc('0', wf); fclose(wf); }
		}
		fprintf(stderr, "AUTOESC KEEP_CHUNK dQCG=%lu dAOT=%lu pages=%lu\n", dq, da, esc_pages_at_decision);
		return;
	}
	if (!escalate_elfaot || !escalate_cache || !escalate_elf) {
		inrun_escalated = true;
		fprintf(stderr, "AUTOESC ABSTAIN missing-paths\n");
		return;
	}
	if (inrun_single_run && sr_descent) {
		// descent mode: the installment builder IS the escalation path (it descends to T=0 on its own,
		// rent-paced). An ESCALATE verdict here only confirms QCG majority; forking a second full build
		// would duplicate work and race the staging dir. Log the verdict, keep the channel open.
		inrun_escalated = true;
		esc_pages_at_last_build = (unsigned long)objprof::GetProfile().size();
		esc_census0_q = esc_qcg_samples;
		esc_census0_a = esc_aot_samples;
		struct timespec tse;
		clock_gettime(CLOCK_MONOTONIC, &tse);
		esc_last_keep = false;
		fprintf(stderr, "AUTOESC ESCALATE_FULL fire_ms=%ld dQCG=%lu dAOT=%lu (descent-covered)\n",
			tse.tv_sec * 1000L + tse.tv_nsec / 1000000L - inrun_start_ms, dq, da);
		return;
	}
	if (esc_full_ski_gate && esc_first_land_ms > esc_first_fire_ms && esc_pages_at_first_fire) {
		objprof::UpdateProfile();
		unsigned long now_pages = (unsigned long)objprof::GetProfile().size();
		long build_wall = esc_first_land_ms - esc_first_fire_ms;
		long price_ms = build_wall * (long)(now_pages / esc_pages_at_first_fire + 1); // online estimate
		struct timespec tsk;
		clock_gettime(CLOCK_MONOTONIC, &tsk);
		long elapsed = tsk.tv_sec * 1000L + tsk.tv_nsec / 1000000L - inrun_start_ms;
		if (elapsed < price_ms) {
			// rent not yet paid for this price: defer (re-evaluated next tick; if the run ends first,
			// the whole full build is SAVED -- the compile-heavy self-abstain, zero constants)
			fprintf(stderr, "AUTOESC SKI_DEFER elapsed=%ld price=%ld (bw=%ld ratio=%lu)\n",
				elapsed, price_ms, build_wall, now_pages / esc_pages_at_first_fire);
			inrun_census0_taken = false; // keep the window fresh
			return;
		}
	}
	inrun_escalated = true;
	esc_pages_at_last_build = (unsigned long)objprof::GetProfile().size();
	if (escalate_time_census)
		setitimer(ITIMER_PROF, nullptr, nullptr);
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	inrun_escalate_fire_ms = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L - inrun_start_ms;
	static char fixed_path[4096];
	snprintf(fixed_path, sizeof fixed_path, "%s/escalated.so", escalate_cache);
	pid_t pid = fork();
	if (pid == 0) { // child: build then publish under the fixed name
		// spare-core semantics: pin the builder to ONE core != the guest's (single-core builder keeps the
		// spend<=rent bound core-denominated; all-core LLVM threads would multiply CPU by nproc)
		int spare = dbt_pick_builder_cpu();
		if (spare < 0) { // asynchronous builder with no distinct allowed CPU: fail closed
			fprintf(stderr, "INRUN_EVENT BUILDER_ABORT reason=no_distinct_allowed_cpu path=escalate\n");
			_exit(70);
		}
		cpu_set_t one;
		CPU_ZERO(&one);
		CPU_SET(spare, &one);
		if (sched_setaffinity(0, sizeof one, &one) != 0) {
			fprintf(stderr, "INRUN_EVENT BUILDER_ABORT reason=setaffinity_failed cpu=%d path=escalate\n",
				spare);
			_exit(71);
		}
		setpgid(0, 0); // own process group: parent can kill the whole builder subtree at exit
		objprof::UpdateProfile(); // refresh the live profile before the full build (grow-only, host stack)
		pid_t b = fork();
		if (b == 0) {
			char cpc[8192];
			snprintf(cpc, sizeof cpc, "cp %s/*.prof %s/ 2>/dev/null",
				 escalate_run_cache ? escalate_run_cache : escalate_cache, escalate_cache);
			(void)!system(cpc);
			char elfarg[4096], cachearg[4096], vlenarg[64];
			snprintf(elfarg, sizeof elfarg, "--elf=%s", escalate_elf);
			snprintf(cachearg, sizeof cachearg, "--cache=%s", escalate_cache);
			// X4g1 VLEN propagation: same per-process argument as the activation invariant below.
			snprintf(vlenarg, sizeof vlenarg, "--vlen=%u", config::vlen_bits);
			// S3.7: one argv slot per route flag, rendered from kRvvRouteContract. execv cannot
			// take a joined string, so this is the array renderer rather than the joined one --
			// same table, same values, different shape.
			// T5f: `InheritParent`, same reason as the two sites above -- this parent is free to
			// carry the substrate, so the loop tier's structural bar does not apply here.
			char rvvslots[kRvvRouteArgMax][64];
			char const *rvvargv[kRvvRouteArgMax];
			size_t n_rvv = RvvRouteArgv(rvvslots, rvvargv, RvvChildSubstrate::InheritParent);
			// Line-B activation invariant: forward the flag so the in-run builder's elfaot instruments
			// exec_instr_seen consistently with elfrun's own QCG-side counter (dbt::config is per-process;
			// this subprocess's copy defaults false unless told, so it must be passed explicitly here).
			// ORDER IS LOAD-BEARING: the sr_activation_invariant slot is `nullptr` whenever the flag is
			// off, which is its default, and execv stops at the first null. Every unconditional argument
			// -- vlenarg included -- must therefore sit BEFORE it, or it is silently dropped in exactly
			// the configuration that runs by default.
			// S3.7: all five contract arguments are spliced here, BEFORE the conditional slot,
			// for the reason stated immediately above -- execv stops at the first nullptr, so an
			// unconditional argument placed after it is silently dropped in the default
			// configuration. Built as a vector so the array length follows the table.
			std::vector<char const *> cargv;
			cargv.push_back(escalate_elfaot);
			cargv.push_back(elfarg);
			cargv.push_back(cachearg);
			cargv.push_back("--llvm=1");
			cargv.push_back(vlenarg);
			for (size_t i = 0; i < n_rvv; ++i)
				cargv.push_back(rvvargv[i]);
			cargv.push_back("--threshold=0");
			if (config::sr_activation_invariant)
				cargv.push_back("--sr-activation-invariant=1");
			cargv.push_back(nullptr);
			execv(escalate_elfaot, const_cast<char *const *>(cargv.data()));
			_exit(127);
		}
		int st;
		waitpid(b, &st, 0);
		// X4g3 publish selector: same reasoning as the P1 builder above. The escalation cache is a
		// LIVE cache, not a scratch staging dir, so after this change it can hold a v512 and a v1024
		// artifact simultaneously -- which is the entire point of qualifying the path. `head -1` over
		// `*.aot.so` would then be a coin flip between specializations. The child was told
		// `--vlen=<vlenarg>`, so select exactly that name.
		char cmd[8192];
		snprintf(cmd, sizeof cmd,
			 "so=$(ls %s/*.v%u.aot.so 2>/dev/null | head -1); [ -n \"$so\" ] && cp \"$so\" %s.tmp && mv %s.tmp %s",
			 escalate_cache, config::vlen_bits, fixed_path, fixed_path, fixed_path);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			_exit(1); // F4: failed build must not republish a stale artifact
		(void)!system(cmd); // research substrate: post-build file publish only (no timing role)
		_exit(0);
	}
	// parent: remember the builder pgid (kill-on-exit enforces the spend<=rent bound), then arm the swap.
	inrun_builder_pid = pid;
	if (inrun_seq_n < kInrunSeqMax) {
		inrun_seq_paths[inrun_seq_n] = fixed_path;
		inrun_seq_n++; // channel is already open (booted stayed false while the decision was pending)
	}
	fprintf(stderr, "AUTOESC ESCALATE_FULL fire_ms=%ld dQCG=%lu dAOT=%lu pid=%d\n", inrun_escalate_fire_ms, dq, da, (int)pid);
}

} // namespace dbt

// Round-17 BCT: C++-linkage shim used by qcgstub_brind's local extern declaration.
bool dbt_inrun_artifact_present()
{
	return dbt::dbt_inrun_artifact_present_impl();
}
