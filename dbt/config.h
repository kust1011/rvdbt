#pragma once

#define DBT_LINUX_GUEST

// __has_feature is a clang extension; GCC does not define it, and an undefined identifier in a
// #if expands to 0 only for plain identifiers -- `__has_feature(...)` is a call and makes the
// preprocessor error out. Guard it so the headers can also be compiled by g++ (needed to build
// the standalone vector-substrate probe on hosts without clang -- see experiments/.../p8_dynamic).
#if defined(__has_feature)
#define DBT_HAS_FEATURE(x) __has_feature(x)
#else
#define DBT_HAS_FEATURE(x) 0
#endif

#if !(DBT_HAS_FEATURE(address_sanitizer) || defined(__SANITIZE_ADDRESS__))
#define DBT_ZERO_MMU_BASE
#endif

#include <vector>
#include <utility>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <cstdint>

namespace dbt::config
{

// ---------------------------------------------------------------------------------------------
// RUNTIME SERVICE REQUESTS (T5d-0 plumbing).
//
// Execute()'s host loop consumes a fixed set of asynchronous requests -- the tier's artifact poll,
// its evaluator tick, the saturation sweep, the P1 scan, the web repack, and the pending mid-run
// boot. Each is an existing `volatile bool` set from the SIGALRM keeper (or from the brind
// slowpath) and cleared where the loop services it. Translated code that wants to ask "is any of
// them pending?" would have to load six separate globals.
//
// `service_request` is a single word holding one bit per request, so that question is ONE load. It
// is not a new decision, a new request, or a new piece of policy: it carries no information the six
// requests do not already carry, and nothing reads it to decide *what* to do -- only whether a
// return to the host loop is owed.
//
// THERE IS ONE COPY OF THE STATE, AND THIS IS WHY. The first version of this type kept a
// `volatile bool` beside the bit and wrote both on assignment. That is a mirror, and a mirror can
// diverge no matter how carefully the two writes are placed: the main thread's `f = false` writes
// the bool, a signal handler's `f = true` then writes bool and bit, and the interrupted `fetch_and`
// resumes and clears the bit -- leaving the bool true and the bit clear, with no unsafe or
// undisciplined code anywhere. Independent review caught the claim that this "cannot drift"; it
// was wrong, and no ordering test or argument could have made it right.
//
// A `ServiceFlag` therefore stores only its bit MASK. Reading it loads the shared word and tests
// the bit; setting and clearing are `fetch_or`/`fetch_and` on that same word. There is no second
// representation to disagree with, so the invariant is not maintained -- it is unrepresentable.
// `static_assert(sizeof(ServiceFlag) == sizeof(uint32_t))` below is the mechanical statement of
// that: the object is its mask and nothing else.
//
// SIGNAL SAFETY. Every mutation is one lock-free atomic RMW, which the standard permits a signal
// handler to perform on the interrupted thread's data and which x86-64 emits as a single
// `lock or`/`lock and`. What that buys is a CONTRACT rather than a lucky instruction selection, and
// the difference was measured rather than assumed: writing the naive `w = load; w |= bit; store(w)`
// instead does NOT reproduce the bug on this target, because with a constant mask clang -O2 folds
// the three volatile accesses back into one un-locked `or %ecx,(%rip)`, which is equally
// uninterruptible. Separate the load from the store by anything at all -- a different expression, a
// runtime mask, another target -- and the handler's set is dropped by the interrupted store. The
// interleaving test in backedge_safepoint_test.cpp detects that (545 trials per run), and the
// mutation harness's `nonatomic_service_word` forces the separation so the detector is shown to
// fire. The word is additionally `volatile` so the compiler cannot coalesce or hoist a read across
// code a handler could interrupt, which is the property the `volatile bool` flags had before and
// which relaxed atomics alone do not promise.
enum ServiceBit : uint32_t {
	kSvcInrunPoll = 1u << 0,
	kSvcInrunBootPending = 1u << 1,
	kSvcInrunEscalate = 1u << 2,
	kSvcSatSweep = 1u << 3,
	kSvcP1Scan = 1u << 4,
	kSvcWebRepack = 1u << 5,
	// T5d2a: the loop tier's own request. A SEVENTH bit and not a reuse of kSvcInrunPoll, because
	// the loop tier shares no state, no channel and no consumer with the BCT/single-run tier: a bit
	// that two independent consumers cleared would let either one swallow the other's opportunity.
	// It carries no evidence and no decision -- see `loop_tier_due` below.
	kSvcLoopTier = 1u << 6,
};

inline volatile std::atomic<uint32_t> service_request{0};
static_assert(sizeof(std::atomic<uint32_t>) == sizeof(uint32_t),
	      "emitted code reads service_request as a plain 32-bit memory location");
static_assert(std::atomic<uint32_t>::is_always_lock_free,
	      "service_request is written from a signal handler; a locked implementation is unsafe there");

// The address emitted code compares against zero. A function rather than a raw `&service_request`
// so the one place that hands the address to a code generator is also the one place documenting
// what may be assumed about it.
inline void *ServiceRequestWordAddr()
{
	return (void *)&service_request;
}

inline bool AnyServiceRequestPending()
{
	return service_request.load(std::memory_order_relaxed) != 0;
}

// One bit of `service_request`, addressed by name. Every existing use site -- `f = true`,
// `f = false`, `if (f)`, `a || b` -- keeps compiling and keeps meaning exactly what it meant. The
// object holds no state of its own: see the block comment above for why that is the point.
struct ServiceFlag {
	explicit constexpr ServiceFlag(uint32_t bit_) : bit(bit_) {}

	ServiceFlag &operator=(bool nv)
	{
		if (nv)
			service_request.fetch_or(bit, std::memory_order_relaxed);
		else
			service_request.fetch_and(~bit, std::memory_order_relaxed);
		return *this;
	}

	operator bool() const
	{
		return (service_request.load(std::memory_order_relaxed) & bit) != 0;
	}

	uint32_t Bit() const
	{
		return bit;
	}

private:
	uint32_t bit;
};
static_assert(sizeof(ServiceFlag) == sizeof(uint32_t),
	      "a ServiceFlag must hold its bit mask and nothing else -- a second member would be a "
	      "mirror of the word, and a mirror can diverge under signal interleaving");
#ifndef NDEBUG
static constexpr bool debug = true;
#else
static constexpr bool debug = false;
#endif
#ifdef DBT_USE_INTERP
static constexpr bool use_interp = true;
#else
static constexpr bool use_interp = false;
#endif
#ifdef DBT_ZERO_MMU_BASE
static constexpr bool zero_membase = true;
#else
static constexpr bool zero_membase = false;
#endif
#ifdef DBT_DUMP_TRACE
static constexpr bool dump_trace = true;
#else
static constexpr bool dump_trace = false;
#endif
// for jit
inline bool merge_ls = false;
inline bool trace = true; // trace execution count more detailed
inline bool use_aot = false;
inline bool dump_time = false;
inline bool not_freq = false;
// 22nd-cycle H4 probe (off-axis, default off): drop GetCompilationIPRange's clip at the next
// existing TB (execute.cpp) -- translate THROUGH existing TB ranges (QEMU-style overlap).
inline bool no_tb_clip = false;
// 22nd-cycle H1'' (A-line candidate, default off): translate THROUGH the next existing TB
// ONLY when that TB is a runtime-observed indirect-branch target (is_brind_target) --
// source-conditioned partition decision; direct-flow boundaries keep stock clipping.
inline bool tb_through_brind = false;
// 23rd-cycle layout-control knob (default 0): dead padding at code_pool start; shifts all
// emitted code by N bytes. Candidates must survive a pad sweep before any wall claim.
inline unsigned code_pad = 0;
// 27th-cycle DC-4 pre-patch (default off): record the semantically-true ecall fallthrough
// edge (syscall returns to ip+4) so module-graph reachability does not depend on the
// is_brind_target pollution bits (aot_module.cpp Panic coupling).
inline bool analyser_ecall_edge = false;
// P2 (--aot-freq-gated-seed, default off): a brind_target forces a region entry ONLY if it is
// itself hot (node exec_count >= threshold). A stale/cold brind bit (hot in an earlier phase,
// cold now -- DC-3) stops being a frequency-blind forced root seed and becomes an ordinary
// interior block. Segment entries are unaffected (they are structural, not frequency-stale).
// Compile-time only: zero deployment-invocation cost.
inline bool aot_freq_gated_seed = false;
// A-line decision-regret-reset (2026-07-27, --aot-brind-seed-oracle-suppress, DIAGNOSTIC ORACLE
// ONLY, never proposed as a deployment mechanism): unconditionally removes is_brind_target from
// ComputeRegionIDF's seed rule, regardless of exec_count -- unlike P2 (which only de-shatters COLD
// brind seeds), this suppresses ALL exclusively-brind_target-forced regions, including hot ones,
// to measure the pure upper-bound compile/execute/full-total cost of Wendell's "always root every
// brind_target" default. Correctness is preserved (a suppressed target still gets a real,
// independently-decided AOT function if it's ALSO a segment_entry; otherwise it falls back to the
// QCG tier exactly like any other unadmitted target -- the same fallback every oracle in this file
// already relies on). This flag exists ONLY to answer "how much would removing this reason cost/
// save," not to be tuned or shipped.
inline bool aot_brind_seed_oracle_suppress = false;
// Design 8 (--aot-link-region-merge, default off, 2026-07-24): a brind_target that is ALSO a
// recorded `link` target (a call site's return continuation, RecordLink -- known statically at
// zero dynamic-evidence cost, since RISC-V's fixed 4-byte instruction width makes "target-4 is a
// call site" an always-true-or-false fact) does not force an independent region entry; it is
// swept into its caller's region by the normal dominance-frontier DFS instead. Measured: 184/244
// (75.4%) of expat's brind_target nodes are link targets -- ordinary function-call/return
// structure, not genuine polymorphic dispatch. See ModuleGraph::ApplyLinkAwareRegionMerge.
//
// SINGLE-ENTRY variant KILLED 2026-07-24 (see DESIGN8_LINK_MERGE_KILLED.md): correct
// (byte-identical SHA on 3 workloads) and does shrink .text (expat -14.66%) and compile time
// (-18-22%), but net single-run wall time is workload-dependent and NEGATIVE on the more
// call/return-heavy real workload -- expat -2.34%, libyaml +5.31%. Root cause: a merged node
// loses its top-level aot_symbols/_aot_tab entry (only region[0] of an admitted region is
// registered there), so every dynamic `ret` that used to resolve to fast native AOT code now
// misses the dispatch table and falls back to QCG for that hit. CORRECTION (2026-07-24,
// Codex audit): this kills the SINGLE-ENTRY variant specifically, not region-merging as a
// class -- the "GHC-cc backend wall" cited as the reason multi-entry can't fix this was
// re-examined at the code level (gdb on a live crash) and found to be a MISDIAGNOSIS: the
// actual crash was `LLVMGen`'s constructor dereferencing `fn2seg.find(name)->second` with no
// missing-key check, after `dbt/aot/llvmaot.cpp`'s Round-41 code renamed the shared worker
// function AFTER fn2seg had already been populated under the pre-rename name. Fixed (one
// `fn2seg` insert under the post-rename name); `--aot-merge-max` now compiles and deploys
// correctly with byte-identical SHA. See `--aot-link-multientry-merge` below for the
// multi-entry-exposed version of this exact mechanism.
inline bool aot_link_region_merge = false;
// Design 8 multi-entry (--aot-link-multientry-merge, default off, 2026-07-24): requires
// --aot-link-region-merge. Instead of silently absorbing a link-merged return-continuation T
// as a dispatch-invisible interior block (the killed single-entry variant above), ALSO
// registers T as a secondary externally-reachable entry into its caller's shared compiled
// body -- a thin wrapper function at T's own address (`_aot_<T>`) that sets `state->ip=T` and
// GHC-tailcalls the caller's own (unrenamed, still-externally-callable) function, which checks
// `state->ip` once at entry to route to T's block instead of its normal first block. Reuses
// the Round-41 multi-entry switch codegen (QIRToLLVM::Run(), unchanged) now that its
// mis-attributed "GHC-cc wall" crash is fixed. Unlike --aot-merge-max's positional grouping
// (which renames/internalizes the shared worker and forces EVERY group member, including the
// most-common entry, through a wrapper + N-way switch on every single invocation), this keeps
// the primary/caller entry's OWN symbol name and pays the state->ip check ONLY on regions that
// actually contain a merged return-continuation, with the primary case free (falls to the
// switch's default arm, no case, no wrapper).
inline bool aot_link_multientry_merge = false;
// Design 8 alias multi-entry (--aot-link-alias-merge, default off, 2026-07-24): requires
// --aot-link-region-merge; a second, ZERO-WRAPPER realization of the same multi-entry idea
// above (Codex-directed 2026-07-24 continuation after the wrapper variant's measured mixed
// economics). Instead of a thin wrapper function, a link-merged T's own symbol (`_aot_<T>`) is
// an `llvm::GlobalAlias` for the SAME address as its caller's shared function -- no extra
// machine code, no extra top-level function, at all. Correctness requires the shared function's
// own entry switch (unchanged) to see the CORRECT `state->ip` regardless of how it was entered;
// every call site that can reach a multi-entry-capable function (CreateQCGGbr's direct path,
// Expand_gbrind's L1-cache fastpath and guarded-fastpath variants) now explicitly refreshes
// `state->ip` to its own actual target immediately before the call (see
// dbt/qmc/llvmgen/llvmgen.cpp) -- the slowpath already did this correctly via the existing
// `qcgstub_brind` runtime stub (confirmed by reading its code, not assumed). No wrapper-cost
// gate: an alias costs no extra compiled code, so entries are exposed by the reachability/
// entry-contract structural invariant (this node is a link-merged return-continuation, i.e.
// realistically only ever entered via a genuinely computed gbrind, never a compile-time-known
// direct branch) rather than a hotness threshold.
//
// STATUS (2026-07-25, see DESIGN8_ALIAS_MULTIENTRY_ROOT_CAUSE_3.md, superseding the prior note
// here): the leading candidate cited below (qemit.cpp Emit_gbr -> jitabi.cpp TryLinkBranch never
// refreshing state->ip on its direct-call self-patch path) WAS a real, general bug -- found and
// fixed (see Emit_gbr's own comment; also gated CreateQCGGbr's previously-unconditional store,
// which was silently taxing the flags-off baseline). Fixing it did NOT resolve the real-workload
// fault: re-diagnosis isolated a THIRD, deeper cause specific to this flag's "no wrapper-cost
// gate, expose every candidate regardless of hotness" policy -- exposing a COLD candidate
// (uniquely done by this flag; wrapper mode's independent exec_count gate silently absorbs the
// same candidate instead, exactly like the single-entry variant) inside a function that ALSO
// contains its own unrelated internal indirect-dispatch site (a computed-goto jump table) causes
// a catastrophic QCG re-compilation livelock for that unrelated site. Wrapper mode is unaffected
// (confirmed correctly exposing ~20 OTHER hot multi-entry regions on the same real-workload run)
// and remains the validated mechanism the jump-table pivot is built on. This flag is FORMALLY
// RETIRED for this research line: kept in the tree default-off as a historical/diagnostic
// artifact, not pursued further, DO NOT enable for real-workload measurement.
inline bool aot_link_alias_merge = false;
// Design 8 multi-entry diagnostic trace (--aot-link-multientry-trace, default off, 2026-07-24):
// increments CPUState::dbg_multientry_switch_hits/dbg_wrapper_calls directly in generated code,
// to PROVE which path executes for a merged secondary entry (external dispatch reaching the
// shared worker's switch case vs a wrapper body actually running) rather than inferring it from
// disassembly. Zero cost when off (no instrumentation code emitted at all).
inline bool aot_link_multientry_trace = false;
// P6 (--aot-function-closure, default off): once a guest function contains >=1 naturally
// admitted region, statically admit every other block inside that function's declared
// [start,size) byte range (STT_FUNC symbol), pre-empting DC-2 cross-input exile at BUILD
// time (zero deployment-invocation cost -- see dbt/aot/llvmaot.cpp ApplyFunctionClosure).
inline bool aot_function_closure = false;
inline char const *aot_function_closure_elf = nullptr; // guest ELF path, for STT_FUNC symbol parsing
// P7 (--aot-jumptable-closure, default off): narrower successor to P6 -- admits only a
// closure function's actual jump-table entries (recovered via bounded backward dataflow
// scan at each jr/jalr), not the whole function body. See llvmaot.cpp ApplyJumpTableClosure.
inline bool aot_jumptable_closure = false;
// Jump-table multi-entry pivot (--aot-jumptable-multientry, default off, 2026-07-24): requires
// --aot-jumptable-closure. Instead of forcing each P7-discovered jump-table handler into its own
// independently-admitted region (the existing, unchanged behavior when this is off), sweeps it
// into the enclosing function's region (link_region_suppressed) and exposes it via the SAME
// validated wrapper mechanism as Design 8 (--aot-link-multientry-merge; see llvmaot.cpp's
// AdmitCandidatesInFunction and the per-region multi-entry loop in LLVMAOTTranslatePage).
inline bool aot_jumptable_multientry = false;
// P9 (--aot-return-closure, default off): admits every call-return continuation (ip+4 of a
// jal/jalr-with-rd) in a closure-triggered function -- statically exact, no dataflow scan.
// See llvmaot.cpp ApplyReturnClosure.
inline bool aot_return_closure = false;
// P10 (--aot-closure-cold-section, default off): compose with any closure variant (P6/P7/P9)
// to place its admitted-only functions in a separate object section, testing whether the
// convergent P6/P7/P9 regression is specifically layout interference. See llvmaot.cpp.
inline bool aot_closure_cold_section = false;
// FDRE (A-line architecture reset, --aot-fdre-region + --aot-fdre-edges=<path>): replaces
// is_brind_target's unconditional region-root seeding with a conservation-gated dominant-
// source rule (ModuleGraph::ApplyFDRE, aot_module.cpp). See A_LINE_ARCHITECTURE_SPEC.md.
inline bool aot_fdre_region = false;
inline char const *aot_fdre_edges_path = nullptr;
// A-line round 22 Gate 1 Row 1: path to a (source,target,count) edge file loaded ONLY into
// ModuleGraphNode::indirect_succs (aot_module.h) -- a typed relation kept structurally separate
// from `succs`, consumed only by the oracle dump/consistency-check this round adds. Default
// empty (feature entirely inert unless set).
inline char const *aot_indirect_succs_file = nullptr;
inline bool aot_dump_indirect_succs = false;
// OPAQUE_BOUNDARY diagnostic (2026-08-21, default off, DIAGNOSTIC ONLY -- not a shipping
// mechanism): path to an LLVM bitcode/IR file containing DEFINITIONS for functions that the AOT
// module only has as external declarations (the hcall targets QIR emits, e.g. qcgstub_rv32_*).
// When set, LLVMAOTCompileELF links this module into cmodule BEFORE the optimization pipeline
// runs, so LLVM's own inliner/CGSCC passes see the callee body instead of an opaque call. This is
// mechanical and generic: it applies to every call site whose target name matches a definition in
// the linked module, not to any specific workload. See OPAQUE_BOUNDARY diagnostic docs.
inline char const *aot_diag_link_bitcode = nullptr;
// OPAQUE_BOUNDARY mechanism ladder (2026-08-21, default off, DIAGNOSTIC ONLY): colon-separated
// exact stub names for which Emit_hcall should reference a direct, named LLVM function value
// (still just a declaration unless --aot-diag-link-bitcode also supplies a body) instead of
// loading a function pointer from CPUState::stub_tab. Independent of aot_diag_link_bitcode/
// aot_diag_inline_funcs so the two variables (dispatch indirection, body visibility/inlining) can
// be varied one at a time: direct_funcs alone with no linked bitcode isolates indirect-call
// removal (A1); direct_funcs + linked bitcode with the name absent from inline_funcs (and
// explicitly marked noinline) isolates linkage/build effects with the call boundary still intact
// (A2); direct_funcs + linked bitcode + the same name present in inline_funcs is the full
// visibility arm (A3).
inline char const *aot_diag_direct_funcs = nullptr;
// Colon-separated exact function names (as they appear in the linked bitcode) to mark
// alwaysinline after linking, forcing LLVM to fold them into every caller regardless of its own
// size/cost heuristic -- isolates "does visibility change anything" from "did the inliner's cost
// model happen to decline". Requires --aot-diag-link-bitcode. Empty = rely on the standard
// pipeline's own inlining decision instead of forcing it.
inline char const *aot_diag_inline_funcs = nullptr;
// If set, write the final optimized LLVM IR (post-pipeline, pre-codegen) to this path as textual
// .ll -- generic, always-available diagnostic, not tied to the bitcode-linking mechanism above.
inline char const *aot_dump_llvm_ir = nullptr;
// T7b diagnostic: the same AOT module immediately before the optimization/legalization pipeline.
// This distinguishes representation at QIRToLLVM's output from the final post-pipeline IR above.
inline char const *aot_dump_llvm_ir_preopt = nullptr;
// A-line round 22 Gate 1 Row 4: same edge-file format as aot_indirect_succs_file, loaded
// separately into InstGBrind::known_targets (QIR-instruction-level, not graph-node-level).
// Default empty (feature entirely inert unless set). See qir.h's InstGBrind comment.
inline char const *aot_qir_known_targets_file = nullptr;
inline bool aot_dump_qir_known_targets = false;
// A-line round 23 Gate 1 Row 5 (oracle-only, default off): attaches real LLVM !prof value-profile
// metadata (IPVK_IndirectCallTarget format) to the gbrind intrinsic call, sourced from
// InstGBrind::known_targets/known_target_counts (same --aot-qir-known-targets-file evidence Row 4
// already loads, now WITH real per-edge counts instead of discarding them). Also enables an
// explicit llvm::PGOIndirectCallPromotionPass invocation right after final intrinsic expansion
// (llvmaot.cpp) so LLVM's own ICP can legally act on the resulting musttail indirect call. See
// ROUND23_ROW5_VP_METADATA.md.
inline bool aot_gbrind_vp_metadata = false;
inline bool aot_log_icp = false;
// A-line round 23 Gate 3 pivot: coarse wall-clock phase breakdown of elfaot's own compile_wall
// (region/QIR/LLVM-IR construction vs the n_expands optimize+expand loop vs object emit+link).
// See llvmaot.cpp's LLVMAOTCompileELF tail and GATE3_DECISION.md.
inline bool aot_log_phase_timing = false;
// A-line 2026-07-25 (--aot-idf-fuse): zero-extra-evidence region-defragmentation. Standard
// ComputeRegionIDF applies iterated-dominance-frontier propagation unconditionally, which turns
// any shared convergence point of >=2 brind_target-seeded regions into its own hard region
// boundary -- fragmenting every converging predecessor into a tiny stub that must jump out to
// reach the shared continuation (see ModuleGraphNode::flags.idf_fused, aot_module.h). This flag
// lets ComputeRegionDomSets's DFS grow THROUGH such propagation-only boundaries (additive
// duplication, same safety discipline as FDRE's fdre_suppressed second-pass copy) instead of
// stopping there. Needs ONLY the is_brind_target/is_segment_entry flags every baseline profile
// already produces -- no source-target edge collection, no per-workload threshold.
inline bool aot_idf_fuse = false;
// A-line 2026-07-25 (--aot-guardonly-lower + --aot-guardonly-edges=<path>): source-local
// guard-only oracle for the expat/Xerces-class (scattered, low-fanout callback/vtable dispatch)
// causal factor CAUSAL_LADDER_R4.md isolated as dominant there (branch-misprediction elimination
// from a guard, NOT region fusion -- region-only alone was noise on that class). Fixes the
// --aot-edge-specialize implementation confound: that mechanism broadcasts the GLOBAL top-K
// targets to EVERY gbrind site in the program (each site checks all K), causing +477% code bloat
// on expat that swamped its own real branch-miss reduction. This map is keyed source_block_ip ->
// its OWN single dominant target (loaded directly from a --brind-edges-out-format file, one
// entry per source, no ranking/broadcast) so each gbrind site only ever guards against ITS OWN
// target. Unlike --aot-fdre-lower, the target is NEVER a same-region fusion candidate (no ip2bb
// membership check) -- MakeGBr's own external-target path (Create_gbr) is used unconditionally,
// so it stays an independently-compiled function; works standalone, does not require
// --aot-fdre-region.
inline bool aot_guardonly_lower = false;
inline std::unordered_map<uint32_t, uint32_t> aot_guardonly_target;
// A-line 2026-07-25 round 12 (--aot-multiguard-lower + --aot-multiguard-edges=<path>): perfect-
// oracle probe for the UNFOLDED-FANOUT semantic class (genuine target polymorphism, share<99.9%,
// SEMANTIC_CENSUS_R11.md) -- the guard-family's UNFOLDED-MONO admission problem was retired
// (ROUND12_AUDIT_CORRECTIONS.md, no causally-validated selector found after 11 rounds); this is a
// DIFFERENT mechanism for a DIFFERENT class, not another MONO selector. --aot-guardonly-lower only
// ever checks ONE (the majority) target, which structurally under-covers a genuinely polymorphic
// site. This map is keyed source_block_ip -> an ORDERED (by descending observed weight, ties broken
// by target_ip for determinism) list of EVERY distinct target the exact oracle observed for that
// source -- a true perfect oracle for this input (N = however many targets were actually observed,
// no tuned cutoff). The jalr translator builds an N-way compare-and-branch chain, one guard per
// target, falling through to the unchanged generic gbrind only if none match.
inline bool aot_multiguard_lower = false;
inline std::unordered_map<uint32_t, std::vector<uint32_t>> aot_multiguard_targets;
// FDRE stage 3 (--aot-fdre-lower): source_block_ip -> dominant_target_ip, populated by
// ModuleGraph::ApplyFDRE (aot_module.cpp) for every APPLIED (not reverted) decision; consumed
// by rv32_qir.cpp's jalr translator to emit a guarded direct branch. Cleared/repopulated per
// compile (elfaot is single-shot per process, so no explicit reset between pages is needed --
// keys are guest addresses, globally unique within one ELF).
inline bool aot_fdre_lower = false;
inline std::unordered_map<uint32_t, uint32_t> aot_fdre_dominant_target;
// Set from ElfAotOptions::use_llvm (elfaot.cpp). FDRE stage 3's guarded brcc lowering
// (rv32_qir.cpp jalr translator) carries the `tgt` vtemp live across a new block boundary
// (bb_src's brcc condition, then the fallback block's gbrind); QCG's per-block register
// allocator (qra.cpp) does not support that cross-block liveness pattern and aborts
// (EmitFill: spill_offs != NO_SPILL) -- confirmed the stock, FDRE-off --llvm=0 AOT path has
// no such issue, so this is specific to the new guarded-branch construction, not a
// pre-existing QCG AOT defect. Until qra.cpp's block-boundary spill/fill sync is extended
// (or the lowering is restructured to avoid a cross-block temp), gate stage 3's lowering to
// the LLVM backend only; QCG falls back to the unchanged unconditional gbrind.
inline bool aot_use_llvm = true;
// DC-9 fix candidate (--aot-brcc-real-weights, default off): llvmgen.cpp's Emit_brcc attaches a
// BLANKET static branch-weight hint (md_unlikely = createBranchWeights(1,12), i.e. P(taken) ~=
// 7.7%) to EVERY guest conditional branch, regardless of the branch's actual behavior -- confirmed
// inverted for the common RISC-V loop-backedge idiom (condition-true = jump backward to continue
// looping, which is normally the HOT case, not a rare one). When on, Emit_brcc instead looks up
// the ALREADY-COLLECTED, always-on objprof exec_count for both branch targets (no new collection
// cost, no region-formation change) and derives the exact per-site weight from it, falling back to
// the unchanged static hint only if either target's exec_count is unavailable (e.g. never
// executed). See DEFECT_CARDS_A.md DC-9 ("confirmed untouched in all 3154 commits").
inline bool aot_brcc_real_weights = false;
// A-line Round 48: the INDIRECT-branch analogue of DC-9 above, targeting a DIFFERENT, always-on
// branch DC-9 never touches -- Emit_gbrind's own L1 gbrind-cache hit/miss check (llvmgen.cpp,
// `CreateCondBr(ICmpNE(entry_gipv, gipv), slowp_bb, fastp_bb, md_unlikely)`), present in EVERY
// indirect dispatch this compiler ever emits, regardless of any oracle flag. `md_unlikely` claims
// P(miss)~=7.7% UNCONDITIONALLY for every gbrind site in the program, exactly the same class of
// blanket-wrong static assumption DC-9 found for guest conditional branches -- but this time on
// the dispatch mechanism's OWN decision, using a per-source quantity Wendell has no representation
// of at all (a hit/miss rate is a summary statistic of that source's own indirect target
// distribution/concentration -- the gap this round's audit named). `--gbrind-hitrate-collect`
// (dbt/elfrun.cpp) gates a NEW, cheap, compile-time-address-baked per-source counter (tcache.h's
// gbrind_hitrate_cache) during the mandatory profiling pass; `aot_gbrind_hitrate_file` (elfaot)
// loads that dump; this flag actually uses it to replace md_unlikely with a real, per-site
// createBranchWeights(hit+1,miss+1) when data is available for that exact source, falling back to
// the unchanged static hint otherwise (same structural floor DC-9 uses, same safety net).
inline bool aot_gbrind_hitrate_weights = false;
inline char const *aot_gbrind_hitrate_file = nullptr;
// for aot
inline bool llvmopt = false;
inline uint64_t threshold = 1000;
inline uint64_t threshold_max = 0; // banded delta compilation: admit iff exec in [threshold, threshold_max); 0=off
inline bool cross_segment_branch = false;
inline std::vector<uint64_t> avoid_ips;
inline bool propagate_exec_count = true;
// V-next: dispatch-aware admission. 0 = off (pure Wendell). If >0, additionally admit brind_target (indirect-dispatch
// handler) regions that executed with exec_count >= this floor even when below the global threshold. Rationale: Wendell's
// exec_count propagation follows direct/sequential edges only [rv32_analyser.cpp], so fragmented dispatch handlers never
// inherit the dispatch loop's hotness and are under-admitted. Default-off; CLI --dispatch-admit-floor.
inline uint64_t dispatch_admit_floor = 0;
// A-line Round 59: `dispatch_admit_floor` deliberately excludes return-continuation regions
// (`IsReturnTarget`) "so it does not overlap Design 8's mechanism" -- a SCOPE boundary, not an
// empirically-tested negative result (confirmed by reading the exclusion's own comment/history).
// Design 8 only MERGES a hot return continuation into its caller's region (already shown flat-to
// -negative, independent of candidate quality); it never gives a return continuation its own,
// ordinary, independent AOT region the way `dispatch_admit_floor` already does for jump-table/brind
// -target handlers. This leaves return continuations with NO below-threshold admission path at all.
// Default off (0 = no cost-model admission). When > 0, a return-continuation region is ALSO admitted
// (as an ordinary, independent AOT region -- no merge, no wrapper, no certificate, no layout change)
// if `exec_count * avg_dispatch_saving_ns > exec_instr_count * avg_compile_ns_per_instr`, where both
// averages are computed ONCE per compile run from this SAME profiling pass's own aggregate data (not
// a fixed magic constant, not tuned per workload) -- a genuine cost-relative decision, not a raw
// count-vs-constant floor. This field holds the SCALE FACTOR (avg_dispatch_saving_ns /
// avg_compile_ns_per_instr, precomputed once) so the per-region check stays a single multiply
// -compare. CLI --aot-return-admit-cost-model.
inline double return_admit_cost_ratio = 0.0;
// A-line Round 59, cheap A/B control for the cost-model above: a raw floor (same shape as
// dispatch_admit_floor) applied ONLY to return-continuation regions, to isolate "does admitting hot
// return continuations at all help" from "does the cost-model's specific ratio matter". Default off.
// CLI --aot-return-admit-floor.
inline uint64_t return_admit_floor = 0;
// A-line Round 59: pair with return_admit_floor/return_admit_cost_ratio -- compile the newly
// -admitted return-continuation regions at O0/optnone (cheap compile) instead of the default O3.
// Tests whether the compile-cost regression found with plain admission is rescued by cheaper
// codegen, the same way `dispatch_handler_optnone` was already tried (and found NOT to generalize,
// regressing compute-heavy handlers) for the DIFFERENT dispatch_admit_floor candidate set.
inline bool return_admit_optnone = false;
// A-line Round 60: move the QCG tier's normally-inlined l1_brind_cache hit-check out-of-line (one
// shared stub, qcgstub_brind_checked, instead of ~5-6 x86 instructions duplicated at every
// indirect-terminated TB). QCG-tier only (gated on jit_mode in Emit_gbrind) -- code compiled once
// per run, never persisted, so its per-site compile cost never amortizes the way AOT's does.
// Default off. CLI --qcg-gbrind-outline.
inline bool qcg_gbrind_outline = false;
// 2026-06-20 jserv-A indirect-edge visibility (default-off): path to a runtime indirect-edge profile (`src dst count`
// per line, from elfrun --brind-edges-out). The warm L1-brind-cache musttail dispatch path bypasses the region
// exec_count, so heavily-dispatched indirect HANDLERS profile as exec=1 -- indistinguishable from truly-cold code by
// the count threshold (verified: dispatch_bench gap is all-or-nothing under a count sweep). The indirect-edge profile
// DOES distinguish them (warm handlers carry large indirect-edge mass). When set, BuildModuleGraph (a) marks each
// observed indirect target a region entry with its TRUE dispatch mass, then (b) PROPAGATES that hotness along direct
// succ edges to admit the reachable warm dispatch COMPONENT (not the whole program). CLI --aot-indirect-edges.
inline char const *aot_indirect_edges = nullptr;
// Research ablation for the existing indirect-flow experiment. Disabling it isolates target admission from
// direct-CFG component completion; it has no effect unless --aot-indirect-edges is also supplied.
inline bool aot_indirect_propagate = true;
inline int aot_admit_mode = 0; // A0-A5 attribution matrix (2026-07-20): 0=A1 jserv-A original
                                        // (pooled+floor, default); 1=A2 pooled,no-floor; 2=A3 per-source
                                        // structural control (no weight); 3=A4 SCA (top1/total); 4=A5 Wilson
                                        // lower bound (sample-size-aware). See dbt/aot/aot.cpp for full derivation.
// V-next closure (mechanism evidence, default-off): count indirect-dispatch slowpath (qcgstub_brind) hits at runtime.
// Used to show DAA reduces the AOT<->QCG indirect-dispatch bounce vs Wendell. CLI --count-brind; printed at exit.
inline bool count_brind = false;
inline uint64_t brind_count = 0;
// A-line round 20: exact per-call cycle accounting for qcgstub_brind (the indirect-dispatch
// slowpath), gated behind the same --count-brind flag. An RAII guard at function entry (see
// jitabi.cpp) accumulates rdtsc-measured cycles across EVERY return path (including the several
// async-housekeeping early-escape paths), so this bounds the true per-event cost rather than
// assuming it from frequency alone.
inline uint64_t brind_slowpath_cycles = 0;
// V-next: AOT LLVM optimization level (0..3, default 3=O3). Lower levels slash AOT compile cost. Combined with
// dispatch-admission (which is compile-cost-dominated), a lower optlevel can fix DAA's lifecycle (break-even) while
// warm runtime barely changes (codegen quality is not the bottleneck). CLI --aot-optlevel.
inline int aot_optlevel = 3;
// V-next: compile dispatch-ADMITTED handler regions (sub-threshold brind_target, recovered by dispatch admission) with
// optnone+noinline so the O3 module pipeline SKIPS them (cheap compile), while HOT regions keep O3. Rationale: codegen
// quality is irrelevant for dispatch handlers (the win is being-in-AOT, not O3) but critical for hot compute loops, so
// global O0 is wrong (degrades hot regions e.g. sha512 -186%); per-handler optnone fixes DAA's compile-cost lifecycle.
inline bool dispatch_handler_optnone = false;
// Round-40 Route E (default-off): per-region hot-floor opt level. If >0, ADMITTED regions (mx>=threshold) whose
// max exec_count mx < aot_hot_floor compile at optnone (cheap, O0-like) while the HOT regions (mx>=aot_hot_floor)
// keep the module optlevel (O3). Coverage is PRESERVED (all admitted regions still compiled) -- unlike trimming.
// Rationale: single-core Wendell is compile-bound on high-cf workloads; cheapening the COLD TAIL of the admitted
// set reduces L_full while keeping exec quality where it matters. CLI --aot-hot-floor.
inline uint64_t aot_hot_floor = 0;
// CPB (2026-07-20, Candidate 2, confidence-proportional compile budget): compile an indirect-admitted
// region at optnone (cheap) instead of the module optlevel iff its indirect_confidence < 0.5 (majority/
// Bayesian break-even -- more-likely-than-not to be the wrong bet on this call site's future behavior).
// DIFFERENT axis than Route E's aot_hot_floor (which gates on raw size/hotness, already found NOT to
// cleanly separate compute-heavy-but-unpredictable handlers from cheap ones -- content, not size, is
// the confound there). CPB gates on PREDICTABILITY instead, orthogonal to compute intensity. Default off.
inline bool aot_cpb_optnone = false;
// Round-41 region-merge (default-off): if >1, group up to this many consecutive admitted regions (same page,
// in iteration order) into ONE LLVM worker function (union of ip-ranges) with an entry switch on state->ip ->
// the requested region-entry block; non-primary group entries become GlobalAliases to the worker. Cuts the
// number of O3-optimized functions (Phase-1: ~57% of compile is per-function overhead) while PRESERVING
// coverage and O3 code quality. CLI --aot-merge-max. 1 (or 0) == off (one function per region, stock).
inline unsigned aot_merge_max = 1;
// Round-42 reduced-O3 pipeline (default-off). The AOT optimize+expand loop runs the FULL O3 pipeline
// n_expands(=4) times for iterated gbr/gbrind intrinsic expansion -> per-function O3-setup cost paid 4x.
// aot_heavy_final: run heavy O3 ONLY on the final expand iteration; iterations 0..n-2 do expand + a
// light cleanup (instcombine+simplifycfg). Heavy opt then runs ONCE on fully-expanded code -> cut
// per-function setup ~ (n_expands-1)x while keeping ~O3 quality. CLI --aot-heavy-final.
inline bool aot_heavy_final = false;
// Round-42: number of FINAL expand iterations that run heavy O3 (the rest do expand+light). 0 = use the
// aot_heavy_final bool (1 if set, else all-heavy = stock). >0 overrides: e.g. 2 = last two heavy. Higher
// = closer to stock O3 quality at more compile. The compile/quality frontier knob. CLI --aot-heavy-last-n.
inline unsigned aot_heavy_last_n = 0;
// Round-42 region-count-aware K (default 0=off): if the module's admitted region count < this, BUMP the
// heavy schedule to >=2 final heavy iterations (early heavy opt matters for small/hot IR -- measured:
// heavy_last1 regresses small few-region exec-bound workloads aes/sha512/qsort). Lets large modules use
// the aggressive K while keeping small ones safe. Signal = region count (build-time, free). CLI
// --aot-heavy-min-regions.
inline unsigned aot_heavy_min_regions = 0;
// Round-44 diagnostic (default-off): count intrinsic expansions per optimize+expand iteration to show
// the expansion FIXPOINT (when lowering converges) -- evidence that K=2 = "heavy on the stable tail" is
// an algorithmic consequence of the n_expands structure, not a tuned magic number. CLI --aot-log-expand.
inline bool aot_log_expand = false;
inline unsigned long intrin_expand_count = 0;
// 2026-07-28 A-line link-phase lever (default-off, byte-of-behavior identical when off): AOT_PHASE_TIMING
// showed objemit_link_ms is UNCHANGED by any optimize/expand-side lever (optnone, idf-fuse, heavy-last-n) --
// it is driven by GNU ld processing the (aottab + N admitted-region) object's symbol table/relocations, a
// genuinely separate axis from LLVM's own IR/codegen pipeline. Switches LinkAOTObject's linker invocation
// from /usr/bin/ld (GNU BFD) to LLVM's own ld.lld (already present in this project's toolchain,
// /usr/lib/llvm-20/bin/ld.lld), which uses a different, generally faster symbol-resolution/relocation
// algorithm. CLI --aot-use-lld.
inline bool aot_use_lld = false;
// 2026-07-28 A-line diagnostic (default-off, -1 = unchanged CodeGenOptLevel::Aggressive): GetAOTTargetMachine
// hardcodes the BACKEND (ISel/scheduling/regalloc) opt level to Aggressive regardless of aot_optlevel, which
// only drives the MIDDLE-END (PassBuilder IR pipeline) level -- two genuinely separate LLVM knobs. Round-41's
// measured cost model (compile_ms = 7.47*n_regions + 0.274*total_instr) attributes ~4.2ms/region to isel
// specifically as NOT reducible via IR-level optnone/heavy-last-n (both already tested this cycle). This is a
// coarse, WHOLE-MODULE diagnostic witness (no per-function selectivity yet) to check whether the backend level
// is a real, separate lever at all before investing in a selective mechanism. CLI --aot-codegen-optlevel.
inline int aot_codegen_optlevel = -1;
// A-line round 7 (2026-07-22) diagnostic: how many gbrind sites, across the whole build, actually
// hit Expand_gbrind's existing unconditional "gipv is already an LLVM Constant -> gbr" shortcut.
// Answers empirically whether that pre-existing optimization already fires for real auipc+jalr
// sites (would make a NEW static-target-fixing candidate redundant) or is dormant (would make
// fixing ITS wireup a real, non-guard candidate). No behavior change; read-only counter.
inline unsigned long gbrind_constfold_count = 0;
inline unsigned long gbrind_total_expand_count = 0; // denominator: total Expand_gbrind(must_expand=true) calls
inline bool aot_log_gbrind_constfold = false; // default-off; must not print unless explicitly requested
// Round-54-fix (default-off): log the module's total LLVM instruction count after each optimize iteration.
// The IR-DELTA between consecutive heavy O3 passes is the optimizer-CONVERGENCE signal -- a candidate for an
// AUTOMATIC detector of the heavy-pass depth K (stop when the IR stops changing) instead of a fixed K=2. CLI
// --aot-log-irsize.
inline bool aot_log_irsize = false;
// P2E: default-off STATIC DIAGNOSTIC PROBE -- append ONE llvm::ReassociatePass over the module after
// every optimize/expand iteration and before codegen. Does not replace or reorder the default O3
// pipeline and adds no InstCombine. Off => that code never runs and the object is byte-identical.
// CLI --aot-reassoc-probe. Diagnostic only; not a method and not a performance feature.
inline bool aot_reassoc_probe = false;
// Round-54 (default -1=stock): run the FINAL intrinsic expansion at this iteration index instead of the last
// (n_expands-1). Lets us test the EXPAND-FIRST alternative schedule (merge the two lowering phases: lower fully
// early, then optimize), to decide whether deferring the bulk expansion to the end (the current two-phase
// design) is optimal vs a single-phase lower-then-optimize. CLI --aot-final-expand-at.
inline int aot_final_expand_at = -1;
// Round-54 (default -1=use aot_optlevel): opt level for the heavy iterations that run BEFORE the final
// expansion (the Phase-1 "optimize surroundings while intrinsics opaque" pass). Lets us test whether Phase-1
// needs full O3 or a cheaper level suffices (a finer per-phase schedule). CLI --aot-phase1-optlevel.
inline int aot_phase1_optlevel = -1;
// Round-46 profile-guided edge specialization (default-off). At a dynamic gbrind, before the L1-brind-cache
// fastpath, emit a guarded DIRECT musttail call for each top-K profiled hot target (a known AOT fn) so LLVM
// can inline/optimize ACROSS the indirect edge; miss falls through to the generic L1-cache+slowpath (correct).
// The top-K targets are force-admitted via dispatch_admit_list. CLI --aot-edge-specialize/-topk/-profile.
inline bool aot_edge_specialize = false;
inline unsigned aot_edge_topk = 0;
inline std::vector<uint32_t> aot_edge_targets; // top-K hot indirect-target guest ips (force-admitted + guarded)
// ORACLE-ONLY (2026-07-22, CORRECTION_ORACLE_OVERCLAIM.md part C): replace the dispatch with an
// unconditional direct call to aot_edge_targets[0], no guard, no fallback. Breaks correctness by
// design; measurement-only, never deployable, default off.
inline bool aot_edge_oracle_unconditional = false;
// A-line round 25 Track A Treatment 1 (ORACLE-ONLY, default off): per-SOURCE unconditional direct
// call for RETURN-class (jalr_class==2) gbrind sites whose known_targets oracle shows EXACTLY one
// distinct target -- unlike aot_edge_oracle_unconditional (a single GLOBAL target for the whole
// program), this is per-site, using the same known_targets/known_target_counts carrier Row 4/5
// already populate from --shadow-edges2-all-jalr evidence. Breaks correctness by design (no guard,
// no fallback) -- measures the PERFECT/FREE ceiling ("if a zero-cost, always-right predictor
// existed, how much value is there") to decide whether the deployable static-fan-in candidate is
// worth building the full function-boundary-heuristic machinery for. Never deployable.
inline bool aot_return_oracle_unconditional = false;
// A-line round 25 Track B free-oracle test (default off, diagnostic only): classify gipv's
// post-O3 IR shape at each Expand_gbrind site that did not const-fold. See llvmgen.cpp.
inline bool aot_log_gipv_shape = false;
// A-line round 25 Track C free-oracle test, step 1 (default off, diagnostic only): dump static
// in-degree (ModuleGraphNode::preds.size()) for every gbrind source block. See llvmaot.cpp.
inline bool aot_dump_gbrind_indegree = false;
// A-line round 26 (default off, diagnostic only): ground-truth per-site tagging to directly
// measure whether multiple logical gbrind QIR sites end up sharing ONE final host dispatch
// instruction after optimization (vs. each getting its own, as CreateQCGFnCall's per-call-site
// construction should produce absent any LLVM-level merging). See llvmgen.cpp/llvmaot.cpp.
inline bool aot_log_gbrind_site_identity = false;
inline uint32_t g_gbrind_site_id_next = 0;
// A-line round 26 Part A/Track C (default off, ORACLE -- known baseline is Ertl/Gregg dispatch
// replication/context threading, not a claimed contribution): give each static predecessor of a
// shared gbrind dispatch its own physical host indirect-transfer site. Same lookup/targets, no
// guard, no offline profile -- isolates predictor-context-loss value in isolation from the
// already-closed target-frequency-guarding family. See llvmgen.cpp.
inline bool aot_gbrind_context_replicate = false;
// A-line round 28 Gate 1 (default off, ORACLE only -- exhaustive-truth-for-the-measured-run, not
// a deployable method): per-SOURCE order-1 context oracle. Reads an offline exhaustive .trans
// file (src prev target count, the SAME format Row 4/5's known_targets already parse, produced by
// --brind-edges-out --sr-record-returns=1) and, for each gbrind SOURCE that has >=1 real observed
// (prev,target) pair, builds a per-SITE (not global, not broadcast) guard chain reading/updating
// that site's OWN dedicated tcache::gbrind_ctx1_slots entry -- never CPUState::last_brind_target,
// never shared with any other site. See llvmgen.cpp/rv32_qir.cpp.
inline bool aot_order1_context_oracle = false;
inline char const *aot_order1_context_file = nullptr;
inline uint32_t g_gbrind_ctx1_slot_next = 0;
// Reachability/correctness counters for the order-1 oracle (Gate 1 point 2) live as CPUState
// fields (CPUState::gbrind_order1_covered/gbrind_order1_hits, rv32_cpu.h) -- same relaxed-
// counter pattern as gbrind_counter, NOT free globals, since AOT-compiled code runs in a
// different process than elfaot compiled it in (see the gbrind_ctx1_slots pointer-indirection
// comment in llvmgen.cpp for why a baked global address would be unsafe here).
inline unsigned long gbrind_context_replicate_sites = 0;
inline unsigned long gbrind_context_replicate_clones = 0;
// A-line round 29 Gate 1 (default off, ORACLE only): per-SOURCE MARGINAL (context-free) target
// oracle. Reuses the SAME --aot-order1-context-file .trans data as the order-1 oracle above, but
// aggregates over prev, so the guard is a single compile-time-constant compare against gipv --
// deliberately zero runtime state (no slot array, no prev-load, no update-store). Independent
// on/off switch from aot_order1_context_oracle so the two treatments can be measured separately
// or (not yet done) composed. See rv32_qir.cpp's LoadMarginalOracle, llvmgen.cpp.
inline bool aot_marginal_context_oracle = false;
// A-line round 32 Gate 2 (default off, ORACLE only): per-SOURCE static jump-table oracle. Reads a
// file (produced offline by reading the guest ELF's own read-only memory, bootstrapped only via
// cheap --shadow-edges2-out evidence to LOCATE the table -- see
// experiments/2026-07-23-0449-.../r32_bootstrap_tool.py) of "src target1 target2 ..." lines: the
// FULL, immutability-verified target set for a genuine compiler-emitted switch table. Lowered as
// a real llvm::SwitchInst so the backend picks O(1) jump-table codegen -- see rv32_qir.cpp's
// LoadStaticTableOracle, llvmgen.cpp.
inline bool aot_static_table_oracle = false;
inline char const *aot_static_table_file = nullptr;
// A-line round 32 R32.9 (default off): TRUE in-process resolution -- no file, no external
// disassembler, no shell-out. Reuses elfaot's own already-mapped guest memory + decode structs
// during normal translation. Independent of aot_static_table_file (set this INSTEAD to skip the
// file-based oracle entirely); requires aot_static_table_oracle=1 as well.
inline bool aot_static_table_inline = false;
// A-line Round 50 (default off): for static_table_md's existing SwitchInst consumer, use
// CreateInlinableQCGFnCall (a non-musttail call with AlwaysInline attached at the call site)
// instead of the generic CreateQCGFnCall for each "hit" case -- see llvmgen.cpp's
// CreateInlinableQCGFnCall comment for the full mechanism/safety rationale. Independent of
// aot_static_table_inline above (a different flag: THAT one is about in-process table
// RESOLUTION, this one is about the CONSUMER'S call-site inlinability).
inline bool aot_static_table_alwaysinline = false;
// A-line Round 64 (default off): isolate the switch-to-proven-candidates consumer from inlining --
// every case uses ordinary CreateQCGFnCall (musttail, zero body duplication), never
// CreateInlinableQCGFnCall. Tests whether real polymorphic-dispatch branch-misprediction cost
// (confirmed via direct PMU sampling on a real site, not assumed) can be recovered by a
// statically-sound switch WITHOUT paying Round 54's causally-identified inlining compile-cost tax.
// Mutually exclusive with aot_static_table_alwaysinline (independent flag, requires
// aot_static_table_oracle=1 as well).
inline bool aot_static_table_switch_noinline = false;
// A-line Round 66 (default off): Round 65's phase-timing breakdown found compile cost is
// dominated (71-74%) by LLVM's optimize+expand pass, run across EVERY admitted function, not by
// anything the switch-noinline consumer itself adds (its own IR-construction delta is <5% of
// compile). static_table_resolve's candidate TARGETS are a SUBSTANTIAL, structurally-identifiable
// fraction of all admitted functions on some real workloads (measured: expat 181/489=37%,
// pcre2_super 294/643=46%, vs libyaml 36/482=7.5%, interpreter_bench 10/171=5.8%,
// antlr4_generated 22/2245=1% -- a real, workload-dependent upper bound, not assumed uniform).
// This marks every such candidate target llvm::Function with OptimizeNone+NoInline -- a genuine
// compile/decision-structure change (which functions get expensive optimization), not a gate on
// whether the switch fires, and applies identically whether switch_noinline/alwaysinline is on or
// off (it changes the SHARED baseline compile cost of these functions, not the dispatch
// mechanism). Requires aot_static_table_oracle=1. Real risk, tested not assumed: any of these
// functions ALSO reached via a direct/hot call path elsewhere pays -O0 execute cost on that path
// too -- this is exactly what the matched-trial execute-time measurement must catch, not asserted
// away.
inline bool aot_static_table_target_optnone = false;
// A-line Round 44 (default off, ORACLE only): index-preserving compact host dispatch. Requires
// aot_static_table_oracle=1 aot_static_table_inline=1 as well (reuses the SAME dataflow proof --
// table-load shape, proven local-constant base, proven local-constant bound, table verified
// immutable, every entry validated as a real code address -- TryResolveIndexed additionally
// captures the index register and the table's raw, index-ordered contents). Lowered
// (Expand_gbrind_EdgeSpecializeAndSlowpath) as a bounds check + one load from a compile-time
// host-address table + one indirect call -- O(1) IR regardless of table size, NOT an N-way
// SwitchInst -- falling back to the unchanged generic gbrind slowpath on out-of-bounds or a
// non-admitted entry.
inline bool aot_indexed_dispatch_oracle = false;
// A-line Round 45 (default off): compile-time-only (zero profile) worst-case cost dominance gate.
// When on, the compact dispatch is emitted for a site ONLY IF every one of its proven table
// entries is independently AOT-admitted (n_admitted == table_len, a fact checkable purely from
// which AOT functions already exist in the module -- no runtime hit-rate/profile data). Under
// this condition the fallback (out-of-bounds/null) path is structurally unreachable for any
// correctly-bounded guest execution, so the extra overhead this consumer adds is never paid
// ADDITIONALLY on top of the original path's own cost -- see llvmgen.cpp's comment at the gate
// for the causal finding (sqlite_super's regression) this is derived from.
inline bool aot_indexed_dispatch_require_full_coverage = false;
// A-line Round 33 (default off, ORACLE only): per-SOURCE C++ virtual-call target-set NARROWING
// (not proven-complete, unlike static_table_targets above -- deliberately GUARDED, falls to the
// unchanged generic gbrind slowpath for any receiver whose vtable isn't in the narrowed set).
// Derives the receiver's static C++ type from the enclosing function's own Itanium-mangled name
// (a fact already encoded in the linked binary, no profiling), then narrows the legal target set
// to that type's transitive RTTI descendants -- see rv32_qir.cpp's vtable_narrow namespace and
// experiments/2026-07-23-0449-.../ROUND33_VTABLE_NARROWING_CENSUS_AND_HYPOTHESIS_A.md for the
// fast-pilot evidence (100% recall, 42-155x candidate-set reduction on 2 independent real C++
// workloads) that justified building this.
inline bool aot_vtable_narrow_oracle = false;
inline bool aot_vtable_narrow_inline = false;
// A-line Round 34 (default off): AUIPC+JALR direct-call-sequence fusion -- a translator
// completeness fix (recognizes the standard RISC-V psABI call/tail pseudo-instruction expansion
// as the compile-time-constant direct call it is), not a narrowing algorithm. See
// dbt/guest/rv32_qir.cpp's direct_call_resolve namespace and
// experiments/2026-07-23-0449-.../ROUND34_AUIPC_JALR_DIRECT_CALL_FUSION.md.
inline bool aot_direct_call_fusion = false;
// A-line Round 56 (default off): return-continuation directification -- a RISC-V "ret" (rd=x0,
// rs1=ra) is lowered as a fully generic Create_gbrind today regardless of whether the enclosing
// function has a statically-proven single caller. When on, TRANSLATOR(jalr) checks the CURRENT
// region's entry ip (the true function entry) against return_target_resolve's whole-binary static
// single-caller certificate (dbt/guest/rv32_qir.cpp) and, if eligible, lowers the return as a
// plain direct branch (MakeGBr) to the one possible continuation -- zero code duplication, zero
// region-membership change (unlike the already-closed Design 8 region-merge), zero guard. Natural
// no-op on any region that isn't eligible.
inline bool aot_return_directify = false;
// A-line Round 36 Consumer A (default off): when vtable_narrow's RTTI-descendant candidate set
// for a site is PROVEN to have exactly one member, lower the dispatch as a TRUE zero-guard
// direct edge (MakeGBr) instead of the existing guarded SwitchInst every candidate-set size
// currently goes through. Requires --aot-vtable-narrow-oracle=1 --aot-vtable-narrow-inline=1.
// See dbt/guest/rv32_qir.cpp's TRANSLATOR(jalr) comment for the soundness argument.
inline bool aot_vtable_narrow_zeroguard_singleton = false;
// Round-46 P6 prof-correct under-admit gate: when on, Expand_gbrind specializes a top-K target ONLY if it is
// NOT naturally admitted (its prof max exec_count < threshold). aot_natural_admitted is populated during the
// AOT DEFINE pass (region entry ips with mx >= threshold) BEFORE the optimize+expand pipeline runs, so the
// gate tests the SAME quantity admission uses (unlike the edge-in-count proxy, which is on a different scale).
inline bool aot_edge_underadmit_gate = false;
inline bool aot_edge_region_merge = false;      // P3: single-entry edge-directed region merge (dispatcher entry, majority-coverage handlers as INTERNAL blocks; gbrind lowers to internal switch -- no GHC-GHC wall, no guard chains)
inline std::unordered_map<uint32_t, std::vector<uint32_t>> aot_region_merge_map; // primary entry ip -> internal target entry ips
inline bool aot_edge_move_not_copy = false; // A-line 2026-07-23: internalized merge targets are MOVED, not copied --
                                            // their standalone region body is replaced by a 2-insn thunk
                                            // (state->ip = T; musttail _xS) that re-enters the source function's
                                            // existing multi-entry state->ip switch. Removes the duplicate compile.
inline bool aot_work_counter = false;           // DVET: emit region-entry work counter in AOT code
// 2026-07-28 A-line causal diagnostic (default off, byte-identical when off): emit a compile-time
// -assigned dense-slot increment (CPUState::region_entry_hits[slot]) at every admitted region's
// Run()-entry, same insertion point/discipline as aot_work_counter above but per-region instead of
// a single global sum. CLI --aot-region-hit-count. Pairs with aot_region_hit_map_out below.
inline bool aot_region_hit_count = false;
// Default-off formal-measurement companion.  Reuse the dense region slots to
// accumulate invariant-TSC deltas from each compiled region's entry to its
// outgoing dispatch.  This is built into dedicated diagnostic artifacts and
// must not be enabled together with aot_region_hit_count.
inline bool aot_region_cycle_count = false;
// Path to dump "slot entry_ip" lines (one per admitted region, in compile order) during THIS
// elfaot invocation, so a later elfrun --dump-region-hits run's slot counts can be joined back to
// real entry IPs. Empty = no dump (still increments the slots if aot_region_hit_count is set).
// CLI --aot-region-hit-map-out.
inline char const *aot_region_hit_map_out = nullptr;
// elfrun-side companion to aot_region_hit_count: dump nonzero CPUState::region_entry_hits[] slots
// at exit. CLI --dump-region-hits.
inline bool dump_region_hits = false;
// Line-B activation invariant (LINEB_GATE_IMPLEMENTATION_PLAN.md, LINEB_ACTIVATION_INVARIANT_CONSTANTS.md):
// activate the census/override machinery iff exec_instr_seen * kDeltaMachineNsPerInstr > kCMachineNs.
// Both constants are machine-measured substrate properties, not workload-tuned: kDeltaMachineNsPerInstr is
// reused (not re-derived) from CDA Round-16's machine-calibrated mean AOT-vs-QCG per-instruction wall
// saving (0.1665 ns/exec-instr, cross-validated against Wendell's own hand-set 262144 threshold);
// kCMachineNs is the collaborator's conservative worst-case substrate-floor derivation (~0.515s), the
// larger of the two measured floors (sqlite/expat), erring toward delaying activation, never
// under-protecting. Default-off; with the flag off, exec_instr_seen never increments and this check is
// never consulted, so behavior is byte-identical to today.
inline bool sr_activation_invariant = false;    // --sr-activation-invariant: gate override on exec_instr_seen
inline constexpr double kDeltaMachineNsPerInstr = 0.1665;
inline constexpr double kCMachineNs = 515'000'000.0;
inline bool aot_count_gbrind = false;           // A-line surface (a): emit gbrind-execution counter in AOT generic dispatch path
inline unsigned long long g_gbrind_exec_mirror = 0;  // exit-print mirror of CPUState::gbrind_counter (updated per evaluator pass)
inline unsigned long long g_multientry_switch_hits_mirror = 0;
inline unsigned long long g_multientry_default_hits_mirror = 0;
inline unsigned long long g_wrapper_calls_mirror = 0;
inline bool dry_page_floor = false;             // dry prefilter: skip pages whose max exec < threshold (region mx <= page max => DRYREGION hot=1 set preserved exactly)
// DVET epoch-trial state (parent side; active only when trial_P.so/trial_S.so appear in staging)
inline bool dvet_enable = false;                // --dvet: run the dual-variant epoch trial when published
inline int dvet_phase = 0;                      // 0 off, 1 P-epoch, 2 S-epoch
inline int dvet_pair = 0;                       // completed pairs
inline int dvet_s_wins = 0;                     // consecutive S pair-wins
inline int dvet_p_wins = 0;                     // consecutive P pair-wins
inline unsigned long dvet_epoch_ticks = 0;      // ticks elapsed in current epoch
inline unsigned long dvet_epoch_len = 2;        // current epoch length in keeper ticks (doubles per pair)
inline unsigned long long dvet_work0 = 0;       // work counter at epoch start
inline unsigned long dvet_us0 = 0;              // wall us at epoch start
inline double dvet_rate_p = 0, dvet_rate_s = 0; // work-rate of the two epochs in the current pair
inline char dvet_verdict = 0;                   // 0 none, 'S' keep-spec, 'P' rollback-plain
inline volatile bool esc_dvet_ripe = false;     // set at AOT-majority; arms the edge estimator (its only consumer)
inline std::vector<unsigned long> sr_tbs_hist;   // per-tick translation counts (fork settling test)
inline std::unordered_set<uint32_t> aot_natural_admitted;
// Design 8 alias multi-entry cross-page safety (2026-07-24, real-workload obstruction found on
// expat after the witness-level CreateQCGGbr fix): a same-page "extra ModuleGraph pred" check is
// NOT sufficient to prove a link-merge candidate is only ever reached via a genuinely computed
// gbrind -- ModuleGraph is built fresh PER PAGE (a pre-existing, repeatedly-documented limitation
// of this codebase), so a direct jal/branch from a DIFFERENT page targeting the same address is
// invisible to that check. Populated ONCE (llvmaot.cpp, before the main per-page translate loop)
// by a raw scan of every executed instruction's own immediate branch/jal target, across ALL
// pages; checked by ModuleGraph::ApplyLinkAwareRegionMerge (aot_module.cpp) to additionally
// exclude any candidate whose target is a genuine direct-branch destination from ANYWHERE in the
// profiled program, not just the same page.
inline std::unordered_set<uint32_t> g_direct_branch_targets;
inline bool g_direct_branch_targets_built = false;
// 2026-06-15 path-history exec-proof: CONTEXT-KEYED (2-level) dispatch specialization. Instead of guarding the
// site-local top-K targets (aot_edge_specialize), guard the PATH context: for each hot (prev_target -> predicted
// target) pair, emit `if (state->last_brind_target == P && gip == T) musttail T_aot()`. The predicted target is
// argmax over the (prev)->target transition profile (.trans). Global prev (CPUState::last_brind_target), the
// minimal prototype. Targets force-admitted like the 1-level path. Default-off. CLI --aot-context-edge-*.
inline bool aot_context_edge_specialize = false;
inline unsigned aot_context_edge_topk = 0;
inline std::vector<std::pair<uint32_t, uint32_t>> aot_context_edges; // (prev_target, predicted_target) hot contexts
// aot_pipeline: if non-empty, a custom LLVM pass-pipeline string used INSTEAD of the default O3 pipeline
// for the heavy iteration(s) (e.g. "function(sroa,early-cse<memssa>,instcombine,gvn,simplifycfg)" --
// keep high-value scalar opts, drop loop/vectorize/inline). CLI --aot-pipeline. Empty == default.
inline char const *aot_pipeline = nullptr;
// 2026-06-19 AARS (adaptive AOT reuse): if set, boot this OTHER binary's .aot.so by guest-ip at startup (in addition
// to / instead of this binary's own artifact). Lets an interpreter's full-AOT be REUSED across guest programs whose
// interpreter regions are byte-identical (matching gips serve AOT; program-specific gips fall back to QCG). The
// loader (BootOneArtifact) keys by gip, not binary checksum, so cross-program reuse is correct-by-byte-identity.
// CLI --aot-reuse <path>. Default off.
inline char const *aot_reuse_path = nullptr;
// AARS byte-identity filter: the ELF the reuse artifact was built from. When set, a reuse aottab gip is served AOT
// ONLY if the current binary's guest bytes over [gip,next_gip) are byte-identical to the reuse ELF's -> correct by
// construction (identical guest region => identical translation). Unmatched gips fall back to QCG. CLI --aot-reuse-elf.
inline char const *aot_reuse_elf = nullptr;
// V-next Phase 2B: SHARDED PARALLEL COMPILE. If aot_shard_mod>1, this elfaot process DEFINES (translates+codegens) only
// admitted regions whose global admitted-index % aot_shard_mod == aot_shard_idx; all entries are still DECLARED so
// cross-shard direct calls stay external (resolved at link). Running aot_shard_mod processes in parallel, each with a
// distinct aot_shard_idx, compiles the SAME region set in parallel -> parallel wall = max-process-time ~ serial/N. This
// is the IMPLEMENTED test of whether parallel compile drops DAA's lifecycle break-even below N<=30 (not arithmetic).
// When sharding, the .o is written to a shard-suffixed path and LinkAOTObject is skipped (link is measured separately).
inline int aot_shard_mod = 1;
inline int aot_shard_idx = 0;
// V-next Phase 2 (R3): SHARD-LINK aggregation mode. If aot_shard_link>0 (=N), this elfaot invocation does NOT codegen
// functions; it records ALL admitted region gips, emits an aottab-only object (single _aot_tab sized for all gips), then
// links it together with the N pre-built shard .o (<obj>.IofN) into ONE runnable .aot.so and writes the resolved aottab.
// This closes the lifecycle proof: the sharded build produces a RUNNABLE artifact (elfrun --aot=1), not just .o files.
inline int aot_shard_link = 0;
// V-next R4: applicability-feature dry-run. If true, elfaot runs admission analysis ONLY (BuildModuleGraph +
// ComputeRegions per page, no codegen/link) and prints the profile-derived applicability features used by the
// build-time gate (dispatch exec-mass fraction = sum exec_count of recovered dispatch handlers / total executed mass;
// recovered/admitted/total region counts). This is the cheap, workload-name-independent signal that predicts whether
// DAA helps (dispatch-bottlenecked) -> whether to use sharded DAA / serial DAA / Wendell. CLI --dump-applicability.
inline bool dump_applicability = false;
// Round-8 region-utility: with --dump-applicability, also emit a per-region line (REGIONDUMP ip exec_count instr_count
// n_nodes is_brind_target is_return_target hot handler) for every executed region, so an offline region-utility model can
// be built (exec_count = steady-state-ness proxy; instr_count = compile/size cost). Default-off; no codegen change.
inline bool dump_regions = false;
// A-line 2026-07-27 (default-off, only meaningful combined with --dump-regions): also emit
// internal-successor REGIONEDGE lines (kind=internal) for edges whose destination IS a member of
// the same region -- the base --dump-regions output only ever logged edges that EXIT a region,
// making region-internal reachability/dominator analysis structurally impossible from its output
// alone. See llvmaot.cpp's REGIONDUMP block.
inline bool dump_regions_internal_edges = false;
// Round-15 DIA (default-off): record indirect source->target EDGES during the profiling run. When enabled, the brind
// slowpath still MARKS targets (profile semantics preserved) but SKIPS the l1 brind-cache insert, so every indirect
// transfer keeps taking the slowpath and the full (src,dst,count) edge multigraph is observed. Profiling-run-only cost.
inline bool profile_brind_edges = false;
// A-line 2026-07-27 (--sr-bounded-exhaustive=<N>): caps the exhaustive profile_brind_edges
// mechanism to the first N dispatches (0 = unlimited, existing behavior unchanged). Gives TRUE
// (not approximated/miss-gated) order-1 data for a bounded prefix of the run, then reverts to
// normal l1-cached dispatch for the remainder -- trades full-run coverage for a controllable,
// non-workload-tuned cost (N is a dispatch-count budget the caller chooses, not a magic rate).
inline unsigned long sr_bounded_exhaustive_limit = 0;
inline unsigned long g_bounded_exhaustive_count = 0;
// Shadow-edge discovery (A-line, next cycle after FDRE): unlike profile_brind_edges (which
// forces EVERY indirect dispatch through the slowpath, disabling the l1 cache entirely for the
// whole run -- measured 13.9x-36.1x wall-time overhead), this keeps the existing l1_brind_cache
// fast path COMPLETELY UNCHANGED and adds one cheap runtime call per dispatch to a SEPARATE,
// SOURCE-indexed shadow cache (jitabi.cpp's ShadowEdgeCheckImpl): on a miss (this source's
// computed target differs from what THIS source last dispatched to -- rare for a monomorphic
// call site, since after the first miss it's a hit forever), it calls the SAME
// dbt::brindedges::Record(src,dst) the exhaustive collector uses, so the SAME Dump()/file format
// is reused -- the deliverable is the (source,target) SUPPORT (existence), not exact per-edge
// counts; counts are reconstructed offline from objprof's own exec_count marginals via
// conservation (see the flow-conservation peeling analysis in
// experiments/2026-07-23-.../scripts/recon_peel.py). Profiling-run-only cost, same as
// profile_brind_edges; mutually exclusive with it (either exhaustive OR shadow-gated, not both).
inline bool shadow_edges = false;
// H2 (RESIDUAL_COMPONENT_ANALYSIS.md's tier-2 sketch, SUPPORT_DISCOVERY_H1_VS_H2.md): a per-source
// K-WAY history SET instead of H1's single last-target slot. On a dispatch (src,tgt), a HIT (tgt
// already in src's up-to-K-entry set) is a no-op; a MISS unconditionally calls the SAME
// brindedges::Record(src,tgt) H1 uses (never silently drops an edge -- capacity only affects how
// OFTEN a miss re-fires, never correctness/recall), then inserts tgt, evicting round-robin/FIFO if
// the set is already full. Orthogonal opt-in: 0 or 1 (default) leaves H1's existing single-slot
// inline fast path (qemit.cpp) completely untouched; >=2 switches QEmit::Emit_gbrind to the K-way
// path (jitabi.cpp's ShadowEdgeKCheckImpl) for shadow-tracked gbrind sites instead. CLI
// --shadow-edges-k=<N>, requires --shadow-edges=1. Clamped to tcache::ShadowEdgeKSlot::kMaxK.
inline unsigned shadow_edges_k = 0;
// A-line round 14 (--shadow-edges2, TRACK 2): fully-INLINE, no-out-of-line-call, fixed 2-slot
// per-source multi-target collector -- see tcache.h's ShadowEdge2Slot comment for the full
// rationale (existing evidence: shadow-majority's inline design measured 7-12% overhead vs.
// shadow-edges-k's out-of-line-call design measuring 41-145% on the same real workloads).
// Independent of shadow_edges/shadow_edges_k (does not require either).
inline bool shadow_edges2 = false;
inline char const *shadow_edges2_out = nullptr;
// A-line Round 48 (--gbrind-hitrate-collect): QCG-tier acquisition gate for the per-source L1
// gbrind-cache hit/miss counter (tcache.h's gbrind_hitrate_cache) -- independent of shadow_edges/
// shadow_edges2 (different question: hit/miss of the existing cache check, not target identity).
// Default off; its own cost must be measured honestly like any other acquisition mechanism.
inline bool gbrind_hitrate_collect = false;
inline char const *gbrind_hitrate_out = nullptr;
// A-line round 15 (TRACK 1): diagnostic-only bypass of the shadow_track exclusion (which skips
// the canonical RETURN idiom, rd=x0/rs1=ra, for source-indexed collectors -- see InstGBrind's
// comment) so --shadow-edges2 can be used as a genuine RETURN-INCLUSIVE dynamic census tool.
// Reuses the already-validated shadow-edges2 mechanism unchanged; only removes the gate. Default
// off so every existing shadow-edges2/multiguard measurement is completely unaffected.
inline bool shadow_edges2_all_jalr = false;
// A-line 2026-07-27 (--temporal-order-collect, Codex 7th audit P1): per-source order-1/order-2
// lag-match collector (tcache.h's temporal_order_cache) -- fully inline, no slowpath forcing, no
// global dispatch cap, covers the WHOLE profiling run (fixes the earlier --sr-bounded-exhaustive
// design's early-window/late-hot bias and its exec_count-accounting interaction bug, since this
// collector never touches profile_brind_edges at all). Independent of shadow_edges2 (that gives
// marginal per-target counts; this gives temporal order), pair the two for a complete site
// statistic. Default off; its own cost is measured the same way as every other collector here.
inline bool temporal_order_collect = false;
inline char const *temporal_order_out = nullptr;
// Mirrors shadow_edges2_all_jalr: the default shadow_track gate excludes the canonical RETURN
// idiom (rd=x0/rs1=ra) -- but this cycle's own real discovery/oracle findings (expat 0001134c/
// 000121cc) are specifically polymorphic RETURN sites (found via --sr-record-returns=1), so this
// collector needs a return-inclusive mode to reproduce them. Default off so non-return-only
// measurements are unaffected.
inline bool temporal_order_all_jalr = false;
// A-line Design 3 (Codex-mandated redesign after H1/H2 both failed end-to-end single-run
// economics, see SHADOW_EDGES_PROGRESS.md): a per-TARGET online Boyer-Moore majority-vote
// counter, piggybacked onto the l1_brind_cache HIT path in Emit_gbrind (qemit.cpp) -- the
// ALREADY-UNCONDITIONALLY-EXECUTED, ALREADY-99.9999%-of-all-dispatches hot path where
// cache_tb_exec_count is already incremented for free. Adds no new hash computation (reuses the
// same offset). Answers exactly what ModuleGraph::ApplyFDRE needs (which single source, if any,
// is this target's strict majority) directly, with NO separate reconstruction pass: correctness
// is the Boyer-Moore/Misra-Gries theorem (a true >50% majority source is ALWAYS the final
// candidate, independent of arrival order or the other sources' distribution) -- not a tuned
// capacity constant. Orthogonal to shadow_edges/shadow_edges_k (does not require them).
inline bool shadow_majority = false;
inline char const *shadow_majority_out = nullptr;
// Round-15 DIA (default-off): if non-empty, elfaot additionally admits exactly the brind-target regions whose entry ip
// is listed in this file (one hex ip per line) -- the island-admission set computed offline from the edge profile.
inline char const *dispatch_admit_list = nullptr;
// A-line 2026-07-27 (fair-budget oracle tooling, measurement-only, default-off): if non-empty,
// elfaot UNCONDITIONALLY refuses admission for any region whose entry ip is listed in this file
// (one hex ip per line), checked BEFORE the threshold test in RegionAdmitted() -- the exact
// complement of dispatch_admit_list. Lets a caller build an arbitrary EXPLICIT admission set
// (force-include via dispatch_admit_list, force-exclude via this) while ComputeRegions()'s own
// topology (region formation/boundaries/CFG) is completely untouched -- unlike
// --threshold=999999999 (which also perturbs SEEDING when combined with aot_freq_gated_seed),
// this never changes dbt::config::threshold, so region formation is unaffected either way.
inline char const *dispatch_deny_list = nullptr;
// 2026-07-25 layout/co-location ceiling oracle (measurement-only, default-off): if non-empty,
// reorders ModuleGraph::ComputeRegions()'s output (llvmaot.cpp LLVMAOTTranslatePage, right after
// the call) to match the EXACT sequence of region-entry ips (one hex ip per line) listed in this
// file, before any codegen/emission loop runs. Regions whose entry ip is NOT listed keep their
// original relative order, stably placed AFTER all listed ones. Changes ONLY the order functions
// are added to the LLVM module (and hence, empirically, their final .text placement) -- code
// CONTENT and per-region size are completely unaffected (region_gsize's own address-sorted copy,
// AOTSymbol content, and all codegen logic are untouched). Lets the SAME compiled bytes be tested
// under different physical orderings (natural Wendell order / dispatch-affinity order / a
// deterministic control permutation) to separate a genuine source-target locality effect from an
// incidental address-alignment shift.
inline char const *aot_region_order_file = nullptr;
// Round-17 BCT (default-off): in-run tier promotion. elfrun starts on QCG with NO artifact; a concurrently-running
// builder (separate process) writes the .aot.so; the brind slowpath cheaply polls for it (rate-limited) and, on
// arrival, forces one escape so the outer Execute loop performs a MID-RUN AOT boot (InsertOrReplace announce). Hot
// dispatch working sets then migrate to AOT through their own brind lookups -- the bounce IS the promotion channel.
inline bool inrun_tier = false;
// R47: print the post-run tier census (QCG_EXEC/AOT_EXEC dynamic mass) on any run, without inrun_tier's
// mid-run promotion behavior. QCG_EXEC mass = dynamic execution that fell into un-admitted QCG = the runtime
// drift/staleness signal (high when the admission profile mismatches the actual input). Default off.
inline bool tier_census = false;
// T4 (2026-08-30): print QCG_CODE_BYTES at exit -- the summed host machine-code size of the QCG code
// this process generated (tcache::CodeBytes). It exists because T4 must report generated-code size
// per measured row in BYTES, and the only pre-existing way to get that number was --dump-tbcode,
// which hex-dumps every block to a file at exit and so charges its I/O to the run's wall clock. This
// is a map walk and three integers, on the exit path only: nothing on any execution path changes,
// no emitted byte changes, and every pinned disassembly golden stays byte-identical. Default off.
inline bool qcg_code_bytes = false;
// R47 closed-loop: when set, UpdateProfile MAX-merges (accumulates) this run's exec_count into the persistent
// profile instead of overwriting. Needed for AOT-run profile updates: AOT-admitted regions may report 0 exec
// (native code doesn't self-count) -> overwrite would drop them; MAX keeps old admitted counts AND adds the
// newly hot-in-QCG (drifted) regions -> grow-only convergent UNION working set across the input stream.
inline bool aot_profile_merge = false;
inline bool inrun_booted = false;
inline ServiceFlag inrun_boot_pending{kSvcInrunBootPending};
inline ServiceFlag inrun_poll_due{kSvcInrunPoll};
// Round-23: deployment-form W_max sampler -- ONE counter increment per brind slowpath visit; a 50ms
// SIGALRM samples the counter and re-poisons the dirty list (deployment-like channel conditions).
// Replaces the heavy edge-multigraph instrument for admission purposes (that one disables the l1
// cache entirely and pays clock+stamp per transfer; kept for research only).
inline bool wmax_sample = false;
inline volatile unsigned long long wmax_visit_count = 0;
inline volatile unsigned long inrun_flush_count = 0; // diagnostics: SIGALRM handler invocations
inline char const *inrun_artifact_path = nullptr;
inline unsigned long inrun_relinked = 0;
// C5d: inline-cache blobs returned to the never-matching sentinel by a mid-run promotion. Counted
// separately from `inrun_relinked` because the two answer different questions -- "how many direct
// edges were migrated" and "how many indirect sites had a stale direct jump revoked" -- and a single
// total would hide a workload in which one of them is the whole effect.
inline unsigned long inrun_ic_unpatched = 0;
inline long inrun_boot_ms = -1; // wall offset (ms since elfrun start) when the mid-run boot fired
inline long inrun_start_ms = 0;
// Round-40 single-core interleaved tiering: a SEQUENCE of armed artifacts (e.g. small-hot then full,
// or per-shard chunks). The poll channel boots seq[idx] when present, advances idx, and only latches
// inrun_booted after the LAST entry -- so the channel stays open across multiple mid-run swaps.
// Length-1 == the legacy single-artifact behavior exactly (back-compat). Default-off (n==0).
inline constexpr int kInrunSeqMax = 16;
inline char const *inrun_seq_paths[kInrunSeqMax] = {};
inline long inrun_seq_boot_ms[kInrunSeqMax] = {}; // per-swap wall offset (mechanism evidence)
inline int inrun_seq_n = 0;
inline int inrun_seq_idx = 0;
inline int inrun_flush_ms = 50;
// 2026-07-05 in-process closed-loop escalation (B-line): after the FIRST staged artifact (chunk) boots,
// evaluate the v2 majority sign test IN-PROCESS on the census DELTA since the swap (post-chunk execution
// only) and, if QCG is still the majority tier, fork+execv a background full-artifact build; the existing
// seq poll channel then swaps it in. Whole decision loop lives in ONE process. Default-off.
inline bool inrun_auto_escalate = false;
inline ServiceFlag inrun_escalate_due{kSvcInrunEscalate}; // set by SIGALRM tick; consumed on host stack
// T5c-0 LIFECYCLE PLUMBING (default off): keeper-armed direct-link escape. The tier's evaluator and
// its artifact boot are consumed only in the Execute() loop, and JIT'd code returns there only via
// the indirect-branch slowpath. A pure-compute leaf loop executes no indirect branch, so the keeper's
// existing brind-cache flush has nothing to force a miss on and the tier degenerates to QCG no matter
// how long the run is. With this on, the keeper also returns a bounded number of recently linked
// DIRECT branch slots to the lazy-JIT stub, so the next traversal reaches the existing call site.
// It changes no admission bar, evidence gate, threshold, region choice or cadence.
inline bool inrun_escape_unlink = false;
inline unsigned long esc_unlink_ticks = 0; // keeper ticks that unlinked at least one slot
inline unsigned long esc_unlink_slots = 0; // slots returned to the lazy stub, total
// -----------------------------------------------------------------------------------------------
// T5d-0 BACKEDGE SAFEPOINT (--qcg-backedge-safepoint, default off).
//
// THE PROBLEM. A QCG direct branch is a `BranchSlot`: a call into the lazy-link stub that, on its
// first traversal, self-patches into a `jmp rel32` straight at the target's host code. From then
// on the edge never re-enters Execute(), which is the only place the runtime services the requests
// above. A long pure-compute loop whose backedge is a direct branch therefore stops asking for
// service entirely, no matter how long it runs.
//
// WHAT THIS IS. On a direct guest edge that goes BACKWARD (`InstGBr::backedge`, decided in the
// translator from the branch instruction's own address and its architectural target -- see
// rv32_qir.cpp's IsDirectBackwardEdge), QEmit::Emit_gbr emits, ahead of the slot, a test of
// `service_request` and a jump to the SAME `escape_link` stub the lazy-link path's not-found case
// already uses. It stores this edge's target guest PC into CPUState::ip and hands Execute() this
// edge's own BranchSlot, so the loop resumes at exactly the target the guest branch named.
//
// WHAT IT IS NOT. It is not an admission policy, a hotness signal, a region choice or a promotion
// point. It answers exactly one question -- "does the runtime want control back?" -- from state
// the runtime already maintains, and it never decides what should be compiled. It scans nothing,
// rewrites no linked slot, and shares no state with --inrun-escape-unlink.
inline bool qcg_backedge_safepoint = false;
// Emission-side: how many gbr sites got a safepoint, and how many JIT-mode direct gbr sites the
// same run emitted, so "the safepoint is on the backedges and only the backedges" is a measured
// ratio rather than a claim about the source. BOTH are counted only while the flag is on -- an off
// run does not move them, does not print them, and is not the source of anyone's denominator.
inline unsigned long long backedge_safepoint_sites = 0;
inline unsigned long long backedge_safepoint_gbr_total = 0;
// Runtime-side: incremented by the EMITTED code, on the taken path only. The fall-through path
// costs a load, a compare and a not-taken branch and touches nothing else.
inline unsigned long long backedge_safepoint_escapes = 0;
// Where those escapes resumed, per guest PC. "The loop came back to the runtime" is only evidence
// if it can be shown to have come back from INSIDE the timed region, and a single total cannot say
// that. This is filled on the HOST STACK, in Execute()'s loop, by noticing that the emitted
// counter moved since the previous iteration -- so the emitted code stays one `inc`, the map walk
// stays where map walks are allowed, and an off run pays nothing. Exactly one escape can occur
// between two iterations of that loop, because an escape IS a return to it.
inline unsigned long long backedge_safepoint_escapes_seen = 0;
inline std::unordered_map<uint32_t, unsigned long long> backedge_safepoint_ips;
inline bool inrun_escalated = false;             // one-shot latch
inline bool inrun_census0_taken = false;
inline unsigned long inrun_census0[4] = {};      // census snapshot at first-artifact boot
inline char const *escalate_elfaot = nullptr;    // builder binary
inline char const *escalate_cache = nullptr;     // staging dir pre-populated with w.elf (+ .prof)
inline char const *escalate_elf = nullptr;       // guest elf path inside staging dir
inline long inrun_escalate_fire_ms = -1;         // wall offset when the fork fired (mechanism evidence)
inline int inrun_builder_pid = 0;                // forked builder pgid; killed at exit (spend<=rent bound)
// 2026-07-07 TIME-census: the entry census counts TB entries, not cycles -- a chunk can absorb the entry
// majority while QCG still burns the time majority (the mediocre-keep boundary). When enabled, the escalate
// decision uses SIGPROF time samples classified into AOT-.so vs QCG-code-pool ranges: same majority sign
// test, evidence = time. Zero constants. Default-off (A/B comparable).
inline bool escalate_time_census = false;
inline volatile unsigned long esc_qcg_samples = 0, esc_aot_samples = 0;
inline volatile unsigned long long esc_aot_lo = 0, esc_aot_hi = 0;   // AOT artifact code range (from boot)
inline volatile unsigned long long esc_qcg_lo = 0, esc_qcg_hi = 0;   // QCG code pool range
inline unsigned long esc_census0_q = 0, esc_census0_a = 0;           // sample snapshot at first eval
// quality proxy: pre-swap QCG time-per-entry baseline (samples & entries snapshotted at chunk boot)
inline unsigned long esc_pre_q_samples = 0;
inline unsigned long long esc_pre_q_entries = 0;
inline bool escalate_quality_proxy = false; // apply the rate sign test to the decision (else print-only)
// 2026-07-14 TRUE SINGLE-RUN: no run-1. The run's OWN objprof (updated mid-run on the host stack) feeds the
// first selective build; the existing census loop then decides the full rung. Zero-constant additions: the
// first build fires at the first evaluation tick (its cost is already covered by the kill-on-exit bound);
// the chunk threshold is Wendell's own default (the baseline's knob, not ours).
inline bool inrun_single_run = false;
// 2026-08-17 CAUSAL CONTROL (default-off, --inrun-observe-only): enter the ENTIRE single-run
// observation/evaluator path -- ticks, brind flushes, mid-run UpdateProfile, poll attempts -- but
// make artifact production IMPOSSIBLE by refusing to spawn any builder, and say so explicitly in
// the event stream. This isolates "what does the single-run observation machinery itself do to
// elapsed time" from "what does executing AOT code do". It is a control arm, never a method.
inline bool inrun_observe_only = false;
inline bool sr_first_fired = false;
// T3b: gate the single-run first fire on RUNTIME EXECUTION EVIDENCE instead of on the first
// evaluator tick. Default OFF, so every accepted arm keeps its exact behaviour. When on, the fire
// waits until the run's own profile shows some region whose exec_count has reached
// sr_chunk_threshold -- the same number handed to the child elfaot as `--threshold`, i.e. the
// compiler's own admission bar, not a new constant. See dbt/aot/aot_boot.cpp.
inline bool inrun_evidence_gate = false;
inline unsigned long long inrun_evidence_hottest = 0;
inline unsigned long inrun_evidence_polls = 0;
inline long sr_chunk_threshold = 262144;   // Wendell default (documented baseline knob)
inline char const *escalate_run_cache = nullptr; // the run's own cache dir (live .prof source)
// re-arm: a KEEP/ESC decision made on an early profile goes STALE if the working set keeps growing. Zero
// constants: re-arm the evaluator ONCE when more profile pages appeared SINCE the decision than existed AT
// the decision (growth majority = the profile the decision saw is now the minority of what is known).
inline unsigned long esc_pages_at_decision = 0;
inline bool esc_rearmed = false;            // kept for stats; re-opens now UNLIMITED under the no-rebuild invariant
inline unsigned long esc_reopen_count = 0;
// TERMINATION INVARIANT (zero constants): a re-open may fire a BUILD only if the profile has grown since the
// last build (grow-only profile => every build strictly more informed => #builds <= #growth-events, finite;
// oscillation without growth costs no compile). Ski gate for the FULL rung: price is ONLINE-calibrated from
// the run's own first build (wall x profile-growth ratio); fire only when elapsed >= price (bounded regret
// for unknown remaining run; saves the compile entirely when the run ends first -- the xerces class).
inline unsigned long esc_pages_at_last_build = 0;
inline long esc_first_fire_ms = -1;
inline long esc_first_land_ms = -1;         // seq[0] boot time (price calibration: land - fire = build wall)
inline unsigned long esc_pages_at_first_fire = 0;
inline bool esc_full_ski_gate = false;      // --escalate-ski-full
inline bool sr_descent = true;              // ablation: geometric descent (off = single build at T0)
inline bool sr_census = true;               // ablation: decision layer (off = descent-only)
inline bool escalate_contradiction = true;  // ablation: contradiction monitor (off = decide-once)
// dual-channel observation: SIGPROF RIP ring (MAP_SHARED file in staging; async-safe plain stores). The
// builder resolves RIPs via the tbmap (translation-time data: complete for ALL translated code regardless
// of execution style) -> sample-mass admission UNION count admission (complementary blind spots).
inline constexpr unsigned long kRipRingSlots = 1ul << 20; // 8MB; 1ms sampling never wraps a normal run
inline volatile unsigned long long *esc_rip_ring = nullptr;
inline volatile unsigned long esc_rip_head = 0;
inline unsigned long esc_prev_boot_q = 0, esc_prev_boot_a = 0;   // realized-benefit window anchors
inline unsigned long esc_pre_share_num = 0, esc_pre_share_den = 0;
inline bool esc_benefit_pending = false;
inline bool sr_sampled_edges = false;            // --sr-sampled-edges: one edge per SIGPROF sample (adaptive rate)
inline bool sr_edges_all_misses = false;         // --sr-edges-all-misses: record EVERY natural L1-miss slowpath visit
                                                 // (no decimation); natural-miss counts are tiny (see jitabi.cpp)
// --sr-edges-epochs: geometric-epoch edge-set resampling. The target-keyed L1 absorbs every
// (other_source -> already-cached target) edge after first touch, so the raw natural-miss SET is
// incomplete (poly-B witness: 4 shared targets appeared exclusive to one source). Flushing the
// brind L1 at the sweep's doubling-backoff eval ticks re-opens one observation window per epoch;
// an edge with non-vanishing arrival share p is missed after k epochs with prob (1-p)^k, so the
// observed set converges in log-many epochs at O(log) flush cost. Counts stay miss-counts --
// this provides the SET, not weights.
inline bool sr_edges_epochs = false;
// dry-stop (structural stopping condition, loop-until-dry with the minimal k=2 that separates
// "converged" from "one unlucky window"): after 2 consecutive epochs discovering NO new distinct
// edge, stop flushing. Residual false-negative bound is probabilistic and honest: an edge whose
// per-epoch observation probability is p survives k discovering epochs w.p. (1-p)^k -- vanishing
// shares can be missed, which is the same class of miss Wendell's threshold admission makes.
inline volatile unsigned long epochs_last_edge_count = 0;
inline volatile unsigned epochs_dry = 0;
inline volatile bool epochs_done = false;
inline unsigned long epochs_flushes = 0; // audit: flush events actually performed
// A-line 9th cycle (--sr-web-repack): SAME-RUN dispatch-web co-location. Measured pool: the hot
// wasm3 dispatch web (58 TBs) is scattered over 259KB of a 268KB code pool (median gap 472B,
// 6/57 line-adjacent) = 8x L1i span. When the epoch edge SET first goes dry (event-driven, no new
// constant), revoke every web member (sources+targets of observed indirect edges); the hot web
// re-arrives immediately and burst-retranslates into CONSECUTIVE fresh pool space -- adjacency by
// construction. Counts/flags carried via the sat_carry mechanism; no edges => never fires.
inline bool sr_web_repack = false;
// M-INL (--qcg-leaf-inline): direct-call leaf-return elision at translation (see rv32_qir.cpp)
inline bool qcg_leaf_inline = false;
// 2026-07-28 A-line (--qcg-jal-closure, default off, elfrun-only -- elfaot never sets this, so AOT
// translation is byte-identical regardless): RV32Translator::TranslateIPRange stops the current QCG
// compile job at EVERY branch-class instruction, including plain `jal` (rd=0, unconditional,
// statically-known target) -- a real fixed-per-job cost is paid (measured ~25.2us/job, dominating
// over the ~4.6ns/insn variable cost for the median 3-instruction job) even though jal's successor
// needs no runtime resolution at all. When on, V_jal continues translating AT THE TARGET within the
// SAME job/Block instead of stopping, IF: the target is still within the current job's existing
// page-bounded `boundary_ip` (reuses TranslateIPRange's own already-enforced page-granularity
// safety check -- unlike --qcg-leaf-inline, which crosses page boundaries without invalidation
// tracking and is explicitly marked oracle-only for that reason, this never exceeds the SAME
// invalidation granularity already in effect for a single-page job), the target has no existing
// TBlock yet (avoid duplicating already-compiled work), and the target has not already been visited
// in THIS job (cycle safety, e.g. `jal` back to an earlier point). Falls back to the unchanged
// MakeGBr+stop path whenever any condition fails -- never a correctness risk, only a missed
// optimization opportunity in that case.
inline bool qcg_jal_closure = false;
inline unsigned long qcg_jal_closure_fires = 0;
inline unsigned long qcg_leaf_inline_fires = 0;
// M-IC-LT (--qcg-ic-lasttarget): IC repatches to the LAST observed target instead of first-wins
inline bool qcg_ic_lasttarget = false;
// 12:14 item A: include RETURN edges in the exhaustive recorder (one-shot observation runs)
inline bool sr_record_returns = false;
inline ServiceFlag web_repack_due{kSvcWebRepack};
inline bool web_repacked = false;
inline unsigned long web_repack_n = 0; // diagnostic: members revoked
inline volatile bool edge_capture_due = false;
inline unsigned long esc_last_promo_window = 0;
inline unsigned long esc_rate_anchor = 0;      // samples at last rate halving
inline long esc_sample_us = 0;              // SIGPROF period; 0 = init to keeper tick at arm time (coarse start)
inline bool esc_anchor_sign = true;
// B-line round 7 (2026-07-22) diagnostic: log every coarsen/refine transition of the EXISTING
// (not GRIC) verdict-stability sampling-rate controller with a wall-clock timestamp, to check
// whether a long stable phase coarsening esc_sample_us all the way to its cap causes a measurable
// real detection-lag when a genuine phase change follows. Read-only; no behavior change when off.
inline bool sr_log_ratecontrol = false;
inline bool sr_ablate_realized = false;         // B-line ablation: disable the realized-benefit loop
inline bool sr_ablate_promote = false;          // B-line ablation: disable promote-evidence-doubling
inline bool sr_ablate_updprof = false;          // B-line ablation: skip per-tick UpdateProfile+dumps (attribution probe)             // census majority sign at last rate change (verdict-stability control)               // current SIGPROF period (self-adapting: doubles per evidence doubling) // promote-evidence-doubling: samples in the window that justified the last promotion
inline bool sr_ablate_regime_reset_parent = false;  // B-line reset-necessity ablation: skip the parent-side esc_last_promo_window reset on regime flip
inline bool sr_ablate_regime_reset_builder = false;
inline bool sr_realized_pend_check = false;    // R6' leela-race fix: no-gain idle consults builder pending mass ($STG/pend); gain un-idles // B-line reset-necessity ablation: skip writing $STG/regime (suppresses the builder-side DRY-head + built_mass reset)
inline unsigned esc_zero_share_swaps = 0;       // consecutive landed swaps with ZERO realized AOT share
inline volatile unsigned long esc_eval_count = 0;       // evaluator runs (starvation detector input)
inline unsigned long brind_slowpath_visits = 0; // steady-state L1 dispatch-cache miss diagnostic (one inc on the already-slow path)
// A-line 2026-07-23 (--qcg-dispatch-ic): self-patching per-site dispatch inline cache at the QCG
// tier. First natural slowpath miss of a site patches a guarded direct jump (first-wins mono IC);
// no profile pass, no thresholds -- the observation and its consumption are the same slowpath visit.
inline bool qcg_dispatch_ic = false;
// PM round-10 attribution instrumentation (--qcg-dispatch-ic-site, default 0/disabled): restricts
// qcg_dispatch_ic's blob emission to ONE guest TB entry IP (matched against _entry_ip), so a
// per-site causal effect can be isolated instead of the whole-program aggregate. 0 = apply to every
// site (unchanged default behavior), matching --qcg-dispatch-ic's existing semantics exactly.
inline unsigned qcg_dispatch_ic_site = 0;
// PM round-10 P3: online, same-run, no-oracle self-verifying guard. Tracks each patched site's own
// (hit, miss) counts (hit = blob's guarded compare matched; miss = this exact slowpath was reached
// AGAIN for a site whose blob is ALREADY patched, i.e. its current committed guess just failed) in
// a dedicated per-site cache (tcache::qcg_ic_regret_cache), keyed the SAME way as the existing
// gbrind_hitrate_cache. The instant a site's cumulative miss count exceeds its cumulative hit count
// (a symmetric, zero-tuned-parameter break-even: the guard can only be a net loss once wrong
// guesses outnumber right ones, given both a hit and a miss pay approximately the same one
// extra-compare fixed cost whenever the guard's own presence is the only difference from the
// unguarded baseline), the site's blob is permanently reverted to the never-matching sentinel
// (dbt::tcache::ICUnpatchTarget's own technique, applied by direct site blob address here) -- the
// SAME safe fallback path every guard mechanism in this codebase already uses. Implies
// qcg_dispatch_ic; default off.
inline bool qcg_ic_regret = false;
inline unsigned long qcg_ic_regret_reverted = 0; // diagnostic: sites permanently reverted this run
// B-DIST probe (--qcg-ic-edge-count, implies qcg_dispatch_ic): IC hit counters become exact
// per-(site,target) edge weights for each site's RESIDENT (first-wins) edge; slowpath misses are
// counted by the edge recorder. PROBE ONLY: exec-count attribution on IC hits is diverted.
inline bool qcg_ic_edge_count = false;
inline char const *qcg_ic_edges_out = nullptr;
inline unsigned long long qcg_ic_dummy_count = 0; // unpatched/freq-off blobs inc this scratch slot
inline unsigned long qcg_ic_patched = 0;          // diagnostic: number of sites patched
// One-slot pending patch across the escape->translate hop: the dominant natural-miss case is an
// UNTRANSLATED target (the site's very first dispatch to it), where the slowpath must escape to
// the execute loop before a code pointer exists. Single-threaded guest: the very next translated
// TB is that target (checked via pending_gip), so the pair (site retaddr, target) is exact.
inline unsigned long qcg_ic_pending_ra = 0;
inline unsigned int qcg_ic_pending_gip = 0;
// A-line 2026-07-23 (--qcg-freq-sat): SATURATING frequency collection. Every d312b122 consumer of
// dynamic counts is boolean (aot.cpp:33 executed>0), threshold (llvmaot.cpp:75), max-then-threshold
// (llvmaot.cpp getMaxExecCountInRegion), or a monotone nonneg sliding sum vs threshold (Wendell's
// propagate_exec_count, rv32_analyser.cpp:36-58). THEOREM: capping every counter at T preserves all
// of these decisions exactly -- if every component < T the sum is exact; if any component >= T its
// cap alone contributes T. So counting beyond T is decision-irrelevant, and the collection can skip
// the RMW once saturated. T must equal the elfaot --threshold of the same pipeline (Wendell's own
// admission constant, not a new tuning knob).
inline bool qcg_freq_sat = false;
inline unsigned long long qcg_freq_sat_t = 262144;
// A-line 2026-07-23 (--qcg-freq-edge): PER-EDGE inline counters. Emit_Cache knows its (site,
// target) edge statically at translation; instead of the 7-insn shared-hash chain (2 dependent
// loads + collision guard + RMW, with silent collision UNDERCOUNT), emit ONE RIP-relative
// `inc qword [slot]` to a slot embedded after the TB's code. Slots fold into per-TB counts at
// objprof::UpdateProfile (the single choke point every .prof write passes through). Counts become
// exact-or-better than Wendell's (collision loss eliminated); edge-level direct/conditional
// counts become available as a byproduct. Indirect (gbrind) path unchanged (dynamic targets).
inline bool qcg_freq_edge = false;
// A-line 2026-07-23 (--qcg-freq-retire): SELF-RETIRING counters (SAT-1b). Once a TB's counter
// reaches T, every Emit_Cache counting sequence targeting it is patched to a jmp over itself
// (loads + RMW + most icache gone), from a periodic host-stack sweep (timer flag -> brind-cache
// flush -> slowpath escape -> sweep&patch; never from signal context, and never while guest RIP
// can sit inside a counting sequence). Decision equivalence: frozen values are >= T, and every
// d312b122 consumer is boolean/threshold/max/monotone-sum vs T (see the saturation theorem
// above). Programs that never saturate execute byte-identical stock code -- zero overhead.
// The sweep period only bounds detection latency of an optimization, never a decision input.
inline bool qcg_freq_retire = false;
// A-line 2026-07-23 (--qcg-freq-entry): ENTRY-SIDE ARRIVAL COUNTERS (v3). Stock counts per EDGE
// at the source (Emit_Cache ~30B per direct edge) plus per brind site (2 insns) plus the execute
// loop (+1) -- all three channels ARRIVE at the target TB's entry in per-TB QCG, so ONE 13-byte
// counter at the TB entry measures the same per-TB total, with hash-collision undercount
// eliminated (exact-or-better than Wendell). Slots live in the data arena and fold into
// tb->flags.exec_count at UpdateProfile. With --qcg-freq-retire, a TB whose count saturates is
// retranslated WITHOUT its entry counter (count carried over) -- compact hot code, frozen >= T.
inline bool qcg_freq_entry = false;
// A-line 2026-07-23 (--qcg-freq-shadow-out=path): SAME-RUN shadow-equivalence probe. Keeps stock
// Wendell counting fully active AND adds an independent entry-arrival shadow counter per TB;
// at exit dumps per-TB "ip stock entry delta brind seg" so channel-level divergences are
// observable within ONE execution (no cross-run comparison). Diagnostic only.
inline char const *qcg_freq_shadow_out = nullptr;
inline ServiceFlag sat_sweep_due{kSvcSatSweep};
inline unsigned long sat_retired_sites = 0; // diagnostic
inline unsigned long sat_sweeps = 0;        // diagnostic
inline volatile bool sat_all_retired = false; // stop tick-flushes once nothing is left to retire
// exponential backoff on sweep evaluation (standard doubling, no tuned constant): a sweep that
// retires nothing doubles the wait; any retirement or new site registration resets it. Bounds the
// long-run flush/poison cost to O(log) events instead of one per tick for the whole run.
inline volatile unsigned long sat_tick = 0;          // ticks seen
inline volatile unsigned long sat_next_eval_tick = 0; // next tick allowed to request a sweep
inline unsigned long sat_backoff = 1;                 // doubling state (sweep-side)
// WITNESS ONLY (--qcg-freq-scratch): replace Emit_Cache's 7-insn hash-chain counting with a single
// `inc [scratch]` to decompose the counting pool (dependent loads vs the RMW itself). Produces a
// WRONG .prof (all counts land in one slot) -- never a method flag, timing witness only.
inline bool qcg_freq_scratch = false;
inline unsigned long long qcg_freq_scratch_slot = 0;
inline unsigned long esc_ms_firstfire = 0;      // pre-NONE trace: SR first-fire block (UpdateProfile+fork)
inline unsigned long esc_us_eval = 0;           // pre-NONE trace: cumulative evaluator time (us)
inline unsigned long esc_us_eval_cpu = 0;       // V151 diagnostic (2026-07-20): same window, CLOCK_THREAD_CPUTIME_ID
                                                 // instead of CLOCK_MONOTONIC -- separates true scan cost from OS
                                                 // scheduling delay landing inside EvalTimer's wall-clock window
                                                 // (see EVALUS_WALLCLOCK_CONTENTION_CONFOUND.md). Diagnostic-only,
                                                 // never read by any decision logic.
inline unsigned long esc_us_acks = 0;           // pre-NONE trace: cumulative wantprof ack work (us)
inline unsigned long esc_n_acks = 0;            // pre-NONE trace: ack count
inline bool esc_last_keep = false; // (superseded by evidence-gated promotion; kept for stats)
inline unsigned long esc_boot_q = 0, esc_boot_a = 0; // sample snapshot at last swap (promotion gate window)
inline bool sr_census_flip_check = false;      // R7'': starvation-proof flip detection via exec-count census (sampler-independent)
// B-line round 10 (2026-07-22): oracle arm + per-action ablation fire counts. sr_oracle_flip_at_ms>0
// fires the SAME CensusFlipWalk actions once, at a precomputed wall-clock instant, bypassing
// doubling-paced detection entirely -- an upper bound for "same action, perfect-information timing",
// not a new/different mechanism. Fire counters are read-only diagnostics, default zero, no behavior
// change from reading them.
inline long long sr_oracle_flip_at_ms = 0;
inline bool esc_oracle_fired = false;
inline unsigned long esc_cf_action_override_fires = 0;
inline unsigned long esc_cf_action_regime_fires = 0;
inline unsigned long esc_cf_action_wake_fires = 0;
inline char const *brind_edges_out_path = nullptr; // persistent copy of --brind-edges-out for sr_live_edges_dump's
                                                     // periodic mid-run Dump() call (the exit-time Dump() already
                                                     // has its own local opts.brind_edges_out; this is the SAME path,
                                                     // just also readable from execute.cpp's host-stack loop).
inline bool sr_live_edges_dump = false;        // B-line (2026-07-22): brindedges::Dump() otherwise fires ONLY at
                                                // elfrun process exit, so a controller watching $STG/edges.txt during
                                                // a live single-run session never sees ANY evidence until the guest
                                                // has already finished -- structurally impossible to react mid-run.
                                                // This flag additionally calls Dump() from the SAME already-existing,
                                                // already-periodic EvaluateAndMaybeEscalate() host-stack call site
                                                // (execute.cpp), so it adds no new timer/signal-safety surface: file
                                                // I/O is safe there (not signal context), same discipline the
                                                // existing wantprof-driven .prof refresh already uses. Writes to
                                                // config::brind_edges_out (must also be set via --brind-edges-out).
inline bool sr_unconditional_poll = false;     // V151 diag fix: the boot-pending promotion channel (inrun_poll_due
                                                // -> dbt_inrun_artifact_present) is otherwise consumed ONLY at the
                                                // brind slowpath (qcgstub_brind); workloads whose hot code, once
                                                // compiled, generates near-zero indirect-branch slowpath traffic
                                                // (e.g. mcf) can starve this channel forever despite the builder
                                                // continuing to produce valid, unbooted artifacts. Adds the SAME
                                                // conditional check to the main Execute loop (gated by the existing
                                                // inrun_poll_due flag, so cost stays ~1 access() call per ~50ms tick,
                                                // not per instruction).
// B-line B2 (2026-07-22): real revoke channel. A controller running OUTSIDE this process (sr_builder.sh's
// GRIC state machine) writes a single hex gip line to revoke_request_path when it decides a previously
// COMMITTED target must be undone (RECOMMIT). The live guest process polls this file from the SAME
// already-periodic EvaluateAndMaybeEscalate() host-stack call site used by sr_live_edges_dump (file I/O
// safe there, not signal context) and applies tcache::RevokeTarget() -- a genuine in-run action, not just
// "stop admitting this target in future builds."
inline bool inrun_revoke_watch = false;
inline char const *revoke_request_path = nullptr;
inline unsigned long long esc_revoke_applied = 0; // count of RevokeTarget() calls actually applied this run

// P1 (2026-07-23, Workflow B prototype, default-off): IN-RUN INDIRECT-TARGET PROMOTION
// (self-healing exile), built ON the BCT substrate (FlushBrindCache bounce channel,
// BootOneArtifact/InsertOrReplace/RelinkTo mid-run swap, slowpath escape discipline). The
// defect: in an --aot run an indirect target NOT admitted to the loaded artifact is
// JIT-translated to counting-free QCG (DC-1: Emit_Cache/gbrind counting gated off by use_aot)
// and pinned into l1_brind_cache forever (DC-2) -- the exiled span runs QCG-tier for the whole
// invocation (expat: +26.4% wall). LEDGER (distinct from the killed same-core BCT-from-cold
// verdict, V151): the baseline here is a FROZEN stale artifact that never recompiles; P1 pays
// one NEW mid-run compile (wall fully counted, serial, one core) to recover the exiled span's
// steady-state QCG-vs-AOT gap for the run's remainder. Mechanism with --p1-promote:
//  1. DC-1 undo, flag-scoped: QCG translations in the aot run DO emit exec counting (qemit.cpp
//     gates), so exiled TBs accumulate real frequency evidence (chicken-and-egg fix: you
//     cannot compile b's regions without b's counts);
//  2. a keeper SIGALRM tick flushes the brind L1 (Round-25 dirty list) so dispatch keeps
//     bouncing through the slowpath = the escape channel for host-stack work;
//  3. a doubling-backoff host-stack scan counts exiled-hot TBs (QCG tcode.size!=0 &&
//     exec_count >= p1_threshold, Wendell's own admission constant -- the promotion bar is the
//     baseline's own bar, not a new knob); when the crossed set is nonempty and DRY for 2
//     consecutive scans (epochs_dry idiom), fire ONCE;
//  4. fire (host stack, SYNCHRONOUS -- guest paused, compile wall counted in-run):
//     aot_profile_merge=true grow-only objprof::UpdateProfile() (a-counts preserved by MAX,
//     b-counts added), cp *.prof to the staging dir (elfrun holds an exclusive flock on the
//     run cache's .prof), run elfaot --llvm=1 --threshold=p1_threshold to produce the
//     b-inclusive artifact, then boot it immediately via the BCT BootOneArtifact
//     (InsertOrReplace + CacheBrind l1 swap + RelinkTo; stale QCG copies stay valid).
// Guest output unaffected; all new state per-run. See
// experiments/2026-07-23-0449-obs-freq-recompute-indirect-asymmetry/FEASIBILITY_P1.md.
inline bool p1_promote = false;              // --p1-promote (pair with --aot=1)
inline char const *p1_staging = nullptr;     // --p1-staging: builder workspace dir (REQUIRED to fire)
inline char const *p1_elf = nullptr;         // --p1-elf: guest elf path for the builder
inline char const *p1_elfaot = nullptr;      // --p1-elfaot: elfaot binary path
inline char const *p1_run_cache = nullptr;   // this run's cache dir (live .prof source for the cp)
inline int p1_flush_ms = 50;                 // --p1-flush-ms keeper cadence (inrun_flush_ms default)
inline unsigned long long p1_threshold = 262144; // --p1-threshold: MUST equal the elfaot --threshold of
                                             // this pipeline (Wendell's own admission constant; same
                                             // contract as qcg_freq_sat_t / sr_chunk_threshold)
inline ServiceFlag p1_scan_due{kSvcP1Scan};  // set by tick; slowpath escapes; host stack scans
inline bool p1_fired = false;                // one-shot build latch (prototype: one build per run)
inline bool p1_booted = false;               // promotion applied; keeper stops flushing
inline unsigned long p1_scans = 0;           // diagnostic: host-stack scans performed
inline unsigned long p1_crossed = 0;         // last scan: exiled TBs with count >= p1_threshold
inline unsigned long p1_crossed_at_fire = 0; // candidate count that justified the fire
inline unsigned long p1_boots = 0;           // artifacts booted (0 or 1 in the prototype)
inline long p1_fire_ms = -1, p1_land_ms = -1; // fire/boot wall offsets; land-fire = measured
                                             // compile+boot cost (the B numerator, printed)
inline long p1_start_ms = 0;                 // process start (CLOCK_MONOTONIC ms)

inline unsigned long long esc_boot_census_q = 0, esc_boot_census_a = 0; // exec-count census snapshot at last swap
inline unsigned long esc_census_walk_last_us = 0, esc_census_walk_gap_us = 0; // doubling-paced walk cadence
inline unsigned long esc_census_walk2_last_us = 0, esc_census_walk2_gap_us = 0; // R7''-7: evaluator-site pacing (separate state -- shared state let steady evaluator walks inflate the gap and systematically delay slowpath-burst flip detection)
// V151 ablation (2026-07-20, eval_us blowup investigation): CensusFlipWalk's post-reset gap floor is
// hardcoded to 1us, guaranteeing the tick immediately after any boot-triggered reset also does a real
// O(tcache_map) scan; if boots recur frequently the gap never escapes this floor and every 50ms tick
// pays the full scan cost (source-confirmed root cause of the eval_us variance this cycle,
// EVAL_US_EXPLAINS_MOST_VARIANCE.md). Default 1 = exactly current behavior, byte-identical when unset.
inline unsigned long sr_cf_reset_gap_us = 1;
// Diagnostic (2026-07-20, phase_keep flips=0 investigation): does CensusFlipWalk ever get CALLED at all
// post-boot, and what did it last see? Always-on (cheap: a few integer increments/copies), not gated
// behind any flag -- this is a read-only counter, no behavior change.
inline unsigned long esc_census_walk_calls = 0;   // total CensusFlipWalk invocations that passed the pacing gate
inline unsigned long esc_census_walk_calls_postboot = 0; // of those, how many happened after the LAST boot
inline unsigned long long esc_last_dq_c = 0, esc_last_da_c = 0; // dq_c/da_c as of the last evaluated walk
inline bool esc_census_override = false;       // R7''-sticky: census QCG-majority latch (persists across calls until boot or counter-walk)
inline bool sr_cf_no_override = false;   // ABLATION: disable the promotion override (latch still tracked)
inline bool sr_cf_no_regime = false;     // ABLATION: disable the regime write (builder anchors keep old baselines)
inline bool sr_cf_no_wake = false;       // ABLATION: disable the builder want=1 wake
inline bool sr_cf_no_reboot = false;     // ABLATION: disable channel-stay-open + top-slot re-boot polling
inline bool sr_cf_once = false;          // ABLATION: fire flip actions once per latch episode (round-3 semantics)
inline int  sr_cf_site = 0;              // ABLATION: 0=both walk sites, 1=slowpath-only, 2=keeper-only
inline long sr_gate_ms = 0; // measured feasibility floor sum (per-machine input, e.g. GATE_DERIVATION 1200ms); 0=off // channel-keeper cadence (sensitivity-swept via --inrun-flush-ms) // v2: direct-link slots re-pointed at promotion (mechanism evidence) // explicit artifact path (staging dir; avoids cache-lock collision) // set by the SIGALRM flush handler; consumed by the brind slowpath
// 2026-06-16 low-N method search: decompose single-run QCG time into JIT-translation vs execution. When on, the
// Execute loop times each CompilerDoJob (one per distinct TB miss). g_translate_ns / g_translate_count = total
// translation cost + #TBs translated. Combined with --dump-tbmap (per-TB exec_count + host code size) this gives
// the cold-translation fraction (how much translation is spent on run-once / few-times TBs). Default-off.
inline bool measure_translation = false;
inline unsigned long long g_translate_ns = 0;
inline unsigned long long g_translate_count = 0;
// 2026-06-17 per-phase decomposition of the QCG backend (GenerateCode): instruction-selection (QSelPass),
// register-allocation (QRegAllocPass), and codegen+encode (QEmit). Gated by measure_translation. Default-off.
// 2026-07-28 A-line P0 (default off, pairs with measure_translation): dump every JIT-translated
// target's guest ip to this path, one per line -- direct set-correspondence proof for which real
// addresses account for TRANSLATE_COUNT, not just the aggregate number. CLI --translate-ip-out.
inline char const *translate_ip_out = nullptr;
inline unsigned long long g_qsel_ns = 0;
inline unsigned long long g_qra_ns = 0;
inline unsigned long long g_emit_ns = 0;
// 2026-06-17 Family-4 headroom probe: count guest vmloads whose ADDRESS is a compile-time constant (foldable from
// the static read-only image) vs total, during AOT lowering. Set via DBT_COUNT_CONST_VMLOAD env. Default-off.
inline bool count_const_vmload = false;
inline unsigned long long g_vmload_total = 0;
inline unsigned long long g_vmload_const_addr = 0;
// 2026-06-17 Family-A value-stability probe: record per-load-PC whether the loaded value is STABLE (always equal
// to the first observed value) over the interpreted samples (tier-0 window). Gated by profile_load_values.
inline bool profile_load_values = false;
// 2026-06-17 Family-A ORACLE upper-bound: substitute profiled stable-load PCs with their constant value at
// translation (TranslateLoad). On the SAME input the value matches -> correct; measures the speedup ceiling of
// value specialization (no guard). Gated by subst_stable_loads; map filled in rv32_qir.cpp via add_stable_load.
inline bool subst_stable_loads = false;
// 2026-07-25 C2 ceiling oracle CORRECTION (OBSERVATION_BOTTOMUP_COST_DECOMPOSITION.md): the
// substitution above only removes the LOAD, not the downstream jalr's dispatch resolution --
// measured zero ceiling on expat because Create_gbrind is unmodified. This SEPARATE oracle,
// keyed by the jalr's own pc (map filled via add_stable_jalr_target, rv32_qir.cpp), skips
// Create_gbrind entirely for a profiled-monomorphic jalr and lowers exactly like a genuinely-
// direct jal (MakeGBr) -- the true "whole dispatch was free" upper bound. No guard, same-input
// only, measurement-only.
inline bool subst_stable_jalr = false;
// 2026-06-16 TIER-0 LAZY TRANSLATION (default-off): interpret a dynamic basic block until its per-entry execution
// count reaches K* (tier0_threshold), THEN JIT-translate it. K* is the cost-model break-even
//   K* = translate_cost / (interp_block_cost - jit_block_cost)
// derived from measured costs, NOT tuned. Cold handlers (run < K*) are never translated -> saves single-run JIT
// translation cost on short-running dispatch-heavy / interpreter workloads (where ~60% of translated code is
// cold). Hot blocks cross K* and get JIT'd. tier0_threshold==0 -> legacy (JIT on first touch).
inline bool tier0_lazy = false;
inline unsigned tier0_threshold = 0;
inline unsigned long long g_interp_blocks = 0; // #blocks interpreted (mechanism evidence)
// 2026-06-21 QCG cross-block register residency (default-off, --qcg-resident). OBSERVED: QCG does 1.6-5x more L1-dcache
// loads/stores than full-AOT because QRegAlloc::BlockBoundary spills+releases EVERY guest register at EVERY intra-region
// branch (no cross-block residency; qra.cpp "TODO: liveness"). METHOD: at an intra-region branch, SYNC dirty guest regs
// to memory (kept for merge-safety) but KEEP them resident in their host regs; only MERGE blocks (preds!=1) / region
// entry reset to memory at block start. A single-predecessor block inherits its predecessor's resident registers ->
// multi-block hot loop bodies load guest regs once at the header instead of once per block. Correct: memory always
// synced, so any merge path reads consistent state. No host-register reservation (avoids V114 pressure explosion).
inline bool qcg_resident = false;
inline unsigned long long g_resident_inherit = 0; // diag: #blocks that inherited resident globals
inline unsigned long long g_resident_reset = 0;   // diag: #blocks that reset globals to memory
inline unsigned long long g_resident_multiblk = 0; // diag: #multi-block regions seen
// 2026-06-22 diag-only spill-emission counter (behavior-neutral): counts QCG spill stores (EmitSpill) + fills (EmitFill)
// at translation, to test whether the static spill count predicts the cross-block-RA savings (ins_PBA - ins_O0). Reported
// to stderr when DBT_REPORT_SPILLS is set. Does NOT affect codegen/output.
inline unsigned long long g_spill_emit = 0;
inline unsigned long long g_spill_store = 0; // EmitSpill (store to slot)
inline unsigned long long g_spill_fill = 0;  // EmitFill (reload from slot)
// 2026-06-22 exec-weighted dynamic spill count = sum over regions of (per-region static spills x region exec_count).
// By identity this == ins_PBA - ins_O0 == the cross-block-RA savings, measured from run-1 profile WITHOUT building O0 ->
// a precise PBA-vs-O0 tier-selection signal. Accumulated in AOTCompileObject's per-region loop. Reported under DBT_REPORT_SPILLS.
inline unsigned long long g_dyn_spill = 0;
inline unsigned long long g_spill_global = 0; // spills of GLOBAL guest regs (cross-block, the RA-removable component)
inline unsigned long long g_spill_local = 0;  // spills of LOCAL temporaries (within-block, both QCG and LLVM have)
// 2026-06-22 Cycle-13 control-flow-structural region formation (jserv-C). Phase-0 diagnostic (behavior-neutral): after
// ComputeRegionIDF, detect natural loops (back-edge u->s where s dominates u via the dominator chain) and count how many
// loop bodies contain an internal region_entry (i.e. are SPLIT across >=2 IDF regions). GO/NO-GO: loops-split fraction.
inline bool dump_loop_vs_idf = false;
inline unsigned long long g_loop_total = 0;        // natural loops (per back-edge) seen
inline unsigned long long g_loop_split = 0;        // loops whose body has >=1 internal region_entry (split across regions)
inline unsigned long long g_loop_internal_re = 0;  // ACTIONABLE internal region_entry (suppressable: not brind/segment)
inline unsigned long long g_loop_internal_re_raw = 0; // ALL internal region_entry inside loop bodies (incl brind/segment)
inline unsigned long long g_loop_split_raw = 0;    // loops with >=1 internal region_entry of ANY kind (incl real entries)
inline unsigned long long g_loop_body_nodes = 0;   // sum of (loop body size - 1) over loops -> avg internal body size (verify loops non-trivial)
inline unsigned long long g_loop_internal_re_nodom = 0; // region_entries strictly inside body, ANY kind, NO dominance filter (artifact check)
inline unsigned long long g_loop_body_max = 0;     // max loop body size (internal nodes) -- characterize the distribution (are large loops also unsplit?)
inline unsigned long long g_loop_big_total = 0;    // #loops with body >= 5 internal nodes (substantial loops)
inline unsigned long long g_loop_big_split = 0;    // of those substantial loops, how many have an internal region_entry
inline unsigned long long g_re_total = 0;          // total region_entry nodes (region count)
inline unsigned long long g_node_total = 0;        // total module-graph nodes
// 2026-06-22 Cycle-13 Phase-1 method (default-off, --loop-structural-regions): suppress region_entry on dom-frontier nodes
// strictly inside a natural-loop body (keep loop header + brind_target + segment_entry) so each loop = one LLVM region.
inline bool loop_structural_regions = false;
inline unsigned long long g_loop_re_suppressed = 0; // diag: region_entry flags cleared by the structural rule
// T5c-0 (2026-08-30, --aot-loop-entry, default off): expose every non-entry natural-loop header as an
// extra ENTRY of the region that already contains it, through the existing multi-entry wrapper
// mechanism. There is NO per-loop hotness gate: region selection is the only hotness filter, because
// a --threshold gate is inert in the background builder (sr_builder.sh compiles with
// --threshold=999999999 and an explicit admit list). Cost therefore scales with the number of natural
// loops in an admitted region -- 8 wrappers and +1.45% artifact size on the frozen T5c-0 guest.
// Region formation is untouched -- this only decides whether an interior loop header gets its own
// entry symbol and `_aot_tab` slot, which is what a mid-run promotion needs in order to redirect a
// loop that is ALREADY RUNNING. Without it, a region whose root is entered once (a single call to a
// long-running kernel: PolyBench's whole shape) can be built, loaded and promoted in-run and still
// execute zero AOT instructions, because there is no future entry left for RelinkTo to catch.
inline bool aot_loop_entry = false;
inline unsigned long long g_loop_entries_exposed = 0; // diag: headers given a late-enterable entry
// T5d1a (2026-08-31, --dump-loop-candidates, default off): the CANONICAL HOT-NATURAL-LOOP CANDIDATE
// dump. It is a DRY RUN -- when set, elfaot builds the WHOLE-PROFILE module graph
// (BuildWholeProfileGraph: one stitched CFG over every profiled executable page, so a loop is not
// missed merely because its blocks straddle a 4 KiB boundary), computes its dominator tree, writes
// ModuleGraph::ComputeNaturalLoopCandidates()'s output, and exits WITHOUT compiling anything.
// Nothing is marked, no region is chosen, no artifact is produced, and region formation still runs
// per page from BuildModuleGraph exactly as before.
//
// The candidate RULE lives in ModuleGraph (aot_module.cpp), not here, and this flag selects only
// whether the dump runs: with it off, elfaot never calls the producer, prints nothing, and behaves
// exactly as a build without this feature. The producer itself is the interface T5d1b consumes; the
// dump is the evidence that it produces what it says it does. Deliberately NOT a member of
// aot_boot.cpp's kRvvRouteContract: it is an elfaot-only diagnostic that terminates the process
// before codegen, so an elfrun that forwarded it would get no artifact at all.
// T5d1b (2026-08-31, --aot-loop-regions, default off): compile T5d1a's SELECTED hot natural loops
// as real LLVM functions rooted at their loop headers, instead of compiling Wendell's per-page
// dominance regions. When set, LLVMAOTCompileELF takes an alternative emission path built from
// BuildWholeProfileGraph() + SelectHotNaturalLoopCandidates(); every other phase of the compile
// (splice, optimize, intrinsic expansion, object emission, link) is the same code.
//
// It is a REGION/CODEGEN mode and nothing else. It adds no admission rule -- the candidate set is
// exactly T5d1a's `header_exec_freq >= threshold` -- no promotion, no OSR, no policy, and no new
// constant. With it off, not one line of the path runs and the artifact is byte-identical.
//
// It deliberately does NOT use the multi-entry wrapper / alias / `loop_entry_exposed` machinery:
// the header IS the function's entry, so there is nothing to expose.
inline bool aot_loop_regions = false;
// Where to write the QIR of every emitted loop region (T5d1b, --aot-loop-regions-qir-out).
// Default null: nothing is printed and PrinterPass is never called. The QIR is what shows an
// exit as a `gbr` BEFORE any LLVM pass has run, which is the only way to tell an edge the
// translator never emitted from one LLVM later proved unreachable and deleted.
inline char const *aot_loop_regions_qir_out = nullptr;
inline unsigned long long g_loopregion_functions = 0;      // emitted header-rooted functions
inline unsigned long long g_loopregion_body_blocks = 0;    // guest blocks compiled, counted with multiplicity
inline unsigned long long g_loopregion_distinct_blocks = 0; // ... and without
inline bool dump_loop_candidates = false;
// Where the dump goes. nullptr (the default, and what an empty --dump-loop-candidates-out means)
// writes to stdout. Never opened, and never even consulted, unless dump_loop_candidates is set.
inline char const *dump_loop_candidates_out = nullptr;
// ---------------------------------------------------------------------------------------------
// T5d2a LOOP TIER (--loop-tier, default off): build T5d1b's loop-rooted artifact DURING the run
// that produced the evidence for it.
//
// WHAT IT IS. One narrow path with one job: wait until THIS run's own execution evidence reaches
// the compiler's admission bar, snapshot the live profile, and launch exactly one background
// `elfaot --aot-loop-regions` on a distinct allowed CPU. It is a producer and nothing else. It does
// not dlopen, announce, relink, promote or time anything; nothing in this process ever executes a
// byte of what it builds. That is T5d2b's subject, and keeping it out is what makes this
// checkpoint's claim ("a correctly selected loop artifact lands before the guest exits") separable
// from a performance claim it is not making.
//
// WHAT IT IS NOT, ITEM BY ITEM. It is NOT the single-run/BCT tier: it does not touch
// `inrun_*`/`esc_*`/`sr_*` state, does not run `sr_builder.sh`, has no geometric threshold descent,
// no ski-rental price, no A/B census or majority sign test, no rung sequence, no trial artifacts,
// no dispatch-closure or wrapper machinery, and no `--inrun-escape-unlink` / `--aot-loop-entry`.
// Those mechanisms are all still in the tree and all still default off; this path calls none of
// them, which is checked in `loop_tier_test.cpp` rather than asserted here.
//
// TIME HAS NO ROLE AT ALL (T5d2a1). There is no keeper, no interval timer, no cadence and no tick.
// `loop_tier_due` is set by ONE emitted instruction sequence: the NOTIFICATION QEmit::Emit_Cache
// appends to a direct BACKWARD edge's existing Wendell counter update. Setting the bit makes
// `service_request` nonzero, which is what T5d0's backedge safepoint tests, so the same edge that
// notified hands control back to `Execute()` a few instructions later.
//
// The notification therefore carries PROGRAM evidence and nothing else: which guest block, and that
// its own execution count has reached the number the compiler admits on.
//
// THE PROTOCOL (T5d2a2), four tests and a claim. The emitted sequence delivers a notification when,
// and only when, all four of these hold -- each one compare, in this order:
//
//   1. this target's `exec_count` has REACHED OR PASSED the compiler's bar (`>=`, not `==`);
//   2. the tier is still ARMED (`loop_tier_state == kLoopTierArmed`), so a notification could still
//      be used at all;
//   3. the one-slot mailbox `loop_tier_event_ip` is FREE, so no notification already in flight is
//      overwritten;
//   4. this GUEST TARGET has not notified before (`loop_tier_notified`, keyed by guest ip).
//
// It then claims 4, fills 3, and raises the bit -- in that order, so a consumer that sees the bit
// sees the target, and a target that got as far as claiming really did deliver.
//
// WHY `>=` AND A SEPARATE ONE-SHOT, rather than T5d2a1's `== bar`. `exec_count` is SHARED by every
// incoming path: Execute()'s host loop increments it on each arrival that returns there, and a
// forward direct edge counts into the same word from its own Emit_Cache. An exact equality can
// therefore be consumed by an arrival this backward edge never runs on, after which the edge sees
// `bar + 1` for ever and the loop is never reported at all. `>=` cannot be consumed by another
// writer. The one-shot that equality provided for free is restored by 4, which is a fact about the
// guest target rather than about one increment of one counter.
//
// WHY THE ONE-SHOT IS KEYED BY GUEST IP AND NOT HELD IN THE TBlock. A TBlock is a TRANSLATION, and
// translations are revoked, replaced and retranslated (tcache::Invalidate, RevokeTarget, the retire
// sweep) for reasons that have nothing to do with this tier. A bit inside one would be cleared by
// those events and the same guest loop would notify again -- once per retranslation, which is a poll
// with extra steps. `loop_tier_notified` outlives every translation of the block it names.
//
// WHAT EACH TEST BUYS, stated separately because they are independent and each is checked on its
// own: 1 is the evidence; 2 makes a terminal tier silent in the generated code, so a spent tier
// causes no further payload store, no further service bit and no further safepoint escape; 3 keeps
// a rejected notification from destroying a different target's; 4 is what makes a REJECTED target
// unable to livelock the consumer.
inline bool loop_tier = false;
inline ServiceFlag loop_tier_due{kSvcLoopTier};
// THE ONE-SLOT MAILBOX. The guest block whose counter delivered the pending notification, written by
// the emitted code immediately before the bit and DRAINED (put back to 0) by the consumer on every
// service, before it decides anything. It is not a profile, not a counter and not a decision input
// in itself: the consumer uses it only to ask the T5d1a selector whether THAT block is one of the
// hot natural-loop headers it selected.
//
// 0 MEANS FREE, which is why the emitted sequence tests it: a target that finds the slot occupied
// leaves its own one-shot INTACT and retries at its next backward edge, so a notification the
// consumer has not read yet is never overwritten and no target's evidence is silently dropped. Guest
// ip 0 is not a translatable block in any program this tier can arm on; were it one, the only
// consequence would be that its notification could be overwritten -- the pre-T5d2a2 behaviour, and
// not a wrong build.
inline uint32_t loop_tier_event_ip = 0;
// The last target the CONSUMER took out of the mailbox, latched for reporting only. Distinct from
// the mailbox itself, which is drained on every service: `mailbox=00000000` in LOOPTIER_SUMMARY is
// the run's own evidence that nothing refilled the slot after the last service -- which, once the
// tier is terminal, the emitted code must not be able to do.
inline uint32_t loop_tier_last_taken_ip = 0;
// T5d2a2: the per-GUEST-TARGET one-shot. Node-based on purpose -- [unord.req] guarantees that
// references and pointers to elements survive rehashing -- so the address handed to the code
// generator at TRANSLATION time keeps naming the same byte for the life of the process, across any
// number of retranslations of that block. Populated only through LoopTierNotifySlot below, which is
// called only from the flag-gated JIT-mode emission path, so an off run never inserts an element and
// never allocates.
inline std::unordered_map<uint32_t, unsigned char> loop_tier_notified;
// The address the emitted notification bakes for `gip`. A function rather than a raw map access so
// the one place that hands a code generator this address is also the one place stating what may be
// assumed about it: the pointer is stable, the byte starts at 0, and the KEY is the guest ip -- not
// the TBlock, not the region, not the translation.
inline unsigned char *LoopTierNotifySlot(uint32_t gip)
{
	return &loop_tier_notified[gip];
}
// Emission-side: how many direct backward edges got a crossing test. Moved only by a run that asked
// for the mode, like every other T5d0/T5d1 counter -- an off run must not differ observably.
inline unsigned long long loop_tier_event_sites = 0;
// Consumer-side: notifications taken, and notifications whose target the selector rejected.
// `events - rejected` is at most one, because a selected target spends the build. Neither counts
// anything that arrives after the tier is terminal -- with the ARMED test in the emitted sequence
// nothing can.
inline unsigned long loop_tier_events = 0;
inline unsigned long loop_tier_rejected = 0;
// The target that actually SPENT the build, latched once. Distinct from `loop_tier_last_taken_ip`,
// which is the last target the consumer took for any outcome, and from the mailbox, which is the
// live slot. Reporting the live word as "the event that built" would have been wrong, and was: the
// first end-to-end T5d2a1 run printed a summary naming a block that had nothing to do with the
// build.
inline uint32_t loop_tier_spawn_ip = 0;
// The child's identity inputs. All three must be given; with any of them missing the tier refuses
// to arm rather than firing into a half-configured build.
inline char const *loop_tier_elfaot = nullptr; // the compiler binary the child executes
inline char const *loop_tier_elf = nullptr;    // the guest ELF the child compiles -- the same one
inline char const *loop_tier_stage = nullptr;  // staging dir: profile snapshot, build, publication
// CLOCK_MONOTONIC origin, in ms, shared with the child through the fork. Every LOOPTIER event on
// either side of the fork prints its offset from THIS instant, so the child's publish and the
// parent's guest-exit are two readings of one clock and can be ordered directly.
inline long loop_tier_start_ms = 0;
// State (looptier::State). An int here so config stays dependency-free; the enum lives in
// dbt/aot/loop_tier.h, which is where the transitions are.
inline int loop_tier_state = 0;
// The ONE state value emitted code compares against, because the notification's "can this still be
// used?" test is GENERATED rather than interpreted. It is not a mirror of `loop_tier_state`: it is
// the constant the generated compare uses, and dbt/aot/loop_tier.cpp static_asserts it against
// State::ARMED so the two cannot drift.
inline constexpr int kLoopTierArmed = 1;
// T5d2b0: the second state value emitted code compares against. The completion poll must treat a
// pending service request as a BUILDER COMPLETION only while a build is actually outstanding --
// SIGCHLD is process-wide, so an unrelated host child's exit raises the same word, and a terminal
// tier that took a side exit for it would be handing control back for a completion that cannot
// exist. dbt/aot/loop_tier.cpp static_asserts this against State::BUILDING.
inline constexpr int kLoopTierBuilding = 2;
// The crossing count the event carried: the selected header's own `header_exec_freq` as the T5d1a
// selector reports it. Reporting only; nothing reads it back.
inline unsigned long long loop_tier_hottest = 0;
inline int loop_tier_pid = 0;
inline int loop_tier_guest_cpu = -1;
inline int loop_tier_builder_cpu = -1;
inline long loop_tier_fire_ms = -1;	  // when the child was spawned
inline long loop_tier_reaped_ms = -1;	  // when the parent observed the child exit
inline long loop_tier_publish_ms = -1;	  // when the parent first observed the published artifact
inline long loop_tier_guest_exit_ms = -1; // when the guest returned from MainThreadExecute
inline int loop_tier_build_rc = -1;
inline unsigned long long loop_tier_artifact_bytes = 0;
// Set only by an observation made while the guest was still executing.
//
// T5d2a2 MAKES THIS FALSE BY CONSTRUCTION, and that is a deliberate trade rather than a regression
// of the claim. The parent can only look at the staging directory when it has control, and it only
// gets control from a safepoint escape, which only a notification can cause -- and after the build
// is spent the tier is not ARMED, so it must raise nothing. The tier therefore stops asking, the
// child is collected at guest exit, and the ordering claim rests where it always did: on
// `loop_tier_publish_ms`, which is the CHILD's own publish instant read from its sidecar, in the
// same monotonic origin as `loop_tier_guest_exit_ms`. `publish_before_guest_exit` is that
// comparison; this flag is the strictly weaker "the parent had noticed by then".
inline bool loop_tier_publish_seen_in_run = false;

// 2026-09-17 EXIT-CANCEL. At guest exit a build still in flight CANNOT benefit this run: installs
// happen in-run only (loop_tier.cpp's load/install gate requires `in_run && LOADED`), so a tier that
// blocks in ReportAtExit until the compiler finishes charges the whole remaining build to COLD
// ELAPSED for an artifact this process will never enter. Measured on the delayed-builder case:
// GUEST_EXIT at 2603 ms, BUILD_END at 45253 ms -- 42.65 s of post-guest waiting.
//
// Default ON, unlike most switches here, because leaving it off preserves the defect. Set 0 to get
// the previous blocking-wait behaviour back for an A/B; nothing else changes with it.
inline bool loop_tier_exit_cancel = true;
// Set only when this process has POSITIVE evidence that the builder's process group exists and its
// pgid equals loop_tier_pid. Without it the tier never signals a group: an unowned pgid is still
// the PARENT's group, and killpg() on it would hit unrelated processes.
inline bool loop_tier_pgid_owned = false;
// Diagnostics for the cancel path; all remain 0 on a run that never cancels.
inline bool loop_tier_canceled = false;
// The child renamed the artifact into place before the signal landed. The file exists but this run
// neither loaded nor installed it, and it must NOT be reported as a successful publication.
inline bool loop_tier_stale_publication = false;
inline long loop_tier_cancel_ms = 0;   // when the cancel decision was taken
inline int loop_tier_cancel_signal = 0; // last signal delivered to the group (SIGTERM or SIGKILL)
// Non-zombie processes still in the owned group after the escalation finished. 0 is the contract;
// anything else (including -1, "could not tell") is the orphan condition and is reported loudly.
inline int loop_tier_cancel_group_live = 0;
// ---------------------------------------------------------------------------------------------
// T5d2a3 IMMEDIATE SERVICE EXIT (--loop-tier-side-exit, default off).
//
// THE DEFECT. T5d2a2's notification is raised on the direct BACKWARD edge that observes its target
// at the compiler's bar, and this guest's hot latches are INTRA-REGION edges (`Emit_br` /
// `Emit_brcc`'s taken arm; see MakeGBr). But the only legal state/frame escape T5d0 built is on a
// region-exit `gbr`, so the request sits raised until the guest happens to reach one. In the
// accepted T5d2a2 run the event target is `00011890` and the single escape is at `000118c4` -- a
// few instructions later, which is a property of THIS loop nest. A loop whose hot path lies wholly
// inside one QCG region has no such bound at all: the request could be carried to the end of the
// timed loop, or to the end of the program.
//
// WHAT IS ADDED. A standard COLD SIDE EXIT on the same dynamic edge that claimed the notification.
// The ordinary, no-event path is untouched: it is still an in-region direct branch, the loop is
// still one region, and no host helper is called on any iteration. Only the instruction that
// follows the `lock or` changes -- from "fall into `skip_cache`" to "jump to this edge's own
// out-of-line exit block", which is reachable only after the one-shot for that guest target has
// been claimed and therefore runs at most ONCE per target for the life of the process.
//
// WHY THE EXIT IS LEGAL AT AN EDGE THAT IS NOT A REGION EXIT. The four properties T5d0 inherited
// from `gbr` are re-established here explicitly, each from the source path rather than by analogy:
//
//  1. GUEST STATE. `QRegAllocVisitor::visitInstBr` / `visitInstBrcc` run `QRegAlloc::BlockBoundary`,
//     which spills every NON-pinned global to `CPUState` before the branch (with `--qcg-resident`,
//     `SyncSpill`, which writes the same memory and only keeps the register too). The globals are
//     exactly `RV32Translator::GetStateInfo`'s x1..x31 and ip -- all scalar. The ONE thing
//     `BlockBoundary` deliberately leaves in a host register is a `--qcg-pin` global, and the exit
//     block writes precisely those back, from `Region::pins`, with the same `StateSpill` the
//     prologue filled them with and the same store `RegionBoundary` performs at a gbr. Vector
//     architectural state is in `CPUState` already: no VPR track is a global, and a typed-chunk
//     group cannot be open across a branch. `--rvv-vector-ssa` is the one route that DOES defer a
//     vector commit past a guest-instruction boundary, so this path refuses to be emitted at all
//     when that switch is set, and `looptier::Arm` refuses to arm -- fail closed, not silently.
//
//  2. HOST FRAME. Nothing between `Prologue`'s `FrameSetup` and a region exit leaves the stack
//     unbalanced -- every other `push`/`pop` in QEmit is paired within one instruction's emission,
//     and the unpaired `FrameDestroy`s all sit on paths that leave the region. So `rsp` at an
//     intra-region branch is the region-entry `rsp` minus that one alignment push, and the exit
//     block's own `FrameDestroy` restores exactly the value `trampoline_to_jit`'s `call` left --
//     which is the shape `qcgstub_escape_link` unwinds from. (`--trace` is the one configuration
//     where that is NOT true: its block in `Emit_Cache` pops the alignment push without a matching
//     one. The side exit is therefore not emitted under `--trace`.)
//
//  3. TARGET PC. The edge's target is a translator-level constant, so the store into `CPUState::ip`
//     is a single immediate, written AFTER the pinned globals are committed -- `ip` is itself a
//     global, and writing the PC first would let a pin spill overwrite it. (`PinSelect` refuses to
//     pin `ip`, so today no spill can name that slot; the order does not depend on that refusal.)
//
//  4. WHAT Execute() RECEIVES. The exit block ends with `lea rax, [rip + slot]; jmp escape_link`,
//     where `slot` is a REAL `BranchSlot` emitted at the end of the block with `gip` = this edge's
//     target. So the direct-edge arm of `Execute()` runs -- `Link`, `RecordLink`, `CacheBr` -- and
//     `assert(branch_slot->gip == state->ip)` holds. Returning `nullptr` through `escape_brind`
//     would have been shorter and is deliberately NOT used: it would push a direct edge through
//     `CacheBrind`, marking the target `is_brind_target` and inserting it into the L1 dispatch
//     cache, i.e. contaminating the very profile the tier's child is about to compile.
//
// JIT MODE ONLY, like every other part of this line: the escape stub and the config addresses are
// this process's. An offline AOT artifact is byte-identical with the switch on or off.
inline bool loop_tier_side_exit = false;
// Emission-side: how many intra-region backward edges got an exit block. Moved only by a run that
// asked for the mode.
inline unsigned long long loop_tier_side_exit_sites = 0;
// Taken-side: incremented by the EMITTED code, on the cold path only.
inline unsigned long long loop_tier_side_exits = 0;
// Execute()'s attribution of those exits to the guest PC they resumed at, same idiom as T5d-0's:
// if the counter moved since the previous pass through the host loop, THIS pass is the one the exit
// returned to and `state->ip` is the PC the edge stored. Bookkeeping; nothing reads it back.
inline unsigned long long loop_tier_side_exits_seen = 0;
inline std::unordered_map<uint32_t, unsigned long long> loop_tier_side_exit_ips;
// ---------------------------------------------------------------------------------------------
// T5d2b0 CHILD-COMPLETION WAKEUP (--loop-tier-completion-exit, default off).
//
// THE GAP IT CLOSES. After T5d2a3 the tier reaches BUILDING with the guest still inside the same
// pure-compute QCG region. The builder publishes and exits a few tens of milliseconds later, but
// nothing tells the parent: the emitted notification is spent (its one-shot is claimed and the tier
// is no longer ARMED, so T5d2a2's guards make the generated code silent by design), a second
// hotness event is deliberately impossible, and `ReportAtExit` only collects the child after
// GUEST_EXIT. So the run ends at BUILDING and `published_in_run` is 0 by construction.
//
// WHAT IS ADDED, and what is deliberately NOT. The child's own termination is the event. SIGCHLD
// raises `loop_tier_due` -- the same bit T5d2a2's notification raises and `Execute()` already
// consumes -- from a handler that does nothing but two lock-free atomic writes. An intra-region
// backedge whose target has already passed the bar tests that word and, when it is set, takes
// T5d2a3's EXISTING exit block. `Execute()` then reaps that one recorded pid with WNOHANG on the
// host stack. There is no timer, no cadence, no directory poll, no blocking wait, no second
// threshold crossing and no second workload event anywhere in the path, and program exit is not
// the successful case -- it is the fallback that is now only reached when the child outlives the
// guest.
//
// WHERE THE POLL SITS, and what it costs. Inside the SAME notification block, immediately after
// T5d2a2's evidence test and before its ARMED test. So a target BELOW the bar pays exactly what it
// paid before -- load the bar, compare, fall through -- and only a target the run has already
// admitted evidence for pays the extra load/compare/not-taken-branch. That is the same question
// T5d0's gbr safepoint asks, on the one edge class T5d0 could not reach.
//
// WHY TESTING THE WHOLE WORD IS EXACT HERE. `Arm()` already refuses to run alongside every other
// consumer of `service_request` (inrun tier, P1, the sat sweep, the web repack, the escalate
// channel, the W_max sampler), so with the loop tier armed the only bit that can be set is
// `kSvcLoopTier`. The poll therefore cannot be woken by somebody else's request, and it is written
// as the same `cmp <word>, 0` T5d0's safepoint uses rather than as a second, private encoding.
inline bool loop_tier_completion_exit = false;
// SET BY THE SIGCHLD HANDLER, CONSUMED BY ONE EXCHANGE. Not a mirror of `loop_tier_due`: that bit
// says "the runtime wants control", this word says WHY -- and the two legitimately differ, because
// a notification raises the bit without a child having exited. The handler writes this first and
// the bit second, so a consumer that sees the bit also sees the reason, which is the same ordering
// discipline the emitted notification uses for its payload.
//
// `exchange` is what makes "consumed exactly once" mechanical rather than conventional: two
// SIGCHLDs collapse into one service, and a service that finds it clear does no completion work.
inline std::atomic<unsigned int> loop_tier_child_exited{0};
static_assert(std::atomic<unsigned int>::is_always_lock_free,
	      "loop_tier_child_exited is written from a signal handler; a locked implementation is unsafe there");

// THE COMPLETION NOTIFICATION, AS ONE ORDERED PAIR, and the only place either word is raised.
//
// It lives here rather than in the handler for two reasons. It is where `kSvcLoopTier` may be
// named, so the handler does not have to; and the ordering contract belongs with the two objects it
// orders rather than being asserted somewhere else about them.
//
// SEQ_CST, NOT RELAXED, AND THAT IS A CORRECTION. An earlier version wrote both with
// `memory_order_relaxed` and claimed that writing the reason first made a consumer that sees the
// request see the reason. It does not: relaxed atomics establish NO ordering between two distinct
// objects, so a consumer could observe the request with the reason still 0 and do completion work
// for a reason it cannot see -- or, worse, a compiler could sink the first store past the second.
// Sequential consistency puts both operations in one total order, which makes "the reason precedes
// the request" a fact about that order rather than a hope. It costs two fenced RMWs on a path taken
// at most once per build, which is not a cost worth trading correctness for.
//
// Both operations are single lock-free atomic RMWs on the interrupted thread's own data, which is
// what the standard permits a signal handler to perform -- unchanged by the ordering.
inline void RaiseLoopTierCompletion()
{
	loop_tier_child_exited.store(1u, std::memory_order_seq_cst); // the reason
	service_request.fetch_or(kSvcLoopTier, std::memory_order_seq_cst); // then the request
}
// Consumer-side: services that consumed a completion notification. Reporting only.
inline unsigned long loop_tier_completion_wakeups = 0;
// Emission-side and taken-side of the poll, kept apart from T5d2a3's own counters so the two
// entries into the one exit block can be told apart in the run's evidence.
inline unsigned long long loop_tier_completion_exit_sites = 0;
inline unsigned long long loop_tier_completion_exits = 0;
// ---------------------------------------------------------------------------------------------
// T5d2b1 LOAD AND VALIDATE (--loop-tier-load, default off).
//
// The step after T5d2b0's in-run reap, and the LAST one before installation: the parent dlopens the
// exact artifact it just published, puts it through the same CPUState-ABI and RVV-VLEN gate every
// other loader in this process uses, and validates the table down to the entry naming the header
// this run spent its build on. It then holds an immutable validated view and STOPS.
//
// WHAT IT IS NOT. No TBlock is allocated or replaced, no L1 cache entry is written, nothing is
// relinked, and no control transfer into compiled code exists anywhere on this path -- the loader
// lives in its own translation unit precisely so that "it cannot promote" is a property of the code
// rather than a claim about which test was run (audit gate T11). `PUBLISHED` (a file exists) and
// `LOADED` (this process mapped and validated it) are separate states for the same reason.
inline bool loop_tier_load = false;
inline long loop_tier_load_ms = -1;	    // when the validated view was established
inline unsigned long long loop_tier_loaded_syms = 0; // table entries the view carries
inline char const *loop_tier_load_refused = nullptr; // the stable reason a load was refused, if any
// ---------------------------------------------------------------------------------------------
// T5d2b2 INSTALL AND ENTER (--loop-tier-install, default off).
//
// The step T5d2b1 stopped short of, and it is deliberately the SMALLEST one that can be taken: the
// validated view's ONE entry naming this run's own spawn header is turned into an AOT `TBlock` and
// replaces that exact guest ip in the translation cache. Nothing else in the artifact is installed,
// no branch is relinked in bulk, and no dispatch cache is written by this path.
//
// WHY NOTHING MORE IS NEEDED, stated as the control flow it rests on rather than as a hope. The
// install runs on the host stack inside `looptier::Service()`, which `Execute()` calls BEFORE its
// `tcache::Lookup(state->ip)`. The escape that delivered this service carried the exact `BranchSlot`
// of the edge it left (T5d2a3's exit block and T5d0's gbr safepoint both leave through
// `qcgstub_escape_link`, which forwards the slot), and both write `CPUState::ip` with that edge's
// own target before leaving. So when the header this run built for IS the PC the run is resuming
// at, the very next lookup in the SAME iteration finds the block installed a few instructions
// earlier, and `Execute()`'s existing direct-edge arm links that slot to the artifact and enters it
// through the ordinary trampoline. `loop_tier_install_at_ip` records the PC at the install, so that
// chain is a number the run prints about itself rather than an argument about the source.
//
// WHAT IS NOT DONE, AND WHY. No `RelinkTo`, no `CacheBr`, no `CacheBrind` from this path: a global
// relink would migrate every already-linked predecessor at once and would make it impossible to say
// which mechanism produced the entry. `InsertOrReplace` is used rather than `Insert` because the
// header already has a QCG block and the two data structures it writes -- the map and the L1 block
// cache -- must not be left disagreeing; that is the mid-run-boot replace semantics that already
// exists, applied to exactly one ip. Stale direct links into the old QCG code stay valid and keep
// executing it, which is correct and lower-tier, and is the reason no relink is required.
inline bool loop_tier_install = false;
inline long loop_tier_install_ms = -1;		  // when the exact header was replaced
inline uint32_t loop_tier_installed_gip = 0;	  // the ONE guest header this run installed
inline unsigned long long loop_tier_install_host = 0; // base + aot_vaddr, the host entry installed
inline uint32_t loop_tier_install_at_ip = 0;	  // the guest PC the run was resuming at

// 2026-09-17 FAULT-STATE DIAGNOSTIC (default off, CLI --dump-fault-state).
//
// A guest memory fault currently reports ip/addr/page/kind and nothing else, so a fault in
// generated code can only be reasoned about by INFERENCE from the faulting address. This makes the
// machine state observable instead: the HOST registers out of the signal ucontext (the ground
// truth for what the faulting instruction actually used), the host PC with its distance from the
// known code anchors, the raw host instruction bytes at that PC, and the guest CPUState register
// file.
//
// THE TWO ARE NOT THE SAME THING AND THE DUMP MUST NOT BLUR THEM. CPUState holds the guest values
// that have been MATERIALIZED; a QCG block may legitimately keep a guest register resident in a
// host register and sync it only at a block boundary, so a zero in CPUState is not by itself
// evidence that the guest value is zero. The host registers are what the faulting instruction read.
inline bool dump_fault_state = false;
// Guest register file captured at the instant the loop tier installed its block, so the fault dump
// can print the BEFORE/AFTER across the AOT entry rather than a single snapshot. Valid only when
// `loop_tier_install_gpr_valid` is set.
inline bool loop_tier_install_gpr_valid = false;
inline unsigned loop_tier_install_gpr[32] = {};
inline unsigned loop_tier_install_ip_at_capture = 0;
// THE PROMOTION BOUNDARY, read at the install and again at exit. `region_entry_hits` is emitted only
// by LLVM-compiled artifact code, so its value here is the before-picture and must be zero.
inline unsigned long long loop_tier_install_aot_hits = 0;
inline unsigned long loop_tier_install_qcg_tbs = 0;
inline unsigned long long loop_tier_install_qcg_mass = 0;
inline char const *loop_tier_install_refused = nullptr;
// C5d: what the install's own promotion actually moved, recorded so the claim "the old QCG paths
// were rewired" is a number the run prints about itself rather than an inference from the source.
// `relinked` is the header's already-self-patched direct fan-in; `ic_unpatched` is the inline-cache
// blobs whose stale direct jump was revoked; `brind_was_target` says whether this ip was an
// indirect-dispatch target BEFORE the promotion, which is what makes a `brind` repoint meaningful
// rather than a slot this run created for itself.
inline unsigned long loop_tier_install_relinked = 0;
inline unsigned long loop_tier_install_ic_unpatched = 0;
inline bool loop_tier_install_brind_was_target = false;
// ================================================================================================
// C5c PROMOTION-ROUTE CENSUS (default off). A DIAGNOSTIC, and it is important that it is only that:
// it repoints nothing, links nothing, revokes nothing and installs nothing. It prints, at two
// instants the run already passes through, what every structure in this process that can name a
// host entry for the promoted header actually holds.
//
// WHY IT EXISTS. C5B's root-cause analysis of T5g says the installed artifact is entered once
// because four of the five entry classes into the header still name the old QCG code after
// `tcache::InsertOrReplace`, and it proposes repointing them. That proposal has a PREMISE --
// that `link_map[gip]` is non-empty at the install, so there is a live direct predecessor to
// repoint -- and no preserved T5g artifact contains it. `LOOPTIER_INSTALL` reports the header, the
// host address and the two censuses, but never the header's fan-in. This flag measures exactly that
// premise and nothing else, so that the repair is implemented against a number rather than a guess.
//
// IT IS NOT IN `kRvvRouteContract`, and that is deliberate rather than an omission: the contract
// carries flags whose value the background `elfaot` child needs in order to choose a lowering. This
// one is read by the PARENT's host stack at two call sites and by nothing the child compiles, so a
// contract row for it would be inert and would dilute the one-row-per-lowering-decision rule.
//
// COST ON THE TIMED PATH: none, and structurally so. Both call sites are host-stack C++ -- the
// installer's pre-mutation read block and `ReportAtExit` -- so no generated instruction changes and
// nothing is emitted into any translation. With the flag off the census function returns on its
// first statement. Any run that sets it is a MECHANISM run and its wall clock must not be quoted.
inline bool loop_tier_route_census = false;
// 2026-06-22 Cycle-14 SEGA (Spill-Exposure-Guided AOT Admission). Phase-0 diagnostic (behavior-neutral): during a PBA
// (--llvm=0) compile, dump per-region (entry_ip, static QCG spills, region-entry exec_count, dynamic-instr weight,
// region instrs, spill_exposure = spills x dynamic-instr-multiplier) to stderr (REGIONSPILL lines). Lets us test whether
// the spill-exposure admission ranking differs from Wendell's exec-count ranking. Gated by dump_region_spill_exposure.
inline bool dump_region_spill_exposure = false;
// 2026-06-21 QCG trace/region register PINNING (default-off, --qcg-pin --qcg-pin-k=K): the bounded region-RA attack.
// For a call-free MULTI-BLOCK region with a BACKEDGE (a loop), reserve K host registers for the K most-used guest
// registers and hold them resident for the WHOLE region: load once at region entry, never spill at intra-region
// branches (incl. the backedge), sync at SIDEEFF + every region exit. A fixed per-region assignment makes merges/
// loop headers trivially consistent (same host reg on all paths) -> no V114-style global reservation, scoped to the
// hot loop. Tests whether loop-carried guest regs can stay resident across hot backedges and win single-run.
inline bool qcg_pin = false;
inline unsigned qcg_pin_k = 0;
inline unsigned long long g_pin_regions = 0; // diag: #regions where pinning applied
inline unsigned long long g_pin_globals = 0; // diag: #(region,global) pins
// 2026-06-21 EXECUTION-PHASE WINDOWS (observation-only, default-off): deterministically window the run by guest
// instruction count. Every phase_window_insns guest instructions, snapshot each live TB's delta exec_count since
// the previous window and record the per-window top-K hot TB set. At exit, elfrun dumps one line per window listing
// the window's hot TBs (ip:delta_exec). Lets us measure whether the hot-region SET shifts across execution time
// (phased behavior) vs is a single stable set (Wendell's static-snapshot assumption). No execution-path change.
inline bool phase_window = false;
inline unsigned long long phase_window_insns = 0; // window size in guest instructions
inline unsigned g_last_block_insns = 0; // #instructions in the last Interpreter::ExecuteBlock (phase windowing)
inline unsigned long long phase_window_max = 0; // cap: stop after N windows (0 = unlimited)
inline char const *phase_window_out_path = nullptr; // dump target for the cap-triggered early dump

// 2026-06-23 NGR (Normalized Gen-code Reuse): reuse a QCG translation across structurally-identical guest
// blocks differing only in immediate fields (parameterized generated code). On a miss, compute a normalized
// fingerprint (immediate fields masked); on a hit, COPY the cached host code + PATCH the immediate bytes
// instead of re-translating. Default off; stock byte-identical when off.
inline bool ngr = false;
inline bool ngr_verify = false;                  // re-translate + byte-compare each reuse (correctness)
inline bool ngr_loops = false;                   // RESEARCH: enable heuristic R_ADDR (loop/branch) reuse.
						 // byte-diff relocation discovery has residual false positives
						 // even gen-code-scoped (antlr4); pair with --ngr-verify.
						 // default --ngr is R_IMM-only (straight-line, provably safe).
inline unsigned long long g_ngr_reuse = 0;       // diag: #blocks served by copy+patch
inline unsigned long long g_ngr_translate = 0;   // diag: #blocks fully translated (miss / non-normalizable)
inline unsigned long long g_ngr_verify_fail = 0; // diag: #reuses that failed byte-verify (fell back)
// 2026-06-23: skip the redundant boot fill of the 4M-entry L1 caches (~160MB). The caches are globals
// (BSS, already zero == the fill value {0,nullptr}) and tcache::Init() is boot-only, so the fill only
// commits 160MB of pages for nothing — a big chunk of rvdbt's ~0.12s fixed startup. Behavior-preserving
// (BSS zero == filled zero). Helps short generated-code workloads where startup dominates.
inline bool fast_boot = false;
// Process-local code-cache policy, independent of guest ISA and RVV methods.
// THP advice is opportunistic; small-page execution remains supported.
inline bool qcg_code_huge_pages = false;

// RVV substrate (2026-08-17): guest VLEN in bits. Runtime-configurable so one guest binary
// runs at any legal VLEN; must be a power of two, a multiple of 8, and <= rv32::VLEN_MAX_BITS.
// Default 128 is the RVV-spec minimum for the V extension (ELEN=64 => VLEN>=128 is typical);
// the scalable-to-fixed experiment sweeps 512 and 1024.
inline unsigned vlen_bits = 128;

// RVV lowering path (P4). 0 = scalar element-at-a-time reference, 1 = width-parametric
// fixed-width host chunks (SSE2/128-bit on this machine). Default 1: the fixed-width path is
// the point of the substrate, and the reference stays reachable as an oracle and a fallback.
// Held as unsigned rather than the rv32::RvvLowering enum so config.h stays guest-agnostic.
inline unsigned rvv_lowering = 1;
// Run BOTH paths on every vector op and compare. Turns "the two agree" into a measurement.
inline bool rvv_verify = false;
// Print the RVV chunk/tail/fallback/verify counters at exit.
inline bool rvv_stats = false;
// Direct QCG lowering of vadd.vv: emit inline SSE2 in JIT-generated code instead of calling the
// helper, guarded at run time and falling back to the helper on any mismatch. Default on; set 0
// to force every vector op through the helper (the A/B control that shows the two agree).
inline bool rvv_direct = true;
// DIAGNOSTIC CONTROL ARM for the pure-QCG AVX-512 chunk work (2026-08-24, vadd.vv slice).
// NOT the method. See the block comment on InstRVVDiagChunkBegin in qmc/qir.h.
//
// Relative to rvv_direct above it changes two things and no more: the chunk count becomes a QIR
// node count (one node at VLEN=512, two at VLEN=1024) and the access width becomes 512-bit EVEX
// instead of 128-bit SSE2. The representation is unchanged -- the nodes carry no operands, so
// there is no QIR vector value, no def-use edge and no register allocation; chunk data still
// round-trips through CPUState::vec and each chunk's ZMM is hardcoded by the emitter.
//
// Its purpose is to be the A/B control for the typed V512-value lowering and to exercise the
// admission gate, architectural guard, counters and helper fallback. Do not cite it as typed
// chunk QIR or as evidence about QIR-level vector dataflow.
//
// Admitted form only (LMUL=1, unmasked, vstart=0, vl=VLMAX, EEW==SEW); every other form keeps
// the existing helper. Default off.
// See experiments/2026-08-24-0508-rvv-qcg-chunk-vadd/docs/DESIGN.md.
inline bool rvv_qcg_diag_chunk = false;
// AUDIT SWITCH (default off). Bypasses ONLY the host AVX-512 feature test, so the encoder and
// the emitted shape can be disassembled on a host that cannot execute AVX-512. Emitted code
// will SIGILL if actually run on such a host. It does not relax the architectural guard.
inline bool rvv_qcg_diag_chunk_force_emit = false;

// TYPED chunk lowering: the first real guest RVV case routed through typed V512 QIR values
// (vstatechunkload -> vchunkadd -> vstatechunkstore) in pure QCG. Unlike the diagnostic arm
// above, the chunk IS a QIR value: defined by one instruction, consumed by name, and given a ZMM
// by QRegAlloc. The emitter picks no register.
//
// ONE case is admitted, and deliberately only one: vadd.vv at VLEN=512, SEW=32, LMUL=1, unmasked,
// vstart=0, vl=VLMAX. At that shape a guest vector register is exactly one 512-bit host chunk, so
// the whole architectural register is covered by a single chunk and the operand-overlap argument
// is trivial (all three operands are one register each and every chunk touches the same byte
// range of its own register). Other SEWs, VLEN=1024 and LMUL>1 are NOT admitted here.
//
// Everything decidable at translation time is decided there; vtype, vl and vstart are checked by
// an emitted runtime guard, and on ANY mismatch the already-verified helper runs exactly as
// before. Default off. See qmc/qir.h InstRVVTypedChunkBegin.
// P5 (2026-09-04): DEFAULT ON. This is no longer a research switch -- it is the production QCG
// lowering for the one admitted `vadd.vv` shape (e32/m1/unmasked/full-VL). M2's audit showed the
// legacy SSE2 `Emit_rvvaddv` route it replaces is defective on the canonical dependency-chain
// guest in two independent ways: it needs a translation-time vtype OBSERVED IN THE SAME TB, so
// only the 51 vadds sharing a TB with the vsetvli were lowered and the remaining 205 fell back to
// rv32_vialu; and it emits 128-bit SSE2 chunks at every VLEN (1/2/4/8 of them), which is not a
// width-correct lowering. The typed route fixes both from one derivation -- VectorVTypeForBytes
// gives XMM/YMM/ZMM, and the C3.1f unknown-vtype candidate plus its emitted runtime guard carry
// the cross-TB case. Setting it to 0 still restores the legacy route exactly, so every accepted
// ablation arm remains expressible; it just has to be asked for.
inline bool rvv_qcg_typed_chunk = true;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_diag_chunk_force_emit above.
// Bypasses ONLY the host AVX-512 feature test so the emitted typed shape can be dumped and
// disassembled on a host that cannot execute it. Such code will SIGILL if actually run. It does
// not relax the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_force_emit = false;
// T7R: exact observed dynamic floating-point ALU closure (e32/e64, ta,ma; unmasked; partial VL
// permitted) through typed V512 QIR and pure QCG. Every other form remains on rv32_vfalu.
// P7E widened the OBSERVED-vtype half from LMUL=2 to LMUL in {1,2}; a block with no vsetvli
// observation still proposes m2 exactly as before.
inline bool rvv_qcg_typed_chunk_falu = false;
inline bool rvv_qcg_typed_chunk_falu_force_emit = false;

// P7I: the FUSED OPFVF forms `vfmadd.vf` and `vfnmsub.vf` at an OBSERVED e32/e64, ta,ma, unmasked
// vtype with LMUL in {1,2}, through a new three-input typed V512 node and pure QCG. Its own switch
// rather than a widening of rvv_qcg_typed_chunk_falu above, because it is a different node, a
// different runtime stub (rv32_vfma, not rv32_vfalu), a different host feature requirement (FMA3
// on top of AVX-512F) and a different admitted operand contract (the OLD vd is an input). Default
// off. The other six FMA funct6 values and the OPFVV forms are deliberately NOT admitted.
inline bool rvv_qcg_typed_chunk_fma = false;
// P8: `vfsqrt.v` at an OBSERVED e32/e64, ta,ma, unmasked vtype with an integer LMUL, through a new
// ONE-input typed V512 node (vchunkfsqrt) and pure QCG. Its own switch for the same reasons the FMA
// route has one: a different node shape (one source -- vfsqrt has no second operand), a different
// runtime stub (rv32_vfunary1), a different host feature requirement (AVX-512F + BMI2, and NOT
// FMA3: no fused multiply is emitted), and a different admitted vl contract (vl == VLMAX only,
// because the FP tail policy for partial vl is an open design question elsewhere). Default off.
// vfclass.v and the two 7-bit estimates share VFUNARY1's funct6 and are deliberately NOT admitted:
// they are different functions, and the estimates are not correctly rounded.
inline bool rvv_qcg_typed_chunk_fsqrt = false;
// 2026-09-17: ordered floating-point reduction (vfredosum.vs / vfredusum.vs) lowered natively by
// the LLVM backend instead of the rv32_vfred helper. Read by RvvLLVMFredAdmit ALONE, like the
// fsqrt switch and for the same reason: an umbrella disjunction would make `=0` a no-op here.
inline bool rvv_qcg_typed_chunk_fredosum = false;
// W7 (2026-09-17): the WHOLE-REGISTER MOVE family `vmv1r.v` / `vmv2r.v` / `vmv4r.v` / `vmv8r.v`
// lowered natively by the LLVM backend instead of the rv32_vmvNr helper. Read by
// RvvLLVMWholeMoveAdmit ALONE, like the fsqrt and fredosum switches and for the same reason.
//
// THE NATIVE ARM IS RESTRICTED TO `vstart == 0`, and that is a semantic decision rather than a
// convenience. A whole-register move's restart unit is the CURRENT SEW (the QCG body computes
// `vstart << vtype.vsew` to get a byte offset), so a restartable body must read vtype at run time
// and copy a byte-granular suffix. Two things make that the wrong thing to duplicate in a second
// backend right now: the RVV 1.0 ratified text (v20240411) and the current ISA main draft word the
// `vstart >= evl` case differently, and QCG's existing body plus the rv32_vmvNr helper are this
// project's recorded contract for that region. So every `vstart != 0` execution keeps the unchanged
// helper and QCG semantics are not touched. At `vstart == 0` the transfer is the full NREG*VLEN
// bits and is INDEPENDENT of vtype/SEW entirely, which is what makes a vtype-independent guard
// sound here. Default off.
inline bool rvv_qcg_typed_chunk_wholemove = false;
// C2a (2026-09-17): `vsetvl` with the vtype in a GPR, lowered by the LLVM backend
// (Emit_rvvsetvlreg) instead of the rv32_vsetvl helper. The immediate forms have been native since
// S3.4; this one differs only in that VLMAX is a run-time table lookup and the vtype may be
// illegal. Read by the vsetvl route ALONE, never through an umbrella. Default off.
inline bool rvv_llvm_setvl_reg = false;
// C2b (2026-09-17): the four scalar <-> vector element-0 transfers (`vmv.s.x`, `vmv.x.s`,
// `vfmv.s.f`, `vfmv.f.s`) lowered by the LLVM backend instead of their helpers. The frame guard is
// GuardKind::VTypeInteger because the architectural rule for this family IS a vstart rule and the
// body implements it. Read by RvvTryLLVMScalarMove ALONE. Default off.
inline bool rvv_llvm_scalar_move = false;
// C5 (2026-09-17, ruled): PARTIAL VL for the LLVM/AOT INTEGER element-wise routes.
//
// The frame guard becomes GuardKind::VTypeIntegerNoRestart (exact vtype, `vstart == 0`,
// `vl <= VLMAX`) instead of the full-VL kind, and every destination store carries an ACTIVE-LANE
// predicate read from the LIVE `vec.vl`, so active elements are written and inactive/tail elements
// are left UNDISTURBED (legal for both vtu and vta); `vl == 0` writes nothing at all.
//
// RESTRICTED TO add / sub / mul / and / or / xor, which is exactly the set whose lane operation
// CANNOT raise anything: no trap, no FP flag, no saturation state. Division and the saturating and
// rounding families are deliberately NOT included -- computing their inactive lanes is observable.
//
// NOT extended to the FP routes here either: `RvvFpBracketCloseBody` ORs the host MXCSR sticky
// flags into the guest `fcsr`, so an inactive FP lane's exception is architecturally visible, and
// LLVM 20's VP intrinsics do not help (a masked `llvm.vp.fadd` lowers to an UNMASKED `vaddps` on
// this target -- measured, see the C5 survey). FP needs operand neutralisation and is a separate
// task. Default off.
inline bool rvv_llvm_partial_vl = false;
// C3 (2026-09-18): the IMMEDIATE-SHIFT forms `vsll.vi` / `vsrl.vi` lowered by the LLVM backend
// (Emit_vchunksll / Emit_vchunksrl) instead of the rv32_vialu helper. SEW 32, LMUL 1, unmasked,
// legal single registers -- exactly the QCG route's shape. The shift amount is reduced modulo SEW
// by the QIR node's constructor and re-checked, never re-masked, in the emitter. `vsra.vi` (the
// ARITHMETIC right shift) has no node here and keeps its helper. Read by the shift shape predicate
// ALONE. Default off.
inline bool rvv_llvm_shift = false;
// C3 (2026-09-18): the integer extension family `vzext.vf{2,4,8}` / `vsext.vf{2,4,8}` lowered by
// the LLVM backend (Emit_vchunkextend) instead of the rv32_vext helper. UNMASKED ONLY -- this
// backend has no architectural-mask lowering, so masked forms keep the helper. Read by
// RvvTryLLVMExtend ALONE. Default off.
inline bool rvv_llvm_extend = false;
// C4 (2026-09-18): `vfclass.v` lowered by the LLVM backend (Emit_vchunkfclass) instead of the
// rv32_vfunary1 helper. It is an FP-TYPED instruction with no FP behaviour: RVV 1.0 13.14 defines
// it as a 10-bit one-hot BIT CLASSIFICATION of each element, it rounds nothing, raises nothing
// (rv32_frame_semantics.h already records "vfclass raises no FP exception") and reads no rounding
// mode -- so it needs no constrained intrinsic, no MXCSR bracket and no FP guard, and it lowers to
// ordinary integer vector IR. UNMASKED ONLY, and `vstart == 0` is proved by the frame's guard
// (GuardKind::VTypeIntegerNoRestart) rather than handled by the body. Read by RvvTryLLVMFClass
// ALONE. Default off.
inline bool rvv_llvm_fclass = false;
// C4 (2026-09-18): `vfcvt.f.x.v` / `vfcvt.f.xu.v` -- SAME-WIDTH integer-to-float -- lowered by the
// LLVM backend (Emit_vchunkitof) instead of the rv32_vfcvt helper. Unlike `vfclass` this DOES round
// and DOES raise NX, so it keeps the FP bracket and uses
// `llvm.experimental.constrained.{si,ui}tofp` with round.dynamic/fpexcept.strict -- NEVER a plain
// `sitofp`/`uitofp`. Measured on the installed LLVM 20.1.8: an unconstrained `uitofp <8 x i64> ->
// <8 x double>` at avx512f lowers to the magic-constant trick (`vporq` then `vsubpd`), whose closing
// subtraction of two equal values yields -0.0 under roundTowardNegative -- exactly the defect
// rv32_vector_lower.h records for the host path. The constrained form emits hardware conversions at
// both feature levels (`vcvtuqq2pd`/`vcvtqq2pd` with AVX512DQ, per-lane `vcvtusi2sd`/`vcvtsi2sd`
// without), which honour MXCSR.RC and perform no subtraction. FULL VL, UNMASKED, RNE only. Widening
// and narrowing forms keep the helper. Read by RvvTryLLVMIntToFloat ALONE. Default off.
inline bool rvv_llvm_fcvt_itof = false;
// C4 (2026-09-18): `vfcvt.rtz.x.f.v` / `vfcvt.rtz.xu.f.v` -- SAME-WIDTH float-to-integer with
// architecturally FIXED round-toward-zero -- lowered by the LLVM backend (Emit_vchunkftoi) instead
// of the rv32_vfcvt helper. The frm-dependent pair (`vfcvt.x.f.v` / `.xu.f.v`) is NOT admitted:
// LLVM's fptosi/fptoui truncate by definition, so those need an explicit round step and are a
// separate change. Inactive/invalid lanes are NEUTRALISED to +0.0 BEFORE the conversion, so no lane
// is ever converted out of range and no poison or undefined result is produced and then selected
// away; NV is then derived from the RVV contract (softfp::cvt_to_int_width) and OR-ed into fcsr
// explicitly, while NX comes from the hardware conversion of the lanes that are genuinely in range.
// That is what keeps NV and NX mutually exclusive, as the architecture requires. Read by
// RvvTryLLVMFloatToInt ALONE. Default off.
inline bool rvv_llvm_fcvt_ftoi = false;
// C4 (2026-09-19): `vfwcvt.f.f.v` -- the WIDENING float-to-float conversion (f32 -> f64) -- lowered
// by the LLVM backend (Emit_vchunkftof) instead of the rv32_vfcvt helper. A bare `fpext` is NOT a
// correct lowering: the contract (softfp::cvt_fmt, and the host path's f64_canon) canonicalises BOTH
// NaN kinds to the target format's canonical quiet NaN and raises NV for a SIGNALLING NaN, whereas
// x86's vcvtps2pd quiets an sNaN while PRESERVING its payload and passes a qNaN through unchanged.
// "Widening a finite float is exact" is true and is NOT the whole contract. NaN lanes are therefore
// selected to the canonical qNaN and NV is derived for sNaN lanes. Read by RvvTryLLVMFloatWiden
// ALONE. Default off.
inline bool rvv_llvm_fcvt_fwiden = false;
// C4 (2026-09-19): `vfncvt.f.f.w` -- the NARROWING float-to-float conversion (f64 -> f32) -- lowered
// by the LLVM backend (Emit_vchunkftof) instead of the rv32_vfcvt helper. It is NOT the mirror of
// the widening route: narrowing ROUNDS, so beyond the NaN canonicalisation it can raise NX, OF|NX
// (with the saturated result depending on the rounding mode) and UF|NX with tininess detected AFTER
// rounding. Those three come from the hardware `vcvtpd2ps`, which agrees with `round_pack` on all
// of them; only the NaN VALUE differs (x86 preserves the payload, the contract canonicalises), so
// that is the one thing this route corrects, plus an explicitly derived NV for signalling NaNs.
// `vfncvt.rod.f.f.w` is NOT admitted: round-to-odd is not one of the five architectural rounding
// modes, cannot be requested through frm and has no host equivalent -- the reference forces it onto
// the exact softfloat path. Read by RvvTryLLVMFloatNarrow ALONE. Default off.
inline bool rvv_llvm_fcvt_fnarrow = false;
// C4 (2026-09-19): `vfwcvt.f.x.v` / `vfwcvt.f.xu.v` -- WIDENING integer-to-float (i16 -> f32 and
// i32 -> f64, the only two the shared predicate admits) -- lowered by the LLVM backend
// (Emit_vchunkitof) instead of the rv32_vfcvt helper. Same flag logic as the same-width route:
// `llvm.experimental.constrained.{si,ui}tofp` with round.dynamic + fpexcept.strict, never a plain
// cast. What is new is only the GEOMETRY -- the destination element is twice the source, so the
// unit's lane count comes from the destination window and the source window is half as wide. Both
// admitted width pairs happen to be exact (16 <= 24 and 32 <= 53 significand bits), so NX cannot
// arise; that is a property of the admitted widths and is checked by the oracle rather than
// assumed. Read by RvvTryLLVMIntToFloatWiden ALONE. Default off.
inline bool rvv_llvm_fcvt_itof_widen = false;
// C4 (2026-09-19): `vfwcvt.{x,xu}.f.v` and `vfwcvt.rtz.{x,xu}.f.v` -- WIDENING float-to-integer --
// lowered by the LLVM backend (Emit_vchunkftoi) instead of the rv32_vfcvt helper. Same body as the
// same-width route: classify with integer bit tests, NEUTRALISE the invalid lanes to +0.0 before the
// conversion, derive NV (and, on the frm arm, NX) from softfp::cvt_to_int_width. The shared
// predicate admits exactly ONE width pair, f32 -> i64 (vtype SEW 32), so the range bounds are 2^63
// and 2^64 expressed as f32 exponents while every bit-layout constant stays in the SOURCE format.
// Read by RvvTryLLVMFloatToIntWiden ALONE. Default off.
inline bool rvv_llvm_fcvt_ftoi_widen = false;
// C5/order-item-3 (2026-09-19): PARTIAL VL for the LLVM conversion routes. The frame's guard drops
// from `vl == VLMAX` to `vl <= VLMAX` (GuardKind::VTypePartialVlVstartFrmRNE) and the body then owes
// a tail policy, which it discharges the way the shared contract requires: an active-lane MASKED
// store from the unit's own element base, so inactive elements are left UNDISTURBED (legal under
// both vta and vtu). For the integer-to-float direction the inactive lanes are additionally
// neutralised to integer 0, which converts to +0.0 exactly and raises nothing -- without that, an
// inactive lane could raise NX into the FP bracket and become architecturally visible. Read by the
// conversion routes' partial-VL arms ALONE. Default off.
inline bool rvv_llvm_fcvt_partial_vl = false;
// ORDER ITEM 3 (2026-09-19): ARCHITECTURAL-MASK SUPPORT for ONE integer family -- the masked OPIVV
// element-wise forms `vadd`/`vsub`/`vand`/`vor`/`vxor` with `vm == 0`, which every backend has so
// far left to the rv32_vialu helper ("every LLVM route is unmasked-only", C0 row D).
//
// WHAT IT ADDS is the third conjunct of the contract's active predicate
// (`rv32_rvv_contract.h` piece 2): the destination store's lane predicate becomes
// `(e < vl) && v0[e]` instead of `(e < vl)` alone, with `vstart == 0` still proved by the frame
// guard (GuardKind::VTypeIntegerNoRestart). Masked-off and tail elements are simply NOT WRITTEN, so
// the destination is preserved, which is legal under all four of vta/vtu x vma/vmu.
//
// THE LANE OPERATION IS NOT MASKED, and that is the family restriction rather than an oversight:
// these six integer lane ops raise nothing and set no flag, so computing an inactive element is
// architecturally unobservable and only the COMMIT needs the predicate. Every other lane emitter in
// llvmgen.cpp still Panics on a masked node, because an FP lane's exception WOULD be visible through
// the MXCSR->fcsr bracket.
//
// REFUSED, and each refusal keeps the unchanged helper: `vd == v0` (RVV 1.0 5.3 reserves a masked
// instruction's destination overlapping the mask, and it is also the one read-after-write hazard
// this body's load-major order does not cover), `vs1 == v0` or `vs2 == v0` (5.2's one-EEW-per-source
// rule once v0 is read at EEW 1), LMUL != 1, SEW outside the route's chunk geometry, and every
// funct3 group but OPIVV. Requires --llvm=1 and --rvv-vector-ssa=1. Default off.
inline bool rvv_llvm_masked = false;
// ORDER ITEM 3 (2026-09-19): FP PREDICATION for the LLVM typed FP lane family (`vfadd`/`vfsub`/
// `vfmul`/`vfdiv`, `.vv` and `.vf`). Admits `vm == 0`, which `RvvLLVMFaluChunkAdmit` refused.
//
// A MASKED FP BODY NEEDS MORE THAN A PREDICATED STORE, and that is the whole difference from the
// integer family. `RvvFpBracketCloseBody` ORs the host MXCSR sticky bits into the guest `fcsr`, so a
// masked-off lane that raised OF/UF/NX/NV WHILE BEING COMPUTED is architecturally visible even
// though its result never reaches guest state. So `Emit_vchunkfalu` neutralises the operands of
// every inactive lane to +1.0 -- and "inactive" is now the full contract predicate
// `(e < vl) && v0[e]`, not the `vl` bound alone. +1.0 rather than +0.0 because `vfdiv` is admitted
// and `(+0)/(+0)` raises NV.
//
// THE NEUTRALISED SET AND THE PUBLISHED SET ARE ONE VALUE, derived by `RvvArchMaskForUnit` from the
// same element base for both the operand select and the masked store. Deriving them separately
// would let an element be suppressed in one and computed in the other, silently.
//
// The frame takes the PARTIAL guard kind whenever it is masked, so one body serves masked,
// partial-VL and both together. Read by `RvvLLVMFaluChunkAdmit` and `Emit_vchunkfalu`. Default off.
inline bool rvv_llvm_fp_masked = false;
// ORDER ITEM 3 (2026-09-19): RESTART for the masked OPIVV integer element-wise family. Supplies the
// LAST unemitted conjunct of the contract's active predicate -- the `vstart` FLOOR -- so the store's
// lane predicate becomes `(vstart <= e) && (e < vl) && v0[e]`.
//
// The frame guard drops from `VTypeIntegerNoRestart` to `VTypeInteger` (exact vtype, `vl <= VLMAX`,
// vstart left to the BODY). The body's floor is taken from the FRAME's guard kind, not from a node
// flag, so "the guard stopped proving it" and "the body started emitting it" are one fact -- the
// pairing whose coming apart was the C4-FIX defect.
//
// AND THE FRAME NOW OWES THE RESET. RVV 1.0 3.7 requires `vstart = 0` on completion; every earlier
// LLVM frame discharged that by proving the value was already 0. This one writes it in the epilogue,
// on the fast path only (the fallback helper performs the whole instruction including its own
// reset). `Emit_rvvtypedchunkend` Panics on a restartable frame that neither declares the epilogue
// clear nor writes vstart in its body, so the omission cannot be silent.
//
// WHY THIS FAMILY CAN RESTART: its lane operations are pure per-element functions with no
// cross-element state and no memory access, so re-executing `[vstart, vl)` is the architecture's own
// definition of resuming. A memory family would additionally owe a partial-progress contract.
// Read by `RvvTryLLVMMaskedAlu` and, through the guard kind, by `Emit_vstatechunkstore`. Default off.
inline bool rvv_llvm_restart = false;
// ORDER ITEM 4 (2026-09-19): `vfncvt.rod.f.f.w` -- ROUND-TO-ODD narrowing, f64 -> f32, lowered
// natively instead of the rv32_vfcvt helper.
//
// IT IS NOT A HOST CONVERSION WITH A REQUESTED ROUNDING MODE, and that is a measured fact about the
// installed LLVM 20.1.8 rather than a design preference: on x86 a constrained `fptrunc` carrying
// `round.towardzero` emits byte-identical code to one carrying `round.dynamic` (and a constrained
// `fadd` with `round.upward` emits a bare `vaddsd`), with no MXCSR write anywhere. Codegen uses
// whatever MXCSR.RC holds, which inside this frame's bracket is the GUEST's frm -- so a ROD arm
// built on that metadata would compute `round_frm(x)` and then set the low bit, a silently wrong
// value whenever frm != RTZ and the conversion is inexact.
//
// So the body is INTEGER IR: truncate the significand, force its low bit whenever anything was
// discarded (`softfp::round_pack`'s FRM_ROD arms), with the three boundaries the reference fixes --
// overflow is `E >= 128` and yields FLT_MAX rather than an infinity, a nonzero input can never
// underflow to zero, and a shift of 64 or more is selected in explicitly because it is poison in
// LLVM. NX/OF/UF are derived by the body; the clause in contract piece 7 that asks a deriving body
// to keep the host from contradicting it is discharged by construction here, because the body
// performs no host floating-point operation at all. Default off.
inline bool rvv_llvm_fcvt_rod = false;
// ORDER ITEM 4 (2026-09-19): the two 7-bit estimates `vfrsqrt7.v` / `vfrec7.v` on the LLVM arm.
//
// THEY ARE NOT IEEE OPERATIONS. `rv32_vector_lower.h` states it and an earlier note in the coverage
// matrix got it wrong: RVV 1.0 specifies them by an EXACT 128-entry table, so two conforming
// implementations agree bit for bit. Lowering them to a host reciprocal or reciprocal-sqrt would be
// a SEMANTIC REPLACEMENT, not a lowering, so the absence of an IEEE intrinsic for them is not a
// reason to keep the helper -- it is a reason not to use one.
//
// The body is integer IR: the table index on the normalised significand (`llvm.ctlz` in place of
// the reference's normalisation loop), a per-lane byte load from the table emitted as a PRIVATE
// MODULE CONSTANT, and a select tree for the special values. No constrained-FP call and no MXCSR
// bracket; DZ/NV/OF/NX are ORed into `fcsr` from bits the body computes. `vfrec7`'s overflow
// direction depends on the guest `frm`, which the body reads from `fcsr` rather than pinning at the
// guard. UNMASKED ONLY, SEW 32/64, `vstart == 0`. Read by `RvvTryLLVMFEstimate` ALONE. Default off.
inline bool rvv_llvm_festimate = false;
// ORDER ITEM 4 (2026-09-19): `vfmerge.vfm` / `vfmv.v.f` on the LLVM arm.
//
// THE MASK IS AN OPERAND, NOT A WRITE ENABLE. `vfmerge` writes EVERY body element --
// `vd[i] = v0[i] ? f[rs1] : vs2[i]` -- so `v0` feeds a SELECT and the store carries the ordinary
// active-lane predicate. Treating `v0` as a store predicate, the way a genuinely masked instruction
// does, would leave `vs2`'s value out of the destination entirely. It is also why this route is
// admitted at `vm == 0` while the FP arithmetic routes are not: a select raises nothing, so there is
// no inactive-lane exception to neutralise.
//
// A typed select and a broadcast: no rounding, no bracket, no constrained call. The SEW-32 NaN
// un-boxing is integer-only, so a signalling payload is moved unchanged rather than raising NV.
// Read by `RvvTryLLVMFMerge` ALONE. Default off.
inline bool rvv_llvm_fmerge = false;
// ORDER ITEM 4 (2026-09-19): the WIDENING FP ARITHMETIC family on the LLVM arm -- `vfwadd`/`vfwsub`/
// `vfwmul` and the four widening FMAs, `.vv`/`.vf`/`.wv`/`.wf`, f32 source and f64 destination.
//
// THE DELIVERY IS ONE EMITTER, not a frame. The QCG route already decomposes this family into nodes
// this backend lowers (`vstatechunkload`, `vchunkfbroadcast`, `vchunkfalu`, `vchunkfma`,
// `vstatechunkstore`) and exactly one it did not: the widening convert. The reference's definition
// survives intact because of that -- widen both operands EXACTLY, then perform ONE operation at the
// wide width. `fpext` f32 -> f64 is exact, so it takes no rounding operand and can raise only NV for
// a signalling NaN, which is what the reference raises.
//
// THREE ROWS NARROWER THAN THE QCG TWIN: unmasked only (the convert and lane emitters refuse a
// masked node); no shared opmask (`vchunkmaskset` has no LLVM lowering, refused in admission); and
// no host CPUID probe, because those bits describe the instructions QEmit selects. The frame takes
// the strictly stronger `VTypeVlVstartFrmRNE`, so partial VL, a nonzero vstart and a non-RNE mode
// all reach the unchanged helper. Read by `RvvLLVMFWidenAdmit` ALONE. Default off.
inline bool rvv_llvm_fwiden = false;
// ORDER ITEM 4 (2026-09-19): the SATURATING integer add/sub family on the LLVM arm --
// `vsaddu`/`vsadd`/`vssubu`/`vssub`, `.vv`/`.vx`/`.vi`.
//
// THE FIRST OF THE FIVE NARROW NODES the fixed-point proposal names. QCG emits this family, together
// with the averaging, round-shift, clip and fractional-multiply ones, through `vchunkpartialalu` --
// a 52-kind mega-node this backend does not lower and whose partial-arm protocol it deliberately
// does not use. One node per semantic family is what makes each reviewable on its own saturation
// rule, and the other four remain recorded as blocked rather than attempted.
//
// LLVM HAS THE ARITHMETIC EXACTLY: `uadd.sat`, `sadd.sat`, `usub.sat`, `ssub.sat` are the four
// operations RVV 1.0 12.1 defines, bound for bound, so nothing here approximates a saturation rule.
// `vxsat` is DERIVED -- a lane saturated exactly when the saturating result differs from the
// wrapping one -- and ORed into the sticky flag, never assigned; inactive and masked-off lanes are
// excluded by the unit's active-lane predicate. Read by `RvvTryLLVMSatAdd` ALONE. Default off.
inline bool rvv_llvm_satadd = false;
// ORDER ITEM 4 (2026-09-19): the CARRY/BORROW family on the LLVM arm -- `vadc`/`vsbc`, the forms
// whose destination is a VECTOR register.
//
// SECOND OF THE FIVE NARROW NODES, and the one the proposal flagged for having `v0` as a REAL
// OPERAND rather than a mask. `vadc` writes EVERY body element and adds `v0[i]` as the carry-in, so
// the bits come from the shared mask-window helper and are ZERO-EXTENDED into the lane type, never
// ANDed into a store predicate. The truncation to SEW is the lane type's, which is the reference's
// `& sew_mask`. It raises nothing, so the node is pure.
//
// `vmadc`/`vmsbc` are NOT admitted: their destination is a MASK register, a different shape with its
// own overlap rule. `.vim` keeps the helper because the immediate `vchunkbroadcast` has no LLVM
// lowering. Read by `RvvTryLLVMAdc` ALONE. Default off.
inline bool rvv_llvm_adc = false;
// ORDER ITEM 4 (2026-09-19): the FIXED-POINT AVERAGING family on the LLVM arm -- `vaaddu`, `vaadd`,
// `vasubu`, `vasub`.
//
// THIRD OF THE FIVE NARROW NODES, and the one that introduces `vxrm`. The result is
// `roundoff(vs2 +/- vs1, 1)`, and `vxrm` selects which of four rounding rules `roundoff` applies --
// a REAL ARCHITECTURAL INPUT, so all four are emitted and one is selected from live state rather
// than any being assumed. The increment comes from the SHARED `RvvRoundoffIncrement`, which `vsmul`
// and `vnclip` are meant to reuse; it mirrors `rounding_incr` on the helper arm.
//
// The sum is formed in 2*SEW so the SEW+1 bit the spec requires is real, and the right shift is
// ARITHMETIC even for the unsigned kinds because `vasubu` can produce a negative difference.
//
// THERE IS NO `.vi` FORM TO REFUSE: this family is OPMVV/OPMVX and RVV 1.0 defines no immediate
// encoding for it, so unlike `vsatadd` and `vadc` its native support here is COMPLETE for every
// form the ISA defines. Read by `RvvTryLLVMAvg` ALONE. Default off.
inline bool rvv_llvm_avg = false;
// ORDER ITEM 4 (2026-09-19): the FRACTIONAL MULTIPLY on the LLVM arm -- `vsmul.vv` / `vsmul.vx`.
//
// FOURTH OF THE FIVE NARROW NODES, and the first to round at a shift greater than one: it reuses
// the SHARED `RvvRoundoffIncrement` that `vavg` introduced, at SEW-1, where the spec's sticky
// `v[d-2:0]` term is a real thirty-bit range rather than the empty one `vaadd`'s shift of 1 leaves.
//
// RVV 1.0 12.3 treats both operands as Q(SEW-1) SIGNED fractions -- there is no unsigned form --
// multiplies into 2*SEW and keeps the high half. The one saturating input pair is MIN*MIN, exactly
// +1.0 in that format; `vxsat` is ORed into the sticky flag and gated by the active-lane predicate,
// the same rule as the saturating add/sub route. Read by `RvvTryLLVMFracMul` ALONE. Default off.
inline bool rvv_llvm_smul = false;
// ORDER ITEM 4 (2026-09-19): the NARROWING CLIP on the LLVM arm -- `vnclipu` / `vnclip`.
//
// LAST OF THE FIVE NARROW NODES, and the only one that combines all three of the family's
// mechanisms at once: a 2*SEW source narrowed to SEW, a `vxrm` rounding right shift, and a
// saturating clip into `vxsat`.
//
// ITS SHIFT IS A RUNTIME VECTOR, not a constant -- `.wv` takes a per-element amount -- so the
// SHARED `RvvRoundoffIncrement` was GENERALISED to a value shift rather than duplicated for it.
// That generalisation is the reason this node needed no rounding code of its own.
//
// ALL THREE FORMS ARE NATIVE, `.wi` included: the immediate here is a SHIFT AMOUNT carried on the
// node, not a broadcast operand, so the missing immediate `vchunkbroadcast` lowering that stops
// `vsatadd.vi` and `vadc.vim` does not apply. Read by `RvvTryLLVMNarrowClip` ALONE. Default off.
inline bool rvv_llvm_nclip = false;
// C6 (2026-09-19): the INTEGER REDUCTIONS on the LLVM arm -- `vredsum`, `vredand`, `vredor`,
// `vredxor`, `vredminu`, `vredmin`, `vredmaxu`, `vredmax`.
//
// REUSES THE QCG ARM'S `InstVReduce` NODE. That node already carries the geometry both backends
// agree on; `Emit_vreducenative` was the only missing half, and a parallel node would have
// duplicated a shape rather than added one.
//
// ALL EIGHT ARE ASSOCIATIVE AND COMMUTATIVE -- modular addition included -- so the group folds
// chunk by chunk with one `llvm.vector.reduce.*` per chunk and the partials combine in any order.
// That is precisely what `vfredosum` may NOT do, and the two live next to each other.
//
// Inactive elements take the operation's IDENTITY rather than being skipped, and `vl == 0` writes
// NOTHING (RVV 1.0 makes it a no-op, not a seed store), so the destination store is predicated.
// Masked and widening forms keep the helper. Read by `RvvTryLLVMIntReduce` ALONE. Default off.
inline bool rvv_llvm_ired = false;
// C6 (2026-09-19): the MASK LOGICAL operations on the LLVM arm -- `vmand`, `vmnand`, `vmandn`,
// `vmxor`, `vmor`, `vmnor`, `vmorn`, `vmxnor`.
//
// REUSES THE QCG ARM'S `InstVMaskLogic` NODE, as the integer reduction reuses `InstVReduce`.
//
// A mask register is ONE register whatever the LMUL and these are bit-wise over it, so SEW does not
// participate and there is no chunk geometry -- only which BITS may change. Bits at or beyond `vl`
// are UNDISTURBED, so the destination word is a BLEND, not a store of the computed value.
//
// The active-bit mask is `<64 x i1>` bitcast to `i64`, whose element-0-in-the-least-significant-bit
// order is the guest's own. Read by `RvvTryLLVMMaskLogic` ALONE. Default off.
inline bool rvv_llvm_mlogic = false;
// W31 (2026-09-21): the INTEGER COMPARE family `vmseq` / `vmsne` / `vmsltu` / `vmslt` / `vmsleu` /
// `vmsle` / `vmsgtu` / `vmsgt`, in all three operand forms, on the LLVM arm.
//
// REUSES THE QCG ARM'S OWN NODE, `InstVChunkPartialAlu` with an architectural mask and one of the
// eight compare Kinds, so the two backends consume ONE definition of the semantics rather than two
// implementations of it. `Emit_vchunkpartialalu` Panicked on this backend for all fifty-two kinds;
// W31 supplies the eight compare ones and leaves the other forty-four Panicking, so the emitter's
// reachable surface grows by exactly what this route admits.
//
// THE DESTINATION IS A MASK REGISTER -- one bit per element, ONE register whatever the LMUL -- so
// the write is a 64-bit read-modify-write at `vd + element_base/8` under the body mask, never a
// store of the computed word. Bits before `vstart`, at or beyond `vl`, and at inactive elements are
// UNDISTURBED, which is what the reference (`rvv_ref::vicmp`) does and what makes `vd == v0` legal.
//
// This is the FIRST route in this backend to read `v0` as a body mask; every earlier element route
// refuses `vm == 0` because it has no architectural-mask lowering. The mask algebra is done in the
// scalar i64 domain, exactly as QEmit does it, so no `<N x i1>` / v0 conversion is involved.
// Read by `RvvTryLLVMIntCompare` ALONE. Default off.
inline bool rvv_llvm_icmp = false;
// W32 (2026-09-21): the PARTIAL-VL arm of the LLVM/AOT unit-stride vector LOAD (`vle<EEW>.v`).
//
// The LLVM arm of the `vle` frame has always carried `GuardKind::VTypeVlVstart`, i.e. it demanded
// `vl == VLMAX`. Measured consequence on official ACT4 (experiments/2026-09-21-0018-...): turning
// the route on took `vle32.v` from 1668 helper calls to 1634 while `guard_fallbacks` went 0 to
// 1591 -- the frame was emitted and then missed its guard on 95% of executions, so the route cost
// a guard test and still called the helper.
//
// With this on, the LLVM arm instead emits ONE body under the same guard kind the QCG partial
// frames already use (`VTypeVlOrPartialVstartBaseLimit`): exact vtype, `vl <= VLMAX`,
// `vstart == 0`, and the guest base register within `2^32 - VLEN/8`. The body's guest-memory load
// and its CPUState store both take their lane mask from the live `vec.vl`, so `vl == VLMAX` is the
// all-ones case of the same code and `vl == 0` writes nothing.
//
// THE LOAD IS `llvm.masked.load`, WHICH IS A CORRECTNESS REQUIREMENT AND NOT AN OPTIMISATION: at
// `vl < VLMAX` the bytes above `vl * EEW` may be unmapped, and that intrinsic is specified not to
// access a lane whose mask bit is false. A full-width load plus a select would fault there.
//
// Read by `RvvEmitTypedVleChunkGroup` ALONE, and only on the LLVM/AOT backend. With it off the
// arm emits byte-identical QIR to what it emitted before. Default off.
inline bool rvv_llvm_mem_partial_vl = false;
// C6 (2026-09-19): `vid.v` on the LLVM arm, reusing the QCG arm's `InstVChunkIndex`.
//
// NOT CROSS-LANE despite its chapter: element `e` gets the constant `e`, so the element index is
// literally the datum and a wrong base or stride is directly readable in the destination. Values
// TRUNCATE at small SEW (at SEW 8 element 256 holds 0), which is the architectural answer, and
// elements at or beyond `vl` are UNDISTURBED. Read by `RvvTryLLVMElementIndex` ALONE. Default off.
inline bool rvv_llvm_vid = false;
// C6 (2026-09-19): `vcpop.m` / `vfirst.m` on the LLVM arm, reusing `InstVMaskScalar`.
//
// THE ONLY TWO INSTRUCTIONS HERE WITH AN INTEGER-REGISTER DESTINATION. Both read `[0, vl)` rather
// than `[vstart, vl)` because RVV 1.0 requires `vstart == 0` for them, so the frame guard states the
// architectural precondition rather than narrowing the envelope. `vfirst` scans the words backwards
// so the lowest word with a set bit is the one left standing, branch-free; `rd == x0` writes
// nothing. Read by `RvvTryLLVMMaskScalar` ALONE. Default off.
inline bool rvv_llvm_mscalar = false;
// C6 (2026-09-19): the MASK PREFIX family `vmsbf.m` / `vmsif.m` / `vmsof.m` on the LLVM arm,
// reusing `InstVMaskPrefix`.
//
// ALL THREE ARE FUNCTIONS OF ONE NUMBER -- the index `f` of the first ACTIVE set bit. Once it is
// known, `vmsbf` is `e < f`, `vmsif` is `e <= f` and `vmsof` is `e == f`: the same function the
// reference's serial `seen` flag computes, in the form a vector unit can evaluate in parallel.
//
// `f` uses `vfirst.m`'s all-ones sentinel for "no active set bit", and that sentinel does the work:
// read as UNSIGNED it exceeds every element index, so the two inequalities hold everywhere and the
// equality nowhere -- the spec's answer for an empty mask, with no special case. Bits at or beyond
// `vl` are UNDISTURBED. Read by `RvvTryLLVMMaskPrefix` ALONE. Default off.
inline bool rvv_llvm_mprefix = false;
// C6 (2026-09-19): `viota.m` on the LLVM arm, reusing `InstVMaskIota`.
//
// THE ONLY GENUINELY CUMULATIVE CROSS-ELEMENT COMPUTATION HERE: element `e` receives the number of
// active set bits STRICTLY BEFORE it. Made parallel by splitting the count in two --
// `vd[base+i] = popcount(bits [0,base)) + popcount(bits [base,base+i))` -- where the first term is
// one scalar per chunk and the second is a single `ctpop` of `splat(w) & M` with `M` a CONSTANT
// per-lane mask vector. No scan.
//
// The intermediate is always `i64`, never the element type: at SEW 8 the lane-63 mask does not fit
// in an `i8`, so computing in the element type would truncate the MASK rather than the RESULT.
// Read by `RvvTryLLVMIota` ALONE. Default off.
inline bool rvv_llvm_viota = false;
// C6 (2026-09-19): `vcompress.vm` on the LLVM arm, reusing `InstVCompress`.
//
// THE ONE C6 FAMILY THAT IS NOT A PER-ELEMENT FUNCTION OF ITS INPUTS: the write index runs BEHIND
// the read index, so source element `e` lands at destination position `viota(vs1)[e]`. LLVM has
// the operation exactly (`llvm.masked.compressstore`), so no scan is built -- the emitter walks the
// source in chunks carrying only the SCALAR count already written.
//
// LMUL 1 ONLY, FOR ADDRESSING RATHER THAN SEMANTICS: the destination position is a runtime value,
// and `vd_base + n * sew` is a plain byte offset inside ONE register but not across a GROUP, where
// consecutive logical bytes jump a 512-byte slot every `regbytes`. Read by `RvvTryLLVMCompress`
// ALONE. Default off.
inline bool rvv_llvm_vcompress = false;
// C6 (2026-09-20): `vrgather` / `vrgatherei16` on the LLVM arm, reusing `InstVGather`.
//
// `vd[e] = vs2[idx[e]]`, the index from `vs1[e]` (at SEW, or a fixed EEW of 16 for the ei16 form),
// a GPR, or an unsigned 5-bit immediate. An index at or beyond VLMAX reads ZERO -- not clamped and
// not wrapped -- which is `masked.gather`'s passthru rather than a branch. Index arithmetic is
// 64-bit because a GPR index can exceed 32 bits.
//
// LMUL 1 ONLY: at LMUL 1 the source group is ONE register, so element `i` is at `src + i * sew`
// and the address vector is a single scaled index. Read by `RvvTryLLVMGather` ALONE. Default off.
inline bool rvv_llvm_vrgather = false;
// C6 (2026-09-20): the SLIDES on the LLVM arm -- `vslideup`, `vslidedown`, `vslide1up`,
// `vslide1down` -- reusing `InstVGather` and the SAME emitter as `vrgather`, because the five
// instructions differ only in which source element each destination element reads.
//
// `vslideup` leaves elements below the offset UNDISTURBED rather than zeroing them; `vslidedown`
// past VLMAX reads zero; `vslide1up`'s scalar lands at element 0 and `vslide1down`'s at `vl - 1`
// -- NOT at VLMAX - 1, a different bound from `vslidedown`'s and the one a shared implementation is
// most likely to get wrong. The vacated lane is exactly the lane whose source does not exist, so
// the scalar arrives as the gather's passthru. Read by `RvvTryLLVMSlide` ALONE. Default off.
inline bool rvv_llvm_vslide = false;
// C7 (2026-09-20): the STRIDED vector memory forms on the LLVM arm -- `vlse<EEW>.v` / `vsse<EEW>.v`.
//
// THE FIRST ROUTE HERE WHOSE ADDRESSES ARE GUEST ADDRESSES. Consecutive elements are not
// contiguous: `base + e * stride`, the stride from a scalar register, so a NEGATIVE stride walks
// backwards and a ZERO stride makes every element touch the same address. Both are legal.
//
// THE ADDRESS IS COMPUTED IN 32 BITS AND MAY WRAP -- the guest's address space is 32-bit and the
// reference wraps in `u32`; the zero-extension to the host pointer width happens AFTER.
//
// Each chunk is one `masked.gather` / `masked.scatter` whose mask is the active-element predicate,
// which is what keeps a lane at or beyond `vl` from touching memory at all. Read by
// `RvvTryLLVMStrided` ALONE. Default off.
inline bool rvv_llvm_vstrided = false;
// C7 (2026-09-20): the INDEXED vector memory forms on the LLVM arm -- `vluxei`/`vloxei` (loads) and
// `vsuxei` (the UNORDERED store). Shares `InstVMemory` and the SAME emitter as the strided forms:
// the two modes differ only in the offset vector.
//
// ORDERED INDEXED STORES (`vsoxei`) ARE NOT ADMITTED, and it is a SEMANTIC limit. `vsoxei` requires
// that when two indices name the same address the LAST element in order wins;
// `llvm.masked.scatter` leaves the order among enabled lanes unspecified, so it cannot express
// that. `vsuxei` has exactly the scatter's guarantee. Both indexed LOADS are admitted because a
// load writes no memory and its order is unobservable. Read by `RvvTryLLVMIndexed` ALONE.
// Default off.
inline bool rvv_llvm_vindexed = false;
// C5-MASK (2026-09-20): the MASKED forms of the fixed-point element-wise families -- `vsatadd`,
// `vavg`, `vsmul` -- on the LLVM arm. ONE SWITCH FOR THREE FAMILIES because it is ONE mechanism.
//
// THE DESTINATION NEEDS NO NEW CODE: the architectural mask is ANDed into the store predicate by
// the shared `Emit_vstatechunkstore`, which has carried that conjunct since order item 3.
//
// THE STICKY FLAG DOES, and that is why this is a semantic change rather than an admission
// widening. A masked-off lane that would saturate must not set `vxsat`, and unlike the destination
// -- which the store simply does not write -- the flag has no second chance to be corrected. So
// `vsatadd`'s and `vsmul`'s `vxsat` reductions are ANDed with the SAME architectural mask the store
// uses. `vavg` sets no flag and needs none of it.
//
// Read by the three fixed-point routes, each of which still needs its OWN family switch as well.
// Default off.
inline bool rvv_llvm_fixed_masked = false;

// C5-MASK-FP (2026-09-20): the same mechanism for the same-width FP element-wise families.
// See the option help in elfrun.cpp for why these four are one group and what the flag buys.
inline bool rvv_llvm_fp_cvt_masked = false;

// C6-FRM (2026-09-20): the FP conversion frame admits frm <= RUP instead of frm == RNE.
// See the option help in elfrun.cpp; RMM still falls back, deliberately.
inline bool rvv_llvm_fp_dynamic_frm = false;

// C7-FWPVL (2026-09-20): the LLVM widening-FP body handles a partial vl.
// See the option help in elfrun.cpp. Default off.
inline bool rvv_llvm_fwiden_partial_vl = false;

// C7-FWMASK (2026-09-20): the MASKED widening-FP forms on the LLVM arm.
// See the option help in elfrun.cpp. Default off.
inline bool rvv_llvm_fwiden_masked = false;
// C3 (2026-09-18): the widening integer family `vwadd`/`vwsub`/`vwmul`/`vwmacc` and their unsigned,
// mixed-sign, `.wv` and `.wx` variants, lowered by the LLVM backend (Emit_vchunkwiden) instead of
// the rv32_vwint helper. UNMASKED ONLY. Read by RvvTryLLVMWiden ALONE. Default off.
inline bool rvv_llvm_widen = false;
// C3 (2026-09-18): the narrowing shifts `vnsrl` / `vnsra` lowered by the LLVM backend
// (Emit_vchunknarrowshift) instead of the rv32_vnshift helper. UNMASKED ONLY. `vnclip` is NOT
// covered -- QCG lowers it through the partial-arm node this backend cannot lower, so saturating
// narrowing keeps its helper. Read by RvvTryLLVMNarrowShift ALONE. Default off.
inline bool rvv_llvm_narrow = false;
// C5-FP (2026-09-18): PARTIAL VL for the LLVM/AOT typed FP lane family (`vfadd`/`vfsub`/`vfmul`/
// `vfdiv`). Unlike the integer families a masked store is NOT sufficient: the FP bracket ORs host
// MXCSR sticky flags into the guest fcsr, so an inactive lane's exception would be architecturally
// visible. The operands of inactive lanes are therefore forced to +1.0 before the constrained op --
// +1.0 and not +0.0 because `(+0)/(+0)` raises NV and division IS admitted. See
// RvvNeutralizeInactiveFP. Default off.
inline bool rvv_llvm_fp_partial_vl = false;
// P9: the FP COMPARE family (13.13) at an OBSERVED e32/e64, unmasked vtype with an integer LMUL,
// through a mask-producing node (vchunkfcmpstate) and pure QCG. Its own switch: the destination is a
// MASK register rather than a vector group, so the node has no value output at all, and the admitted
// contract differs from every other FP route (vd must not overlap the sources, and a chunk must
// cover whole mask bytes). Default off. The pre-existing vector-SSA route for vmfgt.vf keeps
// priority wherever it applies; this one only picks up what would otherwise reach the helper.
inline bool rvv_qcg_typed_chunk_fcmp = false;
// P10: the WIDENING FP family, e32 -> e64 add / sub / mul in the .vv .vf .wv .wf forms, at an
// OBSERVED e32 vtype -- masked or not, any tail/mask policy, LMUL mf2/1/2/4 (the destination group
// is 2*LMUL registers, so m8 has no legal encoding). Its own switch because the frame's chunk
// mapping is not one-to-one -- it iterates over DESTINATION chunks and reads a half-width window of
// each narrow source -- and because it needs a node no other route has (vchunkfwidencvt, whose
// window is half its output's width). The widening FMAs and the widening reductions share this
// decode and are NOT admitted. Default off.
inline bool rvv_qcg_typed_chunk_fwiden = false;
// P10b: the WIDENING FMA family -- vfwmacc / vfwnmacc / vfwmsac / vfwnmsac, .vv and .vf, e32 -> e64.
// It shares P10's frame, guard, source conversion and admitted vtype/overlap set, and differs in
// exactly two things, both forced by the operation: vd is READ as the addend before it is written,
// and the lane operation is the existing fused vchunkfma rather than vchunkfalu.
//
// ITS OWN SWITCH, and independent of P10's rather than nested under it, for two reasons that are
// properties and not style: it needs a THIRD host feature (FMA3, which is a separate CPUID bit from
// AVX-512F -- see RvvQcgTypedFmaAdmit), and the evidence for the arithmetic forms was collected with
// P10 alone, so folding these four opcodes into that switch would silently change what that evidence
// covers. Default off.
inline bool rvv_qcg_typed_chunk_fwiden_fma = false;
// AUDIT SWITCH (default off). Bypasses ONLY the two CPUID probes -- AVX-512F and FMA3 -- so that a
// structural test can inspect the emitted shape on a development host that has neither.
//
// IT IS NOT A "RUN THIS ROUTE ANYWAY" SWITCH. Code emitted with it on executes vfmadd213pd, which
// #UDs (SIGILL) on a host without FMA3 or AVX-512F. It is admissible ONLY in a test that allocates
// its code into a std::vector<u8>, never mmaps, never sets PROT_EXEC and never branches into the
// bytes. No measurement arm may set it.
//
// It does NOT relax the emitted architectural guard, does NOT widen the admitted opcode/vtype set,
// and does NOT bypass the RVV_FP_FORCE_SOFT compile-time refusal in RvvQcgTypedFmaAdmit.
inline bool rvv_qcg_typed_chunk_fma_force_emit = false;
// AUDIT SWITCH (default off), vfsqrt's counterpart of the line above and no weaker: code emitted
// with it on executes vsqrtpd under an EVEX mask, which #UDs on a host without AVX-512F.
inline bool rvv_qcg_typed_chunk_fsqrt_force_emit = false;
// AUDIT SWITCH (default off), the compare route's counterpart: emitted code executes a masked EVEX
// vcmpp{s,d} into a k register, which #UDs on a host without AVX-512F.
inline bool rvv_qcg_typed_chunk_fcmp_force_emit = false;
// AUDIT SWITCH (default off): emitted code executes a masked EVEX vcvtps2pd, which #UDs without
// AVX-512F -- and, for the P10b widening FMA forms, a vfmadd231pd, which #UDs without FMA3.
inline bool rvv_qcg_typed_chunk_fwiden_force_emit = false;

// P3.5a: the same typed V512 chunk route for exact unmasked `vmul.vv`
// (vstatechunkload -> vchunkmul -> vstatechunkstore), on its OWN switch.
//
// A separate flag rather than widening rvv_qcg_typed_chunk above, for one reason that is not
// taste: every accepted C2/C3 evidence arm was produced with `--rvv-qcg-typed-chunk 1`, and
// silently making that flag admit a second opcode would retroactively change what those accepted
// arms mean. With two flags, the vadd arms are bit-identical to their accepted form and the mul
// route is independently ablatable, which is what the C3.0 measurement contract asks of any new
// admission.
//
// The admitted shape is exactly the shape RvvQcgTypedMulChunkAdmit tests, and it is narrower than
// the add's in one respect that matters: SEW must be 4. x86 has no packed byte multiply and puts
// the 16/64-bit forms in AVX-512 subsets this route does not probe for, so admitting another width
// would mean emitting an instruction the feature test never cleared. Default off.
inline bool rvv_qcg_typed_chunk_mul = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the mul route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if actually run. It does
// not relax the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_mul_force_emit = false;

// S2.1: the same typed V512 chunk route for exact unmasked `vsub.vv`
// (vstatechunkload -> vchunksub -> vstatechunkstore), on its OWN switch.
//
// A third flag rather than widening either of the two above, for exactly the reason the mul got its
// own: every accepted C2/C3/C5/S2.0 evidence arm was produced with a specific set of these flags,
// and silently making one of them admit another opcode would retroactively change what those arms
// mean. Three flags keep the vadd and vmul arms bit-identical to their accepted form and make the
// sub route independently ablatable.
//
// The admitted shape is exactly the shape RvvQcgTypedSubChunkAdmit tests -- e32, LMUL=1, unmasked,
// vstart=0, vl=VLMAX, VLEN 512 or 1024, pure QCG, AVX-512F -- i.e. the add's shape narrowed to
// SEW=4. The host instruction (vpsubd) is AVX512F exactly as vpaddd is, so nothing here depends on
// a feature bit the probe does not clear. Default off.
inline bool rvv_qcg_typed_chunk_sub = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the sub route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if actually run. It does not
// relax the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_sub_force_emit = false;

// S2.2: the same typed V512 chunk route for exact unmasked `vxor.vv`
// (vstatechunkload -> vchunkxor -> vstatechunkstore), on its OWN switch.
//
// A fourth flag rather than widening any of the three above, for the reason each of them got its
// own: every accepted C2/C3/C5/S2.0/S2.1 evidence arm was produced with a specific set of these
// flags, and silently making one of them admit another opcode would retroactively change what those
// arms mean. Four flags keep the vadd, vmul and vsub arms bit-identical to their accepted form and
// make the xor route independently ablatable.
//
// The admitted shape is exactly the shape RvvQcgTypedXorChunkAdmit tests -- e32, LMUL=1, unmasked,
// vstart=0, vl=VLMAX, VLEN 512 or 1024, pure QCG, AVX-512F. The host instruction (vpxord) is
// AVX512F exactly as vpaddd/vpsubd are, so nothing here depends on a feature bit the probe does not
// clear.
//
// ONE THING IS DIFFERENT FROM ITS THREE ARITHMETIC SIBLINGS, and it is a reason for MORE caution,
// not less. `vxor.vv` originally decoded out of the SAME generic `vialu` family as `vand.vv` and
// `vor.vv`, at adjacent funct6 values (VF6_VAND=0b001001, VF6_VOR=0b001010, VF6_VXOR=0b001011). A
// one-bit slip in the decoder predicate would silently route a guest AND or OR through an XOR
// emitter -- structurally perfect, numerically wrong. That risk is what the route's decoder sweep
// and the frozen suite's untouched `kern_and` arm exist to close. (Since S2.3, 0b001010 has its own
// op and its own switch below; with only THIS switch on, `vor.vv` still keeps the helper, and the
// two routes' decoder sweeps each require exactly one encoding to reach their own op.) Default off.
inline bool rvv_qcg_typed_chunk_xor = false;

// P7N-B. TYPED chunk lowering for exact unmasked `vsll.vi` / `vsrl.vi`, and the vector-run member
// rows that go with them. Default OFF like every other route switch, and INDEPENDENTLY ablatable
// for the reason the five `.vv` routes are: an accepted evidence arm for any of them must keep
// meaning what it meant.
//
// ONE SWITCH FOR BOTH SHIFTS, and that is a deliberate departure from "one switch per opcode".
// The two are not independently useful: the only way to express a ROTATE in RVV without Zvbb is
// `vsll` + `vsrl` + `vor`, so admitting one without the other would leave every rotate still
// broken by a helper call and would produce an evidence arm that answers no question anyone has.
// They share one shape predicate, one body shape and one host encoding form; what they do not
// share is the host opcode, which is why they are still two QIR nodes and two decode splits.
//
// vsra IS NOT IN SCOPE. It is an arithmetic shift needing vpsrad, a different host instruction
// with a different sign behaviour, and nothing in this checkpoint's evidence exercises it.
inline bool rvv_qcg_typed_chunk_shift = false;
// Audit-only bypass of the host CPUID probes, on exactly the terms the other routes' force-emit
// switches use: it lets a machine WITHOUT AVX-512 build and inspect the emitted bytes, and it must
// never be set on an arm that EXECUTES them.
inline bool rvv_qcg_typed_chunk_shift_force_emit = false;

// P7N-D. THE HOST CHUNK GEOMETRY, DERIVED FROM VLEN INSTEAD OF FIXED AT 512 BITS.
//
// It is not a new route and it admits no new opcode, SEW, LMUL or mask form. It replaces ONE rule
// -- "a guest vector register must be a whole number of 512-bit host chunks", which is
// RvvGenericChunkShapeAdmit's `vlen % 512` and the reason every route but vadd.vv and the two
// shifts REFUSES VLEN 128 and 256 -- with the rule those three already use:
//
//     chunk width = min(VLEN/8, 64) bytes      chunk count = (VLEN/8) / width
//
// so VLEN 128/256/512/1024 lower to one xmm, one ymm, one zmm and two zmm chunks. No VLEN is
// enumerated anywhere in it, and AT EVERY VLEN >= 512 IT RETURNS EXACTLY WHAT THE OLD RULE
// RETURNED ({64, k}); the switch can therefore only change what happens at 128 and 256. That is
// why the 512/1024 arms of an accepted evidence set cannot move, and the focused test asserts the
// two rules agree at every VLEN the old one admitted rather than leaving it as a claim.
//
// DEFAULT OFF, like every route switch, so the before/after ablation exists and so no accepted arm
// silently changes meaning.
//
// PURE QCG ONLY. The LLVM/AOT backend keeps the whole-512-chunk rule at every width: its narrow
// lowering evidence covers vadd.vv alone (P4), and widening it here would ship an admission this
// checkpoint produced no artifact for. RvvSSAEnabled() also refuses VLEN < 512 on its own, so this
// is belt and braces in the fail-closed direction.
//
// WHICH ROUTES IT REACHES, and the omissions are deliberate rather than an oversight:
//   * `vxor.vv`, `vor.vv`  -- measured dynamic blockers of the P7N ChaCha20 arm at VLEN 128/256;
//   * `vse32.v`            -- likewise;
//   * `vsetvli`            -- likewise, and it emits no vector instruction at all, so it is
//                             admitted from the geometry without the narrow-EVEX host probe.
// `vsub.vv`, `vmul.vv`, `vand.vv` and `vle32.v` are NOT reached. Every one of them has zero
// dynamic executions in this workload at every width, so widening them would ship an admission
// with no dynamic evidence behind it; they keep their existing helper at 128/256 and the focused
// test proves they still do.
inline bool rvv_qcg_narrow_chunk_width = false;
// Audit-only bypass of the AVX512VL probe the narrow (xmm/ymm) forms carry, on exactly the terms
// every other force-emit switch in this file uses: it lets a host WITHOUT AVX-512 build and
// disassemble the emitted bytes, and it must never be set on an arm that EXECUTES them.
inline bool rvv_qcg_narrow_chunk_width_force_emit = false;

// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the xor route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax
// the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_xor_force_emit = false;

// S2.3: the same typed V512 chunk route for exact unmasked `vor.vv`
// (vstatechunkload -> vchunkor -> vstatechunkstore), on its OWN switch.
//
// A fifth flag rather than widening any of the four above, for the reason each of them got its own:
// every accepted C2/C3/C5/S2.0/S2.1/S2.2 evidence arm was produced with a specific set of these
// flags, and silently making one of them admit another opcode would retroactively change what those
// arms mean. Five flags keep the vadd, vmul, vsub and vxor arms bit-identical to their accepted form
// and make the or route independently ablatable.
//
// The admitted shape is exactly the shape RvvQcgTypedOrChunkAdmit tests -- e32, LMUL=1, unmasked,
// vstart=0, vl=VLMAX, VLEN 512 or 1024, pure QCG, AVX-512F. The host instruction (vpord) is AVX512F
// exactly as vpaddd/vpsubd/vpxord are, so nothing here depends on a feature bit the probe does not
// clear.
//
// ITS HAZARD IS NOT THE XOR'S, AND IT IS THE HARDER OF THE TWO. When the xor route landed, both of
// its funct6 neighbours (VF6_VAND=0b001001, VF6_VOR=0b001010) were ordinary helper-path members of
// the generic `vialu` family, so a one-bit decoder slip could only give a route to a shape that had
// none. `vor.vv` sits BETWEEN vand.vv below it and the ACCEPTED vxor.vv route above it, so a slip
// upward would not add a wrong route -- it would take the accepted S2.2 route away from vxor.vv and
// compute an OR for a guest XOR. Emitting `vpxord` instead of `vpord` inside this route's own
// emitter has the same shape of consequence one line further down. The route's exhaustive decoder
// sweep (which gates all five splits at once), the untouched `kern_and`/`kern_xor` arms of the
// frozen suite and the emitter mutation gate exist to close both directions. (Since S2.4, vand.vv
// has its own op and its own switch below, so the downward direction is now accepted territory too
// and `kern_and` is no longer a helper-path control for anything; with only THIS switch on, vand.vv
// still keeps the helper.) Default off.
inline bool rvv_qcg_typed_chunk_or = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the or route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax
// the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_or_force_emit = false;

// S2.4: the same typed V512 chunk route for exact unmasked `vand.vv`
// (vstatechunkload -> vchunkand -> vstatechunkstore), on its OWN switch.
//
// A sixth flag rather than widening any of the five above, for the reason each of them got its own:
// every accepted C2/C3/C5/S2.0/S2.1/S2.2/S2.3 evidence arm was produced with a specific set of these
// flags, and silently making one of them admit another opcode would retroactively change what those
// arms mean. Six flags keep the vadd, vmul, vsub, vxor and vor arms bit-identical to their accepted
// form and make the and route independently ablatable.
//
// The admitted shape is exactly the shape RvvQcgTypedAndChunkAdmit tests -- e32, LMUL=1, unmasked,
// vstart=0, vl=VLMAX, VLEN 512 or 1024, pure QCG, AVX-512F. The host instruction (vpandd) is AVX512F
// exactly as vpaddd/vpsubd/vpxord/vpord are, so nothing here depends on a feature bit the probe does
// not clear.
//
// ITS HAZARD IS THE OR'S, WITH THE REMAINING ESCAPE HATCH CLOSED. `vor.vv` sat between an unrouted
// sibling below and an accepted route above, so one of its two slip directions still had a
// helper-path control to fall back on. `vand.vv` (VF6_VAND=0b001001) is the LAST of the three
// adjacent bitwise values: VF6_VOR=0b001010 and VF6_VXOR=0b001011 above it are BOTH accepted routes,
// so an upward slip can only REMOVE accepted evidence, and 0b001000 below it is not an OPIVV
// encoding at all, so a downward slip fails closed to `ill`. Emitting `vpord` or `vpxord` instead of
// `vpandd` inside this route's own emitter has the same shape of consequence one and two identifiers
// further down, and would additionally mimic a route that already has accepted evidence.
//
// A SECOND, SHARPER DECODER TRAP IS SPECIFIC TO THIS FUNCT6 VALUE. VF6_VAADD (OPMVV) is ALSO
// 0b001001, so `vaadd.vv` differs from `vand.vv` in the funct3 group and nothing else. A predicate
// that compared funct6 without its group would capture an averaging add. The route's exhaustive
// decoder sweep (which gates all six splits at once), its named `vaadd.vv` negative row, the
// untouched `kern_or`/`kern_xor` arms of the frozen suite and the emitter mutation gate exist to
// close all of these. Default off.
inline bool rvv_qcg_typed_chunk_and = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the and route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax
// the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_and_force_emit = false;

// S2.6: the typed V512 chunk route for exact unmasked unit-stride `vle32.v`
// (vchunkload -> vstatechunkstore), on its OWN switch.
//
// A seventh flag, for the reason each of the six above got its own: every accepted evidence arm was
// produced with a specific set of these flags, and widening one of them to admit another opcode
// would retroactively change what those arms mean. This one carries more weight than the previous
// six, because this is the first route whose opcode is a MEMORY opcode: an arm produced with it on
// is the first in which the frozen mixed loop's guest-memory reads are not helper calls, and that
// difference must remain attributable to one switch.
//
// The admitted shape is exactly what RvvQcgTypedVleChunkAdmit tests -- EEW=32 from the ENCODING,
// SEW=32 and LMUL=1 from vtype (so EMUL=1), unmasked, unit-stride, vstart=0, vl=VLMAX, VLEN 512 or
// 1024, pure QCG, non-Ref lowering, AVX-512F, and a non-x0 base register. Everything else keeps the
// unchanged `rv32_vle` helper.
//
// ITS DECODER HAZARD HAS NO ANALOGUE IN THE SIX ALU ROUTES, and it is the reason this route's
// admission predicate is the only one that re-reads instruction fields the decoder already looked
// at. rv32_decode.h gives every ALU route its own Op for the exact unmasked encoding, so `vm == 1`
// and the operation came for free. It does NOT do that here: masked `vle32.v` and `vle8/16/64.v`
// all reach the SAME Op::_vle. A predicate that forgot either test would turn a masked load -- whose
// inactive elements must stay undisturbed -- or a narrower EEW into a 64-byte block move.
//
// ITS SECOND HAZARD IS THE ADDRESS, and it is closed in the QIR op rather than here: the second
// chunk of a VLEN=1024 register is addressed with a HOST-pointer displacement, which is what makes
// this route agree with the `rvv_chunked` helper arm on the top 64 guest addresses instead of
// wrapping modulo 2^32 (S2.5 section 4.3; see qir.h InstVChunkLoad). Default off.
inline bool rvv_qcg_typed_chunk_vle = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the vle route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax
// the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_vle_force_emit = false;

// S2.7: the typed V512 chunk route for exact unmasked unit-stride `vse32.v`
// (vstatechunkload -> vchunkstore), on its OWN switch.
//
// An eighth flag, for the reason each of the seven above got its own: every accepted evidence arm
// was produced with a specific set of these flags, and widening one of them to admit another opcode
// would retroactively change what those arms mean. Keeping it separate from the vle switch matters
// more than any earlier separation, because the two are the only routes that touch guest memory and
// they touch it in OPPOSITE directions -- an arm that could not distinguish them could not attribute
// a wrong guest-memory byte to a read route or a write route.
//
// The admitted shape is exactly what RvvQcgTypedVseChunkAdmit tests -- EEW=32 from the ENCODING,
// SEW=32 and LMUL=1 from vtype (so EMUL=1), unmasked, unit-stride, vstart=0, vl=VLMAX, VLEN 512 or
// 1024, pure QCG, non-Ref lowering, AVX-512F, and a non-x0 base register. Everything else keeps the
// unchanged `rv32_vse` helper.
//
// ITS DECODER HAZARD IS THE LOAD'S. rv32_decode.h routes MASKED unit-stride stores and every
// supported EEW (8/16/32/64) to the same Op::_vse, so `vm` and the width field are this route's own
// obligation. A predicate that forgot either would turn a masked store -- which must leave inactive
// elements of guest MEMORY untouched -- or a narrower EEW into a 64-byte block write.
//
// ITS BLAST RADIUS IS STRICTLY LARGER THAN THE LOAD'S, and that is the whole reason it was ordered
// after it (S2.5 section 5C). A wrong `vle` corrupts an architectural vector register, which the
// frozen guest's own self-check observes. A wrong `vse` writes GUEST MEMORY: a wrong address, a
// wrong length or a wrong direction overwrites another buffer, the stack or a code page, and rvdbt
// performs no translation invalidation on guest stores. The address form is therefore closed
// structurally in the QIR op -- chunk 1 is a HOST-pointer displacement, so it cannot wrap modulo
// 2^32 and write to the bottom of the address space (see qir.h InstVChunkStore) -- rather than being
// excluded by a runtime guard. Default off.
inline bool rvv_qcg_typed_chunk_vse = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the vse route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax
// the architectural guard and it does not widen the admitted case.
inline bool rvv_qcg_typed_chunk_vse_force_emit = false;

// Z3 (2026-09-12, --rvv-qcg-typed-chunk-vlse-gather, default off): the AVX-512 gather chunk for
// STRIDED LOADS (`vlse32.v`, mop=10, EEW=32), inside the frame the integer-family memory route
// already builds. QCG only.
//
// WHAT IT REPLACES, AND WHY IT IS NOT ANOTHER CHUNK ROUTE. `vlse32.v` is already native: it is NOT
// a helper call. RvvTryIntegerFamily admits it into a VTypeInteger frame whose body is
// Emit_vmemorynative's ELEMENT LOOP -- eighteen host instructions per element, of which exactly one
// moves data and seventeen recompute the guest address, the VRF offset, the restart index, the
// address-space-top split and the loop. This switch adds ONE alternative body for that node, and
// leaves the element loop in the same emitted region as its fallback. Nothing else about the frame,
// the guard, the route, the QIR or any other opcode changes. See
// experiments/2026-08-30-prof-hung-teacher-closure/VLSE32_GATHER_LOWERING_DESIGN_Z1_20260912.md.
//
// THE ADMITTED SHAPE, all of it decidable at translation time: a LOAD (not vsse), mode == 1
// (scalar stride: mop == 10, so neither unit-stride nor indexed), UNMASKED, nf == 1 (a strided
// SEGMENT load is RvvTrySegmentMemory's and keeps its element loop), EEW == 32 (x86 has no
// byte/word gather and the EEW-64 form is a different instruction, VPGATHERQQ/VPGATHERDQ, which
// this switch deliberately does not admit), VLEN >= 512 so the chunk is a full 64-byte ZMM, a
// translation-time VLMAX recorded on the node, and a host with AVX-512F + BMI2. EVERY other strided
// load -- every EEW, every masked form, every segment form, VLEN 128/256 -- keeps the element loop
// byte-for-byte. With the switch off the emitted bytes are the pre-Z3 bytes exactly.
//
// TWO RUNTIME CONDITIONS ALSO KEEP THE ELEMENT LOOP, and they are the reason the loop is emitted
// after the fast path rather than replaced by it:
//
//   * vstart != 0. The element loop starts at vstart and publishes vstart before every access, so
//     a host fault reports the exact restart index. One gather is sixteen accesses and cannot do
//     that. The fast path therefore runs only from a zero vstart, which is checked once, at run
//     time, against the live CPUState -- not assumed from the frame's guard, which is VTypeInteger
//     and does NOT check vstart.
//   * An ACTIVE lane whose guest address exceeds 0xFFFFFFFC. RV32 wraps such an access modulo 2^32
//     and the element loop assembles it byte by byte; a gather cannot wrap, and the host bytes past
//     the end of the 4 GiB reservation are RVDBT'S OWN HEAP (ukernel.cpp hints host allocations at
//     mmu::base + ASPACE_SIZE). This is a memory-safety condition, not a rounding one. It is tested
//     per chunk, with a signed compare against the same 0xFFFFFFFC the element loop splits on, and
//     the branch is emitted BEFORE that chunk's masked store -- so a chunk that is refused has
//     written nothing and the element loop, which is a pure function of guest memory, reruns the
//     whole instruction from element zero and produces exactly what it would have produced alone.
//     Neither exit touches rvv_direct_fallbacks: this is a WITHIN-NODE fallback, not a frame
//     fallback, so `guard_fallbacks == 0` keeps meaning exactly what it meant before Z3.
//
// THE ONE ACCEPTED SEMANTIC DIVERGENCE IS DIAGNOSTIC, and it is not hidden: on a host fault the
// published vstart is 0 rather than the faulting element index. It is unobservable to the guest
// because rvdbt has no recoverable memory-fault trap and no guest signal delivery -- a guest load
// fault ends the process through dbt_sigaction_memory -- so only DumpTrace's restart index
// degrades. si_addr and the guest ip are unaffected. The gather is in one respect STRICTER than the
// loop: it faults before writing any part of the destination, where the loop leaves a partially
// written VRF.
//
// SIGNED VSIB INDICES ARE HANDLED BY A BIAS, NOT BY AN EXCLUSION. VPGATHERDD sign-extends each dword
// index, so a guest address >= 2^31 would address BELOW mmu::base. The emitted form adds 2^31 to the
// scalar base and subtracts it from the host base, which is exact for the whole 4 GiB space and
// costs two instructions per instruction, not per lane. See the route's comment in qemit.cpp.
inline bool rvv_qcg_typed_chunk_vlse_gather = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_force_emit above, for
// the vlse gather route. Bypasses ONLY the host AVX-512F/BMI2 feature test so the emitted shape can
// be disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax
// the architectural guard, does not widen the admitted shape, and does not remove either runtime
// condition above.
inline bool rvv_qcg_typed_chunk_vlse_gather_force_emit = false;
// Z4B DIAGNOSTIC (2026-09-12, --rvv-qcg-typed-chunk-vlse-gather-census, default off). NOT a
// lowering, not an admission change, not a threshold: one `inc` at each of the gather body's two
// outcomes, into CPUState::rvv_vlse_gather_fast / rvv_vlse_gather_fallback.
//
// THE QUESTION IT EXISTS FOR. The route's two runtime exits both jump into the element loop kept
// INSIDE the same node, so they cross no frame fallback arm and touch no existing counter. Z4 could
// therefore prove the gather was EMITTED (4 vpgatherdd per TB at VLEN 512, 8 at 1024) and could
// DERIVE that it should always be taken, but the direct observation was absent -- and Z4 recorded
// that any timing interpretation which assumes the fast path runs every time must close that gap
// with a real observation first. This switch is that observation and nothing more.
//
// THE COUNTERS ARE NOT REDUNDANT WITH ANY EXISTING ONE. `rvv_direct_hits` counts the typed FRAME's
// join (every typed frame, globally); `rvv_direct_fallbacks` counts the frame's guard-miss arm;
// `RVV_ROUTE handler_calls` counts C++ helper entries. None of the three can see an edge that is
// internal to one node's body.
//
// EVIDENCE-ONLY, AND STRUCTURALLY SO. Arming it adds two instructions to the emitted code of every
// admitted vlse32.v site, so an armed execution is by construction not an arm of a timing campaign
// -- the same discipline --rvv-run-frame-census carries. With it off, the emitter runs the same
// code path and emits nothing, so a default-off build's bytes are the Z3 bytes for gather off AND
// gather on; the focused test rvv_vlse_gather_census_test.cpp checks exactly that, per cell.
//
// Requires --rvv-qcg-typed-chunk-vlse-gather=1 to have anything to count; with the route off it is
// inert because the emitter returns before reaching either increment.
inline bool rvv_qcg_typed_chunk_vlse_gather_census = false;

// A13 (2026-09-05, --rvv-qcg-typed-chunk-mem-e64, default off). TWO things, both QCG-only, both
// stated here because the switch is the ablation unit:
//
//   1. The unit-stride unmasked EEW=64 pair (`vle64.v`/`vse64.v`) is admitted by the SAME shape
//      rule the EEW=32 pair uses (RvvMemChunkShape: the guest register is a whole number of host
//      chunks, chunk = min(VLEN/8, 64) bytes, count = (VLEN/8)/chunk), under the same vtype
//      conditions (SEW == EEW so EMUL = LMUL = 1, vta/vma free, unmasked, vstart 0, vl == VLMAX)
//      and the same frame (k vchunkload + k vstatechunkstore, or the mirror). Byte-wise the two
//      widths move the identical window: vl*EEW = VLMAX*SEW = VLEN/8 bytes. The A11 e64 chains
//      called these helpers 768..8192 times per rep; the vle/vse switches above still gate both.
//   2. (A13-FIX: NO LONGER TIED TO THIS SWITCH.) THE BASE-RANGE GUARD
//      (InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit) is now on EVERY QCG
//      unit-stride frame the vle/vse routes build, switch on or off, EEW=32 included, because it
//      is the frame's correctness contract and not an e64 feature. The
//      frame addresses guest memory as HOST pointers (R_MEMBASE + zero-extended base + chunk
//      displacement), so a base within VLEN/8 bytes of 2^32 would read or WRITE past the end of
//      the 4 GiB guest reservation -- straight into whatever host mapping follows it (mmu.cpp
//      hints host allocations at base + ASPACE_SIZE). RV32 semantics wrap the effective address
//      modulo 2^32 instead, which lands on the never-mapped low pages and faults. The guard
//      (`base <= 2^32 - VLEN/8`, one load/compare/branch per frame) sends such a base to the
//      helper. THE HELPER HAS THE SAME OVER-ACCESS (rvv_chunked::copy_chunked walks host
//      pointers) -- A13-FIX closed it: rv32_vector_lower.h's guest_span_wraps /
//      guest_*_wrapped give the scalar reference, the chunked helper and the masked variants one
//      byte-granular mod-2^32 address rule, so a guard-miss base now lands on the never-mapped low
//      pages and terminates through the ordinary guest fault instead of touching host memory.
//      With this switch off, every frame is the A12 frame PLUS the guard (three instructions);
//      the pre-A13-FIX byte-identical form was not preserved because it carried the over-access.
//
// What stays with the helper, by the guard or by admission: vl < VLMAX (the helper moves exactly
// vl*EEW bytes; the direct frame never runs, so no byte past vl is touched), vl == 0, masked
// forms, EEW != SEW (EMUL != 1), LMUL != 1, nonzero vstart, x0 base, --rvv-lowering 0,
// --rvv-verify, the LLVM/AOT backend (its gate is untouched and refuses EEW=64).
inline bool rvv_qcg_typed_chunk_mem_e64 = false;

// Native-2 (2026-08-30, --rvv-qcg-whole-reg, default off): pure-QCG direct lowering for the
// whole-register transfer pair `vl<nf>re<eew>.v` / `vs<nf>r.v`. Clang emits these for every
// strip-mined load and store because it configures vl at VLMAX, so on the QCG path they were the
// largest remaining helper population in the frozen workload. The frame is the vle/vse chunk frame
// with a vtype-INDEPENDENT guard (`vlenb == VLEN/8 && vstart == 0`): RVV 1.0 defines these to move
// whole registers irrespective of SEW, LMUL and vl and to stay valid under vill, so a vtype guard
// would make the route's coverage a property of the surrounding code rather than of the
// instruction. Chunk count and displacements are nregs and the runtime VLEN through the shared
// RvvHostChunkGeometry (A17: 16/32-byte chunks at VLEN 128/256, 64-byte at 512/1024); illegal
// register groups, masked or non-whole-register encodings, a VLEN that is not a whole number of
// host chunks, a host without AVX-512(F, and VL for the narrow chunks), more than four chunks and
// a nonzero vstart all keep the unchanged rv32_vlNre / rv32_vsNr helper. QCG only -- the LLVM/AOT backend's
// existing typed vector-SSA route for these opcodes is not touched.
inline bool rvv_qcg_whole_reg = false;
// A14 AUDIT SWITCH (default off), the counterpart of the other *_force_emit switches: bypasses ONLY
// the host AVX-512F probe of the whole-register route so its frame can be inspected on a host that
// cannot execute it. Does not relax the guard or widen the admitted case.
inline bool rvv_qcg_whole_reg_force_emit = false;

// Native-3 (2026-08-30, --rvv-qcg-vx-mulacc, default off): direct lowering for the SCALAR-operand
// integer multiply pair `vmul.vx` and `vmacc.vx`, unmasked, e32, LMUL=1, full VL -- in BOTH
// backends, unlike Native-2. Clang emits the `.vx` forms whenever one multiplicand is a loop
// invariant, which is what the frozen PolyBench gemm kernel's inner statement is, and T5b-1 measured
// them as the one hot family with no typed lowering in either backend.
//
// WHAT IS NEW HERE IS THE SCALAR, NOT THE ARITHMETIC. `vmul.vx vd, vs2, rs1` is
// `vd[i] = vs2[i] * x[rs1]` and `vmacc.vx vd, rs1, vs2` is `vd[i] = vd[i] + vs2[i] * x[rs1]`, both
// modulo 2^SEW. So the frame is the accepted `.vv` chunk frame with its vs1 chunk-load replaced by
// ONE `vchunkbroadcast` -- a splat of the guest GPR word read from CPUState -- and, for the
// accumulate form, one extra chunk-add whose other input is vd read BEFORE any chunk is written.
//
// The envelope is the `.vv` routes': vtype pinned to e32/m1/ta/ma with vl == VLMAX and vstart == 0
// proved by the frame's own runtime guard. Every other funct6 of the OPMVX multiply family
// (vmulh/vmulhu/vmulhsu, the whole divide/remainder set, vnmsac, vmadd, vnmsub), the masked forms,
// other SEW, LMUL != 1, a partial vl, a nonzero vstart and a host without AVX-512 all keep the
// unchanged rv32_vimul helper.
//
// A21 (2026-09-06): the pure-QCG arm's WIDTH is the shared RvvRouteChunkShape rule, the same one
// vadd/vsub/vmul.vv, and/or/xor, the shifts, vmv, vadd.vx and the unit-stride/whole-register
// transfers use: 64-byte zmm chunks at VLEN >= 512 (k = VLEN/512, as vmul.vv) and, with
// --rvv-qcg-narrow-chunk-width on and AVX512VL present, one 16-/32-byte xmm/ymm chunk at VLEN
// 128/256. Before A21 the route enumerated {512, 1024} and GEMM at 128/256 kept 3.3e8 / 1.6e8
// helper calls for these two words alone (A17 §2.3). The LLVM arm is unchanged (512/1024 only).
inline bool rvv_qcg_vx_mulacc = false;
// AUDIT SWITCH (default off), the exact counterpart of rvv_qcg_typed_chunk_mul_force_emit above,
// for the Native-3 route. Bypasses ONLY the host AVX-512F feature test so the emitted shape can be
// disassembled on a host that cannot execute it; such code will SIGILL if run. It does not relax the
// architectural guard and it does not widen the admitted case. It has no effect on the LLVM arm,
// which has no host-feature probe to bypass.
inline bool rvv_qcg_vx_mulacc_force_emit = false;

// A2 (2026-09-05, --rvv-qcg-typed-chunk-vmv, default off): pure-QCG direct lowering for the
// scalar-to-vector move `vmv.v.x vd, rs1` (OP-V, OPIVX, funct6 010111, vm=1, vs2=v0 by encoding):
// `vd[i] = x[rs1]` for i in [0, vl). The frame is the accepted typed-chunk guard, ONE
// `vchunkbroadcast` of the guest GPR word from its CPUState slot (x0's slot is kept zero by the
// runtime, so rs1 == x0 splats 0 exactly as the helper does) and one `vstatechunkstore` per host
// chunk into vd's window. Width comes from the same RvvRouteChunkShape rule the integer ALU family
// uses, so VLEN 128/256/512/1024 emit ONE vpbroadcastd xmm/ymm/zmm/2xzmm. SEW=32, LMUL=1, unmasked
// only; vmerge.vxm (vm=0), vmv.v.v, vmv.v.i, other SEW, LMUL != 1 keep the unchanged rv32_vmerge
// helper. Guarded at run time on vtype/vl/vstart: a partial vl or a nonzero vstart runs the
// existing helper unchanged (which, for vstart != 0, keeps rvdbt's documented illegal-instruction
// behaviour). QCG only; the LLVM/AOT arm's rvvmerge lowering is untouched.
inline bool rvv_qcg_typed_chunk_vmv = false;
// AUDIT SWITCH (default off): bypass ONLY the host AVX-512F feature test for the vmv.v.x QCG path.
inline bool rvv_qcg_typed_chunk_vmv_force_emit = false;

// A6 (2026-09-05, --rvv-qcg-typed-chunk-vadd-scalar, default off): pure-QCG direct lowering for
// the SCALAR- and IMMEDIATE-source forms of the integer add, `vadd.vx vd, vs2, rs1` (OPIVX) and
// `vadd.vi vd, vs2, simm5` (OPIVI), unmasked, e32, LMUL=1. Same chunk shape (RvvVaddChunkShape),
// same lane operation (vchunkadd) and same guard as the accepted vadd.vv route; the ONLY difference
// is source 1: ONE `vchunkbroadcast` per frame -- of x[rs1]'s CPUState word (x0's slot is 0) or of
// the sign-extended 5-bit immediate materialised in the fixed scratch GPR -- consumed by every
// chunk's add. Partial vl (0 <= vl < VLMAX) takes the A3 bounded arm with the same broadcast
// source; any other mismatch (vstart != 0, other vtype) runs the pre-existing rv32_vialu helper
// unchanged. NOT a run member this round: the run classifier has no row for these encodings, so
// they remain a run cut exactly as they were as helpers. QCG only; LLVM/AOT untouched.
inline bool rvv_qcg_typed_chunk_vadd_scalar = false;
// AUDIT SWITCH (default off): bypass ONLY the host AVX-512F feature test for that path.
inline bool rvv_qcg_typed_chunk_vadd_scalar_force_emit = false;

// A3 (2026-09-05, --rvv-qcg-partial-vl, default off): PARTIAL-vl direct execution for the typed
// integer element-wise .vv family (add/sub/mul/xor/or/and, e32, LMUL=1, unmasked, vstart=0).
// Every typed frame (single instruction or vector run) whose members are ALL of that family gets a
// SECOND body: the guard keeps the full-vl fast arm byte-for-byte (vl == VLMAX jumps straight into
// the unchanged body), and 0 <= vl < VLMAX now jumps to a partial arm instead of the helper. The
// partial arm computes one AVX-512 opmask per host chunk from vec.vl ONCE (vchunkmaskset), then
// executes the members in guest order as load-compute-merge-store: sources and the OLD vd chunk are
// read from CPUState, the unmasked lane op runs, and `vpblendmd d{k}, old, tmp` keeps every
// inactive lane at the old vd value (tail-UNDISTURBED, which is also a legal tail-agnostic result).
// vl == 0 therefore writes vd back unchanged. Masks are recomputed per frame from the live vl, so
// one translation serves full and partial strips alike. Frames with any other member (shifts, FP,
// .vx forms) keep the old guard and helper fallback. Costs: the frame's code size roughly doubles;
// the full-vl arm gains ONE branch (`je` on vl == VLMAX) and nothing else.
inline bool rvv_qcg_partial_vl = false;

// A12 (2026-09-05, default off). ONE active-element mask per host chunk per FP typed frame, shared
// by every vfalu/vfma lane op of that chunk, instead of the per-op prologue (vl load, clamp, bzhi,
// kmovw) Emit_vchunkfalu/Emit_vchunkfma re-derive for every lane op.
//
// THE INVARIANT IT RELIES ON, stated so it can be checked rather than assumed: inside one typed
// frame's hit arm nothing writes vec.vl or vec.vtype. The guard pins both on entry; every body
// node (vstatechunkload/store, vchunkfbroadcast, vchunkdep, the lane ops, the FP bracket) reads or
// writes vreg windows, MXCSR or fcsr only; rvvsetvl and every helper call sit outside the frame
// (Emit_mov and the run former both refuse to place one inside). So clamp(vl - chunk*lanes, 0,
// lanes) is the same value at every lane op of the frame, and computing it once is exact.
//
// THE MASK-REGISTER CONTRACT. The producer is the existing A3 node vchunkmaskset (k(1+chunk) :=
// active lanes of chunk c), emitted once per chunk right after rvvqcgfpbegin, and each consumer
// names its register explicitly (InstVChunkFALU/FMA::kmask == 1 + chunk); the emitter never infers
// a mask from an earlier opcode. x86 has seven writable opmasks k1..k7 (k0 = "no mask"). The FP
// epilogue needs ONE scratch mask (NaN detection, then the A4 all-ones tail), which with sharing is
// k7 -- never k2, because k2 is chunk 1's resident mask. Hence the frame may share only when its
// chunk count is at most 6 (k1..k6 resident, k7 scratch): a frame with more chunks, or a frame whose
// element width is decided at run time (the two-vtype vfadd.vv frame, sew_bytes == 0, whose lane
// count is not a translation-time constant), keeps the per-op prologue unchanged. No frame, run,
// guard, admission or tier decision is changed; semantics (active lanes, tail, NaN
// canonicalisation, fflags, vl == 0) are the A4/A9 ones, verified by the same oracles.
inline bool rvv_qcg_fp_shared_mask = false;
// The derived bound above: seven writable opmasks, minus the one scratch the epilogue needs.
inline constexpr unsigned rvv_qcg_fp_shared_mask_max_chunks = 6;

// S1-2A (2026-09-08, --rvv-qcg-active-vl-bound, default off). STOP EXECUTING CHUNKS THAT LIE
// ENTIRELY IN THE TAIL.
//
// A typed FP frame materialises the WHOLE register group: its chunk count is
// `emul_group_regs(LMUL) * (VLEN/512)` and `vl` appears nowhere in it. A guest that configures a
// short AVL therefore pays for every chunk of the group even though only the first few hold active
// elements -- the frame computes a lane mask, loads both sources, runs an EVEX-masked lane
// operation under an all-zero opmask, and issues a masked store that writes nothing.
//
// With this on, the single-instruction FP frames -- the vfalu route (vfadd/vfsub/vfmul/vfdiv/
// vfmin/vfmax/vfsgnj* and the two reversed forms) and, since S1-2D, the vfma route (the six fused
// multiply-add funct6 values, `.vv` and `.vf`) -- are emitted chunk-major and each chunk is
// preceded by one `vchunkactive` node, which compares the LIVE vec.vl against that chunk's first
// element index and leaves the body when the chunk starts at or above it. Because that index is
// strictly increasing, an inactive chunk is always a SUFFIX and one forward branch retires all of
// them; the branch lands inside the FP bracket, so the MXCSR/fflags epilogue and `vstart = 0` still
// run. The active mask is NOT the test: with `vstart > 0` a LEADING chunk's mask is zero too, so a
// mask-based test would skip live work. Prestart chunks keep running under their zero mask.
//
// WHAT STAYS THE SAME, AND WHAT THE FRAME GAINS. Unchanged: the admission decision, the frame's
// guard KIND and the guard code it emits, the fallback arm, and each chunk's existing guarded body
// (mask derivation, load, lane op, masked store) together with its tail, masked and architectural
// vstart behaviour. NOT unchanged, and this is a shape change, not a no-op: a bounded frame emits
// one extra `vchunkactive` node per bounded chunk (two host instructions each), so the frame's
// DECLARED node count grows by exactly that many, and the frame gains that many forward branches to
// its existing body-done label -- which also shifts the displacement of the guard's own forward
// branch over the body. On this FP route the architectural `vstart = 0` write needs no relocation:
// the FP bracket's epilogue already runs unconditionally, which is why the early exit lands inside
// it. Vector runs, the integer routes and every LLVM route are untouched.
// The FMA route reads the OLD vd, so chunk-major gives up load-major BETWEEN chunks there; that is
// covered by the same equal-EMUL byte-disjointness the batch loop already relies on, argued at
// RvvEmitTypedFmaChunkGroup. Off by default, so with the switch clear every frame is byte-identical
// to before.
//
// MEASURED BOUNDARY (see the accepted whole-application ablations; no numbers are repeated here).
// The elimination pays only where the runtime vl leaves a MATERIAL inactive suffix in the program's
// hot vector work. Where it does not, a never-taken bound is a real, measurable retired-instruction
// cost on a full-VL execution -- that cost has been observed on a real application, not merely
// modelled. The three policy switches are therefore NOT ready to be defaulted on.
inline bool rvv_qcg_active_vl_bound = false;
// Fuse an adjacent suffix guard and FP lane-mask derivation in QCG.
inline bool rvv_qcg_active_vl_mask_fusion = false;
// Enumerate enabled memory lanes after a masked-off element; no access reordering.
inline bool rvv_qcg_active_mask_memory = false;

// S1-3A (2026-09-11, --rvv-qcg-active-vl-int-bound, default off). THE SAME ELIMINATION, ON THE
// INTEGER LANE ROUTES WHOSE UNITS ARE INDEXED BY DESTINATION ELEMENT -- the EQUAL-WIDTH SAME-EEW
// block, and since W27 the NARROWING block as well.
//
// THE SWITCH'S SCOPE, STATED FIRST BECAUSE IT GREW. As of W27 this one switch is the INTEGER
// ACTIVE-RANGE POLICY over two blocks of `RvvTryIntegerFamily`:
//
//   * the equal-width same-EEW `vchunkpartialalu` block (vadd/vsub/vmul/vmin/vmax/logical/shift/
//     vmerge/vadc/compare/saturating/averaging/round-shift/vsmul, .vv/.vx/.vi, masked and not);
//   * the narrowing `id_rv32_vnshift`/`id_rv32_vnclip` block (vnsrl/vnsra through
//     `InstVChunkNarrowShift`, vnclipu/vnclip through the narrowing `InstVChunkPartialAlu` arm,
//     .wv/.wx/.wi, masked and not).
//
// They share a switch because they are one policy measured together: both emit one body node per
// host unit at the same guard kind with the same `vstart` ownership, and their full-VL costs are
// the same 2(n-1) instructions in the same units. The FP switch above and the widening switch below
// stay separate, because their costs differ structurally (an FP frame's per-chunk shared mask moves
// rather than being added, and a widening frame has twice the units at the same LMUL).
//
// WHAT IT DOES. Both blocks already emit one body node per host unit, unit-major, each carrying its
// own `element_base`. With this on, a frame that satisfies the shared planner's STRUCTURAL conjuncts
// (rv32_active_chunk_plan.h, plus the decision sites in rv32_qir.cpp) precedes each unit c >= 1 with
// one `vchunkactive` node -- `cmp [vec.vl], element_base_c` + `jbe` to the frame's body-done label.
// `element_base_c` is unit c's first architectural element index, so `vl <= it` means every element
// the unit covers is in the tail set [vl, VLMAX) (RVV 1.0 v-spec 3.4.3): the unit's body mask is
// empty, its masked store writes no byte, its compare destination is read back and written
// unchanged, and its `vxsat` contribution -- vsadd/vssub/vsmul on the equal-width block, vnclip on
// the narrowing one -- is already AND-ed with that empty mask. Since `element_base` strictly
// increases, inactive units are a SUFFIX and one forward branch retires all of them.
//
// THE NARROWING GEOMETRY IS THE ONE THING THAT IS NOT SHARED, AND IT IS NOT A SPECIAL CASE. A
// narrowing unit READS `bytes` of the double-width source group and WRITES `bytes/2` of the
// destination, so it covers `(bytes/2)/SEW` architectural elements, half the equal-width answer at
// the same host chunk width. The shared planner therefore takes the unit's DESTINATION byte span
// rather than a host chunk width; feeding it the source span would double the stride and retire
// LIVE units on a full-VL execution. For a narrowing op the vtype SEW is the DESTINATION width
// (the source is 2*SEW), which is why the element width needs no adjustment.
//
// WHY UNIT 0 IS NEVER BOUNDED. `element_base_0 == 0`, so its test is `vl <= 0`, true only for the
// architecturally empty vector -- which the existing body already handles correctly under an
// all-zero mask. Emitting it would cost two instructions on EVERY execution, including full VL, to
// save work in one rare case. The omission is geometry, not a threshold: base 0 is zero for every
// vtype, VLEN and workload. Its consequence is that a `units == 1` frame is byte-identical to
// before even with the switch on -- including every fractional-LMUL narrowing frame.
//
// WHAT IT COSTS. A bounded n-unit frame retires 2(n-1) extra instructions and carries n-1 extra
// not-taken branches on a full-VL execution. That is NOT assumed free: rvdbt's emitted RVV code is
// instruction-delivery bound, so the full-VL ablation is a prerequisite of any performance claim.
//
// WHAT CHANGES IN THE EMITTED FRAME. This switch DOES change frame shape, and saying otherwise
// would be wrong. A bounded frame (a) emits one extra `vchunkactive` node per bounded unit, two
// host instructions each; (b) grows its DECLARED node count by exactly that many -- a mismatch is
// an emitter panic, not a silent pass; (c) RELOCATES the architectural `vstart = 0` write from the
// last body node's `finish` flag to the frame epilogue, because the early exit would otherwise jump
// over it, which is also why unit 0 is never bounded; and (d) gains that many forward branches to
// the frame's existing body-done label, shifting the displacement of the guard's own forward branch.
//
// WHAT IT DOES NOT TOUCH. Widening (its own switch below), mask-logic, reduction, slide/gather,
// vector memory, whole-register transfers, multi-member vector runs, every LLVM route, the FP
// switch above; and within the routes it does cover: the admission decision, the guard KIND and the
// guard code it emits, the fallback arm, and each unit's existing guarded body. Off by default, so
// with the switch clear every emitted byte is what it was.
//
// MEASURED BOUNDARY. Useful where the runtime vl leaves a material inactive suffix in the hot
// vector work; where it does not, the never-taken ladder is a measurable retired-instruction cost
// on a full-VL execution, observed on a real application. Not ready to be defaulted on.
inline bool rvv_qcg_active_vl_int_bound = false;

// W28 ABLATION CONTROL (--rvv-qcg-active-vl-narrow-bound, default TRUE). NOT A POLICY SWITCH AND NOT
// A FOURTH FAMILY: it exists only so the NARROWING half of the integer active-range policy above can
// be measured on its own, because the two halves deliberately share one switch.
//
// AND-GATED, AND THAT IS LOAD-BEARING. The narrowing producer reads
// `rvv_qcg_active_vl_int_bound && rvv_qcg_active_vl_narrow_bound`, so:
//
//   * default TRUE means the policy switch alone behaves exactly as the W27 checkpoint shipped it --
//     setting only `--rvv-qcg-active-vl-int-bound=1` still bounds both blocks;
//   * with the policy switch OFF this flag is inert at either value, in both blocks;
//   * `--rvv-qcg-active-vl-int-bound=1 --rvv-qcg-active-vl-narrow-bound=0` is the equal-width-only
//     arm, i.e. the pre-W27 behaviour, and is the ONLY thing that distinguishes the two arms of the
//     W28 screen.
//
// It is NOT an OR-gated sub-flag: the accepted trap (`--rvv-qcg-typed-chunk-falu=0` doing nothing
// while its umbrella flag is 1) is why the polarity is stated here and pinned by a test.
// It carries no workload, PC, symbol, VLEN or threshold -- it names a route, not a program.
//
// ITS DEFAULT IS TRUE AND MUST STAY TRUE: that is what keeps the POLICY switch's shipped behaviour
// unchanged. Being default-true does NOT mean narrowing is on by default -- with the policy switch
// at its own compile-time default of false this flag is inert. When it does take effect it inherits
// the policy switch's shape change (added bound nodes, grown declared node count, `vstart = 0`
// relocated to the epilogue) and the same measured boundary: worth it only where a material
// inactive suffix exists, a measurable retired-instruction cost on full-VL executions otherwise.
inline bool rvv_qcg_active_vl_narrow_bound = true;

// S1-3W (2026-09-11, --rvv-qcg-active-vl-widen-bound, default off). THE SAME ELIMINATION, ON THE
// WIDENING INTEGER ROUTE (`RvvTryIntegerFamily`'s `id_rv32_vwint` block, every InstVChunkWiden node:
// vwaddu/vwadd/vwsubu/vwsub and their .wv/.wx wide-vs2 forms, vwmulu/vwmulsu/vwmul, and
// vwmaccu/vwmacc/vwmaccus/vwmaccsu, .vv and .vx, masked and unmasked).
//
// A THIRD SEPARATE SWITCH, for the same reason the second one exists: the full-VL cost of carrying
// a never-taken bound has to be ablatable per family. Sharing a switch with `..._int_bound` would
// make every widening measurement a measurement of the equal-width route as well, and the two have
// different costs -- a widening frame's destination group is 2*LMUL registers, so it has TWICE the
// host chunks, and therefore twice the bounds, of the equal-width frame at the same LMUL.
//
// WHAT IT DOES. Each host chunk c >= 1 is preceded by one `vchunkactive` node -- `cmp [vec.vl],
// element_base_c` + `jbe` to the frame's body-done label. `element_base_c == c * bytes / (2*SEW)`
// is chunk c's first ARCHITECTURAL ELEMENT index. RVV widening changes the element WIDTH, never the
// element INDEX (destination element i comes from source element i, v-spec 11.2), so source and
// destination share one active set [vstart, vl) and that index is in `vec.vl`'s own unit. `vl <= it`
// therefore means every element the chunk covers is tail (v-spec 3.4.3): its body mask is empty and
// its masked store writes no byte. Emit_vchunkwiden derives that mask from the SAME `base` and the
// SAME destination lane count the bound is built from, so bound and body cannot disagree about
// where a chunk starts. `element_base` strictly increases, so inactive chunks are a SUFFIX and one
// forward branch retires all of them; the test is on `vl` and never on the mask, because with
// `vstart > 0` a LEADING chunk's mask is zero too.
//
// WHY THIS FAMILY. Widening is the family whose host chunk count is STRUCTURALLY doubled, so at a
// given vtype it carries twice the skippable suffix; and it needs no NEW emitter, because the
// existing `Emit_vchunkwiden` already keeps its single `vstart` write behind its own `finish` flag.
// That is not the same as leaving the frame unchanged: a bounded frame CLEARS that flag and the
// frame epilogue performs the `vstart = 0` write instead, which is a relocation of an architectural
// side effect, not a no-op.
//
// WHAT IT COSTS. As above: 2(n-1) extra retired instructions and n-1 extra not-taken branches on a
// full-VL execution, and n here is twice the equal-width n. Not assumed free; the full-VL ablation
// is a prerequisite of any performance claim.
//
// WHAT CHANGES IN THE EMITTED FRAME. The same four things the integer switch above lists: one extra
// `vchunkactive` node per bounded chunk (two host instructions each), a correspondingly larger
// DECLARED node count (mismatch is an emitter panic), the `vstart = 0` relocation just described,
// and the added forward branches to the existing body-done label, which shift the guard's own
// forward-branch displacement.
//
// WHAT IT DOES NOT TOUCH. The equal-width, narrowing, mask-logic, reduction, slide/gather, vector
// memory and whole-register routes, multi-member vector runs (no run kind carries a widening
// member), every LLVM route, the two switches above; and within the widening route itself: the
// admission decision, the guard KIND and the guard code it emits, the fallback arm, and each
// chunk's existing guarded body. Off by default, so with the switch clear every emitted byte is
// what it was.
//
// MEASURED BOUNDARY. Same as the integer switch: it pays where the runtime vl leaves a material
// inactive suffix, and costs measurable retired instructions on full-VL executions where it does
// not. Not ready to be defaulted on.
inline bool rvv_qcg_active_vl_widen_bound = false;

// P2a (2026-09-13, --rvv-qcg-active-chunk-census, default off). THE DIRECT DYNAMIC COUNT OF HOST
// WORK UNITS IN PLANNER-ELIGIBLE NATIVE QCG FRAMES, and nothing else.
//
// WHAT THE TWO NUMBERS ARE. Over executions of the NATIVE fast body of every frame the common
// finalizer classified `Ineligibility::None`:
//
//   chunks_available  the host work units that frame would execute with suffix skipping OFF, i.e.
//                     the finalizer's own derived unit count, added once per native execution.
//   chunks_executed   the units actually REACHED after the frame's active-suffix bounds: the
//                     always-executed prefix (units carrying no bound) added once at the native
//                     join, plus one per `vchunkactive` bound that fell through.
//
// NEITHER IS A COUNT OF "USEFUL" WORK. With the policy switches off a frame carries no bound, every
// unit is reached, and `chunks_executed == chunks_available` BY CONSTRUCTION -- including the units
// whose every element is tail. That equality is the switch-off invariant, not a claim that the work
// was needed. For an enabled and correctly bounded frame the reached units coincide with the units
// holding an architecturally active element, but that is an INTERPRETATION of the bound's own
// semantics (Emit_vchunkactive's `vl <= element_base`), not the definition of this counter.
//
// WHERE THE NUMBERS COME FROM. The unit count and the index of the first bounded unit are read off
// the frame's end node, where `rvvfinal::CloseFrame` recorded the geometry it had ALREADY derived
// from the emitted QIR body for the `reason == None` arm. There is no opcode list, no guest PC, no
// workload case, no VLEN threshold and no second eligibility predicate anywhere in this feature: a
// frame the finalizer refuses contributes nothing, and a frame it accepts contributes its own
// derived geometry.
//
// THE HELPER ARM CONTRIBUTES NOTHING. Both join-side adds sit after `rvv_typed_chunk_join`, which is
// reached only when the frame's guard PASSED; the guard-miss arm binds `rvv_typed_chunk_fallback`
// past the `jmp done` and never crosses them. That is the same placement argument
// `EmitRvvFrameCensusIncr` already makes, and it is why `rvv_direct_fallbacks` stays the separate
// count of the other arm.
//
// NOT A CPUState FIELD, for the reason stated at `g_vlse_gather_fast` in rv32_cpu.h: the AOT ABI
// signature mixes `sizeof(CPUStateImpl)` and ukernel.cpp pins it in a static_assert, so growing the
// struct for a default-off diagnostic would refuse every AOT artifact built from this tree. These
// are process-global u64s addressed by absolute address, two instructions instead of one.
//
// ARMING IT CHANGES EMITTED BYTES (four instructions at each native join, two after each bound), so
// it must NEVER be set on an arm that is being timed. With it off nothing at all is emitted and the
// bytes are the pre-P2a bytes exactly. QCG only: the LLVM backend emits no census.
inline bool rvv_qcg_active_chunk_census = false;


// G11-A (2026-09-07, --rvv-qcg-full-vl-fast-body, default off). THE FRAME'S OWN GUARD ALREADY
// PROVED THE LANE PREDICATE; STOP RE-DERIVING IT FROM CPUState.
//
// A typed frame whose guard kind is one of the three that test `vl` with `jne vlmax` and `vstart`
// with `jne 0` (qir::InstRVVTypedChunkBegin::GuardProvesFullVl) has established, for every body op
// that can run at all, that the prestart set [0, vstart) and the tail set [vl, VLMAX) are both
// EMPTY (RVV 1.0 v-spec 3.7 and 3.4.3). With an unmasked member (vm == 1, v-spec 5.3) every
// element of the destination register group is therefore an active body element, `vta`/`vtu` and
// `vma`/`vmu` are vacuous, and the mask Emit_vchunkfalu/Emit_vchunkfma rebuild per chunk per lane
// op from vec.vl and vec.vstart is the translation-time constant all-ones.
//
// WHAT IT REMOVES, and nothing else: (1) the per-chunk lane-mask prologue (vl load, clamp, bzhi,
// vstart load, kmovw) and the `{k}` on the lane op, which becomes an unmasked host operation;
// (2) the tail-agnostic all-ones fill (`knotw` + `vpternlog $0xff`), whose write mask is provably
// empty here -- Emit_vchunkfalu's own comment already said so and emitted it anyway, because the
// emitter had no way to know; (3) the destination seed `vmovdqu64 out, vs2`, but ONLY for the
// funct6 arms whose selected host operation writes every lane of the destination without reading
// it (RvvFaluArmFullyWritesDest). The FMA forms read the destination as multiplicand or
// accumulator, the min/max arm writes it through several partial masks, and the sign-injection arm
// uses it as a VPTERNLOG input; all three keep their seed.
//
// WHAT IT DOES NOT TOUCH: NaN canonicalisation (its mask is the data-dependent unordered compare,
// not a vl fact), the FP exception-flag bracket and fflags folding, masked (vm == 0) members, any
// partial-vl or non-zero-vstart path, and the ordered fallback arm. A frame the predicate does not
// admit is byte-identical, and so is every frame when this switch is off.
//
// COHERENCE WITH A12, which is the one thing that can go wrong here. The A12 shared lane masks and
// this are mutually exclusive by construction: a frame cannot both hold a resident k(1+chunk) and
// claim its lane ops are unmasked. RvvEmitFpSharedMasks refuses to build them for an admitted
// frame, and QEmit::Emit_vchunkmaskset Panics if one reaches an admitted frame anyway, so a
// disagreement between the two passes is a loud translation failure rather than a lane op that
// silently consumes a mask register nobody wrote.
inline bool rvv_qcg_full_vl_fast_body = false;

// S2.9, widened by Native-1: the DIRECT-STATE route for exact `vsetvli rd, rs1, e32, m1, ta, ma`
// (one `rvvsetvl` QIR op -> eight host instructions), on its OWN switch. Every register
// combination is admitted except rd == x0 && rs1 == x0, the reserved keep-vl form, whose
// runtime-conditional vill write set this guard-free emitter cannot express.
//
// A ninth flag, for the reason each of the eight above got its own: every accepted evidence arm was
// produced with a specific set of these flags, and widening one of them to admit another opcode
// would retroactively change what those arms mean. Here the separation carries a weight none of the
// eight has, because THIS OPCODE WRITES THE STATE THEIR GUARDS READ BACK. `Emit_rvvtypedchunkbegin`
// compares vec.vtype and vec.vl against constants the translator put on the node, so a wrong value
// written here does not corrupt one lane -- it either turns twelve accepted direct frames into
// twelve silent helper fallbacks, or leaves the guard passing over a wrong element count. Both are
// observable (`inline_hits`/`guard_fallbacks` and the guest's own output hash respectively), and
// keeping this on its own switch is what makes either observation attributable to one token.
//
// The admitted shape is exactly what RvvQcgSetVLAdmit tests -- vsetvli (bit31 == 0, so never
// vsetivli or vsetvl), OP-V/OPCFG, a supported vtypei of exactly e32/m1/ta/ma, any (rd, rs1) pair
// except the reserved rd == x0 && rs1 == x0 keep-vl form, VLEN 512 or 1024, pure QCG, not
// --rvv-verify. Everything else keeps the unchanged rv32_vsetvli (or rv32_vsetvl) helper, including
// the reserved-vtype `vill` path and that one keep-vl form.
//
// IT HAS NO force-emit TWIN AND NO HOST-FEATURE TEST, unlike all eight above, and the asymmetry is
// not an omission: `mov`/`cmp`/`cmov` are baseline x86-64, so there is no AVX-512 probe to bypass.
//
// IT ALSO HAS NO RUNTIME GUARD AND NO FALLBACK EDGE, which no other routed RVV opcode can say. Its
// one run-time input is AVL, and `vl = min(AVL, VLMAX)` is exact over the whole 2^32 AVL domain, so
// there is no data predicate left to guard. See qir.h InstRVVSetVL. Default off.
inline bool rvv_qcg_direct_setvl = false;

// R1A.3a: form the VECTOR RUN (VRUN) descriptor at translation time.
//
// THIS SWITCH GENERATES NO CODE, at any setting. With it on, the translator additionally scans
// forward from each instruction it is about to translate and records which consecutive
// instructions COULD form one guarded multi-instruction vector run under the R1A.2 A1-A5 semantic
// predicates -- the members' raw words, guest PCs, fallback stubs, typed operations, operands,
// run dataflow (live-in, live-out, per-source defining member) and a conservative peak-liveness
// bound. The result goes into rvvrun::g_stats and nowhere else; every instruction is then
// translated by exactly the route it would have taken with this switch off.
//
// It is therefore an OBSERVATION switch this checkpoint, and the descriptor's consumer -- the
// single guard, the SSA-preserving fast body and the ordered whole-run fallback of R1A.2 3.5 --
// is a later checkpoint. Default off, and with it off the scan is not called at all, so the
// emitted code of every accepted single-instruction route is bit-identical to its accepted form.
inline bool rvv_vector_run = false;

// F1 SCAN FAST-REJECT (2026-09-23; CLI --rvv-run-scan-fast-reject, default ON in F1). With
// rvv_vector_run on, every guest instruction not covered by an earlier run was scanned by
// FormRun, and every instruction's consumer copied and reset the 1,616-byte pending descriptor --
// even for a scalar instruction that cannot start a run. F0's timing, PMU and translation-time
// measurements attribute ~1.6k host instructions per such scan to this work. With the switch on,
// a scan whose first instruction cannot be a run's first member (rvvrun::EmptyScanCut) records the
// identical statistics without forming a descriptor, and the consumer refuses a pending descriptor
// with fewer than two members without copying it. Admission of every run that CAN form, and the
// emitted code, are unchanged; the switch exists so the same binary can reproduce F0's path (off)
// for A/B control.
inline bool rvv_run_scan_fast_reject = true;

// F1 GUARD (2026-09-23). A QCG FP-bracket vector run whose non-FP members are lane-local,
// non-trapping, vector-state-only routes (vmv.v.*, vfmv.v.f, vsll.vi/vsrl.vi, the integer .vv
// and .vx rows) may take the FP routes' own `vl <= VLMAX` guard (VTypePartialVlVstartFrmRNE)
// instead of `vl == VLMAX`, because every live-out store of such a frame is masked by the live
// vl. Default on in the F1 build; 0 reproduces the F1 scan-only frame (full-VL guard and
// unmasked run stores) for A/B control.
inline bool rvv_run_fp_store_masked_partial_vl = true;
// F1 GUARD, second half: in such a frame, a masked live-out store of chunk c uses the frame's
// resident shared active mask k(1 + c) (A12, --rvv-qcg-fp-shared-mask) instead of deriving the
// same mask again from vl/vstart per store. Default on; 0 keeps the per-store derivation. Inert
// when the frame holds no shared masks.
inline bool rvv_run_fp_store_mask_reuse_shared = true;

// SCALAR PASSTHROUGH AS A RUN MEMBER, AS A PURE ABLATION FACTOR.
//
// WHAT IT SELECTS. The run classifier's membership rule is otherwise entirely about VECTOR routes:
// a decode class is a member iff it has a TypedAluRoute<> row whose own admission predicate says
// yes. This switch selects whether a THIRD class of instruction may additionally be carried
// through a run -- the three non-trapping RV32 integer ALU forms `add`, `addi` and `sub`, admitted
// only to BRIDGE two vector members so that address/counter maintenance sitting between them does
// not cut the vector island.
//
//   false (DEFAULT)  the three forms are ordinary non-members and cut the run with
//                    CutReason::ScalarInsn, exactly as every other scalar instruction does. No
//                    descriptor carries a RunOp::Scalar member, no frame emits an `rvvrunscalar`
//                    op, and `n_scalar_members` is zero everywhere.
//   true             the bridging rule above applies.
//
// THIS ONE IS READ BY ADMISSION, AND THAT IS THE DIFFERENCE FROM EVERY OTHER `rvv_run_*` SWITCH.
// `rvv_run_body_materialize`, `rvv_run_order_chunk_major`, `rvv_run_live_range_split` and the
// dependency-probe pair are BODY selectors, and each of their comments states -- and
// rvv_vector_run_admission_test.cpp asserts -- that they must never reach FormRun, an admission
// predicate or the descriptor, because the two arms of those ablations have to form the SAME run.
// This switch is the opposite kind: its whole subject is WHICH INSTRUCTIONS ARE MEMBERS, so it is
// read in exactly one place on the admission side (rvvrun::Classify, the `else if` arm for the
// three integer ALU forms) and in no body, no emitter and no execution path. The two arms of THIS
// ablation are therefore expected to form different runs; that is the factor being measured, and
// nothing else differs between them.
//
// Default false, so an unset switch reproduces the pre-passthrough behaviour: a run is a maximal
// stretch of admitted VECTOR members and nothing else.
inline bool rvv_run_scalar_passthrough = false;

// P7O-1: COMPONENT-SEPARABLE RUN FORMATION.
// See experiments/2026-08-30-prof-hung-teacher-closure/COMPONENT_SEPARABLE_RUN_DESIGN.md.
//
// WHAT THE DESIGN IS. When a guest vector register is `k` host chunks wide, the run's fast body
// keeps ALL `k` components of every touched register live at once, because pass 1 loads every
// (live-in register, chunk) pair before pass 2 runs and pass 3 stores every (live-out register,
// chunk) pair after it. Its admission bound therefore multiplies by `k` (RvvRunPeakLiveBound in
// guest/rv32_vrun.h) and cuts a run with CutReason::RegisterPressure when the product exceeds
// kHostVectorRegs. If the run is provably lane-local -- no member reads a lane another component
// owns -- the same frame can instead run pass 1, pass 2 and pass 3 for component 0, then for
// component 1, and so on; only ONE component is then live at a time, and the bound loses its `k`
// factor (RvvRunPeakLiveBoundCS).
//
// WHAT THIS SWITCH DOES. It is read in exactly ONE place -- the bound selection inside
// rvvrun::FormRun, whose answer is recorded as `RunDescriptor::component_separable` -- and:
//
//   false (DEFAULT)  `component_separable` is false on EVERY descriptor the translator forms, so
//                    the P1-P11 predicate is not merely unused, its answer is absent. No cut, no
//                    bound, no emitted body and no counter differs from the pre-P7O-1 build.
//   true             a run takes the component-resident bound ONLY IF every committed member and
//                    the candidate satisfy the conservative P1-P11 predicate AND
//                    RvvRunPeakLiveBoundCS is not larger than RvvRunPeakLiveBound for that run --
//                    so turning this on can never cut a run the default arm admits. Any other run
//                    keeps the existing bound and the existing body, unchanged.
//
// THE BIT IS A DECISION, NOT A LEGALITY ANSWER, AND IT SELECTS BOTH THE BOUND AND THE BODY. A run
// admitted on RvvRunPeakLiveBoundCS is emitted with the component-major body -- pass-1 loads, the
// member body and pass-3 stores run completely for component c before component c+1 begins -- and
// RV32Translator::RvvEmitVectorRunGroup reads that ONE descriptor field and no switch of its own.
// The pairing is the point: the bound that admits a run has to bound the body that is emitted for
// it, or the frame carries a peak the allocator never budgeted for. The frame-scope broadcasts and
// the single FP bracket stay outside the component loop, and the typed-op accounting is unchanged
// (the same ops in a different order).
//
// IT IS AN ADMISSION-SIDE SWITCH, and that is deliberate, stated here for the same reason
// `rvv_run_scalar_passthrough` above states it. The body selectors (`rvv_run_body_materialize`,
// `rvv_run_order_chunk_major`, `rvv_run_live_range_split`, the dependency-probe pair) must never
// reach FormRun because their two arms have to form the SAME run. This one's subject IS the
// admission bound, so its two arms are EXPECTED to form different runs; any ablation using it must
// therefore report the run-shape counters (`runs_formed`, `multi_member_runs`,
// `members_admitted`, the `register_pressure` cut) next to any timing, or the two effects are
// mixed. That obligation is recorded in the design document's section 4.2.
//
// MUTUALLY EXCLUSIVE WITH THE BODY SELECTORS, refused loudly in elfrun/elfaot rather than silently
// resolved: `--rvv-run-body=materialize` and `--rvv-run-live-range-split` each rewrite pass 1/2/3
// themselves with a different residency model, and under `--rvv-run-order=chunk` a single
// component's sub-body makes member-major and chunk-major the same thing, which would stop the
// ablation being one-factor.
inline bool rvv_run_component_separable = false;
// Bound simultaneous vector/mask residency without reducing the architectural VLEN.
inline bool rvv_run_bounded_batches = false;

// P7O-2: WHERE the component-major body's CPUState accesses SIT, and nothing else.
//
// This is an EMISSION-SIDE switch, unlike `rvv_run_component_separable` directly above it. It is
// read once, INSIDE the component-major arm of RV32Translator::RvvEmitVectorRunGroup, after the
// scan, the admission predicates, the descriptor, its dataflow and its pressure bound are all
// finished. Both arms therefore form the SAME batch of runs, from the same descriptors, with the
// same cut accounting -- the obligation `rvv_run_component_separable` carries (report the
// run-shape counters next to any timing) does NOT apply here, because there is nothing for the
// two arms to disagree about upstream of emission.
//
//   false (DEFAULT)  the accepted P7O-1 component-major body: for each component c, pass 1 loads
//                    every live-in chunk of c, the members run, pass 3 stores every live-out
//                    chunk of c. Not one node of the emitted sequence differs from a build
//                    without this switch.
//   true             the SAME nodes, with the load and store placement demand-driven:
//                      Rule L  a live-in's chunk-c load is emitted immediately before the FIRST
//                              member of component c that reads it, at its operand-binding site.
//                      Rule S  a live-out's chunk-c store is emitted immediately after the member
//                              `RunDescriptor::last_def[r]` has finished all of its lane ops for
//                              component c -- the EARLIEST safe point, because before that member
//                              `cur[r][c]` is not yet the run's final value and after it the
//                              value never changes again.
//
// WHAT IS AND IS NOT ALLOWED TO DIFFER. The arithmetic is untouched: the same lane ops, in the
// same linear order, reading the same SSA values, so the frame's declared `n_typed` is the same
// number and every operand-overlap rule (vd==vs2, vd==vs1, the fused third source) still binds
// every source before any destination is published. The state accesses are untouched in COUNT:
// exactly `popcount(live_in_mask)` loads and `popcount(live_out_mask)` stores per component,
// asserted per component rather than assumed, so this switch can neither add nor remove a single
// CPUState access. Only their POSITION differs. Register ASSIGNMENT is not claimed identical --
// the allocator sees a different value order -- which is the same caveat `--rvv-run-order`
// carries.
//
// WHY IT CANNOT RAISE THE PEAK THE ADMISSION BOUND BUDGETED FOR. Rule L only moves a live-in's
// birth LATER and Rule S only moves a live-out's last use EARLIER, so at every arithmetic anchor
// the live set is a SUBSET of the default component-major arm's live set at that anchor. The
// peak can only fall, so `RvvRunPeakLiveBoundCS` -- the bound the run was admitted under -- still
// bounds the body actually emitted, and no admission code has to know this switch exists.
//
// REQUIRES `rvv_run_component_separable`, and is refused loudly otherwise: with it off no
// descriptor carries the bit, the component-major arm is unreachable, and a "demand placement"
// that places nothing would silently be the same arm as one that did not ask for it. It inherits
// that switch's exclusions (materialize body, live-range splitting, chunk-major order) and adds
// one of its own: the dependency probe appends `vchunkdep` nodes after each lane op, which makes
// `cur[rd][c]` the probe's output rather than the member's, so Rule S's anchor would no longer be
// the point after which the value stops changing.
inline bool rvv_run_component_demand_placement = false;

// T7g: analysis-only real-candidate census.  The translator constructs T7f Input values from the
// same raw guest words, per-route admission predicates, typed-QIR facts and QIR basic-block
// interval it is already using.  It records diagnostics only and is never consulted by lowering,
// code generation or execution.  The output path is required when enabled.
inline bool rvv_lane_census = false;
inline char const *rvv_lane_census_out = nullptr;

// R1A.3d: WHICH BODY a consumed vector run emits inside its ONE guard.
//
// This is the single factor of the R1A.3d causal ablation. Both settings produce the SAME frame
// -- the same admission decision, the same descriptor, the same guard, the same join, the same
// ordered fallback arm, the same per-member guest-PC stores -- and differ ONLY in what sits
// between the guard and the join:
//
//   false (ssa, DEFAULT)  the accepted R1A.3b body: load each live-in chunk once, run the members
//                         over component SSA values, store each live-out chunk once.
//   true  (materialize)   the SAME body the single-instruction route emits, once per member: two
//                         source loads, the lane op, the destination store, per chunk. The
//                         members therefore still hand values to each other through CPUState.
//
// So arm B (materialize) minus arm C (ssa) is exactly `k` CPUState reloads of the intermediate
// per pair per strip step, and nothing else. `RvvEmitTypedAluChunkBody` is the ONE emitter both
// arm A and arm B use, so "arm B's body is arm A's body" is a structural fact rather than two
// hand-written functions that happen to agree.
//
// READ IN EXACTLY ONE PLACE: RV32Translator::RvvEmitVectorRunGroup. It must never reach FormRun,
// any admission predicate or the descriptor, or the two arms could form DIFFERENT runs and the
// ablation would not have a single factor. rvv_vector_run_admission_test.cpp asserts that.
//
// Default false, so an unset switch reproduces the accepted R1A.3b/R1A.3c generated code exactly.
inline bool rvv_run_body_materialize = false;

// P6C (P6A Estimand D): the ISSUE ORDER of the vector-run SSA body's lane operations.
//
// THIS IS A TOPOLOGICAL REORDERING AND NOTHING ELSE. In the SSA body every read and every write of
// a component value uses `cur[r][c]` at ONE fixed chunk index `c`, so no value produced in chunk
// `c` is ever read from chunk `c' != c`. The `k` chunks are therefore `k` disjoint dataflow
// components, and the two nestings of the member loop and the chunk loop are both legal linear
// extensions of the SAME SSA value graph:
//
//   false (member-major, DEFAULT)  L1,H1, L2,H2, ... Ln,Hn -- guest order outside, chunk inside.
//                                  Sibling chunks of one guest op are issued adjacently.
//   true  (chunk-major)            L1,L2,...,Ln, H1,H2,...,Hn -- chunk outside, guest order inside.
//                                  One whole independent chain is issued before the next begins.
//
// WHAT IS IDENTICAL IN BOTH, BY CONSTRUCTION AND NOT BY INSPECTION: the admission decision, the
// descriptor, `nchunks`, `chunk_bytes`, the member list, `n_typed` (the SSA formula
// (|live_in| + |live_out| + m) * k does not mention order), the single guard, the join, the
// ordered fallback arm, pass 1's loads, pass 3's stores, and the emitted host instruction
// multiset. The per-chunk def-use graph is identical too: each chunk still has the same number of
// lane ops with the same producer/consumer edges. ONLY the linear order changes.
//
// WHAT IS NOT CLAIMED IDENTICAL: the register ASSIGNMENT. QRA sees a different instruction order,
// so live ranges differ. The gate is "same multiset + zero spill", never "same registers".
//
// WHY PER-CHUNK PUBLICATION IS EQUIVALENT. Member-major buffers a member's `k` destinations in
// `def[]` and publishes them all after the chunk loop, so `vd == vs1/vs2` reads the
// pre-instruction value. That guarantee is per-chunk: the sources bound for chunk `c` are read
// from `cur[..][c]` before `cur[rd][c]` is overwritten, and no other chunk's slot is touched. In
// chunk-major the same member/chunk pair binds the same two sources and publishes the same
// destination, so publishing immediately after the op is the identical value sequence for that
// chunk. Both arms produce, for every `c`, the exact same ordered list of (op, src, src -> def).
//
// SCOPE: the vector-run SSA body only. With `rvv_vector_run` off, or with the materialize body,
// every guest op owns its own frame or its own CPUState round trip and there is no legal
// reordering left that keeps the frame count fixed, so this switch is ignored there.
//
// READ IN EXACTLY ONE PLACE: RV32Translator::RvvEmitVectorRunGroup, on the same line as
// `rvv_run_body_materialize` and for the same reason -- nothing above it (the scan, the admission
// predicates, the descriptor, its dataflow, its pressure bound) may see it, or the two arms would
// form DIFFERENT runs and the ablation would not have a single factor.
//
// The admission pressure bound needs no change, and that is read out of the model rather than
// assumed: `RvvRunPeakLiveBound = max((touched+1)*k, 3k)` already charges every (touched register,
// chunk) pair a live value at once, because pass 1 loads ALL chunks of every live-in up front in
// both arms. Chunk-major has at most ONE in-flight destination instead of `k`, so its true peak is
// not above the bound the descriptor was already admitted under.
//
// Default false, so an unset switch reproduces the accepted R1A.3b/R1A.3c/P5 generated code
// exactly.
inline bool rvv_run_order_chunk_major = false;

// P7N-G. LIVE-RANGE SPLITTING FOR THE VECTOR RUN'S SSA BODY.
//
// WHAT IT CHANGES, AND THE ONE THING IT DOES NOT. The SSA body has, since R1A.3b, had a fixed
// load/store placement: pass 1 loads EVERY live-in chunk at frame entry and pass 3 stores EVERY
// live-out chunk after the whole body. P7N-F measured the consequence -- ChaCha20's whole hot
// translation block needs an exact peak of 35 simultaneously live host chunks at VLEN 1024, while
// ArchTraits::VPR_POOL is 30 -- and that is why FormRun cuts the run at 30 members.
//
// With this on, the body instead manages residency per HOST CHUNK COMPONENT with exact next-use
// information: a live-in chunk is loaded at its FIRST USE, a component whose last use has passed
// is released, and ONLY when the resident set would actually exceed the pool is a live range split
// -- dead components first, then the component whose next use is farthest away, materialized to
// ITS OWN EXISTING CPUState slot and reloaded on demand.
//
// THE ISSUE ORDER IS NOT TOUCHED. Members stay in guest order with the chunk loop inside, so a
// guest operation's low/high sibling chunks are still issued adjacently. Turning the body
// chunk-major would reduce the peak far more cheaply and is deliberately NOT what this does: the
// research question is whether the sibling independence of ONE RVV operation buys anything, and
// chunk-major dissolves the question rather than answering it. Combining this with
// `rvv_run_order_chunk_major` is refused loudly rather than silently taking one of them.
//
// IT IS NOT A REGISTER ALLOCATOR AND IT CHANGES NO ALLOCATOR LIMIT. ArchTraits::VPR_POOL and
// rvvrun::kHostVectorRegs are untouched. What this does is bound the number of simultaneously live
// QIR values the frame contains, so the EXISTING allocator never has to spill inside the guarded
// window -- which is the property QEmit::Emit_mov's Panic protects.
//
// DEFAULT OFF, like every other body switch, so every accepted evidence arm keeps its meaning.
inline bool rvv_run_live_range_split = false;

// P7M-E. THE PER-FRAME DYNAMIC EXECUTION CENSUS (`--rvv-run-frame-census`).
//
// A DIAGNOSTIC, NOT A LOWERING SWITCH. It changes no admission, no member order, no body, no
// splitting decision and no existing counter's meaning: the only thing it does is register an
// identity for every emitted MULTI-member vector-run frame and make that frame's fast-arm join
// increment its own slot. `rvvrun::FrameCensusEntry` states what an entry is and why neither
// `rvvrun::g_stats` (translation-time) nor `CPUState::rvv_direct_hits` (one global, every typed
// frame) can answer the question it answers.
//
// ARMING IT CHANGES EMITTED BYTES, so it is default off and must never be set on an arm that is
// being timed. That is the same discipline `rvv_qcg_hit_counter` already carries, and the reason
// this is a separate switch rather than a widening of that one: `rvv_qcg_hit_counter` is default
// TRUE and its counter is deliberately shared by every typed frame, so extending it would both
// change accepted goldens and destroy the per-frame identity that is the entire point here.
inline bool rvv_run_frame_census = false;

// P7N-J. THE VALUE-EPOCH-AWARE, COST-WEIGHTED RESIDENCY SURROGATE FOR THAT SAME BODY.
//
// WHY IT EXISTS. CHACHA20_LIVE_SPLIT_OPTIMALITY_AND_MEMORY_FOLDING.md proved, by exhaustion over
// every gap subset of size <= 3, that the real 64-member ChaCha20 frame at `0x12204` needs exactly
// 3 reloads and 0 extra stores (35 CPUState loads / 34 stores) under the SAME fixed member-major
// order, the SAME operation multiset, the SAME pool of 30 and the SAME one-slot-per-component
// spill target -- while the shipped body pays 5 reloads AND 5 extra stores (37 / 39). The same
// document isolated the two rule defects that account for the whole 10-vs-3 gap, each of which is
// stated over the run's def/use structure alone and carries no workload constant:
//
//   D1 (value epoch)  `RvvRunNextUseStep` answers "when is this REGISTER next read", not "when is
//                     the value this component holds RIGHT NOW next read". A component whose value
//                     a later member overwrites before any read is already dead; reporting a far
//                     next use for it holds a host register for nothing AND corrupts the victim
//                     ranking. With this on, the scan stops at the next DEFINITION of the
//                     register, and a dead dirty component is released -- dropped with NO store
//                     when a later definition will re-establish the slot, stored NOW when it is
//                     that component's final value, because that store is owed at the close
//                     either way.
//
//   D2 (weighted)     farthest-next-use is Belady, which is optimal only when every fetch costs
//                     the same. Here the victim's cost is `1 + [dirty AND not the final value]`:
//                     a clean component, a final value and a dead-and-later-redefined value all
//                     cost one reload and NO store. With this on, victims are ranked by that cost
//                     class FIRST and by farthest next use only within a class.
//
// IT IS A SURROGATE, NOT A PLANNER. It is still one greedy pass in emission order and claims no
// global optimality; it exists to test whether the two structural rules alone are worth an exact
// min-cost planner, and its acceptance evidence is the ChaCha frame's proven optimum, not timing.
//
// NOTHING ELSE MOVES. Same members, same order, same lane operations, same slots, same pool, same
// admission -- and it is read ONLY inside RvvEmitVectorRunSplitBody, by both the counting pass and
// the emitting pass, so the two cannot disagree about a decision. Legal only with
// `rvv_run_live_range_split` on, and with it off this body is not emitted at all. DEFAULT OFF: with
// it off every branch below takes the shipped arm and the emitted bytes are unchanged.
inline bool rvv_run_split_value_weighted = false;

// P7L-B1: THE MATCHED DEPENDENCY PROBE. An experiment instrument, not a lowering and not a method.
//
// WHAT IT IS FOR. At VLEN 1024 a guest vector register is two 512-bit host chunks, and the
// vector-run SSA body keeps each chunk's chain in host registers across several guest operations,
// so the two chains are architecturally independent. Whether they OVERLAP on the machine cannot be
// read off that structure, and it cannot be read off a VLEN 512-vs-1024 comparison either: at a
// fixed total element count, doubling VLEN halves the guest operation count AND splits the chain,
// and both predict the same direction (M3 measured 0.512/0.514/0.558 for three arms whose
// dependence structures are completely different).
//
// So the question is asked the only way it can be: hold VLEN, the guest ELF, the input, the
// admission decision, the frame, the guard and the emitted instruction MULTISET fixed, and change
// ONE register operand so that a dependency edge either stays inside a chunk's own chain or
// crosses to its sibling. The time difference is then attributable to the edge and to nothing
// else.
//
//   rvv_run_dep_probe_depth   0 = OFF (default). N > 0 appends N value-preserving `vchunkdep`
//                             ops after EVERY (member, chunk) lane op of the vector-run SSA body.
//   rvv_run_dep_probe_cross   false = the probe's second source is the chunk's OWN running value
//                             (independent); true = it is chunk `(c + 1) % k`'s running value
//                             (serialised).
//
// WHY `(c + 1) % k` AND NOT A SPECIAL CASE. At k == 1 -- VLEN 512 for every shape these routes
// admit -- `(c + 1) % 1 == 0 == c`, so the two arms emit BYTE-IDENTICAL code with no `if` anywhere
// deciding that. That is a free null control: any measured difference between the two arms at
// VLEN 512 is measuring the harness, not the machine.
//
// WHY IT SERIALISES AT k == 2. The chunks are visited in index order and each probe reads its
// sibling's running value AS IT CURRENTLY STANDS. Chunk 0 therefore reads chunk 1's value from
// BEFORE chunk 1 was probed (this member's lane result), and chunk 1 reads chunk 0's value from
// AFTER it was (this member's probe result). The critical path becomes
// `def1 -> probe0 -> probe1 -> def1' -> ...`, i.e. 1 + 2N per member against the independent arm's
// 1 + N, and it grows with N -- which is what makes a depth ladder a dose-response rather than a
// single point.
//
// READ IN EXACTLY ONE PLACE: RV32Translator::RvvEmitVectorRunGroup, on the same line as
// `rvv_run_body_materialize` and `rvv_run_order_chunk_major` and for the same reason. Neither
// switch may reach FormRun, an admission predicate, the descriptor, its dataflow or its pressure
// bound, or the two arms would form DIFFERENT runs and the ablation would not have a single
// factor. `rvv_vector_run_admission_test.cpp` asserts that for the existing two; the P7L-B1
// focused test asserts it for these.
//
// SCOPE, stated so it cannot be widened by accident: the SSA body only. With `rvv_vector_run` off,
// or with the materialize body, every guest op owns its own CPUState round trip and there is no
// cross-operation chain for a probe to be about, so the switches are ignored there. Chunk-major
// issue order is REFUSED while the probe is on rather than silently reinterpreted: in that order a
// member's sibling chunk has not been computed when the probe would need it, so the rule above
// would not be expressible.
//
// Default 0/false, so an unset switch reproduces the accepted generated code exactly -- and that
// is a gate, not an aspiration: P7L-B1 requires the depth-0 TB bytes to be byte-identical to the
// pre-P7L-B1 build's.
inline unsigned rvv_run_dep_probe_depth = 0;
inline bool rvv_run_dep_probe_cross = false;

// C4e (2026-09-14, --rvv-run-grouped-component-major, default off). THE GROUPED COMPONENT-MAJOR
// RUN BODY: the arm an active-suffix bound can be placed on, and the CONTROL for that bound.
//
// WHY A SECOND COMPONENT-MAJOR SWITCH EXISTS AT ALL. `rvv_run_component_separable` above is an
// ADMISSION-side switch: it changes which runs are formed (its bound is RvvRunPeakLiveBoundCS) and
// its legality predicate deliberately REFUSES `partial_vl_ok` (rv32_vrun.cpp, P6's vl half). The
// runs an active-suffix bound can guard are exactly the `partial_vl_ok` ones -- a frame whose guard
// proves `vl == VLMAX` has no inactive suffix to leave -- so that switch cannot host the bound.
// This one is EMISSION-side only: it forms the identical runs and changes only the linear order of
// an already-formed run's body, which is what lets the bound-off and bound-on arms be the same
// frames differing in one factor.
//
// WHAT IT SELECTS. For a run this file's own predicate accepts, the body becomes
//
//     for c in 0..k-1 { maskset(c); pass1(c); members(c); pass3(c) }
//
// instead of `pass1(all c); members(all c); pass3(all c)`. That order is what makes the frame's
// INACTIVE COMPONENTS a contiguous TAIL of the body, which is the property the single frame-level
// early exit (`vchunkactive` -> the body-done label) already expresses and the member-major order
// does not: in member-major order component c of member i is followed by component 0 of member
// i+1, which is live.
//
// THE ADMITTED CLASS IS DERIVED, NOT CHOSEN. RvvRunGroupedComponentMajor() accepts a run only when
// its guard kind is the one kind that both bounds `vec.vl` by `vlmax` and does NOT prove
// `vl == VLMAX` (qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax && !GuardProvesFullVl), which on
// the run path is `VTypePartialVlVstartFrmRNE` and nothing else. No opcode list, no guest pc, no
// VLEN special case and no threshold appears in that predicate or here.
//
// IT DOES NOT ENABLE THE BOUND. With this switch on and `rvv_qcg_active_vl_run_bound` off, the
// frame is the grouped body with NO `vchunkactive` node in it -- the control arm. The two arms'
// bodies are identical node for node except for the bound nodes, which is the single-factor
// property the ablation needs and which the focused test asserts directly.
//
// MUTUALLY EXCLUSIVE WITH THE OTHER BODY SELECTORS, refused loudly in elfrun/elfaot:
// `--rvv-run-body=materialize`, `--rvv-run-live-range-split`, `--rvv-run-order=chunk`,
// `--rvv-run-component-separable` and `--rvv-run-dep-probe-depth` each rewrite or reorder the same
// body with a different residency model.
inline bool rvv_run_grouped_component_major = false;

// C4e (2026-09-14, --rvv-qcg-active-vl-run-bound, default off). THE ACTIVE-SUFFIX BOUND ON A
// GROUPED MULTI-MEMBER RUN FRAME, and the ONLY factor separating arm C from arm B.
//
// It is the fourth member of the `rvv_qcg_active_vl_*` policy family and it is read in exactly the
// same place the other three are: as `ActiveChunkInput::family_enabled`, by the caller, for its own
// frame family. Everything else about the decision -- the guard conjuncts, the element stride, the
// `vl == 0` unit, the 64-chunk cap -- is the SHARED planner's and is not restated here.
//
// IT CANNOT BE SET WITHOUT THE BODY. `--rvv-qcg-active-vl-run-bound` requires
// `--rvv-run-grouped-component-major=1`, refused in elfrun/elfaot: on a member-major body the early
// exit would jump past LATER MEMBERS, which is the fact
// `rvvplan::ActiveChunkInput::suffix_is_body_tail` states and `QEmit::Emit_vchunkactive` Panics on.
inline bool rvv_qcg_active_vl_run_bound = false;

// C4h (2026-09-14, --rvv-qcg-active-vl-bound-placebo, default off). AN EVALUATION-ONLY MEASUREMENT
// CONTROL. NOT a lowering, NOT a policy, NOT a method, and it must never be defaulted on or appear
// in any performance, ROI or ceiling claim.
//
// WHAT PROBLEM IT EXISTS FOR. C4g measured arm C (bound on) against arm B (bound off) and found
// that at the two runtime `vl` values where the bound CANNOT fire -- census-confirmed
// `chunks_executed == chunks_available` -- arm C still finished 0.91 % / 2.67 % faster while
// retiring 2.4 % MORE instructions. A difference that survives at constant executed work is a
// property of the emitted code's SHAPE (its length, its branch inventory, and everything a 24-byte
// longer hot block does to where the following blocks land), not of any work the bound skipped.
// B -> C therefore is not a single factor: it changes the code shape AND the work.
//
// WHAT IT DOES. It weakens the immediate every `vchunkactive` node compares `vec.vl` against, from
// that unit's own first element index to 0. Nothing else: the node is still created, by the same
// finalizer, at the same position, with the same `chunk` index, and QEmit emits the same two
// instructions (`cmp [vec.vl], imm` + `jbe` to the frame's body-done label) at the same place with
// the same branch target. The arm therefore carries the bound's full code-shape cost and skips
// nothing, which is the control arm B cannot be.
//
// WHY 0 IS SOUND AND IS NOT A MAGIC NUMBER. A bound is correct because
// `vl <= element_base(c)` implies every element unit c..units-1 covers lies in the tail set
// [vl, VLMAX) (qir.h, InstVChunkActive). Replacing `element_base(c)` with any SMALLER value `t`
// preserves the implication direction -- `vl <= t` implies `vl <= element_base(c)` -- so the bound
// can only skip LESS, never more. `t = 0` is `element_base(0)`, the frame's own first architectural
// element index, produced by the same planner expression; it is the weakest sound member of the
// same family. It fires exactly when `vl == 0`, the architecturally empty vector, which is a case
// the real bound's own unit-0 immediate already fires on. So this arm's skipped-component set is a
// SUBSET of the real arm's at every `vl`, and the frame's values are correct on every path.
//
// WHERE IT IS READ. `rvvfinal::CloseFrame`'s bound-insertion loop, and nowhere else. It must NOT be
// pushed into `rvvplan::ActiveChunkPlan::element_base()`: that one expression is used TWICE, once
// for the bound's immediate and once for the guarded unit's own lane-mask base, and weakening it
// there would move the body's active lanes -- wrong values rather than a control.
//
// ENCODING EQUIVALENCE, which is the whole point and is a property of the frame family rather than
// of this switch. asmjit encodes `cmp dword ptr [reg+disp32], imm` as the 8-byte `REX 83 /7 ib`
// form while the immediate fits in a signed byte and as the 11-byte `81 /7 id` form otherwise, so
// substituting 0 leaves the emitted length unchanged only while every bound immediate in the frame
// is already below 128. For the grouped run family that is a theorem, not a hope: EMUL is pinned to
// 1, `rvvrun::kMaxChunks` is `VLEN_MAX_BITS / 512 == 8`, and an FP host chunk holds at most 16
// lanes, so the largest immediate any admitted frame can carry is 7 * 16 == 112. The focused test
// asserts both halves -- that this family stays under the boundary, and that crossing it really
// does change the length, so the equivalence check is live rather than vacuous.
//
// REQUIRES `rvv_qcg_active_vl_run_bound`, refused in elfrun/elfaot: with no bound node to weaken
// the switch would silently name an arm identical to its control.
inline bool rvv_qcg_active_vl_bound_placebo = false;

// R1A.3d: emit the QCG research hit counter.
//
// `CPUState::rvv_direct_hits` is incremented by JIT-EMITTED code at the join of EVERY typed frame
// -- one `inc` per frame, on the TIMED fast path. That is instrumentation of this research build,
// not method, and R1A.3c had to report it as part of its measured delta because it could not be
// turned off. This switch turns it off, so a timing arm can be counter-free.
//
// SCOPE, stated here because getting it wrong invalidated an earlier design: the counter costs one
// instruction PER TYPED FRAME, not one per anything else. The R1A.3c frozen microkernel executes
// six typed frames per strip step with `rvv_vector_run=0` and five with it on, so switching this
// off removes six and five instructions per strip step respectively.
//
// The FALLBACK counter (`rvv_direct_fallbacks`) is deliberately NOT gated by this switch. It sits
// after the guard-miss label, so it costs a timed guard-hit arm nothing, and `guard_fallbacks == 0`
// is the one validity gate a counter-free timing arm can still carry on every invocation.
//
// The LLVM backend has had exactly this shape since S3.7 (QIRToLLVM::RvvCount, gated on
// `rvv_vector_ssa_counters`, default OFF). This restores the symmetry for QCG -- but with the
// default the other way round, TRUE, so every accepted pinned golden stays byte-identical.
inline bool rvv_qcg_hit_counter = true;

// Strong prior-art comparator: typed fixed-512-bit chunk SSA, explicit masks
// and EVL through QIR into the LLVM AOT backend.  Default off keeps B exactly
// the current helper path.  The emitted artifact contains runtime semantic
// guards and uses B on every unsupported state.
inline bool rvv_vector_ssa = false;
inline bool rvv_vector_ssa_counters = false;
// T7a experiment (default off): preserve the one admitted unmasked e32/m1/full-VL vadd.vv as
// InstRVVAddV and lower it to one VLEN-wide LLVM vector operation instead of partitioning it into
// V512 QIR chunks.  Only meaningful with LLVM AOT + rvv_vector_ssa at VLEN 512/1024.  The ordinary
// chunked route remains the baseline when this is off; no other opcode consults this switch.
inline bool rvv_llvm_wide_vadd = false;
// T7b experiment (default off): retain the same exact vadd.vv as one wide LLVM add, but take and
// return the accepted route's V512 QIR SSA values instead of crossing through CPUState.  T7a's
// state-backed switch above remains independently available for audit.
inline bool rvv_llvm_wide_vadd_ssa = false;
// Set by elfaot from the actual code-generation host.  LLVM lowers a strict
// constrained FMA to a libc call when the target has no hardware FMA; that is
// neither a direct vector substrate nor safe on rvdbt's boundary-switched host
// stack.  Such hosts retain all other typed operations and use the exact RVV
// helper for FMA.
inline bool rvv_vector_ssa_host_fma = false;
// TEST HOOK (default 0 = off): deliberately corrupt the fixed-width result of the Nth vector op.
// Exists so --rvv-verify can be DEMONSTRATED to catch a divergence -- a differential checker
// that has never fired is not evidence of anything. Never set outside the verifier self-test.
inline unsigned long long rvv_inject_fault = 0;
// P13 dynamic RVV cost census (2026-08-18). 0 = off (one predicted-not-taken branch per vector
// helper, nothing at all in scalar handlers), 1 = invocation/element counts, 2 = counts plus an
// rdtsc pair per vector instruction. Mode 1 exists so element work is never read off a run whose
// timing was distorted by the instrumentation. See dbt/guest/rv32_vector_census.h.
// T5b-1 DIAGNOSTIC, default off. Per-guest-PC census of vector instructions that ran in C++
// instead of in emitted host code. The route census is limited to T1's nine opcodes and the P13
// census is process-wide; neither can say whether a fallback came from the timed kernel or from
// the adapter. Cold path only; nothing emitted changes. See dbt/guest/rv32_pc_census.h.
inline bool rvv_pc_census = false;
inline char const *rvv_pc_census_out = "";
inline unsigned rvv_census = 0;
inline char const *rvv_census_out = "";
// T3a per-route execution census (default OFF). When set, every execution of a vector instruction
// that runs in the C++ handler -- whether reached through the JIT's stub call on a guard miss, or
// through the interpreter -- is counted against the guest OPCODE it decodes to. The two existing
// counters (CPUState::rvv_direct_hits / rvv_direct_fallbacks) are aggregate over all typed frames
// and cannot answer "did THIS opcode take the direct route", which is what T3a has to establish;
// and four ALU opcodes share the one `rv32_vialu` helper, so per-stub counting could not separate
// them either. Costs one predicted-not-taken branch in vector handlers only (the call site is
// behind `if constexpr (name_is_vector(...))`), and changes NOTHING in emitted code, so every
// pinned disassembly golden is byte-identical with this on or off. See
// dbt/guest/rv32_route_census.h.
inline bool rvv_route_census = false;
// P13 phase-B probes (default 0 = off). Bit 1: per-PC vector census. Bit 2: evaluate B1's FP
// precondition without acting on it. Probes never change behaviour; they exist so a candidate
// can be falsified before a lowering is written.
// P13 phase C: semantic-class chunk lowering with discharged obligations. Default OFF so every
// measurement has an in-binary A/B control; the ablation flips only this bit.
inline bool rvv_fast = false;
// P15 candidate 7: fuse an adjacent pair of integer element-wise VV ops so the intermediate stays
// in a host vector register instead of round-tripping through VectorState. Default OFF so every
// measurement has an in-binary A/B control. Admitted only for the shape proven unobservable in
// rvv_fusible_pair(); everything else runs the unchanged single-op path.
inline bool rvv_fuse_pairs = false;
// M1 (docs/M1_TAIL_ROUNDED_EXTENT.md): round the executed byte extent up to a whole host chunk when
// the guest's tail policy is AGNOSTIC (vta=1), so a short vl runs one whole-width chunk instead of
// a per-element residue loop. Default OFF so every measurement has an in-binary A/B control.
// Register-to-register arithmetic only; memory operations keep their exact extent because
// over-reading past vl could fault on a page the guest never touches.
inline bool rvv_tail_round = false;
// Pre-admission extent guard: refuse an operation whose extent cannot reach the narrowest host
// chunk, so it goes straight to the reference loop instead of the fast path's per-element
// out-of-line fallback. Default off so every measurement has an in-binary A/B control.
inline bool rvv_preadmit_extent = false;
// C-beta substrate: host gather for the guest's UNORDERED indexed load (vluxei). Default off so the
// substrate has its own in-binary A/B arm and its gain is never folded into a method's.
inline bool rvv_gather = false;
// Which semantic classes the method may admit, as a bitmask: 1 = integer element-wise,
// 2 = FP element-wise add/sub/mul/div, 4 = the FP fused multiply-add forms, 8 = FP compare
// (mask-producing). Default all. This exists so the operation-class ablation needs no rebuild:
// FMA is predicted to account for most of the method's coverage, and a reader is entitled to see
// that separated rather than folded into one number.
inline unsigned rvv_fast_classes = 15;
// P13 B3-narrow (2026-08-19, docs/P3_B3_NARROW_PROTOTYPE_DESIGN.md): let try_falu/try_fma/
// try_vfcmp hand an open FRound bracket to the immediately-following guest instruction instead
// of closing it, when that instruction is also eligible (same-block, zero intervening
// instructions -- the STRICT tier of docs/P3_B3_RUN_LENGTH_ANALYSIS.md). Default ON so it is
// part of the method's real coverage; 0 is the isolated A/B control that shows the marginal
// effect of batching specifically, holding every other admitted class/shape decision fixed.
inline bool rvv_fround_batch = true;
// P13 Ceiling-P4 (2026-08-19, docs/HW_CALIBRATION_FINDINGS.md): the MXCSR bracket itself, as
// opposed to how many brackets get opened. Hardware counters on xbd measure one full bracket
// (STMXCSR save + LDMXCSR set + STMXCSR harvest + LDMXCSR restore) at 57.0 cycles -- against
// 2.0 cycles for an entire ialu chunk -- making it the single largest cost in the method, and
// 36.0 of those 57.0 are the save/restore pair rather than the semantically-required
// set-mode/harvest-flags pair. This selects how much of that pair to elide:
//
//   0 = current shipped behaviour: read the old MXCSR, restore exactly it. The A/B control.
//   1 = drop the SAVE. PROVABLY equivalent to mode 0 as the source stands: the only writers of
//       MXCSR anywhere in rvdbt are this bracket and the scalar FRound in rv32_fpu.h, and
//       nothing anywhere sets FTZ/DAZ/exception-mask bits, so `saved & ~(RC|FLAGS)` is a
//       process-lifetime constant. `g_mxcsr_resting` captures it once; re-reading it per run is
//       pure redundancy. Still restores the resting value on close.
//   2 = additionally drop the RESTORE. This one is NOT free of preconditions: it requires the
//       invariant that no host FP code executing BETWEEN brackets depends on MXCSR.RC or on the
//       accrued exception-flag bits. That holds for rvdbt as written (every host FP path goes
//       through one of the two brackets, each of which sets RC explicitly and clears FLAGS on
//       entry), but it is an invariant to ENFORCE, not one the type system gives us -- hence a
//       separate mode rather than folding it into 1.
//
// Default 0: this is a measurement instrument for the executable ceiling (Texe), and a mode
// that changes guest-visible FP results would be a bug, so the A/B control must be the default
// until the correctness gate has run against every mode.
inline unsigned rvv_fround_mxcsr_mode = 0;
// P14 cycle 4: amortise the scalar-FP rounding bracket across consecutive FP ops. Off by default
// so every measurement has an in-binary A/B control.
inline bool rvv_scalar_fround_run = false;
// G7 cycle 3: compare the mirrored rounding-control field instead of re-reading MXCSR on every
// continued FP op. Off by default = the A/B control.
inline bool rvv_scalar_fround_rcmirror = false;
// N2b candidate 5: dispatch whole-register copies on a constant size so they inline. Engineering
// fix, off by default = the A/B control.
inline bool rvv_fixed_copy = false;
// Captured once, before any guest code runs, from the process's own MXCSR: the bits outside
// RC and FLAGS (FTZ, DAZ, exception masks) that no rvdbt code ever modifies.
inline unsigned g_mxcsr_resting = 0;
// P13 Ceiling-P5: replace try_vfcmp's per-ELEMENT mask read-modify-write with a single batched
// write per host chunk. Hardware counters measure the per-element path at 75 instructions /
// 19.29 cycles per chunk versus 18 / 2.84 for the batched form -- the largest per-chunk gap of
// any arithmetic family (85%). Default OFF so the per-element path stays the A/B control, and
// because the corpus-weighted end-to-end value of this change is exactly what has to be
// MEASURED rather than assumed: the equivalent MXCSR model term proved 1.9x optimistic when its
// executable oracle was finally run, so this one gets the same treatment before any claim.
inline bool rvv_vfcmp_batch_mask = false;
// P13 cross-VLEN: specialise the reduction element loop on its LOOP-INVARIANT semantic parameters.
// Measured cause (docs/REDUCTION_HEADROOM_AND_DECISION.md): rv32_vector_lower.h's vfred re-tests
// f6 (opcode), md.path (FP mode), sew and vm on EVERY element and round-trips the accumulator
// through integer bits with a canonicalisation each step, costing 12.45 cyc/element where the
// semantic floor -- the latency of a serial dependent FP add, since vfredosum is ORDERED and may
// not be reassociated -- is 3.00. All four tested properties are fixed for the whole instruction.
// Default OFF: this is a measurement arm until the differential correctness gate passes.
// Staged so the three independent changes can be ABLATED SEPARATELY rather than only as a bundle:
//   0 = original per-element loop (baseline)
//   1 = + invariant hoisting only: opcode/FP-mode/SEW/mask tested ONCE outside the loop, but the
//       accumulator still round-trips through integer bits and canonicalises every element
//   2 = + native accumulator: the accumulator stays a float/double, still canonicalised per element
//   3 = + canonicalisation moved to the end (the full method)
//   4 = MEASUREMENT ARM ONLY, not a proposed implementation: canonicalisation at the end but the
//       accumulator still round-tripping through bits. It is the fourth cell of the
//       {native accumulator} x {canonicalisation placement} 2x2, so each of those two effects can
//       be read at both levels of the other and the attribution is not an artefact of the order
//       they were applied in. Stage 4 is dominated by stage 3 and is never a shipping candidate.
inline unsigned rvv_fred_specialize = 0;
// Codex 5th review, BOUND_DEFINITION.md: the run-detection trace-replay oracle. 0 = off (normal
// `fround_run_peek_next_eligible`, unaffected). 1 = RECORD -- run the real peek exactly as
// normal, additionally append its return value to `rvv_fround_oracle_file`. 2 = REPLAY (the
// oracle itself, `To`) -- skip the real peek's guest-memory bounds check/decode entirely and
// return the next value from a preloaded trace instead, an O(1) array read. Requires
// `rvv_fround_batch = true` (batch=0 already means "never continue," independent of this).
inline unsigned rvv_fround_oracle_mode = 0;
inline char const *rvv_fround_oracle_file = "";
// P13 U2 width policy: 0 = off (the compile-time fixed width path, i.e. the existing control),
// 1 = fixed16, 2 = fixed64, 3 = cascade. One binary carries all four arms so the ablation is a
// runtime flag and can never be a build effect.
inline unsigned rvv_width_policy = 0;
inline unsigned rvv_probe = 0;
inline char const *rvv_probe_out = "";
inline unsigned rvv_seqtrace = 0;
inline char const *rvv_seqtrace_out = "";
// 2026-06-23: AOT-static + NGR-gencode composition enabler. elfaot profiles a generated-code workload ->
// the profile includes RUNTIME gen-code pages (mmap'd matchers), which are NOT in the static ELF. The AOT
// then reads those unmapped guest addresses -> SIGSEGV (manymatch + pcre2 both crash). With this flag the
// AOT skips pages outside the ELF's PF_X PT_LOAD ranges (g_elf_exec_ranges), compiling ONLY the static
// .text. No-op for normal workloads (all exec pages are ELF-backed). Lets us AOT the static library and
// JIT/NGR the runtime gen-code in one run.
inline bool aot_skip_nonelf = false;
inline std::vector<std::pair<uint32_t, uint32_t>> g_elf_exec_ranges; // [start,end) of ELF PF_X PT_LOAD segments
// A-line round 32 R32.9: [start,end) of ELF PT_LOAD segments WITHOUT PF_W -- i.e. genuinely
// non-writable at the OS level for this process's whole lifetime (same loader, same mmap PROT
// translation as g_elf_exec_ranges above). Used by the in-process static jump-table resolver
// (rv32_qir.cpp) to certify a candidate table's memory is immutable, without a separate
// analysis pass or file: this is a byproduct of the SAME LoadElf call every elfaot/elfrun
// invocation already performs.
inline std::vector<std::pair<uint32_t, uint32_t>> g_elf_nonwritable_ranges;
} // namespace dbt::config
namespace dbt::brindedges
{
extern unsigned long g_rec_n, g_rec_stride, g_rec_skip;
static inline bool ShouldRecord()
{
	// doubling decimation, caller-side (one branch + decrement per slowpath miss): stride doubles each
	// time the recorded count doubles past a 64-record floor -> log-many records, transient preserved
	if (g_rec_skip > 0) {
		g_rec_skip--;
		return false;
	}
	g_rec_n++;
	if ((g_rec_n & (g_rec_n - 1)) == 0 && g_rec_n >= 64)
		g_rec_stride *= 2;
	g_rec_skip = g_rec_stride - 1;
	return true;
}
void Record(uint32_t src, uint32_t dst);
void RecordWindowVisit(uint32_t gip);
void Dump(char const *path);
unsigned long Count(); // distinct edges observed (dry-stop audit)
void ForEachNode(void (*cb)(unsigned)); // web-repack: enumerate observed web nodes
} // namespace dbt::brindedges
