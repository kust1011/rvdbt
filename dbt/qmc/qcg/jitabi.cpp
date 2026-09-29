#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/execute.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/tcache/tcache.h"

// Round-15 DIA: indirect source->target edge profile storage (default-off; populated only with --profile-brind-edges).
// Single-threaded guest; keyed (src<<32)|dst.
#include <array>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
#include <time.h>
#include <cstdio>
static std::unordered_map<unsigned long long, unsigned long long> g_brind_edges;
// Round-21: temporal channel profile -- stub visits per 50ms window (ALL indirect transfers incl returns).
// The max silent window predicts BCT promotion-channel latency (the qsort 2.1s init-phase case).
static std::vector<unsigned> g_brind_windows;
static std::vector<unsigned> g_brind_window_distinct; // round-24: distinct targets per window (epoch-stamp approx)
static long g_window_t0_ms = -1;
static unsigned g_stamp_tab[1 << 16];                 // gip-hash -> last window id (+1); collisions undercount slightly
// 2026-06-15 method-search OBS2 (default-off, only under --brind-edges-out): per-SITE temporal predictability.
// For each indirect source, track whether the target equals the immediately-previous target at that site
// (sequential 1-step same-rate). Comparing this to the iid baseline sum(p_i^2) measures TEMPORAL LOCALITY:
// if seq-same >> iid-same, a high-global-entropy site is locally predictable (target runs) -> specializable
// per-phase even though global-entropy methods (PCDL/SDS) abstain. Pure measurement, no behavior change.
static std::unordered_map<uint32_t, uint32_t> g_brind_last;             // src -> last dst
static std::unordered_map<uint32_t, unsigned long long> g_brind_seqsame; // src -> #(dst==last) [1-level MRU hit]
static std::unordered_map<uint32_t, unsigned long long> g_brind_seqdiff; // src -> #(dst!=last)
// OBS3 (default-off): 2-level / path-history predictor. Key (src, prev_dst) -> last dst observed in that context.
// Hit = current dst equals the prediction for (src, prev_dst). If 2-level hit-rate >> 1-level (seqsame) hit-rate,
// the target is PATH-PREDICTABLE (context-sensitive devirtualization possible) even when site-alone is polymorphic.
static std::unordered_map<unsigned long long, uint32_t> g_brind_2lvl;    // (src<<32|prev_dst) -> predicted dst
static std::unordered_map<uint32_t, unsigned long long> g_brind_2hit;    // src -> #(dst==pred[src,prev])
static std::unordered_map<uint32_t, unsigned long long> g_brind_2miss;   // src -> #(dst!=pred[src,prev])
// R4 cross-input test: full 2-level transition multigraph (src,prev)->target->count, so a table learned on
// program A can be cross-applied to program B's transitions (does PATH structure transfer where 1-level target
// distribution does NOT, V135). Default-off (only under --brind-edges-out).
static std::unordered_map<unsigned long long, std::unordered_map<uint32_t, unsigned long long>> g_brind_trans;
// Round-31 Gate 1: per-window per-source target-identity collector (default-off, only active
// under --brind-edges-out, same discipline as g_brind_trans above). Keyed by (src, window) ->
// target -> count. Windows are DETERMINISTIC EXECUTION-COUNT buckets (every PHASE_WINDOW_SIZE
// recorded dispatches = one window), NOT wall-time -- chosen because wall-time (50ms,
// RecordWindowVisit above) is subject to scheduler jitter/preemption noise and is not
// reproducible run-to-run, while an execution-count window is exactly reproducible from the
// deterministic guest instruction stream, matching this whole project's "exhaustive truth for
// the measured run" discipline. PHASE_WINDOW_SIZE=100000 is a round, workload-independent
// constant chosen BEFORE looking at any phase-collector output (not fit to expat/wasm3/any
// workload's statistics) -- it gives a window count in the same order of magnitude as the
// existing wall-time windows (expat 536, wasm3_indcall 292) without curve-fitting: expat's
// 39.3M total dispatches / 100000 = ~393 windows, wasm3's 23.4M / 100000 = ~234 windows.
static constexpr unsigned long long PHASE_WINDOW_SIZE = 100000;
static unsigned long long g_phase_dispatch_count = 0;
static std::map<std::pair<uint32_t, uint32_t>, std::unordered_map<uint32_t, unsigned long long>> g_brind_phase;
bool dbt_inrun_artifact_present(); // Round-17 BCT (defined in aot_boot.cpp, global scope)
namespace dbt::brindedges
{
unsigned long Count() { return (unsigned long)g_brind_edges.size(); } // distinct edges observed
// A-line web-repack: enumerate the observed web's node set (sources and targets)
void ForEachNode(void (*cb)(unsigned))
{
	for (auto const &[k, c] : g_brind_edges) {
		cb((unsigned)(k >> 32));
		cb((unsigned)k);
	}
}
// DOUBLING DECIMATION state (see ShouldRecord below); DECIM raw taught the second half of the lesson:
// the decimation gate must run BEFORE the caller's guest-memory read (is_ret), or the per-visit cost
// (one guest load + branches on EVERY slowpath miss) returns in full (sqlite +4~+21, xalan 8.3->11.7).
unsigned long g_rec_n = 0, g_rec_stride = 1, g_rec_skip = 0;
void Record(uint32_t src, uint32_t dst)
{
	g_brind_edges[((unsigned long long)src << 32) | dst]++;
	auto it = g_brind_last.find(src);
	if (it != g_brind_last.end()) {
		uint32_t prev = it->second;
		if (prev == dst)
			g_brind_seqsame[src]++;
		else
			g_brind_seqdiff[src]++;
		// OBS3 2-level: predict dst from (src, prev_dst) context
		unsigned long long key = ((unsigned long long)src << 32) | prev;
		g_brind_trans[key][dst]++; // R4: full transition table for cross-input transfer eval
		auto p = g_brind_2lvl.find(key);
		if (p != g_brind_2lvl.end()) {
			if (p->second == dst)
				g_brind_2hit[src]++;
			else
				g_brind_2miss[src]++;
			p->second = dst;
		} else {
			g_brind_2lvl[key] = dst;
		}
		it->second = dst;
	} else {
		g_brind_last[src] = dst;
	}
}
void RecordWindowVisit(uint32_t gip)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
	long now = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
	if (g_window_t0_ms < 0)
		g_window_t0_ms = now;
	unsigned w = (unsigned)((now - g_window_t0_ms) / 50);
	if (g_brind_windows.size() <= w) {
		g_brind_windows.resize(w + 1, 0);
		g_brind_window_distinct.resize(w + 1, 0);
	}
	g_brind_windows[w]++;
	unsigned h = (gip >> 1) & 0xffff;
	if (g_stamp_tab[h] != w + 1) {
		g_stamp_tab[h] = w + 1;
		g_brind_window_distinct[w]++;
	}
}
// Round-31 Gate 1: deterministic execution-count-window per-source target-identity recorder. Only
// called from the SAME --brind-edges-out call site as Record()/RecordWindowVisit() above, with the
// SAME is_return gating already applied by the caller -- inherits correct RETURN/TAILCALL exclusion
// for free rather than re-deriving it. window index is g_phase_dispatch_count / PHASE_WINDOW_SIZE at
// the moment of THIS call, so the very first call is window 0 and windows advance monotonically and
// deterministically with the guest instruction stream (never with wall time).
void RecordPhase(uint32_t src, uint32_t dst)
{
	unsigned window = (unsigned)(g_phase_dispatch_count / PHASE_WINDOW_SIZE);
	g_brind_phase[{src, window}][dst]++;
	g_phase_dispatch_count++;
}
void Dump(char const *path)
{
	FILE *f = fopen(path, "w");
	if (!f)
		return;
	for (auto const &[k, c] : g_brind_edges)
		fprintf(f, "%08x %08x %llu\n", (unsigned)(k >> 32), (unsigned)k, c);
	fclose(f);
	std::string wp = std::string(path) + ".windows";
	FILE *fw = fopen(wp.c_str(), "w");
	if (!fw)
		return;
	for (size_t i = 0; i < g_brind_windows.size(); ++i)
		fprintf(fw, "%zu %u %u\n", i * 50, g_brind_windows[i],
			i < g_brind_window_distinct.size() ? g_brind_window_distinct[i] : 0);
	fclose(fw);
	// OBS2: per-site sequential predictability (src seqsame seqdiff) -> temporal-locality analysis.
	std::string sp = std::string(path) + ".seq";
	FILE *fs = fopen(sp.c_str(), "w");
	if (!fs)
		return;
	for (auto const &[src, same] : g_brind_seqsame)
		fprintf(fs, "%08x %llu %llu\n", src, same,
			g_brind_seqdiff.count(src) ? g_brind_seqdiff[src] : 0ull);
	// also emit sites that only ever had diffs (no same)
	for (auto const &[src, diff] : g_brind_seqdiff)
		if (!g_brind_seqsame.count(src))
			fprintf(fs, "%08x %llu %llu\n", src, 0ull, diff);
	fclose(fs);
	// OBS3: per-site 2-level (path-history) predictor hits/misses (src 2hit 2miss).
	std::string s2 = std::string(path) + ".seq2";
	FILE *f2 = fopen(s2.c_str(), "w");
	if (!f2)
		return;
	for (auto const &[src, hit] : g_brind_2hit)
		fprintf(f2, "%08x %llu %llu\n", src, hit,
			g_brind_2miss.count(src) ? g_brind_2miss[src] : 0ull);
	for (auto const &[src, miss] : g_brind_2miss)
		if (!g_brind_2hit.count(src))
			fprintf(f2, "%08x %llu %llu\n", src, 0ull, miss);
	fclose(f2);
	// R4: full 2-level transition multigraph (src prev target count) for cross-input transfer evaluation.
	std::string tp = std::string(path) + ".trans";
	FILE *ft = fopen(tp.c_str(), "w");
	if (!ft)
		return;
	for (auto const &[key, tm] : g_brind_trans)
		for (auto const &[tgt, c] : tm)
			fprintf(ft, "%08x %08x %08x %llu\n", (unsigned)(key >> 32), (unsigned)key, tgt, c);
	fclose(ft);
	// Round-31 Gate 1: per-window per-source target-identity table (src window target count).
	// Sum over window for a fixed src reproduces that src's row in g_brind_edges/.trans exactly
	// (same underlying Record() population, just also bucketed by deterministic dispatch-count
	// window) -- the consistency check task cross-references this directly.
	std::string pp = std::string(path) + ".phase";
	FILE *fp = fopen(pp.c_str(), "w");
	if (!fp)
		return;
	for (auto const &[key, tm] : g_brind_phase)
		for (auto const &[tgt, c] : tm)
			fprintf(fp, "%08x %u %08x %llu\n", key.first, key.second, tgt, c);
	fclose(fp);
}
} // namespace dbt::brindedges

namespace dbt::jitabi
{

struct _RetPair {
	void *v0;
	void *v1;
};

#define HELPER extern "C" NOINLINE __attribute__((used))
#define HELPER_ASM extern "C" NOINLINE __attribute__((used, naked))

/*    qmc qcg/llvm frame layout, grows down
 *
 *			| ....		|  Execution loop
 *	trampoline call +---------------+-----------------------
 *			| link+fp|saved |  qcg spill frame, created in trampoline
 *			+---------------+  no callee saved regs expected
 *			| qcg locals	|  returning to this frame is not allowed
 *  	       tailcall +---------------+-----------------------
 *			| link+pad  	|  Translated region frame
 *			+---------------|  Destroyed on branch to next region
 *			| llvm locals	|  qcg/ghccc callconv doesn't preserve fp
 *   abs/qcg-reloc call +---------------+-----------------------
 *			| ....		|  qcgstub_* frame
 */

static_assert((qcg::ArchTraits::spillframe_size & 15) == 0);
static_assert(qcg::ArchTraits::STATE == asmjit::x86::Gp::kIdR13);
static_assert(qcg::ArchTraits::MEMBASE == asmjit::x86::Gp::kIdBp);

// Build qcg spillframe and enter translated code
HELPER_ASM ppoint::BranchSlot *trampoline_to_jit(CPUState *state, void *vmem, void *tc_ptr)
{
	asm("pushq	%rbp\n\t"
	    "pushq	%rbx\n\t"
	    "pushq	%r12\n\t"
	    "pushq	%r13\n\t"
	    "pushq	%r14\n\t"
	    "pushq	%r15\n\t"
	    "movq 	%rdi, %r13\n\t"	  // STATE
	    "movq	%rsi, %rbp\n\t"); // MEMBASE
	asm("sub     	$%c0, %%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("leaq	-8(%rsp), %rsi\n\t"); // sp of qcg tailcall frame
	asm("movq	%%rsi, %c0(%%r13)\n\t" : : "i"(offsetof(CPUState, sp_unwindptr)));
	asm("callq	*%rdx\n\t" // tc_ptr
	    "int	$3");	   // use escape/raise stub instead
}

// Escape from translated code, forward rax(slot) to caller
HELPER_ASM void qcgstub_escape_link()
{
	asm("addq   	$%c0, %%rsp" : : "i"(qcg::ArchTraits::spillframe_size + 16));
	asm("popq	%r15\n\t"
	    "popq	%r14\n\t"
	    "popq	%r13\n\t"
	    "popq	%r12\n\t"
	    "popq	%rbx\n\t"
	    "popq	%rbp\n\t"
	    "retq	\n\t");
}

// Escape from translated code, return nullptr(slot) to caller
// A different stub used because llvm may overwrite rax before escaping
HELPER_ASM void qcgstub_escape_brind()
{
	asm("addq   	$%c0, %%rsp" : : "i"(qcg::ArchTraits::spillframe_size + 16));
	asm("popq	%r15\n\t"
	    "popq	%r14\n\t"
	    "popq	%r13\n\t"
	    "popq	%r12\n\t"
	    "popq	%rbx\n\t"
	    "popq	%rbp\n\t"
	    "xorq	%rax, %rax\n\t"
	    "retq	\n\t");
}

// Caller uses 2nd value in returned pair as jump target
static ALWAYS_INLINE _RetPair TryLinkBranch(CPUState *state, ppoint::BranchSlot *slot)
{
	if (dbt::config::trace) {
		state->DumpTraceCache(slot->gip, state->ip);
	}
	// T5c-0 DIRECT-LINK ESCAPE, consumer half (--inrun-escape-unlink, default off). The keeper has
	// just returned this slot to the lazy stub; re-linking here and jumping straight on would put
	// control back in the code cache without ever passing the Execute() loop, so the pending tier
	// event would still not be consumed and the unlink would have bought nothing. Take the escape
	// the not-found case below already uses instead: it sets state->ip and returns to the loop,
	// which re-links this slot on the host stack after running the evaluator/boot call site. This
	// is the same idiom the brind slowpath uses for the identical reason (see the inrun_escalate_due
	// escape in qcgstub_brind_slowpath); it adds no decision and no new state.
	bool esc = unlikely(dbt::config::inrun_escape_unlink) && dbt::config::inrun_tier &&
		   !dbt::config::inrun_booted &&
		   (dbt::config::inrun_escalate_due || dbt::config::inrun_poll_due);
	auto found = tcache::Lookup(slot->gip);
	if (likely(found) && !esc) {
		// found->flags.exec_count += 1;
		slot->Link(found->tcode.ptr);
		tcache::RecordLink(slot, found, slot->flags.cross_segment);
		tcache::CacheBr(found);
		return {slot, found->tcode.ptr};
	}
	state->ip = slot->gip;
	return {slot, (void *)qcgstub_escape_link};
}

// Lazy region linking, absolute call target (jit/aot mode)
HELPER_ASM void qcgstub_link_branch_jit()
{
	asm("movq	0(%rsp), %rsi\n\t"
	    "movq	%r13, %rdi\n\t"
	    "callq	qcg_TryLinkBranchJIT@plt\n\t"
	    "popq	%rdi\n\t" // pop somewhere
	    "jmpq	*%rdx\n\t");
}

// Lazy region linking, qcg-relocation call target (aot mode)
HELPER_ASM void qcgstub_link_branch_aot()
{
	asm("movq	0(%rsp), %rsi\n\t"
	    "movq	%r13, %rdi\n\t"
	    "callq	qcg_TryLinkBranchAOT@plt\n\t"
	    "popq	%rdi\n\t" // pop somewhere
	    "jmpq	*%rdx\n\t");
}

// Lazy region linking, qcg-relocation call target with stack check (llvm aot mode)
HELPER_ASM void qcgstub_link_branch_llvmaot()
{
	asm("leaq	8(%rsp), %rdx\n\t" // sp in patchpoint
	    "movq	0(%rsp), %rsi\n\t"
	    "movq	%r13, %rdi\n\t"
	    "callq	qcg_TryLinkBranchLLVMAOT@plt\n\t"
	    "popq	%rdi\n\t" // pop somewhere
	    "jmpq	*%rdx\n\t");
}

HELPER _RetPair qcg_TryLinkBranchJIT(CPUState *state, void *retaddr)
{
	return TryLinkBranch(state, ppoint::BranchSlot::FromCallPtrRetaddr(retaddr));
}

HELPER _RetPair qcg_TryLinkBranchAOT(CPUState *state, void *retaddr)
{
	return TryLinkBranch(state, ppoint::BranchSlot::FromCallRuntimeStubRetaddr(retaddr));
}

HELPER _RetPair qcg_TryLinkBranchLLVMAOT(CPUState *state, void *retaddr, uptr in_sp)
{
	assert(in_sp == state->sp_unwindptr);
	return TryLinkBranch(state, ppoint::BranchSlot::FromCallRuntimeStubRetaddr(retaddr));
}

// A-line round 20: RAII rdtsc guard, accumulates into brind_slowpath_cycles on ANY return path
// (the function below has several early escapes for unrelated async housekeeping -- a destructor
// fires correctly regardless of which one is taken, unlike a hand-placed pre-return measurement).
struct BrindCycleGuard {
	uint64_t t0;
	bool active;
	BrindCycleGuard() : active(dbt::config::count_brind)
	{
		if (active)
			t0 = __builtin_ia32_rdtsc();
	}
	~BrindCycleGuard()
	{
		if (active)
			dbt::config::brind_slowpath_cycles += __builtin_ia32_rdtsc() - t0;
	}
};

// Indirect branch slowpath
HELPER void *qcgstub_brind(CPUState *state, u32 gip)
{
	BrindCycleGuard _brind_cycle_guard;
	if (dbt::config::count_brind) {
		dbt::config::brind_count++;
	}
	if (unlikely(dbt::config::wmax_sample)) {
		dbt::config::wmax_visit_count = dbt::config::wmax_visit_count + 1; // W_max sampler: sole per-visit cost
	}
	if (unlikely(dbt::config::inrun_tier) && !dbt::config::inrun_booted) {
		// Round-17 BCT: the bounce IS the promotion channel. Rate-limited file poll; when the concurrently-built
		// artifact lands, force ONE escape so the outer Execute loop performs the mid-run AOT boot (dlopen etc.
		// must not run on this spill frame). Dispatch working sets pass here constantly -> promotion applies fast.
		if (dbt::config::inrun_poll_due && !dbt::config::inrun_boot_pending) {
			dbt::config::inrun_poll_due = false;
			if (::dbt_inrun_artifact_present()) {
				dbt::config::inrun_boot_pending = true;
				state->ip = gip;
				return (void *)qcgstub_escape_brind;
			}
		}
		if (dbt::config::inrun_boot_pending) {
			state->ip = gip;
			return (void *)qcgstub_escape_brind;
		}
	}
	// A-line SAT-1b: sweep tick pending -- escape to the Execute loop where patching is safe
	// (host stack, no guest RIP inside any counting sequence). Same pattern as the BCT escapes.
	if (unlikely(dbt::config::sat_sweep_due) && dbt::config::qcg_freq_retire) {
		state->ip = gip;
		return (void *)qcgstub_escape_brind;
	}
	// P1: scan tick pending -- escape to the Execute loop (the scan walks tcache_map and the
	// one-shot fire does file I/O + a synchronous build; none of that may run on this spill
	// frame). Same BCT escape discipline as above.
	if (unlikely(dbt::config::p1_scan_due) && dbt::config::p1_promote) {
		state->ip = gip;
		return (void *)qcgstub_escape_brind;
	}
	// A-line web-repack: same escape discipline (revokes must run on the host stack)
	if (unlikely(dbt::config::web_repack_due) && dbt::config::sr_web_repack) {
		state->ip = gip;
		return (void *)qcgstub_escape_brind;
	}
	dbt::config::brind_slowpath_visits++;
	if (unlikely(dbt::config::sr_sampled_edges) &&
	    (dbt::config::sr_edges_all_misses || dbt::brindedges::ShouldRecord())) {
		// A-line 2026-07-23 (--sr-edges-all-misses): record EVERY natural slowpath visit, no
		// decimation. Measured natural-miss counts in whole profiling runs are tiny (wasm3_swtable
		// 350, sqlite_super 2082 via --count-brind) because the L1 dispatch cache absorbs the hot
		// repeats -- the DECIM cost lesson above applies to the exhaustive-forced recorder (every
		// dispatch a miss), not to this natural-miss population.
		// windowed edge sampling v2: record every NATURAL slowpath visit (keeper flushes already create
		// periodic observation windows; no cache bypass, no extra visits => zero added cost, orders more
		// coverage than the starved one-shot design). Returns excluded as in the exhaustive recorder.
		u32 prev = gip >= 4 ? *reinterpret_cast<u32 const *>((uptr)mmu::base + (uptr)(gip - 4)) : 0;
		u32 opcode = prev & 0x7f;
		bool is_ret = (opcode == 0x6f || opcode == 0x67) && ((prev >> 7) & 0x1f) != 0;
		if (!is_ret || dbt::config::sr_record_returns) // 12:14 A: opt-in return-edge SET
			dbt::brindedges::Record(state->ip, gip);
	}
	if (unlikely(dbt::config::inrun_escalate_due)) {
		// auto-escalate: force ONE escape so the Execute loop evaluates the census sign test on the host
		// stack (map walk + fork must not run on this spill frame). Same pattern as the boot escape above.
		state->ip = gip;
		return (void *)qcgstub_escape_brind;
	}
	if (dbt::config::trace) {
		state->DumpTraceCache(gip, state->ip);
	}
	if (unlikely(dbt::config::profile_brind_edges) &&
	    (dbt::config::sr_bounded_exhaustive_limit == 0 ||
	     dbt::config::g_bounded_exhaustive_count < dbt::config::sr_bounded_exhaustive_limit)) {
		if (dbt::config::sr_bounded_exhaustive_limit != 0)
			dbt::config::g_bounded_exhaustive_count++;
		// Round-15 DIA: profiling-mode jalr translation explicitly spills the source ModuleGraph-node
		// entry to state->ip before reaching this stub. Record that source key and preserve target marking
		// (objprof semantics), but SKIP the l1 brind-cache insert so every transfer keeps hitting this
		// slowpath -> full (src,dst,count) edge multigraph observed during the profiling run.
		// RETURN transfers (target preceded by a JALR call: same static predicate as admission's
		// IsReturnTarget) are NOT recorded: returns are excluded from admission anyway, and recording
		// every (caller,return-site) pair explodes the map (millions of distinct cold edges).
		dbt::brindedges::RecordWindowVisit(gip); // temporal channel profile: ALL visits incl returns
		u32 prev = gip >= 4 ? *reinterpret_cast<u32 const *>((uptr)mmu::base + (uptr)(gip - 4)) : 0;
		u32 opcode = prev & 0x7f;
		bool is_return = (opcode == 0x6f || opcode == 0x67) && ((prev >> 7) & 0x1f) != 0;
		// 12:14 review item A (--sr-record-returns): ALSO record return edges (ret-PC ->
		// continuation) with exact dynamic counts, to measure the true polymorphic-return
		// distribution. Map-explosion risk accepted for ONE bounded observation run; the
		// offline analysis separates return edges by re-decoding the target's predecessor.
		if (!is_return || dbt::config::sr_record_returns) {
			dbt::brindedges::Record(state->ip, gip);
			// Round-31 Gate 1: same population, same is_return gating as Record() above (inherits
			// correct RETURN/TAILCALL exclusion for free) -- also buckets by deterministic
			// execution-count window for phase-locality analysis.
			dbt::brindedges::RecordPhase(state->ip, gip);
		}
		state->ip = gip;
		auto *found = tcache::Lookup(gip);
		if (likely(found)) {
			found->flags.is_brind_target = true;
			tcache::CacheExecCountOnly(found); // keep frequency attribution; skip ONLY the l1 inline-cache insert
			// FDRE stage-1 fix (A-line architecture reset): THIS path returns directly to the
			// caller's machine code and never re-enters execute.cpp's outer dispatcher, which
			// is where exec_count is normally incremented (and which the fast-path's emitted
			// Emit_Cache `inc` also normally does, but that fast path is disabled in this
			// collection mode) -- so every repeat visit reaching here must self-account.
			// Verified missing (froze every indirect target's exec_count at 1) via
			// witness_fdre.c (950,000 true visits read back as 1) before this fix; the OTHER
			// CacheExecCountOnly call site (execute.cpp's escape path) must NOT also do this,
			// since IT already falls through to that same unconditional increment.
			found->flags.exec_count++;
			return (void *)found->tcode.ptr;
		}
		return (void *)qcgstub_escape_brind;
	}
	state->ip = gip;
	auto *found = tcache::Lookup(gip);
	if (likely(found)) {
		// A-line 2026-07-24: this call site is the SAME "repeat-visit path returns directly to
		// the caller's machine code" case the Round-15 DIA comment on CacheExecCountOnly (above,
		// tcache.h) already documents -- CacheBrind fills cache_tb_exec_count but does not itself
		// increment exec_count, and Emit_gbrind's inline fast path only increments on a
		// cache_tb_exec_count HIT, never on the miss that reaches here. Left disabled since
		// a51e3ab9f ("update test scripts and fix profiler with gbr", over-generalized by analogy
		// with TryLinkBranch's correctly-redundant disable, since Emit_gbr's Emit_Cache backstop
		// covers TryLinkBranch's case but Emit_gbrind has no equivalent miss-side backstop) --
		// root-caused via a real 5-workload joint flow-conservation reconstruction (see
		// experiments/2026-07-23-0449-obs-freq-recompute-indirect-asymmetry/SHADOW_EDGES_PROGRESS.md):
		// xalan showed exec_count exactly 1 low on indirect targets reached this way (a return
		// site compiled first via a direct/fallthrough predecessor, then reached again by its
		// actual indirect arrival). The other 4 (smaller/simpler) workloads never happened to
		// exercise this call site's found!=null case, hence never showed it.
		found->flags.exec_count++;
		tcache::CacheBrind(found);
		// A-line 2026-07-23 (--qcg-dispatch-ic): first-wins mono IC patch. This very slowpath
		// visit IS the observation (the site's first natural miss for this target) and the
		// consumption (patch a guarded direct jump into the site) -- no pass, no threshold.
		if (unlikely(dbt::config::qcg_dispatch_ic)) {
			auto ra = (uptr)__builtin_return_address(0);
			// PM round-10 P3 (--qcg-dispatch-ic-regret): if this site's blob is ALREADY patched
			// (sentinel != the never-matching value), THIS slowpath visit is direct evidence the
			// currently-committed guess just failed -- a real guard miss, not the first-ever
			// patching visit. Check BEFORE calling ICTryPatch (which would be a no-op here anyway
			// under first-wins, but checking first keeps the miss/patch distinction unambiguous).
			if (unlikely(dbt::config::qcg_ic_regret)) {
				auto *info = tcache::ICLookup(ra);
				if (info && info->blob && info->blob[0] == 0x81 && info->blob[1] == 0xFE) {
					u32 sentinel = *(u32 *)(info->blob + 2);
					if (sentinel != 0xFFFFFFFFu)
						tcache::QcgIcRegretMiss(info->site_ip, info->blob);
				}
			}
			tcache::ICTryPatch(ra, found);
		}
		return (void *)found->tcode.ptr;
	}
	// A-line IC: the dominant natural-miss case -- target not yet translated. Remember the site's
	// retaddr across the escape->translate hop; the execute loop patches after translation.
	if (unlikely(dbt::config::qcg_dispatch_ic)) {
		dbt::config::qcg_ic_pending_ra = (uptr)__builtin_return_address(0);
		dbt::config::qcg_ic_pending_gip = gip;
	}
	return (void *)qcgstub_escape_brind;
}

// A-line Round 60 (--qcg-gbrind-outline): the QCG tier's `Emit_gbrind` normally INLINES the
// l1_brind_cache hit-check (load base, hash, compare, conditional jump -- ~5-6 x86 instructions,
// emitted at EVERY indirect-terminated TB) so a cache HIT never pays a function-call cost. This is
// the right tradeoff for AOT (compiled once, reused across the artifact's whole lifetime, persisted
// to disk) but not necessarily for QCG (recompiled from scratch every single run, never persisted)
// -- confirmed via PMU sample attribution (Round 59-60): indirect-terminated QCG TBs cost ~50% more
// host bytes per guest instruction than direct-terminated ones, and QCG JIT compilation itself is a
// real, measured ~11.4% of total cycles on a real workload. This moves the SAME check out-of-line
// (one shared copy, not one per site), trading a mandatory function-call per dispatch (even on a
// cache hit) for a much smaller per-site compile footprint. Correctness: identical hash
// (`tcache::l1hash`) and identical hit condition to the inline version; a miss falls through to the
// UNMODIFIED, already-validated `qcgstub_brind` above, so every escape/async-check/cache-population
// path stays exactly as it was -- this wrapper only shortcuts the ALREADY-cached case, it never
// changes what gets cached or how.
HELPER void *qcgstub_brind_checked(CPUState *state, u32 gip)
{
	auto &entry = dbt::tcache::l1_brind_cache[dbt::tcache::l1hash(gip)];
	if (entry.gip == gip)
		return entry.code;
	return qcgstub_brind(state, gip);
}

HELPER void qcgstub_raise()
{
	RaiseTrap();
}

#define PUSH_NONCSR_GPR()                                                                                    \
	"pushq	%rax\n\t"                                                                                     \
	"pushq	%rcx\n\t"                                                                                     \
	"pushq	%rdx\n\t"                                                                                     \
	"pushq	%rsi\n\t"                                                                                     \
	"pushq	%rdi\n\t"                                                                                     \
	"pushq	%r8\n\t"                                                                                      \
	"pushq	%r9\n\t"                                                                                      \
	"pushq	%r10\n\t"                                                                                     \
	"pushq	%r11\n\t"

#define POP_NONCSR_GPR()                                                                                     \
	"popq	%r11\n\t"                                                                                      \
	"popq	%r10\n\t"                                                                                      \
	"popq	%r9\n\t"                                                                                       \
	"popq	%r8\n\t"                                                                                       \
	"popq	%rdi\n\t"                                                                                      \
	"popq	%rsi\n\t"                                                                                      \
	"popq	%rdx\n\t"                                                                                      \
	"popq	%rcx\n\t"                                                                                      \
	"popq	%rax\n\t"

HELPER_ASM void qcgstub_trace()
{
	asm(PUSH_NONCSR_GPR());

	asm("pushq	%r13\n\t"
	    "movq	%r13, %rdi\n\t" // STATE
	    "subq	$16, %rsp\n\t" // TODO: figure out 16 or 8, sometime only one work.
	    "callq	qcg_DumpTrace@plt\n\t"
	    "addq	$16, %rsp\n\t"
	    "popq	%r13\n\t");

	asm(POP_NONCSR_GPR());
	asm("retq	\n\t");
}

HELPER_ASM void qcgstub_trace_cache()
{
	asm(PUSH_NONCSR_GPR());

	asm("pushq	%r13\n\t"
	    "movq	%r13, %rdi\n\t" // STATE
	    "pushq	%r14\n\t"
	    "movq	%r14, %rsi\n\t" // gip
	    "pushq	%r15\n\t"
	    "movq	%r15, %rdx\n\t" // entry_ip
	    "subq	$8, %rsp\n\t"
	    "callq	qcg_DumpTraceCache@plt\n\t"
	    "addq	$8, %rsp\n\t"
	    "popq	%r15\n\t"
	    "popq	%r14\n\t"
	    "popq	%r13\n\t");

	asm(POP_NONCSR_GPR());
	asm("retq	\n\t");
}

// Shadow-edge discovery (A-line, --shadow-edges): unlike the existing l1_brind_cache (indexed by
// TARGET address -- confirmed by reading tcache.h/qemit.cpp's Emit_gbrind: cache[hash(target)] =
// {target, code}, so a HIT only means "this exact target has been dispatched to before, from
// ANY source" -- a second, different source reaching an ALREADY-cached target is a hit and is
// NEVER observed), this is a SEPARATE cache indexed by SOURCE address, so a target reached by two
// distinct sources is independently discovered from EACH source's own miss. Empirically confirmed
// this distinction matters: the existing --sr-sampled-edges (natural L1-miss, target-indexed)
// found exactly 76/33 edges on expat/libyaml -- exactly the number of DISTINCT TARGETS in each,
// i.e. exactly one (whichever-arrived-first) source per target, never a second.
//
// The hit/miss compare itself now lives INLINE in QEmit::Emit_gbrind (qemit.cpp), keyed on
// tcache::shadow_edge_cache -- this handler is reached ONLY on a genuine miss or hash collision,
// not unconditionally on every dispatch (fixes the 4.67x-14.89x measured overhead of the earlier,
// unconditional-hcall design). This handler re-validates src/tgt independently as a correctness
// backstop (cheap now that it is rare), so a bug in the inline check can only cause an extra
// re-log, never a silently wrong Record.
extern "C" void ShadowEdgeCheckImpl(CPUState *state, uint32_t /*unused, see rv32_qir.cpp*/)
{
	tcache::shadow_edge_slow_calls++;
	u32 src = state->ip;              // spilled by Emit_gbrind's slow path (compile-time-known _entry_ip)
	u32 tgt = state->shadow_edge_tgt; // spilled instead of passed as the hcall operand, see rv32_qir.cpp's comment
	auto &slot = tcache::shadow_edge_cache[tcache::shadow_edge_hash(src)];
	if (slot.src != src) {
		if (slot.src != 0 || slot.tgt != 0) { // slot previously held a DIFFERENT source: true collision
			tcache::shadow_edge_collisions++;
		}
		brindedges::Record(src, tgt);
		slot.src = src;
		slot.tgt = tgt;
	} else if (slot.tgt != tgt) {
		brindedges::Record(src, tgt);
		slot.tgt = tgt;
	}
}

HELPER_ASM void qcgstub_shadow_edge_check()
{
	// Called directly from QEmit::Emit_gbrind's inline slow path (qemit.cpp), the same way the
	// existing id_brind slowpath call is made -- NOT via the generic Emit_hcall/Create_hcall QIR
	// path (shadow-edge discovery only ever runs during a --aot=0 profiling run, QCG/interpreter
	// only). %rdi=state is set by Emit_gbrind's own inline mov before this stub is reached;
	// state->ip/state->shadow_edge_tgt are spilled the same way, both preserved (not clobbered)
	// by PUSH_NONCSR_GPR, so ShadowEdgeCheckImpl reads them back correctly.
	asm(PUSH_NONCSR_GPR());
	asm("callq	ShadowEdgeCheckImpl@plt\n\t");
	asm(POP_NONCSR_GPR());
	asm("retq	\n\t");
}

// H2 (--shadow-edges-k=<N>, N>=2): per-source K-WAY history SET, the "next cycle" design flagged
// in SHADOW_EDGES_PROGRESS.md/RESIDUAL_COMPONENT_ANALYSIS.md for workloads (wasm3_indcall) whose
// indirect sites alternate among MORE than one recent target -- H1's single-slot "did the target
// change since last dispatch" definition fires on ~40% of dispatches there because a genuinely
// K-ary rotation looks like a miss every single time to a K=1 cache.
//
// Scoping decision (deliberate, not an oversight): unlike H1's item-3 fix (1d91df85), this FIRST
// CUT does NOT inline the hit/miss compare into QEmit::Emit_gbrind -- QEmit::Emit_gbrind calls
// this handler UNCONDITIONALLY on every shadow-tracked dispatch (mirroring H1's ORIGINAL,
// pre-inline design, c2aa6c31), and the K-way membership test (a short linear scan over <=K
// entries, K in {2,4,8} here -- cheap, cache-resident) runs entirely in C++. This means H2 is
// measured HONESTLY as "unconditional call + linear scan", not "best-case inlined K-way", per
// this cycle's mandate (SUPPORT_DISCOVERY_H1_VS_H2.md); inlining is flagged as a follow-up, not
// hidden as already-done.
//
// Safety invariant (non-negotiable, matches H1): a miss for THIS source's K-way set ALWAYS
// unconditionally calls brindedges::Record -- eviction (round-robin/FIFO, see ShadowEdgeKSlot)
// may only cause an already-seen edge to be RE-recorded after it cycles out and back in (harmless,
// deduped downstream), never cause a genuine edge to be silently dropped. Capacity (K) therefore
// affects COST (slow_calls/capacity_evictions) only, never recall.
extern "C" void ShadowEdgeKCheckImpl(CPUState *state, uint32_t /*unused, see rv32_qir.cpp*/)
{
	tcache::shadow_edge_k_total_dispatches++;
	u32 src = state->ip;              // spilled by Emit_gbrind's H2 slow path (compile-time-known _entry_ip)
	u32 tgt = state->shadow_edge_tgt; // spilled the same way H1 uses (see rv32_qir.cpp's comment)
	auto &slot = tcache::shadow_edge_k_cache[tcache::shadow_edge_hash(src)]; // same hash space as H1
	u32 K = dbt::config::shadow_edges_k;
	if (K < 2) K = 2;                              // defensive; CLI clamps to [2, kMaxK] already
	if (K > tcache::ShadowEdgeKSlot::kMaxK) K = tcache::ShadowEdgeKSlot::kMaxK;

	if (slot.src != src) {
		// Hash-address collision (a DIFFERENT real source previously owned this slot) or the
		// slot's first-ever use -- either way this source's own K-way set is empty here, so this
		// dispatch is unconditionally a miss for it.
		if (slot.n_valid != 0) { // slot held real data for a different source: true hash collision
			tcache::shadow_edge_k_hash_collisions++;
		}
		tcache::shadow_edge_k_slow_calls++;
		brindedges::Record(src, tgt);
		slot.src = src;
		slot.targets[0] = tgt;
		slot.counts[0] = 1; // round 13: true per-target hit counter, see ShadowEdgeKSlot comment
		slot.n_valid = 1;
		slot.evict_next = 1 % K;
		return;
	}

	for (u32 i = 0; i < slot.n_valid; i++) {
		if (slot.targets[i] == tgt) {
			slot.counts[i]++; // round 13: was a pure no-op; this is the only added per-dispatch cost
			return;           // hit: tgt already in this source's K-way set (no Record call, as before)
		}
	}

	// Miss for this source's own K-way set (safety invariant: always record on a genuine miss).
	tcache::shadow_edge_k_slow_calls++;
	brindedges::Record(src, tgt);
	if (slot.n_valid < K) {
		slot.counts[slot.n_valid] = 1;
		slot.targets[slot.n_valid++] = tgt;
	} else {
		// Capacity exhausted (this source has already cycled through K DIFFERENT targets, not a
		// hash-slot collision with another source) -- evict round-robin/FIFO, the simplest correct
		// policy; see ShadowEdgeKSlot's comment for why LRU is not required for this comparison.
		tcache::shadow_edge_k_capacity_evictions++;
		slot.targets[slot.evict_next] = tgt;
		slot.counts[slot.evict_next] = 1; // fresh occupant, restart its count (round 13)
		slot.evict_next = (slot.evict_next + 1) % K;
	}
}

HELPER_ASM void qcgstub_shadow_edge_check_k()
{
	// Same calling convention as qcgstub_shadow_edge_check above (%rdi=state set by
	// QEmit::Emit_gbrind's H2 branch before this stub is reached; state->ip/shadow_edge_tgt
	// spilled the same way).
	asm(PUSH_NONCSR_GPR());
	asm("callq	ShadowEdgeKCheckImpl@plt\n\t");
	asm(POP_NONCSR_GPR());
	asm("retq	\n\t");
}

static_assert(qcg::ArchTraits::STATE == asmjit::x86::Gp::kIdR13);

struct TraceRing {
	static constexpr u32 size = 64;

	struct Record {
		u32 gip;
	};

	void push(Record const &rec)
	{
		arr[head++ % size] = rec;
	}

	auto &at_idx(u32 i)
	{
		return arr[(head - 1 - i) % size];
	}

	u32 head = 0;
	std::array<Record, size> arr{};
};

thread_local TraceRing trace_ring;

extern "C" __attribute__((used)) void __log_trace_ring()
{
	for (u32 i = 0; i < trace_ring.size; ++i) {
		auto const &e = trace_ring.at_idx(i);
		log_dbt("%08x", e.gip);
	}
}

HELPER void qcg_DumpTrace(CPUState *state)
{
	state->DumpTrace("entry");
}

HELPER void qcg_DumpTraceCache(CPUState *state, u32 gip, u32 entry_ip)
{
	// log_dbt("DumpTraceCache called with state=%p, gip=%08x", state, gip);
	// log_dbt("DumpTraceCache from %08x to %08x", state->ip, gip);
	state->DumpTraceCache(gip, entry_ip);
}
} // namespace dbt::jitabi
