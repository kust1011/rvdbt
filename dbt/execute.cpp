#include "dbt/execute.h"
#include "dbt/fault_snapshot.h"
#include "dbt/ccrf_materializer.h"
#include "dbt/aot/aot.h"
#include "dbt/aot/loop_tier.h"
#include "dbt/guest/rv32_runtime.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/ngr.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/guest/rv32_runtime.h"
#include <time.h>
#include <unordered_map>
#include <vector>
#include <utility>
#include <algorithm>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <fstream>

bool dbt_inrun_artifact_present(); // defined in aot_boot.cpp, global scope (mirrors jitabi.cpp's declaration)
namespace dbt::brindedges { void Dump(char const *path); } // defined in jitabi.cpp (mirrors aot_boot.cpp's declaration)

// B-line B2 revoke channel: poll revoke_request_path for a pending single-target revoke, apply it, and
// truncate the file so it is not reprocessed. Reads/writes are ordinary host-stack file I/O -- called only
// from the same non-signal call site as the existing sr_live_edges_dump Dump(), never from signal context.
static void PollRevokeRequest()
{
	FILE *f = fopen(dbt::config::revoke_request_path, "r+");
	if (!f)
		return;
	char line[32];
	if (fgets(line, sizeof(line), f)) {
		unsigned gip = 0;
		if (sscanf(line, "%x", &gip) == 1 && gip != 0) {
			dbt::tcache::RevokeTarget((u32)gip);
			dbt::config::esc_revoke_applied++;
			FILE *lf = fopen((std::string(dbt::config::revoke_request_path) + ".applied").c_str(), "a");
			if (lf) {
				struct timespec ts;
				clock_gettime(CLOCK_MONOTONIC, &ts);
				fprintf(lf, "%lld.%03ld %08x\n", (long long)ts.tv_sec, ts.tv_nsec / 1000000, gip);
				fclose(lf);
			}
		}
	}
	fclose(f);
	// truncate so a stale/unchanged request is not reapplied every poll tick
	FILE *tf = fopen(dbt::config::revoke_request_path, "w");
	if (tf)
		fclose(tf);
}

namespace dbt
{

sigjmp_buf trap_unwind_env;

// 2026-06-21 EXECUTION-PHASE WINDOWS (observation-only). Accumulates guest instructions; each window of
// config::phase_window_insns instructions records a fresh per-TB execution-count map. At window close the map is
// pushed to g_phase_windows. elfrun dumps the windows at exit. No execution-path semantics change.
//
// A-line round 58 CORRECTION (found via a confirmed, single-run-reproducible ~4000x discrepancy
// against RETURN_CENSUS on antlr4_generated): this counter's true semantics are NARROWER than the
// comment above implies. `phase_window_record` (below) is called ONLY from Execute()'s host `while`
// loop, at the same call site as `tb->flags.exec_count += 1` -- i.e. only when control returns to
// this host loop for a fresh `tcache::Lookup` (a cold block, or a `branch_slot` needing its first
// link). This DBT's steady-state execution model is precisely designed to AVOID this: once a
// branch_slot is linked, subsequent dispatches tail-chain through already-JIT-compiled code
// (`Create_gbr`/`Create_gbrind`, `TryLinkBranch` self-patched direct branches) without ever
// returning here. RETURN_CENSUS (`dbt/qmc/qcg/qemit.cpp`'s `shadow_edge2_dispatches_*` counters)
// increments via a real `inc` baked directly into the JIT-compiled code at each jalr site, firing on
// EVERY dynamic dispatch regardless of host-loop involvement -- the correct "total dispatch volume"
// signal. `phase_window`'s counters instead measure HOST-LOOP RE-ENTRY events (cold lookups + fresh
// links) -- a proxy for translation/linking churn, NOT total execution volume, and NOT a fixed
// fraction of it (the ratio depends on how long each tail-dispatch chain runs before next needing a
// fresh link, which varies dynamically -- no constant rescaling reconciles the two). Do not use this
// collector's `insns`/`exec` fields as a stand-in for real dispatch/instruction volume; see the
// runtime consistency check in `phase_window_dump()` below and
// `ROUND58_...` for the minimal single-process reproduction
// (`--phase-windows-out=... --phase-window-insns=1000000 --shadow-edges2=1
// --shadow-edges2-all-jalr=1`, compare the dumped file's total against stderr's `RETURN_CENSUS`).
struct PhaseWindowRec { std::unordered_map<u32, u64> counts; unsigned long long insns; };
std::vector<PhaseWindowRec> g_phase_windows;
static PhaseWindowRec g_phase_cur;
static unsigned long long g_phase_acc = 0;
void phase_window_flush_final()
{
	if (config::phase_window && (g_phase_cur.insns > 0 || !g_phase_cur.counts.empty())) {
		g_phase_windows.push_back(std::move(g_phase_cur));
		g_phase_cur = PhaseWindowRec{};
	}
}
void phase_window_dump(char const *path)
{
	// A-line round 58: fail-fast consistency check. When RETURN_CENSUS's inline-JIT dispatch
	// counters are ALSO active, cross-check this collector's accumulated total against them --
	// if this collector's total is not at least within an order of magnitude, it is measuring
	// host-loop re-entries (translation/link churn), not real dispatch volume (see the correction
	// above this file's PhaseWindowRec definition), and must not be read as such.
	if (config::shadow_edges2 && config::shadow_edges2_all_jalr) {
		unsigned long long window_total = 0;
		for (auto const &rec : g_phase_windows)
			window_total += rec.insns;
		unsigned long long census_total = tcache::shadow_edge2_dispatches_call + tcache::shadow_edge2_dispatches_tailcall +
						   tcache::shadow_edge2_dispatches_return;
		if (census_total > 0 && window_total * 10 < census_total) {
			fprintf(stderr,
				"PHASE_WINDOW_CONSISTENCY_WARNING window_total_insns=%llu vs RETURN_CENSUS_total_dispatches=%llu "
				"(ratio=%.6f) -- phase-window counters measure host-loop re-entries (cold lookups + fresh "
				"branch_slot links), NOT total dispatch volume, whenever tail-dispatch chains stay resident "
				"in already-linked JIT code; do not treat window insns/exec as real execution volume here.\n",
				window_total, census_total, census_total ? (double)window_total / census_total : 0.0);
		}
	}
	FILE *f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "# window insns nhot ip:exec...\n");
	for (size_t w = 0; w < g_phase_windows.size(); ++w) {
		auto &rec = g_phase_windows[w];
		std::vector<std::pair<u32, u64>> v(rec.counts.begin(), rec.counts.end());
		std::sort(v.begin(), v.end(), [](auto &a, auto &b) { return a.second > b.second; });
		fprintf(f, "%zu %llu %zu", w, rec.insns, v.size());
		// obs/crossinput-drift: raise per-window IP cap 40->400 so the captured mass is
		// large enough to expose late-emerging / below-top-40 hot regions for regret analysis.
		size_t topn = v.size() < 400 ? v.size() : 400;
		for (size_t i = 0; i < topn; ++i)
			fprintf(f, " %08x:%llu", v[i].first, (unsigned long long)v[i].second);
		fprintf(f, "\n");
	}
	fclose(f);
}
void phase_window_request_exit()
{
	phase_window_flush_final();
	if (config::phase_window_out_path)
		phase_window_dump(config::phase_window_out_path);
	fflush(nullptr);
	_exit(0);
}
static inline void phase_window_record(u32 ip, u32 ninsn)
{
	g_phase_cur.counts[ip] += 1;
	g_phase_cur.insns += ninsn;
	g_phase_acc += ninsn;
	if (g_phase_acc >= config::phase_window_insns) {
		g_phase_windows.push_back(std::move(g_phase_cur));
		g_phase_cur = PhaseWindowRec{};
		g_phase_acc = 0;
		// optional cap: stop the guest after N windows so long runs are tractable for phase observation
		if (config::phase_window_max > 0 && g_phase_windows.size() >= config::phase_window_max) {
			extern void phase_window_request_exit();
			phase_window_request_exit();
		}
	}
}

static inline bool HandleTrap(CPUState *state)
{
	// Currenlty only delegates to ukernel
	return !state->IsTrapPending();
}

struct JITCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		return tcache::AllocateCode(sz, align);
	}

	bool AllowsRelocation() const override
	{
		return false;
	}

	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	// void *AnnounceRegion(u32 ip, std::span<u8> const &code) override
	{
		// TODO: concurrent tcache
		auto tb = tcache::AllocateTBlock();
		if (tb == nullptr) {
			Panic();
		}
		tb->ip = ip;
		tb->tcode = TBlock::TCode{code.data(), code.size()};
		tb->flags.exec_instr_count = num_insns;
		// A-line RETIRE-v2: a retranslated (previously revoked) TB inherits its frozen count and
		// brind-target mark, so every downstream admission/region decision sees the same values.
		if (unlikely(config::qcg_freq_retire || config::sr_web_repack)) {
			auto c = tcache::sat_carry.find(ip);
			if (c != tcache::sat_carry.end() && c->second.had_tb) {
				tb->flags.exec_count = c->second.count;
				if (c->second.brt)
					tb->flags.is_brind_target = true;
				if (c->second.seg)
					tb->flags.is_segment_entry = true;
				tcache::sat_carry.erase(c);
			}
		}
		tcache::Insert(tb);
		return (void *)tb;
	}
};

static inline IpRange GetCompilationIPRange(u32 ip)
{
	u32 upper = roundup(ip, mmu::PAGE_SIZE);
	if (config::dump_trace) {
		return {ip, upper};
	}
	// TODO: this avoid translate until an existing TB, whose IP range may overlap with the new one that is hard to profile
	if (!config::no_tb_clip) {
		if (auto *tb_upper = tcache::LookupUpperBound(ip)) {
			if (!(config::tb_through_brind && tb_upper->flags.is_brind_target))
				upper = std::min(upper, tb_upper->ip);
		}
	}
	return {ip, upper};
}

void Execute(CPUState *state)
{
	sigsetjmp(dbt::trap_unwind_env, 0);

	jitabi::ppoint::BranchSlot *branch_slot = nullptr;

	while (likely(!HandleTrap(state))) {
		if (unlikely(ccrf::Enabled()) && ccrf::ObserveBoundary(state)) {
			branch_slot = nullptr;
			continue;
		}
		if (unlikely(fault_snapshot::Enabled()))
			fault_snapshot::ObserveEntry(state);
		// T5d-0: attribute a backedge-safepoint escape to the guest PC it resumed at. The emitted
		// safepoint only increments a counter; if that counter moved since the previous pass
		// through this loop, THIS iteration is the one the escape returned to, and `state->ip` is
		// the target PC the edge stored. Gated on the flag, so an ordinary run does not even load
		// the counter. This is bookkeeping, not a decision: nothing below reads the map.
		if (unlikely(config::qcg_backedge_safepoint) &&
		    config::backedge_safepoint_escapes != config::backedge_safepoint_escapes_seen) {
			config::backedge_safepoint_escapes_seen = config::backedge_safepoint_escapes;
			config::backedge_safepoint_ips[state->ip]++;
		}
		// T5d2a3: the same attribution for the INTRA-REGION exit, kept in its own counter and its
		// own map on purpose. The two mechanisms answer different questions -- "a region exit gave
		// control back" and "an in-region loop latch gave control back at its own edge" -- and
		// summing them into one number would hide exactly the fact this checkpoint claims: which
		// guest PC the run resumed at.
		if (unlikely(config::loop_tier_side_exit) &&
		    config::loop_tier_side_exits != config::loop_tier_side_exits_seen) {
			config::loop_tier_side_exits_seen = config::loop_tier_side_exits;
			config::loop_tier_side_exit_ips[state->ip]++;
		}
		if (config::sr_unconditional_poll && unlikely(config::inrun_poll_due) && config::inrun_tier &&
		    !config::inrun_booted && !config::inrun_boot_pending) {
			// V151 diag fix: mirror qcgstub_brind's poll-consumption at an UNCONDITIONAL heartbeat (this
			// loop runs every guest block regardless of indirect-branch traffic), so workloads whose hot
			// code has no further brind slowpath visits post-compile don't starve the promotion channel.
			config::inrun_poll_due = false;
			if (::dbt_inrun_artifact_present())
				config::inrun_boot_pending = true;
		}
		if (unlikely(config::sat_sweep_due) && config::qcg_freq_retire) {
			// A-line SAT-1b: retire saturated counting sequences (host stack; see tcache.cpp)
			config::sat_sweep_due = false;
			tcache::SatSweepAndPatch(config::qcg_freq_sat_t);
		}
		if (unlikely(config::p1_scan_due) && config::p1_promote) {
			// P1: exiled-hot evidence walk + one-shot synchronous promote (host stack;
			// aot_boot.cpp). The compile wall lands inside this invocation by design.
			config::p1_scan_due = false;
			P1ScanAndMaybePromote();
		}
		if (unlikely(config::web_repack_due) && config::sr_web_repack && !config::web_repacked) {
			// A-line web-repack (host stack): revoke every observed web member; the hot web
			// re-arrives immediately and burst-retranslates into consecutive pool space.
			// Counts/flags survive via the sat_carry path (consumed at AnnounceRegion).
			config::web_repack_due = false;
			config::web_repacked = true;
			brindedges::ForEachNode([](unsigned ip) {
				auto *tb = tcache::Lookup(ip);
				if (!tb || tb->tcode.size == 0)
					return;
				auto &c = tcache::sat_carry[ip];
				c.count += tb->flags.exec_count;
				c.instr = tb->flags.exec_instr_count;
				c.brt = c.brt || tb->flags.is_brind_target;
				c.seg = c.seg || tb->flags.is_segment_entry;
				c.had_tb = true;
				tcache::RevokeTarget(ip);
				config::web_repack_n++;
			});
		}
		if (unlikely(config::loop_tier) && config::loop_tier_due) {
			// T5d2a: one loop-tier service opportunity. The flag is tested FIRST so an
			// ordinary run does not even load the service word here, and the request is
			// cleared before the work so a long build cannot be re-requested by its own
			// pending bit. What happens next is decided entirely by this run's profile
			// against the compiler's threshold -- see looptier::Decide. Nothing is loaded,
			// promoted or timed; the tier only produces an artifact.
			config::loop_tier_due = false;
			looptier::Service();
		}
		if (unlikely(config::inrun_boot_pending) && !config::inrun_booted) {
			// Round-17 BCT: artifact landed mid-run (signaled by the brind slowpath); boot it here on the
			// host stack. After this, lookups resolve into AOT code and dispatch working sets migrate.
			BootAOTFileInRun();
			config::inrun_boot_pending = false;
		}
		if (unlikely(config::inrun_escalate_due)) {
			config::inrun_escalate_due = false;
			EvaluateAndMaybeEscalate(); // host stack: census walk + fork are safe here
			if (unlikely(config::sr_live_edges_dump) && config::brind_edges_out_path)
				// B-line: periodic mid-run edge snapshot, same host-stack call site (file I/O is
				// signal-unsafe; this is NOT the signal handler, same discipline as the .prof refresh).
				brindedges::Dump(config::brind_edges_out_path);
			if (unlikely(config::inrun_revoke_watch) && config::revoke_request_path)
				// B-line B2: same host-stack call site, poll for a pending real revoke request.
				PollRevokeRequest();
		}
		assert(state == CPUState::Current());
		assert(state->gpr[0] == 0);
		assert(!branch_slot || branch_slot->gip == state->ip);
		if constexpr (config::use_interp) {
			Interpreter::Execute(state);
			continue;
		}

		TBlock *tb = tcache::Lookup(state->ip);
		if (tb == nullptr && unlikely(config::tier0_lazy)) {
			// TIER-0: interpret this block instead of JIT-translating it, until its per-entry execution
			// count reaches the cost-model break-even K* (tier0_threshold). Cold blocks (run < K*) are
			// never translated. ExecuteBlock advances state->ip; loop back to decide the next block.
			static std::unordered_map<u32, u32> g_interp_count;
			u32 &c = g_interp_count[state->ip];
			if (c < config::tier0_threshold) {
				c++;
				config::g_interp_blocks++;
				u32 blk_ip = state->ip; // entry ip BEFORE the block runs (it advances state->ip)
				Interpreter::ExecuteBlock(state); // interprets one block, advances state->ip (traps unwind)
				if (unlikely(config::phase_window))
					phase_window_record(blk_ip, config::g_last_block_insns);
				branch_slot = nullptr;            // no JIT trampoline slot from the interpreter path
				continue;
			}
			// crossed K* -> fall through to JIT-translate this hot block
		}
		if (tb == nullptr) {
			auto jrt = JITCompilerRuntime();
			u32 gip_page = rounddown(state->ip, mmu::PAGE_SIZE);
			// P7G: the ONLY production site that fills the live-RVV-configuration hint,
			// and it is here because this is the only place the two facts it needs are
			// simultaneously true: the guest is PAUSED on the host stack (the asserts
			// above), and `state->ip` is exactly the ip this job is about to compile
			// (the same value GetCompilationIPRange and tcache::Lookup used). So
			// `state->vec.vtype` is the configuration every guest instruction BEFORE
			// this block left behind -- including a `vsetvli` in a loop preheader that
			// belongs to a different translation block.
			//
			// The raw word is passed through unexamined: whether it is supported, vill,
			// or usable is the guest translator's rule, not this loop's. Nothing here
			// reads vl or vstart -- see the RvvEntryHint comment for why.
			qir::CompilerJob job(&jrt, (uptr)mmu::base,
					     qir::CodeSegment(gip_page, mmu::PAGE_SIZE),
					     {GetCompilationIPRange(state->ip)},
					     qir::RvvEntryHint{state->vec.vtype, true});
			if (unlikely(config::ngr)) {
				auto rr = GetCompilationIPRange(state->ip);
				tb = (TBlock *)ngr::CompileOrReuse(job, rr.first, rr.second);
			} else if (unlikely(config::measure_translation)) {
				struct timespec a, b;
				clock_gettime(CLOCK_MONOTONIC, &a);
				tb = (TBlock *)qir::CompilerDoJob(job);
				clock_gettime(CLOCK_MONOTONIC, &b);
				config::g_translate_ns += (unsigned long long)(b.tv_sec - a.tv_sec) * 1000000000ull +
							  (b.tv_nsec - a.tv_nsec);
				config::g_translate_count += 1;
				if (unlikely(config::translate_ip_out)) {
					static std::ofstream tip_out(config::translate_ip_out);
					auto job_ns = (unsigned long long)(b.tv_sec - a.tv_sec) * 1000000000ull + (b.tv_nsec - a.tv_nsec);
					tip_out << std::hex << state->ip << std::dec << " ns=" << job_ns
						<< " insns=" << tb->flags.exec_instr_count << "\n";
				}
			} else {
				tb = (TBlock *)qir::CompilerDoJob(job);
			}
		}

		if (branch_slot) {
			branch_slot->Link(tb->tcode.ptr);
			tcache::RecordLink(branch_slot, tb, branch_slot->flags.cross_segment);
			tcache::CacheBr(tb);
		} else {
			if (unlikely(config::profile_brind_edges)) {
				// Round-15 DIA: keep target marking + exec-count attribution but skip the l1 insert
				// so every indirect transfer keeps taking qcgstub_brind (full edge multigraph).
				tcache::CacheExecCountOnly(tb);
			} else {
				tcache::CacheBrind(tb);
			}
			// A-line IC: complete the pending patch from the brind slowpath's escape (the
			// untranslated-target case). pending_gip check makes the (site, target) pair exact.
			if (unlikely(config::qcg_dispatch_ic) && config::qcg_ic_pending_ra) {
				if (tb->ip == config::qcg_ic_pending_gip)
					tcache::ICTryPatch(config::qcg_ic_pending_ra, tb);
				config::qcg_ic_pending_ra = 0;
			}
		}

		if (!unlikely(config::qcg_freq_entry))
			tb->flags.exec_count += 1; // v3: this arrival passes the entry counter instead
		if (unlikely(config::phase_window))
			phase_window_record(tb->ip, tb->flags.exec_instr_count);
		log_dbt("ip %08x back to loop with count %d, insn count %d", state->ip, tb->flags.exec_count, tb->flags.exec_instr_count);
		branch_slot = jitabi::trampoline_to_jit(state, mmu::base, tb->tcode.ptr);
	}
}

} // namespace dbt
