#pragma once

#include "dbt/arena.h"
#include "dbt/mmu.h"
#include "dbt/tcache/cflow_dump.h"
#include "dbt/util/logger.h"

#include <array>
#include <bitset>
#include <deque>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace dbt
{
LOG_STREAM(tcache);

namespace jitabi::ppoint
{
struct BranchSlot;
} // namespace jitabi::ppoint

struct alignas(8) TBlock {
	struct TCode {
		void *ptr{nullptr};
		size_t size{0};
	};

	TCode tcode{};
	u32 ip{0};
	struct {
		bool is_brind_target : 1 {false};
		bool is_segment_entry : 1 {false};
		u64 exec_count : 64 {0};
		u32 exec_instr_count: 32 {0};
	} flags;
};

struct tcache {
	static void Init();
	static void Destroy();
	static void Invalidate();
	static void Insert(TBlock *tb);
	static void InsertOrReplace(TBlock *tb); // Round-17 BCT mid-run boot
	// Round-17 BCT: clear the l1 brind inline cache so the next indirect transfer (incl returns) takes the
	// slowpath = the promotion channel. Called from a SIGALRM handler on the SAME thread as the guest -- the
	// handler completes before execution resumes, so there is no concurrent read (single-threaded guest).
	static void FlushBrindCache()
	{
		// Only poison the gip field (0x1 = impossible: gips are >=2-aligned); NEVER touch the code ptr.
		// Round-25: targeted flush via the dirty list (slots filled since the last flush) -- the 4M full
		// sweep cost C_loop (~10ms/flush, footprint-independent) drops to ~us. Signal-handler context:
		// reads a vector populated on the same thread; size() read once; no allocation here.
		for (size_t i = 0, n = brind_dirty.size(); i < n; ++i)
			l1_brind_cache[brind_dirty[i]].gip = 1;
		brind_dirty.clear();
	}
	// A-line 2026-07-23 (--qcg-dispatch-ic): self-patching per-site dispatch inline cache. Every
	// QCG gbrind site carries a 31-byte patchable blob (guard cmp + count inc + direct jmp) ahead
	// of the shared L1-hash path; the brind slowpath patches it on the site's FIRST natural miss
	// (first-wins mono IC; no thresholds, no extra pass). ic_ret_map keys the slowpath call's
	// return address to the site's blob; ic_target_map lets invalidation unpatch by target gip
	// (mirrors link_map's unlink discipline).
	struct ICSiteInfo {
		u8 *blob;
		u32 site_ip; // guest ip of the dispatch site's region entry (B-DIST edge attribution)
	};
	static void ICRegister(uptr retaddr, u8 *blob, u32 site_ip)
	{
		ic_ret_map[retaddr] = {blob, site_ip};
	}
	static ICSiteInfo *ICLookup(uptr retaddr)
	{
		auto it = ic_ret_map.find(retaddr);
		return it == ic_ret_map.end() ? nullptr : &it->second;
	}
	// B-DIST probe (--qcg-ic-edge-count): per-(site,target) IC hit counters -- exact weights for
	// the site's RESIDENT (first-wins) edge; misses are counted by the slowpath edge recorder.
	static std::vector<std::tuple<u32, u32, unsigned long long *>> ic_edge_counts;
	static void ICMarkPatched(u32 tgt, u8 *blob) { ic_target_map.emplace(tgt, blob); }
	static void ICUnpatchTarget(u32 gip);
	static void ICUnpatchPage(u32 pvaddr);
	// Patch the site blob keyed by slowpath retaddr `ra` to dispatch directly to `tb` (first-wins;
	// no-op if the site is already patched, unknown, or the byte-pattern precheck fails).
	static void ICTryPatch(uptr ra, TBlock *tb);
	// A-line EDGE counters (--qcg-freq-edge): slots live in a SEPARATE data arena (deque = stable
	// addresses), NEVER in the code pool -- writing next to executing code triggers x86 SMC
	// machine-clears (measured 2x whole-run slowdown when slots were embedded after TB code).
	// Drained into per-TB exec counts by FoldEdgeCounters() (called from objprof::UpdateProfile).
	static unsigned long long *EdgeSlotAlloc(u32 target)
	{
		edge_slot_arena.push_back(0);
		auto *slot = &edge_slot_arena.back();
		edge_slots.push_back({slot, target});
		return slot;
	}
	// shadow probe: same arena, separate registry -- NEVER folded into exec_count
	static std::vector<std::pair<unsigned long long *, u32>> shadow_slots;
	static size_t EdgeSlotCount() { return edge_slot_arena.size(); }
	static unsigned long long *ShadowSlotAlloc(u32 ip)
	{
		edge_slot_arena.push_back(0);
		auto *slot = &edge_slot_arena.back();
		shadow_slots.push_back({slot, ip});
		return slot;
	}
	static void FoldEdgeCounters();
	// A-line RETIRE-v2 (--qcg-freq-retire): counting-sequence sites registered at emission. The
	// v1 in-place jmp-patch was falsified (sha512 +0.03%: the tax is FRONT-END/layout, not µops),
	// so the sweep now RETRANSLATES site TBs owning a seq whose target saturated: RevokeTarget +
	// exec-count/brind-flag carry-over; the fresh translation's Emit_Cache skips emission for
	// saturated targets entirely, producing compact counting-free hot code.
	struct SatSite {
		u32 site_ip;              // owning region entry -- the retranslation unit
		u32 target;               // the counted BLOCK ip
		unsigned long long *slot; // its arrival slot (TB-less blocks saturate via the slot)
	};
	static std::vector<SatSite> sat_sites;
	// RETIRE: everything the .prof consumer reads about a revoked TB must survive the revoke --
	// count, static instr count (the analyser's propagation input), and the observed bits. A
	// revoked TB that is never re-executed still reaches the profile via UpdateProfile's
	// leftover-carry pass (a missing node breaks ModuleGraph reachability, found by the oracle).
	struct SatCarry {
		unsigned long long count{0};
		u32 instr{0};
		bool brt{false}, seg{false};
		// had_tb: this carry came from a real revoked TB and belongs in the profile/count seed.
		// TB-less interior-block carries (had_tb=false) exist ONLY to keep the emission-time
		// skip working across retranslation -- stock never credits TB-less ips, so leaking them
		// into the .prof or a later TB seed would break stock equivalence.
		bool had_tb{false};
	};
	static std::unordered_map<u32, SatCarry> sat_carry;
	static void SatSiteRegister(u32 site_ip, u32 target, unsigned long long *slot); // re-arms tick
	static void SatSweepAndPatch(u64 threshold);
	static bool SatTargetSaturated(u32 target, u64 threshold)
	{
		auto it = tcache_map.find(target);
		return it != tcache_map.end() && it->second->flags.exec_count >= threshold;
	}
	// v3: a revoked-for-retirement TB's frozen count lives in sat_carry until retranslation
	// completes; the retranslation's own emission consults it to drop the entry counter.
	static bool SatCarrySaturated(u32 ip, u64 threshold)
	{
		auto it = sat_carry.find(ip);
		return it != sat_carry.end() && it->second.count >= threshold;
	}
	static void ICReset()
	{
		ic_ret_map.clear();
		ic_target_map.clear();
	}
	static void InvalidatePage(u32 pvaddr);
	// B-line (2026-07-22): single-target analogue of InvalidatePage, scoped to ONE gip instead of a whole
	// page. This is the real revoke primitive: it does not merely "stop building this target again" -- it
	// actively undoes the prior commitment's linkage so SUBSEQUENT dispatch is forced to re-resolve. Direct
	// branch slots already linked to the (revoked) code are relinked to the lazy-JIT stub; the l1 dispatch
	// caches and tcache_map entry for gip are cleared so the next indirect visit or block-entry lookup misses
	// and falls through to a fresh (correct, just lower-tier) recompilation. Safe: a miss/relink can only ever
	// fall back to a slower-but-correct path, never a dangling or stale-wrong code pointer.
	static void RevokeTarget(u32 gip);

	static ALWAYS_INLINE TBlock *LookupFast(u32 ip)
	{
		auto *tb = l1_cache[l1hash(ip)];
		return (tb->ip == ip) ? tb : nullptr;
	}

	static TBlock *Lookup(u32 ip)
	{
		auto hash = l1hash(ip);
		auto *tb = l1_cache[hash];
		if (tb != nullptr && tb->ip == ip)
			return tb;
		tb = LookupFull(ip);
		if (tb != nullptr)
			l1_cache[hash] = tb;
		return tb;
	}

	static TBlock *LookupUpperBound(u32 gip);

	static void CacheBr(TBlock *tb)
	{
		auto &entry = cache_tb_exec_count[l1hash(tb->ip)];
		if (entry.tb && entry.tb->ip != tb->ip) {
			log_tcache("Cache collision, both %08x and %08x with hash %08x", entry.tb->ip, tb->ip, l1hash(tb->ip));
		}
		cache_tb_exec_count[l1hash(tb->ip)] = {tb->ip, tb};
	}

	// Round-15 DIA: the exec-count attribution part of CacheBrind WITHOUT the l1 inline-cache
	// insert (edge profiling must keep the frequency profile intact while forcing every
	// transfer onto the slowpath). Does NOT itself increment exec_count -- it has TWO call
	// sites with DIFFERENT surrounding contexts (execute.cpp's escape path has its own
	// unconditional `tb->flags.exec_count += 1` immediately after; jitabi.cpp's repeat-visit
	// path returns directly to the caller's machine code and has no such safety net), so the
	// increment must live at the CALL SITE that actually needs it, not here (see jitabi.cpp).
	static void CacheExecCountOnly(TBlock *tb)
	{
		cache_tb_exec_count[l1hash(tb->ip)] = {tb->ip, tb};
		tb->flags.is_brind_target = true;
	}

	static void CacheBrind(TBlock *tb)
	{
		// Round-25: dirty-list for targeted flush -- record which brind-cache slots were filled since the
		// last flush so FlushBrindCache poisons only those (C_loop 4M-sweep ~10ms -> ~us). Only active when
		// the in-run channel needs it (inrun_tier && !booted); bounded by inserts-per-window.
		if ((unlikely(dbt::config::inrun_tier) && !dbt::config::inrun_booted) ||
		    unlikely(dbt::config::wmax_sample) || unlikely(dbt::config::qcg_freq_retire) ||
		    unlikely(dbt::config::sr_edges_epochs) || // A-line: retire sweep + epoch resampling
		    (unlikely(dbt::config::p1_promote) && !dbt::config::p1_booted)) // P1 keeper channel
			brind_dirty.push_back(l1hash(tb->ip));
		auto &entry = cache_tb_exec_count[l1hash(tb->ip)];
		if (entry.tb && entry.tb->ip != tb->ip) {
			log_tcache("Cache collision, both %08x and %08x with hash %08x", entry.tb->ip, tb->ip, l1hash(tb->ip));
		}
		// l1_brind_cache[l1hash(tb->ip)] = {tb->ip, tb->tcode.ptr, tb};
		l1_brind_cache[l1hash(tb->ip)] = {tb->ip, tb->tcode.ptr};
		cache_tb_exec_count[l1hash(tb->ip)] = {tb->ip, tb};
		if (unlikely(!tb->flags.is_brind_target)) {
			cflow_dump::RecordBrindEntry(tb->ip);
		}
		tb->flags.is_brind_target = true;
	}

	// Round-18 BCT v2: re-point every already-linked direct-branch slot targeting gip to new code.
	// This completes mid-run promotion: without it, pre-promotion QCG link chains (direct jal/branch edges)
	// keep dragging execution back into QCG forever (round-17's coremark/xerces/nbody/qsort losses).
	// Called from the outer Execute loop with the guest paused on this thread -- patching is safe.
	static u32 RelinkTo(u32 gip, void *code); // defined in tcache.cpp (BranchSlot complete there)
	// ==========================================================================================
	// C5d MID-RUN PROMOTION, AS ONE OPERATION. Make `tb` the only host entry for `tb->ip` that any
	// structure in this process can still deliver control to.
	//
	// WHY THIS EXISTS AS A PRIMITIVE. Replacing a guest ip's translation is not one write; this
	// class holds SIX places that can name a host address for a guest ip, and a promotion that
	// updates some of them leaves the rest delivering control to code the process has just decided
	// to stop using. That is not hypothetical twice over:
	//
	//   * Round-17's BCT boot updated only the map and the block cache, and the already-linked
	//     direct edges "kept dragging execution back into QCG forever" -- Round-18 added `RelinkTo`
	//     to close it (see that function's own comment, and the coremark/xerces/nbody/qsort losses
	//     it names).
	//   * T5d2b2's loop-tier installer then re-created the SAME defect by design, on the argument
	//     that `Execute()`'s own lookup would enter the artifact. T5g measured the consequence: in
	//     35 of 40 trials the installed artifact was entered exactly once, and C5C read the reason
	//     off the run -- at the instant of the install the header's one already-linked predecessor
	//     still pointed at the pre-promotion QCG code.
	//
	// So the promotion wiring is written ONCE, here, and every mid-run promoter calls it. A caller
	// that wants "the same but without X" does not get to omit X: it would be re-creating the
	// partial-update class of defect, and the point of this function is that the class has no
	// spelling left.
	//
	// WHAT IT TOUCHES, and why each one is a control-transfer path and not bookkeeping:
	//   1. `tcache_map` + `l1_cache`   (InsertOrReplace) -- what `Execute()`'s lookup returns.
	//   2. `cache_tb_exec_count`       (CacheBr)         -- the block the emitted Emit_Cache
	//                                                       counter walks to. Not a transfer path,
	//                                                       but leaving it on the old block makes
	//                                                       the two disagree about which block the
	//                                                       header IS; BootOneArtifact has always
	//                                                       written it and this keeps that.
	//   3. `l1_brind_cache`            (CacheBrind)      -- a RAW host pointer the generated
	//                                                       indirect fast path jumps to without
	//                                                       consulting any TBlock.
	//   4. `link_map`'s slots          (RelinkTo)        -- self-patched direct branches.
	//   5. `ic_target_map`'s blobs     (ICUnpatchTarget) -- see below.
	//
	// 5 IS NEW HERE AND IS A REAL GAP, not tidiness. A patched inline-cache blob holds a `rel32` to
	// the target's host code and a pointer to that TBlock's own `exec_count` (ICTryPatch). Nothing
	// in the process rewrites those on a promotion, so an IC site patched before one keeps jumping
	// straight into the pre-promotion code, bypassing every structure above. `ICTryPatch` refuses
	// AOT blocks outright (`tcode.size == 0`), so the blob cannot simply be re-patched at the new
	// address; the correct action is the one `ICUnpatchTarget` already implements -- rewind the
	// guard immediate to the never-matching sentinel so the site falls back to the L1 hash path,
	// which step 3 has just pointed at the new code. BootOneArtifact did not do this; it does now,
	// by construction, because it no longer spells the promotion itself.
	//
	// PRECONDITION: the guest is PAUSED on the host stack. Every step patches memory that generated
	// code reads, and `RelinkTo`'s own comment already states this requirement; the call sites are
	// `Execute()`'s loop and the loop tier's host-stack service, both of which satisfy it. Never
	// call this from a signal handler.
	//
	// NOT IN SCOPE, deliberately: this does not invalidate, revoke or retranslate anything, and it
	// does not touch a TB whose emitted code merely CONTAINS `tb->ip` as an interior block -- no
	// structure in this process records that relation (`TBlock` carries no `ip_end`), and C5C
	// measured its conservative upper bound rather than guessing at it.
	struct PromoteCounts {
		u32 relinked;	      // direct-branch slots repointed at the new code
		u32 ic_unpatched;     // inline-cache blobs returned to the sentinel
		bool brind_was_target; // was this ip already an indirect-dispatch target
	};
	static PromoteCounts PromoteTarget(TBlock *tb);
	// Round-20: post-run tier census (mechanism evidence): walk tcache_map, classify each TB as AOT
	// (announce-created: tcode.size==0) or QCG, sum exec counts -> measured migrated vs residual mass.
	static void TierCensus(unsigned long out[4]);
	// T4 (2026-08-30): generated-host-code size, in BYTES, of the QCG code this process emitted.
	// TierCensus counts translation blocks; a block count is not a code size and the two must not
	// be reported in the same column. Each TB's tcode.size is the exact number of host machine-code
	// bytes QCG generated for it, so summing it over the non-AOT TBs is the QCG arm's generated-code
	// size directly, with no disassembly step and no unit conversion.
	//   out[0] = QCG generated host bytes   out[1] = QCG TBs   out[2] = AOT TBs
	// Same cost class as TierCensus: one map walk, at exit only, nothing on any execution path.
	static void CodeBytes(unsigned long out[3]);
	// P1 (2026-07-23): count exiled-hot TBs -- QCG-translated (tcode.size != 0, i.e. NOT served by the
	// loaded artifact) whose re-enabled in-run exec_count crossed the pipeline's own admission
	// threshold. The promotion trigger's evidence walk (host stack only; TierCensus cost class).
	static unsigned long CountExiledHot(u64 threshold);
	static void CodePoolBounds(unsigned long long *lo, unsigned long long *hi);
	// ==========================================================================================
	// C5c PROMOTION-ROUTE CENSUS (--loop-tier-route-census, default off). A PURE READ of every
	// structure in this process that can name a host entry for ONE guest ip, taken at an instant
	// the caller chooses. It exists because C5B's design rests on a quantity no preserved T5g
	// artifact contains: at the moment a header is promoted, what does each of its caches hold?
	//
	// IT IS DECLARED HERE, NOT IN THE TIER, because the structures it reads are this class's --
	// `tcache_map`, `link_map` and `ic_target_map` are private, and the honest way to read a
	// private index is a method on its owner, not a friend declaration or a copy of the walk.
	//
	// PURE MEANS PURE. It calls `LookupFull`, never `Lookup`: the latter WARMS `l1_cache` on a
	// full-lookup hit, so a diagnostic written on top of it would change which entry the next
	// dispatch finds. Nothing else here writes: three array reads by index, two `equal_range`s
	// and one ordered walk of the map. `loop_tier_route_census_test` asserts the whole observable
	// cache state is byte-identical across a call, which is the runtime half of the same claim.
	//
	// CLASSIFICATION IS BY POINTER IDENTITY AGAINST TWO CALLER-SUPPLIED TAGS, not by guesswork:
	// `tag_qcg` is the `tcode.ptr` the header's block had when the caller first sampled it (i.e.
	// before any promotion), `tag_aot` is the host entry a promotion installed (0 before one).
	// Both are echoed on the emitted line so the classification can be re-derived from the record
	// rather than trusted. The code-pool range is read as an INDEPENDENT second opinion: QCG code
	// is allocated from `code_pool` and an artifact's is not, so `link_in_pool` must agree with
	// `link_to_qcg` and a disagreement is a defect in one of the two, not a finding.
	static constexpr unsigned ROUTE_CENSUS_MAX_INTERIOR = 16;
	struct RouteCensusOut {
		u32 gip;
		// What the map says now. `cur_is_aot` is the announce-created shape (tcode.size == 0).
		void const *cur_ptr;
		int cur_present, cur_is_aot;
		int l1_tb_is_cur; // does l1_cache[l1hash(gip)] hold the same block the map does
		// link_map: the already-self-patched direct-branch slots that target `gip`.
		u32 link_slots, link_to_qcg, link_to_aot, link_to_other, link_lazy, link_in_pool,
		    link_undecodable;
		// l1_brind_cache: the indirect-dispatch fast path's cached raw host pointer.
		int brind_tag_hit, brind_is_qcg, brind_is_aot, brind_in_pool;
		// cache_tb_exec_count: the PROFILING cache the emitted Emit_Cache counter walks.
		int exec_tag_hit, exec_tb_is_qcg, exec_tb_is_aot, exec_tb_is_cur;
		unsigned long long exec_count;
		// ic_target_map: A-line inline-cache blobs patched to jump straight at `gip`.
		u32 ic_blobs;
		// The §4.7 residue, as a CONSERVATIVE UPPER BOUND and never as a measurement: a TB whose
		// emitted code may contain `gip` as an interior block, which no structure in this process
		// records because `TBlock` carries no `ip_end`. Two bounds, both over-approximations:
		//   _page -- every TB on `gip`'s page with a lower entry ip, since a compilation range
		//            never crosses a page (GetCompilationIPRange);
		//   _insn -- those additionally satisfying ip + 4*exec_instr_count > gip, using 4 as the
		//            maximum RV32 instruction length, so it can only over-count.
		u32 interior_ub_page, interior_ub_insn, interior_n;
		u32 interior_ip[ROUTE_CENSUS_MAX_INTERIOR];
	};
	static void RouteCensus(u32 gip, void const *tag_qcg, void const *tag_aot, RouteCensusOut *out);
	// PURE map read. Unlike `Lookup` it does not warm `l1_cache`; the census caller uses it to
	// latch the pre-promotion host entry without changing what the next dispatch sees.
	static TBlock *PeekBlock(u32 gip)
	{
		return LookupFull(gip);
	}
	// How many (target, slot) edges the link index holds. Exists so RecordLink's idempotence can be
	// asserted from a test instead of argued from its source: with the T5d-0 safepoint escaping on
	// every traversal of an already-linked edge, "the map does not grow" is a property that has to
	// be checked, and the private member cannot be read from outside.
	static size_t LinkMapSize()
	{
		return link_map.size();
	}
	static void DumpTBMap(char const *path); // qcg_tbs, aot_tbs, qcg_exec, aot_exec
	// A-line Round 61: like DumpTBMap, but also hex-dumps each QCG TB's raw host machine code
	// bytes in-process (no gdb/ptrace interaction, no ASLR-address staleness) so an offline
	// disassembly classifier can compare direct- vs indirect-terminated TBs' generated code
	// directly. Analysis-only, default-off.
	static void DumpTBCode(char const *path);

	static void RecordLink(jitabi::ppoint::BranchSlot *slot, TBlock *tgt, bool cross_segment)
	{
		tgt->flags.is_segment_entry |= cross_segment;
		// IDEMPOTENT IN (target, slot), and this is a correctness property, not a tidiness one.
		//
		// `link_map` is an index from a target ip to the slots that jump to it, and its only
		// consumers are RevokeTarget/InvalidatePage, which walk the range and unlink every slot in
		// it. A second identical entry therefore carries no information -- it makes those walks
		// unlink the same slot twice.
		//
		// But a slot really can be linked to the same target many times. Any escape that returns
		// to Execute() from an already-linked direct edge re-links it on the way back, and the
		// T5d-0 backedge safepoint turns that from a rarity into a routine event: one re-link per
		// escape. Without this test the map grew with the ESCAPE COUNT rather than with the number
		// of distinct edges -- measured at 183k nodes on a 0.07 s pilot run whose guest has 156
		// direct edges, and the multimap destructor at process exit then ran long enough for the
		// keeper's timer tick to land inside it and fault. Refusing the duplicate removes the
		// growth at its source.
		//
		// Cost: one equal_range plus a scan of that target's existing predecessors, on the host
		// loop's link path, which is already doing a tcache lookup. The range is the fan-in of one
		// guest block.
		auto [lo, hi] = link_map.equal_range(tgt->ip);
		bool known = false;
		for (auto it = lo; it != hi; ++it) {
			if (it->second == slot) {
				known = true;
				break;
			}
		}
		if (!known)
			link_map.insert({tgt->ip, slot});
		// Deliberately OUTSIDE the test: the T5c escape ring's contents are a recency record of
		// linking EVENTS, not a set of edges, so gating it here would change --inrun-escape-unlink's
		// behaviour. It stays exactly as it was.
		if (unlikely(config::inrun_escape_unlink))
			RecordEscLink(slot);
	}

	// T5c-0 LIFECYCLE PLUMBING: the keeper-armed DIRECT-LINK escape.
	//
	// WHY THIS EXISTS. Every mid-run host-stack event in rvdbt -- the tier's evaluator, the artifact
	// boot, the P1 scan, the saturation sweep -- is consumed in the Execute() loop, and JIT'd code
	// only returns there through the indirect-branch slowpath (jitabi.cpp, qcgstub_escape_brind).
	// bct_alarm_handler's remedy is to flush the brind L1 so the next indirect transfer misses and
	// escapes. That works for a loop that HAS an indirect transfer the cache was absorbing. It does
	// nothing for a pure-compute leaf loop that executes none: PolyBench gemm's kernel contains
	// exactly one indirect transfer, its own closing `ret`, so 113 keeper ticks produced 17 escapes
	// in 5.7 s -- the same 15 a 0.07 s run of the same kernel produced. The escape count is a
	// property of the program's call structure, not of its duration, so no dataset, threshold or
	// cadence can fix it. Measured in T5C0_FORMAL_REAL_WORKLOAD.md §5.
	//
	// WHAT IT DOES. Direct branches self-patch into a `jmp rel32` on first traversal and never come
	// back. This records each slot as it is linked (host stack, once per edge) and lets the keeper
	// return a bounded number of them to the lazy-JIT stub, so the very next traversal lands in
	// Execute() and the ALREADY-EXISTING evaluator/boot call site runs. It is an escape route and
	// nothing else: no admission bar, evidence gate, threshold, region choice or cadence is touched,
	// and it is armed only while the tier is armed and un-booted. Default OFF.
	static constexpr unsigned ESC_LINK_SLOTS = 512;
	static void RecordEscLink(jitabi::ppoint::BranchSlot *slot)
	{
		esc_link_ring[esc_link_head & (ESC_LINK_SLOTS - 1)] = slot;
		esc_link_head = esc_link_head + 1;
	}
	// Signal-safe: a bounded array walk and one 12-byte store per slot, no allocation, no map.
	// Patching is safe against the interrupted guest because a signal is delivered at an instruction
	// boundary, a linked slot is a single `jmp rel32`, so the interrupted RIP is either the slot's
	// first byte or outside it, and the rewrite completes before sigreturn refetches.
	static unsigned UnlinkRecorded();
	// Any pointer in the ring may be freed by a page invalidation or a target revoke. Both run on
	// the host stack and both drop the whole ring: it is a hint, so losing it costs one escape, and
	// keeping a stale entry would let the keeper write into reclaimed code.
	static void ClearEscLinks()
	{
		for (unsigned i = 0; i < ESC_LINK_SLOTS; ++i)
			esc_link_ring[i] = nullptr;
		esc_link_head = 0;
	}
	static jitabi::ppoint::BranchSlot *esc_link_ring[ESC_LINK_SLOTS];
	static volatile unsigned esc_link_head;

	static void *AllocateCode(size_t sz, u16 align);
	static TBlock *AllocateTBlock();

	static constexpr u32 L1_CACHE_BITS = 22; // TODO: this should depend on the size of the executable, to avoid cache miss that possibly leads to inacurate profiler.
	using L1Cache = std::array<TBlock *, 1u << L1_CACHE_BITS>;
	static L1Cache l1_cache;

	struct BrindCacheEntry {
		u32 gip;
		void *code;
	};
	using L1BrindCache = std::array<BrindCacheEntry, 1u << L1_CACHE_BITS>;
	static L1BrindCache l1_brind_cache;
	struct CacheTbExecCountEntry {
		u32 gip;
		TBlock *tb;
	};
	using L1CacheTbExecCount = std::array<CacheTbExecCountEntry, 1u << L1_CACHE_BITS>;
	static L1CacheTbExecCount cache_tb_exec_count;

	// A-line (Codex-mandated redesign, 2026-07-24): Design 3, a per-TARGET online Boyer-Moore
	// majority-vote counter, piggybacked on the ALREADY-HOT, ALREADY-UNCONDITIONALLY-EXECUTED
	// l1_brind_cache HIT path (Emit_gbrind, qemit.cpp) -- reuses the SAME already-computed hash
	// offset (`tmp0`) that indexes l1_brind_cache/cache_tb_exec_count at that site, so no new hash
	// computation is added. 16 bytes/slot (matches BrindCacheEntry/CacheTbExecCountEntry's size so
	// the existing *16-scaled offset needs no rescaling). `target_gip` is redundant with
	// l1_brind_cache[same slot].gip (already verified equal by the hit check) but kept explicit so
	// the offline dump does not need to know l1_brind_cache's internal layout.
	//
	// Correctness is a MATHEMATICAL guarantee (Boyer-Moore 1981 / Misra-Gries k=2), not a tuned
	// constant: if a source S accounts for a STRICT MAJORITY (>50%) of a target's arrivals, S is
	// GUARANTEED to be the final candidate regardless of arrival order or any other sources'
	// distribution -- there is no capacity/K to tune for correctness. `counter` is the algorithm's
	// own vote margin (not a workload-tuned cap); it is read, never resized based on workload.
	//
	// Boyer-Moore alone only guarantees CORRECTNESS of the candidate IF a true majority exists; it
	// does not certify that one does. `candidate_hits` closes this gap without a second pass: an
	// EXACT count of dispatches where src==candidate_src, reset to 1 whenever candidate_src is
	// (re)adopted. candidate_hits is therefore always <= the candidate's TRUE total arrival count
	// at this target (it only ever undercounts, by missing any hits from BEFORE the candidate's
	// most recent adoption) -- so `candidate_hits*2 > target_exec_count` is a SUFFICIENT, safe,
	// never-wrong certificate of a real strict majority, checked entirely from single-pass data,
	// no oracle, no reconstruction. If it does not hold, abstain (never report a guessed edge).
	struct MajorityVoteEntry {
		u32 target_gip;
		u32 candidate_src;
		u32 counter;
		u32 candidate_hits;
	};
	using L1MajorityCache = std::array<MajorityVoteEntry, 1u << L1_CACHE_BITS>;
	static L1MajorityCache majority_cache;

	static ALWAYS_INLINE u32 l1hash(u32 ip)
	{
		return (ip >> 2) & ((1ull << L1_CACHE_BITS) - 1);
	}

	// A-line (--shadow-edges): a SEPARATE cache from l1_brind_cache above, indexed by SOURCE
	// address instead of TARGET address (l1_brind_cache: cache[hash(target)] = {target, code},
	// so a hit only proves "this target was dispatched to before, from ANY source" -- a second
	// distinct source reaching an already-cached target is invisible to it). QEmit::Emit_gbrind
	// does the hit/miss compare INLINE (mirroring the l1_brind_cache check just below it in the
	// same function) so only a genuine miss or hash collision reaches ShadowEdgeCheckImpl
	// (jitabi.cpp). SHADOW_EDGE_BITS is a correctness-neutral COST parameter, not a correctness
	// parameter: two distinct source addresses colliding on the same slot can only cause an
	// extra (harmless) re-log of an already-known edge -- the inline check re-validates BOTH
	// `src` and `tgt` before treating a lookup as a hit, so a collision is always treated as "not
	// this exact (src,tgt)" and falls to the slow path, never as "no new edge." See
	// SHADOW_EDGES_PROGRESS.md for the measured collision/relog rate this size implies on real
	// corpora (justification is empirical, not an a-priori "large enough" claim).
	struct ShadowEdgeSlot {
		u32 src;
		u32 tgt;
	};
	static constexpr u32 SHADOW_EDGE_BITS = 16;
	using ShadowEdgeCache = std::array<ShadowEdgeSlot, 1u << SHADOW_EDGE_BITS>;
	static ShadowEdgeCache shadow_edge_cache;

	static ALWAYS_INLINE u32 shadow_edge_hash(u32 ip)
	{
		return (ip >> 2) & ((1u << SHADOW_EDGE_BITS) - 1);
	}

	// Item-3 required measurement (not a debug scaffold): total inline-checked dispatches,
	// how many of those fell through to the slow-path handler, and of those, how many were true
	// hash collisions (a DIFFERENT source's slot) vs. a same-source target change (a genuine new
	// edge observation). Incremented inline in QEmit::Emit_gbrind / ShadowEdgeCheckImpl; dumped
	// alongside the edge file so cost is never asserted without being measured.
	static u64 shadow_edge_total_dispatches;
	static u64 shadow_edge_slow_calls;
	static u64 shadow_edge_collisions;

	// H2 (--shadow-edges-k=<N>, N>=2; see config.h shadow_edges_k and
	// SUPPORT_DISCOVERY_H1_VS_H2.md): a per-source K-WAY history SET, replacing H1's single
	// last-target slot with up to kMaxK remembered targets per hashed source slot. Same hash
	// space/discipline as ShadowEdgeSlot above (direct-mapped by shadow_edge_hash(src), a
	// hash-address COLLISION -- a different real source landing on the same slot -- is
	// distinguished from this source's OWN set simply being at CAPACITY; both are harmless
	// (an extra, safe re-log via brindedges::Record), never a dropped edge, since capacity
	// affects cost only, per this cycle's non-negotiable safety invariant). Eviction is plain
	// round-robin/FIFO (evict_next), not LRU -- simplest correct choice for a first cut; a
	// smarter replacement policy would only ever change COST, not correctness, so it is not
	// required to establish whether widening the set helps at all.
	struct ShadowEdgeKSlot {
		static constexpr u32 kMaxK = 8; // upper bound on config::shadow_edges_k (CLI-clamped)
		u32 src;
		std::array<u32, kMaxK> targets{};
		// A-line 2026-07-25 round 13: per-slot saturating HIT counter, parallel to `targets` --
		// incremented on every dispatch that matches an already-tracked target (the H2 "hit" path,
		// previously a pure no-op), and initialized to 1 on first insertion/eviction-reinsertion.
		// Adds exactly one integer increment to a code path already called unconditionally on every
		// dispatch (see ShadowEdgeKCheckImpl) -- no new call, no new branch structure, near-zero
		// marginal cost. Needed because H2's original design only calls brindedges::Record on a
		// SET-MISS (new-to-this-source target), so for the common case (a source's true polymorphism
		// fits within K, i.e. no eviction ever happens), the exact-oracle count downstream of Record
		// reflects DISCOVERY order/frequency, not true per-target HIT frequency -- useless for
		// weight-ordering a multiguard chain. This counter is the true, cheaply-tracked quantity.
		std::array<u32, kMaxK> counts{};
		u8 n_valid{0};    // how many of targets[0..n_valid) are populated (<= config::shadow_edges_k)
		u8 evict_next{0}; // round-robin cursor once n_valid saturates at config::shadow_edges_k
	};
	using ShadowEdgeKCache = std::array<ShadowEdgeKSlot, 1u << SHADOW_EDGE_BITS>;
	static ShadowEdgeKCache shadow_edge_k_cache;

	// Same counter discipline as H1's shadow_edge_* trio above, always measured (not asserted)
	// when --shadow-edges-k>=2 is active. total_dispatches/slow_calls are directly comparable to
	// H1's same-named counters (both count "reached the handler" / "issued a brindedges::Record",
	// H2's handler is reached on EVERY shadow-tracked dispatch since this first cut calls it
	// unconditionally -- see qemit.cpp -- so here total_dispatches==slow_calls by construction;
	// kept as two counters anyway for exact parity with H1's dump format and any future inlined
	// H2 fast path). hash_collisions is H1-equivalent (different SOURCE, same hashed slot);
	// capacity_evictions is the genuinely NEW quantity H2 introduces (this source's own K-way set
	// was already full of K DIFFERENT targets and a K+1th target arrived) -- the two must be
	// reported separately, never merged, since they answer different questions (hash table sizing
	// vs. per-source polymorphism exceeding K).
	static u64 shadow_edge_k_total_dispatches;
	static u64 shadow_edge_k_slow_calls;
	static u64 shadow_edge_k_hash_collisions;
	static u64 shadow_edge_k_capacity_evictions;

	// A-line round 14 (--shadow-edges2): TRACK 2 (near-zero-marginal multi-target collector) --
	// H2's out-of-line C++ handler call measured 41-145% evidence-acquisition overhead (Round 13),
	// while shadow-majority's fully-INLINE, no-function-call design (piggybacked on the l1_brind_
	// cache hit path) measured only 7-12% overhead on the same real workloads -- strong existing
	// evidence that the call itself, not the underlying idea, is the cost. This is a fixed, 2-slot
	// PER-SOURCE inline collector (source-indexed, like H1/H2 -- NOT target-indexed like shadow-
	// majority, since multiguard needs "this source's targets", not "this target's dominant
	// source"), hashed and compile-time-address-baked exactly like H1's ShadowEdgeSlot (see
	// shadow_edge_hash) so there is no runtime hash computation, no out-of-line call, and no loop
	// -- a fixed 2-slot straight-line compare/update sequence, structurally the same complexity
	// class as shadow-majority's already-working inline 3-way case. 2 slots is a STRUCTURAL bound
	// (this struct's own fixed field count, mirroring H1's 1-slot precedent), not a workload-tuned
	// accuracy cutoff: a 3rd+ distinct target for a source is dropped (never Recorded, never
	// evicted-and-replaced) -- purely a coverage/precision cost, never a correctness one, since
	// multiguard's own generic-gbrind fallback covers any target this collector never saw.
	struct ShadowEdge2Slot {
		u32 src;
		u32 t0, c0;
		u32 t1, c1;
	};
	static constexpr u32 SHADOW_EDGE2_BITS = 16; // same size class as H1/H2
	using ShadowEdge2Cache = std::array<ShadowEdge2Slot, 1u << SHADOW_EDGE2_BITS>;
	static ShadowEdge2Cache shadow_edge2_cache;

	static ALWAYS_INLINE u32 shadow_edge2_hash(u32 ip)
	{
		return (ip >> 2) & ((1u << SHADOW_EDGE2_BITS) - 1);
	}

	// A-line 2026-07-27 (--temporal-order-collect): per-SOURCE order-1/order-2 lag-match collector,
	// direct response to the Codex 7th audit's P1 (the earlier --sr-bounded-exhaustive design
	// caps the first N dispatches of the WHOLE PROGRAM, biasing against late-heating sites, AND
	// corrupts admission exec_count accounting past the cap -- see
	// experiments/2026-07-27-1812-aline-fresh-decision-trace-mismatch/SECTION_D_REAL_WORLD_BRIDGE.md).
	// This collector never forces a slowpath and never touches profile_brind_edges/exec_count at
	// all -- it is a fully independent, always-inline, per-dispatch update piggybacked on the SAME
	// technique shadow_edge2_cache already validates (7-12% measured overhead, whole-run, no
	// window): _entry_ip is compile-time-constant for a jalr-terminated TB, so the slot address is
	// baked as an immediate, zero runtime hash. Every real dispatch through an instrumented site
	// updates this slot, for the entire run, not just an early window -- directly fixing the
	// late-hot/phase bias the bounded-exhaustive design had.
	//
	// Fields: `total` = EXACT real dispatch count (unconditional, every dispatch, sample-size/
	// confidence denominator for marginal purposes -- comparable to Wendell's own exec_count).
	// `compared` = number of those dispatches on which the EXPENSIVE lag1/lag2 compare actually ran
	// (stride-16-decimated, see the cost-fix comment on qemit.cpp's Emit_gbrind for why: the
	// compare itself, not the cheap last1/last2 shift, is the real per-dispatch cost driver, since
	// its outcome is a data-dependent, inherently-hard-to-predict branch). `lag1_match`/
	// `lag2_match` = count of dispatches (out of `compared`, NOT `total`) where the target equals
	// the immediately-previous / two-dispatches-ago target AT THIS SOURCE (order-1 "same as last" /
	// order-2 "period-2 match" -- this is what distinguishes a strict alternating dispatch,
	// order-1 same-rate 0, from a truly unpredictable one; see the expat 0001134c/000121cc real
	// finding this statistic already reproduced exactly under the OLD 100%-sampled design).
	// `lag1_match/compared` and `lag2_match/compared` are the correct rates -- dividing by `total`
	// instead would silently deflate them by ~16x. `last1`/`last2` are the small rolling history
	// (always exact, every real dispatch, never decimated), never read externally. Marginal
	// per-target counts (needed for the collision-probability null hypothesis) are NOT duplicated
	// here -- reuse the already-existing, already-inline, already whole-run shadow_edge2_cache (2
	// slots/source) for that, joined offline by the same _entry_ip key. Bounded, fixed memory:
	// sizeof(TemporalOrderSlot) * 2^SHADOW_EDGE2_BITS, exact bytes reported by the dump function.
	struct TemporalOrderSlot {
		u32 src;
		u32 last1, last2;
		u64 total;
		u64 compared;
		u64 lag1_match, lag2_match;
	};
	using TemporalOrderCache = std::array<TemporalOrderSlot, 1u << SHADOW_EDGE2_BITS>;
	static TemporalOrderCache temporal_order_cache;

	// A-line 2026-07-27 P1-fix (real measured overhead too high at 100% sampling: expat +8.5%,
	// wasm3_indcall +12.2%, pugixml +15.6%, n=5 -- see SECTION_D_REAL_WORLD_BRIDGE.md): decimate the
	// EXPENSIVE lag1/lag2 compare-and-increment work (data-dependent, hard-to-predict branches -- the
	// actual cost driver) to 1-in-N dispatches, while `total` and the last1/last2 shift always run
	// (cheap, unconditional, correctness-critical). A first version used a SEPARATE GLOBAL tick (its
	// own cache line, touched every dispatch regardless of site) -- measured WORSE than no decimation
	// at all (expat 16.7% vs 8.5%): the extra always-paid global memory access cost more than the
	// decimated compares saved. Fixed by reusing `total`'s OWN just-incremented low bits (this slot's
	// OWN dispatch count, no new memory location -- the cache line is already being touched by the
	// `total` inc immediately before) as the decimation clock instead. This also makes the clock
	// PER-SITE rather than global, which is a cleaner phase-robustness property: a site that only
	// becomes hot late in the run still gets its proportional share of samples spread uniformly
	// across ITS OWN real lifetime (not a first-N-dispatches cutoff, and not diluted by how many
	// OTHER sites fire in between). N is a power of 2 (mask check, no division); not workload-tuned.
	static constexpr u32 TEMPORAL_ORDER_STRIDE_BITS = 4; // stride = 16

	// A-line round 15 (TRACK 1, --shadow-edges2-all-jalr): TRUE total dispatch counts by static
	// class (CALL/TAILCALL/RETURN), independent of the 2-slot target cache above -- the per-
	// target counts undercount RETURN sites specifically (a shared function's return site can
	// have far more than 2 distinct real targets/callers, so most of its dispatches never match
	// either cached slot and are silently dropped from the target-count data). These 3 plain
	// counters are incremented UNCONDITIONALLY on every shadow_edges2-instrumented dispatch,
	// regardless of hit/miss/capacity-drop, giving an exact denominator per class.
	static u64 shadow_edge2_dispatches_call;
	static u64 shadow_edge2_dispatches_tailcall;
	static u64 shadow_edge2_dispatches_return;

	// A-line round 28 Gate 1 (default off, ORACLE only): per-SOURCE order-1 context slots. Each
	// eligible gbrind SITE (not target, not a shared global like CPUState::last_brind_target) is
	// assigned a unique compile-time slot index (dbt::config::g_gbrind_site_id_next-style
	// counter, bounded by this array's size -- sites beyond the bound simply get no oracle,
	// falling back to the unchanged generic path, safe by construction). Holds the last ACTUAL
	// target THIS ONE SITE observed, read+updated on every dispatch through it, never shared with
	// any other site. Deliberately a plain array, direct-indexed (no hash, no collision) since the
	// index is a compile-time-assigned dense integer, not a runtime hash of an address.
	static constexpr u32 GBRIND_CTX1_SLOTS = 4096;
	static std::array<u32, GBRIND_CTX1_SLOTS> gbrind_ctx1_slots;

	// A-line Round 48 (--gbrind-hitrate-collect, default off): per-SOURCE hit/miss counter for the
	// ALREADY-EXISTING, always-on L1 gbrind-cache check every indirect dispatch performs
	// (Emit_gbrind's inlined l1_brind_cache lookup) -- a DIFFERENT question than shadow_edges2's
	// target IDENTITY/distribution (which target did this source hit): purely "was THIS source's
	// own already-executed cache check a hit or a miss", to correct llvmgen.cpp's blanket
	// `md_unlikely` (P(miss)~=7.7% unconditionally) hint on that check's branch with this source's
	// OWN real observed rate. Fixed-size, hashed, compile-time-address-baked exactly like
	// shadow_edge2_cache (1 extra `inc` per path, no runtime hash, no out-of-line call, no slot
	// compare/evict logic since there is nothing to identify beyond hit-vs-miss) -- collisions
	// (two different sources sharing a hashed slot) merge their counts, an accepted approximation,
	// same tradeoff shadow_edge2_cache already makes for target identity.
	struct GbrindHitrateSlot {
		u64 hit, miss;
	};
	static constexpr u32 GBRIND_HITRATE_BITS = 16; // same size class as shadow_edge2_cache
	using GbrindHitrateCache = std::array<GbrindHitrateSlot, 1u << GBRIND_HITRATE_BITS>;
	static GbrindHitrateCache gbrind_hitrate_cache;

	static ALWAYS_INLINE u32 gbrind_hitrate_hash(u32 ip)
	{
		return (ip >> 2) & ((1u << GBRIND_HITRATE_BITS) - 1);
	}

	// PM round-10 P3 (--qcg-dispatch-ic-regret): per-SOURCE (hit, miss) counters for the
	// qcg_dispatch_ic guard itself (not the L1 cache -- a different check). hit is incremented by
	// the patched blob itself (ICTryPatch redirects the existing hit-counter address here when
	// regret-tracking is on); miss is incremented in qcgstub_brind (jitabi.cpp) whenever the
	// slowpath is reached AGAIN for a site whose blob is ALREADY patched (i.e. its current guess
	// just failed). Same hash/collision tradeoff as gbrind_hitrate_cache above.
	struct QcgIcRegretSlot {
		u64 hit, miss;
		u8 *blob; // this source's OWN guard blob address, populated post-emission (EmitCode()),
		          // read back by the inline miss-path revert check below -- always populated
		          // before any runtime execution of the code that reads it (compile-time
		          // registration happens synchronously before the compiled code is ever run).
	};
	using QcgIcRegretCache = std::array<QcgIcRegretSlot, 1u << GBRIND_HITRATE_BITS>;
	static QcgIcRegretCache qcg_ic_regret_cache;

	// Backup/diagnostic-only check, called from qcgstub_brind when a slowpath visit lands on an
	// ALREADY-patched site. The PRIMARY revert mechanism is now fully inline (qemit.cpp emits a
	// compare+conditional-store right after the miss counter increment, so it fires on EVERY guard
	// miss, not just the rarer subset that also misses the L1 cache and reaches this slowpath) --
	// this is a harmless, idempotent second check for the subset of misses that DO reach here.
	static void QcgIcRegretMiss(u32 site_ip, u8 *blob)
	{
		auto &slot = qcg_ic_regret_cache[gbrind_hitrate_hash(site_ip)];
		if (slot.miss > slot.hit) {
			u32 *guard_imm = (u32 *)(blob + 2);
			if (*guard_imm != 0xFFFFFFFFu) { // avoid a redundant write if already reverted
				*guard_imm = 0xFFFFFFFFu;
				dbt::config::qcg_ic_regret_reverted++;
			}
		}
	}

	static void PrintTBPoolStats()
	{
		log_tcache("TB pool used size: %zu", tb_pool.GetUsedSize());
	}

	static void PrintCodePoolStats()
	{
		log_tcache("Code pool used size: %zu", code_pool.GetUsedSize());
	}

private:
	tcache() = delete;
	friend struct objprof;

	static TBlock *LookupFull(u32 ip);

	using MapType = std::map<u32, TBlock *>;
	static MapType tcache_map;

	static constexpr size_t TB_POOL_SIZE = 32 * 1024 * 1024;
	static MemArena tb_pool;

	static constexpr size_t CODE_POOL_SIZE = 128 * 1024 * 1024;
	static MemArena code_pool;

	static std::multimap<u32, jitabi::ppoint::BranchSlot *> link_map;
	static std::vector<u32> brind_dirty; // round-25: slots filled since last flush (targeted poison)
	static std::unordered_map<uptr, ICSiteInfo> ic_ret_map; // A-line IC: slowpath retaddr -> site
	static std::multimap<u32, u8 *> ic_target_map;    // A-line IC: patched target gip -> blob
	static std::vector<std::pair<unsigned long long *, u32>> edge_slots;
	static std::deque<unsigned long long> edge_slot_arena;
};

} // namespace dbt
