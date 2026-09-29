#include "dbt/tcache/tcache.h"
#include "dbt/qmc/qcg/jitabi.h"

namespace dbt
{

tcache::L1Cache tcache::l1_cache{};
tcache::L1BrindCache tcache::l1_brind_cache{};
jitabi::ppoint::BranchSlot *tcache::esc_link_ring[tcache::ESC_LINK_SLOTS]{};
volatile unsigned tcache::esc_link_head{0};
tcache::L1CacheTbExecCount tcache::cache_tb_exec_count{};
tcache::L1MajorityCache tcache::majority_cache{};
tcache::ShadowEdgeCache tcache::shadow_edge_cache{};
u64 tcache::shadow_edge_total_dispatches{0};
u64 tcache::shadow_edge_slow_calls{0};
u64 tcache::shadow_edge_collisions{0};
tcache::ShadowEdgeKCache tcache::shadow_edge_k_cache{};
u64 tcache::shadow_edge_k_total_dispatches{0};
u64 tcache::shadow_edge_k_slow_calls{0};
u64 tcache::shadow_edge_k_hash_collisions{0};
u64 tcache::shadow_edge_k_capacity_evictions{0};
tcache::ShadowEdge2Cache tcache::shadow_edge2_cache{};
u64 tcache::shadow_edge2_dispatches_call{0};
u64 tcache::shadow_edge2_dispatches_tailcall{0};
u64 tcache::shadow_edge2_dispatches_return{0};
tcache::TemporalOrderCache tcache::temporal_order_cache{};
std::array<u32, tcache::GBRIND_CTX1_SLOTS> tcache::gbrind_ctx1_slots{};
tcache::GbrindHitrateCache tcache::gbrind_hitrate_cache{};
tcache::QcgIcRegretCache tcache::qcg_ic_regret_cache{};
tcache::MapType tcache::tcache_map{};
MemArena tcache::code_pool{};
MemArena tcache::tb_pool{};
std::multimap<u32, jitabi::ppoint::BranchSlot *> tcache::link_map;
std::vector<u32> tcache::brind_dirty;
std::unordered_map<uptr, tcache::ICSiteInfo> tcache::ic_ret_map;
std::vector<std::tuple<u32, u32, unsigned long long *>> tcache::ic_edge_counts;
std::multimap<u32, u8 *> tcache::ic_target_map;
std::vector<std::pair<unsigned long long *, u32>> tcache::edge_slots;
std::vector<std::pair<unsigned long long *, u32>> tcache::shadow_slots;
std::deque<unsigned long long> tcache::edge_slot_arena;
std::vector<tcache::SatSite> tcache::sat_sites;
std::unordered_map<u32, tcache::SatCarry> tcache::sat_carry;

void tcache::SatSiteRegister(u32 site_ip, u32 target, unsigned long long *slot)
{
	sat_sites.push_back({site_ip, target, slot});
	dbt::config::sat_all_retired = false; // re-arm the tick (fresh sites may saturate later)
	dbt::config::sat_backoff = 1;         // new sites reset the sweep backoff
	dbt::config::sat_next_eval_tick = 0;
}

// A-line RETIRE-v2: retranslate site TBs owning a counting seq whose target saturated. Host stack
// only (Execute loop; no guest frame can return into a revoked TB -- QCG frames are destroyed on
// branch-out). Counts and the is_brind_target bit are carried across the revoke so admission
// decisions are unchanged (frozen-at->=T values satisfy the saturation theorem).
void tcache::SatSweepAndPatch(u64 threshold)
{
	dbt::config::sat_sweeps++;
	if (dbt::config::qcg_freq_entry)
		FoldEdgeCounters(); // v3: counts live in arena slots until folded
	std::unordered_set<u32> to_retranslate;
	for (size_t i = 0; i < sat_sites.size();) {
		auto &s = sat_sites[i];
		auto it = tcache_map.find(s.target);
		// saturation = folded TB count (if a TB exists) plus the live slot residue; TB-less
		// interior blocks saturate purely via their (monotone, never-folded) slot
		unsigned long long c = (it != tcache_map.end() ? it->second->flags.exec_count : 0) +
				       (s.slot ? *s.slot : 0);
		if (c >= threshold) {
			// TB-less block: preserve the skip decision across the retranslation via a
			// profile-invisible carry (had_tb=false)
			if (it == tcache_map.end()) {
				auto &bc = sat_carry[s.target];
				bc.count += s.slot ? *s.slot : 0;
			}
			to_retranslate.insert(s.site_ip);
			s = sat_sites.back();
			sat_sites.pop_back();
			continue;
		}
		++i;
	}
	for (u32 ip : to_retranslate) {
		auto it = tcache_map.find(ip);
		if (it == tcache_map.end())
			continue;
		auto *tb = it->second;
		if (tb->tcode.size == 0)
			continue; // AOT-announced: never touch
		auto &c = sat_carry[ip];
		c.count += tb->flags.exec_count;
		c.instr = tb->flags.exec_instr_count;
		c.brt = c.brt || tb->flags.is_brind_target;
		c.seg = c.seg || tb->flags.is_segment_entry;
		c.had_tb = true;
		RevokeTarget(ip);
		// drop this site TB's remaining seqs -- they die with the revoked code
		for (size_t i = 0; i < sat_sites.size();) {
			if (sat_sites[i].site_ip == ip) {
				sat_sites[i] = sat_sites.back();
				sat_sites.pop_back();
			} else {
				++i;
			}
		}
		dbt::config::sat_retired_sites++; // counts retranslated site TBs in v2
	}
	if (sat_sites.empty())
		dbt::config::sat_all_retired = true; // silence tick flushes until new sites register
	// doubling backoff bookkeeping (see sat_alarm_handler)
	if (!to_retranslate.empty())
		dbt::config::sat_backoff = 1;
	else
		dbt::config::sat_backoff *= 2;
	dbt::config::sat_next_eval_tick = dbt::config::sat_tick + dbt::config::sat_backoff;
}

// A-line EDGE: drain per-edge counters into their target TB's exec count. Reset-on-read keeps the
// fold idempotent across multiple UpdateProfile calls. A slot whose target TB is gone loses its
// pending delta -- identical to stock semantics, where counts accumulated since the last
// UpdateProfile die with the TB.
void tcache::FoldEdgeCounters()
{
	for (auto &[slot, tgt] : edge_slots) {
		unsigned long long v = *slot;
		if (!v)
			continue;
		auto it = tcache_map.find(tgt);
		if (it == tcache_map.end())
			continue; // TB-less block: keep accumulating (retirement reads the slot directly);
				  // stock never credits such ips either, so nothing enters the profile
		*slot = 0;
		it->second->flags.exec_count += v;
	}
}

// A-line IC: unpatching only rewinds the guard immediate to the never-matching sentinel
// (0xFFFFFFFF is odd; guest jalr targets always have bit 0 cleared), leaving the rest of the
// blob inert -- the site falls back to the unchanged L1-hash path, slower but always correct.
void tcache::ICUnpatchTarget(u32 gip)
{
	auto [lo, hi] = ic_target_map.equal_range(gip);
	for (auto it = lo; it != hi; ++it)
		*(u32 *)(it->second + 2) = 0xFFFFFFFFu;
	ic_target_map.erase(lo, hi);
}

void tcache::ICTryPatch(uptr ra, TBlock *tb)
{
	if (!tb || tb->tcode.size == 0) // JIT targets only (AOT-announced TBs have no QCG code)
		return;
	auto *info = ICLookup(ra);
	u8 *blob = info ? info->blob : nullptr;
	if (!blob || blob[0] != 0x81 || blob[1] != 0xFE)
		return; // fail-safe: unknown site or wrong mapping degrades to no-op
	u32 sentinel;
	memcpy(&sentinel, blob + 2, 4);
	if (sentinel != 0xFFFFFFFFu && !dbt::config::qcg_ic_lasttarget)
		return; // already patched (first-wins; last-target mode repatches instead)
	i64 rel = (i64)(uptr)tb->tcode.ptr - ((i64)(uptr)blob + 31);
	if (rel < INT32_MIN || rel > INT32_MAX)
		return;
	if (unlikely(dbt::config::qcg_ic_regret)) {
		// PM round-10 P3: redirect the hit-counter to this SOURCE's own regret-tracking slot
		// (keyed by info->site_ip, the guard's own guest ip) instead of the target's shared
		// exec_count, so hit and miss (incremented in qcgstub_brind) land in the same slot for a
		// clean per-site comparison. KNOWINGLY diverts exec-count attribution on IC hits, same
		// tradeoff qcg_ic_edge_count's probe mode already makes above.
		u64 cnt = (u64)&qcg_ic_regret_cache[gbrind_hitrate_hash(info->site_ip)].hit;
		memcpy(blob + 15, &cnt, 8);
	} else if (unlikely(dbt::config::qcg_ic_edge_count)) {
		// B-DIST probe: the IC hit counter becomes a per-(site,target) edge-weight slot.
		// Exact weight for the resident edge; exec-count attribution on IC hits is
		// KNOWINGLY diverted (probe-only flag, never a pipeline mode).
		edge_slot_arena.push_back(0);
		auto *slot = &edge_slot_arena.back();
		ic_edge_counts.push_back({info->site_ip, tb->ip, slot});
		u64 cnt = (u64)slot;
		memcpy(blob + 15, &cnt, 8);
	} else if (!dbt::config::use_aot && !dbt::config::not_freq) {
		u64 cnt = (u64)((u8 *)tb + offsetof(TBlock, flags) + 8); // &tb->flags.exec_count
		memcpy(blob + 15, &cnt, 8);
	}
	i32 rel32 = (i32)rel;
	memcpy(blob + 27, &rel32, 4);
	u32 gip = tb->ip;
	memcpy(blob + 2, &gip, 4); // activate last
	ICMarkPatched(gip, blob);
	dbt::config::qcg_ic_patched++;
}

void tcache::ICUnpatchPage(u32 pvaddr)
{
	for (auto it = ic_target_map.lower_bound(pvaddr);
	     it != ic_target_map.end() && it->first < pvaddr + mmu::PAGE_SIZE;) {
		*(u32 *)(it->second + 2) = 0xFFFFFFFFu;
		it = ic_target_map.erase(it);
	}
}

void tcache::Init()
{
	brind_dirty.reserve(1u << 20); // F2 fix: no realloc ever => no UAF window in the SIGALRM flush

	// The 3 L1 caches are globals (BSS, already zero == the fill value), and Init() is boot-only, so the
	// fill below only re-commits ~160MB of pages for nothing. With --fast-boot, rely on BSS zero and let
	// the caches commit lazily on first touch — cuts a big chunk of rvdbt's fixed startup. Equivalent state.
	if (!config::fast_boot) {
		l1_cache.fill(nullptr);
		l1_brind_cache.fill({0, nullptr});
		cache_tb_exec_count.fill({0, nullptr});
	}
	tcache_map.clear();
	ClearEscLinks(); // T5c-0: the escape ring names code_pool addresses; a (re)init makes them dead
	tb_pool.Init(TB_POOL_SIZE, PROT_READ | PROT_WRITE);
	code_pool.Init(CODE_POOL_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
		config::qcg_code_huge_pages);
}

void tcache::Destroy()
{
	log_tcache("Destroy tcache, code_pool size: %zu", code_pool.GetUsedSize());

	l1_cache.fill(nullptr);
	l1_brind_cache.fill({0, nullptr});
	cache_tb_exec_count.fill({0, nullptr});
	tcache_map.clear();
	ClearEscLinks(); // T5c-0: same discipline -- the pool is about to be unmapped
	tb_pool.Destroy();
	code_pool.Destroy();
}

void tcache::Invalidate()
{
	l1_cache.fill(nullptr);
	l1_brind_cache.fill({0, nullptr});
	cache_tb_exec_count.fill({0, nullptr});
	tcache_map.clear();
	tb_pool.Reset();
	code_pool.Reset();
	link_map.clear();
	ClearEscLinks(); // T5c-0: the escape ring holds raw BranchSlot* into the pool ICReset is about
			 // to declare dead. Exactly the same reason, one line later.
	ICReset(); // A-line IC: code pool is gone; all blob pointers are dead
	edge_slots.clear(); // A-line EDGE: stock-equivalent count loss (uncommitted deltas die here)
	shadow_slots.clear();
	edge_slot_arena.clear();
	sat_sites.clear(); // A-line RETIRE (counts die with the pool, stock-equivalent)
	sat_carry.clear();
}

void tcache::DumpTBMap(char const *path)
{
	// Round-26 attribution instrument: guest_ip -> host code range for every QCG TB, so a perf
	// host-IP profile can be attributed back to guest regions. Analysis-only output.
	FILE *f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "guest_ip host_start host_size exec_count\n");
	for (auto const &[ip, tb] : tcache_map) {
		if (tb->tcode.size == 0)
			continue; // AOT-announced, no QCG code
		fprintf(f, "%08x %p %zu %lu\n", ip, tb->tcode.ptr, tb->tcode.size,
			(unsigned long)tb->flags.exec_count);
	}
	fclose(f);
}

void tcache::DumpTBCode(char const *path)
{
	FILE *f = fopen(path, "w");
	if (!f)
		return;
	for (auto const &[ip, tb] : tcache_map) {
		if (tb->tcode.size == 0)
			continue; // AOT-announced, no QCG code
		fprintf(f, "%08x %zu ", ip, tb->tcode.size);
		auto const *bytes = reinterpret_cast<u8 const *>(tb->tcode.ptr);
		for (size_t i = 0; i < tb->tcode.size; i++)
			fprintf(f, "%02x", bytes[i]);
		fprintf(f, "\n");
	}
	fclose(f);
}

void tcache::TierCensus(unsigned long out[4])
{
	out[0] = out[1] = out[2] = out[3] = 0;
	for (auto const &[ip, tb] : tcache_map) {
		bool aot = tb->tcode.size == 0;
		out[aot ? 1 : 0]++;
		out[aot ? 3 : 2] += tb->flags.exec_count;
	}
}

// T4 (2026-08-30): the QCG arm's generated-code size in bytes. An AOT-served TB is announce-created
// with tcode.size == 0 -- its code lives in the artifact, not in the code pool -- so summing
// tcode.size over the rest is exactly the host machine-code QCG generated in this process, and it
// deliberately excludes the artifact's bytes, which T4 reports in their own separate columns.
void tcache::CodeBytes(unsigned long out[3])
{
	out[0] = out[1] = out[2] = 0;
	for (auto const &[ip, tb] : tcache_map) {
		if (tb->tcode.size == 0) {
			out[2]++;
			continue;
		}
		out[0] += tb->tcode.size;
		out[1]++;
	}
}

// P1 (2026-07-23): exiled-hot census. A TB with tcode.size != 0 was JIT-translated THIS run,
// i.e. the loaded artifact does not serve its ip; with the P1 DC-1 undo its exec_count is real
// in-run frequency. Crossing the pipeline's own admission threshold = "the offline build would
// have admitted this had it seen this input" -- the exile predicate made quantitative.
unsigned long tcache::CountExiledHot(u64 threshold)
{
	unsigned long n = 0;
	for (auto const &[ip, tb] : tcache_map) {
		if (tb->tcode.size != 0 && tb->flags.exec_count >= threshold)
			n++;
	}
	return n;
}

u32 tcache::RelinkTo(u32 gip, void *code)
{
	u32 n = 0;
	auto [lo, hi] = link_map.equal_range(gip);
	for (auto it = lo; it != hi; ++it, ++n)
		it->second->Link(code);
	return n;
}

// C5d: see the block comment on the declaration in tcache.h. The ORDER is Round-18's, unchanged --
// map, exec-count cache, indirect cache, direct slots -- with the inline-cache step appended. The
// order is not observable (the guest is paused for all of it) but it is kept so that the diff
// against the sequence BootOneArtifact used to spell is a pure extraction plus one new step.
tcache::PromoteCounts tcache::PromoteTarget(TBlock *tb)
{
	PromoteCounts n{};
	if (tb == nullptr || tb->tcode.ptr == nullptr) {
		return n; // nothing to promote to; every structure keeps what it had
	}
	// READ BEFORE THE MUTATION, AND FROM THE IP RATHER THAN FROM THE INCOMING BLOCK. `tb` is a
	// freshly allocated announce-shaped block, so its own `is_brind_target` is false by
	// construction and reading it here would report "never an indirect target" for every promotion
	// -- a field that is constant is not evidence. The question is about the GUEST IP: was anything
	// dispatching to it indirectly before this call. Two independent witnesses, OR'd, because
	// either can be true alone: the outgoing block's flag survives a cache eviction, and the cache
	// tag survives a block that was replaced without the flag being carried.
	{
		auto const *prev = LookupFull(tb->ip);
		n.brind_was_target = (prev != nullptr && prev->flags.is_brind_target) ||
				     l1_brind_cache[l1hash(tb->ip)].gip == tb->ip;
	}
	InsertOrReplace(tb);
	CacheBr(tb);
	CacheBrind(tb);
	n.relinked = RelinkTo(tb->ip, tb->tcode.ptr);
	// Counted BEFORE the unpatch, because the unpatch is what removes the entries being counted.
	n.ic_unpatched = (u32)ic_target_map.count(tb->ip);
	ICUnpatchTarget(tb->ip);
	return n;
}

void tcache::InvalidatePage(u32 pvaddr)
{
	assert(rounddown(pvaddr, mmu::PAGE_SIZE) == pvaddr);
	ClearEscLinks(); // same reason as RevokeTarget: the ring may name slots this call frees
	for (auto it = link_map.upper_bound(pvaddr); it->first < pvaddr + mmu::PAGE_SIZE;) {
		it->second->LinkLazyJIT();
		it = link_map.erase(it);
	}
	for (auto it = tcache_map.upper_bound(pvaddr); it->first < pvaddr + mmu::PAGE_SIZE;) {
		it = tcache_map.erase(it);
	}
	ICUnpatchPage(pvaddr); // A-line IC: dispatch must not jump to invalidated targets
	for (auto &e : l1_cache) {
		if (rounddown(e->ip, mmu::PAGE_SIZE) == pvaddr) {
			e = nullptr;
		}
	}
	for (auto &e : l1_brind_cache) {
		if (rounddown(e.gip, mmu::PAGE_SIZE) == pvaddr) {
			e = {0, 0};
		}
	}
	for (auto &e : cache_tb_exec_count) {
		if (rounddown(e.gip, mmu::PAGE_SIZE) == pvaddr) {
			e = {0, 0};
		}
	}
}

// T5c-0: return recently linked direct branch slots to the lazy-JIT stub so the next traversal lands
// in the Execute() loop. Called from the SIGALRM keeper: bounded array walk, one 12-byte store per
// live slot, no allocation and no map -- the same signal-safety class as FlushBrindCache().
unsigned tcache::UnlinkRecorded()
{
	unsigned n = 0;
	for (unsigned i = 0; i < ESC_LINK_SLOTS; ++i) {
		auto *s = esc_link_ring[i];
		if (s == nullptr)
			continue;
		s->LinkLazyJIT();
		esc_link_ring[i] = nullptr; // one escape per link; it re-links on its next traversal
		n++;
	}
	esc_link_head = 0;
	return n;
}

void tcache::RevokeTarget(u32 gip)
{
	ClearEscLinks(); // these slots may be freed below; a stale escape hint must never be patched
	auto [lo, hi] = link_map.equal_range(gip);
	for (auto it = lo; it != hi;) {
		it->second->LinkLazyJIT();
		it = link_map.erase(it);
	}
	tcache_map.erase(gip);
	ICUnpatchTarget(gip); // A-line IC: same unlink discipline as the branch slots above
	auto h = l1hash(gip);
	if (l1_cache[h] && l1_cache[h]->ip == gip)
		l1_cache[h] = nullptr;
	if (l1_brind_cache[h].gip == gip)
		l1_brind_cache[h] = {0, nullptr};
	if (cache_tb_exec_count[h].gip == gip)
		cache_tb_exec_count[h] = {0, nullptr};
}

void tcache::Insert(TBlock *tb)
{
	tcache_map.insert({tb->ip, tb});
	l1_cache[l1hash(tb->ip)] = tb;
}

// Round-17 BCT: replace semantics for MID-RUN AOT boot -- the map may already hold a QCG TBlock for this ip; later
// lookups must find the AOT version. Stale direct links keep executing the old QCG code (correct, just lower tier).
void tcache::InsertOrReplace(TBlock *tb)
{
	tcache_map[tb->ip] = tb;
	l1_cache[l1hash(tb->ip)] = tb;
}

TBlock *tcache::LookupUpperBound(u32 gip)
{
	auto it = tcache_map.upper_bound(gip);
	if (it == tcache_map.end()) {
		return nullptr;
	}
	return it->second;
}

TBlock *tcache::LookupFull(u32 gip)
{
	auto it = tcache_map.find(gip);
	if (likely(it != tcache_map.end())) {
		return it->second;
	}
	return nullptr;
}

TBlock *tcache::AllocateTBlock()
{
	auto *res = tb_pool.Allocate<TBlock>();
	if (res == nullptr) {
		Invalidate();
	}
	return new (res) TBlock{};
}

void *tcache::AllocateCode(size_t code_sz, u16 align)
{
	// layout control: per-allocation dead padding perturbs RELATIVE code offsets
	// (a uniform pool-start shift preserves them and cannot break BTB conflicts)
	if (config::code_pad)
		code_pool.Allocate(config::code_pad, 1);
	void *res = code_pool.Allocate(code_sz, align);
	if (res == nullptr) {
		Invalidate();
	}
	return res;
}

void tcache::CodePoolBounds(unsigned long long *lo, unsigned long long *hi)
{
	*lo = (unsigned long long)code_pool.BaseAddr();
	*hi = *lo + CODE_POOL_SIZE;
}

// C5c: WHAT A SLOT CURRENTLY JUMPS TO, decoded from its own bytes.
//
// `BranchSlot`'s patch union is its first member, so the slot address IS the first opcode byte.
// `Link` emits `jmp rel32` when the displacement fits and `mov rax, imm64; jmp rax` when it does
// not, and BOTH are decoded here: the question this census asks is about the DESTINATION, and
// which encoding `Link` happened to pick is not part of it. The two LAZY forms -- `mov rax, imm64;
// call rax` (LinkLazyJIT) and `call [r13+imm32]` (LinkLazyAOT/LLVMAOT) -- are reported as their own
// class rather than folded into "other": a slot that has never been traversed is a different fact
// from a slot linked to something this census cannot name, and conflating them would let an
// unlinked edge be read as evidence that the promotion missed a live predecessor.
//
// Returns: 1 = linked, `*target` written; 0 = lazy (never linked); -1 = undecodable.
static int RouteCensusSlotTarget(void const *slot, void const **target)
{
	auto const *p = (unsigned char const *)slot;
	if (p[0] == 0xe9) { // jmp rel32
		i32 rel;
		memcpy(&rel, p + 1, 4);
		*target = (void const *)(p + 5 + rel);
		return 1;
	}
	if (p[0] == 0x48 && p[1] == 0xb8 && p[10] == 0xff) {
		u64 imm;
		memcpy(&imm, p + 2, 8);
		if (p[11] == 0xe0) { // jmp rax
			*target = (void const *)(uptr)imm;
			return 1;
		}
		if (p[11] == 0xd0) // call rax -- LinkLazyJIT, not yet linked
			return 0;
	}
	if (p[0] == 0x41 && p[1] == 0xff && p[2] == 0x95) // call [r13+imm32] -- LinkLazyAOT
		return 0;
	return -1;
}

// C5c: see the block comment on the declaration in tcache.h. Reads only; every loop below is over
// an index this class owns, and the only two derived facts -- the code-pool range and the page
// bound -- are computed from constants.
void tcache::RouteCensus(u32 gip, void const *tag_qcg, void const *tag_aot, RouteCensusOut *out)
{
	if (!out)
		return;
	*out = RouteCensusOut{};
	out->gip = gip;

	unsigned long long pool_lo = 0, pool_hi = 0;
	CodePoolBounds(&pool_lo, &pool_hi);
	auto in_pool = [&](void const *p) {
		auto a = (unsigned long long)(uptr)p;
		return a >= pool_lo && a < pool_hi;
	};

	// 1. What the map says NOW. LookupFull, never Lookup: warming l1_cache would make this
	//    diagnostic change the thing it is measuring.
	auto *cur = LookupFull(gip);
	if (cur) {
		out->cur_present = 1;
		out->cur_ptr = cur->tcode.ptr;
		out->cur_is_aot = cur->tcode.size == 0;
	}
	out->l1_tb_is_cur = cur && l1_cache[l1hash(gip)] == cur;

	// 2. link_map -- the already-self-patched direct-branch slots that name this target. This is
	//    the population `RelinkTo` would repoint, and the count C5B's premise rests on.
	auto [lo, hi] = link_map.equal_range(gip);
	for (auto it = lo; it != hi; ++it) {
		out->link_slots++;
		void const *tgt = nullptr;
		int const kind = RouteCensusSlotTarget((void const *)it->second, &tgt);
		if (kind == 0) {
			out->link_lazy++;
			continue;
		}
		if (kind < 0) {
			out->link_undecodable++;
			continue;
		}
		if (in_pool(tgt))
			out->link_in_pool++;
		if (tag_qcg && tgt == tag_qcg)
			out->link_to_qcg++;
		else if (tag_aot && tgt == tag_aot)
			out->link_to_aot++;
		else
			out->link_to_other++;
	}

	// 3. l1_brind_cache -- the indirect fast path's cached RAW host pointer, which no
	//    InsertOrReplace touches.
	auto const &b = l1_brind_cache[l1hash(gip)];
	if (b.gip == gip) {
		out->brind_tag_hit = 1;
		out->brind_is_qcg = tag_qcg && b.code == tag_qcg;
		out->brind_is_aot = tag_aot && b.code == tag_aot;
		out->brind_in_pool = in_pool(b.code);
	}

	// 4. cache_tb_exec_count -- the PROFILING cache the emitted Emit_Cache counter walks. Its
	//    `exec_count` is reported beside the classification because the T5g fingerprint is exactly
	//    "this counter is large while the artifact's own region_entry_hits is 1".
	auto const &e = cache_tb_exec_count[l1hash(gip)];
	if (e.gip == gip && e.tb) {
		out->exec_tag_hit = 1;
		out->exec_tb_is_aot = e.tb->tcode.size == 0;
		out->exec_tb_is_qcg = !out->exec_tb_is_aot;
		out->exec_tb_is_cur = e.tb == cur;
		out->exec_count = e.tb->flags.exec_count;
	}

	// 5. A-line inline-cache blobs patched to jump straight at this target.
	out->ic_blobs = (u32)ic_target_map.count(gip);

	// 6. The interior-reference upper bound. See the declaration for why both bounds are
	//    over-approximations and why neither is a measurement.
	for (auto it = tcache_map.begin(); it != tcache_map.end() && it->first < gip; ++it) {
		u32 const page_end = (u32)roundup(it->first, mmu::PAGE_SIZE);
		if (page_end <= gip)
			continue;
		out->interior_ub_page++;
		if (out->interior_n < ROUTE_CENSUS_MAX_INTERIOR)
			out->interior_ip[out->interior_n++] = it->first;
		u64 const insn_end = (u64)it->first + 4ull * (u64)it->second->flags.exec_instr_count;
		if (insn_end > (u64)gip)
			out->interior_ub_insn++;
	}
}

} // namespace dbt
