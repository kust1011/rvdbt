#include "dbt/aot/aot.h"
#include "dbt/aot/aot_module.h"
#include "dbt/guest/rv32_analyser.h"
#include "dbt/qmc/compile.h"
#include "dbt/tcache/objprof.h"
#include <vector>
#include <unordered_map>
#include <fstream>
#include <cmath>
#include <algorithm>
#include <cstdio>

namespace dbt
{
LOG_STREAM(aot)

// 2026-06-20 jserv-A, extended 2026-07-20 for the A0-A5 attribution matrix (isolating WHERE any benefit
// actually comes from -- floor removal vs data restructuring vs confidence weighting vs sample-size-aware
// statistics -- per the explicit requirement not to protect any one candidate). `aot_admit_mode` selects:
//   0 (A1, default) = jserv-A original: pooled per-target count, floor-to-threshold on any observed target.
//   1 (A2) = pooled per-target count, NO floor (raw pooled count is genuine additional evidence, must earn
//            admission on its own like any other exec_count).
//   2 (A3) = STRUCTURAL CONTROL: same per-source two-pass grouping code path as A4/A5, but the per-target
//            credit is still just the raw pooled sum (mathematically identical to A2) -- isolates "did
//            restructuring the computation by source change anything" from "did the WEIGHTING change
//            anything". A2 and A3 MUST produce byte-identical DRYREGION output; if they don't, that is a
//            bug in this function, not a research finding.
//   3 (A4) = SCA: per-target credit weighted by each contributing SOURCE's raw top1/total concentration.
//   4 (A5) = statistically principled: per-target credit weighted by each contributing source's target
//            concentration's WILSON SCORE INTERVAL LOWER BOUND at 95% confidence (treats "does source S
//            call its most common target" as a Bernoulli trial; n=1 at p=1.0 yields a low lower bound,
//            unlike A4's raw ratio which cannot distinguish "confident from 1 sample" from "confident from
//            1000 samples" -- this is the sample-size-uncertainty fix A4 is missing). z=1.96 is the
//            standard 95%-confidence constant (a statistical convention, not a workload-fit number) --
//            per `WilsonLowerBound`'s own comment for the derivation.
// A0 (pure Wendell, no indirect evidence at all) is simply "no --aot-indirect-edges given" -- IndirectInMass
// returns empty and BuildModuleGraph's `ind_in.find(ip)` never hits, unconditionally.
static double WilsonLowerBound(u64 successes, u64 total)
{
	// Wilson score interval lower bound, z=1.96 (95% two-sided confidence) -- Wilson, E.B. (1927), "Probable
	// Inference, the Law of Succession, and Statistical Inference", JASA 22(158):209-212. Standard textbook
	// formula for a binomial proportion confidence interval; z is a fixed statistical-convention constant
	// (matches the field's default 95% level), not fit to any workload in this repo.
	if (total == 0)
		return 0.0;
	double p = (double)successes / (double)total;
	double n = (double)total;
	double z = 1.96;
	double z2 = z * z;
	double center = (p + z2 / (2 * n)) / (1 + z2 / n);
	double margin = (z / (1 + z2 / n)) * std::sqrt(p * (1 - p) / n + z2 / (4 * n * n));
	double lb = center - margin;
	return lb < 0 ? 0.0 : lb;
}

static std::unordered_map<u32, u64> const &IndirectInMass()
{
	static std::unordered_map<u32, u64> m;
	static bool loaded = false;
	if (!loaded) {
		loaded = true;
		if (config::aot_indirect_edges && config::aot_indirect_edges[0]) {
			std::ifstream f(config::aot_indirect_edges);
			u32 src, dst;
			u64 cnt;
			int mode = config::aot_admit_mode;
			if (mode == 0) { // A1: original jserv-A, unmodified
				while (f >> std::hex >> src >> dst >> std::dec >> cnt)
					m[dst] += cnt;
				log_aot("indirect-edge profile (A1 pooled+floor): %zu targets", m.size());
			} else if (mode == 1) { // A2: pooled count, no floor (floor removal applied downstream)
				while (f >> std::hex >> src >> dst >> std::dec >> cnt)
					m[dst] += cnt;
				log_aot("indirect-edge profile (A2 pooled, no floor): %zu targets", m.size());
			} else if (mode == 5) { // A6 (2026-07-22 source-conditioned witness): per-SOURCE total-mass
				// floor. Wendell's admission is a per-TARGET decision (this target's own aggregate
				// exec_count >= threshold); A1-A5 above only ever re-weight or re-derive that SAME
				// per-target quantity. A wide-fan-out dispatch SITE whose total outgoing traffic is huge
				// but is split thinly across many targets can leave EVERY target individually
				// sub-threshold while the site itself is unambiguously hot -- a genuinely different
				// question Wendell cannot ask because it has no source->target edges at all. If a
				// source's SUMMED outgoing mass (across all its observed targets) crosses the threshold,
				// every target reachable from that source is floored to threshold (admitted), regardless
				// of its own individual share. This is source-conditioned information end to end: it is
				// impossible to compute from Wendell's per-target aggregate counts alone.
				std::unordered_map<u32, std::unordered_map<u32, u64>> src_dst;
				while (f >> std::hex >> src >> dst >> std::dec >> cnt)
					src_dst[src][dst] += cnt;
				u64 nsrc_hot = 0;
				for (auto const &[s, dsts] : src_dst) {
					u64 total = 0;
					for (auto const &[d, c] : dsts)
						total += c;
					if (total >= config::threshold) {
						++nsrc_hot;
						for (auto const &[d, c] : dsts)
							m[d] = std::max(m[d], config::threshold);
					}
				}
				log_aot("indirect-edge profile (A6 per-source floor): %zu targets, %zu sources, %zu hot sources",
					m.size(), src_dst.size(), (size_t)nsrc_hot);
			} else { // A3/A4/A5: per-source grouping, differing only in per-source weight formula
				std::unordered_map<u32, std::unordered_map<u32, u64>> src_dst;
				while (f >> std::hex >> src >> dst >> std::dec >> cnt)
					src_dst[src][dst] += cnt;
				for (auto const &[s, dsts] : src_dst) {
					u64 total = 0, top1 = 0;
					for (auto const &[d, c] : dsts) {
						total += c;
						if (c > top1)
							top1 = c;
					}
					double weight = 1.0; // A3: structural control, no weighting (must equal A2 numerically)
					if (mode == 3)        // A4: raw top1/total ratio (no sample-size awareness)
						weight = total > 0 ? (double)top1 / (double)total : 0.0;
					else if (mode == 4)   // A5: Wilson lower bound (sample-size-aware)
						weight = WilsonLowerBound(top1, total);
					for (auto const &[d, c] : dsts)
						m[d] += (u64)((double)c * weight);
				}
				log_aot("indirect-edge profile (mode=%d per-source): %zu targets, %zu sources", mode, m.size(),
					src_dst.size());
			}
		}
	}
	return m;
}

// CPB (2026-07-20): per-target confidence (MAX over contributing sources' own top1/total ratio -- "is
// there at least one confident source", the relevant question for whether specializing this target is
// worth full compile effort). Computed independently of aot_admit_mode's credit weighting (CPB gates
// COMPILE EFFORT on an admitted region, not the admission decision itself -- orthogonal consumer).
static std::unordered_map<u32, double> const &IndirectConfidence()
{
	static std::unordered_map<u32, double> m;
	static bool loaded = false;
	if (!loaded) {
		loaded = true;
		if (config::aot_indirect_edges && config::aot_indirect_edges[0]) {
			std::ifstream f(config::aot_indirect_edges);
			u32 src, dst;
			u64 cnt;
			std::unordered_map<u32, std::unordered_map<u32, u64>> src_dst;
			while (f >> std::hex >> src >> dst >> std::dec >> cnt)
				src_dst[src][dst] += cnt;
			for (auto const &[s, dsts] : src_dst) {
				u64 total = 0, top1 = 0;
				for (auto const &[d, c] : dsts) {
					total += c;
					if (c > top1)
						top1 = c;
				}
				double conf = total > 0 ? (double)top1 / (double)total : 0.0;
				for (auto const &[d, c] : dsts) {
					auto it = m.find(d);
					if (it == m.end() || conf > it->second)
						m[d] = conf;
				}
			}
		}
	}
	return m;
}

// FDRE (A-line architecture reset): the edge-evidence file, loaded once per elfaot process.
// Distinct from IndirectInMass/IndirectConfidence above (those only re-weight the exec_count
// NUMBER used for admission; FDRE changes the region-formation SEEDING RULE itself -- see
// A_LINE_ARCHITECTURE_SPEC.md and ModuleGraph::ApplyFDRE).
static std::vector<ModuleGraph::FDREEdge> const &FDREEdges()
{
	static std::vector<ModuleGraph::FDREEdge> edges =
	    dbt::config::aot_fdre_region ? ModuleGraph::LoadFDREEdges(dbt::config::aot_fdre_edges_path)
					 : std::vector<ModuleGraph::FDREEdge>{};
	return edges;
}

// One page's NODES and their profile flags, recorded into `mg`. Split out of BuildModuleGraph
// unchanged so that the whole-profile graph (BuildWholeProfileGraph) can record EVERY page's nodes
// before any edge is analysed, which is what lets a cross-page branch target resolve to a real node.
//
// IT DECLARES NO ENTRY OF ITS OWN. The only nodes it hands to `root` are the ones the profile itself
// marks -- `segment_entry` and `brind_target`. Making a page's first block an entry "so the page is
// reachable" would be an artificial root: it would make that block dominate its page's flow no matter
// what really reaches it, and every loop whose header lies earlier would stop being a natural loop.
// Nothing here does that, and loop_candidate_test section 8f and 8e require it not to.
//
// Returns the page's executed block ips, ascending -- the iplist the analysis pass walks.
std::vector<u32> RecordProfilePageNodes(ModuleGraph &mg, objprof::PageData const &page)
{
	auto const &ind_in = IndirectInMass();
	auto const &ind_conf = IndirectConfidence();
	u32 const page_vaddr = page.pageno << mmu::PAGE_BITS;

	std::vector<u32> iplist;
	for (u32 idx = 0; idx < page.executed.size(); ++idx) {
		if (!page.executed[idx]) {
			continue;
		}
		u32 ip = page_vaddr + objprof::PageData::idx2po(idx);
		iplist.push_back(ip);
		mg.RecordEntry(ip);
		bool brind_tgt = page.brind_target[idx];
		u64 ec = page.exec_count[idx];
		// Experimental indirect-flow admission. A corrected 2026-07-22 audit found that normal QCG profiling already
		// accounts for indirect-target executions on the L1 fast path; an exhaustive edge-profiling run does not. Thus
		// this evidence is useful for source->target structure, but must not be described as generally recovering missing
		// target counts. Keep it default-off and compare only against a profile collected without the edge recorder.
		if (auto it = ind_in.find(ip); it != ind_in.end()) {
			ec = it->second > ec ? it->second : ec;
			if (config::aot_admit_mode == 0) // A1 only: jserv-A's original unconditional floor-to-threshold
				if (ec < config::threshold)
					ec = config::threshold;
			// A2/A3/A4/A5 (modes 1-4): the credit is genuine additional evidence on the natural exec_count
			// scale, no artificial floor -- must earn admission on its own merit like any other region.
			brind_tgt = true;
		}
		if (brind_tgt) {
			mg.RecordBrindTarget(ip);
		}
		if (page.segment_entry[idx]) {
			mg.RecordSegmentEntry(ip);
		}
		if (ec > 0) {
			mg.RecordExec(ip, page.exec_instr_count[idx], ec);
		}
		if (auto cit = ind_conf.find(ip); cit != ind_conf.end()) {
			mg.GetNode(ip)->flags.indirect_confidence = cit->second;
		}
	}
	return iplist;
}

// One page's EDGES, from the guest's own instructions, with Wendell's exec-count propagation state
// held per page exactly as it always was. Split out of BuildModuleGraph unchanged: the propagation
// carries a running sum along ONE page's address-ordered blocks, so giving the whole profile a single
// running sum would change every frequency the graph carries. It does not.
void AnalyseProfilePageEdges(ModuleGraph &mg, objprof::PageData const &page, std::vector<u32> const &iplist)
{
	u32 const next_page_vaddr = (page.pageno << mmu::PAGE_BITS) + mmu::PAGE_SIZE;
	// we use a variable to aggregate the execution count of the same IP range
	// and a map to decrement the IP if the current IP passes the range.
	u64 exec_count = 0;
	std::map<u32, u64> exec_count_map;
	for (size_t idx = 0; idx < iplist.size(); ++idx) {
		u32 ip = iplist[idx];
		u32 ip_next = (idx == iplist.size() - 1) ? next_page_vaddr : iplist[idx + 1];

		rv32::RV32Analyser::Analyse(&mg, ip, ip_next, (uptr)mmu::base, exec_count, exec_count_map);
	}
}

ModuleGraph BuildModuleGraph(objprof::PageData const &page)
{
	auto const &ind_in = IndirectInMass();
	u32 const page_vaddr = page.pageno << mmu::PAGE_BITS;

	ModuleGraph mg(qir::CodeSegment(page_vaddr, mmu::PAGE_SIZE));
	auto iplist = RecordProfilePageNodes(mg, page);
	AnalyseProfilePageEdges(mg, page, iplist);

	// Experimental component-completion ablation: from each edge-admitted target, propagate through direct successors.
	// The 2026-07-22 corrected-profile audit found no measurable benefit on wasm3; retained only for reproducibility.
	if (!ind_in.empty() && config::aot_indirect_propagate) {
		std::vector<ModuleGraphNode *> wl;
		for (u32 ip : iplist) {
			auto *n = mg.GetNode(ip);
			if (n && n->flags.is_brind_target && n->flags.exec_count >= config::threshold && ind_in.count(ip))
				wl.push_back(n);
		}
		std::unordered_map<ModuleGraphNode *, bool> seen;
		for (auto *n : wl)
			seen[n] = true;
		while (!wl.empty()) {
			auto *n = wl.back();
			wl.pop_back();
			for (auto *s : n->succs) {
				if (seen.count(s))
					continue;
				seen[s] = true;
				if (s->flags.exec_count < config::threshold)
					s->flags.exec_count = config::threshold; // admit: part of the warm dispatch component
				wl.push_back(s);
			}
		}
	}

	mg.ApplyFDRE(FDREEdges());
	if (config::aot_link_region_merge)
		mg.ApplyLinkAwareRegionMerge();
	return mg;
}

// T5d1a: ONE module graph over EVERY profiled executable page.
//
// WHY IT EXISTS. Wendell compiles a page at a time, so `BuildModuleGraph` cuts the guest into 4 KiB
// module graphs and a branch leaving the page becomes a `cross_succ` with no target node. That is
// right for per-page region formation and wrong for a natural-loop selector: whether a loop is
// visible would depend on where the linker happened to put its blocks, so the same source compiled to
// a different layout would yield a different candidate set. A selector that behaves that way is not a
// standard loop analysis, and no workload can demonstrate otherwise -- a guest whose loops happen not
// to cross a page proves nothing about one whose loops do.
//
// HOW IT IS STITCHED, in two phases, and the order is the mechanism:
//
//   1. every page's NODES first (RecordProfilePageNodes for all pages), so that
//   2. when the analyser then walks each page's instructions (AnalyseProfilePageEdges),
//      `RecordGBr`'s `GetNode(target)` finds the node of a target on ANOTHER page and makes it a real
//      `succ`/`pred` pair instead of an unresolved `cross_succ`.
//
// Reversing those two phases -- analysing each page as it is recorded -- silently reproduces the
// per-page behaviour while looking correct, which is why the report prints `cross_page_edges` and the
// verifier requires it to be non-zero on a guest that has inter-page control flow.
//
// The stitched edges include FALL-THROUGH across a page boundary: the analyser's `TB_OVF` edge at the
// end of a page targets the next page's first address, and that now resolves too.
//
// ENTRIES ARE THE PROFILE'S OWN. `root` gains a successor only where the profile says
// `segment_entry` or `brind_target`, exactly as in the per-page builder. No page is given an
// artificial entry. This matters for correctness, not tidiness: an artificial root edge into a page
// makes that block dominate the page's flow regardless of what really reaches it, and a loop whose
// header sits above it stops dominating its latch -- the loop disappears. See loop_candidate_test 8e.
//
// REACHABILITY IS NOT A NEW RISK. The seed set is the union of the per-page seed sets and the edge
// set is a superset of the per-page edge sets restricted to the same nodes, and reachability is
// monotone in edges -- so any node the per-page graph could reach from root, this one can too.
// `ComputeDomTree`'s "unreachable regions in modulegraph" therefore cannot start firing here.
//
// WHAT IT DOES NOT DO. It applies neither `ApplyFDRE` nor `ApplyLinkAwareRegionMerge`: both exist to
// change region SEEDING, both are default-off, and `ApplyFDRE` adds edges -- so honouring them would
// make the loop set depend on a region-formation flag this selector-only checkpoint must not touch.
// It forms no region, marks no node and changes no compilation: `AOTCompileObject` and
// `LLVMAOTCompileELF` still call `BuildModuleGraph` per page, unchanged.
ModuleGraph BuildWholeProfileGraph()
{
	// The same page filter the LLVM producer applies, so the selector sees the pages the compiler
	// would compile and not a different set.
	auto is_elf_exec = [](objprof::PageData const &page) -> bool {
		if (!config::aot_skip_nonelf)
			return true;
		u32 pv = page.pageno << mmu::PAGE_BITS;
		for (auto const &r : config::g_elf_exec_ranges)
			if (pv >= r.first && pv < r.second)
				return true;
		return false;
	};

	std::vector<objprof::PageData const *> pages;
	for (auto const &page : objprof::GetProfile())
		if (is_elf_exec(page))
			pages.push_back(&page);
	std::sort(pages.begin(), pages.end(),
		  [](auto const *a, auto const *b) { return a->pageno < b->pageno; });

	// One segment spanning every profiled page. A gap between two profiled pages stays inside the
	// span: a branch into it simply finds no node and stays an unresolved cross edge, which is the
	// honest answer -- that address was never executed in this profile.
	u32 lo = 0, hi_end = 0;
	if (!pages.empty()) {
		lo = pages.front()->pageno << mmu::PAGE_BITS;
		hi_end = (pages.back()->pageno << mmu::PAGE_BITS) + mmu::PAGE_SIZE;
	}
	ModuleGraph mg(qir::CodeSegment(lo, hi_end - lo));

	std::vector<std::vector<u32>> iplists;
	iplists.reserve(pages.size());
	for (auto const *page : pages) // phase 1: every node, before any edge
		iplists.push_back(RecordProfilePageNodes(mg, *page));
	for (size_t i = 0; i < pages.size(); ++i) // phase 2: edges, now resolvable across pages
		AnalyseProfilePageEdges(mg, *pages[i], iplists[i]);

	return mg;
}

// T5d1a (--dump-loop-candidates, default off): the canonical hot-natural-loop candidate set of the
// profile this elfaot invocation was given, written out and nothing else.
//
// It is a DRY RUN over the WHOLE-PROFILE graph (BuildWholeProfileGraph): one stitched CFG for every
// profiled executable page, one dominator tree, one canonical candidate set. It prints and returns;
// the caller then exits before any region is formed or any code is generated, so "this dump did not
// change what was compiled" is structural rather than asserted -- region formation is not reached and
// still runs per page, from BuildModuleGraph, untouched.
//
// The output is canonical across the whole module: unresolved boundary edges, then back edges, then
// candidates, each ascending, with candidate bodies free to span pages. Two runs of the same elfaot
// on the same profile produce byte-identical files.
void DumpNaturalLoopCandidates()
{
	FILE *f = stdout;
	bool close_f = false;
	if (config::dump_loop_candidates_out && *config::dump_loop_candidates_out) {
		f = fopen(config::dump_loop_candidates_out, "w");
		if (!f)
			Panic("cannot open --dump-loop-candidates-out");
		close_f = true;
	}

	auto mg = BuildWholeProfileGraph();
	// ComputeDomTree numbers nodes with a u16 marker (its own "TODO: use u32" applies), and the
	// whole-profile graph is the first thing in the tree big enough to reach that. Fail loudly
	// rather than trip an assert that Release builds compile away.
	if (mg.ip_map.size() + 1 > std::numeric_limits<u16>::max())
		Panic("whole-profile graph exceeds ComputeDomTree's u16 node numbering");
	mg.ComputeDomTree(); // the candidate rule's one precondition, and the only pass run here
	mg.WriteLoopCandidateReport(f, nullptr);

	if (close_f)
		fclose(f);
	else
		fflush(f);
}

static void AOTCompilePage(CompilerRuntime *aotrt, objprof::PageData const &page)
{
	auto mg = BuildModuleGraph(page);
	auto regions = mg.ComputeRegions();

#if 1
	for (auto const &r : regions) {
		assert(r[0]->flags.region_entry);
		// if (r[0]->flags.exec_count <= 10000)
		// 	continue;
		// log_aot("Compile region: %08x, %08x", r[0]->ip, r[r.size() - 1]->ip_end);
		qir::CompilerJob::IpRangesSet ipranges;
		for (auto n : r) {
			ipranges.push_back({n->ip, n->ip_end});
		}

		qir::CompilerJob job(aotrt, (uptr)mmu::base, mg.segment, std::move(ipranges));
		unsigned long long spill_before = dbt::config::g_spill_emit; // 2026-06-22 exec-weighted dynamic spill count
		qir::CompilerDoJob(job);
		// loop-aware weight: region execution multiplier = dynamic-instr / static-instr (captures loop iterations,
		// unlike region-entry exec_count which undercounts loops). Per-block exec_count x size summed over the region.
		double dyn_instr = 0, static_instr = 0;
		unsigned long mx = 0; // Wendell's actual admission metric = MAX node exec_count over the region (llvmaot.cpp:112)
		for (auto n : r) {
			dyn_instr += (double)n->flags.exec_count * n->flags.exec_instr_count;
			static_instr += n->flags.exec_instr_count;
			if (n->flags.exec_count > mx)
				mx = (unsigned long)n->flags.exec_count;
		}
		double mult = static_instr > 0 ? dyn_instr / static_instr : (double)r[0]->flags.exec_count;
		unsigned long long region_spills = dbt::config::g_spill_emit - spill_before;
		dbt::config::g_dyn_spill += (unsigned long long)(region_spills * mult);
		if (dbt::config::dump_region_spill_exposure) // Cycle-14 SEGA Phase-0: per-region admission signal dump (PBA path)
			fprintf(stderr, "REGIONSPILL ip=%08x spills=%llu exec=%lu mx=%lu dyn_instr=%.0f instrs=%.0f exposure=%.0f\n",
				r[0]->ip, region_spills, (unsigned long)r[0]->flags.exec_count, mx, dyn_instr, static_instr,
				region_spills * mult);
	}
#else
	for (auto const &e : mg.ip_map) {
		auto const &n = *e.second;
		qir::CompilerJob job(aotrt, mg.segment, {{n.ip, n.ip_end}});
		qir::CompilerDoJob(job);
	}
#endif
}

void AOTCompileObject(CompilerRuntime *aotrt)
{
	for (auto const &page : objprof::GetProfile()) {
		AOTCompilePage(aotrt, page);
	}
}

} // namespace dbt
