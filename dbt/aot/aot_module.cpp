#include "dbt/aot/aot_module.h"
#include "dbt/mmu.h"
#include <algorithm>
#include <iomanip>
#include <list>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace dbt
{
LOG_STREAM(aot)

static FILE *g_modulegraph_dump = nullptr;

// Add this global structure to store cross-segment branch information
struct CrossSegmentBranch {
	u32 src_ip;
	u32 target_ip;
};
static std::vector<CrossSegmentBranch> g_cross_segment_branches;
static std::set<u32> g_ip_set;

void InitModuleGraphDump(char const *dir)
{
	auto fpath = std::string(dir) + "/modulegraph.gv";
	FILE *f = fopen(fpath.c_str(), "w");
	if (f == nullptr) {
		Panic();
	}
	g_modulegraph_dump = f;
	fprintf(f, "digraph rvdbt_modulegraph{\nnode[style=\"rounded,filled\",shape=rect]\n");
	atexit([]() {
		// Add all cross-segment branch edges
		// if (dbt::config::cross_segment_branch) {
		// 	for (const auto& branch : g_cross_segment_branches) {
		// 		if (g_ip_set.find(branch.target_ip) != g_ip_set.end()) {
		// 			fprintf(g_modulegraph_dump, 
		// 				"B%08x->B%08x[color=magenta,penwidth=2,style=dashed]\n", 
		// 				branch.src_ip, branch.target_ip);
		// 		}
		// 	}
		// }
		
		fprintf(g_modulegraph_dump, "}\n");
		fclose(g_modulegraph_dump);
	});
}

static void DumpModuleGraph(ModuleGraph *mg, std::vector<std::vector<ModuleGraphNode *>> const *regions)
{
	mg->Dump(g_modulegraph_dump, regions);
}

void ModuleGraph::Dump(FILE *f, std::vector<std::vector<ModuleGraphNode *>> const *regions)
{
	auto const add_node = [f](u32 ip, u64 exec_count, u32 exec_instr_count, char const *color) {
		auto end = ip + exec_instr_count * 4; // TODO: print this instead of exec_instr_count for easier checking
		fprintf(f, "B%08x[fillcolor=%s,label=\"%08x\\n%lu\\n%u\"]\n", ip, color, ip, exec_count, exec_instr_count);
	};

	auto const add_edge = [f](u32 src, u32 tgt, char const *opts) {
		fprintf(f, "B%08x->B%08x[%s]\n", src, tgt, opts);
	};

	auto dump_node = [&](ModuleGraphNode const &n) {
		auto flags = n.flags;
		g_ip_set.insert(n.ip);

		add_node(n.ip, n.flags.exec_count, n.flags.exec_instr_count,
			(dbt::config::threshold && flags.exec_count >= dbt::config::threshold) ? "red" 
					: flags.is_segment_entry  ? "green"
			       : flags.is_brind_target ? "orange"
			       : flags.region_entry    ? "purple"
						       : "cyan");
	};

	auto dump_edge = [&](ModuleGraphNode const &n, ModuleGraphNode const &t) {
		if (n.ip >= t.ip) {
			add_edge(t.ip, n.ip, "color=red,penwidth=2,dir=back");
		} else {
			add_edge(n.ip, t.ip, "");
		}
	};

	auto dump_link = [&](ModuleGraphNode const &n, ModuleGraphNode const &t) {
		add_edge(n.ip, t.ip, "color=darkgreen,style=dashed");
	};

	auto dump_crosssegment_branch = [&](ModuleGraphNode const &n, u32 target_ip) {
		// Create a virtual node for the external target with special styling
		fprintf(f, "B%08x_ext[fillcolor=yellow,style=dashed,label=\"%08x\\nExternal\"]\n", 
				target_ip, target_ip);
		
		// Add an edge from the source to the virtual target
		fprintf(f, "B%08x->B%08x_ext[color=magenta,penwidth=2,style=dashed]\n", 
				n.ip, target_ip);
	};

	// Dump all nodes and regular edges
	for (auto const &it : ip_map) {
		auto const &n = *it.second;
		dump_node(n);
		for (auto const &s : n.succs) {
			dump_edge(n, *s);
		}
		if (n.link) {
			dump_link(n, *n.link);
		}
		// Visualize cross-segment branches
		if (dbt::config::cross_segment_branch) {
			for (auto const &target_ip : n.cross_succs) {
				dump_crosssegment_branch(n, target_ip);
				// g_cross_segment_branches.push_back({n.ip, target_ip});
			}
		}
	}

	if (regions) {
		for (auto const &r : *regions) {
			fprintf(f, "subgraph cluster_R%08x{style=filled;color=lightgrey;\n", r[0]->ip);
			for (auto const &n : r) {
				fprintf(f, " B%08x", n->ip);
			}
			fprintf(f, "}\n");
		}
	}
}

struct RPOTraversal {
	using OrderVec = std::vector<ModuleGraphNode *>;

	using rpo_iterator = OrderVec::reverse_iterator;
	using const_rpo_iterator = OrderVec::const_reverse_iterator;

	RPOTraversal(ModuleGraph &graph)
	{
		Compute(graph);
	}

	rpo_iterator begin()
	{
		return po_nodes.rbegin();
	}
	const_rpo_iterator begin() const
	{
		return po_nodes.crbegin();
	}
	rpo_iterator end()
	{
		return po_nodes.rend();
	}
	const_rpo_iterator end() const
	{
		return po_nodes.crend();
	}

private:
	void Compute(ModuleGraph &graph);

	std::vector<ModuleGraphNode *> po_nodes;
};

void RPOTraversal::Compute(ModuleGraph &graph)
{
	auto n_nodes = graph.ip_map.size() + 1;
	po_nodes.reserve(n_nodes);

	using ChildIt = std::vector<ModuleGraphNode *>::iterator;
	std::vector<std::pair<ModuleGraphNode *, ChildIt>> stk;

	qir::Marker<ModuleGraphNode, bool> marker(&graph.markers, 2);

	auto push_node = [&](ModuleGraphNode *node) {
		if (!marker.Get(node)) {
			stk.push_back(std::make_pair(node, node->succs.begin()));
			marker.Set(node, true);
		}
	};

	push_node(graph.root.get());

	while (!stk.empty()) {
		auto &p = stk.back();
		if (p.second == p.first->succs.end()) {
			po_nodes.push_back(p.first);
			stk.pop_back();
		} else {
			push_node(*p.second++);
		}
	}
}

bool ModuleGraph::ComputeDomTree(bool fail_closed)
{
	using Node = ModuleGraphNode;
	auto const rpot = RPOTraversal(*this);

	auto n_nodes = ip_map.size() + 1;
	// The u16 node numbering is a hard limit of `rpon` below, not a preference. In elfaot an
	// oversized graph is a build-time surprise and the assert is the right answer; in a live guest
	// (T5d2a1) it must be a refusal, because the alternative is killing a run that is executing
	// correctly. Same computation, two dispositions.
	if (n_nodes > std::numeric_limits<u16>::max()) {
		if (fail_closed)
			return false;
		Panic("module graph exceeds ComputeDomTree's u16 node numbering");
	}
	qir::Marker<ModuleGraphNode, u16> rpon(&markers, n_nodes);
	{
		u16 rpo_no = 0;
		for (auto n : rpot) {
			rpon.Set(n, rpo_no++);
		}
		if (rpo_no != n_nodes) {
			log_analyse("%lu v.s. %u", rpo_no, n_nodes);
			if (fail_closed)
				return false;
			Panic("unreachable regions in modulegraph");
		}
	}

	auto *start = root.get();
	start->dominator = start;

	auto intersect = [&](Node *b1, Node *b2) {
		while (b1 != b2) {
			while (rpon.Get(b1) > rpon.Get(b2)) {
				b1 = b1->dominator;
			}
			while (rpon.Get(b2) > rpon.Get(b1)) {
				b2 = b2->dominator;
			}
		}
		return b1;
	};

	bool changed = true;
	while (changed) {
		changed = false;
		for (auto b : rpot) {
			if (b == start) {
				continue;
			}
			Node *new_idom = nullptr;
			for (auto p : b->preds) {
				if (p->dominator) {
					new_idom = new_idom ? intersect(p, new_idom) : p;
				}
			}
			assert(new_idom);
			if (b->dominator != new_idom) {
				b->dominator = new_idom;
				changed = true;
			}
		}
	}
	return true;
}

void ModuleGraph::ComputeDomFrontier()
{
	for (auto const &e : ip_map) {
		auto b = e.second.get();
		if (b->preds.size() > 1) {
			for (auto runner : b->preds) {
				while (runner != b->dominator) {
					runner->domfrontier.insert(b);
					runner = runner->dominator;
				}
			}
		}
	}
}

std::vector<ModuleGraph::FDREEdge> ModuleGraph::LoadFDREEdges(char const *path)
{
	std::vector<FDREEdge> out;
	if (!path || !*path)
		return out;
	FILE *f = fopen(path, "r");
	if (!f)
		return out;
	unsigned long s, d;
	unsigned long long w;
	while (fscanf(f, "%lx %lx %llu", &s, &d, &w) == 3)
		out.push_back({(u32)s, (u32)d, (u64)w});
	fclose(f);
	return out;
}

void ModuleGraph::ApplyFDRE(std::vector<FDREEdge> const &edges)
{
	if (edges.empty())
		return;
	// Group by target, restricted to (src,dst) pairs BOTH resolvable in THIS segment (a
	// cross-page edge is silently skipped -- safe abstain, matches RecordGBr's own
	// cross-segment handling elsewhere in this file).
	std::unordered_map<u32, std::vector<std::pair<u32, u64>>> by_target;
	for (auto const &e : edges) {
		if (!GetNode(e.src) || !GetNode(e.dst))
			continue;
		by_target[e.dst].push_back({e.src, e.weight});
	}
	struct Decision {
		ModuleGraphNode *target, *source;
		u64 weight; // best_w: this decision's dominant-edge weight, used to break source-key
			    // collisions below (a single jalr call site can be the sole/majority source
			    // for MULTIPLE targets -- call-site-side polymorphism -- but the lowering
			    // guard can only encode ONE candidate per source, so ties must be resolved
			    // by an explicit rule, not by map-insertion order).
	};
	std::vector<Decision> decisions;
	for (auto &[t, srcs] : by_target) {
		auto *tn = GetNode(t);
		if (!tn->flags.is_brind_target)
			continue; // only relevant for indirect-reached nodes
		u64 W = 0;
		for (auto const &[s, w] : srcs)
			W += w;
		u64 A = tn->flags.exec_count;
		// A-line 2026-07-24: an earlier version of this function gated on `A <
		// dbt::config::threshold`, reusing the SAME --threshold that governs ordinary AOT region
		// admission. RETRACTED per Codex audit: region-admission hotness (is this block worth
		// compiling into the AOT unit at all, in units of raw exec_count) and per-guard compile-
		// cost repayment (is the LLVM lowering work for THIS decision, ~3-4ms measured, repaid by
		// its runtime benefit, in units of TIME) are different decisions measured in different
		// units -- sharing one constant between them was a convenience, not a derivation, and is
		// exactly the "corpus-tuned magic number in disguise" this cycle's discipline forbids.
		// No replacement cost/benefit gate is installed here: deriving one honestly would need a
		// per-site runtime-benefit estimate (this project's own prior, already-closed audit --
		// CONSUMER_EXHAUSTION_AUDIT.md's "L1 inline-cache resolves indirect dispatch 99.9999% of
		// the time" finding -- means the guard's benefit is NOT simply proportional to dispatch
		// count the way the compile cost is, since the already-hot L1-cache-hit path is already
		// nearly as cheap as a direct branch; the guard's real benefit looks more like a codegen-
		// quality effect, LLVM optimizing across a now-direct call, which varies per call site and
		// is not cleanly estimable without per-site profiling this cycle does not yet have). All
		// certified decisions are admitted unfiltered; see SINGLE_RUN_ECONOMICS.md for the
		// resulting (honest, ungated) compile-time cost.
		// Conservation-residual gate: slack = number of distinct sources (see spec stage 1 --
		// each distinct source can miss at most its OWN first-ever dispatch, never more).
		u64 slack = srcs.size();
		long long resid = (long long)A - (long long)W;
		if (getenv("FDRE_DEBUG"))
			fprintf(stderr, "FDRE_CANDIDATE target=%08x A=%llu W=%llu slack=%llu resid=%lld nsrc=%zu\n",
				t, (unsigned long long)A, (unsigned long long)W, (unsigned long long)slack,
				resid, srcs.size());
		if (resid < 0 || (u64)resid > slack)
			continue; // evidence untrustworthy for this target: abstain
		u32 best_src = 0;
		u64 best_w = 0;
		for (auto const &[s, w] : srcs) {
			if (w > best_w) {
				best_w = w;
				best_src = s;
			}
		}
		if (best_w * 2 <= W)
			continue; // no strict-majority source: genuine polymorphism, abstain
		decisions.push_back({tn, GetNode(best_src), best_w});
	}
	if (decisions.empty())
		return;
	// RecordBrindTarget (called earlier, unconditionally, while building the initial graph)
	// already added root->AddSucc(target) for every is_brind_target node. That stale edge
	// must be REMOVED for a target we are about to suppress -- otherwise the target still has
	// TWO real predecessors (root AND the new dominant source), which makes
	// ComputeDomFrontier's multi-pred logic treat it as a genuine join point and re-mark it
	// region_entry via ITERATED dominance-frontier PROPAGATION regardless of the suppression
	// flag (found via direct instrumentation of ComputeRegionIDF's propagation loop -- the
	// flag check in the seeding loop was correct, but propagation from an unrelated root
	// through this leftover edge silently re-set it). Removing root's edge makes the dominant
	// source the target's ONLY real predecessor, exactly matching how a `jal` target looks.
	auto remove_succ = [](ModuleGraphNode *from, ModuleGraphNode *to) {
		auto &sv = from->succs;
		sv.erase(std::remove(sv.begin(), sv.end(), to), sv.end());
		auto &pv = to->preds;
		pv.erase(std::remove(pv.begin(), pv.end(), from), pv.end());
	};
	for (auto const &d : decisions) {
		d.target->flags.fdre_suppressed = true;
		remove_succ(root.get(), d.target);
		d.source->AddSucc(d.target);
	}
	// Whole-graph reachability-from-root check (same discipline as the P6/P7/P9 closure BFS):
	// a suppression is only safe if the target remains reachable from root through SOME path
	// (its own root edge, if not suppressed, or transitively via the new source->target
	// edges). Revert any suppression that would otherwise orphan its target -- restoring a
	// node's root status can only ADD reachability for others, so a single pass suffices.
	std::unordered_set<ModuleGraphNode *> reached{root.get()};
	std::vector<ModuleGraphNode *> bfsq{root.get()};
	auto expand = [&]() {
		while (!bfsq.empty()) {
			auto *n = bfsq.back();
			bfsq.pop_back();
			for (auto *s : n->succs)
				if (reached.insert(s).second)
					bfsq.push_back(s);
		}
	};
	for (auto const &e : ip_map) {
		auto *n = e.second.get();
		if ((n->flags.is_brind_target && !n->flags.fdre_suppressed) || n->flags.is_segment_entry) {
			if (reached.insert(n).second)
				bfsq.push_back(n);
		}
	}
	expand();
	// Source-key collision resolution (found via stage-5 measurement + FDRE_DEBUG on
	// expat.elf/libyaml.elf): a single jalr call site can legitimately be the majority/sole
	// source for MULTIPLE distinct targets (the call site itself is polymorphic even though
	// each individual target is source-exclusive). `decisions` groups by TARGET, so this shows
	// up as several entries sharing the same `source`. Stage 3's lowering can only encode ONE
	// guarded candidate per jalr, so ties must be broken by the dominant edge's WEIGHT (highest
	// hit-rate candidate), not by unordered_map insertion order -- confirmed by disassembly that
	// insertion-order resolution had silently picked a 17%-hit-rate candidate over an available
	// 83%-hit-rate one at expat.elf's hottest affected site (0x1ec50). Targets that lose this
	// tie-break still get the Stage-2 region merge (graph-correct, dual-region-safe); they just
	// don't get a Stage-3 guard of their own, identical to any other non-dominant minority source.
	std::unordered_map<u32, u64> best_weight_for_source;
	for (auto const &d : decisions) {
		auto it = best_weight_for_source.find(d.source->ip);
		if (it == best_weight_for_source.end() || d.weight > it->second)
			best_weight_for_source[d.source->ip] = d.weight;
	}
	unsigned n_applied = 0, n_reverted = 0;
	for (auto const &d : decisions) {
		if (!reached.count(d.target)) {
			d.target->flags.fdre_suppressed = false;
			remove_succ(d.source, d.target); // undo the tentative edge
			root->AddSucc(d.target);         // restore stock reachability exactly
			n_reverted++;
		} else {
			n_applied++;
			// Stage 3 (rv32_qir.cpp jalr translator) reads this to lower the guarded direct
			// branch; keyed by SOURCE block ip. Only the highest-weight decision for this
			// source wins the slot (see collision-resolution note above).
			if (dbt::config::aot_fdre_lower && d.weight == best_weight_for_source[d.source->ip])
				dbt::config::aot_fdre_dominant_target[d.source->ip] = d.target->ip;
		}
		if (getenv("FDRE_DEBUG"))
			fprintf(stderr, "FDRE_DECISION target=%08x source=%08x suppressed=%d region_entry=%d\n",
				d.target->ip, d.source->ip, d.target->flags.fdre_suppressed,
				d.target->flags.region_entry);
	}
	fprintf(stderr, "FDRE_REGION applied=%u reverted=%u candidates=%zu\n", n_applied, n_reverted,
		decisions.size());
}

// Design 8 (2026-07-24): link-aware region merge. See aot_module.h's flag comment for the
// rationale (a return continuation's ONLY possible indirect source is statically determinable --
// `target - 4` is either a recorded call site or it isn't -- no dynamic evidence needed). Reuses
// FDRE's exact graph-surgery + reachability-safety pattern, verified functional by
// experiment 8573b40a's own negative result (adding a source->target edge WITHOUT ALSO removing
// the stale root->target edge and skipping the region_entry seed is structurally inert -- this
// function does both, exactly like ApplyFDRE, just gated on a free static fact instead of an
// expensive dynamic one).
void ModuleGraph::ApplyLinkAwareRegionMerge()
{
	auto remove_succ = [](ModuleGraphNode *from, ModuleGraphNode *to) {
		auto &sv = from->succs;
		sv.erase(std::remove(sv.begin(), sv.end(), to), sv.end());
		auto &pv = to->preds;
		pv.erase(std::remove(pv.begin(), pv.end(), from), pv.end());
	};

	struct Candidate {
		ModuleGraphNode *source, *target;
	};
	std::vector<Candidate> candidates;
	for (auto const &e : ip_map) {
		auto *src = e.second.get();
		auto *tgt = src->link;
		if (!tgt || !tgt->flags.is_brind_target || tgt->flags.fdre_suppressed)
			continue; // not a call site, or its continuation was never actually dispatched to,
				  // or FDRE already claimed this target via a real dynamic decision
		// Cost-model gate (2026-07-24): silently absorbing a return-continuation as a plain
		// interior block (no multi-entry exposure) drops its _aot_tab entry, so any dynamic
		// `ret` still targeting it falls back to QCG -- rare/cheap for a COLD continuation,
		// but measured to dominate (and flip the net economics negative) for a HOT one on
		// call-dense real workloads (see DESIGN8_LINK_MERGE_KILLED.md). Reuses Wendell's OWN
		// existing admission threshold, not a new magic constant: a hot target only merges
		// here if a multi-entry exposure mechanism (wrapper OR alias) is also on to give it
		// back a real entry instead of losing it silently.
		if (tgt->flags.exec_count >= dbt::config::threshold && !dbt::config::aot_link_multientry_merge &&
		    !dbt::config::aot_link_alias_merge)
			continue;
		// Structural entry-contract invariant for the alias variant only (2026-07-24, real-workload
		// obstruction found on expat after the witness-level fix): the alias mechanism is only
		// correct if the ONLY way to dynamically reach `tgt` at its own address is a genuinely
		// computed indirect jump (a `ret`, always routed through Expand_gbrind, which now always
		// refreshes state->ip before entering a multi-entry function). If `tgt` ALSO has a real,
		// ordinary predecessor edge (a ModuleGraph pred other than `root`, i.e. a ordinary direct/
		// conditional branch from elsewhere in the SAME translation), that OTHER caller's `jal` is
		// compiled via a self-patching lazy-link mechanism (rv32_qir.cpp `jal` -> qemit.cpp
		// Emit_gbr / jitabi.cpp TryLinkBranch on the QCG tier, or CreateQCGGbr's own ASM-PATCH
		// fallback on the AOT tier) whose HIT path permanently patches a direct jump WITHOUT ever
		// setting state->ip (confirmed by reading TryLinkBranch: only the miss path does) --
		// structurally incompatible with a multi-entry target for exactly the same reason as the
		// witness-level CreateQCGGbr bug, but via a different call site than the one this candidate
		// was derived from. The wrapper variant does not have this exposure (its body is a real,
		// independent function that always runs its own state->ip store, regardless of how it is
		// entered), so this exclusion is alias-specific.
		if (dbt::config::aot_link_alias_merge && tgt->preds.size() > 1)
			continue;
		// Cross-page extension of the same invariant (2026-07-24): the same-page preds check above
		// is NOT sufficient by itself -- ModuleGraph is built fresh PER PAGE, so a direct jal/branch
		// from a DIFFERENT page targeting `tgt`'s address is invisible to `tgt->preds`. Confirmed via
		// a real, isolated control test on expat.elf: the IDENTICAL merge candidate set (hotness gate
		// bypassed) produces byte-identical CORRECT output under --aot-link-multientry-merge (the
		// wrapper variant, which does not depend on this invariant at all) but a real guest memory
		// fault under --aot-link-alias-merge with only the same-page check above -- proving the
		// switch/entry-selection mechanism itself is sound and the gap is specifically an
		// alias-exposure safety hole, not a data-dependency bug in the shared region. See
		// dbt::config::g_direct_branch_targets (populated once, globally, before this runs).
		if (dbt::config::aot_link_alias_merge && dbt::config::g_direct_branch_targets.count(tgt->ip))
			continue;
		candidates.push_back({src, tgt});
	}
	if (candidates.empty())
		return;

	for (auto const &c : candidates) {
		c.target->flags.link_region_suppressed = true;
		remove_succ(root.get(), c.target);
		c.source->AddSucc(c.target);
	}

	// Same whole-graph reachability-from-root BFS discipline as ApplyFDRE: a suppression is
	// only safe if the target remains reachable from root through SOME path. Seeds from every
	// node that is STILL an unconditional root under either suppression scheme, so this is
	// correct whether or not ApplyFDRE also ran on this graph.
	std::unordered_set<ModuleGraphNode *> reached{root.get()};
	std::vector<ModuleGraphNode *> bfsq{root.get()};
	auto expand = [&]() {
		while (!bfsq.empty()) {
			auto *n = bfsq.back();
			bfsq.pop_back();
			for (auto *s : n->succs)
				if (reached.insert(s).second)
					bfsq.push_back(s);
		}
	};
	for (auto const &e : ip_map) {
		auto *n = e.second.get();
		bool still_root = n->flags.is_segment_entry ||
				  (n->flags.is_brind_target && !n->flags.fdre_suppressed &&
				   !n->flags.link_region_suppressed);
		if (still_root && reached.insert(n).second)
			bfsq.push_back(n);
	}
	expand();

	unsigned n_applied = 0, n_reverted = 0;
	for (auto const &c : candidates) {
		if (!reached.count(c.target)) {
			c.target->flags.link_region_suppressed = false;
			remove_succ(c.source, c.target);
			root->AddSucc(c.target);
			n_reverted++;
		} else {
			n_applied++;
		}
		if (getenv("LINKMERGE_DEBUG"))
			fprintf(stderr, "LINKMERGE_DECISION target=%08x source=%08x suppressed=%d\n",
				c.target->ip, c.source->ip, c.target->flags.link_region_suppressed);
	}
	fprintf(stderr, "LINKMERGE_REGION applied=%u reverted=%u candidates=%zu\n", n_applied, n_reverted,
		candidates.size());
}

void ModuleGraph::ComputeRegionIDF()
{
	std::vector<ModuleGraphNode *> wlist;

	for (auto const &e : ip_map) {
		auto n = e.second.get();
		bool seed = n->flags.is_segment_entry;
		if (n->flags.is_brind_target && !dbt::config::aot_brind_seed_oracle_suppress) {
			// P2 frequency gate: cold (stale) brind seeds do not force a region entry.
			seed = seed || !dbt::config::aot_freq_gated_seed ||
			       n->flags.exec_count >= dbt::config::threshold;
			// FDRE: a target with a conservation-verified dominant source (ApplyFDRE, called
			// before ComputeRegions()) is reached via a real graph edge instead -- do not
			// ALSO force it as an unconditional root (that would defeat the merge: seeing it
			// via succs from its dominant source's DFS is what sweeps it into that region;
			// ComputeRegionDomSets stops its DFS at any OTHER region_entry node).
			seed = seed && !n->flags.fdre_suppressed;
			// Design 8: a return-continuation target reached via the real call-site->target
			// edge instead (ApplyLinkAwareRegionMerge, called before ComputeRegions()) is swept
			// into its caller's region by the normal DFS -- same discipline as the FDRE line
			// above, just gated on a free static fact instead of a conservation-verified one.
			seed = seed && !n->flags.link_region_suppressed;
			if (getenv("FDRE_DEBUG"))
				fprintf(stderr, "FDRE_IDF ip=%08x is_brind=%d suppressed=%d seed=%d\n", n->ip,
					n->flags.is_brind_target, n->flags.fdre_suppressed, seed);
		}
		if (seed) {
			n->flags.region_entry = true;
			wlist.push_back(n);
		}
	}

	while (!wlist.empty()) {
		auto x = wlist.back();
		wlist.pop_back();

		for (auto y : x->domfrontier) {
			if (!y->flags.region_entry) {
				// A-line IDF-fuse: this node is becoming region_entry ONLY because it is in
				// some seed's dominance frontier (a shared convergence point), not because it
				// is itself a real entry requirement -- see the `idf_fused` flag comment.
				y->flags.idf_fused = true;
				wlist.push_back(y);
			}
		}

		if (getenv("FDRE_DEBUG") && !x->flags.region_entry)
			fprintf(stderr, "FDRE_IDF_PROPAGATE ip=%08x marked region_entry via domfrontier propagation\n",
				x->ip);
		x->flags.region_entry = true;
	}

	// A-line decision-regret-reset (2026-07-27): admission-reason diagnostic, default-off, zero
	// new state -- every field read here (is_segment_entry/is_brind_target/idf_fused/exec_count)
	// already exists; this ONLY prints a composite reason breakdown per region_entry node so a
	// "brind_target-EXCLUSIVELY-forced" region (a candidate for further cost/benefit measurement --
	// NOT itself proof of regret; whether it is regret-bearing depends on actually measuring
	// compile-cost saved vs execution-cost lost, done separately, never inferred from this flag
	// breakdown alone) can be distinguished from one that would have been admitted anyway (also a
	// segment_entry) or that exists only as an IDF-propagation artifact (idf_fused, not a real
	// dispatch target at all). No behavior change; diagnostic print only.
	if (getenv("ADMISSION_REASON_LOG")) {
		for (auto const &e : ip_map) {
			auto n = e.second.get();
			if (!n->flags.region_entry)
				continue;
			bool exclusively_brind =
				n->flags.is_brind_target && !n->flags.is_segment_entry && !n->flags.idf_fused;
			fprintf(stderr,
				"ADMISSION_REASON ip=%08x segment_entry=%d brind_target=%d idf_fused=%d "
				"exec_count=%llu hot=%d exclusively_brind_forced=%d exec_instr_count=%u\n",
				n->ip, n->flags.is_segment_entry, n->flags.is_brind_target, n->flags.idf_fused,
				(unsigned long long)n->flags.exec_count,
				(int)(n->flags.exec_count >= dbt::config::threshold), (int)exclusively_brind,
				n->flags.exec_instr_count);
		}
	}
}

// Cycle-13: does `a` dominate `b`? (walk b's immediate-dominator chain; stops at root self-loop or unreachable null)
static bool NodeDominates(ModuleGraphNode *a, ModuleGraphNode *b)
{
	for (auto d = b; d != nullptr;) {
		if (d == a)
			return true;
		if (d->dominator == d || d->dominator == nullptr)
			break;
		d = d->dominator;
	}
	return false;
}

// Cycle-13: enumerate natural loops by back-edges. A back-edge is u->s where s dominates u; the loop body is {s} plus all
// nodes that reach u without passing through s. Returns {latch u, header s, body-set} per back-edge (nested/shared headers
// allowed).
//
// THE RULE IS DOMINANCE, NOT ADDRESS ORDER. `NodeDominates(s, u)` walks u's immediate-dominator chain
// on the tree ComputeDomTree built from the real CFG. A retreating edge (one whose target address is
// below its source's) that is NOT a natural back-edge -- the entry edge of an irreducible cycle, the
// textbook example being two blocks in a cycle that are each independently reachable from the entry --
// fails this test and produces no loop here, which is the whole reason the tree is consulted instead
// of comparing the two ips.
//
// The root node cannot appear in a body, and that is a property of the definition rather than of any
// guard: root is a predecessor only of segment entries and indirect-branch targets, so if a body node
// other than the header had root as a predecessor there would be a path root->that node->...->latch
// avoiding the header, and the header would not dominate the latch. The Panic below states that as a
// checkable fact instead of an assumption.
std::vector<ModuleGraph::NaturalLoopBackEdge> ModuleGraph::EnumerateNaturalLoopBackEdges()
{
	std::vector<NaturalLoopBackEdge> loops;
	for (auto const &e : ip_map) {
		auto u = e.second.get();
		for (auto s : u->succs) {
			if (!NodeDominates(s, u)) // back-edge iff successor s dominates u
				continue;
			std::set<ModuleGraphNode *> body;
			body.insert(s);
			std::vector<ModuleGraphNode *> stk;
			if (u != s) {
				body.insert(u);
				stk.push_back(u);
			}
			while (!stk.empty()) {
				auto n = stk.back();
				stk.pop_back();
				for (auto p : n->preds) {
					if (body.insert(p).second)
						stk.push_back(p);
				}
			}
			if (body.count(root.get()))
				Panic("natural-loop body reached the module-graph root");
			loops.push_back({u, s, std::move(body)});
		}
	}
	return loops;
}

// Cycle-13's original shape, unchanged for its existing callers: the same back-edges in the same
// order, with the latch dropped.
std::vector<std::pair<ModuleGraphNode *, std::set<ModuleGraphNode *>>> ModuleGraph::DetectNaturalLoops()
{
	std::vector<std::pair<ModuleGraphNode *, std::set<ModuleGraphNode *>>> loops;
	for (auto &be : EnumerateNaturalLoopBackEdges())
		loops.emplace_back(be.header, std::move(be.body));
	return loops;
}

// T5d1a: the canonical hot-natural-loop candidate set.
//
// WHAT A CANDIDATE IS. One per natural-loop HEADER, because a header is the only node a back-edge can
// carry control to and therefore the only place a loop-rooted region can be rooted. A header reached
// by several back-edges -- one `continue` per branch of an `if` in the source, a compiler that
// duplicated the latch -- is ONE loop, not several, so its latches are merged into one sorted list and
// its body is the UNION of the per-back-edge bodies. That union is exactly the standard definition of
// the natural loop of a set of back-edges with a common header.
//
// NESTED LOOPS STAY DISTINCT. An inner and an outer loop have different headers, so they are different
// candidates, and the inner body is a subset of the outer's. Merging them would be a policy decision
// about which one to compile; this function does not make it. Neither does it order the candidates by
// anything but header ip -- there is no ranking here, only a set.
//
// THE DYNAMIC EVIDENCE IS THIS PROFILE'S OWN, AND THE BAR IS THE COMPILER'S OWN. `hot` is
// `header->flags.exec_count >= dbt::config::threshold`: the header block's EXECUTION FREQUENCY in the
// run being compiled, against the SAME `--threshold` this elfaot invocation uses as its primary
// admission test in llvmaot.cpp's RegionAdmitted. No new constant, no ratio, no fraction of anything,
// no per-workload number, and nothing about the guest's identity. Note the bar is applied to the
// header BLOCK's own frequency, not to RegionAdmitted's max-over-a-region: a header that clears it is
// a block the compiler's own bar already calls hot, and the two tests share their one constant rather
// than one deriving a new number from the other.
//
// WHAT THE HEADER'S FREQUENCY IS, EXACTLY. It is the loop's RUNTIME ACTIVITY EVIDENCE: a header that
// clears the bar belongs to a loop this run spent real time in, and one that does not, does not. It
// is deliberately NOT described as the loop's trip count, because it is not one:
//
//   * it counts every ENTRY into the loop from outside as well as every continuation, so a loop
//     entered many times and iterated twice each time reads the same as one entered once and iterated
//     many times -- and an inner loop's header is re-entered once per iteration of its enclosing loop;
//   * `--propagate-exec-count` (dbt::config::propagate_exec_count, DEFAULT ON) ADDS a carried sum to
//     `flags.exec_count` along the address-ordered analysis of a page's blocks (rv32_analyser.cpp),
//     so the value the graph carries can exceed what the block's own counter recorded;
//   * it says nothing at all about how expensive one pass through the body is.
//
// A hotness comparison is what it supports and all that is asked of it here. The interior blocks are
// no better: their frequencies depend on which path through the body ran, so they answer a different
// question again. The header is chosen because it is the loop's single entry, not because its number
// is exact.
//
// SELECTS ONLY. No node is marked, `region_entry` and `loop_entry_exposed` are neither read nor
// written, no region is formed and no counter moves. Calling it twice returns the same thing.
std::vector<ModuleGraph::LoopCandidate> ModuleGraph::ComputeNaturalLoopCandidates()
{
	// ComputeDomTree sets root->dominator = root; before it runs every `dominator` is null and
	// NodeDominates answers "no" for every pair, which would return an empty candidate set that is
	// indistinguishable from a genuine one.
	if (!root->dominator)
		Panic("ComputeNaturalLoopCandidates without a dominator tree");

	// Keyed and valued by ip so that the output depends on the guest's addresses and on nothing
	// else -- in particular not on the heap addresses of the nodes, which is what a std::set of
	// ModuleGraphNode* would order by.
	struct Merged {
		u64 header_exec_freq{};
		std::set<u32> latches;
		std::set<u32> body;
	};
	std::map<u32, Merged> by_header;

	for (auto &be : EnumerateNaturalLoopBackEdges()) {
		auto &m = by_header[be.header->ip];
		m.header_exec_freq = be.header->flags.exec_count;
		m.latches.insert(be.latch->ip);
		for (auto *n : be.body)
			m.body.insert(n->ip);
	}

	std::vector<LoopCandidate> out;
	out.reserve(by_header.size());
	for (auto const &[header_ip, m] : by_header) {
		LoopCandidate c;
		c.header_ip = header_ip;
		c.header_exec_freq = m.header_exec_freq;
		c.latch_ips.assign(m.latches.begin(), m.latches.end());
		c.body_ips.assign(m.body.begin(), m.body.end());
		c.hot = c.header_exec_freq >= dbt::config::threshold;
		out.push_back(std::move(c));
	}
	return out;
}

std::vector<ModuleGraph::LoopCandidate> ModuleGraph::SelectHotNaturalLoopCandidates()
{
	std::vector<LoopCandidate> hot;
	for (auto &c : ComputeNaturalLoopCandidates())
		if (c.hot)
			hot.push_back(std::move(c));
	return hot;
}

// T5d1b: the ip ranges a loop-rooted region is compiled from.
//
// HEADER FIRST is not cosmetic. RV32Translator::Translate takes `(*ipranges)[0].first` as the
// region's entry ip and creates the blocks in ipranges order, and QIRToLLVM::Run takes the block
// with id 0 as the function's entry -- so putting the header first is what makes the emitted
// function's external entry the loop header itself, with no wrapper and no entry switch. The rest
// follow ascending so the same candidate always produces the same region.
//
// The ranges are the candidate's canonical body and nothing else. They may span guest pages; that is
// the point of T5d1a's whole-profile graph and nothing here re-imposes a page boundary.
std::vector<std::pair<u32, u32>> ModuleGraph::LoopCandidateIpRanges(LoopCandidate const &c)
{
	std::vector<std::pair<u32, u32>> out;
	out.reserve(c.body_ips.size());
	auto push = [&](u32 ip) {
		auto *n = GetNode(ip);
		if (!n)
			Panic("loop candidate body names an ip with no node");
		// ip_end is one past the block's last instruction, written by RV32Analyser. A zero or
		// backwards extent would make TranslateIPRange's boundary test meaningless, so it is
		// refused rather than compiled into something arbitrary.
		if (n->ip_end <= n->ip)
			Panic("loop candidate body block has no instruction extent");
		out.emplace_back(n->ip, n->ip_end);
	};
	push(c.header_ip);
	for (u32 ip : c.body_ips)
		if (ip != c.header_ip)
			push(ip);
	return out;
}

// T5d1b: every control-flow edge that leaves the candidate's body.
//
// A successor whose ip is the source block's own `ip_end` is the block's FALL-THROUGH; anything else
// reached from a block that ends in a branch is a TAKEN edge; a `cross_succ` is UNRESOLVED -- the
// profile never executed the target, so this graph has no node for it. All three must survive into
// the emitted function as real exits: the first two as `gbr`s the translator emits because the
// target is not in `ip2bb`, the third through the same generic path, because the translator looks up
// the target address and finds nothing either way. Nothing here invents a target.
//
// A branch whose target happens to BE the next address is reported as a fall-through. That is not a
// misclassification: for control-flow purposes the two are the same edge.
std::vector<ModuleGraph::LoopExit> ModuleGraph::LoopCandidateExits(LoopCandidate const &c)
{
	std::set<u32> body(c.body_ips.begin(), c.body_ips.end());
	std::vector<LoopExit> out;
	for (u32 ip : c.body_ips) {
		auto *n = GetNode(ip);
		if (!n)
			continue;
		for (auto *s : n->succs)
			if (!body.count(s->ip))
				out.push_back({n->ip, s->ip,
					       s->ip == n->ip_end ? LoopExit::Kind::FALLTHROUGH
								  : LoopExit::Kind::TAKEN});
		for (u32 t : n->cross_succs)
			out.push_back({n->ip, t, LoopExit::Kind::UNRESOLVED});
	}
	std::sort(out.begin(), out.end(), [](LoopExit const &a, LoopExit const &b) {
		return a.src_ip != b.src_ip ? a.src_ip < b.src_ip : a.tgt_ip < b.tgt_ip;
	});
	return out;
}

// T5d1a: the direct edges this graph could not resolve to a node of its own.
//
// A cross edge is recorded by RecordGBr whenever the branch target has no node -- either because the
// address lies outside the graph's segment, or because it lies inside it but was never executed in
// the profile the graph was built from. On the WHOLE-PROFILE graph the second case is the only one
// that matters, and it is a real boundary of the evidence rather than an artefact of how the graph
// was cut up: the guest branched somewhere this run never went. It is reported, not absorbed.
std::vector<std::pair<u32, u32>> ModuleGraph::UnresolvedCrossEdges()
{
	std::set<std::pair<u32, u32>> out;
	for (auto const &e : ip_map)
		for (u32 tgt : e.second->cross_succs)
			out.emplace(e.second->ip, tgt);
	return {out.begin(), out.end()};
}

// T5d1a: how many RESOLVED edges cross a guest page boundary. Zero on a per-page graph by
// construction -- no node of another page exists to point at -- and non-zero on a stitched
// whole-profile graph for any guest with inter-page control flow. A builder that forgot to stitch
// reports 0 here while still producing a plausible-looking candidate set, which is why the number is
// printed rather than assumed.
unsigned long long ModuleGraph::CountResolvedCrossPageEdges()
{
	unsigned long long n = 0;
	for (auto const &e : ip_map)
		for (auto *s : e.second->succs)
			if ((e.second->ip >> mmu::PAGE_BITS) != (s->ip >> mmu::PAGE_BITS))
				n++;
	return n;
}

// T5d1a: the whole loop report for this graph, header line to summary line.
//
// It writes the RAW BACK EDGES as well as the canonical candidates, and the COLD candidates as well
// as the HOT ones, because a set that only ever shows what it selected cannot be told apart from a
// rule that selects everything -- which is exactly the T5c-0 expose-all-loop-headers diagnostic this
// checkpoint exists to replace. It writes the unresolved boundary edges for the same reason.
//
// Canonical: unresolved edges ascending by (source, target), back edges ascending by (header, latch),
// candidates ascending by header, latch and body lists ascending inside a line -- all across the
// WHOLE graph, so a candidate whose body spans two pages sorts as one list. The only inputs are guest
// ips and profile frequencies, so the same profile produces byte-identical text on any host and in
// any process.
void ModuleGraph::WriteLoopCandidateReport(FILE *f, LoopCandidateTotals *totals)
{
	std::vector<std::pair<u32, u32>> edge_ips; // (header, latch)
	for (auto const &be : EnumerateNaturalLoopBackEdges())
		edge_ips.emplace_back(be.header->ip, be.latch->ip);
	std::sort(edge_ips.begin(), edge_ips.end());
	auto cands = ComputeNaturalLoopCandidates();
	auto unresolved = UnresolvedCrossEdges();
	unsigned long long cross_page = CountResolvedCrossPageEdges();

	std::set<u32> pages;
	for (auto const &e : ip_map)
		pages.insert(e.second->ip >> mmu::PAGE_BITS);

	auto print_ips = [f](std::vector<u32> const &ips) {
		for (size_t i = 0; i < ips.size(); ++i)
			fprintf(f, "%s%08x", i ? "," : "", ips[i]);
	};

	fprintf(f, "LOOPCAND_VERSION 2\n");
	fprintf(f, "LOOPCAND_RULE header_dominates_latch exec_freq_ge_threshold\n");
	// What the evidence number is, stated in the report itself so a reader of the raw file cannot
	// mistake it for a trip count. See LoopCandidate::header_exec_freq.
	fprintf(f, "LOOPCAND_EVIDENCE header_exec_freq=profile_execution_frequency_of_header_block "
		   "not_backedge_taken_count not_iteration_cost not_exact_trip_count "
		   "propagate_exec_count=%d\n",
		(int)dbt::config::propagate_exec_count);
	fprintf(f, "LOOPCAND_THRESHOLD %llu\n", (unsigned long long)dbt::config::threshold);
	fprintf(f, "LOOPCAND_SCOPE whole_profile pages=%zu nodes=%zu vaddr_lo=%08x vaddr_hi=%08x "
		   "cross_page_edges=%llu unresolved=%zu\n",
		pages.size(), ip_map.size(), segment.gip_base, segment.gip_base + segment.size,
		cross_page, unresolved.size());
	for (auto const &[s, t] : unresolved)
		fprintf(f, "LOOPUNRESOLVED src=%08x tgt=%08x\n", s, t);
	for (auto const &[h, l] : edge_ips)
		fprintf(f, "LOOPEDGE header=%08x latch=%08x\n", h, l);
	for (auto const &c : cands) {
		fprintf(f, "LOOPCAND header=%08x exec_freq=%llu threshold=%llu disposition=%s nlatch=%zu latches=",
			c.header_ip, (unsigned long long)c.header_exec_freq,
			(unsigned long long)dbt::config::threshold, c.hot ? "HOT" : "COLD",
			c.latch_ips.size());
		print_ips(c.latch_ips);
		fprintf(f, " nbody=%zu body=", c.body_ips.size());
		print_ips(c.body_ips);
		fprintf(f, "\n");
	}
	unsigned long long n_hot = 0;
	for (auto const &c : cands)
		if (c.hot)
			n_hot++;
	fprintf(f, "LOOPCAND_SUMMARY pages=%zu backedges=%zu loops_all=%zu hot=%llu cold=%llu "
		   "unresolved=%zu cross_page_edges=%llu threshold=%llu\n",
		pages.size(), edge_ips.size(), cands.size(), n_hot, cands.size() - n_hot,
		unresolved.size(), cross_page, (unsigned long long)dbt::config::threshold);
	if (totals) {
		totals->backedges += edge_ips.size();
		totals->loops += cands.size();
		totals->hot += n_hot;
		totals->cold += cands.size() - n_hot;
		totals->unresolved += unresolved.size();
		totals->cross_page += cross_page;
	}
}

// Cycle-13 Phase-0 diagnostic (behavior-neutral): count natural loops whose body contains an ACTIONABLE internal
// region_entry -- a region_entry strictly inside the loop, dominated by the header, that is NOT a real entry point
// (brind_target/segment_entry). That is exactly the set Phase-1 would suppress -> the true go/no-go surface area.
void ModuleGraph::AnalyzeLoopVsIDF()
{
	auto loops = DetectNaturalLoops();
	for (auto &lp : loops) {
		auto header = lp.first;
		unsigned actionable = 0, raw = 0, nodom = 0;
		dbt::config::g_loop_body_nodes += (lp.second.size() > 0 ? lp.second.size() - 1 : 0); // body minus header
		for (auto n : lp.second) {
			if (n == header || !n->flags.region_entry)
				continue;
			nodom++; // any region_entry strictly inside body, NO dominance filter (detection-artifact check)
			if (!NodeDominates(header, n)) // only header-dominated body nodes are legally part of the single-entry loop region
				continue;
			raw++; // any region_entry strictly inside the loop body (incl. brind/segment real entry points)
			if (n->flags.is_brind_target || n->flags.is_segment_entry)
				continue;
			actionable++; // a pure IDF dominance-frontier merge -> suppressable by the structural rule
		}
		dbt::config::g_loop_internal_re_nodom += nodom;
		unsigned body_internal = (lp.second.size() > 0 ? (unsigned)lp.second.size() - 1 : 0);
		if (body_internal > dbt::config::g_loop_body_max)
			dbt::config::g_loop_body_max = body_internal;
		if (body_internal >= 5) { // substantial loop: enough room for an internal merge/region boundary
			dbt::config::g_loop_big_total++;
			if (nodom > 0)
				dbt::config::g_loop_big_split++;
		}
		dbt::config::g_loop_total++;
		if (actionable > 0)
			dbt::config::g_loop_split++;
		if (raw > 0)
			dbt::config::g_loop_split_raw++;
		dbt::config::g_loop_internal_re += actionable;
		dbt::config::g_loop_internal_re_raw += raw;
	}
	for (auto const &e : ip_map) {
		dbt::config::g_node_total++;
		if (e.second->flags.region_entry)
			dbt::config::g_re_total++;
	}
}

// Cycle-13 Phase-1 method: clear region_entry on dom-frontier nodes strictly inside a natural-loop body so the whole loop
// becomes one LLVM region. Correctness: only clear if the header dominates the node (single-entry-into-region preserved --
// the only external entry remains the header) and the node is not itself a real entry point (brind_target/segment_entry).
void ModuleGraph::SuppressIntraLoopRegionEntries()
{
	auto loops = DetectNaturalLoops();
	for (auto &lp : loops) {
		auto header = lp.first;
		for (auto n : lp.second) {
			if (n == header || !n->flags.region_entry)
				continue;
			if (n->flags.is_brind_target || n->flags.is_segment_entry)
				continue;
			if (!NodeDominates(header, n))
				continue;
			n->flags.region_entry = false;
			dbt::config::g_loop_re_suppressed++;
		}
	}
}

// T5c-0: mark the natural-loop headers that a mid-run promotion would otherwise be unable to reach.
//
// The rule is purely STRUCTURAL and contains no constant: a natural-loop header, as DetectNaturalLoops
// already defines one by dominance, that is not already a region entry.
//
//   natural-loop header         -- the only node a back-edge can carry control to, so it is the only
//                                  place a relinked guest branch can re-enter a loop that is already
//                                  running. Reused from the existing detector, not a new analysis.
//   not already a region entry  -- a header that IS one already has its own `_aot_tab` symbol and is
//                                  already relinkable; exposing it again would be a duplicate symbol,
//                                  not a fix.
//
// NO HOTNESS GATE, and that is deliberate rather than lax. Design 8 gates its candidates on
// `--threshold` because its candidate set is every return continuation in the program. Loop headers
// are a far smaller, structurally bounded set, and more decisively: the in-run builder does not
// compile at `--threshold` at all -- sr_builder.sh runs the admission pass separately and then calls
// elfaot with `--threshold=999999999 --dispatch-admit-list=...`, so any gate written against
// `config::threshold` is silently INERT on the one path this mechanism exists for. Reading hotness
// from a number that the consumer does not use would have been a gate in name only; the honest
// choice is a structural rule plus the region filter that llvmaot.cpp already applies, since it only
// iterates the members of regions it is actually compiling.
//
// This function sets a bit and nothing else. It runs AFTER ComputeRegionIDF (so `region_entry` is
// final) and BEFORE ComputeRegionDomSets, which does not read the bit -- so region membership,
// region count and generated region code are bit-for-bit what they were. The only difference in the
// artifact is an extra entry wrapper and an extra `_aot_tab` slot per exposed header.
void ModuleGraph::MarkLateEnterableLoopHeaders()
{
	for (auto &lp : DetectNaturalLoops()) {
		auto *h = lp.first;
		if (h->flags.region_entry || h->flags.loop_entry_exposed)
			continue;
		h->flags.loop_entry_exposed = true;
		dbt::config::g_loop_entries_exposed++;
		if (getenv("LOOPENTRY_DEBUG"))
			fprintf(stderr, "LOOPENTRY_MARK ip=%08x exec_count=%llu\n", h->ip,
				(unsigned long long)h->flags.exec_count);
	}
}

std::vector<std::vector<ModuleGraphNode *>> ModuleGraph::ComputeRegionDomSets()
{
	std::vector<std::vector<ModuleGraphNode *>> regions;

	auto compute_region = [this](ModuleGraphNode *entry) {
		qir::Marker<ModuleGraphNode, bool> marker(&markers, 2);

		std::vector<ModuleGraphNode *> region_nodes{};

		using ChildIt = std::vector<ModuleGraphNode *>::iterator;
		std::vector<std::pair<ModuleGraphNode *, ChildIt>> stk;

		// A-line IDF-fuse safety bound (structural, not workload-tuned): cap how many DISTINCT
		// idf_fused convergence points a single predecessor's region may absorb to exactly 1.
		// Without this, a chain of nested convergence points (a second shared merge point reached
		// FROM the first fused-through one) can duplicate multiplicatively -- the same
		// unstructural-bound risk FDRE_FIVE_ITEM_AUDIT_AND_VERDICT.md already flagged for its own
		// duplication mechanism ("the algorithm does not structurally forbid a target's own
		// dominated subregion from containing another FDRE-suppressed node"). Measured concretely:
		// upython_embed's compiled size grew 797% (13,456B -> 120,752B) uncapped, vs 10-42% growth
		// on every OTHER real workload tested -- a clear outlier, not a tuned threshold: the cap is
		// "1" because that is the minimum structural bound that still fixes the single-shared-
		// convergence-point pattern (interpreter_bench's witness, and the common real-workload
		// shape) while forbidding chains of 2+ (the only source of multiplicative blowup).
		unsigned fused_absorbed = 0;
		auto push_node = [&](ModuleGraphNode *node, bool force = false) {
			// A-line IDF-fuse (--aot-idf-fuse, measurement-only, default-off): a node that
			// became region_entry SOLELY via dominance-frontier propagation (idf_fused, not a
			// real is_brind_target/is_segment_entry/*_suppressed seed) is not a genuine entry
			// requirement -- let the DFS grow THROUGH it (a real, additive duplicate of its body
			// into this predecessor's region) instead of stopping there. The node keeps its own
			// independent region regardless (unchanged, below), so paths not captured by any
			// predecessor's DFS stay correct.
			bool fusable = dbt::config::aot_idf_fuse && node->flags.idf_fused && fused_absorbed < 1;
			bool boundary = node->flags.region_entry && !fusable;
			if (force || (!marker.Get(node) && !boundary)) {
				if (!force && fusable && node->flags.region_entry)
					fused_absorbed++;
				stk.push_back(std::make_pair(node, node->succs.begin()));
				marker.Set(node, true);
				region_nodes.push_back(node);
			}
		};

		push_node(entry, true);

		while (!stk.empty()) {
			auto &p = stk.back();
			if (p.second == p.first->succs.end()) {
				stk.pop_back();
			} else {
				push_node(*p.second++);
			}
		}

		return region_nodes;
	};

	for (auto const &e : ip_map) {
		auto n = e.second.get();
		if (n->flags.region_entry) {
			regions.push_back(compute_region(n));
		}
	}

	// FDRE: an `fdre_suppressed` target is (by design) swept into its dominant source's
	// region above as a plain interior member -- but it must ALSO remain independently
	// compilable, because any OTHER (minority) source, the generic slowpath, or a future
	// input's dispatch pattern still needs a real, standalone entry to reach it (the safety
	// property in A_LINE_ARCHITECTURE_SPEC.md #4: merging is ADDITIVE, never a removal of the
	// existing correct path). Compute a SECOND, independent region rooted at the target
	// itself (using the SAME compute_region logic, entered with force=true exactly like any
	// other root) -- this duplicates the target's own compiled body (a real code-size cost,
	// measured at the performance stage) in exchange for both paths staying correct.
	for (auto const &e : ip_map) {
		auto n = e.second.get();
		if (n->flags.fdre_suppressed) {
			// Downstream consumers (AOTCompilePage et al.) assert region_entry on r[0] for
			// every region; safe to set now (IDF propagation is already fully computed --
			// ComputeRegionIDF ran before this function) without affecting the earlier
			// seeding/propagation phases this flag was deliberately kept false through.
			n->flags.region_entry = true;
			regions.push_back(compute_region(n));
		}
	}

	return regions;
}

std::vector<std::vector<ModuleGraphNode *>> ModuleGraph::ComputeRegions()
{
	ComputeDomTree();
	ComputeDomFrontier();
	ComputeRegionIDF();
	if (dbt::config::dump_loop_vs_idf) // Cycle-13 Phase-0: measure-only loop-vs-IDF split surface (behavior-neutral)
		AnalyzeLoopVsIDF();
	if (dbt::config::loop_structural_regions) // Cycle-13 Phase-1: structural loop-closed regions (default-off method)
		SuppressIntraLoopRegionEntries();
	if (dbt::config::aot_loop_entry) // T5c-0: mark-only, after region_entry is final; regions unchanged
		MarkLateEnterableLoopHeaders();
	auto regions = ComputeRegionDomSets();

	if (g_modulegraph_dump) {
		DumpModuleGraph(this, &regions);
	}
	return regions;
}

} // namespace dbt
