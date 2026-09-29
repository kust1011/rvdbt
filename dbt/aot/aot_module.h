#pragma once

#include "dbt/qmc/compile.h"
#include "dbt/qmc/marker.h"
#include "dbt/util/logger.h"
#include <cstdio>
#include <map>
#include <memory>
#include <set>
#include <vector>

namespace dbt
{

LOG_STREAM(analyse)

// TODO: optimize layout and use Arena containers
struct ModuleGraphNode {
	explicit ModuleGraphNode(u32 ip_) : ip(ip_) {}

	struct EdgeInfo {
		enum class Type {
			BR,
			CALL,
		};
	};

	void AddSucc(ModuleGraphNode *succ)
	{
		succs.push_back(succ);
		succ->preds.push_back(this);
	}

	void AddCrossSucc(u32 ip)
	{
		cross_succs.push_back(ip);
	}

	u32 ip{};
	u32 ip_end{0};
	
	struct {
		bool is_brind_target : 1 {false};
		bool is_segment_entry : 1 {false};
		bool region_entry : 1 {false};
		bool is_brind_source : 1 {false};
		bool is_crosssegment_br : 1 {false};
		u64 exec_count{0};
		u32 exec_instr_count{0};
		bool is_critical : 1 {false};
		double indirect_confidence{1.0}; // CPB (2026-07-20): the confidence of the indirect SOURCE(s) that
						  // admitted this node as a brind target; 1.0 = not indirect-admitted
						  // or fully confident (default, no effect on non-indirect regions).
		// FDRE (A-line architecture reset): set by ModuleGraph::ApplyFDRE when this brind_target
		// node has a conservation-verified DOMINANT source and a real graph edge from that
		// source already exists (see ApplyFDRE) -- ComputeRegionIDF must NOT unconditionally
		// force a region root here; the node is swept into the dominant source's region by the
		// normal DFS instead, exactly like a `jal` target. Reachability from mg->root is
		// verified (not assumed) before this is set -- see ApplyFDRE's revert pass.
		bool fdre_suppressed : 1 {false};
		// Design 8 (2026-07-24, link-aware region merge): set by
		// ModuleGraph::ApplyLinkAwareRegionMerge when this brind_target node is ALSO a recorded
		// `link` target (i.e. it is exactly `call_site_ip + 4` for some statically-known call
		// site with rd!=0 -- a function-call return continuation, not a genuinely polymorphic
		// dispatch target). Unlike FDRE's dominant-source decision, this needs NO dynamic edge
		// evidence at all: RISC-V's fixed 4-byte instruction width makes "target - 4 is a call
		// site" a STATIC, always-true-or-false fact already computed for free during the SAME
		// per-page analysis pass that builds this graph (RecordLink, rv32_analyser.cpp). See
		// ApplyLinkAwareRegionMerge for the reachability-safety discipline (same BFS pattern as
		// FDRE's own revert pass).
		bool link_region_suppressed : 1 {false};
		// Jump-table multi-entry pivot (2026-07-25, ceiling-test fix): set by
		// ApplyJumpTableClosure (llvmaot.cpp) instead of link_region_suppressed when a
		// P7-discovered handler is swept into its enclosing function's region under
		// --aot-jumptable-multientry. Distinct from link_region_suppressed because the two
		// mechanisms have OPPOSITE admission policies by design: Design 8's link-merge
		// candidates are real, ALREADY-observed return continuations, correctly gated on
		// exec_count (a cold one is genuinely rare, cheap to silently absorb). A P7-discovered
		// handler's entire reason for existing is static, PROFILE-INDEPENDENT coverage -- a
		// handler with exec_count==0 (never seen in the profiling run) is exactly the case P7
		// exists to protect, not a candidate for the same hotness gate. Conflating the two
		// (both previously set link_region_suppressed and shared one gate) silently dropped
		// _aot_tab protection for every never-profiled P7 handler, defeating cross-input
		// coverage while leaving compiled output byte-identical to not using P7 at all -- see
		// DESIGN8_ALIAS_MULTIENTRY_ROOT_CAUSE_3.md's sibling ceiling-test doc.
		bool jumptable_region_suppressed : 1 {false};
		// T5c-0 (2026-08-30, late-enterable loop entry): set by MarkLateEnterableLoopHeaders on
		// EVERY natural-loop header that is not itself a region_entry. There is no per-loop
		// hotness test -- see MarkLateEnterableLoopHeaders for why one would be inert -- and the
		// only filter is applied later, by llvmaot.cpp, which reads this bit solely for the
		// members of regions the compiler already selected.
		//
		// WHY SUCH A NODE EXISTS AT ALL. ComputeRegionIDF seeds region entries from exactly two
		// things: is_segment_entry and is_brind_target. A loop header inside a function, reached
		// only by direct branches, is neither -- so it never becomes a region entry, never gets an
		// `_aot_tab` slot, and BootOneArtifact's RelinkTo can never redirect the loop's backedge
		// into AOT code. For an offline AOT run that costs nothing: the artifact is loaded before
		// the guest starts and the region is entered normally at its root. For the SAME-RUN tier it
		// is fatal whenever the region's root is entered once -- a single call to a long-running
		// kernel -- because by the time the artifact lands there is no future entry left to catch.
		// Measured on PolyBench gemm: the one admitted region is rooted at a block in main that
		// runs once, its hottest interior block runs 80,400,000 times, and promotion relinked 0
		// slots and executed 0 AOT instructions.
		//
		// WHAT THE FLAG CHANGES. Nothing about region formation: the regions, their members and
		// their code are identical. It only marks the node so the EXISTING multi-entry exposure
		// (llvmaot.cpp's link_secondary_entries -> QIRToLLVM::merge_entries switch +
		// CreateLinkEntryWrapper + an aot_symbols slot) gives it a real entry symbol, which is what
		// makes the region late-enterable at its loop header. Gated by --aot-loop-entry, default off.
		bool loop_entry_exposed : 1 {false};
		// A-line (2026-07-25, IDF-fuse): set by ComputeRegionIDF when this node became
		// region_entry SOLELY via iterated-dominance-frontier PROPAGATION (a shared merge point
		// where >=2 distinct seeded regions converge) and NOT because it is itself a real,
		// independent entry requirement (is_brind_target/is_segment_entry/fdre_suppressed/
		// link_region_suppressed/jumptable_region_suppressed). Such a node needs no `_aot_tab`
		// protection of its own for THIS reason (nothing dispatches to it directly) -- it is only
		// a Wendell region-formation ARTIFACT of the standard SSA-style dominance-frontier
		// construction applied unconditionally to brind_target seeds. See ComputeRegionDomSets's
		// `--aot-idf-fuse` consumer: instead of treating this as a hard region boundary (which
		// truncates every converging predecessor into a tiny stub that must jump out to reach the
		// shared continuation -- the mechanism behind the interpreter_bench-class fragmentation
		// documented in METHOD_CANDIDATE_R4.md/CAUSAL_LADDER_R4.md), each predecessor's DFS is
		// allowed to grow THROUGH it (a real, additive duplicate -- same safety discipline as
		// FDRE's fdre_suppressed second-pass copy), while the node ALSO keeps its own independent
		// region (unchanged) so any path not captured by a predecessor's DFS remains correct.
		// Purely structural: needs no source-target edge weights, no profiling beyond the
		// is_brind_target/is_segment_entry flags every baseline compile already has for free.
		bool idf_fused : 1 {false};
	} flags;

	ModuleGraphNode *link{};

	std::vector<ModuleGraphNode *> succs;
	std::vector<ModuleGraphNode *> preds;
	std::vector<u32> cross_succs;
	// A-line round 22 Gate 1 Row 1 (--aot-indirect-succs-file, oracle-only, default-empty): a
	// TYPED, SEPARATE indirect-edge relation, populated from exact offline (source,target)
	// pairs, deliberately NOT the same storage as `succs` above (which region formation,
	// merge/link, and lowering all read). This field is read ONLY by the oracle consistency-
	// check/dump this round adds (ModuleGraph::DumpIndirectSuccs) -- no region-seed, no
	// merge/link, no gbrind lowering, no layout pass touches it. Isolates "does the graph
	// merely CONTAINING this information change anything" from "does some consumer ACT on it"
	// (Round 21 found `succs` structurally fuses CFG-visibility with region-growth; this field
	// is the typed relation that avoids that fusion).
	std::vector<u32> indirect_succs;

	ModuleGraphNode *dominator{};
	std::set<ModuleGraphNode *> domfrontier;
	qir::Mark mark{};

	qir::Mark GetMark() const
	{
		return mark;
	}
	void SetMark(qir::Mark mark_)
	{
		mark = mark_;
	}
};

struct ModuleGraph {
	explicit ModuleGraph(qir::CodeSegment segment_)
	    : segment(segment_), root(std::make_unique<ModuleGraphNode>(0))
	{
	}

	bool InModule(u32 ip)
	{
		return segment.InSegment(ip);
	}

	ModuleGraphNode *GetNode(u32 ip)
	{
		if (!InModule(ip)) {
			return nullptr;
		}
		auto it = ip_map.find(ip);
		if (likely(it != ip_map.end())) {
			return it->second.get();
		}
		return nullptr;
	}

	ModuleGraphNode *AddNode(u32 ip)
	{
		auto res = ip_map.insert({ip, std::make_unique<ModuleGraphNode>(ip)});
		assert(res.second);
		return res.first->second.get();
	}

	void RecordEntry(u32 ip)
	{
		AddNode(ip);
	}

	void RecordBrindTarget(u32 ip)
	{
		auto *node = GetNode(ip);
		node->flags.is_brind_target = true;
		root->AddSucc(node);
	}

	void RecordSegmentEntry(u32 ip)
	{
		auto *node = GetNode(ip);
		node->flags.is_segment_entry = true;
		root->AddSucc(node);
	}

	void RecordExec(u32 ip, u32 exec_instr_count, u64 exec_count)
	{
		auto *node = GetNode(ip);
		node->flags.exec_instr_count = exec_instr_count;
		node->flags.exec_count = exec_count;
	}

	void RecordGBr(u32 ip, u32 tgtip)
	{
		auto src = GetNode(ip);
		if (auto tgt = GetNode(tgtip); tgt) {
			src->AddSucc(tgt);
		} else {
			src->AddCrossSucc(tgtip);
			src->flags.is_crosssegment_br = true;
		}
	}

	void RecordGBrind(u32 ip)
	{
		GetNode(ip)->flags.is_brind_source = true;
	}

	void RecordLink(u32 ip, u32 linkip)
	{
		GetNode(ip)->link = GetNode(linkip);
	}

	// FDRE (A-line architecture reset): one edge-evidence record from the exhaustive
	// (source_block_ip, target_ip, count) collector (--brind-edges-out /
	// dbt::brindedges::Dump, verified exact modulo a named per-source first-dispatch miss --
	// see A_LINE_ARCHITECTURE_SPEC.md stage 1). `weight` is the observed dynamic count.
	struct FDREEdge {
		u32 src, dst;
		u64 weight;
	};
	// Loads a `--brind-edges-out`-format file (lines "SRC DST COUNT" in hex/dec, exactly what
	// dbt::brindedges::Dump already writes -- no new file format). Returns an empty vector
	// (safe no-op) if the path is empty or unreadable.
	static std::vector<FDREEdge> LoadFDREEdges(char const *path);
	// Applies the conservation-gated dominant-source rule (see spec): for each brind_target
	// node with an incoming edge SET (all within this ModuleGraph's segment) whose total
	// weight is consistent with the node's own exact exec_count (within the named per-source
	// slack bound), and whose traffic has a strict-majority single source, add a real graph
	// edge dominant_source->target and mark the target `fdre_suppressed`. A whole-graph
	// reachability-from-root check (reusing the same BFS discipline validated in the P6/P7/P9
	// closure work) reverts any suppression that would otherwise orphan the target -- this
	// can only ever fall back toward stock behavior, never produce a wrong decision. Must be
	// called AFTER all Record*/RecordExec calls and BEFORE ComputeRegions(). No-op if `edges`
	// is empty (exact-Wendell / flag-off byte-identical).
	void ApplyFDRE(std::vector<FDREEdge> const &edges);
	// Design 8 (link-aware region merge): for every brind_target node that is ALSO some node's
	// recorded `link` (a call-site's return continuation, known statically, zero dynamic
	// evidence), remove the artificial root->target edge, add the real call-site->target edge,
	// and mark it `link_region_suppressed` so ComputeRegionIDF does not force it as an
	// independent region root -- it is instead swept into its caller's region by the normal
	// dominance-frontier computation, exactly like a `jal` target. Reuses the exact
	// reachability-from-root safety discipline validated by ApplyFDRE/P6/P7/P9: a suppression
	// that would orphan its target from `root` is reverted, so this can only ever fall back
	// toward stock (unsuppressed) behavior, never produce an unreachable/wrong region. No
	// external evidence file needed -- purely a function of this ModuleGraph's own
	// already-built `link` structure. Must be called AFTER all Record*/RecordLink calls and
	// BEFORE ComputeRegions() (mirrors ApplyFDRE's own calling convention).
	void ApplyLinkAwareRegionMerge();
	// `fail_closed=false` (every pre-existing caller) keeps the Panic on an unreachable node: in
	// elfaot that is a build-time invariant violation and aborting is right. T5d2a1 runs the same
	// dominator computation INSIDE A LIVE GUEST PROCESS, where a Panic would kill a run that was
	// executing correctly, so it passes `true` and gets `false` back instead. The computation is
	// one implementation either way -- a second copy is exactly how the in-process selector would
	// stop being "the exact T5d1a selector".
	bool ComputeDomTree(bool fail_closed = false);
	void ComputeDomFrontier();
	void ComputeRegionIDF();
	// T5d1a: one natural-loop back edge, as the textbook defines it -- an edge latch->header whose
	// HEADER DOMINATES ITS LATCH, together with that edge's own natural-loop body. This is the
	// relation DetectNaturalLoops has always computed; naming the latch is the only thing added,
	// and it is needed because canonicalisation merges the several latches of one header.
	struct NaturalLoopBackEdge {
		ModuleGraphNode *latch{};
		ModuleGraphNode *header{};
		std::set<ModuleGraphNode *> body; // includes the header
	};
	std::vector<NaturalLoopBackEdge> EnumerateNaturalLoopBackEdges();
	// Cycle-13: natural-loop helpers (back-edge based). DetectNaturalLoops returns {header, body-set} per back-edge.
	std::vector<std::pair<ModuleGraphNode *, std::set<ModuleGraphNode *>>> DetectNaturalLoops();
	// T5d1a: ONE canonical candidate per natural-loop HEADER. See ComputeNaturalLoopCandidates.
	struct LoopCandidate {
		u32 header_ip{};
		// THIS PROFILE'S EXECUTION FREQUENCY FOR THE HEADER BLOCK, and nothing more precise than
		// that. It is `ModuleGraphNode::flags.exec_count` as the graph builder leaves it, which is
		// the loop's RUNTIME ACTIVITY EVIDENCE -- how much this block ran in the profiled run. It
		// is NOT:
		//   * a backedge-taken count -- it also counts every entry into the loop from outside, and
		//     an inner loop's header is re-entered once per iteration of its enclosing loop;
		//   * an iteration COST -- it says nothing about how long one pass through the body takes;
		//   * an exact source-level trip count -- besides the entry term above, Wendell's
		//     `--propagate-exec-count` (dbt::config::propagate_exec_count, DEFAULT ON) adds a
		//     carried sum along the address-ordered analysis of a page's blocks
		//     (rv32_analyser.cpp), so the value can exceed what the block's own counter recorded.
		// The rule below uses it for exactly what it supports: a hotness comparison against the
		// compiler's own admission bar.
		u64 header_exec_freq{};
		std::vector<u32> latch_ips; // sorted, deduplicated: every latch of THIS header
		std::vector<u32> body_ips;  // sorted, deduplicated: the UNION of the latches' bodies
		bool hot{false};	    // header_exec_freq >= dbt::config::threshold
	};
	// Every natural loop of this module graph, canonicalised by header and classified against this
	// elfaot run's own admission bar. Requires ComputeDomTree() to have run (Panics otherwise --
	// without a dominator tree every dominance test answers "no" and the honest answer would be an
	// empty set that looks like a legitimate one).
	std::vector<LoopCandidate> ComputeNaturalLoopCandidates();
	// The hot subset, in the same canonical order: the actual candidate set a loop-rooted region
	// builder consumes. Selection only -- neither this nor the producer above marks a node, touches
	// region_entry / loop_entry_exposed, or changes region formation.
	std::vector<LoopCandidate> SelectHotNaturalLoopCandidates();
	// T5d1b: one control-flow edge that LEAVES a candidate's body. Every such edge must become an
	// explicit region exit in the emitted function; none may be dropped or invented.
	struct LoopExit {
		enum class Kind {
			TAKEN,	     // a branch target outside the body
			FALLTHROUGH, // the block's own next address (ip_end) is outside the body
			UNRESOLVED,  // the target has no node at all -- see UnresolvedCrossEdges
		};
		u32 src_ip{};
		u32 tgt_ip{};
		Kind kind{Kind::TAKEN};
	};
	// T5d1b: the ip ranges a loop-rooted region is compiled from -- the candidate's canonical body
	// and nothing else, HEADER FIRST so the translator's `region_entry_ip` and QIRToLLVM's
	// `first_bb` are the loop header, then the remaining body ips ascending for determinism. The
	// ranges may span guest pages; nothing here truncates or reorders them by page.
	std::vector<std::pair<u32, u32>> LoopCandidateIpRanges(LoopCandidate const &c);
	// T5d1b: every edge leaving that body, ascending by (source, target). Derived from the same
	// graph the candidate came from, so it is the ground truth the emitted function's exits are
	// checked against rather than a re-derivation from the generated code.
	std::vector<LoopExit> LoopCandidateExits(LoopCandidate const &c);
	// T5d1a: every direct edge whose TARGET is not a node of this graph, ascending and deduplicated.
	// On a whole-profile graph these are the real boundary of what was profiled -- a branch into
	// code this run never executed -- and not an artefact of how the graph was cut up. Reported by
	// the dump so the boundary is visible rather than silently absorbed.
	std::vector<std::pair<u32, u32>> UnresolvedCrossEdges();
	// T5d1a: resolved edges whose source and target sit on DIFFERENT guest pages. Zero on a
	// per-page graph by construction; non-zero on a stitched whole-profile graph whenever the guest
	// has any inter-page control flow at all. This is the measure that a builder which forgot to
	// stitch would report as 0.
	unsigned long long CountResolvedCrossPageEdges();
	struct LoopCandidateTotals {
		unsigned long long backedges{}, loops{}, hot{}, cold{}, unresolved{}, cross_page{};
	};
	// T5d1a: this graph's WHOLE loop report, header line to summary line, in canonical order: the
	// scope it covers, the unresolved boundary edges, every raw back edge, then every canonical
	// candidate with its disposition. EVERY loop is written, not only the selected ones, so that a
	// selector cannot be confused with a rule that exposes all loop headers. Fills *totals when
	// non-null. The whole file is written here rather than half here and half in the caller, so
	// that the canonical text is one testable thing.
	void WriteLoopCandidateReport(FILE *f, LoopCandidateTotals *totals);
	void AnalyzeLoopVsIDF();             // Phase-0 diagnostic (behavior-neutral): count loops split across IDF regions
	void SuppressIntraLoopRegionEntries(); // Phase-1 method: clear region_entry strictly inside loop bodies
	void MarkLateEnterableLoopHeaders();   // T5c-0: mark non-entry loop headers for multi-entry exposure
	std::vector<std::vector<ModuleGraphNode *>> ComputeRegionDomSets();

	std::vector<std::vector<ModuleGraphNode *>> ComputeRegions();
	void Dump(FILE *f, std::vector<std::vector<ModuleGraphNode *>> const *regions = nullptr);

	qir::CodeSegment segment;

	std::unique_ptr<ModuleGraphNode> root;

	using RegionMap = std::map<u32, std::unique_ptr<ModuleGraphNode>>;
	RegionMap ip_map;

	qir::MarkerKeeper markers;
};

void InitModuleGraphDump(char const *dir);

} // namespace dbt
