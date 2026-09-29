// T5d1a focused test: the canonical hot-natural-loop candidate producer.
//
// WHAT IS BEING CLAIMED. `ModuleGraph::ComputeNaturalLoopCandidates()` turns a module graph plus the
// profile it was built from into ONE candidate per natural-loop header, and
// `SelectHotNaturalLoopCandidates()` keeps the ones this compile's own admission bar calls hot. The
// claim has six parts, and each has a section here that FAILS when that part is broken:
//
//   (a) a loop is a CFG edge latch->header whose HEADER DOMINATES ITS LATCH -- not an edge whose
//       target address is below its source's;
//   (b) the several latches of one header are ONE candidate, whose body is the union of theirs;
//   (c) nested loops stay distinct candidates, and the inner body stays a subset of the outer;
//   (d) the bar is `header exec_freq >= config::threshold`, met at equality and not one below,
//       read from the HEADER and from no other block, where `exec_freq` is THIS PROFILE'S EXECUTION
//       FREQUENCY for the header block -- hotness evidence, not a trip count (see below);
//   (e) the analysis is over ONE STITCHED CFG spanning every profiled page, so a loop whose header
//       and latch sit on different pages is found, an unresolved target is reported rather than
//       absorbed, two pages are never mis-stitched, and no page is given an artificial entry;
//   (f) it selects and nothing else -- it marks no node, moves no counter, and leaves the graph and
//       the regions the compiler would form bit-identical.
//
// HOW EACH ASSERTION CAN FAIL, stated because a passing test that cannot fail is not evidence:
//
//   [2] is the discriminating case for the RULE. Its graph contains an edge whose target address is
//       BELOW its source's, in a real cycle, that is NOT a natural loop -- an irreducible cycle with
//       two independent entries. The section first asserts that the address comparison WOULD select
//       it, then requires the producer to return nothing. Replace the dominance test with
//       `target <= source` and this section fails immediately.
//   [3] counts raw back-edges and candidates separately. Stop merging and 3 sees 2 candidates where
//       it requires 1; merge by something other than the header and 4 sees 1 where it requires 2.
//   [5] moves the header frequency across the bar in both directions and puts a huge frequency on a
//       body block of a cold loop. Use max-over-the-body, or `>` instead of `>=`, and it fails.
//   [8a-8f] are the discriminating case for the SCOPE. 8a builds a natural loop whose header is on
//       one page and whose latch is on another -- invisible to any per-page graph. 8b pins the
//       two-phase ordering (all nodes, then all edges) that makes the stitch possible at all. 8c
//       requires an unresolved target to be reported, 8d requires an edge to land on exactly its
//       target or nowhere, and 8e/8f require that no page is handed an artificial root entry --
//       8e by showing that doing so DESTROYS 8a's loop, 8f by running the shipped node recorder.
//   [7] snapshots every node flag, dominator pointer and edge vector, runs the producer, and
//       requires equality; then forms regions with and without a producer call in between and
//       requires the same regions. Set one bit in the producer -- `loop_entry_exposed` is the one
//       this checkpoint is forbidden to touch, and is checked by name -- and it fails.
//
// ON THE WORD "FREQUENCY". `LoopCandidate::header_exec_freq` is the header block's execution
// frequency in the profiled run and is deliberately NOT called a trip count: it also counts every
// entry into the loop from outside, and `--propagate-exec-count` (default ON) adds a carried sum to
// the underlying `flags.exec_count`. Section 9 requires the report to say so in the file itself.
//
// WHAT IT DELIBERATELY DOES NOT DO. It runs no guest program, compiles nothing, times nothing, and
// makes no claim about promotion, region building or performance. Every graph is built by hand from
// ModuleGraph's own Record* interface -- except 8f, which runs the shipped RecordProfilePageNodes
// over synthetic profile pages -- so what is under test is the analysis, not the decoder.

#include "dbt/aot/aot.h"
#include "dbt/aot/aot_module.h"
#include "dbt/config.h"
#include "dbt/tcache/objprof.h"
#include "dbt/qmc/compile.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;

namespace
{

int g_failed = 0;
int g_checks = 0;

void check(bool ok, char const *what)
{
	g_checks++;
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		g_failed++;
}

void checkf(bool ok, char const *fmt, ...) __attribute__((format(printf, 2, 3)));
void checkf(bool ok, char const *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	check(ok, buf);
}

void section(char const *name)
{
	printf("\n[%s]\n", name);
}

constexpr u32 kPageSize = 0x1000;
constexpr u32 kBase = 0x11000;   // page 1
constexpr u32 kPage2 = 0x12000;  // page 2
// The hand-built graphs span BOTH pages, exactly as BuildWholeProfileGraph's segment does, so that a
// cross-page edge is an ordinary resolved edge here and not a special case.
constexpr u32 kSize = 0x2000;

// A hand-built module graph, in the same shape BuildModuleGraph produces: every block is a node,
// `entry` blocks are segment entries and `brind` blocks are indirect-branch targets (both of which
// become successors of the synthetic root), and every direct edge is a succ/pred pair.
struct Graph {
	explicit Graph(std::vector<u32> const &ips) : mg(qir::CodeSegment(kBase, kSize))
	{
		for (u32 ip : ips)
			mg.RecordEntry(ip);
	}

	void Entry(u32 ip) { mg.RecordSegmentEntry(ip); }
	void Brind(u32 ip) { mg.RecordBrindTarget(ip); }
	void Edge(u32 src, u32 dst) { mg.RecordGBr(src, dst); }
	void Exec(u32 ip, u64 count) { mg.RecordExec(ip, 4, count); }
	void Doms() { mg.ComputeDomTree(); }

	ModuleGraph mg;
};

std::string IpList(std::vector<u32> const &ips)
{
	std::string s;
	char buf[16];
	for (size_t i = 0; i < ips.size(); ++i) {
		snprintf(buf, sizeof(buf), "%s%05x", i ? "," : "", ips[i]);
		s += buf;
	}
	return s;
}

// Does `a` dominate `b`? Walks b's immediate-dominator chain, the same way the production rule
// does. Spelled out here so section 8e can say WHY an artificial page root destroys a loop.
bool ChainDominates(ModuleGraphNode *a, ModuleGraphNode *b)
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

// The address-order rule this checkpoint is required NOT to use, spelled out so section 2 can show
// what it would have answered on the same graph.
bool AddressOrderRetreating(u32 latch_ip, u32 header_ip)
{
	return header_ip <= latch_ip;
}

// ---------------------------------------------------------------------------------------------

// 1. A real natural loop: entry -> header -> body -> header, with an exit.
void Test1_RealLoop()
{
	section("1. a real natural loop is one candidate rooted at its header");
	u32 const E = kBase, H = kBase + 4, B = kBase + 8, X = kBase + 12;
	Graph g({E, H, B, X});
	g.Entry(E);
	g.Edge(E, H);
	g.Edge(H, B);
	g.Edge(B, H); // the back edge: H dominates B
	g.Edge(B, X);
	g.Exec(E, 1);
	g.Exec(H, 100);
	g.Exec(B, 100);
	g.Exec(X, 1);
	g.Doms();

	auto edges = g.mg.EnumerateNaturalLoopBackEdges();
	checkf(edges.size() == 1, "exactly one back edge (got %zu)", edges.size());
	if (edges.size() == 1) {
		check(edges[0].header->ip == H, "its header is H");
		check(edges[0].latch->ip == B, "its latch is B");
	}

	config::threshold = 50;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 1, "exactly one candidate (got %zu)", cands.size());
	if (cands.size() != 1)
		return;
	auto const &c = cands[0];
	checkf(c.header_ip == H, "header=%05x", c.header_ip);
	checkf(c.header_exec_freq == 100, "header exec_freq=%llu (this profile's frequency for the header block)",
	       (unsigned long long)c.header_exec_freq);
	checkf(IpList(c.latch_ips) == IpList({B}), "latches=%s", IpList(c.latch_ips).c_str());
	checkf(IpList(c.body_ips) == IpList({H, B}), "body=%s (header included, exit excluded)",
	       IpList(c.body_ips).c_str());
	check(c.hot, "HOT at threshold 50");
	check(g.mg.SelectHotNaturalLoopCandidates().size() == 1, "the hot subset holds it");
}

// 2. THE DISCRIMINATING CASE. An irreducible cycle: two blocks that branch to each other, each
// independently reachable from outside the cycle. The edge from the higher address to the lower one
// is retreating BY ADDRESS and is not a natural loop, because neither block dominates the other.
void Test2_RetreatingButNotNatural()
{
	section("2. a retreating edge that is not a natural loop is excluded");
	u32 const E = kBase, A = kBase + 8, B = kBase + 12;
	Graph g({E, A, B});
	g.Entry(E);
	g.Edge(E, A);
	g.Brind(B); // B is ALSO reachable independently -- this is what makes the cycle irreducible
	g.Edge(A, B);
	g.Edge(B, A); // retreating by address (A < B), but A does not dominate B
	g.Exec(E, 1);
	g.Exec(A, 1000);
	g.Exec(B, 1000);
	g.Doms();

	check(AddressOrderRetreating(B, A), "an address-order rule WOULD select the edge B->A");
	check(!AddressOrderRetreating(A, B), "and would not select A->B");

	auto *na = g.mg.GetNode(A);
	auto *nb = g.mg.GetNode(B);
	check(na->dominator != nullptr && nb->dominator != nullptr, "both blocks have a dominator");
	check(nb->dominator == g.mg.root.get(), "B's immediate dominator is the root, not A");

	auto edges = g.mg.EnumerateNaturalLoopBackEdges();
	checkf(edges.empty(), "the dominance rule finds no back edge (got %zu)", edges.size());
	config::threshold = 1;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.empty(), "and no candidate, at a threshold both blocks clear (got %zu)", cands.size());

	// The same two blocks, with B no longer independently reachable, ARE a natural loop -- so
	// section 2's emptiness is caused by the irreducibility and not by the shape of the graph.
	Graph g2({E, A, B});
	g2.Entry(E);
	g2.Edge(E, A);
	g2.Edge(A, B);
	g2.Edge(B, A);
	g2.Exec(A, 1000);
	g2.Exec(B, 1000);
	g2.Doms();
	auto edges2 = g2.mg.EnumerateNaturalLoopBackEdges();
	checkf(edges2.size() == 1, "removing the second entry makes the SAME edge a natural back edge (got %zu)",
	       edges2.size());
	if (edges2.size() == 1)
		check(edges2[0].header->ip == A && edges2[0].latch->ip == B, "header=A latch=B");
}

// 3. One header, two latches -- two back edges, one candidate, the union of their bodies.
void Test3_MultiLatchMerge()
{
	section("3. several latches of one header merge into one candidate");
	u32 const E = kBase, H = kBase + 4, L1 = kBase + 8, L2 = kBase + 12, X = kBase + 16;
	Graph g({E, H, L1, L2, X});
	g.Entry(E);
	g.Edge(E, H);
	g.Edge(H, L1);
	g.Edge(H, L2);
	g.Edge(L1, H); // latch 1
	g.Edge(L2, H); // latch 2
	g.Edge(H, X);
	g.Exec(H, 100);
	g.Exec(L1, 60);
	g.Exec(L2, 40);
	g.Doms();

	auto edges = g.mg.EnumerateNaturalLoopBackEdges();
	checkf(edges.size() == 2, "two raw back edges (got %zu)", edges.size());
	bool same_header = edges.size() == 2 && edges[0].header == edges[1].header;
	check(same_header, "both name the same header");

	config::threshold = 100;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 1, "ONE candidate for the two back edges (got %zu)", cands.size());
	if (cands.size() != 1)
		return;
	auto const &c = cands[0];
	checkf(c.header_ip == H, "header=%05x", c.header_ip);
	checkf(IpList(c.latch_ips) == IpList({L1, L2}), "latches=%s, sorted", IpList(c.latch_ips).c_str());
	checkf(IpList(c.body_ips) == IpList({H, L1, L2}), "body=%s, the union of both bodies",
	       IpList(c.body_ips).c_str());
	check(c.hot, "HOT: the header's own count reaches the bar");
}

// 4. Nested loops keep their own headers, and the inner body is contained in the outer one.
void Test4_NestedStayDistinct()
{
	section("4. nested loops are distinct candidates");
	u32 const E = kBase, H1 = kBase + 4, H2 = kBase + 8, L2 = kBase + 12, L1 = kBase + 16;
	Graph g({E, H1, H2, L2, L1});
	g.Entry(E);
	g.Edge(E, H1);
	g.Edge(H1, H2);
	g.Edge(H2, L2);
	g.Edge(L2, H2); // inner back edge
	g.Edge(L2, L1);
	g.Edge(L1, H1); // outer back edge
	g.Exec(H1, 10);
	g.Exec(H2, 1000);
	g.Exec(L2, 1000);
	g.Exec(L1, 10);
	g.Doms();

	config::threshold = 500;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 2, "two candidates (got %zu)", cands.size());
	if (cands.size() != 2)
		return;
	auto const &outer = cands[0]; // canonical order is by header ip, and H1 < H2
	auto const &inner = cands[1];
	checkf(outer.header_ip == H1 && inner.header_ip == H2, "headers %05x and %05x, ascending",
	       outer.header_ip, inner.header_ip);
	checkf(IpList(inner.body_ips) == IpList({H2, L2}), "inner body=%s", IpList(inner.body_ips).c_str());
	checkf(IpList(outer.body_ips) == IpList({H1, H2, L2, L1}), "outer body=%s",
	       IpList(outer.body_ips).c_str());
	std::set<u32> ob(outer.body_ips.begin(), outer.body_ips.end());
	bool contained = true;
	for (u32 ip : inner.body_ips)
		contained = contained && ob.count(ip);
	check(contained, "the inner body is contained in the outer one");
	check(!outer.hot && inner.hot, "they are classified independently: outer COLD, inner HOT");
	auto hot = g.mg.SelectHotNaturalLoopCandidates();
	checkf(hot.size() == 1 && hot[0].header_ip == H2, "the hot subset is the inner loop alone (%zu)",
	       hot.size());
}

// 5. The bar: met at equality, missed one below, and read from the header and nowhere else.
void Test5_ThresholdBoundary()
{
	section("5. the admission bar is the header's own execution frequency against config::threshold");
	u32 const E = kBase, H = kBase + 4, B = kBase + 8;
	auto build = [&](u64 header_count, u64 body_count) {
		auto g = std::make_unique<Graph>(std::vector<u32>{E, H, B});
		g->Entry(E);
		g->Edge(E, H);
		g->Edge(H, B);
		g->Edge(B, H);
		g->Exec(H, header_count);
		g->Exec(B, body_count);
		g->Doms();
		return g;
	};

	config::threshold = 1000;
	{
		auto g = build(1000, 1);
		auto c = g->mg.ComputeNaturalLoopCandidates();
		check(c.size() == 1 && c[0].hot, "exec_freq == threshold is HOT");
		check(g->mg.SelectHotNaturalLoopCandidates().size() == 1, "and is selected");
	}
	{
		auto g = build(999, 1);
		auto c = g->mg.ComputeNaturalLoopCandidates();
		check(c.size() == 1 && !c[0].hot, "exec_freq == threshold-1 is COLD");
		check(g->mg.SelectHotNaturalLoopCandidates().empty(), "and is not selected");
		check(c[0].header_exec_freq == 999, "but it is still reported, with its real frequency");
	}
	{
		// A cold header whose body block is enormously hot. A max-over-the-region rule would
		// admit this; the header's own frequency is what decides.
		auto g = build(999, 100000000);
		auto c = g->mg.ComputeNaturalLoopCandidates();
		check(c.size() == 1 && !c[0].hot, "a hot BODY block does not make a cold header hot");
	}
	{
		// The bar moves with the compile's own --threshold and with nothing else.
		config::threshold = 999;
		auto g = build(999, 1);
		auto c = g->mg.ComputeNaturalLoopCandidates();
		check(c.size() == 1 && c[0].hot, "the same loop is HOT once --threshold is lowered to it");
	}
	{
		// A block never executed in this profile has exec_count 0 and cannot be a candidate at
		// any bar above zero -- the evidence is dynamic, not structural.
		config::threshold = 1;
		auto g = build(0, 0);
		auto c = g->mg.ComputeNaturalLoopCandidates();
		check(c.size() == 1 && !c[0].hot, "an unexecuted loop is a loop, but never a HOT candidate");
	}
}

// 6. Canonical output: sorted by header, sorted inside, and independent of insertion order.
void Test6_Canonical()
{
	section("6. the candidate set is canonical and repeatable");
	u32 const E = kBase, H = kBase + 4, L1 = kBase + 8, L2 = kBase + 12;
	auto build = [&](bool reverse_order) {
		std::vector<u32> ips{E, H, L1, L2};
		auto g = std::make_unique<Graph>(ips);
		g->Entry(E);
		g->Edge(E, H);
		g->Edge(H, L1);
		g->Edge(H, L2);
		if (reverse_order) { // the two back edges recorded the other way round
			g->Edge(L2, H);
			g->Edge(L1, H);
		} else {
			g->Edge(L1, H);
			g->Edge(L2, H);
		}
		g->Exec(H, 10);
		g->Doms();
		return g;
	};
	auto render = [](std::vector<ModuleGraph::LoopCandidate> const &cs) {
		std::string s;
		char buf[64];
		for (auto const &c : cs) {
			snprintf(buf, sizeof(buf), "%05x/%llu/%d[", c.header_ip,
				 (unsigned long long)c.header_exec_freq, (int)c.hot);
			s += buf;
			s += IpList(c.latch_ips) + "][" + IpList(c.body_ips) + "] ";
		}
		return s;
	};

	config::threshold = 5;
	auto a = build(false);
	auto b = build(true);
	auto ra = render(a->mg.ComputeNaturalLoopCandidates());
	auto rb = render(b->mg.ComputeNaturalLoopCandidates());
	checkf(ra == rb, "insertion order does not change the answer: %s", ra.c_str());
	auto ra2 = render(a->mg.ComputeNaturalLoopCandidates());
	check(ra == ra2, "calling it twice returns the same thing");

	// A single-block loop: the header IS the latch. Included because a self-edge is the one shape
	// where the body walk never runs at all.
	u32 const S = kBase + 16;
	Graph g({E, S});
	g.Entry(E);
	g.Edge(E, S);
	g.Edge(S, S);
	g.Exec(S, 10);
	g.Doms();
	auto sc = g.mg.ComputeNaturalLoopCandidates();
	checkf(sc.size() == 1, "a self-edge is one candidate (got %zu)", sc.size());
	if (sc.size() == 1) {
		check(IpList(sc[0].latch_ips) == IpList({S}), "its latch is its header");
		check(IpList(sc[0].body_ips) == IpList({S}), "its body is itself");
	}
}

// 7. It selects and nothing else.
void Test7_InertAndNeutral()
{
	section("7. the producer marks nothing and changes nothing");
	u32 const E = kBase, H = kBase + 4, B = kBase + 8, X = kBase + 12;
	auto build = [&]() {
		auto g = std::make_unique<Graph>(std::vector<u32>{E, H, B, X});
		g->Entry(E);
		g->Brind(X);
		g->Edge(E, H);
		g->Edge(H, B);
		g->Edge(B, H);
		g->Edge(B, X);
		g->Exec(E, 1);
		g->Exec(H, 100000);
		g->Exec(B, 100000);
		g->Exec(X, 1);
		return g;
	};
	// The whole observable state of a module graph node, rendered as text.
	auto snapshot = [](ModuleGraph &mg) {
		std::string s;
		char buf[256];
		for (auto const &e : mg.ip_map) {
			auto const *n = e.second.get();
			snprintf(buf, sizeof(buf),
				 "%05x brind=%d seg=%d re=%d bsrc=%d xseg=%d crit=%d fdre=%d link=%d "
				 "jt=%d loopentry=%d idf=%d exec=%llu instr=%u dom=%05x nsucc=%zu npred=%zu\n",
				 n->ip, n->flags.is_brind_target, n->flags.is_segment_entry,
				 n->flags.region_entry, n->flags.is_brind_source, n->flags.is_crosssegment_br,
				 n->flags.is_critical, n->flags.fdre_suppressed, n->flags.link_region_suppressed,
				 n->flags.jumptable_region_suppressed, n->flags.loop_entry_exposed,
				 n->flags.idf_fused, (unsigned long long)n->flags.exec_count,
				 n->flags.exec_instr_count, n->dominator ? n->dominator->ip : 0xffffffffu,
				 n->succs.size(), n->preds.size());
			s += buf;
		}
		return s;
	};

	config::threshold = 1000;
	auto g = build();
	g->Doms();
	auto before = snapshot(g->mg);
	auto cands = g->mg.ComputeNaturalLoopCandidates();
	auto hot = g->mg.SelectHotNaturalLoopCandidates();
	auto after = snapshot(g->mg);
	checkf(cands.size() == 1 && hot.size() == 1, "the graph does have a hot candidate (%zu/%zu)",
	       cands.size(), hot.size());
	check(before == after, "every flag, dominator and edge list is unchanged");

	bool any_exposed = false;
	for (auto const &e : g->mg.ip_map)
		any_exposed = any_exposed || e.second->flags.loop_entry_exposed;
	check(!any_exposed, "loop_entry_exposed is set on no node -- this checkpoint does not expose entries");

	// And the regions the compiler would form are the same whether or not the producer ran. Both
	// graphs are built from the identical description, so any difference is the producer's.
	auto render_regions = [](std::vector<std::vector<ModuleGraphNode *>> const &rs) {
		std::map<u32, std::vector<u32>> byentry;
		for (auto const &r : rs) {
			if (r.empty())
				continue;
			auto &v = byentry[r[0]->ip];
			for (auto *n : r)
				v.push_back(n->ip);
			std::sort(v.begin(), v.end());
		}
		std::string s;
		for (auto const &[entry, members] : byentry)
			s += IpList({entry}) + ":" + IpList(members) + " ";
		return s;
	};
	auto plain = build();
	auto r_plain = render_regions(plain->mg.ComputeRegions());
	auto probed = build();
	probed->Doms();
	(void)probed->mg.ComputeNaturalLoopCandidates();
	auto r_probed = render_regions(probed->mg.ComputeRegions());
	checkf(r_plain == r_probed, "region formation is identical: %s", r_plain.c_str());
	check(!r_plain.empty(), "and it did form regions (the comparison is not vacuous)");

	// The dump flag is off by default, and this test never sets it.
	check(config::dump_loop_candidates == false, "config::dump_loop_candidates defaults to off");
	check(config::dump_loop_candidates_out == nullptr, "and its output path defaults to unset");
}

// 8. CROSS-PAGE. The selector analyses ONE stitched CFG over every profiled page, so whether a loop
// is found does not depend on where the linker put its blocks.
//
// 8a builds the case that matters: a natural loop whose HEADER is on page 1 and whose LATCH is on
// page 2. Per-page graphs cannot see it at all -- the back edge's target has no node in the latch's
// own graph -- so this section is the one that fails if the whole-profile view is lost.
void Test8a_CrossPageLoop()
{
	section("8a. a natural loop whose header and latch are on different pages");
	u32 const E = kBase, H = kBase + 4, M = kBase + 8;      // page 1
	u32 const P2 = kPage2, L = kPage2 + 4, X = kPage2 + 8;  // page 2
	Graph g({E, H, M, P2, L, X});
	g.Entry(E);
	g.Edge(E, H);
	g.Edge(H, M);
	g.Edge(M, P2); // forward, across the page boundary
	g.Edge(P2, L);
	g.Edge(L, H);  // THE BACK EDGE, from page 2 to page 1
	g.Edge(L, X);
	g.Exec(E, 1);
	g.Exec(H, 5000);
	g.Exec(M, 5000);
	g.Exec(P2, 5000);
	g.Exec(L, 5000);
	g.Exec(X, 1);
	g.Doms();

	checkf((H >> 12) != (L >> 12), "the header %05x and the latch %05x really are on different pages",
	       H, L);
	auto edges = g.mg.EnumerateNaturalLoopBackEdges();
	checkf(edges.size() == 1, "the stitched graph finds the back edge (got %zu)", edges.size());
	if (edges.size() == 1)
		check(edges[0].header->ip == H && edges[0].latch->ip == L, "header on page 1, latch on page 2");

	config::threshold = 1000;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 1, "one candidate (got %zu)", cands.size());
	if (cands.size() != 1)
		return;
	auto const &c = cands[0];
	checkf(c.header_ip == H, "header=%05x", c.header_ip);
	checkf(IpList(c.body_ips) == IpList({H, M, P2, L}),
	       "body=%s -- it SPANS the two pages and sorts as one ascending list", IpList(c.body_ips).c_str());
	check(c.hot, "and it is classified against the same bar as any other candidate");
	check(g.mg.CountResolvedCrossPageEdges() == 2, "two resolved edges cross the page boundary");
	check(g.mg.UnresolvedCrossEdges().empty(), "and nothing was left unresolved");
}

// 8b. The stitch is an ORDERING property, and the builder's two phases are what create it: every
// page's nodes are recorded before any page's edges are analysed. Interleaving them reproduces the
// per-page behaviour while looking correct, so the difference is pinned here.
void Test8b_NodesBeforeEdges()
{
	section("8b. a target with no node yet becomes an unresolved edge, not a back edge");
	u32 const E = kBase, H = kBase + 4;
	u32 const L = kPage2;

	// The wrong order: page 1's edges recorded while page 2 has no nodes.
	ModuleGraph bad(qir::CodeSegment(kBase, kSize));
	bad.RecordEntry(E);
	bad.RecordEntry(H);
	bad.RecordSegmentEntry(E);
	bad.RecordGBr(E, H);
	bad.RecordGBr(H, L); // L does not exist yet
	bad.RecordEntry(L);  // ... and adding it afterwards cannot repair the edge
	bad.RecordGBr(L, H);
	bad.RecordExec(H, 4, 5000);
	auto *nh = bad.GetNode(H);
	check(nh->cross_succs.size() == 1 && nh->succs.empty(),
	      "recording the edge first leaves it in cross_succs for ever");
	checkf(bad.UnresolvedCrossEdges().size() == 1, "and it is reported as unresolved (%zu)",
	       bad.UnresolvedCrossEdges().size());

	// The builder's order: all nodes, then all edges.
	ModuleGraph good(qir::CodeSegment(kBase, kSize));
	good.RecordEntry(E);
	good.RecordEntry(H);
	good.RecordEntry(L);
	good.RecordSegmentEntry(E);
	good.RecordGBr(E, H);
	good.RecordGBr(H, L);
	good.RecordGBr(L, H);
	good.RecordExec(H, 4, 5000);
	good.ComputeDomTree();
	check(good.GetNode(H)->succs.size() == 1 && good.GetNode(H)->cross_succs.empty(),
	      "recording nodes first makes the same edge a real succ");
	config::threshold = 1000;
	auto cands = good.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 1 && cands[0].header_ip == H,
	       "and only then is the cross-page loop a candidate (%zu)", cands.size());
}

// 8c. An unresolved target is safe and is REPORTED. This is a real boundary of the evidence -- the
// guest branched somewhere this profile never went -- and not an artefact of cutting the graph up.
void Test8c_UnresolvedIsSafe()
{
	section("8c. a target that is in no page of the profile is reported, not absorbed");
	u32 const E = kBase, H = kBase + 4, B = kBase + 8;
	u32 const NEVER_RUN = kBase + 0x40;   // inside the segment, never executed -> no node
	u32 const OFF_SEGMENT = kBase - 4;    // outside the segment entirely
	Graph g({E, H, B});
	g.Entry(E);
	g.Edge(E, H);
	g.Edge(H, B);
	g.Edge(B, NEVER_RUN);
	g.Edge(B, OFF_SEGMENT);
	g.Edge(B, H);
	g.Exec(H, 5000);
	g.Doms();

	check(g.mg.GetNode(NEVER_RUN) == nullptr && g.mg.GetNode(OFF_SEGMENT) == nullptr,
	      "neither target has a node");
	auto un = g.mg.UnresolvedCrossEdges();
	checkf(un.size() == 2, "both are reported as unresolved boundary edges (%zu)", un.size());
	if (un.size() == 2) {
		check(un[0] == std::make_pair(B, OFF_SEGMENT) && un[1] == std::make_pair(B, NEVER_RUN),
		      "ascending by (source, target)");
	}
	config::threshold = 1000;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 1 && cands[0].header_ip == H,
	       "the resolvable loop is still found, and an unresolved edge creates none (%zu)", cands.size());
	check(g.mg.CountResolvedCrossPageEdges() == 0, "no page boundary was crossed by a resolved edge");
}

// 8d. Two pages must not be MIS-stitched: an edge resolves to the node at exactly its target address
// or to no node at all -- never to the nearest one, and never to a page as a whole.
void Test8d_NoMisStitch()
{
	section("8d. a cross-page edge lands on exactly its target, or nowhere");
	u32 const E = kBase, S = kBase + 4;
	u32 const P2_HEAD = kPage2, P2_MID = kPage2 + 16, P2_GAP = kPage2 + 8;
	Graph g({E, S, P2_HEAD, P2_MID});
	g.Entry(E);
	g.Brind(P2_HEAD); // page 2 has its own real entry, from the profile
	g.Edge(E, S);
	g.Edge(S, P2_MID);  // targets the MIDDLE of page 2, not its first block
	g.Edge(S, P2_GAP);  // targets a page-2 address with no node
	g.Edge(P2_HEAD, P2_MID);
	g.Exec(S, 10);
	g.Doms();

	auto *ns = g.mg.GetNode(S);
	checkf(ns->succs.size() == 1 && ns->succs[0]->ip == P2_MID,
	       "the resolved successor is exactly %05x", P2_MID);
	auto *nhead = g.mg.GetNode(P2_HEAD);
	bool head_has_s = false;
	for (auto *p : nhead->preds)
		head_has_s = head_has_s || p == ns;
	check(!head_has_s, "page 2's first block did NOT acquire the edge meant for its middle");
	auto un = g.mg.UnresolvedCrossEdges();
	checkf(un.size() == 1 && un[0] == std::make_pair(S, P2_GAP),
	       "the gap target stayed unresolved rather than snapping to a neighbour (%zu)", un.size());
	config::threshold = 1;
	check(g.mg.ComputeNaturalLoopCandidates().empty(), "and no loop was invented by the stitch");
}

// 8e. WHY THE BUILDER MUST NOT ROOT EVERY PAGE. Giving page 2 an artificial entry -- the shortcut a
// per-page builder is tempted into so that "the page is reachable" -- destroys the dominance that
// makes 8a's cross-page loop a loop. This is a correctness property, not tidiness.
void Test8e_ArtificialPageRootBreaksDominance()
{
	section("8e. an artificial per-page root entry destroys the cross-page loop");
	u32 const E = kBase, H = kBase + 4, M = kBase + 8;
	u32 const P2 = kPage2, L = kPage2 + 4;
	auto build = [&](bool artificial_page_root) {
		auto g = std::make_unique<Graph>(std::vector<u32>{E, H, M, P2, L});
		g->Entry(E);
		if (artificial_page_root)
			g->Entry(P2); // the shortcut: page 2's first block declared an entry
		g->Edge(E, H);
		g->Edge(H, M);
		g->Edge(M, P2);
		g->Edge(P2, L);
		g->Edge(L, H);
		g->Exec(H, 5000);
		g->Doms();
		return g;
	};

	config::threshold = 1000;
	auto honest = build(false);
	auto cands = honest->mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 1 && cands[0].header_ip == H,
	       "with the profile's own entries only, the cross-page loop is a candidate (%zu)", cands.size());

	check(ChainDominates(honest->mg.GetNode(H), honest->mg.GetNode(L)),
	      "because the header dominates the latch across the page boundary");

	auto rooted = build(true);
	auto rooted_cands = rooted->mg.ComputeNaturalLoopCandidates();
	check(rooted_cands.empty(),
	      "with an artificial entry into page 2, the SAME graph has no natural loop at all");
	check(rooted->mg.GetNode(P2)->dominator == rooted->mg.root.get() &&
		      !ChainDominates(rooted->mg.GetNode(H), rooted->mg.GetNode(L)),
	      "because page 2 now hangs off the root, so the header no longer dominates the latch");
}

// 8f. And the shipped node recorder does not take that shortcut: the only nodes it hands to `root`
// are the ones the profile itself marks. This runs the REAL RecordProfilePageNodes over synthetic
// pages, so a builder that rooted every page is caught here as well as by 8e.
void Test8f_PageNodesDeclareNoEntry()
{
	section("8f. RecordProfilePageNodes declares no entry the profile did not");
	auto page = std::make_unique<objprof::PageData>();
	auto page2 = std::make_unique<objprof::PageData>();
	page->pageno = kBase >> 12;
	page2->pageno = kPage2 >> 12;
	for (u32 off : {0u, 4u, 8u}) {
		page->executed[objprof::PageData::po2idx(off)] = true;
		page->exec_count[objprof::PageData::po2idx(off)] = 100;
		page->exec_instr_count[objprof::PageData::po2idx(off)] = 1;
		page2->executed[objprof::PageData::po2idx(off)] = true;
		page2->exec_count[objprof::PageData::po2idx(off)] = 100;
		page2->exec_instr_count[objprof::PageData::po2idx(off)] = 1;
	}

	ModuleGraph mg(qir::CodeSegment(kBase, kSize));
	auto ips1 = RecordProfilePageNodes(mg, *page);
	auto ips2 = RecordProfilePageNodes(mg, *page2);
	checkf(ips1.size() == 3 && ips2.size() == 3, "both pages contributed their executed blocks (%zu, %zu)",
	       ips1.size(), ips2.size());
	checkf(mg.ip_map.size() == 6, "one graph now holds both pages' nodes (%zu)", mg.ip_map.size());
	checkf(mg.root->succs.empty(),
	       "and NO node was made a root entry, because neither page declared one (%zu)",
	       mg.root->succs.size());

	// A page that DOES declare an entry gets exactly that one, so the check above is not vacuous.
	auto page3 = std::make_unique<objprof::PageData>(*page2);
	page3->pageno = (kPage2 + 0x1000) >> 12;
	page3->segment_entry[objprof::PageData::po2idx(4)] = true;
	ModuleGraph mg3(qir::CodeSegment(kPage2 + 0x1000, kPageSize));
	RecordProfilePageNodes(mg3, *page3);
	checkf(mg3.root->succs.size() == 1 && mg3.root->succs[0]->ip == kPage2 + 0x1004,
	       "a declared segment entry becomes the one root successor (%zu)", mg3.root->succs.size());
}

// 9. The report the CLI dump writes: the whole canonical file, module-level, with every loop and its
// disposition, the unresolved boundary and the stitch count.
void Test9_Report()
{
	section("9. the whole report is exactly the canonical module-level text");
	// One cold loop, one hot loop whose two latches sit on DIFFERENT pages, and one unresolved
	// boundary edge -- so the rendered text carries a COLD line, a merged cross-page HOT line and a
	// LOOPUNRESOLVED line at once.
	u32 const E = kBase, H1 = kBase + 4, L1 = kBase + 8;
	u32 const H2 = kBase + 12, La = kBase + 16;
	u32 const Lb = kPage2, NOWHERE = kPage2 + 0x100;
	Graph g({E, H1, L1, H2, La, Lb});
	g.Entry(E);
	g.Edge(E, H1);
	g.Edge(H1, L1);
	g.Edge(L1, H1);
	g.Edge(L1, H2);
	g.Edge(H2, La);
	g.Edge(H2, Lb);
	g.Edge(La, H2);
	g.Edge(Lb, H2);
	g.Edge(Lb, NOWHERE);
	g.Exec(E, 1);
	g.Exec(H1, 7);
	g.Exec(L1, 7);
	g.Exec(H2, 900000);
	g.Exec(La, 400000);
	g.Exec(Lb, 500000);
	g.Doms();

	config::threshold = 1000;
	bool const saved_prop = config::propagate_exec_count;
	config::propagate_exec_count = true; // the shipped default; the report states which it was
	ModuleGraph::LoopCandidateTotals totals;
	FILE *f = tmpfile();
	check(f != nullptr, "a temporary file to render into");
	if (!f) {
		config::propagate_exec_count = saved_prop;
		return;
	}
	g.mg.WriteLoopCandidateReport(f, &totals);
	fflush(f);
	rewind(f);
	std::string text;
	char buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		text.append(buf, n);
	fclose(f);
	config::propagate_exec_count = saved_prop;
	printf("%s", text.c_str());

	std::string const expect =
		"LOOPCAND_VERSION 2\n"
		"LOOPCAND_RULE header_dominates_latch exec_freq_ge_threshold\n"
		"LOOPCAND_EVIDENCE header_exec_freq=profile_execution_frequency_of_header_block "
		"not_backedge_taken_count not_iteration_cost not_exact_trip_count propagate_exec_count=1\n"
		"LOOPCAND_THRESHOLD 1000\n"
		"LOOPCAND_SCOPE whole_profile pages=2 nodes=6 vaddr_lo=00011000 vaddr_hi=00013000 "
		"cross_page_edges=2 unresolved=1\n"
		"LOOPUNRESOLVED src=00012000 tgt=00012100\n"
		"LOOPEDGE header=00011004 latch=00011008\n"
		"LOOPEDGE header=0001100c latch=00011010\n"
		"LOOPEDGE header=0001100c latch=00012000\n"
		"LOOPCAND header=00011004 exec_freq=7 threshold=1000 disposition=COLD nlatch=1 "
		"latches=00011008 nbody=2 body=00011004,00011008\n"
		"LOOPCAND header=0001100c exec_freq=900000 threshold=1000 disposition=HOT nlatch=2 "
		"latches=00011010,00012000 nbody=3 body=0001100c,00011010,00012000\n"
		"LOOPCAND_SUMMARY pages=2 backedges=3 loops_all=2 hot=1 cold=1 unresolved=1 "
		"cross_page_edges=2 threshold=1000\n";
	check(text == expect, "the rendered text is exactly the canonical report");
	checkf(totals.backedges == 3 && totals.loops == 2 && totals.hot == 1 && totals.cold == 1 &&
		       totals.unresolved == 1 && totals.cross_page == 2,
	       "totals: backedges=%llu loops=%llu hot=%llu cold=%llu unresolved=%llu cross_page=%llu",
	       totals.backedges, totals.loops, totals.hot, totals.cold, totals.unresolved,
	       totals.cross_page);
	check(totals.hot < totals.loops, "hot is a STRICT subset here -- the report is not expose-all");
	check(text.find("not_exact_trip_count") != std::string::npos,
	      "and the report states what the frequency is NOT, in the file itself");
}

// 10. The one precondition, and that it is fail-closed rather than silently empty.
void Test10_PreconditionIsFailClosed()
{
	section("10. asking for candidates without a dominator tree dies instead of answering");
	u32 const E = kBase, H = kBase + 4, B = kBase + 8;
	// Run in a child, because the required outcome is that the process does NOT return. Without a
	// dominator tree every node's `dominator` is null, NodeDominates answers "no" for every pair,
	// and a producer that did not check would hand back an empty candidate set that is
	// indistinguishable from a program with no loops.
	pid_t pid = fork();
	if (pid == 0) {
		Graph g({E, H, B});
		g.Entry(E);
		g.Edge(E, H);
		g.Edge(H, B);
		g.Edge(B, H);
		g.Exec(H, 1000);
		// deliberately NO g.Doms()
		auto c = g.mg.ComputeNaturalLoopCandidates();
		// Only reachable if the precondition was not enforced. Exit 0 so the parent can tell
		// this apart from the required death.
		fprintf(stderr, "child returned %zu candidates without a dominator tree\n", c.size());
		_exit(0);
	}
	check(pid > 0, "forked a child");
	if (pid < 0)
		return;
	int status = 0;
	waitpid(pid, &status, 0);
	bool died = WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0);
	checkf(died, "the child did not return an answer (status raw=%d)", status);

	// And the same graph WITH a dominator tree answers normally, so section 10 is about the
	// missing precondition and not about the graph.
	Graph g({E, H, B});
	g.Entry(E);
	g.Edge(E, H);
	g.Edge(H, B);
	g.Edge(B, H);
	g.Exec(H, 1000);
	g.Doms();
	config::threshold = 1000;
	check(g.mg.ComputeNaturalLoopCandidates().size() == 1, "with the tree, the same graph has its loop");
}

// 11. The refactor: Cycle-13's DetectNaturalLoops is the new enumerator with the latch dropped.
//
// EnumerateNaturalLoopBackEdges is not a new analysis; it is DetectNaturalLoops with the latch kept,
// and DetectNaturalLoops now calls it. Two features that ship today read DetectNaturalLoops
// (--dump-loop-vs-idf and --loop-structural-regions), so "the refactor changed nothing" is a
// regression claim and needs a check rather than a reading of the diff.
void Test11_DetectNaturalLoopsUnchanged()
{
	section("11. DetectNaturalLoops sees exactly the same loops, in the same order");
	// A graph with all four shapes at once: a nested pair, a two-latch header, a self edge, and a
	// loop that shares no block with the others -- so an ordering or filtering difference between
	// the two entry points has somewhere to show up.
	u32 const E = kBase, H1 = kBase + 4, H2 = kBase + 8, L2 = kBase + 12, L1 = kBase + 16;
	u32 const S = kBase + 20, M = kBase + 24, Ma = kBase + 28, Mb = kBase + 32;
	Graph g({E, H1, H2, L2, L1, S, M, Ma, Mb});
	g.Entry(E);
	g.Edge(E, H1);
	g.Edge(H1, H2);
	g.Edge(H2, L2);
	g.Edge(L2, H2);
	g.Edge(L2, L1);
	g.Edge(L1, H1);
	g.Edge(L1, S);
	g.Edge(S, S);
	g.Edge(S, M);
	g.Edge(M, Ma);
	g.Edge(M, Mb);
	g.Edge(Ma, M);
	g.Edge(Mb, M);
	g.Exec(H1, 10);
	g.Exec(H2, 1000);
	g.Exec(S, 55);
	g.Exec(M, 77);
	g.Doms();

	auto edges = g.mg.EnumerateNaturalLoopBackEdges();
	auto legacy = g.mg.DetectNaturalLoops();
	// L2->H2, L1->H1, S->S, Ma->M, Mb->M
	checkf(edges.size() == 5, "five back edges in this graph (got %zu)", edges.size());
	checkf(edges.size() == legacy.size(), "both entry points return the same count (%zu vs %zu)",
	       edges.size(), legacy.size());
	if (edges.size() != legacy.size())
		return;
	bool same = true;
	for (size_t i = 0; i < edges.size(); ++i) {
		same = same && edges[i].header == legacy[i].first;
		same = same && edges[i].body == legacy[i].second;
	}
	check(same, "header and body agree element by element, in order");
	config::threshold = 50;
	auto cands = g.mg.ComputeNaturalLoopCandidates();
	checkf(cands.size() == 4, "and the five collapse into four candidates (got %zu)", cands.size());
}

} // namespace

int main()
{
	// Unbuffered, so that a section that dies (section 10 forks; a broken rule can Panic) leaves
	// the output up to that point in the log instead of losing it in a stdio buffer.
	setvbuf(stdout, nullptr, _IONBF, 0);
	printf("T5d1a: canonical hot-natural-loop candidate producer\n");
	u64 const saved_threshold = config::threshold;

	Test1_RealLoop();
	Test2_RetreatingButNotNatural();
	Test3_MultiLatchMerge();
	Test4_NestedStayDistinct();
	Test5_ThresholdBoundary();
	Test6_Canonical();
	Test7_InertAndNeutral();
	Test8a_CrossPageLoop();
	Test8b_NodesBeforeEdges();
	Test8c_UnresolvedIsSafe();
	Test8d_NoMisStitch();
	Test8e_ArtificialPageRootBreaksDominance();
	Test8f_PageNodesDeclareNoEntry();
	Test9_Report();
	Test10_PreconditionIsFailClosed();
	Test11_DetectNaturalLoopsUnchanged();

	config::threshold = saved_threshold;
	printf("\nLOOPCAND_TEST checks=%d failed=%d\n", g_checks, g_failed);
	return g_failed ? 1 : 0;
}
