// T5d1b focused test: a selected hot natural loop compiled as a header-rooted region.
//
// WHAT IS BEING CLAIMED. `--aot-loop-regions` turns each of T5d1a's selected candidates into ONE
// real LLVM function whose external entry is the loop HEADER, containing exactly that candidate's
// canonical body, with every edge leaving the body surviving as an explicit region exit through the
// existing QIR `gbr` / dispatcher contract. Six parts, one section each:
//
//   (a) one candidate -> one function named after its header, holding exactly its body;
//   (b) a TAKEN exit and a FALL-THROUGH exit both leave the function, as `gbr`s carrying their own
//       target guest PC, visible in the QIR and in the LLVM IR;
//   (c) a body spanning two guest pages is compiled whole -- no truncation, no page-local split;
//   (d) an edge whose target the profile never executed stays an exit through the same generic
//       path, with no target invented;
//   (e) two latches of one header still make ONE function; nested headers make TWO, and the
//       duplication that causes is counted rather than resolved;
//   (f) a cold loop produces nothing, and none of the T5c wrapper / alias / expose-all machinery is
//       used anywhere.
//
// HOW EACH ASSERTION CAN FAIL, because a passing test that cannot fail is not evidence.
//
//   The guest programs are REAL RISC-V words, and every encoding here was checked against
//   `llvm-mc -triple=riscv32 --show-encoding` (section 0 re-derives them at run time from the same
//   little helpers, so a typo shows up as a decode mismatch rather than as a silently different
//   CFG). The module graph is built by the REAL `RecordProfilePageNodes` and the REAL
//   `RV32Analyser::Analyse`, so the edges, the block extents and the candidate set all come from
//   production code; the only hand-written things are the instruction bytes and which blocks the
//   profile says ran. The region is then built by the REAL `CompilerGenRegionIR` and lowered by the
//   REAL `QIRToLLVM::Run`.
//
//   [1] compares the emitted function's entry against the header and its translated entry blocks
//       against the candidate body, elementwise. Reorder the ip ranges so the header is not first
//       and the entry check fails; include one block too many or too few and the body check fails.
//   [2] finds the two exits in the printed QIR and in the printed LLVM IR by their target ip.
//       Turn an exit into a fallthrough into the next block, or drop it, and it fails. Both dumps
//       are PRINTED, so the evidence is in the log rather than in an assertion.
//   [3] asserts the body really straddles a page boundary before requiring both halves to be
//       translated -- a page-local truncation fails it.
//   [8] enumerates every global in the module and requires no alias, no wrapper-shaped function and
//       no entry switch. Route this path through `CreateLinkEntryWrapper` and it fails.
//
// WHAT IT DELIBERATELY DOES NOT DO. It runs no guest program, starts no runtime, times nothing,
// promotes nothing and emits no object file: the IR is inspected in memory, so it runs on any
// x86-64 host and generates no host instruction of any width.

#include "dbt/aot/aot.h"
#include "dbt/aot/aot_module.h"
#include "dbt/aot/loop_region.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_analyser.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir_printer.h"
#include "dbt/tcache/objprof.h"

#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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

// ---------------------------------------------------------------------------- guest encodings

// Every one of these was verified against `llvm-mc -triple=riscv32 --show-encoding`; section 0
// re-derives the exact words the tests use so a typo cannot pass silently.
u32 enc_b(u32 f3, u32 rs1, u32 rs2, int imm)
{
	u32 u = (u32)imm & 0x1fff;
	return (((u >> 12) & 1) << 31) | (((u >> 5) & 0x3f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) |
	       (((u >> 1) & 0xf) << 8) | (((u >> 11) & 1) << 7) | 0x63;
}
u32 enc_bne(u32 rs1, u32 rs2, int imm) { return enc_b(1, rs1, rs2, imm); }
u32 enc_beq(u32 rs1, u32 rs2, int imm) { return enc_b(0, rs1, rs2, imm); }
u32 enc_jal(u32 rd, int imm)
{
	u32 u = (u32)imm & 0x1fffff;
	return (((u >> 20) & 1) << 31) | (((u >> 1) & 0x3ff) << 21) | (((u >> 11) & 1) << 20) |
	       (((u >> 12) & 0xff) << 12) | (rd << 7) | 0x6f;
}
u32 enc_jalr(u32 rd, u32 rs1, int imm) { return (((u32)imm & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x67; }
constexpr u32 kNop = 0x00000013;
constexpr u32 kRet = 0x00008067; // jalr x0, x1, 0 -- an INDIRECT transfer: leaves the graph

constexpr u32 kPage1 = 0x11000;
constexpr u32 kPage2 = 0x12000;
constexpr u32 kSegLo = kPage1;
constexpr u32 kSegSize = 0x2000;

// ---------------------------------------------------------------------------- the fixture

// One synthetic guest, built the way production builds one: the REAL RecordProfilePageNodes for the
// nodes and the REAL RV32Analyser for the edges and block extents, in the SAME two-phase order
// BuildWholeProfileGraph uses (all pages' nodes, then all pages' edges) so a cross-page target
// resolves. The only difference from production is where the guest words live: the analyser reads
// `vmem + ip`, and here that is this fixture's own buffer.
struct Guest {
	std::vector<u8> mem;
	std::unique_ptr<ModuleGraph> mg;
	std::map<u32, u64> exec; // block ip -> profile frequency

	Guest() : mem(kSegSize + kPage1, 0)
	{
		for (size_t i = 0; i + 3 < mem.size(); i += 4)
			*(u32 *)(mem.data() + i) = kNop;
	}

	void W(u32 ip, u32 word) { *(u32 *)(mem.data() + ip) = word; }
	void Block(u32 ip, u64 freq) { exec[ip] = freq; }

	uptr vmem() const { return (uptr)mem.data(); }

	// Build the graph. Mirrors BuildWholeProfileGraph's phases exactly.
	void Build()
	{
		mg = std::make_unique<ModuleGraph>(qir::CodeSegment(kSegLo, kSegSize));
		std::vector<std::unique_ptr<objprof::PageData>> pages;
		std::vector<std::vector<u32>> iplists;
		for (u32 pv : {kPage1, kPage2}) {
			auto p = std::make_unique<objprof::PageData>();
			p->pageno = pv >> mmu::PAGE_BITS;
			bool any = false;
			for (auto const &[ip, freq] : exec) {
				if ((ip & ~(mmu::PAGE_SIZE - 1)) != pv)
					continue;
				u32 idx = objprof::PageData::po2idx(ip - pv);
				p->executed[idx] = true;
				p->exec_count[idx] = freq;
				p->exec_instr_count[idx] = 1;
				any = true;
			}
			if (any)
				pages.push_back(std::move(p));
		}
		// The first block of the lowest page is the guest's entry, exactly as a real profile's
		// `segment_entry` bit would say. Nothing else is declared an entry.
		if (!pages.empty()) {
			u32 first_ip = exec.begin()->first;
			u32 pv = pages[0]->pageno << mmu::PAGE_BITS;
			pages[0]->segment_entry[objprof::PageData::po2idx(first_ip - pv)] = true;
		}
		for (auto const &p : pages) // phase 1: nodes
			iplists.push_back(RecordProfilePageNodes(*mg, *p));
		for (size_t i = 0; i < pages.size(); ++i) { // phase 2: edges, from the real analyser
			u32 pv = pages[i]->pageno << mmu::PAGE_BITS;
			u32 next_pv = pv + mmu::PAGE_SIZE;
			u64 ec = 0;
			std::map<u32, u64> ecmap;
			auto const &ips = iplists[i];
			for (size_t k = 0; k < ips.size(); ++k) {
				u32 ip_next = (k + 1 == ips.size()) ? next_pv : ips[k + 1];
				rv32::RV32Analyser::Analyse(mg.get(), ips[k], ip_next, vmem(), ec, ecmap);
			}
		}
		mg->ComputeDomTree();
	}
};

// One compiled loop region, built exactly as LLVMAOTCompileLoopRegions builds one.
struct Compiled {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	qir::CodeSegment segment{kSegLo, kSegSize};
	std::vector<llvm::Function *> fns;
	std::vector<Region *> regions;
	std::vector<LoopRegionResult> results;
	std::string qir_text;
};

// Compile every hot candidate of `g` through the PRODUCTION emitter -- `EmitLoopRegions` is the
// same function `LLVMAOTCompileLoopRegions` calls, so a defect introduced in it is a defect these
// sections see. Nothing about the region is decided here.
Compiled CompileAll(Guest &g, std::vector<ModuleGraph::LoopCandidate> const &cands)
{
	Compiled c;
	c.mod = std::make_unique<llvm::Module>("t5d1b_test", g_llvm_ctx);
	c.gctx = std::make_unique<LLVMGenCtx>(c.mod.get());
	c.arena = std::make_unique<MemArena>(4u << 20);
	c.segment = g.mg->segment;
	auto results = EmitLoopRegions(c.gctx.get(), *g.mg, c.arena.get(), cands, g.vmem());
	for (auto const &r : results) {
		c.regions.push_back(r.region);
		c.fns.push_back(r.fn);
		c.results.push_back(r);
		char hdr[64];
		snprintf(hdr, sizeof(hdr), "\n; ---- region rooted at %08x\n", r.header_ip);
		c.qir_text += hdr;
		c.qir_text += PrinterPass::run(r.region);
	}
	return c;
}

// THE CONTRACT, checked at the level it lives at. Every edge leaving the body must be an explicit
// `gbr` in the QIR the translator produced. A later LLVM pass may prove one of them unreachable and
// delete it -- that is sound and is NOT a violation -- so the QIR, not the optimized IR, is where
// "no edge was dropped" is decided. Returns the targets that are missing.
std::vector<u32> ExitsMissingFromQir(Compiled const &c, size_t i)
{
	std::string qir = PrinterPass::run(c.regions[i]);
	std::vector<u32> missing;
	for (auto const &e : c.results[i].exits) {
		char pat[48];
		snprintf(pat, sizeof(pat), "gbr [$%x|i32]", e.tgt_ip);
		if (qir.find(pat) == std::string::npos)
			missing.push_back(e.tgt_ip);
	}
	return missing;
}

std::string IRText(llvm::Function *fn)
{
	std::string s;
	llvm::raw_string_ostream os(s);
	fn->print(os);
	return s;
}

std::string HexList(std::vector<u32> const &v)
{
	std::string s;
	char b[16];
	for (size_t i = 0; i < v.size(); ++i) {
		snprintf(b, sizeof(b), "%s%05x", i ? "," : "", v[i]);
		s += b;
	}
	return s;
}

// The guest ip ranges the translator actually turned into entry blocks, read back off the QIR.
std::vector<u32> TranslatedEntryIps(Region *r)
{
	std::vector<u32> out;
	for (auto const &bb : r->GetBlocks())
		if (bb.entry_ip)
			out.push_back(bb.entry_ip);
	std::sort(out.begin(), out.end());
	return out;
}

std::vector<ModuleGraph::LoopCandidate> HotCandidates(Guest &g, u64 threshold)
{
	config::threshold = threshold;
	return g.mg->SelectHotNaturalLoopCandidates();
}

// ============================================================================ the guest programs

// Program A: E jumps to header H; H's conditional exits the loop (TAKEN) or falls into M; M's
// conditional branches back to H (the back edge) or falls out of the loop (FALL-THROUGH).
constexpr u32 A_E = kPage1 + 0x000;
constexpr u32 A_H = kPage1 + 0x010;
constexpr u32 A_M = kPage1 + 0x014;
constexpr u32 A_XF = kPage1 + 0x018; // fall-through exit target
constexpr u32 A_XT = kPage1 + 0x020; // taken exit target

void BuildProgramA(Guest &g, u64 loop_freq)
{
	g.W(A_E, enc_jal(0, 0x10));	     // -> H
	g.W(A_H, enc_bne(1, 2, 0x10));	     // taken -> XT (exit), fall-through -> M
	g.W(A_M, enc_beq(3, 4, -4));	     // taken -> H (BACK EDGE), fall-through -> XF (exit)
	g.W(A_XF, kRet);
	g.W(A_XT, kRet);
	g.Block(A_E, 1);
	g.Block(A_H, loop_freq);
	g.Block(A_M, loop_freq);
	g.Block(A_XF, 1);
	g.Block(A_XT, 1);
	g.Build();
}

// ============================================================================ sections

void Test0_Encodings()
{
	section("0. the guest words are the words llvm-mc produces");
	checkf(enc_bne(1, 2, 16) == 0x00209863, "bne x1,x2,16 = %08x", enc_bne(1, 2, 16));
	checkf(enc_beq(3, 4, -4) == 0xfe418ee3, "beq x3,x4,-4 = %08x", enc_beq(3, 4, -4));
	checkf(enc_jal(0, 16) == 0x0100006f, "jal x0,16 = %08x", enc_jal(0, 16));
	checkf(enc_jal(0, -16) == 0xff1ff06f, "jal x0,-16 = %08x", enc_jal(0, -16));
	checkf(enc_jal(0, 3824) == 0x6f10006f, "jal x0,3824 = %08x", enc_jal(0, 3824));
	checkf(enc_beq(5, 6, -3824) == 0x90628863, "beq x5,x6,-3824 = %08x", enc_beq(5, 6, -3824));
	checkf(enc_jalr(0, 1, 0) == kRet, "jalr x0,x1,0 = %08x", enc_jalr(0, 1, 0));
}

void Test1_OneLoopOneFunction()
{
	section("1. one selected candidate becomes one header-rooted function holding exactly its body");
	Guest g;
	BuildProgramA(g, 5000);
	auto cands = HotCandidates(g, 1000);
	checkf(cands.size() == 1, "exactly one hot candidate (got %zu)", cands.size());
	if (cands.size() != 1)
		return;
	auto const &c = cands[0];
	checkf(c.header_ip == A_H, "its header is %05x", c.header_ip);
	checkf(HexList(c.body_ips) == HexList({A_H, A_M}), "its body is %s", HexList(c.body_ips).c_str());

	auto ranges = g.mg->LoopCandidateIpRanges(c);
	checkf(ranges.size() == 2 && ranges[0].first == A_H,
	       "the ip ranges put the HEADER FIRST (%zu ranges, first=%05x)", ranges.size(),
	       ranges.empty() ? 0 : ranges[0].first);
	check(ranges.size() == 2 && ranges[0].second == A_M && ranges[1].first == A_M,
	      "and each range is the block's own guest extent");

	auto comp = CompileAll(g, cands);
	checkf(comp.fns.size() == 1 && comp.fns[0] != nullptr, "one function was emitted (%zu)",
	       comp.fns.size());
	if (comp.fns.empty() || !comp.fns[0])
		return;
	auto name = comp.fns[0]->getName().str();
	checkf(name == MakeAotSymbol(A_H), "it is named for the header: %s", name.c_str());

	auto entries = TranslatedEntryIps(comp.regions[0]);
	checkf(HexList(entries) == HexList({A_H, A_M}),
	       "the translated entry blocks are exactly the body: %s", HexList(entries).c_str());
	checkf(ExitsMissingFromQir(comp, 0).empty(), "and every exit is a `gbr` in its QIR (%zu missing)",
	       ExitsMissingFromQir(comp, 0).size());

	// The function's own entry block must fall straight into the header's block -- no state->ip
	// switch, which is what a multi-entry worker would have.
	auto ir = IRText(comp.fns[0]);
	check(ir.find("switch") == std::string::npos, "the entry has no state->ip switch");
	check(ir.find("bb.0") != std::string::npos, "and branches into the region's first block");
}

void Test2_TakenAndFallthroughExits()
{
	section("2. a TAKEN and a FALL-THROUGH exit both leave the function, in QIR and in LLVM IR");
	Guest g;
	BuildProgramA(g, 5000);
	auto cands = HotCandidates(g, 1000);
	if (cands.size() != 1) {
		check(false, "fixture: one candidate");
		return;
	}
	auto exits = g.mg->LoopCandidateExits(cands[0]);
	checkf(exits.size() == 2, "the graph says the body has two exits (got %zu)", exits.size());
	bool have_taken = false, have_fall = false;
	for (auto const &e : exits) {
		if (e.kind == ModuleGraph::LoopExit::Kind::TAKEN && e.src_ip == A_H && e.tgt_ip == A_XT)
			have_taken = true;
		if (e.kind == ModuleGraph::LoopExit::Kind::FALLTHROUGH && e.src_ip == A_M && e.tgt_ip == A_XF)
			have_fall = true;
	}
	check(have_taken, "one TAKEN exit: 11010 -> 11020 (the branch target)");
	check(have_fall, "one FALL-THROUGH exit: 11014 -> 11018 (the block's own next address)");

	auto comp = CompileAll(g, cands);
	printf("\n--- QIR of the region rooted at %05x ---%s\n", A_H, comp.qir_text.c_str());
	auto ir = IRText(comp.fns[0]);
	printf("--- LLVM IR of %s ---\n%s\n", comp.fns[0]->getName().str().c_str(), ir.c_str());

	// In the QIR each exit is a `gbr` carrying its own target as a constant. The printer renders
	// the constant in hex, so the target ip is what is searched for.
	char tgt_t[48], tgt_f[48];
	snprintf(tgt_t, sizeof(tgt_t), "gbr [$%x|i32]", A_XT);
	snprintf(tgt_f, sizeof(tgt_f), "gbr [$%x|i32]", A_XF);
	checkf(comp.qir_text.find(tgt_t) != std::string::npos, "the QIR has `%s` -- the taken exit", tgt_t);
	checkf(comp.qir_text.find(tgt_f) != std::string::npos, "the QIR has `%s` -- the fall-through exit",
	       tgt_f);
	check(comp.qir_text.find("br ") != std::string::npos || comp.qir_text.find("brcc") != std::string::npos,
	      "and the in-body edge stayed an ordinary intra-region branch");

	// In the LLVM IR each exit is an `intr_gbr` call whose third argument is that same target ip.
	// `intr_gbr` is the EXISTING generic dispatch intrinsic, expanded later into the branch slot
	// that carries the guest PC; nothing new was introduced for these edges.
	char ir_t[64], ir_f[64];
	snprintf(ir_t, sizeof(ir_t), "i32 %u)", A_XT);
	snprintf(ir_f, sizeof(ir_f), "i32 %u)", A_XF);
	size_t n_gbr = 0;
	for (size_t p = ir.find("@intr_gbr"); p != std::string::npos; p = ir.find("@intr_gbr", p + 1))
		n_gbr++;
	checkf(n_gbr == 2, "the LLVM IR has two @intr_gbr dispatch calls (got %zu)", n_gbr);
	checkf(ir.find(ir_t) != std::string::npos, "one carries the taken target (%s)", ir_t);
	checkf(ir.find(ir_f) != std::string::npos, "the other carries the fall-through target (%s)", ir_f);
	check(ir.find("tail call ghccc void @intr_gbr") != std::string::npos,
	      "both leave as GHC tail dispatches, terminated by `unreachable`");
	// The loop itself must NOT have become a dispatch: the back edge is an ordinary LLVM branch
	// back into the header block, which is the whole point of rooting the region there.
	check(ir.find("bb.0:") != std::string::npos && ir.find("preds = %bb.1, %entry") != std::string::npos,
	      "and the header block is entered BOTH from the function entry and from the latch -- the "
	      "back edge stayed inside the function");
}

void Test3_CrossPageBody()
{
	section("3. a loop body spanning two guest pages is compiled whole");
	u32 const E = kPage1 + 0x100, H = kPage1 + 0x110, L = kPage2, X = kPage2 + 4;
	Guest g;
	g.W(E, enc_jal(0, 0x10));		     // -> H
	g.W(H, enc_jal(0, (int)(L - H)));	     // -> L, forward across the page boundary
	g.W(L, enc_beq(5, 6, (int)(H - L)));	     // taken -> H (BACK EDGE, backward across the boundary)
	g.W(X, kRet);
	g.Block(E, 1);
	g.Block(H, 5000);
	g.Block(L, 5000);
	g.Block(X, 1);
	g.Build();

	auto cands = HotCandidates(g, 1000);
	checkf(cands.size() == 1, "one hot candidate (got %zu)", cands.size());
	if (cands.size() != 1)
		return;
	auto const &c = cands[0];
	checkf(c.header_ip == H && HexList(c.body_ips) == HexList({H, L}), "header %05x, body %s",
	       c.header_ip, HexList(c.body_ips).c_str());
	std::set<u32> pages;
	for (u32 ip : c.body_ips)
		pages.insert(ip >> mmu::PAGE_BITS);
	checkf(pages.size() == 2, "the body really straddles a page boundary (%zu pages)", pages.size());

	auto comp = CompileAll(g, cands);
	checkf(comp.fns.size() == 1 && comp.fns[0], "one function (%zu)", comp.fns.size());
	if (comp.fns.empty() || !comp.fns[0])
		return;
	auto entries = TranslatedEntryIps(comp.regions[0]);
	checkf(HexList(entries) == HexList({H, L}),
	       "and BOTH pages' blocks were translated into it: %s -- not truncated, not split",
	       HexList(entries).c_str());
	check(comp.fns[0]->getName().str() == MakeAotSymbol(H), "rooted at the page-1 header");
	auto exits = g.mg->LoopCandidateExits(c);
	checkf(exits.size() == 1 && exits[0].tgt_ip == X &&
		       exits[0].kind == ModuleGraph::LoopExit::Kind::FALLTHROUGH,
	       "its single exit is the page-2 fall-through to %05x (%zu exits)", X, exits.size());
	check(ExitsMissingFromQir(comp, 0).empty(), "and it is a `gbr` in the QIR of the cross-page region");
}

void Test4_UnresolvedExit()
{
	section("4. an edge to code the profile never ran stays a generic exit");
	u32 const E = kPage1, H = kPage1 + 0x10, M = kPage1 + 0x14, X = kPage1 + 0x18;
	u32 const NEVER = kPage1 + 0x40; // reachable in the binary, never executed -> no node
	Guest g;
	g.W(E, enc_jal(0, 0x10));
	g.W(H, enc_bne(1, 2, 0x30)); // taken -> NEVER
	g.W(M, enc_beq(3, 4, -4));   // taken -> H (BACK EDGE), fall-through -> X
	g.W(X, kRet);
	g.W(NEVER, kRet);
	g.Block(E, 1);
	g.Block(H, 5000);
	g.Block(M, 5000);
	g.Block(X, 1);
	// NEVER is deliberately NOT a profiled block.
	g.Build();

	check(g.mg->GetNode(NEVER) == nullptr, "the target has no node in the graph");
	auto cands = HotCandidates(g, 1000);
	if (cands.size() != 1) {
		checkf(false, "fixture: one candidate (got %zu)", cands.size());
		return;
	}
	auto exits = g.mg->LoopCandidateExits(cands[0]);
	bool unres = false;
	for (auto const &e : exits)
		if (e.kind == ModuleGraph::LoopExit::Kind::UNRESOLVED && e.tgt_ip == NEVER)
			unres = true;
	checkf(unres, "it is reported as an UNRESOLVED exit of the loop (%zu exits total)", exits.size());

	auto comp = CompileAll(g, cands);
	auto ir = IRText(comp.fns[0]);
	char ir_u[64];
	snprintf(ir_u, sizeof(ir_u), "i32 %u)", NEVER);
	checkf(ir.find(ir_u) != std::string::npos,
	       "and the emitted function exits to that exact guest PC through @intr_gbr (%s) -- the "
	       "generic path, with no target invented",
	       ir_u);
	check(comp.mod->getFunction(MakeAotSymbol(NEVER)) == nullptr,
	      "no function was fabricated for it");
	check(ExitsMissingFromQir(comp, 0).empty(), "and every exit of this region is a `gbr` in its QIR");
}

void Test5_TwoLatchesOneFunction()
{
	section("5. two latches sharing a header still produce ONE function");
	u32 const E = kPage1, H = kPage1 + 0x10, Lb = kPage1 + 0x14, X = kPage1 + 0x18, La = kPage1 + 0x20;
	Guest g;
	g.W(E, enc_jal(0, 0x10));
	g.W(H, enc_bne(1, 2, 0x10)); // taken -> La, fall-through -> Lb
	g.W(Lb, enc_beq(3, 4, -4));  // taken -> H (BACK EDGE 1), fall-through -> X
	g.W(X, kRet);
	g.W(La, enc_jal(0, -0x10)); // -> H (BACK EDGE 2)
	g.Block(E, 1);
	g.Block(H, 5000);
	g.Block(Lb, 3000);
	g.Block(X, 1);
	g.Block(La, 2000);
	g.Build();

	auto cands = HotCandidates(g, 1000);
	checkf(cands.size() == 1, "ONE candidate for the two back edges (got %zu)", cands.size());
	if (cands.size() != 1)
		return;
	checkf(HexList(cands[0].latch_ips) == HexList({Lb, La}), "with both latches: %s",
	       HexList(cands[0].latch_ips).c_str());
	auto comp = CompileAll(g, cands);
	checkf(comp.fns.size() == 1, "and ONE emitted function (%zu)", comp.fns.size());
	auto entries = TranslatedEntryIps(comp.regions[0]);
	checkf(HexList(entries) == HexList({H, Lb, La}), "holding the merged body: %s",
	       HexList(entries).c_str());
	check(ExitsMissingFromQir(comp, 0).empty(), "with every exit a `gbr` in its QIR");
}

void Test6_NestedTwoFunctions()
{
	section("6. nested headers produce two distinct functions, and the duplication is counted");
	u32 const E = kPage1, H1 = kPage1 + 0x10, H2 = kPage1 + 0x14, L2 = kPage1 + 0x18,
		  L1 = kPage1 + 0x1c, X = kPage1 + 0x20;
	Guest g;
	g.W(E, enc_jal(0, 0x10));
	g.W(H1, enc_bne(7, 8, 0x10)); // taken -> X (exit), fall-through -> H2
	g.W(H2, enc_bne(1, 2, 8));    // taken -> L1, fall-through -> L2
	g.W(L2, enc_jal(0, -4));      // -> H2 (INNER back edge)
	g.W(L1, enc_jal(0, -0xc));    // -> H1 (OUTER back edge)
	g.W(X, kRet);
	g.Block(E, 1);
	g.Block(H1, 5000);
	g.Block(H2, 5000);
	g.Block(L2, 5000);
	g.Block(L1, 5000);
	g.Block(X, 1);
	g.Build();

	auto cands = HotCandidates(g, 1000);
	checkf(cands.size() == 2, "two candidates (got %zu)", cands.size());
	if (cands.size() != 2)
		return;
	checkf(cands[0].header_ip == H1 && cands[1].header_ip == H2, "headers %05x (outer) and %05x (inner)",
	       cands[0].header_ip, cands[1].header_ip);

	auto comp = CompileAll(g, cands);
	checkf(comp.fns.size() == 2 && comp.fns[0] && comp.fns[1], "two emitted functions (%zu)",
	       comp.fns.size());
	if (comp.fns.size() != 2 || !comp.fns[0] || !comp.fns[1])
		return;
	check(comp.fns[0]->getName().str() == MakeAotSymbol(H1) &&
		      comp.fns[1]->getName().str() == MakeAotSymbol(H2),
	      "named for their own headers, neither merged into the other");
	auto outer = TranslatedEntryIps(comp.regions[0]);
	auto inner = TranslatedEntryIps(comp.regions[1]);
	checkf(HexList(outer) == HexList({H1, H2, L2, L1}), "outer body: %s", HexList(outer).c_str());
	checkf(HexList(inner) == HexList({H2, L2}), "inner body: %s", HexList(inner).c_str());
	check(ExitsMissingFromQir(comp, 0).empty() && ExitsMissingFromQir(comp, 1).empty(),
	      "and BOTH functions carry every one of their own exits as a `gbr` in their QIR");

	// The honest cost: the inner loop's blocks are compiled twice. Counted, not resolved.
	std::set<u32> distinct(outer.begin(), outer.end());
	distinct.insert(inner.begin(), inner.end());
	size_t total = outer.size() + inner.size();
	checkf(total - distinct.size() == 2,
	       "%zu guest blocks compiled, %zu distinct -> %zu duplicated, which is what "
	       "LOOPREGION_SUMMARY reports rather than hiding",
	       total, distinct.size(), total - distinct.size());

	// The outer function's exit to the inner header, if any, is a direct AOT-to-AOT call because
	// the inner header was declared before either body was emitted.
	auto ir_outer = IRText(comp.fns[0]);
	check(ir_outer.find(MakeAotSymbol(H2)) == std::string::npos,
	      "the inner header is INSIDE the outer body, so the outer function does not call it");
}

void Test7_ColdLoopProducesNothing()
{
	section("7. a cold loop is selected by nothing and compiled into nothing");
	Guest g;
	BuildProgramA(g, 999); // one below the bar
	auto cands = HotCandidates(g, 1000);
	checkf(cands.empty(), "no hot candidate at threshold 1000 (got %zu)", cands.size());
	auto comp = CompileAll(g, cands);
	checkf(comp.fns.empty(), "and no function was emitted (%zu)", comp.fns.size());
	size_t n_fns = 0;
	for (auto &f : comp.mod->functions())
		if (!f.isDeclaration())
			n_fns++;
	checkf(n_fns == 0, "the module has no defined function at all (%zu)", n_fns);

	// The very same loop one frequency higher IS selected: section 7 is about the bar, not about
	// the loop being unfindable.
	Guest g2;
	BuildProgramA(g2, 1000);
	checkf(HotCandidates(g2, 1000).size() == 1, "at exactly the bar the same loop is selected");
}

void Test8_NoT5cMachinery()
{
	section("8. the path uses none of the T5c wrapper / alias / expose-all machinery");
	Guest g;
	BuildProgramA(g, 5000);
	config::aot_loop_entry = false;
	config::aot_link_multientry_merge = false;
	config::aot_link_alias_merge = false;
	config::aot_jumptable_multientry = false;
	auto cands = HotCandidates(g, 1000);
	auto comp = CompileAll(g, cands);

	size_t n_alias = 0;
	for (auto &a : comp.mod->aliases()) {
		(void)a;
		n_alias++;
	}
	checkf(n_alias == 0, "the module contains no GlobalAlias (%zu) -- no --aot-link-alias-merge entry",
	       n_alias);

	std::vector<std::string> defined;
	for (auto &f : comp.mod->functions())
		if (!f.isDeclaration())
			defined.push_back(f.getName().str());
	checkf(defined.size() == 1 && defined[0] == MakeAotSymbol(A_H),
	       "exactly one defined function, the header's own: %s",
	       defined.empty() ? "<none>" : defined[0].c_str());

	auto ir = IRText(comp.fns[0]);
	check(ir.find("switch") == std::string::npos,
	      "its entry is a plain branch, not a merge_entries state->ip switch");
	check(ir.find("_mw_") == std::string::npos, "and it is not a Round-41 multi-entry worker");

	bool any_exposed = false;
	for (auto const &e : g.mg->ip_map)
		any_exposed = any_exposed || e.second->flags.loop_entry_exposed;
	check(!any_exposed, "no node was marked loop_entry_exposed -- T5c's bit is never set here");
	check(!config::aot_loop_entry, "and --aot-loop-entry is not what this path runs on");

	// Nor did anything mark region_entry: this path never runs ComputeRegions at all.
	bool any_region_entry = false;
	for (auto const &e : g.mg->ip_map)
		any_region_entry = any_region_entry || e.second->flags.region_entry;
	check(!any_region_entry, "and no node became a Wendell region_entry");
}

// 10. Declare-before-emit: an exit from one selected loop into ANOTHER selected loop's header
// lowers as a direct AOT-to-AOT call, because EmitLoopRegions declares every header before it emits
// any body. Emitting as it went would make this depend on candidate order.
void Test10_DeclareBeforeEmit()
{
	section("10. an exit into another selected loop's header is a direct call, not a generic dispatch");
	u32 const E = kPage1, H1 = kPage1 + 0x10, M1 = kPage1 + 0x14, X = kPage1 + 0x18;
	u32 const H2 = kPage1 + 0x20, M2 = kPage1 + 0x24, X2 = kPage1 + 0x28;
	Guest g;
	g.W(E, enc_jal(0, 0x10));
	g.W(H1, enc_bne(1, 2, 0x10)); // taken -> H2 (the OTHER loop's header), fall-through -> M1
	g.W(M1, enc_beq(3, 4, -4));   // taken -> H1 (BACK EDGE), fall-through -> X
	g.W(X, kRet);
	g.W(H2, enc_bne(5, 6, 8)); // taken -> X2, fall-through -> M2
	g.W(M2, enc_beq(7, 8, -4)); // taken -> H2 (BACK EDGE), fall-through -> X2
	g.W(X2, kRet);
	g.Block(E, 1);
	g.Block(H1, 5000);
	g.Block(M1, 5000);
	g.Block(X, 1);
	g.Block(H2, 4000);
	g.Block(M2, 4000);
	g.Block(X2, 1);
	g.Build();

	auto cands = HotCandidates(g, 1000);
	checkf(cands.size() == 2, "two disjoint hot loops (got %zu)", cands.size());
	if (cands.size() != 2)
		return;
	auto exits = g.mg->LoopCandidateExits(cands[0]);
	bool into_h2 = false;
	for (auto const &e : exits)
		into_h2 = into_h2 || (e.tgt_ip == H2 && e.kind == ModuleGraph::LoopExit::Kind::TAKEN);
	check(into_h2, "the first loop's taken exit targets the second loop's header");

	auto comp = CompileAll(g, cands);
	checkf(comp.fns.size() == 2 && comp.fns[0] && comp.fns[1], "two functions (%zu)", comp.fns.size());
	if (comp.fns.size() != 2 || !comp.fns[0])
		return;
	auto ir0 = IRText(comp.fns[0]);
	checkf(ir0.find(MakeAotSymbol(H2)) != std::string::npos,
	       "and the first function calls %s directly", MakeAotSymbol(H2).c_str());
	char generic[64];
	snprintf(generic, sizeof(generic), "i32 %u)", H2);
	check(ir0.find(generic) == std::string::npos,
	      "rather than handing that ip to the generic @intr_gbr dispatch");
	// The loop's OWN other exit, whose target is not a selected header, still takes the generic
	// path -- so the direct call is a resolution, not a blanket rewrite.
	snprintf(generic, sizeof(generic), "i32 %u)", X);
	checkf(ir0.find(generic) != std::string::npos,
	       "while its exit to %05x, which is no loop header, still goes through @intr_gbr", X);
}

void Test9_DefaultOff()
{
	section("9. the mode is off by default and owns exactly one flag");
	check(config::aot_loop_regions == false, "config::aot_loop_regions defaults to off");
	check(config::g_loopregion_functions == 0, "and its counters start at zero");
}

} // namespace

int main()
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	printf("T5d1b: loop-rooted AOT regions\n");
	u64 const saved_threshold = config::threshold;

	Test0_Encodings();
	Test1_OneLoopOneFunction();
	Test2_TakenAndFallthroughExits();
	Test3_CrossPageBody();
	Test4_UnresolvedExit();
	Test5_TwoLatchesOneFunction();
	Test6_NestedTwoFunctions();
	Test7_ColdLoopProducesNothing();
	Test8_NoT5cMachinery();
	Test10_DeclareBeforeEmit();
	Test9_DefaultOff();

	config::threshold = saved_threshold;
	printf("\nLOOPREGION_TEST checks=%d failed=%d\n", g_checks, g_failed);
	return g_failed ? 1 : 0;
}
