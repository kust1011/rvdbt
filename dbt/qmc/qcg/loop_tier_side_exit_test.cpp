// T5d2a3 focused test: the IMMEDIATE SERVICE EXIT for an intra-region direct backedge.
//
// WHAT IS BEING CLAIMED. T5d2a2's notification is raised by the backedge that observes its target
// at the compiler's bar, but on a tight loop that edge is INTRA-REGION (`Emit_br` / `Emit_brcc`'s
// taken arm; see MakeGBr) and T5d0's only legal escape is at a region-exit `gbr`. With
// `--loop-tier-side-exit` (default off) that same edge services the request itself:
//
//   (a) control reaches the host BEFORE the next instruction of the target block and BEFORE the
//       loop completes, at the exact guest PC the edge names, with the guest state committed;
//   (b) the ordinary, no-event path is unchanged -- still an in-region direct branch, no helper
//       call, no permanent region split -- and with the switch off the bytes are IDENTICAL;
//   (c) it is scoped to intra-region BACKEDGES: a `gbr` backedge (which already has T5d0's
//       safepoint at its own slot), a forward edge, a fall-through and a `jalr` get nothing;
//   (d) Execute() receives this edge's own real `BranchSlot`, so the DIRECT-edge arm runs and the
//       target is not pushed through the indirect-dispatch bookkeeping.
//
// HOW EACH ASSERTION CAN FAIL, stated because a passing test that cannot fail is not evidence:
//
//   [1] reads the QIR the REAL translator built from real RISC-V words: the conditional form must
//       be a `brcc` with `t_gbr == false` and `t_backedge == true`, and the unconditional form a
//       `br` with `backedge == true` in a region with NO `gbr` at all. Stop carrying the
//       retreating fact through MakeGBr's in-region arm and section 1 fails.
//   [2] locates the exit block in the emitted bytes by three addresses known here independently of
//       the emitter -- `&config::loop_tier_side_exits`, the `escape_link` stub, and the lazy-JIT
//       stub the BranchSlot carries -- and requires its internal ORDER, its position AFTER every
//       in-region branch, and that splicing it and its one entry `jmp` back out reproduces the
//       switch-off bytes EXACTLY. Move a store, inline the block, or disturb one other byte and
//       this section fails.
//   [3] and [4] EXECUTE real loops on the real code pool through the real trampoline. [3b] is the
//       DEFECT ITSELF, measured: with the switch off, the notification fires mid-loop and the loop
//       still runs to completion before anything returns to the host. [3c] is the fix on the same
//       loop, same bar, same everything else. [4] is the unbounded case -- a region whose ONLY
//       control transfer is its own latch, so with the switch off it contains no escape point at
//       all and could never return; [4a] proves that statically, [4b] runs it.
//   [5] pins guest registers into host registers (--qcg-pin) and requires the exit block to have
//       written them back, and runs a NON-LEAF loop (a real frame) so a missing FrameDestroy is a
//       SIGSEGV here rather than a pass.
//
// WHAT IT DELIBERATELY DOES NOT DO. It loads, announces, relinks, promotes and times nothing. It
// makes no hotness, selection or performance claim: which loop a notification leads to compiling is
// the selector's question (loop_tier_test), and the notification protocol itself is T5d2a2's
// (loop_tier_event_test). This file is about where control goes once one has been raised.

#include "dbt/aot/loop_tier.h"
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/runtime_stubs.h"
#include "dbt/tcache/tcache.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
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
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	check(ok, buf);
}

void section(char const *s)
{
	printf("\n== %s ==\n", s);
}

// ---------------------------------------------------------------------------------------------
// The fixture. Same shape as backedge_safepoint_test.cpp's and loop_tier_event_test.cpp's: the
// translator reads instructions from `vmem_base + insn_ip`, so a plain buffer indexed by the guest
// address IS the whole guest.
// ---------------------------------------------------------------------------------------------

constexpr u32 GUEST_SIZE = 0x1000;

struct Guest {
	Guest() : mem(GUEST_SIZE / 4, 0u) {}
	void put(u32 ip, u32 word)
	{
		mem[ip / 4] = word;
	}
	uptr base() const
	{
		return (uptr)mem.data();
	}
	std::vector<u32> mem;
};

u32 enc_b(u32 f3, u32 rs1, u32 rs2, int32_t off)
{
	u32 u = (u32)off;
	return (((u >> 12) & 1u) << 31) | (((u >> 5) & 0x3fu) << 25) | (rs2 << 20) | (rs1 << 15) |
	       (f3 << 12) | (((u >> 1) & 0xfu) << 8) | (((u >> 11) & 1u) << 7) | 0x63u;
}
u32 enc_j(u32 rd, int32_t off)
{
	u32 u = (u32)off;
	return (((u >> 20) & 1u) << 31) | (((u >> 1) & 0x3ffu) << 21) | (((u >> 11) & 1u) << 20) |
	       (((u >> 12) & 0xffu) << 12) | (rd << 7) | 0x6fu;
}
u32 enc_addi(u32 rd, u32 rs1, int32_t imm)
{
	return (((u32)imm & 0xfffu) << 20) | (rs1 << 15) | (0b000u << 12) | (rd << 7) | 0x13u;
}
u32 enc_jalr(u32 rd, u32 rs1, int32_t imm)
{
	return (((u32)imm & 0xfffu) << 20) | (rs1 << 15) | (0b000u << 12) | (rd << 7) | 0x67u;
}
// `vsetvli rd, rs1, e32,m1,ta,ma` -- used ONLY to force a region NON-LEAF: with every direct route
// off it lowers to an hcall into the pre-existing rv32_vsetvli helper, so QSel marks the region as
// having calls and Prologue emits a real frame push.
u32 enc_vsetvli(u32 rd, u32 rs1, u32 vtypei)
{
	return (vtypei << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
constexpr u32 F3_BNE = 0b001;

// Every switch this file depends on, pinned to its default, so nothing an earlier section set can
// change what a later one measures.
void ResetConfig()
{
	config::loop_tier = false;
	config::loop_tier_side_exit = false;
	config::loop_tier_completion_exit = false;
	config::qcg_backedge_safepoint = false;
	config::inrun_escape_unlink = false;
	config::qcg_freq_entry = false;
	config::qcg_freq_edge = false;
	config::qcg_freq_scratch = false;
	config::qcg_freq_sat = false;
	config::qcg_freq_retire = false;
	config::qcg_jal_closure = false;
	config::qcg_pin = false;
	config::qcg_pin_k = 0;
	config::qcg_resident = false;
	config::trace = false;
	config::use_aot = false;
	config::not_freq = false;
	config::rvv_direct = false;
	config::rvv_vector_ssa = false;
	config::aot_link_alias_merge = false;
	config::aot_link_multientry_merge = false;
	config::service_request.store(0, std::memory_order_relaxed);
	config::loop_tier_event_ip = 0;
	config::loop_tier_state = 0;
}

struct BufRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode: the only mode the exit is emitted in
	}
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

// The AOT producer's shape: relocatable output, compiled in one process and executed in another.
struct AotRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return true; // jit_mode == false
	}
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

// The real code pool: PROT_READ|WRITE|EXEC, the allocator Execute()'s JITCompilerRuntime uses.
struct PoolRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		return tcache::AllocateCode(sz, align);
	}
	bool AllowsRelocation() const override
	{
		return false;
	}
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override
	{
		return nullptr;
	}
};

Region *TranslateAt(MemArena &arena, Guest const &g, u32 entry, u32 n_words)
{
	CompilerJob::IpRangesSet ranges = {{entry, entry + 4 * n_words}};
	CompilerJob job(nullptr, g.base(), CodeSegment(0u, GUEST_SIZE), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

template <typename RT> std::vector<u8> EmitWith(MemArena &arena, Guest const &g, u32 entry, u32 n_words)
{
	Region *region = TranslateAt(arena, g, entry, n_words);
	CodeSegment segment(0u, GUEST_SIZE);
	RT cr;
	auto span = qcg::GenerateCode(&cr, &segment, region, entry);
	return std::vector<u8>(span.begin(), span.end());
}

std::vector<u8> EmitAt(MemArena &arena, Guest const &g, u32 entry, u32 n_words)
{
	return EmitWith<BufRuntime>(arena, g, entry, n_words);
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			n += (ins.GetOpcode() == op);
	return n;
}

std::vector<size_t> FindBytes(std::vector<u8> const &code, std::vector<u8> const &pat)
{
	std::vector<size_t> hits;
	if (pat.empty() || code.size() < pat.size())
		return hits;
	for (size_t i = 0; i + pat.size() <= code.size(); ++i)
		if (memcmp(code.data() + i, pat.data(), pat.size()) == 0)
			hits.push_back(i);
	return hits;
}

std::vector<u8> MovAbs(u8 rex, u8 op, uptr imm)
{
	std::vector<u8> p = {rex, op};
	u8 b[8];
	memcpy(b, &imm, 8);
	p.insert(p.end(), b, b + 8);
	return p;
}
std::vector<u8> MovAbsRax(uptr imm) // 48 B8
{
	return MovAbs(0x48, 0xb8, imm);
}
std::vector<u8> MovAbsR12(uptr imm) // 49 BC
{
	return MovAbs(0x49, 0xbc, imm);
}

// `mov dword ptr [r13 + offsetof(CPUState, ip)], imm32`, the exact encoding Emit_gbr's own
// alias-merge store and the T5d0 safepoint use: 41 C7 85 <disp32> <imm32>.
std::vector<u8> StoreIpImm(u32 ip)
{
	std::vector<u8> p = {0x41, 0xc7, 0x85};
	u32 disp = (u32)offsetof(CPUState, ip);
	u8 b[4];
	memcpy(b, &disp, 4);
	p.insert(p.end(), b, b + 4);
	memcpy(b, &ip, 4);
	p.insert(p.end(), b, b + 4);
	return p;
}

// Every BranchSlot in `code`, found by the lazy-JIT stub entry LinkLazyJIT writes.
std::vector<size_t> FindSlots(std::vector<u8> const &code)
{
	uptr lazy = (*RuntimeStubTab::GetGlobal())[RuntimeStubId::id_link_branch_jit];
	std::vector<size_t> hits;
	for (size_t off : FindBytes(code, MovAbsRax(lazy)))
		if (off + 12 <= code.size() && code[off + 10] == 0xff && code[off + 11] == 0xd0)
			hits.push_back(off);
	return hits;
}

// The exit block's head: `mov rax, &config::loop_tier_side_exits; inc qword ptr [rax]`. The counter
// is written by the emitted code and by nothing else, so its address cannot appear anywhere but in
// an exit block.
std::vector<size_t> FindExitCounters(std::vector<u8> const &code)
{
	std::vector<size_t> hits;
	for (size_t off : FindBytes(code, MovAbsRax((uptr)&config::loop_tier_side_exits)))
		if (off + 13 <= code.size() && code[off + 10] == 0x48 && code[off + 11] == 0xff &&
		    code[off + 12] == 0x00)
			hits.push_back(off);
	return hits;
}

// From the counter to the last byte of the block's BranchSlot: inc(13) lea(7) movabs(10) jmp(3).
constexpr size_t kExitTailLen = 13 + 7 + 10 + 3 + sizeof(jitabi::ppoint::BranchSlot);

// ---------------------------------------------------------------------------------------------
// The displacement repair used by section 2c.
//
// Inserting a `jmp rel32` in the middle of a region makes every jump whose span crosses the
// insertion point five bytes longer, so a plain splice cannot reproduce the switch-off bytes. That
// is not a licence to check something weaker: the claim is that those displacements are the ONLY
// thing that changed. `DispField` names the displacement a differing byte belongs to, by walking
// back to the jump opcode that owns it; the caller then requires the two builds' values to differ
// by exactly the five bytes it removed before accepting the repair. A byte that is not inside such
// a field, or a field whose delta is not exactly 5, fails the section.
// ---------------------------------------------------------------------------------------------

struct Field {
	size_t at;
	size_t width; // 4 or 1; 0 == "this byte is not in a jump displacement"
};

Field DispField(std::vector<u8> const &code, size_t i)
{
	for (size_t back = 1; back <= 5 && back <= i; ++back) {
		size_t p = i - back;
		if (code[p] == 0xe9 && i >= p + 1 && i < p + 5)
			return {p + 1, 4}; // jmp rel32
		if (p >= 1 && code[p - 1] == 0x0f && (code[p] & 0xf0u) == 0x80u && i >= p + 1 && i < p + 5)
			return {p + 1, 4}; // jcc rel32
		if (back == 1 && ((code[p] & 0xf0u) == 0x70u || code[p] == 0xeb))
			return {p + 1, 1}; // jcc/jmp rel8
	}
	return {0, 0};
}

long ReadDisp(std::vector<u8> const &code, Field f)
{
	if (f.width == 4) {
		int32_t v;
		memcpy(&v, code.data() + f.at, 4);
		return v;
	}
	return (int8_t)code[f.at];
}

void WriteDisp(std::vector<u8> &code, Field f, long v)
{
	if (f.width == 4) {
		int32_t w = (int32_t)v;
		memcpy(code.data() + f.at, &w, 4);
	} else {
		code[f.at] = (u8)(int8_t)v;
	}
}

// ---------------------------------------------------------------------------------------------
// The execution fixture. A loop is translated into the REAL code pool, given the L1 entry and the
// TBlock the running system would have given it, and entered through the REAL trampoline.
//
// The two outcomes are distinguishable without ambiguity, by the `gip` of the slot that comes back:
//
//   loop completed  -> the fall-through gbr's own lazy-link path returns ITS slot, gip = the
//                      instruction after the loop, and the guest counter holds the trip count;
//   side exit       -> this checkpoint's block returns the LATCH's slot, gip = the loop header,
//                      and the guest counter holds the iteration the bar was reached on.
// ---------------------------------------------------------------------------------------------

struct LoopResult {
	jitabi::ppoint::BranchSlot *slot;
	u32 ip_after;
	u32 x1;	 // the guest loop counter, out of CPUState
	u32 x3;	 // a second guest global, used by the --qcg-pin case
	unsigned long long exits;  // side exits taken during this run
	unsigned long long escapes; // T5d0 safepoint escapes during this run
	u32 svc;		    // the service word as the run left it
	TBlock *tb;
};

// `entry` must be the loop header. `bar` is installed as sr_chunk_threshold BEFORE the region is
// compiled, because the emitted evidence test bakes it as an immediate at TRANSLATION time -- so a
// bar installed after codegen would be the wrong number, silently.
LoopResult RunLoop(Guest const &g, u32 entry, u32 n_words, u32 x1_init, u32 x2_init, u64 bar,
		   u32 pending = 0)
{
	u64 bar0 = config::sr_chunk_threshold;
	config::sr_chunk_threshold = bar;

	MemArena arena(1u << 20);
	PoolRuntime cr;
	Region *region = TranslateAt(arena, g, entry, n_words);
	CodeSegment segment(0u, GUEST_SIZE);
	auto span = qcg::GenerateCode(&cr, &segment, region, entry);

	auto *tb = tcache::AllocateTBlock();
	tb->ip = entry;
	tb->tcode = TBlock::TCode{(u8 *)span.data(), (u32)span.size()};
	tb->flags.exec_count = 0;
	tcache::Insert(tb);
	// What the running system would have done on the arrival that first reached this header: the
	// L1 tag and the TBlock the counter update finds through it.
	tcache::cache_tb_exec_count[tcache::l1hash(entry)] = {entry, tb};

	CPUState state(nullptr);
	state.ip = entry;
	state.gpr[1] = x1_init;
	state.gpr[2] = x2_init;
	state.gpr[3] = 0;
	CPUState::SetCurrent(&state);

	unsigned long long e0 = config::loop_tier_side_exits;
	unsigned long long s0 = config::backedge_safepoint_escapes;
	// `pending` is what the runtime had already asked for when the loop was entered. T5d2b0's
	// completion poll reads exactly this word, so a run that starts with the loop tier's bit set is
	// a run in which the builder has already terminated.
	config::service_request.store(pending, std::memory_order_relaxed);

	auto *slot = jitabi::trampoline_to_jit(&state, nullptr, (void *)span.data());

	u32 svc = config::service_request.load(std::memory_order_relaxed);
	config::service_request.store(0, std::memory_order_relaxed);
	config::sr_chunk_threshold = bar0;
	return {slot,
		state.ip,
		state.gpr[1],
		state.gpr[3],
		config::loop_tier_side_exits - e0,
		config::backedge_safepoint_escapes - s0,
		svc,
		tb};
}

} // namespace

int main()
{
	printf("T5d2a3 loop-tier intra-region side-exit test\n");
	ResetConfig();
	tcache::Init();

	uptr const A_ESCAPE_LINK = (*RuntimeStubTab::GetGlobal())[RuntimeStubId::id_escape_link];
	uptr const A_EXITS = (uptr)&config::loop_tier_side_exits;

	// -----------------------------------------------------------------------------------------
	section("1. what the REAL translator builds: the two intra-region backedge forms");
	// -----------------------------------------------------------------------------------------
	{
		// 1a. THE CONDITIONAL FORM, and the loop this whole checkpoint is about.
		//
		//   L:  addi x1, x1, 1
		//       bne  x1, x2, L        <- taken edge stays IN-REGION (MakeGBr's ip2bb hit)
		//   X:  (outside the region)  <- the fall-through is the loop's ONLY gbr
		//
		// While the loop runs, the only edge executed is the latch. The `gbr` exists, but it is on
		// the LOOP-EXIT path: a request raised at the latch is carried to loop COMPLETION.
		Guest g;
		u32 const L = 0x0800;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, L, 2);
		checkf(CountOp(r, Op::_brcc) == 1, "the conditional loop compiles to one brcc (got %u)",
		       CountOp(r, Op::_brcc));
		InstBrcc *brcc = nullptr;
		for (auto &bb : r->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_brcc)
					brcc = static_cast<InstBrcc *>(&ins);
		check(brcc && !brcc->t_gbr, "its TAKEN arm is an in-region successor, not a gbr");
		check(brcc && brcc->t_backedge, "and it carries the retreating fact (t_backedge)");
		checkf(brcc && brcc->t_ip == L, "targeting the loop header %08x (got %08x)", L,
		       brcc ? brcc->t_ip : 0u);
		check(brcc && brcc->f_gbr, "while the FALL-THROUGH arm is the gbr -- the loop EXIT");
		checkf(CountOp(r, Op::_gbr) == 1, "so the region has exactly one gbr (got %u)",
		       CountOp(r, Op::_gbr));
	}
	{
		// 1b. THE UNCONDITIONAL FORM, and the unbounded case: a region whose ONLY control transfer
		// is its own latch. There is no gbr anywhere, so with T5d2a2 alone this program can never
		// return to Execute() -- not late, not ever.
		Guest g;
		u32 const L = 0x0900;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_j(0, -4)); // jal x0, L
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, L, 2);
		checkf(CountOp(r, Op::_br) >= 1, "the unconditional loop compiles to a br (got %u)",
		       CountOp(r, Op::_br));
		checkf(CountOp(r, Op::_gbr) == 0, "and the region has NO gbr at all (got %u)",
		       CountOp(r, Op::_gbr));
		checkf(CountOp(r, Op::_gbrind) == 0, "and no gbrind either (got %u)",
		       CountOp(r, Op::_gbrind));
		bool marked = false, targets_header = false;
		for (auto &bb : r->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_br) {
					auto *b = static_cast<InstBr *>(&ins);
					marked |= b->backedge;
					targets_header |= (b->ip == L);
				}
		check(marked, "the br carries the retreating fact (InstBr::backedge)");
		check(targets_header, "and names the loop header as its target");
	}

	// -----------------------------------------------------------------------------------------
	section("2. the emitted bytes: one jmp on the cold path, one out-of-line block, nothing else");
	// -----------------------------------------------------------------------------------------
	Guest gcond;
	u32 const CL = 0x0800;
	gcond.put(CL, enc_addi(1, 1, 1));
	gcond.put(CL + 4, enc_b(F3_BNE, 1, 2, -4));
	std::vector<u8> off_bytes, on_bytes;
	{
		config::loop_tier = true;
		config::loop_tier_side_exit = false;
		config::loop_tier_state = config::kLoopTierArmed;
		unsigned long long sites0 = config::loop_tier_side_exit_sites;
		MemArena a1(1u << 20);
		off_bytes = EmitAt(a1, gcond, CL, 2);
		checkf(config::loop_tier_side_exit_sites == sites0,
		       "switch off: not one exit site is even counted (%llu)",
		       config::loop_tier_side_exit_sites - sites0);
		check(FindExitCounters(off_bytes).empty(), "and the exit counter's address is nowhere in the code");

		config::loop_tier_side_exit = true;
		MemArena a2(1u << 20);
		on_bytes = EmitAt(a2, gcond, CL, 2);
		checkf(config::loop_tier_side_exit_sites == sites0 + 1,
		       "switch on: exactly one exit site for the one intra-region backedge (%llu)",
		       config::loop_tier_side_exit_sites - sites0);
	}
	{
		auto exits = FindExitCounters(on_bytes);
		checkf(exits.size() == 1, "the emitted code contains exactly one exit block (got %zu)",
		       exits.size());
		if (exits.size() == 1) {
			size_t head = exits[0];
			// 2a. THE ORDER INSIDE THE BLOCK. The target-PC store must come BEFORE the counter,
			// the counter before the `lea`, and the whole thing must end in the escape jump
			// followed by a real BranchSlot. Read as byte patterns, so a reordering fails here.
			auto ipst = FindBytes(on_bytes, StoreIpImm(CL));
			bool ip_before = false;
			for (size_t p : ipst)
				ip_before |= (p < head && p + 11 <= head);
			check(ip_before, "the exact target PC is stored into CPUState::ip before the counter");
			size_t p = head + 13;
			bool lea_ok = p + 7 <= on_bytes.size() && on_bytes[p] == 0x48 && on_bytes[p + 1] == 0x8d &&
				      on_bytes[p + 2] == 0x05;
			check(lea_ok, "then `lea rax, [rip + slot]`");
			p += 7;
			bool esc_ok = false;
			if (p + 10 <= on_bytes.size()) {
				auto want = MovAbsR12(A_ESCAPE_LINK);
				esc_ok = memcmp(on_bytes.data() + p, want.data(), want.size()) == 0;
			}
			check(esc_ok, "then `mov r12, qcgstub_escape_link` -- the SAME stub T5d0's escape uses");
			p += 10;
			bool jmp_ok = p + 3 <= on_bytes.size() && on_bytes[p] == 0x41 && on_bytes[p + 1] == 0xff &&
				      on_bytes[p + 2] == 0xe4;
			check(jmp_ok, "then `jmp r12`");
			p += 3;
			auto slots = FindSlots(on_bytes);
			bool slot_follows = false;
			for (size_t s : slots)
				slot_follows |= (s == p);
			check(slot_follows, "and a real BranchSlot immediately after it");
			if (slot_follows) {
				auto *bs = (jitabi::ppoint::BranchSlot const *)(on_bytes.data() + p);
				checkf(bs->gip == CL, "whose gip is THIS edge's target %08x (got %08x)", CL,
				       bs->gip);
			}
			// 2b. OUT OF LINE. Every BranchSlot the region's own blocks emitted (the loop-exit
			// gbr's) lies before the exit block; the exit block is at the end of the region.
			checkf(slots.size() == 2, "the region has two slots: the loop-exit gbr's and this one (got %zu)",
			       slots.size());
			bool after_all = true;
			for (size_t s : slots)
				if (s != p)
					after_all &= (s < head);
			check(after_all, "and the exit block lies AFTER every in-region branch -- out of line");
		}
	}
	{
		// 2c. THE ONE INSTRUCTION ON THE EDGE. Remove the out-of-line block and the single `jmp`
		// that enters it, repair the jump displacements those five removed bytes shortened, and
		// require what is left to be the switch-off bytes EXACTLY. Every repair is itself checked:
		// a differing byte that is not inside a jump displacement, or a displacement whose delta is
		// not exactly 5, fails. So "the ordinary path is unchanged" is a byte fact here, and the
		// only inserted instruction is accounted for by address.
		auto exits = FindExitCounters(on_bytes);
		bool spliced_ok = false;
		unsigned repaired = 0;
		if (exits.size() == 1) {
			size_t head = exits[0];
			size_t end = head + kExitTailLen;
			// The entry jmp: the one `jmp rel32` whose target lands just before the counter, i.e.
			// on the block's first instruction. Found by its TARGET, not by its position.
			size_t ins = 0, start = 0;
			for (size_t p = 0; p + 5 <= on_bytes.size(); ++p) {
				if (on_bytes[p] != 0xe9)
					continue;
				int32_t rel;
				memcpy(&rel, &on_bytes[p + 1], 4);
				size_t t = p + 5 + (size_t)(long)rel;
				if (t < head && t + 64 > head && t > p) {
					ins = p;
					start = t;
				}
			}
			checkf(ins != 0 && start != 0, "exactly one `jmp rel32` enters the exit block (at %zu -> %zu)",
			       ins, start);
			if (ins != 0 && start != 0 && end <= on_bytes.size() && ins + 5 <= start) {
				std::vector<u8> cut(on_bytes.begin(), on_bytes.begin() + (long)ins);
				cut.insert(cut.end(), on_bytes.begin() + (long)(ins + 5),
					   on_bytes.begin() + (long)start);
				cut.insert(cut.end(), on_bytes.begin() + (long)end, on_bytes.end());
				checkf(cut.size() == off_bytes.size(),
				       "the switch adds exactly the jmp, the block, and nothing else (%zu vs %zu)",
				       cut.size(), off_bytes.size());
				if (cut.size() == off_bytes.size()) {
					spliced_ok = true;
					for (size_t i = 0; i < cut.size(); ++i) {
						if (cut[i] == off_bytes[i])
							continue;
						Field f = DispField(cut, i);
						Field g = DispField(off_bytes, i);
						if (f.width == 0 || f.at != g.at || f.width != g.width) {
							spliced_ok = false;
							break;
						}
						long a = ReadDisp(cut, f), b = ReadDisp(off_bytes, g);
						if (a - b != 5 && b - a != 5) {
							spliced_ok = false;
							break;
						}
						WriteDisp(cut, f, b);
						repaired++;
					}
					spliced_ok = spliced_ok && (cut == off_bytes);
				}
			}
		}
		checkf(spliced_ok,
		       "removing them and repairing %u jump displacements (each by exactly 5) reproduces "
		       "the switch-off bytes EXACTLY",
		       repaired);
	}
	{
		// 2d. SCOPE. A gbr backedge, a forward edge, a fall-through and a jalr get NOTHING: the
		// first already escapes at its own slot through T5d0, and the rest are not backedges.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::qcg_backedge_safepoint = true;
		struct Case {
			char const *what;
			u32 entry, w0, w1;
			u32 n;
		};
		Guest gg;
		Case const cases[] = {
		    {"a gbr BACKedge (jal x0, -0x80)", 0x0a00, enc_j(0, -0x80), 0, 1},
		    {"a forward jal", 0x0a40, enc_j(0, 0x80), 0, 1},
		    {"a forward conditional branch", 0x0a80, enc_b(F3_BNE, 1, 2, 0x40), 0, 1},
		    {"a straight-line region's fall-through", 0x0ac0, 0x00000013u, 0x00000013u, 2},
		    {"an indirect exit (jalr)", 0x0b00, enc_jalr(0, 1, 0), 0, 1},
		};
		for (auto const &c : cases) {
			Guest g;
			g.put(c.entry, c.w0);
			if (c.n > 1)
				g.put(c.entry + 4, c.w1);
			MemArena a(1u << 20);
			auto code = EmitAt(a, g, c.entry, c.n);
			checkf(FindExitCounters(code).empty(), "%s: no exit block (found %zu)", c.what,
			       FindExitCounters(code).size());
		}
		config::qcg_backedge_safepoint = false;
	}
	{
		// 2e. THE AOT PRODUCER EMITS NONE OF IT. Every address the block bakes is this process's,
		// so a relocatable compile must not contain one.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		MemArena a(1u << 20);
		auto code = EmitWith<AotRuntime>(a, gcond, CL, 2);
		check(FindExitCounters(code).empty(), "AOT (relocatable) mode emits no exit block");
		check(FindBytes(code, MovAbsR12(A_ESCAPE_LINK)).empty(),
		      "and does not name the escape stub at all");
		check(FindBytes(code, MovAbsRax(A_EXITS)).empty(), "nor the exit counter");
	}

	// -----------------------------------------------------------------------------------------
	section("3. EXECUTED: a loop whose only gbr is its EXIT -- the defect, then the fix");
	// -----------------------------------------------------------------------------------------
	// Three runs of the SAME loop shape at three different guest addresses (each case installs its
	// own TBlock and claims its own one-shot, so sharing an address would let one case answer
	// another's question). N = 50 iterations; the bar is reached at iteration 20.
	constexpr u32 N = 50;
	constexpr u64 BAR = 20;
	{
		// 3a. BELOW THE BAR. Nothing is notified, nothing exits, the loop completes.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		Guest g;
		u32 const L = 0x0800;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		auto r = RunLoop(g, L, 2, 0, N, 1000000);
		checkf(r.x1 == N, "below the bar the loop runs to completion (x1 = %u, want %u)", r.x1, N);
		checkf(r.exits == 0, "no side exit (%llu)", r.exits);
		checkf(r.ip_after == L + 8, "and control returns at the loop EXIT %08x (got %08x)", L + 8,
		       r.ip_after);
		checkf(r.svc == 0, "with no service request raised (%08x)", r.svc);
	}
	{
		// 3b. THE DEFECT, MEASURED. Same loop, same bar, notification ON -- but the side exit OFF.
		// The request is raised at iteration 20 and the loop still runs all 50 iterations before
		// anything returns to the host. On this fixture the delay is 30 iterations because the
		// loop is short; on a loop wholly inside one region it is unbounded (section 4).
		config::loop_tier = true;
		config::loop_tier_side_exit = false;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		Guest g;
		u32 const L = 0x0840;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		auto r = RunLoop(g, L, 2, 0, N, BAR);
		checkf((r.svc & config::kSvcLoopTier) != 0, "the notification WAS raised (svc=%08x)", r.svc);
		checkf(config::loop_tier_event_ip == L, "naming the loop header %08x (got %08x)", L,
		       config::loop_tier_event_ip);
		checkf(r.exits == 0, "but no exit was taken (%llu)", r.exits);
		checkf(r.x1 == N, "and the loop ran to COMPLETION anyway (x1 = %u, want %u)", r.x1, N);
		checkf(r.ip_after == L + 8,
		       "control came back only at the loop's exit %08x, %llu iterations late (got %08x)",
		       L + 8, (unsigned long long)(N - BAR), r.ip_after);
		config::loop_tier_event_ip = 0;
	}
	{
		// 3c. THE FIX, on the same loop at the same bar.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		Guest g;
		u32 const L = 0x0880;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		auto r = RunLoop(g, L, 2, 0, N, BAR);
		checkf(r.exits == 1, "exactly one side exit was taken (%llu)", r.exits);
		checkf(r.escapes == 0, "and no T5d0 gbr safepoint escape at all (%llu)", r.escapes);
		checkf(r.ip_after == L,
		       "control returns at the LATCH'S OWN TARGET %08x -- the loop header (got %08x)", L,
		       r.ip_after);
		checkf(r.x1 == (u32)BAR,
		       "BEFORE the loop completed: the guest counter is %u, not the trip count %u",
		       r.x1, N);
		check(r.x1 < N, "i.e. the loop was interrupted, not finished");
		checkf((r.svc & config::kSvcLoopTier) != 0,
		       "the request the exit was taken for is still pending for Execute() (svc=%08x)", r.svc);
		checkf(config::loop_tier_event_ip == L, "and the mailbox names this header (%08x)",
		       config::loop_tier_event_ip);
		// 3d. WHAT Execute() RECEIVES: a real slot for THIS edge's target, so its direct-edge arm
		// runs and its own assert holds. `escape_brind` would have returned nullptr here.
		check(r.slot != nullptr, "the trampoline returns a BranchSlot, not nullptr");
		if (r.slot) {
			checkf(r.slot->gip == r.ip_after,
			       "and Execute()'s `branch_slot->gip == state->ip` holds (%08x vs %08x)",
			       r.slot->gip, r.ip_after);
			check(!r.tb->flags.is_brind_target,
			      "the target was NOT marked is_brind_target -- the direct-edge arm, not CacheBrind");
			// 3e. The loop really can resume: do what Execute() does next.
			r.slot->Link(r.tb->tcode.ptr);
			CPUState st2(nullptr);
			st2.ip = L;
			st2.gpr[1] = r.x1;
			st2.gpr[2] = N;
			CPUState::SetCurrent(&st2);
			config::service_request.store(0, std::memory_order_relaxed);
			config::loop_tier_event_ip = 0;
			unsigned long long e0 = config::loop_tier_side_exits;
			auto *again = jitabi::trampoline_to_jit(&st2, nullptr, r.tb->tcode.ptr);
			checkf(st2.gpr[1] == N, "re-entering there finishes the loop (x1 = %u)", st2.gpr[1]);
			checkf(config::loop_tier_side_exits == e0,
			       "and the one-shot is spent: it does NOT exit a second time (%llu)",
			       config::loop_tier_side_exits - e0);
			check(again != nullptr && again->gip == L + 8,
			      "the resumed loop leaves through its own exit gbr");
		}
		config::loop_tier_event_ip = 0;
	}

	// -----------------------------------------------------------------------------------------
	section("4. EXECUTED: a loop with NO gbr anywhere -- the unbounded case");
	// -----------------------------------------------------------------------------------------
	{
		// 4a. STATICALLY, with the switch off, this region has no way back to the host at all.
		// Checked rather than run, because running it would not terminate -- which is the point.
		config::loop_tier = true;
		config::loop_tier_side_exit = false;
		config::qcg_backedge_safepoint = true; // even WITH T5d0 armed
		Guest g;
		u32 const L = 0x0900;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_j(0, -4));
		MemArena a(1u << 20);
		auto code = EmitAt(a, g, L, 2);
		checkf(FindSlots(code).empty(), "switch off: the region contains NO BranchSlot (got %zu)",
		       FindSlots(code).size());
		check(FindBytes(code, MovAbsR12(A_ESCAPE_LINK)).empty(),
		      "and no reference to the escape stub -- with T5d0 armed, there is no gbr to put it on");
		check(FindExitCounters(code).empty(), "and no exit block: this loop could never return");
		config::qcg_backedge_safepoint = false;
	}
	{
		// 4b. With the switch on it returns -- at its own latch, with exact state.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		Guest g;
		u32 const L = 0x0940;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_j(0, -4)); // an infinite loop, in one region
		auto r = RunLoop(g, L, 2, 0, 0, BAR);
		checkf(r.exits == 1, "the unconditional intra-region backedge exits exactly once (%llu)",
		       r.exits);
		checkf(r.ip_after == L, "at its own target %08x (got %08x)", L, r.ip_after);
		checkf(r.x1 == (u32)BAR, "with the guest counter at the bar (x1 = %u, want %llu)", r.x1,
		       (unsigned long long)BAR);
		check(r.slot != nullptr && r.slot->gip == L, "and a real BranchSlot for that target");
		config::loop_tier_event_ip = 0;
	}

	// -----------------------------------------------------------------------------------------
	section("5. the state and the frame the exit is responsible for");
	// -----------------------------------------------------------------------------------------
	{
		// 5a. --qcg-pin holds the most-used guest globals in reserved host registers for the WHOLE
		// region: QRegAlloc::BlockBoundary deliberately does NOT write them back at an intra-region
		// branch, so they are the one thing the exit block must commit itself. The loop below
		// writes x1 AND x3 every iteration, and the pin selector's preconditions (multi-block,
		// call-free, with a backedge) are exactly this region's.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		config::qcg_pin = true;
		config::qcg_pin_k = 2;
		Guest g;
		u32 const L = 0x0980;
		g.put(L, enc_addi(1, 1, 1));	 // x1 += 1
		g.put(L + 4, enc_addi(3, 3, 7)); // x3 += 7
		g.put(L + 8, enc_b(F3_BNE, 1, 2, -8));
		{
			MemArena a(1u << 20);
			Region *rg = TranslateAt(a, g, L, 3);
			CodeSegment seg(0u, GUEST_SIZE);
			BufRuntime cr;
			(void)qcg::GenerateCode(&cr, &seg, rg, L);
			checkf(rg->n_pins > 0, "the pin selector pinned %u guest globals in this region",
			       rg->n_pins);
		}
		auto r = RunLoop(g, L, 3, 0, N, BAR);
		checkf(r.exits == 1, "one side exit (%llu)", r.exits);
		checkf(r.ip_after == L, "at the loop header %08x (got %08x)", L, r.ip_after);
		checkf(r.x1 == (u32)BAR, "and CPUState holds the PINNED x1 (%u, want %llu)", r.x1,
		       (unsigned long long)BAR);
		checkf(r.x3 == (u32)BAR * 7, "and the PINNED x3 (%u, want %llu)", r.x3,
		       (unsigned long long)BAR * 7);
		config::qcg_pin = false;
		config::qcg_pin_k = 0;
		config::loop_tier_event_ip = 0;
	}
	{
		// 5b. A NON-LEAF loop: the `vsetvli` lowers to an hcall, so QSel marks the region as having
		// calls and Prologue pushes a real frame. If the exit block did not FrameDestroy, the
		// escape stub would unwind from the wrong rsp and this process would not come back from
		// trampoline_to_jit at all -- the check below would never be reached.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		Guest g;
		u32 const L = 0x09c0;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_vsetvli(5, 6, 0x0d0)); // -> hcall: the region is NOT a leaf
		g.put(L + 8, enc_b(F3_BNE, 1, 2, -8));
		{
			MemArena a(1u << 20);
			auto code = EmitAt(a, g, L, 3);
			auto ex = FindExitCounters(code);
			checkf(ex.size() == 1, "the non-leaf region has one exit block (got %zu)", ex.size());
			// `pop rcx` is 0x59; FrameDestroy must appear inside the block, before the PC store.
			auto ipst = FindBytes(code, StoreIpImm(L));
			size_t store = 0;
			for (size_t q : ipst)
				if (!ex.empty() && q < ex[0])
					store = q;
			bool popped = false;
			if (store > 0)
				for (size_t i = store > 16 ? store - 16 : 0; i < store; ++i)
					popped |= (code[i] == 0x59);
			check(popped, "and a `pop rcx` (FrameDestroy) inside it, ahead of the PC store");
		}
		auto r = RunLoop(g, L, 3, 0, N, BAR);
		check(r.slot != nullptr, "the trampoline returned -- the stack unwound correctly");
		checkf(r.exits == 1, "one side exit (%llu)", r.exits);
		checkf(r.ip_after == L, "at the loop header %08x (got %08x)", L, r.ip_after);
		checkf(r.x1 == (u32)BAR, "with the guest counter at the bar (%u)", r.x1);
		config::loop_tier_event_ip = 0;
	}
	{
		// 5c. The rule the emitted block implements is looptier::ShouldNotify, unchanged: an exit
		// can only follow a notification, so every state that refuses a notification refuses an
		// exit. Driven here through the same function the generated code's four guards implement.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		struct St {
			char const *name;
			int st;
		};
		St const terminal[] = {{"BUILDING", (int)looptier::State::BUILDING},
				       {"PUBLISHED", (int)looptier::State::PUBLISHED},
				       {"FAILED", (int)looptier::State::FAILED},
				       {"ABSTAINED", (int)looptier::State::ABSTAINED}};
		u32 L = 0x0b40;
		for (auto const &s : terminal) {
			config::loop_tier_state = s.st;
			config::loop_tier_event_ip = 0;
			Guest g;
			g.put(L, enc_addi(1, 1, 1));
			g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
			auto r = RunLoop(g, L, 2, 0, N, BAR);
			checkf(r.exits == 0 && r.x1 == N, "%s: no exit, the loop completes (exits=%llu x1=%u)",
			       s.name, r.exits, r.x1);
			L += 0x40;
		}
		// ...and the same loop with the tier ARMED still exits, so those zeros are not vacuous.
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		Guest g;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		auto r = RunLoop(g, L, 2, 0, N, BAR);
		checkf(r.exits == 1 && r.x1 == (u32)BAR,
		       "ARMED: the same loop DOES exit (exits=%llu x1=%u) -- the zeros above are real",
		       r.exits, r.x1);
		config::loop_tier_event_ip = 0;
	}

	// -----------------------------------------------------------------------------------------
	section("6. the two configurations the exit refuses to be emitted in");
	// -----------------------------------------------------------------------------------------
	{
		// Both refusals are fail-closed, and both are about a precondition of the block rather
		// than about the loop tier. `looptier::Arm` refuses to arm a run that asks for either, so
		// a run cannot silently fall back to T5d2a2's later-gbr behaviour while its command line
		// says otherwise; these two checks are the emitter's half of the same refusal.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		{
			// --trace: Emit_Cache's own trace block pops the region's alignment push without a
			// matching one, so `rsp` at an intra-region branch is NOT the region-entry level the
			// escape stub unwinds from.
			config::trace = true;
			MemArena a(1u << 20);
			auto code = EmitAt(a, gcond, CL, 2);
			check(FindExitCounters(code).empty(), "--trace: no exit block is emitted at all");
			config::trace = false;
		}
		{
			// --rvv-vector-ssa: the one route that keeps architectural VECTOR state live past a
			// guest-instruction boundary, so a value the guest can observe could still be in a
			// host register at the latch.
			config::rvv_vector_ssa = true;
			MemArena a(1u << 20);
			auto code = EmitAt(a, gcond, CL, 2);
			check(FindExitCounters(code).empty(), "--rvv-vector-ssa: no exit block is emitted at all");
			config::rvv_vector_ssa = false;
		}
		{
			// ...and with neither set, the same region does emit one, so the two zeros above are
			// refusals rather than a fixture that never had an exit to begin with.
			MemArena a(1u << 20);
			auto code = EmitAt(a, gcond, CL, 2);
			checkf(FindExitCounters(code).size() == 1,
			       "with neither set the same region emits one (got %zu) -- the zeros are refusals",
			       FindExitCounters(code).size());
		}
	}

	// -----------------------------------------------------------------------------------------
	section("7. T5d2b0: while BUILDING, the child's completion is what hands control back");
	// -----------------------------------------------------------------------------------------
	// THE GAP. Once the tier is BUILDING its notification is spent BY DESIGN -- the one-shot is
	// claimed and T5d2a2's ARMED guard makes the generated code silent -- and a second hotness
	// event is deliberately impossible. So with T5d2a3 alone, a loop that stays inside one region
	// keeps running and the parent never learns that its builder finished. `--loop-tier-completion
	// -exit` (default off) adds ONE poll of the service word, after the evidence test and before
	// the ARMED test, into the SAME exit block the notification path uses.
	//
	// Every case below is BUILDING with the target's one-shot ALREADY CLAIMED, so nothing here can
	// be produced by a notification: the only thing that can hand control back is the completion.
	constexpr u32 N7 = 50;
	constexpr u64 BAR7 = 20;
	{
		// 7a. THE GAP ITSELF, MEASURED. Completion switch OFF, a completion pending: the loop still
		// runs to completion. This is T5d2a3's behaviour and it is what the checkpoint closes.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_completion_exit = false;
		config::loop_tier_state = (int)looptier::State::BUILDING;
		config::loop_tier_event_ip = 0;
		Guest g;
		u32 const L = 0x0c00;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		*config::LoopTierNotifySlot(L) = 1; // the one-shot is spent: no notification is possible
		auto r = RunLoop(g, L, 2, 0, N7, BAR7, config::kSvcLoopTier);
		checkf(r.exits == 0, "completion switch off: no exit, even with a completion pending (%llu)",
		       r.exits);
		checkf(r.x1 == N7, "...the loop runs to COMPLETION (x1=%u)", r.x1);
		checkf(r.ip_after == L + 8, "...and control comes back only at the loop's exit %08x", L + 8);
	}
	{
		// 7b. THE FIX, same loop, same state, same spent one-shot.
		config::loop_tier_completion_exit = true;
		config::loop_tier_state = (int)looptier::State::BUILDING;
		Guest g;
		u32 const L = 0x0c40;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		*config::LoopTierNotifySlot(L) = 1;
		unsigned long long c0 = config::loop_tier_completion_exits;
		auto r = RunLoop(g, L, 2, 0, N7, BAR7, config::kSvcLoopTier);
		checkf(r.exits == 1, "a pending completion takes exactly one exit (%llu)", r.exits);
		checkf(config::loop_tier_completion_exits == c0 + 1,
		       "...counted as a COMPLETION exit, not as a notification one (%llu)",
		       config::loop_tier_completion_exits - c0);
		checkf(r.ip_after == L, "...at the latch's own target %08x (got %08x)", L, r.ip_after);
		checkf(r.x1 == (u32)BAR7, "...BEFORE the loop completed (x1=%u, trip count %u)", r.x1, N7);
		check(r.slot != nullptr && r.slot->gip == L,
		      "...through the same legal exit: a real BranchSlot for that target");
		checkf(config::loop_tier_event_ip == 0,
		       "...and NO notification was raised: the mailbox is untouched (%08x)",
		       config::loop_tier_event_ip);
	}
	{
		// 7c. NO COMPLETION, NO EXIT. Same everything, an empty service word.
		config::loop_tier_completion_exit = true;
		config::loop_tier_state = (int)looptier::State::BUILDING;
		Guest g;
		u32 const L = 0x0c80;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		*config::LoopTierNotifySlot(L) = 1;
		auto r = RunLoop(g, L, 2, 0, N7, BAR7, 0);
		checkf(r.exits == 0, "no completion pending: no exit (%llu)", r.exits);
		checkf(r.x1 == N7, "...the loop runs to completion (x1=%u)", r.x1);
	}
	{
		// 7d. THE EXIT IS NOT REPEATED. The consumer clears the word (Execute() does it before
		// Service()), and nothing can set it again: the only writers are the emitted notification --
		// which needs ARMED and an unclaimed one-shot -- and the SIGCHLD handler, which needs a
		// child. So re-entering the same loop with the word clear runs it to the end.
		config::loop_tier_completion_exit = true;
		config::loop_tier_state = (int)looptier::State::BUILDING;
		Guest g;
		u32 const L = 0x0cc0;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		*config::LoopTierNotifySlot(L) = 1;
		auto r = RunLoop(g, L, 2, 0, N7, BAR7, config::kSvcLoopTier);
		checkf(r.exits == 1 && r.x1 == (u32)BAR7, "one completion -> one exit (%llu, x1=%u)",
		       r.exits, r.x1);
		// Only re-enter through the EXIT BLOCK's own slot. Linking whatever came back would, when
		// the exit did not happen, link the loop-EXIT gbr's slot to the loop entry and spin for
		// ever -- a hang instead of a reported failure, which is not a usable negative control.
		if (r.exits == 1 && r.slot != nullptr && r.slot->gip == L) {
			// What Execute() does next: clear the request, service it, link and resume.
			r.slot->Link(r.tb->tcode.ptr);
			CPUState st2(nullptr);
			st2.ip = L;
			st2.gpr[1] = r.x1;
			st2.gpr[2] = N7;
			CPUState::SetCurrent(&st2);
			config::service_request.store(0, std::memory_order_relaxed);
			unsigned long long e0 = config::loop_tier_side_exits;
			auto *again = jitabi::trampoline_to_jit(&st2, nullptr, r.tb->tcode.ptr);
			checkf(st2.gpr[1] == N7, "...and with the word cleared the loop FINISHES (x1=%u)",
			       st2.gpr[1]);
			checkf(config::loop_tier_side_exits == e0,
			       "...taking no further exit: the completion is not repeated (%llu)",
			       config::loop_tier_side_exits - e0);
			check(again != nullptr && again->gip == L + 8, "...and leaves by its own exit gbr");
		}
	}
	{
		// 7e. NO BUILD OUTSTANDING, NO COMPLETION EXIT -- EVEN WITH THE WORD SET.
		//
		// THIS IS THE REVIEWER-FOUND DEFECT, and it is a real one rather than a tidiness point.
		// SIGCHLD is process-wide, so ANY unrelated host child terminating raises this same word.
		// Without a `state == BUILDING` test in the emitted poll, a tier that had already finished
		// -- PUBLISHED, FAILED, ABSTAINED -- or one that had not started -- ARMED -- would hand
		// control back for a builder completion that cannot exist. Each state is driven with the
		// word DELIBERATELY SET, which is exactly what the old code could not survive.
		config::loop_tier_completion_exit = true;
		u32 L = 0x0d00;
		struct StCase {
			char const *name;
			int st;
		};
		StCase const nonbuilding[] = {{"PUBLISHED", (int)looptier::State::PUBLISHED},
					      {"FAILED", (int)looptier::State::FAILED},
					      {"ABSTAINED", (int)looptier::State::ABSTAINED},
					      {"ARMED", config::kLoopTierArmed}};
		for (auto const &c : nonbuilding) {
			config::loop_tier_state = c.st;
			config::loop_tier_event_ip = 0;
			Guest g;
			g.put(L, enc_addi(1, 1, 1));
			g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
			*config::LoopTierNotifySlot(L) = 1; // spent, so no notification is possible either
			unsigned long long c0 = config::loop_tier_completion_exits;
			auto r = RunLoop(g, L, 2, 0, N7, BAR7, config::kSvcLoopTier);
			checkf(r.exits == 0 && config::loop_tier_completion_exits == c0 && r.x1 == N7,
			       "%s with the word SET: no completion exit, the loop completes (%llu, x1=%u)",
			       c.name, r.exits, r.x1);
			L += 0x40;
		}
		// ...and the same loop in BUILDING with the same word DOES exit, so those zeros are a
		// refusal and not a fixture that could never have exited.
		config::loop_tier_state = (int)looptier::State::BUILDING;
		Guest gb;
		gb.put(L, enc_addi(1, 1, 1));
		gb.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		*config::LoopTierNotifySlot(L) = 1;
		auto rb = RunLoop(gb, L, 2, 0, N7, BAR7, config::kSvcLoopTier);
		checkf(rb.exits == 1 && rb.x1 == (u32)BAR7,
		       "BUILDING with the same word DOES exit (%llu, x1=%u) -- the zeros above are real",
		       rb.exits, rb.x1);
		L += 0x40;

		// 7e2. MODE OFF. The poll is not even emitted, so a pending word cannot move it.

		config::loop_tier = false; // mode off: the whole block, poll included, is not emitted
		Guest g2;
		u32 const L2 = L;
		g2.put(L2, enc_addi(1, 1, 1));
		g2.put(L2 + 4, enc_b(F3_BNE, 1, 2, -4));
		{
			MemArena a(1u << 20);
			auto code = EmitAt(a, g2, L2, 2);
			// `movabs rsi, &service_request` is the poll's first instruction and appears
			// nowhere else in an intra-region region's code.
			check(FindBytes(code, MovAbs(0x48, 0xbe, (uptr)config::ServiceRequestWordAddr()))
				  .empty(),
			      "mode off: the completion poll is not emitted at all");
		}
		auto r2 = RunLoop(g2, L2, 2, 0, N7, BAR7, config::kSvcLoopTier);
		checkf(r2.exits == 0 && r2.x1 == N7,
		       "...so a pending word moves nothing (%llu, x1=%u)", r2.exits, r2.x1);
		config::loop_tier = true;
	}
	{
		// 7f. THE POLL IS AFTER THE EVIDENCE TEST, so a target BELOW the bar pays nothing new and
		// cannot exit however loudly the runtime is asking. This is what keeps the cost on the one
		// loop the run has already admitted evidence for.
		config::loop_tier = true;
		config::loop_tier_completion_exit = true;
		config::loop_tier_state = (int)looptier::State::BUILDING;
		Guest g;
		u32 const L = 0x0d80;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		*config::LoopTierNotifySlot(L) = 1;
		auto r = RunLoop(g, L, 2, 0, N7, 1000000, config::kSvcLoopTier);
		checkf(r.exits == 0 && r.x1 == N7,
		       "below the bar, a pending completion takes no exit (%llu, x1=%u)", r.exits, r.x1);
	}
	{
		// 7g. ONE BLOCK, TWO ENTRIES. The completion poll and the notification jump to the SAME
		// out-of-line block: one BranchSlot, one target guest PC, one place the state is committed.
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_completion_exit = true;
		config::loop_tier_state = config::kLoopTierArmed;
		Guest g;
		u32 const L = 0x0dc0;
		g.put(L, enc_addi(1, 1, 1));
		g.put(L + 4, enc_b(F3_BNE, 1, 2, -4));
		MemArena a(1u << 20);
		auto code = EmitAt(a, g, L, 2);
		auto ex = FindExitCounters(code);
		checkf(ex.size() == 1, "still exactly ONE exit block (got %zu)", ex.size());
		auto slots = FindSlots(code);
		checkf(slots.size() == 2, "and still two BranchSlots: the loop-exit gbr's and the block's "
					  "(got %zu)", slots.size());
		// Two `jmp rel32` now land on the block's first instruction, not one.
		size_t head = ex.empty() ? 0 : ex[0];
		unsigned entries = 0;
		long tgt = -1;
		for (size_t q = 0; q + 5 <= code.size(); ++q) {
			if (code[q] != 0xe9)
				continue;
			int32_t rel;
			memcpy(&rel, &code[q + 1], 4);
			long t = (long)(q + 5) + rel;
			if (t < (long)head && t + 64 > (long)head && t > (long)q) {
				entries++;
				if (tgt < 0)
					tgt = t;
				else
					check(t == tgt, "...and both enter it at the SAME first instruction");
			}
		}
		checkf(entries == 2, "two entries into the one block: the poll and the notification (%u)",
		       entries);
	}

	ResetConfig();
	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_failed);
	printf("%s\n", g_failed ? "LOOPTIER_SIDE_EXIT_TEST FAIL" : "LOOPTIER_SIDE_EXIT_TEST PASS");
	return g_failed ? 1 : 0;
}
