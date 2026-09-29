// T5d-0 focused test: the QCG direct-backedge runtime safepoint.
//
// WHAT IS BEING CLAIMED. `--qcg-backedge-safepoint` (default off) makes a QCG direct BACKWARD
// region exit ask, before it takes its branch slot, whether the runtime wants control back; and if
// it does, leave translated code for Execute() carrying that edge's own target guest PC. The
// claim has four parts, and this file is organised so each one has a section that FAILS when that
// part is broken:
//
//   (a) only backward direct edges carry it -- forward direct edges, the region-boundary
//       fallthrough and every indirect/return edge are untouched;
//   (b) with the flag off nothing changes at all, byte for byte;
//   (c) the escape is control-flow correct: it happens BEFORE the target block runs, it hands
//       Execute() the right guest PC and the right BranchSlot, and the host stack it leaves
//       behind is the one Execute()'s trampoline built;
//   (d) it escapes when, and only when, a runtime-service request the Execute() loop already
//       consumes is pending.
//
// HOW EACH ASSERTION CAN FAIL, stated because a passing test that cannot fail is not evidence:
//
//   [2] reads InstGBr::backedge off regions built by the REAL translator from real RISC-V words.
//       Mark a forward edge and section 2 fails; stop marking the backward one and it fails.
//   [3] emits the same region twice with the flag off, once with the backedge bit set and once
//       clear, and requires byte equality. Emit anything under the flag-off path and it fails.
//   [4] finds the safepoint in the emitted bytes by the ADDRESS of config::service_request, and
//       requires (i) exactly one on the backward edge, (ii) none on the forward edge, the
//       fallthrough or the jalr region, (iii) its conditional branch to land exactly on the
//       BranchSlot's first byte, and (iv) splicing it out to reproduce the flag-off bytes
//       EXACTLY. Move the safepoint anywhere else in the block, or let it disturb one other
//       byte, and (iii) or (iv) fails.
//   [5]-[9] EXECUTE the emitted code on the real code pool through the real
//       jitabi::trampoline_to_jit, with a real target block that records that it ran. The two
//       outcomes are distinguishable without ambiguity: an escape returns the BranchSlot and
//       leaves the target's counter at zero, while a normal traversal links the slot, runs the
//       target and returns nullptr through the target's own escape. Break the frame teardown and
//       the process dies here rather than passing.
//   [10] drives every runtime-service flag Execute() consumes and requires the aggregate word to
//       follow it. Add a seventh request as a plain bool and section 10's enumeration no longer
//       covers it -- which is why the source-level check that no such bool exists lives in the
//       verifier, not here.
//
// WHAT IT DELIBERATELY DOES NOT DO. It runs no guest program, times nothing, and makes no claim
// about hotness, region selection, promotion or performance. It also never calls, reads or
// perturbs tcache::UnlinkRecorded / esc_link_ring -- section 11 asserts that the T5c escape ring
// stayed untouched through every case above, so "this is not the T5c workaround renamed" is a
// measured fact here rather than a statement in a document.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"
#include "dbt/qmc/runtime_stubs.h"
#include "dbt/tcache/tcache.h"

#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <sys/time.h>
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

double now_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// The signal side of section 10b. Shaped like the real keeper: it ONLY sets, never clears, and it
// raises the flag before publishing the fact that it did, so a reader that sees `g_svc_sets > 0`
// knows the flag was set at least once.
volatile sig_atomic_t g_svc_sets = 0;
void svc_set_handler(int)
{
	dbt::config::inrun_poll_due = true;
	g_svc_sets = g_svc_sets + 1;
}

// ---------------------------------------------------------------------------------------------
// 1. RISC-V encodings, and the predicate that reads them.
// ---------------------------------------------------------------------------------------------

u32 enc_b(u32 funct3, u32 rs1, u32 rs2, i32 imm)
{
	u32 u = (u32)imm;
	return (((u >> 12) & 1u) << 31) | (((u >> 5) & 0x3fu) << 25) | (rs2 << 20) | (rs1 << 15) |
	       (funct3 << 12) | (((u >> 1) & 0xfu) << 8) | (((u >> 11) & 1u) << 7) | 0x63u;
}

u32 enc_j(u32 rd, i32 imm)
{
	u32 u = (u32)imm;
	return (((u >> 20) & 1u) << 31) | (((u >> 1) & 0x3ffu) << 21) | (((u >> 11) & 1u) << 20) |
	       (((u >> 12) & 0xffu) << 12) | (rd << 7) | 0x6fu;
}

// `vsetvli rd, rs1, e32, m1, ta, ma` -- used only to force a region to be NON-LEAF, because with
// every direct-route switch off it lowers to an hcall into the pre-existing rv32_vsetvli helper.
u32 enc_vsetvli(u32 rd, u32 rs1, u32 vtypei)
{
	return (vtypei << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}

// `jalr rd, rs1, imm` -- the INDIRECT transfer, present so section 4 can show that a region whose
// exit is indirect gets no safepoint at all.
u32 enc_jalr(u32 rd, u32 rs1, i32 imm)
{
	return (((u32)imm & 0xfffu) << 20) | (rs1 << 15) | (0b000u << 12) | (rd << 7) | 0x67u;
}

constexpr u32 F3_BEQ = 0b000, F3_BNE = 0b001;

// ---------------------------------------------------------------------------------------------
// Region fixtures.
//
// GUEST_BASE is not zero on purpose: a backward branch needs somewhere below it to point at, and
// an address that underflows u32 would make the test's own arithmetic the thing under test. The
// translator reads instructions from `vmem_base + insn_ip`, so the fixture buffer is indexed by
// the guest address directly.
// ---------------------------------------------------------------------------------------------

constexpr u32 GUEST_SIZE = 0x1000;
constexpr u32 GUEST_BASE = 0x0800; // region entry: 2 KiB into the fixture

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

// The whole switch surface this test depends on, pinned to its default value, so a stray global
// left over from an earlier section cannot change what a later one measures.
void ResetConfig()
{
	config::qcg_backedge_safepoint = false;
	config::inrun_escape_unlink = false;
	config::aot_link_alias_merge = false;
	config::aot_link_multientry_merge = false;
	config::qcg_freq_entry = false;
	config::qcg_freq_edge = false;
	config::qcg_freq_scratch = false;
	config::qcg_freq_retire = false;
	config::qcg_jal_closure = false;
	config::subst_stable_jalr = false;
	config::aot_direct_call_fusion = false;
	config::aot_return_directify = false;
	config::shadow_edges = false;
	config::shadow_edges2 = false;
	config::trace = false;
	config::use_aot = false;
	config::rvv_direct = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = false;
	config::service_request.store(0, std::memory_order_relaxed);
}

Region *TranslateAt(MemArena &arena, Guest const &g, u32 entry, u32 n_words)
{
	CompilerJob::IpRangesSet ranges = {{entry, entry + 4 * n_words}};
	CompilerJob job(nullptr, g.base(), CodeSegment(0u, GUEST_SIZE), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

std::vector<InstGBr *> CollectGBr(Region *region)
{
	std::vector<InstGBr *> out;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_gbr)
				out.push_back(static_cast<InstGBr *>(&ins));
		}
	}
	return out;
}

InstGBr *FindGBr(Region *region, u32 target)
{
	for (auto *g : CollectGBr(region))
		if (g->tpc.GetConst() == target)
			return g;
	return nullptr;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			n += (ins.GetOpcode() == op);
	return n;
}

// AllocateCode resizes a vector; nothing this runtime produces is ever executed. Sections 3 and 4
// use it, sections 5-9 use the real code pool instead.
struct BufRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode: exactly the mode the safepoint is scoped to
	}
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

// The real code pool: PROT_READ|WRITE|EXEC, the same allocator Execute()'s JITCompilerRuntime uses.
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

std::vector<u8> EmitAt(MemArena &arena, Guest const &g, u32 entry, u32 n_words, BufRuntime &cr)
{
	Region *region = TranslateAt(arena, g, entry, n_words);
	CodeSegment segment(0u, GUEST_SIZE);
	auto span = qcg::GenerateCode(&cr, &segment, region, entry);
	return std::vector<u8>(span.begin(), span.end());
}

// ---------------------------------------------------------------------------------------------
// Byte-level location of the safepoint and of the branch slot.
//
// Both are found by an ADDRESS that is known here independently of the emitter: the safepoint by
// &config::service_request, the slot by the lazy-JIT stub entry that BranchSlot::LinkLazyJIT
// writes. Neither search can drift with a change to the surrounding code, and neither can be
// satisfied by an unrelated instruction that happens to have the same opcode.
// ---------------------------------------------------------------------------------------------

std::vector<size_t> FindMovRaxImm(std::vector<u8> const &code, uptr imm)
{
	std::vector<size_t> hits;
	u8 pat[10] = {0x48, 0xb8};
	memcpy(pat + 2, &imm, 8);
	for (size_t i = 0; i + sizeof pat <= code.size(); ++i)
		if (memcmp(code.data() + i, pat, sizeof pat) == 0)
			hits.push_back(i);
	return hits;
}

std::vector<size_t> FindSlots(std::vector<u8> const &code)
{
	uptr lazy = (*RuntimeStubTab::GetGlobal())[RuntimeStubId::id_link_branch_jit];
	std::vector<size_t> hits;
	for (size_t off : FindMovRaxImm(code, lazy))
		if (off + 12 <= code.size() && code[off + 10] == 0xff && code[off + 11] == 0xd0)
			hits.push_back(off);
	return hits;
}

std::vector<size_t> FindSafepoints(std::vector<u8> const &code)
{
	return FindMovRaxImm(code, (uptr)config::ServiceRequestWordAddr());
}

// Decode the `cmp dword ptr [rax], 0` + conditional branch that follows a safepoint head, and
// return the absolute offset the branch lands on. `ok` is false if the shape is not the one the
// emitter is supposed to produce.
size_t SafepointBranchTarget(std::vector<u8> const &code, size_t head, bool &ok)
{
	ok = false;
	size_t p = head + 10;
	if (p + 3 > code.size() || code[p] != 0x83 || code[p + 1] != 0x38 || code[p + 2] != 0x00)
		return 0; // not `cmp dword ptr [rax], 0`
	p += 3;
	if (p + 2 <= code.size() && code[p] == 0x74) { // je rel8
		ok = true;
		return p + 2 + (size_t)(i8)code[p + 1];
	}
	if (p + 6 <= code.size() && code[p] == 0x0f && code[p + 1] == 0x84) { // je rel32
		i32 rel;
		memcpy(&rel, code.data() + p + 2, 4);
		ok = true;
		return p + 6 + (size_t)rel;
	}
	return 0;
}

// ---------------------------------------------------------------------------------------------
// Execution fixture (sections 5-9).
// ---------------------------------------------------------------------------------------------

unsigned long long g_target_ran = 0;

// A hand-assembled "target block": count one execution, then leave translated code through the
// SAME escape stub the indirect slowpath uses. Written as literal bytes rather than through an
// assembler so the reader can check the stack contract by eye:
//
//   48 b8 <&g_target_ran>   mov  rax, imm64
//   48 ff 00                inc  qword ptr [rax]
//   48 b8 <escape_brind>    mov  rax, imm64
//   ff e0                   jmp  rax
//
// It is entered by a `jmp` from a linked BranchSlot, so its rsp is the region-entry rsp that
// qcgstub_escape_brind unwinds from -- the same precondition the safepoint's own escape relies on.
void *BuildTargetBlock()
{
	u8 code[25];
	size_t n = 0;
	uptr counter = (uptr)&g_target_ran;
	uptr esc = (*RuntimeStubTab::GetGlobal())[RuntimeStubId::id_escape_brind];
	code[n++] = 0x48;
	code[n++] = 0xb8;
	memcpy(code + n, &counter, 8);
	n += 8;
	code[n++] = 0x48;
	code[n++] = 0xff;
	code[n++] = 0x00;
	code[n++] = 0x48;
	code[n++] = 0xb8;
	memcpy(code + n, &esc, 8);
	n += 8;
	code[n++] = 0xff;
	code[n++] = 0xe0;
	void *p = tcache::AllocateCode(n, 16);
	memcpy(p, code, n);
	return p;
}

struct RunResult {
	jitabi::ppoint::BranchSlot *returned_slot;
	u32 ip_after;
	unsigned long long target_ran;
	unsigned long long escapes;
};

// Translate `entry`, emit into the executable pool, install a target block for `target`, then run
// it through the real trampoline exactly as Execute() does.
RunResult RunRegion(Guest const &g, u32 entry, u32 n_words, u32 target, u32 pending_bits)
{
	MemArena arena(1u << 20);
	PoolRuntime cr;
	Region *region = TranslateAt(arena, g, entry, n_words);
	CodeSegment segment(0u, GUEST_SIZE);
	auto span = qcg::GenerateCode(&cr, &segment, region, entry);

	auto *tb = tcache::AllocateTBlock();
	tb->ip = target;
	tb->tcode = TBlock::TCode{(u8 *)BuildTargetBlock(), 25};
	tcache::Insert(tb);

	CPUState state(nullptr);
	state.ip = entry;
	CPUState::SetCurrent(&state);

	g_target_ran = 0;
	unsigned long long esc0 = config::backedge_safepoint_escapes;
	config::service_request.store(pending_bits, std::memory_order_relaxed);

	auto *slot = jitabi::trampoline_to_jit(&state, nullptr, (void *)span.data());

	config::service_request.store(0, std::memory_order_relaxed);
	return {slot, state.ip, g_target_ran, config::backedge_safepoint_escapes - esc0};
}

} // namespace

int main()
{
	printf("T5d-0 QCG direct-backedge safepoint test\n");
	ResetConfig();
	tcache::Init();

	// -----------------------------------------------------------------------------------------
	printf("\n[1] the guest words, against an independent assembler\n");
	// Cross-checked with `llvm-mc -triple=riscv32 -show-encoding`; the constants below are that
	// tool's output, so the fixture's encoders are verified rather than trusted.
	checkf(enc_b(F3_BNE, 1, 2, -8) == 0xfe209ce3u, "bne x1,x2,-8 encodes to fe209ce3 (got %08x)",
	       enc_b(F3_BNE, 1, 2, -8));
	checkf(enc_b(F3_BEQ, 1, 2, 16) == 0x00208863u, "beq x1,x2,+16 encodes to 00208863 (got %08x)",
	       enc_b(F3_BEQ, 1, 2, 16));
	checkf(enc_j(0, -16) == 0xff1ff06fu, "jal x0,-16 encodes to ff1ff06f (got %08x)", enc_j(0, -16));
	checkf(enc_j(1, 24) == 0x018000efu, "jal x1,+24 encodes to 018000ef (got %08x)", enc_j(1, 24));
	// The predicate itself, at its two boundaries. `target == branch` is a self-loop and counts.
	check(qir::rv32::RV32Translator::IsDirectBackwardEdge(0x800, 0x7fc), "target below the branch is backward");
	check(qir::rv32::RV32Translator::IsDirectBackwardEdge(0x800, 0x800), "a self-loop is backward");
	check(!qir::rv32::RV32Translator::IsDirectBackwardEdge(0x800, 0x804), "the very next instruction is forward");

	// -----------------------------------------------------------------------------------------
	printf("\n[2] which gbr the REAL translator marks\n");
	{
		// 2a. A backward `jal`: one gbr, marked.
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80)); // jal x0, GUEST_BASE-0x80
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 1);
		auto gbrs = CollectGBr(r);
		checkf(gbrs.size() == 1, "backward jal produces exactly one gbr (got %zu)", gbrs.size());
		if (gbrs.size() == 1) {
			checkf(gbrs[0]->tpc.GetConst() == GUEST_BASE - 0x80,
			       "its target is the branch's own architectural target %08x (got %08x)",
			       GUEST_BASE - 0x80, gbrs[0]->tpc.GetConst());
			check(gbrs[0]->backedge, "and it is marked backedge");
		}
	}
	{
		// 2b. A forward `jal`: one gbr, not marked.
		Guest g;
		g.put(GUEST_BASE, enc_j(0, 0x80));
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 1);
		auto gbrs = CollectGBr(r);
		checkf(gbrs.size() == 1, "forward jal produces exactly one gbr (got %zu)", gbrs.size());
		if (gbrs.size() == 1)
			check(!gbrs[0]->backedge, "and it is NOT marked backedge");
	}
	{
		// 2c. A backward conditional branch: TWO gbrs, and only the taken one is marked. This is
		// the case that separates "marks backward edges" from "marks every edge of a backward
		// branch instruction": the fall-through of a backward `bne` is `insn_ip + 4`.
		Guest g;
		g.put(GUEST_BASE, enc_b(F3_BNE, 1, 2, -0x80));
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 1);
		auto gbrs = CollectGBr(r);
		checkf(gbrs.size() == 2, "backward bne produces two gbrs (got %zu)", gbrs.size());
		auto *taken = FindGBr(r, GUEST_BASE - 0x80);
		auto *fall = FindGBr(r, GUEST_BASE + 4);
		check(taken != nullptr && taken->backedge, "the TAKEN edge is marked backedge");
		check(fall != nullptr && !fall->backedge, "the FALL-THROUGH edge is not");
	}
	{
		// 2d. A forward conditional branch: neither edge marked.
		Guest g;
		g.put(GUEST_BASE, enc_b(F3_BEQ, 1, 2, 0x40));
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 1);
		auto gbrs = CollectGBr(r);
		checkf(gbrs.size() == 2, "forward beq produces two gbrs (got %zu)", gbrs.size());
		bool any = false;
		for (auto *gb : gbrs)
			any |= gb->backedge;
		check(!any, "neither edge of a forward branch is marked");
	}
	{
		// 2e. The region-boundary fallthrough. A region of N straight-line words ends in a gbr to
		// the next instruction, produced by the budget check and not by any branch at all.
		Guest g;
		for (u32 i = 0; i < 4; ++i)
			g.put(GUEST_BASE + 4 * i, 0x00000013u); // nop (addi x0,x0,0)
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 4);
		auto gbrs = CollectGBr(r);
		checkf(gbrs.size() == 1, "a straight-line region ends in one gbr (got %zu)", gbrs.size());
		if (gbrs.size() == 1) {
			checkf(gbrs[0]->tpc.GetConst() == GUEST_BASE + 16,
			       "targeting the next instruction %08x (got %08x)", GUEST_BASE + 16,
			       gbrs[0]->tpc.GetConst());
			check(!gbrs[0]->backedge, "and it is not a backedge");
		}
	}
	{
		// 2f. An INDIRECT exit. `jalr` produces a gbrind, never a gbr, so there is nothing here
		// for the safepoint to attach to whatever address the register happens to hold.
		Guest g;
		g.put(GUEST_BASE, enc_jalr(0, 1, 0)); // ret
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 1);
		checkf(CountOp(r, Op::_gbrind) == 1, "jalr produces one gbrind (got %u)",
		       CountOp(r, Op::_gbrind));
		checkf(CollectGBr(r).size() == 0, "and no gbr at all (got %zu)", CollectGBr(r).size());
	}
	{
		// 2g. A backward branch to the region's OWN entry stays INSIDE the region: `MakeGBr`'s
		// ip2bb lookup hits, so the edge becomes a successor of the compiled block instead of a
		// region exit. It never becomes a BranchSlot, never returns to Execute(), and therefore
		// cannot carry a safepoint. This is the mechanism's stated boundary (a loop small enough
		// to fit in one translation block is not covered), asserted here so it is a measured
		// property of the translator rather than a footnote in a document.
		Guest g;
		g.put(GUEST_BASE, 0x00000013u);                 // nop
		g.put(GUEST_BASE + 4, enc_b(F3_BNE, 1, 2, -4)); // bne back to GUEST_BASE
		MemArena arena(1u << 20);
		Region *r = TranslateAt(arena, g, GUEST_BASE, 2);
		check(FindGBr(r, GUEST_BASE) == nullptr, "an intra-region backedge produces no gbr");
		checkf(CountOp(r, Op::_brcc) == 1, "the branch is still compiled (one brcc, got %u)",
		       CountOp(r, Op::_brcc));
		// The taken edge is a block successor rather than an instruction: find the entry block
		// among the branching block's successors.
		bool loops_to_entry = false;
		for (auto &bb : r->GetBlocks()) {
			bool has_brcc = false;
			for (auto &ins : bb.ilist)
				has_brcc |= (ins.GetOpcode() == Op::_brcc);
			if (!has_brcc)
				continue;
			for (auto *s : bb.GetSuccs())
				loops_to_entry |= (s->entry_ip == GUEST_BASE);
		}
		check(loops_to_entry, "its taken edge is an in-region successor of the entry block");
		// And with the flag on, that region emits no safepoint at all.
		config::qcg_backedge_safepoint = true;
		MemArena a2(1u << 20);
		BufRuntime cr;
		Guest g2 = g;
		auto code = EmitAt(a2, g2, GUEST_BASE, 2, cr);
		checkf(FindSafepoints(code).empty(),
		       "and with the flag on it emits no safepoint (found %zu) -- the stated boundary",
		       FindSafepoints(code).size());
		config::qcg_backedge_safepoint = false;
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[3] with the flag OFF the emitted bytes do not depend on the backedge bit\n");
	{
		Guest gb, gf;
		gb.put(GUEST_BASE, enc_j(0, -0x80)); // backward: backedge = true
		gf.put(GUEST_BASE, enc_j(0, -0x80)); // same words, but the bit will be cleared by hand
		config::qcg_backedge_safepoint = false;
		// Deltas, not absolutes: these counters are process-global and cumulative, and an earlier
		// section already ran with the flag on. The claim being checked is that THIS section's
		// flag-off emissions move nothing.
		unsigned long long const sites0 = config::backedge_safepoint_sites;
		unsigned long long const total0 = config::backedge_safepoint_gbr_total;

		MemArena a1(1u << 20), a2(1u << 20);
		BufRuntime cr1, cr2;
		auto marked = EmitAt(a1, gb, GUEST_BASE, 1, cr1);

		// The same region with the bit forcibly cleared: the only difference between the two runs
		// is the value the safepoint reads, so equality here means the flag-off path never reads it.
		Region *r2 = TranslateAt(a2, gf, GUEST_BASE, 1);
		for (auto *gbr : CollectGBr(r2))
			gbr->backedge = false;
		CodeSegment seg(0u, GUEST_SIZE);
		auto span2 = qcg::GenerateCode(&cr2, &seg, r2, GUEST_BASE);
		std::vector<u8> cleared(span2.begin(), span2.end());

		checkf(marked == cleared, "flag off: marked and unmarked emit identical bytes (%zu vs %zu)",
		       marked.size(), cleared.size());
		checkf(FindSafepoints(marked).empty(), "flag off: no safepoint in the emitted code (found %zu)",
		       FindSafepoints(marked).size());
		checkf(config::backedge_safepoint_sites == sites0,
		       "flag off: no safepoint site counted (delta %llu)",
		       config::backedge_safepoint_sites - sites0);
		checkf(config::backedge_safepoint_gbr_total == total0,
		       "flag off: not even the DENOMINATOR moves (delta %llu) -- an off run is the run that "
		       "existed before this feature, and a counter is still observable state",
		       config::backedge_safepoint_gbr_total - total0);
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[4] with the flag ON: where the safepoint is, and where it is not\n");
	std::vector<u8> back_off, back_on;
	{
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80));

		config::qcg_backedge_safepoint = false;
		MemArena a1(1u << 20);
		BufRuntime cr1;
		back_off = EmitAt(a1, g, GUEST_BASE, 1, cr1);

		unsigned long long sites0 = config::backedge_safepoint_sites;
		config::qcg_backedge_safepoint = true;
		MemArena a2(1u << 20);
		BufRuntime cr2;
		back_on = EmitAt(a2, g, GUEST_BASE, 1, cr2);
		checkf(config::backedge_safepoint_sites == sites0 + 1,
		       "exactly one safepoint site was counted for one backward edge (delta %llu)",
		       config::backedge_safepoint_sites - sites0);

		auto sps = FindSafepoints(back_on);
		auto slots = FindSlots(back_on);
		checkf(sps.size() == 1, "exactly one safepoint in the emitted block (got %zu)", sps.size());
		checkf(slots.size() == 1, "exactly one branch slot in the emitted block (got %zu)", slots.size());
		if (sps.size() == 1 && slots.size() == 1) {
			bool shape_ok = false;
			size_t landing = SafepointBranchTarget(back_on, sps[0], shape_ok);
			check(shape_ok, "the safepoint is `cmp dword ptr [rax], 0` + a conditional branch");
			checkf(landing == slots[0],
			       "its not-taken branch lands exactly on the slot's first byte (%zu vs %zu)",
			       landing, slots[0]);
			checkf(sps[0] < slots[0], "and the whole safepoint precedes the slot (%zu < %zu)",
			       sps[0], slots[0]);
			// THE PURE-INSERTION CHECK. Cut the bytes between the safepoint head and the slot out
			// of the flag-on block; what remains must be the flag-off block, byte for byte. This
			// is what rules out the safepoint having also moved, resized or rewritten anything
			// else in the frame -- including the profiling code Emit_Cache puts ahead of it.
			std::vector<u8> spliced(back_on.begin(), back_on.begin() + sps[0]);
			spliced.insert(spliced.end(), back_on.begin() + slots[0], back_on.end());
			checkf(spliced == back_off,
			       "removing the safepoint reproduces the flag-off bytes exactly (%zu vs %zu)",
			       spliced.size(), back_off.size());
			printf("       safepoint at +%zu, slot at +%zu, insertion is %zu bytes\n", sps[0],
			       slots[0], slots[0] - sps[0]);
		}
	}
	{
		// Forward edge, flag ON: nothing.
		config::qcg_backedge_safepoint = true;
		Guest g;
		g.put(GUEST_BASE, enc_j(0, 0x80));
		MemArena a(1u << 20);
		BufRuntime cr;
		auto code = EmitAt(a, g, GUEST_BASE, 1, cr);
		checkf(FindSafepoints(code).empty(), "flag on, forward jal: no safepoint (found %zu)",
		       FindSafepoints(code).size());
		checkf(FindSlots(code).size() == 1, "but the branch slot is still there (got %zu)",
		       FindSlots(code).size());
	}
	{
		// Conditional branch, flag ON: exactly one safepoint for two slots.
		config::qcg_backedge_safepoint = true;
		Guest g;
		g.put(GUEST_BASE, enc_b(F3_BNE, 1, 2, -0x80));
		MemArena a(1u << 20);
		BufRuntime cr;
		auto code = EmitAt(a, g, GUEST_BASE, 1, cr);
		checkf(FindSlots(code).size() == 2, "backward bne emits two branch slots (got %zu)",
		       FindSlots(code).size());
		checkf(FindSafepoints(code).size() == 1,
		       "and exactly ONE safepoint, on the taken edge only (got %zu)",
		       FindSafepoints(code).size());
	}
	{
		// Region-boundary fallthrough and indirect exit, flag ON: nothing.
		config::qcg_backedge_safepoint = true;
		Guest g1;
		for (u32 i = 0; i < 4; ++i)
			g1.put(GUEST_BASE + 4 * i, 0x00000013u);
		MemArena a1(1u << 20);
		BufRuntime cr1;
		checkf(FindSafepoints(EmitAt(a1, g1, GUEST_BASE, 4, cr1)).empty(),
		       "flag on, region-boundary fallthrough: no safepoint");

		Guest g2;
		g2.put(GUEST_BASE, enc_jalr(0, 1, 0));
		MemArena a2(1u << 20);
		BufRuntime cr2;
		checkf(FindSafepoints(EmitAt(a2, g2, GUEST_BASE, 1, cr2)).empty(),
		       "flag on, indirect exit (ret): no safepoint");
	}

	// -----------------------------------------------------------------------------------------
	// EXECUTED CASES. Each runs the emitted bytes on the real code pool. The two outcomes are
	// mutually exclusive and neither can be produced by the other path:
	//
	//   traversal -> the slot links to the target, the target's own stub runs and escapes,
	//                trampoline_to_jit returns NULLPTR, g_target_ran == 1;
	//   safepoint -> control leaves before the slot, trampoline_to_jit returns THIS EDGE'S SLOT,
	//                g_target_ran == 0, state->ip == the edge's target.
	// -----------------------------------------------------------------------------------------
	// Every executed case gets its OWN region entry and its OWN target address, because each one
	// installs a real TBlock for its target; sharing an address between two cases would let an
	// earlier case's block satisfy a later one's lookup and blur what is being measured.
	Guest gback, gfwd, gbackoff;
	u32 const back_entry = GUEST_BASE;
	u32 const fwd_entry = GUEST_BASE + 0x100;
	u32 const off_entry = GUEST_BASE + 0x200;
	gback.put(back_entry, enc_j(0, -0x80));
	gfwd.put(fwd_entry, enc_j(0, 0x80));
	gbackoff.put(off_entry, enc_j(0, -0x80));
	u32 const back_target = back_entry - 0x80;
	u32 const fwd_target = fwd_entry + 0x80;
	u32 const off_target = off_entry - 0x80;

	printf("\n[5] executed: backward edge, flag ON, NO request pending -> no escape\n");
	{
		config::qcg_backedge_safepoint = true;
		auto r = RunRegion(gback, back_entry, 1, back_target, 0);
		check(r.returned_slot == nullptr, "the trampoline returns nullptr (the target's own escape)");
		checkf(r.target_ran == 1, "the target block ran (%llu)", r.target_ran);
		checkf(r.escapes == 0, "no safepoint escape was taken (%llu)", r.escapes);
	}

	printf("\n[6] executed: backward edge, flag ON, request pending -> escape before the target\n");
	{
		config::qcg_backedge_safepoint = true;
		auto r = RunRegion(gback, back_entry, 1, back_target, config::kSvcInrunEscalate);
		check(r.returned_slot != nullptr, "the trampoline returns a BranchSlot");
		checkf(r.target_ran == 0, "the target block did NOT run (%llu)", r.target_ran);
		checkf(r.escapes == 1, "exactly one safepoint escape was taken (%llu)", r.escapes);
		checkf(r.ip_after == back_target, "CPUState::ip is the edge's target %08x (got %08x)",
		       back_target, r.ip_after);
		if (r.returned_slot) {
			// Execute()'s own invariant, asserted at the top of its loop.
			checkf(r.returned_slot->gip == r.ip_after,
			       "and Execute()'s `branch_slot->gip == state->ip` holds (%08x vs %08x)",
			       r.returned_slot->gip, r.ip_after);
			// 6b. The loop really can resume from here: do what Execute() does next -- link the
			// returned slot to the block it looked up, and re-enter. The target must now run.
			auto *tb = tcache::Lookup(r.ip_after);
			check(tb != nullptr, "tcache::Lookup(state->ip) finds the target block");
			if (tb) {
				g_target_ran = 0;
				r.returned_slot->Link(tb->tcode.ptr);
				CPUState state(nullptr);
				state.ip = r.ip_after;
				CPUState::SetCurrent(&state);
				config::service_request.store(0, std::memory_order_relaxed);
				auto *again = jitabi::trampoline_to_jit(&state, nullptr, tb->tcode.ptr);
				check(again == nullptr && g_target_ran == 1,
				      "re-entering at that ip runs the target -- the loop resumes correctly");
			}
		}
	}

	printf("\n[7] executed: FORWARD edge, flag ON, request pending -> unaffected\n");
	{
		config::qcg_backedge_safepoint = true;
		auto r = RunRegion(gfwd, fwd_entry, 1, fwd_target, config::kSvcInrunEscalate);
		check(r.returned_slot == nullptr, "the trampoline returns nullptr");
		checkf(r.target_ran == 1, "the target block ran (%llu)", r.target_ran);
		checkf(r.escapes == 0, "no escape (%llu)", r.escapes);
	}

	printf("\n[8] executed: backward edge, flag OFF, request pending -> unaffected\n");
	{
		config::qcg_backedge_safepoint = false;
		auto r = RunRegion(gbackoff, off_entry, 1, off_target, config::kSvcInrunEscalate);
		check(r.returned_slot == nullptr, "the trampoline returns nullptr");
		checkf(r.target_ran == 1, "the target block ran (%llu)", r.target_ran);
		checkf(r.escapes == 0, "no escape (%llu)", r.escapes);
	}

	printf("\n[9] executed: NON-LEAF backward edge -- the frame teardown, with a real frame\n");
	{
		// Sections 5-8 all run leaf regions, whose Prologue emits no frame push at all, so they
		// cannot tell a correct FrameDestroy from a missing one. This region contains an hcall
		// (a `vsetvli` with every direct route off falls back to the pre-existing rv32_vsetvli
		// helper), which makes QSel mark it non-leaf: Prologue pushes, and Emit_gbr must pop
		// before the safepoint runs. If it did not, the escape stub would unwind from the wrong
		// rsp and this process would not return from trampoline_to_jit at all.
		config::qcg_backedge_safepoint = true;
		Guest g;
		u32 const entry = GUEST_BASE + 0x200;
		g.put(entry, enc_vsetvli(5, 6, 0x0d0)); // vsetvli t0, t1, e32,m1,ta,ma
		g.put(entry + 4, enc_j(0, -0x80));
		u32 const target = entry + 4 - 0x80;

		MemArena arena(1u << 20);
		BufRuntime cr;
		auto code = EmitAt(arena, g, entry, 2, cr);
		checkf(FindSafepoints(code).size() == 1, "the non-leaf region has one safepoint (got %zu)",
		       FindSafepoints(code).size());
		// `pop rcx` is 0x59; it must appear between the last call and the safepoint.
		auto sps = FindSafepoints(code);
		bool popped = false;
		if (sps.size() == 1)
			for (size_t i = 0; i < sps[0]; ++i)
				popped |= (code[i] == 0x59);
		check(popped, "and a `pop rcx` (FrameDestroy) ahead of it");

		auto r = RunRegion(g, entry, 2, target, config::kSvcInrunEscalate);
		check(r.returned_slot != nullptr, "the trampoline returns a BranchSlot -- the stack unwound");
		checkf(r.target_ran == 0, "the target block did NOT run (%llu)", r.target_ran);
		checkf(r.escapes == 1, "exactly one escape (%llu)", r.escapes);
		checkf(r.ip_after == target, "CPUState::ip is the edge's target %08x (got %08x)", target,
		       r.ip_after);
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[10] every runtime-service request Execute() consumes owns a bit, and only its own\n");
	{
		struct Entry {
			char const *name;
			config::ServiceFlag *flag;
			u32 bit;
		};
		Entry const flags[] = {
		    {"inrun_poll_due", &config::inrun_poll_due, config::kSvcInrunPoll},
		    {"inrun_boot_pending", &config::inrun_boot_pending, config::kSvcInrunBootPending},
		    {"inrun_escalate_due", &config::inrun_escalate_due, config::kSvcInrunEscalate},
		    {"sat_sweep_due", &config::sat_sweep_due, config::kSvcSatSweep},
		    {"p1_scan_due", &config::p1_scan_due, config::kSvcP1Scan},
		    {"web_repack_due", &config::web_repack_due, config::kSvcWebRepack},
		};
		config::service_request.store(0, std::memory_order_relaxed);
		u32 seen = 0;
		bool distinct = true;
		for (auto const &e : flags) {
			distinct &= ((seen & e.bit) == 0) && e.bit != 0;
			seen |= e.bit;
			distinct &= (e.flag->Bit() == e.bit);
		}
		check(distinct, "the six flags own six distinct, correctly-declared bits");

		// THERE IS NO SECOND COPY OF THE STATE, and this is a compile-time fact rather than a
		// behavioural one: a ServiceFlag is its bit mask and nothing else. The first version of
		// this type kept a `volatile bool` beside the bit, and that mirror could diverge under
		// signal interleaving no matter how the two writes were ordered (section 10b reaches the
		// interleaving that does it). A static_assert is the right shape of evidence here, because
		// it rules the state out instead of failing to find it.
		check(sizeof(config::ServiceFlag) == sizeof(uint32_t),
		      "a ServiceFlag holds only its mask -- no mirrored copy of the word exists");

		bool ok = true;
		for (auto const &e : flags) {
			*e.flag = true;
			ok &= (bool)*e.flag;
			ok &= (config::service_request.load(std::memory_order_relaxed) & e.bit) != 0;
			ok &= config::AnyServiceRequestPending();
			*e.flag = false;
			ok &= !(bool)*e.flag;
			ok &= (config::service_request.load(std::memory_order_relaxed) & e.bit) == 0;
			ok &= !config::AnyServiceRequestPending();
			if (!ok) {
				printf("       first failure at %s\n", e.name);
				break;
			}
		}
		check(ok, "setting a flag raises exactly its bit; clearing it lowers exactly its bit");

		// Every subset of the six, exhaustively: the word is the OR of the flags that are set and
		// nothing else, so no combination can leave a stale bit behind.
		bool subsets_ok = true;
		for (u32 mask = 0; mask < 64u; ++mask) {
			config::service_request.store(0, std::memory_order_relaxed);
			u32 expect = 0;
			for (unsigned i = 0; i < 6; ++i)
				if (mask & (1u << i)) {
					*flags[i].flag = true;
					expect |= flags[i].bit;
				}
			subsets_ok &= (config::service_request.load(std::memory_order_relaxed) == expect);
			subsets_ok &= (config::AnyServiceRequestPending() == (expect != 0));
			for (unsigned i = 0; i < 6; ++i)
				subsets_ok &= ((bool)*flags[i].flag == ((mask & (1u << i)) != 0));
		}
		config::service_request.store(0, std::memory_order_relaxed);
		check(subsets_ok, "all 64 subsets of the six requests read back exactly, in both directions");

		// Interleaving: two pending requests must not cancel each other when one is serviced.
		config::inrun_escalate_due = true;
		config::p1_scan_due = true;
		config::inrun_escalate_due = false;
		check(config::AnyServiceRequestPending() && (bool)config::p1_scan_due,
		      "servicing one request leaves another one pending");
		config::p1_scan_due = false;
		check(!config::AnyServiceRequestPending(), "and the word is clear once both are serviced");

		// The address emitted code was given really is this word's.
		check(config::ServiceRequestWordAddr() == (void *)&config::service_request,
		      "the address handed to the code generator is the word itself");
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[10b] under real signal interleaving\n");
	{
		// WHY THIS SECTION EXISTS. Section 10 drives the flags sequentially, and sequential tests
		// cannot see either of the two defects that actually threaten this word: a set performed
		// inside a signal handler being lost by a concurrent clear, and a mirrored copy of the
		// state disagreeing with the bit. Both need the handler to run INSIDE another flag
		// operation, so both are tested here by actually delivering signals during one.
		//
		// The handler is the shape of the real one: it only ever SETS. The main loop only ever
		// clears. That asymmetry is what makes the detectors exact rather than statistical.
		g_svc_sets = 0;
		config::service_request.store(0, std::memory_order_relaxed);

		struct sigaction sa {};
		struct sigaction old_sa {};
		sa.sa_handler = svc_set_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGALRM, &sa, &old_sa);
		struct itimerval tick {};
		tick.it_interval.tv_usec = 500;
		tick.it_value.tv_usec = 500;

		// 10b.1 -- A LOST UPDATE. The handler sets kSvcInrunPoll; the main loop sets and clears a
		// DIFFERENT flag. A tick landing between the main loop's load and its store would drop the
		// handler's set if the update were a plain load/modify/store rather than one atomic RMW.
		//
		// THE RE-ARM IS THE POINT, and the first version of this detector did not have it. It
		// simply required kSvcInrunPoll to stay set once the handler had raised it -- but after the
		// first delivery the bit is ALREADY set, so every later delivery writes a value the
		// clobbering store would have preserved anyway, and only the very first tick out of 800 was
		// capable of exposing anything. The non-atomic mutation passed that version. Clearing the
		// flag at the top of every iteration makes each delivery a real 0 -> 1 transition, so every
		// tick is a trial.
		//
		// The detector is exact, not statistical: `seen` is read AFTER main's own clear, so a
		// delivery counted by `g_svc_sets > seen` happened strictly after it, and nothing in the
		// iteration clears the flag again. If it is not set at the check, the set was lost.
		setitimer(ITIMER_REAL, &tick, nullptr);
		unsigned long long lost = 0, iters = 0, armed = 0;
		for (double t0 = now_ms(); now_ms() - t0 < 400.0;) {
			for (int k = 0; k < 512; ++k) {
				config::inrun_poll_due = false;
				unsigned long long const seen = (unsigned long long)g_svc_sets;
				config::inrun_escalate_due = true;
				config::inrun_escalate_due = false;
				if ((unsigned long long)g_svc_sets > seen) {
					armed++;
					if (!config::inrun_poll_due)
						lost++;
				}
				iters++;
			}
		}
		unsigned long long const sets1 = (unsigned long long)g_svc_sets;
		setitimer(ITIMER_REAL, nullptr, nullptr);

		// Not vacuous, twice over: the timer must have fired, AND its deliveries must have landed
		// inside the window the detector watches. `armed` is the number of real trials.
		checkf(sets1 >= 20, "the handler really ran during the loop (%llu deliveries, %llu iterations)",
		       sets1, iters);
		checkf(armed >= 20, "and %llu of those deliveries landed inside the measured window", armed);
		checkf(lost == 0, "a set made inside a signal handler is never lost by a concurrent clear "
				  "of another flag (%llu losses in %llu trials)", lost, armed);

		// 10b.2 -- A MIRROR. Now the main loop clears the SAME flag the handler sets, and checks
		// the one implication that a divergent mirror breaks: if the flag reads pending, the WORD
		// the emitted safepoint tests must be non-zero. Between those two reads only the handler
		// can run, and the handler only sets, so a correct implementation cannot produce a false
		// positive. A mirror can: main writes bool=false, the handler writes bool=true and sets
		// the bit, main's interrupted clear then lowers the bit -- bool true, word zero, and a
		// safepoint that never fires for a request the host loop believes is pending.
		g_svc_sets = 0;
		config::service_request.store(0, std::memory_order_relaxed);
		setitimer(ITIMER_REAL, &tick, nullptr);
		unsigned long long diverged = 0, iters2 = 0;
		for (double t0 = now_ms(); now_ms() - t0 < 400.0;) {
			for (int k = 0; k < 512; ++k) {
				config::inrun_poll_due = false;
				if ((bool)config::inrun_poll_due && !config::AnyServiceRequestPending())
					diverged++;
				iters2++;
			}
		}
		unsigned long long const sets2 = (unsigned long long)g_svc_sets;
		setitimer(ITIMER_REAL, nullptr, nullptr);
		sigaction(SIGALRM, &old_sa, nullptr);
		config::service_request.store(0, std::memory_order_relaxed);

		checkf(sets2 >= 20, "the handler ran during the clear loop too (%llu deliveries, %llu iterations)",
		       sets2, iters2);
		checkf(diverged == 0,
		       "the flag and the word the safepoint tests never disagree (%llu divergences)",
		       diverged);
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[12] a repeatedly escaped edge does not grow the link index\n");
	{
		// THE DEFECT THIS GUARDS, found by running the mechanism rather than by reading it. Every
		// escape returns to Execute(), which links the slot and calls tcache::RecordLink. On an
		// edge that is escaped over and over -- exactly what happens while a request stays pending
		// -- that used to add one identical node to `link_map` per escape. On a 0.07 s pilot run it
		// reached 183k nodes for a guest with 156 direct edges, and destroying that multimap at
		// process exit took long enough for the keeper's 1 ms timer tick to land inside it and
		// fault: 30 crashes in 30 runs, against 0 in 30 with the safepoint off.
		//
		// The loop below is Execute()'s own handling of a returned slot, run 2000 times on ONE
		// edge. Delete RecordLink's duplicate test and `added` becomes 2000 instead of at most 1.
		config::qcg_backedge_safepoint = true;
		Guest g;
		u32 const entry = GUEST_BASE + 0x300;
		g.put(entry, enc_j(0, -0x80));
		u32 const target = entry - 0x80;

		MemArena arena(1u << 20);
		PoolRuntime cr;
		Region *region = TranslateAt(arena, g, entry, 1);
		CodeSegment segment(0u, GUEST_SIZE);
		auto span = qcg::GenerateCode(&cr, &segment, region, entry);

		auto *tb = tcache::AllocateTBlock();
		tb->ip = target;
		tb->tcode = TBlock::TCode{(u8 *)BuildTargetBlock(), 25};
		tcache::Insert(tb);

		CPUState state(nullptr);
		CPUState::SetCurrent(&state);
		config::service_request.store(config::kSvcInrunEscalate, std::memory_order_relaxed);
		size_t const before = tcache::LinkMapSize();
		unsigned long long const esc0 = config::backedge_safepoint_escapes;
		unsigned const iters = 2000;
		unsigned done = 0;
		g_target_ran = 0;
		for (unsigned i = 0; i < iters; ++i) {
			state.ip = entry;
			auto *slot = jitabi::trampoline_to_jit(&state, nullptr, (void *)span.data());
			if (!slot)
				break; // the target ran: the safepoint failed to fire, caught below
			auto *found = tcache::Lookup(state.ip);
			if (!found)
				break;
			slot->Link(found->tcode.ptr);
			tcache::RecordLink(slot, found, slot->flags.cross_segment);
			tcache::CacheBr(found);
			done++;
		}
		config::service_request.store(0, std::memory_order_relaxed);
		size_t const added = tcache::LinkMapSize() - before;
		checkf(done == iters && config::backedge_safepoint_escapes - esc0 == iters,
		       "the same edge escaped %u times in a row (%u completed, %llu counted)", iters, done,
		       config::backedge_safepoint_escapes - esc0);
		checkf(g_target_ran == 0, "and the target never ran (%llu)", g_target_ran);
		checkf(added <= 1, "%u re-links of ONE edge added %zu link-index entries (must be <= 1)",
		       iters, added);
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[13] with the flag OFF the process is the one that existed before this feature\n");
	{
		// Byte-identical generated code is only part of "default off". A run with the feature
		// switched off must also produce the same OUTPUT and touch the same STATE, and the first
		// version of this checkpoint failed both: it printed a `BACKEDGE_SAFEPOINT on=0 ...` line
		// on every elfrun invocation in the tree, it printed a ` backedge` token in every QIR dump
		// of a backward edge, and it incremented a global denominator per direct region exit.
		// Independent review rejected all three. This section is the check that they stay gone.
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80)); // a marked backward edge, so the token has something to print
		g.put(GUEST_BASE + 0x40, enc_j(0, 0x40));

		// 13a. THE QIR DUMP. `PrinterPass::run` is the one place a region becomes text.
		config::qcg_backedge_safepoint = false;
		MemArena a_off(1u << 20);
		std::string dump_off = PrinterPass::run(TranslateAt(a_off, g, GUEST_BASE, 1));
		config::qcg_backedge_safepoint = true;
		MemArena a_on(1u << 20);
		std::string dump_on = PrinterPass::run(TranslateAt(a_on, g, GUEST_BASE, 1));
		config::qcg_backedge_safepoint = false;

		check(dump_off.find("backedge") == std::string::npos,
		      "flag off: the QIR dump contains no `backedge` token anywhere");
		check(dump_on.find("backedge") != std::string::npos,
		      "flag on: it does (so 13a is not passing because the printer is simply broken)");
		// THE PRE-FEATURE EQUIVALENCE. A build without this feature had no InstGBr::backedge and no
		// branch in the printer, so its dump is exactly this dump with every ` backedge` token
		// removed. Reconstruct that from the flag-on text and require the flag-off text to equal it
		// byte for byte: that rules out the printer having changed spacing, ordering or anything
		// else, not just this one token.
		std::string reconstructed = dump_on;
		for (size_t p = reconstructed.find(" backedge"); p != std::string::npos;
		     p = reconstructed.find(" backedge", p))
			reconstructed.erase(p, strlen(" backedge"));
		checkf(reconstructed == dump_off,
		       "flag off: the dump IS the pre-feature dump -- deleting every ` backedge` token from "
		       "the flag-on dump reproduces it exactly (%zu vs %zu bytes)",
		       reconstructed.size(), dump_off.size());

		// 13b. THE COUNTERS. Emit several flag-off regions of both kinds and require every
		// emission-side global to be untouched.
		unsigned long long const s0 = config::backedge_safepoint_sites;
		unsigned long long const t0 = config::backedge_safepoint_gbr_total;
		unsigned long long const e0 = config::backedge_safepoint_escapes;
		for (u32 i = 0; i < 4; ++i) {
			MemArena a(1u << 20);
			BufRuntime cr;
			EmitAt(a, g, GUEST_BASE, 1, cr);
			MemArena a2(1u << 20);
			BufRuntime cr2;
			EmitAt(a2, g, GUEST_BASE + 0x40, 1, cr2);
		}
		checkf(config::backedge_safepoint_sites == s0 && config::backedge_safepoint_gbr_total == t0 &&
			   config::backedge_safepoint_escapes == e0,
		       "flag off: eight emitted regions move no counter (sites +%llu, gbr_total +%llu, "
		       "escapes +%llu)",
		       config::backedge_safepoint_sites - s0, config::backedge_safepoint_gbr_total - t0,
		       config::backedge_safepoint_escapes - e0);
		// And with the flag on the denominator is available in full, so nothing is lost by
		// refusing to collect it in an off run.
		config::qcg_backedge_safepoint = true;
		{
			MemArena a(1u << 20);
			BufRuntime cr;
			EmitAt(a, g, GUEST_BASE, 1, cr);
		}
		config::qcg_backedge_safepoint = false;
		checkf(config::backedge_safepoint_gbr_total == t0 + 1 &&
			   config::backedge_safepoint_sites == s0 + 1,
		       "flag on: the same region counts one direct exit and one safepoint (+%llu, +%llu)",
		       config::backedge_safepoint_gbr_total - t0, config::backedge_safepoint_sites - s0);
	}

	// -----------------------------------------------------------------------------------------
	printf("\n[11] independence from the T5c escape ring\n");
	{
		// The safepoint must not be --inrun-escape-unlink under another name. It never calls
		// UnlinkRecorded, never records a slot for later rewriting, and never needs the ring
		// armed: every escape above happened with the ring's own switch off and its counters at
		// zero. These are the ring's OWN counters, so a version of this patch that quietly reused
		// the T5c channel would move them.
		check(!config::inrun_escape_unlink, "--inrun-escape-unlink was off for every case above");
		checkf(config::esc_unlink_ticks == 0 && config::esc_unlink_slots == 0,
		       "and the ring did no work at all (ticks=%lu slots=%lu)", config::esc_unlink_ticks,
		       config::esc_unlink_slots);
		checkf(config::backedge_safepoint_escapes > 0,
		       "while the safepoint itself escaped %llu times", config::backedge_safepoint_escapes);
	}

	ResetConfig();
	printf("\n%s (%d checks, %d failed)\n",
	       g_failed ? "BACKEDGE_SAFEPOINT: FAIL" : "BACKEDGE_SAFEPOINT: PASS", g_checks, g_failed);
	return g_failed ? 1 : 0;
}
