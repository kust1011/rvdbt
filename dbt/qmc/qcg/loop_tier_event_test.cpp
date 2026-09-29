// T5d2a2 focused test: the loop-tier NOTIFICATION -- read in the emitted bytes, and then EXECUTED.
//
// WHAT IS BEING CLAIMED. With `--loop-tier` on, a QCG direct BACKWARD edge asks four extra questions
// as part of the Wendell counter update it already performs, and delivers at most one notification
// per guest target for the life of the process:
//
//   (1) has this target's `exec_count` REACHED OR PASSED the compiler's bar?
//   (2) is the tier still ARMED, so a notification could still be used?
//   (3) is the one-slot mailbox free, so nothing already in flight is overwritten?
//   (4) has this GUEST TARGET not notified before? -- claim it, store the payload, set the bit.
//
// Sections 1-6 read that out of the machine code the real backend produced. Section 7 EXECUTES it:
// the emitted counter-update sequence is copied verbatim onto an executable page, given the L1
// entry and the `TBlock` the running system would have given it, and called -- so what the run does
// and what this test drives are the same instructions, not a re-implementation.
//
// HOW EACH ASSERTION CAN FAIL, stated because a passing test that cannot fail is not evidence:
//
//   [1] locates the evidence test as ONE CONTIGUOUS byte pattern that literally spells
//       `inc qword [r12+32]` / `movabs rsi, bar` / `cmp qword [r12+32], rsi`. Change the base
//       register, change the offset, reload the L1 base, insert a second lookup, or move the test
//       away from the increment, and the pattern is not there.
//   [2] counts `movabs r12, &cache_tb_exec_count` -- the hash-table base load, i.e. the lookup --
//       in the flag-on and flag-off builds of the SAME region and requires the two counts to be
//       equal. Add any second lookup and the counts diverge.
//   [3] requires all four guards, each as an exact encoding, each followed by a conditional jump to
//       the SAME join label; requires `jb` (>=) rather than `jne` (==) on the bar; and requires the
//       claim to be stored before the payload and the payload before the bit.
//   [4] emits the same words as a forward edge, as a fallthrough and as a `jalr`, and requires the
//       notification's own addresses to appear ZERO times.
//   [5] splices the inserted bytes back out, repairs the one branch displacement that had to grow,
//       and requires the result to equal the flag-off bytes EXACTLY.
//   [6] requires that TRANSLATING the sequence raises nothing, and that an AOT-mode compile bakes
//       none of this process's addresses.
//   [7] runs it. A forward arrival takes the counter TO the bar (which is what defeats an equality
//       test); the next backward edge must notify exactly once; repeats must not notify again;
//       a retranslation with a FRESH TBlock must not rearm the target; and after BUILDING /
//       PUBLISHED / FAILED / ABSTAINED a different, never-notified hot target must leave the
//       payload and the service word alone -- while the same target with the tier ARMED still
//       fires, so those zeros are not vacuous.
//
// WHAT IT DELIBERATELY DOES NOT DO. It runs no guest program, times nothing, and makes no claim
// about hotness, selection, promotion or performance. Which loop a notification leads to compiling
// is the selector's question and is tested in loop_tier_test; whether the artifact lands is the
// run's question and is measured on xbd.

#include "dbt/aot/loop_tier.h"
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/tcache/tcache.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <sys/mman.h>
}

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
// The fixture. Same shape as backedge_safepoint_test.cpp's, for the same reason: the translator
// reads instructions from `vmem_base + insn_ip`, so a plain buffer indexed by guest address is the
// whole guest, and a backward branch needs somewhere below the entry to point at.
// ---------------------------------------------------------------------------------------------

constexpr u32 GUEST_SIZE = 0x1000;
constexpr u32 GUEST_BASE = 0x0800;

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

u32 enc_j(u32 rd, int32_t off)
{
	u32 imm = (u32)off;
	return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3ff) << 21) | (((imm >> 11) & 1) << 20) |
	       (((imm >> 12) & 0xff) << 12) | (rd << 7) | 0x6f;
}
u32 enc_b(u32 f3, u32 rs1, u32 rs2, int32_t off)
{
	u32 imm = (u32)off;
	return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) | (rs2 << 20) | (rs1 << 15) |
	       (f3 << 12) | (((imm >> 1) & 0xf) << 8) | (((imm >> 11) & 1) << 7) | 0x63;
}
u32 enc_jalr(u32 rd, u32 rs1, int32_t imm)
{
	return (((u32)imm & 0xfff) << 20) | (rs1 << 15) | (0u << 12) | (rd << 7) | 0x67;
}
constexpr u32 F3_BNE = 1;

void ResetConfig()
{
	config::loop_tier = false;
	config::qcg_backedge_safepoint = false;
	config::inrun_escape_unlink = false;
	config::qcg_freq_entry = false;
	config::qcg_freq_edge = false;
	config::qcg_freq_scratch = false;
	config::qcg_freq_sat = false;
	config::qcg_freq_retire = false;
	config::qcg_jal_closure = false;
	config::trace = false;
	config::use_aot = false;
	config::not_freq = false;
	config::rvv_direct = false;
	config::rvv_vector_ssa = false;
	config::service_request.store(0, std::memory_order_relaxed);
	config::loop_tier_event_ip = 0;
	config::loop_tier_state = 0;
}

// The AOT producer's shape. `jit_mode` is `!AllowsRelocation()`, so this is what elfaot looks like
// to the emitter: relocatable output, compiled in one process and executed in another. Every
// address the notification bakes is THIS process's, so it must not be emitted here at all.
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

struct BufRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode: the only mode the notification is emitted in
	}
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

template <typename RT> std::vector<u8> EmitWith(MemArena &arena, Guest const &g, u32 entry, u32 n_words)
{
	CompilerJob::IpRangesSet ranges = {{entry, entry + 4 * n_words}};
	CompilerJob job(nullptr, g.base(), CodeSegment(0u, GUEST_SIZE), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	CodeSegment segment(0u, GUEST_SIZE);
	RT cr;
	auto span = qcg::GenerateCode(&cr, &segment, region, entry);
	return std::vector<u8>(span.begin(), span.end());
}

std::vector<u8> EmitAt(MemArena &arena, Guest const &g, u32 entry, u32 n_words)
{
	return EmitWith<BufRuntime>(arena, g, entry, n_words);
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

std::vector<u8> operator+(std::vector<u8> a, std::vector<u8> const &b)
{
	a.insert(a.end(), b.begin(), b.end());
	return a;
}

// `movabs <reg>, imm64`. rsi is `48 BE`, r12 is `49 BC`.
std::vector<u8> MovAbs(u8 rex, u8 op, uptr imm)
{
	std::vector<u8> p = {rex, op};
	u8 b[8];
	memcpy(b, &imm, 8);
	p.insert(p.end(), b, b + 8);
	return p;
}
std::vector<u8> MovAbsRsi(uptr imm)
{
	return MovAbs(0x48, 0xbe, imm);
}
std::vector<u8> MovAbsR12(uptr imm)
{
	return MovAbs(0x49, 0xbc, imm);
}
std::vector<u8> Imm32(u32 v)
{
	std::vector<u8> b(4);
	memcpy(b.data(), &v, 4);
	return b;
}

// Where a conditional jump at `pos` lands, for the two widths asmjit may pick. -1 if `pos` does not
// begin one of the two forms this file expects.
long JccTarget(std::vector<u8> const &code, size_t pos)
{
	if (pos + 6 <= code.size() && code[pos] == 0x0f && (code[pos + 1] == 0x82 || code[pos + 1] == 0x85)) {
		int32_t d;
		memcpy(&d, &code[pos + 2], 4);
		return (long)(pos + 6) + d;
	}
	if (pos + 2 <= code.size() && (code[pos] == 0x72 || code[pos] == 0x75))
		return (long)(pos + 2) + (int8_t)code[pos + 1];
	return -1;
}

// ---------------------------------------------------------------------------------------------
// Section 7's machinery: run the emitted counter-update sequence.
//
// The sequence is self-contained between the L1 base load and the shared `skip_cache` label -- it
// reads the L1 array, the TBlock it finds there and the tier's own globals, and it writes only
// those globals. Copying [start, skip) verbatim keeps every internal branch valid, because they are
// all relative and all target the end of the copied block; `push r12` / `pop r12` around it
// preserves the one callee-saved register it uses (rsi is caller-saved).
// ---------------------------------------------------------------------------------------------

struct Runnable {
	void *page = nullptr;
	size_t len = 0;
	void (*fn)() = nullptr;

	bool Build(std::vector<u8> const &code, size_t start, size_t stop)
	{
		if (start >= stop || stop > code.size())
			return false;
		std::vector<u8> blob = {0x41, 0x54}; // push r12
		blob.insert(blob.end(), code.begin() + (long)start, code.begin() + (long)stop);
		blob.push_back(0x41); // pop r12  -- and the target of every branch inside the block
		blob.push_back(0x5c);
		blob.push_back(0xc3); // ret
		len = (blob.size() + 4095) & ~(size_t)4095;
		page = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED) {
			page = nullptr;
			return false;
		}
		memcpy(page, blob.data(), blob.size());
		if (mprotect(page, len, PROT_READ | PROT_EXEC) != 0)
			return false;
		fn = (void (*)())page;
		return true;
	}
	void Run(unsigned n = 1)
	{
		for (unsigned i = 0; i < n; ++i)
			fn();
	}
	~Runnable()
	{
		if (page)
			munmap(page, len);
	}
};

// The state the running system would have handed the sequence: an L1 entry whose tag matches the
// target and whose `tb` is the TBlock the increment must land in.
void InstallL1(u32 ip, TBlock *tb)
{
	tcache::cache_tb_exec_count[tcache::l1hash(ip)] = {ip, tb};
}

void HexDump(char const *what, std::vector<u8> const &code, size_t start, size_t stop)
{
	printf("    %s [%zu,%zu):", what, start, stop);
	for (size_t i = start; i < stop && i < code.size(); ++i)
		printf("%s%02x", (i - start) % 16 == 0 ? "\n      " : " ", code[i]);
	printf("\n");
}

} // namespace

int main()
{
	printf("T5d2a2 loop-tier notification test\n");
	tcache::Init();
	MemArena arena(1u << 20);

	// The two encodings the reuse claim is made of, built here from the SAME offsetof the emitter
	// uses -- so if TBlock's layout moves, this test moves with it rather than silently checking a
	// stale offset.
	unsigned const cnt_off = offsetof(TBlock, flags) + 8;
	checkf(cnt_off < 128, "the exec_count offset (%u) is disp8-encodable, so the patterns below are exact",
	       cnt_off);
	// inc qword [r12 + cnt_off]
	std::vector<u8> const INC_R12 = {0x49, 0xff, 0x44, 0x24, (u8)cnt_off};
	// cmp qword [r12 + cnt_off], rsi
	std::vector<u8> const CMP_R12_RSI = {0x49, 0x39, 0x74, 0x24, (u8)cnt_off};

	// The addresses the notification names, each known here independently of the emitter.
	uptr const A_L1 = (uptr)tcache::cache_tb_exec_count.data();
	uptr const A_STATE = (uptr)&config::loop_tier_state;
	uptr const A_EVENT_IP = (uptr)&config::loop_tier_event_ip;
	uptr const A_SVC = (uptr)config::ServiceRequestWordAddr();

	// A bar that cannot be confused with anything else in the instruction stream, and that is
	// deliberately ABOVE INT32_MAX: an emitter that used an imm32 compare would truncate it, and
	// the pattern below would not be found.
	u64 const BAR = 0x0000'0007'DEAD'BEEFull;

	// -------------------------------------------------------------------------------------
	section("1. the evidence test reuses the counter update: same TBlock pointer, same offset, no lookup");
	std::vector<u8> back_on, back_off;
	{
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80)); // jal x0, GUEST_BASE-0x80 -- a direct BACKWARD edge
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		back_off = EmitAt(arena, g, GUEST_BASE, 1);
		config::loop_tier = true;
		back_on = EmitAt(arena, g, GUEST_BASE, 1);
		ResetConfig();

		// THE REUSE, as one contiguous pattern: increment the counter through r12, load the bar,
		// compare THE SAME memory operand. Nothing between them, so nothing was looked up again.
		auto reuse = INC_R12 + MovAbsRsi((uptr)BAR) + CMP_R12_RSI;
		auto hits = FindBytes(back_on, reuse);
		checkf(hits.size() == 1,
		       "exactly one `inc [r12+%u]; movabs rsi,bar; cmp [r12+%u],rsi` sequence (%zu found)",
		       cnt_off, cnt_off, hits.size());
		check(FindBytes(back_off, reuse).empty(), "and none of it with the flag off");
	}
	{
		// THE LOOKUP COUNT IS UNCHANGED. `movabs r12, &cache_tb_exec_count` IS the hash lookup's
		// base load; if the notification did its own lookup there would be one more of them.
		auto on = FindBytes(back_on, MovAbsR12(A_L1));
		auto off = FindBytes(back_off, MovAbsR12(A_L1));
		checkf(on.size() == off.size() && on.size() == 1,
		       "the L1-base load appears %zu times with the flag on and %zu with it off -- the "
		       "notification adds no second lookup",
		       on.size(), off.size());
	}
	{
		// And the notification's own addresses are there exactly once each.
		checkf(FindBytes(back_on, MovAbsRsi(A_STATE)).size() == 1,
		       "the tier state is read exactly once");
		checkf(FindBytes(back_on, MovAbsR12(A_EVENT_IP)).size() == 1,
		       "the mailbox address is loaded exactly once -- tested and stored through one load");
		checkf(FindBytes(back_on, MovAbsRsi(A_SVC)).size() == 1,
		       "the service word is named exactly once by the notification");
		check(FindBytes(back_off, MovAbsRsi(A_STATE)).empty() &&
			  FindBytes(back_off, MovAbsR12(A_EVENT_IP)).empty() &&
			  FindBytes(back_off, MovAbsRsi(A_SVC)).empty(),
		      "none of them appears with the flag off");
	}

	// -------------------------------------------------------------------------------------
	section("2. the four guards, their order, and the one join they all jump to");
	// The notify byte for THIS target, resolved the way the emitter resolves it: at translation
	// time, from the guest ip. `GUEST_BASE - 0x80` is where the backward edge points.
	u32 const BACK_TARGET = GUEST_BASE - 0x80;
	uptr const A_NOTIFY = (uptr)config::LoopTierNotifySlot(BACK_TARGET);
	size_t g_join = 0;
	{
		// Each guard as an EXACT encoding: the address it loads, the compare it performs, and the
		// jump kind that follows. A guard that tested the wrong word, the wrong width, or the wrong
		// condition would not be found at all.
		struct Guard {
			char const *what;
			std::vector<u8> pat;
			u8 jcc_op; // 0x82 = jb (>=), 0x85 = jne (==)
		};
		std::vector<Guard> guards = {
		    {"(1) exec_count >= bar, and `jb` so no other writer can step over it",
		     MovAbsRsi((uptr)BAR) + CMP_R12_RSI, 0x82},
		    {"(2) loop_tier_state == ARMED",
		     MovAbsRsi(A_STATE) + std::vector<u8>{0x83, 0x3e, (u8)config::kLoopTierArmed}, 0x85},
		    {"(3) the mailbox is free",
		     MovAbsR12(A_EVENT_IP) + std::vector<u8>{0x41, 0x83, 0x3c, 0x24, 0x00}, 0x85},
		    {"(4) this guest target has not notified before",
		     MovAbsRsi(A_NOTIFY) + std::vector<u8>{0x80, 0x3e, 0x00}, 0x85},
		};
		std::vector<long> targets;
		size_t prev = 0;
		bool ordered = true;
		for (auto const &gd : guards) {
			auto hits = FindBytes(back_on, gd.pat);
			checkf(hits.size() == 1, "guard %s is emitted exactly once (%zu)", gd.what, hits.size());
			if (hits.size() != 1)
				continue;
			ordered = ordered && hits[0] >= prev;
			prev = hits[0];
			size_t jat = hits[0] + gd.pat.size();
			bool right_jcc = (jat + 1 < back_on.size() && back_on[jat] == 0x0f &&
					  back_on[jat + 1] == gd.jcc_op) ||
					 (jat < back_on.size() && back_on[jat] == (u8)(gd.jcc_op - 0x10));
			checkf(right_jcc, "...and is followed by the %s form (%02x %02x)",
			       gd.jcc_op == 0x82 ? "JB" : "JNE", back_on[jat],
			       jat + 1 < back_on.size() ? back_on[jat + 1] : 0);
			targets.push_back(JccTarget(back_on, jat));
		}
		check(ordered, "the four guards are emitted in the stated order");
		bool same = targets.size() == 4 && targets[0] > 0;
		for (auto t : targets)
			same = same && t == targets[0];
		checkf(same, "all four guards skip FORWARD to the same join (%s)",
		       targets.empty() ? "none found" : "one target");
		if (same)
			g_join = (size_t)targets[0];
	}
	{
		// The claim, then the payload, then the bit -- in that order and between guard (4) and the
		// join. A consumer that sees the bit must be able to see the target, and a target that
		// claimed must really have delivered.
		auto claim = std::vector<u8>{0xc6, 0x06, 0x01};	    // mov byte [rsi], 1
		auto store = std::vector<u8>{0x41, 0xc7, 0x04, 0x24} + Imm32(BACK_TARGET); // mov [r12], ip
		auto c = FindBytes(back_on, claim), s = FindBytes(back_on, store);
		checkf(c.size() == 1, "the one-shot is claimed exactly once (%zu)", c.size());
		checkf(s.size() == 1, "the payload is the edge's own target, stored exactly once (%zu)",
		       s.size());
		auto svc = FindBytes(back_on, MovAbsRsi(A_SVC));
		checkf(c.size() == 1 && s.size() == 1 && svc.size() == 1 && c[0] < s[0] && s[0] < svc[0],
		       "claim -> payload -> service bit, in that order");
		// The service bit is set with ONE locked read-modify-write, as the word's contract requires.
		size_t lo = svc.empty() ? 0 : svc[0] + 10;
		bool locked = lo + 3 < back_on.size() && back_on[lo] == 0xf0;
		checkf(locked, "and the bit is set with a LOCKed or (%02x)", lo < back_on.size() ? back_on[lo] : 0);
		if (g_join) {
			checkf(!svc.empty() && svc[0] < g_join && g_join <= back_on.size(),
			       "the whole body lies before the join at %zu", g_join);
			HexDump("notification body", back_on, FindBytes(back_on, INC_R12)[0], g_join);
		}
		// The rule as the consumer states it, checked against the same numbers. `>=`, not `==`.
		check(!looptier::CrossedBar(BAR - 1, BAR) && looptier::CrossedBar(BAR, BAR) &&
			  looptier::CrossedBar(BAR + 1, BAR),
		      "looptier::CrossedBar agrees with the emitted `jb` at, below and above the bar");
	}

	// -------------------------------------------------------------------------------------
	section("3. only a direct BACKWARD edge carries it");
	auto notify_free = [&](char const *what, Guest const &g, u32 entry, u32 n_words) {
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		config::loop_tier = true;
		auto code = EmitAt(arena, g, entry, n_words);
		ResetConfig();
		size_t n = FindBytes(code, MovAbsRsi(A_STATE)).size() +
			   FindBytes(code, MovAbsRsi((uptr)BAR)).size() +
			   FindBytes(code, CMP_R12_RSI).size();
		checkf(n == 0, "%s carries no notification (%zu notification bytes found)", what, n);
		return code;
	};
	{
		Guest g;
		g.put(GUEST_BASE, enc_j(0, 0x80)); // jal x0, forward
		notify_free("a forward direct edge", g, GUEST_BASE, 1);
	}
	{
		Guest g;
		g.put(GUEST_BASE, enc_b(F3_BNE, 1, 2, 0x40)); // forward conditional: both arms forward
		notify_free("a forward conditional edge", g, GUEST_BASE, 1);
	}
	{
		Guest g; // a straight run of nops: the region-boundary fallthrough, no branch at all
		for (u32 i = 0; i < 4; ++i)
			g.put(GUEST_BASE + 4 * i, 0x00000013u);
		notify_free("the region-boundary fallthrough", g, GUEST_BASE, 4);
	}
	{
		Guest g;
		g.put(GUEST_BASE, enc_jalr(0, 1, 0)); // ret: an indirect edge
		notify_free("an indirect (jalr) edge", g, GUEST_BASE, 1);
	}
	{
		// The INTRA-REGION backward conditional arm, which is the case the frozen GEMM's hottest
		// loops actually take: the taken target is this region's own entry, so `t_gbr` is false,
		// the arm never becomes a gbr, and the notification has to ride `InstBrcc::t_backedge`
		// instead. Removing that flag was measured to make the tier see events only from blocks
		// that are not loop headers -- so this section is the one that keeps the fix honest.
		Guest g;
		g.put(GUEST_BASE, 0x00000013u);                 // nop
		g.put(GUEST_BASE + 4, enc_b(F3_BNE, 1, 2, -4)); // bne back to GUEST_BASE, INSIDE the region
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		config::loop_tier = true;
		auto code = EmitAt(arena, g, GUEST_BASE, 2);
		ResetConfig();
		checkf(FindBytes(code, CMP_R12_RSI).size() == 1,
		       "an intra-region backward conditional arm carries exactly one notification (%zu)",
		       FindBytes(code, CMP_R12_RSI).size());
	}
	{
		// And the region-exit form of the same shape: a BACKWARD CONDITIONAL branch whose taken
		// target leaves the region. Its taken arm is a gbr with InstGBr::backedge set, so it
		// carries the notification there -- exactly one, on the backward arm and not on the
		// fall-through.
		Guest g;
		// The branch target must be OUTSIDE the translated range, or the taken arm stays an
		// intra-region `brcc` to a block this same region contains and never becomes a `gbr` at
		// all -- which is a property of the region, not of this feature.
		g.put(GUEST_BASE, enc_b(F3_BNE, 1, 2, -0x80));
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		config::loop_tier = true;
		auto code = EmitAt(arena, g, GUEST_BASE, 1);
		ResetConfig();
		checkf(FindBytes(code, CMP_R12_RSI).size() == 1,
		       "a backward conditional branch carries exactly one notification, on its backward arm");
	}

	// -------------------------------------------------------------------------------------
	section("4. the flag-off path emits nothing, and the insertion disturbs nothing else");
	{
		checkf(back_on.size() > back_off.size(), "the flag adds %zu bytes",
		       back_on.size() - back_off.size());
		size_t grew = back_on.size() - back_off.size();
		// The FIRST byte where the two builds differ must be the displacement of the `jne` that
		// skips the counter update -- the only thing the insertion can legally change, because the
		// code it skips over got longer. Everything before it must be identical.
		size_t d = 0;
		while (d < back_off.size() && back_on[d] == back_off[d])
			d++;
		checkf(d > 0 && d < back_off.size(), "the two builds share a prefix and then differ (at %zu)", d);
		// The first difference must be the DISPLACEMENT of the jne that skips the counter update
		// (the code it jumps over got longer) -- not an instruction, not an opcode, not an operand.
		// The jne is `0F 85 <rel32>`, so the displacement starts two bytes after its opcode.
		bool jne_disp = d >= 2 && back_on[d - 2] == 0x0f && back_on[d - 1] == 0x85 &&
				back_off[d - 2] == 0x0f && back_off[d - 1] == 0x85;
		bool jne8_disp = !jne_disp && d >= 1 && back_on[d - 1] == 0x75 && back_off[d - 1] == 0x75;
		check(jne_disp || jne8_disp, "the first difference is a JNE displacement, not an instruction");
		long on_d = 0, off_d = 0;
		if (jne_disp && d + 4 <= back_on.size() && d + 4 <= back_off.size()) {
			memcpy(&on_d, &back_on[d], 4);
			memcpy(&off_d, &back_off[d], 4);
		} else if (jne8_disp) {
			on_d = (int8_t)back_on[d];
			off_d = (int8_t)back_off[d];
		}
		checkf((jne_disp || jne8_disp) && (size_t)(on_d - off_d) == grew,
		       "...and it grew by exactly the inserted length (%ld vs %zu)", on_d - off_d, grew);
		// Splice the insertion back out, repair that one displacement, and require the result to
		// be the flag-off bytes EXACTLY.
		auto inc_at = FindBytes(back_on, INC_R12);
		checkf(inc_at.size() == 1, "one counter increment to splice after (%zu)", inc_at.size());
		if (inc_at.size() == 1 && jne_disp) {
			size_t cut = inc_at[0] + INC_R12.size();
			std::vector<u8> spliced(back_on.begin(), back_on.begin() + (long)cut);
			spliced.insert(spliced.end(), back_on.begin() + (long)(cut + grew), back_on.end());
			if (d < spliced.size())
				spliced[d] = back_off[d];
			check(spliced == back_off,
			      "splicing the notification out reproduces the flag-off bytes exactly");
		}
	}
	{
		// Belt and braces: the flag-off build must not name any of the notification's addresses,
		// and must be identical to a build made with the whole config reset.
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80));
		// An off build must also allocate NOTHING: the notify table is the one piece of state the
		// emitter can grow, and "default off" means the process behaves as it did before the
		// feature existed. Counted across the emission rather than tested for emptiness, because
		// the sections above have legitimately populated it.
		size_t slots_before = config::loop_tier_notified.size();
		auto again = EmitAt(arena, g, GUEST_BASE, 1);
		check(again == back_off, "the flag-off build is deterministic");
		check(FindBytes(again, MovAbsRsi((uptr)BAR)).empty(),
		      "and never loads the bar: an off run pays nothing at all");
		checkf(config::loop_tier_notified.size() == slots_before,
		       "an off build allocates no notify slot at all (%zu before, %zu after)", slots_before,
		       config::loop_tier_notified.size());
	}

	// -------------------------------------------------------------------------------------
	section("5. no timer, no tick, no cadence anywhere in the request");
	{
		// The request's ONLY producer is the emitted notification. Setting the mode on and
		// translating a backward edge must not, by itself, make the word nonzero -- the code has to
		// RUN, and nothing here runs it.
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		config::loop_tier = true;
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80));
		(void)EmitAt(arena, g, GUEST_BASE, 1);
		check(!config::AnyServiceRequestPending(),
		      "translating the notification does not raise the request; only executing it can");
		check(*config::LoopTierNotifySlot(BACK_TARGET) == 0,
		      "...and translating does not claim the target's one-shot either");
		ResetConfig();
	}

	// -------------------------------------------------------------------------------------
	section("6. the AOT producer emits none of it");
	{
		// EVERY address the notification bakes -- the bar, &loop_tier_state, &loop_tier_event_ip,
		// the notify byte, &service_request -- belongs to THIS process. elfaot compiles in one
		// process and elfrun executes in another, so baking them into relocatable output would be
		// meaningless at best and a wild store at worst. `jit_mode` is what excludes that, and this
		// section is the check that it does.
		//
		// FAILS IF: the `jit_mode` conjunct is dropped from the emission guard. The offline AOT
		// artifact would then differ with the flag on -- which is also what the run's flag-off
		// byte-identity cell would catch, one process later and far less specifically.
		ResetConfig();
		config::sr_chunk_threshold = (long)BAR;
		Guest g;
		g.put(GUEST_BASE, enc_j(0, -0x80));
		auto aot_off = EmitWith<AotRuntime>(arena, g, GUEST_BASE, 1);
		config::loop_tier = true;
		auto aot_on = EmitWith<AotRuntime>(arena, g, GUEST_BASE, 1);
		ResetConfig();
		size_t baked = FindBytes(aot_on, MovAbsRsi((uptr)BAR)).size() +
			       FindBytes(aot_on, MovAbsRsi(A_STATE)).size() +
			       FindBytes(aot_on, MovAbsR12(A_EVENT_IP)).size() +
			       FindBytes(aot_on, MovAbsRsi(A_NOTIFY)).size() +
			       FindBytes(aot_on, MovAbsRsi(A_SVC)).size() +
			       FindBytes(aot_on, CMP_R12_RSI).size();
		checkf(baked == 0, "an AOT-mode compile bakes none of this process's addresses (%zu found)",
		       baked);
		check(aot_on == aot_off,
		      "and its output is byte-identical with the flag on and off");
	}

	// -------------------------------------------------------------------------------------
	section("7. the protocol, EXECUTED on the emitted bytes");
	{
		// A small bar, so a handful of calls can cross it, and three distinct guest targets. Each
		// target is reached from a HIGHER entry (a backward edge) and, for T1, also from a LOWER
		// one (a forward edge) -- two different edges counting the SAME guest block through the
		// SAME L1 entry, which is the sharing this checkpoint is about.
		u64 const B = 4;
		u32 const T1 = 0x0900, T2 = 0x0904, T3 = 0x0908;
		u32 const BACK1 = 0x0980, BACK2 = 0x0984, BACK3 = 0x0988, FWD1 = 0x0880;
		// One direct edge from `entry` to `t`, translated with the tier on. Backward or forward is
		// decided by the addresses alone -- by the translator's own IsDirectBackwardEdge, never by
		// this test.
		auto build_edge = [&](u32 entry, u32 t, std::vector<u8> *out) {
			Guest g;
			g.put(entry, enc_j(0, (int32_t)t - (int32_t)entry));
			ResetConfig();
			config::sr_chunk_threshold = (long)B;
			config::loop_tier = true;
			*out = EmitAt(arena, g, entry, 1);
			ResetConfig();
		};
		// [start, stop) of the counter-update sequence: from the L1 base load to the join every
		// guard jumps to. For the forward form there is no guard, so the sequence ends after the
		// increment -- which is exactly the claim that a forward edge only counts.
		auto seq = [&](std::vector<u8> const &code, bool with_notify, size_t *start, size_t *stop) {
			auto l1 = FindBytes(code, MovAbsR12(A_L1));
			auto inc = FindBytes(code, INC_R12);
			if (l1.size() != 1 || inc.size() != 1 || inc[0] < l1[0])
				return false;
			*start = l1[0];
			if (!with_notify) {
				*stop = inc[0] + INC_R12.size();
				return true;
			}
			auto cmp = FindBytes(code, CMP_R12_RSI);
			if (cmp.size() != 1)
				return false;
			long j = JccTarget(code, cmp[0] + CMP_R12_RSI.size());
			if (j <= 0 || (size_t)j > code.size())
				return false;
			*stop = (size_t)j;
			return true;
		};

		std::vector<u8> c1, cf, c2, c3;
		build_edge(BACK1, T1, &c1);
		build_edge(FWD1, T1, &cf);
		size_t s0, s1;
		Runnable back1, fwd;
		bool built = seq(c1, true, &s0, &s1) && back1.Build(c1, s0, s1);
		checkf(built, "the emitted notification sequence is executable [%zu,%zu)", s0, s1);
		size_t f0, f1;
		bool builtf = seq(cf, false, &f0, &f1) && fwd.Build(cf, f0, f1);
		checkf(builtf, "so is the forward edge's bare counter update [%zu,%zu)", f0, f1);
		if (!built || !builtf) {
			printf("\nRESULT checks=%d failures=%d\n", g_checks, g_failed);
			printf("LOOPTIER_EVENT_TEST FAIL\n");
			return 1;
		}

		TBlock tb1{};
		tb1.ip = T1;
		InstallL1(T1, &tb1);
		config::loop_tier = true;
		config::sr_chunk_threshold = (long)B;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		config::service_request.store(0, std::memory_order_relaxed);
		*config::LoopTierNotifySlot(T1) = 0;

		// --- below the bar: the sequence counts and says nothing.
		back1.Run(3);
		checkf(tb1.flags.exec_count == 3, "three backward arrivals counted (%llu)",
		       (unsigned long long)tb1.flags.exec_count);
		check(!config::AnyServiceRequestPending() && config::loop_tier_event_ip == 0,
		      "below the bar: nothing is notified");
		check(*config::LoopTierNotifySlot(T1) == 0, "...and the one-shot is untouched");

		// --- THE DEFECT T5d2a1 HAD: a NON-BACKEDGE arrival takes the counter TO the bar. Under
		// `== bar` the equality is consumed here, by code that carries no notification, and the
		// backward edge below would then see bar+1 and never notify at all.
		InstallL1(T1, &tb1); // the forward form counts the same target through the same L1 entry
		fwd.Run(1);
		checkf(tb1.flags.exec_count == B, "a FORWARD arrival lands the counter exactly on the bar (%llu)",
		       (unsigned long long)tb1.flags.exec_count);
		check(!config::AnyServiceRequestPending(),
		      "...and notifies nothing itself: a forward edge only counts");

		// --- the next backward edge observes >= bar and notifies exactly once.
		back1.Run(1);
		checkf(tb1.flags.exec_count == B + 1, "the backward edge counts past the bar (%llu)",
		       (unsigned long long)tb1.flags.exec_count);
		check((bool)config::loop_tier_due, "the service bit is raised on that edge");
		checkf(config::loop_tier_event_ip == T1, "the mailbox names the target that notified (%08x)",
		       config::loop_tier_event_ip);
		check(*config::LoopTierNotifySlot(T1) == 1, "the target's one-shot is claimed");
		checkf(config::service_request.load(std::memory_order_relaxed) == config::kSvcLoopTier,
		       "and no other service bit was disturbed (%08x)",
		       config::service_request.load(std::memory_order_relaxed));

		// --- REJECTION: the consumer drains the mailbox and leaves the tier ARMED. Repeated
		// backward edges from the same target must never notify again -- this is the livelock the
		// `>=` form would have if the one-shot were not durable.
		config::loop_tier_due = false;
		config::loop_tier_event_ip = 0;
		back1.Run(1000);
		checkf(tb1.flags.exec_count == B + 1001, "a thousand more arrivals are counted (%llu)",
		       (unsigned long long)tb1.flags.exec_count);
		check(!config::AnyServiceRequestPending() && config::loop_tier_event_ip == 0,
		      "a rejected target, still ARMED and far above the bar, notifies nothing again");

		// --- RETRANSLATION: invalidate the translation cache, translate the same guest edge
		// again, and give the target a FRESH TBlock whose counter starts at zero. A one-shot held
		// in the TBlock would rearm here; one keyed by the guest ip does not.
		tcache::Invalidate();
		build_edge(BACK1, T1, &c2);
		size_t r0, r1;
		Runnable back1b;
		bool rebuilt = seq(c2, true, &r0, &r1) && back1b.Build(c2, r0, r1);
		check(rebuilt, "the same guest target retranslates into an executable sequence");
		checkf(!FindBytes(c2, MovAbsRsi((uptr)config::LoopTierNotifySlot(T1))).empty(),
		       "the retranslation names the SAME notify byte (%p)",
		       (void *)config::LoopTierNotifySlot(T1));
		TBlock tb1b{};
		tb1b.ip = T1;
		InstallL1(T1, &tb1b);
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = 0;
		config::service_request.store(0, std::memory_order_relaxed);
		if (rebuilt)
			back1b.Run(2 * B + 5);
		checkf(tb1b.flags.exec_count == 2 * B + 5, "the fresh TBlock counts from zero again (%llu)",
		       (unsigned long long)tb1b.flags.exec_count);
		check(!config::AnyServiceRequestPending() && config::loop_tier_event_ip == 0,
		      "and the retranslated target does NOT notify again: the one-shot survived the cache");

		// --- TERMINAL STATES: a different, never-notified target, far above the bar, must not
		// store a payload, must not set the bit, and must not claim its own one-shot.
		build_edge(BACK2, T2, &c3);
		size_t t0, t1;
		Runnable back2;
		bool built2 = seq(c3, true, &t0, &t1) && back2.Build(c3, t0, t1);
		check(built2, "a second, never-notified target is executable too");
		TBlock tb2{};
		tb2.ip = T2;
		InstallL1(T2, &tb2);
		*config::LoopTierNotifySlot(T2) = 0;
		struct {
			char const *name;
			int st;
		} terminal[] = {{"BUILDING", 2}, {"PUBLISHED", 3}, {"FAILED", 4}, {"ABSTAINED", 5}};
		for (auto const &t : terminal) {
			config::loop_tier_state = t.st;
			config::loop_tier_event_ip = 0;
			config::service_request.store(0, std::memory_order_relaxed);
			if (built2)
				back2.Run(2 * B);
			checkf(!config::AnyServiceRequestPending() && config::loop_tier_event_ip == 0 &&
				   *config::LoopTierNotifySlot(T2) == 0,
			       "after %s a hot target overwrites no payload, sets no bit, escapes nothing",
			       t.name);
		}
		checkf(tb2.flags.exec_count == 4 * 2 * B,
		       "...while still being counted normally, so the zeros above are not a dead sequence (%llu)",
		       (unsigned long long)tb2.flags.exec_count);
		// The control that makes those four zeros mean something: the SAME target, the SAME code,
		// with the tier ARMED, does notify.
		config::loop_tier_state = config::kLoopTierArmed;
		if (built2)
			back2.Run(1);
		check((bool)config::loop_tier_due && config::loop_tier_event_ip == T2 &&
			  *config::LoopTierNotifySlot(T2) == 1,
		      "and with the tier ARMED again the very same sequence notifies -- the guard is the state");

		// --- THE MAILBOX: an occupied slot is never overwritten, and the target that finds it
		// occupied keeps its one-shot for a later attempt.
		std::vector<u8> c4;
		build_edge(BACK3, T3, &c4);
		size_t m0, m1;
		Runnable back3;
		bool built3 = seq(c4, true, &m0, &m1) && back3.Build(c4, m0, m1);
		check(built3, "a third target is executable");
		TBlock tb3{};
		tb3.ip = T3;
		InstallL1(T3, &tb3);
		*config::LoopTierNotifySlot(T3) = 0;
		config::loop_tier_state = config::kLoopTierArmed;
		config::loop_tier_event_ip = T2; // a notification already in flight
		config::service_request.store(config::kSvcLoopTier, std::memory_order_relaxed);
		if (built3)
			back3.Run(2 * B);
		checkf(config::loop_tier_event_ip == T2, "an occupied mailbox is not overwritten (%08x)",
		       config::loop_tier_event_ip);
		check(*config::LoopTierNotifySlot(T3) == 0,
		      "...and the target that found it occupied keeps its one-shot INTACT");
		config::loop_tier_event_ip = 0; // the consumer drains it
		config::service_request.store(0, std::memory_order_relaxed);
		if (built3)
			back3.Run(1);
		check(config::loop_tier_event_ip == T3 && *config::LoopTierNotifySlot(T3) == 1,
		      "so once the slot is free it notifies -- no evidence was dropped, only deferred");

		// The rule as the consumer states it, at every point section 7 executed.
		check(!looptier::ShouldNotify(B - 1, B, config::kLoopTierArmed, 0, 0) &&
			  looptier::ShouldNotify(B, B, config::kLoopTierArmed, 0, 0) &&
			  looptier::ShouldNotify(B + 1000, B, config::kLoopTierArmed, 0, 0) &&
			  !looptier::ShouldNotify(B + 1, B, 3, 0, 0) &&
			  !looptier::ShouldNotify(B + 1, B, config::kLoopTierArmed, 0x700, 0) &&
			  !looptier::ShouldNotify(B + 1, B, config::kLoopTierArmed, 0, 1),
		      "looptier::ShouldNotify agrees with the executed sequence at all four guards");
		ResetConfig();
	}

	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_failed);
	printf("%s\n", g_failed == 0 ? "LOOPTIER_EVENT_TEST PASS" : "LOOPTIER_EVENT_TEST FAIL");
	return g_failed == 0 ? 0 : 1;
}
