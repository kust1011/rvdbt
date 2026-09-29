// C5c focused test: the promotion-route census READS, and reads the right things.
//
// WHAT IS BEING CLAIMED, and this file drives all of it:
//
//   (a) with the flag off the census writes NOTHING -- not a short line, not a header, nothing;
//   (b) it is a PURE READ: every structure a promotion could care about is byte-identical across a
//       call, INCLUDING `l1_cache[l1hash(gip)]`, which is the one an implementation written on top
//       of `tcache::Lookup` instead of `PeekBlock` would silently warm;
//   (c) the link-index split is by pointer identity against the two tags it is given, and a slot
//       registered for a DIFFERENT target is not counted;
//   (d) the three caches (indirect L1, Emit_Cache profiling L1, inline-cache blobs) are each read
//       at the header's own slot and classified, including the T5g fingerprint state where the
//       profiling cache names an AOT block;
//   (e) the interior bound is conservative AND non-vacuous -- a bound derived from the map's own
//       successor key would be identically zero whenever the header has a block of its own, which
//       is always, so a test that only asserted "conservative" would pass on a useless metric;
//   (f) the emitted line carries every key, unconditionally.
//
// EVERY CHECK BELOW STATES THE FAILURE PATH IT IS SENSITIVE TO, because an assertion whose failure
// mode is not stated is not evidence. They are listed per section.
//
// WHAT THIS FILE DELIBERATELY DOES NOT DO. It installs nothing, loads no artifact, executes no
// generated code, repoints nothing and times nothing. The census is a diagnostic; whether the
// numbers it prints are large or small is a question about a real run, answered there.

#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/tcache/tcache.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

using namespace dbt;
using namespace dbt::looptier;

static int g_checks = 0, g_fail = 0;
static void CHECK(bool ok, char const *what)
{
	g_checks++;
	g_fail += !ok;
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
}
__attribute__((format(printf, 2, 3))) static void CHECKF(bool ok, char const *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	CHECK(ok, buf);
}
static void SECTION(char const *s)
{
	printf("\n%s\n", s);
}

// A real, writable `BranchSlot`. Nothing executes it; what matters is the bytes `Link` writes and
// the bytes the census decodes back.
struct SlotBuf {
	alignas(16) unsigned char raw[64];
	jitabi::ppoint::BranchSlot *slot()
	{
		return (jitabi::ppoint::BranchSlot *)raw;
	}
};

// A host address that is deliberately NOT in the JIT code pool, standing in for an artifact's
// entry. Its only job is to be a distinct pointer the census must classify as `aot` and must not
// classify as `in_pool`.
alignas(16) static unsigned char g_fake_artifact[64];

static TBlock *PlantQcg(u32 ip, u32 insns)
{
	auto *tb = tcache::AllocateTBlock();
	tb->ip = ip;
	tb->tcode = TBlock::TCode{tcache::AllocateCode(64, 16), 64};
	memset(tb->tcode.ptr, 0x90, 64);
	tb->flags.exec_instr_count = insns;
	tcache::InsertOrReplace(tb);
	return tb;
}

// Capture everything written to fd 2 while `fn` runs. Used for (a) and (f).
template <typename F>
static std::string CaptureStderr(F &&fn)
{
	int pipefd[2];
	if (pipe(pipefd) != 0)
		return "<pipe failed>";
	int saved = dup(2);
	fflush(stderr);
	dup2(pipefd[1], 2);
	close(pipefd[1]);
	fn();
	fflush(stderr);
	dup2(saved, 2);
	close(saved);
	std::string out;
	char buf[4096];
	// The census writes ONE line with a single write(2), so a single non-blocking drain is enough;
	// the fd is set non-blocking so a census that wrote nothing does not hang this test.
	int fl = fcntl(pipefd[0], F_GETFL, 0);
	fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);
	for (;;) {
		ssize_t n = read(pipefd[0], buf, sizeof buf);
		if (n <= 0)
			break;
		out.append(buf, (size_t)n);
	}
	close(pipefd[0]);
	return out;
}

// The observable routing state, captured so "pure read" is measured rather than argued.
struct RouteSnapshot {
	TBlock *l1_tb;
	tcache::BrindCacheEntry brind;
	tcache::CacheTbExecCountEntry exec;
	unsigned long long exec_count_value;
	size_t links;
	unsigned long tier[4];
	unsigned char slot_bytes[64];
	bool operator==(RouteSnapshot const &o) const
	{
		return l1_tb == o.l1_tb && brind.gip == o.brind.gip && brind.code == o.brind.code &&
		       exec.gip == o.exec.gip && exec.tb == o.exec.tb &&
		       exec_count_value == o.exec_count_value && links == o.links &&
		       tier[0] == o.tier[0] && tier[1] == o.tier[1] && tier[2] == o.tier[2] &&
		       tier[3] == o.tier[3] && memcmp(slot_bytes, o.slot_bytes, sizeof slot_bytes) == 0;
	}
};

static RouteSnapshot Snap(u32 gip, SlotBuf &sb)
{
	RouteSnapshot s{};
	auto h = tcache::l1hash(gip);
	s.l1_tb = tcache::l1_cache[h];
	s.brind = tcache::l1_brind_cache[h];
	s.exec = tcache::cache_tb_exec_count[h];
	s.exec_count_value = s.exec.tb ? s.exec.tb->flags.exec_count : 0;
	s.links = tcache::LinkMapSize();
	tcache::TierCensus(s.tier);
	memcpy(s.slot_bytes, sb.raw, sizeof s.slot_bytes);
	return s;
}

int main()
{
	printf("C5c loop-tier promotion-route census test\n");
	tcache::Init();

	u32 const GIP = 0x11890;	 // the promoted header under test
	u32 const OTHER = 0x11a00;	 // a different target, used to prove the walk is scoped
	u32 const PREV_SAME_PAGE = 0x11840; // a lower TB on the SAME page as GIP
	auto const H = tcache::l1hash(GIP);

	auto *qcg = PlantQcg(GIP, 64);
	auto *other_tb = PlantQcg(OTHER, 8);
	void const *qcg_ptr = qcg->tcode.ptr;
	void const *aot_ptr = (void const *)g_fake_artifact;

	// Three real predecessor slots for GIP: one linked to the QCG code, one linked to the
	// stand-in artifact entry, one never linked at all.
	static SlotBuf s_qcg{}, s_aot{}, s_lazy{}, s_other{};
	s_qcg.slot()->gip = GIP;
	s_qcg.slot()->Link(qcg->tcode.ptr);
	tcache::RecordLink(s_qcg.slot(), qcg, false);
	s_aot.slot()->gip = GIP;
	s_aot.slot()->Link(g_fake_artifact);
	tcache::RecordLink(s_aot.slot(), qcg, false);
	s_lazy.slot()->gip = GIP;
	s_lazy.slot()->LinkLazyJIT();
	tcache::RecordLink(s_lazy.slot(), qcg, false);
	// ...and one registered for a DIFFERENT target, which must not be counted.
	s_other.slot()->gip = OTHER;
	s_other.slot()->Link(other_tb->tcode.ptr);
	tcache::RecordLink(s_other.slot(), other_tb, false);

	// -------------------------------------------------------------------------------------
	SECTION("1. default off: the census writes nothing at all");
	// FAILURE PATH: an emitter that prints a header, or a zero line, or anything before testing
	// the flag, makes this non-empty. This is the check that makes "default off" mean the process
	// behaves as it did before this file existed.
	{
		config::loop_tier_route_census = false;
		config::loop_tier_install_host = 0;
		ResetRouteCensus();
		auto out = CaptureStderr([&] { RouteCensusEmit("pre_install", GIP); });
		CHECKF(out.empty(), "flag off emits 0 bytes (got %zu)", out.size());
	}

	// -------------------------------------------------------------------------------------
	SECTION("2. pure read: nothing observable moves across a census");
	// FAILURE PATH, and it is the specific one this check exists for: `l1_cache[l1hash(GIP)]` is
	// cleared below, so an implementation that reached the map through `tcache::Lookup` instead of
	// `tcache::PeekBlock` would WARM it and `l1_tb` would change from nullptr to `qcg`. The rest of
	// the snapshot catches any accidental write to the two L1 caches, the link index, the map or
	// the predecessor slot's own bytes.
	{
		config::loop_tier_route_census = true;
		tcache::l1_cache[H] = nullptr; // the state a Lookup-based implementation would destroy
		tcache::l1_brind_cache[H] = {GIP, (void *)qcg->tcode.ptr};
		tcache::cache_tb_exec_count[H] = {GIP, qcg};
		qcg->flags.exec_count = 12345;

		auto before = Snap(GIP, s_qcg);
		tcache::RouteCensusOut o{};
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		auto after_walk = Snap(GIP, s_qcg);
		CHECK(before == after_walk, "tcache::RouteCensus moves nothing observable");
		CHECKF(tcache::l1_cache[H] == nullptr,
		       "and it did NOT warm l1_cache[l1hash(gip)] (a Lookup-based census would have)");

		ResetRouteCensus();
		(void)CaptureStderr([&] { RouteCensusEmit("pre_install", GIP); });
		auto after_emit = Snap(GIP, s_qcg);
		CHECK(before == after_emit, "RouteCensusEmit moves nothing observable either");
		CHECK(tcache::l1_cache[H] == nullptr, "and the emitter did not warm it either");
	}

	// -------------------------------------------------------------------------------------
	SECTION("3. the link-index split, by pointer identity against the two tags");
	// FAILURE PATH: a decoder that handles only `jmp rel32` and not the absolute form (or vice
	// versa) pushes a slot into `link_undecodable`; a classifier that compares TBlock pointers
	// instead of code pointers cannot tell the two linked slots apart; an implementation that
	// folds the never-linked slot into `other` makes `link_lazy` zero and `other` two, which would
	// let an UNLINKED edge be read as a live predecessor the promotion missed.
	{
		tcache::RouteCensusOut o{};
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		CHECKF(o.link_slots == 3, "link_slots == 3 for this header (got %u)", o.link_slots);
		CHECKF(o.link_to_qcg == 1, "link_to_old_qcg == 1 (got %u)", o.link_to_qcg);
		CHECKF(o.link_to_aot == 1, "link_to_aot == 1 (got %u)", o.link_to_aot);
		CHECKF(o.link_lazy == 1, "link_lazy == 1, reported as its own class (got %u)", o.link_lazy);
		CHECKF(o.link_to_other == 0, "link_to_other == 0 (got %u)", o.link_to_other);
		CHECKF(o.link_undecodable == 0, "every linked slot decoded (undecodable=%u)",
		       o.link_undecodable);
		CHECKF(o.link_in_pool == 1,
		       "the independent code-pool classifier agrees: exactly the QCG-linked slot is in "
		       "the pool (got %u)",
		       o.link_in_pool);
		CHECKF(o.link_slots == o.link_to_qcg + o.link_to_aot + o.link_to_other + o.link_lazy +
					   o.link_undecodable,
		       "the five classes partition link_slots exactly");
	}

	// -------------------------------------------------------------------------------------
	SECTION("4. the walk is scoped to this target");
	// FAILURE PATH: an implementation that iterated the whole `link_map` instead of
	// `equal_range(gip)` would report 4 here, and would then over-predict what a repoint buys.
	{
		tcache::RouteCensusOut o{};
		tcache::RouteCensus(OTHER, other_tb->tcode.ptr, aot_ptr, &o);
		CHECKF(o.link_slots == 1, "the other target has its own single slot (got %u)", o.link_slots);
		CHECKF(o.link_to_qcg == 1, "and it is classified against ITS tag (got %u)", o.link_to_qcg);
	}

	// -------------------------------------------------------------------------------------
	SECTION("5. the three caches, at the header's own slot");
	// FAILURE PATH: reading the wrong array index (a different hash, or the block cache instead of
	// the brind cache) makes every tag_hit zero, which would look exactly like "this workload does
	// not use that path" -- the false negative this section exists to exclude.
	{
		tcache::RouteCensusOut o{};
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		CHECK(o.brind_tag_hit == 1 && o.brind_is_qcg == 1 && o.brind_is_aot == 0,
		      "l1_brind_cache: tag hit, and the cached raw pointer is the QCG code");
		CHECK(o.brind_in_pool == 1, "and the code-pool classifier agrees about it");
		CHECK(o.exec_tag_hit == 1 && o.exec_tb_is_qcg == 1 && o.exec_tb_is_aot == 0,
		      "cache_tb_exec_count: tag hit, naming the QCG block");
		CHECK(o.exec_tb_is_cur == 1, "and that block is the one the map currently holds");
		CHECKF(o.exec_count == 12345, "the counter's VALUE is reported (got %llu)", o.exec_count);
		CHECKF(o.ic_blobs == 0, "no inline-cache blob names this target yet (got %u)", o.ic_blobs);
	}

	// -------------------------------------------------------------------------------------
	SECTION("6. the T5g fingerprint state is representable");
	// This is the state T5g recorded: the map holds an announce-shaped AOT block for the header
	// while the profiling cache names that same AOT block, so the emitted QCG counter credits an
	// artifact that is not running. If the census could not distinguish it, C5B's §4.2 argument
	// would be unfalsifiable.
	// FAILURE PATH: a classifier that decided "AOT" from the MAP rather than from the cache entry
	// would report the same answer in both of the two states below.
	{
		auto *aot_tb = tcache::AllocateTBlock();
		aot_tb->ip = GIP;
		aot_tb->tcode = TBlock::TCode{(void *)g_fake_artifact, 0}; // announce shape: size == 0
		aot_tb->flags.exec_count = 777;
		tcache::InsertOrReplace(aot_tb);
		tcache::cache_tb_exec_count[H] = {GIP, aot_tb};

		tcache::RouteCensusOut o{};
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		CHECK(o.cur_present == 1 && o.cur_is_aot == 1, "the map now holds the AOT-shaped block");
		CHECK(o.exec_tag_hit == 1 && o.exec_tb_is_aot == 1 && o.exec_tb_is_qcg == 0,
		      "and the profiling cache is seen to name an AOT block -- the T5g fingerprint");
		CHECKF(o.exec_count == 777, "with that block's own counter value (got %llu)", o.exec_count);
		CHECK(o.link_to_qcg == 1 && o.link_to_aot == 1,
		      "the link split still classifies against the tags, not against the map");

		// Put the QCG block back so later sections read the state they were written for.
		tcache::InsertOrReplace(qcg);
		tcache::cache_tb_exec_count[H] = {GIP, qcg};
	}

	// -------------------------------------------------------------------------------------
	SECTION("7. inline-cache blobs are counted");
	// FAILURE PATH: `ic_target_map` is a multimap keyed by target gip; counting the wrong map (or
	// the site map) would report 0 with a blob present, and the E3 leak would look absent.
	{
		static unsigned char blob[64] = {0x81, 0xfe};
		memcpy(blob + 2, &GIP, 4);
		tcache::ICMarkPatched(GIP, blob);
		tcache::RouteCensusOut o{};
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		CHECKF(o.ic_blobs == 1, "one patched blob names this target (got %u)", o.ic_blobs);
		tcache::ICUnpatchTarget(GIP);
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		CHECKF(o.ic_blobs == 0, "and none after it is unpatched (got %u)", o.ic_blobs);
	}

	// -------------------------------------------------------------------------------------
	SECTION("8. the interior bound is conservative AND non-vacuous");
	// THE POINT OF THIS SECTION. A bound derived from the map's own successor key -- "T's range
	// ends at the next key" -- is identically ZERO whenever the header has a block of its own,
	// which it always does, because the header IS the next key. Such a metric would pass a test
	// that only checked "it is an upper bound". So the bound is derived from the PAGE (a
	// compilation range never crosses one) and refined by 4 bytes per guest instruction, and both
	// halves are checked here.
	// FAILURE PATH: a successor-key bound makes ub_page 0; a bound that forgot the page clip
	// counts a TB on an earlier page; a refinement that used 2 bytes per instruction would
	// UNDER-count and stop being an upper bound.
	{
		auto *prev = PlantQcg(PREV_SAME_PAGE, 64); // 0x11840 + 4*64 = 0x11940 > GIP
		auto *prev_short = PlantQcg(PREV_SAME_PAGE - 0x20, 2); // ends well before GIP
		auto *earlier_page = PlantQcg(GIP - mmu::PAGE_SIZE, 4096);
		(void)prev;
		(void)prev_short;
		(void)earlier_page;
		tcache::RouteCensusOut o{};
		tcache::RouteCensus(GIP, qcg_ptr, aot_ptr, &o);
		CHECKF(o.interior_ub_page >= 2,
		       "both same-page predecessors are in the page bound (got %u)", o.interior_ub_page);
		CHECKF(o.interior_ub_insn >= 1 && o.interior_ub_insn < o.interior_ub_page,
		       "the instruction refinement is strictly tighter and still non-zero (page=%u insn=%u)",
		       o.interior_ub_page, o.interior_ub_insn);
		bool saw_earlier_page = false;
		for (u32 i = 0; i < o.interior_n; ++i)
			saw_earlier_page |= o.interior_ip[i] == GIP - mmu::PAGE_SIZE;
		CHECK(!saw_earlier_page, "a TB on an EARLIER page is not a candidate");
	}

	// -------------------------------------------------------------------------------------
	SECTION("9. the emitted line carries every key, unconditionally");
	// FAILURE PATH: a key printed only when non-zero cannot be told from a key a build forgot, and
	// the offline parser gate would silently accept a truncated line. This is the in-process half
	// of that gate; scripts/c5c_parse.py is the offline half and requires the same key set.
	{
		config::loop_tier_route_census = true;
		config::loop_tier_install_host = (unsigned long long)(uptr)g_fake_artifact;
		ResetRouteCensus();
		auto line = CaptureStderr([&] { RouteCensusEmit("pre_install", GIP); });
		static char const *const KEYS[] = {
		    "when=pre_install", "gip=00011890", "cur_present=", "cur_is_aot=", "cur_ptr=0x",
		    "l1_tb_is_cur=", "qcg=0x", "aot=0x", "link_slots=", "link_to_old_qcg=",
		    "link_to_aot=", "link_to_other=", "link_lazy=", "link_in_pool=", "link_undecodable=",
		    "brind_tag_hit=", "brind_is_old_qcg=", "brind_is_aot=", "brind_in_pool=",
		    "execcount_tag_hit=", "execcount_tb_is_old_qcg=", "execcount_tb_is_aot=",
		    "execcount_tb_is_cur=", "execcount_value=", "ic_blobs=", "interior_ub_page=",
		    "interior_ub_insn=", "interior_list=", "interior_bound=conservative_no_ip_end"};
		bool all = true;
		for (auto const *k : KEYS) {
			if (line.find(k) == std::string::npos) {
				printf("    missing key: %s\n", k);
				all = false;
			}
		}
		CHECK(all, "every key of the census line is present");
		CHECK(line.find('\n') != std::string::npos && line.back() == '\n',
		      "the line is newline-terminated and written whole");
		CHECKF(line.find("LOOPTIER_ROUTE_CENSUS") == 0,
		       "and it starts with its own prefix (line starts: %.32s)", line.c_str());

		auto exit_line = CaptureStderr([&] { RouteCensusEmit("guest_exit", GIP); });
		CHECK(exit_line.find("when=guest_exit") != std::string::npos,
		      "the second sample is labelled guest_exit");
		CHECK(exit_line.find("aot=0x0 ") == std::string::npos,
		      "and it carries the installed host entry as the aot tag");
	}

	// -------------------------------------------------------------------------------------
	SECTION("10. a run whose tier selected nothing says so instead of censusing ip 0");
	// FAILURE PATH: without this, a never-armed run would print a full line about guest ip 0 and an
	// analyser could not tell "no target" from "a target with an empty fan-in" -- which are the two
	// answers this whole campaign exists to separate.
	{
		auto line = CaptureStderr([&] { RouteCensusEmit("guest_exit", 0); });
		CHECK(line.find("skipped=no_target") != std::string::npos,
		      "gip 0 is reported as skipped=no_target");
		CHECK(line.find("link_slots=") == std::string::npos,
		      "and no count is invented for it");
	}

	config::loop_tier_route_census = false;
	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_fail);
	printf("LOOPTIER_ROUTE_CENSUS_TEST %s\n", g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
