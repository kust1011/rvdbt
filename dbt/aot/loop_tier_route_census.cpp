// C5c: THE PROMOTION-ROUTE CENSUS -- one line, twice, and it changes nothing.
//
// WHAT IT IS FOR, in one sentence: C5B's root-cause analysis of T5g concludes that the installed
// artifact is entered once because four of the five entry classes into the promoted header still
// name the old QCG code after `tcache::InsertOrReplace`, and it proposes repointing them; that
// proposal has a PREMISE -- a non-empty `link_map[gip]` at the instant of the install -- which no
// preserved T5g artifact records, and this file measures exactly that premise.
//
// WHAT IT IS NOT. It is not `RepointTarget`, it is not a partial version of it, and it must not
// become one. It performs no `Link`, no `RelinkTo`, no `CacheBr`, no `CacheBrind`, no
// `RevokeTarget`, no `ICUnpatchTarget`, no `InsertOrReplace` and no `trampoline_to_jit`. Audit gate
// T14 reads this file's symbols and fails if any of those names appears, for the same reason gates
// T11 and T12 read the loader's and the installer's: "this code cannot repoint anything" is a
// statement about the code, so it is checked against the code.
//
// WHY A TRANSLATION UNIT OF ITS OWN, and not two lines inside `loop_tier_install.cpp`. Gate T12
// forbids the installer from naming `l1_brind_cache`, `cache_tb_exec_count`, `CacheBr`, `RelinkTo`
// and the rest, and that gate is an accepted property of T5d2b2 which this checkpoint must leave
// holding VERBATIM. The installer therefore calls one function by name and learns nothing about
// what it reads; every structure name lives here and in `tcache`.
//
// WHERE THE ACTUAL READING HAPPENS. In `tcache::RouteCensus` (dbt/tcache/tcache.cpp), because
// `tcache_map`, `link_map` and `ic_target_map` are that class's private indexes and the honest way
// to read a private index is a method on its owner. This file owns the two things that are NOT
// tcache's: which instant is being sampled, and the pre-promotion host entry that the second sample
// classifies against.
//
// COST. Two host-stack C++ calls in a run that asked for them, and a first-statement return in one
// that did not. No generated instruction changes, nothing is emitted into any translation, and no
// admission decision reads any of it. A run that sets the flag is a MECHANISM run: its wall clock is
// not a measurement and must not be quoted.

#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"
#include "dbt/tcache/tcache.h"

#include <cstdarg>
#include <cstdio>

extern "C" {
#include <unistd.h>
}

namespace dbt::looptier
{

// One line, assembled on the stack and written with a single write(2) -- the same discipline
// `loop_tier.cpp`'s `Event` uses and for the same reason: these lines interleave with a child's on
// the same fd, and a partially buffered line is not evidence. 2048 rather than 1024 because the
// interior list is variable-length and a truncated census line must not look like a short one.
__attribute__((format(printf, 1, 2))) static void CensusLine(char const *fmt, ...)
{
	char line[2048];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(line, sizeof line, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof line)
		n = (int)sizeof line - 1;
	(void)!write(2, line, (size_t)n);
}

// THE LATCH, and the only mutable state in this file.
//
// It holds the `tcode.ptr` the promoted header's block had at the FIRST sample -- i.e. before the
// installer replaced it. The second sample needs it because after the install the old QCG block is
// no longer in `tcache_map`: without the latch, a slot still jumping at the pre-promotion code
// would be classified as "other", which is precisely the distinction C5B's premise turns on.
//
// It is written at most once per process and only by the first sample that finds a non-AOT block,
// so a run whose header was already AOT-served (there is no such run today; `--aot 0` is a
// precondition of arming) leaves it null and the line reports `qcg=0x0` rather than a wrong tag.
static void const *g_qcg_tag = nullptr;
static bool g_qcg_tag_set = false;

void ResetRouteCensus()
{
	g_qcg_tag = nullptr;
	g_qcg_tag_set = false;
}

void RouteCensusEmit(char const *when, u32 gip)
{
	// DEFAULT OFF MEANS THE PROCESS BEHAVES AS IT DID BEFORE THIS FILE EXISTED, and the first
	// statement is what makes that true rather than the call sites' discipline.
	if (!config::loop_tier_route_census)
		return;
	if (!when)
		when = "?";
	if (gip == 0) {
		// Not a failure: a run whose tier never selected a header has nothing to census, and
		// saying so is better than printing a line about ip 0.
		CensusLine("LOOPTIER_ROUTE_CENSUS when=%s gip=00000000 skipped=no_target\n", when);
		return;
	}

	// The pre-promotion tag, latched on the first sample. `PeekBlock` is the map read that does
	// NOT warm `l1_cache`; using `Lookup` here would make the census change which entry the next
	// dispatch finds, which is the one thing a pure read may not do.
	if (!g_qcg_tag_set) {
		auto const *tb = tcache::PeekBlock(gip);
		if (tb && tb->tcode.size != 0) {
			g_qcg_tag = tb->tcode.ptr;
			g_qcg_tag_set = true;
		}
	}
	// The installed host entry, or 0 before an install. Read from the installer's own record so
	// the two files cannot disagree about what was installed.
	auto const *aot_tag = (void const *)(uptr)config::loop_tier_install_host;

	tcache::RouteCensusOut o{};
	tcache::RouteCensus(gip, g_qcg_tag, aot_tag, &o);

	char interior[512];
	int used = 0;
	interior[0] = '\0';
	for (u32 i = 0; i < o.interior_n; ++i) {
		int w = snprintf(interior + used, sizeof interior - (size_t)used, "%s%08x", i ? "," : "",
				 o.interior_ip[i]);
		if (w < 0 || (size_t)(used + w) >= sizeof interior)
			break;
		used += w;
	}
	if (used == 0)
		snprintf(interior, sizeof interior, "-");

	// ONE LINE, ALL FIELDS UNCONDITIONALLY, INCLUDING THE ZEROES. A field that is printed only
	// when non-zero cannot be told from a field a build forgot to print, and the parser gate for
	// this line requires every key on every line -- which is only checkable if the emitter always
	// writes them. `qcg=`/`aot=` are the two classification tags themselves, echoed so the split
	// can be re-derived from the record instead of trusted.
	CensusLine("LOOPTIER_ROUTE_CENSUS when=%s gip=%08x "
		   "cur_present=%d cur_is_aot=%d cur_ptr=0x%llx l1_tb_is_cur=%d "
		   "qcg=0x%llx aot=0x%llx "
		   "link_slots=%u link_to_old_qcg=%u link_to_aot=%u link_to_other=%u "
		   "link_lazy=%u link_in_pool=%u link_undecodable=%u "
		   "brind_tag_hit=%d brind_is_old_qcg=%d brind_is_aot=%d brind_in_pool=%d "
		   "execcount_tag_hit=%d execcount_tb_is_old_qcg=%d execcount_tb_is_aot=%d "
		   "execcount_tb_is_cur=%d execcount_value=%llu "
		   "ic_blobs=%u "
		   "interior_ub_page=%u interior_ub_insn=%u interior_list=%s "
		   "interior_bound=conservative_no_ip_end\n",
		   when, o.gip, o.cur_present, o.cur_is_aot, (unsigned long long)(uptr)o.cur_ptr,
		   o.l1_tb_is_cur, (unsigned long long)(uptr)g_qcg_tag,
		   (unsigned long long)(uptr)aot_tag, o.link_slots, o.link_to_qcg, o.link_to_aot,
		   o.link_to_other, o.link_lazy, o.link_in_pool, o.link_undecodable, o.brind_tag_hit,
		   o.brind_is_qcg, o.brind_is_aot, o.brind_in_pool, o.exec_tag_hit, o.exec_tb_is_qcg,
		   o.exec_tb_is_aot, o.exec_tb_is_cur, o.exec_count, o.ic_blobs, o.interior_ub_page,
		   o.interior_ub_insn, interior);
}

} // namespace dbt::looptier
