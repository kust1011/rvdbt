#include "dbt/aot/loop_tier.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/tcache/objprof.h"
#include "dbt/tcache/tcache.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>

extern "C" {
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
}

namespace dbt::looptier
{

// ==============================================================================================
// T5d2b0: the child-completion notification, and its OWNERSHIP WINDOW.
//
// THIS IS THE ONLY SIGNAL THIS PATH USES, AND IT IS NOT A TIMER. SIGCHLD is raised by the kernel
// when a child terminates -- one edge, and the edge the parent is actually waiting for. Nothing here
// is periodic: no setitimer, no alarm, no tick, no cadence, no clock, and scripts/
// loop_tier_timer_audit.py gates T1 and T10 check that against this file.
//
// BUT SIGCHLD IS PROCESS-WIDE, AND THAT IS THE DEFECT THIS BLOCK NOW CLOSES. The first version
// installed the handler at Arm() and restored it at ReportAtExit(), so the tier owned the
// disposition for the whole run -- including every instant at which no builder existed. Any
// unrelated host child terminating in that window raised the completion reason and the service bit,
// and since the emitted poll did not require a build to be outstanding, a terminal tier could take a
// side exit for a completion that could not exist. Both halves are fixed: the ownership window is
// now exactly the interval in which a builder is outstanding, and the emitted poll tests
// `loop_tier_state == BUILDING` before it treats the request as a completion.
//
//   install   -- immediately BEFORE the fork (DoSpawn). Before, not after: a child that exits
//                between fork and install would deliver its SIGCHLD to the old disposition and the
//                wakeup would be lost, which is a race and not a rare case for a fast failure.
//   restore   -- the instant the EXACT builder is consumed by waitpid (DoReap), whatever its
//                disposition; and on every path that leaves no builder outstanding: a failed fork,
//                a reap that reports no such child, and the guest-exit fallback. Idempotent, so a
//                path that is reached twice restores once.
//
// THE HANDLER DOES ONE ORDERED PAIR OF LOCK-FREE ATOMIC WRITES AND NOTHING ELSE -- see
// config::RaiseLoopTierCompletion, which is where the two words and their ordering live. No waitpid
// (the child stays a zombie until the host stack collects it), no stat, no printf, no allocation,
// no state transition, no clock read: every one of those is either not async-signal-safe or is a
// decision, and both belong on the host stack.
static void LoopTierSigchld(int)
{
	dbt::config::RaiseLoopTierCompletion();
}

// The disposition this process had before the tier took SIGCHLD, and whether it currently holds it.
static struct sigaction g_sigchld_prev;
static bool g_sigchld_installed = false;

// IS THE PROCESS'S SIGCHLD DISPOSITION ONE THE TIER MAY TAKE? Only SIG_DFL without SA_NOCLDWAIT is.
// Everything else is refused, and two of the refusals are correctness rather than politeness:
//
//   SIG_IGN and SA_NOCLDWAIT both mean "this process does not want child statuses". On Linux, and
//   as POSIX permits, they let the kernel REAP children automatically -- including a zombie that
//   already exists when the disposition is set. A tier that took over such a disposition would put
//   it back at the end and then find its own builder gone: the exact `waitpid` returns ECHILD and
//   the build's status is unrecoverable. That was measured, not deduced (T5D2B0 §5). Restoring
//   AFTER the wait fixes the ordering, but it does not make the disposition safe to adopt in the
//   first place -- a child terminating at any point while it is in force can still be auto-reaped.
//   So this fails closed. Implementing equivalent semantics would mean reproducing the auto-reap
//   contract for every other child in the process, which is not this checkpoint's to own.
//
//   Any installed handler (SA_SIGINFO or not) means another consumer is already using child
//   notifications; taking it over would swallow theirs or have ours swallowed.
static bool CompletionDispositionIsFree(char const **why)
{
	struct sigaction cur {};
	if (sigaction(SIGCHLD, nullptr, &cur) != 0) {
		*why = "sigchld_query_failed";
		return false;
	}
	if (cur.sa_flags & SA_NOCLDWAIT) {
		*why = "sigchld_nocldwait_autoreaps";
		return false;
	}
	if (cur.sa_flags & SA_SIGINFO) {
		*why = "sigchld_already_owned";
		return false;
	}
	if (cur.sa_handler == SIG_IGN) {
		*why = "sigchld_ignored_autoreaps";
		return false;
	}
	if (cur.sa_handler != SIG_DFL) {
		*why = "sigchld_already_owned";
		return false;
	}
	return true;
}

bool CompletionDispositionAcceptable(char const **why)
{
	char const *ignored = "";
	return CompletionDispositionIsFree(why ? why : &ignored);
}

bool InstallCompletionNotification()
{
	char const *why = "";
	if (g_sigchld_installed)
		return false; // already ours: a second install would lose the process's own disposition
	if (!CompletionDispositionIsFree(&why))
		return false;
	struct sigaction sa {};
	sa.sa_handler = LoopTierSigchld;
	sigemptyset(&sa.sa_mask);
	// SA_RESTART so a SIGCHLD arriving inside a guest syscall does not turn into an EINTR the guest
	// would have to see; SA_NOCLDSTOP so only TERMINATION wakes the parent, never a stop/continue.
	// SA_NOCLDWAIT is deliberately NOT set: the child must stay collectable by the exact waitpid.
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, &g_sigchld_prev) != 0)
		return false;
	g_sigchld_installed = true;
	return true;
}

void RestoreCompletionNotification()
{
	if (!g_sigchld_installed)
		return;
	sigaction(SIGCHLD, &g_sigchld_prev, nullptr);
	g_sigchld_installed = false;
	// The window is over, so any reason left behind belongs to it and must not be read as a
	// completion by a later service. Cleared here, on the host stack, next to the disposition it
	// belongs to.
	dbt::config::loop_tier_child_exited.store(0u, std::memory_order_seq_cst);
}

bool CompletionNotificationHeld()
{
	return g_sigchld_installed;
}

// ==============================================================================================
// Clock and event stream.
//
// One origin (config::loop_tier_start_ms, taken when the tier arms) and one printer, used on both
// sides of the fork. The child's publish and the parent's guest-exit are therefore two readings of
// the same CLOCK_MONOTONIC, which is what lets "publication preceded guest exit" be an ORDERING of
// two recorded instants rather than an inference from which line appeared first in a pipe.
//
// TIMESTAMPS ARE OUTPUT, NOT INPUT. Nothing below reads them back. `Decide` -- the only function
// that decides anything -- takes two counts and a state, and there is no clock in scope where it
// is called from.
static long NowMs()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L - config::loop_tier_start_ms;
}

// One line, assembled on the stack and written with a single write(2). The child uses this AFTER a
// fork from a process that has a helper thread, so it must not touch stdio buffers or the malloc
// arena it inherited: a lock held by another thread at fork time is still held in the child, and
// the thread that would release it does not exist there.
__attribute__((format(printf, 1, 2))) static void Event(char const *fmt, ...)
{
	char line[1024];
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

// ==============================================================================================
// The decision.

// The state value the emitted code compares against is a constant in config, because the test is
// generated rather than interpreted. This is the one place the two spellings meet.
static_assert((int)State::ARMED == config::kLoopTierArmed,
	      "the emitted notification's ARMED compare must name looptier::State::ARMED");
static_assert((int)State::BUILDING == config::kLoopTierBuilding,
	      "the emitted completion poll's BUILDING compare must name looptier::State::BUILDING");

bool CrossedBar(u64 count, u64 bar)
{
	return count >= bar;
}

bool ShouldNotify(u64 count, u64 bar, int state, u32 mailbox, unsigned char notified)
{
	// The four tests the generated sequence performs, in the order it performs them. Each is
	// independent: 1 is the evidence, 2 keeps a spent tier silent, 3 protects a notification that
	// is already in flight, and 4 is the durable per-target one-shot.
	return CrossedBar(count, bar) && state == (int)State::ARMED && mailbox == 0 && !notified;
}

Action Decide(State st, bool enabled, bool target_is_selected_header)
{
	if (!enabled)
		return Action::NOTHING; // mode off: this is the whole of "inert"
	switch (st) {
	case State::ARMED:
		// THE QUESTION IS NOT "IS SOMETHING HOT" ANY MORE. The notification already proves that
		// the block it names reached the compiler's bar -- that is what the generated evidence
		// test tested. The only thing left to decide is whether that block is one of the hot
		// natural-loop HEADERS T5d1a's selector picks, because those are exactly the regions
		// T5d1b can compile. A backward edge into something that is not such a header (a latch, a
		// merge point, a block inside a loop body) is rejected here, spends no build, and cannot
		// come back: that guest target's own one-shot byte is already claimed, for the life of the
		// process and across any retranslation. The mailbox it filled was drained before this
		// call, so a DIFFERENT target may still notify -- which is what keeps a rejection from
		// starving the tier without letting the rejected target livelock it.
		return target_is_selected_header ? Action::SPAWN : Action::REJECT;
	case State::BUILDING:
		// No NOTIFICATION can arrive here -- T5d2a2's ARMED test in the emitted sequence makes
		// the generated code silent while a child exists, and that is deliberate. What DOES
		// arrive, once --loop-tier-completion-exit is on, is the child's own TERMINATION
		// (T5d2b0): SIGCHLD raises the same service bit, an intra-region backedge polls it and
		// takes T5d2a3's exit, and the reap happens here on the host stack. Without that switch
		// the child is collected at guest exit instead (ReportAtExit).
		return Action::REAP;
	case State::OFF:
	case State::PUBLISHED:
	case State::LOADED:
	case State::INSTALLED:
	case State::FAILED:
	case State::ABSTAINED:
	case State::CANCELED:
		return Action::NOTHING; // terminal: the one allowed build is spent or refused
	}
	// Unreachable for a valid State; a defensive answer rather than a Panic, because this runs
	// inside a live guest.
	return Action::NOTHING;
}

bool MayPublish(int build_rc, size_t n_headers)
{
	// Two independent ways to fail, one answer. A compiler that exited nonzero may still have left
	// a complete-looking file behind, and a compiler that exited zero may have selected nothing --
	// the T5d1b path emits one aottab entry per SELECTED candidate, so an empty table is exactly
	// "this profile contains no admissible loop". Neither is publishable.
	return build_rc == 0 && n_headers > 0;
}

// ==============================================================================================
// The selector -- T5d1a's, called rather than reimplemented.

bool SelectedLoopHeaders(u64 bar, std::vector<u32> *headers, u64 *header_freq_of, u32 target)
{
	headers->clear();
	if (header_freq_of)
		*header_freq_of = 0;
	if (!objprof::HasProfile())
		return false;
	auto mg = BuildWholeProfileGraph();
	// Fail-closed, in a live guest: `ComputeDomTree(true)` refuses instead of Panicking on a graph
	// that is too large for its u16 numbering or that has an unreachable node. Both are analysis
	// limits, and neither is a reason to kill a run that is executing correctly.
	if (!mg.ComputeDomTree(/*fail_closed=*/true))
		return false;
	// The bar the selector reads is `config::threshold` -- the same field the child elfaot sets
	// from `--threshold`. Installing the loop tier's bar here for the duration of the call is what
	// makes this the child's admission rule and not a second one. Restored unconditionally.
	u64 saved = config::threshold;
	config::threshold = bar;
	auto cands = mg.SelectHotNaturalLoopCandidates();
	config::threshold = saved;
	for (auto const &c : cands) {
		headers->push_back(c.header_ip);
		if (header_freq_of && c.header_ip == target)
			*header_freq_of = c.header_exec_freq;
	}
	return true;
}

// ==============================================================================================
// CPU placement.

int SelectDistinctCpu(cpu_set_t const *allowed, int guest_cpu)
{
	for (int c = 0; c < CPU_SETSIZE; ++c) {
		if (CPU_ISSET(c, allowed) && c != guest_cpu)
			return c; // a DISTINCT allowed CPU: the two-CPU protocol's builder core
	}
	// No distinct allowed CPU. A background builder sharing the guest's only core is not a
	// background builder -- it would take the compile wall out of the guest's own core budget,
	// which is the one thing this checkpoint may not do. Every caller must fail closed.
	//
	// CPU NUMBERS ARE NEVER ASSUMED. The candidate set is the process's own allowed mask, so a
	// cpuset that grants 2-3 out of 0-5 yields 2 or 3 and nothing else; arithmetic on
	// sched_getcpu() (the pre-2026-08-17 rule) routinely named a CPU the process could not use,
	// and sched_setaffinity then failed while the caller still reported a live builder.
	return -1;
}

int PickBuilderCpu()
{
	cpu_set_t allowed;
	CPU_ZERO(&allowed);
	if (sched_getaffinity(0, sizeof allowed, &allowed) != 0)
		return -1;
	return SelectDistinctCpu(&allowed, sched_getcpu());
}

// ==============================================================================================
// The artifact gate.
//
// "At least one SELECTED LOOP-HEADER symbol" is read out of the produced .so and out of nothing
// else -- not the compiler's log, not the parent's expectations. Under `--aot-loop-regions` the
// aottab is populated ONLY by LLVMAOTCompileLoopRegions, one entry per selected candidate, keyed by
// its header ip; so an aottab entry IS a selected loop header, and confirming that the recorded
// address really is the address of the artifact's own `_x<header>` definition closes the loop
// between the table and the code.
//
// Allocates nothing. The forked child calls this on an mmap'd image for the reason given at
// Event(): the malloc arena it inherited is not safe to use.

static bool ReadAt(void const *buf, size_t n, size_t off, void *dst, size_t len)
{
	if (off > n || n - off < len)
		return false;
	memcpy(dst, (u8 const *)buf + off, len);
	return true;
}

// The name QIRToLLVM gives a region rooted at `ip`. Spelled with snprintf rather than through
// MakeAotSymbol (which builds a std::stringstream) so it is usable after a fork; the test asserts
// the two spellings agree, so they cannot drift.
void AotSymbolName(u32 ip, char *out, size_t n)
{
	snprintf(out, n, "%.*s%x", (int)AOT_SYM_PREFIX.size(), AOT_SYM_PREFIX.data(), ip);
}

// ONE PARSER, TWO PROJECTIONS, AND NO ALLOCATION ANYWHERE. `ArtifactLoopHeaders` (the publish gate,
// which runs in the forked child and must not touch the malloc arena it inherited) wants the gips;
// T5d2b1's loader wants the whole `AOTSymbol`, because comparing only the gip against the mapped
// table would let an artifact whose entry names the same guest ip at a DIFFERENT host address pass.
// Both are the same walk, so they are one function with two optional output buffers rather than two
// readers that can drift about what a well-formed table is.
static long ParseAotTab(void const *buf, size_t n, u32 *gips, AOTSymbol *syms, size_t max)
{
	Elf64_Ehdr eh;
	if (!ReadAt(buf, n, 0, &eh, sizeof eh))
		return -1;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh.e_ident[EI_DATA] != ELFDATA2LSB)
		return -1;
	if (eh.e_shentsize < sizeof(Elf64_Shdr) || eh.e_shnum == 0 || eh.e_shstrndx >= eh.e_shnum)
		return -1;

	auto shdr = [&](unsigned i, Elf64_Shdr *sh) {
		return ReadAt(buf, n, eh.e_shoff + (size_t)i * eh.e_shentsize, sh, sizeof *sh);
	};
	Elf64_Shdr shstr;
	if (!shdr(eh.e_shstrndx, &shstr) || shstr.sh_offset > n || n - shstr.sh_offset < shstr.sh_size)
		return -1;
	auto const *shstrtab = (char const *)buf + shstr.sh_offset;
	auto sec_name = [&](Elf64_Shdr const &sh) -> char const * {
		return sh.sh_name < shstr.sh_size ? shstrtab + sh.sh_name : "";
	};

	// The aottab, and a symbol table to resolve its entries against. `.symtab` is what the linker
	// leaves and what LinkAOTObject itself reads back; `.dynsym` is accepted as a fallback so a
	// stripped artifact is judged rather than merely unparsed.
	Elf64_Shdr tab{}, sym{}, str{};
	bool have_tab = false, have_sym = false;
	for (unsigned i = 0; i < eh.e_shnum; ++i) {
		Elf64_Shdr sh;
		if (!shdr(i, &sh))
			return -1;
		char const *nm = sec_name(sh);
		if (!have_tab && strcmp(nm, ".aottab") == 0) {
			tab = sh;
			have_tab = true;
		}
		if (sh.sh_type == SHT_SYMTAB || (!have_sym && sh.sh_type == SHT_DYNSYM)) {
			if (sh.sh_type == SHT_SYMTAB || !have_sym) {
				Elf64_Shdr s2;
				if (sh.sh_link >= eh.e_shnum || !shdr(sh.sh_link, &s2))
					return -1;
				sym = sh;
				str = s2;
				have_sym = true;
			}
		}
	}
	if (!have_tab || !have_sym)
		return -1;
	if (tab.sh_type == SHT_NOBITS || tab.sh_offset > n || n - tab.sh_offset < tab.sh_size)
		return -1;
	if (sym.sh_entsize < sizeof(Elf64_Sym) || sym.sh_offset > n || n - sym.sh_offset < sym.sh_size)
		return -1;
	if (str.sh_offset > n || n - str.sh_offset < str.sh_size)
		return -1;

	AOTTabHeader hdr;
	if (!ReadAt(buf, n, tab.sh_offset, &hdr, sizeof hdr))
		return -1;
	// A count the section cannot hold is a corrupt or truncated artifact, not an empty one.
	if (hdr.n_sym > (tab.sh_size - sizeof(AOTTabHeader)) / sizeof(AOTSymbol))
		return -1;
	if (hdr.n_sym > max)
		return -1;

	auto const *strtab = (char const *)buf + str.sh_offset;
	size_t n_ent = sym.sh_size / sym.sh_entsize;
	long found = 0;
	for (u64 k = 0; k < hdr.n_sym; ++k) {
		AOTSymbol as;
		if (!ReadAt(buf, n, tab.sh_offset + sizeof(AOTTabHeader) + (size_t)k * sizeof(AOTSymbol),
			    &as, sizeof as))
			return -1;
		char want[64];
		AotSymbolName(as.gip, want, sizeof want);
		bool ok = false;
		for (size_t e = 0; e < n_ent && !ok; ++e) {
			Elf64_Sym es;
			if (!ReadAt(buf, n, sym.sh_offset + e * sym.sh_entsize, &es, sizeof es))
				return -1;
			if (es.st_shndx == SHN_UNDEF || es.st_name >= str.sh_size)
				continue;
			if (strcmp(strtab + es.st_name, want) == 0 && es.st_value == as.aot_vaddr)
				ok = true;
		}
		if (!ok)
			return -1; // the table names a header the artifact does not define: fail closed
		if (gips)
			gips[found] = as.gip;
		if (syms)
			syms[found] = as;
		found++;
	}
	return found;
}

long ArtifactLoopHeaders(void const *buf, size_t n, u32 *out, size_t max)
{
	return ParseAotTab(buf, n, out, nullptr, max);
}

long ArtifactLoopSymbols(void const *buf, size_t n, AOTSymbol *out, size_t max)
{
	return ParseAotTab(buf, n, nullptr, out, max);
}

// The artifact's EXECUTABLE PT_LOAD segments, from its own program header table. This is what makes
// "is this entry's host address a plausible code address" a question about the ELF rather than about
// the file's byte length: a virtual address has nothing to do with how many bytes the file happens
// to be, and comparing the two was simply the wrong test. Bounded and allocation-free like the walk
// above, and it refuses rather than truncates when the table does not fit `max`.
long ArtifactExecRanges(void const *buf, size_t n, ExecRange *out, size_t max)
{
	Elf64_Ehdr eh;
	if (!ReadAt(buf, n, 0, &eh, sizeof eh))
		return -1;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh.e_ident[EI_DATA] != ELFDATA2LSB)
		return -1;
	if (eh.e_phnum == 0 || eh.e_phentsize < sizeof(Elf64_Phdr))
		return 0; // no program headers: no executable range, so every non-zero address is refused
	if (eh.e_phnum > max)
		return -1;
	long found = 0;
	for (unsigned i = 0; i < eh.e_phnum; ++i) {
		Elf64_Phdr ph;
		if (!ReadAt(buf, n, eh.e_phoff + (size_t)i * eh.e_phentsize, &ph, sizeof ph))
			return -1;
		if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X))
			continue;
		// An interval that wraps is not an interval. Refuse the artifact rather than admit a
		// range whose end is below its start.
		if (ph.p_memsz > UINT64_MAX - ph.p_vaddr)
			return -1;
		out[found].vaddr = ph.p_vaddr;
		out[found].memsz = ph.p_memsz;
		found++;
	}
	return found;
}

// ==============================================================================================
// Publication.

bool PublishAtomically(char const *src, char const *dst)
{
	// SAME DIRECTORY IS THE POINT, not a convenience. rename(2) is atomic within a filesystem, and
	// requiring the two paths to share a directory is the cheapest way to guarantee they are on
	// one. What it buys: the compiler writes its artifact under its own name and the published
	// name only ever appears complete, so a reader polling `dst` can never observe a half-written
	// object -- which is exactly what the promotion step of T5d2b will be doing.
	auto dirlen = [](char const *p) -> size_t {
		char const *slash = strrchr(p, '/');
		return slash ? (size_t)(slash - p) : 0;
	};
	size_t ds = dirlen(src), dd = dirlen(dst);
	if (ds != dd || ds == 0 || strncmp(src, dst, ds) != 0)
		return false;
	if (strcmp(src, dst) == 0)
		return false;
	return rename(src, dst) == 0;
}

// ==============================================================================================
// The builder child.

// Copy `src` to `dst` byte for byte. Used on the HOST STACK only, with the guest stopped, so the
// copy is a consistent snapshot of the live profile by construction rather than by locking: the
// only writer of that mapping is the thread performing the copy.
bool CopyProfileSnapshot(char const *src, char const *dst)
{
	int in = open(src, O_RDONLY);
	if (in < 0)
		return false;
	struct stat source;
	struct stat destination;
	if (fstat(in, &source) != 0 || !S_ISREG(source.st_mode) ||
	    (stat(dst, &destination) == 0 && source.st_dev == destination.st_dev &&
	     source.st_ino == destination.st_ino)) {
		close(in);
		return false;
	}
	int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out < 0) {
		close(in);
		return false;
	}
	auto copy_range = [&](off_t first, off_t last) {
		char b[1 << 16];
		while (first < last) {
			size_t want = (size_t)std::min<off_t>(last - first, sizeof b);
			ssize_t r;
			do {
				r = pread(in, b, want, first);
			} while (r < 0 && errno == EINTR);
			if (r <= 0)
				return false;
			ssize_t done = 0;
			while (done < r) {
				ssize_t w;
				do {
					w = pwrite(out, b + done, (size_t)(r - done), first + done);
				} while (w < 0 && errno == EINTR);
				if (w <= 0)
					return false;
				done += w;
			}
			first += r;
		}
		return true;
	};
	bool ok = true;
#if defined(SEEK_DATA) && defined(SEEK_HOLE)
	// Preserve file holes: the profile's address-indexed mapping is logically large but sparse.
	// Reading/writing every zero page materializes both mappings in charged page-cache memory.
	for (off_t pos = 0; ok && pos < source.st_size;) {
		off_t data;
		do {
			data = lseek(in, pos, SEEK_DATA);
		} while (data < 0 && errno == EINTR);
		if (data < 0) {
			if (errno == ENXIO)
				break; // remaining bytes are holes
			if (errno == EINVAL || errno == EOPNOTSUPP || errno == ENOSYS)
				ok = copy_range(0, source.st_size);
			else
				ok = false;
			break;
		}
		if (data < pos || data >= source.st_size) {
			ok = false;
			break;
		}
		off_t hole;
		do {
			hole = lseek(in, data, SEEK_HOLE);
		} while (hole < 0 && errno == EINTR);
		if (hole < 0) {
			if (errno == EINVAL || errno == EOPNOTSUPP || errno == ENOSYS)
				ok = copy_range(0, source.st_size);
			else
				ok = false;
			break;
		}
		if (hole <= data) {
			ok = false;
			break;
		}
		pos = std::min(hole, source.st_size);
		ok = copy_range(data, pos);
	}
#else
	ok = copy_range(0, source.st_size);
#endif
	// Explicit size preserves an all-hole file and trailing holes without allocating their pages.
	if (ok && ftruncate(out, source.st_size) != 0)
		ok = false;
	close(in);
	if (close(out) != 0)
		ok = false;
	return ok;
}

// Fork a builder that compiles `elf` from the profile already staged in `stage` and, only if that
// succeeds and the result carries a selected loop header, publishes it atomically at
// `<stage>/<publish>`. Returns the child's pid, or -1.
//
// The argv is assembled HERE, before the fork, and written to `<stage>/loop_tier_build.cmd` from
// the very array execv receives -- so the run's own evidence records what the child was given
// rather than what this function meant to give it. scripts/vlen_propagation_audit.py reads this
// site and requires the parent's live `--vlen` and the whole rendered route contract, in that
// order, ahead of the terminator; T5f added gate G9, which requires that this site -- and only this
// site -- render the contract with `RvvChildSubstrate::LlvmPrerequisite`.
pid_t SpawnBuilder(int cpu, char const *loop_tier_elfaot, char const *elf, char const *stage,
		   char const *artifact, char const *publish, u64 bar)
{
	if (cpu < 0)
		return -1;
	char elfarg[4096], cachearg[4096], vlenarg[64], thrarg[64], cmdpath[4096], logpath[4096];
	snprintf(elfarg, sizeof elfarg, "--elf=%s", elf);
	snprintf(cachearg, sizeof cachearg, "--cache=%s", stage);
	snprintf(vlenarg, sizeof vlenarg, "--vlen=%u", config::vlen_bits);
	snprintf(thrarg, sizeof thrarg, "--threshold=%llu", (unsigned long long)bar);
	snprintf(cmdpath, sizeof cmdpath, "%s/loop_tier_build.cmd", stage);
	snprintf(logpath, sizeof logpath, "%s/loop_tier_build.log", stage);
	// S3.7: one argv slot per route flag, rendered from the ONE table in aot_boot.cpp. Rendered
	// unconditionally, off values included, so the child's routes are a function of THIS process's
	// configuration and not of elfaot's defaults -- see kRvvRouteContract's comment.
	//
	// T5f: `LlvmPrerequisite`, AND THIS IS THE ONLY SITE THAT PASSES IT. The child two lines below
	// is told `--llvm=1`: it is an LLVM compile, and in that backend `--rvv-vector-ssa` is not a
	// route the parent may or may not want but the typed-vector SUBSTRATE every elfaot typed route
	// is gated on. This parent cannot supply it -- looptier::Arm() refuses
	// `side_exit_needs_committed_vector_state` under `config::rvv_vector_ssa`, because that flag in
	// THIS process means QCG may hold a guest-observable vector value in a host register across a
	// guest instruction boundary, which is what would make MakeGBr's in-region side exit illegal.
	// So inheritance here can only ever render 0, and 0 is precisely the value at which the child
	// takes none of the nine routes it was just handed. T5e measured that outcome: a published
	// artifact of 166 bytes, four helper calls per iteration, zero ZMM operands.
	//
	// This does not weaken the QCG-side precondition and does not claim the parent's vector state is
	// committed by anything new. It is the opposite claim: the parent stays at 0, and BECAUSE it
	// stays at 0 every QCG RVV route finishes its load/compute/store inside one guest instruction,
	// so all guest-visible vector state is already in CPUState::VectorState at the header this
	// artifact is entered at -- the same pairing T5e's offline arm ran, digest-correct, throughout.
	//
	// The value is rendered INTO the substrate row's own slot. Nothing is appended and no option
	// appears twice; see RvvRouteRenderedValue for why that shape was rejected.
	char rvvslots[kRvvRouteArgMax][64];
	char const *rvvargv[kRvvRouteArgMax];
	size_t n_rvv = RvvRouteArgv(rvvslots, rvvargv, RvvChildSubstrate::LlvmPrerequisite);
	std::vector<char const *> cargv;
	cargv.push_back(loop_tier_elfaot);
	cargv.push_back(elfarg);
	cargv.push_back(cachearg);
	cargv.push_back("--llvm=1");
	cargv.push_back(vlenarg);
	for (size_t i = 0; i < n_rvv; ++i)
		cargv.push_back(rvvargv[i]);
	cargv.push_back(thrarg);
	cargv.push_back("--aot-loop-regions=1");
	cargv.push_back(nullptr);
	if (FILE *cf = fopen(cmdpath, "w")) {
		for (size_t i = 0; cargv[i]; ++i)
			fprintf(cf, "%s%s", i ? " " : "", cargv[i]);
		fprintf(cf, "\n");
		fclose(cf);
	}

	pid_t pid = fork();
	if (pid != 0) {
		// THE PARENT'S HALF OF THE DOUBLE-setpgid IDIOM, HERE RATHER THAN IN THE CALLER, because
		// the race it closes belongs to this fork. After this returns, the builder's pgid is known
		// to equal its pid, so a later killpg(pid) can only reach processes this tier created.
		// Both outcomes below are positive evidence of that:
		//   0      -- this call created the group;
		//   EACCES -- the child already exec'd, which it can only do AFTER its own setpgid(0,0).
		// Anything else (notably ESRCH: the child is already gone) leaves the flag false, and the
		// cancel path then refuses to signal a group at all rather than guessing which one.
		if (pid > 0)
			config::loop_tier_pgid_owned = (setpgid(pid, pid) == 0 || errno == EACCES);
		return pid;
	}

	// ---- builder child. Everything from here is _exit-terminated: the parent's atexit handlers,
	// its profile mapping and its tcache belong to the guest and must not be torn down twice.
	cpu_set_t one;
	CPU_ZERO(&one);
	CPU_SET(cpu, &one);
	if (sched_setaffinity(0, sizeof one, &one) != 0) {
		Event("LOOPTIER_BUILD ABORT reason=setaffinity_failed cpu=%d\n", cpu);
		_exit(71);
	}
	// HALF OF THE DOUBLE-setpgid IDIOM. The parent performs the other half immediately after
	// fork(); whichever runs first creates the group and the loser fails harmlessly (EACCES once
	// this child has exec'd, ESRCH once it is gone). Doing it in BOTH places is what removes the
	// window in which this process is still in the PARENT's group -- a window in which a
	// killpg(loop_tier_pid) aimed at "the builder" would instead signal the parent's own group.
	// CHECKED, AND FATAL. If this fails the child is still in the PARENT's group, and forking the
	// compiler from here would put the compiler there too -- so a later killpg aimed at "the
	// builder" would either reach the parent's own group or, once the tier refuses to signal an
	// unowned group, leave the compiler running with nothing able to stop it. Neither is a state
	// worth continuing into, so no compiler is forked at all.
	if (setpgid(0, 0) != 0) {
		Event("LOOPTIER_BUILD ABORT reason=setpgid_failed errno=%d\n", errno);
		_exit(73);
	}

	pid_t b = fork();
	if (b == 0) {
		int lf = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (lf >= 0) {
			dup2(lf, 1);
			dup2(lf, 2);
			close(lf);
		}
		execv(loop_tier_elfaot, const_cast<char *const *>(cargv.data()));
		_exit(127);
	}
	if (b < 0)
		_exit(72);
	int wst = 0;
	waitpid(b, &wst, 0);
	int rc = WIFEXITED(wst) ? WEXITSTATUS(wst) : -1;
	Event("LOOPTIER_BUILD COMPILED t_ms=%ld rc=%d cpu=%d artifact=%s\n", NowMs(), rc,
	      sched_getcpu(), artifact);

	// The artifact gate, on the produced file. Fail-closed in every direction: a missing file, an
	// unreadable one, an empty aottab and a nonzero compiler rc all end here without a publish.
	u32 headers[4096];
	long n_hdr = -1;
	int af = open(artifact, O_RDONLY);
	if (af >= 0) {
		struct stat st;
		if (fstat(af, &st) == 0 && st.st_size > 0) {
			void *m = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, af, 0);
			if (m != MAP_FAILED) {
				n_hdr = ArtifactLoopHeaders(m, (size_t)st.st_size, headers,
							    sizeof headers / sizeof headers[0]);
				munmap(m, (size_t)st.st_size);
			}
		}
		close(af);
	}
	if (!MayPublish(rc, n_hdr > 0 ? (size_t)n_hdr : 0)) {
		Event("LOOPTIER_BUILD NOPUBLISH t_ms=%ld rc=%d headers=%ld\n", NowMs(), rc, n_hdr);
		_exit(2);
	}
	char pubpath[4096];
	snprintf(pubpath, sizeof pubpath, "%s/%s", stage, publish);
	if (!PublishAtomically(artifact, pubpath)) {
		Event("LOOPTIER_BUILD PUBLISH_FAILED t_ms=%ld\n", NowMs());
		_exit(3);
	}
	// The publish instant, in the SAME monotonic origin the parent prints its guest-exit in, left
	// where the parent can read it after reaping. Without this the parent could only record when
	// it NOTICED the file, which is bounded below by its next service opportunity -- a build that
	// landed during the run but was noticed after it would then be indistinguishable from one that
	// landed late, and that distinction is this checkpoint's whole claim.
	long publish_ms = NowMs();
	char tpath[4096];
	snprintf(tpath, sizeof tpath, "%s.t_ms", pubpath);
	int tf = open(tpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (tf >= 0) {
		char tbuf[64];
		int tn = snprintf(tbuf, sizeof tbuf, "%ld\n", publish_ms);
		(void)!write(tf, tbuf, (size_t)(tn > 0 ? tn : 0));
		close(tf);
	}
	struct stat ps;
	unsigned long long bytes = stat(pubpath, &ps) == 0 ? (unsigned long long)ps.st_size : 0;
	char hex[1024];
	int off = 0;
	for (long k = 0; k < n_hdr && off < (int)sizeof hex - 16; ++k)
		off += snprintf(hex + off, sizeof hex - (size_t)off, "%s%08x", k ? "," : "", headers[k]);
	Event("LOOPTIER_BUILD PUBLISHED t_ms=%ld bytes=%llu headers=%ld hdr=%s path=%s\n", publish_ms,
	      bytes, n_hdr, hex, pubpath);
	_exit(0);
}

// ==============================================================================================
// Host-stack state machine.

// Where the parent expects the child to publish, and what the compiler will have called its own
// output. Both are derived from the SAME identity the loader already uses -- objprof's guest-ELF
// checksum and this process's active VLEN -- so a build for a different program or a different
// width cannot satisfy this run: the name simply is not there. Filled at Arm(), fixed for the run.
static char g_artifact[4096];
static char g_publish[256];
static char g_pubpath[4096];

// Called only after the child has been collected, so a published artifact's sidecar is already
// there. The parent NEVER dlopens, announces or relinks what it finds here -- it stats a file and
// reads a number. Loading is T5d2b's subject and its absence is what keeps this checkpoint's claim
// about publication and not about execution.
// The publication's name, derived from the staging directory and the ACTIVE VLEN, in one place.
// Split out of Arm() (T5d2b0) for two reasons: the name now has a single definition rather than
// being spelled inside the arming sequence, and `loop_tier_test` can establish it and drive the
// real Disposition/DoReap without a booted guest and a mapped 64 MiB profile. It reads config and
// writes two static buffers; it decides nothing.
void SetPublishPath()
{
	using namespace dbt::config;
	snprintf(g_publish, sizeof g_publish, "loop_tier.v%u.so", config::vlen_bits);
	snprintf(g_pubpath, sizeof g_pubpath, "%s/%s", loop_tier_stage ? loop_tier_stage : ".", g_publish);
}

char const *PublishPath()
{
	return g_pubpath;
}


// ---------------------------------------------------------------------------------------------
// IS ANY PROCESS OF THIS OWNED GROUP STILL ALIVE?
//
// `killpg(pgid, 0)` cannot answer this. The group persists while ANY member exists, and our own
// unreaped leader is a member until it is waited for -- so the probe would report "alive" because
// of our own zombie, and reaping first to avoid that opens a pid-reuse window in which a later
// killpg could reach an unrelated group. Reading /proc is the accurate answer to the question that
// actually matters: how many NON-ZOMBIE processes are still in the group we created.
//
// THIS IS THE DEFECT IT CLOSES. The leader exiting is not the group stopping. A wrapper that dies
// on SIGTERM while the compiler (or a compiler's own child) ignores it leaves `waitpid(leader)`
// returning >0 -- "done" -- with a live compiler still running. Escalation must be driven by the
// GROUP's liveness, never by the leader's.
static int OwnedGroupLiveCount(pid_t pgid)
{
	DIR *d = opendir("/proc");
	if (!d)
		return -1; // unknown: callers must not read this as "empty"
	int live = 0;
	while (struct dirent *e = readdir(d)) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		char path[256];
		snprintf(path, sizeof path, "/proc/%s/stat", e->d_name);
		FILE *f = fopen(path, "r");
		if (!f)
			continue; // raced with exit; it is not alive for our purposes
		char buf[1024];
		size_t n = fread(buf, 1, sizeof buf - 1, f);
		fclose(f);
		if (n == 0)
			continue;
		buf[n] = '\0';
		// `comm` is parenthesised and may contain spaces and ')', so every field after it is
		// parsed from the LAST ')' -- the standard way to read this file safely.
		char *p2 = strrchr(buf, ')');
		if (!p2)
			continue;
		char state = 0;
		int ppid = 0, pgrp = 0;
		if (sscanf(p2 + 1, " %c %d %d", &state, &ppid, &pgrp) != 3)
			continue;
		if (pgrp == (int)pgid && state != 'Z')
			++live;
	}
	closedir(d);
	return live;
}

// waitpid that is not defeated by a signal arriving mid-call.
static pid_t WaitpidEintr(pid_t pid, int *st, int flags)
{
	for (;;) {
		pid_t r = waitpid(pid, st, flags);
		if (r >= 0 || errno != EINTR)
			return r;
	}
}

static void Disposition(bool in_run)
{
	using namespace dbt::config;
	// C6: A CANCELLED BUILD IS NEVER A PUBLICATION. This function turns a finished build into
	// PUBLISHED or FAILED, and neither is true of one this run deliberately killed: the compiler
	// was not wrong, it was simply no longer useful. Returning here keeps State::CANCELED, which
	// the caller has already recorded along with whether a file was left behind
	// (`loop_tier_stale_publication`) -- and because the state never becomes PUBLISHED, the load
	// and install gates below, which require PUBLISHED then LOADED, cannot fire for it either.
	if (loop_tier_canceled)
		return;
	struct stat st;
	bool present = stat(g_pubpath, &st) == 0 && st.st_size > 0;
	if (present && loop_tier_build_rc == 0) {
		loop_tier_state = (int)State::PUBLISHED;
		loop_tier_artifact_bytes = (unsigned long long)st.st_size;
		// The CHILD's publish instant, in this process's own monotonic origin. Falls back to now
		// -- an upper bound -- only if the sidecar is unreadable, and says which it used.
		loop_tier_publish_ms = NowMs();
		char tpath[4096];
		snprintf(tpath, sizeof tpath, "%s.t_ms", g_pubpath);
		if (FILE *tf = fopen(tpath, "r")) {
			long v = -1;
			if (fscanf(tf, "%ld", &v) == 1 && v >= 0)
				loop_tier_publish_ms = v;
			fclose(tf);
		}
		if (in_run)
			loop_tier_publish_seen_in_run = true;
	} else {
		loop_tier_state = (int)State::FAILED;
	}
	Event("LOOPTIER_EVENT %s t_ms=%ld rc=%d bytes=%llu in_run=%d path=%s\n",
	      loop_tier_state == (int)State::PUBLISHED ? "PUBLISHED" : "BUILD_FAILED", NowMs(),
	      loop_tier_build_rc, loop_tier_artifact_bytes, (int)in_run, g_pubpath);
	// T5d2b1: LOAD AND VALIDATE, on the host stack, only in the run that published it.
	//
	// IN_RUN ONLY, and that is the claim rather than an optimisation: what this checkpoint has to
	// show is PUBLISHED < LOADED < GUEST_EXIT. A load performed from the guest-exit fallback would
	// be a load after the guest had already finished, which orders nothing.
	//
	// PUBLISHED ONLY. A FAILED disposition has no artifact to map. Nothing below installs, relinks
	// or enters anything -- LoadAndValidateArtifact does not have the vocabulary to (see its own
	// file), and the state it produces is LOADED, which no promoter reads yet.
	if (in_run && loop_tier_load && loop_tier_state == (int)State::PUBLISHED) {
		char const *why = "";
		auto const *view = LoadAndValidateArtifact(g_pubpath, loop_tier_spawn_ip, &why);
		if (view) {
			loop_tier_state = (int)State::LOADED;
			loop_tier_load_ms = NowMs();
			loop_tier_loaded_syms = view->n_sym;
			Event("LOOPTIER_EVENT LOADED t_ms=%ld syms=%llu spawn_ip=%08x base=%p path=%s\n",
			      loop_tier_load_ms, (unsigned long long)view->n_sym, loop_tier_spawn_ip,
			      (void const *)view->base, g_pubpath);
		} else {
			// The artifact stays PUBLISHED: the file is still there and the build still
			// succeeded. What failed is this process's ability to prove the mapping is the one
			// it meant, and the honest record of that is a refusal with its reason.
			loop_tier_load_refused = why;
			Event("LOOPTIER_EVENT LOAD_REFUSED t_ms=%ld reason=%s path=%s\n", NowMs(), why,
			      g_pubpath);
		}
	}
	// T5d2b2: INSTALL THE EXACT HEADER, on the same host stack, in the same service.
	//
	// IN_RUN AND LOADED ONLY. `LOADED` is the only state in which a validated mapping exists, and
	// in_run is what puts this before the fresh `tcache::Lookup` of the loop `Execute()` is about to
	// perform -- which is the whole mechanism (see loop_tier_install.cpp's header comment). An
	// install from the guest-exit fallback would replace a block nothing can ever look up again.
	//
	// The installer decides nothing about WHICH header: it takes the view's own `spawn_gip`. What
	// happens next is decided by `Execute()`, by comparing the PC it is resuming at against the
	// translation cache -- which is why `at_ip` is reported beside `gip` rather than assumed equal.
	if (in_run && loop_tier_install && loop_tier_state == (int)State::LOADED) {
		char const *why = "";
		if (InstallLoadedArtifact(&why)) {
			loop_tier_state = (int)State::INSTALLED;
			loop_tier_install_ms = NowMs();
			Event("LOOPTIER_EVENT INSTALLED t_ms=%ld gip=%08x host=0x%llx at_ip=%08x "
			      "aot_hits_before=%llu qcg_tbs_before=%lu qcg_mass_before=%llu\n",
			      loop_tier_install_ms, loop_tier_installed_gip, loop_tier_install_host,
			      loop_tier_install_at_ip, loop_tier_install_aot_hits,
			      loop_tier_install_qcg_tbs, loop_tier_install_qcg_mass);
		} else {
			// The tier stays LOADED: the mapping is still valid and still held. What failed is
			// the install, and the honest record of that is a refusal with its reason.
			loop_tier_install_refused = why;
			Event("LOOPTIER_EVENT INSTALL_REFUSED t_ms=%ld reason=%s\n", NowMs(), why);
		}
	}
}

static void DoSpawn(u32 target, u64 hottest, u64 bar)
{
	using namespace dbt::config;
	loop_tier_spawn_ip = target;
	Event("LOOPTIER_EVENT SELECTED t_ms=%ld target=%08x header_exec_freq=%llu threshold=%llu "
	      "events=%lu rejected=%lu\n",
	      NowMs(), target, (unsigned long long)hottest, (unsigned long long)bar, loop_tier_events,
	      loop_tier_rejected);

	int gcpu = sched_getcpu();
	cpu_set_t original_affinity;
	CPU_ZERO(&original_affinity);
	int bcpu = sched_getaffinity(0, sizeof original_affinity, &original_affinity) == 0 && gcpu >= 0
		       ? SelectDistinctCpu(&original_affinity, gcpu) : -1;
	loop_tier_guest_cpu = gcpu;
	loop_tier_builder_cpu = bcpu;
	if (bcpu < 0) {
		// Report and abstain. Terminal on purpose: the allowed mask is a property of how the run
		// was launched, not of the guest, so re-asking it every opportunity could only produce the
		// same answer and a stream of identical lines.
		loop_tier_state = (int)State::ABSTAINED;
		Event("LOOPTIER_EVENT ABSTAIN t_ms=%ld reason=no_distinct_allowed_cpu guest_cpu=%d\n",
		      NowMs(), gcpu);
		return;
	}

	// THE SNAPSHOT. The guest is stopped (this is its own thread, inside Execute()'s loop), so the
	// copy is exactly the profile the evidence above was read from. It is a COPY because the run
	// holds an exclusive lock on the live file; a child pointed at the run's own cache would fail
	// its open, and one pointed at the mapping would race the guest that is about to resume.
	std::string src = objprof::GetProfilePath();
	char dst[4096];
	char const *base = strrchr(src.c_str(), '/');
	snprintf(dst, sizeof dst, "%s/%s", loop_tier_stage, base ? base + 1 : src.c_str());
	if (!CopyProfileSnapshot(src.c_str(), dst)) {
		loop_tier_state = (int)State::FAILED;
		Event("LOOPTIER_EVENT SNAPSHOT_FAILED t_ms=%ld src=%s dst=%s\n", NowMs(), src.c_str(), dst);
		return;
	}
	struct stat ss;
	Event("LOOPTIER_EVENT SNAPSHOT t_ms=%ld pages=%zu bytes=%llu path=%s\n", NowMs(),
	      objprof::GetProfile().size(),
	      stat(dst, &ss) == 0 ? (unsigned long long)ss.st_size : 0ull, dst);

	// T5d2b0: TAKE SIGCHLD IMMEDIATELY BEFORE THE FORK. Before, because a builder that dies
	// between the fork and the install would deliver its notification to the old disposition and
	// the wakeup would be lost -- a race, and the likeliest case for a build that fails instantly.
	// Fail closed rather than build without the mechanism the command line asked for: a run that
	// silently loses its wakeup is indistinguishable from one whose builder was simply slow.
	if (loop_tier_completion_exit && !InstallCompletionNotification()) {
		loop_tier_state = (int)State::FAILED;
		Event("LOOPTIER_EVENT SPAWN_REFUSED t_ms=%ld reason=sigchld_not_available\n", NowMs());
		return;
	}
	// Keep the foreground off the selected builder CPU after the snapshot resumes.
	// The child explicitly selects its CPU inside the enclosing cgroup's allowed pair.
	cpu_set_t foreground_affinity;
	CPU_ZERO(&foreground_affinity);
	CPU_SET(gcpu, &foreground_affinity);
	if (sched_setaffinity(0, sizeof foreground_affinity, &foreground_affinity) != 0) {
		RestoreCompletionNotification();
		loop_tier_state = (int)State::FAILED;
		Event("LOOPTIER_EVENT SPAWN_REFUSED t_ms=%ld reason=foreground_affinity_failed cpu=%d\n",
		      NowMs(), gcpu);
		return;
	}
	loop_tier_fire_ms = NowMs();
	pid_t pid = SpawnBuilder(bcpu, loop_tier_elfaot, loop_tier_elf, loop_tier_stage, g_artifact,
				 g_publish, bar);
	if (pid < 0) {
		if (sched_setaffinity(0, sizeof original_affinity, &original_affinity) != 0)
			Event("LOOPTIER_EVENT AFFINITY_RESTORE_FAILED t_ms=%ld\n", NowMs());
		// No builder exists, so the window is over before it began.
		RestoreCompletionNotification();
		loop_tier_state = (int)State::FAILED;
		Event("LOOPTIER_EVENT SPAWN_FAILED t_ms=%ld\n", NowMs());
		return;
	}
	loop_tier_pid = (int)pid;
	loop_tier_state = (int)State::BUILDING;
	Event("LOOPTIER_EVENT CPU_PLACEMENT foreground_cpu=%d builder_cpu=%d foreground_pinned=1\n",
	      gcpu, bcpu);
	Event("LOOPTIER_EVENT SPAWNED t_ms=%ld pid=%d guest_cpu=%d builder_cpu=%d vlen=%u threshold=%llu\n",
	      loop_tier_fire_ms, (int)pid, gcpu, bcpu, config::vlen_bits, (unsigned long long)bar);
}

// Collect the child if it has finished. WNOHANG is what keeps requirement 7 true: the guest resumes
// from here whether or not the compiler is done, so no part of the build wall is ever charged to
// guest execution.
static void DoReap(bool in_run)
{
	using namespace dbt::config;
	int wst = 0;
	pid_t r = waitpid((pid_t)loop_tier_pid, &wst, WNOHANG);
	if (r == 0)
		return; // still compiling; the guest goes straight back to QCG, and the window stays open
	if (r < 0) {
		// There is no builder left to wait for, whatever the reason, so the window is over.
		RestoreCompletionNotification();
		loop_tier_state = (int)State::FAILED;
		Event("LOOPTIER_EVENT REAP_FAILED t_ms=%ld pid=%d\n", NowMs(), loop_tier_pid);
		return;
	}
	// T5d2b0: THE EXACT BUILDER HAS BEEN CONSUMED, so the tier gives SIGCHLD back HERE -- not at
	// guest exit. From this instruction on, an unrelated host child's termination is the process's
	// own business again and cannot raise this tier's completion.
	RestoreCompletionNotification();
	loop_tier_build_rc = WIFEXITED(wst) ? WEXITSTATUS(wst) : -1;
	loop_tier_reaped_ms = NowMs();
	Event("LOOPTIER_EVENT BUILD_END t_ms=%ld pid=%d rc=%d build_ms=%ld\n", loop_tier_reaped_ms,
	      loop_tier_pid, loop_tier_build_rc, loop_tier_reaped_ms - loop_tier_fire_ms);
	Disposition(in_run);
}

void Service()
{
	using namespace dbt::config;
	if (!loop_tier)
		return; // mode off: not one line below this runs, and no state moves

	// THE MAILBOX IS DRAINED FIRST, AND UNCONDITIONALLY. The emitted notification stored this
	// target immediately before setting the bit, on this same edge, a few instructions ago -- so
	// this is the block whose counter reached the bar, not wherever the escape happened to land
	// (`state->ip` agrees with it, which the run's evidence cross-checks). Emptying the slot here,
	// before anything is decided, is what lets a REJECTED notification be followed by a different
	// target's: from this instruction the slot is free, and the guest is not running. It also makes
	// the slot's value at exit meaningful -- the consumer always leaves it empty, so a non-zero
	// mailbox in the summary would mean generated code refilled it after the last service.
	u32 target = loop_tier_event_ip;
	loop_tier_event_ip = 0;
	if (target)
		loop_tier_last_taken_ip = target;

	// T5d2b0. CONSUMED EXACTLY ONCE, whatever woke this service. `exchange` is what makes that
	// mechanical: two SIGCHLDs before one service collapse into one consumption, and a service that
	// finds it clear does no completion work and reports none. It is read here -- before the state
	// dispatch and unconditionally -- for the same reason the mailbox is drained first: leaving it
	// set for a later pass would make "a completion is pending" mean something different depending
	// on which branch below happened to run.
	bool const completion = loop_tier_child_exited.exchange(0u, std::memory_order_relaxed) != 0;
	if (completion)
		loop_tier_completion_wakeups++;

	State st = (State)loop_tier_state;
	u64 bar = (u64)sr_chunk_threshold;
	if (st == State::BUILDING) {
		if (completion)
			Event("LOOPTIER_EVENT CHILD_EXITED t_ms=%ld pid=%d wakeups=%lu\n", NowMs(),
			      loop_tier_pid, loop_tier_completion_wakeups);
		// WNOHANG, and only the recorded pid: a completion the handler observed for some other
		// child (there is none today, but the reap must not depend on that) leaves this one
		// running and the guest resumes immediately. No part of the build wall is ever charged to
		// guest execution, with or without the wakeup.
		DoReap(true);
		return;
	}
	if (st != State::ARMED)
		return; // terminal: the one allowed build is spent or refused

	loop_tier_events++;

	// THE PROFILE THE CHILD WILL CONSUME, folded first so the selector sees this run's counts.
	objprof::UpdateProfile();

	// THE EXACT T5d1a SELECTOR, at the same bar: whole-profile stitched CFG, real dominator tree,
	// natural loops by dominance, HOT iff the header's own exec_count reaches the bar. The
	// question asked of it is the only one left -- is the block that crossed one of the headers
	// T5d1b can root a region at?
	std::vector<u32> headers;
	u64 header_freq = 0;
	bool ok = SelectedLoopHeaders(bar, &headers, &header_freq, target);
	bool member = false;
	for (u32 h : headers)
		member = member || h == target;

	switch (Decide(st, loop_tier, ok && member)) {
	case Action::NOTHING:
		return;
	case Action::REJECT: {
		// The BUILD is deliberately not consumed: `loop_tier_state` is untouched, so a later
		// notification from a different target can still spend it. This one cannot repeat -- that
		// target's own one-shot byte was claimed by the generated code before it stored the
		// payload -- so this is a refusal, not a deferral, and it cannot livelock.
		loop_tier_rejected++;
		char hx[512];
		int off = 0;
		for (size_t i = 0; i < headers.size() && off < (int)sizeof hx - 16; ++i)
			off += snprintf(hx + off, sizeof hx - (size_t)off, "%s%08x", i ? "," : "",
					headers[i]);
		Event("LOOPTIER_EVENT EVENT_REJECTED t_ms=%ld target=%08x reason=%s n_headers=%zu "
		      "headers=%s events=%lu rejected=%lu\n",
		      NowMs(), target, ok ? "not_a_selected_loop_header" : "selector_refused_the_graph",
		      headers.size(), headers.empty() ? "-" : hx, loop_tier_events, loop_tier_rejected);
		return;
	}
	case Action::SPAWN:
		loop_tier_hottest = header_freq;
		DoSpawn(target, header_freq, bar);
		return;
	case Action::REAP:
		DoReap(true);
		return;
	}
}

bool Arm()
{
	using namespace dbt::config;
	// Declared before the mode-off return so that the ONE refusal that can precede it spells its
	// line exactly like every other. It captures nothing and emits nothing until it is called, so
	// a run with the whole path off is unchanged.
	auto refuse = [](char const *why) {
		fprintf(stderr, "LOOPTIER_EVENT ARM_REFUSED reason=%s\n", why);
		return false;
	};
	// T5d2a3 CLI CONTRACT, AND IT HAS TO BE TESTED ABOVE THE MODE-OFF RETURN BECAUSE THAT RETURN IS
	// WHAT USED TO SWALLOW IT. `--loop-tier-side-exit` is a property of the loop tier's own
	// notification path -- the exit block is emitted only inside QEmit::Emit_Cache's `loop_tier`
	// block -- so with the tier off the switch has no effect whatsoever. The run then completed
	// normally and printed `LOOPTIER_SIDEEXIT on=1 sites=0 exits=0`, which is indistinguishable
	// from a hot loop that never got hot: a requested mechanism whose producer is disabled looked
	// exactly like a cold workload. The option text already said the switch requires --loop-tier;
	// this is that sentence made enforceable. Fail closed, with the same fatal-refusal discipline
	// every other reason here has (elfrun exits 2), and with a reason string that names the missing
	// prerequisite rather than the symptom.
	if (loop_tier_side_exit && !loop_tier)
		return refuse("side_exit_requires_loop_tier");
	// T5d2b0, same rule and same reason: with the tier off nothing raises the word this poll reads
	// and no exit block exists to jump to, so the switch is inert and must not be accepted alone.
	if (loop_tier_completion_exit && !loop_tier)
		return refuse("completion_exit_requires_loop_tier");
	if (loop_tier_load && !loop_tier)
		return refuse("load_requires_loop_tier");
	// T5d2b2, same rule and same reason: with the tier off there is no build, no artifact and no
	// validated view, so the installer can never run and the switch would be inert -- which is
	// indistinguishable from a workload that never got hot.
	if (loop_tier_install && !loop_tier)
		return refuse("install_requires_loop_tier");
	if (!loop_tier)
		return true;
	// The shared clock origin, taken here so every LOOPTIER line on either side of the fork -- and
	// the guest-exit instant it is compared against -- is an offset from one instant.
	{
		struct timespec ts0;
		clock_gettime(CLOCK_MONOTONIC, &ts0);
		loop_tier_start_ms = ts0.tv_sec * 1000L + ts0.tv_nsec / 1000000L;
	}
	if (!loop_tier_elfaot || !*loop_tier_elfaot)
		return refuse("no_elfaot");
	if (!loop_tier_elf || !*loop_tier_elf)
		return refuse("no_guest_elf");
	if (!loop_tier_stage || !*loop_tier_stage)
		return refuse("no_stage_dir");
	if (access(loop_tier_elfaot, X_OK) != 0)
		return refuse("elfaot_not_executable");
	if (access(loop_tier_elf, R_OK) != 0)
		return refuse("guest_elf_unreadable");
	if (access(loop_tier_stage, W_OK) != 0)
		return refuse("stage_dir_not_writable");
	// REQUIREMENT, NOT PREFERENCE. The loop this tier exists to observe is a pure-compute guest
	// loop whose backedge is a self-patched direct branch: without T5d0's safepoint it never
	// re-enters Execute(), so the request below would be set and never consumed and the tier would
	// silently never fire. Refusing is the honest behaviour; a warning would let a run that could
	// not possibly fire be mistaken for one whose workload was not hot enough.
	if (!qcg_backedge_safepoint)
		return refuse("needs_qcg_backedge_safepoint");
	// T5d2a3: THE INTRA-REGION EXIT MUST BE EMITTABLE WHERE IT IS CLAIMED TO BE. Its legality rests
	// on two facts about the configuration, and if either is false the exit block is not emitted at
	// all -- so a run must refuse rather than fall back silently to T5d2a2's later-gbr behaviour
	// while its command line says otherwise.
	//
	//   --trace: Emit_Cache's trace block pops the region's alignment push without a matching one,
	//            so `rsp` at an intra-region branch is NOT the region-entry level the escape stub
	//            unwinds from. (That imbalance predates this checkpoint; the exit does not fix it,
	//            it declines to be emitted on top of it.)
	//   --rvv-vector-ssa: the ONE route that keeps architectural VECTOR state live past a guest
	//            instruction boundary -- MakeGBr's in-region arm does not RvvCommit, so a value the
	//            guest can observe could still be in a host register at the latch. Every other RVV
	//            route completes its load/compute/store inside one guest instruction.
	//
	// T5f DID NOT WEAKEN THIS REFUSAL AND DOES NOT DEPEND ON IT BEING WEAKENED. The refusal is about
	// THIS process's QCG. What T5f changed is that the background elfaot child no longer inherits
	// this process's value for a flag that means something else in the LLVM backend -- see
	// SpawnBuilder's `RvvChildSubstrate::LlvmPrerequisite`. The parent still runs at 0, still arms
	// only at 0, and this line still fails closed at 1.
	if (loop_tier_side_exit && trace)
		return refuse("side_exit_frame_unbalanced_under_trace");
	if (loop_tier_side_exit && rvv_vector_ssa)
		return refuse("side_exit_needs_committed_vector_state");
	// T5d2b0: the completion poll is emitted INSIDE the notification block and jumps to T5d2a3's
	// exit block, so without either of those it is inert -- the same "a requested mechanism whose
	// producer is disabled must not look like a cold workload" rule the side exit itself is under.
	if (loop_tier_completion_exit && !loop_tier_side_exit)
		return refuse("completion_exit_requires_side_exit");
	// T5d2b1: the loader is entered only from the in-run reap, which only the completion wakeup
	// produces. Without it a run that asked to load would simply never load and would look like a
	// build that was too slow -- the same "a requested mechanism whose producer is disabled must
	// not look like a cold workload" rule the side exit and the wakeup are already under.
	if (loop_tier_load && !loop_tier_completion_exit)
		return refuse("load_requires_completion_exit");
	// T5d2b2: the installer's ONLY input is T5d2b1's validated view, and its only call site is the
	// in-run LOADED disposition that produces it. Without the loader there is no view, so the
	// switch could not install anything and the run would look like a build that was too slow.
	if (loop_tier_install && !loop_tier_load)
		return refuse("install_requires_load");
	// T5d2a1: THE NOTIFICATION MUST BE EMITTABLE. It is appended to the counter update inside
	// QEmit::Emit_Cache, so every switch that makes that function return early, count somewhere
	// else, or stop counting at the bar removes the tier's only event source. Each of these would
	// otherwise produce a run that emits nothing, fires nothing, and looks exactly like a workload
	// that never got hot.
	if (not_freq)
		return refuse("no_counting_not_freq");
	if (use_aot && !p1_promote)
		return refuse("no_counting_in_aot_run");
	if (qcg_freq_entry)
		return refuse("counter_moved_to_block_entry");
	if (qcg_freq_scratch)
		return refuse("counter_replaced_by_scratch_slot");
	if (qcg_freq_edge)
		return refuse("counter_replaced_by_edge_slots");
	if (qcg_freq_sat)
		return refuse("counter_saturates_before_the_bar");
	// ONE WRITER OF THE SERVICE WORD -- AND WHAT THAT IS AND IS NOT FOR (restated at T5d2a2).
	//
	// Under T5d2a1 these refusals were load-bearing for CORRECTNESS: the event was an exact
	// equality, so the argument that no other consumer could take an escape first was what made
	// "the increment that lands on the bar is the one the emitted test observes" true. That
	// argument was too weak -- `exec_count` has other writers regardless of who owns the service
	// word -- and T5d2a2 removes the dependency entirely: `>=` cannot be stepped over, and the
	// one-shot lives in a byte keyed by the guest target.
	//
	// What these refusals still buy is a CHANNEL this tier does not share. Another consumer's
	// clear of the word would swallow the escape a notification is waiting for, and the SIGALRM
	// keepers below would re-introduce the contention T5d2a's list already refused for. They are
	// therefore an untested-composition refusal, stated as one, and not a correctness claim.
	if (inrun_tier)
		return refuse("service_word_shared_with_inrun_tier");
	if (p1_promote)
		return refuse("service_word_shared_with_p1");
	if (wmax_sample)
		return refuse("sigalrm_owned_by_wmax");
	if (qcg_freq_retire || sr_edges_epochs)
		return refuse("service_word_shared_with_sat_sweep");
	if (sr_web_repack)
		return refuse("service_word_shared_with_web_repack");
	if (inrun_auto_escalate)
		return refuse("service_word_shared_with_escalate");
	if (!objprof::HasProfile())
		return refuse("no_profile_mapping");
	// Nothing may already be pending: the tier's first service must answer its own notification,
	// not a bit some earlier phase left set. This is the arming-time statement of the one-writer
	// invariant.
	if (AnyServiceRequestPending())
		return refuse("service_word_not_clear_at_arm");
	// ...and the mailbox starts free, which is what the generated code tests before it stores a
	// payload. A run that armed with a stale target in the slot would refuse every notification
	// until its first service, for no reason a reader of the log could see.
	if (loop_tier_event_ip != 0)
		return refuse("mailbox_not_empty_at_arm");

	// The names, from the identity the loader itself keys on.
	std::string art = objprof::GetCachePath(AOT_SO_EXTENSION);
	char const *base = strrchr(art.c_str(), '/');
	snprintf(g_artifact, sizeof g_artifact, "%s/%s", loop_tier_stage, base ? base + 1 : art.c_str());
	SetPublishPath();
	// T5d2b0. Arm() only CHECKS the disposition -- it does not take it. Ownership begins at the
	// fork and ends when the builder is consumed (see DoSpawn/DoReap), because SIGCHLD is
	// process-wide and holding it while no builder exists means an unrelated host child's exit
	// raises this tier's completion. Checking here is still worth doing: a configuration that
	// cannot support the mechanism must refuse before the guest runs, not halfway through it.
	if (loop_tier_completion_exit) {
		char const *why = "";
		if (!CompletionDispositionAcceptable(&why))
			return refuse(why);
	}
	loop_tier_state = (int)State::ARMED;
	fprintf(stderr,
		"LOOPTIER_EVENT ARMED t_ms=%ld threshold=%llu vlen=%u guest_cpu=%d elf=%s stage=%s "
		"artifact=%s publish=%s\n",
		NowMs(), (unsigned long long)sr_chunk_threshold, config::vlen_bits, sched_getcpu(),
		loop_tier_elf, loop_tier_stage, g_artifact, g_pubpath);
	return true;
}

void ReportAtExit()
{
	using namespace dbt::config;
	if (!loop_tier)
		return; // off runs print nothing at all: an off run is recognised by SILENCE
	loop_tier_guest_exit_ms = NowMs();
	Event("LOOPTIER_EVENT GUEST_EXIT t_ms=%ld\n", loop_tier_guest_exit_ms);
	if ((State)loop_tier_state == State::BUILDING && loop_tier_exit_cancel) {
		// ---- EXIT CANCEL ------------------------------------------------------------------
		// The guest has stopped. An artifact that lands now can never be INSTALLED -- the install
		// gate is `in_run && LOADED` and there is no further in-run service -- so blocking here
		// charges the whole remaining compile to cold elapsed for code this process will never
		// enter. Cancel the build this tier owns instead of waiting for it.
		//
		// C3: THE RACE IS RESOLVED BEFORE ANY SIGNAL. The child may already have finished (and
		// published) between its last service and this instant; a WNOHANG first means such a run
		// takes the ordinary completion path below and loses nothing.
		int wst = 0;
		pid_t done = WaitpidEintr((pid_t)loop_tier_pid, &wst, WNOHANG);
		if (done == 0) {
			loop_tier_cancel_ms = NowMs();
			// C1: signal ONLY a group this tier is known to own. Without that evidence the
			// pgid may still be the parent's, and killpg would reach unrelated processes --
			// so the tier degrades to the old blocking wait rather than guessing.
			if (loop_tier_pgid_owned) {
				// C4: THE GROUP, AND THE GROUP'S OWN LIVENESS DECIDES THE ESCALATION.
				//
				// The earlier version escalated only while the LEADER was unreaped, which is
				// not the same question: a wrapper that dies on SIGTERM while the compiler --
				// or a compiler's own child -- ignores it satisfies `waitpid(leader) > 0` and
				// would have stopped the escalation with a live compiler still running. So the
				// loop below polls the whole owned group and does not treat the leader's exit
				// as the group's exit.
				//
				// The leader is deliberately NOT reaped yet. Its zombie keeps the pid, and
				// therefore the pgid, reserved, so no unrelated group can appear at this pgid
				// between our probes; OwnedGroupLiveCount ignores zombies, so our own leader
				// does not make the group look alive.
				pid_t const pgid = (pid_t)loop_tier_pid;
				auto signal_group = [&](int sig) {
					loop_tier_cancel_signal = sig;
					if (killpg(pgid, sig) == 0)
						return true;
					if (errno == ESRCH)
						return true; // already gone: not a failure
					Event("LOOPTIER_EVENT CANCEL_SIGNAL_FAILED t_ms=%ld pgid=%d sig=%d "
					      "errno=%d\n", NowMs(), (int)pgid, sig, errno);
					return false;
				};
				auto settle = [&](int max_ms) {
					for (int i = 0; i < max_ms; ++i) {
						int live = OwnedGroupLiveCount(pgid);
						if (live == 0)
							return 0;
						struct timespec ts = {0, 1000000};
						nanosleep(&ts, nullptr);
					}
					return OwnedGroupLiveCount(pgid);
				};
				signal_group(SIGTERM);
				int live = settle(200);
				if (live != 0) {
					// Anything still in the group -- including a descendant that ignored
					// SIGTERM after its leader had already exited.
					signal_group(SIGKILL);
					live = settle(2000);
				}
				loop_tier_cancel_group_live = live;
				if (live != 0) {
					// Never silently: an unknown (-1) or non-empty group at this point is
					// the orphan condition this whole path exists to prevent.
					Event("LOOPTIER_EVENT CANCEL_INCOMPLETE t_ms=%ld pgid=%d live=%d\n",
					      NowMs(), (int)pgid, live);
				}
				done = WaitpidEintr((pid_t)loop_tier_pid, &wst, WNOHANG);
			} else {
				Event("LOOPTIER_EVENT CANCEL_REFUSED t_ms=%ld reason=pgid_not_owned pid=%d\n",
				      NowMs(), loop_tier_pid);
			}
			// C5: reap the exact child either way -- a cancelled build must leave no zombie,
			// and the disposition is restored only after this wait, exactly as before.
			if (done == 0)
				done = WaitpidEintr((pid_t)loop_tier_pid, &wst, 0);
			loop_tier_reaped_ms = NowMs();
			if (done > 0) {
				loop_tier_build_rc = WIFEXITED(wst) ? WEXITSTATUS(wst) : -1;
				loop_tier_canceled = true;
				// C6: a cancelled build is NEVER a success. If the child had already renamed
				// the artifact before the signal landed, the file exists but this run neither
				// loaded nor installed it, and saying so is the whole point of the flag.
				struct stat ps;
				loop_tier_stale_publication = (g_pubpath[0] != '\0' && stat(g_pubpath, &ps) == 0);
				loop_tier_state = (int)State::CANCELED;
				Event("LOOPTIER_EVENT BUILD_CANCELED t_ms=%ld pid=%d signal=%d rc=%d "
				      "waited_ms=%ld after_guest_exit=1 stale_publication=%d "
				      "group_live=%d\n",
				      loop_tier_reaped_ms, loop_tier_pid, loop_tier_cancel_signal,
				      loop_tier_build_rc, loop_tier_reaped_ms - loop_tier_guest_exit_ms,
				      (int)loop_tier_stale_publication, loop_tier_cancel_group_live);
				Disposition(false);
			} else {
				loop_tier_state = (int)State::FAILED;
				Event("LOOPTIER_EVENT REAP_FAILED t_ms=%ld pid=%d after_guest_exit=1 "
				      "canceled=1\n", NowMs(), loop_tier_pid);
			}
		} else if (done > 0) {
			// It had already finished: the ordinary completion record, unchanged.
			loop_tier_build_rc = WIFEXITED(wst) ? WEXITSTATUS(wst) : -1;
			loop_tier_reaped_ms = NowMs();
			Event("LOOPTIER_EVENT BUILD_END t_ms=%ld pid=%d rc=%d build_ms=%ld "
			      "after_guest_exit=1 canceled=0\n",
			      loop_tier_reaped_ms, loop_tier_pid, loop_tier_build_rc,
			      loop_tier_reaped_ms - loop_tier_fire_ms);
			Disposition(false);
		} else {
			loop_tier_state = (int)State::FAILED;
			Event("LOOPTIER_EVENT REAP_FAILED t_ms=%ld pid=%d after_guest_exit=1\n", NowMs(),
			      loop_tier_pid);
		}
	} else if ((State)loop_tier_state == State::BUILDING) {
		// --loop-tier-exit-cancel=0: the previous behaviour, kept reachable for an A/B and for
		// nothing else. It blocks until the compiler finishes.
		int wst = 0;
		if (waitpid((pid_t)loop_tier_pid, &wst, 0) > 0) {
			loop_tier_build_rc = WIFEXITED(wst) ? WEXITSTATUS(wst) : -1;
			loop_tier_reaped_ms = NowMs();
			Event("LOOPTIER_EVENT BUILD_END t_ms=%ld pid=%d rc=%d build_ms=%ld after_guest_exit=1\n",
			      loop_tier_reaped_ms, loop_tier_pid, loop_tier_build_rc,
			      loop_tier_reaped_ms - loop_tier_fire_ms);
			Disposition(false);
		} else {
			loop_tier_state = (int)State::FAILED;
			Event("LOOPTIER_EVENT REAP_FAILED t_ms=%ld pid=%d after_guest_exit=1\n", NowMs(),
			      loop_tier_pid);
		}
	}
	// T5d2b0: THE GUEST-EXIT FALLBACK, AND THE WAIT COMES FIRST. Restoring before the blocking
	// waitpid above would put the process's own disposition back while this tier's builder is still
	// a live child -- and if that disposition auto-reaps (SIG_IGN / SA_NOCLDWAIT), the exact wait
	// would return ECHILD and the build's status would be lost. Arm() now refuses those dispositions
	// outright, so this ordering is belt as well as braces; it costs nothing and it is the order the
	// contract actually requires. Idempotent: in a run whose builder was already consumed by DoReap
	// this is a no-op, because the window closed there.
	RestoreCompletionNotification();
	static char const *const kNames[] = {"OFF",    "ARMED",     "BUILDING", "PUBLISHED",
					     "FAILED", "ABSTAINED", "LOADED",   "INSTALLED",
					     "CANCELED"};
	static constexpr size_t kNamesN = sizeof kNames / sizeof kNames[0];
	static_assert((int)State::CANCELED + 1 == (int)kNamesN,
		      "a State was added without its name; the summary would print past the array");
	int s = loop_tier_state;
	// `notify_slots` is how many guest targets ever got a notification byte (one per counted
	// backward-edge target, allocated at translation); `notified` is how many CLAIMED it. A claim
	// is immediately followed by the payload store and the service bit, so `notified == events`
	// exactly -- unless the guest exited before the last notification reached a safepoint, in
	// which case it is one larger and `mailbox` names that target.
	//
	// `mailbox` is therefore 00000000 in any run whose tier is terminal, because a terminal tier's
	// generated code cannot store a payload at all; the consumer drained the slot at the service
	// that made it terminal and nothing may refill it. A non-zero mailbox in a PUBLISHED run would
	// be exactly the T5d2a1 defect this checkpoint fixes.
	unsigned long long notified = 0;
	for (auto const &kv : loop_tier_notified)
		notified += kv.second ? 1u : 0u;
	Event("LOOPTIER_SUMMARY state=%s event_sites=%llu notify_slots=%zu notified=%llu events=%lu "
	      "rejected=%lu spawn_ip=%08x last_taken_ip=%08x mailbox=%08x hottest=%llu threshold=%llu "
	      "vlen=%u guest_cpu=%d "
	      "builder_cpu=%d pid=%d fire_ms=%ld build_end_ms=%ld publish_ms=%ld guest_exit_ms=%ld "
	      "rc=%d bytes=%llu published_in_run=%d publish_before_guest_exit=%d path=%s\n",
	      (s >= 0 && (size_t)s < kNamesN) ? kNames[s] : "?", loop_tier_event_sites, loop_tier_notified.size(),
	      notified, loop_tier_events,
	      loop_tier_rejected, loop_tier_spawn_ip, loop_tier_last_taken_ip, loop_tier_event_ip,
	      (unsigned long long)loop_tier_hottest, (unsigned long long)sr_chunk_threshold,
	      config::vlen_bits, loop_tier_guest_cpu, loop_tier_builder_cpu, loop_tier_pid,
	      loop_tier_fire_ms, loop_tier_reaped_ms, loop_tier_publish_ms, loop_tier_guest_exit_ms,
	      loop_tier_build_rc, loop_tier_artifact_bytes, (int)loop_tier_publish_seen_in_run,
	      (int)(loop_tier_publish_ms >= 0 && loop_tier_publish_ms <= loop_tier_guest_exit_ms),
	      g_pubpath);
	// T5d2b1, printed only by a run that asked to load, and separately from the line above so the
	// two claims stay apart: PUBLISHED is a file, LOADED is a validated mapping in this process.
	if (loop_tier_load) {
		Event("LOOPTIER_LOAD on=1 state=%s load_ms=%ld syms=%llu spawn_ip=%08x publish_ms=%ld "
		      "guest_exit_ms=%ld loaded_before_guest_exit=%d refused=%s\n",
		      (s >= 0 && (size_t)s < kNamesN) ? kNames[s] : "?", loop_tier_load_ms,
		      (unsigned long long)loop_tier_loaded_syms, loop_tier_spawn_ip, loop_tier_publish_ms,
		      loop_tier_guest_exit_ms,
		      (int)(loop_tier_load_ms >= 0 && loop_tier_publish_ms >= 0 &&
			    loop_tier_publish_ms <= loop_tier_load_ms &&
			    loop_tier_load_ms <= loop_tier_guest_exit_ms),
		      loop_tier_load_refused ? loop_tier_load_refused : "-");
		// THE BOUNDARY, MEASURED IN THE RUN ITSELF. TierCensus walks tcache_map and classifies
		// every translation block by `tcode.size == 0` -- an announce-created AOT block has no code
		// in the pool. An artifact that had been INSTALLED would appear here as an AOT block, so
		// `aot_tbs=0` beside a non-zero `qcg_tbs` is this checkpoint's whole claim stated as two
		// numbers the run prints about itself.
		//
		// THE INDICES ARE tcache::TierCensus's OWN: out[0]/out[2] are the QCG count and mass,
		// out[1]/out[3] the AOT ones. Naming them in the wrong order once produced a line reading
		// `aot_tbs=111`, which is exactly the false alarm -- and, had the numbers been the other
		// way round, exactly the false reassurance -- that a mislabelled census gives.
		unsigned long census[4] = {0, 0, 0, 0};
		tcache::TierCensus(census);
		Event("LOOPTIER_LOAD_TCACHE qcg_tbs=%lu aot_tbs=%lu qcg_mass=%lu aot_mass=%lu\n", census[0],
		      census[1], census[2], census[3]);
	}
	// T5d2b2, printed only by a run that asked to install, and separately again, because INSTALLED
	// and EXECUTED are two more claims that must not be read off one number.
	//
	//   `gip`/`host`               -- WHAT was installed: one guest header, one host entry.
	//   `at_ip`                    -- the PC the run was resuming at when it was installed. Equal to
	//                                 `gip` means `Execute()`'s very next lookup, in the same
	//                                 iteration, is a lookup of the header just replaced.
	//   `aot_hits_before`/`_after` -- the artifact's OWN region-entry counter, read at the install
	//                                 and again here. It is emitted by LLVM-compiled artifact code
	//                                 and by nothing else, so `before == 0 && after > 0` is the
	//                                 promotion boundary: QCG ran before, the artifact ran after.
	//   `tb_exec`                  -- how many times the HOST LOOP arrived at the installed block.
	//                                 Supporting only: it counts arrivals at `Execute()`, not
	//                                 executions of the artifact, and after the escape's slot is
	//                                 linked the loop stops returning here at all.
	//
	// `aot_hits_after` is the evidence for execution. A block existing, an address being right and a
	// state saying INSTALLED are all compatible with the artifact never running.
	if (loop_tier_install) {
		auto const *tb = InstalledBlock();
		unsigned long long hits_now = 0;
		if (auto *st = CPUState::Current()) {
			for (unsigned i = 0; i < CPUState::REGION_HIT_SLOTS; ++i)
				hits_now += st->region_entry_hits[i];
		}
		// C5d adds three fields, and they are the promotion's own report on itself:
		//   `relinked`        -- already-self-patched direct predecessors repointed at the artifact.
		//                        This is the number T5g could not print and C5C had to measure with
		//                        a separate diagnostic; it is now on the tier's own line.
		//   `ic_unpatched`    -- inline-cache blobs whose stale direct jump was revoked.
		//   `brind_was_tgt`   -- whether this ip was ALREADY an indirect-dispatch target. Without it
		//                        a `brind` repoint cannot be told from a slot this promotion created.
		Event("LOOPTIER_INSTALL on=1 state=%s install_ms=%ld gip=%08x host=0x%llx at_ip=%08x "
		      "load_ms=%ld guest_exit_ms=%ld installed_after_load=%d installed_before_guest_exit=%d "
		      "aot_hits_before=%llu aot_hits_after=%llu tb_exec=%llu qcg_tbs_before=%lu "
		      "qcg_mass_before=%llu relinked=%lu ic_unpatched=%lu brind_was_tgt=%d refused=%s\n",
		      (s >= 0 && (size_t)s < kNamesN) ? kNames[s] : "?", loop_tier_install_ms, loop_tier_installed_gip,
		      loop_tier_install_host, loop_tier_install_at_ip, loop_tier_load_ms,
		      loop_tier_guest_exit_ms,
		      (int)(loop_tier_install_ms >= 0 && loop_tier_load_ms >= 0 &&
			    loop_tier_load_ms <= loop_tier_install_ms),
		      (int)(loop_tier_install_ms >= 0 && loop_tier_install_ms < loop_tier_guest_exit_ms),
		      loop_tier_install_aot_hits, hits_now,
		      (unsigned long long)(tb ? tb->flags.exec_count : 0ull),
		      loop_tier_install_qcg_tbs, loop_tier_install_qcg_mass,
		      loop_tier_install_relinked, loop_tier_install_ic_unpatched,
		      (int)loop_tier_install_brind_was_target,
		      loop_tier_install_refused ? loop_tier_install_refused : "-");
	}
	// C5c: THE SECOND SAMPLE, after the last line that reports the install and before anything is
	// released. `loop_tier_spawn_ip` rather than `loop_tier_installed_gip`, on purpose: a run that
	// SELECTED a header but never installed one still has a routing state worth recording, and
	// using the installed gip would make exactly those runs print nothing. Both are already on the
	// LOOPTIER_INSTALL line above, so a reader can tell the two cases apart.
	//
	// Pure read, default off, and it must stay after ReportAtExit's own numbers so that the
	// `execcount_value` it prints and the `TIER_CENSUS` line are describing the same instant.
	RouteCensusEmit("guest_exit", loop_tier_spawn_ip);
	// The view's stated lifetime ends here, after the last line that reports it.
	ReleaseLoadedArtifact();
	ReleaseInstalledBlock();
}

} // namespace dbt::looptier
