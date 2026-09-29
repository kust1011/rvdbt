// T5d2a focused test -- the loop tier's state machine, its artifact gate and its publication, and
// (T5d2a2) the notification RULE and the consumer's half of the notification protocol.
//
// WHAT EACH SECTION CAN FAIL ON. Every check below names the defect that makes it fail, because a
// check that cannot be made to fail is not evidence. The mutation harness
// (t5d2a2_mutations.sh) turns each of those sentences into an actual source defect and requires this
// binary to reject it; a check whose named defect the harness cannot reproduce is a check to delete.
//
// WHAT IT DOES NOT NEED. No guest, no compiler, no profile, no AVX-512, no second CPU, no clock.
// The state machine is driven by counts this file supplies, the ELF reader by images this file
// builds byte by byte, and the spawn site by a fork whose "compiler" is /bin/echo -- so what
// section 6 inspects is the argument vector `execv` really received.

#include "dbt/aot/loop_tier.h"
#include "dbt/qmc/compile.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
}

using namespace dbt;
using namespace dbt::looptier;

static int g_checks = 0, g_fail = 0;
static void CHECK(bool ok, char const *what)
{
	g_checks++;
	if (!ok) {
		g_fail++;
		printf("  FAIL %s\n", what);
	} else {
		printf("  ok   %s\n", what);
	}
}
static void SECTION(char const *s)
{
	printf("\n== %s ==\n", s);
}

// ==============================================================================================
// A minimal but REAL ELF64 shared-object image: an .aottab holding `n` AOTSymbols and a .symtab
// defining `_x<gip>` for each of them. Built here rather than compiled by a toolchain so the
// failure cases -- an empty table, a table naming a symbol that is not defined, a table whose count
// overruns its own section -- can be constructed exactly.
struct FakeSo {
	std::vector<u8> img;
	size_t Add(void const *p, size_t n, size_t align = 1)
	{
		while (img.size() % align)
			img.push_back(0);
		size_t off = img.size();
		img.insert(img.end(), (u8 const *)p, (u8 const *)p + n);
		return off;
	}
};

// `defined_names`: how many of the aottab entries also get a defined `_x<gip>` symbol (the rest are
// left out entirely). `claim_n`: the n_sym the header claims, which may exceed what was written.
// `wrong_value`: give the first symbol an address the table does not record.
// `shrink_tab_to`: declare a .aottab sh_size covering only this many entries, while the file
// physically holds -- and correctly defines -- all of them. That separates "the count overruns the
// section" from every other failure: an image built this way is fully VALID on every other axis, so
// a reader that skips the bounds check returns a plausible answer instead of an error, and only a
// reader that checks the section's own size refuses it.
static std::vector<u8> MakeSo(std::vector<u32> const &gips, size_t defined_names, u64 claim_n,
			      bool wrong_value = false, size_t shrink_tab_to = 0)
{
	FakeSo f;
	Elf64_Ehdr eh{};
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_type = ET_DYN;
	eh.e_machine = EM_X86_64;
	eh.e_version = EV_CURRENT;
	eh.e_ehsize = sizeof eh;
	eh.e_shentsize = sizeof(Elf64_Shdr);
	f.Add(&eh, sizeof eh);

	// .aottab content
	AOTTabHeader hdr{};
	hdr.n_sym = claim_n;
	size_t tab_off = f.Add(&hdr, sizeof hdr, 16);
	for (size_t i = 0; i < gips.size(); ++i) {
		AOTSymbol as{};
		as.gip = gips[i];
		as.aot_vaddr = 0x1000 + 0x40 * i;
		as.gsize = 0;
		f.Add(&as, sizeof as);
	}
	size_t tab_size = f.img.size() - tab_off;

	// .strtab / .symtab
	std::string str;
	str.push_back('\0');
	std::vector<Elf64_Sym> syms(1); // index 0 is the reserved null entry
	for (size_t i = 0; i < gips.size() && i < defined_names; ++i) {
		char nm[64];
		AotSymbolName(gips[i], nm, sizeof nm);
		Elf64_Sym s{};
		s.st_name = (Elf64_Word)str.size();
		str += nm;
		str.push_back('\0');
		s.st_shndx = 1; // any defined section
		s.st_value = 0x1000 + 0x40 * i + (wrong_value && i == 0 ? 8 : 0);
		s.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
		syms.push_back(s);
	}
	size_t str_off = f.Add(str.data(), str.size(), 1);
	size_t sym_off = f.Add(syms.data(), syms.size() * sizeof(Elf64_Sym), 8);

	// section-header string table
	std::string shstr;
	shstr.push_back('\0');
	auto nm = [&](char const *s) {
		size_t o = shstr.size();
		shstr += s;
		shstr.push_back('\0');
		return (Elf64_Word)o;
	};
	Elf64_Word n_null = nm(""), n_tab = nm(".aottab"), n_str = nm(".strtab"), n_sym = nm(".symtab"),
		   n_shstr = nm(".shstrtab");
	size_t shstr_off = f.Add(shstr.data(), shstr.size(), 1);

	std::vector<Elf64_Shdr> sh(5);
	sh[0].sh_name = n_null;
	sh[0].sh_type = SHT_NULL;
	sh[1].sh_name = n_tab;
	sh[1].sh_type = SHT_PROGBITS;
	sh[1].sh_offset = tab_off;
	sh[1].sh_size = shrink_tab_to ? sizeof(AOTTabHeader) + shrink_tab_to * sizeof(AOTSymbol)
				      : tab_size;
	sh[2].sh_name = n_str;
	sh[2].sh_type = SHT_STRTAB;
	sh[2].sh_offset = str_off;
	sh[2].sh_size = str.size();
	sh[3].sh_name = n_sym;
	sh[3].sh_type = SHT_SYMTAB;
	sh[3].sh_offset = sym_off;
	sh[3].sh_size = syms.size() * sizeof(Elf64_Sym);
	sh[3].sh_entsize = sizeof(Elf64_Sym);
	sh[3].sh_link = 2;
	sh[4].sh_name = n_shstr;
	sh[4].sh_type = SHT_STRTAB;
	sh[4].sh_offset = shstr_off;
	sh[4].sh_size = shstr.size();
	size_t sh_off = f.Add(sh.data(), sh.size() * sizeof(Elf64_Shdr), 8);

	auto *e = (Elf64_Ehdr *)f.img.data();
	e->e_shoff = sh_off;
	e->e_shnum = (Elf64_Half)sh.size();
	e->e_shstrndx = 4;
	return f.img;
}

static std::string MakeTempDir()
{
	char t[] = "/tmp/rvdbt_looptier_XXXXXX";
	char *d = mkdtemp(t);
	return d ? std::string(d) : std::string();
}

static std::string Slurp(std::string const &p)
{
	std::string out;
	int fd = open(p.c_str(), O_RDONLY);
	if (fd < 0)
		return out;
	char b[4096];
	ssize_t r;
	while ((r = read(fd, b, sizeof b)) > 0)
		out.append(b, (size_t)r);
	close(fd);
	return out;
}

// T5f helpers. Section 8 asserts things about the child's argv AS A SEQUENCE OF ARGUMENTS -- which
// option names appear, how many times each appears, and in what order -- rather than by substring
// search alone. Substring search cannot see a repeated option, and a repeated option with two
// different values is exactly the shape this checkpoint is forbidden to ship.
static std::vector<std::string> SplitArgs(std::string const &cmd)
{
	std::vector<std::string> v;
	size_t i = 0;
	while (i < cmd.size()) {
		while (i < cmd.size() && (cmd[i] == ' ' || cmd[i] == '\n'))
			++i;
		size_t b = i;
		while (i < cmd.size() && cmd[i] != ' ' && cmd[i] != '\n')
			++i;
		if (i > b)
			v.push_back(cmd.substr(b, i - b));
	}
	return v;
}

// "--rvv-vector-ssa=1" -> "--rvv-vector-ssa". A bare argument maps to itself.
static std::string OptName(std::string const &arg)
{
	size_t eq = arg.find('=');
	return eq == std::string::npos ? arg : arg.substr(0, eq);
}

// How many arguments in `v` name option `opt`, at ANY value. This is the duplicate detector: the
// rejected shape (render the table, then append `--rvv-vector-ssa=1` and let the child's parser
// take the last one) makes this return 2.
static int CountOpt(std::vector<std::string> const &v, char const *opt)
{
	int n = 0;
	for (auto const &a : v)
		if (OptName(a) == opt)
			n++;
	return n;
}

// Index of the first argument named `opt`, or -1. Used for the order assertions.
static int IndexOf(std::vector<std::string> const &v, std::string const &opt)
{
	for (size_t i = 0; i < v.size(); ++i)
		if (OptName(v[i]) == opt)
			return (int)i;
	return -1;
}

// Index of the rendered contract slot whose option name is `opt`. Aborts the lookup to 0 if absent;
// the caller's surrounding checks already fail in that case (a missing row fails `all`).
static size_t IndexOfRendered(char const *const *rendered, size_t n, char const *opt)
{
	for (size_t i = 0; i < n; ++i)
		if (OptName(rendered[i]) == opt)
			return i;
	return 0;
}

// Run Arm() with stderr captured and return the `reason=` it printed, or "" if it refused silently
// or did not refuse. Arm()'s refusals are a single line -- `LOOPTIER_EVENT ARM_REFUSED reason=X` --
// which is why a test can assert WHICH precondition fired rather than merely that one did.
static std::string ArmRefusalReason(std::string const &tmp)
{
	fflush(stderr);
	int saved = dup(2);
	int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		dup2(fd, 2);
		close(fd);
	}
	bool armed = Arm();
	fflush(stderr);
	if (saved >= 0) {
		dup2(saved, 2);
		close(saved);
	}
	std::string out = Slurp(tmp);
	unlink(tmp.c_str());
	if (armed)
		return "";
	size_t k = out.find("reason=");
	if (k == std::string::npos)
		return "";
	size_t b = k + 7, e = out.find_first_of(" \n", b);
	return out.substr(b, e == std::string::npos ? std::string::npos : e - b);
}

int main()
{
	printf("T5d2a loop-tier test\n");

	// -------------------------------------------------------------------------------------
	SECTION("1. mode off is inert");
	// FAILS IF: Decide stops testing `enabled` first -- e.g. someone moves the state switch above
	// it, or treats OFF as "not yet armed" and lets an event arm it. Then an off run would fire.
	CHECK(Decide(State::ARMED, false, true) == Action::NOTHING,
	      "off + a selected header -> NOTHING");
	CHECK(Decide(State::BUILDING, false, false) == Action::NOTHING, "off + BUILDING -> NOTHING");
	CHECK(Decide(State::OFF, true, true) == Action::NOTHING,
	      "un-armed state never fires, even with the mode on");
	{
		// Service() must not touch a single counter when the mode is off. FAILS IF: the early
		// return is dropped or moved below the selector call.
		config::loop_tier = false;
		unsigned long ev0 = config::loop_tier_events, rj0 = config::loop_tier_rejected;
		int state0 = config::loop_tier_state;
		config::loop_tier_event_ip = 0x11890;
		Service();
		CHECK(config::loop_tier_events == ev0, "Service() with the mode off takes no event");
		CHECK(config::loop_tier_rejected == rj0, "Service() with the mode off rejects nothing");
		CHECK(config::loop_tier_state == state0, "Service() with the mode off moves no state");
		CHECK(config::loop_tier_event_ip == 0x11890,
		      "...and does not even drain the mailbox: the off path is the first statement");
		config::loop_tier_event_ip = 0;
	}

	// -------------------------------------------------------------------------------------
	SECTION("2. the notification: reached-or-passed, and a one-shot that does not live in a counter");
	// This is the predicate the emitted code implements (qemit.cpp, Emit_Cache). Section 2 of
	// loop_tier_event_test checks that the EMITTED bytes implement this same conjunction and
	// section 7 executes them; here it is pinned as a rule.
	//
	// FAILS IF: the evidence test becomes `==` again (which a non-backedge arrival can consume --
	// T5d2a2's whole subject), `>` (which skips the exact-bar case), or if the bar stops being the
	// argument.
	CHECK(!CrossedBar(0, 262144), "count 0 is not evidence");
	CHECK(!CrossedBar(1, 262144), "count 1 is not evidence");
	CHECK(!CrossedBar(262143, 262144), "one below the bar is not evidence");
	CHECK(CrossedBar(262144, 262144), "the increment that reaches the bar IS evidence");
	CHECK(CrossedBar(262145, 262144), "and so is any later count -- no other writer can step over it");
	CHECK(CrossedBar(7, 7) && !CrossedBar(7, 8), "the bar is the argument, not a constant");
	{
		// THE ONE-SHOT IS NOT IN THE COUNTER ANY MORE. Over the whole life of one target, the
		// evidence test is true from the bar onwards; what fires exactly once is the NOTIFICATION,
		// because the durable per-target byte is claimed the first time it does.
		unsigned evidence = 0, notified = 0;
		unsigned char one_shot = 0;
		for (u64 c = 1; c <= 300000; ++c) {
			evidence += CrossedBar(c, 262144) ? 1 : 0;
			if (ShouldNotify(c, 262144, (int)State::ARMED, 0, one_shot)) {
				notified++;
				one_shot = 1; // the generated code's `mov byte [rsi], 1`
			}
		}
		CHECK(evidence == 300000 - 262144 + 1, "the evidence holds from the bar onwards");
		CHECK(notified == 1, "over 300,000 increments exactly ONE notification is delivered");
	}
	{
		// The other three guards, each falsified on its own with the evidence held true. FAILS IF
		// any conjunct is dropped from ShouldNotify -- which is the same conjunction the emitted
		// bytes are checked against.
		u64 const hot = 262145, bar = 262144;
		CHECK(ShouldNotify(hot, bar, (int)State::ARMED, 0, 0), "armed + free + unnotified -> notify");
		for (State st : {State::OFF, State::BUILDING, State::PUBLISHED, State::FAILED,
				 State::ABSTAINED})
			CHECK(!ShouldNotify(hot, bar, (int)st, 0, 0),
			      "a tier that is not ARMED is never notified, at any count");
		CHECK(!ShouldNotify(hot, bar, (int)State::ARMED, 0x11890, 0),
		      "an occupied mailbox defers the notification instead of overwriting it");
		CHECK(!ShouldNotify(hot, bar, (int)State::ARMED, 0, 1),
		      "a target that already notified never notifies again");
		CHECK(!ShouldNotify(bar - 1, bar, (int)State::ARMED, 0, 0),
		      "and below the bar nothing else matters");
	}
	{
		// THE ONE-SHOT'S DURABILITY, as a property of where it lives. `LoopTierNotifySlot` hands
		// the code generator an address at TRANSLATION time; that address must keep naming the same
		// byte no matter how many other targets are later added (rehashing) and no matter how many
		// times the block is retranslated.
		//
		// FAILS IF: the table is changed to a vector/array-backed container (whose elements move on
		// growth), or the slot is keyed by anything but the guest ip.
		unsigned char *first = config::LoopTierNotifySlot(0x11890);
		*first = 1;
		for (u32 k = 0; k < 20000; ++k)
			(void)config::LoopTierNotifySlot(0x20000 + 4 * k);
		CHECK(config::LoopTierNotifySlot(0x11890) == first,
		      "20,000 later targets do not move an already-issued notify slot");
		CHECK(*first == 1, "...and the claim it holds survives them");
		CHECK(config::LoopTierNotifySlot(0x11890) == config::LoopTierNotifySlot(0x11890),
		      "the same guest ip always names the same byte -- a retranslation cannot rearm it");
		CHECK(config::LoopTierNotifySlot(0x11894) != first, "a different guest ip is a different byte");
		CHECK(*config::LoopTierNotifySlot(0x11894) == 0, "and a fresh slot starts unclaimed");
		*first = 0;
	}

	// -------------------------------------------------------------------------------------
	SECTION("3. the event's target decides, and the one-shot is spent only for a header");
	// FAILS IF: a non-header event consumes the one-shot (the tier would then never build for the
	// real header that crosses later), or a header event does not spawn, or a spent tier can spawn
	// again.
	CHECK(Decide(State::ARMED, true, false) == Action::REJECT,
	      "a crossing into something that is not a selected loop header -> REJECT");
	CHECK(Decide(State::ARMED, true, true) == Action::SPAWN,
	      "a crossing into a selected hot loop header -> SPAWN");
	CHECK(Decide(State::BUILDING, true, true) == Action::REAP,
	      "once building, another header event cannot start a second build");
	// EVERY terminal state, exhaustively -- LOADED (T5d2b1) and INSTALLED (T5d2b2) included. A state
	// added to the enum but not to `Decide`'s terminal arm would fall through to the defensive
	// `return Action::NOTHING` and look fine here; what this loop protects against instead is a state
	// added to the arm and then quietly given a non-terminal answer.
	for (State term : {State::PUBLISHED, State::LOADED, State::INSTALLED, State::FAILED,
			   State::ABSTAINED}) {
		char what[80];
		snprintf(what, sizeof what, "a terminal state never spawns again (state=%d)", (int)term);
		CHECK(Decide(term, true, true) == Action::NOTHING, what);
	}
	{
		// A run's worth of events, modelled exactly as Service() sequences them: REJECT leaves the
		// state alone, SPAWN advances it once. FAILS IF the rejection path advances the state --
		// then `spawns` would be 0 because the tier was already spent by the first latch.
		State st = State::ARMED;
		unsigned spawns = 0, rejects = 0;
		bool member[] = {false, false, false, true, true, false, true};
		for (bool m : member) {
			switch (Decide(st, true, m)) {
			case Action::REJECT:
				rejects++;
				break; // state deliberately untouched
			case Action::SPAWN:
				spawns++;
				st = State::BUILDING;
				break;
			default:
				break;
			}
		}
		CHECK(rejects == 3, "three non-header crossings were refused");
		CHECK(spawns == 1, "and the one allowed build was spent exactly once, on the first header");
		CHECK(st == State::BUILDING, "the tier is building after that one spawn");
	}
	{
		// THE NO-LIVELOCK PROPERTY, stated as the fact that produces it. A rejected target's
		// evidence stays true for ever (that is what `>=` means), so what stops it from asking
		// again is its own claimed one-shot -- and that is durable, so no retranslation restores
		// it. The tier stays ARMED, so a DIFFERENT target can still spend the build: a rejection
		// costs one notification, not the tier.
		CHECK(CrossedBar(262145, 262144) && CrossedBar(1ull << 40, 262144),
		      "a rejected target's counter stays above the bar for ever");
		CHECK(!ShouldNotify(262145, 262144, (int)State::ARMED, 0, 1) &&
			  !ShouldNotify(1ull << 40, 262144, (int)State::ARMED, 0, 1),
		      "...and it still cannot notify again at any later count");
		CHECK(ShouldNotify(262145, 262144, (int)State::ARMED, 0, 0),
		      "while a different target, never notified, still can");
	}

	// -------------------------------------------------------------------------------------
	SECTION("4. no distinct CPU abstains");
	// FAILS IF: the selector falls back to arithmetic on the current CPU, wraps around, or returns
	// the guest's own CPU when the mask holds nothing else -- the pre-2026-08-17 defect, which named
	// CPUs the process was not allowed to use.
	{
		cpu_set_t m;
		CPU_ZERO(&m);
		CPU_SET(3, &m);
		CHECK(SelectDistinctCpu(&m, 3) == -1, "mask {3}, guest on 3 -> -1 (abstain)");
		CHECK(SelectDistinctCpu(&m, 5) == 3, "mask {3}, guest on 5 -> 3");
		CPU_ZERO(&m);
		CPU_SET(2, &m);
		CPU_SET(3, &m);
		CHECK(SelectDistinctCpu(&m, 2) == 3, "mask {2,3}, guest on 2 -> 3, not 2+1 by arithmetic");
		CHECK(SelectDistinctCpu(&m, 3) == 2, "mask {2,3}, guest on 3 -> 2");
		CPU_ZERO(&m);
		CPU_SET(17, &m);
		CPU_SET(29, &m);
		CHECK(SelectDistinctCpu(&m, 17) == 29, "no CPU number is assumed: {17,29} -> 29");
		CPU_ZERO(&m);
		CHECK(SelectDistinctCpu(&m, 0) == -1, "an empty mask abstains");
	}

	// -------------------------------------------------------------------------------------
	SECTION("5. the artifact gate: only a real selected loop header publishes");
	// FAILS IF: the gate counts aottab entries without checking they are defined, accepts a
	// mismatched address, trusts a claimed n_sym the section cannot hold, or reports a corrupt
	// image as an empty selection (which MayPublish would then treat identically, hiding it).
	{
		u32 out[64];
		std::vector<u32> gips = {0x11844, 0x11890, 0x118c4};
		auto good = MakeSo(gips, gips.size(), gips.size());
		long n = ArtifactLoopHeaders(good.data(), good.size(), out, 64);
		CHECK(n == 3, "3 defined headers -> 3");
		CHECK(n == 3 && out[0] == 0x11844 && out[1] == 0x11890 && out[2] == 0x118c4,
		      "the gips come back as the artifact records them");
		// The name really is MakeAotSymbol's, so the fork-safe spelling cannot drift from the
		// compiler's. FAILS IF: AotSymbolName changes prefix, case or width.
		char nm[64];
		AotSymbolName(0x11844, nm, sizeof nm);
		CHECK(MakeAotSymbol(0x11844) == nm, "AotSymbolName == MakeAotSymbol");

		auto empty = MakeSo({}, 0, 0);
		CHECK(ArtifactLoopHeaders(empty.data(), empty.size(), out, 64) == 0,
		      "an artifact that selected nothing reports 0, not an error");

		auto undef = MakeSo(gips, 2, gips.size()); // third gip has no defining symbol
		CHECK(ArtifactLoopHeaders(undef.data(), undef.size(), out, 64) == -1,
		      "a table naming a header the artifact does not define is refused");

		auto wrongaddr = MakeSo(gips, gips.size(), gips.size(), /*wrong_value=*/true);
		CHECK(ArtifactLoopHeaders(wrongaddr.data(), wrongaddr.size(), out, 64) == -1,
		      "a symbol at an address the table does not record is refused");

		// The section says it holds ONE entry; the file holds three, all of them individually
		// valid. Only the bounds check against sh_size can tell this apart from `good`, so this
		// is the case that keeps that check honest -- a reader without it returns 3.
		auto overrun = MakeSo(gips, gips.size(), gips.size(), false, /*shrink_tab_to=*/1);
		CHECK(ArtifactLoopHeaders(overrun.data(), overrun.size(), out, 64) == -1,
		      "a claimed n_sym the .aottab section cannot hold is refused, even when every entry "
		      "past the end happens to be valid");

		auto huge = MakeSo(gips, gips.size(), 1ull << 40); // a count no buffer could hold
		CHECK(ArtifactLoopHeaders(huge.data(), huge.size(), out, 64) == -1,
		      "an absurd claimed n_sym is refused");

		CHECK(ArtifactLoopHeaders(good.data(), good.size(), out, 2) == -1,
		      "more headers than the caller's buffer is refused, not truncated");
		CHECK(ArtifactLoopHeaders(good.data(), 16, out, 64) == -1, "a truncated image is refused");
		char junk[512];
		memset(junk, 0xa5, sizeof junk);
		CHECK(ArtifactLoopHeaders(junk, sizeof junk, out, 64) == -1, "a non-ELF buffer is refused");
	}

	// -------------------------------------------------------------------------------------
	SECTION("6. failure and emptiness are both unpublishable");
	// FAILS IF: either half of the conjunction is dropped. The middle two are the cases that matter:
	// a compiler that succeeded but selected nothing, and one that failed after leaving a file.
	CHECK(MayPublish(0, 3), "rc=0 with headers publishes");
	CHECK(!MayPublish(0, 0), "rc=0 with an empty selection does NOT publish");
	CHECK(!MayPublish(1, 3), "a failed compile does NOT publish, even with headers");
	CHECK(!MayPublish(-1, 3), "a killed compile does NOT publish");
	CHECK(!MayPublish(2, 0), "both wrong does not publish");

	// -------------------------------------------------------------------------------------
	SECTION("7. publication is an in-directory rename");
	// FAILS IF: the publish copies instead of renaming (an observer could then read a partial
	// file), or accepts a cross-directory move (which rename(2) does not promise to make atomic
	// across filesystems, and which would silently become a link/copy fallback if anyone added one).
	{
		std::string d = MakeTempDir();
		CHECK(!d.empty(), "temp dir created");
		std::string src = d + "/a.so", dst = d + "/loop_tier.v512.so";
		{
			FILE *f = fopen(src.c_str(), "w");
			fputs("ARTIFACT-BYTES", f);
			fclose(f);
		}
		CHECK(PublishAtomically(src.c_str(), dst.c_str()), "publish succeeds");
		CHECK(Slurp(dst) == "ARTIFACT-BYTES", "the published file has the artifact's bytes");
		CHECK(access(src.c_str(), F_OK) != 0, "the source name is gone: it was renamed, not copied");
		CHECK(!PublishAtomically(src.c_str(), dst.c_str()), "publishing a missing source fails");
		std::string d2 = MakeTempDir();
		std::string cross = d2 + "/x.so";
		{
			FILE *f = fopen(cross.c_str(), "w");
			fputs("X", f);
			fclose(f);
		}
		CHECK(!PublishAtomically(cross.c_str(), dst.c_str()),
		      "a cross-directory publish is refused");
		CHECK(Slurp(dst) == "ARTIFACT-BYTES", "...and did not overwrite the published artifact");
		CHECK(!PublishAtomically(dst.c_str(), dst.c_str()), "publishing onto itself is refused");
		unlink(dst.c_str());
		unlink(cross.c_str());
		rmdir(d.c_str());
		rmdir(d2.c_str());
	}

	// -------------------------------------------------------------------------------------
	SECTION("8. the active VLEN and the route contract reach the child");
	// This forks the REAL SpawnBuilder with /bin/echo standing in for the compiler, so what is
	// inspected below is the argv `execv` received and the file the site wrote from that same array.
	//
	// FAILS IF: --vlen is dropped, cached, or fed from anything but config::vlen_bits; a route flag
	// is spelled by hand instead of rendered from kRvvRouteContract (a newly added row would then be
	// missing); --threshold does not carry the caller's bar; --aot-loop-regions is not requested (the
	// child would build Wendell per-page regions, not T5d1b loops); or a forbidden T5c flag appears.
	// It ALSO fails if an empty build is published: /bin/echo produces no artifact at all.
	//
	// T5f CONFIGURES THE PARENT THE WAY A REAL TIER RUN IS CONFIGURED, which is the point of the
	// section now. `config::rvv_vector_ssa = false` is not a convenience here: it is the ONLY value
	// at which looptier::Arm() accepts `--loop-tier-side-exit`, so it is the only parent state in
	// which this spawn site is reachable at all. Before T5f the section set it to TRUE -- a state
	// the tier can never be in -- and so the `--rvv-vector-ssa=1` it then observed in the child was
	// inheritance working correctly on a configuration that does not occur, and the defect T5e
	// measured was invisible to it.
	{
		std::string d = MakeTempDir();
		config::vlen_bits = 1024;
		// The parent's REAL tier configuration: the substrate off (Arm() requires it), one route
		// on and one route off, so both rendered polarities are exercised.
		config::rvv_vector_ssa = false;
		config::rvv_qcg_typed_chunk_sub = true;
		config::rvv_qcg_typed_chunk_mul = false;
		config::rvv_vector_ssa_counters = true;  // a diagnostic ON...
		config::aot_loop_entry = false;          // ...and a diagnostic OFF
		pid_t pid = SpawnBuilder(sched_getcpu(), "/bin/echo", "/dev/null", d.c_str(),
					 (d + "/absent.aot.so").c_str(), "loop_tier.v1024.so", 262144);
		CHECK(pid > 0, "the builder forked");
		int st = 0;
		waitpid(pid, &st, 0);
		int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
		std::string cmd = Slurp(d + "/loop_tier_build.cmd");
		std::string log = Slurp(d + "/loop_tier_build.log");
		std::vector<std::string> argv = SplitArgs(cmd);
		CHECK(cmd.find("--vlen=1024") != std::string::npos, "argv carries the parent's active --vlen");
		CHECK(log.find("--vlen=1024") != std::string::npos,
		      "...and the child really received it (echoed by the exec'd process)");
		CHECK(cmd.find("--threshold=262144") != std::string::npos, "argv carries the caller's bar");
		CHECK(cmd.find("--aot-loop-regions=1") != std::string::npos,
		      "argv asks for T5d1b loop-rooted regions");
		CHECK(cmd.find("--llvm=1") != std::string::npos, "argv asks for the LLVM backend");
		CHECK(cmd.find("--cache=" + d) != std::string::npos, "argv points the child at the staging dir");

		// ---- T5f: THE PARENT'S VALUE AND THE CHILD'S VALUE ARE READ SEPARATELY, AND DIFFER.
		//
		// FAILS IF: the child is left inheriting the parent (back to `--rvv-vector-ssa=0`, the T5e
		// artifact); or the substrate row is dropped from the rendering altogether; or the fix is
		// taken by mutating the parent's own live config -- which would be a silent removal of
		// Arm()'s side-exit precondition, not a child-contract fix.
		CHECK(config::rvv_vector_ssa == false,
		      "the PARENT is still at rvv-vector-ssa=0 -- the spawn site did not touch its config");
		CHECK(cmd.find("--rvv-vector-ssa=1") != std::string::npos,
		      "the CHILD is told --rvv-vector-ssa=1: the LLVM substrate, not the parent's value");
		CHECK(cmd.find("--rvv-vector-ssa=0") == std::string::npos,
		      "...and the inherited 0 appears nowhere in the child's argv");
		// The parent's precondition is still enforceable at the value that would break it, AND it
		// refuses for THIS reason rather than for one of the dozen other reasons Arm() can refuse
		// for. The reason string is read back from Arm()'s own stderr line, because "Arm() returned
		// false" would pass just as well with the vector-state check deleted and some earlier
		// prerequisite left unmet -- which is not evidence of anything.
		//
		// FAILS IF: `side_exit_needs_committed_vector_state` is removed or weakened -- i.e. if T5e
		// is "fixed" by letting the parent carry the substrate instead of by giving the child its
		// own. Every prerequisite ahead of it is satisfied here on purpose, so this refusal is the
		// first one reachable.
		{
			bool sv_lt = config::loop_tier, sv_se = config::loop_tier_side_exit;
			bool sv_tr = config::trace, sv_bs = config::qcg_backedge_safepoint;
			char const *sv_ea = config::loop_tier_elfaot, *sv_el = config::loop_tier_elf;
			char const *sv_st = config::loop_tier_stage;
			config::loop_tier = true;
			config::loop_tier_side_exit = true;
			config::trace = false;              // else the frame-balance refusal fires first
			config::qcg_backedge_safepoint = true;
			config::loop_tier_elfaot = "/bin/echo";
			config::loop_tier_elf = "/dev/null";
			config::loop_tier_stage = d.c_str();
			config::rvv_vector_ssa = true;      // the value the tier may never run at
			std::string reason = ArmRefusalReason(d + "/arm_at_1.err");
			config::rvv_vector_ssa = false;
			config::loop_tier = sv_lt;
			config::loop_tier_side_exit = sv_se;
			config::trace = sv_tr;
			config::qcg_backedge_safepoint = sv_bs;
			config::loop_tier_elfaot = sv_ea;
			config::loop_tier_elf = sv_el;
			config::loop_tier_stage = sv_st;
			CHECK(reason == "side_exit_needs_committed_vector_state",
			      "Arm() still refuses side-exit at parent rvv-vector-ssa=1, for that exact reason");
		}

		// ---- T5f: NO OPTION IS EMITTED TWICE, at any value.
		//
		// FAILS IF: the substrate is delivered by appending a second `--rvv-vector-ssa=1` after the
		// rendered table and relying on the child's parser taking the last value.
		{
			bool dup = false;
			std::string dupname;
			for (size_t i = 0; i < argv.size(); ++i) {
				std::string n = OptName(argv[i]);
				if (n.rfind("--", 0) != 0)
					continue;
				if (CountOpt(argv, n.c_str()) != 1) {
					dup = true;
					dupname = n;
				}
			}
			CHECK(!dup, "every option in the child's argv appears exactly once");
			CHECK(CountOpt(argv, "--rvv-vector-ssa") == 1,
			      "...--rvv-vector-ssa specifically: one occurrence, one explicit value");
		}

		// ---- The whole contract, in table order, at the child's values.
		//
		// The expectation is rendered with the SAME parameter the spawn site declares, so a row
		// added to kRvvRouteContract is covered without editing this test -- and a row whose value
		// the site resolves differently from this renderer is caught immediately.
		char slots[kRvvRouteArgMax][64];
		char const *rendered[kRvvRouteArgMax];
		size_t n_rvv = RvvRouteArgv(slots, rendered, RvvChildSubstrate::LlvmPrerequisite);
		CHECK(n_rvv > 0, "the route contract has rows");
		bool all = true, saw_on = false, saw_off = false, ordered = true;
		int prev = -1;
		for (size_t i = 0; i < n_rvv; ++i) {
			bool here = false;
			for (auto const &a : argv)
				if (a == rendered[i])
					here = true;
			if (!here)
				all = false;
			if (strstr(rendered[i], "=1"))
				saw_on = true;
			if (strstr(rendered[i], "=0"))
				saw_off = true;
			int at = IndexOf(argv, OptName(rendered[i]));
			if (at < 0 || at <= prev)
				ordered = false;
			prev = at;
		}
		CHECK(all, "every rendered contract flag appears in the child's argv, value included");
		CHECK(saw_on && saw_off, "both an on and an off value are rendered (not just the on ones)");
		CHECK(ordered, "the contract appears in table order, contiguously ascending");
		// ...and the contract sits where the audit says it must: after --vlen, before --threshold.
		{
			int i_llvm = IndexOf(argv, "--llvm"), i_vlen = IndexOf(argv, "--vlen");
			int i_first = IndexOf(argv, OptName(rendered[0]));
			int i_last = IndexOf(argv, OptName(rendered[n_rvv - 1]));
			int i_thr = IndexOf(argv, "--threshold"), i_reg = IndexOf(argv, "--aot-loop-regions");
			CHECK(i_llvm > 0 && i_vlen > i_llvm && i_first > i_vlen,
			      "--llvm then --vlen then the contract");
			CHECK(i_thr > i_last && i_reg > i_thr,
			      "...then --threshold, then --aot-loop-regions, then the terminator");
			CHECK((size_t)i_reg == argv.size() - 1, "--aot-loop-regions is the last argument");
		}
		CHECK(cmd.find("--rvv-qcg-typed-chunk-sub=1") != std::string::npos,
		      "an ON route carries the parent's value -- route policy is still inherited");
		CHECK(cmd.find("--rvv-qcg-typed-chunk-mul=0") != std::string::npos,
		      "the OFF route is rendered too, so a default change cannot switch it on silently");
		CHECK(cmd.find("--rvv-vector-ssa-counters=1") != std::string::npos,
		      "the ON diagnostic carries the parent's value");
		CHECK(cmd.find("--aot-loop-entry=0") != std::string::npos,
		      "T5c's loop-entry exposure is carried OFF, never requested");
		CHECK(cmd.find("--inrun-escape-unlink") == std::string::npos,
		      "the T5c escape ring is nowhere in the child's argv");
		CHECK(cmd.find("sr_builder.sh") == std::string::npos, "no builder script is involved");
		CHECK(rc != 0, "a run that produced no artifact exits nonzero");
		CHECK(access((d + "/loop_tier.v1024.so").c_str(), F_OK) != 0,
		      "...and publishes nothing: an empty/failed build fails closed");
		unlink((d + "/loop_tier_build.cmd").c_str());
		unlink((d + "/loop_tier_build.log").c_str());
		rmdir(d.c_str());
	}

	// -------------------------------------------------------------------------------------
	SECTION("8b. T5f: the substrate row is the ONLY thing the parameter moves");
	// The two renderings are compared against each other rather than against a hand-written list, so
	// this holds for any future table.
	//
	// FAILS IF: `LlvmPrerequisite` is implemented as "turn everything on" (it would flip the OFF
	// routes too, silently enabling lowering nobody asked for); or as a no-op (the diff is empty,
	// which is the pre-T5f state and the T5e artifact); or the substrate row's kind is edited to
	// Route/Diagnostic (also an empty diff).
	{
		config::rvv_vector_ssa = false;
		config::rvv_qcg_typed_chunk_sub = true;
		config::rvv_qcg_typed_chunk_mul = false;
		config::aot_loop_entry = false;
		char s_inh[kRvvRouteArgMax][64], s_llvm[kRvvRouteArgMax][64];
		char const *inh[kRvvRouteArgMax];
		char const *llvm[kRvvRouteArgMax];
		size_t n_i = RvvRouteArgv(s_inh, inh, RvvChildSubstrate::InheritParent);
		size_t n_l = RvvRouteArgv(s_llvm, llvm, RvvChildSubstrate::LlvmPrerequisite);
		CHECK(n_i == n_l && n_i > 0, "both renderings have the same number of rows");
		int diffs = 0;
		std::string which;
		for (size_t i = 0; i < n_i && i < n_l; ++i)
			if (strcmp(inh[i], llvm[i]) != 0) {
				diffs++;
				which = inh[i];
			}
		CHECK(diffs == 1, "exactly ONE row differs between the two renderings");
		CHECK(which == "--rvv-vector-ssa=0", "...and it is the substrate row, at the parent's 0");
		// The OFF policy rows are identical under both, which is what "not a global enable" means.
		CHECK(std::string(inh[IndexOfRendered(inh, n_i, "--rvv-qcg-typed-chunk-mul")]) ==
			  std::string(llvm[IndexOfRendered(llvm, n_l, "--rvv-qcg-typed-chunk-mul")]),
		      "an OFF route is rendered identically under both: this is not a global enable");
		// And the site every OTHER builder uses is byte-identical to its pre-T5f rendering: the
		// parent's live value, off included. T5f changed one call site, not the contract's meaning
		// for the P1 and escalation builders.
		bool inherit_is_parents = true;
		for (size_t i = 0; i < n_i; ++i)
			if (strcmp(inh[i], "--rvv-vector-ssa=0") == 0 && config::rvv_vector_ssa)
				inherit_is_parents = false;
		CHECK(inherit_is_parents && std::string(inh[0]) == "--rvv-vector-ssa=0",
		      "InheritParent still renders the parent's live value: other builders are unchanged");
	}

	// -------------------------------------------------------------------------------------
	SECTION("9. a bad pin is fatal to the child, not to the guest");
	// FAILS IF: SpawnBuilder accepts a caller that did not decide a CPU. The abstain decision lives
	// in Service(); this is the second gate, so a future caller cannot start an unpinned builder.
	CHECK(SpawnBuilder(-1, "/bin/echo", "/dev/null", "/tmp", "/tmp/x", "y.so", 1) == -1,
	      "cpu=-1 is refused before any fork");

	// -------------------------------------------------------------------------------------
	SECTION("10. the request rides T5d0's service word");
	// FAILS IF: the loop tier is given a bit an existing consumer also clears (it would swallow the
	// opportunity), or a bit outside the word the safepoint tests (the emitted `cmp [word],0` would
	// then never see it and a direct-branch loop would never come back).
	{
		u32 mine = config::kSvcLoopTier;
		u32 others = config::kSvcInrunPoll | config::kSvcInrunBootPending | config::kSvcInrunEscalate |
			     config::kSvcSatSweep | config::kSvcP1Scan | config::kSvcWebRepack;
		CHECK((mine & others) == 0, "kSvcLoopTier collides with no existing request");
		CHECK(__builtin_popcount(mine) == 1, "it is exactly one bit");
		config::service_request.store(0, std::memory_order_relaxed);
		CHECK(!config::AnyServiceRequestPending(), "the word starts clear");
		config::loop_tier_due = true;
		CHECK(config::AnyServiceRequestPending(),
		      "setting it makes the word nonzero -- what the backedge safepoint tests");
		CHECK((bool)config::loop_tier_due, "and the flag reads back set");
		config::loop_tier_due = false;
		CHECK(!config::AnyServiceRequestPending(), "clearing it leaves the word clear");
		// Independence, both ways: neither consumer may clear the other's request.
		config::inrun_poll_due = true;
		config::loop_tier_due = true;
		config::inrun_poll_due = false;
		CHECK((bool)config::loop_tier_due, "another consumer clearing its bit leaves ours set");
		config::loop_tier_due = false;
		config::inrun_poll_due = true;
		config::loop_tier_due = true;
		config::loop_tier_due = false;
		CHECK((bool)config::inrun_poll_due, "and ours leaves theirs set");
		config::inrun_poll_due = false;
	}

	// -------------------------------------------------------------------------------------
	SECTION("11. the consumer's half of the protocol: the mailbox is always drained");
	// The generated code fills a one-slot mailbox and the consumer empties it. Both halves are
	// needed for the same property: a notification is delivered ONCE and never overwritten. This
	// section drives the real Service().
	//
	// FAILS IF: the drain is dropped, or moved below the state dispatch (a terminal or building
	// service would then leave a stale target in the slot, and the run's `mailbox=` evidence --
	// "nothing refilled the slot after the last service" -- would be meaningless), or if
	// `last_taken_ip` is not latched (the summary would name whatever arrived last instead of what
	// the consumer acted on).
	{
		config::loop_tier = true;
		config::loop_tier_event_ip = 0x11890;
		config::loop_tier_last_taken_ip = 0;
		config::loop_tier_state = (int)State::PUBLISHED; // terminal: nothing else may happen
		unsigned long ev0 = config::loop_tier_events, rj0 = config::loop_tier_rejected;
		Service();
		CHECK(config::loop_tier_event_ip == 0, "a terminal service still empties the mailbox");
		CHECK(config::loop_tier_last_taken_ip == 0x11890, "...and latches what it took");
		CHECK(config::loop_tier_events == ev0 && config::loop_tier_rejected == rj0,
		      "...and counts nothing: a terminal tier takes no notification");
		CHECK(config::loop_tier_state == (int)State::PUBLISHED, "...and moves no state");

		// ARMED, with no profile mapped: the selector refuses the graph, so this is the REJECT
		// path -- the one that must leave the tier ARMED and the slot free for another target.
		config::loop_tier_event_ip = 0x11838;
		config::loop_tier_state = (int)State::ARMED;
		Service();
		CHECK(config::loop_tier_event_ip == 0, "an ARMED service empties the mailbox too");
		CHECK(config::loop_tier_last_taken_ip == 0x11838, "...and latches that target");
		CHECK(config::loop_tier_events == ev0 + 1, "...and counts the notification it took");
		CHECK(config::loop_tier_rejected == rj0 + 1, "...which was refused, having no selected header");
		CHECK(config::loop_tier_state == (int)State::ARMED,
		      "a rejection leaves the tier ARMED: the build is not spent by a refusal");
		config::loop_tier = false;
		config::loop_tier_event_ip = 0;
		config::loop_tier_state = (int)State::OFF;
	}

	// -------------------------------------------------------------------------------------
	SECTION("12. the CLI/arming contract: a requested mechanism whose producer is off must refuse");
	// T5d2a3. `--loop-tier-side-exit` is a property of the loop tier's own notification path -- the
	// exit block is emitted only inside QEmit::Emit_Cache's `loop_tier` block -- so with the tier
	// off the switch has no effect at all. Before this section existed, `Arm()` returned true from
	// its `if (!loop_tier)` line before ever looking at the switch, so such a run completed
	// normally and printed `LOOPTIER_SIDEEXIT on=1 sites=0 exits=0`: a requested mechanism whose
	// producer was disabled looked exactly like a workload that never got hot.
	//
	// This section drives the REAL Arm(), and reads the REAL stderr line it writes, for all three
	// cases. It is not a source check: a grep could not tell the difference between the gate being
	// present and the gate being unreachable, which is precisely what the defect was.
	//
	// FAILS IF: the prerequisite is removed; or moved BELOW the `if (!loop_tier) return true` line,
	// which makes it unreachable and is the exact original defect; or if it fires on a run that
	// asked for both (12c), or on an ordinary run that asked for neither (12a).
	{
		// Capture what Arm() writes, so "emits nothing" and "refuses with THIS reason" are both
		// measured rather than inferred from the return value.
		auto arm_capture = [](std::string *out) {
			fflush(stderr);
			FILE *tmp = tmpfile();
			int saved = dup(STDERR_FILENO);
			dup2(fileno(tmp), STDERR_FILENO);
			bool rc = Arm();
			fflush(stderr);
			dup2(saved, STDERR_FILENO);
			close(saved);
			rewind(tmp);
			char buf[1024];
			size_t n = fread(buf, 1, sizeof buf - 1, tmp);
			buf[n] = 0;
			fclose(tmp);
			*out = buf;
			return rc;
		};
		int const tier0 = config::loop_tier_state;
		bool const se0 = config::loop_tier_side_exit;
		bool const lt0 = config::loop_tier;
		std::string said;

		// 12a. THE ORDINARY RUN. Neither switch: Arm() succeeds and says nothing at all, which is
		// what keeps every unrelated run in the tree identical to what it was.
		config::loop_tier = false;
		config::loop_tier_side_exit = false;
		bool ok = arm_capture(&said);
		CHECK(ok, "both switches off: Arm() succeeds");
		CHECK(said.empty(), "...and emits nothing at all");

		// 12b. THE DEFECT. The exit switch alone must REFUSE, by name.
		config::loop_tier = false;
		config::loop_tier_side_exit = true;
		ok = arm_capture(&said);
		CHECK(!ok, "the exit switch WITHOUT --loop-tier: Arm() refuses");
		CHECK(said.find("ARM_REFUSED reason=side_exit_requires_loop_tier") != std::string::npos,
		      "...naming the missing prerequisite exactly");

		// 12c. THE VALID COMBINATION IS NOT SWALLOWED. With both switches set, control must pass
		// the new gate and run the WHOLE existing prerequisite chain. This process has no profile
		// mapped (objprof::HasProfile() is false in a test binary), so the run stops at the last
		// precondition a unit test cannot construct -- and the reason must be THAT one, not the new
		// gate. Everything before it is satisfied here with real files, so the chain is genuinely
		// traversed rather than short-circuited early.
		char tmpl[] = "/tmp/rvdbt_lt_arm_XXXXXX";
		char const *stage = mkdtemp(tmpl);
		CHECK(stage != nullptr, "a writable staging directory for the valid-combination case");
		std::string self = "/proc/self/exe"; // exists and is executable: a real --loop-tier-elfaot
		config::loop_tier = true;
		config::loop_tier_side_exit = true;
		config::loop_tier_elfaot = self.c_str();
		config::loop_tier_elf = self.c_str();
		config::loop_tier_stage = stage;
		config::qcg_backedge_safepoint = true;
		config::trace = false;
		config::rvv_vector_ssa = false;
		config::not_freq = false;
		config::use_aot = false;
		config::qcg_freq_entry = config::qcg_freq_scratch = config::qcg_freq_edge = false;
		config::qcg_freq_sat = config::qcg_freq_retire = false;
		config::inrun_tier = config::p1_promote = config::wmax_sample = false;
		config::sr_edges_epochs = config::sr_web_repack = config::inrun_auto_escalate = false;
		config::service_request.store(0, std::memory_order_relaxed);
		config::loop_tier_event_ip = 0;
		ok = arm_capture(&said);
		CHECK(!ok && said.find("reason=no_profile_mapping") != std::string::npos,
		      "--loop-tier AND the exit switch: the chain runs to its LAST precondition");
		CHECK(said.find("side_exit_requires_loop_tier") == std::string::npos,
		      "...and the new gate does NOT fire on the valid combination");
		// The remaining step -- that this same combination then reaches ARMED and publishes -- is
		// not constructible here (it needs a mapped 64 MiB profile and a booted guest ELF) and is
		// not asserted here: the frozen-GEMM cells `lt_v512`/`lt_v1024` are that evidence, and
		// t5d2a3_verify.py requires their ARMED->...->PUBLISHED chain.
		if (stage)
			rmdir(stage);
		config::loop_tier_elfaot = config::loop_tier_elf = config::loop_tier_stage = nullptr;
		config::qcg_backedge_safepoint = false;
		config::loop_tier = lt0;
		config::loop_tier_side_exit = se0;
		config::loop_tier_state = tier0;
	}

	// -------------------------------------------------------------------------------------
	SECTION("13. T5d2b0: a real child's termination wakes the parent, and Service() reaps it");
	// The gap this closes: after T5d2a3 the tier sits in BUILDING with the guest inside the same
	// pure-compute region. The notification is spent by design, a second hotness event is
	// deliberately impossible, and nothing else was telling the parent the builder had finished.
	//
	// Every case below uses the REAL install, the REAL handler (driven by a REAL child exiting),
	// the REAL exchange and the REAL waitpid -- not a re-implementation. What is NOT here is any
	// notion of elapsed time: the test never sleeps for a fixed period as the mechanism, it waits
	// for the flag the kernel's own SIGCHLD set (with a bounded fail-safe so a broken build cannot
	// hang the suite).
	//
	// FAILS IF: the handler is not installed; the handler does not raise the service bit; the
	// exchange does not clear exactly once; the reap is not WNOHANG on the recorded pid; a failed
	// builder is reported as PUBLISHED; the disposition is not restored; or a terminal/off tier
	// still does completion work.
	{
		auto spawn_child = [](int code, char const *touch) {
			pid_t p = fork();
			if (p == 0) {
				if (touch) {
					int fd = open(touch, O_CREAT | O_WRONLY | O_TRUNC, 0644);
					if (fd >= 0) {
						(void)!write(fd, "x", 1);
						close(fd);
					}
				}
				_exit(code);
			}
			return p;
		};
		// Wait for the HANDLER, not for a duration: poll the flag the kernel set, with a bounded
		// fail-safe so a broken build fails the check instead of hanging the suite.
		auto await_flag = []() {
			for (int i = 0; i < 20000; ++i) {
				if (config::loop_tier_child_exited.load(std::memory_order_relaxed))
					return true;
				usleep(200);
			}
			return false;
		};
		char tmpl[] = "/tmp/rvdbt_lt_completion_XXXXXX";
		char const *stage = mkdtemp(tmpl);
		CHECK(stage != nullptr, "a staging directory for the completion cases");
		config::loop_tier_stage = stage;
		config::vlen_bits = 0;
		SetPublishPath(); // the same name Arm() would have established
		std::string pub = PublishPath();

		// 13a. THE NOTIFICATION ITSELF. Install, let a real child exit, and require the handler to
		// have raised EXACTLY the loop tier's own bit and recorded the reason.
		config::service_request.store(0, std::memory_order_relaxed);
		config::loop_tier_child_exited.store(0, std::memory_order_relaxed);
		bool installed = InstallCompletionNotification();
		CHECK(installed, "the completion notification installs on a free SIGCHLD");
		pid_t c1 = spawn_child(0, nullptr);
		CHECK(c1 > 0, "a real child was forked");
		bool woke = await_flag();
		CHECK(woke, "its TERMINATION raised the completion flag -- no timer, no poll of a directory");
		CHECK(config::service_request.load(std::memory_order_relaxed) == config::kSvcLoopTier,
		      "...and raised EXACTLY the loop tier's service bit, no other");
		CHECK((bool)config::loop_tier_due, "...which is the bit Execute() already consumes");
		// 13b. SIGCHLD IS NOT TAKEN TWICE.
		CHECK(!InstallCompletionNotification(),
		      "a SIGCHLD already owned is refused, not taken over");
		CHECK(CompletionNotificationHeld(), "...and the tier still holds the one it installed");

		// 13c. THE CONSUMER. Service() must clear the completion exactly once, reap ONLY the
		// recorded pid with WNOHANG, and reach PUBLISHED for a real published artifact.
		{
			int fd = open(pub.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (fd >= 0) {
				(void)!write(fd, "SO", 2);
				close(fd);
			}
		}
		config::loop_tier = true;
		config::loop_tier_pid = (int)c1;
		config::loop_tier_state = (int)State::BUILDING;
		config::loop_tier_build_rc = -1;
		unsigned long w0 = config::loop_tier_completion_wakeups;
		Service();
		CHECK(config::loop_tier_completion_wakeups == w0 + 1,
		      "Service() consumed the completion exactly once");
		CHECK(config::loop_tier_child_exited.load(std::memory_order_relaxed) == 0,
		      "...and cleared it");
		CHECK(config::loop_tier_build_rc == 0, "...reaped the recorded pid and read its status");
		CHECK(waitpid(c1, nullptr, WNOHANG) < 0,
		      "...so the child is collected: a second wait finds no such child");
		CHECK(config::loop_tier_state == (int)State::PUBLISHED,
		      "...and a real published artifact reaches PUBLISHED, during the run");
		// T5d2b0 fix: the window closes with the reap, NOT at guest exit.
		CHECK(!CompletionNotificationHeld(),
		      "...and SIGCHLD is given back IMMEDIATELY, not at guest exit");
		CHECK(config::loop_tier_publish_seen_in_run,
		      "...observed IN RUN, which before this checkpoint was false by construction");
		// 13d. A SECOND SERVICE DOES NOTHING. The completion is spent, and the tier is terminal.
		unsigned long w1 = config::loop_tier_completion_wakeups;
		int st1 = config::loop_tier_state;
		Service();
		CHECK(config::loop_tier_completion_wakeups == w1 && config::loop_tier_state == st1,
		      "a second service with no completion pending does nothing at all");

		// 13e. A FAILED BUILDER. Same path, non-zero exit and no artifact -> FAILED, not PUBLISHED.
		unlink(pub.c_str());
		config::service_request.store(0, std::memory_order_relaxed);
		config::loop_tier_child_exited.store(0, std::memory_order_relaxed);
		CHECK(InstallCompletionNotification(),
		      "the window is re-opened for the next build, as DoSpawn does before each fork");
		pid_t c2 = spawn_child(3, nullptr);
		CHECK(c2 > 0 && await_flag(), "a FAILING builder's termination also raises the completion");
		config::loop_tier_pid = (int)c2;
		config::loop_tier_state = (int)State::BUILDING;
		config::loop_tier_build_rc = -1;
		Service();
		CHECK(config::loop_tier_build_rc == 3, "...its non-zero status is read, not assumed");
		CHECK(config::loop_tier_state == (int)State::FAILED,
		      "...and the tier reaches FAILED, not PUBLISHED");
		CHECK(!CompletionNotificationHeld(),
		      "...and a FAILED disposition gives SIGCHLD back just as immediately");

		// 13f. A COMPLETION FOR SOMEBODY ELSE'S CHILD LEAVES OURS ALONE. WNOHANG on the recorded
		// pid is what makes this true: the reap must not collect an unrelated child, and must not
		// block waiting for one that is still running.
		config::loop_tier_child_exited.store(0, std::memory_order_relaxed);
		CHECK(InstallCompletionNotification(), "the window is open again for the WNOHANG case");
		pid_t slow = fork();
		if (slow == 0) {
			usleep(600000);
			_exit(0);
		}
		// A DECOY: a second child that has already terminated and is sitting as a zombie. It is not
		// the recorded builder, so the reap must not collect it and must not report its status as
		// the build's. `waitpid(-1, ...)` would do exactly that, which is why the decoy exists.
		pid_t decoy = spawn_child(7, nullptr);
		CHECK(decoy > 0 && await_flag(), "a decoy child, not the builder, has terminated");
		config::loop_tier_pid = (int)slow;
		config::loop_tier_state = (int)State::BUILDING;
		config::loop_tier_build_rc = -1;
		config::loop_tier_child_exited.store(1, std::memory_order_relaxed);
		Service();
		CHECK(config::loop_tier_state == (int)State::BUILDING,
		      "a completion whose child is still running leaves the tier BUILDING (WNOHANG)");
		CHECK(config::loop_tier_build_rc == -1, "...and reads no status");
		CHECK(waitpid(decoy, nullptr, WNOHANG) == decoy,
		      "...and the decoy is STILL collectable: only the recorded pid was waited on");
		kill(slow, SIGKILL);
		waitpid(slow, nullptr, 0);
		// This test collected the child itself instead of letting DoReap do it, so it closes the
		// window itself too -- that is the step DoReap performs the instant the exact builder is
		// consumed, and leaving it open here would be the very defect 13i measures.
		RestoreCompletionNotification();
		CHECK(!CompletionNotificationHeld(), "...and the window closes with the builder");

		// 13g. MODE OFF HANDLES NOTHING. Service() returns before any completion work.
		config::loop_tier_child_exited.store(1, std::memory_order_relaxed);
		unsigned long w2 = config::loop_tier_completion_wakeups;
		config::loop_tier = false;
		Service();
		CHECK(config::loop_tier_completion_wakeups == w2,
		      "mode off: a pending completion is not consumed and nothing is reported");
		CHECK(config::loop_tier_child_exited.load(std::memory_order_relaxed) == 1,
		      "...and the flag is left exactly as it was");
		config::loop_tier_child_exited.store(0, std::memory_order_relaxed);

		// 13i. THE REVIEWER-FOUND DEFECT: AN UNRELATED CHILD AFTER THE BUILDER IS GONE.
		//
		// SIGCHLD is process-wide. The first version held it from Arm() to ReportAtExit(), so once
		// the exact builder had been reaped and the tier was terminal, ANY other host child's exit
		// still set this tier's completion reason and service bit -- and the emitted poll did not
		// require a build to be outstanding, so a terminal tier could take a side exit for a
		// completion that could not exist. Measured before the fix, not deduced.
		//
		// The fix is two-sided: ownership now ends the instant the exact builder is consumed
		// (below), and the emitted poll tests `state == BUILDING` (loop_tier_side_exit_test 7e).
		{
			config::service_request.store(0, std::memory_order_relaxed);
			config::loop_tier_child_exited.store(0, std::memory_order_relaxed);
			CHECK(!CompletionNotificationHeld(),
			      "after the exact builder was reaped the tier no longer holds SIGCHLD");
			// A real, unrelated host child -- the thing the old code could not tell apart.
			pid_t other = spawn_child(0, nullptr);
			CHECK(other > 0, "an unrelated host child is forked");
			int ost = 0;
			CHECK(waitpid(other, &ost, 0) == other,
			      "...and the process can still collect it itself: the default disposition is back");
			CHECK(config::loop_tier_child_exited.load(std::memory_order_relaxed) == 0,
			      "...its exit set NO loop-tier completion reason");
			CHECK(config::service_request.load(std::memory_order_relaxed) == 0,
			      "...and raised NO service request");
			// And a service in that state does no completion work.
			unsigned long wU = config::loop_tier_completion_wakeups;
			config::loop_tier_state = (int)State::PUBLISHED;
			Service();
			CHECK(config::loop_tier_completion_wakeups == wU,
			      "...so a service consumes no completion");
		}

		// 13j. SIG_IGN AND SA_NOCLDWAIT ARE REFUSED, NOT ADOPTED. Both let the kernel auto-reap
		// children, which would make the exact waitpid return ECHILD and lose the build's status --
		// measured against the old code, which accepted SIG_IGN and then could not collect its own
		// builder. Every case here saves and restores the process's real disposition.
		{
			struct sigaction saved {};
			CHECK(sigaction(SIGCHLD, nullptr, &saved) == 0, "the process's own SIGCHLD is saved");
			char const *why = "";
			CHECK(CompletionDispositionAcceptable(&why),
			      "SIG_DFL without SA_NOCLDWAIT is acceptable");

			struct sigaction ign {};
			ign.sa_handler = SIG_IGN;
			sigemptyset(&ign.sa_mask);
			sigaction(SIGCHLD, &ign, nullptr);
			why = "";
			CHECK(!CompletionDispositionAcceptable(&why) &&
				  std::string(why) == "sigchld_ignored_autoreaps",
			      "an explicit SIG_IGN is REFUSED, by name");
			CHECK(!InstallCompletionNotification() && !CompletionNotificationHeld(),
			      "...and the install refuses too, taking nothing");

			struct sigaction ncw {};
			ncw.sa_handler = SIG_DFL;
			sigemptyset(&ncw.sa_mask);
			ncw.sa_flags = SA_NOCLDWAIT;
			sigaction(SIGCHLD, &ncw, nullptr);
			why = "";
			CHECK(!CompletionDispositionAcceptable(&why) &&
				  std::string(why) == "sigchld_nocldwait_autoreaps",
			      "SA_NOCLDWAIT is REFUSED, by name");
			CHECK(!InstallCompletionNotification() && !CompletionNotificationHeld(),
			      "...and the install refuses too");

			struct sigaction other {};
			other.sa_handler = SIG_DFL;
			sigemptyset(&other.sa_mask);
			sigaction(SIGCHLD, &other, nullptr);
			// A foreign HANDLER is a different refusal with its own reason.
			struct sigaction foreign {};
			foreign.sa_handler = [](int) {};
			sigemptyset(&foreign.sa_mask);
			sigaction(SIGCHLD, &foreign, nullptr);
			why = "";
			CHECK(!CompletionDispositionAcceptable(&why) &&
				  std::string(why) == "sigchld_already_owned",
			      "a foreign handler is REFUSED, by its own name");

			CHECK(sigaction(SIGCHLD, &saved, nullptr) == 0,
			      "the process's own SIGCHLD disposition is restored by this section");
			struct sigaction back {};
			sigaction(SIGCHLD, nullptr, &back);
			CHECK(back.sa_handler == saved.sa_handler && back.sa_flags == saved.sa_flags,
			      "...and reads back exactly as it was");
		}

		// 13h. THE DISPOSITION IS PUT BACK, AND BY THE CALL SITE THE RUN USES. ReportAtExit is
		// where the process hands SIGCHLD back; driving the function directly would pass even if
		// nothing ever called it. The tier is terminal here, so ReportAtExit reaps nothing and
		// only reports.
		config::loop_tier = true;
		config::loop_tier_state = (int)State::PUBLISHED;
		config::loop_tier_pid = 0;
		ReportAtExit();
		config::service_request.store(0, std::memory_order_relaxed);
		pid_t c3 = spawn_child(0, nullptr);
		if (c3 > 0)
			waitpid(c3, nullptr, 0);
		CHECK(config::loop_tier_child_exited.load(std::memory_order_relaxed) == 0 &&
			  config::service_request.load(std::memory_order_relaxed) == 0,
		      "after the restore a child's exit raises nothing: the disposition is the process's own");

		if (stage) {
			unlink(pub.c_str());
			rmdir(stage);
		}
		config::loop_tier_stage = nullptr;
		config::loop_tier_pid = 0;
		config::loop_tier_state = (int)State::OFF;
		config::loop_tier_build_rc = -1;
		config::loop_tier_publish_seen_in_run = false;
		config::service_request.store(0, std::memory_order_relaxed);
	}

	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_fail);
	printf("%s\n", g_fail == 0 ? "LOOPTIER_TEST PASS" : "LOOPTIER_TEST FAIL");
	return g_fail == 0 ? 0 : 1;
}
