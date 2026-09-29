// T5d2b2 focused test: INSTALL THE EXACT HEADER, and let Execute()'s own lookup do the rest.
//
// WHAT IS BEING CLAIMED, in three parts, and this file drives all three:
//
//   (a) the ONE table entry naming this run's spawn header -- and no other symbol the artifact
//       carries -- replaces that exact guest ip in the translation cache;
//   (b) that replacement is enough for `Execute()`'s existing sequence to ENTER the artifact:
//       `tcache::Lookup(state->ip)` returns the installed block and the escape's own `BranchSlot`
//       is linked to the artifact's host entry. This file runs that exact sequence, with the real
//       lookup and the real `BranchSlot::Link`, and decodes the bytes the link wrote;
//   (c) C5d: the promotion is COMPLETE for that one ip -- the already-linked predecessor is
//       repointed at the artifact and both L1 dispatch arrays resolve the header to it. Until C5d
//       this line read "nothing global happens", which was T5d2b2's contract and is the partial
//       promotion T5g measured (35 of 40 trials entered the artifact exactly once). Scope is still
//       ONE guest ip: (a) is what checks that, and it is unchanged.
//
// (b) IS WHY THE L1 BLOCK CACHE IS PRE-WARMED IN EVERY SUCCESS CASE. `tcache::Lookup` consults
// `l1_cache[l1hash(ip)]` FIRST and returns it on a tag match. An installer that wrote only
// `tcache_map` would leave the stale QCG block in that array, the lookup would return it, and the
// run would link the escape back into QCG while every state word said INSTALLED -- an install that
// loads and never executes. So the header always has a QCG block that has ALREADY been looked up
// before the install, which is the state a real hot header is in.
//
// (c) IS MEASURED, NOT ASSERTED. A real `BranchSlot` is linked to the OLD QCG code and registered in
// the link index for the header before the install; its bytes are captured, and after the install
// they must have CHANGED and must now name the artifact's own entry. The header's own slot in each
// L1 array is read by index rather than by occupancy count, so a rise caused by an unrelated ip
// cannot make the check pass for the wrong reason, and the link-index SIZE must be unchanged --
// slots are repointed, never unlinked or added.
//
// THE ARTIFACTS ARE REAL, linked by the host toolchain in two passes for the reason
// loop_tier_load_test gives: a real artifact carries the RESOLVED `_x<gip>` addresses on disk, and
// the file-side reader the loader reuses checks exactly that. The spawn header is deliberately NOT
// the first table entry, so an installer that took entry 0 rather than the one whose gip matches is
// caught here rather than by inspection.
//
// WHAT IT DELIBERATELY DOES NOT DO. It executes no artifact code (the fixtures' `_x` symbols are a
// bare `ret`, and nothing here calls them), times nothing, and claims no speedup. Whether the
// installed code RAN is a question about a real run and is answered there by the artifact's own
// region-entry counter, not by this file.

#include "dbt/aot/aot.h"
#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/tcache/tcache.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <dlfcn.h>
#include <unistd.h>
}

using namespace dbt;
using namespace dbt::looptier;

static int g_checks = 0, g_fail = 0;
static void CHECK(bool ok, char const *what)
{
	g_checks++;
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		g_fail++;
}
static void CHECKF(bool ok, char const *fmt, ...) __attribute__((format(printf, 2, 3)));
static void CHECKF(bool ok, char const *fmt, ...)
{
	char b[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	CHECK(ok, b);
}
static void SECTION(char const *s)
{
	printf("\n== %s ==\n", s);
}

// ==============================================================================================
// A REAL artifact: `_aot_tab` with the resolved addresses on disk, the ABI and VLEN symbols this
// process's gate demands, and a defined `_x<gip>` per entry. Two passes, exactly as
// loop_tier_load_test builds them and for the same reason -- `.quad _xNNNN` leaves 0 plus a
// relocation in the section, while a real artifact carries the linked value.
static void EmitAsm(FILE *f, std::vector<u32> const &gips, u64 abi, u64 vlen,
		    std::vector<u64> const *resolved)
{
	fprintf(f, "\t.text\n");
	for (u32 g : gips)
		fprintf(f, "\t.globl _x%x\n\t.type _x%x,@function\n_x%x:\n\tret\n\t.size _x%x,.-_x%x\n", g, g,
			g, g, g);
	fprintf(f, "\t.data\n\t.globl _aot_cpustate_abi\n\t.align 8\n_aot_cpustate_abi:\n\t.quad %llu\n",
		(unsigned long long)abi);
	fprintf(f, "\t.data\n\t.globl _aot_rvv_vlen_bits\n\t.align 8\n_aot_rvv_vlen_bits:\n\t.quad %llu\n",
		(unsigned long long)vlen);
	fprintf(f, "\t.section .aottab,\"a\",@progbits\n\t.align 16\n\t.globl _aot_tab\n_aot_tab:\n");
	fprintf(f, "\t.quad %zu\n", gips.size());
	for (size_t k = 0; k < gips.size(); ++k) {
		fprintf(f, "\t.long 0x%x\n\t.zero 4\n", gips[k]);
		if (resolved)
			fprintf(f, "\t.quad 0x%llx\n", (unsigned long long)(*resolved)[k]);
		else
			fprintf(f, "\t.quad _x%x\n", gips[k]);
		fprintf(f, "\t.long 0\n\t.zero 4\n");
	}
}

static bool BuildRealSo(std::string const &path, std::vector<u32> const &gips, u64 abi, u64 vlen)
{
	std::string asmsrc = path + ".S";
	auto link = [&](std::vector<u64> const *resolved) {
		FILE *f = fopen(asmsrc.c_str(), "w");
		if (!f)
			return false;
		EmitAsm(f, gips, abi, vlen, resolved);
		fclose(f);
		char cmd[2048];
		snprintf(cmd, sizeof cmd, "cc -shared -fPIC -nostdlib -o '%s' '%s' 2>/dev/null", path.c_str(),
			 asmsrc.c_str());
		return system(cmd) == 0 && access(path.c_str(), R_OK) == 0;
	};
	if (!link(nullptr))
		return false;
	std::vector<u64> vals(gips.size(), 0);
	for (size_t k = 0; k < gips.size(); ++k) {
		char cmd[512], nm[64];
		AotSymbolName(gips[k], nm, sizeof nm);
		snprintf(cmd, sizeof cmd,
			 "nm -f posix --defined-only '%s' 2>/dev/null | awk '$1==\"%s\"{print $3}'", path.c_str(),
			 nm);
		FILE *pp = popen(cmd, "r");
		if (!pp)
			return false;
		char out[64] = {0};
		bool got = fgets(out, sizeof out, pp) != nullptr;
		pclose(pp);
		if (!got)
			return false;
		vals[k] = strtoull(out, nullptr, 16);
		if (vals[k] == 0)
			return false;
	}
	unlink(path.c_str());
	bool ok = link(&vals);
	unlink(asmsrc.c_str());
	return ok;
}

// ==============================================================================================
// The observable state an install must and must not move, all from APIs that already exist.
struct Census {
	unsigned long qcg_bytes, qcg_tbs_bytes, aot_tbs_bytes;
	unsigned long tier[4];
	size_t l1_exec_nonempty, l1_brind_nonempty, links;
	bool operator==(Census const &o) const
	{
		return qcg_bytes == o.qcg_bytes && qcg_tbs_bytes == o.qcg_tbs_bytes &&
		       aot_tbs_bytes == o.aot_tbs_bytes && tier[0] == o.tier[0] && tier[1] == o.tier[1] &&
		       tier[2] == o.tier[2] && tier[3] == o.tier[3] &&
		       l1_exec_nonempty == o.l1_exec_nonempty && l1_brind_nonempty == o.l1_brind_nonempty &&
		       links == o.links;
	}
};

static Census Snapshot()
{
	Census c{};
	unsigned long bytes[3] = {0, 0, 0};
	tcache::CodeBytes(bytes);
	c.qcg_bytes = bytes[0];
	c.qcg_tbs_bytes = bytes[1];
	c.aot_tbs_bytes = bytes[2];
	tcache::TierCensus(c.tier);
	c.l1_exec_nonempty = 0;
	c.l1_brind_nonempty = 0;
	for (size_t i = 0; i < tcache::cache_tb_exec_count.size(); ++i)
		c.l1_exec_nonempty += tcache::cache_tb_exec_count[i].tb != nullptr;
	for (size_t i = 0; i < tcache::l1_brind_cache.size(); ++i)
		c.l1_brind_nonempty += tcache::l1_brind_cache[i].gip != 0;
	c.links = tcache::LinkMapSize();
	return c;
}

// A real, writable `BranchSlot`. Nothing executes it; what matters is the bytes `Link` writes.
struct SlotBuf {
	alignas(16) unsigned char raw[64];
	jitabi::ppoint::BranchSlot *slot()
	{
		return (jitabi::ppoint::BranchSlot *)raw;
	}
};

// Decode what a linked slot jumps to. `BranchSlot::Link` emits `jmp rel32` when the displacement
// fits and an absolute `mov rax, imm64; jmp rax` otherwise; both forms are read here so the check
// is about the DESTINATION rather than about which encoding happened to be chosen.
static void const *SlotTarget(SlotBuf &sb)
{
	unsigned char const *p = sb.raw;
	if (p[0] == 0xe9) {
		int32_t rel;
		memcpy(&rel, p + 1, 4);
		return (void const *)(p + 5 + rel);
	}
	if (p[0] == 0x48 && p[1] == 0xb8 && p[10] == 0xff && p[11] == 0xe0) {
		u64 imm;
		memcpy(&imm, p + 2, 8);
		return (void const *)(uptr)imm;
	}
	return nullptr;
}

// Plant a QCG block for `ip` with real code-pool bytes, and LOOK IT UP, so the L1 block cache holds
// it -- the state a hot header is actually in when the tier installs over it.
static TBlock *PlantQcg(u32 ip)
{
	auto *tb = tcache::AllocateTBlock();
	tb->ip = ip;
	tb->tcode = TBlock::TCode{tcache::AllocateCode(64, 16), 64};
	memset(tb->tcode.ptr, 0x90, 64);
	tcache::InsertOrReplace(tb);
	(void)tcache::Lookup(ip); // warm l1_cache[l1hash(ip)]
	return tb;
}

int main()
{
	printf("T5d2b2 loop-tier install test\n");
	tcache::Init();
	char t[] = "/tmp/rvdbt_t5d2b2_XXXXXX";
	char *d = mkdtemp(t);
	if (!d) {
		printf("FATAL: no temp dir\n");
		return 1;
	}
	std::string dir = d;
	config::loop_tier_stage = dir.c_str();
	config::vlen_bits = 512;
	SetPublishPath();
	std::string pub = PublishPath();

	u32 const SPAWN = 0x11890;
	u32 const OTHER_WITH_TB = 0x118c4;  // an artifact symbol that ALSO has a QCG block here
	u32 const OTHER_NO_TB = 0x11a00;    // ...and one that has no block at all
	// THE SPAWN HEADER IS DELIBERATELY NOT FIRST. An installer that took entry 0 instead of the
	// entry whose gip matches would install OTHER_WITH_TB, which §3 reads directly.
	std::vector<u32> const GIPS = {OTHER_WITH_TB, SPAWN, OTHER_NO_TB};
	u64 const ABI = rv32::CPUStateAbiSignature();

	if (!BuildRealSo(pub, GIPS, ABI, 512)) {
		printf("FATAL: the host toolchain could not build the fixture artifact\n");
		return 1;
	}

	// The loaded, validated view this checkpoint consumes. Established through the REAL loader, so
	// the install is driven by the same object a run hands it.
	char const *why = "";
	auto const *view = LoadAndValidateArtifact(pub.c_str(), SPAWN, &why);
	CHECKF(view != nullptr, "the fixture artifact LOADS and validates (`%s`)", why);
	if (!view) {
		printf("\nRESULT checks=%d failures=%d\nLOOPTIER_INSTALL_TEST FAIL\n", g_checks, g_fail);
		return 1;
	}
	// The artifact's own answer for where the spawn header's code is, derived independently of the
	// installer: `dlsym` on the very handle the view holds.
	void const *spawn_host = dlsym(view->handle, "_x11890");
	void const *other_host = dlsym(view->handle, "_x118c4");
	CHECK(spawn_host != nullptr && other_host != nullptr,
	      "and dlsym gives this test its OWN answer for both entry addresses");

	// -------------------------------------------------------------------------------------
	SECTION("1. default off: the mode is what makes the install happen at all");
	{
		config::loop_tier_install = false;
		config::loop_tier_state = (int)State::LOADED;
		Census before = Snapshot();
		char const *w = "";
		CHECK(!InstallLoadedArtifact(&w) && strcmp(w, "install_disabled") == 0,
		      "with the switch off the install refuses, by name");
		CHECK(before == Snapshot(), "...and no cache state moved");
		CHECK(InstalledBlock() == nullptr, "...and no block is recorded");
		CHECK(tcache::Lookup(SPAWN) == nullptr, "...and the header has no block at all yet");
	}

	// -------------------------------------------------------------------------------------
	SECTION("2. only a LOADED tier holding a validated view may install");
	{
		config::loop_tier_install = true;
		struct {
			State st;
			char const *name;
		} const bad[] = {{State::OFF, "OFF"},	      {State::ARMED, "ARMED"},
				 {State::BUILDING, "BUILDING"}, {State::PUBLISHED, "PUBLISHED"},
				 {State::FAILED, "FAILED"},     {State::ABSTAINED, "ABSTAINED"},
				 {State::INSTALLED, "INSTALLED"}};
		for (auto const &b : bad) {
			config::loop_tier_state = (int)b.st;
			Census before = Snapshot();
			char const *w = "";
			CHECKF(!InstallLoadedArtifact(&w) && strcmp(w, "not_loaded") == 0,
			       "state %s is refused (`%s`)", b.name, w);
			CHECK(before == Snapshot(), "   ...with no cache state moved");
			CHECK(InstalledBlock() == nullptr, "   ...and no block recorded");
		}
		// LOADED is a state; a validated view is a separate fact. A state moved by hand must not be
		// enough on its own.
		ReleaseLoadedArtifact();
		config::loop_tier_state = (int)State::LOADED;
		Census before = Snapshot();
		char const *w = "";
		CHECK(!InstallLoadedArtifact(&w) && strcmp(w, "no_validated_view") == 0,
		      "LOADED without a view is refused: the state is not the evidence");
		CHECK(before == Snapshot(), "...and no cache state moved");
		// Re-establish the view for everything below.
		char const *w2 = "";
		view = LoadAndValidateArtifact(pub.c_str(), SPAWN, &w2);
		CHECKF(view != nullptr, "the view is re-established for the success cases (`%s`)", w2);
		spawn_host = view ? dlsym(view->handle, "_x11890") : nullptr;
		other_host = view ? dlsym(view->handle, "_x118c4") : nullptr;
	}
	if (!view) {
		printf("\nRESULT checks=%d failures=%d\nLOOPTIER_INSTALL_TEST FAIL\n", g_checks, g_fail);
		return 1;
	}

	// -------------------------------------------------------------------------------------
	SECTION("3. the exact header is replaced, and nothing else is installed");
	TBlock *qcg_spawn = nullptr, *qcg_other = nullptr;
	SlotBuf pred{}; // an already-linked predecessor of the header, registered in the link index
	unsigned char pred_before[sizeof pred.raw];
	Census pre_install{};
	{
		qcg_spawn = PlantQcg(SPAWN);
		qcg_other = PlantQcg(OTHER_WITH_TB);
		CHECK(tcache::Lookup(SPAWN) == qcg_spawn,
		      "the header starts out as a QCG block that has already been looked up");
		CHECK(tcache::Lookup(OTHER_NO_TB) == nullptr,
		      "and one of the artifact's other symbols has no block at all");

		// A REAL predecessor edge into the header, linked to the QCG code and indexed. Its bytes
		// are captured here as the BEFORE picture: section 5 requires the install to have repointed
		// them at the artifact, and comparing raw bytes rather than re-deriving the target is what
		// makes that a measurement of the promotion instead of a restatement of it.
		pred.slot()->gip = SPAWN;
		pred.slot()->flags.cross_segment = false;
		pred.slot()->Link(qcg_spawn->tcode.ptr);
		tcache::RecordLink(pred.slot(), qcg_spawn, false);
		CHECK(SlotTarget(pred) == qcg_spawn->tcode.ptr,
		      "a predecessor edge is linked to the header's QCG code and indexed");
		memcpy(pred_before, pred.raw, sizeof pred.raw);

		config::loop_tier_state = (int)State::LOADED;
		config::loop_tier_install = true;
		config::loop_tier_installed_gip = 0;
		config::loop_tier_install_host = 0;
		pre_install = Snapshot();

		char const *w = "";
		CHECKF(InstallLoadedArtifact(&w), "the install succeeds (`%s`)", w);
		CHECK(strcmp(w, "ok") == 0, "...reporting `ok`");

		auto *now = tcache::Lookup(SPAWN);
		CHECK(now != nullptr && now != qcg_spawn,
		      "the header no longer resolves to its QCG block");
		CHECKF(now != nullptr && now->tcode.ptr == spawn_host,
		       "...it resolves to the ARTIFACT's own `_x11890` (%p vs %p)",
		       now ? now->tcode.ptr : nullptr, spawn_host);
		CHECK(now != nullptr && now->tcode.size == 0,
		      "...as an AOT block: the code lives in the artifact, not in this process's pool");
		CHECK(now != nullptr && now->ip == SPAWN, "...and it names the header");
		CHECK(InstalledBlock() == now, "...and the installer's own record is that block");
		// The address really belongs to the object the loader mapped -- not a file offset, not a
		// bare `aot_vaddr` that happens to be readable.
		Dl_info di{};
		CHECK(now != nullptr && dladdr(now->tcode.ptr, &di) && di.dli_fbase == (void *)view->base,
		      "...and the runtime agrees the address is inside the loaded artifact");

		// NOT THE FIRST TABLE ENTRY, AND NOT ANY OTHER ONE.
		auto *o1 = tcache::Lookup(OTHER_WITH_TB);
		CHECK(o1 == qcg_other && o1->tcode.size != 0,
		      "the artifact's FIRST table entry was NOT installed: it is still its QCG block");
		CHECK(tcache::Lookup(OTHER_NO_TB) == nullptr,
		      "and the entry that had no block still has none");

		Census after = Snapshot();
		CHECKF(after.tier[1] == 1, "exactly ONE AOT block exists in the whole cache (%lu)",
		       after.tier[1]);
		CHECKF(after.tier[0] == pre_install.tier[0] - 1,
		       "...and it REPLACED a QCG block rather than adding to them (%lu -> %lu)",
		       pre_install.tier[0], after.tier[0]);
		// C5d: BOTH L1 DISPATCH ARRAYS ARE NOW WRITTEN, AND THAT IS THE FIX RATHER THAN A
		// REGRESSION. Until C5d this asserted the opposite -- "neither L1 dispatch array was
		// written" -- which was T5d2b2's contract and is exactly the partial promotion T5g
		// measured: `l1_brind_cache` holds a RAW host pointer that the generated indirect fast path
		// jumps to without consulting any TBlock, so leaving it on the pre-promotion code is a live
		// bypass of the block this installer just put in the map. The assertions below are about
		// the header's OWN slot, not about array occupancy totals, because a count can rise for an
		// unrelated ip and would make this check pass for the wrong reason.
		{
			auto const h = tcache::l1hash(SPAWN);
			CHECKF(tcache::cache_tb_exec_count[h].gip == SPAWN &&
				   tcache::cache_tb_exec_count[h].tb == now,
			       "the exec-count cache names the header and resolves to the AOT block");
			CHECKF(tcache::l1_brind_cache[h].gip == SPAWN &&
				   tcache::l1_brind_cache[h].code == spawn_host,
			       "the indirect-dispatch cache holds the ARTIFACT's entry, not the QCG code "
			       "(%p vs %p)",
			       tcache::l1_brind_cache[h].code, spawn_host);
			CHECK(tcache::l1_brind_cache[h].code != qcg_spawn->tcode.ptr,
			      "...so no cache can still deliver control to the pre-promotion code");
		}
		CHECK(after.links == pre_install.links, "and the link index did not grow");

		CHECKF(config::loop_tier_installed_gip == SPAWN, "the run records WHICH header (%08x)",
		       config::loop_tier_installed_gip);
		CHECKF(config::loop_tier_install_host == (unsigned long long)(uptr)spawn_host,
		       "...and WHICH host entry (0x%llx)", config::loop_tier_install_host);
		CHECKF(config::loop_tier_install_qcg_tbs == pre_install.tier[0],
		       "...and the QCG census as it stood BEFORE the install (%lu)",
		       config::loop_tier_install_qcg_tbs);
		CHECKF(config::loop_tier_install_aot_hits == 0,
		       "...and that no artifact code had run yet (%llu)", config::loop_tier_install_aot_hits);
	}

	// -------------------------------------------------------------------------------------
	SECTION("4. Execute()'s own resume sequence also lands in the artifact");
	// WHAT THIS SECTION STILL CLAIMS, AND WHAT IT NO LONGER CLAIMS. Its title used to end
	// "-- no relink needed", which was T5d2b2's argument and is now false: C5d makes the
	// install repoint the header's already-linked predecessors (section 5). What survives is
	// the narrower and still-useful fact this code actually drives -- the escape's OWN slot,
	// which is created fresh by the escape and is therefore NOT in the link index, is resolved
	// correctly by `Execute()`'s ordinary lookup-and-link. That path is independent of the
	// promotion and has to keep working, because it is how the run resumes at the header in
	// the same iteration the install happened in.
	{
		// EXACTLY WHAT Execute() DOES, in its order: the escape wrote `CPUState::ip` with the edge's
		// target and handed back that edge's own slot; the loop looks the PC up and links the slot
		// to whatever it found. Run here against the REAL lookup and the REAL Link.
		u32 resumed_ip = SPAWN; // what T5d2a3's exit block / T5d0's safepoint store before escaping
		SlotBuf esc{};
		esc.slot()->gip = resumed_ip;
		esc.slot()->flags.cross_segment = false;

		TBlock *tb = tcache::Lookup(resumed_ip);
		CHECK(tb != nullptr, "the fresh lookup of the resumed PC finds a block");
		CHECK(tb != nullptr && tb->tcode.size == 0,
		      "...and it is the AOT one -- which is the whole mechanism: the install ran on the "
		      "host stack BEFORE this lookup");
		if (tb) {
			esc.slot()->Link(tb->tcode.ptr);
			CHECKF(SlotTarget(esc) == spawn_host,
			       "the escape's own BranchSlot is now linked to the artifact (%p vs %p)",
			       SlotTarget(esc), spawn_host);
		}
		CHECK(esc.slot()->gip == resumed_ip,
		      "and the slot still names the header, so Execute()'s `slot->gip == state->ip` holds");

		// THE COUNTER-CASE, so (b) is not vacuous: a stale L1 block-cache entry is exactly what an
		// installer that wrote only `tcache_map` would leave behind, and the lookup would then hand
		// Execute() the QCG block. Constructed here directly to show the check can fail.
		auto *stale = tcache::Lookup(OTHER_WITH_TB);
		SlotBuf esc2{};
		esc2.slot()->gip = OTHER_WITH_TB;
		esc2.slot()->flags.cross_segment = false;
		esc2.slot()->Link(stale->tcode.ptr);
		CHECK(SlotTarget(esc2) != spawn_host && SlotTarget(esc2) == stale->tcode.ptr,
		      "an uninstalled header links back into QCG, so the check above distinguishes them");
	}

	// -------------------------------------------------------------------------------------
	SECTION("5. the already-linked predecessor is REPOINTED at the artifact");
	// C5d INVERTS THIS SECTION, and the inversion is the checkpoint. It used to assert that the
	// predecessor's bytes were IDENTICAL across the install -- T5d2b2's stated contract, on the
	// argument that `Execute()` would link the one edge it happened to be holding. T5g measured what
	// that leaves: 35 of 40 trials entered the installed artifact exactly once, because every OTHER
	// predecessor kept its pre-promotion target. C5C then read the fan-in off a real run at the
	// instant of the install and found it non-empty with its slot still on the QCG code.
	//
	// The before-picture is captured in section 3 (`pred_before`), so this is a genuine before/after
	// on one real `BranchSlot`'s bytes and not a re-derivation.
	{
		CHECK(memcmp(pred.raw, pred_before, sizeof pred.raw) != 0,
		      "the predecessor's bytes CHANGED across the install");
		CHECKF(SlotTarget(pred) == spawn_host,
		       "...and it now jumps into the ARTIFACT's own entry (%p vs %p)", SlotTarget(pred),
		       spawn_host);
		CHECK(SlotTarget(pred) != qcg_spawn->tcode.ptr,
		      "...and no longer into the header's pre-promotion QCG code");
		CHECK(tcache::LinkMapSize() == pre_install.links,
		      "the link index is the size it was: slots were repointed, not unlinked or added");
	}

	// -------------------------------------------------------------------------------------
	SECTION("6. one install, and one AOT block for the header");
	{
		// THE ONE-SHOT IS THE PRIMITIVE'S, NOT THE CALLER'S, and this section is arranged so that
		// distinction cannot be blurred. In the real run the tier moves to INSTALLED and its state
		// machine has no path back, so a second call would be refused by `not_loaded` even if the
		// primitive had no one-shot at all -- which would make a passing test here evidence about
		// the CALLER's structure rather than about this function. So the state is deliberately left
		// at LOADED, checked to still be LOADED immediately before the second call, and the refusal
		// must therefore be `already_installed` and nothing else.
		CHECKF(config::loop_tier_state == (int)State::LOADED,
		       "the tier is still LOADED, so the second call is refused by the PRIMITIVE and not by "
		       "its caller's state (state=%d)",
		       config::loop_tier_state);
		Census before = Snapshot();
		auto const *first = InstalledBlock();
		auto const *tb_before = tcache::Lookup(SPAWN);
		char const *w = "";
		CHECK(!InstallLoadedArtifact(&w) && strcmp(w, "already_installed") == 0,
		      "a second install is refused: the one-shot is a property of the primitive");
		CHECK(before == Snapshot(), "...and no cache state moved");
		CHECK(InstalledBlock() == first, "...and the recorded block is still the first one");
		CHECK(tcache::Lookup(SPAWN) == tb_before,
		      "...and the header still resolves to the very same block: no second AllocateTBlock, "
		      "no second replace");
		// ...and a THIRD call, still at LOADED, is refused the same way. One call could be refused
		// by an accident of ordering; a repeated refusal is the one-shot.
		char const *w3 = "";
		CHECK(!InstallLoadedArtifact(&w3) && strcmp(w3, "already_installed") == 0,
		      "...and so is a third, at the same state");
		CHECK(before == Snapshot() && InstalledBlock() == first,
		      "...with the cache and the recorded block still unmoved");

		// Re-driving the primitive after a release must still leave ONE AOT block for the header:
		// the header is REPLACED, never accumulated.
		ReleaseInstalledBlock();
		CHECK(InstalledBlock() == nullptr, "after release the installer holds no block");
		config::loop_tier_state = (int)State::LOADED;
		char const *w2 = "";
		CHECKF(InstallLoadedArtifact(&w2), "the primitive can be driven again (`%s`)", w2);
		Census after = Snapshot();
		CHECKF(after.tier[1] == 1, "and the header still has exactly ONE AOT block (%lu)",
		       after.tier[1]);
		CHECK(tcache::Lookup(SPAWN) != nullptr && tcache::Lookup(SPAWN)->tcode.ptr == spawn_host,
		      "...pointing at the same artifact entry");
		// THE DISPATCH ARRAYS ARE WRITTEN AGAIN BY THE RE-DRIVE -- they are part of the
		// promotion -- so what must hold is that they still RESOLVE THE HEADER TO THE ARTIFACT,
		// not that they were left alone. Occupancy is checked too, and separately: it must be
		// unchanged because the same two hash slots are overwritten rather than new ones taken,
		// which is what distinguishes a re-promotion from an accumulating one.
		{
			auto const h = tcache::l1hash(SPAWN);
			CHECK(tcache::cache_tb_exec_count[h].gip == SPAWN &&
				  tcache::cache_tb_exec_count[h].tb == tcache::Lookup(SPAWN),
			      "...the exec-count cache still names the header's current AOT block");
			CHECKF(tcache::l1_brind_cache[h].gip == SPAWN &&
				   tcache::l1_brind_cache[h].code == spawn_host,
			       "...the indirect-dispatch cache still holds the artifact's entry (%p)",
			       tcache::l1_brind_cache[h].code);
			CHECK(after.l1_exec_nonempty == before.l1_exec_nonempty &&
				  after.l1_brind_nonempty == before.l1_brind_nonempty,
			      "...and no NEW dispatch slot was taken: the same ones were overwritten");
		}
	}

	// -------------------------------------------------------------------------------------
	SECTION("7. the install never enters anything by itself");
	{
		// The whole file has installed twice and linked two slots by hand, and no artifact code has
		// been called: the fixtures' `_x` symbols are a bare `ret` and nothing invokes them. Stated
		// as a check on the one counter that WOULD have moved, so the boundary is measured here in
		// the same terms the real run reports it.
		unsigned long long hits = 0;
		if (auto *st = CPUState::Current())
			for (unsigned i = 0; i < CPUState::REGION_HIT_SLOTS; ++i)
				hits += st->region_entry_hits[i];
		CHECKF(hits == 0, "no region-entry counter moved: installing is not executing (%llu)", hits);
	}

	ReleaseInstalledBlock();
	ReleaseLoadedArtifact();
	config::loop_tier_install = false;
	config::loop_tier_state = 0;
	unlink(pub.c_str());
	rmdir(dir.c_str());
	config::loop_tier_stage = nullptr;
	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_fail);
	printf("%s\n", g_fail == 0 ? "LOOPTIER_INSTALL_TEST PASS" : "LOOPTIER_INSTALL_TEST FAIL");
	return g_fail == 0 ? 0 : 1;
}
