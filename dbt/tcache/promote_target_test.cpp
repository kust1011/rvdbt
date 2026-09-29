// C5d focused test: `tcache::PromoteTarget` leaves NO structure able to deliver control to the
// pre-promotion code, and it does that for exactly one guest ip.
//
// WHY A TEST OF ITS OWN, separate from `loop_tier_install_test`. That file tests an INSTALLER: which
// table entry it picks, its refusals, its one-shot. This one tests the PROMOTION -- the property
// that the two mid-run promoters now share because they call the same function. Testing it through
// either caller would mean a defect in the shared wiring could be masked by that caller's setup, and
// the whole point of C5d is that there is only one copy of the wiring to get wrong.
//
// THE SHAPE OF EVERY CHECK IS BEFORE/AFTER ON REAL STRUCTURES. A `BranchSlot` is really linked and
// really decoded from its own bytes; the two L1 arrays are read at the header's own hash slot; the
// inline-cache blob is really patched through the production entry point. Nothing is re-derived from
// the function's return value, because a function that lied about what it did would then agree with
// itself.
//
// EVERY CHECK STATES THE FAILURE PATH IT IS SENSITIVE TO -- an assertion whose failure mode is not
// stated is not evidence. They are listed per section.
//
// WHAT THIS FILE DOES NOT DO: it loads no artifact, executes no generated code, times nothing, and
// makes no claim about whether a promoted block is ENTERED more often. Entry is a property of a real
// run and is answered there by the artifact's own region-entry counter.

#include "dbt/config.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/tcache/tcache.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

using namespace dbt;

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
	printf("\n== %s\n", s);
}

// A real, writable `BranchSlot`. Nothing executes it; what matters is the bytes `Link` writes and
// the bytes this file decodes back.
struct SlotBuf {
	alignas(16) unsigned char raw[64];
	jitabi::ppoint::BranchSlot *slot()
	{
		return (jitabi::ppoint::BranchSlot *)raw;
	}
};

// Decode what a linked slot jumps to. `Link` emits `jmp rel32` when the displacement fits and
// `mov rax, imm64; jmp rax` otherwise; both are read, because the question is about the DESTINATION
// and not about which encoding was chosen.
static void const *SlotTarget(SlotBuf &sb)
{
	unsigned char const *p = sb.raw;
	if (p[0] == 0xe9) {
		int32_t rel;
		memcpy(&rel, p + 1, 4);
		return (void const *)(p + 5 + rel);
	}
	if (p[0] == 0x48 && p[1] == 0xb8 && p[10] == 0xff && p[11] == 0xe0) {
		unsigned long long imm;
		memcpy(&imm, p + 2, 8);
		return (void const *)(uptr)imm;
	}
	return nullptr;
}

static TBlock *PlantQcg(u32 ip)
{
	auto *tb = tcache::AllocateTBlock();
	tb->ip = ip;
	tb->tcode = TBlock::TCode{tcache::AllocateCode(64, 16), 64};
	memset(tb->tcode.ptr, 0x90, 64);
	tcache::InsertOrReplace(tb);
	(void)tcache::Lookup(ip); // warm l1_cache: the state a hot header is really in
	return tb;
}

// An AOT block in the announce-created shape the promoters build: the code lives in an artifact, so
// `tcode.size == 0` and the pointer is outside this process's code pool.
alignas(16) static unsigned char g_artifact_a[64];
alignas(16) static unsigned char g_artifact_b[64];

static TBlock *MakeAot(u32 ip, void *host)
{
	auto *tb = tcache::AllocateTBlock();
	tb->ip = ip;
	tb->tcode = TBlock::TCode{host, 0};
	return tb;
}

int main()
{
	printf("C5d tcache::PromoteTarget focused test\n");
	tcache::Init();

	u32 const GIP = 0x11890;   // the header being promoted
	u32 const OTHER = 0x11a00; // a different ip, used to prove the scope is one
	auto const H = tcache::l1hash(GIP);
	auto const HO = tcache::l1hash(OTHER);

	auto *qcg = PlantQcg(GIP);
	auto *qcg_other = PlantQcg(OTHER);
	void const *qcg_code = qcg->tcode.ptr;
	void const *other_code = qcg_other->tcode.ptr;

	// The state a hot header is really in before a mid-run promotion: two linked predecessors in
	// the link index, both dispatch caches warm, and an inline-cache blob patched at it.
	static SlotBuf p1{}, p2{}, p_other{};
	p1.slot()->gip = GIP;
	p1.slot()->Link(qcg->tcode.ptr);
	tcache::RecordLink(p1.slot(), qcg, false);
	p2.slot()->gip = GIP;
	p2.slot()->Link(qcg->tcode.ptr);
	tcache::RecordLink(p2.slot(), qcg, false);
	p_other.slot()->gip = OTHER;
	p_other.slot()->Link(qcg_other->tcode.ptr);
	tcache::RecordLink(p_other.slot(), qcg_other, false);
	tcache::CacheBr(qcg);
	tcache::CacheBrind(qcg);
	tcache::CacheBr(qcg_other);
	tcache::CacheBrind(qcg_other);
	qcg->flags.exec_count = 4242;
	// SET EXPLICITLY ON THE OLD BLOCK, not left to `CacheBrind`'s side effect. `brind_was_target` is
	// a question about the guest ip BEFORE the promotion, and the incoming AOT block is freshly
	// allocated with the flag false -- so a promotion that read the flag off the block it is
	// installing would report false for every promotion, and a constant field is not a diagnostic.
	// Section 2 asserts the true case against this line; section 7 asserts the false case against an
	// ip that was never an indirect target, which is what makes the field falsifiable.
	qcg->flags.is_brind_target = true;

	// A patched inline-cache blob naming the header. Built through the production entry point so
	// the bytes are the ones a real site would carry: `ICTryPatch` writes the guard gip at +2, the
	// counter address at +15 and a rel32 to the target at +27.
	//
	// THE BLOB IS ALLOCATED FROM THE CODE POOL, not from this file's BSS, and that is required
	// rather than tidy: `ICTryPatch` bakes a rel32 from the blob to the target's code and REFUSES
	// the patch when the displacement does not fit in 32 bits. A static buffer in the test binary
	// is gigabytes away from the mmap'd code pool, so the patch would silently never happen and
	// section 2's unpatch check would pass against a blob that was never patched. A real IC blob
	// lives inside JIT code, which is exactly where this one now is.
	auto *blob = (unsigned char *)tcache::AllocateCode(64, 16);
	memset(blob, 0, 64);
	blob[0] = 0x81;
	blob[1] = 0xfe;
	memcpy(blob + 2, "\xff\xff\xff\xff", 4); // the never-matching sentinel: unpatched
	uptr const ic_ra = 0x1234;
	tcache::ICRegister(ic_ra, blob, GIP);
	config::qcg_dispatch_ic = true;
	tcache::ICTryPatch(ic_ra, qcg);

	unsigned char pre_p1[sizeof p1.raw], pre_p2[sizeof p2.raw], pre_other[sizeof p_other.raw];
	memcpy(pre_p1, p1.raw, sizeof pre_p1);
	memcpy(pre_p2, p2.raw, sizeof pre_p2);
	memcpy(pre_other, p_other.raw, sizeof pre_other);
	u32 ic_guard_before = 0;
	memcpy(&ic_guard_before, blob + 2, 4);
	size_t const links_before = tcache::LinkMapSize();

	// -------------------------------------------------------------------------------------
	SECTION("1. the BEFORE picture is the one a partial promotion would leave behind");
	// FAILURE PATH: if the fixture did not actually reach the pre-promotion state -- an unlinked
	// slot, a cold dispatch cache, an unpatched IC -- every "after" check below would pass for free
	// and this file would assert nothing. So the before-state is checked, not assumed.
	{
		CHECK(tcache::Lookup(GIP) == qcg, "the header resolves to its QCG block");
		CHECKF(SlotTarget(p1) == qcg_code && SlotTarget(p2) == qcg_code,
		       "both direct predecessors jump into the OLD QCG code (%p)", qcg_code);
		CHECKF(tcache::l1_brind_cache[H].gip == GIP && tcache::l1_brind_cache[H].code == qcg_code,
		       "the indirect-dispatch cache holds the OLD QCG code");
		CHECKF(tcache::cache_tb_exec_count[H].gip == GIP &&
			   tcache::cache_tb_exec_count[H].tb == qcg,
		       "the exec-count cache names the OLD QCG block");
		CHECKF(ic_guard_before == GIP,
		       "an inline-cache blob is patched AT this target (guard=%08x)", ic_guard_before);
		CHECKF(links_before >= 3, "the link index holds this header's fan-in (%zu)", links_before);
		CHECK(qcg->flags.is_brind_target,
		      "the OLD block for this ip is marked an indirect-dispatch target");
	}

	// -------------------------------------------------------------------------------------
	SECTION("2. after PromoteTarget, no structure still delivers the old QCG code");
	// THIS IS THE CHECKPOINT. Five structures, each read where the generated code or the host loop
	// actually reads it.
	// FAILURE PATH, per line: dropping `RelinkTo` leaves the slots on `qcg_code` (this is the T5g
	// bypass); dropping `CacheBrind` leaves the indirect fast path jumping at `qcg_code` without
	// ever consulting a TBlock; dropping `InsertOrReplace` leaves the map or the L1 block cache on
	// the QCG block; dropping the IC unpatch leaves a site with a baked rel32 into the old code.
	auto *aot = MakeAot(GIP, g_artifact_a);
	tcache::PromoteCounts pc{};
	{
		pc = tcache::PromoteTarget(aot);

		CHECK(tcache::Lookup(GIP) == aot, "the map and the L1 block cache resolve to the AOT block");
		CHECK(tcache::Lookup(GIP)->tcode.size == 0, "...in the announce-created AOT shape");
		CHECKF(SlotTarget(p1) == (void const *)g_artifact_a,
		       "direct predecessor 1 now jumps into the ARTIFACT (%p vs %p)", SlotTarget(p1),
		       (void const *)g_artifact_a);
		CHECKF(SlotTarget(p2) == (void const *)g_artifact_a,
		       "direct predecessor 2 now jumps into the ARTIFACT (%p)", SlotTarget(p2));
		CHECK(SlotTarget(p1) != qcg_code && SlotTarget(p2) != qcg_code,
		      "...and neither jumps into the old QCG code any more");
		CHECK(memcmp(pre_p1, p1.raw, sizeof pre_p1) != 0 &&
			  memcmp(pre_p2, p2.raw, sizeof pre_p2) != 0,
		      "...which is visible in both slots' own bytes");
		CHECKF(tcache::l1_brind_cache[H].gip == GIP &&
			   tcache::l1_brind_cache[H].code == (void *)g_artifact_a,
		       "the indirect-dispatch cache holds the ARTIFACT's entry (%p)",
		       tcache::l1_brind_cache[H].code);
		CHECKF(tcache::cache_tb_exec_count[H].gip == GIP &&
			   tcache::cache_tb_exec_count[H].tb == aot,
		       "the exec-count cache names the AOT block");
		u32 ic_guard_after = 0;
		memcpy(&ic_guard_after, blob + 2, 4);
		CHECKF(ic_guard_after == 0xFFFFFFFFu,
		       "the inline-cache blob is back on the never-matching sentinel (%08x)",
		       ic_guard_after);
		CHECKF(pc.ic_unpatched == 1, "...and the promotion reports having done it (%u)",
		       pc.ic_unpatched);
		CHECKF(pc.relinked == 2, "the promotion reports 2 relinked slots (%u)", pc.relinked);
		// FAILURE PATH, and this is the one the PM review caught: reading the flag off `tb` --
		// the block being installed -- gives false for every promotion, because `MakeAot` (like
		// `AllocateTBlock` in the real promoters) hands back a zeroed block. The value must come
		// from the ip's PRIOR state, read before `InsertOrReplace` replaces it.
		CHECK(pc.brind_was_target,
		      "...and that this ip was ALREADY an indirect target -- read from the OLD block, not "
		      "from the freshly allocated one being installed");
		CHECK(!aot->flags.is_brind_target == false,
		      "...the installed block is itself marked a brind target now (CacheBrind), so reading "
		      "the flag AFTER the replace would also be wrong, in the other direction");
	}

	// -------------------------------------------------------------------------------------
	SECTION("3. the scope is exactly one guest ip");
	// FAILURE PATH: a promotion that walked the whole link index, or wrote every L1 slot, would
	// silently migrate an ip the caller never asked about -- which for the loop tier would mean
	// installing one header and repointing the program.
	{
		CHECKF(SlotTarget(p_other) == other_code,
		       "the other ip's predecessor is untouched (%p)", SlotTarget(p_other));
		CHECK(memcmp(pre_other, p_other.raw, sizeof pre_other) == 0,
		      "...byte for byte");
		CHECK(tcache::Lookup(OTHER) == qcg_other, "the other ip still resolves to its QCG block");
		CHECKF(tcache::l1_brind_cache[HO].code == other_code,
		       "...and its dispatch cache still holds its own code");
		CHECKF(tcache::LinkMapSize() == links_before,
		       "the link index is the size it was: slots were repointed, not unlinked or added "
		       "(%zu vs %zu)",
		       tcache::LinkMapSize(), links_before);
	}

	// -------------------------------------------------------------------------------------
	SECTION("4. an inline cache cannot be re-patched onto an AOT block");
	// WHY THE UNPATCH IS THE ONLY CORRECT ACTION, rather than re-patching the blob at the new
	// address: `ICTryPatch` refuses a block with `tcode.size == 0` outright, because the blob's
	// baked counter pointer and rel32 assume QCG code in this process's pool. So the site MUST fall
	// back to the L1 hash path -- which the promotion has just pointed at the artifact.
	// FAILURE PATH: if `ICTryPatch` ever started accepting AOT blocks, unpatching would become the
	// wrong action and this check is what would notice.
	{
		tcache::ICTryPatch(ic_ra, aot);
		u32 g = 0;
		memcpy(&g, blob + 2, 4);
		CHECKF(g == 0xFFFFFFFFu, "the blob stays on the sentinel: an AOT target is refused (%08x)",
		       g);
	}

	// -------------------------------------------------------------------------------------
	SECTION("5. promotion is idempotent and re-appliable");
	// FAILURE PATH: a second promotion that double-counted the link index, or that failed to move
	// slots already pointing at an artifact, would make a re-promotion (a second artifact for the
	// same ip, which `BootOneArtifact` explicitly supports) leave a mixture of two generations.
	{
		auto *aot2 = MakeAot(GIP, g_artifact_b);
		auto const pc2 = tcache::PromoteTarget(aot2);
		CHECK(tcache::Lookup(GIP) == aot2, "the second artifact replaces the first");
		CHECKF(SlotTarget(p1) == (void const *)g_artifact_b &&
			   SlotTarget(p2) == (void const *)g_artifact_b,
		       "both predecessors follow it (%p)", SlotTarget(p1));
		CHECKF(tcache::l1_brind_cache[H].code == (void *)g_artifact_b,
		       "the dispatch cache follows it too");
		CHECKF(pc2.relinked == 2, "the same two slots are reported (%u)", pc2.relinked);
		CHECKF(pc2.ic_unpatched == 0, "no inline-cache blob is left to unpatch (%u)",
		       pc2.ic_unpatched);
		CHECKF(tcache::LinkMapSize() == links_before, "the link index still has not grown (%zu)",
		       tcache::LinkMapSize());
	}

	// -------------------------------------------------------------------------------------
	SECTION("6. fail-closed on a block with nothing to promote to");
	// FAILURE PATH: a null or codeless block would otherwise be written into the map and both
	// dispatch caches, and the next lookup would hand generated code a null entry point.
	{
		auto before_tb = tcache::Lookup(GIP);
		auto before_brind = tcache::l1_brind_cache[H];
		auto const n0 = tcache::PromoteTarget(nullptr);
		auto *codeless = MakeAot(GIP, nullptr);
		auto const n1 = tcache::PromoteTarget(codeless);
		CHECK(n0.relinked == 0 && n0.ic_unpatched == 0 && n1.relinked == 0 && n1.ic_unpatched == 0,
		      "both refusals report having moved nothing");
		CHECK(tcache::Lookup(GIP) == before_tb, "...and the map is unchanged");
		CHECK(tcache::l1_brind_cache[H].gip == before_brind.gip &&
			  tcache::l1_brind_cache[H].code == before_brind.code,
		      "...and so is the dispatch cache");
		CHECKF(SlotTarget(p1) == (void const *)g_artifact_b,
		       "...and the predecessors still name the last real promotion");
	}

	// -------------------------------------------------------------------------------------
	SECTION("7. brind_was_target is FALSE for an ip that was never an indirect target");
	// WITHOUT THIS SECTION THE FIELD IS UNFALSIFIABLE. Section 2 shows it reports true where the ip
	// really was a dispatch target; a field that is hardcoded true would pass that check too. This
	// promotes an ip that has a QCG block and a linked predecessor but was never `CacheBrind`-ed and
	// has no entry in the indirect cache, and requires the report to be false.
	// FAILURE PATH: reading the flag after `CacheBrind` (which sets it unconditionally) makes this
	// true; reading the cache tag after the promotion does the same.
	{
		u32 const COLD = 0x11c00;
		auto *cold_qcg = PlantQcg(COLD);
		static SlotBuf p_cold{};
		p_cold.slot()->gip = COLD;
		p_cold.slot()->Link(cold_qcg->tcode.ptr);
		tcache::RecordLink(p_cold.slot(), cold_qcg, false);
		CHECK(!cold_qcg->flags.is_brind_target,
		      "the cold ip's block is not marked an indirect target");
		CHECK(tcache::l1_brind_cache[tcache::l1hash(COLD)].gip != COLD,
		      "...and nothing indirect has ever dispatched to it");

		alignas(16) static unsigned char artifact_c[64];
		auto const pc3 = tcache::PromoteTarget(MakeAot(COLD, artifact_c));
		CHECK(!pc3.brind_was_target,
		      "the promotion reports brind_was_target=false for it");
		CHECKF(pc3.relinked == 1, "...while still repointing its one direct predecessor (%u)",
		       pc3.relinked);
		CHECKF(SlotTarget(p_cold) == (void const *)artifact_c,
		       "...at the artifact (%p)", SlotTarget(p_cold));
	}

	config::qcg_dispatch_ic = false;
	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_fail);
	printf("PROMOTE_TARGET_TEST %s\n", g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
