// T5c-0 focused lifetime test: the direct-link escape ring must never outlive the code it names.
//
// THE DEFECT THIS GUARDS. --inrun-escape-unlink records raw `BranchSlot*` into tcache::esc_link_ring
// as branches are linked, and the SIGALRM keeper later calls tcache::UnlinkRecorded(), which writes
// 12 bytes through every live pointer. Those pointers are addresses inside tcache::code_pool. Any
// boundary that resets, unmaps or re-initialises that pool makes them dangling, and the next keeper
// tick would patch reclaimed memory. The first version of the patch cleared the ring only in
// RevokeTarget/InvalidatePage and missed Init(), Destroy() and Invalidate() -- the three places that
// touch the WHOLE pool. gemm happens not to take those paths, which is exactly why "the workload
// passes" is not evidence and this test exists.
//
// WHAT IT ASSERTS, AND HOW EACH ASSERTION CAN FAIL. Every case first proves the ring is genuinely
// populated (so a broken recorder cannot make the test pass vacuously), then crosses one boundary,
// then requires the ring to be empty and UnlinkRecorded() to report zero work. Delete the
// ClearEscLinks() call from any one of the four executed boundaries and the corresponding case
// fails -- verified by doing exactly that, one boundary at a time, before this test was committed.
//
// It drives the real tcache -- real MemArena, real code_pool allocations, real BranchSlot patching
// via the real RuntimeStubTab -- with no guest, no emitted guest code and no mock. Runs anywhere.

#include "dbt/config.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/tcache/tcache.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace
{

int g_failed = 0;

void check(bool ok, char const *what)
{
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		g_failed++;
}

// How many live pointers the ring currently holds.
unsigned ring_live()
{
	unsigned n = 0;
	for (unsigned i = 0; i < dbt::tcache::ESC_LINK_SLOTS; ++i)
		if (dbt::tcache::esc_link_ring[i] != nullptr)
			n++;
	return n;
}

// True iff any live ring entry points inside [lo, hi) -- the byte range the pool just handed out.
bool ring_points_into(void *lo, void *hi)
{
	for (unsigned i = 0; i < dbt::tcache::ESC_LINK_SLOTS; ++i) {
		auto *p = (unsigned char *)dbt::tcache::esc_link_ring[i];
		if (p && p >= (unsigned char *)lo && p < (unsigned char *)hi)
			return true;
	}
	return false;
}

// Allocate real code-pool space, put N BranchSlots in it, and link each one to a TBlock so the
// production path (tcache::RecordLink -> RecordEscLink) is what fills the ring. Returns the byte
// range the slots occupy so a later check can ask whether anything still points into it.
struct Populated {
	void *lo, *hi;
	std::vector<dbt::jitabi::ppoint::BranchSlot *> slots;
	std::vector<dbt::TBlock *> tbs;
};

Populated populate(unsigned n, u32 first_gip)
{
	Populated p{};
	size_t slot_sz = sizeof(dbt::jitabi::ppoint::BranchSlot);
	auto *base = (unsigned char *)dbt::tcache::AllocateCode(slot_sz * n + 64, 16);
	p.lo = base;
	p.hi = base + slot_sz * n;
	for (unsigned i = 0; i < n; ++i) {
		auto *tb = dbt::tcache::AllocateTBlock();
		tb->ip = first_gip + i;
		// A TBlock needs somewhere to point; its own code is irrelevant to this test, but it must
		// be a real address so Link() computes a real displacement rather than trapping.
		tb->tcode = dbt::TBlock::TCode{base, slot_sz};
		auto *slot = (dbt::jitabi::ppoint::BranchSlot *)(base + slot_sz * i);
		memset(slot, 0, slot_sz);
		slot->gip = tb->ip;
		slot->flags.cross_segment = false;
		dbt::tcache::Insert(tb);
		dbt::tcache::RecordLink(slot, tb, false); // the production recorder
		p.slots.push_back(slot);
		p.tbs.push_back(tb);
	}
	return p;
}

// One case: populate, prove the ring is live and inside the pool, cross a boundary, require empty.
void boundary_case(int id, char const *name, unsigned n, u32 gip, void (*cross)())
{
	printf("[%d] %s\n", id, name);
	dbt::tcache::ClearEscLinks();
	auto p = populate(n, gip);
	// If this fails the rest of the case proves nothing, so it is checked rather than assumed.
	check(ring_live() == n, "the ring really is populated before the boundary");
	check(ring_points_into(p.lo, p.hi), "and its entries really point into the code pool");
	cross();
	check(ring_live() == 0, "no ring entry survives the boundary");
	check(dbt::tcache::esc_link_head == 0, "the ring head is reset too");
	check(dbt::tcache::UnlinkRecorded() == 0, "a keeper tick after the boundary patches nothing");
	check(!ring_points_into(p.lo, p.hi), "nothing still points into the freed/reset range");
}

} // namespace

int main()
{
	dbt::config::inrun_escape_unlink = true; // the recorder is gated on this
	printf("T5c-0 esc_link_ring lifetime test\n\n");

	dbt::tcache::Init();

	// [0] The mechanism works at all: a live ring is patched, and patching consumes it.
	// Without this, every "returns 0" assertion below could be satisfied by a ring that never
	// fills, and the whole test would be vacuous.
	printf("[0] the escape ring is functional\n");
	dbt::tcache::ClearEscLinks();
	{
		auto p = populate(4, 0x20000);
		check(ring_live() == 4, "four linked branches recorded");
		unsigned patched = dbt::tcache::UnlinkRecorded();
		check(patched == 4, "UnlinkRecorded patches every live slot");
		check(ring_live() == 0, "and consumes the ring -- one escape per link");
		// LinkLazyJIT writes a 12-byte `mov rax, imm64; call rax`. Check the opcodes landed, so
		// "patched" is a fact about memory and not just a return value.
		auto *b = (unsigned char *)p.slots[0];
		check(b[0] == 0x48 && b[1] == 0xb8 && b[10] == 0xff && b[11] == 0xd0,
		      "the patched bytes really are the lazy-JIT stub call");
	}

	// [1] Recording is gated: with the flag off nothing is recorded at all.
	printf("[1] the recorder is inert when the flag is off\n");
	dbt::tcache::ClearEscLinks();
	dbt::config::inrun_escape_unlink = false;
	populate(4, 0x21000);
	check(ring_live() == 0, "flag off records nothing");
	dbt::config::inrun_escape_unlink = true;

	// [2]-[5] The reachable lifetime boundaries.
	boundary_case(2, "tcache::Invalidate() -- code_pool.Reset()", 8, 0x22000,
		      [] { dbt::tcache::Invalidate(); });

	boundary_case(3, "tcache::RevokeTarget() -- one target unlinked", 8, 0x23000,
		      [] { dbt::tcache::RevokeTarget(0x23000); });

	// Re-initialisation: Init() on an already-initialised tcache re-arms the pools, so any pointer
	// recorded before it names memory the allocator is free to hand out again.
	boundary_case(4, "tcache::Init() -- re-initialisation", 8, 0x25000,
		      [] { dbt::tcache::Init(); });

	// Destroy() unmaps the pool outright. Checked last because nothing can allocate after it.
	boundary_case(5, "tcache::Destroy() -- pool unmapped", 8, 0x26000,
		      [] { dbt::tcache::Destroy(); });

	printf("\n%s (%d failed)\n", g_failed ? "ESC_LINK_RING_LIFETIME: FAIL" : "ESC_LINK_RING_LIFETIME: PASS",
	       g_failed);
	return g_failed ? 1 : 0;
}
