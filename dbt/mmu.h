#pragma once

#include "dbt/util/allocator.h"
#include "dbt/util/logger.h"
#include <bitset>
#include <cstdint>
#include <memory>
#include <unordered_map>
extern "C" {
#include <sys/mman.h>
}

namespace dbt
{

struct mmu {
	enum class BackingType : u8 { None, Anonymous, File };
	struct PageInfo {
		bool mapped{};
		int prot{};
		bool is_private{};
		bool is_shared{};
		BackingType backing{BackingType::None};
	};
	static constexpr size_t ASPACE_SIZE = (1ull) << 32;
	static constexpr size_t PAGE_BITS = 12; // true for rv32 and amd64
	static constexpr size_t PAGE_SIZE = 1 << PAGE_BITS;
	static constexpr size_t PAGE_MASK = ~(PAGE_SIZE - 1);
	static constexpr size_t MIN_MMAP_ADDR = 64 * PAGE_SIZE;
	// TODO: this should be large enough, like 32, to avoid weird behavior of syscall in 502.gcc, but the reason remains to find out.
	static void Init();
	static void Destroy();
	static void *mmap(u32 vaddr, u32 len, int prot, int flag = MAP_ANON | MAP_PRIVATE | MAP_FIXED,
			  int fd = -1, size_t offs = 0);
	static int munmap(u32 vaddr, u32 len);
	static int mprotect(u32 vaddr, u32 len, int prot);
	// Detailed mapping facts are observer-owned and deliberately absent in ordinary runs.
	// Enabling is only valid before Init(), so no guest mapping can precede the table.
	static bool EnableDetailedMetadata();
	static bool DetailedMetadataEnabled();
	static bool QueryPage(u32 gaddr, PageInfo &out);
	static u64 MappingEpoch();

	static ALWAYS_INLINE bool check_h2g(void *hptr)
	{
		return ((uptr)hptr - (uptr)base) < ASPACE_SIZE;
	}

	static ALWAYS_INLINE u32 h2g(void *hptr)
	{
		return (uptr)hptr - (uptr)base;
	}

	static ALWAYS_INLINE void *g2h(u32 gptr)
	{
		return base + gptr;
	}

	// Is the page containing this guest address mapped?
	//
	// Added for fault-only-first loads, which must PREDICT a fault rather than take one: the
	// architecture requires that a fault on any element after the first trims vl and completes
	// without trapping, and there is no way to unwind out of a faulting memcpy inside a helper
	// called from generated code. used_pages is already maintained on both mmap paths
	// (MAP_FIXED at mmu.cpp:92 and the searched path at mmu.cpp:137), so this is a read of
	// existing state, not new bookkeeping.
	static ALWAYS_INLINE bool page_mapped(u32 gaddr)
	{
		return mapped_pages[gaddr >> PAGE_BITS];
	}

	// Is the page containing this guest address READABLE BY THE GUEST?
	//
	// A SEPARATE BITSET FROM `mapped_pages`, AND NOT `page_details[].prot`, for two reasons that
	// are both properties of this file rather than preferences. First, mapped != readable: a page
	// mapped PROT_NONE or write-only is present but must not be read, and the address-space guard
	// page ukernel maps at the top is exactly that. Second, page_details is OPTIONAL -- it is
	// allocated only when an observer calls EnableDetailedMetadata() before Init(), so in an
	// ordinary run it is null and every write to it is skipped; a predicate reading it would
	// silently answer "no permission data" for the whole address space. This bitset is maintained
	// on the same three paths mapped_pages is (mmap, munmap, mprotect) and costs one bit a page.
	static ALWAYS_INLINE bool page_readable(u32 gaddr)
	{
		return readable_pages[gaddr >> PAGE_BITS];
	}

	// The readability counterpart of range_mapped, and the predicate a fault-only-first load
	// wants: it answers "would the guest be allowed to read these bytes", which is what decides
	// whether the access faults.
	// STEPPED BY REMAINING BYTES, so the guest address wraps the way RV32 does. A range that
	// runs past 0xffffffff continues at 0 -- that is an ordinary XLEN-bit address computation,
	// not an error -- so there is no "first > last means refuse" case here: the loop advances to
	// the next page boundary until the bytes run out, and `a += in_page` wraps on its own.
	static ALWAYS_INLINE bool range_readable(u32 gaddr, u32 len)
	{
		u32 a = gaddr;
		for (u32 left = len; left != 0;) {
			if (!readable_pages[a >> PAGE_BITS])
				return false;
			u32 const in_page = (u32)PAGE_SIZE - (a & (u32)(PAGE_SIZE - 1));
			if (in_page >= left)
				break;
			left -= in_page;
			a += in_page;
		}
		return true;
	}

	// Report a guest memory fault at a KNOWN guest address and terminate, which is what the
	// SIGSEGV handler does after it recovers the same two facts from the signal. Callable so that
	// a helper which PREDICTED a fault can report it without touching the address: on x86 a host
	// mapping made for a write-only guest page is readable, so touching it would not fault and
	// the guest error would be silently dropped.
	[[noreturn]] static void ReportGuestFault(u32 gip, u32 gaddr, char const *kind);

	// Does an access of `len` bytes starting at `gaddr` lie entirely in mapped pages? Checked
	// per page rather than per byte because an access may straddle a boundary into an unmapped
	// page -- a 4-byte load one byte before the end of a mapping faults even though its first
	// byte does not.
	static ALWAYS_INLINE bool range_mapped(u32 gaddr, u32 len)
	{
		if (len == 0)
			return true;
		u32 const first = gaddr >> PAGE_BITS;
		u32 const last = (u32)(gaddr + len - 1) >> PAGE_BITS;
		if (last < first)
			return false; // wrapped past the end of the address space
		for (u32 p = first; p <= last; ++p)
			if (!mapped_pages[p])
				return false;
		return true;
	}

	static u8 *base;

private:
	static void MarkMapped(u32 pvaddr, u32 plen);
	static void MarkReadable(u32 pvaddr, u32 plen, int prot);
	static void MarkUnmapped(u32 pvaddr, u32 plen);
	static std::bitset<(ASPACE_SIZE >> PAGE_BITS)> used_pages;
	// Separate from used_pages, which is the allocator's and whose length convention is
	// broken (see mmu.cpp). This one is accurate and is read by FOF.
	static std::bitset<(ASPACE_SIZE >> PAGE_BITS)> mapped_pages;
	// The subset of mapped_pages the guest may READ. See page_readable() above for why it is a
	// bitset of its own rather than a lookup into the optional page_details table.
	static std::bitset<(ASPACE_SIZE >> PAGE_BITS)> readable_pages;
	struct PageDetail {
		int prot{};
		u8 flags{};
		BackingType backing{BackingType::None};
	};
	static std::unique_ptr<PageDetail[]> page_details;
	static bool initialized;
	static u64 mapping_epoch;
	static u32 mmap_hint_page;

	static void MarkUsedPages(u32 pvaddr, u32 plen);
	static void MarkFreePages(u32 pvaddr, u32 plen);
	static u32 LookupFreeRange(u32 pvaddr, u32 plen);

	mmu() = delete;
};

} // namespace dbt
