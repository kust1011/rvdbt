#include "dbt/mmu.h"
#include "dbt/ukernel.h"
#include <cstdlib>
#include <map>

namespace dbt
{
LOG_STREAM(mmu);

void *host_mmap(void *addr, size_t len, int prot, int flags, int fd, __off_t offset)
{
	if (!addr) { // hint: prefer not to allocate in 32-bit guest addresses
		addr = mmu::base + mmu::ASPACE_SIZE;
	}
	void *res = ::mmap(addr, len, prot, flags, fd, offset);
	log_mmu("host_mmap allocated at %p", res);

	if (mmu::check_h2g(res)) {
		log_mmu("host alloc in guest mem");
	}
	return res;
}

u8 *mmu::base{nullptr};
u32 mmu::mmap_hint_page = mmu::MIN_MMAP_ADDR >> mmu::PAGE_BITS;
std::bitset<(mmu::ASPACE_SIZE >> mmu::PAGE_BITS)> mmu::used_pages;
std::unique_ptr<mmu::PageDetail[]> mmu::page_details;
std::bitset<(mmu::ASPACE_SIZE >> mmu::PAGE_BITS)> mmu::readable_pages;
bool mmu::initialized{};
u64 mmu::mapping_epoch{};

bool mmu::EnableDetailedMetadata()
{
	if (initialized)
		return false;
	if (!page_details)
		page_details = std::make_unique<PageDetail[]>(ASPACE_SIZE >> PAGE_BITS);
	return true;
}

bool mmu::DetailedMetadataEnabled()
{
	return page_details != nullptr;
}

void mmu::Init()
{
	mapped_pages.reset();
	readable_pages.reset();
	mapping_epoch = 0;
	initialized = true;
	MarkUsedPages(0, MIN_MMAP_ADDR);

	if constexpr (!config::zero_membase) {
		// Allocate and immediately deallocate region, result is g2h(0)
		base =
		    (u8 *)::mmap(NULL, ASPACE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
		if (base == MAP_FAILED || ::munmap(base + MIN_MMAP_ADDR, ASPACE_SIZE - MIN_MMAP_ADDR)) {
			Panic("mmu::Init failed");
		}
	}
	log_mmu("mmu::base initialized at %p", base);
}

void mmu::Destroy()
{
	int rc = ::munmap(base, ASPACE_SIZE);
	if (rc) {
		Panic("mmu::Destroy failed");
	}
	page_details.reset();
	initialized = false;
}

// NOTE: `used_pages` is the ALLOCATOR's structure and its loop bound reads the second argument as
// an END page while callers pass a LENGTH, so mappings that do not start at page 0 mark nothing.
// That is left exactly as it was: correcting it changes which addresses LookupFreeRange hands
// out, and doing so made the guest fault during boot. It is recorded in
// docs/FOF_FAULT_PATH_TRACE.md as a separate pre-existing defect rather than fixed here, because
// fault-only-first needs an accurate page map and must not be the thing that reshuffles the
// address space to get one. `mapped_pages` below is maintained alongside it for that purpose.
void mmu::MarkUsedPages(u32 pvaddr, u32 plen)
{
	for (u32 p = pvaddr; p < plen; ++p) {
		used_pages.set(p);
	}
}

void mmu::MarkFreePages(u32 pvaddr, u32 plen)
{
	for (u32 p = pvaddr; p < plen; ++p) {
		used_pages.reset(p);
	}
}

// Accurate map of what is actually mapped, kept only so a fault-only-first load can PREDICT a
// fault. Read-only from the guest's point of view and never consulted by the allocator, so it
// cannot change which addresses are handed out.
std::bitset<(mmu::ASPACE_SIZE >> mmu::PAGE_BITS)> mmu::mapped_pages;

void mmu::MarkMapped(u32 pvaddr, u32 plen)
{
	for (u32 p = pvaddr; p < pvaddr + plen && p < (ASPACE_SIZE >> PAGE_BITS); ++p) {
		mapped_pages.set(p);
	}
}
void mmu::MarkUnmapped(u32 pvaddr, u32 plen)
{
	for (u32 p = pvaddr; p < pvaddr + plen && p < (ASPACE_SIZE >> PAGE_BITS); ++p) {
		mapped_pages.reset(p);
		readable_pages.reset(p);
	}
}

// Readability is set where the prot is KNOWN -- mmap and mprotect -- rather than in MarkMapped,
// which is not told it.
void mmu::MarkReadable(u32 pvaddr, u32 plen, int prot)
{
	bool const readable = (prot & PROT_READ) != 0;
	for (u32 p = pvaddr; p < pvaddr + plen && p < (ASPACE_SIZE >> PAGE_BITS); ++p) {
		if (readable)
			readable_pages.set(p);
		else
			readable_pages.reset(p);
	}
}

[[noreturn]] void mmu::ReportGuestFault(u32 gip, u32 gaddr, char const *kind)
{
	// The SAME line the SIGSEGV handler prints, emitted from the one place that formats it.
	fprintf(stderr, "GUEST_FAULT ip=%08x addr=%08x page=%08x kind=%s\n", gip, gaddr,
		(u32)(gaddr & PAGE_MASK), kind);
	Panic("Memory fault in guest address space. See logs for more details");
}

u32 mmu::LookupFreeRange(u32 pvaddr, u32 plen)
{
	u32 count = plen;
	for (u32 p = pvaddr; p < ASPACE_SIZE >> PAGE_BITS; ++p) {
		if (used_pages.test(p)) {
			count = plen;
		} else if (--count == 0) {
			return p + 1 - plen;
		}
	}
	return 0;
}

void *mmu::mmap(u32 vaddr, u32 len, int prot, int flags, int fd, size_t offs)
{
	assert((u64)vaddr + len - 1 < ASPACE_SIZE);
	len = roundup(len, PAGE_SIZE);
	u32 const plen = len >> PAGE_BITS;

	if (flags & MAP_FIXED) {
		void *hptr = g2h(vaddr);
		hptr = ::mmap(hptr, len, prot, flags, fd, offs);
		if (hptr == MAP_FAILED) {
			log_mmu("mmu::mmap fixed failed");
			return MAP_FAILED;
		}
		log_mmu("mmu::mmap allocated at %p sz=0x%08x", hptr, len);
		MarkUsedPages(vaddr >> PAGE_BITS, plen);
		MarkMapped(vaddr >> PAGE_BITS, plen);
		MarkReadable(vaddr >> PAGE_BITS, plen, prot);
		if (page_details)
			for (u32 p = vaddr >> PAGE_BITS; p < (vaddr >> PAGE_BITS) + plen; ++p)
				page_details[p] = {prot, (u8)((flags & MAP_SHARED) ? 2 : ((flags & MAP_PRIVATE) ? 1 : 0)),
					((flags & MAP_ANONYMOUS) || fd < 0) ? BackingType::Anonymous : BackingType::File};
		++mapping_epoch;
		return hptr;
	}

	u32 paddr = mmap_hint_page;
	bool paddr_wrapped = false;
	void *hptr;
	while (1) {
		while (1) {
			paddr = LookupFreeRange(paddr, plen);
			if (paddr_wrapped && (paddr == 0 || paddr > mmap_hint_page)) {
				log_mmu("mmu::mmap: no free range in vm");
				return MAP_FAILED;
			}
			if (paddr == 0) {
				log_mmu("mmu::mmap: vm lookup wrapped");
				paddr_wrapped = true;
				paddr = MIN_MMAP_ADDR >> PAGE_BITS;
			} else {
				break;
			}
		}

		log_mmu("mmu::mmap: try at %p", g2h(paddr << PAGE_BITS));
		hptr = ::mmap(g2h(paddr << PAGE_BITS), len, PROT_NONE,
			      MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (hptr == MAP_FAILED) {
			Panic("mmu::mmap failed, probably host oom");
		}
		if (check_h2g((u8 *)hptr + len - 1)) {
			break;
		}
		log_mmu("mmu::mmap: miss %p", hptr);
		if (::munmap(hptr, len) != 0) {
			Panic();
		}
		paddr += plen;
	}

	void *res = ::mmap(hptr, len, prot, flags | MAP_FIXED, fd, offs);
	if (res == MAP_FAILED || res != hptr) {
		Panic();
	}
	log_mmu("mmu::mmap allocated at %p sz=0x%08x", hptr, len);
	paddr = h2g(hptr) >> PAGE_BITS;
	MarkUsedPages(paddr, plen);
	MarkMapped(paddr, plen);
	MarkReadable(paddr, plen, prot);
	if (page_details)
		for (u32 p = paddr; p < paddr + plen; ++p)
			page_details[p] = {prot, (u8)((flags & MAP_SHARED) ? 2 : ((flags & MAP_PRIVATE) ? 1 : 0)),
				((flags & MAP_ANONYMOUS) || fd < 0) ? BackingType::Anonymous : BackingType::File};
	++mapping_epoch;
	mmap_hint_page = paddr + plen;
	return res;
}

int mmu::munmap(u32 vaddr, u32 len)
{
	int rc = ::munmap(g2h(vaddr), len);
	if (rc != 0)
		return rc;
	u32 const first = vaddr >> PAGE_BITS;
	u32 const plen = roundup(len, PAGE_SIZE) >> PAGE_BITS;
	MarkUnmapped(first, plen);
	if (page_details)
		for (u32 p = first; p < first + plen; ++p)
			page_details[p] = {};
	++mapping_epoch;
	return 0;
}

int mmu::mprotect(u32 vaddr, u32 len, int prot)
{
	int rc = ::mprotect(g2h(vaddr), len, prot);
	if (rc != 0)
		return rc;
	u32 const first = vaddr >> PAGE_BITS;
	u32 const plen = roundup(len, PAGE_SIZE) >> PAGE_BITS;
	MarkReadable(first, plen, prot);
	if (page_details)
		for (u32 p = first; p < first + plen; ++p)
			page_details[p].prot = prot;
	++mapping_epoch;
	return 0;
}

bool mmu::QueryPage(u32 gaddr, PageInfo &out)
{
	if (!page_details)
		return false;
	u32 const p = gaddr >> PAGE_BITS;
	auto const &detail = page_details[p];
	out = {mapped_pages[p], detail.prot, detail.flags == 1, detail.flags == 2, detail.backing};
	return true;
}

u64 mmu::MappingEpoch()
{
	return mapping_epoch;
}

} // namespace dbt
