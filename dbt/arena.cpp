#include "dbt/arena.h"
#include "dbt/util/allocator.h"
#include <limits>

void MemArena::Init(size_t size, int prot, bool prefer_huge_pages)
{
	assert(!pool);
	pool_sz = roundup(size, 4096);
	used = 0;
#if defined(__linux__) && defined(__x86_64__) && defined(MADV_HUGEPAGE)
	// Align the code arena for demand-backed x86 PMD pages, without reserving
	// hugetlb pages or changing the host's global VM policy. Advice is optional.
	constexpr size_t huge_page_size = 2 * 1024 * 1024;
	if (prefer_huge_pages && pool_sz >= huge_page_size &&
	    pool_sz <= std::numeric_limits<size_t>::max() - huge_page_size) {
		auto raw = (u8 *)dbt::host_mmap(NULL, pool_sz + huge_page_size, prot,
			MAP_ANON | MAP_PRIVATE, -1, 0);
		if (raw != MAP_FAILED) {
			auto aligned = roundup((uintptr_t)raw, huge_page_size);
			size_t prefix = aligned - (uintptr_t)raw;
			size_t suffix = huge_page_size - prefix;
			pool = (u8 *)aligned;
			if ((prefix && munmap(raw, prefix)) ||
			    (suffix && munmap(pool + pool_sz, suffix))) {
				dbt::Panic("MemArena::Init alignment unmap failed");
			}
			// Rejected advice or unavailable THP leaves a valid normal-page arena.
			(void)madvise(pool, pool_sz, MADV_HUGEPAGE);
			return;
		}
	}
#endif
	pool = (u8 *)dbt::host_mmap(NULL, pool_sz, prot, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (pool == MAP_FAILED) {
		dbt::Panic("MemArena::Init failed");
	}
}

void MemArena::Destroy()
{
	if (!pool)
		return;
	int rc = munmap(pool, pool_sz);
	if (rc) {
		dbt::Panic("MemArena::Destroy failed");
	}
	pool = nullptr;
}
