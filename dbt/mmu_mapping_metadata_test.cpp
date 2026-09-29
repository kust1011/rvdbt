#include "dbt/mmu.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdio>

using dbt::mmu;

static int checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); } } while (0)

int main()
{
	// Default-off lifecycle: the FOF presence bitmap remains operational, while detailed
	// observer storage is absent and QueryPage fails closed. Late enablement is forbidden.
	mmu::Init();
	CHECK(!mmu::DetailedMetadataEnabled());
	mmu::PageInfo p;
	CHECK(!mmu::QueryPage((u32)mmu::MIN_MMAP_ADDR, p));
	CHECK(!mmu::EnableDetailedMetadata());
	CHECK(mmu::mmap((u32)mmu::MIN_MMAP_ADDR, mmu::PAGE_SIZE, PROT_READ,
		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS) != MAP_FAILED);
	CHECK(mmu::page_mapped((u32)mmu::MIN_MMAP_ADDR));
	CHECK(mmu::munmap((u32)mmu::MIN_MMAP_ADDR, mmu::PAGE_SIZE) == 0);
	mmu::Destroy();

	// Observer-on lifecycle: allocation precedes Init and therefore every guest mapping.
	CHECK(mmu::EnableDetailedMetadata());
	CHECK(mmu::DetailedMetadataEnabled());
	mmu::Init();
	u32 const a = (u32)mmu::MIN_MMAP_ADDR;
	CHECK(mmu::MappingEpoch() == 0);
	CHECK(mmu::mmap(a, mmu::PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS) != MAP_FAILED);
	CHECK(mmu::MappingEpoch() == 1);
	CHECK(mmu::QueryPage(a, p));
	CHECK(p.mapped && p.prot == (PROT_READ | PROT_WRITE));
	CHECK(p.is_private && !p.is_shared && p.backing == mmu::BackingType::Anonymous);
	CHECK(mmu::mprotect(a, mmu::PAGE_SIZE, PROT_READ | PROT_EXEC) == 0);
	CHECK(mmu::MappingEpoch() == 2);
	CHECK(mmu::QueryPage(a, p));
	CHECK(p.mapped && p.prot == (PROT_READ | PROT_EXEC) && p.is_private);
	CHECK(mmu::munmap(a, mmu::PAGE_SIZE) == 0);
	CHECK(mmu::MappingEpoch() == 3);
	CHECK(mmu::QueryPage(a, p) && !p.mapped);

	char path[] = "/tmp/rvdbt-mmu-meta-XXXXXX";
	int fd = mkstemp(path);
	CHECK(fd >= 0 && ftruncate(fd, mmu::PAGE_SIZE) == 0);
	u32 const b = a + mmu::PAGE_SIZE;
	CHECK(mmu::mmap(b, mmu::PAGE_SIZE, PROT_READ, MAP_FIXED | MAP_SHARED, fd, 0) != MAP_FAILED);
	CHECK(mmu::MappingEpoch() == 4);
	CHECK(mmu::QueryPage(b, p));
	CHECK(p.mapped && p.prot == PROT_READ && !p.is_private && p.is_shared && p.backing == mmu::BackingType::File);
	CHECK(mmu::munmap(b, mmu::PAGE_SIZE) == 0 && mmu::MappingEpoch() == 5);
	close(fd);
	unlink(path);
	mmu::Destroy();
	printf("MMU_MAPPING_METADATA_TEST: %s (%d/%d)\n", failures ? "FAIL" : "PASS", checks - failures, checks);
	return failures ? 1 : 0;
}
