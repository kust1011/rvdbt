#include "dbt/arena.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/prctl.h>

static int checks, failures, advice_calls;
static bool fail_mapping, fail_advice;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); } } while (0)

extern "C" void *__real_mmap(void *, size_t, int, int, int, off_t);
extern "C" int __real_madvise(void *, size_t, int);
extern "C" void *__wrap_mmap(void *p, size_t n, int prot, int flags, int fd, off_t off)
{
	if (fail_mapping) {
		fail_mapping = false;
		errno = ENOMEM;
		return MAP_FAILED;
	}
	return __real_mmap(p, n, prot, flags, fd, off);
}
extern "C" int __wrap_madvise(void *p, size_t n, int advice)
{
	++advice_calls;
	if (fail_advice) {
		errno = EINVAL;
		return -1;
	}
	return __real_madvise(p, n, advice);
}

static void exercise(bool prefer, bool reject_mapping, bool reject_advice)
{
	constexpr size_t size = 4 * 1024 * 1024;
	MemArena arena;
	advice_calls = 0;
	fail_mapping = reject_mapping;
	fail_advice = reject_advice;
	arena.Init(size, PROT_READ | PROT_WRITE | PROT_EXEC, prefer);
	CHECK(advice_calls == (prefer && !reject_mapping ? 1 : 0));
	if (prefer && !reject_mapping)
		CHECK((uintptr_t)arena.BaseAddr() % (2 * 1024 * 1024) == 0);
	auto base = (unsigned char *)arena.Allocate(size, 64);
	CHECK(base == arena.BaseAddr());
	std::memset(base, 0xa5, size);
	CHECK(base[0] == 0xa5 && base[size - 1] == 0xa5);
	CHECK(arena.GetUsedSize() == size);
#if defined(__x86_64__)
	// mov eax,42; ret: exercise the allocated executable mapping, not only data.
	unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
	std::memcpy(base, code, sizeof(code));
	CHECK(((int (*)())base)() == 42);
#endif
	arena.Reset();
	CHECK(arena.GetUsedSize() == 0 && arena.Allocate(64, 64) == base);
	arena.Destroy();
	unsigned char residency;
	errno = 0;
	CHECK(mincore(base, 4096, &residency) == -1 && errno == ENOMEM);
	arena.Destroy();
	arena.Init(4096, PROT_READ | PROT_WRITE, prefer);
	CHECK(arena.Allocate(4096, 1) == arena.BaseAddr());
	arena.Destroy();
}

int main()
{
	exercise(false, false, false);
	exercise(true, false, false);
	exercise(true, true, false);
	exercise(true, false, true);
#if defined(PR_SET_THP_DISABLE)
	CHECK(prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0) == 0);
	exercise(true, false, false);
	CHECK(prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) == 0);
#endif
	printf("ARENA_PAGE_POLICY: %d/%d checks passed\n", checks - failures, checks);
	return failures ? 1 : 0;
}
