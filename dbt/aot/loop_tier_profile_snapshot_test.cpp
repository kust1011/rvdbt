#include "dbt/aot/loop_tier.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { if (!(condition)) { std::fprintf(stderr, "FAIL line%d: %s\n", __LINE__, #condition); ++failures; } } while (0)

static bool EqualFiles(char const *a, char const *b)
{
	int x = open(a, O_RDONLY), y = open(b, O_RDONLY);
	if (x < 0 || y < 0) {
		if (x >= 0) close(x);
		if (y >= 0) close(y);
		return false;
	}
	char bx[65536], by[65536];
	bool equal = true;
	for (;;) {
		ssize_t nx = read(x, bx, sizeof bx), ny = read(y, by, sizeof by);
		if (nx < 0 || ny < 0 || nx != ny || (nx > 0 && std::memcmp(bx, by, (size_t)nx))) {
			equal = false;
			break;
		}
		if (nx == 0) break;
	}
	close(x); close(y);
	return equal;
}

int main()
{
	char dir[] = "/tmp/lt_snapshot_XXXXXX";
	if (!mkdtemp(dir)) return 2;
	char source[256], dest[256], alias[256];
	std::snprintf(source, sizeof source, "%s/source.prof", dir);
	std::snprintf(dest, sizeof dest, "%s/snapshot.prof", dir);
	std::snprintf(alias, sizeof alias, "%s/alias.prof", dir);
	int fd = open(source, O_CREAT | O_RDWR | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd < 0) return 2;
	constexpr off_t size = 64 * 1024 * 1024;
	CHECK(ftruncate(fd, size) == 0);
	char const payload[] = "profile-address-count";
	CHECK(pwrite(fd, payload, sizeof payload, 7) == (ssize_t)sizeof payload);
	CHECK(pwrite(fd, payload, sizeof payload, size / 2 + 13) == (ssize_t)sizeof payload);
	CHECK(pwrite(fd, payload, sizeof payload, size - 4096) == (ssize_t)sizeof payload);
	CHECK(dbt::looptier::CopyProfileSnapshot(source, dest));
	struct stat srcstat, dststat;
	CHECK(fstat(fd, &srcstat) == 0);
	CHECK(stat(dest, &dststat) == 0);
	CHECK(dststat.st_size == size);
#if defined(SEEK_DATA) && defined(SEEK_HOLE)
	// Only require sparse storage if this filesystem actually exposes a hole in the source.
	off_t hole = lseek(fd, 0, SEEK_HOLE);
	if (hole >= 0 && hole < size)
		CHECK(dststat.st_blocks <= srcstat.st_blocks + 16);
#endif
	CHECK(EqualFiles(source, dest));
	CHECK(!dbt::looptier::CopyProfileSnapshot(source, source));
	CHECK(link(source, alias) == 0);
	CHECK(!dbt::looptier::CopyProfileSnapshot(source, alias));
	CHECK(fstat(fd, &srcstat) == 0 && srcstat.st_size == size);
	CHECK(unlink(alias) == 0);
	// Reusing the destination must not leave old data under newly empty holes.
	CHECK(ftruncate(fd, 0) == 0);
	CHECK(ftruncate(fd, size) == 0);
	CHECK(dbt::looptier::CopyProfileSnapshot(source, dest));
	CHECK(EqualFiles(source, dest));
	CHECK(stat(dest, &dststat) == 0 && dststat.st_size == size);
	CHECK(ftruncate(fd, 0) == 0);
	CHECK(dbt::looptier::CopyProfileSnapshot(source, dest));
	CHECK(stat(dest, &dststat) == 0 && dststat.st_size == 0);
	// Dense content and a non-page-aligned EOF use the same contract.
	char dense[8197];
	for (size_t i = 0; i < sizeof dense; ++i) dense[i] = (char)(i * 17 + 3);
	CHECK(pwrite(fd, dense, sizeof dense, 0) == (ssize_t)sizeof dense);
	CHECK(dbt::looptier::CopyProfileSnapshot(source, dest));
	CHECK(EqualFiles(source, dest));
	CHECK(!dbt::looptier::CopyProfileSnapshot("/nonexistent/lt-profile", dest));
	CHECK(!dbt::looptier::CopyProfileSnapshot(source, "/nonexistent/lt-snapshot"));
	close(fd);
	unlink(source); unlink(dest); rmdir(dir);
	std::printf("%s (%u failures)\n", failures ? "FAIL" : "PASS", failures);
	return failures ? 1 : 0;
}
