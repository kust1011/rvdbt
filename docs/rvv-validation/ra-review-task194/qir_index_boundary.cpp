// Independent representation probe; no QCG, LLVM or guest execution.
// Link production arena.cpp, with only its process services supplied below.
#include "dbt/qmc/qir.h"
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace dbt {
LogStreamI::Setup::Setup(LogStreamI &) {}
void *host_mmap(void *a, size_t n, int p, int f, int fd, __off_t o)
{
	return ::mmap(a, n, p, f, fd, o);
}
void Panic(char const *s)
{
	std::fprintf(stderr, "%s\n", s);
	std::abort();
}
}

int main()
{
	using namespace dbt::qir;
	MemArena arena(2 * 1024 * 1024);
	StateReg globals[32]{};
	StateInfo state{globals, 32};
	VRegsInfo info(&arena, &state);
	constexpr size_t limit = std::numeric_limits<RegN>::max();
	for (size_t expected = 32; expected < limit; ++expected)
		if (info.AddLocal(VType::V512) != expected) return 1;
	if (info.NumAll() != limit || info.GetLocalType(65534) != VType::V512) return 2;
	std::printf("RA-supported count=%zu last-index=65534\n", info.NumAll());
	auto sentinel = info.AddLocal(VType::V512);
	if (sentinel != RegNBad || info.NumAll() != 65536) return 3;
	std::printf("RA-rejected count=%zu returned-index=%u (RegNBad)\n",
		info.NumAll(), unsigned(sentinel));
	auto wrapped = info.AddLocal(VType::V512);
	if (wrapped != 0 || info.NumAll() != 65537) return 4;
	std::printf("RA-rejected count=%zu returned-index=%u (aliases global 0)\n",
		info.NumAll(), unsigned(wrapped));
	return 0;
}
