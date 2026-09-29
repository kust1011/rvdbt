// Analysis-only exact QIR dump for a caller-supplied guest memory image and address range.
//
// The tool deliberately knows no workload, symbol, PC, opcode, or expected operation.  Its input
// range is selected from the ELF by the separate fact extractor.  It invokes the ordinary RV32
// IRTranslator and PrinterPass, but never invokes QCG/LLVM, maps executable memory, or runs guest
// code.  This gives provenance analysis a complete, non-overlapping QIR region instead of choosing
// one occurrence from an overlapping profile-selected region dump.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir_printer.h"

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
bool ParseU32(char const *text, u32 &result)
{
	errno = 0;
	char *end = nullptr;
	unsigned long value = std::strtoul(text, &end, 0);
	if (errno || end == text || *end || value > std::numeric_limits<u32>::max())
		return false;
	result = static_cast<u32>(value);
	return true;
}
} // namespace

int main(int argc, char **argv)
{
	if (argc < 5 || ((argc - 3) & 1)) {
		std::cerr << "usage: qir_exact_region_dump MEMORY_IMAGE VLEN_BITS START END [START END ...]\n";
		return 2;
	}
	u32 vlen;
	if (!ParseU32(argv[2], vlen) || !vlen || (vlen & 7)) {
		std::cerr << "invalid vlen\n";
		return 2;
	}
	CompilerJob::IpRangesSet ranges;
	u32 segment_start = std::numeric_limits<u32>::max(), segment_end = 0;
	for (int i = 3; i < argc; i += 2) {
		u32 start, end;
		if (!ParseU32(argv[i], start) || !ParseU32(argv[i + 1], end) || start >= end ||
		    (start & 3) || (end & 3)) {
			std::cerr << "invalid range\n";
			return 2;
		}
		for (auto const &range : ranges)
			if (start < range.second && range.first < end) {
				std::cerr << "overlapping ranges\n";
				return 2;
			}
		ranges.emplace_back(start, end);
		segment_start = std::min(segment_start, start);
		segment_end = std::max(segment_end, end);
	}
	std::ifstream input(argv[1], std::ios::binary);
	if (!input) {
		std::cerr << "cannot open memory image\n";
		return 2;
	}
	std::vector<u8> memory((std::istreambuf_iterator<char>(input)), {});
	if (memory.size() < segment_end) {
		std::cerr << "memory image does not cover end address\n";
		return 2;
	}

	config::vlen_bits = vlen;
	config::rvv_direct = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_run = false;
	MemArena arena(16_MB);
	CompilerJob job(nullptr, reinterpret_cast<uptr>(memory.data()),
			CodeSegment(segment_start, segment_end - segment_start),
			std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	std::cout << "; exact-qir-region vlen: " << std::dec << vlen << " ranges:";
	for (int i = 3; i < argc; i += 2) {
		u32 start, end;
		ParseU32(argv[i], start);
		ParseU32(argv[i + 1], end);
		std::cout << " " << std::hex << start << "-" << end;
	}
	std::cout << std::dec << "\n" << PrinterPass::run(region) << "\n";
	return 0;
}
