#pragma once
// T5b-1 -- PER-GUEST-PC census of vector instructions that ran in C++ rather than in emitted code.
//
// INSTRUMENTATION, NOT A MEASUREMENT. Default off, on the cold side only, and nothing it does
// changes an emitted byte. It exists because the T5b-1 route audit asks a question the existing
// counters cannot answer, and answering it by reading source would be exactly the "silently
// classify from source alone" the checkpoint forbids.
//
// WHAT THE EXISTING COUNTERS CANNOT DO.
//
//   route_census (T3a)  counts handler entries per opcode, but only for the NINE routes T1 closed;
//                       everything else lands in one `other-vector` bucket. The real workload's hot
//                       families -- vl1re32.v, vs1r.v, vmul.vx, vmacc.vx -- are all in that bucket,
//                       so it cannot say which of them fell back.
//   rvv_census (P13)    counts handler entries per HANDLER FAMILY with vl/SEW/LMUL, which separates
//                       the families, but is process-wide: it cannot say whether an execution came
//                       from the timed kernel_gemm or from the adapter, init_array or print_array.
//                       The audit has to separate those, and a family that appears in both is
//                       indistinguishable in that view.
//
// So this adds exactly one thing: the guest PC. Keyed by PC, it records the raw encoding, the rvdbt
// handler family, how many times that PC ran in C++, and the elements those executions covered.
// Attribution to the timed kernel is then a range test against the ELF's own symbol table, done
// offline by the analyser, and every recorded PC can be checked to land on a vector instruction in
// the ELF's disassembly -- a PC that did not would mean this hook reads the wrong thing.
//
// WHAT A COUNT HERE MEANS, and what it does not. `note()` is called from `H_<name>`, the single
// point both paths into the C++ implementation pass through: the JIT's `qcgstub_rv32_<name>`
// wrapper and `Interpreter::Execute`/`ExecuteBlock`. So a count here is "this PC did NOT run as
// emitted host code, this many times". It is NOT the total execution count of that PC: an
// instruction that took a direct or typed route is invisible here, by construction. The total comes
// from a separate control run with every direct and typed route switched off, in which every
// execution must pass through C++; direct executions are then total minus these.
//
// COST when enabled: one predicted-not-taken branch on the cold path plus a linear-probe lookup in
// a fixed table. When disabled: one load of a bool. Nothing in the JIT fast path changes.

#include "dbt/util/common.h"
#include <cstdio>

namespace dbt::rv32::pc_census
{

struct Entry {
	u32 pc;
	u32 raw;
	char const *family; // the rvdbt handler name, e.g. "vlNre", "vimul", "vsetvli"
	u64 calls;
	u64 elems;
};

// A guest has a small, fixed number of distinct vector instruction PCs -- the frozen PolyBench gemm
// binary has eleven. 4096 slots is three orders of magnitude of headroom; overflow is COUNTED and
// reported rather than silently dropping evidence, because a census that quietly loses rows would
// make an incomplete audit look complete.
inline constexpr unsigned CAP = 4096;
inline Entry g_tab[CAP]{};
inline unsigned g_used = 0;
inline u64 g_overflow = 0;

inline void note(u32 pc, u32 raw, char const *family, u32 vl)
{
	unsigned h = (pc >> 2) & (CAP - 1);
	for (unsigned i = 0; i < CAP; ++i) {
		Entry &e = g_tab[(h + i) & (CAP - 1)];
		if (e.calls == 0 && e.pc == 0 && e.raw == 0) {
			e.pc = pc;
			e.raw = raw;
			e.family = family;
			e.calls = 1;
			e.elems = vl;
			++g_used;
			return;
		}
		if (e.pc == pc) {
			++e.calls;
			e.elems += vl;
			return;
		}
	}
	++g_overflow; // table full: recorded, never silently dropped
}

inline void dump(char const *path)
{
	if (!path || !*path)
		return;
	FILE *f = std::fopen(path, "w");
	if (!f)
		return;
	std::fprintf(f, "# rvv_pc_census v1 distinct_pcs=%u overflow=%llu\n", g_used,
		     (unsigned long long)g_overflow);
	std::fprintf(f, "pc,raw,family,handler_calls,handler_elems\n");
	for (unsigned i = 0; i < CAP; ++i) {
		Entry const &e = g_tab[i];
		if (e.calls == 0)
			continue;
		std::fprintf(f, "0x%08x,0x%08x,%s,%llu,%llu\n", e.pc, e.raw,
			     e.family ? e.family : "?", (unsigned long long)e.calls,
			     (unsigned long long)e.elems);
	}
	std::fclose(f);
}

} // namespace dbt::rv32::pc_census
