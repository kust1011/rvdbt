// C-beta SUBSTRATE (ISA/support work, NOT the thesis method): host gather for the guest's
// unordered indexed load. Compiled with -mavx2 in its own TU and reached only through a runtime
// CPUID check, so the SSE2 baseline is untouched.
//
// Why this is support work and not a contribution: mapping a guest indexed load onto a host gather
// instruction is a direct ISA mapping. It is implemented because its causal headroom bound is the
// largest clean one measured (16.5%, docs/N6B_CBETA_BOUND.md), and it is reported in its own
// ablation arm so its gain is never attributed to a method.
//
// ADMISSION RULE, and every clause is checkable before a single element is touched:
//   * UNORDERED only. RVV distinguishes vluxei (unordered, mop=01) from vloxei (ordered, mop=11).
//     Only the unordered form lets an implementation perform the element accesses in arbitrary
//     order, which is exactly what a host gather does. The ordered form keeps the reference.
//   * FAULT-FREEDOM IS PROVEN, NOT ASSUMED. A host gather that faults part-way cannot report a
//     precise vstart, so instead of recovering we refuse unless no access can fault: the index
//     vector is pre-scanned for its min and max byte offset and the whole touched range is checked
//     against mmu::range_mapped. If any page in it is unmapped, the fast path refuses and the
//     reference runs, faulting exactly as before. The pre-scan reads the same indices the gather
//     will use, so it cannot disagree with them.
//   * unmasked (vm=1), vstart == 0, and data EEW == index EEW == 4. Other widths, masks and a
//     non-zero vstart all fall through to the reference.
#include "dbt/guest/rv32_vector.h"
#include "dbt/mmu.h"

#include <immintrin.h>
#include <cstring>

namespace dbt::rv32::rvv_gather
{
// Reachability counters: a correctness A/B that passes because the path never ran is vacuous, so
// firing is reported and checked, not assumed.
extern "C" unsigned long long g_gather_calls = 0;
extern "C" unsigned long long g_gather_elems = 0;
extern "C" unsigned long long g_gather_attempts = 0;
extern "C" unsigned long long g_gather_unmapped = 0;


// Returns true if it performed the whole operation; false means the caller must run the reference.
extern "C" bool rvv_gather_e32_avx2(void *vs_void, unsigned vd, unsigned vs2, unsigned char *vmem,
				    unsigned base, unsigned vlen_bits, unsigned vl)
{
	auto &vs = *reinterpret_cast<VectorState *>(vs_void);
	g_gather_attempts++;
	if (vl == 0)
		return true;
	// Pre-scan: min/max of the byte offsets this gather would touch. Same reads the gather uses.
	unsigned lo = ~0u, hi = 0;
	for (unsigned e = 0; e < vl; ++e) {
		unsigned const off = (unsigned)vs.elem_u(vs2, e, 4, vlen_bits);
		unsigned const a = base + off; // u32 wrap matches the reference's addressing exactly
		if (a < lo)
			lo = a;
		if (a > hi)
			hi = a;
	}
	if (hi < lo)
		return false;
	// Fault-freedom obligation. 4 bytes per element, so the last touched byte is hi+3.
	if (!mmu::range_mapped(lo, (hi - lo) + 4)) {
		g_gather_unmapped++;
		return false;
	}

	g_gather_calls++;
	g_gather_elems += vl;
	unsigned e = 0;
	for (; e + 8 <= vl; e += 8) {
		int idx[8];
		for (unsigned k = 0; k < 8; ++k)
			idx[k] = (int)(unsigned)(base + (unsigned)vs.elem_u(vs2, e + k, 4, vlen_bits));
		__m256i const vidx = _mm256_loadu_si256((__m256i const *)idx);
		__m256i const g = _mm256_i32gather_epi32((int const *)vmem, vidx, 1);
		alignas(32) int out[8];
		_mm256_store_si256((__m256i *)out, g);
#ifdef RVDBT_FAULT_INJECT_GATHER
		// FAULT INJECTION, diagnostic builds only: corrupt one ACTIVE element so the oracle
		// can be shown to detect active-element corruption rather than passing vacuously.
		out[0] ^= 1;
#endif
		for (unsigned k = 0; k < 8; ++k)
			std::memcpy(vs.elem_ptr(vd, e + k, 4, vlen_bits), &out[k], 4);
	}
	for (; e < vl; ++e) {
		unsigned const off = (unsigned)vs.elem_u(vs2, e, 4, vlen_bits);
		std::memcpy(vs.elem_ptr(vd, e, 4, vlen_bits), vmem + (unsigned)(base + off), 4);
	}
	return true;
}

} // namespace dbt::rv32::rvv_gather
