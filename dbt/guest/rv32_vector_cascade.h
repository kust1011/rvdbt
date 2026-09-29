#pragma once

// Width cascade: pick the widest host width the CPU supports that fits the remaining active
// extent, then narrower powers of two, then leave the residue to the element path.
//
// The rule has no free parameter. The width set comes from CPUID and XCR0; the choice comes from
// the extent. No workload name, threshold or observed winner enters it.
//
// CAPABILITY IS PER (OPERATION CLASS, WIDTH), NOT PER WIDTH. FMA3 provides VEX-encoded 128-bit
// forms whenever AVX + FMA and the OS's XCR0 state are present -- it does not require AVX2. A
// cascade that offered FMA only at 256/512 would drop every short-extent fused multiply-add to
// the element path and preserve exactly the regressions it exists to remove, so there are two
// 16-byte kernel sets: the SSE2 baseline, always available, and a VEX-128 set with FMA.
//
// XCR0 matters because CPUID feature bits report what the SILICON has; they do not report whether
// the OS has enabled the register state. Executing a YMM or ZMM instruction when XCR0 has not
// enabled that state raises #UD. `__builtin_cpu_supports` on clang/gcc already consults XCR0 via
// __cpu_indicator_init, and the explicit XGETBV check below is kept as a second, independent
// gate rather than trusting one mechanism.

#include "dbt/util/common.h"

#include <cstdint>

extern "C" {
// SSE2 baseline, always linkable and always executable on x86-64.
uint32_t rvv_run_ialu16(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu16(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
// VEX-128 with FMA3: needs AVX + FMA + OS state.
uint32_t rvv_run_ialu16v(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu16v(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_fma16v(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
// AVX2 + FMA.
uint32_t rvv_run_ialu32(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu32(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_fma32(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
// AVX-512F/BW/DQ/VL + FMA.
uint32_t rvv_run_ialu64(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu64(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_fma64(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
// Splat forms: the scalar arrives as raw bits and is broadcast once, outside the chunk loop.
uint32_t rvv_run_ialu_vs16(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu_vs16(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_ialu_vs16v(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu_vs16v(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_fma_vs16v(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_ialu_vs32(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu_vs32(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_fma_vs32(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_ialu_vs64(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_falu_vs64(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
uint32_t rvv_run_fma_vs64(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
}

namespace dbt::rv32::rvv_cascade
{

// off      = the cascade is not used at all; the compile-time fixed width path runs (control)
// fixed16  = only the 16-byte tier, whatever the host supports (ablation control)
// fixed64  = only the 64-byte tier, when the host has it (ablation control)
// cascade  = widest supported tier that fits the remaining extent, descending
enum class Policy : unsigned { Off = 0, Fixed16 = 1, Fixed64 = 2, Cascade = 3 };

struct Caps {
	bool avx, fma, avx2, avx512;
	bool have16v() const { return avx && fma; }
	bool have32() const { return avx2 && fma; }
	bool have64() const { return avx512 && fma; }
};

inline Caps detect()
{
	Caps c{};
#ifdef RVDBT_DIAG_ASSUME_HOST_CAPS
	// OPAQUE_BOUNDARY diagnostic build only -- see rv32_vector.h's host_has_avx2() comment for
	// why __builtin_cpu_supports()/__cpu_model cannot be linked into an ad-hoc .aot.so here.
	c.avx = c.fma = c.avx2 = c.avx512 = true;
#elif defined(__x86_64__)
	__builtin_cpu_init();
	// XCR0: bit 1 SSE state, bit 2 YMM state, bits 5-7 opmask/ZMM_Hi256/Hi16_ZMM.
	unsigned eax = 0, edx = 0;
	bool osxsave = __builtin_cpu_supports("avx"); // implies OSXSAVE+XCR0 on clang/gcc
	unsigned long long xcr0 = 0;
	if (osxsave) {
		__asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
		xcr0 = ((unsigned long long)edx << 32) | eax;
	}
	bool const ymm_ok = (xcr0 & 0x6) == 0x6;	    // SSE + YMM state
	bool const zmm_ok = (xcr0 & 0xe6) == 0xe6;	    // + opmask, ZMM_Hi256, Hi16_ZMM
	c.avx = __builtin_cpu_supports("avx") && ymm_ok;
	c.fma = __builtin_cpu_supports("fma");
	c.avx2 = __builtin_cpu_supports("avx2") && ymm_ok;
	c.avx512 = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
		   __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512vl") &&
		   zmm_ok;
#endif
	return c;
}

inline Caps const &caps()
{
	static Caps const c = detect();
	return c;
}

// Which tiers a policy may use, widest first. Returned as a fixed array so the walk has no
// allocation and no branch beyond the tier test itself.
using RunVV = uint32_t (*)(void *, void const *, void const *, uint32_t, uint32_t, uint32_t);
using RunVS = uint32_t (*)(void *, void const *, uint64_t, uint32_t, uint32_t, uint32_t);
struct Tier {
	uint32_t bytes;
	RunVV ialu, falu, fma;
	RunVS ialu_vs, falu_vs, fma_vs;
};

// Cached tier table. tiers_for() writes up to 4 Tier records of 7 function pointers each into a
// stack array, and it was being called on EVERY guest vector instruction -- the table depends only
// on the policy and the host caps, both fixed for a run. Measured motivation: admitting one extra
// handler made a sparse workload 11.4% SLOWER, ~214 cycles per invocation of pure added overhead,
// which this rebuild dominates. Cached per policy; the builder below is unchanged.
struct TierTable {
	Tier t[4];
	u32 n;
};
inline u32 tiers_for(Policy p, Tier out[4]);
inline TierTable const &tiers_cached(Policy p)
{
	static TierTable tab[4] = {};
	static bool built[4] = {};
	u32 const i = (u32)p & 3;
	if (!built[i]) {
		tab[i].n = tiers_for(p, tab[i].t);
		built[i] = true;
	}
	return tab[i];
}

inline u32 tiers_for(Policy p, Tier out[4])
{
	Caps const &c = caps();
	u32 n = 0;
	auto push64 = [&] {
		out[n++] = {64,	  rvv_run_ialu64,    rvv_run_falu64,	rvv_run_fma64,
			    rvv_run_ialu_vs64, rvv_run_falu_vs64, rvv_run_fma_vs64};
	};
	auto push32 = [&] {
		out[n++] = {32,	  rvv_run_ialu32,    rvv_run_falu32,	rvv_run_fma32,
			    rvv_run_ialu_vs32, rvv_run_falu_vs32, rvv_run_fma_vs32};
	};
	auto push16 = [&] {
		// Prefer the VEX-128 set when it is available: same width, but it carries FMA.
		if (c.have16v())
			out[n++] = {16,	     rvv_run_ialu16v,	 rvv_run_falu16v,
				    rvv_run_fma16v,  rvv_run_ialu_vs16v, rvv_run_falu_vs16v,
				    rvv_run_fma_vs16v};
		else
			out[n++] = {16,	     rvv_run_ialu16, rvv_run_falu16, nullptr,
				    rvv_run_ialu_vs16, rvv_run_falu_vs16, nullptr};
	};
	switch (p) {
	case Policy::Cascade:
		if (c.have64())
			push64();
		if (c.have32())
			push32();
		push16();
		break;
	case Policy::Fixed64:
		if (c.have64())
			push64();
		break;
	case Policy::Fixed16:
		push16();
		break;
	default:
		break;
	}
	return n;
}

// Greedy descent over one register's active byte extent. Each tier consumes whole chunks of its
// own width from the remaining bytes; tiers are disjoint by construction because each starts
// where the previous stopped. Returns bytes consumed; the caller finishes the residue with the
// element path, which is the only thing below the narrowest tier.
// ---------------------------------------------------------------------------------------------
// Cycle Q width-retention census (docs/CYCLE_Q_PREREGISTRATION.md).
//
// The thesis problem is stated in terms of how much of the guest's data parallelism survives
// decomposition into fixed-width host chunks, and until now that quantity was not observable:
// the cascade picks a tier per extent and NOTHING recorded which tier ran. These counters record
// bytes of guest vector data consumed at each host tier width.
//
// Gated on the SAME compile-time switch as the admission counters, so timing binaries -- built
// with -DRVDBT_FAST_STATS=0 by CMakeLists.txt:85 -- delete it entirely and are bit-identical to
// before this patch. `residue_elems` in FastStats already covers the scalar fallback, so no
// counter is added there.
// ---------------------------------------------------------------------------------------------
#ifndef RVDBT_FAST_STATS
#define RVDBT_FAST_STATS 1
#endif
static constexpr bool kTierCensus = RVDBT_FAST_STATS != 0;

struct TierCensus {
	// index: 0 = 64 B, 1 = 32 B, 2 = 16 B, 3 = any other width the cascade may gain later
	unsigned long long bytes[4];
	unsigned long long calls[4];
};
inline TierCensus g_tier{};

ALWAYS_INLINE u32 tier_slot(u32 w) { return w == 64 ? 0 : w == 32 ? 1 : w == 16 ? 2 : 3; }

template <typename Pick>
ALWAYS_INLINE u32 run_extent(Tier const *t, u32 nt, void *d, void const *a, void const *b,
			     u32 bytes, u32 f6, u32 sew, Pick pick)
{
	u32 off = 0;
	for (u32 i = 0; i < nt && off < bytes; i++) {
		auto fn = pick(t[i]);
		if (!fn || t[i].bytes > bytes - off)
			continue;
		u32 const got = fn((char *)d + off, (char const *)a + off, (char const *)b + off,
				   bytes - off, f6, sew);
		if constexpr (kTierCensus) {
			u32 const s = tier_slot(t[i].bytes);
			g_tier.bytes[s] += got;
			g_tier.calls[s]++;
		}
		off += got;
	}
	return off;
}

// Greedy descent for the splat forms. Same disjoint-byte contract; the scalar is passed through
// as raw bits and each tier broadcasts it once.
template <typename Pick>
ALWAYS_INLINE u32 run_extent_vs(Tier const *t, u32 nt, void *d, void const *a, u64 sval, u32 bytes,
				u32 f6, u32 sew, Pick pick)
{
	u32 off = 0;
	for (u32 i = 0; i < nt && off < bytes; i++) {
		auto fn = pick(t[i]);
		if (!fn || t[i].bytes > bytes - off)
			continue;
		u32 const got = fn((char *)d + off, (char const *)a + off, sval, bytes - off, f6, sew);
		if constexpr (kTierCensus) {
			u32 const s = tier_slot(t[i].bytes);
			g_tier.bytes[s] += got;
			g_tier.calls[s]++;
		}
		off += got;
	}
	return off;
}

} // namespace dbt::rv32::rvv_cascade
