#pragma once

// Width-parametric decomposition of scalable RVV operations onto FIXED-WIDTH host vectors.
//
// This is the substrate's central idea, and it is deliberately expressed ONCE, in one rule:
//
//     a guest vector register is VLEN bits; the host executes CHUNK bits at a time;
//     therefore each guest register is  chunks_per_reg = VLEN / CHUNK  host operations,
//     and a vl-element operation spans  full_regs = vl / elems_per_reg  whole registers
//     plus one partial register holding  tail_elems = vl % elems_per_reg  elements.
//
// Every quantity is DERIVED from (VLEN, vl, element width, host chunk width). Nothing here
// branches on a specific VLEN. VLEN=512 and VLEN=1024 execute the identical code and differ
// only in the value of `chunks_per_reg` (4 vs 8 at CHUNK=128), which is exactly the property
// the AVX-512 stage needs: at CHUNK=512 the same rule yields 1 and 2 ZMM chunks.
//
// Local host has SSE2 but NOT AVX-512, so the executable path here is 128-bit. The scalar
// element-at-a-time reference (rvv_ref::) stays as the oracle and the fallback; the two are
// cross-checked at runtime under --rvv-verify.
//
// TAIL POLICY: elements at index >= vl are left UNDISTURBED. A chunk is only used when it lies
// entirely below vl; the sub-chunk remainder is finished element-wise. This is what keeps the
// fixed-width path from writing past vl -- the single most likely way a decomposition like this
// silently corrupts state.

#include <type_traits>
#include "dbt/config.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_softfp.h"
#include "dbt/mmu.h"
#include "dbt/guest/rv32_vector.h"

#include <immintrin.h>

namespace dbt::rv32
{

// ---------------------------------------------------------------------------------------------
// The host chunk primitive. This is the ONLY width-dependent code in the file: the plan, the
// loops and the tail policy below are written against these three operations and never mention
// a width. Selected at compile time by RVV_HOST_CHUNK_BITS, which defaults to 128 because that
// is what this machine can EXECUTE.
//
// The 512-bit instantiation is what the P5 artifact compiles (with -mavx512f -mavx512bw) to
// show that the identical decomposition yields one ZMM chunk at VLEN=512 and two independent
// ZMM chunks at VLEN=1024. It is never linked into elfrun and never executed here.
// ---------------------------------------------------------------------------------------------
#ifndef RVV_HOST_CHUNK_BITS
#define RVV_HOST_CHUNK_BITS 128
#endif

#if RVV_HOST_CHUNK_BITS == 128
using host_chunk_t = __m128i;
ALWAYS_INLINE host_chunk_t chunk_load(void const *p) { return _mm_loadu_si128((__m128i const *)p); }
ALWAYS_INLINE void chunk_store(void *p, host_chunk_t v) { _mm_storeu_si128((__m128i *)p, v); }
ALWAYS_INLINE host_chunk_t chunk_add(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm_add_epi8(a, b);
	case 2:
		return _mm_add_epi16(a, b);
	case 4:
		return _mm_add_epi32(a, b);
	default:
		return _mm_add_epi64(a, b);
	}
}
ALWAYS_INLINE host_chunk_t chunk_mul(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	// Only SEW 2 and 4 have a direct packed low-half multiply. SEW 1 and 8 do not, and are
	// refused by ialu_class_supported so the reference path keeps them rather than being
	// emulated here, which would risk a semantic gap for no coverage gain.
	// SSE2 baseline: only _mm_mullo_epi16 exists. _mm_mullo_epi32 is SSE4.1, which this TU is
	// deliberately not compiled with -- the SSE2 fallback is a hard requirement. SEW=4 is
	// therefore refused here and would need the runtime-CPUID multiversioning treatment that
	// host_has_fma() uses, which is NOT done.
	return _mm_mullo_epi16(a, b);
}
#elif RVV_HOST_CHUNK_BITS == 256
using host_chunk_t = __m256i;
ALWAYS_INLINE host_chunk_t chunk_load(void const *p) { return _mm256_loadu_si256((__m256i const *)p); }
ALWAYS_INLINE void chunk_store(void *p, host_chunk_t v) { _mm256_storeu_si256((__m256i *)p, v); }
ALWAYS_INLINE host_chunk_t chunk_add(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm256_add_epi8(a, b);
	case 2:
		return _mm256_add_epi16(a, b);
	case 4:
		return _mm256_add_epi32(a, b);
	default:
		return _mm256_add_epi64(a, b);
	}
}
ALWAYS_INLINE host_chunk_t chunk_mul(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	// Only SEW 2 and 4 have a direct packed low-half multiply. SEW 1 and 8 do not, and are
	// refused by ialu_class_supported so the reference path keeps them rather than being
	// emulated here, which would risk a semantic gap for no coverage gain.
	return sew_bytes == 2 ? _mm256_mullo_epi16(a, b) : _mm256_mullo_epi32(a, b);
}
#elif RVV_HOST_CHUNK_BITS == 512
using host_chunk_t = __m512i;
ALWAYS_INLINE host_chunk_t chunk_load(void const *p) { return _mm512_loadu_si512(p); }
ALWAYS_INLINE void chunk_store(void *p, host_chunk_t v) { _mm512_storeu_si512(p, v); }
ALWAYS_INLINE host_chunk_t chunk_add(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm512_add_epi8(a, b); // AVX-512BW
	case 2:
		return _mm512_add_epi16(a, b); // AVX-512BW
	case 4:
		return _mm512_add_epi32(a, b);
	default:
		return _mm512_add_epi64(a, b);
	}
}
ALWAYS_INLINE host_chunk_t chunk_mul(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	// Only SEW 2 and 4 have a direct packed low-half multiply. SEW 1 and 8 do not, and are
	// refused by ialu_class_supported so the reference path keeps them rather than being
	// emulated here, which would risk a semantic gap for no coverage gain.
	return sew_bytes == 2 ? _mm512_mullo_epi16(a, b) : _mm512_mullo_epi32(a, b);
}
#else
#error "RVV_HOST_CHUNK_BITS must be 128, 256 or 512"
#endif

// ---------------------------------------------------------------------------------------------
// P13 phase C: the rest of the width-dependent primitive set.
//
// Everything above this point is P12's: load, store and integer add. The method needs three more
// integer operations and a floating-point chunk type, and -- crucially -- a packed RISC-V
// canonicalisation, which is what makes a packed FP result equal the element-wise reference
// instead of merely approximating it (docs/B1_SEMANTIC_OBLIGATIONS.md SS0.1).
//
// This is still the ONLY width-dependent code. Everything in rv32_vector_fast.h is written
// against these names and never mentions a width.
// ---------------------------------------------------------------------------------------------
static constexpr u32 RVV_CANON_F32 = 0x7fc00000u;
static constexpr u64 RVV_CANON_F64 = 0x7ff8000000000000ull;

#if RVV_HOST_CHUNK_BITS == 128
ALWAYS_INLINE host_chunk_t chunk_sub(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm_sub_epi8(a, b);
	case 2:
		return _mm_sub_epi16(a, b);
	case 4:
		return _mm_sub_epi32(a, b);
	default:
		return _mm_sub_epi64(a, b);
	}
}
ALWAYS_INLINE host_chunk_t chunk_and(host_chunk_t a, host_chunk_t b) { return _mm_and_si128(a, b); }
ALWAYS_INLINE host_chunk_t chunk_or(host_chunk_t a, host_chunk_t b) { return _mm_or_si128(a, b); }
ALWAYS_INLINE host_chunk_t chunk_xor(host_chunk_t a, host_chunk_t b) { return _mm_xor_si128(a, b); }
// The .vx and .vi forms are the SAME semantic class as .vv -- only the second operand's origin
// differs -- so they are served by broadcasting the scalar once per operation rather than by a
// separate fast path. Excluding them would be exactly the per-opcode behaviour this method exists
// to replace.
ALWAYS_INLINE host_chunk_t chunk_splat(u64 v, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm_set1_epi8((char)v);
	case 2:
		return _mm_set1_epi16((short)v);
	case 4:
		return _mm_set1_epi32((int)v);
	default:
		return _mm_set1_epi64x((long long)v);
	}
}

using host_fchunk32_t = __m128;
using host_fchunk64_t = __m128d;
ALWAYS_INLINE host_fchunk32_t fchunk32_load(void const *p) { return _mm_loadu_ps((float const *)p); }
ALWAYS_INLINE void fchunk32_store(void *p, host_fchunk32_t v) { _mm_storeu_ps((float *)p, v); }
ALWAYS_INLINE host_fchunk32_t fchunk32_add(host_fchunk32_t a, host_fchunk32_t b) { return _mm_add_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_sub(host_fchunk32_t a, host_fchunk32_t b) { return _mm_sub_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_mul(host_fchunk32_t a, host_fchunk32_t b) { return _mm_mul_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_div(host_fchunk32_t a, host_fchunk32_t b) { return _mm_div_ps(a, b); }
// Compare, packed mask-bit result (one bit per lane, low N bits meaningful): one primitive per
// PREDICATE, same pattern as add/sub/mul/div -- the RVV funct6 switch that picks among them lives
// in rv32_vector_fast.h (mirroring falu_chunk), not here, because the VF6_VMF* constants are
// declared later in this file than the width-tiered primitive sections. GT/GE are not given their
// own primitive: RVV's own spec omits vmfgt.vv/vmfge.vv from the .vv encoding on the assumption
// that a real implementation swaps operands and reuses LT/LE (exact, not an approximation -- NaN
// detection and the LT/LE predicate are both symmetric under the swap), so the caller does that
// swap and calls fchunk32_cmp_lt/le. Predicate suffixes (_OQ quiet / _OS signalling / _UQ
// quiet-unordered) match rvv_ref::vfcmp's own `quiet` flag EXACTLY (only EQ/NE are quiet) so the
// hardware's own MXCSR invalid flag lands on FFLAG_NV through the same FRound exception harvest
// arithmetic already uses -- no separate isnan/snan branch needed. All four predicates used here
// (EQ_OQ=0, LT_OS=1, LE_OS=2, NEQ_UQ=4) fit the legacy 3-bit encoding, so this compiles to plain
// SSE `cmpps`/`cmppd` and needs no AVX on this (128-bit) tier.
ALWAYS_INLINE u32 fchunk32_cmp_eq(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm_movemask_ps(_mm_cmp_ps(a, b, _CMP_EQ_OQ));
}
ALWAYS_INLINE u32 fchunk32_cmp_ne(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm_movemask_ps(_mm_cmp_ps(a, b, _CMP_NEQ_UQ));
}
ALWAYS_INLINE u32 fchunk32_cmp_lt(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm_movemask_ps(_mm_cmp_ps(a, b, _CMP_LT_OS));
}
ALWAYS_INLINE u32 fchunk32_cmp_le(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm_movemask_ps(_mm_cmp_ps(a, b, _CMP_LE_OS));
}
// RISC-V: a NaN an operation PRODUCES is the canonical quiet NaN and an input payload is never
// propagated. That is a lane-wise select on `isnan`, i.e. an unordered self-compare.
ALWAYS_INLINE host_fchunk32_t fchunk32_canon(host_fchunk32_t r)
{
	__m128 const m = _mm_cmpunord_ps(r, r);
	__m128 const c = _mm_castsi128_ps(_mm_set1_epi32((int)RVV_CANON_F32));
	return _mm_or_ps(_mm_and_ps(m, c), _mm_andnot_ps(m, r));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_load(void const *p) { return _mm_loadu_pd((double const *)p); }
ALWAYS_INLINE void fchunk64_store(void *p, host_fchunk64_t v) { _mm_storeu_pd((double *)p, v); }
ALWAYS_INLINE host_fchunk64_t fchunk64_add(host_fchunk64_t a, host_fchunk64_t b) { return _mm_add_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_sub(host_fchunk64_t a, host_fchunk64_t b) { return _mm_sub_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_mul(host_fchunk64_t a, host_fchunk64_t b) { return _mm_mul_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_div(host_fchunk64_t a, host_fchunk64_t b) { return _mm_div_pd(a, b); }
ALWAYS_INLINE u32 fchunk64_cmp_eq(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm_movemask_pd(_mm_cmp_pd(a, b, _CMP_EQ_OQ));
}
ALWAYS_INLINE u32 fchunk64_cmp_ne(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm_movemask_pd(_mm_cmp_pd(a, b, _CMP_NEQ_UQ));
}
ALWAYS_INLINE u32 fchunk64_cmp_lt(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm_movemask_pd(_mm_cmp_pd(a, b, _CMP_LT_OS));
}
ALWAYS_INLINE u32 fchunk64_cmp_le(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm_movemask_pd(_mm_cmp_pd(a, b, _CMP_LE_OS));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_canon(host_fchunk64_t r)
{
	__m128d const m = _mm_cmpunord_pd(r, r);
	__m128d const c = _mm_castsi128_pd(_mm_set1_epi64x((long long)RVV_CANON_F64));
	return _mm_or_pd(_mm_and_pd(m, c), _mm_andnot_pd(m, r));
}
ALWAYS_INLINE host_fchunk32_t fchunk32_splat(float v) { return _mm_set1_ps(v); }
// Fused multiply-add. RVV's vfmacc/vfmadd family rounds ONCE, and so does x86 FMA3, so the two
// agree exactly; without FMA3 the reference falls back to a libm fma() and the fast path must not
// be admitted at all, which is why this is compiled only when the host has it.
#ifdef __FMA__
ALWAYS_INLINE host_fchunk32_t fchunk32_fma(host_fchunk32_t x, host_fchunk32_t y, host_fchunk32_t z)
{
	return _mm_fmadd_ps(x, y, z);
}
ALWAYS_INLINE host_fchunk64_t fchunk64_fma(host_fchunk64_t x, host_fchunk64_t y, host_fchunk64_t z)
{
	return _mm_fmadd_pd(x, y, z);
}
#endif
// Sign flip is a bit operation, exact for every value including NaN and zero.
ALWAYS_INLINE host_fchunk32_t fchunk32_neg(host_fchunk32_t x)
{
	return _mm_xor_ps(x, _mm_castsi128_ps(_mm_set1_epi32((int)0x80000000u)));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_neg(host_fchunk64_t x)
{
	return _mm_xor_pd(x, _mm_castsi128_pd(_mm_set1_epi64x((long long)0x8000000000000000ull)));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_splat(double v) { return _mm_set1_pd(v); }

#elif RVV_HOST_CHUNK_BITS == 256
ALWAYS_INLINE host_chunk_t chunk_sub(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm256_sub_epi8(a, b);
	case 2:
		return _mm256_sub_epi16(a, b);
	case 4:
		return _mm256_sub_epi32(a, b);
	default:
		return _mm256_sub_epi64(a, b);
	}
}
ALWAYS_INLINE host_chunk_t chunk_and(host_chunk_t a, host_chunk_t b) { return _mm256_and_si256(a, b); }
ALWAYS_INLINE host_chunk_t chunk_or(host_chunk_t a, host_chunk_t b) { return _mm256_or_si256(a, b); }
ALWAYS_INLINE host_chunk_t chunk_xor(host_chunk_t a, host_chunk_t b) { return _mm256_xor_si256(a, b); }
ALWAYS_INLINE host_chunk_t chunk_splat(u64 v, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm256_set1_epi8((char)v);
	case 2:
		return _mm256_set1_epi16((short)v);
	case 4:
		return _mm256_set1_epi32((int)v);
	default:
		return _mm256_set1_epi64x((long long)v);
	}
}

using host_fchunk32_t = __m256;
using host_fchunk64_t = __m256d;
ALWAYS_INLINE host_fchunk32_t fchunk32_load(void const *p) { return _mm256_loadu_ps((float const *)p); }
ALWAYS_INLINE void fchunk32_store(void *p, host_fchunk32_t v) { _mm256_storeu_ps((float *)p, v); }
ALWAYS_INLINE host_fchunk32_t fchunk32_add(host_fchunk32_t a, host_fchunk32_t b) { return _mm256_add_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_sub(host_fchunk32_t a, host_fchunk32_t b) { return _mm256_sub_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_mul(host_fchunk32_t a, host_fchunk32_t b) { return _mm256_mul_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_div(host_fchunk32_t a, host_fchunk32_t b) { return _mm256_div_ps(a, b); }
// See the 128-bit tier's fchunk32_cmp_* for the full rationale (predicate choice, GT/GE-via-swap,
// no separate NaN/sNaN branch). AVX2 gives the extended 32-predicate imm8 range natively.
ALWAYS_INLINE u32 fchunk32_cmp_eq(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm256_movemask_ps(_mm256_cmp_ps(a, b, _CMP_EQ_OQ));
}
ALWAYS_INLINE u32 fchunk32_cmp_ne(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm256_movemask_ps(_mm256_cmp_ps(a, b, _CMP_NEQ_UQ));
}
ALWAYS_INLINE u32 fchunk32_cmp_lt(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm256_movemask_ps(_mm256_cmp_ps(a, b, _CMP_LT_OS));
}
ALWAYS_INLINE u32 fchunk32_cmp_le(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm256_movemask_ps(_mm256_cmp_ps(a, b, _CMP_LE_OS));
}
ALWAYS_INLINE host_fchunk32_t fchunk32_canon(host_fchunk32_t r)
{
	__m256 const m = _mm256_cmp_ps(r, r, _CMP_UNORD_Q);
	__m256 const c = _mm256_castsi256_ps(_mm256_set1_epi32((int)RVV_CANON_F32));
	return _mm256_blendv_ps(r, c, m);
}
ALWAYS_INLINE host_fchunk64_t fchunk64_load(void const *p) { return _mm256_loadu_pd((double const *)p); }
ALWAYS_INLINE void fchunk64_store(void *p, host_fchunk64_t v) { _mm256_storeu_pd((double *)p, v); }
ALWAYS_INLINE host_fchunk64_t fchunk64_add(host_fchunk64_t a, host_fchunk64_t b) { return _mm256_add_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_sub(host_fchunk64_t a, host_fchunk64_t b) { return _mm256_sub_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_mul(host_fchunk64_t a, host_fchunk64_t b) { return _mm256_mul_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_div(host_fchunk64_t a, host_fchunk64_t b) { return _mm256_div_pd(a, b); }
ALWAYS_INLINE u32 fchunk64_cmp_eq(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm256_movemask_pd(_mm256_cmp_pd(a, b, _CMP_EQ_OQ));
}
ALWAYS_INLINE u32 fchunk64_cmp_ne(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm256_movemask_pd(_mm256_cmp_pd(a, b, _CMP_NEQ_UQ));
}
ALWAYS_INLINE u32 fchunk64_cmp_lt(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm256_movemask_pd(_mm256_cmp_pd(a, b, _CMP_LT_OS));
}
ALWAYS_INLINE u32 fchunk64_cmp_le(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm256_movemask_pd(_mm256_cmp_pd(a, b, _CMP_LE_OS));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_canon(host_fchunk64_t r)
{
	__m256d const m = _mm256_cmp_pd(r, r, _CMP_UNORD_Q);
	__m256d const c = _mm256_castsi256_pd(_mm256_set1_epi64x((long long)RVV_CANON_F64));
	return _mm256_blendv_pd(r, c, m);
}
ALWAYS_INLINE host_fchunk32_t fchunk32_splat(float v) { return _mm256_set1_ps(v); }
#ifdef __FMA__
ALWAYS_INLINE host_fchunk32_t fchunk32_fma(host_fchunk32_t x, host_fchunk32_t y, host_fchunk32_t z)
{
	return _mm256_fmadd_ps(x, y, z);
}
ALWAYS_INLINE host_fchunk64_t fchunk64_fma(host_fchunk64_t x, host_fchunk64_t y, host_fchunk64_t z)
{
	return _mm256_fmadd_pd(x, y, z);
}
#endif
ALWAYS_INLINE host_fchunk32_t fchunk32_neg(host_fchunk32_t x)
{
	return _mm256_xor_ps(x, _mm256_castsi256_ps(_mm256_set1_epi32((int)0x80000000u)));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_neg(host_fchunk64_t x)
{
	return _mm256_xor_pd(x,
			     _mm256_castsi256_pd(_mm256_set1_epi64x((long long)0x8000000000000000ull)));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_splat(double v) { return _mm256_set1_pd(v); }

#else // 512
ALWAYS_INLINE host_chunk_t chunk_sub(host_chunk_t a, host_chunk_t b, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm512_sub_epi8(a, b);
	case 2:
		return _mm512_sub_epi16(a, b);
	case 4:
		return _mm512_sub_epi32(a, b);
	default:
		return _mm512_sub_epi64(a, b);
	}
}
ALWAYS_INLINE host_chunk_t chunk_and(host_chunk_t a, host_chunk_t b) { return _mm512_and_si512(a, b); }
ALWAYS_INLINE host_chunk_t chunk_or(host_chunk_t a, host_chunk_t b) { return _mm512_or_si512(a, b); }
ALWAYS_INLINE host_chunk_t chunk_xor(host_chunk_t a, host_chunk_t b) { return _mm512_xor_si512(a, b); }
ALWAYS_INLINE host_chunk_t chunk_splat(u64 v, u32 sew_bytes)
{
	switch (sew_bytes) {
	case 1:
		return _mm512_set1_epi8((char)v);
	case 2:
		return _mm512_set1_epi16((short)v);
	case 4:
		return _mm512_set1_epi32((int)v);
	default:
		return _mm512_set1_epi64((long long)v);
	}
}

using host_fchunk32_t = __m512;
using host_fchunk64_t = __m512d;
ALWAYS_INLINE host_fchunk32_t fchunk32_load(void const *p) { return _mm512_loadu_ps((float const *)p); }
ALWAYS_INLINE void fchunk32_store(void *p, host_fchunk32_t v) { _mm512_storeu_ps((float *)p, v); }
ALWAYS_INLINE host_fchunk32_t fchunk32_add(host_fchunk32_t a, host_fchunk32_t b) { return _mm512_add_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_sub(host_fchunk32_t a, host_fchunk32_t b) { return _mm512_sub_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_mul(host_fchunk32_t a, host_fchunk32_t b) { return _mm512_mul_ps(a, b); }
ALWAYS_INLINE host_fchunk32_t fchunk32_div(host_fchunk32_t a, host_fchunk32_t b) { return _mm512_div_ps(a, b); }
// See the 128-bit tier's fchunk32_cmp_* for the full rationale (predicate choice, GT/GE-via-swap,
// no separate NaN/sNaN branch). AVX-512 gives the mask directly (__mmask16), no movemask step.
ALWAYS_INLINE u32 fchunk32_cmp_eq(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm512_cmp_ps_mask(a, b, _CMP_EQ_OQ);
}
ALWAYS_INLINE u32 fchunk32_cmp_ne(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm512_cmp_ps_mask(a, b, _CMP_NEQ_UQ);
}
ALWAYS_INLINE u32 fchunk32_cmp_lt(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm512_cmp_ps_mask(a, b, _CMP_LT_OS);
}
ALWAYS_INLINE u32 fchunk32_cmp_le(host_fchunk32_t a, host_fchunk32_t b)
{
	return (u32)_mm512_cmp_ps_mask(a, b, _CMP_LE_OS);
}
// AVX-512 gives the isnan test as a MASK register directly, so the select is a masked blend and
// no compare result has to be materialised in a vector register.
ALWAYS_INLINE host_fchunk32_t fchunk32_canon(host_fchunk32_t r)
{
	__mmask16 const m = _mm512_cmp_ps_mask(r, r, _CMP_UNORD_Q);
	__m512 const c = _mm512_castsi512_ps(_mm512_set1_epi32((int)RVV_CANON_F32));
	return _mm512_mask_blend_ps(m, r, c);
}
ALWAYS_INLINE host_fchunk64_t fchunk64_load(void const *p) { return _mm512_loadu_pd((double const *)p); }
ALWAYS_INLINE void fchunk64_store(void *p, host_fchunk64_t v) { _mm512_storeu_pd((double *)p, v); }
ALWAYS_INLINE host_fchunk64_t fchunk64_add(host_fchunk64_t a, host_fchunk64_t b) { return _mm512_add_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_sub(host_fchunk64_t a, host_fchunk64_t b) { return _mm512_sub_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_mul(host_fchunk64_t a, host_fchunk64_t b) { return _mm512_mul_pd(a, b); }
ALWAYS_INLINE host_fchunk64_t fchunk64_div(host_fchunk64_t a, host_fchunk64_t b) { return _mm512_div_pd(a, b); }
ALWAYS_INLINE u32 fchunk64_cmp_eq(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm512_cmp_pd_mask(a, b, _CMP_EQ_OQ);
}
ALWAYS_INLINE u32 fchunk64_cmp_ne(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm512_cmp_pd_mask(a, b, _CMP_NEQ_UQ);
}
ALWAYS_INLINE u32 fchunk64_cmp_lt(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm512_cmp_pd_mask(a, b, _CMP_LT_OS);
}
ALWAYS_INLINE u32 fchunk64_cmp_le(host_fchunk64_t a, host_fchunk64_t b)
{
	return (u32)_mm512_cmp_pd_mask(a, b, _CMP_LE_OS);
}
ALWAYS_INLINE host_fchunk64_t fchunk64_canon(host_fchunk64_t r)
{
	__mmask8 const m = _mm512_cmp_pd_mask(r, r, _CMP_UNORD_Q);
	__m512d const c = _mm512_castsi512_pd(_mm512_set1_epi64((long long)RVV_CANON_F64));
	return _mm512_mask_blend_pd(m, r, c);
}
ALWAYS_INLINE host_fchunk32_t fchunk32_splat(float v) { return _mm512_set1_ps(v); }
#ifdef __FMA__
ALWAYS_INLINE host_fchunk32_t fchunk32_fma(host_fchunk32_t x, host_fchunk32_t y, host_fchunk32_t z)
{
	return _mm512_fmadd_ps(x, y, z);
}
ALWAYS_INLINE host_fchunk64_t fchunk64_fma(host_fchunk64_t x, host_fchunk64_t y, host_fchunk64_t z)
{
	return _mm512_fmadd_pd(x, y, z);
}
#endif
ALWAYS_INLINE host_fchunk32_t fchunk32_neg(host_fchunk32_t x)
{
	return _mm512_castsi512_ps(
	    _mm512_xor_si512(_mm512_castps_si512(x), _mm512_set1_epi32((int)0x80000000u)));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_neg(host_fchunk64_t x)
{
	return _mm512_castsi512_pd(_mm512_xor_si512(
	    _mm512_castpd_si512(x), _mm512_set1_epi64((long long)0x8000000000000000ull)));
}
ALWAYS_INLINE host_fchunk64_t fchunk64_splat(double v) { return _mm512_set1_pd(v); }
#endif

// Host fixed-width chunk, in bytes. Derived from the selected primitive.
static constexpr u32 HOST_CHUNK_BYTES = RVV_HOST_CHUNK_BITS / 8;

// Derived shape of one vector operation. Constructed from the architectural parameters only.
struct ChunkPlan {
	u32 vlen_bytes;	    // VLEN/8
	u32 elem_bytes;	    // EEW/8 for loads/stores, SEW/8 for arithmetic
	u32 elems_per_reg;  // vlen_bytes / elem_bytes
	u32 full_regs;	    // registers covered completely by vl
	u32 tail_elems;	    // elements in the trailing partial register (0 if vl divides evenly)
	u32 chunks_per_reg; // vlen_bytes / HOST_CHUNK_BYTES -- the width-parametric chunk count
};

inline ChunkPlan make_chunk_plan(u32 vlen_bits, u32 vl, u32 elem_bytes)
{
	ChunkPlan p{};
	p.vlen_bytes = vlen_bits / 8;
	p.elem_bytes = elem_bytes;
	p.elems_per_reg = p.vlen_bytes / elem_bytes;
	p.full_regs = vl / p.elems_per_reg;
	p.tail_elems = vl % p.elems_per_reg;
	p.chunks_per_reg = p.vlen_bytes / HOST_CHUNK_BYTES;
	return p;
}

// Runtime evidence counters. Zero-cost on the fast path (plain increments, no atomics -- rvdbt
// guest execution here is single-threaded) and dumped by elfrun under --rvv-stats, so the
// "how much actually ran on host vectors vs fell back" question is answered by measurement
// rather than by reading the source.
struct RvvStats {
	unsigned long long chunk_ops;	 // 128-bit host operations executed
	unsigned long long tail_elems;	 // elements finished element-wise below a full chunk
	unsigned long long ref_fallback; // ops that took the scalar reference path entirely
	unsigned long long verify_ok;	 // ops cross-checked against the reference and matching
	unsigned long long verify_fail;	 // ops where the two paths disagreed (must stay 0)
};
inline RvvStats g_rvv_stats{};

// ---------------------------------------------------------------------------------------------
// A13-FIX (2026-09-05). THE UNIT-STRIDE ADDRESS CONTRACT, shared by the scalar reference, the
// chunked helper and (through the frame guard) the direct QCG frames.
//
// RV32 forms every effective address modulo 2^XLEN (unpriv spec, "Memory" / v-ext 7.x: the
// address of element e of a unit-stride access is base + e*EEW, as an XLEN-bit value). Every byte
// of the access therefore lives at (u32)(base + i), and an access whose span reaches 2^32 continues
// at guest address 0. In this system the low MIN_MMAP_ADDR bytes are never mapped, so such a
// wrapped byte faults through the ordinary guest-fault path (host SIGSEGV -> GUEST_FAULT at the
// instruction's pc -> terminate). What must NOT happen is the previous behaviour: `vmem + base`
// walked as a HOST pointer past 2^32 into whatever host mapping follows the guest reservation,
// silently reading or writing host memory.
//
// The rule is applied at BYTE granularity: an element that itself straddles 2^32 is copied byte
// by byte with each byte's own wrapped address, and an inactive (masked-off) element or a byte
// past vl is never touched, so a wrap that only the unaccessed part of the span would reach does
// not fault. Spans that do not reach 2^32 keep the unchanged fast copies.
// ---------------------------------------------------------------------------------------------
ALWAYS_INLINE bool guest_span_wraps(u32 base, u32 bytes)
{
	return bytes != 0 && ((u64)base + (u64)bytes) > 0x1'0000'0000ull;
}
// dst[0..bytes) <- guest bytes at (u32)(gaddr + i), each with its own wrapped address.
ALWAYS_INLINE void guest_load_bytes_wrapped(u8 *dst, u8 const *vmem, u32 gaddr, u32 bytes)
{
	// Wrapped accesses must not be combined into a host load past the guest reservation.
	u8 const volatile *memory = vmem;
	for (u32 i = 0; i < bytes; ++i)
		dst[i] = memory[(u32)(gaddr + i)];
}
ALWAYS_INLINE void guest_store_bytes_wrapped(u8 *vmem, u32 gaddr, u8 const *src, u32 bytes)
{
	u8 volatile *memory = vmem;
	for (u32 i = 0; i < bytes; ++i)
		memory[(u32)(gaddr + i)] = src[i];
}
// One element: the fast memcpy when its bytes do not reach 2^32, the wrapped byte copy otherwise.
ALWAYS_INLINE void guest_load_elem(u8 *dst, u8 const *vmem, u32 gaddr, u32 bytes)
{
	if (likely(!guest_span_wraps(gaddr, bytes)))
		std::memcpy(dst, vmem + gaddr, bytes);
	else
		guest_load_bytes_wrapped(dst, vmem, gaddr, bytes);
}
ALWAYS_INLINE void guest_store_elem(u8 *vmem, u32 gaddr, u8 const *src, u32 bytes)
{
	if (likely(!guest_span_wraps(gaddr, bytes)))
		std::memcpy(vmem + gaddr, src, bytes);
	else
		guest_store_bytes_wrapped(vmem, gaddr, src, bytes);
}

// ---------------------------------------------------------------------------------------------
// Reference (oracle) implementations: one element at a time, straight from the spec wording.
// These are also the fallback whenever the fixed-width path is disabled or inapplicable.
// ---------------------------------------------------------------------------------------------
namespace rvv_ref
{

inline void load_unit_stride(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits, u32 vl,
			     u32 eew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		vs.vstart=e;
		u8 *dst = vs.elem_ptr(vd, e, eew_bytes, vlen_bits);
		guest_load_elem(dst, vmem, (u32)(base + e * eew_bytes), eew_bytes); // A13-FIX
	}
	vs.vstart=0;
}

inline void store_unit_stride(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 vlen_bits, u32 vl,
			      u32 eew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		vs.vstart=e;
		u8 const *src = vs.elem_ptr(vs3, e, eew_bytes, vlen_bits);
		guest_store_elem(vmem, (u32)(base + e * eew_bytes), src, eew_bytes); // A13-FIX
	}
	vs.vstart=0;
}

// ---- strided access ------------------------------------------------------------------------
// vlse<EEW>.v / vsse<EEW>.v: element e lives at base + e*stride, where stride is a SIGNED byte
// count taken from a scalar register (so a negative stride walks backwards, and a zero stride
// broadcasts / repeatedly overwrites -- both legal). Distinct family from unit-stride because
// the address progression is data-dependent, which is exactly why it cannot use the chunked
// path: consecutive elements are not contiguous in memory.
inline void load_strided(VectorState &vs, u32 vd, u8 *vmem, u32 base, i32 stride, u32 vlen_bits,
			 u32 vl, u32 eew_bytes, bool vm)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		vs.vstart=e;
		guest_load_elem(vs.elem_ptr(vd,e,eew_bytes,vlen_bits),vmem,base+e*(u32)stride,eew_bytes);
	}
	vs.vstart=0;
}

inline void store_strided(VectorState &vs, u32 vs3, u8 *vmem, u32 base, i32 stride, u32 vlen_bits,
			  u32 vl, u32 eew_bytes, bool vm)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		vs.vstart=e;
		guest_store_elem(vmem,base+e*(u32)stride,vs.elem_ptr(vs3,e,eew_bytes,vlen_bits),eew_bytes);
	}
	vs.vstart=0;
}

// ---- fault-only-first load: vle<EEW>ff.v ------------------------------------------------------
//
// The distinguishing behaviour is NOT the load; it is what happens when an element cannot be
// loaded. Element vstart (the first one this execution is responsible for) faults exactly like an
// ordinary load. Any LATER element that would fault instead TRIMS vl to that index and completes
// without trapping, so the guest sees a short vector and re-executes from there. That is what
// lets a strlen-style loop read up to a page boundary without knowing where the data ends.
//
// A fault is PREDICTED from mmu's existing page map rather than taken. Taking it is not an
// option: the access happens inside a memcpy in a helper called from generated code, and there is
// no unwind path back out of the signal handler (ukernel.cpp:149 diagnoses the fault precisely
// and then panics).
//
// THE PREDICATE IS GUEST READ PERMISSION, NOT PAGE PRESENCE. `mapped_pages` answers whether a page
// exists; what decides whether a load faults is whether the GUEST may read it, and the two differ
// on PROT_NONE, on write-only, and on the guard page ukernel maps at the top of the address space.
// Reading the mapped-only predicate here would let a write-only page through -- and on x86 the host
// mapping made for it IS readable, so the memcpy below would quietly succeed and hand the guest
// bytes the architecture says it cannot see. mmu::range_readable is the permission predicate.
//
// Three rules that are easy to get wrong and are written out explicitly:
//   * a masked-off element must NOT fault and must NOT trim -- it is not accessed at all;
//   * the check is per PAGE RANGE, not per starting address, because an element may straddle a
//     boundary into an unmapped page;
//   * ELEMENT 0 IS THE ONE THAT MAY TRAP, AND THAT IS THE ARCHITECTURAL INDEX 0 -- not "the first
//     element this execution owns". 7.7 says the instruction "will only take a trap caused by a
//     synchronous exception on element 0", so a RESTARTED execution (vstart > 0) whose element
//     vstart is inaccessible must TRIM to vstart rather than fault. Reading it as `e == vstart`
//     turns exactly that case into a trap the architecture does not allow, and it is invisible
//     until something restarts the instruction. QEMU 11.1 reads it the same way: vext_ldff loops
//     from env->vstart but its allow-fault branch is `if (i == 0)`
//     (target/riscv/tcg/vector_helper.c:717-725).
//
// SEGMENTS SHARE THIS FUNCTION. A unit-stride fault-only-first SEGMENT load (7.8.1) is this
// instruction with nf fields per element: the accessibility unit becomes the whole segment --
// nf*EEW contiguous bytes -- and trimming still happens at ELEMENT granularity, because vl counts
// segments. nf == 1 is the non-segment form and the arithmetic below degenerates to it exactly.
//
// THE FAULT ADDRESS IS AN OUTPUT, and it has to be. Element 0's FIRST byte can be perfectly
// readable while the access still faults -- the fault may be in field 1 of a segment, or on the
// other side of a page boundary the element straddles. A caller that reported the fault by
// touching `base` would then not fault at all, and the instruction would complete silently having
// loaded nothing: no trap, no trim, no architectural effect. So this returns the first byte of the
// access that lies in an unmapped page, which is the byte the guest would fault on.
inline u32 first_unreadable_byte(u32 addr, u32 len)
{
	u32 a = addr;
	for (u32 left = len; left != 0;) {
		if (!mmu::page_readable(a))
			return a;
		// Stepped by REMAINING BYTES, matching mmu::range_readable exactly: a range that runs
		// past the top of the address space continues at 0, and `a += in_page` wraps there on
		// its own. The two must agree, or this could be asked for a byte in a range the other
		// one had already called readable.
		u32 const in_page = (u32)mmu::PAGE_SIZE - (a & (u32)(mmu::PAGE_SIZE - 1));
		if (in_page >= left)
			break;
		left -= in_page;
		a += in_page;
	}
	return addr; // only reachable if the caller asked about a fully readable range
}

// Returns the new vl. `faulted_at_start` says the trap must be taken, which can only happen at
// element 0 and therefore only when vstart == 0; `fault_gaddr` is then the guest byte the caller
// must touch to report it.
inline u32 load_fault_only_first(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits,
				 u32 vl, u32 vstart, u32 eew_bytes, bool vm, bool &faulted_at_start,
				 u32 &fault_gaddr, u32 nf = 1, u32 field_stride_regs = 1)
{
	faulted_at_start = false;
	fault_gaddr = base;
	u32 const seg_bytes = nf * eew_bytes;
	for (u32 e = vstart; e < vl; ++e) {
		// INACTIVE ELEMENTS ARE NOT PROBED AT ALL -- the mask test comes first, before any
		// look at the address. A masked-off element is not accessed, so it can neither fault
		// nor trim, and probing it would let an unmapped page under an element the
		// instruction never touches shorten vl.
		if (!vm && !vs.mask_get(0, e))
			continue;
		u32 const addr = base + e * seg_bytes;
		if (unlikely(!mmu::range_readable(addr, seg_bytes))) {
			if (e == 0) {
				// Element 0, the only one the architecture lets fault.
				faulted_at_start = true;
				fault_gaddr = first_unreadable_byte(addr, seg_bytes);
				return vl;
			}
			return e; // trim: elements [vstart, e) are loaded, vl becomes e
		}
		for (u32 f = 0; f < nf; ++f) {
			// The guest address is completed in u32 before it meets `vmem`, and the move
			// itself goes through the shared element accessor, which is what makes an
			// element that CROSSES the top of the address space wrap instead of running
			// off the reservation. Same contract as the non-segment unit-stride path.
			u32 const gaddr = addr + f * eew_bytes;
			guest_load_elem(vs.elem_ptr(vd + f * field_stride_regs, e, eew_bytes, vlen_bits),
					vmem, gaddr, eew_bytes);
		}
	}
	return vl;
}

// ---- indexed (gather/scatter) load and store ------------------------------------------------
// vluxei<EEW> / vloxei<EEW> / vsuxei<EEW> / vsoxei<EEW>.
//
// The INDEX element width is the instruction's width field, which is INDEPENDENT of SEW: that is
// the whole point of the encoding, and it means the index group's EMUL is (index_EEW/SEW)*LMUL
// and can differ from the data group's. The data width is SEW.
//
// Indices are BYTE OFFSETS from the base address and are treated as UNSIGNED. They are not
// scaled by the element size -- a common and silently-wrong assumption, since scaling would give
// plausible results for a unit-stride-like index vector and wrong ones for everything else.
//
// The ordered (vloxei/vsoxei) and unordered (vluxei/vsuxei) forms differ only in the memory
// ordering an implementation may use between elements. Performing them in element order is a
// legal implementation of both, so they share this code; for stores that matters, because
// overlapping scatter indices must resolve to the LAST element in order.
inline void load_indexed(VectorState &vs, u32 vd, u32 vs2, u8 *vmem, u32 base, u32 vlen_bits,
			 u32 vl, u32 data_eew, u32 index_eew, bool vm)
{
#ifdef RVDBT_DIAG_FREE_GATHER
	// DIAGNOSTIC ONLY, INCORRECT BY CONSTRUCTION: makes the guest indexed load do nothing so the
	// C-beta headroom (host gather for guest indexed access) can be BOUNDED before any mechanism
	// is designed. Never shipped, never a speedup claim.
	return;
#endif

	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const off = vs.elem_u(vs2, e, index_eew, vlen_bits);
		vs.vstart=e;
		guest_load_elem(vs.elem_ptr(vd,e,data_eew,vlen_bits),vmem,base+(u32)off,data_eew);
	}
	vs.vstart=0;
}

inline void store_indexed(VectorState &vs, u32 vs3, u32 vs2, u8 *vmem, u32 base, u32 vlen_bits,
			  u32 vl, u32 data_eew, u32 index_eew, bool vm)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const off = vs.elem_u(vs2, e, index_eew, vlen_bits);
		vs.vstart=e;
		guest_store_elem(vmem,base+(u32)off,vs.elem_ptr(vs3,e,data_eew,vlen_bits),data_eew);
	}
	vs.vstart=0;
}

// ---- segment load and store -------------------------------------------------------------------
// vlseg<nf>e<EEW> / vsseg<nf>e<EEW>, their strided (vlsseg/vssseg) and indexed (vluxseg/vloxseg/
// vsuxseg/vsoxseg) variants.
//
// A segment access moves NF CONSECUTIVE FIELDS per element and deposits field f of element i into
// register group (vd + f*EMUL) at index i. That transpose is the entire content of the
// instruction: memory holds an array of structures, the registers hold a structure of arrays.
// Each field is its own register GROUP of EMUL registers, so the run vd..vd+nf*EMUL is bounded by
// EIGHT registers, not by the file's 32 -- a legality rule with no analogue in the non-segment
// forms, and one this file states rather than implements: see vseg_registers_legal above.
//
// `eew` is the DATA element width and `field_stride_regs` the field groups' EMUL in registers.
// For the indexed forms neither comes from the instruction's `width` field, which is the INDEX
// width there; vseg_shape is what resolves that, and passing the width-derived values here would
// place the fields in the wrong registers.
//
// vstart IS HONOURED, and it is why these loops start where they do: elements below it are
// PRESTART, the architecture forbids touching them, and a restarted access must not re-execute
// them. Starting at 0 would repeat memory accesses the first execution already performed.
inline void load_segment(VectorState &vs, u32 vd, u8 *vmem, u32 base, i32 stride, u32 vlen_bits,
			 u32 vl, u32 eew, u32 nf, u32 field_stride_regs, bool vm, u32 vstart = 0)
{
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		// Unit-stride segments advance by the whole segment (nf fields) per element;
		// strided segments advance by the given byte stride.
		//
		// EVERY TERM IS UNSIGNED, and both halves of that matter. `e * (i32)stride` would be
		// a SIGNED multiplication that overflows -- undefined behaviour, reachable from the
		// guest with nothing more exotic than a large stride in rs2 -- while the guest
		// arithmetic it stands for is an XLEN-bit wrap. And the per-field address is formed
		// BEFORE it meets `vmem`: `vmem + seg_base + f * eew` would associate as
		// `(vmem + seg_base) + f * eew`, so a segment starting near 4 GiB would run off the
		// end of the reservation instead of wrapping to its base, which is what RV32 does.
		u32 const seg_base = base + e * (u32)stride;
		for (u32 f = 0; f < nf; ++f) {
			u32 const gaddr = seg_base + f * eew;
			guest_load_elem(vs.elem_ptr(vd + f * field_stride_regs, e, eew, vlen_bits),
					vmem, gaddr, eew);
		}
	}
}

inline void store_segment(VectorState &vs, u32 vs3, u8 *vmem, u32 base, i32 stride, u32 vlen_bits,
			  u32 vl, u32 eew, u32 nf, u32 field_stride_regs, bool vm, u32 vstart = 0)
{
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u32 const seg_base = base + e * (u32)stride; // unsigned: see load_segment
		for (u32 f = 0; f < nf; ++f) {
			u32 const gaddr = seg_base + f * eew;
			guest_store_elem(vmem, gaddr,
					 vs.elem_ptr(vs3 + f * field_stride_regs, e, eew, vlen_bits), eew);
		}
	}
}

// Indexed segment: the base of each segment comes from the index vector instead of from a stride.
inline void load_segment_indexed(VectorState &vs, u32 vd, u32 vs2, u8 *vmem, u32 base,
				 u32 vlen_bits, u32 vl, u32 eew, u32 index_eew, u32 nf,
				 u32 field_stride_regs, bool vm, u32 vstart = 0)
{
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u32 const seg_base = base + (u32)vs.elem_u(vs2, e, index_eew, vlen_bits);
		for (u32 f = 0; f < nf; ++f) {
			u32 const gaddr = seg_base + f * eew; // wraps in u32, like load_segment
			guest_load_elem(vs.elem_ptr(vd + f * field_stride_regs, e, eew, vlen_bits),
					vmem, gaddr, eew);
		}
	}
}

inline void store_segment_indexed(VectorState &vs, u32 vs3, u32 vs2, u8 *vmem, u32 base,
				  u32 vlen_bits, u32 vl, u32 eew, u32 index_eew, u32 nf,
				  u32 field_stride_regs, bool vm, u32 vstart = 0)
{
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u32 const seg_base = base + (u32)vs.elem_u(vs2, e, index_eew, vlen_bits);
		for (u32 f = 0; f < nf; ++f) {
			u32 const gaddr = seg_base + f * eew; // wraps in u32, like load_segment
			guest_store_elem(vmem, gaddr,
					 vs.elem_ptr(vs3 + f * field_stride_regs, e, eew, vlen_bits), eew);
		}
	}
}

// Masked unit-stride variants. Kept element-wise on purpose: a masked access must not touch
// inactive elements at all, so the chunked path (which moves whole 16-byte spans) cannot be
// used, and pretending otherwise would silently write elements the mask excluded.
inline void load_unit_stride_masked(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits,
				    u32 vl, u32 eew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vs.mask_get(0, e))
			continue;
		vs.vstart=e;
		guest_load_elem(vs.elem_ptr(vd, e, eew_bytes, vlen_bits), vmem,
				(u32)(base + e * eew_bytes), eew_bytes); // A13-FIX
	}
	vs.vstart=0;
}

inline void store_unit_stride_masked(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 vlen_bits,
				     u32 vl, u32 eew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vs.mask_get(0, e))
			continue;
		vs.vstart=e;
		guest_store_elem(vmem, (u32)(base + e * eew_bytes),
				 vs.elem_ptr(vs3, e, eew_bytes, vlen_bits), eew_bytes); // A13-FIX
	}
	vs.vstart=0;
}

inline void add_vv(VectorState &vs, u32 vd, u32 vs2, u32 vs1, u32 vlen_bits, u32 vl, u32 sew_bytes)
{
	for (u32 e = 0; e < vl; ++e) {
		u8 *pd = vs.elem_ptr(vd, e, sew_bytes, vlen_bits);
		u8 const *p2 = vs.elem_ptr(vs2, e, sew_bytes, vlen_bits);
		u8 const *p1 = vs.elem_ptr(vs1, e, sew_bytes, vlen_bits);
		switch (sew_bytes) {
		case 1: { u8 a, b; std::memcpy(&a, p2, 1); std::memcpy(&b, p1, 1); u8 r = (u8)(a + b); std::memcpy(pd, &r, 1); break; }
		case 2: { u16 a, b; std::memcpy(&a, p2, 2); std::memcpy(&b, p1, 2); u16 r = (u16)(a + b); std::memcpy(pd, &r, 2); break; }
		case 4: { u32 a, b; std::memcpy(&a, p2, 4); std::memcpy(&b, p1, 4); u32 r = a + b; std::memcpy(pd, &r, 4); break; }
		default: { u64 a, b; std::memcpy(&a, p2, 8); std::memcpy(&b, p1, 8); u64 r = a + b; std::memcpy(pd, &r, 8); break; }
		}
	}
}


} // namespace rvv_ref

// ---------------------------------------------------------------------------------------------
// RVV 1.0 7.8: THE SHAPE OF A SEGMENT ACCESS, derived once for every caller.
//
// The three addressing modes disagree about what the instruction's `width` field MEANS, and that
// is the whole reason this is a shared derivation rather than a line in each handler:
//
//   * unit-stride and strided segments: `width` is the DATA EEW. Each field's register group has
//     EMUL = (EEW/SEW)*LMUL, and consecutive fields are EMUL registers apart.
//   * INDEXED segments (mop 01/11): `width` is the INDEX EEW -- the width of one element of vs2 --
//     and the DATA moves at SEW. So the field groups' EMUL is LMUL, NOT the width-derived one, and
//     the index group is a separate group with its own EMUL. Using the width-derived EMUL as the
//     field stride puts field f in the wrong register whenever the index EEW differs from SEW.
//
// A fractional EMUL still occupies one whole register per field, which is why `field_regs` is
// separate from `data_emul_log2`.
struct VSegShape {
	u32 nf;              // NFIELDS = the encoded nf + 1, so 1..8 (the decoder routes nf==1 elsewhere)
	u32 data_eew;        // bytes moved per field element
	u32 index_eew;       // bytes of one index element; 0 unless `indexed`
	i32 data_emul_log2;  // EMUL of ONE field's register group
	i32 index_emul_log2; // EMUL of the index register group; 0 unless `indexed`
	u32 field_regs;      // registers one field group occupies (a fractional EMUL still uses one)
	bool indexed;
	bool valid;
	constexpr explicit operator bool() const { return valid; }
};

constexpr VSegShape vseg_shape(u32 width_funct3, u32 mop, u32 nf_encoded, VType vt)
{
	VSegShape s{};
	i32 const width_eew_log2 = eew_log2_from_width(width_funct3);
	if (width_eew_log2 < 0)
		return s; // a width this substrate does not implement; `valid` stays false
	u32 const width_eew = 1u << (width_eew_log2 - 3);
	s.nf = (nf_encoded & 7u) + 1u;
	s.indexed = mop == 0b01 || mop == 0b11;
	if (s.indexed) {
		s.index_eew = width_eew;
		s.index_emul_log2 = compute_emul_log2(vt, (u32)width_eew_log2);
		s.data_eew = vt.sew() / 8u;
		s.data_emul_log2 = vt.lmul_log2();
	} else {
		s.data_eew = width_eew;
		s.data_emul_log2 = compute_emul_log2(vt, (u32)width_eew_log2);
	}
	s.field_regs = emul_group_regs(s.data_emul_log2);
	s.valid = true;
	return s;
}

// 7.8's register rules, which are NOT the ordinary ones: a segment access names nf groups at once.
//
//   * EMUL * NFIELDS <= 8. The registers a segment touches are vd, vd+EMUL, ..., vd+(nf-1)*EMUL,
//     and the ISA bounds that run at eight registers -- not at the 32 the file happens to have.
//     A fractional EMUL uses one register per field, so the bound is nf << max(EMUL_log2, 0).
//   * The run must not increment past v31, and vd must be EMUL-aligned.
//   * A masked LOAD may not write v0 (5.3), the mask source.
//   * An INDEXED form's index group must be legal for the INDEX EMUL, and an EEW=64 index is
//     outside what this substrate implements -- see the note at that test, which is a statement
//     about this configuration's scope rather than about the encoding being reserved.
//   * For an INDEXED LOAD the destination groups may not overlap the index group AT ALL (7.8.3).
//     The decoder sends nf==1 to the non-segment routes, so every encoding reaching here has
//     nf > 1 and this stricter rule -- rather than 5.2's per-group one -- is the applicable one.
constexpr bool vseg_registers_legal(VSegShape const &s, u32 vd, u32 vs2, bool is_load, bool vm)
{
	if (!s.valid || s.nf == 0 || s.nf > 8 || s.field_regs == 0)
		return false;
	if (!emul_in_range(s.data_emul_log2))
		return false;
	u64 const regs_used = (u64)s.nf * s.field_regs; // == nf << max(EMUL_log2, 0)
	if (regs_used > 8 || (u64)vd + regs_used > VREG_NUM || (vd % s.field_regs) != 0)
		return false;
	if (is_load && !vm && vd == 0)
		return false;
	if (s.indexed) {
		// EEW=64 INDICES ARE AN IMPLEMENTATION-SCOPE REFUSAL, NOT A RESERVED ENCODING, and the
		// distinction is worth the four lines. 18.3 defines the V extension as supporting
		// "all vector load and store instructions, except ... EEW=64 for index values when
		// XLEN=32"; this substrate is V at XLEN=32, so the encoding is outside the set it
		// implements and fails closed here. That says what THIS configuration provides -- it
		// does not say every RV32 design must trap, which is why it is not phrased like the
		// 5.2 rules above. QEMU 11.1 makes the same call (vext_check_st_index:
		// `get_xl(s) == MXL_RV32` -> `eew != MO_64`), which is what keeps it a differential
		// oracle for this family rather than a source of disagreement.
		if (s.index_eew > 4)
			return false;
		if (!emul_in_range(s.index_emul_log2) ||
		    !reg_group_legal(vs2, s.index_emul_log2))
			return false;
		if (is_load) {
			u32 const iregs = emul_group_regs(s.index_emul_log2);
			if (vd < vs2 + iregs && vs2 < vd + regs_used)
				return false;
		}
	}
	return true;
}

// ---------------------------------------------------------------------------------------------
// Generic integer-vector families.
//
// These are written ONCE against (funct6, operand-source, SEW) rather than once per mnemonic,
// which is what keeps ~40 RVV instructions from becoming ~40 special cases. The decoder decides
// which funct6 values are admitted for each family; anything it does not admit never reaches
// here and traps as `ill`.
//
// Masking is handled uniformly: when vm==0 the instruction is masked by v0, element i executes
// only if v0's mask bit i is set, and inactive elements are left UNDISTURBED (legal under both
// the mask-undisturbed and mask-agnostic policies, and deterministic).
// ---------------------------------------------------------------------------------------------

// Where the second operand of an integer ALU op comes from.
enum class VSrc : u8 { VV, VX, VI };

// funct6 encodings, OPIVV/OPIVX/OPIVI (RVV 1.0 Table "vector integer arithmetic instructions").
enum : u32 {
	VF6_VADD = 0b000000,
	VF6_VSUB = 0b000010,
	VF6_VRSUB = 0b000011,
	VF6_VMINU = 0b000100,
	VF6_VMIN = 0b000101,
	VF6_VMAXU = 0b000110,
	VF6_VMAX = 0b000111,
	VF6_VAND = 0b001001,
	VF6_VOR = 0b001010,
	VF6_VXOR = 0b001011,
	VF6_VSLL = 0b100101,
	VF6_VSRL = 0b101000,
	VF6_VSRA = 0b101001,
	// comparisons (mask-producing)
	VF6_VMSEQ = 0b011000,
	VF6_VMSNE = 0b011001,
	VF6_VMSLTU = 0b011010,
	VF6_VMSLT = 0b011011,
	VF6_VMSLEU = 0b011100,
	VF6_VMSLE = 0b011101,
	VF6_VMSGTU = 0b011110,
	VF6_VMSGT = 0b011111,
	// merge / move
	VF6_VMERGE = 0b010111,

	// Fixed-point saturating add/subtract (OPIVV/OPIVX/OPIVI).
	VF6_VSADDU = 0b100000, VF6_VSADD = 0b100001,
	VF6_VSSUBU = 0b100010, VF6_VSSUB = 0b100011,
	// Fixed-point averaging (OPMVV/OPMVX).
	VF6_VAADDU = 0b001000, VF6_VAADD = 0b001001,
	VF6_VASUBU = 0b001010, VF6_VASUB = 0b001011,
	// Slides and gathers (OPIVV/OPIVX/OPIVI); vslideup and vrgatherei16 share funct6 001110
	// and are distinguished by funct3, which is why they are dispatched separately.
	VF6_VSLIDEUP = 0b001110, VF6_VSLIDEDOWN = 0b001111,
	VF6_VRGATHER = 0b001100, VF6_VRGATHEREI16 = 0b001110,
	// vslide1up/vslide1down live in OPMVX (integer) and OPFVF (float) at these funct6.
	VF6_VSLIDE1UP = 0b001110, VF6_VSLIDE1DOWN = 0b001111,
	// Narrowing shifts (OPIVV/OPIVX/OPIVI), source is 2*SEW.
	VF6_VNSRL = 0b101100, VF6_VNSRA = 0b101101,
	// Carry/borrow (OPIVV/OPIVX/OPIVI). The .vvm forms take a carry-in from v0 and are
	// encoded with vm=0; the vmadc/vmsbc forms without carry-in use vm=1. v0 here is a real
	// OPERAND, not a mask, so these instructions are never "masked" in the usual sense.
	VF6_VADC = 0b010000, VF6_VMADC = 0b010001,
	VF6_VSBC = 0b010010, VF6_VMSBC = 0b010011,
	// Fractional multiply with rounding and saturation (reads vxrm, sets vxsat).
	VF6_VSMUL = 0b100111,
	// Vector FP widening arithmetic. The .w forms take an already-wide vs2, as in the integer
	// widening group.
	VF6_VFWADD = 0b110000, VF6_VFWREDUSUM = 0b110001, VF6_VFWSUB = 0b110010,
	VF6_VFWREDOSUM = 0b110011, VF6_VFWADD_W = 0b110100, VF6_VFWSUB_W = 0b110110,
	VF6_VFWMUL = 0b111000,
	VF6_VFWMACC = 0b111100, VF6_VFWNMACC = 0b111101,
	VF6_VFWMSAC = 0b111110, VF6_VFWNMSAC = 0b111111,
	// Fixed-point scaling shifts and narrowing clips (read vxrm; the clips set vxsat).
	VF6_VSSRL = 0b101010, VF6_VSSRA = 0b101011,
	VF6_VNCLIPU = 0b101110, VF6_VNCLIP = 0b101111,
	// Widening integer reductions (OPIVV).
	VF6_VWREDSUMU = 0b110000, VF6_VWREDSUM = 0b110001,
	// vcompress.vm (OPMVV) and the VMUNARY0 mask group (OPMVV f6=010100, sub in vs1).
	VF6_VCOMPRESS = 0b010111, VF6_VMUNARY0 = 0b010100,
	// Integer extension sub-encodings live in the vs1 field of VXUNARY0 (OPMVV).
	VF6_VXUNARY0 = 0b010010,
	// Widening integer add/sub/mul/macc (OPMVV/OPMVX). The .w* forms (1101xx) take an
	// ALREADY-WIDE vs2, which is what distinguishes them from the 1100xx narrow-source forms.
	VF6_VWADDU = 0b110000, VF6_VWADD = 0b110001,
	VF6_VWSUBU = 0b110010, VF6_VWSUB = 0b110011,
	VF6_VWADDU_W = 0b110100, VF6_VWADD_W = 0b110101,
	VF6_VWSUBU_W = 0b110110, VF6_VWSUB_W = 0b110111,
	VF6_VWMULU = 0b111000, VF6_VWMULSU = 0b111010, VF6_VWMUL = 0b111011,
	VF6_VWMACCU = 0b111100, VF6_VWMACC = 0b111101,
	VF6_VWMACCUS = 0b111110, VF6_VWMACCSU = 0b111111,
};

// OPMVV/OPMVX integer multiply / divide / multiply-accumulate funct6 values.
enum : u32 {
	VF6_VDIVU = 0b100000, VF6_VDIV = 0b100001, VF6_VREMU = 0b100010, VF6_VREM = 0b100011,
	VF6_VMULHU = 0b100100, VF6_VMUL = 0b100101, VF6_VMULHSU = 0b100110, VF6_VMULH = 0b100111,
	VF6_VMADD = 0b101001, VF6_VNMSUB = 0b101011, VF6_VMACC = 0b101101, VF6_VNMSAC = 0b101111,
};

constexpr bool vimul_supported(u32 funct6)
{
	switch (funct6) {
	case VF6_VDIVU: case VF6_VDIV: case VF6_VREMU: case VF6_VREM:
	case VF6_VMULHU: case VF6_VMUL: case VF6_VMULHSU: case VF6_VMULH:
	case VF6_VMADD: case VF6_VNMSUB: case VF6_VMACC: case VF6_VNMSAC:
		return true;
	default:
		return false;
	}
}
// vd is also a SOURCE for the multiply-accumulate forms.
constexpr bool vimul_reads_vd(u32 funct6)
{
	return funct6 == VF6_VMADD || funct6 == VF6_VNMSUB || funct6 == VF6_VMACC ||
	       funct6 == VF6_VNMSAC;
}

enum : u32 {
	VF6_VREDSUM = 0b000000, VF6_VREDAND = 0b000001, VF6_VREDOR = 0b000010,
	VF6_VREDXOR = 0b000011, VF6_VREDMINU = 0b000100, VF6_VREDMIN = 0b000101,
	VF6_VREDMAXU = 0b000110, VF6_VREDMAX = 0b000111,
	VF6_VWXUNARY0 = 0b010000, // vmv.x.s (OPMVV) / vmv.s.x (OPMVX)
};

constexpr bool vred_supported(u32 funct6) { return funct6 <= VF6_VREDMAX; }

// ---- vector floating point ------------------------------------------------------------------
// OPFVV (funct3=001) / OPFVF (funct3=101) funct6 values. Element FP width is SEW, so only
// SEW=32 (binary32) and SEW=64 (binary64) are meaningful here -- SEW=8/16 FP is Zvfh/Zvfbfmin,
// separate standard extensions, and is NOT admitted.
enum : u32 {
	VF6_VFADD = 0b000000, VF6_VFREDUSUM = 0b000001, VF6_VFSUB = 0b000010,
	VF6_VFREDOSUM = 0b000011, VF6_VFMIN = 0b000100, VF6_VFREDMIN = 0b000101,
	VF6_VFMAX = 0b000110, VF6_VFREDMAX = 0b000111,
	VF6_VFSGNJ = 0b001000, VF6_VFSGNJN = 0b001001, VF6_VFSGNJX = 0b001010,
	VF6_VWFUNARY0 = 0b010000, // vfmv.f.s (OPFVV) / vfmv.s.f (OPFVF)
	VF6_VFUNARY0 = 0b010010,  // conversions
	VF6_VFUNARY1 = 0b010011,  // vfsqrt / vfclass
	VF6_VFMERGE = 0b010111,   // vfmerge.vfm / vfmv.v.f
	VF6_VMFEQ = 0b011000, VF6_VMFLE = 0b011001, VF6_VMFLT = 0b011011,
	VF6_VMFNE = 0b011100, VF6_VMFGT = 0b011101, VF6_VMFGE = 0b011111,
	VF6_VFDIV = 0b100000, VF6_VFRDIV = 0b100001, VF6_VFMUL = 0b100100,
	VF6_VFRSUB = 0b100111,
	VF6_VFMADD = 0b101000, VF6_VFNMADD = 0b101001, VF6_VFMSUB = 0b101010,
	VF6_VFNMSUB = 0b101011, VF6_VFMACC = 0b101100, VF6_VFNMACC = 0b101101,
	VF6_VFMSAC = 0b101110, VF6_VFNMSAC = 0b101111,
};

constexpr bool vfalu_supported(u32 f6, bool is_vf)
{
	switch (f6) {
	case VF6_VFADD: case VF6_VFSUB: case VF6_VFMIN: case VF6_VFMAX:
	case VF6_VFSGNJ: case VF6_VFSGNJN: case VF6_VFSGNJX:
	case VF6_VFDIV: case VF6_VFMUL:
		return true;
	case VF6_VFRDIV: case VF6_VFRSUB:
		return is_vf; // reverse forms exist only in the vector-scalar encoding
	default:
		return false;
	}
}

// The subset of `vfalu_supported` that the LLVM/AOT backend lowers NATIVELY, and the RULE that
// selects it. It is DERIVED, not enumerated by workload: a funct6 belongs iff
//
//   (a) `vfalu_supported` already admits it in the VECTOR-VECTOR form -- which is why the test below
//       calls that function instead of restating its rows, so this set can never grow past the
//       family the production QCG typed-FALU route accepts; and
//   (b) its RVV element semantics are EXACTLY one IEEE 754 arithmetic operation, so a single
//       `llvm.experimental.constrained.f{add,sub,mul,div}` carrying `round.dynamic` and
//       `fpexcept.strict` reproduces the value, the rounding and the raised exceptions with nothing
//       left over.
//
// (b) is what excludes the rest of the family, and each exclusion is a semantic statement rather
// than a missing case:
//
//   vfmin / vfmax   RVV defines these as IEEE 754-2019 minimumNumber/maximumNumber. LLVM's
//                   constrained minnum/maxnum are the 754-2008 minNum/maxNum, and x86
//                   VMINPS/VMAXPS differ again on signaling NaN and on +-0.
//                   `QEmit::Emit_vchunkfalu` spends a three-mask sequence (ORD_Q compare, EQ_OQ
//                   compare, NaN-in-vs2 select) precisely to bridge that gap. No single constrained
//                   intrinsic expresses it, so admitting them here would be a silent semantic
//                   substitution, not a lowering.
//   vfsgnj{,n,x}    sign injection is a BITWISE operation on the sign bit: it rounds nothing and
//                   raises no FP exception, so it is not a constrained-FP operation at all. The QCG
//                   arm emits VPTERNLOG, not an arithmetic instruction.
//   vfrdiv / vfrsub these exist only in the OPFVF vector-scalar encoding, whose scalar operand needs
//                   a frame-scope broadcast of an F register. `InstRVVFALU` carries no operand for
//                   one, so the form is not expressible in this node at all.
//
// A funct6 added to `vfalu_supported` later does NOT silently join this set: it must be named here
// as well, and `QIRToLLVM::Emit_rvvfalu` Panics on any funct6 it has no intrinsic for.
constexpr bool vfalu_llvm_constrained_vv_supported(u32 f6)
{
	switch (f6) {
	case VF6_VFADD:
	case VF6_VFSUB:
	case VF6_VFMUL:
	case VF6_VFDIV:
		return vfalu_supported(f6, /*is_vf=*/false);
	default:
		return false;
	}
}
constexpr bool vfma_supported(u32 f6) { return f6 >= VF6_VFMADD && f6 <= VF6_VFNMSAC; }
constexpr bool vfcmp_supported(u32 f6, bool is_vf)
{
	switch (f6) {
	case VF6_VMFEQ: case VF6_VMFLE: case VF6_VMFLT: case VF6_VMFNE:
		return true;
	case VF6_VMFGT: case VF6_VMFGE:
		return is_vf; // no vector-vector form (swap the operands instead)
	default:
		return false;
	}
}
constexpr bool vfred_supported(u32 f6)
{
	return f6 == VF6_VFREDUSUM || f6 == VF6_VFREDOSUM || f6 == VF6_VFREDMIN ||
	       f6 == VF6_VFREDMAX;
}
// VFUNARY0 sub-encodings live in the vs1 field.
constexpr bool vfcvt_supported(u32 vs1)
{
	switch (vs1) {
	case 0b00000: case 0b00001: case 0b00010: case 0b00011: case 0b00110: case 0b00111:
	case 0b01000: case 0b01001: case 0b01010: case 0b01011: case 0b01100: case 0b01110:
	case 0b01111:
	case 0b10000: case 0b10001: case 0b10010: case 0b10011: case 0b10100: case 0b10101:
	case 0b10110: case 0b10111:
		return true;
	default:
		return false;
	}
}
constexpr bool vfcvt_is_widening(u32 vs1) { return vs1 >= 0b01000 && vs1 <= 0b01111; }
constexpr bool vfcvt_is_narrowing(u32 vs1) { return vs1 >= 0b10000; }
// vfsqrt (vs1=00000) and vfclass (vs1=10000) are the VFUNARY1 forms implemented.
// VFUNARY1: 00000 vfsqrt.v, 00100 vfrsqrt7.v, 00101 vfrec7.v, 10000 vfclass.v.
constexpr bool vfunary1_supported(u32 vs1)
{
	return vs1 == 0b00000 || vs1 == 0b00100 || vs1 == 0b00101 || vs1 == 0b10000;
}

// FP SEW must be 32 or 64: those are the only widths the base V extension defines FP for.
constexpr bool vf_sew_supported(u32 sew_bytes) { return sew_bytes == 4 || sew_bytes == 8; }

// Mask-register logic, OPMVV funct6 values.
enum : u32 {
	VF6_VMANDN = 0b011000,
	VF6_VMAND = 0b011001,
	VF6_VMOR = 0b011010,
	VF6_VMXOR = 0b011011,
	VF6_VMORN = 0b011100,
	VF6_VMNAND = 0b011101,
	VF6_VMNOR = 0b011110,
	VF6_VMXNOR = 0b011111,
};

// True iff `funct6` is an integer ALU op this substrate implements.
constexpr bool vialu_supported(u32 funct6)
{
	switch (funct6) {
	case VF6_VADD: case VF6_VSUB: case VF6_VRSUB:
	case VF6_VMINU: case VF6_VMIN: case VF6_VMAXU: case VF6_VMAX:
	case VF6_VAND: case VF6_VOR: case VF6_VXOR:
	case VF6_VSLL: case VF6_VSRL: case VF6_VSRA:
		return true;
	default:
		return false;
	}
}
// vsub has no .vi form; vrsub has no .vv form (RVV 1.0 encoding tables).
// vsext/vzext sub-encodings: vs1 = 00010 vzext.vf8, 00011 vsext.vf8, 00100 vzext.vf4,
// 00101 vsext.vf4, 00110 vzext.vf2, 00111 vsext.vf2. Everything else in VXUNARY0 is not
// implemented and must fail closed rather than be treated as one of these.
constexpr bool vext_supported(u32 vs1f) { return vs1f >= 0b00010 && vs1f <= 0b00111; }
constexpr u32 vext_divisor(u32 vs1f) { return vs1f <= 0b00011 ? 8 : (vs1f <= 0b00101 ? 4 : 2); }
constexpr bool vext_is_signed(u32 vs1f) { return (vs1f & 1) != 0; }

constexpr bool vsatadd_supported(u32 funct6)
{
	return funct6 == VF6_VSADDU || funct6 == VF6_VSADD || funct6 == VF6_VSSUBU ||
	       funct6 == VF6_VSSUB;
}
// vssubu/vssub have no immediate form: subtracting a 5-bit immediate is expressed as vsadd of
// its negation, so the .vi encodings are not defined.
constexpr bool vsatadd_form_supported(u32 funct6, VSrc src)
{
	if (src == VSrc::VI && (funct6 == VF6_VSSUBU || funct6 == VF6_VSSUB))
		return false;
	return vsatadd_supported(funct6);
}
constexpr bool vavg_supported(u32 funct6)
{
	return funct6 == VF6_VAADDU || funct6 == VF6_VAADD || funct6 == VF6_VASUBU ||
	       funct6 == VF6_VASUB;
}
constexpr bool vwint_supported(u32 funct6)
{
	if (funct6 >= VF6_VWADDU && funct6 <= VF6_VWSUB_W)
		return true;
	if (funct6 == VF6_VWMULU || funct6 == VF6_VWMULSU || funct6 == VF6_VWMUL)
		return true;
	return funct6 >= VF6_VWMACCU && funct6 <= VF6_VWMACCSU;
}
// vs2 is already 2*SEW for the .wv/.wx forms only.
constexpr bool vwint_wide_vs2(u32 funct6)
{
	return funct6 >= VF6_VWADDU_W && funct6 <= VF6_VWSUB_W;
}
// vwmaccus exists only in the .vx form: it multiplies a signed vector by an unsigned scalar,
// which has no vector-vector counterpart.
constexpr bool vwint_form_supported(u32 funct6, VSrc src)
{
	if (src == VSrc::VI)
		return false; // no widening immediate forms
	if (funct6 == VF6_VWMACCUS && src != VSrc::VX)
		return false;
	return vwint_supported(funct6);
}

inline bool narrow_registers_legal(VType vt, VSrc src, u32 vd, u32 vs2, u32 vs1, bool vm)
{
	i32 const lm = vt.lmul_log2(), wl = lm + 1;
	if (vt.sew() > 32 || !emul_in_range(wl) || !reg_group_legal(vd,lm) || !reg_group_legal(vs2,wl) ||
	    (src == VSrc::VV && !reg_group_legal(vs1,lm)) ||
	    (!vm && (vd == 0 || vs2 == 0 || (src == VSrc::VV && vs1 == 0)))) return false;
	u32 const dg = emul_group_regs(lm), sg = emul_group_regs(wl);
	auto overlap = [](u32 a,u32 an,u32 b,u32 bn) { return a < b + bn && b < a + an; };
	if (overlap(vd,dg,vs2,sg) && vd != vs2) return false;
	if (src == VSrc::VV && overlap(vs1,dg,vs2,sg)) return false;
	return true;
}

inline bool vwint_registers_legal(VType vt, u32 f6, VSrc src, u32 vd, u32 vs2, u32 vs1, bool vm)
{
	i32 const lm = vt.lmul_log2(), wl = lm + 1;
	bool const wide2 = vwint_wide_vs2(f6), acc = f6 >= VF6_VWMACCU;
	if (vt.sew() > 32 || !emul_in_range(wl) || !reg_group_legal(vd, wl) ||
	    !reg_group_legal(vs2, wide2 ? wl : lm) || (src == VSrc::VV && !reg_group_legal(vs1, lm)) ||
	    (!vm && (vd == 0 || vs2 == 0 || (src == VSrc::VV && vs1 == 0)))) return false;
	u32 const dg = emul_group_regs(wl), ng = emul_group_regs(lm), sg = wide2 ? dg : ng;
	auto overlap = [](u32 a, u32 an, u32 b, u32 bn) { return a < b + bn && b < a + an; };
	auto narrow_overlap_ok = [&](u32 r) {
		return !overlap(vd, dg, r, ng) || (!acc && lm >= 0 && r + ng == vd + dg);
	};
	if (!wide2 && !narrow_overlap_ok(vs2)) return false;
	if (src == VSrc::VV && (!narrow_overlap_ok(vs1) ||
	    (wide2 && overlap(vs2, sg, vs1, ng)))) return false;
	return true;
}

constexpr bool vadc_supported(u32 funct6)
{
	return funct6 == VF6_VADC || funct6 == VF6_VMADC || funct6 == VF6_VSBC ||
	       funct6 == VF6_VMSBC;
}
// vsbc/vmsbc have no immediate form: there is no borrow-in subtract from a 5-bit immediate.
constexpr bool vadc_form_supported(u32 funct6, VSrc src)
{
	if (src == VSrc::VI && (funct6 == VF6_VSBC || funct6 == VF6_VMSBC))
		return false;
	return vadc_supported(funct6);
}
constexpr bool vsshift_supported(u32 funct6)
{
	return funct6 == VF6_VSSRL || funct6 == VF6_VSSRA;
}
constexpr bool vnclip_supported(u32 funct6)
{
	return funct6 == VF6_VNCLIPU || funct6 == VF6_VNCLIP;
}
constexpr bool vsmul_supported(u32 funct6, VSrc src)
{
	// No immediate form: a fractional multiply by a 5-bit immediate is not defined.
	return funct6 == VF6_VSMUL && src != VSrc::VI;
}
// Widening FP reductions occupy their own funct6 values and exist only in OPFVV.
constexpr bool vfwred_supported(u32 f6, bool is_vf)
{
	return !is_vf && (f6 == VF6_VFWREDUSUM || f6 == VF6_VFWREDOSUM);
}
constexpr bool vfwarith_supported(u32 f6, bool /*is_vf*/)
{
	switch (f6) {
	case VF6_VFWADD: case VF6_VFWSUB: case VF6_VFWADD_W: case VF6_VFWSUB_W:
	case VF6_VFWMUL: case VF6_VFWMACC: case VF6_VFWNMACC: case VF6_VFWMSAC:
	case VF6_VFWNMSAC:
		return true;
	default:
		return false;
	}
}
constexpr bool vfw_wide_vs2(u32 f6) { return f6 == VF6_VFWADD_W || f6 == VF6_VFWSUB_W; }
constexpr bool vfw_is_fma(u32 f6) { return f6 >= VF6_VFWMACC; }

// RVV 1.0 5.2 for the WIDENING FP FAMILY, in ONE place because two callers must not be able to
// disagree about which encodings exist: the vfwarith handler (which is also the JIT's fallback
// helper) and the direct QCG admission. `vm` is the ENCODED bit, so true means UNMASKED.
//
// TWO INDEPENDENT RULES, and the widening FMAs sit differently under each.
//
//   * DESTINATION/SOURCE OVERLAP. The destination EEW is 2*SEW and a narrow source's is SEW, so
//     5.2 permits an overlap only when the source EMUL is at least 1 AND the source group is the
//     HIGHEST-numbered part of the destination group -- `src + nregs == vd + wregs`, both groups
//     being power-of-two aligned. A `.w` form's vs2 carries the destination's own EEW and may
//     overlap freely; equal-size aligned groups make vs2 == vd the only reachable case.
//
//   * ONE REGISTER, ONE SOURCE EEW: "A vector register cannot be used to provide source operands
//     with more than one EEW for a single instruction ... A mask register source is considered to
//     have EEW=1 for this constraint", and such an encoding is RESERVED. This is the rule that
//     makes the widening FMAs STRICTER than the arithmetic forms rather than the same: vfwmacc and
//     its three siblings READ vd as the addend at 2*SEW, so a narrow source may not share a
//     register with the destination group at all -- not even in the highest part the first rule
//     would allow, which is exactly why `vfwadd.vv v8, v9, v24` is legal and
//     `vfwmacc.vv v8, v24, v9` is not. The same rule forbids a `.w` form's narrow vs1 overlapping
//     its wide vs2, and forbids any masked form whose source groups contain v0.
//
// It decides REGISTERS ONLY. SEW, 2*SEW <= ELEN, vill and vl are each checked where they belong.
constexpr bool vfw_registers_legal(u32 f6, bool is_vf, i32 lmul_log2, u32 vd, u32 vs2, u32 vs1,
				   bool vm)
{
	i32 const wlmul = lmul_log2 + 1;
	if (!emul_in_range(lmul_log2) || !emul_in_range(wlmul))
		return false;
	bool const wide2 = vfw_wide_vs2(f6), fma = vfw_is_fma(f6);
	u32 const nregs = emul_group_regs(lmul_log2), wregs = emul_group_regs(wlmul);
	if (!reg_group_legal(vd, wlmul) || !reg_group_legal(vs2, wide2 ? wlmul : lmul_log2) ||
	    (!is_vf && !reg_group_legal(vs1, lmul_log2)))
		return false;
	// A masked instruction reads v0 with EEW=1. An aligned group contains v0 only when its base
	// is v0, so this is the whole of the mask half of the one-register-one-EEW rule -- and for vd
	// it is also the pre-existing "a masked op may not write v0" rule.
	if (!vm && (vd == 0 || vs2 == 0 || (!is_vf && vs1 == 0)))
		return false;
	auto overlaps = [](u32 a, u32 na, u32 b, u32 nb) { return a < b + nb && b < a + na; };
	auto narrow_source_ok = [&](u32 src) {
		if (!overlaps(vd, wregs, src, nregs))
			return true;             // disjoint: nothing to decide
		if (fma)
			return false;            // vd is a 2*SEW SOURCE here
		return lmul_log2 >= 0 && src + nregs == vd + wregs;
	};
	if (!wide2 && !narrow_source_ok(vs2))
		return false;
	if (!is_vf && !narrow_source_ok(vs1))
		return false;
	// The `.w` forms' two sources: 2*SEW on vs2 and SEW on vs1, so they may not share a register.
	if (wide2 && !is_vf && overlaps(vs2, wregs, vs1, nregs))
		return false;
	return true;
}

constexpr bool vwred_supported(u32 funct6)
{
	return funct6 == VF6_VWREDSUMU || funct6 == VF6_VWREDSUM;
}
// VMUNARY0 sub-encodings in the vs1 field: 00001 vmsbf, 00010 vmsof, 00011 vmsif,
// 10000 viota, 10001 vid (handled separately since it needs no mask source).
constexpr bool vmunary_supported(u32 vs1f)
{
	return vs1f == 0b00001 || vs1f == 0b00010 || vs1f == 0b00011 || vs1f == 0b10000;
}
// VWXUNARY0 sub-encodings that read a mask and write a GPR: 10000 vcpop.m, 10001 vfirst.m.
constexpr bool vmaskpop_supported(u32 vs1f) { return vs1f == 0b10000 || vs1f == 0b10001; }

constexpr bool vnshift_supported(u32 funct6)
{
	return funct6 == VF6_VNSRL || funct6 == VF6_VNSRA;
}

constexpr bool vialu_form_supported(u32 funct6, VSrc src)
{
	// RVV min/max has vector and scalar-register sources, but no immediate form.
	if (src == VSrc::VI && (funct6 == VF6_VMINU || funct6 == VF6_VMIN ||
	                       funct6 == VF6_VMAXU || funct6 == VF6_VMAX))
		return false;
	if (funct6 == VF6_VSUB && src == VSrc::VI)
		return false;
	if (funct6 == VF6_VRSUB && src == VSrc::VV)
		return false;
	return vialu_supported(funct6);
}

constexpr bool vicmp_supported(u32 funct6, VSrc src)
{
	switch (funct6) {
	case VF6_VMSEQ: case VF6_VMSNE:
		return true;
	case VF6_VMSLTU: case VF6_VMSLT:
		return src != VSrc::VI; // no immediate form
	case VF6_VMSLEU: case VF6_VMSLE:
		return true;
	case VF6_VMSGTU: case VF6_VMSGT:
		return src != VSrc::VV; // no vector-vector form
	default:
		return false;
	}
}

constexpr bool vmlogic_supported(u32 funct6)
{
	return funct6 >= VF6_VMANDN && funct6 <= VF6_VMXNOR;
}

namespace rvv_ref
{

// Second operand for element i: another vector element, a scalar register, or a 5-bit immediate
// (sign-extended, per RVV 1.0 -- the immediate is signed for arithmetic and compares, and is
// Shift immediates are unsigned and are handled by vialu before applying the operation.
ALWAYS_INLINE u64 vialu_rhs(VectorState &vs, VSrc src, u32 vs1, u32 rs1_val, i32 simm5, u32 e,
			    u32 sew_bytes, u32 vlen)
{
	u64 const mask = sew_bytes == 8 ? ~u64(0) : (u64(1) << (8 * sew_bytes)) - 1;
	switch (src) {
	case VSrc::VV:
		return vs.elem_u(vs1, e, sew_bytes, vlen);
	case VSrc::VX:
		return (u64)(i64)(i32)rs1_val & mask; // truncate below XLEN, sign-extend above XLEN
	default:
		return (u64)(i64)simm5 & mask;
	}
}

// Width helpers shared by the fixed-point, narrowing and gather families.
ALWAYS_INLINE u64 sew_mask(u32 sew_bytes)
{
	return sew_bytes >= 8 ? ~0ull : (((u64)1 << (8 * sew_bytes)) - 1);
}
ALWAYS_INLINE i64 sext_sew(u64 v, u32 sew_bytes)
{
	u32 const sh = 64 - 8 * sew_bytes;
	return sh == 0 ? (i64)v : ((i64)(v << sh) >> sh);
}
ALWAYS_INLINE u64 vialu_apply(u32 funct6, u64 a, u64 b, u32 sew_bytes)
{
	u32 const bits = 8 * sew_bytes;
	u32 const sh = 64 - bits;
	auto sx = [sh](u64 v) { return (i64)(v << sh) >> sh; };
	switch (funct6) {
	case VF6_VADD:
		return a + b;
	case VF6_VSUB:
		return a - b;
	case VF6_VRSUB:
		return b - a;
	case VF6_VMINU:
		return a < b ? a : b;
	case VF6_VMIN:
		return sx(a) < sx(b) ? a : b;
	case VF6_VMAXU:
		return a > b ? a : b;
	case VF6_VMAX:
		return sx(a) > sx(b) ? a : b;
	case VF6_VAND:
		return a & b;
	case VF6_VOR:
		return a | b;
	case VF6_VXOR:
		return a ^ b;
	// Shift amount is taken modulo SEW (low log2(SEW) bits), per the spec.
	case VF6_VSLL:
		return a << (b & (bits - 1));
	case VF6_VSRL:
		return (a & (bits == 64 ? ~0ull : ((1ull << bits) - 1))) >> (b & (bits - 1));
	default: // VF6_VSRA
		return (u64)(sx(a) >> (b & (bits - 1)));
	}
}

ALWAYS_INLINE bool vicmp_apply(u32 funct6, u64 a, u64 b, u32 sew_bytes)
{
	u32 const sh = 64 - 8 * sew_bytes;
	auto sx = [sh](u64 v) { return (i64)(v << sh) >> sh; };
	switch (funct6) {
	case VF6_VMSEQ:
		return a == b;
	case VF6_VMSNE:
		return a != b;
	case VF6_VMSLTU:
		return a < b;
	case VF6_VMSLT:
		return sx(a) < sx(b);
	case VF6_VMSLEU:
		return a <= b;
	case VF6_VMSLE:
		return sx(a) <= sx(b);
	case VF6_VMSGTU:
		return a > b;
	default: // VF6_VMSGT
		return sx(a) > sx(b);
	}
}

// Integer ALU, all of OPIVV/OPIVX/OPIVI. vd is a register GROUP at LMUL; the mask (v0) is not.
inline void vialu(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		  i32 simm5, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue; // inactive: undisturbed
		u64 const a = vs.elem_u(vs2, e, sew_bytes, vlen);
		bool const shift_imm = src == VSrc::VI &&
			(funct6 == VF6_VSLL || funct6 == VF6_VSRL || funct6 == VF6_VSRA);
		u64 const b = shift_imm ? (u32(simm5) & 31u) :
			vialu_rhs(vs, src, vs1, rs1_val, simm5, e, sew_bytes, vlen);
		vs.elem_put(vd, e, sew_bytes, vlen, vialu_apply(funct6, a, b, sew_bytes));
	}
}

// Comparison: writes a MASK register (one bit per element), not an element group.
inline void vicmp(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		  i32 simm5, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const a = vs.elem_u(vs2, e, sew_bytes, vlen);
		u64 const b = vialu_rhs(vs, src, vs1, rs1_val, simm5, e, sew_bytes, vlen);
		vs.mask_set(vd, e, vicmp_apply(funct6, a, b, sew_bytes));
	}
}

// Mask-register logic. Operates on single registers, bit per element, never masked itself.
inline void vmlogic(VectorState &vs, u32 funct6, u32 vd, u32 vs2, u32 vs1, u32 vl)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		// The spec defines these as vd = f(vs2, vs1) -- vmandn is vs2 AND NOT vs1, not the
		// other way round. Six of the eight are symmetric in their operands, so a swap is
		// invisible in them; it shows up only in vmandn and vmorn. TSVC s279 was the first
		// workload to use one.
		bool const x = vs.mask_get(vs2, e), y = vs.mask_get(vs1, e);
		bool r;
		switch (funct6) {
		case VF6_VMANDN: r = x && !y; break;
		case VF6_VMAND:  r = y && x;  break;
		case VF6_VMOR:   r = y || x;  break;
		case VF6_VMXOR:  r = y != x;  break;
		case VF6_VMORN:  r = x || !y; break;
		case VF6_VMNAND: r = !(y && x); break;
		case VF6_VMNOR:  r = !(y || x); break;
		default:         r = (y == x); break; // VMXNOR
		}
		vs.mask_set(vd, e, r);
	}
}

// vmerge (vm==0: select by v0) and vmv.v.* (vm==1: unconditional move). Same funct6 by design.
inline void vmerge_or_mv(VectorState &vs, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
			 i32 simm5, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		u64 const rhs = vialu_rhs(vs, src, vs1, rs1_val, simm5, e, sew_bytes, vlen);
		u64 v;
		if (vm) {
			v = rhs; // vmv.v.{v,x,i}: no mask, take the source
		} else {
			// vmerge: mask bit selects rhs (vs1/rs1/imm), else vs2.
			v = vs.mask_get(0, e) ? rhs : vs.elem_u(vs2, e, sew_bytes, vlen);
		}
		vs.elem_put(vd, e, sew_bytes, vlen, v);
	}
}

// Integer multiply / divide / multiply-accumulate, OPMVV and OPMVX.
//
// Division follows the RVV 1.0 rules exactly (they differ from the scalar M extension only in
// being element-wise): divide by zero yields all-ones for the quotient and the dividend for the
// remainder -- no trap -- and the signed most-negative / -1 overflow case yields the dividend
// for the quotient and zero for the remainder.
ALWAYS_INLINE u64 vimul_apply(u32 funct6, u64 vd_old, u64 a /*vs2*/, u64 b /*vs1|rs1*/,
			      u32 sew_bytes)
{
	u32 const bits = 8 * sew_bytes;
	u32 const sh = 64 - bits;
	u64 const mask = bits == 64 ? ~0ull : ((1ull << bits) - 1);
	auto sx = [sh](u64 v) { return (i64)(v << sh) >> sh; };
	auto lo = [mask](unsigned __int128 p) { return (u64)p & mask; };
	switch (funct6) {
	case VF6_VMUL:
		return lo((unsigned __int128)(a & mask) * (b & mask));
	case VF6_VMULHU:
		return (u64)(((unsigned __int128)(a & mask) * (b & mask)) >> bits) & mask;
	case VF6_VMULH:
		return (u64)(((__int128)sx(a) * (__int128)sx(b)) >> bits) & mask;
	case VF6_VMULHSU:
		return (u64)(((__int128)sx(a) * (__int128)(unsigned __int128)(b & mask)) >> bits) & mask;
	case VF6_VDIVU:
		return (b & mask) == 0 ? mask : ((a & mask) / (b & mask));
	case VF6_VDIV: {
		i64 const x = sx(a), y = sx(b);
		if (y == 0)
			return mask; // -1 in SEW bits
		i64 const minv = -(i64)((1ull << (bits - 1)) - 1) - 1;
		if (x == minv && y == -1)
			return (u64)x & mask; // overflow: dividend
		return (u64)(x / y) & mask;
	}
	case VF6_VREMU:
		return (b & mask) == 0 ? (a & mask) : ((a & mask) % (b & mask));
	case VF6_VREM: {
		i64 const x = sx(a), y = sx(b);
		if (y == 0)
			return (u64)x & mask;
		i64 const minv = -(i64)((1ull << (bits - 1)) - 1) - 1;
		if (x == minv && y == -1)
			return 0;
		return (u64)(x % y) & mask;
	}
	// Multiply-accumulate. Note the operand roles differ between the macc and madd pairs:
	// vmacc/vnmsac multiply the two SOURCES and accumulate into vd; vmadd/vnmsub multiply vd
	// by the scalar/vector operand and add the other source.
	case VF6_VMACC:
		return lo((unsigned __int128)(b & mask) * (a & mask) + (vd_old & mask));
	case VF6_VNMSAC:
		return lo((unsigned __int128)(vd_old & mask) -
			  (unsigned __int128)((b & mask) * (a & mask)));
	case VF6_VMADD:
		return lo((unsigned __int128)(b & mask) * (vd_old & mask) + (a & mask));
	default: // VF6_VNMSUB
		return lo((unsigned __int128)(a & mask) -
			  (unsigned __int128)((b & mask) * (vd_old & mask)));
	}
}

inline void vimul(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		  bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const a = vs.elem_u(vs2, e, sew_bytes, vlen);
		u64 const b = src == VSrc::VV ? vs.elem_u(vs1, e, sew_bytes, vlen)
					      : (u64)(i64)(i32)rs1_val;
		u64 const old = vimul_reads_vd(funct6) ? vs.elem_u(vd, e, sew_bytes, vlen) : 0;
		vs.elem_put(vd, e, sew_bytes, vlen, vimul_apply(funct6, old, a, b, sew_bytes));
	}
}

// ---- reductions and the scalar element interface --------------------------------------------
// One family because both concern element 0 of a vector register used as a SCALAR slot:
//   vred*.vs   vd[0] = vs1[0] OP (fold over the active elements of the vs2 GROUP)
//   vmv.s.x    vd[0] = x[rs1]                (write the scalar slot)
//   vmv.x.s    x[rd] = vs2[0]                (read the scalar slot)
// The reduction's scalar seed coming from vs1[0] -- not from a GPR -- is what lets a compiler
// chain partial reductions without leaving the vector unit.
ALWAYS_INLINE u64 vred_combine(u32 funct6, u64 acc, u64 x, u32 sew_bytes)
{
	u32 const sh = 64 - 8 * sew_bytes;
	auto sx = [sh](u64 v) { return (i64)(v << sh) >> sh; };
	switch (funct6) {
	case VF6_VREDSUM:  return acc + x;
	case VF6_VREDAND:  return acc & x;
	case VF6_VREDOR:   return acc | x;
	case VF6_VREDXOR:  return acc ^ x;
	case VF6_VREDMINU: return x < acc ? x : acc;
	case VF6_VREDMIN:  return sx(x) < sx(acc) ? x : acc;
	case VF6_VREDMAXU: return x > acc ? x : acc;
	default:           return sx(x) > sx(acc) ? x : acc; // VREDMAX
	}
}

inline void vred(VectorState &vs, u32 funct6, u32 vd, u32 vs2, u32 vs1, bool vm, u32 vlen, u32 vl,
		 u32 sew_bytes)
{
	// vl == 0 leaves vd[0] untouched (RVV 1.0: the reduction is a no-op, not "write the seed").
	if (vl == 0)
		return;
	u64 acc = vs.elem_u(vs1, 0, sew_bytes, vlen); // scalar seed from vs1[0]
	for (u32 e = 0; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		acc = vred_combine(funct6, acc, vs.elem_u(vs2, e, sew_bytes, vlen), sew_bytes);
	}
	vs.elem_put(vd, 0, sew_bytes, vlen, acc);
}


// ---- vector FP semantics ---------------------------------------------------------------------
// Written against the SAME helpers as the scalar F/D unit (rv32_fpu.h), so IEEE behaviour --
// rounding mode, accrued flags, NaN canonicalisation, min/max NaN rules -- cannot differ
// between the scalar and vector paths. Element width is SEW: 32 = binary32, 64 = binary64.

ALWAYS_INLINE double vf_read(VectorState &vs, u32 reg, u32 e, u32 sew, u32 vlen)
{
	u64 const b = vs.elem_u(reg, e, sew, vlen);
	return sew == 4 ? (double)bits_to_f32((u32)b) : bits_to_f64(b);
}
ALWAYS_INLINE void vf_write(VectorState &vs, u32 reg, u32 e, u32 sew, u32 vlen, double v)
{
	u64 const b = sew == 4 ? (u64)f32_canon(f32_to_bits((float)v)) : f64_canon(f64_to_bits(v));
	vs.elem_put(reg, e, sew, vlen, b);
}
// Raw-bit access, for the operations that manipulate sign bits rather than values.
ALWAYS_INLINE u64 vf_bits(VectorState &vs, u32 reg, u32 e, u32 sew, u32 vlen)
{
	return vs.elem_u(reg, e, sew, vlen);
}

// The scalar operand of a .vf form comes from an F register, not a GPR.
ALWAYS_INLINE double vf_scalar(FPUState &fs, u32 rs1, u32 sew)
{
	return sew == 4 ? (double)bits_to_f32(f32_unbox(fs.f[rs1])) : bits_to_f64(fs.f[rs1]);
}

// SEW=32 elements are computed in `float`, NOT double-then-narrow.
//
// For + - * / and sqrt, double rounding via binary64 is value-exact for binary32
// (53 >= 2*24+2), so computing in double produced the right VALUES. It did NOT produce the
// right EXCEPTION FLAGS: an operation that overflows or goes subnormal in binary32 does neither
// in binary64, so OF/UF/NX were silently wrong. FMA is worse -- the fused result is not covered
// by the double-rounding argument at all. Computing at the element width fixes both.
#define VF_BINOP(EXPR)                                                                                       \
	do {                                                                                                 \
		if (sew == 4) {                                                                              \
			float const x = bits_to_f32((u32)abits), y = bits_to_f32((u32)bbits);                \
			vs.elem_put(vd, e, sew, vlen, (u64)f32_canon(f32_to_bits(EXPR)));                    \
		} else {                                                                                     \
			double const x = bits_to_f64(abits), y = bits_to_f64(bbits);                         \
			vs.elem_put(vd, e, sew, vlen, f64_canon(f64_to_bits(EXPR)));                         \
		}                                                                                            \
	} while (0)

// Same operation through the exact integer core. Vector FP has no rm field, so `md` always came
// from fcsr.frm; this path is what executes when that says RMM.
ALWAYS_INLINE u64 vf_soft_binop(FPUState &fs, FpMode md, u32 f6, u64 a, u64 b, u32 sew)
{
	auto const &F = sew == 4 ? softfp::FMT32 : softfp::FMT64;
	u32 fl = 0;
	u64 z;
	switch (f6) {
	case VF6_VFADD:
		z = softfp::op_add(a, b, false, F, md.rm, fl);
		break;
	case VF6_VFSUB:
		z = softfp::op_add(a, b, true, F, md.rm, fl);
		break;
	case VF6_VFRSUB:
		z = softfp::op_add(b, a, true, F, md.rm, fl);
		break;
	case VF6_VFMUL:
		z = softfp::op_mul(a, b, F, md.rm, fl);
		break;
	case VF6_VFDIV:
		z = softfp::op_div(a, b, F, md.rm, fl);
		break;
	default: // VF6_VFRDIV
		z = softfp::op_div(b, a, F, md.rm, fl);
		break;
	}
	fs.raise(fl);
	return z;
}

#define VF_ARITH(EXPR)                                                                               \
	do {                                                                                         \
		if (md.path == FP_SOFT)                                                              \
			vs.elem_put(vd, e, sew, vlen,                                                \
				    vf_soft_binop(fs, md, f6, abits, bbits, sew));                   \
		else                                                                                 \
			VF_BINOP(EXPR);                                                              \
	} while (0)

// Starts at vstart: the prestart elements keep their old values. The rounding bracket is opened
// once, before the loop, so the restart changes which elements are computed and nothing else.
inline void vfalu(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		  bool vm, u32 vlen, u32 vl, u32 sew, u32 vstart = 0)
{
	FpMode const md = fp_mode(fs, FRM_DYN);
	FRound r(fs, md);
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const abits = vf_bits(vs, vs2, e, sew, vlen);
		u64 const bbits = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
					: vf_bits(vs, vs1, e, sew, vlen);
		switch (f6) {
		case VF6_VFADD: VF_ARITH(x + y); break;
		case VF6_VFSUB: VF_ARITH(x - y); break;
		case VF6_VFRSUB: VF_ARITH(y - x); break;
		case VF6_VFMUL: VF_ARITH(x * y); break;
		case VF6_VFDIV: VF_ARITH(x / y); break;
		case VF6_VFRDIV: VF_ARITH(y / x); break;
		case VF6_VFMIN:
		case VF6_VFMAX: {
			bool const mx = f6 == VF6_VFMAX;
			u64 res = sew == 4
				      ? (u64)f32_minmax(fs, (u32)abits, (u32)bbits, mx)
				      : f64_minmax(fs, abits, bbits, mx);
			vs.elem_put(vd, e, sew, vlen, res);
			break;
		}
		default: { // sign injection: pure bit manipulation, no flags, no canonicalisation
			u64 const sign_bit = sew == 4 ? (1ull << 31) : (1ull << 63);
			u64 const mag = abits & ~sign_bit;
			u64 sign = f6 == VF6_VFSGNJ ? (bbits & sign_bit)
						    : f6 == VF6_VFSGNJN ? (~bbits & sign_bit)
									: ((abits ^ bbits) & sign_bit);
			vs.elem_put(vd, e, sew, vlen, mag | sign);
			break;
		}
		}
	}
	r.finish(fs);
}

// Starts at vstart, for vfalu's reason: vd is also an operand here, so a prestart element that was
// recomputed would be multiplied into its own already-updated value.
inline void vfma(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		 bool vm, u32 vlen, u32 vl, u32 sew, u32 vstart = 0)
{
	FpMode const md = fp_mode(fs, FRM_DYN);
	FRound r(fs, md);
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		if (md.path == FP_SOFT) {
			// The exact core takes the three operands in canonical (a*b)+c order, with the
			// negations that distinguish the eight forms passed as flags rather than folded
			// into the operands.
			u64 const ab = vf_bits(vs, vs2, e, sew, vlen);
			u64 const bb = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
					     : vf_bits(vs, vs1, e, sew, vlen);
			u64 const db = vf_bits(vs, vd, e, sew, vlen);
			auto const &F = sew == 4 ? softfp::FMT32 : softfp::FMT64;
			u32 fl = 0;
			u64 z;
			switch (f6) {
			case VF6_VFMACC:  z = softfp::op_fma(bb, ab, db, false, false, F, md.rm, fl); break;
			case VF6_VFNMACC: z = softfp::op_fma(bb, ab, db, true, true, F, md.rm, fl); break;
			case VF6_VFMSAC:  z = softfp::op_fma(bb, ab, db, false, true, F, md.rm, fl); break;
			case VF6_VFNMSAC: z = softfp::op_fma(bb, ab, db, true, false, F, md.rm, fl); break;
			case VF6_VFMADD:  z = softfp::op_fma(db, bb, ab, false, false, F, md.rm, fl); break;
			case VF6_VFNMADD: z = softfp::op_fma(db, bb, ab, true, true, F, md.rm, fl); break;
			case VF6_VFMSUB:  z = softfp::op_fma(db, bb, ab, false, true, F, md.rm, fl); break;
			default:          z = softfp::op_fma(db, bb, ab, true, false, F, md.rm, fl); break;
			}
			fs.raise(fl);
			vs.elem_put(vd, e, sew, vlen, z);
			continue;
		}
		if (sew == 4) {
			// binary32 FMA must use fmaf: the fused product-sum is NOT covered by the
			// double-rounding exactness argument, so double-then-narrow can differ.
			float const a = bits_to_f32((u32)vf_bits(vs, vs2, e, sew, vlen));
			float const b = is_vf ? bits_to_f32(f32_unbox(fs.f[vs1]))
					      : bits_to_f32((u32)vf_bits(vs, vs1, e, sew, vlen));
			float const d = bits_to_f32((u32)vf_bits(vs, vd, e, sew, vlen));
			float r32;
			switch (f6) {
			case VF6_VFMACC:  r32 = std::fmaf(b, a, d); break;
			case VF6_VFNMACC: r32 = std::fmaf(-b, a, -d); break;
			case VF6_VFMSAC:  r32 = std::fmaf(b, a, -d); break;
			case VF6_VFNMSAC: r32 = std::fmaf(-b, a, d); break;
			case VF6_VFMADD:  r32 = std::fmaf(d, b, a); break;
			case VF6_VFNMADD: r32 = std::fmaf(-d, b, -a); break;
			case VF6_VFMSUB:  r32 = std::fmaf(d, b, -a); break;
			default:          r32 = std::fmaf(-d, b, a); break;
			}
			vs.elem_put(vd, e, sew, vlen, (u64)f32_canon(f32_to_bits(r32)));
			continue;
		}
		double const a = vf_read(vs, vs2, e, sew, vlen);
		double const b = is_vf ? vf_scalar(fs, vs1, sew) : vf_read(vs, vs1, e, sew, vlen);
		double const d = vf_read(vs, vd, e, sew, vlen);
		double res;
		// macc/msac multiply the two SOURCES and accumulate into vd; madd/msub multiply vd
		// by an operand and add the other -- the same asymmetry as the integer forms.
		switch (f6) {
		case VF6_VFMACC:  res = std::fma(b, a, d); break;
		case VF6_VFNMACC: res = std::fma(-b, a, -d); break;
		case VF6_VFMSAC:  res = std::fma(b, a, -d); break;
		case VF6_VFNMSAC: res = std::fma(-b, a, d); break;
		case VF6_VFMADD:  res = std::fma(d, b, a); break;
		case VF6_VFNMADD: res = std::fma(-d, b, -a); break;
		case VF6_VFMSUB:  res = std::fma(d, b, -a); break;
		default:          res = std::fma(-d, b, a); break; // VFNMSUB
		}
		vf_write(vs, vd, e, sew, vlen, res);
	}
	r.finish(fs);
}

// Single-element compare, factored out of the loop below so rv32_vector_fast.h's residue path
// (the sub-chunk tail the fast path finishes element-wise) can call the SAME logic instead of
// re-deriving it independently -- two independent encodings of six predicates x quiet/signalling
// NaN classification is exactly the kind of duplication that drifts silently, which is why
// vialu_apply (this file, integer ALU) already gets called from both the reference loop and
// rv32_vector_fast.h's residue; this gives vfcmp the same structure.
ALWAYS_INLINE bool vfcmp_apply(FPUState &fs, u32 f6, u64 ab, u64 bb, u32 sew)
{
	// Compare on the RAW BITS at element width. Reading through a double loses the
	// distinction this needs: converting an f32 signalling NaN to double quiets it, so
	// an sNaN operand became indistinguishable from a qNaN and vmfeq/vmfne silently
	// raised no invalid flag where QEMU raises one.
	bool nan, snan;
	double a, b;
	if (sew == 4) {
		float const x = bits_to_f32((u32)ab), y = bits_to_f32((u32)bb);
		nan = std::isnan(x) || std::isnan(y);
		snan = f32_is_snan((u32)ab) || f32_is_snan((u32)bb);
		a = (double)x;
		b = (double)y;
	} else {
		a = bits_to_f64(ab);
		b = bits_to_f64(bb);
		nan = std::isnan(a) || std::isnan(b);
		snan = f64_is_snan(ab) || f64_is_snan(bb);
	}
	// vmfeq/vmfne are QUIET comparisons: only a signalling NaN raises invalid. The
	// ordered comparisons signal on any NaN.
	bool const quiet = f6 == VF6_VMFEQ || f6 == VF6_VMFNE;
	if (quiet ? snan : nan)
		fs.raise(FFLAG_NV);
	switch (f6) {
	case VF6_VMFEQ: return !nan && a == b;
	case VF6_VMFNE: return nan || a != b;
	case VF6_VMFLT: return !nan && a < b;
	case VF6_VMFLE: return !nan && a <= b;
	case VF6_VMFGT: return !nan && a > b;
	default:        return !nan && a >= b; // VMFGE
	}
}

// Starts at vstart: the prestart mask bits must be left as they are.
inline void vfcmp(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		  bool vm, u32 vlen, u32 vl, u32 sew, u32 vstart = 0)
{
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const ab = vf_bits(vs, vs2, e, sew, vlen);
		u64 const bb = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
				     : vf_bits(vs, vs1, e, sew, vlen);
		vs.mask_set(vd, e, vfcmp_apply(fs, f6, ab, bb, sew));
	}
}

// The four ablation cells are TEMPLATE parameters, not runtime flags, and the per-element test is
// `if constexpr`. That is a measurement-validity requirement, not a style choice: when these were
// two ordinary `bool const`s, LLVM stopped unswitching the loop for the SEW=64 instantiation and
// every arm silently acquired a per-element branch. On tsvc_s311 that was lost in a 52 % effect,
// but on pb_atax -- where the whole effect is ~4 % -- the branch cost about as much as the
// canonicalisation being removed, and the arm under test measured as no gain at all. An ablation
// whose arms differ by anything other than the component under test is measuring its own scaffolding.
template <bool NativeAcc, bool CanonAtEnd>
ALWAYS_INLINE void vfred_sum32(VectorState &vs, u32 vd, u32 vs2, u32 vlen, u32 vl, u64 acc)
{
	if constexpr (NativeAcc) {
		float a = bits_to_f32((u32)acc);
		for (u32 e = 0; e < vl; ++e) {
			a += bits_to_f32((u32)vf_bits(vs, vs2, e, 4, vlen));
			if constexpr (!CanonAtEnd)
				a = bits_to_f32(f32_canon(f32_to_bits(a)));
		}
		vs.elem_put(vd, 0, 4, vlen, (u64)f32_canon(f32_to_bits(a)));
	} else {
		u32 b = (u32)acc;
		for (u32 e = 0; e < vl; ++e) {
			b = f32_to_bits(bits_to_f32(b) + bits_to_f32((u32)vf_bits(vs, vs2, e, 4, vlen)));
			if constexpr (!CanonAtEnd)
				b = f32_canon(b);
		}
		vs.elem_put(vd, 0, 4, vlen, (u64)f32_canon(b));
	}
}

template <bool NativeAcc, bool CanonAtEnd>
ALWAYS_INLINE void vfred_sum64(VectorState &vs, u32 vd, u32 vs2, u32 vlen, u32 vl, u64 acc)
{
	if constexpr (NativeAcc) {
		double a = bits_to_f64(acc);
		for (u32 e = 0; e < vl; ++e) {
			a += bits_to_f64(vf_bits(vs, vs2, e, 8, vlen));
			if constexpr (!CanonAtEnd)
				a = bits_to_f64(f64_canon(f64_to_bits(a)));
		}
		vs.elem_put(vd, 0, 8, vlen, f64_canon(f64_to_bits(a)));
	} else {
		u64 b = acc;
		for (u32 e = 0; e < vl; ++e) {
			b = f64_to_bits(bits_to_f64(b) + bits_to_f64(vf_bits(vs, vs2, e, 8, vlen)));
			if constexpr (!CanonAtEnd)
				b = f64_canon(b);
		}
		vs.elem_put(vd, 0, 8, vlen, f64_canon(b));
	}
}

// STAGE 5 MEASUREMENT ARM: stage 3 plus HOISTED ELEMENT ADDRESSING.
//
// Motivated by measurement, not by inspection alone. After the canonicalisation fix, tsvc_s311 at
// VLEN=1024 costs 5.479 cyc per reduction element while the semantics-equivalent native reference
// costs 1.959 -- and 1.959 is exactly the independently measured dependent-FP-add floor
// (raw/fp_add_latency.csv, chain_reset), so the arithmetic is already AT its floor and all 3.52
// remaining cycles per element are something else.
//
// `VectorState::elem_ptr` is that something else's leading candidate: per element it recomputes
// two __builtin_ctz, a subtract, a shift, a mask, a multiply and a two-dimensional index -- even
// though vlen and SEW are fixed for the whole instruction and a register's elements are contiguous
// (`vreg` is std::array<std::array<u8, VLEN_MAX_BYTES>, VREG_NUM>, so the row stride is constant).
//
// Hoisting it is the SAME CLASS of transformation as the shipped method -- take loop-invariant work
// out of the element loop -- and it is derived from the register group's layout invariant, not from
// any workload. It is staged as a measurement arm first so its contribution is measured before any
// claim is made about it.
template <bool Wide>
ALWAYS_INLINE void vfred_sum_hoist(VectorState &vs, u32 vd, u32 vs2, u32 vlen, u32 vl, u64 acc)
{
	constexpr u32 SEW = Wide ? 8 : 4;
	u32 const per_reg = (vlen >> 3) / SEW; // elements of this width per vector register
	u32 reg = vs2;
	using F = std::conditional_t<Wide, double, float>;
	F a = Wide ? (F)bits_to_f64(acc) : (F)bits_to_f32((u32)acc);
	for (u32 e0 = 0; e0 < vl; e0 += per_reg, ++reg) {
		u32 const n = (vl - e0) < per_reg ? (vl - e0) : per_reg;
		u8 const *const base = &vs.vreg[reg][0];
		for (u32 k = 0; k < n; ++k) {
			if constexpr (Wide) {
				u64 t;
				__builtin_memcpy(&t, base + k * 8, 8);
				a += bits_to_f64(t);
			} else {
				u32 t;
				__builtin_memcpy(&t, base + k * 4, 4);
				a += bits_to_f32(t);
			}
		}
	}
	if constexpr (Wide)
		vs.elem_put(vd, 0, 8, vlen, f64_canon(f64_to_bits(a)));
	else
		vs.elem_put(vd, 0, 4, vlen, (u64)f32_canon(f32_to_bits((float)a)));
}

inline void vfred(VectorState &vs, FPUState &fs, u32 f6, u32 vd, u32 vs2, u32 vs1, bool vm,
		  u32 vlen, u32 vl, u32 sew)
{
	if (vl == 0)
		return;
	FpMode const md = fp_mode(fs, FRM_DYN);
	FRound r(fs, md);
	// The accumulator is carried as ELEMENT-WIDTH BITS, not as a double that is narrowed each
	// step. Narrowing kept the values right (53 >= 2*24+2) but produced binary64 exception
	// flags for a binary32 reduction, so an intermediate that overflows or goes subnormal at
	// SEW=32 reported nothing.
	u64 acc = vf_bits(vs, vs1, 0, sew, vlen); // scalar seed from vs1[0]

	// Specialised path: hoist the loop-invariant semantic decisions out of the element loop and
	// keep the accumulator in its native type. Ordering is UNCHANGED -- this is still a strictly
	// sequential accumulation in element order, which is what vfredosum requires and what
	// vfredusum permits, so it is legal for both. Restricted to the exact shape it was proven
	// for: host FP path, unmasked, SEW=32 or 64, sum. Everything else falls through to the
	// general loop below, so this can only ever be a fast path, never a semantic change.
	//
	// WHY CANONICALISATION MAY MOVE TO THE END. `f32_canon`/`f64_canon` rewrite any NaN to the
	// architectural canonical NaN; they change nothing else. A reduction's intermediate
	// accumulator is NOT architectural state -- only the final element 0 is -- so the only
	// question is whether deferring canonicalisation can change the final value or the flags:
	//   * value: NaN is absorbing for +. Once the accumulator is a NaN it stays a NaN for every
	//     remaining element, under either payload, and the final canon maps every NaN to the same
	//     canonical NaN. So the two orders agree on the final value.
	//   * flags: the per-element canon is a pure bit rewrite -- it raises nothing. The host add
	//     raises NV for an sNaN operand and that operand comes from vs2, which canon never
	//     touches. Adding a NaN (canonical or not) to anything raises nothing further. So the
	//     flag sequence is identical element for element.
	// This is the semantic invariant the method rests on, and it is proven rather than asserted:
	// the differential gate compares against QEMU 11.1.0 over sNaN/qNaN/inf/subnormal/+-0/overflow
	// inputs as both seed and data, in all five rounding modes, folding fcsr into the hash.
	if (config::rvv_fred_specialize && md.path == FP_HOST && vm &&
	    (f6 == VF6_VFREDUSUM || f6 == VF6_VFREDOSUM) && (sew == 4 || sew == 8)) {
		// SEW is a SEMANTIC INVARIANT of the instruction, so specialising on it is the same
		// kind of hoisting as the opcode/mode/mask tests -- not workload tuning. Both widths
		// occur in real code: TSVC's float reductions are SEW=32, PolyBench's double
		// reductions (pb_atax) are SEW=64.
		//
		// Ordering is UNCHANGED in every stage: strictly sequential accumulation in element
		// order, which vfredosum requires and vfredusum permits.
		// The two remaining components are crossed rather than nested, so each one's effect can
		// be read at BOTH levels of the other and the attribution does not depend on the order
		// they are applied in. Stage 4 is the fourth cell of that 2x2; it is not a proposed
		// implementation (a bits accumulator with no per-element canonicalisation is strictly
		// worse than stage 3), it exists so the canonicalisation effect is measurable
		// independently of the accumulator change.
		// One switch outside the loop selects an already-specialised, branch-free instantiation.
		// <NativeAcc, CanonAtEnd>: 1=<false,false> 2=<true,false> 3=<true,true> 4=<false,true>.
#define VFRED_CELL(NA, CE)                                                                         \
	do {                                                                                       \
		if (sew == 4)                                                                      \
			vfred_sum32<NA, CE>(vs, vd, vs2, vlen, vl, acc);                           \
		else                                                                               \
			vfred_sum64<NA, CE>(vs, vd, vs2, vlen, vl, acc);                           \
	} while (0)
		switch (config::rvv_fred_specialize) {
		case 1:
			VFRED_CELL(false, false);
			break;
		case 2:
			VFRED_CELL(true, false);
			break;
		case 3:
			VFRED_CELL(true, true);
			break;
		case 5: // stage 3 + hoisted element addressing (measurement arm)
			if (sew == 4)
				vfred_sum_hoist<false>(vs, vd, vs2, vlen, vl, acc);
			else
				vfred_sum_hoist<true>(vs, vd, vs2, vlen, vl, acc);
			break;
		default:
			VFRED_CELL(false, true);
			break; // stage 4
		}
#undef VFRED_CELL
		r.finish(fs);
		return;
	}

	for (u32 e = 0; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const x = vf_bits(vs, vs2, e, sew, vlen);
		switch (f6) {
		case VF6_VFREDUSUM:
		case VF6_VFREDOSUM:
			// Ordered and unordered sums are implemented identically -- sequential in
			// element order. That is a LEGAL implementation of vfredusum (which permits
			// any order) and the required one for vfredosum, so both are correct; it
			// simply means unordered gains no reassociation freedom here.
			if (md.path == FP_SOFT) {
				u32 fl = 0;
				acc = softfp::op_add(acc, x, false,
						     sew == 4 ? softfp::FMT32 : softfp::FMT64, md.rm,
						     fl);
				fs.raise(fl);
			} else if (sew == 4) {
				acc = (u64)f32_canon(
				    f32_to_bits(bits_to_f32((u32)acc) + bits_to_f32((u32)x)));
			} else {
				acc = f64_canon(f64_to_bits(bits_to_f64(acc) + bits_to_f64(x)));
			}
			break;
		case VF6_VFREDMIN:
			acc = sew == 4 ? (u64)f32_minmax(fs, (u32)acc, (u32)x, false)
				       : f64_minmax(fs, acc, x, false);
			break;
		default:
			acc = sew == 4 ? (u64)f32_minmax(fs, (u32)acc, (u32)x, true)
				       : f64_minmax(fs, acc, x, true);
			break;
		}
	}
	vs.elem_put(vd, 0, sew, vlen, acc);
	r.finish(fs);
}

// VFUNARY0: single-width, widening (dest SEW = 2x) and narrowing (source SEW = 2x) conversions.
// `dsew`/`ssew` are the destination and source element widths in bytes, resolved by the caller
// from the sub-encoding, which is what makes the EMUL of each side differ.
inline void vfcvt(VectorState &vs, FPUState &fs, u32 sub, u32 vd, u32 vs2, bool vm, u32 vlen,
		  u32 vl, u32 ssew, u32 dsew)
{
	// The rtz forms round toward zero regardless of frm; vfncvt.rod uses round-to-odd, which
	// is not an architectural mode and has no host equivalent, so it always takes the exact
	// path; everything else uses frm.
	bool const rtz = sub == 0b00110 || sub == 0b00111 || sub == 0b01110 || sub == 0b01111 ||
			 sub == 0b10110 || sub == 0b10111;
	bool const rod = sub == 0b10101;
	FpMode md = fp_mode(fs, rtz ? FRM_RTZ : FRM_DYN);
	if (rod)
		md = FpMode{FRM_ROD, FP_SOFT};
	FRound r(fs, md);
	u32 const kind = sub & 0b00111; // low bits select xu/x/f-from-xu/f-from-x/f-from-f
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		if (kind == 0 || kind == 1 || kind == 6 || kind == 7) {
			u32 fl = 0;
			u64 const result = softfp::cvt_to_int_width(vf_bits(vs, vs2, e, ssew, vlen),
				(kind & 1) != 0, ssew == 4 ? softfp::FMT32 : softfp::FMT64, md.rm, dsew * 8, fl);
			vs.elem_put(vd, e, dsew, vlen, result);
			fs.raise(fl);
			continue;
		}
		if (md.path == FP_SOFT) {
			auto const &SF = ssew == 4 ? softfp::FMT32 : softfp::FMT64;
			auto const &DF = dsew == 4 ? softfp::FMT32 : softfp::FMT64;
			u32 fl = 0;
			switch (kind) {
			case 0b010:
				vs.elem_put(vd, e, dsew, vlen,
					    softfp::cvt_from_int(vs.elem_u(vs2, e, ssew, vlen),
								 false, DF, md.rm, fl));
				break;
			case 0b011: {
				i64 const x = vs.elem_i(vs2, e, ssew, vlen);
				vs.elem_put(vd, e, dsew, vlen,
					    softfp::cvt_from_int(x < 0 ? (u64)-x : (u64)x, x < 0, DF,
								 md.rm, fl));
				break;
			}
			default:
				vs.elem_put(vd, e, dsew, vlen,
					    softfp::cvt_fmt(vf_bits(vs, vs2, e, ssew, vlen), SF, DF,
							    md.rm, fl));
				break;
			}
			fs.raise(fl);
			continue;
		}
		switch (kind) {
		// Integer -> float goes through the exact core even on the host path. Clang lowers a
		// 64-bit unsigned-to-double conversion with the magic-constant trick, whose closing
		// subtraction of two equal values yields -0.0 under FE_DOWNWARD, so vfcvt.f.xu.v of
		// zero returned -0.0 where QEMU returns +0.0. That trick is only correct for
		// round-to-nearest at all, so the exposure is not limited to zero, and it is a
		// property of the host's code generation rather than of anything this file states.
		// The scalar unit escapes it only because it converts at 32-bit width, where the
		// hardware instruction is used directly.
		case 0b010: { // *cvt.f.xu -- unsigned integer to float
			u32 fl = 0;
			vs.elem_put(vd, e, dsew, vlen,
				    softfp::cvt_from_int(vs.elem_u(vs2, e, ssew, vlen), false,
							 dsew == 4 ? softfp::FMT32 : softfp::FMT64,
							 md.rm, fl));
			fs.raise(fl);
			break;
		}
		case 0b011: { // *cvt.f.x -- signed integer to float
			i64 const x = vs.elem_i(vs2, e, ssew, vlen);
			u32 fl = 0;
			vs.elem_put(vd, e, dsew, vlen,
				    softfp::cvt_from_int(x < 0 ? (u64)-x : (u64)x, x < 0,
							 dsew == 4 ? softfp::FMT32 : softfp::FMT64,
							 md.rm, fl));
			fs.raise(fl);
			break;
		}
		default: { // 0b100: *cvt.f.f -- float to float (widen or narrow)
			double const v = vf_read(vs, vs2, e, ssew, vlen);
			vf_write(vs, vd, e, dsew, vlen, dsew == 4 ? (double)(float)v : v);
			break;
		}
		}
	}
	r.finish(fs);
}

// VFUNARY1: vfsqrt (sub=00000) and vfclass (sub=10000).
// ---- vfrsqrt7 / vfrec7: 7-bit reciprocal and reciprocal-square-root estimates ------------------
//
// These are NOT implementation-defined. RVV 1.0 specifies them by EXACT lookup table, so two
// conforming implementations produce identical bits and a differential against QEMU is
// meaningful. An earlier note in the coverage matrix claimed otherwise and was wrong.
//
// Both tables are indexed by the top bits of the significand (vfrsqrt7 additionally by the low
// bit of the exponent, because the square root of an odd-exponent value falls in a different
// binade). The table entry becomes the top 7 bits of the result significand and the rest is zero
// -- hence "7", and hence the results being estimates rather than correctly-rounded values.
static constexpr u8 VFRSQRT7_TAB[128] = {
    52,  51,  50,  48,  47,  46,  44,  43,  42,  41,  40,  39,  38,  36,  35,  34,
    33,  32,  31,  30,  30,  29,  28,  27,  26,  25,  24,  23,  23,  22,  21,  20,
    19,  19,  18,  17,  16,  16,  15,  14,  14,  13,  12,  12,  11,  10,  10,  9,
    9,   8,   7,   7,   6,   6,   5,   4,   4,   3,   3,   2,   2,   1,   1,   0,
    127, 125, 123, 121, 119, 118, 116, 114, 113, 111, 109, 108, 106, 105, 103, 102,
    100, 99,  97,  96,  95,  93,  92,  91,  90,  88,  87,  86,  85,  84,  83,  82,
    80,  79,  78,  77,  76,  75,  74,  73,  72,  71,  70,  70,  69,  68,  67,  66,
    65,  64,  63,  63,  62,  61,  60,  59,  59,  58,  57,  56,  56,  55,  54,  53,
};
static constexpr u8 VFREC7_TAB[128] = {
    127, 125, 123, 121, 119, 117, 116, 114, 112, 110, 109, 107, 105, 104, 102, 100,
    99,  97,  96,  94,  93,  91,  90,  88,  87,  85,  84,  83,  81,  80,  79,  77,
    76,  75,  74,  72,  71,  70,  69,  68,  66,  65,  64,  63,  62,  61,  60,  59,
    58,  57,  56,  55,  54,  53,  52,  51,  50,  49,  48,  47,  46,  45,  44,  43,
    42,  41,  40,  40,  39,  38,  37,  36,  35,  35,  34,  33,  32,  31,  31,  30,
    29,  28,  28,  27,  26,  25,  25,  24,  23,  23,  22,  21,  21,  20,  19,  19,
    18,  17,  17,  16,  15,  15,  14,  14,  13,  12,  12,  11,  11,  10,  9,   9,
    8,   8,   7,   7,   6,   5,   5,   4,   4,   3,   3,   2,   2,   1,   1,   0,
};

// Normalise a subnormal significand: shift left until the hidden bit position is set, returning
// the adjusted (still unbiased-by-format) exponent. Both estimates must do this because the
// table index is defined on the NORMALISED significand.
ALWAYS_INLINE void vfest_normalize(u64 &sig, i32 &exp, u32 mant_bits)
{
	while ((sig & ((u64)1 << mant_bits)) == 0) {
		sig <<= 1;
		exp -= 1;
	}
	sig &= ((u64)1 << mant_bits) - 1; // drop the hidden bit again
}

inline u64 vfrsqrt7_elem(FPUState &fs, u64 bits, u32 sew)
{
	u32 const mant = sew == 4 ? 23 : 52;
	u32 const expb = sew == 4 ? 8 : 11;
	i32 const bias = sew == 4 ? 127 : 1023;
	u64 const qnan = sew == 4 ? F32_CANONICAL_NAN : F64_CANONICAL_NAN;
	u64 const emask = ((u64)1 << expb) - 1;
	bool const sign = (bits >> (mant + expb)) & 1;
	i32 e = (i32)((bits >> mant) & emask);
	u64 sig = bits & (((u64)1 << mant) - 1);

	if (e == (i32)emask)
		return sig ? (sew == 4 ? (f32_is_snan((u32)bits) ? (fs.raise(FFLAG_NV), qnan) : qnan)
					: (f64_is_snan(bits) ? (fs.raise(FFLAG_NV), qnan) : qnan))
			   : (sign ? (fs.raise(FFLAG_NV), qnan) : 0); // +inf -> +0
	if (e == 0 && sig == 0) { // +/-0 -> +/-inf, divide-by-zero
		fs.raise(FFLAG_DZ);
		return ((u64)sign << (mant + expb)) | (emask << mant);
	}
	if (sign) { // any other negative operand is invalid
		fs.raise(FFLAG_NV);
		return qnan;
	}
	if (e == 0) { // subnormal: normalise before indexing
		u64 full = sig;
		i32 ee = 1;
		while ((full & ((u64)1 << mant)) == 0) {
			full <<= 1;
			ee -= 1;
		}
		sig = full & (((u64)1 << mant) - 1);
		e = ee;
	}
	// Index: low bit of the (biased) exponent, then the top 6 significand bits.
	u32 const idx = (u32)(((e & 1) << 6) | (u32)(sig >> (mant - 6)));
	u64 const out_sig = (u64)VFRSQRT7_TAB[idx] << (mant - 7);
	i32 const out_exp = (3 * bias - 1 - e) / 2;
	return ((u64)(u32)out_exp << mant) | out_sig;
}

inline u64 vfrec7_elem(FPUState &fs, u64 bits, u32 sew, u32 rm)
{
	u32 const mant = sew == 4 ? 23 : 52;
	u32 const expb = sew == 4 ? 8 : 11;
	i32 const bias = sew == 4 ? 127 : 1023;
	u64 const qnan = sew == 4 ? F32_CANONICAL_NAN : F64_CANONICAL_NAN;
	u64 const emask = ((u64)1 << expb) - 1;
	u64 const sbit = (u64)1 << (mant + expb);
	bool const sign = (bits >> (mant + expb)) & 1;
	i32 e = (i32)((bits >> mant) & emask);
	u64 sig = bits & (((u64)1 << mant) - 1);

	if (e == (i32)emask) {
		if (sig) {
			bool const sn = sew == 4 ? f32_is_snan((u32)bits) : f64_is_snan(bits);
			if (sn)
				fs.raise(FFLAG_NV);
			return qnan;
		}
		return sign ? sbit : 0; // +/-inf -> +/-0
	}
	if (e == 0 && sig == 0) { // +/-0 -> +/-inf
		fs.raise(FFLAG_DZ);
		return (sign ? sbit : 0) | (emask << mant);
	}
	// A sufficiently small subnormal has a reciprocal beyond the format's range entirely.
	if (e == 0) {
		i32 const lead = [&] {
			i32 n = 0;
			u64 t = sig;
			while ((t & ((u64)1 << (mant - 1))) == 0) {
				t <<= 1;
				n++;
			}
			return n;
		}();
		if (lead > 1) {
			// Overflows: the result depends on the rounding mode, exactly as an
			// overflowing arithmetic result does.
			fs.raise(FFLAG_NX | FFLAG_OF);
			bool const to_inf = (rm == FRM_RNE || rm == FRM_RMM) ||
					    (rm == FRM_RUP && !sign) || (rm == FRM_RDN && sign);
			return (sign ? sbit : 0) |
			       (to_inf ? (emask << mant)
				       : (((emask - 1) << mant) | (((u64)1 << mant) - 1)));
		}
		// Otherwise normalise and continue.
		u64 full = sig;
		i32 ee = 1;
		while ((full & ((u64)1 << mant)) == 0) {
			full <<= 1;
			ee -= 1;
		}
		sig = full & (((u64)1 << mant) - 1);
		e = ee;
	}
	u32 const idx = (u32)(sig >> (mant - 7));
	u64 out_sig = (u64)VFREC7_TAB[idx] << (mant - 7);
	i32 out_exp = 2 * bias - 1 - e;
	if (out_exp <= 0) {
		// The reciprocal is subnormal: the hidden bit becomes explicit and the significand
		// shifts right, which is where the estimate loses its last bits.
		if (out_exp < -1) {
			fs.raise(FFLAG_NX | FFLAG_OF);
			return (sign ? sbit : 0) | (emask << mant);
		}
		out_sig = (out_sig | ((u64)1 << mant)) >> (1 - out_exp);
		out_exp = 0;
	}
	return (sign ? sbit : 0) | ((u64)(u32)out_exp << mant) | out_sig;
}

inline void vfunary1(VectorState &vs, FPUState &fs, u32 sub, u32 vd, u32 vs2, bool vm, u32 vlen,
		     u32 vl, u32 sew)
{
	FpMode const md = fp_mode(fs, FRM_DYN);
	FRound r(fs, md);
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		if (sub == 0b00100 || sub == 0b00101) {
			// The 7-bit estimates are pure table lookups on the operand bits: no
			// rounding mode applies to the significand, though vfrec7's overflow case
			// does consult frm to pick between infinity and the largest finite value.
			u64 const x = vf_bits(vs, vs2, e, sew, vlen);
			vs.elem_put(vd, e, sew, vlen,
				    sub == 0b00100 ? vfrsqrt7_elem(fs, x, sew)
						   : vfrec7_elem(fs, x, sew, md.rm));
		} else if (sub == 0b00000) {
			if (md.path == FP_SOFT) {
				u32 fl = 0;
				vs.elem_put(vd, e, sew, vlen,
					    softfp::op_sqrt(vf_bits(vs, vs2, e, sew, vlen),
							    sew == 4 ? softfp::FMT32 : softfp::FMT64,
							    md.rm, fl));
				fs.raise(fl);
			} else if (sew == 4) {
				float const v = bits_to_f32((u32)vf_bits(vs, vs2, e, sew, vlen));
				vs.elem_put(vd, e, sew, vlen, (u64)f32_canon(f32_to_bits(std::sqrt(v))));
			} else {
				vf_write(vs, vd, e, sew, vlen,
					 std::sqrt(bits_to_f64(vf_bits(vs, vs2, e, sew, vlen))));
			}
		} else {
			u64 const b = vf_bits(vs, vs2, e, sew, vlen);
			u32 const c = sew == 4 ? f32_classify((u32)b) : f64_classify(b);
			vs.elem_put(vd, e, sew, vlen, c);
		}
	}
	r.finish(fs);
}

// vfmerge.vfm (vm=0) / vfmv.v.f (vm=1) -- the FP twin of vmerge/vmv.v.x.
inline void vfmerge(VectorState &vs, FPUState &fs, u32 vd, u32 vs2, u32 rs1, bool vm, u32 vlen,
		    u32 vl, u32 sew)
{
	u64 const sbits = sew == 4 ? (u64)f32_unbox(fs.f[rs1]) : fs.f[rs1];
	for (u32 e = vs.vstart; e < vl; ++e) {
		u64 v;
		if (vm)
			v = sbits;
		else
			v = vs.mask_get(0, e) ? sbits : vs.elem_u(vs2, e, sew, vlen);
		vs.elem_put(vd, e, sew, vlen, v);
	}
}

// ---- whole-register transfers ------------------------------------------------------------
// vmv<nr>r.v / vl<nr>re<eew>.v / vs<nr>r.v move NR ENTIRE registers and are, by definition,
// independent of vl/LMUL. Memory transfers use encoded EEW; register moves use SEW
// only to convert vstart into a byte offset. Complete transfers always move NR*VLEN bits.
inline void whole_reg_move(VectorState &vs, u32 vd, u32 vs2, u32 nregs, u32 vlen_bits)
{
	u32 const bytes = vlen_bits / 8;
	u64 const start=(u64)vs.vstart << ((vs.vtype >> 3)&7);
	for(u32 r=0;r<nregs;++r){
		u32 const end=(r+1)*bytes;
		if(start>=end)continue;
		u32 const offset=start>r*bytes?(u32)start-r*bytes:0;
		if(vd!=vs2)std::memcpy(&vs.vreg[vd+r][offset],&vs.vreg[vs2+r][offset],bytes-offset);
	}
	vs.vstart=0;
}

// N2b candidate 5. `bytes` here is VLEN/8 -- a RUNTIME value, so `std::memcpy` cannot be inlined
// and every whole-register load/store becomes a call into libc's size-dispatching memmove.
// Measured: __memmove_avx512_unaligned_erms is 16.4 % of pb_syrk at VLEN=512 and 16.0 % of
// tsvc_s000 at VLEN=1024 (raw/BASELINE_COST_CATEGORIES.txt).
//
// VLEN is a power of two between VLEN_MIN and VLEN_MAX, so `bytes` takes one of a handful of
// values. Dispatching once on it and calling __builtin_memcpy with a COMPILE-TIME constant lets
// the compiler emit straight-line moves instead of a call. No ISA-specific code and no intrinsics:
// the compiler picks whatever the translation unit's baseline allows, so this stays portable and
// needs no CPUID guard. Behind --rvv-fixed-copy, default off, so the A/B is in-binary.
//
// This is an engineering fix, not a research contribution, and is labelled as such in
// docs/N2B_SECOND_CANDIDATE_BATCH.md.
ALWAYS_INLINE void sized_copy(void *dst, void const *src, u32 bytes)
{
	if (!config::rvv_fixed_copy) { std::memcpy(dst, src, bytes); return; }
	switch (bytes) {
	case 16: __builtin_memcpy(dst, src, 16); return;
	case 32: __builtin_memcpy(dst, src, 32); return;
	case 64: __builtin_memcpy(dst, src, 64); return;
	case 128: __builtin_memcpy(dst, src, 128); return;
	default: std::memcpy(dst, src, bytes); return;
	}
}

// A14 (2026-09-05). THE SAME mod-2^32 ADDRESS CONTRACT AS UNIT-STRIDE (guest_span_wraps and the
// wrapped byte copies above), applied with THIS opcode's own transfer length: a whole-register
// transfer moves nregs * VLEN/8 bytes and reads neither vl nor vtype (v-st-ext 7.9: "vl and vtype
// are ignored"; vl == 0 still moves every byte). A span that reaches 2^32 continues at guest
// address 0 byte by byte; one that does not keeps the sized fast copy.
// A14-RESTART (2026-09-05). NONZERO vstart. A whole-register transfer operates on elements
// [vstart, evl) with evl = nregs * VLEN / EEW (v-st-ext 7.9: EEW is the load's encoded width, 8
// for a store); the elements below vstart -- the PREFIX -- are neither read from memory nor
// written (register prefix stays for a load, memory prefix stays for a store), and the
// instruction clears vstart on completion. `start_byte` is vstart * EEW/8, computed by the caller
// in 64-bit and already checked against evl (vstart >= evl: no memory effect at all, vstart := 0,
// the caller never gets here). The byte view is exact because a whole-register transfer is a byte
// copy: element e of EEW occupies bytes [e*EEW/8, (e+1)*EEW/8) of the group, in memory and in the
// register file alike. The vstart == 0 fast path is byte-identical to before.
inline void whole_reg_load(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 nregs, u32 vlen_bits,
			   u32 start_byte = 0)
{
	u32 const bytes = vlen_bits / 8;
	u32 const total = nregs * bytes;
	if (unlikely(start_byte >= total))
		return;
	if (unlikely(start_byte != 0 || guest_span_wraps(base, total))) {
		// suffix [start_byte, total), register by register, every byte at its own wrapped
		// guest address; the prefix bytes of the group are not touched
		for (u32 r = 0; r < nregs; ++r) {
			u32 const lo = r * bytes, hi = lo + bytes;
			if (hi <= start_byte)
				continue;
			u32 const from = start_byte > lo ? start_byte : lo;
			guest_load_bytes_wrapped(&vs.vreg[vd + r][from - lo], vmem, (u32)(base + from),
						 hi - from);
		}
		return;
	}
	for (u32 r = 0; r < nregs; ++r)
		sized_copy(&vs.vreg[vd + r][0], vmem + (u32)(base + r * bytes), bytes);
}

inline void whole_reg_store(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 nregs, u32 vlen_bits,
			    u32 start_byte = 0)
{
	u32 const bytes = vlen_bits / 8;
	u32 const total = nregs * bytes;
	if (unlikely(start_byte >= total))
		return;
	if (unlikely(start_byte != 0 || guest_span_wraps(base, total))) {
		for (u32 r = 0; r < nregs; ++r) {
			u32 const lo = r * bytes, hi = lo + bytes;
			if (hi <= start_byte)
				continue;
			u32 const from = start_byte > lo ? start_byte : lo;
			guest_store_bytes_wrapped(vmem, (u32)(base + from), &vs.vreg[vs3 + r][from - lo],
						  hi - from);
		}
		return;
	}
	for (u32 r = 0; r < nregs; ++r)
		sized_copy(vmem + (u32)(base + r * bytes), &vs.vreg[vs3 + r][0], bytes);
}

// A14-RESTART: the shared vstart -> byte-offset rule for both whole-register handlers. Returns
// false when vstart >= evl (the caller clears vstart and performs no memory access), otherwise
// sets *start_byte = vstart * eew_bytes. 64-bit arithmetic: vstart is an arbitrary CSR value.
ALWAYS_INLINE bool whole_reg_start_byte(u32 vstart, u32 eew_bytes, u32 nregs, u32 vlen_bits,
					u32 *start_byte)
{
	u64 const evl = (u64)nregs * (vlen_bits / 8u) / eew_bytes;
	if ((u64)vstart >= evl)
		return false;
	*start_byte = (u32)((u64)vstart * eew_bytes);
	return true;
}

// vid.v: element index. Masked forms write only active elements.
// ---- integer extension: vsext.vf2/vf4/vf8, vzext.vf2/vf4/vf8 (VXUNARY0) ---------------------
// The source EEW is SEW/f, so the source group's EMUL is LMUL/f. `ssew_bytes` is resolved by the
// caller from the vs1 sub-encoding, which is what makes the two sides' register groups differ.
inline void vext(VectorState &vs, bool is_signed, u32 vd, u32 vs2, bool vm, u32 vlen, u32 vl,
		 u32 dsew_bytes, u32 ssew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const v = is_signed ? (u64)vs.elem_i(vs2, e, ssew_bytes, vlen)
					: vs.elem_u(vs2, e, ssew_bytes, vlen);
		vs.elem_put(vd, e, dsew_bytes, vlen, v);
	}
}

// ---- slides -----------------------------------------------------------------------------------
// vslideup leaves elements below the offset UNDISTURBED (it does not zero them), and the spec
// makes vslideup's destination overlap with the source illegal precisely because the copy runs
// upward. vslidedown reads past vl as ZERO rather than leaving the tail undisturbed. Getting
// either of those backwards produces plausible-looking data, so they are written out explicitly.
inline void vslideup(VectorState &vs, u32 vd, u32 vs2, u64 off, bool vm, u32 vlen, u32 vl,
		     u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (e < off)
			continue; // below the offset: untouched, NOT zeroed
		if (!vm && !vs.mask_get(0, e))
			continue;
		vs.elem_put(vd, e, sew_bytes, vlen, vs.elem_u(vs2, (u32)(e - off), sew_bytes, vlen));
	}
}

inline void vslidedown(VectorState &vs, u32 vd, u32 vs2, u64 off, bool vm, u32 vlen, u32 vl,
		       u32 sew_bytes, u32 vlmax)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const src = (u64)e + off;
		// Reads at or beyond VLMAX are defined to produce zero.
		u64 const v = src >= vlmax ? 0 : vs.elem_u(vs2, (u32)src, sew_bytes, vlen);
		vs.elem_put(vd, e, sew_bytes, vlen, v);
	}
}

// vslide1up.vx / vslide1down.vx and their .vf twins: a one-element slide with the scalar filling
// the vacated end. vslide1down's fill lands at vl-1, NOT at VLMAX-1.
inline void vslide1(VectorState &vs, bool down, u32 vd, u32 vs2, u64 scalar, bool vm, u32 vlen,
		    u32 vl, u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 v;
		if (down)
			v = (e + 1 < vl) ? vs.elem_u(vs2, e + 1, sew_bytes, vlen) : scalar;
		else
			v = (e == 0) ? scalar : vs.elem_u(vs2, e - 1, sew_bytes, vlen);
		vs.elem_put(vd, e, sew_bytes, vlen, v);
	}
}

// ---- register gather ----------------------------------------------------------------------------
// vrgather.vv/.vx/.vi and vrgatherei16.vv. An index at or beyond VLMAX reads as zero (it is NOT
// clamped or wrapped). vrgatherei16 takes its indices at a fixed EEW of 16 regardless of SEW,
// which is the whole point of the instruction: it keeps the index group small at large SEW.
inline void vrgather(VectorState &vs, u32 vd, u32 vs2, u32 vs1, VSrc src, u64 scalar_idx,
		     bool ei16, bool vm, u32 vlen, u32 vl, u32 sew_bytes, u32 vlmax)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 idx;
		if (src == VSrc::VV)
			idx = ei16 ? vs.elem_u(vs1, e, 2, vlen) : vs.elem_u(vs1, e, sew_bytes, vlen);
		else
			idx = scalar_idx;
		u64 const v = idx >= vlmax ? 0 : vs.elem_u(vs2, (u32)idx, sew_bytes, vlen);
		vs.elem_put(vd, e, sew_bytes, vlen, v);
	}
}

// ---- fixed-point saturating add/subtract ---------------------------------------------------------
// Saturation sets vxsat, which is a STICKY flag: it is never cleared by a later non-saturating
// operation, only by an explicit CSR write.
inline void vsatadd(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		    i32 simm5, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	u32 const bits = sew_bytes * 8;
	u64 const umax = sew_mask(sew_bytes);
	i64 const smax = (i64)(umax >> 1);
	i64 const smin = -smax - 1;
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const a = vs.elem_u(vs2, e, sew_bytes, vlen);
		u64 const b = vialu_rhs(vs, src, vs1, rs1_val, simm5, e, sew_bytes, vlen);
		u64 out;
		switch (funct6) {
		case VF6_VSADDU: {
			u64 const r = (a + b) & umax;
			bool const ov = r < (a & umax);
			out = ov ? umax : r;
			if (ov)
				vs.vxsat = 1;
			break;
		}
		case VF6_VSSUBU: {
			bool const ov = (a & umax) < (b & umax);
			out = ov ? 0 : ((a - b) & umax);
			if (ov)
				vs.vxsat = 1;
			break;
		}
		case VF6_VSADD: {
			i64 const x = sext_sew(a, sew_bytes), y = sext_sew(b, sew_bytes);
			// The overflow test must be applied at SEW WIDTH. Testing the sign bits of a
			// 64-bit sum never fires for SEW=32 -- 0x7fffffff + 0x55555555 is a perfectly
			// positive i64 -- so the result silently wrapped instead of saturating.
			i64 const r = sext_sew((u64)x + (u64)y, sew_bytes);
			// Overflow iff the operands share a sign that the result does not.
			bool const ov = ((x ^ r) & (y ^ r)) < 0;
			out = (u64)(ov ? (x < 0 ? smin : smax) : r) & umax;
			if (ov)
				vs.vxsat = 1;
			break;
		}
		default: { // VF6_VSSUB
			i64 const x = sext_sew(a, sew_bytes), y = sext_sew(b, sew_bytes);
			i64 const r = sext_sew((u64)x - (u64)y, sew_bytes);
			bool const ov = ((x ^ y) & (x ^ r)) < 0;
			out = (u64)(ov ? (x < 0 ? smin : smax) : r) & umax;
			if (ov)
				vs.vxsat = 1;
			break;
		}
		}
		(void)bits;
		vs.elem_put(vd, e, sew_bytes, vlen, out);
	}
}

// ---- fixed-point averaging ------------------------------------------------------------------------
// (a op b) >> 1 with the rounding mode taken from vxrm, which is a real architectural input: the
// same instruction gives four different answers depending on it. `roundoff` implements the
// spec's rounding function on the bits shifted out.
ALWAYS_INLINE u64 rounding_incr(u64 v, u32 shift, u32 vxrm)
{
	if (shift == 0)
		return 0;
	u64 const lsb = (v >> (shift - 1)) & 1;               // bit about to be shifted out
	u64 const rest = shift >= 2 ? (v & (((u64)1 << (shift - 1)) - 1)) : 0;
	switch (vxrm) {
	case 0: return lsb;                                    // rnu: round-to-nearest-up
	case 1: return lsb && (rest != 0 || ((v >> shift) & 1)); // rne
	case 2: return 0;                                      // rdn: truncate
	default: return (lsb || rest) ? (((v >> shift) & 1) ? 0 : 1) : 0; // rod: round-to-odd
	}
}

inline void vavg(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		 i32 simm5, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	u64 const umask = sew_mask(sew_bytes);
	u32 const vxrm = vs.vxrm;
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const a = vs.elem_u(vs2, e, sew_bytes, vlen);
		u64 const b = vialu_rhs(vs, src, vs1, rs1_val, simm5, e, sew_bytes, vlen);
		// Keep the SEW+1 arithmetic bit, including for 64-bit elements.
		bool const sign = funct6 == VF6_VAADD || funct6 == VF6_VASUB;
		__int128 const x = sign ? (__int128)sext_sew(a, sew_bytes) : (__int128)(a & umask);
		__int128 const y = sign ? (__int128)sext_sew(b, sew_bytes) : (__int128)(b & umask);
		__int128 const sum = funct6 == VF6_VAADDU || funct6 == VF6_VAADD ? x + y : x - y;
		u64 const out = (u64)((sum >> 1) + rounding_incr((u64)sum, 1, vxrm)) & umask;
		vs.elem_put(vd, e, sew_bytes, vlen, out);
	}
}

// ---- narrowing shifts: vnsrl.wv/wx/wi, vnsra.wv/wx/wi -------------------------------------------
// The SOURCE is 2*SEW wide (hence the .w suffix) and the destination is SEW. The shift amount is
// taken modulo 2*SEW, not modulo SEW.
inline void vnshift(VectorState &vs, bool arith, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		    u32 uimm5, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	u32 const wsew = sew_bytes * 2;
	u32 const shmask = wsew * 8 - 1;
	u64 const dmask = sew_mask(sew_bytes);
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const w = vs.elem_u(vs2, e, wsew, vlen);
		u32 sh;
		if (src == VSrc::VV)
			sh = (u32)(vs.elem_u(vs1, e, sew_bytes, vlen) & shmask);
		else if (src == VSrc::VX)
			sh = rs1_val & shmask;
		else
			sh = uimm5 & shmask;
		u64 const r = arith ? (u64)(sext_sew(w, wsew) >> sh) : (w >> sh);
		vs.elem_put(vd, e, sew_bytes, vlen, r & dmask);
	}
}

// ---- widening integer add/sub/multiply/multiply-accumulate ---------------------------------------
// Destination EEW is 2*SEW and destination EMUL is 2*LMUL, so vd and vs2 have different alignment
// requirements. Each form fixes the signedness of EACH operand independently: vwmulsu and the
// vwmaccsu/vwmaccus pair are mixed-sign, and treating them as uniformly signed or unsigned gives
// answers that are right for small magnitudes and wrong at the boundary.
inline void vwint(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		  bool vm, u32 vlen, u32 vl, u32 sew)
{
	u32 const wsew = sew * 2;
	u64 const wmask = sew_mask(wsew);
	bool const wide_vs2 = vwint_wide_vs2(funct6);
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const raw_a = vs.elem_u(vs2, e, wide_vs2 ? wsew : sew, vlen);
		u64 const raw_b = src == VSrc::VV ? vs.elem_u(vs1, e, sew, vlen) : (u64)rs1_val;
		u64 out;
		switch (funct6) {
		case VF6_VWADDU:
			out = (raw_a & sew_mask(sew)) + (raw_b & sew_mask(sew));
			break;
		case VF6_VWSUBU:
			out = (raw_a & sew_mask(sew)) - (raw_b & sew_mask(sew));
			break;
		case VF6_VWADD:
			out = (u64)(sext_sew(raw_a, sew) + sext_sew(raw_b, sew));
			break;
		case VF6_VWSUB:
			out = (u64)(sext_sew(raw_a, sew) - sext_sew(raw_b, sew));
			break;
		case VF6_VWADDU_W:
			out = (raw_a & wmask) + (raw_b & sew_mask(sew));
			break;
		case VF6_VWSUBU_W:
			out = (raw_a & wmask) - (raw_b & sew_mask(sew));
			break;
		case VF6_VWADD_W:
			out = raw_a + (u64)sext_sew(raw_b, sew);
			break;
		case VF6_VWSUB_W:
			out = raw_a - (u64)sext_sew(raw_b, sew);
			break;
		case VF6_VWMULU:
			out = (raw_a & sew_mask(sew)) * (raw_b & sew_mask(sew));
			break;
		case VF6_VWMUL:
			out = (u64)(sext_sew(raw_a, sew) * sext_sew(raw_b, sew));
			break;
		case VF6_VWMULSU: // vs2 signed, vs1/rs1 unsigned
			out = (u64)(sext_sew(raw_a, sew) * (i64)(raw_b & sew_mask(sew)));
			break;
		case VF6_VWMACCU:
			out = vs.elem_u(vd, e, wsew, vlen) +
			      (raw_a & sew_mask(sew)) * (raw_b & sew_mask(sew));
			break;
		case VF6_VWMACC:
			out = vs.elem_u(vd, e, wsew, vlen) + (u64)(sext_sew(raw_a, sew) * sext_sew(raw_b, sew));
			break;
		// The MACC forms name their operands in the order (vd, vs1, vs2), the opposite of
		// vwmulsu's (vd, vs2, vs1), and the spec fixes signedness per OPERAND NAME rather
		// than per position: vwmaccsu is signed(vs1) * unsigned(vs2), while vwmulsu is
		// signed(vs2) * unsigned(vs1). Carrying vwmulsu's convention across to the macc
		// forms inverts both products.
		case VF6_VWMACCSU: // signed(vs1) * unsigned(vs2)
			out = vs.elem_u(vd, e, wsew, vlen) + (u64)(sext_sew(raw_b, sew) * (i64)(raw_a & sew_mask(sew)));
			break;
		default: // VF6_VWMACCUS (.vx only): unsigned(rs1) * signed(vs2)
			out = vs.elem_u(vd, e, wsew, vlen) + (u64)((i64)(raw_b & sew_mask(sew)) * sext_sew(raw_a, sew));
			break;
		}
		vs.elem_put(vd, e, wsew, vlen, out & wmask);
	}
}

// ---- vsmul: signed fractional multiply, rounded by vxrm and saturated -------------------------
// The product of two SEW-bit signed values is 2*SEW bits; vsmul keeps the HIGH half after a
// rounding right shift of SEW-1, which is the fixed-point convention that treats operands as
// Q(SEW-1) fractions. The single saturating case is MIN*MIN, whose exact result is +1.0 in that
// format and therefore one ulp above the representable maximum.
inline void vsmul(VectorState &vs, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val, bool vm,
		  u32 vlen, u32 vl, u32 sew)
{
	u64 const m = sew_mask(sew);
	i64 const smax = (i64)(m >> 1), smin = -smax - 1;
	u32 const sh = sew * 8 - 1;
	u32 const vxrm = vs.vxrm;
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		i64 const a = sext_sew(vs.elem_u(vs2, e, sew, vlen), sew);
		i64 const b = sext_sew(vialu_rhs(vs,src,vs1,rs1_val,0,e,sew,vlen),sew);
		// The intermediate is twice SEW even when the result fits ELEN=64.
		__int128 const prod = (__int128)a * b;
		__int128 r = (prod >> sh) + rounding_incr((u64)prod, sh, vxrm);
		if (r > smax) { r = smax; vs.vxsat = 1; }
		else if (r < smin) { r = smin; vs.vxsat = 1; }
		vs.elem_put(vd, e, sew, vlen, (u64)r & m);
	}
}

// ---- mask load / store: vlm.v, vsm.v ----------------------------------------------------------
// These move ceil(vl/8) BYTES of a single register and are independent of SEW and LMUL: the
// effective EEW is 8 and the effective vl is the byte count. Treating them as ordinary EEW=8
// unit-stride loads would transfer vl bytes instead of ceil(vl/8), which is 8x too many.
inline void load_mask_reg(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits, u32 vl)
{
	u32 const bytes = (vl + 7) / 8;
	for (u32 b = vs.vstart; b < bytes; ++b) {
		vs.vstart=b;
		guest_load_elem(vs.elem_ptr(vd,b,1,vlen_bits),vmem,base+b,1);
	}
	vs.vstart=0;
}
inline void store_mask_reg(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 vlen_bits, u32 vl)
{
	u32 const bytes = (vl + 7) / 8;
	for (u32 b = vs.vstart; b < bytes; ++b) {
		vs.vstart=b;
		guest_store_elem(vmem,base+b,vs.elem_ptr(vs3,b,1,vlen_bits),1);
	}
	vs.vstart=0;
}

// ---- vector FP widening arithmetic and FMA ------------------------------------------------------
// Destination EEW is 2*SEW. For the .w forms vs2 is ALREADY wide; for everything else both
// sources are SEW and are widened exactly before the operation, which is what distinguishes a
// widening multiply-add from a narrow one followed by a convert.
// `vstart` is honoured rather than assumed zero: the elements below it are PRESTART and this
// implementation leaves them exactly as they were, which is what lets the handler use
// RVV_REQUIRE_RESTARTABLE_VTYPE instead of refusing a non-zero vstart outright. Starting the loop at
// 0 would recompute -- and rewrite -- elements the architecture says must not be touched.
inline void vfwarith(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		     bool vm, u32 vlen, u32 vl, u32 sew, u32 vstart = 0)
{
	FpMode const md = fp_mode(fs, FRM_DYN);
	FRound r(fs, md);
	u32 const wsew = sew * 2;
	bool const wide_vs2 = vfw_wide_vs2(f6);
	for (u32 e = vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		// Widen both narrow operands exactly. A single-to-double conversion is exact, so
		// this introduces no rounding of its own.
		u64 const raw_a = vf_bits(vs, vs2, e, wide_vs2 ? wsew : sew, vlen);
		u64 const raw_b = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
					: vf_bits(vs, vs1, e, sew, vlen);
		double a, b;
		if (wide_vs2)
			a = wsew == 4 ? (double)bits_to_f32((u32)raw_a) : bits_to_f64(raw_a);
		else
			a = sew == 4 ? (double)bits_to_f32((u32)raw_a) : bits_to_f64(raw_a);
		b = sew == 4 ? (double)bits_to_f32((u32)raw_b) : bits_to_f64(raw_b);

		if (md.path == FP_SOFT) {
			auto const &SF = sew == 4 ? softfp::FMT32 : softfp::FMT64;
			auto const &DF = wsew == 4 ? softfp::FMT32 : softfp::FMT64;
			u32 fl = 0;
			u64 const wa = wide_vs2 ? raw_a
						: softfp::cvt_fmt(raw_a, SF, DF, md.rm, fl);
			u64 const wb = softfp::cvt_fmt(raw_b, SF, DF, md.rm, fl);
			u64 z;
			switch (f6) {
			case VF6_VFWADD: case VF6_VFWADD_W:
				z = softfp::op_add(wa, wb, false, DF, md.rm, fl); break;
			case VF6_VFWSUB: case VF6_VFWSUB_W:
				z = softfp::op_add(wa, wb, true, DF, md.rm, fl); break;
			case VF6_VFWMUL:
				z = softfp::op_mul(wa, wb, DF, md.rm, fl); break;
			default: {
				u64 const d = vf_bits(vs, vd, e, wsew, vlen);
				bool const negp = f6 == VF6_VFWNMACC || f6 == VF6_VFWNMSAC;
				bool const negc = f6 == VF6_VFWNMACC || f6 == VF6_VFWMSAC;
				z = softfp::op_fma(wa, wb, d, negp, negc, DF, md.rm, fl);
				break;
			}
			}
			fs.raise(fl);
			vs.elem_put(vd, e, wsew, vlen, z);
			continue;
		}
		double z;
		switch (f6) {
		case VF6_VFWADD: case VF6_VFWADD_W: z = a + b; break;
		case VF6_VFWSUB: case VF6_VFWSUB_W: z = a - b; break;
		case VF6_VFWMUL: z = a * b; break;
		default: {
			double const d = bits_to_f64(vf_bits(vs, vd, e, wsew, vlen));
			switch (f6) {
			case VF6_VFWMACC:  z = std::fma(a, b, d); break;
			case VF6_VFWNMACC: z = std::fma(-a, b, -d); break;
			case VF6_VFWMSAC:  z = std::fma(a, b, -d); break;
			default:           z = std::fma(-a, b, d); break; // VFWNMSAC
			}
			break;
		}
		}
		vs.elem_put(vd, e, wsew, vlen, f64_canon(f64_to_bits(z)));
	}
	r.finish(fs);
}

// Widening FP reduction: accumulator and scalar seed are both 2*SEW.
inline void vfwred(VectorState &vs, FPUState &fs, u32 vd, u32 vs2, u32 vs1, bool vm, u32 vlen,
		   u32 vl, u32 sew)
{
	if (vl == 0)
		return;
	FpMode const md = fp_mode(fs, FRM_DYN);
	FRound r(fs, md);
	u32 const wsew = sew * 2;
	u64 acc = vf_bits(vs, vs1, 0, wsew, vlen);
	for (u32 e = 0; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const x = vf_bits(vs, vs2, e, sew, vlen);
		auto const &SF = sew == 4 ? softfp::FMT32 : softfp::FMT64;
		auto const &DF = wsew == 4 ? softfp::FMT32 : softfp::FMT64;
		if (md.path == FP_SOFT) {
			u32 fl = 0;
			u64 const w = softfp::cvt_fmt(x, SF, DF, md.rm, fl);
			acc = softfp::op_add(acc, w, false, DF, md.rm, fl);
			fs.raise(fl);
		} else {
			double const w = sew == 4 ? (double)bits_to_f32((u32)x) : bits_to_f64(x);
			acc = f64_canon(f64_to_bits(bits_to_f64(acc) + w));
		}
	}
	vs.elem_put(vd, 0, wsew, vlen, acc);
	r.finish(fs);
}

// ---- carry / borrow --------------------------------------------------------------------------
// v0 is an OPERAND here, not a mask: vadc adds a carry-in bit per element, and vmadc PRODUCES the
// carry-out as a mask. These instructions are therefore never masked, and the carry-in variants
// are the ones encoded with vm=0 -- the reverse of the usual reading of that bit.
inline void vadc(VectorState &vs, u32 funct6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		 i32 simm5, bool carry_in, u32 vlen, u32 vl, u32 sew)
{
	u64 const m = sew_mask(sew);
	for (u32 e = vs.vstart; e < vl; ++e) {
		u64 const a = vs.elem_u(vs2, e, sew, vlen) & m;
		u64 const b = vialu_rhs(vs, src, vs1, rs1_val, simm5, e, sew, vlen) & m;
		u64 const c = carry_in && vs.mask_get(0, e) ? 1u : 0u;
		if (funct6 == VF6_VADC) {
			vs.elem_put(vd, e, sew, vlen, (a + b + c) & m);
		} else if (funct6 == VF6_VSBC) {
			vs.elem_put(vd, e, sew, vlen, (a - b - c) & m);
		} else if (funct6 == VF6_VMADC) {
			// Carry-out of an unsigned add: the truncated sum is smaller than either
			// addend, or equals it when the carry-in made up the difference.
			u64 const r = (a + b + c) & m;
			vs.mask_set(vd, e, c ? r <= a : r < a);
		} else { // VF6_VMSBC: borrow-out
			vs.mask_set(vd, e, c ? a <= b : a < b);
		}
	}
}

// ---- fixed-point scaling shift: vssrl / vssra (rounding right shift, reads vxrm) --------------
inline void vsshift(VectorState &vs, bool arith, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		    u32 uimm5, bool vm, u32 vlen, u32 vl, u32 sew)
{
	u64 const m = sew_mask(sew);
	u32 const shmask = sew * 8 - 1;
	u32 const vxrm = vs.vxrm;
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const a = vs.elem_u(vs2, e, sew, vlen) & m;
		u32 sh;
		if (src == VSrc::VV)
			sh = (u32)(vs.elem_u(vs1, e, sew, vlen) & shmask);
		else if (src == VSrc::VX)
			sh = rs1_val & shmask;
		else
			sh = uimm5 & shmask;
		u64 const base = arith ? (u64)(sext_sew(a, sew) >> sh) : (a >> sh);
		u64 const inc = rounding_incr(arith ? (u64)sext_sew(a, sew) : a, sh, vxrm);
		vs.elem_put(vd, e, sew, vlen, (base + inc) & m);
	}
}

// ---- narrowing clip: vnclipu / vnclip (2*SEW source, rounds by vxrm, saturates into vxsat) ----
inline void vnclip(VectorState &vs, bool is_signed, VSrc src, u32 vd, u32 vs2, u32 vs1,
		   u32 rs1_val, u32 uimm5, bool vm, u32 vlen, u32 vl, u32 sew)
{
	u32 const wsew = sew * 2;
	u32 const shmask = wsew * 8 - 1;
	u64 const dmask = sew_mask(sew);
	i64 const smax = (i64)(dmask >> 1), smin = -smax - 1;
	u32 const vxrm = vs.vxrm;
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const w = vs.elem_u(vs2, e, wsew, vlen);
		u32 sh;
		if (src == VSrc::VV)
			sh = (u32)(vs.elem_u(vs1, e, sew, vlen) & shmask);
		else if (src == VSrc::VX)
			sh = rs1_val & shmask;
		else
			sh = uimm5 & shmask;
		u64 out;
		if (is_signed) {
			i64 const v = sext_sew(w, wsew);
			i64 const r = (v >> sh) + (i64)rounding_incr((u64)v, sh, vxrm);
			if (r > smax) { out = (u64)smax; vs.vxsat = 1; }
			else if (r < smin) { out = (u64)smin; vs.vxsat = 1; }
			else out = (u64)r;
		} else {
			u64 const v = w & sew_mask(wsew);
			u64 const r = (v >> sh) + rounding_incr(v, sh, vxrm);
			if (r > dmask) { out = dmask; vs.vxsat = 1; }
			else out = r;
		}
		vs.elem_put(vd, e, sew, vlen, out & dmask);
	}
}

// ---- widening integer reduction ------------------------------------------------------------------
// The accumulator and the result are 2*SEW; the scalar seed in vs1[0] is read at 2*SEW too.
inline void vwred(VectorState &vs, bool is_signed, u32 vd, u32 vs2, u32 vs1, bool vm, u32 vlen,
		  u32 vl, u32 sew)
{
	if (vl == 0)
		return;
	u32 const wsew = sew * 2;
	u64 acc = vs.elem_u(vs1, 0, wsew, vlen);
	for (u32 e = 0; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		u64 const x = vs.elem_u(vs2, e, sew, vlen);
		acc += is_signed ? (u64)sext_sew(x, sew) : (x & sew_mask(sew));
	}
	vs.elem_put(vd, 0, wsew, vlen, acc & sew_mask(wsew));
}

// ---- mask population and first-set ----------------------------------------------------------------
// Both write a GPR, and both respect the mask: only ACTIVE elements are considered.
inline u32 vcpop_m(VectorState &vs, u32 vs2, bool vm, u32 vl)
{
	u32 n = 0;
	for (u32 e = 0; e < vl; ++e)
		if ((vm || vs.mask_get(0, e)) && vs.mask_get(vs2, e))
			n++;
	return n;
}
inline i32 vfirst_m(VectorState &vs, u32 vs2, bool vm, u32 vl)
{
	for (u32 e = 0; e < vl; ++e)
		if ((vm || vs.mask_get(0, e)) && vs.mask_get(vs2, e))
			return (i32)e;
	return -1; // no active set bit
}

// ---- vmsbf / vmsif / vmsof and viota ---------------------------------------------------------------
// set-before-first, set-including-first, set-only-first. All three stop contributing once the
// first active set bit has been seen; inactive elements are left undisturbed, so the "first" is
// the first ACTIVE set bit, not the first set bit.
inline void vmsetop(VectorState &vs, u32 sub, u32 vd, u32 vs2, bool vm, u32 vl)
{
	bool seen = false;
	for (u32 e = 0; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		bool const bit = vs.mask_get(vs2, e);
		bool r;
		if (sub == 0b00001) // vmsbf: set strictly before the first set bit
			r = !seen && !bit;
		else if (sub == 0b00010) // vmsof: set only AT the first set bit
			r = !seen && bit;
		else // vmsif: set up to and including the first set bit
			r = !seen;
		vs.mask_set(vd, e, r);
		if (bit)
			seen = true;
	}
}

// viota.m: each element receives the number of active set bits STRICTLY BEFORE it. The running
// count advances only over active elements, which is what makes it usable as a compress index.
inline void viota(VectorState &vs, u32 vd, u32 vs2, bool vm, u32 vlen, u32 vl, u32 sew)
{
	u64 n = 0;
	for (u32 e = 0; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		vs.elem_put(vd, e, sew, vlen, n);
		if (vs.mask_get(vs2, e))
			n++;
	}
}

// vcompress.vm: pack the elements selected by vs1 into the low end of vd. It is NOT maskable in
// the usual sense -- vs1 IS the selector -- and the destination must not overlap either source,
// since the write index runs behind the read index.
inline void vcompress(VectorState &vs, u32 vd, u32 vs2, u32 vs1, u32 vlen, u32 vl, u32 sew)
{
	u32 n = 0;
	for (u32 e = 0; e < vl; ++e)
		if (vs.mask_get(vs1, e))
			vs.elem_put(vd, n++, sew, vlen, vs.elem_u(vs2, e, sew, vlen));
}

inline void vid(VectorState &vs, u32 vd, bool vm, u32 vlen, u32 vl, u32 sew_bytes)
{
	for (u32 e = vs.vstart; e < vl; ++e) {
		if (!vm && !vs.mask_get(0, e))
			continue;
		vs.elem_put(vd, e, sew_bytes, vlen, e);
	}
}

} // namespace rvv_ref

// ---------------------------------------------------------------------------------------------
// Fixed-width implementations, written entirely against chunk_load/chunk_store/chunk_add.
//
// Guest memory is accessed with the UNALIGNED forms: the guest chooses the address and RVV
// unit-stride accesses carry no alignment guarantee. The register file is 16-byte aligned by
// construction (VectorState::vreg is alignas(16) and each register slot is VLEN_MAX_BYTES, a
// multiple of 64), but the unaligned form is used there too -- on x86 it costs nothing when the
// address is in fact aligned, it removes an entire class of UB from a correctness substrate,
// and it keeps the code valid at chunk widths above the 16-byte guaranteed alignment.
// ---------------------------------------------------------------------------------------------
namespace rvv_chunked
{

// Copy `bytes` from `src` to `dst` in HOST_CHUNK_BYTES chunks plus a byte remainder.
// Returns the number of chunk operations issued (for the evidence counters).
ALWAYS_INLINE u32 copy_chunked(u8 *dst, u8 const *src, u32 bytes)
{
	u32 const chunks = bytes / HOST_CHUNK_BYTES;
	for (u32 c = 0; c < chunks; ++c)
		chunk_store(dst + c * HOST_CHUNK_BYTES, chunk_load(src + c * HOST_CHUNK_BYTES));
	u32 const done = chunks * HOST_CHUNK_BYTES;
	if (bytes > done)
		std::memcpy(dst + done, src + done, bytes - done);
	return chunks;
}

// vle32-style unit-stride load. Memory is contiguous across the whole access; the REGISTER FILE
// is not (each architectural register occupies its own VLEN_MAX_BYTES slot), so the copy is
// driven per register -- that stride is the whole reason a naive "one big memcpy" is wrong at
// VLEN < VLEN_MAX.
inline void load_unit_stride(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits, u32 vl,
			     u32 eew_bytes)
{
	ChunkPlan const p = make_chunk_plan(vlen_bits, vl, eew_bytes);
	// A13-FIX: a span that reaches 2^32 takes the wrapped byte path (see guest_span_wraps); the
	// chunk copies below walk HOST pointers and must not be handed such a span.
	if (unlikely(guest_span_wraps(base, vl * eew_bytes))) {
		for (u32 r = 0; r < p.full_regs; ++r)
			guest_load_bytes_wrapped(&vs.vreg[vd + r][0], vmem, (u32)(base + r * p.vlen_bytes),
						 p.vlen_bytes);
		if (p.tail_elems)
			guest_load_bytes_wrapped(&vs.vreg[vd + p.full_regs][0], vmem,
						 (u32)(base + p.full_regs * p.vlen_bytes),
						 p.tail_elems * eew_bytes);
		return;
	}
	u32 chunk_ops = 0;
	// Register r covers memory bytes [r*vlen_bytes, (r+1)*vlen_bytes) -- elems_per_reg *
	// eew_bytes IS vlen_bytes. Computing the offset directly instead of accumulating keeps the
	// loop free of a carried dependency (an earlier accumulating version made the compiler
	// emit a vectorized paddd reduction just to maintain the element counter).
	for (u32 r = 0; r < p.full_regs; ++r) {
		chunk_ops += copy_chunked(&vs.vreg[vd + r][0],
					  vmem + (u32)(base + r * p.vlen_bytes), p.vlen_bytes);
	}
	if (p.tail_elems) {
		// Only the first tail_elems elements of this register may be written; elements
		// beyond vl stay undisturbed.
		chunk_ops += copy_chunked(&vs.vreg[vd + p.full_regs][0],
					  vmem + (u32)(base + p.full_regs * p.vlen_bytes),
					  p.tail_elems * eew_bytes);
		g_rvv_stats.tail_elems += p.tail_elems;
	}
	g_rvv_stats.chunk_ops += chunk_ops;
}

inline void store_unit_stride(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 vlen_bits, u32 vl,
			      u32 eew_bytes)
{
	ChunkPlan const p = make_chunk_plan(vlen_bits, vl, eew_bytes);
	// A13-FIX: see load_unit_stride above; on the store side the host-pointer walk was a WRITE
	// into host memory past the guest reservation.
	if (unlikely(guest_span_wraps(base, vl * eew_bytes))) {
		for (u32 r = 0; r < p.full_regs; ++r)
			guest_store_bytes_wrapped(vmem, (u32)(base + r * p.vlen_bytes), &vs.vreg[vs3 + r][0],
						  p.vlen_bytes);
		if (p.tail_elems)
			guest_store_bytes_wrapped(vmem, (u32)(base + p.full_regs * p.vlen_bytes),
						  &vs.vreg[vs3 + p.full_regs][0], p.tail_elems * eew_bytes);
		return;
	}
	u32 chunk_ops = 0;
	for (u32 r = 0; r < p.full_regs; ++r) {
		chunk_ops += copy_chunked(vmem + (u32)(base + r * p.vlen_bytes),
					  &vs.vreg[vs3 + r][0], p.vlen_bytes);
	}
	if (p.tail_elems) {
		chunk_ops += copy_chunked(vmem + (u32)(base + p.full_regs * p.vlen_bytes),
					  &vs.vreg[vs3 + p.full_regs][0], p.tail_elems * eew_bytes);
		g_rvv_stats.tail_elems += p.tail_elems;
	}
	g_rvv_stats.chunk_ops += chunk_ops;
}

// Element-wise add of `bytes` bytes at SEW granularity: chunked, then an element-wise remainder.
ALWAYS_INLINE u32 add_range(u8 *d, u8 const *s2, u8 const *s1, u32 bytes, u32 sew_bytes)
{
	u32 const chunks = bytes / HOST_CHUNK_BYTES;
	for (u32 c = 0; c < chunks; ++c) {
		// Chunk c reads and writes ONLY bytes [off, off+HOST_CHUNK_BYTES). Distinct c are
		// disjoint, so the chunks of one register carry no dependency on each other -- the
		// property the two-ZMM VLEN=1024 artifact has to demonstrate.
		u32 const off = c * HOST_CHUNK_BYTES;
		chunk_store(d + off, chunk_add(chunk_load(s2 + off), chunk_load(s1 + off), sew_bytes));
	}
	// Sub-chunk remainder. bytes is always a multiple of sew_bytes and HOST_CHUNK_BYTES is a
	// multiple of every supported sew_bytes, so this loop is element-aligned.
	for (u32 off = chunks * HOST_CHUNK_BYTES; off < bytes; off += sew_bytes) {
		switch (sew_bytes) {
		case 1: { u8 a, b; std::memcpy(&a, s2 + off, 1); std::memcpy(&b, s1 + off, 1); u8 r = (u8)(a + b); std::memcpy(d + off, &r, 1); break; }
		case 2: { u16 a, b; std::memcpy(&a, s2 + off, 2); std::memcpy(&b, s1 + off, 2); u16 r = (u16)(a + b); std::memcpy(d + off, &r, 2); break; }
		case 4: { u32 a, b; std::memcpy(&a, s2 + off, 4); std::memcpy(&b, s1 + off, 4); u32 r = a + b; std::memcpy(d + off, &r, 4); break; }
		default: { u64 a, b; std::memcpy(&a, s2 + off, 8); std::memcpy(&b, s1 + off, 8); u64 r = a + b; std::memcpy(d + off, &r, 8); break; }
		}
	}
	return chunks;
}

// ---- scalar fallbacks: one implementation, shared with the reference ---------------------------
// No chunk decomposition is written here for strided (vlse/vsse) or masked unit-stride accesses, so
// these entry points forward to rvv_ref instead of keeping a second copy of the same semantics. The
// copies that used to sit here had drifted from it on three points -- signed `(i32)e * stride`
// instead of unsigned RV32 arithmetic, a plain memcpy instead of the A13-FIX byte-granularity wrap
// at 2^32, and a loop from 0 with no vstart bookkeeping. They had no caller (the interpreter calls
// rvv_ref directly), so this is a consolidation, not a bug fix and not a speedup. Signatures are
// unchanged; `ref_fallback` stays a dispatch-layer counter.
inline void load_strided(VectorState &vs, u32 vd, u8 *vmem, u32 base, i32 stride, u32 vlen_bits,
			 u32 vl, u32 eew_bytes, bool vm)
{
	rvv_ref::load_strided(vs, vd, vmem, base, stride, vlen_bits, vl, eew_bytes, vm);
}

inline void store_strided(VectorState &vs, u32 vs3, u8 *vmem, u32 base, i32 stride, u32 vlen_bits,
			  u32 vl, u32 eew_bytes, bool vm)
{
	rvv_ref::store_strided(vs, vs3, vmem, base, stride, vlen_bits, vl, eew_bytes, vm);
}

inline void load_unit_stride_masked(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits,
				    u32 vl, u32 eew_bytes)
{
	rvv_ref::load_unit_stride_masked(vs, vd, vmem, base, vlen_bits, vl, eew_bytes);
}

inline void store_unit_stride_masked(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 vlen_bits,
				     u32 vl, u32 eew_bytes)
{
	rvv_ref::store_unit_stride_masked(vs, vs3, vmem, base, vlen_bits, vl, eew_bytes);
}

inline void add_vv(VectorState &vs, u32 vd, u32 vs2, u32 vs1, u32 vlen_bits, u32 vl, u32 sew_bytes)
{
	ChunkPlan const p = make_chunk_plan(vlen_bits, vl, sew_bytes);
	u32 chunk_ops = 0;
	for (u32 r = 0; r < p.full_regs; ++r) {
		chunk_ops += add_range(&vs.vreg[vd + r][0], &vs.vreg[vs2 + r][0], &vs.vreg[vs1 + r][0],
				       p.vlen_bytes, sew_bytes);
	}
	if (p.tail_elems) {
		u32 const r = p.full_regs;
		chunk_ops += add_range(&vs.vreg[vd + r][0], &vs.vreg[vs2 + r][0], &vs.vreg[vs1 + r][0],
				       p.tail_elems * sew_bytes, sew_bytes);
		g_rvv_stats.tail_elems += p.tail_elems;
	}
	g_rvv_stats.chunk_ops += chunk_ops;
}

} // namespace rvv_chunked

// ---------------------------------------------------------------------------------------------
// Dispatch. `config::rvv_lowering` selects the path; `config::rvv_verify` additionally runs the
// reference and compares, which is what turns "the two paths agree" from an assertion into a
// measurement. Overlap between vd and the sources is legal in RVV when EMUL matches, and the
// reference is deliberately run on a SNAPSHOT so an in-place overlapping update cannot make the
// oracle observe the optimized path's partial results.
// ---------------------------------------------------------------------------------------------

enum class RvvLowering : u8 {
	Ref = 0, // scalar element-at-a-time reference only
	Sse2 = 1 // 128-bit fixed-width chunks, reference kept as fallback/oracle
};

// Reported when the two paths disagree. Kept out of line so the fast path stays small.
void RvvVerifyFailed(char const *op, u32 vlen_bits, u32 vl, u32 elem_bytes);

// Verifier self-test hook. Counts vector ops only while the injection flag is set, so the
// normal path pays a single predictable compare and nothing else.
inline unsigned long long g_rvv_op_seq = 0;
ALWAYS_INLINE bool rvv_fault_here()
{
	if (likely(config::rvv_inject_fault == 0))
		return false;
	return ++g_rvv_op_seq == config::rvv_inject_fault;
}

inline void dispatch_load_unit_stride(VectorState &vs, u32 vd, u8 *vmem, u32 base, u32 vlen_bits,
				      u32 vl, u32 eew_bytes)
{
	if (unlikely(config::rvv_lowering == (u8)RvvLowering::Ref)) {
		g_rvv_stats.ref_fallback++;
		rvv_ref::load_unit_stride(vs, vd, vmem, base, vlen_bits, vl, eew_bytes);
		return;
	}
	if (unlikely(config::rvv_verify)) {
		VectorState shadow = vs;
		rvv_ref::load_unit_stride(shadow, vd, vmem, base, vlen_bits, vl, eew_bytes);
		rvv_chunked::load_unit_stride(vs, vd, vmem, base, vlen_bits, vl, eew_bytes);
		if (unlikely(rvv_fault_here()))
			vs.vreg[vd][0] ^= 1;
		if (std::memcmp(shadow.vreg.data(), vs.vreg.data(), sizeof(shadow.vreg)) != 0) {
			g_rvv_stats.verify_fail++;
			RvvVerifyFailed("vle", vlen_bits, vl, eew_bytes);
		} else {
			g_rvv_stats.verify_ok++;
		}
		return;
	}
	rvv_chunked::load_unit_stride(vs, vd, vmem, base, vlen_bits, vl, eew_bytes);
}

inline void dispatch_store_unit_stride(VectorState &vs, u32 vs3, u8 *vmem, u32 base, u32 vlen_bits,
				       u32 vl, u32 eew_bytes)
{
	if (unlikely(config::rvv_lowering == (u8)RvvLowering::Ref)) {
		g_rvv_stats.ref_fallback++;
		rvv_ref::store_unit_stride(vs, vs3, vmem, base, vlen_bits, vl, eew_bytes);
		return;
	}
	if (unlikely(config::rvv_verify)) {
		// A store's effect is on GUEST MEMORY, so the comparison has to be against the
		// bytes actually written. Snapshot the destination range, let the reference write
		// it, capture that, restore, then let the optimized path write and compare.
		u32 const bytes = vl * eew_bytes;
		// Single-threaded guest execution, and this is a diagnostic mode, so plain statics
		// are fine. Sized well above any legal vl*EEW (EMUL <= 8 => <= 8*VLEN_MAX/8 bytes).
		static u8 want[VLEN_MAX_BYTES * VREG_NUM];
		static u8 orig[VLEN_MAX_BYTES * VREG_NUM];
		// Skip the comparison (but still take the fast path) if the access would wrap the
		// 4 GiB guest space: the contiguous snapshot below would not model that correctly,
		// and reporting a bogus mismatch is worse than reporting no result.
		bool const wraps = ((u64)base + bytes) > 0x1'0000'0000ull;
		if (bytes <= sizeof(want) && !wraps) {
			std::memcpy(orig, vmem + base, bytes);
			rvv_ref::store_unit_stride(vs, vs3, vmem, base, vlen_bits, vl, eew_bytes);
			std::memcpy(want, vmem + base, bytes);
			std::memcpy(vmem + base, orig, bytes);
			rvv_chunked::store_unit_stride(vs, vs3, vmem, base, vlen_bits, vl, eew_bytes);
			if (unlikely(rvv_fault_here()))
				vmem[base] ^= 1;
			if (std::memcmp(want, vmem + base, bytes) != 0) {
				g_rvv_stats.verify_fail++;
				RvvVerifyFailed("vse", vlen_bits, vl, eew_bytes);
			} else {
				g_rvv_stats.verify_ok++;
			}
			return;
		}
	}
	rvv_chunked::store_unit_stride(vs, vs3, vmem, base, vlen_bits, vl, eew_bytes);
}

inline void dispatch_add_vv(VectorState &vs, u32 vd, u32 vs2, u32 vs1, u32 vlen_bits, u32 vl,
			    u32 sew_bytes)
{
	if (unlikely(config::rvv_lowering == (u8)RvvLowering::Ref)) {
		g_rvv_stats.ref_fallback++;
		rvv_ref::add_vv(vs, vd, vs2, vs1, vlen_bits, vl, sew_bytes);
		return;
	}
	if (unlikely(config::rvv_verify)) {
		VectorState shadow = vs;
		rvv_ref::add_vv(shadow, vd, vs2, vs1, vlen_bits, vl, sew_bytes);
		rvv_chunked::add_vv(vs, vd, vs2, vs1, vlen_bits, vl, sew_bytes);
		if (unlikely(rvv_fault_here()))
			vs.vreg[vd][0] ^= 1;
		if (std::memcmp(shadow.vreg.data(), vs.vreg.data(), sizeof(shadow.vreg)) != 0) {
			g_rvv_stats.verify_fail++;
			RvvVerifyFailed("vadd.vv", vlen_bits, vl, sew_bytes);
		} else {
			g_rvv_stats.verify_ok++;
		}
		return;
	}
	rvv_chunked::add_vv(vs, vd, vs2, vs1, vlen_bits, vl, sew_bytes);
}

} // namespace dbt::rv32
