#pragma once
#include <cstdint>
#include <immintrin.h>

namespace dbt::rv32::fma_invalid
{
// RISC-V requires NV for zero * infinity even when the addend is a quiet NaN.
// Host FMA may suppress that exception. Classify only the multiplicands; signs
// and the addend do not affect this rule. The fused result still comes from FMA.
inline bool product(uint64_t x, uint64_t y, unsigned bytes)
{
	uint64_t const signless = bytes == 4 ? 0x7fffffffull : 0x7fffffffffffffffull;
	uint64_t const inf = bytes == 4 ? 0x7f800000ull : 0x7ff0000000000000ull;
	x &= signless;
	y &= signless;
	return (x == 0 && y == inf) || (y == 0 && x == inf);
}
inline void accrue(bool invalid)
{
	if (invalid)
		_mm_setcsr(_mm_getcsr() | 1u);
}
#ifdef __AVX__
inline void product(__m128 x, __m128 y)
{
	x = _mm_and_ps(x, _mm_castsi128_ps(_mm_set1_epi32(0x7fffffff)));
	y = _mm_and_ps(y, _mm_castsi128_ps(_mm_set1_epi32(0x7fffffff)));
	accrue(_mm_movemask_ps(
		   _mm_or_ps(_mm_and_ps(_mm_cmp_ps(x, _mm_setzero_ps(), _CMP_EQ_OQ),
					_mm_cmp_ps(y, _mm_set1_ps(__builtin_inff()), _CMP_EQ_OQ)),
			     _mm_and_ps(_mm_cmp_ps(y, _mm_setzero_ps(), _CMP_EQ_OQ),
					_mm_cmp_ps(x, _mm_set1_ps(__builtin_inff()), _CMP_EQ_OQ)))) != 0);
}
inline void product(__m128d x, __m128d y)
{
	x = _mm_and_pd(x, _mm_castsi128_pd(_mm_set1_epi64x(0x7fffffffffffffffLL)));
	y = _mm_and_pd(y, _mm_castsi128_pd(_mm_set1_epi64x(0x7fffffffffffffffLL)));
	accrue(_mm_movemask_pd(
		   _mm_or_pd(_mm_and_pd(_mm_cmp_pd(x, _mm_setzero_pd(), _CMP_EQ_OQ),
					_mm_cmp_pd(y, _mm_set1_pd(__builtin_inf()), _CMP_EQ_OQ)),
			     _mm_and_pd(_mm_cmp_pd(y, _mm_setzero_pd(), _CMP_EQ_OQ),
					_mm_cmp_pd(x, _mm_set1_pd(__builtin_inf()), _CMP_EQ_OQ)))) != 0);
}
inline void product(__m256 x, __m256 y)
{
	x = _mm256_and_ps(x, _mm256_castsi256_ps(_mm256_set1_epi32(0x7fffffff)));
	y = _mm256_and_ps(y, _mm256_castsi256_ps(_mm256_set1_epi32(0x7fffffff)));
	accrue(_mm256_movemask_ps(_mm256_or_ps(
		   _mm256_and_ps(_mm256_cmp_ps(x, _mm256_setzero_ps(), _CMP_EQ_OQ),
				 _mm256_cmp_ps(y, _mm256_set1_ps(__builtin_inff()), _CMP_EQ_OQ)),
		   _mm256_and_ps(_mm256_cmp_ps(y, _mm256_setzero_ps(), _CMP_EQ_OQ),
				 _mm256_cmp_ps(x, _mm256_set1_ps(__builtin_inff()), _CMP_EQ_OQ)))) != 0);
}
inline void product(__m256d x, __m256d y)
{
	x = _mm256_and_pd(x, _mm256_castsi256_pd(_mm256_set1_epi64x(0x7fffffffffffffffLL)));
	y = _mm256_and_pd(y, _mm256_castsi256_pd(_mm256_set1_epi64x(0x7fffffffffffffffLL)));
	accrue(_mm256_movemask_pd(_mm256_or_pd(
		   _mm256_and_pd(_mm256_cmp_pd(x, _mm256_setzero_pd(), _CMP_EQ_OQ),
				 _mm256_cmp_pd(y, _mm256_set1_pd(__builtin_inf()), _CMP_EQ_OQ)),
		   _mm256_and_pd(_mm256_cmp_pd(y, _mm256_setzero_pd(), _CMP_EQ_OQ),
				 _mm256_cmp_pd(x, _mm256_set1_pd(__builtin_inf()), _CMP_EQ_OQ)))) != 0);
}
#endif
#ifdef __AVX512F__
inline void product(__m512 x, __m512 y)
{
	x = _mm512_castsi512_ps(_mm512_and_si512(_mm512_castps_si512(x), _mm512_set1_epi32(0x7fffffff)));
	y = _mm512_castsi512_ps(_mm512_and_si512(_mm512_castps_si512(y), _mm512_set1_epi32(0x7fffffff)));
	accrue(((_mm512_cmp_ps_mask(x, _mm512_setzero_ps(), _CMP_EQ_OQ) &
		 _mm512_cmp_ps_mask(y, _mm512_set1_ps(__builtin_inff()), _CMP_EQ_OQ)) |
		(_mm512_cmp_ps_mask(y, _mm512_setzero_ps(), _CMP_EQ_OQ) &
		 _mm512_cmp_ps_mask(x, _mm512_set1_ps(__builtin_inff()), _CMP_EQ_OQ))) != 0);
}
inline void product(__m512d x, __m512d y)
{
	x = _mm512_castsi512_pd(
	    _mm512_and_si512(_mm512_castpd_si512(x), _mm512_set1_epi64(0x7fffffffffffffffLL)));
	y = _mm512_castsi512_pd(
	    _mm512_and_si512(_mm512_castpd_si512(y), _mm512_set1_epi64(0x7fffffffffffffffLL)));
	accrue(((_mm512_cmp_pd_mask(x, _mm512_setzero_pd(), _CMP_EQ_OQ) &
		 _mm512_cmp_pd_mask(y, _mm512_set1_pd(__builtin_inf()), _CMP_EQ_OQ)) |
		(_mm512_cmp_pd_mask(y, _mm512_setzero_pd(), _CMP_EQ_OQ) &
		 _mm512_cmp_pd_mask(x, _mm512_set1_pd(__builtin_inf()), _CMP_EQ_OQ))) != 0);
}
#endif
} // namespace dbt::rv32::fma_invalid
