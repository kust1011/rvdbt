#pragma once
#include "dbt/guest/rv32_softfp.h"

// RVV narrowing conversion tininess. IEEE detects tininess after precision
// rounding with an unbounded exponent, before subnormal exponent rounding.
// A final minimum-normal encoding can therefore still raise UF. Keep this
// correction local to vector conversion; scalar arithmetic is unchanged.
namespace dbt::rv32::rvv_fpconvert
{
inline bool tiny_f64_to_f32(u64 bits, u32 rm)
{
	bool const sign = bits >> 63;
	u64 const magnitude = bits & 0x7fffffffffffffffull;
	// Binary64 encodings of binary32's minimum normal, the last value below
	// it at unbounded binary32 precision, and their precision-rounding tie.
	constexpr u64 normal = 0x3810000000000000ull;
	constexpr u64 previous = normal - (1ull << 29); // normal - 2^-150
	constexpr u64 tie = normal - (1ull << 28);      // normal - 2^-151
	if (magnitude >= normal)
		return false;
	if (rm == FRM_RNE || rm == FRM_RMM)
		return magnitude < tie;
	if ((rm == FRM_RDN && sign) || (rm == FRM_RUP && !sign))
		return magnitude <= previous;
	return true; // RTZ/ROD and rounding toward smaller magnitude
}

inline u64 cvt_fmt(u64 bits, softfp::Fmt const &from, softfp::Fmt const &to, u32 rm, u32 &flags)
{
	u32 raised = 0;
	u64 const result = softfp::cvt_fmt(bits, from, to, rm, raised);
	if (from.mant == 52 && to.mant == 23) {
		raised &= ~FFLAG_UF;
		if ((raised & FFLAG_NX) && tiny_f64_to_f32(bits, rm))
			raised |= FFLAG_UF;
	}
	flags |= raised;
	return result;
}
}
