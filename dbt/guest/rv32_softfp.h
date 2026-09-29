#pragma once

#include "dbt/util/common.h"
#include "dbt/guest/rv32_fpu.h"

#include <cstring>

// Exact integer-significand IEEE-754 binary32/binary64 core.
//
// WHY THIS EXISTS
// ---------------
// The host FPU can be driven through four of RISC-V's five rounding modes with fesetround, and a
// 33106-record differential against QEMU 11.1 shows that path is bit-exact for RNE/RTZ/RDN/RUP in
// both results and fflags. It cannot reach the fifth. RMM (round to nearest, ties to MAX
// MAGNITUDE) has no x86 equivalent: SSE encodes exactly four modes in MXCSR.RC.
//
// Declaring RMM unimplemented would be a real gap, not a technicality -- it is a base F/D
// rounding mode, reachable from any guest by `csrw frm, 4` or by a static rm field on any
// arithmetic instruction, and QEMU demonstrably produces different answers with it (fcvt.w.s of
// -0.5 is -1 under RMM and 0 under RNE). So the mode is implemented exactly instead.
//
// HOW IT WORKS
// ------------
// Every value is carried as a plain integer significand times a power of two:
//
//     value = (-1)^sign * sig * 2^exp        (sig an exact u128 integer)
//
// Each operation produces that exact product/sum/quotient with a sticky bit recording any bits
// that could not be kept, and a single `round_pack` applies the format's precision, all five
// rounding modes, subnormals, overflow and the NX/UF/OF flags. There is no floating-point
// arithmetic anywhere in this file, so there is nothing for the host's rounding mode, its
// flush-to-zero settings, its extended x87 precision, or the compiler's freedom to contract or
// reassociate expressions to perturb. The result is a function of the input bits alone.
//
// A u128 is wide enough for every base F/D operation to be carried exactly: the widest
// intermediate is the binary64 fused product, 106 bits.
//
// TRUST
// -----
// This is not used only on the RMM path. Building with -DRVV_FP_FORCE_SOFT=1 routes every
// rounding mode through this core, and the same 33106-record differential must still match QEMU
// exactly. That is what makes the RMM results credible: the identical code is checked against an
// independent oracle in the four modes where an oracle comparison is possible.
namespace dbt::rv32::softfp
{

using u128 = unsigned __int128;

ALWAYS_INLINE int clz128(u128 v) // v != 0
{
	u64 const hi = (u64)(v >> 64);
	return hi ? __builtin_clzll(hi) : 64 + __builtin_clzll((u64)v);
}

// A format is fully described by its explicit mantissa width and exponent field width. `emin` is
// the exponent of the value = sig * 2^exp representation when sig is a subnormal significand, and
// `emax` the largest exponent a normalised significand may carry.
struct Fmt {
	int mant;
	int expb;
	int bias;
	int emin;
	int emax;
	u64 qnan;
};
constexpr Fmt FMT32{23, 8, 127, -149, 104, 0x7fc00000ull};
constexpr Fmt FMT64{52, 11, 1023, -1074, 971, 0x7ff8000000000000ull};

enum Cls { C_ZERO, C_FIN, C_INF, C_QNAN, C_SNAN };

struct Un {
	bool sign;
	int cls;
	u128 sig;
	int exp;
};

ALWAYS_INLINE u64 sign_bit(bool s, Fmt const &f) { return s ? (1ull << (f.mant + f.expb)) : 0; }
ALWAYS_INLINE u64 inf_of(bool s, Fmt const &f)
{
	return sign_bit(s, f) | ((u64)((1ull << f.expb) - 1) << f.mant);
}
ALWAYS_INLINE u64 maxfin_of(bool s, Fmt const &f)
{
	return sign_bit(s, f) | ((u64)((1ull << f.expb) - 2) << f.mant) | ((1ull << f.mant) - 1);
}

ALWAYS_INLINE Un unpack(u64 bits, Fmt const &f)
{
	Un u{};
	u64 const emask = (1ull << f.expb) - 1;
	u64 const mmask = (1ull << f.mant) - 1;
	u.sign = (bits >> (f.mant + f.expb)) & 1;
	u64 const be = (bits >> f.mant) & emask;
	u64 const m = bits & mmask;
	if (be == emask) {
		u.cls = m == 0 ? C_INF : (((m >> (f.mant - 1)) & 1) ? C_QNAN : C_SNAN);
		return u;
	}
	if (be == 0) {
		u.cls = m == 0 ? C_ZERO : C_FIN;
		u.sig = (u128)m;
		u.exp = f.emin;
		return u;
	}
	u.cls = C_FIN;
	u.sig = (u128)((1ull << f.mant) | m);
	u.exp = (int)be - f.bias - f.mant;
	return u;
}

// The single rounding point. Rounds (-1)^sign * sig * 2^exp into `f`, where `ext_sticky` records
// that the true value is strictly greater in magnitude than sig * 2^exp by less than one unit in
// the last place of sig.
inline u64 round_pack(bool sign, u128 sig, int exp, bool ext_sticky, Fmt const &f, u32 rm, u32 &fl)
{
	if (sig == 0) {
		if (!ext_sticky)
			return sign_bit(sign, f);
		sig = 0; // fall through: a pure sticky rounds to zero or the smallest subnormal
	}

	int const msb = sig ? 127 - clz128(sig) : 0;
	// Normalising would put the leading bit at position `mant`; clamp at emin for subnormals.
	int E = sig ? exp + msb - f.mant : f.emin;
	if (E < f.emin)
		E = f.emin;
	int const shift = E - exp;

	u128 m;
	bool guard = false, sticky = ext_sticky;
	if (shift <= 0) {
		m = sig << (-shift);
	} else if (shift >= 128) {
		m = 0;
		sticky = sticky || sig != 0;
	} else {
		m = sig >> shift;
		guard = (bool)((sig >> (shift - 1)) & 1);
		if (shift >= 2)
			sticky = sticky || (sig & (((u128)1 << (shift - 1)) - 1)) != 0;
	}

	bool const inexact = guard || sticky;
	bool inc = false;
	switch (rm) {
	case FRM_RNE:
		inc = guard && (sticky || (m & 1));
		break;
	case FRM_RTZ:
		break;
	case FRM_RDN:
		inc = inexact && sign;
		break;
	case FRM_RUP:
		inc = inexact && !sign;
		break;
	case FRM_RMM:
		inc = guard; // a tie is exactly guard=1, sticky=0, and RMM takes it away from zero
		break;
	case FRM_ROD:
		break; // handled after the increment: truncate, then force the low bit
	}
	if (inc)
		m++;
	// Round-to-odd is NOT one of the five architectural rounding modes and cannot be
	// requested through frm. vfncvt.rod.f.f.w uses it so that a narrowing convert followed by
	// a second rounding gives the same answer as one correctly-rounded step -- the classic
	// double-rounding defence. It truncates and then sets the low bit whenever anything was
	// discarded, which is why it cannot be expressed on the host FPU at all.
	if (rm == FRM_ROD && inexact)
		m |= 1;
	if (m >= ((u128)1 << (f.mant + 1))) { // carry out of the significand
		m >>= 1;
		E++;
	}

	if (E > f.emax || (m >= ((u128)1 << (f.mant + 1)))) {
		bool to_inf;
		switch (rm) {
		case FRM_RTZ:
		case FRM_ROD: // round-to-odd never produces an infinity from a finite value
			to_inf = false;
			break;
		case FRM_RDN:
			to_inf = sign;
			break;
		case FRM_RUP:
			to_inf = !sign;
			break;
		default:
			to_inf = true; // RNE and RMM
			break;
		}
		fl |= FFLAG_OF | FFLAG_NX;
		return to_inf ? inf_of(sign, f) : maxfin_of(sign, f);
	}

	u64 out;
	if (m < ((u128)1 << f.mant)) { // subnormal (or zero) result
		out = sign_bit(sign, f) | (u64)m;
		// Tininess is detected AFTER rounding, matching both x86 and the QEMU reference:
		// a value that rounds up to the smallest normal does not signal underflow.
		if (inexact)
			fl |= FFLAG_UF;
	} else {
		u64 const be = (u64)(E + f.bias + f.mant);
		out = sign_bit(sign, f) | (be << f.mant) | (u64)(m - ((u128)1 << f.mant));
	}
	if (inexact)
		fl |= FFLAG_NX;
	return out;
}

// ---- exact addition ---------------------------------------------------------------------------
// Both operands are shifted to a common exponent chosen so the larger lands with its leading bit
// at position 126; only the strictly-smaller-magnitude operand can lose bits, and it loses them
// into a sticky. Works unchanged for the 106-bit fused product, which is why FMA reuses it.
inline u64 add_exact(bool sa, u128 A, int ea, bool sb, u128 B, int eb, Fmt const &f, u32 rm, u32 &fl)
{
	if (A == 0 && B == 0) {
		// x + x preserves the sign; +0 + -0 is +0 except downward, where it is -0.
		bool const s = (sa == sb) ? sa : (rm == FRM_RDN);
		return sign_bit(s, f);
	}
	if (A == 0)
		return round_pack(sb, B, eb, false, f, rm, fl);
	if (B == 0)
		return round_pack(sa, A, ea, false, f, rm, fl);

	int const sca = ea + (127 - clz128(A));
	int const scb = eb + (127 - clz128(B));
	int const e = (sca > scb ? sca : scb) - 126;

	bool sticky = false;
	auto align = [&](u128 v, int ev) -> u128 {
		int const sh = ev - e;
		if (sh >= 0)
			return v << sh;
		if (-sh >= 128) {
			sticky = sticky || v != 0;
			return 0;
		}
		if ((v & (((u128)1 << (-sh)) - 1)) != 0)
			sticky = true;
		return v >> (-sh);
	};
	u128 const AA = align(A, ea);
	u128 const BB = align(B, eb);

	if (sa == sb)
		return round_pack(sa, AA + BB, e, sticky, f, rm, fl);

	// Opposite signs: subtract. Only the strictly-smaller-scale operand is ever right-shifted,
	// and the surviving one keeps its leading bit at position 126, so the larger aligned value
	// always dominates and the sign is simply the sign of the larger.
	if (AA == BB && !sticky)
		return sign_bit(rm == FRM_RDN, f); // exact cancellation is +0, except downward
	bool const a_big = AA >= BB;
	u128 diff = a_big ? AA - BB : BB - AA;
	bool const rs = a_big ? sa : sb;
	// A discarded tail belongs to the subtrahend (it is the smaller operand), so the true
	// difference is one unit less with a non-zero remainder: borrow one and keep the sticky.
	// diff >= 2^126 - 2^106 here, so the borrow cannot underflow.
	if (sticky)
		diff -= 1;
	return round_pack(rs, diff, e, sticky, f, rm, fl);
}

// ---- integer square root over u128 --------------------------------------------------------------
inline u128 isqrt128(u128 v, bool &exact)
{
	if (v == 0) {
		exact = true;
		return 0;
	}
	int sh = (127 - clz128(v)) & ~1; // start at an even bit position
	u128 rem = 0, root = 0;
	for (int i = sh; i >= 0; i -= 2) {
		rem = (rem << 2) | ((v >> i) & 3);
		root <<= 1;
		if (rem > (root << 1))
			rem -= (root << 1) | 1, root |= 1;
	}
	exact = rem == 0;
	return root;
}

// ---- the operations -----------------------------------------------------------------------------
// Special-case handling is written out rather than delegated because it is rounding-mode
// independent and short; the -DRVV_FP_FORCE_SOFT differential checks it against QEMU too.

ALWAYS_INLINE bool nan_in(Un const &a, u32 &fl)
{
	if (a.cls == C_SNAN)
		fl |= FFLAG_NV;
	return a.cls == C_SNAN || a.cls == C_QNAN;
}

inline u64 op_add(u64 ab, u64 bb, bool sub, Fmt const &f, u32 rm, u32 &fl)
{
	Un a = unpack(ab, f), b = unpack(bb, f);
	if (sub)
		b.sign = !b.sign;
	bool na = nan_in(a, fl), nb = nan_in(b, fl);
	if (na || nb)
		return f.qnan;
	if (a.cls == C_INF || b.cls == C_INF) {
		if (a.cls == C_INF && b.cls == C_INF && a.sign != b.sign) {
			fl |= FFLAG_NV; // inf - inf
			return f.qnan;
		}
		return inf_of(a.cls == C_INF ? a.sign : b.sign, f);
	}
	return add_exact(a.sign, a.sig, a.exp, b.sign, b.sig, b.exp, f, rm, fl);
}

inline u64 op_mul(u64 ab, u64 bb, Fmt const &f, u32 rm, u32 &fl)
{
	Un a = unpack(ab, f), b = unpack(bb, f);
	bool na = nan_in(a, fl), nb = nan_in(b, fl);
	if (na || nb)
		return f.qnan;
	bool const s = a.sign ^ b.sign;
	if (a.cls == C_INF || b.cls == C_INF) {
		if (a.cls == C_ZERO || b.cls == C_ZERO) {
			fl |= FFLAG_NV; // 0 * inf
			return f.qnan;
		}
		return inf_of(s, f);
	}
	if (a.cls == C_ZERO || b.cls == C_ZERO)
		return sign_bit(s, f);
	return round_pack(s, a.sig * b.sig, a.exp + b.exp, false, f, rm, fl);
}

inline u64 op_div(u64 ab, u64 bb, Fmt const &f, u32 rm, u32 &fl)
{
	Un a = unpack(ab, f), b = unpack(bb, f);
	bool na = nan_in(a, fl), nb = nan_in(b, fl);
	if (na || nb)
		return f.qnan;
	bool const s = a.sign ^ b.sign;
	if (a.cls == C_INF) {
		if (b.cls == C_INF) {
			fl |= FFLAG_NV;
			return f.qnan;
		}
		return inf_of(s, f);
	}
	if (b.cls == C_INF)
		return sign_bit(s, f);
	if (b.cls == C_ZERO) {
		if (a.cls == C_ZERO) {
			fl |= FFLAG_NV; // 0 / 0
			return f.qnan;
		}
		fl |= FFLAG_DZ;
		return inf_of(s, f);
	}
	if (a.cls == C_ZERO)
		return sign_bit(s, f);
	// The numerator shift must be derived from the OPERANDS, not fixed. A constant shift is
	// wrong whenever the significands differ greatly in width, which is exactly what happens
	// with subnormals: dividing 2^-1074 (one significant bit) by a 53-bit subnormal leaves a
	// 13-bit quotient, so rounding lands at the wrong position and no sticky bit can repair it.
	// Choosing L so the quotient carries mant+3 bits makes the guard position correct for every
	// operand pair; wa <= mant and wb >= 0 keep L positive and a.sig << L inside 128 bits.
	int const wa = 127 - clz128(a.sig), wb = 127 - clz128(b.sig);
	int const L = f.mant + 3 + wb - wa;
	u128 const num = a.sig << L;
	u128 const q = num / b.sig;
	bool const inexact = (num % b.sig) != 0;
	return round_pack(s, q, a.exp - b.exp - L, inexact, f, rm, fl);
}

inline u64 op_sqrt(u64 ab, Fmt const &f, u32 rm, u32 &fl)
{
	Un a = unpack(ab, f);
	if (nan_in(a, fl))
		return f.qnan;
	if (a.cls == C_ZERO)
		return sign_bit(a.sign, f); // sqrt(-0) = -0
	if (a.sign) {
		fl |= FFLAG_NV;
		return f.qnan;
	}
	if (a.cls == C_INF)
		return inf_of(false, f);
	// Scale by an even power of two so the exponent halves cleanly, leaving the radicand as
	// wide as u128 allows: the root then carries far more bits than any format needs.
	int e = a.exp;
	u128 v = a.sig;
	int room = clz128(v) & ~1;
	v <<= room;
	e -= room;
	if (e & 1) {
		v >>= 1;
		e += 1;
	}
	bool exact;
	u128 const r = isqrt128(v, exact);
	return round_pack(false, r, e / 2, !exact, f, rm, fl);
}

// fmadd/fmsub/fnmsub/fnmadd differ only in which of the product and the addend are negated.
inline u64 op_fma(u64 ab, u64 bb, u64 cb, bool neg_prod, bool neg_c, Fmt const &f, u32 rm, u32 &fl)
{
	Un a = unpack(ab, f), b = unpack(bb, f), c = unpack(cb, f);
	bool na = nan_in(a, fl), nb = nan_in(b, fl), nc = nan_in(c, fl);
	bool const prod_invalid =
	    (a.cls == C_INF && b.cls == C_ZERO) || (a.cls == C_ZERO && b.cls == C_INF);
	if (prod_invalid)
		fl |= FFLAG_NV;
	if (na || nb || nc || prod_invalid)
		return f.qnan;
	bool ps = (a.sign ^ b.sign) ^ neg_prod;
	if (neg_c)
		c.sign = !c.sign;

	if (a.cls == C_INF || b.cls == C_INF) {
		if (c.cls == C_INF && c.sign != ps) {
			fl |= FFLAG_NV;
			return f.qnan;
		}
		return inf_of(ps, f);
	}
	if (c.cls == C_INF)
		return inf_of(c.sign, f);
	if (a.cls == C_ZERO || b.cls == C_ZERO) {
		if (c.cls == C_ZERO) {
			bool const s = (ps == c.sign) ? ps : (rm == FRM_RDN);
			return sign_bit(s, f);
		}
		return round_pack(c.sign, c.sig, c.exp, false, f, rm, fl);
	}
	// The product is carried EXACTLY (106 bits at most) into the addition, which is what makes
	// this a fused multiply-add rather than a multiply followed by an add.
	return add_exact(ps, a.sig * b.sig, a.exp + b.exp, c.sign, c.sig, c.exp, f, rm, fl);
}

// ---- conversions --------------------------------------------------------------------------------
inline u64 cvt_fmt(u64 ab, Fmt const &from, Fmt const &to, u32 rm, u32 &fl)
{
	Un a = unpack(ab, from);
	if (a.cls == C_SNAN) {
		fl |= FFLAG_NV;
		return to.qnan;
	}
	if (a.cls == C_QNAN)
		return to.qnan;
	if (a.cls == C_INF)
		return inf_of(a.sign, to);
	if (a.cls == C_ZERO)
		return sign_bit(a.sign, to);
	return round_pack(a.sign, a.sig, a.exp, false, to, rm, fl);
}

inline u64 cvt_from_int(u64 mag, bool sign, Fmt const &to, u32 rm, u32 &fl)
{
	if (mag == 0)
		return 0;
	return round_pack(sign, (u128)mag, 0, false, to, rm, fl);
}

// Vector integer width is independent of the RV32 scalar register width.
// Range-check the rounded magnitude before narrowing; invalid suppresses inexact.
inline u64 cvt_to_int_width(u64 ab, bool is_signed, Fmt const &f, u32 rm, u32 bits, u32 &fl)
{
	if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
		Panic("softfp: invalid integer result width");
	Un a = unpack(ab, f);
	u64 const all = ~u64(0) >> (64 - bits), sign = u64(1) << (bits - 1);
	u64 const sat_max = is_signed ? sign - 1 : all;
	u64 const sat_min = is_signed ? sign : 0;
	if (a.cls == C_SNAN || a.cls == C_QNAN) {
		fl |= FFLAG_NV;
		return sat_max;
	}
	if (a.cls == C_INF) {
		fl |= FFLAG_NV;
		return a.sign ? sat_min : sat_max;
	}
	if (a.cls == C_ZERO)
		return 0;

	u128 ip;
	bool guard = false, sticky = false;
	if (a.exp >= 0) {
		if (a.exp > 64) { // certainly out of range
			fl |= FFLAG_NV;
			return a.sign ? sat_min : sat_max;
		}
		ip = a.sig << a.exp;
	} else {
		int const sh = -a.exp;
		if (sh >= 128) {
			ip = 0;
			sticky = true;
		} else {
			ip = a.sig >> sh;
			guard = (bool)((a.sig >> (sh - 1)) & 1);
			if (sh >= 2)
				sticky = (a.sig & (((u128)1 << (sh - 1)) - 1)) != 0;
		}
	}
	bool const inexact = guard || sticky;
	bool inc = false;
	switch (rm) {
	case FRM_RNE:
		inc = guard && (sticky || (ip & 1));
		break;
	case FRM_RTZ:
		break;
	case FRM_RDN:
		inc = inexact && a.sign;
		break;
	case FRM_RUP:
		inc = inexact && !a.sign;
		break;
	case FRM_RMM:
		inc = guard;
		break;
	}
	if (inc)
		ip++;

	// Range check on the ROUNDED magnitude; NV and NX are mutually exclusive here.
	if (is_signed) {
		u128 const lim = a.sign ? (u128)sign : (u128)sat_max;
		if (ip > lim) {
			fl |= FFLAG_NV;
			return a.sign ? sat_min : sat_max;
		}
	} else {
		if (a.sign && ip != 0) {
			fl |= FFLAG_NV;
			return sat_min;
		}
		if (ip > (u128)all) {
			fl |= FFLAG_NV;
			return sat_max;
		}
	}
	if (inexact)
		fl |= FFLAG_NX;
	u64 const mag = (u64)ip;
	return (a.sign ? u64(0) - mag : mag) & all;
}

inline u32 cvt_to_int(u64 ab, bool is_signed, Fmt const &f, u32 rm, u32 &fl)
{
	return (u32)cvt_to_int_width(ab, is_signed, f, rm, 32, fl);
}

} // namespace dbt::rv32::softfp
