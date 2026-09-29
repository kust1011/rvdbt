#pragma once

// RV32F + RV32D scalar floating-point substrate.
//
// rvdbt had NO floating point at all: no f registers, no fcsr, no FP opcodes. That is why
// every floating PolyBench kernel was unreachable -- not because RVV lacked a family, but
// because there was no architectural state for a vector FP unit to sit on. This file adds that
// state and its semantics; the vector FP families build on the same helpers so the scalar and
// vector paths cannot define IEEE behaviour differently.
//
// Design decisions worth stating:
//
//  * f registers are 64 bits (RV32D). Single-precision values are NAN-BOXED per the spec: a
//    valid 32-bit value has all-ones in bits [63:32], and reading a single-precision operand
//    from a register that is not properly boxed yields the canonical NaN. Getting this wrong is
//    invisible until a program mixes .s and .d on the same register, so it is implemented
//    directly rather than approximated by storing floats unboxed.
//
//  * Arithmetic uses the HOST FPU (x86-64 SSE, IEEE-754 binary32/binary64) with the rounding
//    mode driven from `frm` and the accrued flags read back into `fflags`. That is the only
//    practical way to get correctly-rounded results including subnormals; a soft-float
//    reimplementation would be a second IEEE implementation to get wrong. The QEMU differential
//    is what validates it.
//
//  * The canonical NaN, the sign of zero, min/max NaN rules and the conversion
//    out-of-range/NaN saturation rules are RISC-V specific and DO NOT match the host's default
//    behaviour, so each is implemented explicitly below.

#include "dbt/util/common.h"

#include <cfenv>
#include <cmath>
#include <immintrin.h> // MXCSR access for FRound (see the P13 baseline-repair note below)
#include <cstring>
#include <limits>

namespace dbt::rv32
{

// ---- fcsr ------------------------------------------------------------------------------------
// fcsr = { frm[7:5], fflags[4:0] }; fflags = NV NZ OF UF NX (bit4..bit0).
enum : u32 {
	FFLAG_NX = 1u << 0, // inexact
	FFLAG_UF = 1u << 1, // underflow
	FFLAG_OF = 1u << 2, // overflow
	FFLAG_DZ = 1u << 3, // divide by zero
	FFLAG_NV = 1u << 4, // invalid operation
};
enum : u32 {
	FRM_RNE = 0, // round to nearest, ties to even
	FRM_RTZ = 1, // round towards zero
	FRM_RDN = 2, // round down (-inf)
	FRM_RUP = 3, // round up (+inf)
	FRM_RMM = 4, // round to nearest, ties to max magnitude
	// Not architectural and not reachable through frm: an internal mode used only by
	// vfncvt.rod.f.f.w, which the spec defines in terms of round-to-odd.
	FRM_ROD = 8,
	FRM_DYN = 7, // use fcsr.frm (only valid in an instruction's rm field)
};

static constexpr u32 F32_CANONICAL_NAN = 0x7fc00000u;
static constexpr u64 F64_CANONICAL_NAN = 0x7ff8000000000000ull;
static constexpr u64 NAN_BOX_MASK = 0xffffffff00000000ull;

struct FPUState {
	u64 f[32]{}; // RV32D: 64-bit registers; single-precision values are NaN-boxed
	u32 fcsr{};  // frm[7:5] | fflags[4:0]

	constexpr u32 frm() const { return (fcsr >> 5) & 0x7; }
	constexpr u32 fflags() const { return fcsr & 0x1f; }
	void set_fflags(u32 f_) { fcsr = (fcsr & ~0x1fu) | (f_ & 0x1f); }
	void raise(u32 f_) { fcsr |= (f_ & 0x1f); }
	void set_frm(u32 r) { fcsr = (fcsr & ~0xe0u) | ((r & 0x7) << 5); }

	// P13 B3-narrow (docs/P3_B3_NARROW_PROTOTYPE_DESIGN.md): when true, a same-block run of
	// immediately-adjacent eligible FP-vector instructions (try_falu/try_fma/try_vfcmp) left the
	// host MXCSR bracket open on purpose -- the NEXT such instruction must not re-open it, and
	// whichever instruction closes the run must restore exactly `fround_run_saved_mxcsr` (the
	// value saved by the run's FIRST instruction, not any intermediate one). Both fields are
	// false/0 whenever no run is open, which is the state outside `try_falu`/`try_fma`/
	// `try_vfcmp`'s own bracket-management code -- nothing else may read or write them.
	bool fround_run_open = false;
	u32 fround_run_saved_mxcsr = 0;
	// T7R QCG direct-vfalu bracket scratch. Kept in architectural state so emitted code needs no
	// process-global storage and can preserve the host MXCSR across helper/direct transitions.
	u32 qcg_current_mxcsr = 0;
	// G3 instrumentation: direct evidence that the scalar bracket amortisation is consumed, and
	// why runs end. sc_open counts brackets started and sc_continue instructions that joined one.
	// The close counters are attributed at their own call sites ONLY; a run closed elsewhere --
	// notably by the vector path, which shares this same run state -- increments none of them, so
	// they do NOT partition sc_open and must not be read as if they did. sc_note_run() is called
	// from the single close funnel, so the histogram and sc_run_len_sum ARE complete.
	// Kept in FPUState rather than rvv_fast::FastStats purely because this header is included
	// first; the dump in elfrun.cpp reads both.
	unsigned long long sc_open = 0, sc_continue = 0;
	unsigned long long sc_close_csr = 0, sc_close_mode = 0, sc_close_tbexit = 0;
	unsigned long long sc_run_len_sum = 0, sc_cur_run = 0;
	unsigned long long sc_hist[9] = {}; // 1,2,3,4,5-8,9-16,17-32,33-64,65+
	// G7 cycle 3. The rounding-control bits currently installed in the host MXCSR, mirrored in
	// plain memory. Without this the "continue an open run" path still executed an STMXCSR on
	// EVERY FP instruction just to compare MXCSR.RC -- which is the serialising access the
	// amortisation exists to remove. Measured before the fix: FRound::FRound was 11.6 % of
	// pb_gemm at VLEN512 and 18.1 % at VLEN1024 despite only 4.7 % of ops opening a bracket.
	// This field is written on every MXCSR write this code performs, so it cannot drift; the
	// A/B flag exists to prove the two agree.
	u32 fround_run_rc = 0;
	void sc_note_run()
	{
		if (!sc_cur_run) return;
		sc_run_len_sum += sc_cur_run;
		unsigned long long n = sc_cur_run;
		unsigned b = n <= 4 ? (unsigned)n - 1 : n <= 8 ? 4 : n <= 16 ? 5 : n <= 32 ? 6
			     : n <= 64 ? 7 : 8;
		sc_hist[b]++;
		sc_cur_run = 0;
	}
};

// ---- NaN boxing ---------------------------------------------------------------------------
// Reading a single-precision operand from an improperly boxed register must yield the canonical
// NaN, not the raw low half. Writing one must set the box.
ALWAYS_INLINE u32 f32_unbox(u64 raw)
{
	return (raw & NAN_BOX_MASK) == NAN_BOX_MASK ? (u32)raw : F32_CANONICAL_NAN;
}
ALWAYS_INLINE u64 f32_box(u32 bits) { return NAN_BOX_MASK | (u64)bits; }

ALWAYS_INLINE float bits_to_f32(u32 b)
{
	float v;
	std::memcpy(&v, &b, 4);
	return v;
}
ALWAYS_INLINE u32 f32_to_bits(float v)
{
	u32 b;
	std::memcpy(&b, &v, 4);
	return b;
}
ALWAYS_INLINE double bits_to_f64(u64 b)
{
	double v;
	std::memcpy(&v, &b, 8);
	return v;
}
ALWAYS_INLINE u64 f64_to_bits(double v)
{
	u64 b;
	std::memcpy(&b, &v, 8);
	return b;
}

// ---- which engine executes a rounding-dependent instruction, and is it even legal ----------------
//
// The rm FIELD and the EFFECTIVE mode are different things, and both can be illegal:
//   * a static rm of 5 or 6 is reserved and always illegal;
//   * rm=7 means "use fcsr.frm", so if frm itself holds 5, 6 or 7 the instruction is illegal.
// A guest reaches the second case with a plain `csrw frm, 5`, and it must trap rather than
// quietly round some other way.
//
// RMM (ties-to-max-magnitude) is the one mode x86 cannot express -- MXCSR.RC encodes exactly
// four -- so it is routed to the exact integer core in rv32_softfp.h instead of being refused.
// Vector FP has no rm field at all and always resolves through frm, which is why this decision
// has to live next to the FPU state rather than in the scalar decoder.
enum FpPath { FP_HOST, FP_SOFT, FP_ILLEGAL };
struct FpMode {
	u32 rm;
	FpPath path;
};

ALWAYS_INLINE FpMode fp_mode(FPUState const &fs, u32 rmfield)
{
	u32 const eff = (rmfield == FRM_DYN) ? fs.frm() : rmfield;
	if (unlikely(eff > FRM_RMM))
		return {eff, FP_ILLEGAL};
#ifdef RVV_FP_FORCE_SOFT
	// Validation build: everything goes through the exact core so the QEMU differential
	// exercises it in the four modes an oracle comparison can cover.
	return {eff, FP_SOFT};
#else
	return {eff, eff == FRM_RMM ? FP_SOFT : FP_HOST};
#endif
}

// ---- host rounding-mode bracket ---------------------------------------------------------------
// Applies the effective rounding mode to the host FPU for the duration of one operation (or one
// vector loop) and accrues the host's raised exceptions into fflags.
//
// Inactive when the caller is using the exact core: leaving the bracket in place there would
// clear and re-read host exception state that no host instruction produced, manufacturing
// flags out of whatever the host FPU last did.
// P13 BASELINE REPAIR (2026-08-18), with the variants kept switchable because the first version
// of it broke a correctness gate and the ablation has to be reproducible.
//
// The bracket used to be four libc calls -- fegetround, fesetround, feclearexcept, fetestexcept --
// per VECTOR INSTRUCTION. The census measured the consequence: ~420 fixed cycles per vfadd.vv
// call against ~78 per element (docs/A2_DYNAMIC_COST_PARETO.md SS4).
//
// All guest FP here is computed in float/double, which clang compiles to SSE, so the state that
// matters is MXCSR; glibc's fenv wrappers additionally touch the x87 control word, which nothing
// on this path uses.
//
//   RVDBT_FROUND_LIBC       0  the original fenv implementation (semantics reference)
//   RVDBT_FROUND_INTRIN     1  _mm_getcsr/_mm_setcsr
//   RVDBT_FROUND_ASM        2  stmxcsr/ldmxcsr through volatile asm with a memory clobber
//
// The distinction between 1 and 2 is not cosmetic. Without `#pragma STDC FENV_ACCESS ON` the
// compiler assumes the default floating-point environment, and `_mm_setcsr` is an ordinary
// intrinsic with no ordering semantics -- so a guest FP operation may legally be scheduled
// BEFORE the store that clears the exception flags, and the flag it raises is then wiped. That
// is a lost-flag bug, not a slow path. Variant 2 makes the accesses volatile asm with a memory
// clobber so nothing may be moved across them.
#ifndef RVDBT_FROUND_IMPL
#define RVDBT_FROUND_IMPL 2
#endif

#if RVDBT_FROUND_IMPL != 0
ALWAYS_INLINE unsigned rvdbt_mxcsr_get()
{
#if RVDBT_FROUND_IMPL == 1
	return _mm_getcsr();
#else
	unsigned v;
	__asm__ volatile("stmxcsr %0" : "=m"(v) : : "memory");
	return v;
#endif
}
ALWAYS_INLINE void rvdbt_mxcsr_set(unsigned v)
{
#if RVDBT_FROUND_IMPL == 1
	_mm_setcsr(v);
#else
	__asm__ volatile("ldmxcsr %0" : : "m"(v) : "memory");
#endif
}
#endif

#if RVDBT_FROUND_IMPL != 0
// Extracted from FRound's RVDBT_FROUND_IMPL==2 constructor/finish() bodies (P13 B3-narrow,
// docs/P3_B3_NARROW_PROTOTYPE_DESIGN.md) so try_falu/try_fma/try_vfcmp's run-batching logic can
// reuse the EXACT SAME rounding-mode and exception-flag mapping FRound itself uses, instead of a
// second, independently-written copy that could silently drift from it. Pure extraction: FRound's
// own behaviour below is unchanged, just calls these instead of inlining them.
ALWAYS_INLINE unsigned mxcsr_rc_for_frm(u32 rm)
{
	switch (rm) {
	case FRM_RNE:
		return 0u << 13; // nearest, ties to even
	case FRM_RTZ:
		return 3u << 13; // truncate
	case FRM_RDN:
		return 1u << 13; // down
	default:
		return 2u << 13; // up
	}
}
ALWAYS_INLINE u32 mxcsr_bits_to_fflags(unsigned e)
{
	u32 f = 0;
	if (e & (1u << 0))
		f |= FFLAG_NV; // invalid
	if (e & (1u << 2))
		f |= FFLAG_DZ; // divide by zero
	if (e & (1u << 3))
		f |= FFLAG_OF; // overflow
	if (e & (1u << 4))
		f |= FFLAG_UF; // underflow
	if (e & (1u << 5))
		f |= FFLAG_NX; // precision / inexact
	return f;
}
#endif

// RVDBT_FROUND_DIAG_NOP: DIAGNOSTIC ONLY. Makes the rounding-mode bracket a no-op so the cost of
// entering it per scalar FP instruction can be measured. The resulting binary is INCORRECT -- it
// neither applies the guest rounding mode nor accumulates fflags -- and must never be shipped or
// used for a correctness or speedup claim. It exists to bound, from above, what perfect run
// amortisation of the bracket could win, before that amortisation is built.
#ifndef RVDBT_FROUND_DIAG_NOP
#define RVDBT_FROUND_DIAG_NOP 0
#endif
#if RVDBT_FROUND_DIAG_NOP
struct FRound {
	static constexpr unsigned MXCSR_RC = 0x6000u;
	static constexpr unsigned MXCSR_FLAGS = 0x3fu;
	unsigned saved;
	bool active;
	FRound(FPUState &, FpMode) : saved(0), active(false) {}
	void finish(FPUState &) {}
};
#else
struct FRound {
	static constexpr unsigned MXCSR_RC = 0x6000u;  // bits [14:13]
	static constexpr unsigned MXCSR_FLAGS = 0x3fu; // IE DE ZE OE UE PE
	unsigned saved;
	bool active;

#if RVDBT_FROUND_IMPL == 0
	FRound(FPUState &, FpMode md)
	{
		active = md.path == FP_HOST;
		saved = (unsigned)std::fegetround();
		if (!active)
			return;
		switch (md.rm) {
		case FRM_RNE:
			std::fesetround(FE_TONEAREST);
			break;
		case FRM_RTZ:
			std::fesetround(FE_TOWARDZERO);
			break;
		case FRM_RDN:
			std::fesetround(FE_DOWNWARD);
			break;
		default:
			std::fesetround(FE_UPWARD);
			break;
		}
		std::feclearexcept(FE_ALL_EXCEPT);
	}
	void finish(FPUState &fs)
	{
		if (!active)
			return;
		int const e = std::fetestexcept(FE_ALL_EXCEPT);
		u32 f = 0;
		if (e & FE_INVALID)
			f |= FFLAG_NV;
		if (e & FE_DIVBYZERO)
			f |= FFLAG_DZ;
		if (e & FE_OVERFLOW)
			f |= FFLAG_OF;
		if (e & FE_UNDERFLOW)
			f |= FFLAG_UF;
		if (e & FE_INEXACT)
			f |= FFLAG_NX;
		fs.raise(f);
		std::fesetround((int)saved);
	}
#else
	// P14 cycle 4: optionally keep the bracket OPEN across consecutive scalar FP instructions
	// instead of paying STMXCSR + LDMXCSR twice per guest op. Sized by the diagnostic no-op
	// ablation (docs/P14_CYCLE4_DESIGN.md): the bracket is up to 45 % of pb_gemm's cycles at
	// VLEN=1024, and its share GROWS with VLEN, so it is also what caps VLEN512->1024 scaling.
	//
	// Reuses the vector path's existing run state (`fs.fround_run_open` /
	// `fs.fround_run_saved_mxcsr`) rather than a second mechanism, so a scalar op and a vector
	// op can continue each other's run and there is exactly one close path. Closing is
	// guaranteed by TbExitCloseOpenFroundRun() at every TB exit, plus an explicit close before
	// anything that can observe fcsr/fflags or change frm.
	//
	// Off by default: `--rvv-scalar-fround-run` is the in-binary A/B control.
	bool continued;
	FRound(FPUState &fs, FpMode md)
	{
		active = md.path == FP_HOST;
		continued = false;
		if (!active) {
			saved = 0;
			return;
		}
		if (config::rvv_scalar_fround_run) {
			u32 const want = mxcsr_rc_for_frm(md.rm);
			if (fs.fround_run_open) {
				// Already inside a run. Continue it only if the rounding mode
				// matches; a different frm needs its own bracket, so close first.
				// The comparison reads the mirrored RC, not MXCSR, so the common
				// continue path costs a load and a compare instead of an STMXCSR.
				u32 const cur = config::rvv_scalar_fround_rcmirror
						  ? fs.fround_run_rc
						  : (rvdbt_mxcsr_get() & MXCSR_RC);
				if (cur == want) {
					continued = true;
					saved = fs.fround_run_saved_mxcsr;
					fs.sc_continue++;
					fs.sc_cur_run++;
					return;
				}
				fs.raise(mxcsr_bits_to_fflags(rvdbt_mxcsr_get()));
				rvdbt_mxcsr_set(fs.fround_run_saved_mxcsr);
				fs.fround_run_open = false;
				fs.sc_close_mode++;
			}
			saved = rvdbt_mxcsr_get();
			rvdbt_mxcsr_set((saved & ~(MXCSR_RC | MXCSR_FLAGS)) | want);
			fs.fround_run_open = true;
			fs.fround_run_saved_mxcsr = saved;
			fs.fround_run_rc = want;
			fs.sc_open++;
			fs.sc_cur_run = 1;
			continued = true; // this op owns the run; finish() leaves it open
			return;
		}
		saved = rvdbt_mxcsr_get();
		rvdbt_mxcsr_set((saved & ~(MXCSR_RC | MXCSR_FLAGS)) | mxcsr_rc_for_frm(md.rm));
	}
	void finish(FPUState &fs)
	{
		if (!active)
			return;
		if (continued) {
			// Leave MXCSR alone: flags keep accumulating in it and are harvested into
			// fflags by whoever closes the run. Nothing between here and the close may
			// read fcsr/fflags -- enforced by the explicit closes described above.
			return;
		}
		u32 const f = mxcsr_bits_to_fflags(rvdbt_mxcsr_get());
		fs.raise(f);
		rvdbt_mxcsr_set(saved);
	}
#endif
};
#endif // RVDBT_FROUND_DIAG_NOP

// ---- canonical NaN ---------------------------------------------------------------------------
// RISC-V requires that whenever an arithmetic operation PRODUCES a NaN, the result is the
// CANONICAL quiet NaN -- the input payload is never propagated. x86 does the opposite: it
// quiets the incoming NaN and keeps its payload, so fadd.s(sNaN 0x7fa00000, 1.0) yields
// 0x7fe00000 on the host where RISC-V requires 0x7fc00000.
//
// This is not a corner case that only adversarial inputs reach: any real program that lets a
// NaN through arithmetic would produce a different bit pattern from a real RISC-V core, and it
// is invisible to a test that only checks finite values. Every arithmetic result therefore goes
// through these. Sign-injection and min/max are deliberately NOT canonicalised -- the spec
// defines them as bit manipulation / operand selection respectively.
ALWAYS_INLINE u32 f32_canon(u32 b)
{
	return ((b & 0x7f800000u) == 0x7f800000u && (b & 0x007fffffu)) ? F32_CANONICAL_NAN : b;
}
ALWAYS_INLINE u64 f64_canon(u64 b)
{
	return ((b & 0x7ff0000000000000ull) == 0x7ff0000000000000ull && (b & 0x000fffffffffffffull))
		   ? F64_CANONICAL_NAN
		   : b;
}
ALWAYS_INLINE float f32_canon_v(float v) { return bits_to_f32(f32_canon(f32_to_bits(v))); }
ALWAYS_INLINE double f64_canon_v(double v) { return bits_to_f64(f64_canon(f64_to_bits(v))); }

// ---- RISC-V specific NaN / min-max / classify rules --------------------------------------------
ALWAYS_INLINE bool f32_is_snan(u32 b)
{
	return ((b & 0x7f800000u) == 0x7f800000u) && (b & 0x007fffffu) && !(b & 0x00400000u);
}
ALWAYS_INLINE bool f64_is_snan(u64 b)
{
	return ((b & 0x7ff0000000000000ull) == 0x7ff0000000000000ull) &&
	       (b & 0x000fffffffffffffull) && !(b & 0x0008000000000000ull);
}

// RISC-V fmin/fmax: if exactly one operand is NaN the result is the other operand; if both are
// NaN the result is the CANONICAL NaN; a signalling NaN always raises NV. -0.0 < +0.0.
template <typename T> struct FMinMax {
};
ALWAYS_INLINE u32 f32_minmax(FPUState &fs, u32 a, u32 b, bool is_max)
{
	float const x = bits_to_f32(a), y = bits_to_f32(b);
	if (f32_is_snan(a) || f32_is_snan(b))
		fs.raise(FFLAG_NV);
	bool const nx = std::isnan(x), ny = std::isnan(y);
	if (nx && ny)
		return F32_CANONICAL_NAN;
	if (nx)
		return b;
	if (ny)
		return a;
	if (x == 0.0f && y == 0.0f) // distinguish -0.0 from +0.0
		return (is_max == ((a >> 31) == 0)) ? a : b;
	return (is_max ? (x > y) : (x < y)) ? a : b;
}
ALWAYS_INLINE u64 f64_minmax(FPUState &fs, u64 a, u64 b, bool is_max)
{
	double const x = bits_to_f64(a), y = bits_to_f64(b);
	if (f64_is_snan(a) || f64_is_snan(b))
		fs.raise(FFLAG_NV);
	bool const nx = std::isnan(x), ny = std::isnan(y);
	if (nx && ny)
		return F64_CANONICAL_NAN;
	if (nx)
		return b;
	if (ny)
		return a;
	if (x == 0.0 && y == 0.0)
		return (is_max == ((a >> 63) == 0)) ? a : b;
	return (is_max ? (x > y) : (x < y)) ? a : b;
}

// fclass: a 10-bit one-hot classification, bit order fixed by the spec.
ALWAYS_INLINE u32 f32_classify(u32 b)
{
	bool const sign = b >> 31;
	u32 const exp = (b >> 23) & 0xff, man = b & 0x7fffff;
	if (exp == 0xff && man)
		return (man & 0x400000) ? (1u << 9) : (1u << 8); // quiet : signalling NaN
	if (exp == 0xff)
		return sign ? (1u << 0) : (1u << 7); // -inf : +inf
	if (exp == 0 && man == 0)
		return sign ? (1u << 3) : (1u << 4); // -0 : +0
	if (exp == 0)
		return sign ? (1u << 2) : (1u << 5); // -subnormal : +subnormal
	return sign ? (1u << 1) : (1u << 6);	     // -normal : +normal
}
ALWAYS_INLINE u32 f64_classify(u64 b)
{
	bool const sign = b >> 63;
	u32 const exp = (u32)((b >> 52) & 0x7ff);
	u64 const man = b & 0xfffffffffffffull;
	if (exp == 0x7ff && man)
		return (man & 0x8000000000000ull) ? (1u << 9) : (1u << 8);
	if (exp == 0x7ff)
		return sign ? (1u << 0) : (1u << 7);
	if (exp == 0 && man == 0)
		return sign ? (1u << 3) : (1u << 4);
	if (exp == 0)
		return sign ? (1u << 2) : (1u << 5);
	return sign ? (1u << 1) : (1u << 6);
}

// ---- float -> integer conversion ----------------------------------------------------------------
// RISC-V saturates instead of trapping and has fixed results for NaN: NaN -> max positive for
// both signed and unsigned. Out-of-range saturates to the min/max of the target type. Every one
// of these cases raises NV, and none of them matches what a bare host cast does (that is UB).
//
// `v` is the UNROUNDED operand. The rounding happens here rather than at the call site because
// the inexact flag is decided by comparing the rounded result against the original, and splitting
// those two steps is what previously lost the flag: std::nearbyint is specified NOT to raise
// inexact (that is std::rint's job), so every non-integral conversion silently reported no NX.
// QEMU's reference run disagreed on exactly 92 records, all of this one shape.
//
// The NV/NX interaction is a real rule, not an ordering accident: RISC-V raises NV alone when the
// rounded result is out of range, and NX alone when it is in range but differs from the operand.
// The two are never raised together, which is why every out-of-range path returns early.
template <typename SI, typename UI>
ALWAYS_INLINE u32 float_to_int(FPUState &fs, double v, bool is_signed, bool is_nan)
{
	constexpr double smin = (double)std::numeric_limits<SI>::min();
	constexpr double smax = (double)std::numeric_limits<SI>::max();
	constexpr double umax = (double)std::numeric_limits<UI>::max();
	if (is_nan) {
		fs.raise(FFLAG_NV);
		return is_signed ? (u32)(SI)std::numeric_limits<SI>::max()
				 : (u32)std::numeric_limits<UI>::max();
	}
	// Rounds under whatever host mode the enclosing FRound installed, so the instruction's rm
	// (or fcsr.frm) applies. Range checks use the ROUNDED value: 2147483647.5 is out of range
	// under RNE but in range under RTZ, and the spec keys off the rounded result.
	double const r = std::nearbyint(v);
	if (is_signed) {
		if (r < smin) {
			fs.raise(FFLAG_NV);
			return (u32)(SI)std::numeric_limits<SI>::min();
		}
		if (r > smax) {
			fs.raise(FFLAG_NV);
			return (u32)(SI)std::numeric_limits<SI>::max();
		}
		if (r != v)
			fs.raise(FFLAG_NX);
		return (u32)(SI)r;
	}
	if (r <= -1.0) {
		fs.raise(FFLAG_NV);
		return 0;
	}
	if (r > umax) {
		fs.raise(FFLAG_NV);
		return (u32)std::numeric_limits<UI>::max();
	}
	if (r != v)
		fs.raise(FFLAG_NX);
	return (u32)(UI)r;
}

} // namespace dbt::rv32
