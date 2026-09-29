// One host width's chunk-run kernels. Included once per translation unit with RVVRUN_W set to
// the width in bytes (16/32/64), each TU compiled with only that width's ISA flags.
//
// WHY A TU PER WIDTH RATHER THAN target-ATTRIBUTE MULTIVERSIONING
// The chunk kernels in rv32_vector_fast.h are ALWAYS_INLINE templates over a compile-time chunk
// type. Multiversioning them would mean either hand-duplicating every kernel per width or forcing
// them out of line and losing the inlining the fast path depends on. Compiling the same source
// three times duplicates nothing.
//
// WHY THIS FILE IS SELF-CONTAINED AND DOES NOT INCLUDE rv32_vector_lower.h
// That header defines its width-dependent primitives as namespace-scope inline functions with
// width-independent NAMES. Including it three times with different RVV_HOST_CHUNK_BITS in one
// binary is an ODR violation: three different definitions of dbt::rv32::chunk_add. Keeping the
// kernels here, with width-suffixed extern "C" symbols and everything else in an anonymous
// namespace, makes each TU's internals private and the ODR question disappear.
//
// The obligations are unchanged and are the same ones already measured: the canonicalising select
// after every FP result (F1), no chunk crossing vl because the caller passes only the active
// extent, and the caller's admission test unchanged. A byte range is processed and the number of
// bytes consumed is returned; the caller finishes the residue.

#ifndef RVVRUN_W
#error "RVVRUN_W must be 16, 32 or 64 (bytes)"
#endif

#include <cstdint>
#include <immintrin.h>

#define RVVRUN_CAT2(a, b) a##b
#define RVVRUN_CAT(a, b) RVVRUN_CAT2(a, b)
// The exported symbol suffix is a separate knob from the width, because CAPABILITY is not a
// function of width. FMA3 provides VEX-encoded 128-bit forms whenever AVX + FMA + the OS XCR0
// state are present; it does not require AVX2. A 16-byte TU built for SSE2 alone therefore has no
// FMA, but a second 16-byte TU built with -mavx -mfma does -- and without it the cascade would
// drop every short-extent FMA back to the element path, preserving exactly the regressions it
// exists to remove.
#ifndef RVVRUN_TAG
#define RVVRUN_TAG RVVRUN_W
#endif
#define RVVRUN(name) RVVRUN_CAT(RVVRUN_CAT(rvv_run_, name), RVVRUN_TAG)

// A/B switch for the chunk-dispatch hoist below. Defined once in rv32_vector_run_flags.cpp and
// set from --rvv-run-hoist at startup; declared here because this file is included once per host
// width. Default is the ORIGINAL path so the flag has to be asked for explicitly.
extern "C" unsigned rvv_run_hoist;

// P14 G7: process TWO host chunks per loop iteration, straight-line, when the run is long enough.
//
// Measured motivation. Fixed-work VLEN512->1024 on linpack is 1.154 with the FP-bracket feature
// on; over the same step host instructions fall 23 % (459.4M -> 355.2M) but cycles fall only 13 %
// (132.7 -> 115.0 Mcyc), i.e. IPC is WORSE at the wider VLEN. At VLEN=1024 each guest vector
// instruction covers two 64-byte host chunks instead of one, so the chunk loop runs twice and the
// two chunks are separated by a loop back-edge. The native control (docs/T1_VALIDATED_CONTROL.md)
// measured exactly this shape: two chunks issued straight-line reach 2.00 of the single-chunk
// throughput, because the second chunk's independent chain fits in the first's latency shadow.
//
// This emits the two chunks back to back with no branch between them. It changes only the ORDER
// in which independent chunks issue, never the arithmetic, so results must be bit-identical --
// which is what --rvv-run-unroll2 exists to check.
extern "C" unsigned rvv_run_unroll2;

namespace
{
using u32_ = uint32_t;
using u64_ = uint64_t;

#if RVVRUN_W == 16
using iv = __m128i;
using fv = __m128;
using dv = __m128d;
static inline iv iload(void const *p) { return _mm_loadu_si128((__m128i const *)p); }
static inline void istore(void *p, iv v) { _mm_storeu_si128((__m128i *)p, v); }
static inline fv fload(void const *p) { return _mm_loadu_ps((float const *)p); }
static inline void fstore(void *p, fv v) { _mm_storeu_ps((float *)p, v); }
static inline dv dload(void const *p) { return _mm_loadu_pd((double const *)p); }
static inline void dstore(void *p, dv v) { _mm_storeu_pd((double *)p, v); }
static inline iv iadd(iv a, iv b, u32_ s)
{
	return s == 1 ? _mm_add_epi8(a, b) : s == 2 ? _mm_add_epi16(a, b)
			: s == 4                    ? _mm_add_epi32(a, b)
						    : _mm_add_epi64(a, b);
}
static inline iv isub(iv a, iv b, u32_ s)
{
	return s == 1 ? _mm_sub_epi8(a, b) : s == 2 ? _mm_sub_epi16(a, b)
			: s == 4                    ? _mm_sub_epi32(a, b)
						    : _mm_sub_epi64(a, b);
}
// M3: packed low-half integer multiply. Only SEW 2 and 4 have a direct form; SEW 1 and 8 are
// refused by ialu_class_supported so this is never reached for them.
// SEW=4 needs a 32-bit packed low multiply, which is SSE4.1. This TU is the SSE2 baseline, so it
// supports SEW=2 only and reports the failure; the AVX-carrying TUs below handle both widths.
static inline bool imul_ok(u32_ s) { return s == 2; }
static inline iv imul(iv a, iv b, u32_ s) { (void)s; return _mm_mullo_epi16(a, b); }
static inline iv iand(iv a, iv b) { return _mm_and_si128(a, b); }
static inline iv ior(iv a, iv b) { return _mm_or_si128(a, b); }
static inline iv ixor(iv a, iv b) { return _mm_xor_si128(a, b); }
static inline iv isplat(uint64_t v, u32_ s)
{
	return s == 1 ? _mm_set1_epi8((char)v) : s == 2 ? _mm_set1_epi16((short)v)
			: s == 4                        ? _mm_set1_epi32((int)v)
							: _mm_set1_epi64x((long long)v);
}
static inline fv fsplat(float v) { return _mm_set1_ps(v); }
static inline dv dsplat(double v) { return _mm_set1_pd(v); }
static inline fv fadd(fv a, fv b) { return _mm_add_ps(a, b); }
static inline fv fsub(fv a, fv b) { return _mm_sub_ps(a, b); }
static inline fv fmul(fv a, fv b) { return _mm_mul_ps(a, b); }
static inline fv fdiv(fv a, fv b) { return _mm_div_ps(a, b); }
static inline fv fcanon(fv r)
{
	fv const m = _mm_cmpunord_ps(r, r);
	fv const c = _mm_castsi128_ps(_mm_set1_epi32((int)0x7fc00000u));
	return _mm_or_ps(_mm_and_ps(m, c), _mm_andnot_ps(m, r));
}
static inline dv dadd(dv a, dv b) { return _mm_add_pd(a, b); }
static inline dv dsub(dv a, dv b) { return _mm_sub_pd(a, b); }
static inline dv dmul(dv a, dv b) { return _mm_mul_pd(a, b); }
static inline dv ddiv(dv a, dv b) { return _mm_div_pd(a, b); }
static inline dv dcanon(dv r)
{
	dv const m = _mm_cmpunord_pd(r, r);
	dv const c = _mm_castsi128_pd(_mm_set1_epi64x((long long)0x7ff8000000000000ull));
	return _mm_or_pd(_mm_and_pd(m, c), _mm_andnot_pd(m, r));
}
#if defined(__FMA__)
static inline fv ffma(fv a, fv b, fv c) { return _mm_fmadd_ps(a, b, c); }
static inline dv dfma(dv a, dv b, dv c) { return _mm_fmadd_pd(a, b, c); }
static inline fv fneg(fv a)
{
	return _mm_xor_ps(a, _mm_castsi128_ps(_mm_set1_epi32((int)0x80000000u)));
}
static inline dv dneg(dv a)
{
	return _mm_xor_pd(a, _mm_castsi128_pd(_mm_set1_epi64x((long long)0x8000000000000000ull)));
}
#endif
#define RVVRUN_HAVE_FMA_W 0

#elif RVVRUN_W == 32
using iv = __m256i;
using fv = __m256;
using dv = __m256d;
static inline iv iload(void const *p) { return _mm256_loadu_si256((__m256i const *)p); }
static inline void istore(void *p, iv v) { _mm256_storeu_si256((__m256i *)p, v); }
static inline fv fload(void const *p) { return _mm256_loadu_ps((float const *)p); }
static inline void fstore(void *p, fv v) { _mm256_storeu_ps((float *)p, v); }
static inline dv dload(void const *p) { return _mm256_loadu_pd((double const *)p); }
static inline void dstore(void *p, dv v) { _mm256_storeu_pd((double *)p, v); }
static inline iv iadd(iv a, iv b, u32_ s)
{
	return s == 1 ? _mm256_add_epi8(a, b) : s == 2 ? _mm256_add_epi16(a, b)
			: s == 4                       ? _mm256_add_epi32(a, b)
						       : _mm256_add_epi64(a, b);
}
static inline iv isub(iv a, iv b, u32_ s)
{
	return s == 1 ? _mm256_sub_epi8(a, b) : s == 2 ? _mm256_sub_epi16(a, b)
			: s == 4                       ? _mm256_sub_epi32(a, b)
						       : _mm256_sub_epi64(a, b);
}
// M3: packed low-half integer multiply. Only SEW 2 and 4 have a direct form; SEW 1 and 8 are
// refused by ialu_class_supported so this is never reached for them.
static inline bool imul_ok(u32_ s) { return s == 2 || s == 4; }
static inline iv imul(iv a, iv b, u32_ s) { return s == 2 ? _mm256_mullo_epi16(a, b) : _mm256_mullo_epi32(a, b); }
static inline iv iand(iv a, iv b) { return _mm256_and_si256(a, b); }
static inline iv ior(iv a, iv b) { return _mm256_or_si256(a, b); }
static inline iv ixor(iv a, iv b) { return _mm256_xor_si256(a, b); }
static inline iv isplat(uint64_t v, u32_ s)
{
	return s == 1 ? _mm256_set1_epi8((char)v) : s == 2 ? _mm256_set1_epi16((short)v)
			: s == 4                           ? _mm256_set1_epi32((int)v)
							   : _mm256_set1_epi64x((long long)v);
}
static inline fv fsplat(float v) { return _mm256_set1_ps(v); }
static inline dv dsplat(double v) { return _mm256_set1_pd(v); }
static inline fv fadd(fv a, fv b) { return _mm256_add_ps(a, b); }
static inline fv fsub(fv a, fv b) { return _mm256_sub_ps(a, b); }
static inline fv fmul(fv a, fv b) { return _mm256_mul_ps(a, b); }
static inline fv fdiv(fv a, fv b) { return _mm256_div_ps(a, b); }
static inline fv fcanon(fv r)
{
	fv const m = _mm256_cmp_ps(r, r, _CMP_UNORD_Q);
	fv const c = _mm256_castsi256_ps(_mm256_set1_epi32((int)0x7fc00000u));
	return _mm256_blendv_ps(r, c, m);
}
static inline dv dadd(dv a, dv b) { return _mm256_add_pd(a, b); }
static inline dv dsub(dv a, dv b) { return _mm256_sub_pd(a, b); }
static inline dv dmul(dv a, dv b) { return _mm256_mul_pd(a, b); }
static inline dv ddiv(dv a, dv b) { return _mm256_div_pd(a, b); }
static inline dv dcanon(dv r)
{
	dv const m = _mm256_cmp_pd(r, r, _CMP_UNORD_Q);
	dv const c = _mm256_castsi256_pd(_mm256_set1_epi64x((long long)0x7ff8000000000000ull));
	return _mm256_blendv_pd(r, c, m);
}
static inline fv ffma(fv a, fv b, fv c) { return _mm256_fmadd_ps(a, b, c); }
static inline dv dfma(dv a, dv b, dv c) { return _mm256_fmadd_pd(a, b, c); }
static inline fv fneg(fv a)
{
	return _mm256_xor_ps(a, _mm256_castsi256_ps(_mm256_set1_epi32((int)0x80000000u)));
}
static inline dv dneg(dv a)
{
	return _mm256_xor_pd(a,
			     _mm256_castsi256_pd(_mm256_set1_epi64x((long long)0x8000000000000000ull)));
}
#define RVVRUN_HAVE_FMA_W 1

#elif RVVRUN_W == 64
using iv = __m512i;
using fv = __m512;
using dv = __m512d;
static inline iv iload(void const *p) { return _mm512_loadu_si512(p); }
static inline void istore(void *p, iv v) { _mm512_storeu_si512(p, v); }
static inline fv fload(void const *p) { return _mm512_loadu_ps((float const *)p); }
static inline void fstore(void *p, fv v) { _mm512_storeu_ps((float *)p, v); }
static inline dv dload(void const *p) { return _mm512_loadu_pd((double const *)p); }
static inline void dstore(void *p, dv v) { _mm512_storeu_pd((double *)p, v); }
static inline iv iadd(iv a, iv b, u32_ s)
{
	return s == 1 ? _mm512_add_epi8(a, b) : s == 2 ? _mm512_add_epi16(a, b)
			: s == 4                       ? _mm512_add_epi32(a, b)
						       : _mm512_add_epi64(a, b);
}
static inline iv isub(iv a, iv b, u32_ s)
{
	return s == 1 ? _mm512_sub_epi8(a, b) : s == 2 ? _mm512_sub_epi16(a, b)
			: s == 4                       ? _mm512_sub_epi32(a, b)
						       : _mm512_sub_epi64(a, b);
}
// M3: packed low-half integer multiply. Only SEW 2 and 4 have a direct form; SEW 1 and 8 are
// refused by ialu_class_supported so this is never reached for them.
static inline bool imul_ok(u32_ s) { return s == 2 || s == 4; }
static inline iv imul(iv a, iv b, u32_ s) { return s == 2 ? _mm512_mullo_epi16(a, b) : _mm512_mullo_epi32(a, b); }
static inline iv iand(iv a, iv b) { return _mm512_and_si512(a, b); }
static inline iv ior(iv a, iv b) { return _mm512_or_si512(a, b); }
static inline iv ixor(iv a, iv b) { return _mm512_xor_si512(a, b); }
static inline iv isplat(uint64_t v, u32_ s)
{
	return s == 1 ? _mm512_set1_epi8((char)v) : s == 2 ? _mm512_set1_epi16((short)v)
			: s == 4                           ? _mm512_set1_epi32((int)v)
							   : _mm512_set1_epi64((long long)v);
}
static inline fv fsplat(float v) { return _mm512_set1_ps(v); }
static inline dv dsplat(double v) { return _mm512_set1_pd(v); }
static inline fv fadd(fv a, fv b) { return _mm512_add_ps(a, b); }
static inline fv fsub(fv a, fv b) { return _mm512_sub_ps(a, b); }
static inline fv fmul(fv a, fv b) { return _mm512_mul_ps(a, b); }
static inline fv fdiv(fv a, fv b) { return _mm512_div_ps(a, b); }
static inline fv fcanon(fv r)
{
	__mmask16 const m = _mm512_cmp_ps_mask(r, r, _CMP_UNORD_Q);
	fv const c = _mm512_castsi512_ps(_mm512_set1_epi32((int)0x7fc00000u));
	return _mm512_mask_blend_ps(m, r, c);
}
static inline dv dadd(dv a, dv b) { return _mm512_add_pd(a, b); }
static inline dv dsub(dv a, dv b) { return _mm512_sub_pd(a, b); }
static inline dv dmul(dv a, dv b) { return _mm512_mul_pd(a, b); }
static inline dv ddiv(dv a, dv b) { return _mm512_div_pd(a, b); }
static inline dv dcanon(dv r)
{
	__mmask8 const m = _mm512_cmp_pd_mask(r, r, _CMP_UNORD_Q);
	dv const c = _mm512_castsi512_pd(_mm512_set1_epi64((long long)0x7ff8000000000000ull));
	return _mm512_mask_blend_pd(m, r, c);
}
static inline fv ffma(fv a, fv b, fv c) { return _mm512_fmadd_ps(a, b, c); }
static inline dv dfma(dv a, dv b, dv c) { return _mm512_fmadd_pd(a, b, c); }
static inline fv fneg(fv a)
{
	return _mm512_castsi512_ps(
	    _mm512_xor_si512(_mm512_castps_si512(a), _mm512_set1_epi32((int)0x80000000u)));
}
static inline dv dneg(dv a)
{
	return _mm512_castsi512_pd(_mm512_xor_si512(_mm512_castpd_si512(a),
						    _mm512_set1_epi64((long long)0x8000000000000000ull)));
}
#define RVVRUN_HAVE_FMA_W 1
#else
#error "RVVRUN_W must be 16, 32 or 64"
#endif
} // namespace

// funct6 values, duplicated here rather than pulled from rv32_vector_lower.h so this file stays
// self-contained. They are architectural constants; the static_asserts in the dispatcher check
// them against the canonical definitions.
enum : uint32_t {
	RR_VADD = 0b000000,
	RR_VSUB = 0b000010,
	RR_VAND = 0b001001,
	RR_VOR = 0b001010,
	RR_VXOR = 0b001011,
	RR_VMUL = 0b100101,
	RR_VFADD = 0b000000,
	RR_VFSUB = 0b000010,
	RR_VFMUL = 0b100100,
	RR_VFDIV = 0b100000,
};

// Integer element-wise over a byte run. Returns bytes consumed.
// P14 chunk-dispatch hoist. Measured motivation (docs/T3_TRANSFER_GAP.md): with the opcode
// `switch` inside the per-chunk loop, every chunk pays a dispatch and a branch and the loop
// back-edge serialises chunk n against chunk n+1. Fixed-work VLEN512->1024 on real workloads
// delivers 0.81-1.09 where the same shape measured natively as a straight-line two-chunk sequence
// reaches 1.98, and doubling VLEN removes only ~10% of host instructions.
//
// The hoist runs the SAME arithmetic; it only moves the opcode decision out of the loop so each
// specialised loop body is straight-line. This is not a change in what is computed, so the two
// paths must be bit-identical -- which is what the A/B flag is for.
#define RVVRUN_IALU_BODY(OPEXPR)                                                                   \
	for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {                                         \
		iv const x = iload((char const *)a + off), y = iload((char const *)b + off);       \
		istore((char *)d + off, (OPEXPR));                                                 \
	}

extern "C" uint32_t RVVRUN(ialu)(void *d, void const *a, void const *b, uint32_t bytes,
				 uint32_t f6, uint32_t sew)
{
	uint32_t off = 0;
	if (rvv_run_hoist) {
		switch (f6) {
		case RR_VADD:
			RVVRUN_IALU_BODY(iadd(x, y, sew));
			break;
		case RR_VSUB:
			RVVRUN_IALU_BODY(isub(x, y, sew));
			break;
		case RR_VAND:
			RVVRUN_IALU_BODY(iand(x, y));
			break;
		case RR_VOR:
			RVVRUN_IALU_BODY(ior(x, y));
			break;
		case RR_VXOR:
			RVVRUN_IALU_BODY(ixor(x, y));
			break;
		case RR_VMUL:
			if (!imul_ok(sew))
				return 0; // this width needs a wider TU; caller falls back
			RVVRUN_IALU_BODY(imul(x, y, sew));
			break;
		default:
			// REFUSE rather than fall through to xor. The previous `default: ixor`
			// silently computed the wrong operation for any f6 admitted upstream but
			// not cased here -- a latent trap that admitting VMUL would have sprung.
			return 0;
		}
		return off;
	}
	for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
		iv const x = iload((char const *)a + off), y = iload((char const *)b + off);
		iv z;
		switch (f6) {
		case RR_VADD:
			z = iadd(x, y, sew);
			break;
		case RR_VSUB:
			z = isub(x, y, sew);
			break;
		case RR_VAND:
			z = iand(x, y);
			break;
		case RR_VOR:
			z = ior(x, y);
			break;
		case RR_VXOR:
			z = ixor(x, y);
			break;
		case RR_VMUL:
			if (!imul_ok(sew))
				return off; // width needs a wider TU; commit what is done
			z = imul(x, y, sew);
			break;
		default:
			// Same trap as the hoisted arm: an unhandled opcode must NOT silently
			// become xor. Stop here and let the caller use the reference path.
			return off;
		}
		istore((char *)d + off, z);
	}
	return off;
}

// FP element-wise add/sub/mul/div, with the canonicalising select that makes the packed result
// equal the element-wise reference.
extern "C" uint32_t RVVRUN(falu)(void *d, void const *a, void const *b, uint32_t bytes,
				 uint32_t f6, uint32_t sew)
{
	uint32_t off = 0;
	if (sew == 4) {
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			fv const x = fload((char const *)a + off), y = fload((char const *)b + off);
			fv r;
			switch (f6) {
			case RR_VFADD:
				r = fadd(x, y);
				break;
			case RR_VFSUB:
				r = fsub(x, y);
				break;
			case RR_VFMUL:
				r = fmul(x, y);
				break;
			default:
				r = fdiv(x, y);
				break;
			}
			fstore((char *)d + off, fcanon(r));
		}
	} else {
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			dv const x = dload((char const *)a + off), y = dload((char const *)b + off);
			dv r;
			switch (f6) {
			case RR_VFADD:
				r = dadd(x, y);
				break;
			case RR_VFSUB:
				r = dsub(x, y);
				break;
			case RR_VFMUL:
				r = dmul(x, y);
				break;
			default:
				r = ddiv(x, y);
				break;
			}
			dstore((char *)d + off, dcanon(r));
		}
	}
	return off;
}

// FMA is compiled in whenever the TU's flags provide it, at ANY width.
#if defined(__FMA__)
// The eight RVV fused forms. `d` is read as well as written; `neg` is an exact bit operation.
extern "C" uint32_t RVVRUN(fma)(void *d, void const *a, void const *b, uint32_t bytes, uint32_t f6,
				uint32_t sew)
{
	uint32_t off = 0;
	// funct6 values of the eight forms, in the order rvv_ref::vfma uses them.
	enum : uint32_t {
		MACC = 0b101100,
		NMACC = 0b101101,
		MSAC = 0b101110,
		NMSAC = 0b101111,
		MADD = 0b101000,
		NMADD = 0b101001,
		MSUB = 0b101010,
		NMSUB = 0b101011
	};
#define RVVRUN_FMA_ONE(LD, ST, VT, FMA, NEG, CANON, OFF)                                           \
	{                                                                                          \
		VT const A = LD((char const *)a + (OFF));                                          \
		VT const B = LD((char const *)b + (OFF));                                          \
		VT const D = LD((char *)d + (OFF));                                                \
		VT r;                                                                              \
		switch (f6) {                                                                      \
		case MACC: r = FMA(B, A, D); break;                                                \
		case NMACC: r = FMA(NEG(B), A, NEG(D)); break;                                     \
		case MSAC: r = FMA(B, A, NEG(D)); break;                                           \
		case NMSAC: r = FMA(NEG(B), A, D); break;                                          \
		case MADD: r = FMA(D, B, A); break;                                                \
		case NMADD: r = FMA(NEG(D), B, NEG(A)); break;                                     \
		case MSUB: r = FMA(D, B, NEG(A)); break;                                           \
		default: r = FMA(NEG(D), B, A); break;                                             \
		}                                                                                  \
		ST((char *)d + (OFF), CANON(r));                                                   \
	}
	if (sew == 4 && rvv_run_unroll2) {
		// two chunks per iteration, straight-line, then the odd chunk if any
		for (; off + 2 * RVVRUN_W <= bytes; off += 2 * RVVRUN_W) {
			RVVRUN_FMA_ONE(fload, fstore, fv, ffma, fneg, fcanon, off)
			RVVRUN_FMA_ONE(fload, fstore, fv, ffma, fneg, fcanon, off + RVVRUN_W)
		}
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W)
			RVVRUN_FMA_ONE(fload, fstore, fv, ffma, fneg, fcanon, off)
		return off;
	}
	if (sew == 4) {
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			fv const A = fload((char const *)a + off);
			fv const B = fload((char const *)b + off);
			fv const D = fload((char *)d + off);
			fv r;
			switch (f6) {
			case MACC: r = ffma(B, A, D); break;
			case NMACC: r = ffma(fneg(B), A, fneg(D)); break;
			case MSAC: r = ffma(B, A, fneg(D)); break;
			case NMSAC: r = ffma(fneg(B), A, D); break;
			case MADD: r = ffma(D, B, A); break;
			case NMADD: r = ffma(fneg(D), B, fneg(A)); break;
			case MSUB: r = ffma(D, B, fneg(A)); break;
			default: r = ffma(fneg(D), B, A); break;
			}
			fstore((char *)d + off, fcanon(r));
		}
	} else if (rvv_run_unroll2) {
		// Same two-chunk straight-line emission for SEW=64. pb_gemm/pb_syrk/linpack are all
		// double precision, so omitting this branch would leave the prototype untested on
		// exactly the FMA-heavy workloads it targets.
		for (; off + 2 * RVVRUN_W <= bytes; off += 2 * RVVRUN_W) {
			RVVRUN_FMA_ONE(dload, dstore, dv, dfma, dneg, dcanon, off)
			RVVRUN_FMA_ONE(dload, dstore, dv, dfma, dneg, dcanon, off + RVVRUN_W)
		}
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W)
			RVVRUN_FMA_ONE(dload, dstore, dv, dfma, dneg, dcanon, off)
		return off;
	} else {
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			dv const A = dload((char const *)a + off);
			dv const B = dload((char const *)b + off);
			dv const D = dload((char *)d + off);
			dv r;
			switch (f6) {
			case MACC: r = dfma(B, A, D); break;
			case NMACC: r = dfma(dneg(B), A, dneg(D)); break;
			case MSAC: r = dfma(B, A, dneg(D)); break;
			case NMSAC: r = dfma(dneg(B), A, D); break;
			case MADD: r = dfma(D, B, A); break;
			case NMADD: r = dfma(dneg(D), B, dneg(A)); break;
			case MSUB: r = dfma(D, B, dneg(A)); break;
			default: r = dfma(dneg(D), B, A); break;
			}
			dstore((char *)d + off, dcanon(r));
		}
	}
	return off;
}
#endif

// ---------------------------------------------------------------------------------------------
// Splat forms. The scalar arrives as raw bits and is broadcast ONCE, outside the chunk loop, so
// the class-wide interface costs one broadcast per operation rather than a materialised vector
// buffer per tier width. `.vx`, `.vi` and `.vf` differ only in where the caller obtained those
// bits, which is why they share one entry point per class -- the same reason they were never
// separate fast paths in the first place.
// ---------------------------------------------------------------------------------------------
extern "C" uint32_t RVVRUN(ialu_vs)(void *d, void const *a, uint64_t sval, uint32_t bytes,
				    uint32_t f6, uint32_t sew)
{
	iv const k = isplat(sval, sew);
	uint32_t off = 0;
	for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
		iv const x = iload((char const *)a + off);
		iv z;
		switch (f6) {
		case RR_VADD: z = iadd(x, k, sew); break;
		case RR_VSUB: z = isub(x, k, sew); break;
		case RR_VAND: z = iand(x, k); break;
		case RR_VOR: z = ior(x, k); break;
		default: z = ixor(x, k); break;
		}
		istore((char *)d + off, z);
	}
	return off;
}

extern "C" uint32_t RVVRUN(falu_vs)(void *d, void const *a, uint64_t sbits, uint32_t bytes,
				    uint32_t f6, uint32_t sew)
{
	uint32_t off = 0;
	if (sew == 4) {
		float sf;
		uint32_t const b32 = (uint32_t)sbits;
		__builtin_memcpy(&sf, &b32, 4);
		fv const k = fsplat(sf);
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			fv const x = fload((char const *)a + off);
			fv r;
			switch (f6) {
			case RR_VFADD: r = fadd(x, k); break;
			case RR_VFSUB: r = fsub(x, k); break;
			case RR_VFMUL: r = fmul(x, k); break;
			default: r = fdiv(x, k); break;
			}
			fstore((char *)d + off, fcanon(r));
		}
	} else {
		double sd;
		__builtin_memcpy(&sd, &sbits, 8);
		dv const k = dsplat(sd);
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			dv const x = dload((char const *)a + off);
			dv r;
			switch (f6) {
			case RR_VFADD: r = dadd(x, k); break;
			case RR_VFSUB: r = dsub(x, k); break;
			case RR_VFMUL: r = dmul(x, k); break;
			default: r = ddiv(x, k); break;
			}
			dstore((char *)d + off, dcanon(r));
		}
	}
	return off;
}

#if defined(__FMA__)
extern "C" uint32_t RVVRUN(fma_vs)(void *d, void const *a, uint64_t sbits, uint32_t bytes,
				   uint32_t f6, uint32_t sew)
{
	enum : uint32_t {
		MACC = 0b101100, NMACC = 0b101101, MSAC = 0b101110, NMSAC = 0b101111,
		MADD = 0b101000, NMADD = 0b101001, MSUB = 0b101010, NMSUB = 0b101011
	};
	uint32_t off = 0;
	if (sew == 4) {
		float sf;
		uint32_t const b32 = (uint32_t)sbits;
		__builtin_memcpy(&sf, &b32, 4);
		fv const B = fsplat(sf);
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			fv const A = fload((char const *)a + off);
			fv const D = fload((char *)d + off);
			fv r;
			switch (f6) {
			case MACC: r = ffma(B, A, D); break;
			case NMACC: r = ffma(fneg(B), A, fneg(D)); break;
			case MSAC: r = ffma(B, A, fneg(D)); break;
			case NMSAC: r = ffma(fneg(B), A, D); break;
			case MADD: r = ffma(D, B, A); break;
			case NMADD: r = ffma(fneg(D), B, fneg(A)); break;
			case MSUB: r = ffma(D, B, fneg(A)); break;
			default: r = ffma(fneg(D), B, A); break;
			}
			fstore((char *)d + off, fcanon(r));
		}
	} else {
		double sd;
		__builtin_memcpy(&sd, &sbits, 8);
		dv const B = dsplat(sd);
		for (; off + RVVRUN_W <= bytes; off += RVVRUN_W) {
			dv const A = dload((char const *)a + off);
			dv const D = dload((char *)d + off);
			dv r;
			switch (f6) {
			case MACC: r = dfma(B, A, D); break;
			case NMACC: r = dfma(dneg(B), A, dneg(D)); break;
			case MSAC: r = dfma(B, A, dneg(D)); break;
			case NMSAC: r = dfma(dneg(B), A, D); break;
			case MADD: r = dfma(D, B, A); break;
			case NMADD: r = dfma(dneg(D), B, dneg(A)); break;
			case MSUB: r = dfma(D, B, dneg(A)); break;
			default: r = dfma(dneg(D), B, A); break;
			}
			dstore((char *)d + off, dcanon(r));
		}
	}
	return off;
}
#endif
