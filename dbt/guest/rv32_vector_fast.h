#pragma once

// Semantic-class chunk lowering with discharged obligations (P13 phase C).
//
// WHY THIS SHAPE, AND NOT THE OBVIOUS ONE
// ---------------------------------------
// P12 built a fixed-width path admitted by OPCODE IDENTITY -- unit-stride load/store and integer
// vadd.vv -- and measured `chunk_ops = 0` on every real workload: the compiler emits something
// else, so the path is never entered. A2 then measured where the cost actually is: 88 % of
// dynamic vector cycles sit in semantic classes (FP arithmetic, FP convert, reduction, memory,
// mask generation, whole-register move) for which the strongest available baseline, QEMU's TCG
// gvec, has no host-SIMD form at all -- it covers 32 mnemonics, all integer. Meanwhile the
// scalable-vector SHAPE is already what a fixed-width path wants: unmasked and vl == VLMAX for
// 88 % of cycles (equal-weighted; 75 % volume-weighted).
//
// So the admission test here is not "is this one of the opcodes we implemented". It is: has every
// architectural obligation of this SEMANTIC CLASS been discharged for this instance? Those
// obligations were enumerated and measured before this file was written --
// docs/B1_SEMANTIC_OBLIGATIONS.md, raw/b0/FP_SEMANTIC_MATRIX.txt.
//
// THE TWO STRUCTURAL DECISIONS
//
// 1. The architectural extent, not the register group, is what gets chunked.
//    Elements [0, vl) occupy, in each register of the group, a CONTIGUOUS byte range starting at
//    offset 0. Covering that range with as many host chunks as fit -- and finishing the residue
//    element-wise -- handles a partial `vl` with the same code as a full one. Chunking whole
//    registers instead would have excluded exactly the two most expensive kernels in the corpus
//    (`tsvc_s112`, `s1112`, which run at vl = 4 for 99.8 % of their cycles).
//    A consequence worth stating: because the fast path never touches a byte at or beyond `vl`,
//    the tail-policy obligation is discharged by construction -- no masked store, and the
//    reference's agnostic-lane behaviour is reproduced bit-for-bit rather than the spec's
//    freedom being exploited (which `--rvv-verify`, a bit comparison, would report as a
//    divergence).
//
// 2. Floating point needs no value predicate.
//    RISC-V canonicalises any NaN an operation produces; x86 propagates a source payload and
//    emits its own sign-set default. That is a lane-wise select, so `packed op` followed by
//    `select(isnan(r), canonical, r)` is bit-identical to the reference in value AND in fflags --
//    measured 256/256 over 16 corner-case operand pairs x {add,sub,mul,div} x 4 rounding modes.
//    There is therefore no speculation, no data-dependent branch, and no flag rollback problem.
//
// WHAT IS DELIBERATELY NOT HERE
//    vfmin/vfmax (minps raises invalid on a QUIET NaN, RISC-V's fmin does not -- 24/384 measured
//    divergences), ordered FP reductions (`vfredosum` is defined as a strict left fold),
//    frm == RMM (no x86 encoding), masked instances (an unmasked packed op would raise exceptions
//    for lanes the architecture never executes), and vstart != 0.

#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_cascade.h"
#include "dbt/guest/rv32_vector_lower.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace dbt::rv32::rvv_fast
{

// ---------------------------------------------------------------------------------------------
// Counters. Separate from g_rvv_stats so the ablation can tell "the fast path ran" from "the old
// P12 chunk path ran", which P12's own counters could not.
// ---------------------------------------------------------------------------------------------
// Research counters. They are ONE INCREMENT PER HOST CHUNK, and the method-off arm never pays
// them -- a corpus gate executed 13.77 billion chunks, so leaving them in a timing binary would
// have meant the measured arm carried billions of updates the control did not. `--rvv-stats` only
// controls PRINTING, not collection, so a runtime flag cannot fix this either.
//
// RVDBT_FAST_STATS=0 removes them entirely: `if constexpr (kFastStats)` deletes the code, so
// there is not even a branch. Performance binaries are built with 0 and cannot report admission;
// coverage and mechanism accounting use a separate instrumented binary built with 1.
#ifndef RVDBT_FAST_STATS
#define RVDBT_FAST_STATS 1
#endif
static constexpr bool kFastStats = RVDBT_FAST_STATS != 0;

struct FastStats {
	unsigned long long ops_admitted;  // vector instructions that took the class fast path
	unsigned long long ops_refused;	  // ... that failed an obligation and used the reference
	unsigned long long chunks;	  // host chunk operations executed
	unsigned long long residue_elems; // elements finished element-wise below one chunk
	unsigned long long refuse_shape;  // refused: masked / vstart / vill
	unsigned long long refuse_class;  // refused: no kernel for this (op, SEW)
	unsigned long long refuse_frm;	  // refused: rounding mode has no host encoding
	// P13 B3-narrow (docs/P3_B3_NARROW_PROTOTYPE_DESIGN.md): how many admitted falu/fma/vfcmp
	// calls handed their FRound bracket to the immediately-following eligible instruction
	// instead of closing it -- i.e. real dynamic evidence the mechanism fired, not just that it
	// compiled. `fround_run_continued + (calls that closed their own bracket) == ops_admitted`
	// for these three classes.
	unsigned long long fround_run_continued;
	// Codex 4th review P1 (scenario d): how many times `Interpreter::ExecuteBlock` exited its
	// translation block (instruction-count cap, page-crossing, or a branch) with a rounding run
	// still open -- i.e. the immediately-preceding instruction predicted a same-block
	// continuation, but the block ended before that continuation was dispatched. Not itself
	// evidence of a bug: the TB-exit safety net (same file, `Interpreter::ExecuteBlock`) always
	// force-closes before returning, so this counter's ONLY purpose is to make the frequency of
	// this edge case observable instead of silently invisible. Zero across a whole corpus run
	// would mean this path is dead code on that corpus, which is itself worth knowing.
	unsigned long long fround_run_tb_exit_open;
	// Diagnostic only (2026-08-21 method-candidate audit, not a shipped mechanism): does a
	// call site's admission-decision signature (sew, lmul_log2, vl, vstart, frm -- the full
	// dynamic input set fp_mode/shape_ok/overlap_ok actually read, gip-keyed since f6/vm/vd/
	// vs2/vs1 are fixed by the guest instruction encoding at a given gip and need no runtime
	// check) actually change between consecutive dynamic calls at the same gip? Answers
	// "would a small direct-mapped per-call-site cache mostly hit or mostly miss" with real
	// counts instead of an assumption. `sig_hit`: same gip, same signature as this slot's last
	// occupant. `sig_miss_stale`: same gip, signature changed. `sig_miss_evict`: a DIFFERENT
	// gip currently occupies this call's slot (a capacity conflict of the fixed-size cache,
	// not a signature change) -- kept separate from `sig_miss_stale` because it is an artifact
	// of the cache SIZE, not of the guard's actual call-to-call variability.
	unsigned long long sig_checks;
	unsigned long long sig_hit;
	unsigned long long sig_miss_stale;
	unsigned long long sig_miss_evict;
	// Diagnostic only (2026-08-21 handler-layer cycle, not a shipped mechanism): no existing
	// counter recorded how often `rvv_fusible_pair`'s forward scan is even ATTEMPTED (i.e. the
	// producer op is a candidate at all -- unmasked .vv, `rvv_fuse_pairs` on) versus how often it
	// actually PROVES a legal pair (`FusePlan.ok`), independent of whether the fused kernel then
	// admits it (that is `refuse_class`/`refuse_shape` on the `try_*_fused` path, already
	// counted). Answers "is the scan itself doing much work for little payoff" separately from
	// "is the fused kernel worth having once a pair is found."
	unsigned long long fuse_scan_attempted;
	unsigned long long fuse_scan_found;
	// Handler-layer causal upper bound (2026-08-21 cycle): correctness precondition counter for
	// RVDBT_DIAG_SKIP_HANDLER_LEGALITY (dbt/guest/rv32_interp.cpp, HANDLER(vfalu)). Nonzero means
	// this corpus's dynamic execution WOULD have hit a register-group/mask legality trap that the
	// diagnostic build silently skips -- any timing/correctness result from a run where this is
	// nonzero must be discarded, not interpreted as a performance number.
	unsigned long long handler_legality_would_trap;
};
inline FastStats g_fast{};

// Diagnostic only, see FastStats::sig_hit et al above. A small direct-mapped cache, sized like a
// plausible real inline-cache implementation (not unbounded), so the hit rate this measures is
// what a real cache of this shape would see, not an idealized per-site-with-infinite-slots rate.
struct SigCacheEntry {
	u32 gip;
	u64 sig;
	bool valid;
};
static constexpr u32 kSigCacheSlots = 256;
inline SigCacheEntry g_sig_cache[kSigCacheSlots]{};

ALWAYS_INLINE void sig_cache_probe(u32 gip, u32 sew, i32 lmul_log2, u32 vl, u32 vstart, u32 frm)
{
	if constexpr (!kFastStats)
		return;
	u64 const sig = (u64)sew | ((u64)(u32)lmul_log2 << 8) | ((u64)vl << 16) |
			 ((u64)vstart << 40) | ((u64)frm << 56);
	u32 const idx = gip % kSigCacheSlots;
	SigCacheEntry &e = g_sig_cache[idx];
	g_fast.sig_checks++;
	if (e.valid && e.gip == gip) {
		if (e.sig == sig)
			g_fast.sig_hit++;
		else
			g_fast.sig_miss_stale++;
	} else {
		g_fast.sig_miss_evict++;
	}
	e = {gip, sig, true};
}

static constexpr u32 CB = HOST_CHUNK_BYTES;

ALWAYS_INLINE u32 tail_rounded_bytes(u32 bytes, bool tail_agnostic)
{
	if (!config::rvv_tail_round || !tail_agnostic)
		return bytes;
	return (bytes + (CB - 1)) & ~(CB - 1);
}

// ---------------------------------------------------------------------------------------------
// The extent walk. This is the whole control structure of the method, and it mentions no width
// other than CB and no opcode at all.
//
// `Chunk(dst, a, b)` performs one CB-byte host operation. `Elem(reg_off, i)` performs element `i`
// of register `reg_off` the reference way. Returns nothing; the counters record what happened.
// ---------------------------------------------------------------------------------------------
// Cascade walk for the splat forms. `sval` is the scalar as raw bits: for .vx and .vi it is the
// sign-extended GPR or immediate, for .vf the unboxed F register, exactly as the element path
// obtains them. One entry point per class, because .vx/.vi/.vf are the same semantic class and
// differ only in where the caller found those bits.
template <typename Elem>
ALWAYS_INLINE void walk_extent_cascade_vs(VectorState &vs, u32 vd, u32 a_reg, u32 vlen_bits,
					  u32 vl, u32 eew, u64 sval, u32 f6, u32 sew,
					  int rc, Elem elem)
{
	using namespace rvv_cascade;
	// Use the cached table: rebuilding it per invocation cost ~214 cycles and made the
	// substrate a net loss (docs/M8_SUBSTRATE_IS_A_NET_LOSS.md).
	TierTable const &tt = tiers_cached((Policy)config::rvv_width_policy);
	Tier const *tiers = tt.t;
	u32 const nt = tt.n;
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	// M1, vector-scalar form. Same rule and same legality argument as the VV path.
	bool const ta = VType{vs.vtype}.vta();
	u32 const widest = nt ? tiers[0].bytes : CB;
	u32 done = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 raw_bytes = n * eew;
		u32 bytes = raw_bytes;
		if (config::rvv_tail_round && ta && widest <= VLEN_MAX_BYTES)
			bytes = (raw_bytes + (widest - 1)) & ~(widest - 1);
		u32 const off = run_extent_vs(
		    tiers, nt, &vs.vreg[vd + r][0], &vs.vreg[a_reg + r][0], sval, bytes, f6, sew,
		    [rc](Tier const &t) { return rc == 0 ? t.ialu_vs : rc == 1 ? t.falu_vs : t.fma_vs; });
		#ifdef RVDBT_DIAG_NO_SHIFT
		for (u32 i = off / eew; i < n; i++) {
#else
		for (u32 i = off >> eew_log2; i < n; i++) {
#endif
			elem(r, i);
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
}

// Unrounded entry point, preserved so every existing caller keeps its exact semantics.
template <typename Chunk, typename Elem>
ALWAYS_INLINE void walk_extent(VectorState &vs, u32 vd, u32 a_reg, u32 b_reg, u32 vlen_bits, u32 vl,
			       u32 eew, Chunk chunk, Elem elem)
{
	walk_extent_ta(vs, vd, a_reg, b_reg, vlen_bits, vl, eew, /*tail_agnostic=*/false, chunk, elem);
}

// Which class's run function a tier should supply. Kept as a tiny tag rather than a function
// pointer at the call site so the walk stays one shape for all three classes.
enum class RunClass { IALU, FALU, FMA };

// The cascade variant of the walk. Identical contract to walk_extent: it never emits a chunk that
// crosses `vl`, because each tier is offered only the bytes that remain inside the active extent.
template <typename Elem>
ALWAYS_INLINE void walk_extent_cascade(VectorState &vs, u32 vd, u32 a_reg, u32 b_reg,
				       u32 vlen_bits, u32 vl, u32 eew, u32 f6, u32 sew,
				       RunClass rc, Elem elem)
{
	using namespace rvv_cascade;
	// Use the cached table: rebuilding it per invocation cost ~214 cycles and made the
	// substrate a net loss (docs/M8_SUBSTRATE_IS_A_NET_LOSS.md).
	TierTable const &tt = tiers_cached((Policy)config::rvv_width_policy);
	Tier const *tiers = tt.t;
	u32 const nt = tt.n;
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	// M1: the guest's own tail policy decides whether the surplus lanes of a rounded extent are
	// architecturally meaningful. Read it from vtype rather than threading a parameter through
	// every caller, so the rule cannot be applied where the policy was not actually checked.
	bool const ta = VType{vs.vtype}.vta();
	// Round to the WIDEST tier the cascade can actually execute, not to the compile-time chunk:
	// run_extent skips a tier whose width exceeds the remaining extent, so under a fixed-64 policy
	// an extent of 32 bytes gets NO tier at all and falls entirely to the element loop. Rounding to
	// 16 could never fix that. The rounding target is therefore the tier width, which is the real
	// host granularity here. Bounded by the VLEN_MAX_BYTES register slot, and tiers are <= 64.
	u32 const widest = nt ? tiers[0].bytes : CB;
	u32 done = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 raw_bytes = n * eew;
		u32 bytes = raw_bytes;
		if (config::rvv_tail_round && ta && widest <= VLEN_MAX_BYTES)
			bytes = (raw_bytes + (widest - 1)) & ~(widest - 1);
		u32 const off = run_extent(
		    tiers, nt, &vs.vreg[vd + r][0], &vs.vreg[a_reg + r][0], &vs.vreg[b_reg + r][0],
		    bytes, f6, sew, [rc](Tier const &t) {
			    return rc == RunClass::IALU ? t.ialu
				   : rc == RunClass::FALU ? t.falu
							  : t.fma;
		    });
		#ifdef RVDBT_DIAG_NO_SHIFT
		for (u32 i = off / eew; i < n; i++) {
#else
		for (u32 i = off >> eew_log2; i < n; i++) {
#endif
			elem(r, i);
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
}

// M1: tail-rounded extent. When the architectural tail is AGNOSTIC, RVV permits the destination
// elements in [vl, VLMAX) to be either preserved or overwritten -- the spec says "can either retain
// the value they previously held, or are overwritten with 1s", and the all-1s choice exists
// precisely to stop software depending on the contents. So computing a whole host chunk and letting
// the surplus lanes land in the tail is a CONFORMING outcome, not a tolerated error.
//
// Memory safety is a property of this translator's register file, not of the ISA: every guest
// register occupies a VLEN_MAX_BYTES slot, and round_up(n*eew, CB) <= round_up(vlen_bytes, CB) ==
// vlen_bytes because VLEN >= 128 bits == CB and vlen_bytes is a power of two. So the rounded extent
// never leaves even the CONFIGURED register, let alone the slot. No page is touched that the
// unrounded extent would not already touch.
//
// This applies to register-to-register work only. Callers that touch memory must pass
// tail_agnostic=false: over-reading MEMORY past vl could fault on an unmapped page, which is a side
// effect the guest must not observe, and the agnostic permission covers destination contents only.

template <typename Chunk, typename Elem>
ALWAYS_INLINE void walk_extent_ta(VectorState &vs, u32 vd, u32 a_reg, u32 b_reg, u32 vlen_bits,
				  u32 vl, u32 eew, bool tail_agnostic, Chunk chunk, Elem elem)
{
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	u32 done = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = tail_rounded_bytes(n * eew, tail_agnostic);
		u32 off = 0;
		for (; off + CB <= bytes; off += CB) {
			chunk(&vs.vreg[vd + r][off], &vs.vreg[a_reg + r][off],
			      &vs.vreg[b_reg + r][off]);
			if constexpr (kFastStats)
				g_fast.chunks++;
		}
		#ifdef RVDBT_DIAG_NO_SHIFT
		for (u32 i = off / eew; i < n; i++) {
#else
		for (u32 i = off >> eew_log2; i < n; i++) {
#endif
			elem(r, i);
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
}

// ---------------------------------------------------------------------------------------------
// Class 1: integer element-wise ALU.
//
// No architectural side conditions at all -- integer arithmetic has no flags, no NaN and no
// rounding mode -- so the only obligations are the shape ones, checked by the caller.
// ---------------------------------------------------------------------------------------------
// P15 candidate 7: compute-only form of the switch, so a fused pair can keep its intermediate in a
// host vector register instead of round-tripping it through VectorState. ialu_chunk is expressed
// in terms of it below, so the single-op and fused paths cannot drift apart.
ALWAYS_INLINE bool ialu_chunk_compute(host_chunk_t &z, host_chunk_t a, host_chunk_t b, u32 f6,
				      u32 sew)
{
	switch (f6) {
	case VF6_VADD: z = chunk_add(a, b, sew); return true;
	case VF6_VSUB: z = chunk_sub(a, b, sew); return true;
	case VF6_VAND: z = chunk_and(a, b); return true;
	case VF6_VOR: z = chunk_or(a, b); return true;
	case VF6_VXOR: z = chunk_xor(a, b); return true;
	default: return false;
	}
}

ALWAYS_INLINE bool ialu_chunk(void *d, void const *pa, void const *pb, u32 f6, u32 sew)
{
	host_chunk_t z;
	if (!ialu_chunk_compute(z, chunk_load(pa), chunk_load(pb), f6, sew))
		return false;
	chunk_store(d, z);
	return true;
}

constexpr bool ialu_class_supported(u32 f6, u32 sew_bytes)
{
	if (sew_bytes != 1 && sew_bytes != 2 && sew_bytes != 4 && sew_bytes != 8)
		return false;
	// NOTE: vmul.vv does NOT route here. HANDLER(vimul) calls rvv_ref::vimul directly and never
	// reaches try_ialu, so admitting VF6_VMUL in this predicate is dead code for it. Verified by
	// source; the admission was reverted rather than left as a misleading no-op.
	// SEW=2 only: the shared 128-bit path is SSE2 (hard requirement for the SSE2 fallback) and
	// SSE2 has no 32-bit packed low multiply. Admitting SEW=4 needs the runtime-CPUID
	// NOTE: vmul.vv does NOT route here. HANDLER(vimul) calls rvv_ref::vimul directly and never
	// reaches try_ialu, so admitting VF6_VMUL in this predicate would be dead code for it. That
	// admission was tried and reverted rather than left as a misleading no-op.
	return f6 == VF6_VADD || f6 == VF6_VSUB || f6 == VF6_VAND || f6 == VF6_VOR ||
	       f6 == VF6_VXOR;
}

// The fused pair. `op1` produces an intermediate that `op2` immediately consumes; the caller has
// already proven the intermediate is architecturally unobservable (op1.vd == op2.vd, so it is
// overwritten before any other reader can see it -- see rvv_fusible_pair()). `z1` never reaches
// memory: that single store+load pair per chunk is the whole saving this candidate exists to test.
//
// Integer element-wise ops have no flags, no NaN and no rounding mode, so eliding the intermediate
// cannot change any architectural side effect. That is why the prototype is scoped to this class.
ALWAYS_INLINE bool ialu_chunk_fused(void *d, void const *pa, void const *pb, void const *pc,
				    u32 f6_1, u32 f6_2, bool second_reads_intermediate_first, u32 sew)
{
	host_chunk_t z1;
	if (!ialu_chunk_compute(z1, chunk_load(pa), chunk_load(pb), f6_1, sew))
		return false;
	host_chunk_t const c = chunk_load(pc);
	host_chunk_t z2;
	// op2's operand order matters for the non-commutative VSUB: vd = vd - c vs vd = c - vd.
	bool const ok = second_reads_intermediate_first
			    ? ialu_chunk_compute(z2, z1, c, f6_2, sew)
			    : ialu_chunk_compute(z2, c, z1, f6_2, sew);
	if (!ok)
		return false;
	chunk_store(d, z2);
	return true;
}

// ---------------------------------------------------------------------------------------------
// Class 2: floating-point element-wise arithmetic.
//
// The canonicalising select is applied unconditionally: it is what makes the packed result equal
// the reference, and it costs two fixed instructions rather than a data-dependent branch.
// ---------------------------------------------------------------------------------------------
// Scalar element forms of the four admitted FP ops, so the fused residue path computes exactly
// what try_falu's element lambda computes. Kept next to the chunk kernel so the two cannot drift.
ALWAYS_INLINE float falu_apply_f32(u32 f6, float x, float y)
{
	switch (f6) {
	case VF6_VFADD: return x + y;
	case VF6_VFSUB: return x - y;
	case VF6_VFMUL: return x * y;
	default: return x / y;
	}
}
ALWAYS_INLINE double falu_apply_f64(u32 f6, double x, double y)
{
	switch (f6) {
	case VF6_VFADD: return x + y;
	case VF6_VFSUB: return x - y;
	case VF6_VFMUL: return x * y;
	default: return x / y;
	}
}

// P15 candidate 7, FP class. The fused pair for OPFVV, which is 26.5 % of the corpus where the
// integer class is 1.07 % (raw/FUSE_CLASS_DIAGNOSIS.txt).
//
// Legality, and why FP is not harder than integer here despite appearances:
//   * the intermediate VALUE is dead -- the caller proved op2 overwrites vd;
//   * fflags are NOT elided. They are sticky bits accrued in MXCSR by the host FP unit at the
//     moment the arithmetic executes, and fusion does not change whether it executes, only
//     whether the result reaches VectorState. The union over lanes harvested at the bracket's
//     end is therefore identical;
//   * the ONE real difference is NaN canonicalisation. The unfused path applies
//     fchunk*_canon to op1's result before op2 reads it back, so the fused path must apply it
//     to the intermediate too -- in register. That is done below, so the value op2 consumes is
//     bit-identical to the unfused case.
// Both ops run inside the SAME rounding bracket the unfused pair would have used, because the
// caller holds it open across them; RVV has no way to change frm between two adjacent vector
// instructions without a CSR write, which ends the scan.
template <typename L, typename S, typename C, typename OP>
ALWAYS_INLINE bool falu_fused_w(void *d, void const *pa, void const *pb, void const *pc, u32 f6_1,
				u32 f6_2, bool int_first, L ld, S st, C canon, OP op)
{
	auto r1 = op(ld(pa), ld(pb), f6_1);
	if (!r1.second)
		return false;
	auto const z1 = canon(r1.first); // exactly what the unfused path stores and reloads
	auto const c = ld(pc);
	auto r2 = int_first ? op(z1, c, f6_2) : op(c, z1, f6_2);
	if (!r2.second)
		return false;
	st(d, canon(r2.first));
	return true;
}

ALWAYS_INLINE bool falu_chunk_fused(void *d, void const *pa, void const *pb, void const *pc,
				    u32 f6_1, u32 f6_2, bool int_first, u32 sew)
{
	if (sew == 4) {
		auto op = [](host_fchunk32_t a, host_fchunk32_t b,
			     u32 f6) -> std::pair<host_fchunk32_t, bool> {
			switch (f6) {
			case VF6_VFADD: return {fchunk32_add(a, b), true};
			case VF6_VFSUB: return {fchunk32_sub(a, b), true};
			case VF6_VFMUL: return {fchunk32_mul(a, b), true};
			case VF6_VFDIV: return {fchunk32_div(a, b), true};
			default: return {a, false};
			}
		};
		return falu_fused_w(
		    d, pa, pb, pc, f6_1, f6_2, int_first,
		    [](void const *p) { return fchunk32_load(p); },
		    [](void *p, host_fchunk32_t v) { fchunk32_store(p, v); },
		    [](host_fchunk32_t v) { return fchunk32_canon(v); }, op);
	}
	if (sew == 8) {
		auto op = [](host_fchunk64_t a, host_fchunk64_t b,
			     u32 f6) -> std::pair<host_fchunk64_t, bool> {
			switch (f6) {
			case VF6_VFADD: return {fchunk64_add(a, b), true};
			case VF6_VFSUB: return {fchunk64_sub(a, b), true};
			case VF6_VFMUL: return {fchunk64_mul(a, b), true};
			case VF6_VFDIV: return {fchunk64_div(a, b), true};
			default: return {a, false};
			}
		};
		return falu_fused_w(
		    d, pa, pb, pc, f6_1, f6_2, int_first,
		    [](void const *p) { return fchunk64_load(p); },
		    [](void *p, host_fchunk64_t v) { fchunk64_store(p, v); },
		    [](host_fchunk64_t v) { return fchunk64_canon(v); }, op);
	}
	return false;
}

// M4 causal decomposition, arm A1 (experiments/2026-08-21-0705-rvv-region-residency-legality/
// docs/M4_ORACLE_SEMANTIC_AUDIT.md). DIAGNOSTIC ONLY, INCORRECT BY CONSTRUCTION for the general
// RVV case: skips the per-chunk canonicalising select (`fchunk32_canon`) that RVV's "any NaN a
// FP op PRODUCES is the canonical qNaN" rule requires (dbt/guest/rv32_vector_lower.h:218, this
// file's top-of-file rationale, `B1_SEMANTIC_OBLIGATIONS.md` F1). Bit-identical to the exact path
// ONLY on inputs that provably never produce a NaN result (verified by hash match against the
// exact path on the same finite, NaN-free operand set the causal probe uses -- NOT a general
// correctness claim). Same technique/precedent as `RVDBT_FROUND_DIAG_NOP` and
// `RVDBT_DIAG_SKIP_OBLIGATIONS` elsewhere in this codebase: bounds a component's cost from above,
// never shipped, never a speedup claim.
#ifndef RVDBT_DIAG_NO_CANON
#define RVDBT_DIAG_NO_CANON 0
#endif

ALWAYS_INLINE bool falu_chunk(void *d, void const *pa, void const *pb, u32 f6, u32 sew)
{
	host_chunk_t z;
	if (sew == 4) {
		host_fchunk32_t const a = fchunk32_load(pa), b = fchunk32_load(pb);
		host_fchunk32_t r;
		switch (f6) {
		case VF6_VFADD:
			r = fchunk32_add(a, b);
			break;
		case VF6_VFSUB:
			r = fchunk32_sub(a, b);
			break;
		case VF6_VFMUL:
			r = fchunk32_mul(a, b);
			break;
		case VF6_VFDIV:
			r = fchunk32_div(a, b);
			break;
		default:
			return false;
		}
#if RVDBT_DIAG_NO_CANON
		fchunk32_store(d, r);
#else
		fchunk32_store(d, fchunk32_canon(r));
#endif
		return true;
	}
	if (sew == 8) {
		host_fchunk64_t const a = fchunk64_load(pa), b = fchunk64_load(pb);
		host_fchunk64_t r;
		switch (f6) {
		case VF6_VFADD:
			r = fchunk64_add(a, b);
			break;
		case VF6_VFSUB:
			r = fchunk64_sub(a, b);
			break;
		case VF6_VFMUL:
			r = fchunk64_mul(a, b);
			break;
		case VF6_VFDIV:
			r = fchunk64_div(a, b);
			break;
		default:
			return false;
		}
		fchunk64_store(d, fchunk64_canon(r));
		return true;
	}
	(void)z;
	return false;
}

// ---------------------------------------------------------------------------------------------
// Class 2b: the fused multiply-add family.
//
// This is not a new class and not an opcode patch -- it is the rest of FP element-wise
// arithmetic, discharging exactly the same obligations by exactly the same construction. It is
// separated only because it needs a third operand (vd is read as well as written) and because it
// requires host FMA3: RVV rounds the product-sum ONCE, and emulating that without a hardware FMA
// would need the libm fallback the reference already uses.
//
// The measurement that made this necessary: with add/sub/mul/div alone the implemented method
// covered 17.4 % of corpus vector cycles, while vfmacc.vv and vfmadd.vf alone are 23.7 % of them.
// Leaving the largest members of an admitted class out would have made the coverage number a
// statement about the implementation rather than about the method.
//
// The eight forms are all fma(+/-x, y, +/-z) over operands drawn from {vd, vs1, vs2}; the sign
// flips are exact bit operations. Operand order follows rvv_ref::vfma exactly.
#ifdef __FMA__
template <typename T, typename Ld, typename St, typename Fma, typename Neg, typename Canon>
ALWAYS_INLINE void fma_form(void *d, void const *pa, void const *pb, u32 f6, Ld ld, St st, Fma fma,
			    Neg neg, Canon canon)
{
	T const a = ld(pa), b = ld(pb), vd = ld(d);
	T r;
	switch (f6) {
	case VF6_VFMACC:
		r = fma(b, a, vd);
		break;
	case VF6_VFNMACC:
		r = fma(neg(b), a, neg(vd));
		break;
	case VF6_VFMSAC:
		r = fma(b, a, neg(vd));
		break;
	case VF6_VFNMSAC:
		r = fma(neg(b), a, vd);
		break;
	case VF6_VFMADD:
		r = fma(vd, b, a);
		break;
	case VF6_VFNMADD:
		r = fma(neg(vd), b, neg(a));
		break;
	case VF6_VFMSUB:
		r = fma(vd, b, neg(a));
		break;
	default: // VF6_VFNMSUB
		r = fma(neg(vd), b, a);
		break;
	}
	st(d, canon(r));
}

ALWAYS_INLINE void fma_chunk(void *d, void const *pa, void const *pb, u32 f6, u32 sew)
{
	if (sew == 4)
		fma_form<host_fchunk32_t>(
		    d, pa, pb, f6, [](void const *p) { return fchunk32_load(p); },
		    [](void *p, host_fchunk32_t v) { fchunk32_store(p, v); },
		    [](host_fchunk32_t x, host_fchunk32_t y, host_fchunk32_t z) {
			    return fchunk32_fma(x, y, z);
		    },
		    [](host_fchunk32_t x) { return fchunk32_neg(x); },
		    [](host_fchunk32_t x) { return fchunk32_canon(x); });
	else
		fma_form<host_fchunk64_t>(
		    d, pa, pb, f6, [](void const *p) { return fchunk64_load(p); },
		    [](void *p, host_fchunk64_t v) { fchunk64_store(p, v); },
		    [](host_fchunk64_t x, host_fchunk64_t y, host_fchunk64_t z) {
			    return fchunk64_fma(x, y, z);
		    },
		    [](host_fchunk64_t x) { return fchunk64_neg(x); },
		    [](host_fchunk64_t x) { return fchunk64_canon(x); });
}
#endif

// Does the HOST have a fused multiply-add, asked of the machine at run time?
//
// This was `#ifndef __FMA__ return false`, which asks instead what flags the *interpreter*
// translation unit happened to be compiled with. That is the wrong question and it silently
// disabled the whole vector-FMA fast path on default builds: guest/rv32_interp.cpp, where this
// predicate is compiled, gets -mfma from neither the per-file COMPILE_OPTIONS in
// dbt/CMakeLists.txt (those cover only guest/rv32_vector_run*.cpp) nor the global flags (which
// add -mavx512f/-mavx2 only inside `if(RVV_HOST_CHUNK_BITS STREQUAL "512"/"256")`, and the
// default is 128). Measured: try_fma then refused 96-98 % of guest FMAs on FMA-heavy workloads
// (pb_gemm 635840 refused vs 23160 admitted) and each fell to rvv_ref::vfma calling libm fma()
// per element.
//
// The capability is a property of the machine, so it is tested on the machine. Setting -mfma
// globally is NOT an acceptable alternative: it lets the compiler emit FMA anywhere in the
// program and the binary then dies with SIGILL on an SSE2-only host (tried, reverted).
inline bool host_has_fma()
{
#ifdef RVDBT_DIAG_ASSUME_HOST_CAPS
	// OPAQUE_BOUNDARY diagnostic build only -- see rv32_vector.h's host_has_avx2() comment.
	return true;
#else
	static bool const yes = __builtin_cpu_supports("fma");
	return yes;
#endif
}

inline bool fma_class_supported(u32 f6, u32 sew_bytes)
{
	// The kernels that actually issue the fused op live in the multiversioned translation units
	// guest/rv32_vector_run{16,32,64}.cpp, each compiled with its own -mfma, and are reached
	// through the width cascade. When the cascade is off (rvv_width_policy == 0) the inline
	// `fma_chunk` below is used instead, and that one does need __FMA__ in THIS TU.
#ifndef __FMA__
	if (config::rvv_width_policy == 0)
		return false; // no inline FMA kernel compiled here; use the libm reference path
#endif
	if (!host_has_fma())
		return false; // reference's libm fma() is what correctness requires on such a host
	if (sew_bytes != 4 && sew_bytes != 8)
		return false;
	return f6 == VF6_VFMACC || f6 == VF6_VFNMACC || f6 == VF6_VFMSAC || f6 == VF6_VFNMSAC ||
	       f6 == VF6_VFMADD || f6 == VF6_VFNMADD || f6 == VF6_VFMSUB || f6 == VF6_VFNMSUB;
}

constexpr bool falu_class_supported(u32 f6, u32 sew_bytes)
{
	if (sew_bytes != 4 && sew_bytes != 8)
		return false;
	return f6 == VF6_VFADD || f6 == VF6_VFSUB || f6 == VF6_VFMUL || f6 == VF6_VFDIV;
}

// ---------------------------------------------------------------------------------------------
// Class 3: floating-point compare (mask-producing). docs/U2_VFCMP_OPPORTUNITY_DECOMPOSITION.md
// has the exact, corrected numbers; the mechanism (CORRECTED there 2026-08-19 after review --
// see that doc's own correction note for what an earlier version got wrong) is: try_vfcmp is
// reached from HANDLER(vfcmp) through the SAME interpreter/QCG helper stub every RVV vector
// instruction goes through, admitted or not -- it does NOT bypass that call. What it changes is
// only the BODY that runs inside the call (a packed-SIMD chunk walk in place of rvv_ref::vfcmp's
// scalar element loop), so the removable cost under this architecture is reference-body cost
// minus packed-body cost, not the whole measured-per-call figure and not the whole non-body
// residual. Eliminating the call boundary itself would need a different architecture (direct
// QIR/QCG inline lowering) -- not what this class does. The obligations are a bounded extension
// of the arithmetic ones (same shape_ok, same quiet-vs-signalling NaN handling as
// B1_SEMANTIC_OBLIGATIONS.md already worked out) plus one genuinely new one: the destination is
// always a SINGLE mask register, never a register group, regardless of LMUL -- see
// mask_dest_overlap_ok below and walk_extent_cmp's own comment for what that changes.
// ---------------------------------------------------------------------------------------------
constexpr bool vfcmp_class_supported(u32 f6, u32 sew_bytes)
{
	if (sew_bytes != 4 && sew_bytes != 8)
		return false;
	return f6 == VF6_VMFEQ || f6 == VF6_VMFNE || f6 == VF6_VMFLT || f6 == VF6_VMFLE ||
	       f6 == VF6_VMFGT || f6 == VF6_VMFGE;
}

// ---------------------------------------------------------------------------------------------
// P13 B3-narrow (docs/P3_B3_NARROW_PROTOTYPE_DESIGN.md, docs/P3_HEADROOM_BOUND.md): is the guest
// instruction word at `vmem[gip+4 .. gip+7]` -- the one that will execute immediately after the
// current one, with certainty, since every RVV instruction is 4 bytes and the current
// (try_falu/try_fma/try_vfcmp-eligible) instruction is never itself a branch -- ALSO one of the
// 18 opcodes those three functions admit? Reused identically by all three so there is exactly one
// definition of "eligible" for this mechanism, matching the *_class_supported predicates above
// (never re-derived independently -- see [[rvdbt-source-claims-need-direct-verification]]).
//
// SEW is NOT re-decoded here: it is inherited from the CURRENT call's own `sew`, which is valid
// because nothing except a vset* instruction can change vtype/SEW, and vset* can never itself be
// eligible (it is not one of the 18 opcodes) -- so if the next instruction IS eligible, it
// necessarily shares the current instruction's vtype/SEW.
//
// This function is a CHEAP, DELIBERATELY CONSERVATIVE OVER-APPROXIMATION: it checks only
// opcode/funct3/funct6/SEW, none of which can prove the next instruction will actually be
// ADMITTED (it may still be refused for shape/vstart/vm/overlap, or by --rvv-fast-classes, or --
// see fp_mode's own definition -- for RMM/illegal frm, though that specific refusal is PROVEN
// unreachable here: frm cannot change between two truly gip-adjacent instructions without an
// intervening scalar CSR-write, which is not OP-V and is therefore never "eligible" by the checks
// below, so if THIS instruction's own frm passed, the next one's identical frm passes too).
// A "yes" from this function is therefore a PREDICTION, not a guarantee -- see
// `FroundRunGuard` below for what makes that safe: whichever function actually runs the next
// instruction is responsible for closing an inherited-but-abandoned bracket on EVERY one of ITS
// OWN refusal paths, so an over-optimistic peek can never leak state, only cost a redundant
// close+reopen when it turns out to be wrong. (Codex 4th review, 2026-08-19: the ORIGINAL version
// of this comment claimed the peek's syntactic check was sufficient by itself, which was wrong --
// try_falu/try_fma/try_vfcmp's own class-mask/RMM/shape/overlap checks run AFTER this peek's
// result is acted on by the PREVIOUS call, so a syntactically-eligible-but-refused next
// instruction left `fs.fround_run_open` stuck true with the run's true saved MXCSR never
// restored. Fixed by `FroundRunGuard`, not by trying to make this peek exact -- duplicating
// admission logic here would only create a second copy that could drift from the real checks.)
//
// SEW is NOT re-decoded here: it is inherited from the CURRENT call's own `sew`, which is valid
// because nothing except a vset* instruction can change vtype/SEW, and vset* can never itself be
// eligible (it is not one of the 18 opcodes) -- so if the next instruction IS eligible, it
// necessarily shares the current instruction's vtype/SEW.
//
// The guest memory read is guarded by `mmu::range_mapped`: `gip+4` is the NEXT instruction only
// when the current one is not the last mapped word before an unmapped page, which is not
// guaranteed for arbitrary guest code layouts (Codex 4th review point (e)) -- treating an
// unmapped-next-page as "not eligible" is always safe (the peek result is only ever a hint).
//
// ---------------------------------------------------------------------------------------------
// Codex 5th review, docs/BOUND_DEFINITION.md: the run-detection trace-replay oracle.
//
// `fround_run_peek_next_eligible` is called exactly once per admitted falu/fma/vfcmp call (from
// `fround_run_close_or_continue` below) -- a fully deterministic function of (the real peek's
// answer, in call order) as long as the binary, guest ELF, CLI flags (VLEN, classes, batch) and
// oracle mode are held fixed. RECORD mode runs the REAL peek exactly as normal and additionally
// appends its return value here, in call order; REPLAY mode (the executable oracle `To`) skips
// the real peek's guest-memory bounds check and raw-word decode entirely and returns the next
// recorded value via an O(1) array read instead. Because REPLAY never alters any ADMISSION
// decision upstream of this call (classes/RMM/shape/overlap are unchanged), and this project's
// interpreter is single-threaded and has no source of nondeterminism that could reorder or drop a
// `fround_run_close_or_continue` call between a RECORD run and a REPLAY run of the identical
// binary+guest+flags, the trace and the live call sequence stay in lockstep by construction --
// verified empirically in BOUND_ORACLE_RESULTS.md by requiring REPLAY's full output (values +
// fflags, the ADV_HASH/PB_HASH/TSVC_HASH convention every other gate in this round uses) to be
// byte-identical to a REAL (non-oracle) run's output, not merely assumed from this argument.
struct FroundOracleTrace {
	std::vector<u8> data;
	size_t idx = 0;
};
inline FroundOracleTrace g_fround_oracle{};

// Called once, before the guest starts executing (dbt/elfrun.cpp), when --rvv-fround-oracle-mode
// is 2 (replay). A short read of a small (single-digit-MB at this corpus's scale) file; see
// BOUND_ORACLE_RESULTS.md for a control measuring this load's own cost so it is not silently
// folded into the oracle's reported detection-cost saving.
inline void fround_oracle_load(char const *path)
{
	FILE *f = std::fopen(path, "rb");
	if (!f) {
		std::fprintf(stderr, "fround_oracle_load: cannot open '%s'\n", path);
		std::abort();
	}
	std::fseek(f, 0, SEEK_END);
	long const sz = std::ftell(f);
	std::fseek(f, 0, SEEK_SET);
	g_fround_oracle.data.resize((size_t)sz);
	size_t const got = sz > 0 ? std::fread(g_fround_oracle.data.data(), 1, (size_t)sz, f) : 0;
	std::fclose(f);
	if (got != (size_t)sz) {
		std::fprintf(stderr, "fround_oracle_load: short read on '%s' (%zu of %ld)\n", path, got,
			     sz);
		std::abort();
	}
	g_fround_oracle.idx = 0;
}

// Called once, after the guest finishes (dbt/elfrun.cpp), when --rvv-fround-oracle-mode is 1
// (record).
inline void fround_oracle_dump(char const *path)
{
	FILE *f = std::fopen(path, "wb");
	if (!f) {
		std::fprintf(stderr, "fround_oracle_dump: cannot open '%s' for write\n", path);
		std::abort();
	}
	if (!g_fround_oracle.data.empty())
		std::fwrite(g_fround_oracle.data.data(), 1, g_fround_oracle.data.size(), f);
	std::fclose(f);
}

inline bool fround_run_peek_next_eligible(u8 const *vmem, u32 gip, u32 sew)
{
	if (!config::rvv_fround_batch) // the A/B control: never continue a run when off
		return false;
	if (config::rvv_fround_oracle_mode == 2) { // REPLAY: the oracle itself, To
		if (g_fround_oracle.idx >= g_fround_oracle.data.size()) {
			std::fprintf(stderr, "fround oracle REPLAY: trace exhausted at call %zu -- "
					      "binary/guest/flags do not match the RECORD run\n",
				     g_fround_oracle.idx);
			std::abort();
		}
		return g_fround_oracle.data[g_fround_oracle.idx++] != 0;
	}
	// The real, syntactic peek -- unchanged from before the oracle, and what RECORD mode logs.
	auto const syntactic = [&]() -> bool {
		u32 const next_gip = gip + 4;
		if (!mmu::range_mapped(next_gip, 4))
			return false;
		u32 const next_raw = *reinterpret_cast<u32 const *>(vmem + next_gip);
		if ((next_raw & 0x7fu) != 0b1010111u) // OP-V major opcode
			return false;
		u32 const funct3 = (next_raw >> 12) & 0x7u;
		if (funct3 != 0b001u && funct3 != 0b101u) // OPFVV or OPFVF -- the only FP-sourced forms
			return false;
		u32 const f6 = (next_raw >> 26) & 0x3fu;
		return falu_class_supported(f6, sew) || fma_class_supported(f6, sew) ||
		       vfcmp_class_supported(f6, sew);
	};
	bool const eligible = syntactic();
	if (config::rvv_fround_oracle_mode == 1) // RECORD: log the real answer, change nothing else
		g_fround_oracle.data.push_back(eligible ? 1 : 0);
	return eligible;
}

// Shared open/close for try_falu/try_fma/try_vfcmp's tail -- one definition so the three call
// sites cannot drift from each other. `open_or_continue` is called AFTER each function's own
// RMM/shape refusal checks, at exactly the point the old unconditional `FRound rb(fs, md);`
// used to sit, so `md.path == FP_HOST` is already guaranteed and there is nothing to check here.
// Unconditional close: harvest + restore, regardless of why. Factored out so both the normal
// close path and the safety-net guard below call the exact same logic.
ALWAYS_INLINE void fround_run_force_close(FPUState &fs)
{
	// G3: every close funnels through here regardless of reason, so the run-length histogram is
	// recorded here. The per-reason counters live at the call sites; a run closed by neither the
	// CSR nor the TB-exit site was closed by the vector path, which shares this run state.
	fs.sc_note_run();
	fs.fround_run_open = false;
	// The harvest is semantically required in every mode: the guest's fflags must accumulate
	// the exceptions its own operations raised, and this STMXCSR is the only way to read them.
	fs.raise(mxcsr_bits_to_fflags(rvdbt_mxcsr_get()));
	if (config::rvv_fround_mxcsr_mode == 0)
		rvdbt_mxcsr_set(fs.fround_run_saved_mxcsr);
	else if (config::rvv_fround_mxcsr_mode == 1)
		rvdbt_mxcsr_set(config::g_mxcsr_resting);
	// mode 2 deliberately does not restore: the next bracket sets RC explicitly and clears
	// FLAGS, and no host FP code between brackets reads either (config.h states the invariant).
}

ALWAYS_INLINE void fround_run_open_or_continue(FPUState &fs, FpMode const &md)
{
	u32 const want = mxcsr_rc_for_frm(md.rm);
	if (fs.fround_run_open) {
		// AN INHERITED BRACKET MAY HOLD SOMEONE ELSE'S ROUNDING MODE.
		//
		// `fround_run_peek_next_eligible`'s argument for continuing without a check covers
		// vector-to-vector only: frm cannot change between two gip-adjacent OP-V
		// instructions without an intervening scalar CSR write. But this run state is
		// deliberately SHARED with the scalar path ("so a scalar op and a vector op can
		// continue each other's run", rv32_fpu.h), and a scalar FP instruction carries its
		// own rm FIELD -- `fdiv.d fa2, fa0, fa1, rup` opens the bracket with MXCSR.RC set
		// to round-up while the vector instruction that follows it must use frm. Continuing
		// that bracket silently computes the whole vector operation in the scalar
		// instruction's rounding mode.
		//
		// Measured, 2026-09-08 (fflags_preclose, `--rvv-fast=1 --rvv-scalar-fround-run=1`,
		// VLEN 512 and 1024): 8 of 10 cases produced vector results that differed from QEMU
		// and from the same chain run without the preceding scalar op, with two distinct
		// wrong outputs matching the two scalar rounding modes the guest used (rup, rtz).
		// The exception flags were correct throughout -- this is a rounding-mode leak, not a
		// flag leak, which is why no fflags-only oracle could see it.
		//
		// The compare is against the MIRRORED field, not an STMXCSR, so the common
		// continue path keeps costing a load and a compare (same reason
		// --rvv-scalar-fround-rcmirror exists). That requires every opener to publish it,
		// which is what the assignments below do.
		if (fs.fround_run_rc == want)
			return;
		fround_run_force_close(fs);
	}
	// config::rvv_fround_mxcsr_mode (see config.h for why each mode is or is not
	// semantics-preserving). Mode 0 is the shipped A/B control and reads the old value;
	// modes 1 and 2 use the process-lifetime-constant resting bits captured at startup,
	// which removes one STMXCSR from the run's critical path.
	if (config::rvv_fround_mxcsr_mode == 0) {
		fs.fround_run_saved_mxcsr = rvdbt_mxcsr_get();
		rvdbt_mxcsr_set((fs.fround_run_saved_mxcsr &
				 ~(FRound::MXCSR_RC | FRound::MXCSR_FLAGS)) |
				want);
	} else {
		rvdbt_mxcsr_set(config::g_mxcsr_resting | want);
	}
	fs.fround_run_rc = want;
}

// P13 B3-narrow SAFETY NET (Codex 4th review, 2026-08-19; fixes a real bug, not a defensive
// no-op): `fround_run_peek_next_eligible` is a syntactic over-approximation, so the instruction it
// predicted would continue a run may still be refused by ITS OWN admission checks (class mask via
// --rvv-fast-classes, RMM, shape_ok, overlap_ok). Construct ONE of these at the very top of
// try_falu/try_fma/try_vfcmp, before any check that can return false. Call `.commit()` at the
// exact point `fround_run_open_or_continue` succeeds (after which the function is guaranteed to
// reach its own `fround_run_close_or_continue` and needs no help). If the function returns early
// without committing, the destructor closes whatever bracket it inherited -- which can only be
// open here if a PREVIOUS instruction's peek guessed wrong, never something this call opened
// itself, so there is nothing to distinguish beyond "is one currently open".
struct FroundRunGuard {
	FPUState &fs;
	bool committed_ = false;
	explicit FroundRunGuard(FPUState &fs_) : fs(fs_) {}
	ALWAYS_INLINE void commit() { committed_ = true; }
	~FroundRunGuard()
	{
		if (!committed_ && fs.fround_run_open)
			fround_run_force_close(fs);
	}
};
ALWAYS_INLINE void fround_run_close_or_continue(FPUState &fs, u32 gip, u8 const *vmem, u32 sew)
{
	if (fround_run_peek_next_eligible(vmem, gip, sew)) {
		fs.fround_run_open = true;
		if constexpr (kFastStats)
			g_fast.fround_run_continued++;
	} else {
		fround_run_force_close(fs);
	}
}

// ---------------------------------------------------------------------------------------------
// Shape obligations, identical for every class. Kept in one place so that adding a class cannot
// forget one.
//   * unmasked   -- an unmasked packed op computes inactive lanes, and their FP exceptions are
//                   sticky in MXCSR; the architecture forbids that contribution (obligation F9)
//   * vstart == 0 -- the host has no notion of resuming mid-vector (F11 / M8)
//   * vtype legal -- the caller has already trapped otherwise
//   * the host chunk fits in one guest register's active extent at least once, otherwise the
//     fast path degenerates to the reference and only adds a test
// ---------------------------------------------------------------------------------------------
ALWAYS_INLINE bool shape_ok(VectorState const &vs, bool vm, u32 vlen_bits, u32 vl, u32 eew)
{
	if (!vm || vs.vstart != 0 || vl == 0)
		return false;
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	u32 const first_extent = (vl < per_reg ? vl : per_reg) * eew;
	return first_extent >= CB;
}

// ---------------------------------------------------------------------------------------------
// Register-group overlap. This is the one obligation the chunk walk could violate that the
// element-wise reference does not, so it is checked rather than left implicit.
//
// RVV allows a destination group to overlap a source group for a same-EEW element-wise
// operation. The walk processes registers in ascending order and, for each, reads the sources and
// then writes the destination. If `vd > src`, the write to `vd + r` lands on `src + r'` with
// r' = r + (vd - src) > r -- a source register a LATER iteration still has to read.
//
// Exact equality is safe: within one iteration the chunk at a given offset is read before it is
// written. Every other overlap is refused, and the refusal is counted so its frequency is
// measured rather than assumed to be zero.
// RVDBT_NO_OVERLAP_GUARD exists so the guard can be DEMONSTRATED to be load-bearing: with it
// defined, the adversarial guest's partial-overlap case must diverge from QEMU. A guard that has
// never been shown to fire is not evidence of anything.
ALWAYS_INLINE bool overlap_ok(u32 vd, u32 a_reg, u32 b_reg, bool has_b, i32 lmul_log2)
{
#ifdef RVDBT_NO_OVERLAP_GUARD
	(void)vd; (void)a_reg; (void)b_reg; (void)has_b; (void)lmul_log2;
	return true;
#endif
	if (vd != a_reg && group_overlaps(vd, a_reg, lmul_log2))
		return false;
	if (has_b && vd != b_reg && group_overlaps(vd, b_reg, lmul_log2))
		return false;
	return true;
}

// ---------------------------------------------------------------------------------------------
// The SAME obligation as overlap_ok, but for a compare's mask destination, which is DIFFERENT
// enough not to reuse it. overlap_ok's `vd != a_reg` exception is safe for arithmetic because a
// chunk's write always lands at the EXACT byte offset it just read -- so a register whose data
// was already consumed can never be revisited, and even vd == a_reg is safe because the read for
// that register happens before its own write. A compare's write does NOT have that property: bits
// are packed into vd at a GLOBALLY GROWING bit offset that has no fixed relationship to the BYTE
// offset the corresponding source chunk was read from, so an earlier register's mask bits can
// land in byte ranges a LATER register (or even that same register's own residue tail) still
// needs to read as source data. Proving exactly which sub-cases are still safe was judged not
// worth the risk this round -- vd aliasing a data source register is not idiomatic RVV codegen
// (a compiler allocates a dedicated mask register), so this refuses ALL overlap, including exact
// equality, rather than asserting a narrower "safe" case without a fully general proof.
ALWAYS_INLINE bool mask_dest_overlap_ok(u32 vd, u32 src_reg, i32 lmul_log2)
{
#ifdef RVDBT_NO_OVERLAP_GUARD
	(void)vd; (void)src_reg; (void)lmul_log2;
	return true;
#endif
	u32 const n = emul_group_regs(lmul_log2);
	return !(vd >= src_reg && vd < src_reg + n);
}

// Pack the low `nbits` of `bits` into vd's byte array starting at bit `bit_off` (0-indexed from
// the register's start; may straddle a byte boundary). A plain per-bit loop over the ALREADY-
// correct mask_set, not a clever batched byte store: docs/U2_VFCMP_OPPORTUNITY_DECOMPOSITION.md
// measured mask writes as architecturally cheap (mask_set is three ALU ops) and NOT a first-order
// cost, so there is nothing to win by making this cleverer, and a loop over a verified primitive
// is the lowest-risk way to get arbitrary bit alignment right.
ALWAYS_INLINE void mask_write_bits(VectorState &vs, u32 vd, u32 bit_off, u32 nbits, u32 bits)
{
	// P13 Ceiling-P5: the batched form, selected by config::rvv_vfcmp_batch_mask (default off,
	// so the per-element loop above remains the A/B control). Hardware counters measured the
	// per-element path at 75 instructions and 19.29 cycles per chunk against 18 instructions
	// and 2.84 for a batched write -- the largest per-chunk gap of any arithmetic family.
	//
	// Why this is safe for every case this method can reach, rather than only the "aligned"
	// ones: `bit_off` starts at 0 for each instruction and advances by exactly `nbits` per
	// chunk, so bit_off is always a multiple of nbits. `nbits = CB/eew`, and CB = 128 bits is
	// the only host chunk width this method ever runs with, giving nbits = 4 (SEW32) or 2
	// (SEW64) -- both exact divisors of 8. So `bit_off & 7` cycles through {0,4} or {0,2,4,6}
	// and the nbits bits can never straddle a byte boundary, by construction rather than by
	// luck. The one path that could produce an odd alignment is the single-element residue
	// tail, which is a SEPARATE vs.mask_set call in walk_extent_cmp and does not come through
	// here at all (and measures residue_elems = 0 across all 26 guests in this corpus anyway).
	// The assert makes that precondition checkable rather than merely asserted in a comment.
	if (config::rvv_vfcmp_batch_mask) {
		assert((bit_off % nbits) == 0 && (8u % nbits) == 0);
		u8 &b = vs.vreg[vd][bit_off >> 3];
		u32 const shift = bit_off & 7u;
		u8 const m = (u8)(((1u << nbits) - 1u) << shift);
		b = (u8)((b & ~m) | ((bits << shift) & m));
		return;
	}
	for (u32 i = 0; i < nbits; i++)
		vs.mask_set(vd, bit_off + i, (bits >> i) & 1u);
}

// ---------------------------------------------------------------------------------------------
// The extent walk for compare: the destination is a single MASK register, not a per-source-
// register-group element write, so unlike walk_extent's Chunk/Elem callbacks (which target vd+r
// at a per-register byte offset), this walk tracks a GLOBAL bit position into `vd` that grows
// monotonically across every source register processed -- element i of the whole vl-length
// operation always lands at bit i of vd, regardless of which source register produced it.
// `Chunk(pa, pb) -> u32` returns CB/eew packed mask bits for one host chunk (low bits meaningful).
// `Elem(r, i) -> bool` computes one residue element's result the reference way.
// ---------------------------------------------------------------------------------------------
template <typename Chunk, typename Elem>
ALWAYS_INLINE void walk_extent_cmp(VectorState &vs, u32 vd, u32 a_reg, u32 b_reg, u32 vlen_bits,
				   u32 vl, u32 eew, Chunk chunk, Elem elem)
{
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	u32 done = 0;
	u32 bitpos = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = n * eew;
		u32 off = 0;
		for (; off + CB <= bytes; off += CB) {
			u32 const bits = chunk(&vs.vreg[a_reg + r][off], &vs.vreg[b_reg + r][off]);
			u32 const nbits = CB >> eew_log2;
			mask_write_bits(vs, vd, bitpos, nbits, bits);
			bitpos += nbits;
			if constexpr (kFastStats)
				g_fast.chunks++;
		}
		#ifdef RVDBT_DIAG_NO_SHIFT
		for (u32 i = off / eew; i < n; i++) {
#else
		for (u32 i = off >> eew_log2; i < n; i++) {
#endif
			vs.mask_set(vd, bitpos, elem(r, i));
			bitpos++;
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
}

// The .vf variant: one source register group plus a pre-broadcast scalar chunk, same bit-packing
// discipline as walk_extent_cmp. Mirrors walk_extent_splat's relationship to walk_extent.
template <typename Chunk, typename Elem>
ALWAYS_INLINE void walk_extent_cmp_splat(VectorState &vs, u32 vd, u32 a_reg, u32 vlen_bits, u32 vl,
					 u32 eew, Chunk chunk, Elem elem)
{
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	u32 done = 0;
	u32 bitpos = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = n * eew;
		u32 off = 0;
		for (; off + CB <= bytes; off += CB) {
			u32 const bits = chunk(&vs.vreg[a_reg + r][off]);
			u32 const nbits = CB >> eew_log2;
			mask_write_bits(vs, vd, bitpos, nbits, bits);
			bitpos += nbits;
			if constexpr (kFastStats)
				g_fast.chunks++;
		}
		#ifdef RVDBT_DIAG_NO_SHIFT
		for (u32 i = off / eew; i < n; i++) {
#else
		for (u32 i = off >> eew_log2; i < n; i++) {
#endif
			vs.mask_set(vd, bitpos, elem(r, i));
			bitpos++;
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
}

// ---------------------------------------------------------------------------------------------
// The extent walk with a broadcast second operand. `.vx` and `.vi` are the same semantic class as
// `.vv`; only where the second operand comes from differs, so the scalar is broadcast once per
// operation and the identical walk is reused.
// ---------------------------------------------------------------------------------------------
template <typename Chunk, typename Elem>
ALWAYS_INLINE void walk_extent_splat(VectorState &vs, u32 vd, u32 a_reg, u32 vlen_bits, u32 vl,
				     u32 eew, Chunk chunk, Elem elem)
{
	u32 const vlen_bytes = vlen_bits >> 3;
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const eew_log2 = 0; // A/B control: forces the original runtime division below
#else
	u32 const eew_log2 = (u32)__builtin_ctz(eew); // eew is 1,2,4,8: exact
#endif
	#ifdef RVDBT_DIAG_NO_SHIFT
	u32 const per_reg = vlen_bytes / eew;
#else
	u32 const per_reg = vlen_bytes >> eew_log2;
#endif
	u32 done = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = n * eew;
		u32 off = 0;
		for (; off + CB <= bytes; off += CB) {
			chunk(&vs.vreg[vd + r][off], &vs.vreg[a_reg + r][off]);
			if constexpr (kFastStats)
				g_fast.chunks++;
		}
		#ifdef RVDBT_DIAG_NO_SHIFT
		for (u32 i = off / eew; i < n; i++) {
#else
		for (u32 i = off >> eew_log2; i < n; i++) {
#endif
			elem(r, i);
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
}

// ---------------------------------------------------------------------------------------------
// Dispatch. Each entry point answers one question -- "are this instance's obligations
// discharged?" -- and then either runs the class kernel or hands the whole operation to the
// reference. Nothing here is keyed on a mnemonic, a workload or a threshold.
//
// Under `--rvv-verify` both paths run on a copy and the destination is compared byte for byte,
// which is the shared correctness contract: the fast path is only ever allowed to be an exact
// re-encoding of the reference.
// ---------------------------------------------------------------------------------------------
// P15 candidate 7: the fused-pair fast path.
//
// Contract, and why it is safe. The caller has proven, from the decoded instruction pair alone,
// that `op1` writes vd, `op2` reads vd and also writes vd, both are unmasked VV integer
// element-wise ops at the same SEW/LMUL with no vsetvl* between them. Because op2 overwrites vd,
// op1's result is dead the instant op2 retires: no architectural state can observe it. Integer
// element-wise ops raise no flags and have no rounding mode, so there is no side effect to
// preserve either. That is the entire legality argument -- it needs no liveness analysis and no
// workload knowledge, which is why it transfers to any DBT with the same register-file shape.
//
// What this removes: one chunk store plus one chunk load per chunk, and one walk. Nothing else.
inline bool try_ialu_fused(VectorState &vs, u32 f6_1, u32 f6_2, u32 vd, u32 vs2, u32 vs1,
			   u32 op2_other, bool second_reads_intermediate_first, u32 vlen, u32 vl,
			   u32 sew, i32 lmul_log2)
{
	if (!(config::rvv_fast_classes & 1) || !ialu_class_supported(f6_1, sew) ||
	    !ialu_class_supported(f6_2, sew)) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	if (!shape_ok(vs, /*vm=*/true, vlen, vl, sew) ||
	    !overlap_ok(vd, vs2, vs1, /*vv=*/true, lmul_log2) ||
	    !overlap_ok(vd, vd, op2_other, /*vv=*/true, lmul_log2)) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}
	u32 const vlen_bytes = vlen >> 3, per_reg = vlen_bytes / sew;
	u32 done = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = n * sew;
		u32 off = 0;
		u8 *d = &vs.vreg[vd + r][0];
		u8 const *pa = &vs.vreg[vs2 + r][0], *pb = &vs.vreg[vs1 + r][0];
		u8 const *pc = &vs.vreg[op2_other + r][0];
		for (; off + HOST_CHUNK_BYTES <= bytes; off += HOST_CHUNK_BYTES) {
			if (!ialu_chunk_fused(d + off, pa + off, pb + off, pc + off, f6_1, f6_2,
					      second_reads_intermediate_first, sew))
				return false;
			if constexpr (kFastStats)
				g_fast.chunks++;
		}
		// Residue below one host chunk: fall back to the element form for BOTH ops, in order.
		for (u32 i = off / sew; i < n; i++) {
			u64 const a = vs.elem_u(vs2 + r, i, sew, vlen);
			u64 const b = vs.elem_u(vs1 + r, i, sew, vlen);
			u64 const z1 = rvv_ref::vialu_apply(f6_1, a, b, sew);
			u64 const c = vs.elem_u(op2_other + r, i, sew, vlen);
			u64 const z2 = second_reads_intermediate_first
					   ? rvv_ref::vialu_apply(f6_2, z1, c, sew)
					   : rvv_ref::vialu_apply(f6_2, c, z1, sew);
			vs.elem_put(vd + r, i, sew, vlen, z2);
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
	if constexpr (kFastStats)
		g_fast.ops_admitted += 2;
	return true;
}

// -------------------------------------------------------------------------------------------
// SUBSTRATE (ISA/support work, NOT a method): fast path for the integer-multiply handler.
//
// Chosen from the dynamic opcode census of the representative sparse workload, not by preference:
// `vimul` is 11.1 % of its dynamic vector calls and 19.7M elements, and it is pure
// register-to-register arithmetic, so it carries no fault or address-generation obligation.
//
// Only VF6_VMUL (low-half product) is admitted. The widening/high-half forms have different
// destination semantics and are left on the reference path.
//
// ISA capability routing is delegated, not assumed: the cascade tiers are built from the runtime
// `caps()` probe, and each width's kernel re-checks with `imul_ok` and refuses rather than
// miscomputing, so a host without the 32-bit packed multiply simply falls through to the
// reference. Nothing here is compiled on an assumption about the host.
//
// Gain from this substrate must be reported as ISA coverage in its own ablation arm. It is not
// attributable to any method.
inline bool try_imul(VectorState &vs, u32 f6, VSrc src, u32 vd, u32 vs2, u32 vs1, bool vm, u32 vlen,
		     u32 vl, u32 sew, i32 lmul_log2)
{
	if (f6 != VF6_VMUL || src != VSrc::VV) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	if (!config::rvv_width_policy) // the inline SSE2 path has no 32-bit packed multiply
		return false;
	// Pre-admission extent guard (docs/N1B_CAUSE_FALLBACK_IS_OUTOFLINE.md). If the operation
	// cannot reach even the narrowest host chunk, the walk would emit no chunk at all and every
	// element would take the out-of-line fallback callback -- measurably worse than the
	// reference's tight loop. Refuse here so short-vl work never pays the fast-path structure.
	// The bound is the host's narrowest tier width, a machine property from the tier table, not
	// a tuned threshold. It must be evaluated per invocation because vl is a runtime register.
	if (config::rvv_preadmit_extent) {
		rvv_cascade::TierTable const &tt0 =
		    rvv_cascade::tiers_cached((rvv_cascade::Policy)config::rvv_width_policy);
		u32 const narrowest = tt0.n ? tt0.t[tt0.n - 1].bytes : CB;
		if (vl * sew < narrowest)
			return false;
	}
	if (!shape_ok(vs, vm, vlen, vl, sew) || !overlap_ok(vd, vs2, vs1, /*vv=*/true, lmul_log2)) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}
	// N2B: walk inline rather than through the generic per-element callback. The profile showed
	// the callback as its own out-of-line symbol at 13.25% of total time, costing ~49 extra
	// instructions per remainder element against the reference's tight loop. The arithmetic and
	// the tier selection are unchanged; only the shape of the remainder loop is.
	rvv_cascade::TierTable const &tt = tiers_cached((rvv_cascade::Policy)config::rvv_width_policy);
	u32 const vlen_bytes = vlen >> 3, per_reg = vlen_bytes / sew;
	u32 done = 0;
	for (u32 r = 0; done < vl; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = n * sew;
		u32 const off = rvv_cascade::run_extent(
		    tt.t, tt.n, &vs.vreg[vd + r][0], &vs.vreg[vs2 + r][0], &vs.vreg[vs1 + r][0], bytes,
		    f6, sew, [](rvv_cascade::Tier const &t) { return t.ialu; });
		// Tight remainder loop: no callback, parameters already live in registers.
		for (u32 i = off / sew; i < n; i++) {
			u64 const a = vs.elem_u(vs2 + r, i, sew, vlen);
			u64 const b = vs.elem_u(vs1 + r, i, sew, vlen);
			vs.elem_put(vd + r, i, sew, vlen, rvv_ref::vimul_apply(f6, 0, a, b, sew));
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
	if constexpr (kFastStats)
		g_fast.ops_admitted++;
	return true;
}

inline bool try_ialu(VectorState &vs, u32 f6, VSrc src, u32 vd, u32 vs2, u32 vs1, u32 rs1_val,
		     i32 simm5, bool vm, u32 vlen, u32 vl, u32 sew, i32 lmul_log2)
{
	if (!(config::rvv_fast_classes & 1) || !ialu_class_supported(f6, sew)) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	if (!shape_ok(vs, vm, vlen, vl, sew) ||
	    !overlap_ok(vd, vs2, vs1, src == VSrc::VV, lmul_log2)) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}
	auto elem = [&](u32 r, u32 i) {
		u64 const a = vs.elem_u(vs2 + r, i, sew, vlen);
		u64 const b = src == VSrc::VV ? vs.elem_u(vs1 + r, i, sew, vlen)
					      : (src == VSrc::VX ? (u64)(i64)(i32)rs1_val
								 : (u64)(i64)simm5);
		vs.elem_put(vd + r, i, sew, vlen, rvv_ref::vialu_apply(f6, a, b, sew));
	};
	if (src == VSrc::VV) {
		// The cascade applies to the two-operand forms. The .vx/.vi forms broadcast a scalar
		// into a register and keep the compile-time walk in this increment; extending the
		// cascade to them needs a materialised broadcast buffer per tier width, which is a
		// separate edit and is not claimed here.
		if (config::rvv_width_policy)
			walk_extent_cascade(vs, vd, vs2, vs1, vlen, vl, sew, f6, sew,
					    RunClass::IALU, elem);
		else
			walk_extent(
			    vs, vd, vs2, vs1, vlen, vl, sew,
			    [&](void *d, void const *a, void const *b) { ialu_chunk(d, a, b, f6, sew); },
			    elem);
	} else {
		u64 const sv = src == VSrc::VX ? (u64)(i64)(i32)rs1_val : (u64)(i64)simm5;
		if (config::rvv_width_policy) {
			walk_extent_cascade_vs(vs, vd, vs2, vlen, vl, sew, sv, f6, sew, 0, elem);
			if constexpr (kFastStats)
				g_fast.ops_admitted++;
			return true;
		}
		host_chunk_t const bc = chunk_splat(sv, sew);
		walk_extent_splat(
		    vs, vd, vs2, vlen, vl, sew,
		    [&](void *d, void const *a) {
			    host_chunk_t const x = chunk_load(a);
			    host_chunk_t z;
			    switch (f6) {
			    case VF6_VADD:
				    z = chunk_add(x, bc, sew);
				    break;
			    case VF6_VSUB:
				    z = chunk_sub(x, bc, sew);
				    break;
			    case VF6_VAND:
				    z = chunk_and(x, bc);
				    break;
			    case VF6_VOR:
				    z = chunk_or(x, bc);
				    break;
			    default:
				    z = chunk_xor(x, bc);
				    break;
			    }
			    chunk_store(d, z);
		    },
		    elem);
	}
	if constexpr (kFastStats)
			g_fast.ops_admitted++;
	return true;
}

// P15 candidate 7, FP fused pair. Same contract as try_ialu_fused; see falu_chunk_fused for why
// eliding the intermediate preserves both the value and the fflags. Both ops execute inside ONE
// rounding bracket, which is also what the unfused pair would have done under B3-narrow run
// continuation, so the bracket accounting is unchanged.
inline bool try_falu_fused(VectorState &vs, FPUState &fs, u32 f6_1, u32 f6_2, u32 vd, u32 vs2,
			   u32 vs1, u32 op2_other, bool int_first, u32 vlen, u32 vl, u32 sew,
			   i32 lmul_log2, u32 pc2, u8 const *vmem)
{
	FroundRunGuard fround_guard{fs};
	if (!(config::rvv_fast_classes & 2) || !falu_class_supported(f6_1, sew) ||
	    !falu_class_supported(f6_2, sew)) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	FpMode const md = fp_mode(fs, FRM_DYN);
	if (md.path != FP_HOST) {
		if constexpr (kFastStats)
			g_fast.refuse_frm++;
		return false;
	}
	// vstart != 0 refuses this path: the kernels below walk from element 0.
	if (vs.vstart != 0 || !shape_ok(vs, /*vm=*/true, vlen, vl, sew) ||
	    !overlap_ok(vd, vs2, vs1, /*vv=*/true, lmul_log2) ||
	    !overlap_ok(vd, vd, op2_other, /*vv=*/true, lmul_log2)) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}
	fround_run_open_or_continue(fs, md);
	fround_guard.commit();

	u32 const vlen_bytes = vlen >> 3, per_reg = vlen_bytes / sew;
	u32 done = 0;
	bool ok = true;
	for (u32 r = 0; done < vl && ok; r++) {
		u32 const n = (vl - done) >= per_reg ? per_reg : (vl - done);
		u32 const bytes = n * sew;
		u32 off = 0;
		u8 *d = &vs.vreg[vd + r][0];
		u8 const *pa = &vs.vreg[vs2 + r][0], *pb = &vs.vreg[vs1 + r][0];
		u8 const *pc = &vs.vreg[op2_other + r][0];
		for (; off + HOST_CHUNK_BYTES <= bytes; off += HOST_CHUNK_BYTES) {
			if (!falu_chunk_fused(d + off, pa + off, pb + off, pc + off, f6_1, f6_2,
					      int_first, sew)) {
				ok = false;
				break;
			}
			if constexpr (kFastStats)
				g_fast.chunks++;
		}
		if (!ok)
			break;
		// Residue below one host chunk: both ops element-wise, in order, same bracket.
		for (u32 i = off / sew; i < n; i++) {
			u64 const a = vs.elem_u(vs2 + r, i, sew, vlen);
			u64 const b = vs.elem_u(vs1 + r, i, sew, vlen);
			u64 const c = vs.elem_u(op2_other + r, i, sew, vlen);
			u64 z2;
			if (sew == 4) {
				float const t = falu_apply_f32(f6_1, bits_to_f32((u32)a),
							       bits_to_f32((u32)b));
				float const tc = bits_to_f32(f32_canon(f32_to_bits(t)));
				float const y = bits_to_f32((u32)c);
				float const o = int_first ? falu_apply_f32(f6_2, tc, y)
							  : falu_apply_f32(f6_2, y, tc);
				z2 = (u64)f32_canon(f32_to_bits(o));
			} else {
				double const t = falu_apply_f64(f6_1, bits_to_f64(a), bits_to_f64(b));
				double const tc = bits_to_f64(f64_canon(f64_to_bits(t)));
				double const y = bits_to_f64(c);
				double const o = int_first ? falu_apply_f64(f6_2, tc, y)
							   : falu_apply_f64(f6_2, y, tc);
				z2 = f64_canon(f64_to_bits(o));
			}
			vs.elem_put(vd + r, i, sew, vlen, z2);
			if constexpr (kFastStats)
				g_fast.residue_elems++;
		}
		done += n;
	}
	fround_run_close_or_continue(fs, pc2, vmem, sew);
	if (!ok)
		return false; // partial work is impossible: the chunk kernel refuses before storing
	if constexpr (kFastStats)
		g_fast.ops_admitted += 2;
	return true;
}

inline bool try_falu(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		     bool vm, u32 vlen, u32 vl, u32 sew, i32 lmul_log2, u32 gip, u8 const *vmem)
{
	// P13 B3-narrow safety net (Codex 4th review): constructed BEFORE any check below can
	// return false, so a run inherited from the previous instruction's optimistic peek is
	// always closed correctly if THIS instruction turns out not to continue it after all.
	FroundRunGuard fround_guard{fs};
	if constexpr (kFastStats)
		sig_cache_probe(gip, sew, lmul_log2, vl, vs.vstart, fs.frm());
	if (!(config::rvv_fast_classes & 2) || !falu_class_supported(f6, sew)) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	// Obligation F6: RMM has no MXCSR encoding, so the whole operation goes to the exact
	// integer core. This is a property of the operation, not of a chunk.
	FpMode const md = fp_mode(fs, FRM_DYN);
	if (md.path != FP_HOST) {
		if constexpr (kFastStats)
			g_fast.refuse_frm++;
		return false;
	}
#ifdef RVDBT_DIAG_SKIP_OBLIGATIONS
	// DIAGNOSTIC ONLY, INCORRECT BY CONSTRUCTION. Skips the per-invocation obligation re-derivation
	// so the C-alpha headroom (wrapper cost vs SIMD kernel cost) can be BOUNDED before any
	// mechanism is designed. Never shipped, never a speedup claim. Same technique that correctly
	// sized the FP bracket and the scalar-FP direction.
	(void)vm; (void)lmul_log2;
#else
	// vstart != 0 refuses this path: the kernels below walk from element 0.
	if (vs.vstart != 0 || !shape_ok(vs, vm, vlen, vl, sew) ||
	    !overlap_ok(vd, vs2, vs1, !is_vf, lmul_log2)) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}
#endif

	// One host rounding-mode bracket for the whole operation, exactly as the reference uses.
	// Obligation F7: the packed operations accrue into the same sticky MXCSR bits, so the
	// harvest at the end is the union over every lane, which is what fflags means.
	//
	// P13 B3-narrow (docs/P3_B3_NARROW_PROTOTYPE_DESIGN.md): if a run is already open (the
	// immediately preceding guest instruction was also eligible and left the bracket open for
	// this call), MXCSR is already correctly configured -- `fround_run_open_or_continue` does
	// not touch it again in that case. `md.path == FP_HOST` is already guaranteed at this point
	// (the RMM refusal above returned false otherwise), so FRound's `active`-false path is
	// unreachable here and this call always either opens or continues a real bracket. From here
	// on this call is committed -- it will reach `fround_run_close_or_continue` at the bottom
	// unconditionally, so the safety-net guard has nothing left to do.
	fround_run_open_or_continue(fs, md);
	fround_guard.commit();
	auto elem = [&](u32 r, u32 i) {
		u64 const abits = vs.elem_u(vs2 + r, i, sew, vlen);
		u64 const bbits = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
					: vs.elem_u(vs1 + r, i, sew, vlen);
		if (sew == 4) {
			float const x = bits_to_f32((u32)abits), y = bits_to_f32((u32)bbits);
			float z;
			switch (f6) {
			case VF6_VFADD:
				z = x + y;
				break;
			case VF6_VFSUB:
				z = x - y;
				break;
			case VF6_VFMUL:
				z = x * y;
				break;
			default:
				z = x / y;
				break;
			}
			vs.elem_put(vd + r, i, sew, vlen, (u64)f32_canon(f32_to_bits(z)));
		} else {
			double const x = bits_to_f64(abits), y = bits_to_f64(bbits);
			double z;
			switch (f6) {
			case VF6_VFADD:
				z = x + y;
				break;
			case VF6_VFSUB:
				z = x - y;
				break;
			case VF6_VFMUL:
				z = x * y;
				break;
			default:
				z = x / y;
				break;
			}
			vs.elem_put(vd + r, i, sew, vlen, f64_canon(f64_to_bits(z)));
		}
	};

	if (!is_vf) {
		if (config::rvv_width_policy)
			walk_extent_cascade(vs, vd, vs2, vs1, vlen, vl, sew, f6, sew,
					    RunClass::FALU, elem);
#ifdef RVDBT_DIAG_HOIST_FALU_DISPATCH
		// M4 causal decomposition, arm A2
		// (experiments/2026-08-21-0705-rvv-region-residency-legality/docs/
		// M4_ORACLE_SEMANTIC_AUDIT.md). DIAGNOSTIC ONLY. `f6` is fixed for the whole call
		// (it is the guest instruction's own opcode field, admission-checked above by
		// `falu_class_supported` before this point is ever reached) -- `falu_chunk`'s
		// `switch (f6)` therefore always takes the same branch on every chunk of a given
		// call, so resolving it ONCE here instead of once per chunk changes nothing
		// observable: same op, same canonicalisation, same store, on every chunk: a loop-
		// unswitching transform, not a semantic change. Narrowly scoped to the one case
		// this cycle's causal probe exercises (unmasked FALU, sew==4, VF6_VFADD); every
		// other case falls through to the unchanged per-chunk-dispatch path below, so no
		// other code path's behaviour changes when this flag is defined.
		else if (f6 == VF6_VFADD && sew == 4)
			walk_extent(
			    vs, vd, vs2, vs1, vlen, vl, sew,
			    [&](void *d, void const *a, void const *b) {
				    host_fchunk32_t const r =
					fchunk32_add(fchunk32_load(a), fchunk32_load(b));
#if RVDBT_DIAG_NO_CANON
				    fchunk32_store(d, r);
#else
				    fchunk32_store(d, fchunk32_canon(r));
#endif
			    },
			    elem);
#endif
		else
			walk_extent(
			    vs, vd, vs2, vs1, vlen, vl, sew,
			    [&](void *d, void const *a, void const *b) { falu_chunk(d, a, b, f6, sew); },
			    elem);
	} else if (sew == 4) {
		host_fchunk32_t const bc = fchunk32_splat(bits_to_f32(f32_unbox(fs.f[vs1])));
		walk_extent_splat(
		    vs, vd, vs2, vlen, vl, sew,
		    [&](void *d, void const *a) {
			    host_fchunk32_t const x = fchunk32_load(a);
			    host_fchunk32_t r;
			    switch (f6) {
			    case VF6_VFADD:
				    r = fchunk32_add(x, bc);
				    break;
			    case VF6_VFSUB:
				    r = fchunk32_sub(x, bc);
				    break;
			    case VF6_VFMUL:
				    r = fchunk32_mul(x, bc);
				    break;
			    default:
				    r = fchunk32_div(x, bc);
				    break;
			    }
			    fchunk32_store(d, fchunk32_canon(r));
		    },
		    elem);
	} else {
		host_fchunk64_t const bc = fchunk64_splat(bits_to_f64(fs.f[vs1]));
		walk_extent_splat(
		    vs, vd, vs2, vlen, vl, sew,
		    [&](void *d, void const *a) {
			    host_fchunk64_t const x = fchunk64_load(a);
			    host_fchunk64_t r;
			    switch (f6) {
			    case VF6_VFADD:
				    r = fchunk64_add(x, bc);
				    break;
			    case VF6_VFSUB:
				    r = fchunk64_sub(x, bc);
				    break;
			    case VF6_VFMUL:
				    r = fchunk64_mul(x, bc);
				    break;
			    default:
				    r = fchunk64_div(x, bc);
				    break;
			    }
			    fchunk64_store(d, fchunk64_canon(r));
		    },
		    elem);
	}
	fround_run_close_or_continue(fs, gip, vmem, sew);
	if constexpr (kFastStats)
			g_fast.ops_admitted++;
	return true;
}

// FMA dispatch. Same obligations, same shape test, same overlap rule as try_falu -- the only
// differences are that vd is also a source (so the walk's destination chunk is read before it is
// written, which is safe within one iteration) and that the class is unavailable without FMA3.
inline bool try_fma(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		    bool vm, u32 vlen, u32 vl, u32 sew, i32 lmul_log2, u32 gip, u8 const *vmem)
{
	// P13 B3-narrow safety net: see try_falu's identical comment above. Declared before the
	// class-mask check too, since that alone can be the reason a peeked-eligible FMA op is
	// actually refused (e.g. --rvv-fast-classes without bit 4 set).
	FroundRunGuard fround_guard{fs};
	if constexpr (kFastStats)
		sig_cache_probe(gip, sew, lmul_log2, vl, vs.vstart, fs.frm());
	bool vf_needs_inline_fma = false;
#ifndef __FMA__
	// Without FMA in this TU the inline fma_chunk does not exist, so BOTH forms must go through
	// the cascade's multiversioned kernels. With the cascade off there is nothing to fall back
	// to and the reference path handles it.
	vf_needs_inline_fma = is_vf && config::rvv_width_policy == 0;
#endif
	if (!(config::rvv_fast_classes & 4) || vf_needs_inline_fma ||
	    !fma_class_supported(f6, sew)) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	FpMode const md = fp_mode(fs, FRM_DYN);
	if (md.path != FP_HOST) {
		if constexpr (kFastStats)
			g_fast.refuse_frm++;
		return false;
	}
	// vstart != 0 refuses this path: the kernels below walk from element 0.
	if (vs.vstart != 0 || !shape_ok(vs, vm, vlen, vl, sew) ||
	    !overlap_ok(vd, vs2, vs1, !is_vf, lmul_log2)) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}
	// P13 B3-narrow: see try_falu's identical comment above.
	fround_run_open_or_continue(fs, md);
	fround_guard.commit();
	// The element residue must be the reference's arithmetic verbatim, including operand order
	// and the use of a genuinely fused fma, or the two halves of one operation would disagree.
	auto elem = [&](u32 r, u32 i) {
		u64 const ab = vs.elem_u(vs2 + r, i, sew, vlen);
		u64 const bb = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
				     : vs.elem_u(vs1 + r, i, sew, vlen);
		u64 const db = vs.elem_u(vd + r, i, sew, vlen);
		if (sew == 4) {
			float const a = bits_to_f32((u32)ab), b = bits_to_f32((u32)bb),
				    d = bits_to_f32((u32)db);
			float z;
			switch (f6) {
			case VF6_VFMACC: z = std::fmaf(b, a, d); break;
			case VF6_VFNMACC: z = std::fmaf(-b, a, -d); break;
			case VF6_VFMSAC: z = std::fmaf(b, a, -d); break;
			case VF6_VFNMSAC: z = std::fmaf(-b, a, d); break;
			case VF6_VFMADD: z = std::fmaf(d, b, a); break;
			case VF6_VFNMADD: z = std::fmaf(-d, b, -a); break;
			case VF6_VFMSUB: z = std::fmaf(d, b, -a); break;
			default: z = std::fmaf(-d, b, a); break;
			}
			vs.elem_put(vd + r, i, sew, vlen, (u64)f32_canon(f32_to_bits(z)));
		} else {
			double const a = bits_to_f64(ab), b = bits_to_f64(bb), d = bits_to_f64(db);
			double z;
			switch (f6) {
			case VF6_VFMACC: z = std::fma(b, a, d); break;
			case VF6_VFNMACC: z = std::fma(-b, a, -d); break;
			case VF6_VFMSAC: z = std::fma(b, a, -d); break;
			case VF6_VFNMSAC: z = std::fma(-b, a, d); break;
			case VF6_VFMADD: z = std::fma(d, b, a); break;
			case VF6_VFNMADD: z = std::fma(-d, b, -a); break;
			case VF6_VFMSUB: z = std::fma(d, b, -a); break;
			default: z = std::fma(-d, b, a); break;
			}
			vs.elem_put(vd + r, i, sew, vlen, f64_canon(f64_to_bits(z)));
		}
	};
	if (!is_vf) {
		if (config::rvv_width_policy)
			walk_extent_cascade(vs, vd, vs2, vs1, vlen, vl, sew, f6, sew,
					    RunClass::FMA, elem);
		else
#ifdef __FMA__
			walk_extent(
			    vs, vd, vs2, vs1, vlen, vl, sew,
			    [&](void *d, void const *a, void const *b) { fma_chunk(d, a, b, f6, sew); },
			    elem);
#else
			// unreachable: fma_class_supported() refuses policy==0 without __FMA__
			__builtin_unreachable();
#endif
	} else if (config::rvv_width_policy) {
		// .vf through the SAME multiversioned run kernels as .vv, via the cascade's
		// scalar-operand entry (rc == 2 selects Tier::fma_vs). This is what keeps the
		// FMA-issuing code inside guest/rv32_vector_run{16,32,64}.cpp, each compiled with
		// its own -mfma, instead of requiring -mfma on this translation unit.
		u64 const sv = (sew == 4) ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1];
		walk_extent_cascade_vs(vs, vd, vs2, vlen, vl, sew, sv, f6, sew, 2, elem);
	} else {
#ifndef __FMA__
		// policy == 0 uses the inline fma_chunk, which needs __FMA__ here. Refused up front.
		__builtin_unreachable();
#else
		// The .vf scalar is broadcast once and then the identical kernel runs; a scratch
		// chunk holds it because fma_chunk takes a pointer, not a value.
		alignas(64) unsigned char bcast[HOST_CHUNK_BYTES];
		if (sew == 4)
			fchunk32_store(bcast, fchunk32_splat(bits_to_f32(f32_unbox(fs.f[vs1]))));
		else
			fchunk64_store(bcast, fchunk64_splat(bits_to_f64(fs.f[vs1])));
		walk_extent_splat(
		    vs, vd, vs2, vlen, vl, sew,
		    [&](void *d, void const *a) { fma_chunk(d, a, bcast, f6, sew); }, elem);
#endif
	}
	fround_run_close_or_continue(fs, gip, vmem, sew);
	if constexpr (kFastStats)
			g_fast.ops_admitted++;
	return true;
}

// Compare dispatch. docs/U2_VFCMP_OPPORTUNITY_DECOMPOSITION.md is the opportunity model this
// implements: this function is reached through the same HANDLER(vfcmp) call every vfcmp goes
// through, admitted or not, so what this function changes is only the BODY -- replacing
// rvv_ref::vfcmp's scalar element loop with the packed-SIMD kernel selection below.
//
// GT/GE have no dedicated kernel: swap operands and reuse LT/LE (fchunk32_cmp_lt(b,a) for GT,
// fchunk32_cmp_le(b,a) for GE) -- exact per rv32_vector_lower.h's fchunk32_cmp_* comment, and
// exactly what the RVV spec's own omission of vmfgt.vv/vmfge.vv from the .vv encoding assumes.
inline bool try_vfcmp(VectorState &vs, FPUState &fs, u32 f6, bool is_vf, u32 vd, u32 vs2, u32 vs1,
		      bool vm, u32 vlen, u32 vl, u32 sew, i32 lmul_log2, u32 gip, u8 const *vmem)
{
	// P13 B3-narrow safety net: see try_falu's identical comment above.
	FroundRunGuard fround_guard{fs};
	if constexpr (kFastStats)
		sig_cache_probe(gip, sew, lmul_log2, vl, vs.vstart, fs.frm());
	if (!(config::rvv_fast_classes & 8) || !vfcmp_class_supported(f6, sew)) {
		if constexpr (kFastStats)
			g_fast.refuse_class++;
		return false;
	}
	// A compare's RESULT never depends on the rounding mode (obligation F6 does not apply the
	// way it does to arithmetic), but FRound's EXCEPTION HARVEST half is still load-bearing:
	// the hardware predicates below set MXCSR's invalid flag under the same quiet-vs-signalling
	// rule rvv_ref::vfcmp_apply uses, and that flag has to be read back into fs the same way
	// arithmetic's does. md.rm is fetched only because FRound's constructor needs some value;
	// which one is irrelevant to a compare's output.
	FpMode const md = fp_mode(fs, FRM_DYN);
	if (md.path != FP_HOST) {
		if constexpr (kFastStats)
			g_fast.refuse_frm++;
		return false;
	}
	// vstart != 0 refuses this path: the kernels below walk from element 0.
	if (vs.vstart != 0 || !shape_ok(vs, vm, vlen, vl, sew) ||
	    !mask_dest_overlap_ok(vd, vs2, lmul_log2) ||
	    (!is_vf && !mask_dest_overlap_ok(vd, vs1, lmul_log2))) {
		if constexpr (kFastStats)
			g_fast.refuse_shape++;
		return false;
	}

	// P13 B3-narrow: see try_falu's identical comment above. `md.rm` is the guest's real `frm`
	// (fetched identically to try_falu/try_fma), so a run mixing compare with arithmetic always
	// sees a consistent rounding-mode configuration regardless of which instruction opened the
	// bracket -- `frm` can only change via a scalar CSR write, which is never itself eligible and
	// so always breaks a run before it could matter.
	fround_run_open_or_continue(fs, md);
	fround_guard.commit();
	auto elem = [&](u32 r, u32 i) -> bool {
		u64 const abits = vs.elem_u(vs2 + r, i, sew, vlen);
		u64 const bbits = is_vf ? (sew == 4 ? (u64)f32_unbox(fs.f[vs1]) : fs.f[vs1])
					: vs.elem_u(vs1 + r, i, sew, vlen);
		return rvv_ref::vfcmp_apply(fs, f6, abits, bbits, sew);
	};

	if (!is_vf) {
		if (sew == 4) {
			walk_extent_cmp(
			    vs, vd, vs2, vs1, vlen, vl, sew,
			    [&](void const *pa, void const *pb) -> u32 {
				    host_fchunk32_t const a = fchunk32_load(pa), b = fchunk32_load(pb);
				    switch (f6) {
				    case VF6_VMFEQ: return fchunk32_cmp_eq(a, b);
				    case VF6_VMFNE: return fchunk32_cmp_ne(a, b);
				    case VF6_VMFLT: return fchunk32_cmp_lt(a, b);
				    case VF6_VMFLE: return fchunk32_cmp_le(a, b);
				    case VF6_VMFGT: return fchunk32_cmp_lt(b, a);
				    default:        return fchunk32_cmp_le(b, a); // VMFGE
				    }
			    },
			    elem);
		} else {
			walk_extent_cmp(
			    vs, vd, vs2, vs1, vlen, vl, sew,
			    [&](void const *pa, void const *pb) -> u32 {
				    host_fchunk64_t const a = fchunk64_load(pa), b = fchunk64_load(pb);
				    switch (f6) {
				    case VF6_VMFEQ: return fchunk64_cmp_eq(a, b);
				    case VF6_VMFNE: return fchunk64_cmp_ne(a, b);
				    case VF6_VMFLT: return fchunk64_cmp_lt(a, b);
				    case VF6_VMFLE: return fchunk64_cmp_le(a, b);
				    case VF6_VMFGT: return fchunk64_cmp_lt(b, a);
				    default:        return fchunk64_cmp_le(b, a); // VMFGE
				    }
			    },
			    elem);
		}
	} else if (sew == 4) {
		host_fchunk32_t const bc = fchunk32_splat(bits_to_f32(f32_unbox(fs.f[vs1])));
		walk_extent_cmp_splat(
		    vs, vd, vs2, vlen, vl, sew,
		    [&](void const *pa) -> u32 {
			    host_fchunk32_t const a = fchunk32_load(pa);
			    switch (f6) {
			    case VF6_VMFEQ: return fchunk32_cmp_eq(a, bc);
			    case VF6_VMFNE: return fchunk32_cmp_ne(a, bc);
			    case VF6_VMFLT: return fchunk32_cmp_lt(a, bc);
			    case VF6_VMFLE: return fchunk32_cmp_le(a, bc);
			    case VF6_VMFGT: return fchunk32_cmp_lt(bc, a);
			    default:        return fchunk32_cmp_le(bc, a); // VMFGE
			    }
		    },
		    elem);
	} else {
		host_fchunk64_t const bc = fchunk64_splat(bits_to_f64(fs.f[vs1]));
		walk_extent_cmp_splat(
		    vs, vd, vs2, vlen, vl, sew,
		    [&](void const *pa) -> u32 {
			    host_fchunk64_t const a = fchunk64_load(pa);
			    switch (f6) {
			    case VF6_VMFEQ: return fchunk64_cmp_eq(a, bc);
			    case VF6_VMFNE: return fchunk64_cmp_ne(a, bc);
			    case VF6_VMFLT: return fchunk64_cmp_lt(a, bc);
			    case VF6_VMFLE: return fchunk64_cmp_le(a, bc);
			    case VF6_VMFGT: return fchunk64_cmp_lt(bc, a);
			    default:        return fchunk64_cmp_le(bc, a); // VMFGE
			    }
		    },
		    elem);
	}
	fround_run_close_or_continue(fs, gip, vmem, sew);
	if constexpr (kFastStats)
			g_fast.ops_admitted++;
	return true;
}

} // namespace dbt::rv32::rvv_fast
