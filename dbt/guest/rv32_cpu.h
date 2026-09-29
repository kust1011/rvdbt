#pragma once

#include "dbt/guest/rv32_ops.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/runtime_stubs.h"
#include "dbt/tcache/tcache.h"
#include "dbt/util/common.h"

#include <array>

namespace dbt::rv32
{

enum class TrapCode : u32 {
	NONE = 0,
	UNALIGNED_IP,
	ILLEGAL_INSN,
	EBREAK,
	ECALL,
};

// TODO: separate guest part
struct CPUStateImpl {
	bool IsTrapPending()
	{
		return trapno == TrapCode::NONE;
	}

	void DumpTrace(char const *event);
	void DumpTraceCache(u32 gip, u32 entry_ip);
	std::unordered_map<u32, std::unordered_map<u32, u64>> ip2ip_counts; // map from ip to gip to count

	using gpr_t = u32;
	static constexpr u8 gpr_num = 32;

	std::array<gpr_t, gpr_num> gpr{};
	gpr_t ip{};
	// Shadow-edge discovery (--shadow-edges, A-line): scratch slot for the computed jalr target,
	// spilled here (same discipline as `ip` above) because QCG's Emit_hcall (qemit.cpp) only
	// supports constant-valued hcall operands -- passing a live vtemp directly hits a register-
	// allocator assertion (GetPGPR: IsPGPR failed), since hcall was previously only ever called
	// with vconst() arguments in this codebase. Spilling to memory sidesteps this entirely.
	gpr_t shadow_edge_tgt{};
	TrapCode trapno{};

	// RVV 1.0 architectural vector state (32 vector registers + vl/vtype/vstart/vlenb).
	// Fixed-size storage (VLEN_MAX_BITS) so the CPUState layout stays stable for AOT code;
	// the ACTIVE width is config::vlen_bits and is read at execution time.
	VectorState vec{};

	tcache::L1BrindCache *l1_brind_cache{&tcache::l1_brind_cache};
	tcache::L1CacheTbExecCount *cache_tb_exec_count{&tcache::cache_tb_exec_count};
	tcache::L1MajorityCache *majority_cache{&tcache::majority_cache};
	// A-line round 28 Gate 1 (default off, ORACLE): pointer to the per-source order-1 context
	// slot array, same "pointer field constructed in the RUNNING process, loaded (never baked as
	// a compile-time absolute address) by AOT-compiled code" discipline as l1_brind_cache above --
	// AOT-compiled code runs in elfrun's process, a DIFFERENT process than elfaot compiled it in,
	// so any address baked in at elfaot-compile-time would be meaningless/unsafe in elfrun.
	u32 *gbrind_ctx1_slots{tcache::gbrind_ctx1_slots.data()};
	RuntimeStubTab stub_tab{};

	uptr sp_unwindptr{};

	using csr_t = u32;
	static constexpr u16 csr_num = 4096;
	std::array<csr_t, csr_num> csr{};

	// 2026-06-15 path-history exec-proof: GLOBAL last indirect-branch target, the path context for the
	// context-keyed (2-level) AOT dispatch specialization. Updated at every gbrind expansion; read as the
	// "previous target" to select the context-predicted next target. Default path (no --aot-context-edge-
	// specialize) never reads/writes it -> baseline unchanged. Global (not per-site) = the minimal prototype.
	u32 last_brind_target{};

	// DVET work counter: guest region entries (one relaxed increment per AOT region entry, emitted only
	// when --aot-work-counter; both trial variants carry it -> unbiased comparison). Appended field:
	// all prior offsets unchanged, existing artifacts stay compatible.
	u64 work_counter{};
	u64 gbrind_counter{}; // A-line: AOT-internal gbrind executions (--aot-count-gbrind artifacts)
	// A-line round 28 Gate 1: order-1 oracle reachability counters, same relaxed load-add-store
	// pattern as gbrind_counter above -- zero cost when the oracle flag is off (no store emitted).
	u64 gbrind_order1_covered{}; // dispatch reached a source with >=1 order-1 (prev,target) pair
	u64 gbrind_order1_hits{};    // guard matched (runtime prev AND actual target both correct)
	// A-line round 29 Gate 1: marginal (context-free) oracle reachability counters, same pattern.
	u64 gbrind_marginal_covered{}; // dispatch reached a source with a marginal majority target
	u64 gbrind_marginal_hits{};    // guard matched (actual target == compile-time majority target)
	// A-line round 32 Gate 2: static jump-table oracle reachability counters, same pattern.
	u64 gbrind_statictable_covered{}; // dispatch reached a source with a proven static table
	u64 gbrind_statictable_hits{};    // switch matched one of the table's proven targets
	// A-line round 33: vtable narrowing reachability counters. "covered" = dispatch reached a
	// source whose receiver type was resolved and RTTI-narrowed to >=1 candidate; "hits" = the
	// actual runtime target was inside that narrowed set (a miss falls to the unchanged generic
	// gbrind path, NOT an error -- narrowing is deliberately non-exhaustive, unlike static table).
	u64 gbrind_vtablenarrow_covered{};
	u64 gbrind_vtablenarrow_hits{};
	// A-line Round 44: index-preserving compact dispatch reachability counters, same pattern.
	// "covered" = dispatch reached a source with a proven index-ordered table; "hits" = the
	// index was in bounds AND the resolved entry was independently AOT-admitted (a miss/OOB/null
	// falls to the unchanged generic gbrind path, never an error).
	u64 gbrind_indexeddispatch_covered{};
	u64 gbrind_indexeddispatch_hits{};

	// Design 8 multi-entry diagnostic counters (2026-07-24, --aot-link-multientry-trace):
	// TEMPORARY instrumentation to prove which code path actually executes for a merged
	// secondary entry, rather than inferring it from disassembly. Incremented directly in the
	// generated code, zero cost when the flag is off (no store emitted at all).
	u64 dbg_multientry_switch_hits{};  // a switch case (secondary entry) was actually taken
	u64 dbg_multientry_default_hits{}; // the switch's default arm (normal/primary entry) was taken
	u64 dbg_wrapper_calls{};	    // a CreateLinkEntryWrapper-generated wrapper body actually ran

	// Line-B activation invariant (LINEB_GATE_IMPLEMENTATION_PLAN.md): total guest instructions executed
	// since process start, incremented once per QCG/AOT region entry by that region's static instruction
	// count (exact for QCG's single-block jobs; region->num_insns on the AOT side). Default path (no
	// --sr-activation-invariant) never increments it -> baseline unchanged.
	u64 exec_instr_seen{};

	// 2026-07-28 A-line causal diagnostic (--aot-region-hit-count, default off): per-region AOT
	// entry-hit counter. Each admitted region's Run()-emitted entry gets a compile-time-assigned
	// dense slot index (direct array indexing, no hash, no collision -- same discipline as
	// tcache.h's gbrind_ctx1_slots) and increments its own slot once per real entry into that
	// region's compiled body. Joins with elfaot's own --aot-region-hit-map-out (slot->entry_ip)
	// to recover per-region real dynamic hit counts, independent of Wendell's own exec_count
	// field, for causal ablation. Zero cost when the flag is off (no store emitted, array unused).
	static constexpr u32 REGION_HIT_SLOTS = 1024;
	u64 region_entry_hits[REGION_HIT_SLOTS]{};

	// RVV direct-lowering evidence. Incremented by JIT-EMITTED code (not by a helper), which is
	// what makes them evidence that the inline path really executed. Placed at the ACTUAL end of
	// the struct so that every preceding field keeps its offset -- an earlier revision put them
	// mid-struct while claiming exactly that, which was false.
	//
	// NOTE this does NOT make the branch AOT-compatible with abadd33b5: `VectorState vec` is
	// necessarily embedded earlier (the emitted code addresses it off the state register), so
	// this branch's CPUState layout differs from the base commit regardless. See
	// CPUStateAbiSignature() below and dbt/aot/aot.h AOT_SYM_ABI for the safeguard.
	u64 rvv_direct_hits{};
	u64 rvv_direct_fallbacks{};

	// RV32F/RV32D architectural state: f0..f31 (64-bit, single-precision NaN-boxed) and fcsr.
	// Appended at the end so every preceding offset is unchanged -- but this DOES change
	// sizeof(CPUState) and therefore the ABI signature, so pre-F/D AOT artifacts are refused
	// by the existing gate rather than silently mismatching.
	FPUState fpu{};
	// T7o certified component images may read their immutable guest objects through a private
	// pre-dispatch snapshot while retaining direct certified stores to the live guest mapping.
	// Null outside that default-off production mode.
	u8 *ccrf_read_base{};
};

// Z4B (--rvv-qcg-typed-chunk-vlse-gather-census, default off). THE DIRECT DYNAMIC COUNT OF THE Z3
// `vlse32.v` GATHER BODY'S TWO OUTCOMES, and nothing else.
//
// WHY A COUNTER HAD TO BE ADDED AT ALL. Both of that body's runtime exits jump into the element loop
// retained INSIDE the same node, so neither crosses the frame's guard-miss arm and neither touches
// `rvv_direct_fallbacks`. `guard_fallbacks == 0` therefore has no discriminating power over them:
// Z4 could show the gather was EMITTED (4 vpgatherdd per TB at VLEN 512, 8 at 1024) and could
// DERIVE, from the guest's zero CSR instructions and from the top page's prot=0, that it should
// always be TAKEN -- but the direct observation was ABSENT. These two counters are that observation.
//
// WHY THEY ARE NOT FIELDS OF CPUState, which is where every other emitted-code counter lives. The
// AOT ABI signature mixes sizeof(CPUStateImpl), and ukernel.cpp pins that size in a static_assert
// whose message is "AOT ABI moved". Growing the struct for a default-off DIAGNOSTIC would refuse
// every existing AOT artifact built from this tree -- a real cost, paid for nothing, since the
// route this counts is pure QCG. So they are ordinary process-global u64s addressed by absolute
// address (two instructions instead of one), exactly the trade EmitRvvFrameCensusIncr already makes
// for the per-frame census slot and for the same stated reason: the cost is irrelevant because this
// is never enabled on a timed arm.
//
// SINGLE-THREADED BY CONSTRUCTION, like every other emitted-code counter here: rvdbt runs one guest
// thread per process and the increment is a plain non-atomic `inc`.
//
// `extern "C"`, and DEFINED IN qemit.cpp, for the same reason rv32_vector.h's g_gather_* counters
// are: the emitted code bakes in the address of one specific object, so there must be exactly one,
// with no chance of a per-translation-unit or per-library copy for the reader to miss.
extern "C" unsigned long long g_vlse_gather_fast;     // the fast path completed: all chunks stored
extern "C" unsigned long long g_vlse_gather_fallback; // left for the element loop (vstart, or top)

// P2a (--rvv-qcg-active-chunk-census, default off). THE TWO ACTIVE-CHUNK COUNTERS, and everything
// said about the pair immediately above applies verbatim: not CPUState fields (the AOT ABI
// signature below mixes sizeof(CPUStateImpl)), single-threaded by construction, `extern "C"` and
// DEFINED IN qemit.cpp so the address the emitted code bakes in names exactly one object.
//
//   g_rvv_chunks_available  host work units a planner-eligible native frame WOULD execute with
//                           suffix skipping off -- the finalizer's derived unit count, added once
//                           per execution of the frame's native body.
//   g_rvv_chunks_executed   units of those actually REACHED: the unbounded prefix, added at the
//                           same join, plus one per active-VL bound that fell through.
//
// DELIBERATELY NOT NAMED `useful`. With the policy switches off every unit is reached and the two
// are equal by construction, tail units included; see config::rvv_qcg_active_chunk_census.
extern "C" unsigned long long g_rvv_chunks_available;
extern "C" unsigned long long g_rvv_chunks_executed;

// ---------------------------------------------------------------------------------------------
// CPUState ABI signature.
//
// AOT artifacts are compiled by `elfaot` in one process and executed by `elfrun` in another,
// with CPUState field offsets baked into the generated machine code. The cache path is keyed
// ONLY by the GUEST ELF's checksum (objprof::MakeCachePath -> g_dbt_cache_dir + csum), so it
// does NOT distinguish artifacts produced by a different rvdbt build. An artifact compiled
// before this branch added `VectorState vec` to CPUState would therefore be found and loaded by
// this elfrun, and every baked offset after `vec` would be wrong -- silent memory corruption,
// not a clean failure.
//
// This signature is derived from the layout itself (size + the offsets the generated code
// actually addresses), embedded in each artifact, and checked at load. Anything built with a
// different layout -- including every artifact that predates this branch, which carries no
// signature symbol at all -- is refused, and execution falls back to the JIT, which is always
// correct.
inline u64 CPUStateAbiSignature()
{
	u64 h = 1469598103934665603ull;
	auto mix = [&h](u64 v) {
		h ^= v;
		h *= 1099511628211ull;
	};
	mix(sizeof(CPUStateImpl));
	mix(offsetof(CPUStateImpl, gpr));
	mix(offsetof(CPUStateImpl, ip));
	mix(offsetof(CPUStateImpl, trapno));
	mix(offsetof(CPUStateImpl, vec));
	mix(sizeof(rv32::VectorState));
	mix(offsetof(CPUStateImpl, stub_tab));
	mix(offsetof(CPUStateImpl, l1_brind_cache));
	mix(offsetof(CPUStateImpl, exec_instr_seen));
	mix(offsetof(CPUStateImpl, region_entry_hits));
	mix(offsetof(CPUStateImpl, rvv_direct_hits));
	mix(offsetof(CPUStateImpl, fpu));
	mix(sizeof(FPUState));
	return h;
}

// qmc config, also used to synchronize int/jit debug tracing
static constexpr u16 TB_MAX_INSNS = 64; // TODO: this cannot be changed too large, but where does the 

} // namespace dbt::rv32

namespace dbt
{
struct uthread;
struct CPUState : rv32::CPUStateImpl {
	CPUState() = delete;
	CPUState(uthread *ut_) : ut(ut_) {}

	static void SetCurrent(CPUState *s)
	{
		tls_current = s;
	}

	static CPUState *Current()
	{
		return tls_current;
	}

	uthread *GetUThread() const
	{
		return ut;
	}

private:
	static thread_local CPUState *tls_current;

	uthread *ut{};
};

} // namespace dbt
