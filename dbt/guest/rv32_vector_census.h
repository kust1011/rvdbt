#pragma once

// Dynamic RVV cost census (2026-08-18, round P13).
//
// WHY THIS EXISTS
// ---------------
// P12 established that the fixed-width chunk path is never entered by compiler-generated RVV
// (`chunk_ops = 0` in 420 timing rows), so host chunk width changes nothing. Before adding any
// lowering, this round has to answer a measurement question the substrate could not answer:
// *where does the dynamic cost of real vector code actually go?*
//
// Three quantities are routinely conflated and are separated here by construction:
//   * STATIC opcode count   -- how many distinct encodings appear in the ELF (objdump; not here);
//   * DYNAMIC invocations   -- how many times each semantic cell is executed (`calls`);
//   * ELEMENT work          -- how many architectural elements those invocations touch (`elems`,
//                              and `active` after the mask);
//   * ELAPSED contribution  -- host cycles actually spent inside the helper (`cycles`).
// A family can be first on one of these and last on another. That is the whole point.
//
// DESIGN CONSTRAINTS
//   * Default off. When `config::rvv_census == 0` the cost is one load of a bool and one
//     not-taken branch, and only in vector handlers (`if constexpr` removes it everywhere else).
//   * No workload-specific anything. The cell key is built from the instruction encoding and the
//     architectural vtype, both spec-defined.
//   * Fail loud, not silent: a full table increments `g_overflow`, which the dump prints and the
//     analysis treats as invalidating.
//   * The timing mode is honest about its own overhead: `calibrate()` measures the empty-scope
//     cost on the same machine at dump time and prints it, so the analysis can subtract
//     `calls * overhead` instead of pretending instrumentation is free.
//
// MODES (`--rvv-census`)
//   0  off
//   1  counts only  -- calls / elems / active. No rdtsc, so the per-call distortion is minimal.
//   2  counts + cycles -- adds an rdtsc pair per vector instruction.
// Mode 1 exists because mode 2's per-call overhead is a significant fraction of a short helper;
// element counts must not be taken from a distorted run when a clean one is this cheap.

#include "dbt/config.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/util/common.h"

#include <cstdio>
#include <cstring>
#include <x86intrin.h>

namespace dbt::rv32::rvv_census
{

// A handler name belongs to the vector census iff it starts with 'v'. That is not a heuristic on
// this codebase: every rv32 base/M/F/D/Zicsr handler name in rv32_interp.cpp begins with another
// letter, and every RVV handler begins with 'v'. Evaluated at compile time on the `#name` literal,
// so scalar handlers carry no census code at all.
constexpr bool name_is_vector(char const *s) { return s[0] == 'v'; }

// RVDBT_CENSUS=0 removes the census hook from the HANDLER macro entirely -- not the branch, the
// whole thing -- so a performance binary carries no instrumentation at all. Default 1 so the
// measurement builds are unchanged.
#ifndef RVDBT_CENSUS
#define RVDBT_CENSUS 1
#endif
static constexpr bool kCensusEnabled = RVDBT_CENSUS != 0;

// ---- cell key ---------------------------------------------------------------------------------
// Everything in the key is read from the encoding or from vtype. Field widths are the spec's.
//
//   [ 7: 0] family id      (interned handler name)
//   [13: 8] funct6         (insn[31:26]; for memory ops this is nf|mew|mop)
//   [16:14] funct3         (insn[14:12]; the operand-source / EEW-width field)
//   [21:17] rs2 field      (only when it is an opcode extension: unit-stride lumop/sumop)
//   [24:22] vsew           (vtype.vsew; 8<<vsew = SEW)
//   [27:25] vlmul          (vtype.vlmul, the signed-log2 encoding)
//   [28:28] vm             (insn[25]; 0 = masked by v0)
//   [29:29] vill           (vtype was illegal when the instruction executed)
//   [40:30] vl             (0..1024; architectural vl for this invocation)
//   [41:41] vta            (vtype.vta; tail-agnostic -- decides whether a whole-register fast
//                           path may legally write past vl)
//   [42:42] vma            (vtype.vma; mask-agnostic -- the same question for inactive elements)
static constexpr u32 KEY_FAM_SH = 0;
static constexpr u32 KEY_F6_SH = 8;
static constexpr u32 KEY_F3_SH = 14;
static constexpr u32 KEY_RS2_SH = 17;
static constexpr u32 KEY_SEW_SH = 22;
static constexpr u32 KEY_LMUL_SH = 25;
static constexpr u32 KEY_VM_SH = 28;
static constexpr u32 KEY_VILL_SH = 29;
static constexpr u32 KEY_VL_SH = 30;
static constexpr u32 KEY_VTA_SH = 41;
static constexpr u32 KEY_VMA_SH = 42;

struct Cell {
	u64 key;	 // 0 == empty slot (a real key always carries a nonzero family id + 1)
	u64 calls;
	u64 elems;      // sum of REQUESTED vl over invocations
	u64 elems_done; // sum of COMPLETED vl (differs only for fault-only-first loads)
	u64 active;     // sum of mask-active elements (== elems for unmasked data ops)
	u64 cycles;   // rdtsc delta, mode 2 only
	u32 example;  // first raw instruction word seen in this cell, for decode cross-check
	u32 _pad;
};

static constexpr u32 TABLE_BITS = 14;
static constexpr u32 TABLE_SIZE = 1u << TABLE_BITS;
static constexpr u32 MAX_FAMILIES = 96;

inline Cell g_table[TABLE_SIZE];
inline char const *g_family[MAX_FAMILIES];
inline u32 g_family_n = 0;
inline u64 g_overflow = 0;    // ops dropped because the table was full -- must stay 0
inline u64 g_vstart_nz = 0;   // invocations that resumed at vstart != 0
inline u64 g_vl_truncated = 0; // non-cfg invocations that changed vl (fault-only-first)
inline u64 g_total_calls = 0; // every censused vector invocation
inline u64 g_total_cycles = 0;
inline u64 g_t0 = 0;         // rdtsc at census start, for a run-length denominator
inline double g_pair_cycles = 0;  // measured cost of the timestamp pair alone
inline double g_scope_cycles = 0; // measured cost of the whole per-instruction hook

inline int intern(char const *name)
{
	for (u32 i = 0; i < g_family_n; i++)
		if (std::strcmp(g_family[i], name) == 0)
			return (int)i;
	if (g_family_n >= MAX_FAMILIES)
		return (int)MAX_FAMILIES - 1;
	g_family[g_family_n] = name;
	return (int)g_family_n++;
}

// Open addressing with linear probing. `key` is never 0 for an occupied slot because the family
// id is stored as id+1.
ALWAYS_INLINE Cell *lookup(u64 key)
{
	u64 h = key * 0x9e3779b97f4a7c15ull;
	u32 idx = (u32)(h >> (64 - TABLE_BITS));
	for (u32 probe = 0; probe < 64; probe++) {
		Cell &c = g_table[(idx + probe) & (TABLE_SIZE - 1)];
		if (c.key == key)
			return &c;
		if (c.key == 0) {
			c.key = key;
			return &c;
		}
	}
	g_overflow++;
	return nullptr;
}

// Number of mask-active elements in v0 over [0, vl).
//
// MUST be evaluated BEFORE the handler runs. A masked instruction whose destination IS v0 is
// legal in RVV 1.0 when the destination is a MASK value (the substrate's
// RVV_REQUIRE_MASK_NO_OVERLAP allows exactly that case, and vicmp/vmsbf/vmsif/vmsof/viota all
// hit it), so reading v0 afterwards would count the result, not the predicate. That was a real
// defect in the first version of this file, not a hypothetical.
ALWAYS_INLINE u64 mask_active(VectorState &vs, u32 vl)
{
	u64 n = 0;
	for (u32 e = 0; e < vl; e++)
		n += vs.mask_get(0, e);
	return n;
}

// Timestamp boundaries.
//
// A bare RDTSC pair is not a defensible interval: RDTSC is not ordered against surrounding
// instructions, so work can drift across either edge. The pattern used here is the conventional
// defensible one:
//   open  = LFENCE ; RDTSC              -- no earlier load/store may be reordered past the read
//   close = RDTSCP ; LFENCE             -- RDTSCP waits for prior instructions to retire, LFENCE
//                                          stops later work from being pulled before the read
// `calibrate_pair()` measures EXACTLY this open/close pair back to back with nothing in between,
// so its result is dimensionally identical to the `dt` stored in a cell and may legitimately be
// subtracted as `calls * pair_cycles`. The cost of the rest of the census (key build, table
// probe, mask scan) lies OUTSIDE the measured interval; it inflates whole-run time, not `dt`,
// and is reported separately as `scope_cycles`.
ALWAYS_INLINE u64 ts_open()
{
	_mm_lfence();
	return __rdtsc();
}
ALWAYS_INLINE u64 ts_close()
{
	unsigned aux;
	u64 const t = __rdtscp(&aux);
	_mm_lfence();
	return t;
}

// One censused vector instruction.
//
// The pre-state is captured before the handler runs because the handler may change vl (the vset*
// family, and fault-only-first loads) or vstart. For the configuration family (`OP-V` with
// funct3 == 0b111, i.e. vsetvli / vsetivli / vsetvl) the interesting vl is the one the
// instruction *produces*, so that family is keyed on the post-state and contributes no element
// work.
struct Scope {
	VectorState *vs;
	u64 key_base;
	u64 active_pre; // mask-active positions, sampled BEFORE the handler can overwrite v0
	u32 vl_pre;
	u32 raw;
	bool is_cfg;
	bool vm;
	u64 t_in;

	ALWAYS_INLINE Scope(int fam, VectorState &v, u32 insn_raw)
	{
		vs = &v;
		raw = insn_raw;
		u32 const opcode = insn_raw & 0x7f;
		u32 const funct3 = (insn_raw >> 12) & 0x7;
		is_cfg = (opcode == 0x57) && (funct3 == 0b111);
		vm = ((insn_raw >> 25) & 1) != 0;
		u32 const f6 = (insn_raw >> 26) & 0x3f;
		// The rs2 field is an opcode extension only for unit-stride memory ops (mop == 00),
		// where it selects plain / whole-register / mask / fault-only-first. Everywhere else
		// it is a register number and must not enter the key.
		bool const is_mem = (opcode == 0x07) || (opcode == 0x27);
		u32 const mop = (insn_raw >> 26) & 0x3;
		u32 const rs2f = (is_mem && mop == 0) ? ((insn_raw >> 20) & 0x1f) : 0;
		key_base = ((u64)(u32)(fam + 1) << KEY_FAM_SH) | ((u64)f6 << KEY_F6_SH) |
			   ((u64)funct3 << KEY_F3_SH) | ((u64)rs2f << KEY_RS2_SH) |
			   ((u64)(vm ? 1 : 0) << KEY_VM_SH);
		vl_pre = v.vl;
		active_pre = (is_cfg || vm) ? (u64)vl_pre : mask_active(v, vl_pre);
		if (v.vstart != 0)
			g_vstart_nz++;
		if (config::rvv_census >= 2)
			t_in = ts_open();
	}

	ALWAYS_INLINE void finish()
	{
		u64 const dt = (config::rvv_census >= 2) ? (ts_close() - t_in) : 0;
		// Post-state vtype is correct for both cases: only the vset* family writes vtype, so
		// for a data operation post == pre, and for vset* the produced vtype is the one we
		// want. vl is different -- a data op must be keyed on the vl it actually consumed.
		VType const vt{vs->vtype};
		u32 const vl = is_cfg ? vs->vl : vl_pre;
		u64 key = key_base | ((u64)(vt.vsew_field() & 7) << KEY_SEW_SH) |
			  ((u64)(vt.vlmul_field() & 7) << KEY_LMUL_SH) |
			  ((u64)(vt.vill() ? 1 : 0) << KEY_VILL_SH) |
			  ((u64)(vl & 0x7ff) << KEY_VL_SH) |
			  ((u64)(vt.vta() ? 1 : 0) << KEY_VTA_SH) |
			  ((u64)(vt.vma() ? 1 : 0) << KEY_VMA_SH);
		Cell *c = lookup(key);
		g_total_calls++;
		g_total_cycles += dt;
		if (!c)
			return;
		if (c->example == 0)
			c->example = raw;
		c->calls++;
		c->cycles += dt;
		if (!is_cfg) {
			// REQUESTED vs COMPLETED element work. A fault-only-first load may TRUNCATE
			// vl: the architectural result is that only the first `vl_post` elements were
			// transferred. Charging the pre-vl would overstate the work done, and
			// charging only the post-vl would hide the fact that the operation was issued
			// for more. Both are kept; for every family except vle<EEW>ff.v they are equal
			// by construction, which the analysis asserts rather than assumes.
			u32 const vl_done = vs->vl < vl ? vs->vl : vl;
			if (vs->vl != vl)
				g_vl_truncated++;
			c->elems += vl;
			c->elems_done += vl_done;
			c->active += active_pre;
		}
	}
};

// ---------------------------------------------------------------------------------------------
// Phase-B probes. Default off, and they NEVER change behaviour -- they evaluate a candidate's
// precondition and record whether it would have held, so a candidate can be falsified before any
// lowering is written. Enabled by `--rvv-probe`, independently of `--rvv-census`.
//
//   probe bit 1  per-PC census: (guest pc, raw) -> calls, elems. Combined with a static
//                basic-block decomposition of the guest ELF this answers B2's question --
//                what fraction of dynamic vector operand reads are produced by an earlier
//                vector instruction in the SAME translation block.
//   probe bit 2  B1's FP predicate: for every OPFVV/OPFVF instruction, are any of the vector
//                source elements NaN? Evaluated generically from the encoding and vtype, so it
//                needs no per-helper hook. (The .vf scalar operand lives in an F register and
//                is not visible here; it is counted separately as `fp_scalar_unchecked`.)
// ---------------------------------------------------------------------------------------------

struct PcCell {
	u64 key; // (pc << 32) | 1  -- nonzero for an occupied slot
	u32 raw;
	u32 _pad;
	u64 calls;
	u64 elems;
};
static constexpr u32 PC_TABLE_BITS = 14;
static constexpr u32 PC_TABLE_SIZE = 1u << PC_TABLE_BITS;
inline PcCell g_pc_table[PC_TABLE_SIZE];
inline u64 g_pc_overflow = 0;

// B1 FP predicate outcome counters.
inline u64 g_fp_ops = 0;	    // OPFVV/OPFVF instructions seen
inline u64 g_fp_ops_clean = 0;	    // ... with no NaN in any vector source element
inline u64 g_fp_elems = 0;	    // element positions inspected
inline u64 g_fp_elems_nan = 0;	    // ... that were NaN
inline u64 g_fp_scalar_unchecked = 0; // .vf forms whose scalar operand this probe cannot see

ALWAYS_INLINE void probe_pc(u32 pc, u32 raw, u32 vl)
{
	u64 const key = ((u64)pc << 32) | 1;
	u32 idx = (u32)((key * 0x9e3779b97f4a7c15ull) >> (64 - PC_TABLE_BITS));
	for (u32 probe = 0; probe < 64; probe++) {
		PcCell &c = g_pc_table[(idx + probe) & (PC_TABLE_SIZE - 1)];
		if (c.key == 0) {
			c.key = key;
			c.raw = raw;
		}
		if (c.key == key) {
			c.calls++;
			c.elems += vl;
			return;
		}
	}
	g_pc_overflow++;
}

ALWAYS_INLINE bool elem_is_nan(VectorState &vs, u32 reg, u32 e, u32 sew_bytes, u32 vlen)
{
	u64 const b = vs.elem_u(reg, e, sew_bytes, vlen);
	if (sew_bytes == 4)
		return ((u32)b & 0x7f800000u) == 0x7f800000u && ((u32)b & 0x007fffffu) != 0;
	if (sew_bytes == 8)
		return (b & 0x7ff0000000000000ull) == 0x7ff0000000000000ull &&
		       (b & 0x000fffffffffffffull) != 0;
	return false; // SEW 8/16 are not IEEE formats this substrate computes in
}

// Evaluate B1's FP precondition WITHOUT acting on it.
inline void probe_fp(VectorState &vs, u32 insn_raw, u32 vl, u32 sew_bytes)
{
	u32 const opcode = insn_raw & 0x7f, funct3 = (insn_raw >> 12) & 0x7;
	if (opcode != 0x57 || (funct3 != 0b001 && funct3 != 0b101))
		return;
	bool const is_vv = funct3 == 0b001;
	u32 const vs2 = (insn_raw >> 20) & 0x1f, vs1 = (insn_raw >> 15) & 0x1f;
	g_fp_ops++;
	if (!is_vv)
		g_fp_scalar_unchecked++;
	bool clean = true;
	for (u32 e = 0; e < vl; e++) {
		g_fp_elems++;
		bool nan = elem_is_nan(vs, vs2, e, sew_bytes, config::vlen_bits);
		if (is_vv)
			nan = nan || elem_is_nan(vs, vs1, e, sew_bytes, config::vlen_bits);
		if (nan) {
			g_fp_elems_nan++;
			clean = false;
		}
	}
	if (clean)
		g_fp_ops_clean++;
}

// Single entry point called from the HANDLER macro before the handler body runs, so the FP
// predicate sees the operands the instruction will actually consume.
ALWAYS_INLINE void probe_one(VectorState &vs, u32 pc, u32 insn_raw)
{
	VType const vt{vs.vtype};
	u32 const vl = vs.vl;
	if (config::rvv_probe & 1)
		probe_pc(pc, insn_raw, vl);
	if ((config::rvv_probe & 2) && !vt.vill())
		probe_fp(vs, insn_raw, vl, vt.sew() / 8);
}

inline void probe_dump(char const *path)
{
	FILE *f = (path && path[0]) ? std::fopen(path, "w") : stderr;
	if (!f)
		f = stderr;
	std::fprintf(f,
		     "# rvv_probe v1 pc_overflow=%llu fp_ops=%llu fp_ops_clean=%llu fp_elems=%llu "
		     "fp_elems_nan=%llu fp_scalar_unchecked=%llu\n",
		     (unsigned long long)g_pc_overflow, (unsigned long long)g_fp_ops,
		     (unsigned long long)g_fp_ops_clean, (unsigned long long)g_fp_elems,
		     (unsigned long long)g_fp_elems_nan,
		     (unsigned long long)g_fp_scalar_unchecked);
	std::fprintf(f, "pc,raw,calls,elems\n");
	for (u32 i = 0; i < PC_TABLE_SIZE; i++) {
		PcCell const &c = g_pc_table[i];
		if (!c.key || !c.calls)
			continue;
		std::fprintf(f, "%08x,%08x,%llu,%llu\n", (u32)(c.key >> 32), c.raw,
			     (unsigned long long)c.calls, (unsigned long long)c.elems);
	}
	if (f != stderr)
		std::fclose(f);
	std::fprintf(stderr,
		     "RVV_PROBE pc_cells_overflow=%llu fp_ops=%llu clean=%llu (%.4f%%) "
		     "fp_elems=%llu nan=%llu\n",
		     (unsigned long long)g_pc_overflow, (unsigned long long)g_fp_ops,
		     (unsigned long long)g_fp_ops_clean,
		     g_fp_ops ? 100.0 * (double)g_fp_ops_clean / (double)g_fp_ops : 0.0,
		     (unsigned long long)g_fp_elems, (unsigned long long)g_fp_elems_nan);
}

// Dimensionally-matched overhead of the timestamp pair alone: exactly the sequence that brackets
// the handler, executed back to back with nothing in between. This -- NOT the whole-scope cost --
// is what may be subtracted from `Cell::cycles`.
inline double calibrate_pair()
{
	u32 const kIter = 200000;
	u64 acc = 0;
	for (u32 i = 0; i < kIter; i++) {
		u64 const a = ts_open();
		acc += ts_close() - a;
	}
	return (double)acc / (double)kIter;
}

// Whole-scope cost: key build + table probe + mask scan + the timestamp pair. This is the
// per-instruction inflation of WHOLE-RUN time under mode 2, and is reported so the difference
// between a mode-0 run and a mode-2 run is explainable. It is NOT subtracted from `Cell::cycles`,
// because most of it lies outside the measured interval.
inline double calibrate_scope()
{
	static VectorState probe_state;
	probe_state.vtype = 0xd0; // e32, m1, ta, ma -- a real vtype, not a guess
	probe_state.vl = 4;
	u32 const kFakeRaw = 0x02848457; // vadd.vv v8,v8,v9 -- a real encoding
	int const fam = intern("__calibration");
	u32 const saved = config::rvv_census;
	u64 const saved_calls = g_total_calls, saved_cycles = g_total_cycles;
	config::rvv_census = 2;
	u32 const kIter = 200000;
	u64 const a = __rdtsc();
	for (u32 i = 0; i < kIter; i++) {
		Scope sc(fam, probe_state, kFakeRaw);
		sc.finish();
	}
	u64 const b = __rdtsc();
	config::rvv_census = saved;
	g_total_calls = saved_calls;
	g_total_cycles = saved_cycles;
	return (double)(b - a) / (double)kIter;
}

// Calibration runs at START, not at dump time, and then wipes everything it touched.
//
// Calibrating at the end wrote 200 000 synthetic invocations into the live table and left a
// `__calibration` family with its own vl in the output -- the validation gate caught exactly
// that. Running first and clearing afterwards keeps the measured cost faithful (same machine,
// same code path, same table) while guaranteeing the dumped table contains only guest work.
inline void start()
{
	if (config::rvv_census >= 2) {
		g_pair_cycles = calibrate_pair();
		g_scope_cycles = calibrate_scope();
	}
	std::memset(g_table, 0, sizeof(g_table));
	g_family_n = 0;
	g_overflow = g_vstart_nz = g_vl_truncated = g_total_calls = g_total_cycles = 0;
	g_t0 = __rdtsc();
}

// CSV to `path`, or to stderr when `path` is empty. One row per occupied cell; the header block
// carries everything needed to interpret it without reading this file.
// `direct_hits` / `direct_fallbacks` are the inline-QCG counters, incremented by JIT-EMITTED
// code and therefore invisible to this hook. They are printed here because a census that silently
// omitted them would under-report exactly the operations the direct path already handles -- which
// is how the first validation run appeared to lose 5000 `vadd.vv`. With --rvv-direct 0 they are
// zero by construction and the helper hook sees everything.
inline void dump(char const *path, u32 vlen_bits, u64 direct_hits, u64 direct_fallbacks)
{
	u64 const t_end = __rdtsc();
	// pair_cycles is dimensionally identical to Cell::cycles and may be subtracted as
	// calls * pair_cycles. scope_cycles is the whole-run inflation and MUST NOT be.
	double const pair = g_pair_cycles, scope = g_scope_cycles;
	FILE *f = (path && path[0]) ? std::fopen(path, "w") : stderr;
	if (!f)
		f = stderr;
	std::fprintf(f, "# rvv_census v3 mode=%u vlen=%u run_cycles=%llu census_calls=%llu "
			"census_cycles=%llu overflow=%llu vstart_nz=%llu vl_truncated=%llu "
			"pair_cycles=%.2f scope_cycles=%.2f direct_inline_hits=%llu "
			"direct_guard_fallbacks=%llu\n",
		     config::rvv_census, vlen_bits, (unsigned long long)(t_end - g_t0),
		     (unsigned long long)g_total_calls, (unsigned long long)g_total_cycles,
		     (unsigned long long)g_overflow, (unsigned long long)g_vstart_nz,
		     (unsigned long long)g_vl_truncated, pair, scope,
		     (unsigned long long)direct_hits, (unsigned long long)direct_fallbacks);
	std::fprintf(f, "family,opcode,funct6,funct3,rs2f,vm,vta,vma,vill,sew,lmul_field,vl,calls,"
			"elems,elems_done,active,cycles,example_raw\n");
	for (u32 i = 0; i < TABLE_SIZE; i++) {
		Cell const &c = g_table[i];
		if (c.key == 0 || c.calls == 0)
			continue;
		u32 const fam = (u32)((c.key >> KEY_FAM_SH) & 0xff) - 1;
		u32 const f6 = (u32)((c.key >> KEY_F6_SH) & 0x3f);
		u32 const f3 = (u32)((c.key >> KEY_F3_SH) & 0x7);
		u32 const rs2f = (u32)((c.key >> KEY_RS2_SH) & 0x1f);
		u32 const sew = (u32)((c.key >> KEY_SEW_SH) & 0x7);
		u32 const lmul = (u32)((c.key >> KEY_LMUL_SH) & 0x7);
		u32 const vm = (u32)((c.key >> KEY_VM_SH) & 1);
		u32 const vill = (u32)((c.key >> KEY_VILL_SH) & 1);
		u32 const vl = (u32)((c.key >> KEY_VL_SH) & 0x7ff);
		u32 const vta = (u32)((c.key >> KEY_VTA_SH) & 1);
		u32 const vma = (u32)((c.key >> KEY_VMA_SH) & 1);
		char const *nm = (fam < g_family_n) ? g_family[fam] : "?";
		std::fprintf(f, "%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%08x\n",
			     nm, (u32)(c.example & 0x7f), f6, f3, rs2f, vm, vta, vma, vill, 8u << sew,
			     lmul, vl,
			     (unsigned long long)c.calls, (unsigned long long)c.elems,
			     (unsigned long long)c.elems_done, (unsigned long long)c.active,
			     (unsigned long long)c.cycles, c.example);
	}
	if (f != stderr)
		std::fclose(f);
	std::fprintf(stderr,
		     "RVV_CENSUS mode=%u calls=%llu cycles=%llu run_cycles=%llu overflow=%llu "
		     "families=%u pair_cycles=%.2f scope_cycles=%.2f direct_inline_hits=%llu "
		     "vl_truncated=%llu out=%s\n",
		     config::rvv_census, (unsigned long long)g_total_calls,
		     (unsigned long long)g_total_cycles, (unsigned long long)(t_end - g_t0),
		     (unsigned long long)g_overflow, g_family_n, pair, scope,
		     (unsigned long long)direct_hits, (unsigned long long)g_vl_truncated,
		     (path && path[0]) ? path : "(stderr)");
}

} // namespace dbt::rv32::rvv_census
