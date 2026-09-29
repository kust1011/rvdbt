#pragma once

// P13 Phase A: fail-closed dynamic RVV sequence collector.
//
// ============================================================================================
// FOURTH correction: THIS IS AN ORDERED VECTOR-EVENT TRACE, NOT A COMPLETE INSTRUCTION STREAM.
// ============================================================================================
// Falsified by direct evidence after commit 8a42eb736: a real run of gemm_mini.elf produced
// gap_count == 0 for all 464 vector events combined, even though the guest's own static
// disassembly has scalar li/lw/mv/addi between several of them (e.g. PCs 0x11210/14/18 between
// the vector events at 0x1120c and 0x1121c). Root cause, confirmed architecturally (not just
// empirically) against dbt/guest/rv32_stubs.h's GUEST_RUNTIME_STUBS list: the QCG JIT lowers
// basic scalar integer arithmetic, loads/stores, and branches -- add/sub/and/or/xor/the shifts/
// slt*/lb/lh/lw/sb/sh/sw/beq/bne/blt/bge/bltu/bgeu/jal/jalr/lui/auipc -- to NATIVE inline host
// code and never calls back through HBody_##name for them once a block is JIT-compiled, which is
// the normal state for any block hot enough to matter. record() is only ever reached for the 93
// opcodes GUEST_RUNTIME_STUBS names: every RVV instruction (which is why the VECTOR side of this
// trace remains reliable -- see below), the M extension, CSR ops, AMO, scalar F/D, and a handful
// of control instructions (fence/ecall/ebreak/mret). The base integer ISA -- the overwhelming
// majority of a strip-mined loop's non-vector instructions -- is invisible to this hook by
// construction, not by a bug that a different placement of the SAME hook could fix.
//
// WHAT REMAINS TRUE. Every vector instruction IS stubbed (confirmed both by the exhaustive
// GUEST_RUNTIME_STUBS list and empirically: the smoke-tested trace's vector-event count matched
// the independently-computed census call count exactly, 464 == 464, in the same run), so the
// ORDERED SEQUENCE of vector events -- their exact 12-field keys, funct6/funct3/vm/sew/vl, and
// the read_mask/write_mask register DAG -- remains valid and is this file's real contribution.
// What is NOT valid is anything derived from GAP records: gap_count, any_branch, any_may_trap on
// a gap systematically UNDERCOUNT (frequently to exactly zero) once code tiers to JIT, and must
// never be read as a scalar instruction count, a dependency-chain distance, or evidence that
// nothing happened between two vector events. scripts/seqtrace_join.py and any future analysis
// MUST ignore gap_count for anything quantitative; the gap mechanism is kept in the code only
// because it is still exact during pure interpretation (DBT_USE_INTERP builds) and costs nothing
// extra to leave in.
//
// THE CORRECT WAY TO RECOVER INTERVENING SCALAR INSTRUCTIONS (not yet built): join the vector
// event PCs this trace DOES reliably capture against the guest's own static disassembly and
// control-flow graph, exactly as scripts/b2_dataflow.py already does for a related question --
// enumerate the static instructions between two consecutive vector-event PCs when the dynamic
// path between them is unambiguous (pc_next > pc_cur with no known branch target landing between
// them), and mark it explicitly UNRESOLVED when it is not (a backward branch closing a loop, or
// any control-flow join). Full raw/U/SEQTRACE_GAP_FALSIFICATION.md.
// ============================================================================================
//
// THIRD correction pass (still valid; superseded only on the GAP question above). Round 2's
// review found six further defects in the version that never ran; every one is fixed here and
// cited at its exact location so a future edit cannot silently regress one:
//   A. the trace could not reconstruct the census's exact cell key (missing opcode, rs2f, vta,
//      vma, vill, lmul_field) -- fixed by RECORDING ALL TWELVE KEY FIELDS, see Rec below;
//   B. masked instructions read v0 as the predicate and the read_mask did not include it --
//      fixed by mask_predicate_family() and the uniform application in record();
//   C. only the 26 dynamically-observed families had a verified schema -- kept fail-closed for
//      the rest (per the review's own "keep unknown fail-closed now"), but
//      scripts/gen_handler_coverage.py now generates and enforces a coverage manifest against
//      every HANDLER(...) in rv32_interp.cpp, not just the ones this corpus happens to exercise;
//   D. base register numbers alone cannot describe NF/EMUL-dependent families -- the ones this
//      round has NOT verified (segmented, fault-only-first, mask load/store, slides, gathers,
//      widening/narrowing beyond vfcvt) are covered by explicit unknown-schema tests in
//      test_seqtrace.cpp rather than a silent guess;
//   E. g_n incremented past CAP without bound, risking u32 wraparound and buffer corruption on a
//      long run -- fixed by saturating: push() stops incrementing once capped;
//   F. dump() returned void and swallowed an fopen failure -- fixed: dump() returns bool and
//      prints a FATAL line to stderr on failure; the caller (dbt/elfrun.cpp) exits nonzero.
//
// WHY A NEW HOOK, NOT --rvv-probe's per-PC census. The per-PC census gives dynamic COUNTS per
// instruction but not ORDER: it cannot say whether the instruction at PC p1 was, in one specific
// dynamic execution, immediately followed by the instruction at PC p2. Producer-consumer reuse
// distance and consecutive-run length are properties of a genuine ORDERED trace.
//
// SCOPE. A bounded window of the dynamic VECTOR-EVENT stream (see the correction block above for
// why "vector-event", not "instruction", is the accurate word) starting at the first vector
// instruction (see the pre-vector skip in record()), capped explicitly at RVDBT_SEQTRACE_CAP
// records and reported as capped in the dump header rather than silently truncated. This corpus's
// kernels are tight, repetitive loops, so a bounded window is sufficient to characterise the
// STRUCTURAL pattern of the repeating steady state; it is not a claim about total dynamic
// instruction count even for the part it does capture reliably. The corpus-wide COST WEIGHT for
// whatever pattern this finds comes from the already-validated per-key census
// (raw/U/u1_analysis_v512/), joined by the full 12-field exact key in scripts/seqtrace_join.py --
// never from this trace's own instruction or record counts.
//
// WHY RAW-BIT EXTRACTION, NOT THE TYPED insn::Insn_##name ACCESSORS. This hook is called from
// inside the SHARED HANDLER macro, once per opcode, so it must compile identically for every
// instruction type. RVV's OP-V major opcode gives every vector instruction the SAME field layout
// (vm at bit 25, funct6 at bits 31:26, funct3 at bits 14:12, vd at bits 11:7, vs1 at bits 19:15,
// vs2 at bits 24:20) regardless of the operation -- the same fact rv32_vector_census.h's Scope
// constructor already exploits -- so every field is extracted by masking `insn_raw`, which
// compiles unconditionally for any u32 and needs no per-type accessor.
//
// EXPLICIT PER-FAMILY OPERAND-ROLE SCHEMA. `family_regmask()` enumerates, for every vector family
// this round's formal census has actually observed executing (raw/U/u1_analysis_v512/
// U1_RESIDUAL_BY_RAWKEY.csv: vadd_vv, vfalu, vfcmp, vfcvt, vfma, vfmerge, vfmvfs, vfmvsf, vfred,
// vialu, vicmp, vid, vimul, vlNre, vle, vlse, vlxei, vmerge, vmlogic, vmvNr, vmvsx, vsNr, vse,
// vsetivli, vsetvli, vsse) plus three cheap, verified additions with an identical operand shape
// to vialu (vsatadd, vavg, vsmul -- rv32_interp.cpp:949-1023) and the five decoder splits whose
// encodings ALREADY belonged to a listed family and whose shape is therefore that family's
// (vmul_vv out of vimul, and vsub_vv, vxor_vv, vor_vv, vand_vv out of vialu), the EXACT registers each operand
// reads or writes, verified against that family's own handler body (cited per family below) and
// against dbt/guest/rv32_vector.h's own EMUL/EEW arithmetic (compute_emul_log2, emul_group_regs,
// eew_log2_from_width, reg_group_legal) -- called directly, not re-derived, so this cannot drift
// from the interpreter's own legality logic. A family NOT in this table returns
// `schema_known = false` with BOTH masks zero AND a distinct `unknown_schema` flag set, which is
// different from "this instruction genuinely touches no vector registers" (also both masks zero,
// but `unknown_schema` clear) -- scripts/seqtrace_join.py rejects (excludes from any Bound-C or
// DAG opportunity claim) every record with `unknown_schema` set, never silently treats it as zero
// contribution.
#include "dbt/config.h"
#include "dbt/guest/rv32_insn.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/util/common.h"

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace dbt::rv32::seqtrace
{

#ifndef RVDBT_SEQTRACE
#define RVDBT_SEQTRACE 0
#endif
static constexpr bool kEnabled = RVDBT_SEQTRACE != 0;

#ifndef RVDBT_SEQTRACE_CAP
#define RVDBT_SEQTRACE_CAP 4000000
#endif
static constexpr u32 CAP = RVDBT_SEQTRACE_CAP;

constexpr bool name_is_vector(char const *s) { return s[0] == 'v'; }

constexpr bool streq(char const *a, char const *b)
{
	while (*a && *b && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

// ---------------------------------------------------------------------------------------------
// Load/store family membership. `name[2]=='s'` (an earlier, WRONG shortcut) misclassified vse
// itself -- v-s-e has 'e' at index 2, not 's' -- plus vlse, vsxei, vsNr, vlseg/vsseg, vsm.
// Verified against every handler named below.
// ---------------------------------------------------------------------------------------------
constexpr bool is_load_family(char const *s)
{
	char const *const names[] = {"vle", "vlse", "vlxei", "vlNre", "vleff", "vlseg", "vlm"};
	for (char const *n : names)
		if (streq(s, n))
			return true;
	return false;
}
constexpr bool is_store_family(char const *s)
{
	char const *const names[] = {"vse", "vsse", "vsxei", "vsNr", "vsseg", "vsm"};
	for (char const *n : names)
		if (streq(s, n))
			return true;
	return false;
}
constexpr bool is_vecmem_family(char const *s) { return is_load_family(s) || is_store_family(s); }
constexpr bool is_vset_family(char const *s)
{
	return streq(s, "vsetvli") || streq(s, "vsetivli") || streq(s, "vsetvl");
}

// ---------------------------------------------------------------------------------------------
// Exactly the seven OP-V funct3 forms. An earlier, WRONG version tested `funct3 != 100 &&
// funct3 != 101` for "vs1 is a vector register", which wrongly included 011 (OPIVI, vs1 is an
// immediate) and 110 (OPMVX, vs1 is a GPR). This is an INCLUSION list of the three vector-sourced
// forms, not an exclusion of the other four -- rv32_interp.cpp:667-678's own comment on
// rvv_src_of makes exactly this point about the two-way-test mistake.
//   000 OPIVV  001 OPFVV  010 OPMVV  -- vs1 is a vector register
//   011 OPIVI  100 OPIVX  101 OPFVF  110 OPMVX  -- vs1 is an immediate, GPR, GPR, or FPR
// This determination is encoding-level and uniform across every arithmetic family; which of the
// seven forms is a legal encoding for a GIVEN family was already checked by the decoder before
// any handler runs, so no per-family override is needed for it.
// ---------------------------------------------------------------------------------------------
constexpr bool funct3_vs1_is_vector(u32 funct3)
{
	return funct3 == 0b000 || funct3 == 0b001 || funct3 == 0b010;
}

// ---------------------------------------------------------------------------------------------
// v0 as an implicit predicate READ when vm==0 (review round 2, defect B). RVV masks apply to
// almost every instruction via v0.t; the exceptions are the families that have NO mask concept
// at all regardless of the raw vm bit's value, verified from their handler bodies not referencing
// i.vm() anywhere: whole-register move/load/store (rv32_interp.cpp:1423-1449, spec: whole-register
// instructions are always unmasked), the single-element scalar<->vector moves
// (rv32_interp.cpp:787-805, 1386-1409, none read i.vm()), mask-register logic
// (rv32_interp.cpp:724-729, "never masked"), and the vset* config family (no mask concept at all).
// Every other family in the table DOES reference i.vm() in its handler and therefore reads v0
// when vm==0 -- including vmerge/vfmerge, where vm==0 selects the "vmerge" alias and v0 is READ
// as the selector, which is the same fact under a different name.
// ---------------------------------------------------------------------------------------------
constexpr bool family_never_masked(char const *s)
{
	char const *const names[] = {"vmvNr", "vlNre", "vsNr",	  "vmvsx",     "vmvxs",
				     "vfmvfs", "vfmvsf", "vmlogic", "vsetvli",   "vsetivli",
				     "vsetvl"};
	for (char const *n : names)
		if (streq(s, n))
			return true;
	return false;
}

static constexpr u32 ALL32 = 0xffffffffu;

inline u32 group_mask(u32 base, i32 emul_log2)
{
	u32 const n = emul_group_regs(emul_log2); // dbt/guest/rv32_vector.h -- the interpreter's own
	return (n >= 32) ? ALL32 : (((1u << n) - 1u) << base);
}
inline u32 nreg_mask(u32 base, u32 nregs) { return ((1u << nregs) - 1u) << base; }
inline u32 single_mask(u32 base) { return 1u << base; }
inline u32 v0_mask() { return 1u; }

struct RegRoles {
	bool schema_known;
	u32 read_mask;	// every vector register READ, unioned (0 if none or unknown) -- v0 NOT
			// included yet here; record() adds it uniformly per family_never_masked()
	u32 write_mask; // every vector register WRITTEN, unioned (0 if none or unknown)
};

// The per-family table. `insn_raw` and `vt` (the vtype IN EFFECT WHEN THE OPERANDS ARE READ --
// i.e. pre-state; vset*'s post-state is applied by the caller) are both needed because EMUL
// depends on vtype and the width/nf sub-fields live in insn_raw at positions the census key does
// not carry.
inline RegRoles family_regmask(char const *name, u32 insn_raw, VType vt)
{
	u32 const funct3 = (insn_raw >> 12) & 0x7;
	u32 const vd_f = (insn_raw >> 7) & 0x1f;
	u32 const vs1_f = (insn_raw >> 15) & 0x1f;
	u32 const vs2_f = (insn_raw >> 20) & 0x1f;
	bool const vm = ((insn_raw >> 25) & 1) != 0;
	i32 const lmul = vt.lmul_log2();
	bool const vs1_is_vec = funct3_vs1_is_vector(funct3);

	// ---- plain element-wise arithmetic: vd, vs2 always groups @ LMUL; vs1 a group @ LMUL only
	// in the .vv/.vfvv/.vmvv form. vsatadd/vavg/vsmul share vialu's exact shape
	// (rv32_interp.cpp:686-706, 949-1023). --------------------------------------------------
	if (streq(name, "vialu") || streq(name, "vimul") || streq(name, "vadd_vv") ||
	    streq(name, "vmul_vv") || streq(name, "vsub_vv") || streq(name, "vxor_vv") ||
	    streq(name, "vor_vv") || streq(name, "vand_vv") ||
	    // P7N-B: the two OPIVI logical-shift splits share vialu's EXACT shape. `vs1_is_vec` is
	    // already false for funct3 == 0b011, so the immediate in the rs1 field is correctly not
	    // counted as a read vector register -- the same rule that already handles vialu's own
	    // OPIVI encodings.
	    streq(name, "vsll_vi") || streq(name, "vsrl_vi") || streq(name, "vsatadd") ||
	    // A6: the OPIVX/OPIVI add splits share vialu's exact shape too (rs1 is a GPR / an imm).
	    streq(name, "vadd_vx") || streq(name, "vadd_vi") ||
	    streq(name, "vavg") || streq(name, "vsmul")) {
		u32 r = group_mask(vs2_f, lmul) | (vs1_is_vec ? group_mask(vs1_f, lmul) : 0);
		return {true, r, group_mask(vd_f, lmul)};
	}
	if (streq(name, "vfalu")) { // is_vf <=> funct3==0b101, the only non-.vv form FP has
		u32 r = group_mask(vs2_f, lmul) | (funct3 != 0b101 ? group_mask(vs1_f, lmul) : 0);
		return {true, r, group_mask(vd_f, lmul)};
	}
	if (streq(name, "vfma")) { // reads vd too (fused multiply-ADD accumulates into it)
		u32 r = group_mask(vs2_f, lmul) | group_mask(vd_f, lmul) |
			(funct3 != 0b101 ? group_mask(vs1_f, lmul) : 0);
		return {true, r, group_mask(vd_f, lmul)};
	}
	// ---- compare: vd is a SINGLE mask register, never a group (rv32_interp.cpp:708-721) ------
	if (streq(name, "vicmp") || streq(name, "vfcmp")) {
		bool const is_vf = streq(name, "vfcmp") ? (funct3 == 0b101) : !vs1_is_vec;
		u32 r = group_mask(vs2_f, lmul) | (is_vf ? 0 : group_mask(vs1_f, lmul));
		return {true, r, single_mask(vd_f)};
	}
	// ---- merge: vs2 read only when vm==0 (vmerge form, not vmv.v.*); vfmerge's vs1 is always
	// an FPR (rv32_interp.cpp:731-749, 1371 comment: "vs2 must be v0 ... and is not read" for
	// the vmv.v.* alias, and vfmerge has no .vv encoding at all) -----------------------------
	if (streq(name, "vmerge")) {
		u32 r = (vm ? 0 : group_mask(vs2_f, lmul)) | (vs1_is_vec ? group_mask(vs1_f, lmul) : 0);
		return {true, r, group_mask(vd_f, lmul)};
	}
	if (streq(name, "vfmerge")) {
		u32 r = vm ? 0 : group_mask(vs2_f, lmul); // vs1 is always fpu.f[rs1], never vector
		return {true, r, group_mask(vd_f, lmul)};
	}
	// ---- mask-register logic: all single, never groups, never masked (rv32_interp.cpp:723) --
	if (streq(name, "vmlogic"))
		return {true, single_mask(vs2_f) | single_mask(vs1_f), single_mask(vd_f)};
	// ---- reduction: vs2 a group @ LMUL, vd/vs1 single registers (rv32_interp.cpp:777-785) ---
	if (streq(name, "vred") || streq(name, "vfred"))
		return {true, group_mask(vs2_f, lmul) | single_mask(vs1_f), single_mask(vd_f)};
	// ---- vid: writes a group, reads no vector source (rv32_interp.cpp:751-759) --------------
	if (streq(name, "vid"))
		return {true, 0, group_mask(vd_f, lmul)};
	// ---- scalar<->vector element-0 moves (rv32_interp.cpp:787-805, 1386-1409) ---------------
	if (streq(name, "vmvsx") || streq(name, "vfmvsf")) // GPR/FPR -> vd, single, element 0
		return {true, 0, single_mask(vd_f)};
	if (streq(name, "vmvxs") || streq(name, "vfmvfs")) // vs2 (single, element 0) -> GPR/FPR
		return {true, single_mask(vs2_f), 0};
	// ---- convert: vd/vs2 groups, possibly at DIFFERENT EMUL for widening/narrowing forms; vs1
	// FIELD holds the VFUNARY0 sub-opcode, never a register (rv32_interp.cpp:1306-1343) -------
	if (streq(name, "vfcvt")) {
		u32 const sub = vs1_f; // VFUNARY0 sub-encoding, rv32_interp.cpp:1310
		bool const widen = vfcvt_is_widening(sub);   // dbt/guest/rv32_vector_lower.h:845
		bool const narrow = vfcvt_is_narrowing(sub); // dbt/guest/rv32_vector_lower.h:846
		i32 const dlmul = widen ? lmul + 1 : lmul;
		i32 const slmul = narrow ? lmul + 1 : lmul;
		return {true, group_mask(vs2_f, slmul), group_mask(vd_f, dlmul)};
	}
	// ---- whole-register move/load/store: nregs in {1,2,4,8}, NOT LMUL-scaled ----------------
	if (streq(name, "vmvNr")) {
		u32 const nregs = ((insn_raw >> 15) & 0x1f) + 1; // vs1 field carries nr-1
		return {true, nreg_mask(vs2_f, nregs), nreg_mask(vd_f, nregs)};
	}
	if (streq(name, "vlNre")) {
		u32 const nregs = ((insn_raw >> 29) & 0x7) + 1;
		return {true, 0, nreg_mask(vd_f, nregs)}; // vs1(rs1) is a scalar base address
	}
	if (streq(name, "vsNr")) {
		u32 const nregs = ((insn_raw >> 29) & 0x7) + 1;
		return {true, nreg_mask(vd_f, nregs), 0}; // rd field holds vs3, the SOURCE, not a dest
	}
	// ---- unit-stride / strided memory: EMUL from EEW (compute_emul_log2), not from LMUL
	// directly; vs1(rs1) is always a scalar base address (rv32_interp.cpp:428-478) -----------
	if (streq(name, "vle") || streq(name, "vlse")) {
		i32 const eew_log2 = eew_log2_from_width(funct3);
		if (eew_log2 < 0)
			return {false, 0, 0};
		return {true, 0, group_mask(vd_f, compute_emul_log2(vt, (u32)eew_log2))};
	}
	if (streq(name, "vse") || streq(name, "vsse")) {
		i32 const eew_log2 = eew_log2_from_width(funct3);
		if (eew_log2 < 0)
			return {false, 0, 0};
		// "rd field holds vs3 for stores" -- rv32_interp.cpp:453,606: a READ, not a write.
		return {true, group_mask(vd_f, compute_emul_log2(vt, (u32)eew_log2)), 0};
	}
	// ---- indexed: data operand @ LMUL (EEW==SEW for data), index operand (the vs2 FIELD) at
	// its OWN emul from the width field (rv32_interp.cpp:511-546) ----------------------------
	if (streq(name, "vlxei")) {
		i32 const idx_eew_log2 = eew_log2_from_width(funct3);
		if (idx_eew_log2 < 0)
			return {false, 0, 0};
		return {true, group_mask(vs2_f, compute_emul_log2(vt, (u32)idx_eew_log2)),
			group_mask(vd_f, lmul)};
	}
	if (streq(name, "vsxei")) {
		i32 const idx_eew_log2 = eew_log2_from_width(funct3);
		if (idx_eew_log2 < 0)
			return {false, 0, 0};
		return {true,
			group_mask(vs2_f, compute_emul_log2(vt, (u32)idx_eew_log2)) |
			    group_mask(vd_f, lmul), // rd = vs3, the data source, a READ
			0};
	}
	// ---- config: writes a GPR, never a vector register --------------------------------------
	if (is_vset_family(name))
		return {true, 0, 0};
	return {false, 0, 0}; // NOT in the verified table -- see the header comment
}

// ---------------------------------------------------------------------------------------------
// Trace record. One per VECTOR instruction -- reliably complete, see the correction block at the
// top of this file -- plus one GAP record per maximal run of intervening non-vector instructions
// that ALSO happened to reach this hook (interpreter tier, or one of GUEST_RUNTIME_STUBS' small
// number of non-vector stubbed opcodes: M-extension, CSR, AMO, scalar F/D, fence/ecall/ebreak/
// mret). Once code is JIT-compiled the base scalar integer ISA bypasses this hook entirely, so a
// GAP record's count is a floor on intervening activity, not a measurement of it, and is
// frequently exactly zero even when real scalar instructions executed there.
//
// KEY FIELDS (review round 2, defect A): pc/name/funct6/funct3/vm/sew/vl/opcode/rs2f/vta/vma/
// vill/lmul_field are exactly the twelve fields rv32_vector_census.h's cell key hashes on, spelled
// out rather than packed, because scripts/seqtrace_join.py joins by this exact tuple against the
// census CSV's own decoded columns (family,opcode,funct6,funct3,rs2f,vm,vta,vma,vill,sew,
// lmul_field,vl) -- never against the packed u64, whose family sub-field is an intern() index
// that depends on this RUN's own execution order and cannot be expected to match a different run.
// ---------------------------------------------------------------------------------------------
struct Rec {
	u32 pc;
	u16 name_id;
	u8 flags; // bit0 is_vector, 1 is_branch, 2 may_trap, 3 is_vecmem, 4 is_vset,
		  // 5 unknown_schema, 6 is_gap (a compressed non-vector run, not a real instruction)
	u8 opcode;   // insn_raw & 0x7f
	u8 funct6;
	u8 funct3;
	u8 rs2f;     // vs2 field AS AN OPCODE EXTENSION -- only nonzero for unit-stride mem lumop/sumop
	u8 vm;
	u8 vta, vma, vill;
	u8 lmul_field; // vtype.vlmul, the raw 3-bit signed-log2 encoding
	u8 sew;	     // architectural SEW in BITS; 0 = n/a
	u16 vl;
	u32 read_mask, write_mask; // vector registers v0..v31; both 0 for a gap record
	u32 gap_count;		   // meaningful only when is_gap: instructions compressed into it
	// vset* PRE-state (meaningful only when is_vset; all other fields above already hold the
	// POST/produced state, matching the census convention that a config instruction is keyed on
	// what it produces): lets a caller tell whether a vsetvli changed anything at all.
	u16 vl_pre;
	u8 sew_pre, lmul_pre, vta_pre, vma_pre, vill_pre;
};
static_assert(sizeof(Rec) <= 40);

inline Rec g_buf[kEnabled ? CAP : 1];
inline u32 g_n = 0; // NOT atomic: the interpreter loop that calls record() is single-threaded,
		    // exactly like rvv_census's g_table -- see rv32_vector_census.h.
inline bool g_capped = false;
inline bool g_seen_vector = false;
inline u64 g_pre_vector_skipped = 0;
inline u32 g_first_vector_pc = 0, g_last_vector_pc = 0;

struct Gap {
	bool open = false;
	u32 start_pc = 0;
	u32 count = 0;
	bool any_branch = false, any_may_trap = false;
};
inline Gap g_gap;

static constexpr u32 MAX_NAMES = 96;
inline char const *g_names[MAX_NAMES];
inline u32 g_name_n = 0;
inline int intern(char const *nm)
{
	for (u32 i = 0; i < g_name_n; i++)
		if (std::strcmp(g_names[i], nm) == 0)
			return (int)i;
	if (g_name_n >= MAX_NAMES)
		return -1;
	g_names[g_name_n] = nm;
	return (int)g_name_n++;
}

// SATURATING push (review round 2, defect E): once capped, g_n is never incremented again, so it
// cannot wrap a u32 on a long run and start overwriting g_buf[0..] with a small wrapped index.
ALWAYS_INLINE bool push(Rec const &r)
{
	if (g_capped)
		return false;
	if (g_n >= CAP) {
		g_capped = true;
		return false;
	}
	g_buf[g_n++] = r;
	return true;
}

ALWAYS_INLINE void flush_gap()
{
	if (!g_gap.open)
		return;
	Rec r{};
	r.pc = g_gap.start_pc;
	r.flags = (u8)(0x40u | (g_gap.any_branch ? 2u : 0u) | (g_gap.any_may_trap ? 4u : 0u));
	r.gap_count = g_gap.count;
	push(r);
	g_gap = Gap{};
}

// Called from HBody_##name (dbt/guest/rv32_interp.cpp) for every opcode the HANDLER macro
// generates -- but HBody_##name itself is only REACHED for the 93 opcodes
// dbt/guest/rv32_stubs.h's GUEST_RUNTIME_STUBS names (every RVV instruction among them) once code
// is JIT-compiled; the base scalar integer ISA bypasses it entirely via native QCG codegen. See
// the correction block at the top of this file. `vtype_pre`/`vl_pre` are the vl/vtype BEFORE this
// instruction ran; `vtype_post`/`vl_post` are AFTER. For every instruction except vset*, pre==post
// (nothing else can change
// vl/vtype). For vset* the KEY fields (funct6..vl, i.e. everything the join needs) are the POST
// state -- what the instruction PRODUCED, matching rv32_vector_census.h's own stated convention
// -- and the PRE state is additionally kept in the vl_pre/sew_pre/lmul_pre/vta_pre/vma_pre/
// vill_pre fields rather than discarded, so a caller can tell whether a given vsetvli changed
// anything at all or merely re-asserted the same configuration.
ALWAYS_INLINE void record(u32 pc, char const *name, bool is_branch, bool may_trap, u32 insn_raw,
			  u32 vl_pre, u32 vtype_pre, u32 vl_post, u32 vtype_post)
{
	if constexpr (!kEnabled)
		return;
	bool const is_vec = name_is_vector(name);
	if (!is_vec) {
		if (!g_seen_vector) {
			g_pre_vector_skipped++;
			return;
		}
		if (!g_gap.open) {
			g_gap.open = true;
			g_gap.start_pc = pc;
		}
		g_gap.count++;
		g_gap.any_branch |= is_branch;
		g_gap.any_may_trap |= may_trap;
		return;
	}
	// A vector instruction: flush any pending gap first so vector order is exactly preserved.
	flush_gap();
	if (!g_seen_vector) {
		g_seen_vector = true;
		g_first_vector_pc = pc;
	}
	g_last_vector_pc = pc;

	bool const is_vset = is_vset_family(name);
	VType const vt_key{is_vset ? vtype_post : vtype_pre}; // the KEY uses POST for vset* -- see doc
	RegRoles roles = family_regmask(name, insn_raw, VType{vtype_pre});
	bool const vm = ((insn_raw >> 25) & 1) != 0;
	if (roles.schema_known && !vm && !family_never_masked(name))
		roles.read_mask |= v0_mask(); // review round 2, defect B: v0 is read as the predicate

	int nid = intern(name);
	Rec r{};
	r.pc = pc;
	r.name_id = (u16)(nid < 0 ? 0xffffu : (u32)nid);
	r.flags = (u8)(1u | (is_branch ? 2u : 0u) | (may_trap ? 4u : 0u) |
		      (is_vecmem_family(name) ? 8u : 0u) | (is_vset ? 16u : 0u) |
		      (roles.schema_known ? 0u : 32u));
	r.opcode = (u8)(insn_raw & 0x7f);
	r.funct6 = (u8)((insn_raw >> 26) & 0x3f);
	r.funct3 = (u8)((insn_raw >> 12) & 0x7);
	{
		// rs2f: the vs2 FIELD reinterpreted as an opcode extension (lumop/sumop) -- only for
		// unit-stride memory (mop==0b00), exactly rv32_vector_census.h's Scope constructor.
		bool const is_mem = r.opcode == 0x07 || r.opcode == 0x27;
		u32 const mop = (insn_raw >> 26) & 0x3;
		r.rs2f = (u8)((is_mem && mop == 0) ? ((insn_raw >> 20) & 0x1f) : 0);
	}
	r.vm = (u8)(vm ? 1 : 0);
	r.vta = (u8)(vt_key.vta() ? 1 : 0);
	r.vma = (u8)(vt_key.vma() ? 1 : 0);
	r.vill = (u8)(vt_key.vill() ? 1 : 0);
	r.lmul_field = (u8)vt_key.vlmul_field();
	r.sew = (u8)vt_key.sew();
	r.vl = (u16)((is_vset ? vl_post : vl_pre) > 0xffff ? 0xffff : (is_vset ? vl_post : vl_pre));
	r.read_mask = roles.read_mask;
	r.write_mask = roles.write_mask;
	if (is_vset) {
		VType const vpre{vtype_pre};
		r.sew_pre = (u8)vpre.sew();
		r.lmul_pre = (u8)vpre.vlmul_field();
		r.vta_pre = (u8)(vpre.vta() ? 1 : 0);
		r.vma_pre = (u8)(vpre.vma() ? 1 : 0);
		r.vill_pre = (u8)(vpre.vill() ? 1 : 0);
		r.vl_pre = (u16)(vl_pre > 0xffff ? 0xffff : vl_pre);
	}
	push(r);
}

// Returns false on any failure (review round 2, defect F): the caller (dbt/elfrun.cpp) must treat
// that as fatal, not swallow it -- a seqtrace run whose dump silently failed would look identical
// to one that was never enabled, which is indistinguishable from lost evidence.
inline bool dump(char const *path)
{
	if constexpr (!kEnabled)
		return true;
	flush_gap();
	u32 const n = g_n; // already saturated at CAP by push(); no clamp needed
	u32 vector_events = 0;
	for (u32 i = 0; i < n; i++)
		if (g_buf[i].flags & 1)
			vector_events++;
	if (vector_events == 0) {
		// A trace with zero vector events captured nothing meaningful (the guest never
		// reached one, or --rvv-seqtrace-out was pointed at a non-vector workload by
		// mistake) -- fail closed rather than write an empty-but-well-formed CSV that a
		// downstream join would silently treat as "this guest has no vector work".
		std::fprintf(stderr,
			     "rvv_seqtrace: FATAL: 0 vector events captured (pre_vector_skipped=%llu"
			     ") -- refusing to write a trace with nothing in it\n",
			     (unsigned long long)g_pre_vector_skipped);
		return false;
	}
	FILE *f = std::fopen(path, "w");
	if (!f) {
		std::fprintf(stderr, "rvv_seqtrace: FATAL: fopen('%s') failed: %s\n", path,
			     std::strerror(errno));
		return false;
	}
	int rc = std::fprintf(
	    f,
	    "# rvv_seqtrace v3 records=%u capped=%d cap=%u pre_vector_skipped=%llu "
	    "first_vector_pc=%08x last_vector_pc=%08x vector_events=%u\n",
	    n, (int)g_capped, CAP, (unsigned long long)g_pre_vector_skipped, g_first_vector_pc,
	    g_last_vector_pc, vector_events);
	rc |= std::fprintf(f,
			   "idx,pc,name,is_vector,is_branch,may_trap,is_vecmem,is_vset,"
			   "unknown_schema,is_gap,opcode,funct6,funct3,rs2f,vm,vta,vma,vill,"
			   "lmul_field,sew,vl,read_mask,write_mask,gap_count,vl_pre,sew_pre,"
			   "lmul_pre,vta_pre,vma_pre,vill_pre\n");
	for (u32 i = 0; i < n; i++) {
		Rec const &r = g_buf[i];
		char const *nm =
		    (r.flags & 0x40) ? "GAP" : (r.name_id < g_name_n ? g_names[r.name_id] : "?");
		// 30 columns, 30 specifiers -- counted against the header above one by one, because
		// a silent off-by-one here (the previous version had 29) shifts every field after
		// it by one column without any compiler diagnostic other than -Wformat.
		int const w = std::fprintf(
		    f,
		    "%u,%08x,%s," // idx,pc,name
		    "%d,%d,%d,%d,%d,%d,%d," // is_vector,is_branch,may_trap,is_vecmem,is_vset,
					    // unknown_schema,is_gap
		    "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u," // opcode,funct6,funct3,rs2f,vm,vta,vma,
							// vill,lmul_field,sew,vl
		    "%u,%u,%u," // read_mask,write_mask,gap_count
		    "%u,%u,%u,%u,%u,%u\n", // vl_pre,sew_pre,lmul_pre,vta_pre,vma_pre,vill_pre
		    i, r.pc, nm, r.flags & 1, (r.flags >> 1) & 1, (r.flags >> 2) & 1,
		    (r.flags >> 3) & 1, (r.flags >> 4) & 1, (r.flags >> 5) & 1, (r.flags >> 6) & 1,
		    r.opcode, r.funct6, r.funct3, r.rs2f, r.vm, r.vta, r.vma, r.vill, r.lmul_field,
		    r.sew, r.vl, r.read_mask, r.write_mask, r.gap_count, r.vl_pre, r.sew_pre,
		    r.lmul_pre, r.vta_pre, r.vma_pre, r.vill_pre);
		if (w < 0)
			rc = -1;
	}
	bool const write_ok = rc >= 0 && std::ferror(f) == 0;
	bool const close_ok = std::fclose(f) == 0;
	if (!write_ok || !close_ok) {
		std::fprintf(stderr,
			     "rvv_seqtrace: FATAL: write or close failed for '%s' (write_ok=%d "
			     "close_ok=%d) -- the dump is INCOMPLETE, do not use it\n",
			     path, (int)write_ok, (int)close_ok);
		return false;
	}
	std::fprintf(stderr, "# rvv_seqtrace: %u records, %u vector events%s -> %s\n", n,
		     vector_events, g_capped ? " (CAPPED)" : "", path);
	return true;
}

} // namespace dbt::rv32::seqtrace
