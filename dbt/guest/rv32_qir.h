#pragma once

// W26: the shared active-chunk plan, whose type appears in the shared FP body's signature below.
// Depends only on dbt/qmc/qir.h, which qir_builder.h already pulls in here, so it adds no cycle.
#include "dbt/guest/rv32_active_chunk_plan.h"
#include "dbt/guest/rv32_insn.h"
// S2.9: RvvQcgSetVLAdmit takes a decoded rv32::VType by value, so the type must be complete here.
// rv32_vector.h depends only on dbt/util/common.h, so this adds no cycle.
#include "dbt/guest/rv32_vector.h"
// R1A.3a: the vector-run descriptor and its translation-time admission substrate. Depends only on
// rv32_insn.h/rv32_vector.h/runtime_stubs.h, so it adds no cycle here.
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir_builder.h"
#include <array>
#include <set>

namespace dbt::static_table_resolve
{
// A-line round 32 R32.9: detection/rejection diagnostics for the in-process static jump-table
// resolver (rv32_qir.cpp), exposed here so elfaot.cpp can dump them at compile end.
struct Stats {
	u64 sites_examined = 0;
	u64 pattern_matched = 0;
	u64 base_resolved = 0;
	u64 bound_proven = 0; // A-line R32.12: bounds-check register traced to a local constant
	u64 table_in_nonwritable = 0;
	u64 table_read_ok = 0;
	// A-line Round 44: indexed-table (index-preserving compact dispatch) diagnostics.
	u64 indexed_resolved = 0;
};
extern Stats g_stats;

// A-line Round 44: unlike TryResolve's deduplicated `std::vector<u32>` (which discards the guest
// program's own index->target mapping), this preserves the FULL dataflow needed for an
// index-preserving compact host dispatch: which guest register holds the index at the jr site
// (the SAME register TryResolve's bounds-check already proves is compared against a local
// compile-time bound -- not a new fact, just not previously exposed), and the table's raw,
// index-ordered contents (one validated entry per proven index, duplicates and all -- the guest's
// OWN table may map multiple opcodes to the same handler; preserving order lets a compact
// dispatch reproduce the guest's exact table[index] semantics without any deduplication-induced
// renumbering).
struct IndexedTable {
	bool found = false;
	u8 index_reg = 0xff; // guest register holding the index at jr_ip (dataflow-proven, not guessed)
	u32 table_base = 0;
	u32 table_len = 0;			  // PROVEN bound + 1, same proof TryResolve already requires
	std::vector<u32> raw_targets;		  // size == table_len, index-ordered, NOT deduplicated
};
} // namespace dbt::static_table_resolve

namespace dbt::vtable_narrow
{
// A-line Round 33: detection/rejection diagnostics for the in-process C++ virtual-call RTTI-
// narrowing resolver (rv32_qir.cpp), exposed here so elfaot.cpp can dump them at compile end.
struct Stats {
	u64 sites_examined = 0;    // every jalr/jr TRANSLATOR(jalr) attempted the pattern match on
	u64 pattern_matched = 0;   // 2-level-load (vptr then slot) shape found
	u64 receiver_sound = 0;    // receiver provenance traced to a provable ABI argument register
	u64 rtti_resolved = 0;     // enclosing function's class had a parseable RTTI entry
	u64 candidates_found = 0;  // >=1 valid candidate target after descendant enumeration
	// Round 33 R33.2 (lazy/bounded RTTI + cost instrumentation, measured not assumed):
	u64 provenance_reject_unrecognized = 0; // backward slice hit a non-copy/reload definition
	u64 provenance_reject_adjusted = 0;     // nonzero pointer adjustment (thunk/subobject) seen
	u64 provenance_reject_liveend = 0;      // reached function entry in a non-argument register
	u64 provenance_hops_total = 0;          // sum of backward-slice hops across all traced sites
	u64 symtab_parse_ns = 0;         // one-time raw ELF symtab/strtab parse (file-level only)
	u64 rtti_lazy_build_ns = 0;      // total time spent building the lazy per-root descendant index
	u64 rtti_lazy_roots = 0;         // distinct root classes actually queried (bounds the lazy graph)
	u64 rtti_lazy_nodes_total = 0;   // sum of descendant-set sizes across all queried roots
	u64 rtti_zti_total = 0;          // total _ZTI symbols in the binary (for O(all) vs O(relevant) contrast)
	u64 provenance_scan_ns = 0;      // total time spent inside TraceReceiverProvenance's backward walk
	u64 tryresolve_total_ns = 0;     // total self-time across every TryResolve call (superset of the above)
	// Round 35: demand-driven interprocedural field-provenance extension (TryFieldConstructorType).
	u64 field_provenance_resolved = 0; // receiver was a field-of-this, resolved via a constructor-parameter summary
	// Round 36 Consumer C pilot: how many resolved candidates make it into the guarded SwitchInst
	// at all -- llvmgen.cpp's Expand_gbrind_EdgeSpecializeAndSlowpath silently drops a candidate
	// (`if (tfn) cases.emplace_back(...)`) whenever its target function isn't ALREADY admitted as
	// its own AOT region for some other reason (natural profile hotness, closure, etc). These two
	// counters measure how much upside a "force-admit resolved candidate targets" consumer could
	// have BEFORE building it -- a candidate_total/candidate_admitted ratio near 1.0 means there is
	// no headroom (kill immediately); a materially lower ratio quantifies the ceiling.
	u64 consumer_candidate_total = 0;
	u64 consumer_candidate_admitted = 0;
};
extern Stats g_stats;
} // namespace dbt::vtable_narrow

namespace dbt::direct_call_resolve
{
// A-line Round 34: detection diagnostics for the in-process AUIPC+JALR direct-call-sequence
// fusion resolver (rv32_qir.cpp) -- a translator completeness fix, not a narrowing oracle.
// Exposed here so elfaot.cpp can dump them at compile end.
struct Stats {
	u64 sites_examined = 0;   // every jalr TRANSLATOR(jalr) attempted this pattern match on
	u64 pattern_matched = 0;  // rs1 traced to a local, provably-unclobbered auipc
	u64 target_verified = 0;  // computed target passed the executable-range safety check
};
extern Stats g_stats;
} // namespace dbt::direct_call_resolve

namespace dbt::return_target_resolve
{
// A-line Round 55: whole-binary static single-caller certificate for return continuations --
// see rv32_qir.cpp's own namespace comment for the full soundness argument. Exposed here so
// elfaot.cpp can dump diagnostics/run the headroom-only measurement mode.
struct Stats {
	u64 total_direct_call_edges = 0;
	u64 address_taken_marks = 0;
	u64 fanin1_targets = 0;
	u64 fanin_ge2_targets = 0;
};
extern Stats g_stats;

// Measurement-only entry point (--dbt-return-headroom-file): runs the whole-binary static scan
// and cross-references it against a REAL profiled edge file (--shadow-edges2-all-jalr's output
// format) to report what fraction of ACTUAL return-class dispatch mass this mechanism's
// certificate would cover -- profile used only to WEIGH the static result, never as part of the
// certificate itself. No codegen change; safe to call standalone.
void RunReturnHeadroomDiagnostic(uptr vmem_base, char const *edges_file);
} // namespace dbt::return_target_resolve

namespace dbt::qir::rv32
{
using namespace dbt::rv32;

// LLVM vector-SSA shape gate shared by the vfalu/vfma/vfcmp/vmerge translators. It is declared
// here so the focused admission test can query the gate before asking the translator to construct
// fixed-size four-chunk QIR groups; production callers and behavior are unchanged.
bool RvvPVectorSSAShapeAdmit(u32 raw_vtype, u32 vlen, u8 &sew, u8 &nregs, u16 &evl);

struct RV32Translator {

#define OP(name, format_, flags_)                                                                            \
	void H_##name(void *insn);                                                                           \
	void V_##name(rv32::insn::Insn_##name);                                                              \
	static constexpr auto _##name = &RV32Translator::H_##name;
	RV32_OPCODE_LIST()
#undef OP

	// P7G: `hint` is the live RVV configuration at the region's entry ip, or a default-
	// constructed (invalid) value when the caller has no live guest state -- every AOT driver
	// and every focused test. It is consumed once, at the region-entry ip range, and never
	// stored: nothing below writes it into the Region, the TBlock, a cache key or an artifact.
	static u32 Translate(qir::Region *region, CompilerJob::IpRangesSet *ipranges, uptr vmem,
			     RvvEntryHint hint = {});

	static StateInfo const *const state_info;

	// R1A.3a. Form the vector-run descriptor for the instructions starting at `entry_pc`, under
	// the same configuration a translation would see. Public and static because the descriptor
	// is a translation-time OBSERVATION with no emitted consequence this checkpoint: there is no
	// generated code to inspect it through, so this is how the admission rule is exercised --
	// including by qmc/qcg/rvv_vector_run_admission_test.cpp, which drives the REAL per-route
	// predicates rather than a copy of them.
	//
	// `observed_vtype` is the block-scoped vtype an in-block `vsetvli` pinned, or ~0u for "none
	// observed", exactly as the field the single-instruction translators read; the candidate
	// shape used in the second case is the same one they propose, and the run's single emitted
	// guard would prove it at run time either way.
	//
	// `limits` is an input rather than a constant so the pressure and length rules can be
	// exercised at their boundaries. Production always passes the defaults.
	static rvvrun::RunDescriptor RvvAdmitVectorRun(uptr vmem, u32 entry_pc, u32 boundary_pc,
						       u32 insn_budget, u32 observed_vtype,
						       rvvrun::RunLimits limits = {});
	// F1 test hook, the fast-reject twin of RvvAdmitVectorRun (same translator setup).
	static std::optional<rvvrun::CutReason> RvvEmptyScanCut(uptr vmem, u32 entry_pc, u32 boundary_pc,
								u32 insn_budget, u32 observed_vtype);

	// C2m. THE MATERIALIZE DISPATCHER'S DECLARATION PASS, reachable from a focused test, for the
	// same reason RvvAdmitVectorRun is: the property under test has no other observable.
	//
	// RvvMaterializeRunMember's COUNTS are already pinned end-to-end through a real translation
	// (rvv_materialize_run_body_test sections [1]-[3]), but its fail-closed backstops are not and
	// cannot be: every one of them fires on a descriptor field combination FormRun does not
	// produce -- a `.vx` member whose rs1 is not a GPR, a member carrying two source-1 kinds, a
	// whole-register member whose direction and `defines_vd` disagree. There is no guest word that
	// reaches them, so an untested backstop is a backstop nobody has ever seen fire.
	//
	// This entry point runs the DECLARATION pass only (`emit=false`), which is what makes it
	// harmless: the dispatcher constructs no QIR in that pass, so no Region and no Builder are
	// needed and nothing is added to the translator that emission could reach. Every check the
	// dispatcher makes is in that pass, ahead of each arm's `if (emit)`.
	static u32 RvvMaterializeRunMemberOps(rvvrun::RunMember const &m, u8 nchunks, u16 chunk_bytes);

private:
	static StateInfo const *GetStateInfo();

	explicit RV32Translator(qir::Region *region, uptr vmem);
	u32 TranslateIPRange(u32 ip, u32 boundary_ip);
	void PreSideeff();
	void TranslateInsn();

	// `backedge` marks a region exit produced by a DIRECT guest branch whose target is not above
	// the branch instruction itself (RV32Translator::IsDirectBackwardEdge). It defaults to false so
	// that every caller which is not such a branch -- the region-boundary fallthrough, and the jalr
	// paths that resolve an indirect transfer to a constant target -- is correct without saying
	// anything, and only the two genuine direct-branch translators pass a computed value.
	void MakeGBr(u32 ip, bool backedge = false);

public:
	// A direct guest control transfer is BACKWARD (retreating) iff its architectural target does
	// not lie above the address of the transferring instruction. Both operands come from the
	// instruction encoding -- `branch_ip` is the instruction's own guest PC and `target_ip` is
	// `branch_ip + sext(imm)` -- so this predicate is a property of the RISC-V encoding alone. It
	// reads no profile, no execution count, no threshold and no guest-PC constant, and it gives
	// the same answer for a given instruction on every run and every workload.
	//
	// `target_ip == branch_ip` (a `jal x0, 0` self-loop, and the RV32 `beq`-to-self encoding) is
	// backward: the edge re-executes the same instruction, which is a loop by any definition.
	//
	// RELATION TO NATURAL LOOPS, stated exactly because the checkpoint's wording invites the
	// stronger reading. A natural-loop backedge is an edge u -> h with h dominating u; deciding
	// that needs a dominator tree over the guest function, and a QCG region is a straight-line
	// span cut at the next existing translation block, so no such tree exists at this point. What
	// is available -- and what every production JIT uses for the same purpose -- is the retreating
	// property above. For code a compiler emits from structured source the two coincide; in
	// general each can contain an edge the other does not (a backward `goto` into an irreducible
	// region is retreating but not a natural backedge; a loop whose header was laid out above its
	// latch is a natural backedge that is not retreating). Nothing about CORRECTNESS depends on
	// which subset is chosen: the safepoint's effect on any edge carrying it is to hand control
	// back to Execute() at a point where the architectural state is already committed, which is
	// legal on every direct region exit. The choice determines only WHERE the runtime is willing
	// to pay for the test, and the point of choosing at all is that a polling point on every
	// direct branch would tax the forward, straight-line edges that make up most of them.
	static constexpr bool IsDirectBackwardEdge(u32 branch_ip, u32 target_ip)
	{
		return target_ip <= branch_ip;
	}

	// M2C. A width-correct host chunk shape: `bytes` is the host chunk width and `count` how many
	// of them cover one guest vector register; `count == 0` means "not admitted". The pair is one
	// decision: it is meaningful only when bytes * count == VLEN/8 exactly, which is the invariant
	// RvvHostChunkGeometry establishes and every consumer relies on instead of re-deriving a width.
	// (A1-review: moved here from the private section so the pure helper below is testable.)
	struct RvvChunkShape {
		u16 bytes{0};
		u8 count{0};
		explicit operator bool() const { return count != 0; }
	};

	// A1-review (2026-09-05). THE ONE PURE GEOMETRY. Side-effect free, reads NO config and probes
	// NO host feature: given a VLEN in bits and a SEW in bytes it returns the host chunk shape --
	// width min(VLEN/8, 64), count (VLEN/8)/width -- or a refusal. Its refusals are exactly the
	// ones every caller used to restate inline: SEW != 32 (the whole admitted set of every
	// integer route today), VLEN below 128 or not a multiple of 8, a register that is not a whole
	// number of 16/32/64-byte host vectors (VLEN 384 gives 48 and is refused, never rounded), and
	// more chunks than rvvrun::kMaxChunks, which sizes the emitters' per-chunk arrays.
	//
	// RvvVaddChunkShape (M2C), RvvQcgTypedShiftChunkShape (P7N-B) and
	// RvvNarrowWidthChunkGeometry (P7N-D) used to carry three copies of this formula, each kept
	// "so that route X is unchanged" stays checkable. That argument does not survive the review:
	// preserving old evidence is not a reason to copy a formula. All three now call this, and
	// each keeps ONLY what is not geometry -- its own switch, the backend test, --rvv-verify,
	// --rvv-direct and its host-feature probe -- at the call site, so their admitted sets are
	// unchanged while the formula has one home. rvv_narrow_width_route_test [1] still asserts the
	// three agree at every width, and [1b] pins this function's truth table directly.
	static RvvChunkShape RvvHostChunkGeometry(u32 vlen_bits, u32 sew_bytes);
	// W5 (2026-09-17). The same tiling with the element width as a parameter. The wrapper above
	// keeps `sew_bytes == 4` for the three integer callers that have no SEW row of their own; a
	// caller that asks THIS one is stating that its emitter lowers the width it passes.
	static RvvChunkShape RvvHostChunkGeometryForSew(u32 vlen_bits, u32 sew_bytes);

private:

	void TranslateLoad(insn::I i, VType type, VSign sgn);
	void TranslateStore(insn::S i, VType type, VSign sgn);
	void TranslateBrcc(insn::B i, CondCode cc);
	inline void TranslateSetcc(insn::R i, CondCode cc);
	inline void TranslateSetcc(insn::I i, CondCode cc);
	// `blocked` is the caller's OWN statement of why it is falling back to the C++ reference,
	// on the shared axes of dbt/guest/rv32_lowering_decision.h. It is defaulted so that every
	// existing call site compiles and behaves exactly as before -- an unstated reason records an
	// unclassified helper lowering rather than inventing one. A translator that KNOWS why it has
	// no route states it here, which is the same "producer states, shared layer checks" contract
	// rvvfinal::CloseFrame's `reason` field already uses.
	inline void TranslateHelper(insn::Base i, RuntimeStubId stub,
				    dbt::rv32::rvvlower::ConstraintSet blocked = 0);
	// RVV 1.0 7.8's segment memory accesses (nf >= 2) through the native vector-memory node.
	// Shape and legality come from the shared vseg_shape / vseg_registers_legal, so this route
	// and the rv32_vlseg / rv32_vsseg helper admit exactly the same encodings. True means the
	// access was emitted and no helper call follows.
	bool RvvTrySegmentMemory(insn::Base i, RuntimeStubId stub);
	bool RvvTryIntegerFamily(insn::Base i, RuntimeStubId stub);
	bool RvvSSAEnabled() const;
	// W5 (2026-09-17). THE LLVM TYPED-CHUNK SUBSTRATE, WITH NO WIDTH CONSTANT IN IT.
	//
	// `RvvSSAEnabled()` is two things at once: the substrate question (is this the LLVM backend
	// with `--rvv-vector-ssa` on?) and a width list (512 or 1024). Every typed-chunk LLVM route
	// asked it and therefore inherited the list, which is why the families were 512/1024 while
	// `RvvHostChunkGeometry` could already describe 128..4096. This asks the substrate question
	// ALONE and leaves the width to the geometry, which is the only thing that knows whether a
	// register tiles into host chunks and whether the count fits `rvvrun::kMaxChunks`.
	//
	// IT IS DELIBERATELY *NOT* USED BY FAMILY A (the P-vector-SSA `Create_rvvfalu`/`Create_rvvfma`
	// arms), by `RvvCommit`/`RvvResetValues`, by `MakeGBr`'s edge commit, by the P7G entry hint or
	// by the R1/R2 run candidate. Those keep `RvvSSAEnabled()` and therefore keep 512/1024. Two
	// reasons, both structural: `RvvPVectorSSAShapeAdmit`'s `nregs * (vlen / 512) <= 4` degenerates
	// below 512 (the product is 0 and the test passes for every group), and Family A's residency is
	// the thing the typed frames commit AGAINST -- widening one without the other would change
	// which representation owns a register at a width neither was measured at. A consequence worth
	// stating rather than discovering: at VLEN 128/256/2048 there is no Family A residency at all,
	// so the typed frames' commit-on-entry is a no-op there rather than a skipped obligation.
	bool RvvLLVMTypedSubstrate() const;
	// W5C (2026-09-17). Is an unobserved-vtype CANDIDATE expressible as a typed chunk frame at
	// this VLEN? A filter on the proposal RvvFormVectorRunAt makes, asking the shared geometry and
	// the shared chunk-capacity bound -- never a second admission rule, and never a claim that the
	// candidate is correct. A candidate that fails it is replaced by the canonical proposal, which
	// is what the scan did before any candidate existed.
	bool RvvCandidateShapeExpressible(u32 raw_vtype) const;
	// W5D (2026-09-17). The vtype a STANDALONE typed FP frame may be built on: the block's
	// observation when it has one, otherwise the region candidate filtered by the same
	// shape/capacity contract a run's proposal is filtered by, otherwise `~0u` for "no frame".
	// Never written back and never an observation.
	u32 RvvStandaloneFrameVType() const;
	void RvvResetValues();
	void RvvCommit(qir::Builder &builder, bool clear_dirty);
	void RvvCloseFP(qir::Builder &builder, bool clear_open);
	void RvvOpenFP();
	std::array<VOperand, 4> RvvReadGroup(u8 reg, u8 nregs);
	std::array<VOperand, 4> RvvNewGroup();
	void RvvDefineGroup(u8 reg, u8 nregs, std::array<VOperand, 4> const &values);
	VOperand RvvReadMask(u8 reg);
	void RvvDefineMask(u8 reg, VOperand value);
	u8 RvvActiveChunks(u8 nregs) const;
	u16 RvvEVL() const;
	u32 RvvExpectedVType() const;
	// Diagnostic chunk control arm for pure QCG/AVX-512 (2026-08-24 vadd.vv slice) -- NOT the
	// method; see the block comment on InstRVVDiagChunkBegin in qmc/qir.h. Returns the number of
	// host chunk NODES to emit, or 0 when the instruction is not admitted and must keep its
	// existing lowering. See experiments/2026-08-24-0508-rvv-qcg-chunk-vadd/docs/DESIGN.md.
	u8 RvvQcgDiagChunkAdmit(u32 sew_bytes) const;

	// Native-2 (config::rvv_qcg_whole_reg). Pure-QCG direct lowering for the whole-register
	// transfer pair `vl<nf>re<eew>.v` / `vs<nf>r.v`. Returns the number of 512-bit host chunks
	// the frame must emit -- nregs * VLEN/512, derived from the runtime VLEN -- or 0 when the
	// instruction keeps the unchanged rv32_vlNre / rv32_vsNr helper. The LLVM/AOT backend is
	// untouched: it routes these through the typed vector-SSA rvvload/rvvstore path instead, and
	// this predicate refuses to run at all when aot_use_llvm is set.
	u8 RvvQcgWholeRegAdmit(u32 raw, bool is_load) const;
	void RvvEmitWholeRegChunkGroup(u32 raw, u8 base_reg, u8 nregs, u8 chunks, bool is_load,
				       RuntimeStubId stub);
	// C2l. THE ONE MATERIALIZING BODY for a whole-register transfer, extracted from the frame
	// above for the reason RvvEmitTypedAluChunkBody was extracted from its own group: both the
	// accepted single-instruction frame and a vector run in materialize mode call it, so "the
	// run's materialize body IS the single-instruction body" stays a structural fact for this
	// route too. It emits NO frame and no guard; the caller owns both.
	//
	// `2 * chunks` typed ops, in two passes: every source read (a guest-memory chunk for a load,
	// a CPUState chunk for a store) before any destination is written, which is what makes an
	// overlapping base pointer and destination register group safe. `base_offs` is the CPUState
	// word holding the guest base address and `chunk_bytes` is simultaneously the chunk width and
	// the stride, in memory and inside the register group.
	void RvvEmitWholeRegChunkBody(bool is_load, u32 base_offs, u8 base_reg, u8 chunks,
				      u32 chunk_bytes);

	// Native-3 (config::rvv_qcg_vx_mulacc). Direct lowering for unmasked e32/LMUL=1 `vmul.vx` and
	// `vmacc.vx`, in BOTH backends. The ENCODING half -- the instruction word and the SEW -- lives
	// once in RvvVxMulAccEncodingAdmit so the two backend gates cannot drift apart about which
	// guest instructions exist in the route, exactly the division S3.4/S3.5/S3.6 made.
	// A21: the WIDTH half is per backend, as it is for vmul.vv. The pure-QCG gate returns a
	// RvvChunkShape from the shared RvvRouteChunkShape (16/32/64-byte chunks, so VLEN 128/256
	// are admitted alongside 512/1024 when --rvv-qcg-narrow-chunk-width is on; {64, VLEN/512}
	// with it off); the LLVM gate still returns the 64-byte chunk count at VLEN 512/1024 and
	// nothing else (RvvVxMulAccShapeAdmit, the pre-A21 rule, kept for that arm and for the CCRF
	// component scope). 0 / an empty shape means "keep the unchanged rv32_vimul helper".
	bool RvvVxMulAccEncodingAdmit(u32 raw, u32 sew_bytes) const;
	u8 RvvVxMulAccShapeAdmit(u32 raw, u32 sew_bytes) const;
	RvvChunkShape RvvQcgVxMulAccShape(u32 raw, u32 sew_bytes) const;
	u8 RvvLLVMVxMulAccAdmit(u32 raw, u32 sew_bytes, u16 *chunk_bytes = nullptr) const;
	void RvvEmitVxMulAccChunkGroup(u32 raw, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				       RvvChunkShape shape);
	// C2l. THE ONE MATERIALIZING BODY for `vmul.vx` / `vmacc.vx`, extracted from the frame above
	// for the reason stated on RvvEmitWholeRegChunkBody. `1 + 3k` typed ops for the multiply and
	// `1 + 5k` for the accumulate -- one GPR broadcast, then per chunk the vs2 load (and, for the
	// accumulate, the old vd load), the multiply (and the add), and the store. Load-major is
	// preserved: every source of every chunk is read before any destination is written, which is
	// what discharges both the accumulator read-before-write obligation and `vd == vs2`.
	void RvvEmitVxMulAccChunkBody(bool is_macc, u32 vd, u32 rs1, u32 vs2, u8 sew_bytes,
				      u8 nchunks, u32 chunk_bytes);

	// A2 (config::rvv_qcg_typed_chunk_vmv). Pure-QCG direct lowering for `vmv.v.x vd, rs1`.
	// The predicate reads the instruction word (OP-V, OPIVX, funct6 010111, vm=1, vs2=0) and
	// derives the width from RvvRouteChunkShape; the frame is the typed-chunk guard, ONE
	// vchunkbroadcast of x[rs1]'s CPUState word and one vstatechunkstore per chunk into vd.
	// A7: the SAME predicate now covers the whole unmasked move family -- vmv.v.x (OPIVX),
	// vmv.v.i (OPIVI, signed imm5) and vmv.v.v (OPIVV, register copy) -- and reports the source
	// kind through `kind` (RvvAluSrc1: XScalar / SImm5 / Vector = copy). vm=0 (vmerge.v?m) and
	// vs2 != 0 (reserved) are refused, as before. The frame: guard, ONE broadcast (x/i) or k
	// chunk loads (v), k stores; with --rvv-qcg-partial-vl the A3 bounded arm (Kind::Mov,
	// masked store, no vs2) handles 0 <= vl < VLMAX so the tail stays undisturbed and vl == 0
	// writes nothing. One switch (rvv_qcg_typed_chunk_vmv) for the family.
	RvvChunkShape RvvQcgTypedVmvChunkShape(u32 raw, u32 sew_bytes, u8 *kind = nullptr) const;
	void RvvEmitTypedVmvChunkGroup(u32 raw, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				       RvvChunkShape shape, u8 kind);
	// C2l. THE ONE MATERIALIZING BODY for the unmasked move/broadcast family, extracted from the
	// frame above for the reason stated on RvvEmitWholeRegChunkBody. `kind` is an RvvAluSrc1
	// value: Vector is `2k` typed ops (k chunk loads of vs1, then k stores of vd, so a self-copy
	// reads every chunk before it writes any), and XScalar / SImm5 / FScalar are `k + 1` (ONE
	// broadcast of x[rs1] / of the sign-extended imm5 / of f[rs1], then k stores). There is no
	// lane operation in any of the four: a move has no arithmetic.
	void RvvEmitTypedVmvChunkBody(u32 vd, u32 rs1, u8 kind, u8 sew_bytes, u8 nchunks,
				      u32 chunk_bytes);

	// A6 (config::rvv_qcg_typed_chunk_vadd_scalar). WHAT SOURCE 1 OF A TYPED INTEGER ALU FRAME
	// IS. Vector: a vector register (every route before A6). XScalar: a GPR, its CPUState word
	// broadcast once per frame (OPIVX). SImm5: the rs1 FIELD is a 5-bit SIGNED immediate value,
	// sign-extended to SEW and broadcast once per frame (OPIVI value forms; NOT the shift
	// forms, whose rs1 field is an unsigned amount consumed by the lane op itself).
	// C2l added FScalar: rs1 names an F register whose NaN-boxed word is broadcast once, which
	// is what `vfmv.v.f` needs and what no integer route has. It is accepted by the MOVE body
	// only; RvvEmitTypedAluChunkBody Panics on it rather than silently broadcasting an immediate,
	// because there is no integer route whose source 1 is an F register.
	enum class RvvAluSrc1 : u8 { Vector = 0, XScalar = 1, SImm5 = 2, FScalar = 3 };
	static constexpr i32 RvvSext5(u32 field) { return (i32)((u32)(field & 0x1fu) << 27) >> 27; }
	// The shape predicate for the two encodings: OP-V, funct6 000000, vm=1, funct3 OPIVX or
	// OPIVI, SEW=32; the width is RvvVaddChunkShape's -- the SAME shape the .vv route and the
	// run's Add arm use. Returns the source-1 kind through `kind`.
	RvvChunkShape RvvQcgTypedVaddScalarChunkShape(u32 raw, u32 sew_bytes, RvvAluSrc1 *kind) const;
	void RvvEmitTypedVaddScalarChunkGroup(u32 raw, u32 vtype_raw, u32 vlen, u32 sew_bytes,
					      RvvChunkShape shape, RvvAluSrc1 kind);

	// TYPED chunk lowering (config::rvv_qcg_typed_chunk). Returns the admitted 512-bit host chunk
	// count -- T6b: RvvGenericChunkShapeAdmit's k, so 1/2/4/8 at VLEN 512/1024/2048/4096 -- and 0
	// when this vadd.vv must keep its existing lowering. SEW=32 and LMUL=1 are still the whole
	// admitted set. Unmasked/vstart=0/vl=VLMAX are not decided here: the first is guaranteed by the
	// decoder and the other two are runtime state checked by the emitted guard.
	u8 RvvQcgTypedChunkAdmit(u32 sew_bytes) const;

	// M2C. The vadd.vv slice's own, WIDTH-CORRECT shape (RvvChunkShape is declared in the public
	// section above, next to RvvHostChunkGeometry).

	// The gate half of RvvQcgTypedChunkAdmit -- switch, --rvv-verify, backend selection and the
	// AVX-512F host probe -- with no shape rule in it. Factored out so the width-correct vadd
	// shape below and the unchanged 512-bit predicate cannot drift apart on WHEN the route is
	// open, while still differing on WHAT it admits.
	// P4: llvm_any_width=true drops only the 512/1024 width term (vadd.vv's shape uses it).
	bool RvvQcgTypedChunkGatesOpen(bool llvm_any_width = false) const;

	// M2C. Width-correct admission for exact unmasked vadd.vv, and the ONLY shape predicate the
	// vadd typed route uses.
	//
	// The chunk width is min(VLEN/8, 64): one host vector register that is never wider than the
	// architectural guest register, and never wider than AVX-512. So VLEN 128/256/512 are one
	// 16/32/64-byte chunk and VLEN 1024 is two 64-byte chunks -- the count only exceeds 1 once a
	// guest register is genuinely wider than the widest host vector.
	//
	// SEPARATE from RvvQcgTypedChunkAdmit rather than a widening of it, deliberately. That
	// predicate is shared by the vector-run member test and by the LLVM arm, both of which are
	// built on 64-byte chunks; widening it in place would silently change the shape those routes
	// construct. Narrowing the blast radius to the one opcode under change is the point.
	RvvChunkShape RvvVaddChunkShape(u32 sew_bytes) const;

	// P7N-B. The WIDTH-CORRECT shape for the two logical shift-immediate forms, and the shape
	// predicate their route uses. Chunk width is min(VLEN/8, 64) and the count is VLEN/8 divided
	// by it -- the SAME derivation RvvVaddChunkShape uses, for the same reason: a guest vector
	// register is a whole number of host chunks, and there are as many as it takes. VLEN
	// 128/256/512/1024 therefore give one 16-byte, one 32-byte, one 64-byte and two 64-byte
	// chunks, with no width named anywhere in the rule.
	//
	// SEPARATE from RvvVaddChunkShape rather than a widening of it, deliberately, and for the
	// reason that predicate's own comment gives: it is the vadd route's ONLY shape predicate and
	// an accepted P4/P5 evidence arm rests on it. Sharing it would make "the vadd route is
	// unchanged" stop being a statement anything checks.
	RvvChunkShape RvvQcgTypedShiftChunkShape(u32 sew_bytes) const;

	// P7N-D. THE VLEN-DERIVED HOST CHUNK GEOMETRY, with no host-feature probe in it.
	//
	// width = min(VLEN/8, 64) bytes, count = (VLEN/8) / width. The SAME derivation
	// RvvVaddChunkShape and RvvQcgTypedShiftChunkShape state, and the third and last restatement
	// of it -- the focused test asserts all three agree at every supported VLEN, so a divergence
	// is a test failure rather than a discovery. Nothing here enumerates a VLEN.
	//
	// It answers none unless `--rvv-qcg-narrow-chunk-width` is on and this is the pure-QCG
	// backend, so with the switch off every caller falls back to the unchanged whole-512-chunk
	// rule and the tree behaves exactly as it did.
	//
	// NO HOST PROBE, deliberately: the narrow forms are EVEX xmm/ymm, which is AVX512VL rather
	// than the AVX512F a route's own gate probed, but `vsetvli` emits NO vector instruction at
	// any width and must not be gated on a feature it never uses. The probe therefore lives in
	// RvvNarrowWidthChunkShape below, which is what the routes that DO emit narrow vector
	// instructions call.
	RvvChunkShape RvvNarrowWidthChunkGeometry(u32 sew_bytes) const;
	// P7N-D. The geometry above plus the AVX512VL probe the narrow EVEX forms need. Fail-closed:
	// on a host with AVX-512F but not VL a narrow width refuses here and keeps the helper rather
	// than emitting bytes it would #UD on.
	RvvChunkShape RvvNarrowWidthChunkShape(u32 sew_bytes) const;
	// P7N-D. THE SHAPE A TYPED CHUNK ROUTE USES: the VLEN-derived geometry when the switch admits
	// it, and otherwise the unchanged whole-512-chunk rule expressed as {64, k}. At every VLEN
	// >= 512 the two branches return the same pair, which is what makes "the switch cannot move a
	// 512 or 1024 arm" structural rather than a claim.
	RvvChunkShape RvvRouteChunkShape(u32 sew_bytes) const;
	// Builds the typed chunk group for one admitted vsll.vi/vsrl.vi. THREE typed ops per chunk,
	// not four: one source load, one lane operation, one destination store. There is no second
	// source to load because the shift amount is an immediate.
	void RvvEmitTypedShiftChunkGroup(rvvrun::RunOp op, u32 rd, u32 rs2, u8 shamt, u32 raw,
					 u32 vtype_raw, u32 vlen, u32 sew_bytes, u8 nchunks,
					 u16 chunk_bytes);
	// C3/C5: `active_lane_store` makes each destination store carry this chunk's element width
	// and index, so Emit_vstatechunkstore predicates it on the LIVE `vec.vl`. Default false keeps
	// the full-width store, so every existing caller is unchanged.
	void RvvEmitTypedShiftChunkBody(rvvrun::RunOp op, u32 rd, u32 rs2, u8 shamt, u8 sew_bytes,
					u8 nchunks, u16 chunk_bytes,
					bool active_lane_store = false);
	// T7R observed dynamic vfalu closure. Returns the register GROUP's total V512 chunk count:
	// emul_group_regs(LMUL) * (VLEN/512). P7E generalized the observed-vtype path from LMUL=2 to
	// LMUL in {1,2}; the unknown-vtype candidate still proposes m2 and is byte-for-byte unchanged.
	// A9: the chunk WIDTH is no longer fixed at 64 bytes. The register group's shape is derived
	// from the SAME rule the integer routes use (RvvRouteChunkShape: chunk = min(VLEN/8, 64)
	// bytes, VLEN/8 / chunk chunks per register), times emul_group_regs(LMUL). The return value
	// is still the group's total chunk count; `chunk_bytes` (16/32/64) is reported through the
	// optional out-parameter so every caller addresses windows and types values with the width
	// the admission decided, never a literal 64.
	u8 RvvQcgTypedFaluAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	void RvvEmitTypedFaluChunkGroup(u32 raw, dbt::rv32::VType vt, u8 nchunks, u16 chunk_bytes = 64);
	// F1 (2026-09-16): the LLVM/AOT twin of the predicate above, and the two are mutually
	// exclusive by construction (that one refuses `config::aot_use_llvm`; this one requires
	// RvvSSAEnabled(), which requires it). Same return convention -- the register group's total
	// chunk count, or 0 for "not admitted". Strictly narrower than the QCG twin: `.vv` or `.vf`
	// only (F2; the reversed OPFVF vfrsub/vfrdiv stay out), unmasked only, an OBSERVED vtype only,
	// 64-byte chunks only, and funct6 restricted to the
	// shared `vfalu_llvm_constrained_vv_supported` family the backend's intrinsic map covers. Its
	// only caller is the run former's member-shape rule; a SINGLE FP instruction still reaches the
	// pre-existing P-vector-SSA route (TRANSLATOR(vfalu)'s `Create_rvvfalu` arm), which is
	// unchanged. See rv32_qir.cpp for why each row is narrower.
	u8 RvvLLVMFaluChunkAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	// F5 (2026-09-16): the predicate above intersected with OPFVF, and nothing else. It is what
	// TRANSLATOR(vfalu)'s STANDALONE LLVM arm asks. `.vv` is excluded there because it already has
	// a better native lowering -- the P-vector-SSA arm, which keeps chunk values live ACROSS guest
	// instructions -- so routing it to a per-instruction typed frame would remove residency and add
	// a commit rather than add coverage. The run former still asks RvvLLVMFaluChunkAdmit, so a
	// `.vv` run member is unaffected. See rv32_qir.cpp.
	u8 RvvLLVMFaluStandaloneAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	// P7I observed dynamic OPFVF FUSED-multiply-add closure: `vfmadd.vf` (funct6 40) and
	// `vfnmsub.vf` (funct6 43) only. Same return convention as RvvQcgTypedFaluAdmit -- the
	// register group's total V512 chunk count, or 0 for "not admitted, keep the rv32_vfma helper".
	//
	// THREE WAYS THIS IS STRICTLY NARROWER THAN THE FALU PREDICATE, each for a stated reason:
	//   * an UNOBSERVED vtype is refused outright. The falu route may propose a candidate shape
	//     and let its guard prove it; this one will not, because a fused frame also has to read
	//     the OLD vd and there is no observation to say which element width that is.
	//   * the host must have FMA3 as well as AVX-512F (and BMI2, which the shared lane-mask
	//     prologue's `bzhi` needs). They are independent CPUID bits.
	//   * under -DRVV_FP_FORCE_SOFT the predicate does not exist at all -- see the definition.
	u8 RvvQcgTypedFmaAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	// F3 (2026-09-16): the LLVM/AOT twin of the predicate above, mutually exclusive with it by
	// construction. Same return convention. Admits the WHOLE eight-member fused family
	// (`vfma_supported`) in both `.vv` and `.vf`, and is narrower than the QCG twin in exactly the
	// ways this backend's body requires: unmasked only, integral LMUL only, 64-byte chunks only,
	// at most rvvrun::kMaxChunks chunks (its only caller is the run former), an OBSERVED vtype
	// only, and no host CPUID probe. Per-funct6 sign placement lives in QIRToLLVM::Emit_vchunkfma.
	u8 RvvLLVMFmaChunkAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	void RvvEmitTypedFmaChunkGroup(u32 raw, dbt::rv32::VType vt, u8 nchunks, u16 chunk_bytes = 64);
	// P8: vfsqrt.v. One source, so it neither shares the falu predicate nor borrows the fused
	// one; see rv32_qir.cpp for the admitted set and for what stays with the helper.
	u8 RvvQcgTypedSqrtAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	// W5F (2026-09-17). The LLVM/AOT half of the square-root route: the same node and frame, its
	// own switch and substrate gate, and a strictly narrower envelope than the QCG twin's --
	// unmasked only, observed-or-guarded vtype, and the full-VL/vstart-0/RNE guard, because this
	// backend's body has no opmask, no tail handling and no per-mode rounding arm.
	u8 RvvLLVMSqrtChunkAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	// W6: the ordered floating reduction's LLVM arm. The fold is fully unrolled at translation
	// time -- one constrained add per element -- so the element count is bounded.
	//
	// THIS IS A COMPILER-RESOURCE BOUND, NOT A PERFORMANCE KNOB. It exists so that an
	// architecturally legal but very large group cannot expand into an unbounded instruction
	// sequence in one basic block; it is not tuned against any measurement and changing it is not
	// a way to make a workload faster. A group past the bound keeps the ordered helper, which is
	// the same result the route gives for every other unsupported state.
	static constexpr u32 kMaxOrderedFoldElems = 256;
	u8 RvvLLVMFredAdmit(u32 raw, dbt::rv32::VType vt, RuntimeStubId stub) const;
	bool RvvTryLLVMFloatReduce(insn::Base i, RuntimeStubId stub);
	// W7: the whole-register move's LLVM arm. No separate `Admit` helper because, unlike the
	// reduction, every condition is a pure function of the encoding and config -- there is no
	// vtype to consult, which is the operation's defining property.
	bool RvvTryLLVMWholeMove(insn::Base i, RuntimeStubId stub);
	// C2b: the scalar <-> vector element-0 transfers' LLVM arm.
	bool RvvTryLLVMScalarMove(insn::Base i, RuntimeStubId stub);
	// C3: the integer extension family's LLVM arm (unmasked only).
	bool RvvTryLLVMExtend(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of `vfclass.v`. See RvvTryLLVMFClass for why this family needs no FP
	// bracket and no constrained intrinsic despite being an OPFVV encoding.
	bool RvvTryLLVMFClass(insn::Base i, RuntimeStubId stub);
	// Order item 4: the LLVM arm of `vfrsqrt7.v` / `vfrec7.v` (unmasked, SEW 32/64).
	bool RvvTryLLVMFEstimate(insn::Base i, RuntimeStubId stub);
	// Order item 4: the LLVM arm of `vfmerge.vfm` / `vfmv.v.f` (SEW 32/64).
	bool RvvTryLLVMFMerge(insn::Base i, RuntimeStubId stub);
	// Order item 4: the LLVM arm of `vsaddu`/`vsadd`/`vssubu`/`vssub` (unmasked, SEW 32, LMUL 1).
	bool RvvTryLLVMSatAdd(insn::Base i, RuntimeStubId stub);
	// Order item 4: the LLVM arm of `vadc`/`vsbc` (vector destination; vmadc/vmsbc keep the helper).
	bool RvvTryLLVMAdc(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMAvg(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMFracMul(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMNarrowClip(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMIntReduce(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMMaskLogic(insn::Base i, RuntimeStubId stub);
	// W31. The integer compare family on the LLVM arm. Deliberately a SEPARATE function from
	// RvvTryIntegerFamily rather than a relaxation of its `aot_use_llvm` refusal: that function
	// emits `vchunkpartialalu` for forty-four other kinds none of which this backend lowers, so
	// opening it would put the whole 52-kind surface one predicate away from a Panic. This one
	// can only ever build the eight compare Kinds. What it does NOT restate is the admitted set:
	// every legality question it asks is asked of the same shared architectural predicate the
	// QCG arm asks (`vicmp_supported`, `vtype_supported`, `reg_group_legal`,
	// `same_width_sources_legal`, `emul_group_regs`), so the two arms cannot disagree about which
	// encodings are legal -- only about which backend lowers them.
	bool RvvTryLLVMIntCompare(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMElementIndex(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMMaskScalar(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMMaskPrefix(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMIota(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMCompress(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMGather(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMSlide(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMStrided(insn::Base i, RuntimeStubId stub);
	bool RvvTryLLVMIndexed(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of the SAME-WIDTH integer-to-float conversions.
	bool RvvTryLLVMIntToFloat(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of the round-toward-zero float-to-integer conversions.
	bool RvvTryLLVMFloatToInt(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of the widening float-to-float conversion.
	bool RvvTryLLVMFloatWiden(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of the narrowing float-to-float conversion.
	bool RvvTryLLVMFloatNarrow(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of the widening integer-to-float conversions.
	bool RvvTryLLVMIntToFloatWiden(insn::Base i, RuntimeStubId stub);
	// C4: the LLVM arm of the widening float-to-integer conversions.
	bool RvvTryLLVMFloatToIntWiden(insn::Base i, RuntimeStubId stub);
	// ORDER ITEM 3. ONE frame policy for every conversion route, so the partial-VL decision --
	// guard kind, geometry, and which close the frame takes -- exists in one place instead of
	// once per opcode. The arms keep their own admission and their own per-unit node; what they
	// stop owning is the policy.
	// The geometry itself lives in the .cpp (rv32_frame_semantics.h is not visible here); what
	// the frame carries across is the decision and the shape it was built from.
	struct RvvConvFrame {
		bool partial{false};
		qir::Inst *begin{nullptr};
		u32 chunks{0}, bytes{0}, dsew{0};
	};
	RvvConvFrame RvvOpenConversionFrame(dbt::rv32::VType vt, u32 vmax, u32 raw,
					    RuntimeStubId stub, u32 chunks, u32 bytes, u32 dsew);
	void RvvCloseConversionFrame(RvvConvFrame const &f, u32 raw, RuntimeStubId stub);
	// C3: the widening integer family's LLVM arm (unmasked only).
	bool RvvTryLLVMWiden(insn::Base i, RuntimeStubId stub);
	// C3: the narrowing shifts' LLVM arm (vnsrl/vnsra only; vnclip keeps its helper).
	bool RvvTryLLVMNarrowShift(insn::Base i, RuntimeStubId stub);
	// ORDER ITEM 3: the FIRST route in either LLVM family that emits the architectural-mask
	// conjunct -- masked OPIVV vadd/vsub/vand/vor/vxor (`vm == 0`). See rv32_qir.cpp for the
	// family restriction (the lane ops raise nothing, so only the commit is predicated) and the
	// four refusals that keep the unchanged rv32_vialu helper.
	bool RvvTryLLVMMaskedAlu(insn::Base i, RuntimeStubId stub);
	void RvvEmitTypedSqrtChunkGroup(u32 raw, dbt::rv32::VType vt, u8 nchunks, u16 chunk_bytes = 64);
	// P9: the FP compare family. The destination is a MASK register, so the frame writes mask
	// bytes rather than vector chunks; see rv32_qir.cpp for the admitted set.
	u8 RvvQcgTypedFCmpAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	void RvvEmitTypedFCmpChunkGroup(u32 raw, dbt::rv32::VType vt, u8 nchunks, u16 chunk_bytes = 64);
	// P10: the widening FP family (e32 -> e64 add / sub / mul, .vv .vf .wv .wf). `nchunks` counts
	// DESTINATION chunks; see rv32_qir.cpp for the admitted set.
	u8 RvvQcgTypedFWidenAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	// Order item 4: the LLVM arm of the widening FP family (unmasked, full VL, SEW 32 source).
	u8 RvvLLVMFWidenAdmit(u32 raw, dbt::rv32::VType vt, u16 *chunk_bytes = nullptr) const;
	void RvvEmitTypedFWidenChunkGroup(u32 raw, dbt::rv32::VType vt, u8 nchunks, u16 chunk_bytes = 64);
	// T7a: independently selected LLVM representation for the same exact vadd.vv envelope. The
	// accepted baseline returns V512 chunks above; this arm keeps InstRVVAddV as one guest operation
	// and lets LLVM legalize its VLEN-wide FixedVectorType. No other instruction calls this gate.
	bool RvvLLVMWideVaddAdmit(u32 sew_bytes) const;
	void RvvEmitLLVMWideVadd(insn::Insn_vadd_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes);
	// T7b: same envelope, but the one wide operation consumes/defines the typed frame's V512 SSA
	// values. This has no chunk-cache commit/reset and no CPUState access beyond the baseline frame.
	bool RvvLLVMFairWideVaddAdmit(u32 sew_bytes) const;
	void RvvEmitLLVMFairWideVadd(insn::Insn_vadd_vv i, u32 vtype_raw, u32 vlen,
				    u32 sew_bytes, u8 nchunks);

	// ------------------------------------------------------------------------------------
	// S3.10a: THE SHARED TYPED INTEGER-ALU CHUNK CORE.
	//
	// S3.9's source audit established that the six element-wise OP-V routes differ in exactly
	// four values -- QIR body opcode, LLVM builder method, fallback stub and route flag -- and
	// agree on everything else: SEW=32, one 512-bit chunk per 512 VLEN bits,
	// `i0 = vs2 / i1 = vs1` operand order, load-major ordering, the 64-byte CPUState windows, the
	// operation-independent guard frame and the `4 * nchunks` node accounting. This enum plus
	// RvvEmitTypedAluChunkGroupCore below is that agreement made into one function instead of one
	// copy per opcode.
	//
	// It carries Add and Sub only. That is the S3.10a slice, not the end state: vmul/vxor/vor/vand
	// keep their existing separate builders and stay fail-closed in the LLVM backend until their
	// own checkpoint routes them through here.

	// The shape half of admission, shared by BOTH backends and by every member of the family.
	// Everything here is decidable at TRANSLATION time; vtype/vl/vstart are runtime state left to
	// the guard the emitter generates. Returns the admitted 512-bit host chunk count or 0. It
	// deliberately contains NO flag, NO backend test and NO host-feature probe: those are the
	// per-backend gates' business, which is what lets one shape rule serve a QCG gate that must
	// fail closed without AVX-512F and an LLVM gate that must not depend on the compiling host's
	// CPUID at all.
	//
	// T6b: its body is now `return RvvGenericChunkShapeAdmit(sew_bytes)`, so the family reaches
	// k=1/2/4/8 through the tree's one whole-chunk rule instead of a private copy of it. The
	// function stays as the family's named entry -- see the definition for why.
	u8 RvvAluChunkShapeAdmit(u32 sew_bytes) const;

	// The LLVM/AOT gate for exact unmasked `vsub.vv` (S3.10a). Same two-gate shape S3.4/S3.5/S3.6
	// established and for the same reason: it requires the route's OWN pre-existing switch
	// (`--rvv-qcg-typed-chunk-sub`) as well as `RvvSSAEnabled()`, so turning on `--rvv-vector-ssa`
	// cannot sweep this opcode into a route nobody asked for, and an accepted evidence arm's flag
	// keeps meaning what it meant. Exactly one of this and RvvQcgTypedSubChunkAdmit can return
	// non-zero for a given compile -- that one requires !aot_use_llvm and this one requires
	// RvvSSAEnabled(), which requires aot_use_llvm -- so the pair is a backend selection, not a
	// widening of what is admitted.
	u8 RvvLLVMSubChunkAdmit(u32 sew_bytes, u16 *chunk_bytes = nullptr) const;

	// The shared group builder. rd/rs1/rs2/raw are plain u32 because the six `Insn_*_vv` types are
	// distinct; the typed wrappers below keep the type-level guarantee that only the right decode
	// path can reach a given operation, which matters because VF6_VAND/VF6_VOR/VF6_VXOR are
	// adjacent funct6 values.
	void RvvEmitTypedAluChunkGroupCore(rvvrun::RunOp op, RuntimeStubId fallback, u32 rd, u32 rs1,
					   u32 rs2, u32 raw, u32 vtype_raw, u32 vlen, u32 sew_bytes,
					   u8 nchunks, u16 chunk_bytes = 64, u8 src1_kind = 0);

	// Builds the typed V512 chunk group for one admitted vadd.vv. Shared by the observed-vtype
	// and unknown-vtype entries so both construct byte-identical QIR (C3.1f).
	// vtype is passed as a raw u32, not an rv32::VType, so this header keeps needing only
	// rv32_insn.h; the callee rebuilds the typed view.
	// S3.10a: now a thin typed wrapper over RvvEmitTypedAluChunkGroupCore. The constructed QIR is
	// unchanged, node for node.
	void RvvEmitTypedChunkGroup(insn::Insn_vadd_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				    RvvChunkShape shape);
	// The diagnostic arm's twin of the above, extracted for the same reason and shared by the
	// same two entries (C3.2a-fix1). Same raw-u32 vtype convention.
	void RvvEmitDiagChunkGroup(insn::Insn_vadd_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				   u8 nchunks);

	// HM.2a. THE GENERIC CHUNK-COUNT RULE: after whole-chunk admission, k = VLEN / 512 -- computed,
	// never enumerated.
	//
	// It states the rule the shape actually obeys -- a guest vector register is a WHOLE number of
	// host chunks, and there are as many chunks as it takes -- so the SAME predicate returns 1, 2,
	// 4 and 8 at VLEN 512, 1024, 2048 and 4096 without naming any of them. Nothing downstream is
	// per-k either: the caller passes the count to RvvEmitTypedAluChunkGroupCore, whose body is a
	// loop. T6b routed the remaining element-wise gates here -- RvvAluChunkShapeAdmit, the vadd
	// gate, the vsetvli/vle32.v/vse32.v shape predicates -- so this is now the tree's only
	// whole-chunk rule rather than the exception to a literal one.
	//
	// It holds NO flag, NO backend test and NO host-feature probe, for the reason
	// RvvAluChunkShapeAdmit gives: those belong to the per-backend gate that calls this.
	//
	// THE DIVISION IS EXACT, AND THAT IS A REFUSAL RATHER THAN A ROUNDING. There is no partial
	// tail chunk and no rounding up: a VLEN that is not a whole multiple of 512 is REFUSED here
	// and keeps the helper, because a 64-byte window covering fewer than 64 live bytes would read
	// and write bytes belonging to the next register's slot. Admission comes first; only on the
	// admitted domain is `k` defined at all, and there it is an exact divide, so the emitted frame
	// covers the register exactly once with no tail. Describing this as a ceiling would suggest a
	// partial-tail capability this slice does not have and does not claim.
	//
	// THE UPPER BOUND IS THE STORAGE RESERVATION, not a policy: kMaxChunks is VLEN_MAX_BITS/512
	// and sizes the shared body's per-chunk arrays, so admitting more chunks than that would
	// overflow them. Checked here rather than assumed.
	u8 RvvGenericChunkShapeAdmit(u32 sew_bytes) const;

	// P3.5a. TYPED chunk lowering for exact unmasked vmul.vv (config::rvv_qcg_typed_chunk_mul).
	// Returns the admitted 512-bit host chunk count or 0 when the instruction must keep the
	// existing rv32_vimul helper. Deliberately a SEPARATE predicate from RvvQcgTypedChunkAdmit
	// above, on its own switch and with a strictly narrower SEW rule: see config.h and the
	// definition for why the multiply cannot inherit the add's width table.
	// HM.2a: its shape half is RvvGenericChunkShapeAdmit, so the count is 1/2/4/8 at VLEN
	// 512/1024/2048/4096. It is the only route with that reach at this checkpoint.
	u8 RvvQcgTypedMulChunkAdmit(u32 sew_bytes) const;
	// A1 (2026-09-05). The width-correct form of the gate above, and the ONE the vmul.vv route
	// and the run admission now use -- the same form RvvQcgTypedXorChunkShape has had since
	// P7N-D. The u8 form above is kept for every pre-existing caller and is
	// `.bytes == 64 ? .count : 0`. The multiply's OWN rows (its switch, the AVX-512F probe for
	// `vpmulld`, SEW=32 only) are unchanged; only the width rule is the shared RvvRouteChunkShape.
	RvvChunkShape RvvQcgTypedMulChunkShape(u32 sew_bytes) const;

	// T1b. The LLVM/AOT gate for exact unmasked `vmul.vv`. Same two-gate shape S3.4/S3.5/S3.6/S3.10a
	// established and for the same reason: it requires the route's OWN pre-existing switch
	// (`--rvv-qcg-typed-chunk-mul`) as well as `RvvSSAEnabled()`, so turning on `--rvv-vector-ssa`
	// cannot sweep this opcode into a route nobody asked for, and an accepted evidence arm's flag
	// keeps meaning what it meant. Exactly one of this and RvvQcgTypedMulChunkAdmit can return
	// non-zero for a given compile -- that one requires !aot_use_llvm and this one requires
	// RvvSSAEnabled(), which requires aot_use_llvm -- so the pair is a backend selection, not a
	// widening of what is admitted.
	//
	// IT SHARES THE MULTIPLY'S OWN SHAPE HALF, RvvGenericChunkShapeAdmit, rather than the narrower
	// RvvAluChunkShapeAdmit the subtract's LLVM gate uses, so one opcode never has two shape rules
	// that could drift apart. The VLEN narrowing to {512, 1024} that T1b's scope requires is NOT
	// restated here: `RvvSSAEnabled()` already refuses every other width (rv32_qir.cpp), so on this
	// arm k is 1 or 2 and nothing else. Stating it twice would be a second, independently mutable
	// copy of a rule that already has one home.
	u8 RvvLLVMMulChunkAdmit(u32 sew_bytes, u16 *chunk_bytes = nullptr) const;
	// Builds the typed V512 chunk group for one admitted vmul.vv. Same load-major shape and the
	// same raw-u32 vtype convention as RvvEmitTypedChunkGroup; the body op is vchunkmul and the
	// guard frame's fallback stub is the pre-existing id_rv32_vimul.
	// A1: takes the SHAPE rather than a bare count and Panics unless `bytes * count == vlen/8`,
	// exactly as the xor/or builders do.
	void RvvEmitTypedMulChunkGroup(insn::Insn_vmul_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				       RvvChunkShape shape);

	// S2.1. TYPED chunk lowering for exact unmasked vsub.vv (config::rvv_qcg_typed_chunk_sub).
	// Returns the admitted 512-bit host chunk count -- 1 at VLEN=512, 2 at VLEN=1024 -- or 0 when
	// the instruction must keep the existing rv32_vialu helper. A SEPARATE predicate on its own
	// switch for the same reason the multiply's is separate (config.h).
	u8 RvvQcgTypedSubChunkAdmit(u32 sew_bytes) const;
	// A1. The width-correct form of the gate above (see RvvQcgTypedMulChunkShape).
	RvvChunkShape RvvQcgTypedSubChunkShape(u32 sew_bytes) const;
	// Builds the typed V512 chunk group for one admitted vsub.vv. Same load-major shape and the
	// same raw-u32 vtype convention as the two above; the body op is vchunksub and the guard
	// frame's fallback stub is the pre-existing id_rv32_vialu. Unlike the add and the multiply the
	// body op's INPUT ORDER is semantic -- vs2 chunk first, vs1 chunk second -- see the definition.
	// S3.10a: now a thin typed wrapper over RvvEmitTypedAluChunkGroupCore, which is where that
	// operand order lives for the whole family. The constructed QIR is unchanged except that the
	// core also takes the vector-SSA precise-state boundary this builder previously lacked -- a
	// no-op on the pure-QCG path, where RvvSSAEnabled() is false and no such cache exists, and a
	// correctness requirement now that the LLVM path can reach this route.
	// A1: takes the SHAPE rather than a bare count (see RvvEmitTypedMulChunkGroup).
	void RvvEmitTypedSubChunkGroup(insn::Insn_vsub_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				       RvvChunkShape shape);

	// S2.2. TYPED chunk lowering for exact unmasked vxor.vv (config::rvv_qcg_typed_chunk_xor).
	// Returns the admitted 512-bit host chunk count -- 1 at VLEN=512, 2 at VLEN=1024 -- or 0 when
	// the instruction must keep the existing rv32_vialu helper. A SEPARATE predicate on its own
	// switch for the same reason the multiply's and the subtract's are separate (config.h).
	// P7N-D: now `RvvQcgTypedXorChunkShape(sew).bytes == 64 ? .count : 0`. The u8 form names a
	// count of SIXTY-FOUR-BYTE chunks and can express nothing else, so a narrow shape must NOT be
	// flattened into it -- a {16,1} reported here as `1` would hand a 64-byte emitter a 16-byte
	// register. Every pre-existing caller of this function therefore sees exactly what it saw
	// before, and the narrow widths are reachable only through the shape form below.
	u8 RvvQcgTypedXorChunkAdmit(u32 sew_bytes) const;
	// P7N-D. The width-correct form of the gate above, and the ONE the vxor.vv route now uses.
	// Its gate rows -- the switch, the backend selection, --rvv-verify and the AVX-512F probe --
	// are the SAME rows in the SAME order the u8 form applies; only the shape half differs, and
	// it differs by calling RvvRouteChunkShape instead of RvvAluChunkShapeAdmit. With
	// `--rvv-qcg-narrow-chunk-width` off the two answer identically at every VLEN.
	RvvChunkShape RvvQcgTypedXorChunkShape(u32 sew_bytes) const;

	// T1d. The LLVM/AOT gate for exact unmasked `vxor.vv`. Same two-gate shape S3.4/S3.5/S3.6/
	// S3.10a/T1b established and for the same reason: it requires the route's OWN pre-existing
	// switch (`--rvv-qcg-typed-chunk-xor`) as well as `RvvSSAEnabled()`, so turning on
	// `--rvv-vector-ssa` cannot sweep this opcode into a route nobody asked for, and an accepted
	// evidence arm's flag keeps meaning what it meant. Exactly one of this and
	// RvvQcgTypedXorChunkAdmit can return non-zero for a given compile -- that one requires
	// !aot_use_llvm and this one requires RvvSSAEnabled(), which requires aot_use_llvm -- so the
	// pair is a backend selection, not a widening of what is admitted.
	//
	// Both gates end in the SAME RvvAluChunkShapeAdmit, which is what keeps one opcode from having
	// two shape rules that could drift apart. T1d moved the QCG gate's inline VLEN/SEW rows onto
	// that shared function to make this true; the admitted set is unchanged (512/1024 x SEW=32).
	u8 RvvLLVMXorChunkAdmit(u32 sew_bytes, u16 *chunk_bytes = nullptr) const;

	// Builds the typed V512 chunk group for one admitted vxor.vv. Same load-major shape and the
	// same raw-u32 vtype convention as the three above; the body op is vchunkxor and the guard
	// frame's fallback stub is the pre-existing id_rv32_vialu -- the SAME stub vsub.vv falls back
	// to, because both encodings belong to the same generic vialu family.
	// P7N-D: takes the SHAPE rather than a bare count, exactly as the vadd builder has since M2C,
	// and Panics unless `bytes * count == vlen/8`. The route's LLVM arm passes {64, k}, which is
	// what it always constructed.
	void RvvEmitTypedXorChunkGroup(insn::Insn_vxor_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				       RvvChunkShape shape);

	// S2.3. TYPED chunk lowering for exact unmasked vor.vv (config::rvv_qcg_typed_chunk_or).
	// Returns the admitted 512-bit host chunk count -- 1 at VLEN=512, 2 at VLEN=1024 -- or 0 when
	// the instruction must keep the existing rv32_vialu helper. A SEPARATE predicate on its own
	// switch for the same reason all four above are separate (config.h).
	// P7N-D: the vxor gate's treatment, for the vxor gate's reason -- see it above.
	u8 RvvQcgTypedOrChunkAdmit(u32 sew_bytes) const;
	// P7N-D. The width-correct form of the gate above, and the ONE the vor.vv route now uses.
	RvvChunkShape RvvQcgTypedOrChunkShape(u32 sew_bytes) const;

	// T1e. The LLVM/AOT gate for exact unmasked `vor.vv`. Same two-gate shape S3.4/S3.5/S3.6/
	// S3.10a/T1b/T1d established and for the same reason: it requires the route's OWN pre-existing
	// switch (`--rvv-qcg-typed-chunk-or`) as well as `RvvSSAEnabled()`, so turning on
	// `--rvv-vector-ssa` cannot sweep this opcode into a route nobody asked for, and an accepted
	// evidence arm's flag keeps meaning what it meant. Exactly one of this and
	// RvvQcgTypedOrChunkAdmit can return non-zero for a given compile -- that one requires
	// !aot_use_llvm and this one requires RvvSSAEnabled(), which requires aot_use_llvm -- so the
	// pair is a backend selection, not a widening of what is admitted.
	//
	// Both gates end in the SAME RvvAluChunkShapeAdmit, which is what keeps one opcode from having
	// two shape rules that could drift apart. T1e moved the QCG gate's inline VLEN/SEW rows onto
	// that shared function to make this true, exactly as T1d did for the xor; the admitted set is
	// unchanged (512/1024 x SEW=32).
	u8 RvvLLVMOrChunkAdmit(u32 sew_bytes, u16 *chunk_bytes = nullptr) const;
	// Builds the typed V512 chunk group for one admitted vor.vv. Same load-major shape and the
	// same raw-u32 vtype convention as the four above; the body op is vchunkor and the guard
	// frame's fallback stub is the pre-existing id_rv32_vialu -- the SAME stub vsub.vv and vxor.vv
	// fall back to, because all three encodings belong to the same generic vialu family.
	// P7N-D: the xor builder's treatment, for the same reason.
	void RvvEmitTypedOrChunkGroup(insn::Insn_vor_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				      RvvChunkShape shape);

	// S2.4. TYPED chunk lowering for exact unmasked vand.vv (config::rvv_qcg_typed_chunk_and).
	// Returns the admitted 512-bit host chunk count -- 1 at VLEN=512, 2 at VLEN=1024 -- or 0 when
	// the instruction must keep the existing rv32_vialu helper. A SEPARATE predicate on its own
	// switch for the same reason all five above are separate (config.h).
	u8 RvvQcgTypedAndChunkAdmit(u32 sew_bytes) const;
	// A1. The width-correct form of the gate above (see RvvQcgTypedMulChunkShape).
	RvvChunkShape RvvQcgTypedAndChunkShape(u32 sew_bytes) const;

	// T1f. The LLVM/AOT gate for exact unmasked `vand.vv`, and the LAST of the typed integer
	// element-wise family to acquire one. Same two-gate shape S3.4/S3.5/S3.6/S3.10a/T1b/T1d/T1e
	// established and for the same reason: it requires the route's OWN pre-existing switch
	// (`--rvv-qcg-typed-chunk-and`) as well as `RvvSSAEnabled()`, so turning on `--rvv-vector-ssa`
	// cannot sweep this opcode into a route nobody asked for, and an accepted evidence arm's flag
	// keeps meaning what it meant. Exactly one of this and RvvQcgTypedAndChunkAdmit can return
	// non-zero for a given compile -- that one requires !aot_use_llvm and this one requires
	// RvvSSAEnabled(), which requires aot_use_llvm -- so the pair is a backend selection, not a
	// widening of what is admitted.
	//
	// Both gates end in the SAME RvvAluChunkShapeAdmit, which is what keeps one opcode from having
	// two shape rules that could drift apart. T1f moved the QCG gate's inline VLEN/SEW rows onto
	// that shared function, exactly as T1d did for the xor and T1e for the or; the admitted set is
	// unchanged (512/1024 x SEW=32). With this the whole family -- add, sub, mul, xor, or, and --
	// shares one shape rule across both backends, with no per-opcode copy left anywhere.
	u8 RvvLLVMAndChunkAdmit(u32 sew_bytes, u16 *chunk_bytes = nullptr) const;
	// Builds the typed V512 chunk group for one admitted vand.vv. Same load-major shape and the
	// same raw-u32 vtype convention as the five above; the body op is vchunkand and the guard
	// frame's fallback stub is the pre-existing id_rv32_vialu -- the SAME stub vsub.vv, vxor.vv
	// and vor.vv fall back to, because all four encodings belong to the same generic vialu family.
	// A1: takes the SHAPE rather than a bare count (see RvvEmitTypedMulChunkGroup).
	void RvvEmitTypedAndChunkGroup(insn::Insn_vand_vv i, u32 vtype_raw, u32 vlen, u32 sew_bytes,
				       RvvChunkShape shape);

	// S2.6. TYPED chunk lowering for exact unmasked unit-stride vle32.v
	// (config::rvv_qcg_typed_chunk_vle). Returns the admitted 512-bit host chunk count -- T6b: the
	// shared RvvGenericChunkShapeAdmit's k, so 1/2/4/8 at VLEN 512/1024/2048/4096 -- or 0 when the
	// instruction must keep the existing rv32_vle helper. A SEPARATE predicate on its own switch
	// for the same reason all six above are separate (config.h).
	//
	// It takes the RAW INSTRUCTION WORD, which none of the six above needs, and that is the whole
	// difference between a memory route and an ALU route here: rv32_decode.h gives each ALU route
	// its own Op for the exact unmasked encoding, but it routes masked loads and every supported
	// EEW to the SAME Op::_vle. `vm` and the width field are therefore this predicate's own
	// obligation and cannot be inherited from the decoder's choice.
	u8 RvvQcgTypedVleChunkAdmit(u32 raw, u32 sew_bytes) const;
	// S1 (2026-09-05). The width-correct form of the gate above, and the ONE the vle32.v route now
	// uses -- the exact twin of RvvQcgTypedVseChunkShape below, for the load side. The u8 form
	// above is kept for every pre-existing caller and is `.bytes == 64 ? .count : 0`.
	RvvChunkShape RvvQcgTypedVleChunkShape(u32 raw, u32 sew_bytes) const;
	// S3.5. The SHAPE half of the S2.6 admission test -- everything that is a property of the
	// instruction word, the vtype-derived SEW and the runtime VLEN, and nothing that is a property
	// of which backend is compiling or of what the HOST CPU can execute. Both backend gates call it,
	// so neither can drift from the other's envelope. Returns the admitted 512-bit host chunk count
	// or 0, exactly as the two gates that wrap it do. T6b: its width and SEW rows are now the shared
	// RvvGenericChunkShapeAdmit; the LLVM gate that wraps it is unaffected above VLEN=1024 because
	// RvvSSAEnabled() refuses those widths on its own.
	u8 RvvVleChunkShapeAdmit(u32 raw, u32 sew_bytes) const;
	// S1. The width-correct form of the shape half: identical instruction-word rows, with the
	// whole-512-chunk width rule replaced by RvvRouteChunkShape -- what P7N-D did for the store.
	// Both backend gates reach the narrow widths only through the pure-QCG one; the LLVM arm is
	// untouched (it asks the u8 form, which reports a narrow shape as 0).
	RvvChunkShape RvvVleChunkShape(u32 raw, u32 sew_bytes) const;
	// A13. THE ONE WIDTH RULE FOR UNIT-STRIDE MEMORY, shared by the load and the store: the
	// register's byte tiling (RvvRouteChunkShape's geometry -- min(VLEN/8,64)-byte chunks,
	// (VLEN/8)/chunk of them, narrow widths only under --rvv-qcg-narrow-chunk-width) checked
	// against the ELEMENT width the encoding names. EEW=32 is the pre-A13 admission; EEW=64 is
	// admitted only under config::rvv_qcg_typed_chunk_mem_e64 and only for the QCG backend.
	// The caller has already required SEW == EEW and LMUL == 1, so EMUL == 1 and the register
	// is the whole transfer: vl*EEW == VLMAX*SEW == VLEN/8 bytes at every admitted EEW.
	RvvChunkShape RvvMemChunkShape(u32 eew_bytes) const;
	// A13: the EEW in bytes the unit-stride encoding's width field names, or 0 if unsupported.
	static u32 RvvUnitStrideEewBytes(u32 raw);
	// S3.5. The LLVM/AOT gate for the same exact vle32.v envelope. Separate from the QCG gate
	// because the two have DIFFERENT backend preconditions and must keep being able to disagree:
	// the QCG gate carries a host AVX-512F probe (it writes a literal EVEX `vmovdqu64`), and this
	// one must not, because the IR it produces is a plain 64-byte load that LLVM legalizes for
	// whatever subtarget the artifact is compiled for.
	u8 RvvLLVMVleChunkAdmit(u32 raw, u32 sew_bytes, u16 *chunk_bytes = nullptr) const;
	// Builds the typed V512 chunk group for one admitted vle32.v. Load-major like the six above,
	// but the two halves are not theirs: the read side is `vchunkload` in its INDIRECT addressing
	// form (guest memory -> ZMM, base read from CPUState through the emitter's fixed scratch
	// register -- see qir.h for why the direct form cannot be used inside a guard frame) and the
	// write side is the already-accepted `vstatechunkstore` into the same vec.vreg windows the six
	// ALU routes write. The guard frame's fallback stub is the pre-existing id_rv32_vle.
	// S1: takes the SHAPE rather than a bare count, and Panics unless `bytes * count == vlen/8`,
	// exactly as the store frame does. On this route that check bounds how many bytes of GUEST
	// MEMORY the frame reads and how many bytes of the vd window it writes.
	void RvvEmitTypedVleChunkGroup(insn::Insn_vle i, u32 vtype_raw, u32 vlen, RvvChunkShape shape);

	// S2.7. TYPED chunk lowering for exact unmasked unit-stride vse32.v
	// (config::rvv_qcg_typed_chunk_vse). Returns the admitted 512-bit host chunk count -- T6b: the
	// shared RvvGenericChunkShapeAdmit's k, so 1/2/4/8 at VLEN 512/1024/2048/4096 -- or 0 when the
	// instruction must keep the existing rv32_vse helper. A SEPARATE predicate on its own switch
	// for the same reason all seven above are separate (config.h).
	//
	// It takes the RAW INSTRUCTION WORD for the load's reason, which applies unchanged on the
	// store side: rv32_decode.h routes masked stores and every supported EEW to the SAME Op::_vse,
	// so `vm` and the width field are this predicate's own obligation. Its ONE structural
	// difference from the load's predicate is the field name -- the unit-stride selector at
	// bits 24:20 is `sumop` here and `lumop` there, and the constant it must equal is the same.
	// P7N-D: now `RvvQcgTypedVseChunkShape(raw, sew).bytes == 64 ? .count : 0`. The u8 form names
	// a count of 64-byte chunks and can express nothing else, so a narrow shape must not be
	// flattened into it -- on THIS route that mistake is a 64-byte write over guest memory the
	// store was not asked to touch.
	u8 RvvQcgTypedVseChunkAdmit(u32 raw, u32 sew_bytes) const;
	// P7N-D. The width-correct form of the gate above, and the ONE the vse32.v route now uses.
	RvvChunkShape RvvQcgTypedVseChunkShape(u32 raw, u32 sew_bytes) const;
	// S3.6. The SHAPE half of the S2.7 admission test -- everything that is a property of the
	// instruction word, the vtype-derived SEW and the runtime VLEN, and nothing that is a property
	// of which backend is compiling or of what the HOST CPU can execute. Both backend gates call
	// it, so neither can drift from the other's envelope. Returns the admitted 512-bit host chunk
	// count or 0, exactly as the two gates that wrap it do -- T6b: from the shared
	// RvvGenericChunkShapeAdmit, as on the load side. Structurally identical to
	// RvvVleChunkShapeAdmit and deliberately NOT merged with it: the two differ in the opcode, in
	// the unit-stride selector's name and, decisively, in direction -- one wrong admission here
	// WRITES 64 bytes of guest memory, so the two envelopes must stay independently auditable.
	u8 RvvVseChunkShapeAdmit(u32 raw, u32 sew_bytes) const;
	// P7N-D. The width-correct form of the shape half: identical instruction-word rows, with the
	// whole-512-chunk width rule replaced by RvvRouteChunkShape. Both backend gates reach the
	// narrow widths only through the pure-QCG one, so the load side's twin and the LLVM arm are
	// untouched.
	RvvChunkShape RvvVseChunkShape(u32 raw, u32 sew_bytes) const;
	// S3.6. The LLVM/AOT gate for the same exact vse32.v envelope. Separate from the QCG gate for
	// the reason RvvLLVMVleChunkAdmit is separate from its own QCG twin: the QCG gate carries a
	// host AVX-512F probe (it writes a literal EVEX `vmovdqu64`) and this one must not, because
	// the IR it produces is a plain 64-byte store that LLVM legalizes for whatever subtarget the
	// artifact is compiled for.
	u8 RvvLLVMVseChunkAdmit(u32 raw, u32 sew_bytes, u16 *chunk_bytes = nullptr) const;
	// Builds the typed V512 chunk group for one admitted vse32.v. The MIRROR of the vle frame:
	// the read side is the already-accepted `vstatechunkload` out of the same vec.vreg windows the
	// six ALU routes read, and the write side is `vchunkstore` in its INDIRECT addressing form
	// (ZMM -> guest memory, base read from CPUState through the emitter's fixed scratch register
	// -- see qir.h for why the direct form cannot be used inside a guard frame). Load-major, so
	// every chunk's CPUState read precedes every chunk's guest-memory write. The guard frame's
	// fallback stub is the pre-existing id_rv32_vse.
	// P7N-D: takes the SHAPE rather than a bare count, and Panics unless
	// `bytes * count == vlen/8`. On this route that check bounds how many bytes of GUEST MEMORY
	// the frame writes.
	void RvvEmitTypedVseChunkGroup(insn::Insn_vse i, u32 vtype_raw, u32 vlen, RvvChunkShape shape);

	// T7S direct-state setup lowering. Legal immediate-vtype vsetvli/vsetivli forms at the
	// proved VLEN512/1024 widths become one `rvvsetvl` node; malformed/reserved forms retain the
	// existing helper. Admission is derived only from instruction fields, architectural vtype
	// legality and VLEN -- never a workload PC or an observed AVL value.
	//
	// It returns a BOOL rather than a chunk count, and that is not cosmetic: this route has no
	// chunks. It writes four scalar CPUState fields and one guest GPR whatever the VLEN is, so
	// there is no per-512-bit-chunk quantity for a count to name. VLEN enters only as the VLMAX
	// and vlenb constants the node carries.
	//
	// Both predicates take the raw word so their shape checks remain fail-closed if decoding
	// changes. The LLVM gate shares the legal immediate-vtype shape but excludes keep-VL.
	bool RvvQcgSetVLAdmit(u32 raw, dbt::rv32::VType vt) const;
	bool RvvQcgSetIVLIAdmit(u32 raw, dbt::rv32::VType vt) const;
	bool RvvQcgSetupShapeAdmit(u32 raw, dbt::rv32::VType vt, bool immediate_avl) const;
	// LLVM's immediate-vtype shape: the shared QCG legality check, excluding keep-VL until
	// the LLVM node can express its reserved-case semantics.
	bool RvvSetVLShapeAdmit(u32 raw, dbt::rv32::VType vt) const;
	// S3.4. The LLVM/AOT gate for the same exact `vsetvli` envelope. Separate from the QCG gate
	// because the two have DIFFERENT backend preconditions and must keep being able to disagree.
	bool RvvLLVMSetVLAdmit(u32 raw, dbt::rv32::VType vt) const;
	// W30. The LLVM/AOT gate for `vsetivli`, i.e. the SAME envelope with the immediate-AVL shape
	// row instead of the register one. It is a separate function from RvvLLVMSetVLAdmit for the
	// reason RvvQcgSetIVLIAdmit is separate from RvvQcgSetVLAdmit -- the two opcodes' shape rows
	// differ (bits 31:30, and vsetivli has no keep-VL form at all) -- and it deliberately does NOT
	// route through RvvSetVLShapeAdmit, whose extra `rd == 0 && field(19:15) == 0` row means
	// "reserved keep-VL" for vsetvli and would wrongly refuse the perfectly legal
	// `vsetivli x0, 0, <vtype>`.
	bool RvvLLVMSetIVLIAdmit(u32 raw, dbt::rv32::VType vt) const;

	// W21. The two halves of the block-scoped VL knowledge (`rvv_bb_vl`, below): what an OPCFG
	// instruction leaves behind, and whether a chunk-planning route may treat the live vl as
	// architecturally full for a given vtype. Both are defined in rv32_qir.cpp, next to each other,
	// with the full creation/propagation/invalidation/TB-boundary rule set.
	void RvvRecordVlAfterSetVl(u32 vtypei, u32 avl, bool avl_known, bool keep_vl);
	bool RvvStaticFullVl(dbt::rv32::VType vt, u32 vlen) const;

	// R1A.3a. A1's evaluation: the admitted 512-bit chunk count for one run member, obtained by
	// calling THAT OPERATION'S OWN admission predicate -- the identical call the corresponding
	// single-instruction TRANSLATOR makes, including its per-route flag, backend gate, VLEN set,
	// SEW rule and host-feature probe. A run can therefore never admit a shape the
	// single-instruction route would have refused, and adding an operation to the family is one
	// row here plus one metadata row in rv32_vrun.cpp.
	// P7M-A: the query carries the raw word and the run's vtype as well as the SEW, because the
	// two FP routes' predicates take those. Nothing is decided from them here -- they are passed
	// straight through to the same predicate the single-instruction translator calls.
	rvvrun::MemberShape RvvRunMemberChunks(rvvrun::MemberQuery const &q) const;
	// The MemberAdmit trampoline: FormRun takes a plain function pointer plus context so it can
	// run inside translation without allocating.
	static rvvrun::MemberShape RvvRunMemberChunksThunk(void *ctx, rvvrun::MemberQuery const &q);
	// Form the run starting at `entry_pc` using this translator's live configuration. Returns an
	// empty descriptor with CutReason::Disabled when the observation switch, --rvv-direct or
	// --rvv-verify say this build must not form runs.
	rvvrun::RunDescriptor RvvFormVectorRunAt(u32 entry_pc, u32 boundary_pc, u32 insn_budget,
						 rvvrun::RunLimits limits) const;
	// R1A.3a observation hook, called from TranslateIPRange only when config::rvv_vector_run is
	// on. Records the descriptor in rvvrun::g_stats and leaves it in rvv_run_pending for the
	// R1A.3b consumer below; emits nothing itself.
	void RvvScanVectorRun(u32 boundary_ip, u32 insn_budget);
	// F1: the vtype a scan at the current point would be formed against -- shared by
	// RvvFormVectorRunAt and RvvEmptyScanCutAt so the two can never disagree about it.
	rvvrun::RunVType RvvScanVType() const;
	// F1: rvvrun::EmptyScanCut with this translator's live configuration, including
	// RvvFormVectorRunAt's own Disabled answer; nullopt when the full scan must run.
	std::optional<rvvrun::CutReason> RvvEmptyScanCutAt(u32 entry_pc, u32 boundary_pc,
							   u32 insn_budget) const;
	// T7g analysis-only observer. Forms maximal non-overlapping candidates inside this real QIR
	// basic-block interval and sends explicit decode/route/QIR/CFG facts to the T7f detector.
	void RvvObserveLaneCandidate(u32 boundary_ip, u32 insn_budget);

	// R1A.3b. THE ONE OPERATION DISPATCH for the typed integer element-wise chunk family. Every
	// member of every frame -- single-instruction or run, first position or last -- gets its lane
	// operation from here, so there is no place where a particular pair of opcodes could be given
	// its own body. Adding an operation is one row here.
	void RvvEmitChunkAluOp(rvvrun::RunOp op, qir::VOperand d, qir::VOperand s2, qir::VOperand s1,
			       u8 sew_bytes);

	// P7M-A. THE ONE OPERATION DISPATCH FOR THE WHOLE FAMILY, integer and FP. Every lane
	// operation emitted into a typed chunk frame -- by the shared integer body, by the shared FP
	// body, and by every member of every run at every position -- comes from here. `funct6` and
	// `chunk` are the two facts an FP lane op needs and an integer one ignores; `dold` is the
	// fused forms' third input and is a BAD operand for everything else. See the definition for
	// the operand-order contract, which is semantic and is fixed there for the whole family.
	void RvvEmitChunkLaneOp(rvvrun::RunOp op, u8 sew_bytes, u8 funct6, u8 chunk, qir::VOperand d,
				qir::VOperand s2, qir::VOperand s1, qir::VOperand dold, u8 imm5 = 0,
				bool masked = false);

	// P7M-A. THE ONE MATERIALIZING BODY for an FP lane instruction -- the counterpart of
	// RvvEmitTypedAluChunkBody below, and extracted for the same reason: both the accepted
	// single-instruction FP frames and a vector run in materialize mode call it, so "the run's
	// materialize body IS the single-instruction body" is structural rather than a coincidence
	// between two hand-written emitters. It emits NO frame of its own and no FP bracket; the
	// caller owns both.
	// A9: `chunk_bytes` (16/32/64) replaces the old VLEN/512 `per_reg`: chunks per register is
	// (VLEN/8)/chunk_bytes, chunk c of a group lives at register (reg + c/per_reg), byte
	// (c%per_reg)*chunk_bytes, and every value is typed VectorVTypeForBytes(chunk_bytes).
	// S1-2A: a BOUNDED `plan` switches this body to CHUNK-MAJOR (batch 1) and makes it emit, per
	// chunk, one `vchunkactive` bound followed by that chunk's own `vchunkmaskset` before its
	// loads. The node SET is otherwise identical -- same loads, same lane ops, same stores, same
	// offsets -- so a caller that passes a bounded plan declares `nchunks` MORE typed ops than one
	// that does not, and nothing else about its frame changes. Only a caller whose shared masks are
	// per-chunk may pass one (the body creates them), which is why both FP groups feed the planner
	// `per_chunk_active_mask = (shared_mask_ops == nchunks)`.
	// S1-2D: the vfma group passes one too, from the same shared planner. The only thing that
	// differs there is `reads_vd`, and the extra load it adds is a load of chunk c inside chunk c's
	// own region, so chunk-major keeps it before that chunk's store exactly as batch mode did.
	// W26: the plan carries the bound's ELEMENT BASE as well as the decision, so this body no longer
	// re-derives `first * (chunk_bytes / sew)` of its own. The default is the REFUSING plan, which
	// is what the vector run's materialize arm gets -- a run frame must never be bounded.
	void RvvEmitTypedFpChunkBody(rvvrun::RunOp op, u32 rd, u32 rs1, u32 rs2, u8 sew, u8 funct6,
				     bool src1_is_fscalar, bool reads_vd, u8 nchunks, u16 chunk_bytes,
				     bool masked = false, bool bounded = false);

	// R1A.3d. THE ONE MATERIALIZING BODY for this shape: per chunk, two source loads, the lane
	// operation, the destination store -- `4 * nchunks` typed ops, and no frame of its own. Both
	// the accepted single-instruction route and a run in materialize mode call it, which is what
	// makes "the run's materialize body IS the single-instruction body" structural rather than a
	// coincidence between two hand-written emitters.
	// M2C: `chunk_bytes` is the width of ONE chunk. Every caller but the vadd slice passes the
	// AVX-512 chunk (64), which is what they have always constructed; only vadd derives it from
	// VLEN. The stride between consecutive chunks is chunk_bytes, so the width and the offset
	// arithmetic cannot disagree.
	// A6: `src1_kind` is an RvvAluSrc1 value. Vector (default) is the two-source body unchanged;
	// XScalar / SImm5 replace source 1 by ONE vchunkbroadcast per frame (of gpr[rs1] / of the
	// sign-extended 5-bit `rs1` field) consumed by every chunk's lane op, so the body is
	// k loads + 1 broadcast + k ops + k stores instead of 2k + k + k.
	// C5: `active_lane_store` makes each destination store carry this chunk's element width and
	// index, so Emit_vstatechunkstore predicates it on the LIVE `vec.vl`. Default false keeps the
	// pre-C5 full-width store, so every existing caller is unchanged.
	// ORDER ITEM 3: `architectural_mask` adds the THIRD conjunct of the contract's active predicate
	// to that same store node -- `(e < vl) && v0[e]`. Only meaningful with `active_lane_store`
	// (an unpredicated store cannot express "some elements are not written"), which the node
	// enforces rather than trusting. Default false keeps every existing caller unchanged.
	void RvvEmitTypedAluChunkBody(rvvrun::RunOp op, u32 rd, u32 rs1, u32 rs2, u8 sew_bytes,
				      u8 nchunks, u16 chunk_bytes = 64, u8 src1_kind = 0,
				      bool active_lane_store = false,
				      bool architectural_mask = false);

	// R1A.3b. Build the guarded frame for a whole admitted run: one guard, one load of each
	// live-in chunk, the members' lane operations in guest order over component SSA values, one
	// store of each FINAL live-out chunk, and an ordered whole-run fallback. Generic in the run
	// length and in the operation of every member.
	void RvvEmitVectorRunGroup(rvvrun::RunDescriptor const &d);
	// C2l. THE ONE PLACE a materialize-run member is lowered, and THE ONE PLACE its typed-op
	// count comes from.
	//
	// `emit=false` constructs nothing and returns the number of typed ops the frame must declare
	// for this member; `emit=true` constructs exactly that many nodes and returns the same
	// number. Planning and emission therefore cannot drift: they are the SAME switch evaluated
	// twice, not two switches that have to be kept in step by hand. This is the idiom
	// RvvEmitFpSharedMasks and the split body already use for their own non-formulaic counts.
	//
	// C2j's failure was the absence of this function. The materialize arm used to decide between
	// exactly two bodies -- FP or "two-input integer ALU" -- so nine of the fifteen member SHAPES
	// the run classifier can admit reached a two-source integer dispatch that has six cases, and
	// the declaration was a single four-term formula that is wrong for seven of the fifteen.
	//
	// The switch inside has NO `default:` on purpose: a new `RunOp` without a body here is a
	// compile-time failure (C2m promotes -Wswitch to an error for guest/rv32_qir.cpp in
	// dbt/CMakeLists.txt; before that it was only a warning), not a run-time Panic. That is
	// fail-closed in the only
	// form this ablation permits -- a MATERIALIZE-CONDITIONAL run-time refusal would make the two
	// arms form different runs and destroy the single-factor comparison the switch exists for.
	// The count is read from the DESCRIPTOR's shape fields only; `raw` is never re-decoded and
	// `src1_def`/`src2_def`/`srcd_def` are never read, because those are SSA dataflow and a
	// materialize member hands its result to the next member through CPUState.
	u32 RvvMaterializeRunMember(rvvrun::RunMember const &m, u8 nchunks, u16 chunk_bytes,
				    bool emit);
	// A3. The partial-vl arm shared by the single-instruction ALU frame and every vector-run
	// body kind. `members` are executed in guest order as load-compute-merge-store. Returns the
	// number of typed body ops the arm emits (or would emit, when `emit` is false), so the
	// frame's n_typed can declare it; 0 means "no arm" (switch off, backend, or a member outside
	// the integer .vv family), in which case the caller keeps the old guard kind.
	// A12. The FP frame's shared active masks. Returns the number of typed body ops the masks
	// add (nchunks when the frame qualifies, else 0 -- switch off, run-time SEW, more chunks
	// than k1..k6 can hold), and when `emit` is set creates one vchunkmaskset per chunk and
	// records in `rvv_fp_shared_mask_chunks` how many chunks' masks are resident so
	// RvvEmitChunkLaneOp can name k(1+chunk) on every FP lane op of this frame. The caller
	// resets the count at the frame's end; no state outlives the frame.
	// G11-A added `full_vl_frame`: a frame whose guard already proved vl == VLMAX and
	// vstart == 0 emits unmasked lane ops and therefore must build no shared mask at all.
	// S1-2A added `defer_nodes`: the emit pass still establishes the frame's mask RESIDENCY (so
	// RvvEmitChunkLaneOp names k(1+chunk) on every lane op, exactly as before) but creates no
	// vchunkmaskset here, because the bounded body creates each chunk's mask inside that chunk's
	// own region. The returned COUNT is unchanged either way, so n_typed cannot drift.
	u32 RvvEmitFpSharedMasks(u8 nchunks, u8 sew_bytes, u16 chunk_bytes, bool emit,
				 bool full_vl_frame, bool defer_nodes = false, bool recycle_masks = false);
	u8 rvv_fp_shared_mask_chunks{0};

	u32 RvvEmitPartialAluArm(rvvrun::RunMember const *members, u8 n_members, u8 nchunks,
				 u16 chunk_bytes, bool emit);

	// P7N-G. What one pass of the live-range-splitting body did, so the frame can declare its
	// typed-op count before emitting and so the cost can be reported instead of hidden.
	//
	// The four counters separate the ops that REPLACE one the fixed placement would have emitted
	// anyway from the ones that are genuinely new. A live-in's FIRST load replaces a pass-1 load
	// one for one; a store of a component that is already dead replaces a pass-3 store one for
	// one. Only `reload` and `spill_live` are extra work, and they are the two numbers the report
	// has to state.
	//
	// P7N-J. WITH `config::rvv_run_split_value_weighted` ON, THE STORE COUNTERS ARE CLASSIFIED BY
	// THE SAME FACT THE COST MODEL USES, which is a strictly sharper question than the one the
	// shipped arm asks. There, a store is charged to `store_dead` when the component is dead;
	// here, when the stored value is that component's FINAL value -- i.e. when the closing loop
	// owed exactly this store and the body merely moved it earlier. A dead value that a later
	// member overwrites is not stored at all on that arm, so the partition is: `store_dead` +
	// `store_final` are the owed stores (their sum is popcount(live_out) * k when every live-out
	// is reached), and `spill_live` is the count of stores no correct body has to emit. The
	// `reload` counter keeps its meaning on both arms. Nothing else reads these fields, so the two
	// arms' numbers must be compared with their own definitions in hand.
	struct RvvSplitCost {
		u32 typed_ops{};   // the exact number of typed body ops this pass emitted
		u32 load_first{};  // first load of a live-in component (replaces a pass-1 load)
		u32 reload{};      // a later load of the same component -- EXTRA
		u32 store_dead{};  // store of a component with no next use (replaces a pass-3 store)
		u32 spill_live{};  // store of a component that is still live -- EXTRA
		u32 store_final{}; // final-pass store (replaces a pass-3 store)
		u32 peak_resident{}; // the largest resident set the pass ever held
	};

	// P7N-G. THE ONE PLACE the splitting body is decided AND emitted.
	//
	// Called TWICE per frame with identical inputs: once with `emit=false` to obtain the exact
	// typed-op count that `rvvtypedchunkbegin` must declare, then once with `emit=true` to
	// produce it. Every decision it makes reads only the residency/dirty bitmaps and the run's
	// own next-use information, never a QIR value, so the two passes take the same branches by
	// construction -- and `Emit_rvvtypedchunkend` Panics if they did not, which makes a
	// divergence loud rather than a frame whose guard-miss arm branches over the wrong bytes.
	//
	// G9. It takes BOTH frame-scope broadcast tables, because a move member's source may be an
	// F register (vfmv.v.f) or a GPR (vmv.v.x) and those values are created once per frame,
	// outside the residency pool, exactly as the fixed-placement body creates them.
	void RvvEmitVectorRunSplitBody(rvvrun::RunDescriptor const &d, u8 k, qir::VType ct,
				       u32 vreg_base, u32 slot, u32 stride,
				       std::array<qir::VOperand, 32> const &fbcast,
				       std::array<qir::VOperand, 32> const &xbcast, bool emit,
				       RvvSplitCost *cost);

	// R1A.3b. Consume the pending run if it has at least two members and the pure-QCG backend can
	// lower it. Returns the number of guest instructions the frame covers (0 = not consumed, in
	// which case the caller translates this instruction by its unchanged single-instruction
	// route). Advances insn_ip past the consumed members.
	u8 RvvTranslateVectorRun();

	qir::Builder qb;
	std::map<u32, qir::Block *> ip2bb;
	enum class Control { NEXT, BRANCH, TB_OVF } control{Control::NEXT};
	uptr vmem_base{};
	u32 insn_ip{0};
	u32 bb_ip{}; // for cflow_dump
	// RVV direct lowering: the vtypei of the most recent vsetvli seen in the CURRENT basic
	// block, or -1 if none. Used to decide whether vadd.vv can be lowered inline instead of
	// calling the helper. This is a PERFORMANCE hint only -- the emitted code re-checks the
	// architectural vtype/vl/vstart at run time and falls back to the helper on any mismatch,
	// so a stale or wrong value here can never produce a wrong result.
	u32 rvv_bb_vtype{~0u};
	// W21. THE BLOCK-SCOPED VL KNOWLEDGE, AND IT IS NOT A HINT.
	//
	// `rvv_bb_vtype` above may be a GUESS (the P7G entry hint, the ip-4 encoding recovery): a wrong
	// vtype costs a guard miss because the emitted frame re-proves vtype at run time. THIS FIELD HAS
	// NO SUCH BACKSTOP. It is read to decide whether a chunk-planning route may emit NO runtime
	// active-VL bound at all, and nothing downstream re-checks it, so it must hold on EVERY execution
	// of the block -- not on the one execution that happened to trigger compilation.
	//
	// Two lattice points, and the representation is the exact value rather than a "full" flag:
	//
	//   RVV_VL_UNKNOWN  dynamic/unknown -- every consumer keeps its existing runtime ladder;
	//   any other value the EXACT architectural `vl` at this point of this block, on every execution.
	//
	// The exact value is the smaller assumption, not the larger one. A "vl == VLMAX" boolean would
	// have to survive a `vsetvli x0,x0` retype that changes VLMAX, which is only safe if one also
	// assumes the guest never executes the reserved form; the exact value re-derives fullness at each
	// consumer from that consumer's own vtype and needs no such assumption. It also distinguishes
	// CONSTANT-SHORT vl (a `vsetivli` immediate below VLMAX) from unknown vl, which is the case the
	// accepted W15/W16 H.264 deblocking ROI is in and which must keep its ladder.
	//
	// Creation, propagation, invalidation and the block boundary are stated once, in
	// RvvRecordVlAfterSetVl and RvvStaticFullVl (rv32_qir.cpp).
	static constexpr u32 RVV_VL_UNKNOWN = ~0u;
	u32 rvv_bb_vl{RVV_VL_UNKNOWN};
	// W21 spec-conformance companion: the VLMAX `rvv_bb_vl` was established under, or 0 when the
	// vl is unknown. RVV 1.0 section 6.2 reserves the `vsetvli x0, x0` retype whenever the new
	// SEW/LMUL ratio CHANGES VLMAX -- whether or not the retained vl would still fit -- so the
	// propagation rule needs the OLD VLMAX, and it must be same-block KNOWLEDGE. `rvv_bb_vtype`
	// cannot serve: it may hold a guess (the P7G entry hint, the ip-4 recovery), which is sound
	// for vtype only because the emitted frame re-proves vtype at run time, and a bound that is
	// never emitted has no such backstop. Because the rule requires VLMAX to be unchanged, this
	// field is invariant for as long as one vl value is live.
	u32 rvv_bb_vl_vlmax{0};
	// P7G: the job's live-RVV-configuration hint, held for the whole region so
	// TranslateIPRange can seed `rvv_bb_vtype` from it at the region-entry ip range only.
	// Read in exactly one place; never written after Translate() sets it.
	// It carries vtype ONLY (see RvvEntryHint in qmc/compile.h, "vl AND vstart ARE DELIBERATELY
	// ABSENT"), and W21 does not add vl to it: see RvvStaticFullVl's TB-boundary rule.
	RvvEntryHint rvv_entry_hint{};
	// R2 (2026-09-17). THE REGION-SCOPED CANDIDATE VTYPE, and every word of that name is a
	// restriction.
	//
	// REGION-SCOPED, not block-scoped: unlike `rvv_bb_vtype` it survives TranslateIPRange's
	// reset, because the whole point is to serve the ip ranges of an AOT region that contain no
	// `vsetvli` of their own (a 256-instruction dependent chain occupies five ranges and only one
	// of them holds the guest's `vsetvli`).
	//
	// CANDIDATE, not knowledge: it is offered to RvvFormVectorRunAt ONLY when `rvv_bb_vtype` is
	// unknown, it is offered with `RunVType::observed` still FALSE, and it never seeds
	// `rvv_bb_vtype` or `rvv_bb_vl`. It is not a claim about control flow -- ip ranges are
	// translated in address order, which is not execution order, so this value may simply be
	// wrong. What makes a wrong value harmless is unchanged and is not here: the frame's
	// GuardKind::VTypeVlVstartFrmRNE re-proves vtype/vl/vstart/frm on every execution and the
	// ordered fallback replays each member through the same already-verified helper. This is the
	// C3.1f rule (rv32_qir.cpp, TRANSLATOR(vadd_vv)) with a better-informed candidate, not a new
	// kind of assumption.
	//
	// ITS ONLY SOURCE IS A DECODED CONSTANT `vsetvli`/`vsetivli` in this region's own instruction
	// stream (TRANSLATOR(vsetvli) / TRANSLATOR(vsetivli)). The register-form `vsetvl` INVALIDATES
	// it, for the same reason that instruction sets `rvv_bb_vtype = ~0u`: the configuration is now
	// a runtime GPR value and any earlier constant describes state that is stale. The P7G entry
	// hint is deliberately NOT a source -- that is live architectural state, not a decoded
	// instruction, and it already has its own one-shot, region-entry-only rule.
	//
	// NOT STORED ANYWHERE. Like `rvv_entry_hint`, it lives in the translator and dies with it: no
	// TBlock, no cache key, no link slot and no AOT artifact learns about it, so it needs no rule
	// in tcache, in the branch-link protocol or in invalidation.
	//
	// `~0u` means "no candidate", and that reproduces the previous behaviour exactly: the scan
	// falls back to the canonical VTYPE_E32_M1_TA_MA proposal it has always made.
	u32 rvv_region_vtype_candidate{~0u};
	// R1A.3a: the next pc the run scan may start at. Runs are maximal and non-overlapping, so a
	// scan that admitted members through pc P must not be repeated from P's interior. Reset at
	// every TranslateIPRange entry, and read only when config::rvv_vector_run is on.
	u32 rvv_run_scan_next_ip{0};
	u32 rvv_lane_scan_next_ip{0};
	// R1A.3b: the descriptor the scan produced for the CURRENT insn_ip, waiting to be consumed.
	// Cleared on every consumption attempt so a refused run can never be re-read at a later pc.
	rvvrun::RunDescriptor rvv_run_pending{};
	// Translation-time SSA environment for the LLVM-AOT prior-art P.  A guest
	// vector register has at most two fixed 512-bit chunks at VLEN=1024.
	std::array<VOperand, 64> rvv_chunk_values;
	std::array<bool, 64> rvv_chunk_valid{};
	std::array<bool, 64> rvv_chunk_dirty{};
	std::array<VOperand, 32> rvv_mask_values;
	std::array<bool, 32> rvv_mask_valid{};
	std::array<bool, 32> rvv_mask_dirty{};
	bool rvv_fp_open{};
	// A-line Round 56 (--aot-return-directify): the CURRENT compile job's region entry ip (the
	// TRUE, top-level, `_aot_tab`-registered function entry -- `job.iprange[0].first`, set once
	// in Translate() and constant for this whole region's translation). Needed so TRANSLATOR(jalr)
	// can ask return_target_resolve's whole-binary static single-caller certificate "does THIS
	// region's own entry have exactly one static caller" when it encounters that region's own
	// return jalr(s) -- a region may contain multiple basic blocks but is compiled as ONE LLVM
	// function, so this is the correct granularity for the certificate (matching
	// MakeAotSymbol(region_entry_ip), the same address `return_target_resolve`'s call-graph scan
	// treats as a callee entry).
	u32 region_entry_ip{0};
	// P7M-E. Emission-order index of the next MULTI-member vector-run frame within this
	// translation of this region, used only to build a frame's census identity. The translator is
	// constructed fresh per translation (rv32_qir.cpp, `RV32Translator t(region, vmem)`), so it
	// starts at 0 for every translation with no reset of its own; a retranslated region therefore
	// re-uses the same indices, which is why FrameCensusEntry documents that the consumer sums
	// rows sharing a `tb_pc`/`frame_index`. Advanced only when a slot was actually allocated, so
	// with the switch off it never moves and no accepted arm can observe it.
	u16 rvv_frame_census_index{0};
	// M-INL (--qcg-leaf-inline): V_jal inlined a scanned leaf callee; the TRANSLATOR macro still
	// sets control=BRANCH for jal, so the translate loop consults this to fall through instead.
	// ORACLE-ONLY STATUS (11:42 review): the mechanism is correctness-scoped to static guests --
	// duplicated inline bodies are NOT invalidated when the CALLEE page is invalidated (SMC gap),
	// and the scanner reads guest code without a mapping guard beyond the jal +-1MB range within
	// the loaded ELF. It also does not preserve Wendell's callee-entry/return accounting. Use as
	// a mechanism oracle; do not generalize this implementation.
	bool inline_continue{false};
	u32 inline_extra_insns{0}; // C-fix: inlined body length, charged to the TB instruction budget

	// 2026-07-28 A-line (--qcg-jal-closure): ips already translated in the CURRENT TranslateIPRange
	// call, so a `jal` back into already-emitted code within the same job is detected and refused
	// (falls back to the normal MakeGBr+stop path) instead of duplicating QIR for the same guest
	// bytes -- a real correctness requirement (not just an efficiency nicety), since re-running
	// TranslateInsn() over already-visited bytes into the same qir::Builder would double-emit their
	// semantics. Fixed-size (TB_MAX_INSNS bound, no heap allocation -- a std::set here was measured
	// to cost more per-instruction than the per-job fixed cost this mechanism saves, canceling the
	// benefit) linear-scan array, reset (jal_closure_visited_n = 0) at the start of every
	// TranslateIPRange call.
	u32 jal_closure_visited[128];
	u32 jal_closure_visited_n{0};
};

} // namespace dbt::qir::rv32

namespace dbt::qir
{
using IRTranslator = qir::rv32::RV32Translator;
} // namespace dbt::qir
