#pragma once

#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/qmc/qcg/qcg.h"

#include <utility>
#include <vector>
#include <type_traits>

namespace dbt::qcg
{
struct QEmit {
	QEmit(qir::Region *region, CompilerRuntime *cruntime_, qir::CodeSegment *segment_, bool is_leaf_);

	void SetBlock(qir::Block *bb_)
	{
		bb = bb_;
		j.bind(labels[bb->GetId()]);
		EmitBlockArrivalCounter();
	}
	// A-line v3.1 (--qcg-freq-entry): per-BLOCK arrival counter. The shadow-equivalence probe
	// proved per-TB entry counters break arrival conservation on multi-block regions (stock's
	// Emit_Cache counts INTRA-region br/brcc edges: wasm3 ip 0003a434 stock=19148 vs entry=13);
	// counting at every block label restores conservation at stock's own granularity.
	void EmitBlockArrivalCounter();

	std::span<u8> EmitCode();
	static void DumpCode(std::span<u8> const &code);

	void Prologue(u32 ip);
	// T5d2a3 (--loop-tier-side-exit): bind and emit every out-of-line exit block Emit_Cache asked
	// for while the blocks were being generated. Called ONCE by QCodegen::Run after the last
	// block, which is what keeps these blocks off every fall-through path in the region. Emits
	// nothing at all when nothing asked. See the definition for the state/frame/PC/slot contract.
	void EmitDeferredSideExits();
	void EmitInstrSeenIncr(u32 n);
	void EmitActiveMaskPair(qir::InstVChunkActive *bound, qir::InstVChunkMaskSet *mask);
	void BeginBodyMaskPair(qir::InstVChunkActive *bound);
	void EndBodyMaskPair();
	void StateSpill(qir::RegN p, qir::VType type, u16 offs);
	void StateFill(qir::RegN p, qir::VType type, u16 offs);
	void LocSpill(qir::RegN p, qir::VType type, u16 offs);
	void LocFill(qir::RegN p, qir::VType type, u16 offs);

#define OP(name, cls, flags) void Emit_##name(qir::cls *ins);
	QIR_OPS_LIST(OP)
#undef OP

	static constexpr auto R_STATE = asmjit::x86::gpq(ArchTraits::STATE);
	static constexpr auto R_MEMBASE = asmjit::x86::gpq(ArchTraits::MEMBASE);
	static constexpr auto R_SP = asmjit::x86::gpq(ArchTraits::SP);

private:
	void EmitPartialAluBody(qir::InstVChunkPartialAlu *ins, bool finish_instruction);
	qir::InstVChunkPartialAlu *rvv_instruction_work_last{nullptr};
	asmjit::Label rvv_instruction_work_done{};
	void FrameSetup();
	void FrameDestroy();
	// `loop_tier_backedge` is passed by the THREE call sites that can count a direct BACKWARD edge
	// -- Emit_gbr (`InstGBr::backedge`), Emit_br (`InstBr::backedge`) and Emit_brcc's taken arm
	// (`InstBrcc::t_backedge`) -- each from a retreating fact the TRANSLATOR computed, never from a
	// literal. It makes this function ALSO emit T5d2a2's loop-tier notification, which reuses the
	// TBlock pointer and the counter this function has already loaded and incremented: there is no
	// second lookup. The never-backward fall-through arm and Emit_gbrind pass nothing. See the
	// definition, and scripts/loop_tier_timer_audit.py gate T4 for the check on the call sites.
	//
	// `intra_region` is T5d2a3's parameter and is passed from the SAME three call sites, from the
	// structural fact each of them already knows: `Emit_gbr` is a region exit and passes false --
	// its edge already has T5d0's safepoint at its own slot -- while `Emit_br` and `Emit_brcc`'s
	// taken arm are in-region successors and pass true. It selects nothing else; only an edge that
	// both is a backedge and stays in the region can need an exit block of its own.
	void Emit_Cache(u32 bb_id, bool loop_tier_backedge = false, bool intra_region = false);

	// T5d2a3: reserve an out-of-line exit block for `target_ip` and return the label the cold path
	// jumps to. The block itself is emitted by EmitDeferredSideExits after the last basic block.
	asmjit::Label RequestSideExit(u32 target_ip);

	// T5d-0 (--qcg-backedge-safepoint): the runtime-service poll on a direct backward region exit.
	// Emitted by Emit_gbr ONLY, immediately before the branch slot `slot_label` names, and only
	// when the flag is on, the edge is `InstGBr::backedge` and this is a JIT-mode compile. See its
	// definition for the frame/state contract it depends on.
	void EmitBackedgeSafepoint(qir::InstGBr *ins, asmjit::Label const &slot_label);

	// V512 copy/spill/fill for Emit_mov; see the comment at its definition.
	void EmitVecMov(qir::VOperand vrd, qir::VOperand vs0);
	// RDI = body mask; clobbers only caller-saved RAX/RDX/RSI. No host opmask use.
	void EmitRvvBodyMask(u32 lanes, u32 element_base, bool masked);
	// Z3 (--rvv-qcg-typed-chunk-vlse-gather): the optional AVX-512 gather body for a strided load,
	// emitted by Emit_vmemorynative BEFORE its element loop. Returns false without emitting a byte
	// when the node is not the admitted shape or the switch is off, in which case the element loop
	// is the whole node exactly as before. Returns true having emitted the fast path, a jump to
	// `done` on its success edge, and its own fallback label bound at the element loop's first
	// instruction; the caller must bind `done` after the element loop's last instruction.
	bool EmitRvvStridedGather(qir::InstVMemory *ins, asmjit::Label const &done);
	void EmitRvvGatherCensus(unsigned long long *counter); // Z4B; no-op unless the switch is on
	void EmitCloseRvvFpBracket();
	void EmitRvvFpLaneMask(u32 lanes, u32 element_base);
	void EmitRvvRunScalarRaw(u32 raw, bool count_body_op);

	template <asmjit::x86::Inst::Id Op>
	ALWAYS_INLINE void EmitInstBinop(qir::InstBinop *ins);

	struct JitErrorHandler : asmjit::ErrorHandler {
		virtual void handleError(asmjit::Error err, const char *message,
					 asmjit::BaseEmitter *origin) override
		{
			Panic("qemit asmjit failed");
		}
	};

	inline asmjit::Operand make_operand(qir::VOperand opr);
	inline asmjit::x86::Mem make_slot(qir::VOperand opr);
	inline asmjit::Operand make_stubcall_target(RuntimeStubId stub);

	qir::Block *bb{};

	CompilerRuntime *cruntime{};
	qir::CodeSegment *segment{};
	bool jit_mode;

	RuntimeStubTab const &stub_tab{*RuntimeStubTab::GetGlobal()};

	bool is_leaf;
	u32 spillframe_sp_offs;

	asmjit::CodeHolder jcode{};
	asmjit::x86::Assembler j{};
	JitErrorHandler jerr{};

	std::vector<asmjit::Label> labels;
	u32 _entry_ip;
	u32 _entry_ip_hash;

	// T5d2a3. The `--qcg-pin` assignment QRegAlloc made for THIS region, copied at construction
	// (the allocator pass has already run by then). It is the exact set of guest globals that
	// `QRegAlloc::BlockBoundary` deliberately does NOT write back at an intra-region branch, so it
	// is the exact set an exit block must commit. Copied rather than kept as a Region pointer so
	// that the one thing this emitter reads out of the region is visibly just the pin table.
	u8 n_pins{0};
	qir::Region::PinLoad pins[8]{};
	struct PendingSideExit {
		asmjit::Label entry;
		u32 target_ip;
	};
	std::vector<PendingSideExit> side_exits;

	// A-line 2026-07-23 (--qcg-dispatch-ic): per-site patchable dispatch-IC blobs emitted by
	// Emit_gbrind; (blob_off, ret_off) pairs resolved to absolute addresses in EmitCode() after
	// the buffer is copied, then registered in tcache's IC maps.
	struct ICSite {
		u32 blob_off, ret_off;
	};
	std::vector<ICSite> ic_sites;
	u32 pending_ic_blob_off{0};
	bool has_pending_ic{false};

	// Diagnostic chunk control arm (Emit_rvvdiagchunkbegin/rvvdiagchunkadd/rvvdiagchunkend; see
	// the block comment on InstRVVDiagChunkBegin in qir.h). `begin` opens the group and creates
	// the two labels its guard branches to; `end` binds them. The flag exists so a malformed
	// group -- reordered, split across blocks, or left unterminated by some future pass -- Panics
	// at emission instead of producing a dangling branch.
	asmjit::Label rvv_diag_chunk_fallback{};
	asmjit::Label rvv_diag_chunk_done{};
	bool rvv_diag_chunk_open{false};
	u8 rvv_diag_chunk_next_index{0};

	// Typed chunk group (Emit_rvvtypedchunkbegin/rvvtypedchunkend). Same label discipline, plus
	// the invariant described on InstRVVTypedChunkBegin in qir.h: while a group is open the ONLY
	// instructions QEmit may emit are the typed chunk ops, because everything between the guard
	// and the fallback label is skipped on the fallback path. `n_typed_seen` is checked against
	// the count `begin` declared, and Emit_mov Panics while the flag is set.
	asmjit::Label rvv_typed_chunk_fallback{};
	asmjit::Label rvv_typed_chunk_done{};
	// A3: the partial arm's entry (bound by rvvtypedchunkpartial) and the join both arms reach.
	asmjit::Label rvv_typed_chunk_partial{};
	asmjit::Label rvv_typed_chunk_join{};
	bool rvv_typed_chunk_has_partial{false};
	bool rvv_fused_active_mask{false};
	bool rvv_fused_body_mask{false};
	u32 rvv_fused_body_base{};
	bool rvv_typed_chunk_partial_seen{false};
	// S1-1: the active-VL bound's join. Created by `begin`, referenced by every Emit_vchunkactive,
	// and bound by Emit_rvvqcgfpend at the TOP of the FP epilogue -- inside the bracket, so a body
	// that left early still runs stmxcsr/fflags/ldmxcsr and still clears vec.vstart. S1-3: an
	// INTEGER frame has no FP epilogue, so Emit_rvvtypedchunkend binds it there instead, right
	// before the frame's single `vstart = 0` write and before the join. It is deliberately a THIRD
	// label rather than a reuse of `rvv_typed_chunk_join` or `rvv_typed_chunk_fallback`: the join
	// is past the FP epilogue and past the vstart write (both would be skipped) and the fallback
	// would re-run the ordered helpers over results the body already stored. Left unbound and
	// unreferenced by every frame that emits no bound, exactly as `rvv_typed_chunk_partial` is for
	// every frame with no partial arm.
	asmjit::Label rvv_typed_chunk_body_done{};
	// Set by the first Emit_vchunkactive of the frame, cleared when Emit_rvvqcgfpend (FP) or
	// Emit_rvvtypedchunkend (integer) binds the label. It is also QEmit's half of the "who clears
	// vstart" agreement checked against InstRVVTypedChunkEnd::frame_clears_vstart.
	bool rvv_typed_chunk_bound_open{false};
	// S1-3: this frame's guard bounds `vec.vl` by `vlmax`
	// (qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax), so `vec.vl` is the frame's live element
	// count and an element index may be compared against it. Set by `begin`, cleared by `end`. A
	// `Vlenb*` whole-register frame clears it, and a bound landing in one is a Panic rather than an
	// early exit driven by a register the transfer's EVL does not depend on.
	bool rvv_typed_chunk_vl_guarded{false};
	// G11-A: this frame's own guard proved `vl == VLMAX && vstart == 0`
	// (qir::InstRVVTypedChunkBegin::GuardProvesFullVl) and the switch is on. Set by
	// `begin`, cleared by `end` and by `rvvtypedchunkpartial` -- code after the partial
	// marker reaches the body through a branch the guard's vl test did NOT prove.
	bool rvv_typed_chunk_full_vl{false};
	u32 rvv_body_mask_known_vl{0};
	bool rvv_typed_chunk_open{false};
	u16 rvv_typed_chunk_expected{0}; // M2E: u16, matching InstRVVTypedChunkBegin::n_typed
	u16 rvv_typed_chunk_seen{0};
	// M2F: enforced rather than asserted in a comment. The identical assertion sits on llvmgen's
	// pair, so BOTH consumers of the declaration are pinned to it and neither can be narrowed --
	// nor can the QIR field be widened again without both following.
	static_assert(std::is_same_v<decltype(rvv_typed_chunk_expected),
				     decltype(qir::InstRVVTypedChunkBegin::n_typed)> &&
			  std::is_same_v<decltype(rvv_typed_chunk_seen),
					 decltype(qir::InstRVVTypedChunkBegin::n_typed)>,
		      "QEmit's typed-op counters must be exactly "
		      "InstRVVTypedChunkBegin::n_typed's type");
	// R1A.3b: how many guest instructions this ONE guard covers, taken from `begin` and checked
	// against `end`. 1 is the accepted single-instruction frame and takes exactly the pre-R1A.3b
	// path; the per-member guest-PC writes exist only for a real run.
	u8 rvv_typed_chunk_members{0};
	// C4e: does the open frame's body run component-major -- one contiguous slice per work unit,
	// each slice holding every member's work for that unit? Taken from `begin` and used by
	// Emit_vchunkactive alone: it is the fact that makes a frame-level early exit skip only
	// INACTIVE work in a MULTI-member frame. False for every single-instruction frame and for
	// every member-major, materialize, chunk-major and live-range-splitting run body.
	bool rvv_typed_chunk_component_major{false};
	// Which chunks own resident k(1 + chunk % 6) masks inside the open frame. A slot's old
	// owner is cleared when recycled; all owners are cleared by begin. A shared-mask op must
	// find its bit set; one that computes its own k1/k2 must find NO bit set, because that
	// prologue would overwrite chunk 0's and chunk 1's resident masks. Both are Panics: a frame
	// mixing the two conventions is a translation bug, never a run-time fallback.
	u64 rvv_typed_chunk_fp_masks{0};
	// P7M-E: this frame's census slot, carried from `begin` to the join in `end`. nullptr on
	// every accepted arm and for every single-instruction frame; see the field's declaration on
	// InstRVVTypedChunkBegin.
	u64 *rvv_typed_chunk_census_slot{nullptr};
	// Store `pc` into CPUState::ip, or nothing at all when the frame covers a single member.
	// See its definition for the register-allocator argument that makes a backend-native store to
	// a guest global legal here.
	void EmitRunMemberIp(u32 pc);
	std::pair<asmjit::x86::KReg, asmjit::x86::KReg> FpMaskRegs(u8 kmask, u8 chunk); // A12
	// R1A.3d: the ONE place the research hit counter is emitted, so "counter-free" is a property
	// of a single decision rather than of three sites that must be kept in agreement. Every
	// fast-arm `rvv_direct_hits` increment in this backend goes through here; the guard-miss
	// `rvv_direct_fallbacks` increments deliberately do NOT. See config::rvv_qcg_hit_counter.
	void EmitRvvHitCount();
	void EmitRvvFrameCensusIncr(); // P7M-E; no-op unless this frame carries a census slot
	// P2a: the ONE place either active-chunk census counter is advanced, by a constant `n`
	// derived from the frame's end node (join) or by 1 (a bound's fall-through). No-op unless
	// config::rvv_qcg_active_chunk_census is on, and no-op for `n == 0`.
	void EmitRvvActiveChunkCensusAdd(unsigned long long *counter, u32 n);
};

}; // namespace dbt::qcg
