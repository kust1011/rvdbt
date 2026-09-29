// (2026-08-31, T5d1b) This header had no include guard, which was invisible while exactly one
// translation unit included it. dbt/aot/loop_region.h now does too.
#pragma once

#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir_builder.h"

#include <unordered_map>
#include <type_traits>
#include <vector>
#include <unordered_set>

#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"

namespace dbt::qir
{

extern thread_local llvm::LLVMContext g_llvm_ctx;

struct LLVMGen;

struct LLVMGenCtx {
	explicit LLVMGenCtx(llvm::Module *cmodule_);

	llvm::LLVMContext &ctx;
	llvm::Module &cmodule;

	llvm::FunctionType *qcg_fnty{};
	llvm::FunctionType *qcg_gbr_patch_fnty{};
	llvm::FunctionType *qcg_stub_brind_fnty{};
	llvm::FunctionType *qcg_helper_fnty{};
	llvm::StructType *brind_cache_entry_ty{};

	llvm::MDNode *md_unlikely{};
	llvm::MDNode *md_astate{};
	llvm::MDNode *md_avmem{};
	llvm::MDNode *md_aother{};

	std::unordered_map<std::string, CodeSegment> fn2seg;
	// Default-off region co-visibility oracle state. QIRToLLVM discovers the guest entry blocks,
	// while IntrinsicExpansionPass later creates a fresh LLVMGen; keep the mapping in the shared
	// context so the expansion pass can actually materialize the internal dispatch switch.
	std::unordered_map<std::string, std::vector<u32>> fn2internal_dispatch_targets;
	// A-line move-not-copy: exact record of which internal-target entry-switch cases were actually
	// added in Run() (llvmgen.cpp ~421). A thunked target whose case is missing would fall through
	// to the source's OWN entry block with a wrong state->ip -- llvmaot.cpp verifies against this
	// set after all pages are translated and aborts the compile rather than emit a wrong artifact.
	std::unordered_map<std::string, std::unordered_set<u32>> fn2switch_cases;
	// T5c-0: the same record, for the merge_entries half of the SAME switch. An entry wrapper is
	// only safe if the switch really routes its ip: the wrapper stores state->ip and tail-calls the
	// primary, so a missing case sends it down the switch's DEFAULT arm into the region's own root
	// block with someone else's state->ip -- a silent miscompile of exactly the kind the set above
	// exists to prevent. llvmaot.cpp creates a loop-entry wrapper only for an ip listed here.
	std::unordered_map<std::string, std::unordered_set<u32>> fn2merge_cases;
	// 10th-cycle splice fix: the internal-dispatch tail/switch must be built ONCE PER FUNCTION,
	// not once per LLVMGen instance -- ExpandIntrinsics constructs a fresh LLVMGen per function
	// per PASS, and a rebuilt duplicate tail adds new predecessors to target blocks whose PHIs
	// (inserted by earlier O3 iterations) are never updated -> verifier abort ("PHINode should
	// have one entry for each predecessor", expat/pugixml/tinyxml2 multi-source selections).
	// Persist them per function name, exactly like fn2entry_blocks.
	std::unordered_map<std::string, llvm::BasicBlock *> fn2gbrind_tail;
	std::unordered_map<std::string, llvm::PHINode *> fn2gbrind_phi;
	std::unordered_map<std::string, std::unordered_map<u32, llvm::BasicBlock *>> fn2entry_blocks;
	std::unordered_map<std::string_view, std::function<bool(LLVMGen &, llvm::CallInst *, bool)>>
	    intrin_fns;

	// A-line Round 51 (--aot-static-table-alwaysinline): call sites built eagerly (at Run()-time,
	// before any O3 pass) that should be DIRECTLY, deterministically spliced via llvm::InlineFunction
	// once ALL region functions across the whole ELF have been Run() (so cross-function/cross-page
	// forward references have real bodies to inline, not just declarations) -- see
	// llvmaot.cpp::LLVMAOTCompileELF's post-translate-loop splice step. Attaching
	// llvm::Attribute::AlwaysInline and hoping a later heuristic pass acts on it was tried and
	// falsified (Round 50/51): the pass that reads it runs BEFORE our deferred call is even
	// constructed, and later re-running it does not help since AlwaysInlinerPass keys off the
	// CALLEE's own function-level attribute, not a call-site attribute -- direct API splicing here
	// is deterministic and does not depend on any pass's heuristics or ordering.
	std::vector<llvm::CallInst *> pending_alwaysinline_splices;
	// A-line Round 54 Hypothesis 1: whole-compile-scope record of which resolved static-table
	// targets have ALREADY been chosen for inlining at an earlier site. Round 54's causal
	// accounting found compile-cost overhead is driven by total code duplicated (copies x callee
	// size), and confirmed a real, currently-unguarded risk: the SAME target can be reachable
	// (and admitted) from more than one distinct switch site (verified in real data: pcre2_super's
	// site-1/site-2 target lists share an address) -- inlining it at EVERY such site multiplies
	// the duplication cost with no additional per-copy benefit (LLVM already has the ONE
	// integrated copy from the first site). Caps total duplication at exactly one inlined copy per
	// target, program-wide -- a structural invariant, not a size/workload-tuned threshold.
	std::unordered_set<u32> already_inlined_targets;

	void AddFunction(u32 region_ip, CodeSegment segment);
};

struct IntrinsicExpansionPass : public llvm::PassInfoMixin<IntrinsicExpansionPass> {

	explicit IntrinsicExpansionPass(LLVMGenCtx &ctx_, bool is_final_) : ctx(ctx_), is_final(is_final_) {}

	llvm::PreservedAnalyses run(llvm::Function &fn, llvm::FunctionAnalysisManager &fam);

private:
	LLVMGenCtx &ctx;
	bool is_final{};
};

struct LLVMGen {
	explicit LLVMGen(LLVMGenCtx &g_, llvm::Function *func_);
	std::vector<u32> internal_dispatch_targets; // P3: same-function handler entries (gbrind -> internal switch)
	std::unordered_map<u32, llvm::BasicBlock *> entry2bb_m; // entry_ip -> block (populated in Run)

	// LaneA cyclic-merge fix (2026-07-23): when internal_dispatch_targets is non-empty, EVERY gbrind
	// call site in this function used to independently re-emit its OWN full copy of "the internal
	// switch + edge-specialize + L1-cache + slowpath" tail. For a genuinely cyclic merge group (a
	// real SCC pulled in as internal blocks), that meant N structurally-identical switches all
	// converging on the SAME target blocks -- a shape LLVM's O3 pipeline classifies as an irreducible
	// (multi-entry) loop and is forced to node-split/clone to make reducible (confirmed via IR dumps,
	// see docs/DIVERGENCE_EVIDENCE.md: one target block ballooned from 1 canonical llvm::BasicBlock
	// into 10 ".us*"-suffixed SimpleLoopUnswitch clones). The N pre-existing redundant copies of the
	// switch were then remapped to those clones INCONSISTENTLY (majority correct, 1-2 stale/wrong per
	// target), producing a genuine miscompilation (wrong guest control transfer -> guest memory
	// fault). Fix: build this tail ONCE per function (below) and have every internal gbrind call site
	// funnel into it via an unconditional branch + a PHI carrying that site's own `gipv` -- collapses
	// the redundant N-copy encoding to a single shared instance, so there is only ever ONE dispatch
	// point for LLVM to clone (self-consistently, if it clones at all) instead of N independently-
	// diverging ones. Every value referenced past this point (`gipv`-derived only; see comment at the
	// call site in Expand_gbrind) is function-generic, so sharing is safe. nullptr until first use;
	// only ever populated when internal_dispatch_targets is non-empty (default/no-merge functions are
	// completely unaffected -- byte-identical).
	llvm::BasicBlock *internal_gbrind_tail_bb{};
	llvm::PHINode *internal_gbrind_gipv_phi{};
	// 18th-cycle splice-PHI fix: true when the tail above was inherited from a PRIOR pass via
	// fn2gbrind_tail. An inherited tail (and its switch targets) has been through O3, which
	// inserts PHIs (GVN-PRE etc.) that a newly added branch edge cannot supply values for --
	// the exact "PHINode should have one entry for each predecessor" breakage. Late call sites
	// (materialized by LLVM inlining between passes) must NOT branch into it; they take the
	// external EdgeSpecializeAndSlowpath path instead, which is always semantically valid.
	bool gbrind_tail_inherited{};

	llvm::Instruction *AScopeState(llvm::Instruction *inst);
	llvm::Instruction *AScopeVMem(llvm::Instruction *inst);
	llvm::Instruction *AScopeOther(llvm::Instruction *inst);
	llvm::Value *MakeStateEP(llvm::PointerType *type, u32 offs);
	llvm::Value *MakeVMemLoc(llvm::PointerType *ptype, llvm::Value *addr);
	llvm::Value *MakeRStub(RuntimeStubId id, llvm::FunctionType *ftype);

	template <u8 Bits>
	llvm::ConstantInt *constv(u64 val)
	{
		return llvm::ConstantInt::get(lctx, llvm::APInt(Bits, val));
	}

	llvm::CallInst *CreateQCGFnCall(llvm::Value *fn);
	// A-line Round 50/51: NOT musttail, unlike CreateQCGFnCall -- deliberately gives up guaranteed
	// tail-call elimination for this ONE call site so it can later be DIRECTLY, deterministically
	// spliced via llvm::InlineFunction (Round 50's llvm::Attribute::AlwaysInline + rely-on-a-later-
	// pass approach was tried and falsified: the pass that reads that attribute runs before this
	// call is even constructed, and it keys off the CALLEE's function-level attribute anyway, not a
	// call-site one). Registers the call in `g.pending_alwaysinline_splices` for
	// llvmaot.cpp::LLVMAOTCompileELF to actually inline once every region function across the whole
	// ELF has a real body (this call may be a forward reference to a not-yet-Run() region). `fn`
	// must be an llvm::Function* (not an arbitrary indirect Value*) -- InlineFunction requires a
	// known callee body.
	llvm::CallInst *CreateInlinableQCGFnCall(llvm::Function *fn);
	void CreateQCGGbr(u32 gipv, bool must_expand);

	void ExpandIntrinsics(bool is_final);

	LLVMGenCtx &g;
	llvm::LLVMContext &lctx;
	llvm::Module &cmodule;

	CodeSegment *segment;

	llvm::IRBuilder<> *lb{};
	llvm::Function *func{};
	llvm::Value *statev{};
	llvm::Value *membasev{};
};

struct QIRToLLVM : public LLVMGen {
	explicit QIRToLLVM(LLVMGenCtx &g_, CodeSegment *segment_, qir::Region *region, u32 region_ip);

	llvm::Function *Run();

	// Round-41 region-merge: if size()>1, the worker is multi-entry; Run() emits an entry switch on
	// state->ip -> the block whose entry_ip == the requested guest ip (one case per group entry).
	std::vector<u32> merge_entries;
	// DC-9-style real branch weights for the merge_entries switch above (reuses the SAME always-on,
	// free objprof exec_count data DC-9 uses for guest brcc weights -- no new acquisition mechanism).
	// The default arm (first_bb, i.e. entered normally/not via a wrapper) is overwhelmingly the
	// common case for a region with only a few hot secondary (wrapper) entries; hinting this lets
	// the branch predictor learn it instead of treating the check as unpredictable.
	u32 region_ip{};


private:
#define OP(name, cls, flags) void Emit_##name(qir::cls *ins);
	QIR_OPS_LIST(OP)
#undef OP

	// TODO: make generic
	struct Visitor : qir::InstVisitor<Visitor, void> {
	public:
		Visitor(QIRToLLVM *cg_) : cg(cg_) {}

		void visitInst(qir::Inst *ins)
		{
			unreachable("");
		}

#define OP(name, cls, flags)                                                                                 \
	void visit_##name(qir::cls *ins)                                                                     \
	{                                                                                                    \
		cg->Emit_##name(ins);                                                                        \
	}
		QIR_OPS_LIST(OP)
#undef OP

	private:
		QIRToLLVM *cg{};
	};

	void CreateVGPRLocs(qir::VRegsInfo *vinfo);
	llvm::Type *MakeType(VType type);
	llvm::PointerType *MakePtrType(VType type);

	llvm::Value *LoadVOperand(qir::VOperand op);
	void StoreVOperand(qir::VOperand op, llvm::Value *val);
	llvm::Value *MakeVMemLoc(VType type, llvm::Value *addr);
	llvm::Value *MakeStateEP(VType type, u32 offs);
	std::pair<llvm::Value *, bool> MakeVOperandEP(VOperand op);
	llvm::ConstantInt *MakeConst(VType type, u64 val);
	llvm::Value *RvvStateLoad(VType type, u32 offs, llvm::Align align);
	void RvvStateStore(VType type, u32 offs, llvm::Value *value, llvm::Align align);
	// `evl` is u32 rather than u16 only so InstRVVTypedChunkBegin::vlmax (a u32) can be passed
	// without a silent narrowing; every pre-C5.2b caller passes a u16 `evl` field and is unchanged.
	// C2b: `check_vstart` exists because one admitted frame kind (GuardKind::VTypeInteger) states
	// that the BODY handles vstart rather than the guard excluding it -- the scalar-move body reads
	// vstart and implements the architectural rule itself. Every other caller keeps the default and
	// is unchanged.
	llvm::Value *RvvGuard(u32 expected_vtype, u32 evl, bool fp, bool partial = false,
			      bool check_vstart = true);
	// W7: the VTYPE-INDEPENDENT frame guard -- `vlenb == expected && vstart == 0` and nothing
	// else. Deliberately NOT a specialisation of RvvGuard: that function always tests vtype and
	// vl, and a whole-register transfer is governed by neither (RVV 1.0 16.6: these instructions
	// are independent of vtype's LMUL/vl and operate on NREG whole registers). Testing vl here
	// would refuse architecturally ordinary executions and would misstate the operation.
	llvm::Value *RvvVlenbVstartGuard(u32 expected_vlenb);
	// C3: the shared immediate-shift lane lowering; `left` picks shl vs lshr.
	llvm::Value *TChunkShiftLower(bool left, u8 sew_bytes, u8 shamt, qir::VOperand src);
	// C1: the whole-register MEMORY frame's guard -- `vlenb == VLEN/8 && vstart == 0 &&
	// addr + total_bytes <= 2^32`. Shared by Emit_rvvload and Emit_rvvstore so the load and the
	// store cannot state different preconditions for the same transfer.
	llvm::Value *RvvWholeRegMemGuard(llvm::Value *addr, u32 total_bytes);
	// C5-FP: the active-lane predicate for a chunk whose first architectural element is
	// `element_base`, read from the LIVE `vec.vl`. Shared by the FP operand neutralisation and
	// available to any later family that needs the same predicate.
	// ORDER ITEM 3: `architectural_mask` ANDs in the THIRD conjunct -- v0's bits for this unit's
	// elements -- so one call produces the WHOLE predicate the contract defines, and the FP
	// operand neutralisation and the destination publication cannot end up predicated on
	// different sets. `vstart` is still the guard's.
	llvm::Value *RvvActiveLaneMask(u32 lanes, u32 element_base,
				       bool architectural_mask = false,
				       bool vstart_floor = false);
	// ORDER ITEM 3: v0's bits for `lanes` elements starting at `element_base`, as `<lanes x i1>`.
	// The window comes from `rvvcontract::MaskWindowForUnit`; Panics on a shape that function
	// refuses, which admission has already excluded.
	llvm::Value *RvvArchMaskForUnit(u32 lanes, u32 element_base);
	// ORDER ITEM 4: the RVV 1.0 fixed-point ROUNDING INCREMENT -- the `r` the spec's `roundoff`
	// function adds after shifting `v` right by `shift`. `v` is a vector of the EXACT pre-shift
	// value in a type wide enough to hold it; the result is a vector of the same type holding 0 or
	// 1 per lane. `vec.vxrm` is read here, from live state, because it is an architectural input
	// that selects between four different answers.
	//
	// SHARED ON PURPOSE. `vaadd`/`vasub`, `vsmul`, `vssrl`/`vssra` and `vnclip` all round by this
	// one rule, and the plan's standing constraint is no per-op duplicated policy -- so the two
	// families still to come are meant to call this rather than restate it. It mirrors
	// `rv32_vector_lower.h`'s `rounding_incr`, which is the same statement for the helper arm.
	llvm::Value *RvvRoundoffIncrement(llvm::Value *v, u32 shift);
	// ORDER ITEM 4: the same rule with a RUNTIME shift, one amount per lane. `vnclip.wv` takes
	// its shift from a vector operand, so the constant form above could not serve it; rather
	// than give the clip its own copy of the rounding rule, the rule was generalised and the
	// constant form now forwards here. `shift` must be a vector of `v`'s type with every lane
	// already reduced modulo the element width.
	llvm::Value *RvvRoundoffIncrement(llvm::Value *v, llvm::Value *shift);
	// C5-FP: force inactive lanes of an FP operand to +1.0. See the block comment at the
	// definition for why +1.0 and not +0.0 -- division.
	llvm::Value *RvvNeutralizeInactiveFP(llvm::Value *v, llvm::Value *mask,
					     llvm::FixedVectorType *fty);
	void RvvStoreGroup(u8 reg, u8 active_chunks, VOperandSpan values, u8 first_operand = 0);
	std::array<llvm::Value *, 4> RvvLoadGroup(u8 reg, u8 active_chunks);
	void RvvCallFallback(RuntimeStubId stub, u32 raw);
	void RvvCount(bool direct);
	// W5: the chunk's own VType, not a literal. `value` is a chunk of `chunk_ty` bytes holding
	// `VTypeToSize(chunk_ty) / sew` elements, and the canonicalised result is returned at the same
	// type. Family A always passes V512 because its chunk IS a 512-bit legalization unit; the
	// typed-chunk families pass the width their frame's geometry admitted.
	llvm::Value *RvvCanonicalize(llvm::Value *value, u8 sew, qir::VType chunk_ty);
	// F1 (2026-09-16): the host FP control/exception bracket's straight-line body, extracted so
	// the P-vector-SSA family (Emit_rvvfpbegin/end) and the typed FP frame
	// (Emit_rvvqcgfpbegin/end) share ONE frm->MXCSR.RC map and ONE MXCSR->fflags table. Neither
	// creates a block, a branch, a guard, or reads `fround_run_open` -- those are the callers'
	// differences, and they are real; see llvmgen.cpp.
	void RvvFpBracketOpenBody();
	void RvvFpBracketCloseBody();
	// F1: one constrained-FP call, with `round.dynamic` + `fpexcept.strict` and the `strictfp`
	// attributes LLVM's own IRBuilder sets in constrained mode. `fty` is the lane vector type the
	// intrinsic is specialised on; `args` are the value operands only (the two metadata operands
	// are appended here so no caller can omit or reorder them).
	// C4: the general form. A constrained intrinsic may be overloaded on MORE THAN ONE type --
	// `llvm.experimental.constrained.{si,ui}tofp` is overloaded on the RESULT and the OPERAND
	// (`.v8f64.v8i64`) -- and passing only one produces a malformed declaration. The single-type
	// overload below forwards to this one and stays correct for the arithmetic intrinsics.
	// C4: the EXCEPTION-ONLY form. `llvm.experimental.constrained.fptosi`/`fptoui` take a single
	// metadata operand (exception behaviour) and NO rounding operand, because the conversion is
	// defined to truncate. Appending a rounding operand to them builds a call the Verifier rejects.
	llvm::Value *RvvConstrainedFPCallNoRound(llvm::Intrinsic::ID id,
						 llvm::ArrayRef<llvm::Type *> overload_tys,
						 llvm::ArrayRef<llvm::Value *> args);
	llvm::Value *RvvConstrainedFPCallN(llvm::Intrinsic::ID id,
					   llvm::ArrayRef<llvm::Type *> overload_tys,
					   llvm::ArrayRef<llvm::Value *> args);
	llvm::Value *RvvConstrainedFPCall(llvm::Intrinsic::ID id, llvm::Type *fty,
					  llvm::ArrayRef<llvm::Value *> args);
	llvm::AllocaInst *rvv_mxcsr_slot{};

	// C5.2b -- typed V512 chunk group (rvvtypedchunkbegin .. rvvtypedchunkend) lowering state.
	//
	// Unlike every other RVV op in this backend, the typed chunk group is SEVERAL QIR nodes for
	// one guest instruction or an admitted integer sequence. Its guard CFG is opened by `begin`,
	// the body lands in the fast block, and `end` emits the ordered fallback and closes it.
	// These fields carry that open group across the nodes in
	// between; all of them are per-group and reset by `end`.
	//
	// `tchunk_vals` is the whole reason the fast arm is real vector SSA rather than alloca
	// traffic: a typed chunk value is defined by exactly one node and consumed by name inside the
	// same group, in the same LLVM block, so its llvm::Value* can be carried directly instead of
	// being spilled through the VRegsInfo alloca `LoadVOperand`/`StoreVOperand` would use. It is
	// keyed by the QIR virtual VPR number (VOperand::GetVVPR).
	llvm::BasicBlock *tchunk_done{};
	llvm::BasicBlock *tchunk_fallback{};
	u8 tchunk_members{};
	std::unordered_map<RegN, llvm::Value *> tchunk_vals;
	// M2F: u16, and it must BE InstRVVTypedChunkBegin::n_typed's type rather than merely be wide
	// enough for the frames this backend happens to receive today.
	//
	// Single-instruction frames once hid the former u8 truncation risk. Multi-member frames
	// now reach this backend, so retain the declaration's u16 width throughout accounting.
	// on the QCG side, waiting in the other consumer.
	//
	// The static_assert is the enforcement: narrowing either counter, or widening the QIR field
	// without widening these, fails the build.
	u16 tchunk_expected{};
	u16 tchunk_seen{};
	static_assert(std::is_same_v<decltype(tchunk_expected),
				     decltype(qir::InstRVVTypedChunkBegin::n_typed)> &&
			  std::is_same_v<decltype(tchunk_seen),
					 decltype(qir::InstRVVTypedChunkBegin::n_typed)>,
		      "llvmgen's typed-op counters must be exactly "
		      "InstRVVTypedChunkBegin::n_typed's type");
	bool tchunk_open{};
	// F1: does THIS frame's own guard already prove `vl == VLMAX && vstart == 0`? Set from
	// InstRVVTypedChunkBegin::GuardProvesFullVl -- the same shared predicate the translator reads
	// -- and cleared by `end` with every other per-frame field. Emit_vchunkfalu refuses to lower
	// without it, because the FP body here is unmasked and stores whole chunks.
	bool tchunk_full_vl{};
	// ORDER ITEM 3, RESTART. Does this frame's guard leave a NONZERO `vec.vstart` to the body?
	// Set from the frame's own guard kind by `begin`, cleared by `end` with every other per-frame
	// field. When it is set, `Emit_vstatechunkstore`'s active-lane predicate gains the contract's
	// `vstart` FLOOR conjunct -- which is the one conjunct that cannot be supplied by a node flag,
	// because it is a property of the FRAME's guard and every node in the frame needs it.
	bool tchunk_body_restart{};
	// ORDER ITEM 3, RESTART. Did any node INSIDE this frame already write `vec.vstart`? Set by
	// `RvvStateStore` itself rather than by each emitter, so a body writer cannot be forgotten:
	// the scalar-move family implements the architectural vstart rule in its own body and must not
	// also get an epilogue clear, while a restart frame whose body does NOT write it must.
	bool tchunk_body_wrote_vstart{};
	// ORDER ITEM 3. ONE ACTIVE-LANE PREDICATE PER (unit, kind) PER FRAME, so that the FP operand
	// neutralisation and the destination publication are literally the same `llvm::Value *` and
	// not two derivations that happen to agree. Two agreeing derivations is how an element comes
	// to be suppressed in one and computed in the other after a later edit -- and for FP that is a
	// guest `fcsr` flag for an element the instruction must not touch.
	//
	// KEYED BY THE INSERTION BLOCK AS WELL, so a reuse can never produce a value that does not
	// dominate its use: if the emitter has moved to a different basic block the predicate is
	// rebuilt. Cleared by `begin` and `end` with every other per-frame field, because the cached
	// value closes over a LOAD of `vec.vl` that is only known-live inside its own frame.
	struct LaneMaskKey {
		u32 lanes, element_base;
		bool architectural_mask, vstart_floor;
		bool operator==(LaneMaskKey const &o) const
		{
			return lanes == o.lanes && element_base == o.element_base &&
			       architectural_mask == o.architectural_mask &&
			       vstart_floor == o.vstart_floor;
		}
	};
	struct LaneMaskEntry {
		LaneMaskKey key;
		llvm::BasicBlock *block;
		llvm::Value *value;
	};
	std::vector<LaneMaskEntry> tchunk_lane_masks;

	void TChunkAccount();
	void TChunkDef(qir::VOperand op, llvm::Value *val);
	llvm::Value *TChunkUse(qir::VOperand op);
	// S3.10a: the single per-opcode instruction of a typed integer-ALU chunk frame. Everything
	// around it -- guard, fallback, join, CPUState windows, SSA bookkeeping -- is already
	// operation-independent, so this enum is the whole extent of the family's variation in this
	// backend. T1b adds Mul, T1d Xor, T1e Or and T1f And -- which COMPLETES the typed integer
	// element-wise family: there is no member left without a lowering here. `a` is the node's i(0)
	// (the vs2 chunk) and `b` its i(1) (the vs1 chunk); that order is semantic for Sub and is fixed
	// by RvvEmitTypedAluChunkGroupCore for every member.
	enum class TChunkAluOp : u8 { Add, Sub, Mul, Xor, Or, And };
	llvm::Value *TChunkAluLower(TChunkAluOp op, u8 sew_bytes, qir::VOperand a, qir::VOperand b);
	// Panics unless `ins` is one of the opcodes a typed chunk group's body may contain. The LLVM
	// counterpart of QEmit's "Emit_mov Panics while a group is open" invariant (qir.h): anything
	// else emitted here would execute on the guard-HIT path only, while the guard-miss path ran
	// the helper -- a silent divergence between the two arms of one guest instruction.
	void TChunkCheckBodyOp(qir::Inst *ins);

	static llvm::CmpInst::Predicate MakeCC(CondCode cc);

	llvm::BasicBlock *MapBB(Block *bb);

	void EmitBinop(llvm::Instruction::BinaryOps opc, qir::InstBinop *ins);
	void EmitShift(llvm::Instruction::BinaryOps opc, qir::InstBinop *ins);
	void EmitTrace();

	qir::Region *region;
	Block *qbb{};
	std::unordered_map<u32, llvm::BasicBlock *> id2bb;
	std::vector<llvm::Value *> vlocs;
	RegN vlocs_nglobals{};
};

} // namespace dbt::qir
