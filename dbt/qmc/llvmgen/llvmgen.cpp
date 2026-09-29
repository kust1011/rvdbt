#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_rvv_contract.h" // the shared RVV semantic contract (order item 2)
#include "dbt/guest/rv32_vector_lower.h" // VF6_* funct6 constants, shared with the semantics
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/qmc/qir_printer.h"
#include "dbt/tcache/objprof.h"
#include "dbt/tcache/tcache.h"

#include <fstream>
#include <unordered_map>

#include "llvm/Config/llvm-config.h" /* LLVM_VERSION_MAJOR, for the API guards below */
#include "llvm/IR/CFG.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/ADT/SmallVector.h"

namespace std
{
template <class Dest, class Source>
#if __has_builtin(__builtin_bit_cast)
constexpr
#else
inline
#endif
    Dest
    bit_cast(const Source &source)
{
#if __has_builtin(__builtin_bit_cast)
	return __builtin_bit_cast(Dest, source);
#else
	static_assert(sizeof(Dest) == sizeof(Source));
	static_assert(std::is_trivially_copyable_v<Dest>);
	static_assert(std::is_trivially_copyable_v<Source>);
	Dest dest;
	memcpy(&dest, &source, sizeof(dest));
	return dest;
#endif
}
} // namespace std

namespace dbt::qir
{

// DC-9 fix (--aot-brcc-real-weights): exec_count is collected by objprof for EVERY executed guest
// block regardless of edge kind, always on, zero extra cost. Forward-declared here so both
// Emit_brcc (guest brcc weights) and QIRToLLVM::Run (multi-entry switch weights) can use it;
// defined below.
static u64 LookupExecCount(u32 ip);

thread_local llvm::LLVMContext g_llvm_ctx;

LLVMGenCtx::LLVMGenCtx(llvm::Module *cmodule_) : ctx(g_llvm_ctx), cmodule(*cmodule_)
{
	auto voidty = llvm::Type::getVoidTy(ctx);
	auto ptrty = llvm::PointerType::get(ctx, 0);
	auto i8ty = llvm::Type::getInt8Ty(ctx);
	auto i8ptrty = llvm::PointerType::getUnqual(i8ty);
	auto i32ty = llvm::Type::getInt32Ty(ctx);

	qcg_fnty = llvm::FunctionType::get(voidty, {i8ptrty, i8ptrty}, false);
	qcg_gbr_patch_fnty = llvm::FunctionType::get(voidty, {i8ptrty, i8ptrty, ptrty}, false);
	qcg_stub_brind_fnty =
	    llvm::FunctionType::get(llvm::PointerType::getUnqual(qcg_fnty), {i8ptrty, i32ty}, false);

	qcg_helper_fnty = llvm::FunctionType::get(voidty, {i8ptrty, i32ty}, false);

	brind_cache_entry_ty = llvm::StructType::create(ctx, {i32ty, ptrty}, "BrindCacheEntry");

	auto mdb = llvm::MDBuilder(ctx);

	md_unlikely = mdb.createBranchWeights(1, 12);

	auto md_adomain = mdb.createAliasScopeDomain("alias_global_domain");
	md_astate = mdb.createAliasScope("alias_state", md_adomain);
	md_avmem = mdb.createAliasScope("alias_vmem", md_adomain);
	md_aother = mdb.createAliasScope("alias_other", md_adomain);
}

void LLVMGenCtx::AddFunction(u32 region_ip, CodeSegment segment)
{
	auto name = MakeAotSymbol(region_ip);
	auto func = cmodule.getFunction(name);
	if (func) {
		return;
	}

	func = llvm::Function::Create(qcg_fnty, llvm::Function::ExternalLinkage, name, cmodule);
	func->setDSOLocal(true);
	func->setCallingConv(llvm::CallingConv::GHC);
	func->setDoesNotThrow();
	func->getArg(0)->addAttr(llvm::Attribute::NoAlias);
	func->getArg(1)->addAttr(llvm::Attribute::NoAlias);

	func->getArg(0)->setName("state");
	func->getArg(1)->setName("membase");

	// TODO: add segment id as MD_annotation
	fn2seg.insert({name, segment});
}

void LLVMGen::ExpandIntrinsics(bool is_final)
{
	auto lirb = llvm::IRBuilder<>(lctx);
	lb = &lirb;

	for (auto &bb : *func) {
		for (auto iit = bb.begin(); iit != bb.end(); ++iit) {
			if (!llvm::isa<llvm::CallInst>(&*iit)) {
				continue;
			}
			llvm::CallInst *call = llvm::cast<llvm::CallInst>(*&iit);

			auto callee = call->getCalledFunction();
			if (!callee) {
				continue;
			}

			if (auto it = g.intrin_fns.find(callee->getName()); it != g.intrin_fns.end()) {
				lb->SetInsertPoint(call);
				if (!it->second(*this, call, is_final)) {
					continue;
				}
				iit = call->eraseFromParent();
				--iit;
				if (config::aot_log_expand) // Round-44: count expansions (fixpoint diagnostic)
					config::intrin_expand_count++;
			}
		}
	}
}

llvm::PreservedAnalyses IntrinsicExpansionPass::run(llvm::Function &fn, llvm::FunctionAnalysisManager &fam)
{
	LLVMGen(ctx, &fn).ExpandIntrinsics(is_final);
	return llvm::PreservedAnalyses::none();
}

LLVMGen::LLVMGen(LLVMGenCtx &g_, llvm::Function *func_) : g(g_), lctx(g.ctx), cmodule(g.cmodule), func(func_)
{
	assert(func);
	auto fn_name = std::string(func->getName());
	segment = &g.fn2seg.find(fn_name)->second;
	if (auto it = g.fn2internal_dispatch_targets.find(fn_name);
	    it != g.fn2internal_dispatch_targets.end())
		internal_dispatch_targets = it->second;
	if (auto it = g.fn2entry_blocks.find(fn_name); it != g.fn2entry_blocks.end())
		entry2bb_m = it->second;
	// 10th-cycle splice fix: reuse the per-function dispatch tail across passes (see llvmgen.h)
	if (auto it = g.fn2gbrind_tail.find(fn_name); it != g.fn2gbrind_tail.end()) {
		internal_gbrind_tail_bb = it->second;
		gbrind_tail_inherited = true;
	}
	if (auto it = g.fn2gbrind_phi.find(fn_name); it != g.fn2gbrind_phi.end())
		internal_gbrind_gipv_phi = it->second;

	statev = func->getArg(0);
	membasev = func->getArg(1);
}

llvm::Instruction *LLVMGen::AScopeState(llvm::Instruction *inst)
{
	auto scope = llvm::MDNode::get(lctx, g.md_astate);
	auto noalias = llvm::MDNode::get(lctx, {g.md_avmem, g.md_aother});

	inst->setMetadata(llvm::LLVMContext::MD_alias_scope, scope);
	inst->setMetadata(llvm::LLVMContext::MD_noalias, noalias);
	return inst;
}

llvm::Instruction *LLVMGen::AScopeVMem(llvm::Instruction *inst)
{
	auto scope = llvm::MDNode::get(lctx, g.md_avmem);
	auto noalias = llvm::MDNode::get(lctx, {g.md_astate, g.md_aother});

	inst->setMetadata(llvm::LLVMContext::MD_alias_scope, scope);
	inst->setMetadata(llvm::LLVMContext::MD_noalias, noalias);
	return inst;
}

llvm::Instruction *LLVMGen::AScopeOther(llvm::Instruction *inst)
{
	auto scope = llvm::MDNode::get(lctx, g.md_aother);
	auto noalias = llvm::MDNode::get(lctx, {g.md_astate, g.md_avmem});

	inst->setMetadata(llvm::LLVMContext::MD_alias_scope, scope);
	inst->setMetadata(llvm::LLVMContext::MD_noalias, noalias);
	return inst;
}

llvm::Value *LLVMGen::MakeStateEP(llvm::PointerType *type, u32 offs)
{
	auto ep = lb->CreateConstInBoundsGEP1_32(lb->getInt8Ty(), statev, offs);
	return lb->CreateBitCast(ep, type);
}

llvm::Value *LLVMGen::MakeVMemLoc(llvm::PointerType *ptype, llvm::Value *addr)
{
	addr = lb->CreateZExt(addr, lb->getIntPtrTy(cmodule.getDataLayout()));
	llvm::Value *ep;
	if constexpr (config::zero_membase) {
		return lb->CreateIntToPtr(addr, ptype);
	} else {
		ep = lb->CreateGEP(lb->getInt8Ty(), membasev, addr);
		return lb->CreateBitCast(ep, ptype);
	}
}

llvm::Value *LLVMGen::MakeRStub(RuntimeStubId id, llvm::FunctionType *ftype)
{
	auto fp_type = llvm::PointerType::getUnqual(ftype);

	auto state_ep = MakeStateEP(llvm::PointerType::getUnqual(fp_type),
				    offsetof(CPUState, stub_tab) + RuntimeStubTab::offs(id));

	return AScopeState(
	    lb->CreateAlignedLoad(fp_type, state_ep, llvm::Align(alignof(uptr)), GetRuntimeStubName(id)));
}

#if 0
// Experiments with llvm.patchpoint-like intrinsics as qcg gbrind patchpoint:
// llvm doesn't support tailcalls for experimental.patchpoint, actual call is not expanded until
// MCInstLowering. The same applies to gc.statepoint
//
// llvm corrupts ghccc Sp in MFs with stackmap, even if stackmap records no values
// I applied this in SelectionDAGBuilder for stackmaps with no liveins:
// + FuncInfo.MF->getFrameInfo().setHasStackMap(CI.arg_size() > 2);
// and the same for patchpoints
void LLVMGen::Emit_gbr(qir::InstGBr *ins)
{
	// Relocation is not necessary, also would overwrite patchpoint data, avoid
#if 1
	std::array<llvm::Value *, 7> args = {const64(ins->tpc.GetConst()),
					     const32(3 + sizeof(jitabi::ppoint::BranchSlot)),
					     llvm::ConstantPointerNull::get(lb->getInt8PtrTy()),
					     // fake_callee,
					     const32(3), statev, membasev};

	auto intr = lb->CreateIntrinsic(llvm::Intrinsic::experimental_patchpoint_void, {}, args);
	intr->addFnAttr(llvm::Attribute::NoReturn);
	intr->setCallingConv(llvm::CallingConv::GHC);
	intr->setTailCall(true);
	// intr->setTailCallKind(llvm::CallInst::TCK_MustTail);
	lb->CreateRetVoid();
#else
	auto stackmap = lb->CreateIntrinsic(
	    llvm::Intrinsic::experimental_stackmap, {},
	    {const64(ins->tpc.GetConst()), const32(3 + sizeof(jitabi::ppoint::BranchSlot))});
	stackmap->setCallingConv(llvm::CallingConv::GHC);
	stackmap->setTailCall(true);
#endif
	// auto call = lb->CreateCall(qcg_ftype, fake_callee, {statev, membasev});
	// call->addFnAttr(llvm::Attribute::NoReturn);
	// call->setCallingConv(llvm::CallingConv::GHC);
	// call->setTailCall(true);
	// call->setTailCallKind(llvm::CallInst::TCK_MustTail);
	// lb->CreateRetVoid();
}
#endif

llvm::CallInst *LLVMGen::CreateQCGFnCall(llvm::Value *fn)
{
	auto call = lb->CreateCall(g.qcg_fnty, fn, {statev, membasev});
	call->addFnAttr(llvm::Attribute::NoReturn);
	call->setCallingConv(llvm::CallingConv::GHC);
	call->setTailCall(true);
	call->setTailCallKind(llvm::CallInst::TCK_MustTail);
	lb->CreateRetVoid();
	return call;
}

// A-line Round 50/51: every guard-based gbrind consumer this project's history has ever built
// (order1/marginal/edge_specialize/vtable_narrow/static_table/indexed_dispatch) calls
// CreateQCGFnCall above on its "hit" path -- which hard-codes TCK_MustTail. A musttail call can
// NEVER be inlined by LLVM, unconditionally, regardless of profile/confidence/size. This is why
// "LLVM cross-dispatch inlining" (this project's own repeatedly-measured source of every real win,
// e.g. V93+V94) was never captured by any guard mechanism: structurally, none of them could have.
// This function deliberately gives up musttail (and therefore guaranteed tail-call elimination,
// i.e. bounded native stack depth across this ONE dispatch) in exchange for making the call
// spliceable -- ONLY safe for a call site whose callee is a proven-small, statically-resolved
// target (never for the generic/unbounded dispatch path).
//
// Round 50 attached llvm::Attribute::AlwaysInline HOPING LLVM's AlwaysInlinerPass would act on it
// later -- FALSIFIED on real measurement (disassembly of the compiled artifact still shows an
// ordinary `call` to the target, and the trampoline's sp_unwindptr invariant still breaks). Root
// cause, confirmed by reading LLVM's own AlwaysInliner pass source: it triggers on the CALLEE
// FUNCTION's own `alwaysinline` attribute (inlining EVERY call site of that function, including its
// legitimate standalone `_aot_tab` entry and any other gbrind site reaching it -- unsafe/wrong for
// a function that must also remain independently callable), not a per-call-site attribute; and even
// where a pass-based approach could work, this compiler's own multi-iteration expand/optimize loop
// (llvmaot.cpp) runs AlwaysInlinerPass as part of each iteration's DEFAULT pipeline, timed before
// this specific call (constructed by a LATER, deferred pass) ever existed as real IR for it to see.
//
// Fixed: do not rely on ANY heuristic pass. This call is registered in `g.pending_alwaysinline_
// splices` and directly, deterministically spliced via `llvm::InlineFunction()` in
// `llvmaot.cpp::LLVMAOTCompileELF`, once every region function across the WHOLE ELF has a real body
// (this call may be a forward reference into a not-yet-Run() function on this or another page) --
// see that call site's own comment for why this timing is required and what happens on failure.
//
// CORRECTNESS FIX (same round, caught before any economics claim, per a live IR-dump audit): a
// `musttail` call can never be inlined -- but the FIRST attempt (plain, non-tail call + `unreachable`
// terminator) is ALSO unsafe: `llvm::InlineFunction` only propagates tail-call-ness onto a spliced
// callee's OWN internal dispatch calls when the call site being replaced is ITSELF in tail position.
// A plain, untagged call is not -- confirmed via a real IR dump (`/tmp/dbt_alwaysinline_ir_dump.ll`,
// pcre2_super): every one of the inlined target's own onward `intr_gbr`/`intr_gbrind` dispatch calls
// came out as an ORDINARY (non-tail) call post-splice, silently breaking the unbounded-tail-dispatch
// invariant this whole architecture depends on -- exactly the crash this round is chasing. The fix:
// mark this call `TCK_Tail` (a plain tail HINT -- unlike `TCK_MustTail`, LLVM's inliner is willing to
// both inline it AND propagate tail-ness onto whatever gets spliced in, since the call site itself is
// already in genuine tail position) and terminate with a real `ret void` (not `unreachable` -- a tail
// call must be immediately followed by a matching `ret` for LLVM to recognize/preserve the tail
// position at all, exactly like `CreateQCGFnCall`'s own shape below). The post-splice repair/audit
// pass (`llvmaot.cpp`) still verifies every touched function afterward and hard-aborts the compile
// if any dispatch call anywhere is left in a genuinely broken (non-tail-positioned) shape -- this
// comment states the intended mechanism, not a substitute for that verification.
llvm::CallInst *LLVMGen::CreateInlinableQCGFnCall(llvm::Function *fn)
{
	auto call = lb->CreateCall(fn, {statev, membasev});
	call->addFnAttr(llvm::Attribute::NoReturn);
	call->setCallingConv(llvm::CallingConv::GHC);
	call->setTailCall(true); // TCK_Tail (a hint) -- NOT TCK_MustTail, which can never be inlined
	lb->CreateRetVoid();
	g.pending_alwaysinline_splices.push_back(call);
	return call;
}

static std::string MakeAsmString(std::span<u8> const &data)
{
	std::string hstr;
	hstr.reserve(data.size() * 4 + 16);
	char const *hexdig_str = "0123456789abcdef";

	for (size_t i = 0; i < data.size(); ++i) {
		hstr += '\\';
		hstr += 'x';
		hstr += hexdig_str[(data[i] >> 4) & 0xf];
		hstr += hexdig_str[data[i] & 0xf];
	}
	return hstr;
}

static std::string MakeGbrAsmString(u32 gip, bool cross_segment)
{
	thread_local auto slot = ([]() {
		std::array<u8, sizeof(jitabi::ppoint::BranchSlot)> fake_payload;
		auto slot = std::bit_cast<jitabi::ppoint::BranchSlot>(fake_payload);
		slot.LinkLazyLLVMAOT(offsetof(CPUState, stub_tab));
		return slot;
	})();
	slot.gip = gip;
	slot.flags.cross_segment = cross_segment;

	return ".string \"" + MakeAsmString({(u8 *)&slot, sizeof(slot)}) + "\"";
}

static bool Expand_gbr(LLVMGen &gen, llvm::CallInst *call, bool must_expand)
{
	if (!must_expand) { // Allows callsites merging
		return false;
	}

	auto *lb = gen.lb;
	lb->GetInsertBlock()->getTerminator()->eraseFromParent();
	gen.CreateQCGGbr(llvm::cast<llvm::ConstantInt>(call->getArgOperand(2))->getZExtValue(), true);
	return true;
}

void LLVMGen::CreateQCGGbr(u32 gip, bool must_expand)
{
	auto name = MakeAotSymbol(gip);
	llvm::Function *tgtfn = cmodule.getFunction(name);
	// Alias-entry root cause (2026-07-24, DESIGN8_ALIAS_MULTIENTRY_OBSTRUCTION.md): `cmodule.
	// getFunction` does NOT find a `GlobalAlias` (--aot-link-alias-merge's secondary entries are
	// aliases, not Functions). Without this, gip's lookup falls through to the `must_expand`
	// branch below -- a SELF-PATCHING lazy-link mechanism (MakeGbrAsmString/TryLinkBranch,
	// jitabi.cpp) whose HIT path patches a PERMANENT, zero-overhead direct jump after first
	// resolution and never touches state->ip on EITHER the first hit or any subsequent call
	// (confirmed by reading TryLinkBranch's code, not assumed) -- structurally incompatible
	// with a multi-entry target, which needs state->ip refreshed on EVERY call, not just set up
	// once. Fix: resolve the alias to its real aliasee Function here and route it through the
	// SAME safe, always-fresh direct-call path below (with the state->ip store), never letting
	// a multi-entry secondary reach the self-patching mechanism at all.
	if (!tgtfn) {
		if (auto *alias = cmodule.getNamedAlias(name))
			tgtfn = llvm::dyn_cast<llvm::Function>(alias->getAliasee());
	}
	if (tgtfn) {
		// TODO: segment check?
		// TODO(tuning): inlining heuristics
		// Alias-entry multi-entry contract (--aot-link-alias-merge / --aot-link-multientry-merge):
		// `tgtfn` may be a multi-entry worker whose OWN entry reads state->ip to route to a
		// secondary (alias- or wrapper-exposed) block. A direct call like this one is the
		// "normal" entry path (no secondary requested unless `gip` itself is the secondary,
		// e.g. after alias resolution above), so state->ip must be refreshed to THIS call's own
		// target -- otherwise a stale value left over from some earlier, unrelated dispatch
		// could accidentally match one of the callee's switch cases and misroute execution.
		// Cheap (one constant store) and always correct, whether or not `tgtfn` actually has a
		// switch. Gated: no multi-entry worker can exist in this module unless one of these two
		// flags is on, so the baseline (both off) path stays byte-for-byte the pre-Design-8 code
		// -- this store must NOT tax every ordinary direct AOT-to-AOT call unconditionally.
		if (dbt::config::aot_link_multientry_merge || dbt::config::aot_link_alias_merge) {
			auto *ipp =
			    MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()), offsetof(CPUState, ip));
			lb->CreateAlignedStore(constv<32>(gip), ipp, llvm::Align(alignof(u32)));
		}
		CreateQCGFnCall(tgtfn);
	} else if (must_expand) {
		// llvm.sponentry - crashes with my llvm build
		// llvm.frameaddress - enforces frame creation in contradiction to ghccc
		auto entrysp =
		    lb->CreateIntrinsic(llvm::Intrinsic::addressofreturnaddress, {lb->getPtrTy()}, {});

		// 2026-09-17 ABI ORDERING FIX. THE STACK POINTER IS NO LONGER A PINNED INPUT.
		//
		// The patch point needs three things live when control reaches it: state in r13, membase
		// in rbp, and rsp back at this function's ENTRY stack pointer. Expressing the third as a
		// `{rsp}` INPUT made LLVM satisfy it by adjusting rsp -- i.e. by tearing this frame down --
		// BEFORE the asm, and it is free to order that against the other two operand copies. When
		// membase had been spilled, the copy that materializes `{rbp}` is a RELOAD FROM THIS
		// FRAME, and it was emitted AFTER the teardown, so it read from the wrong address:
		//
		//     30c7  add  $0x48,%rsp          <- frame gone
		//     30cb  mov  0x40(%rsp),%rbp     <- reload from a slot that is no longer the frame
		//     30d0  call *0x4140(%r13)       <- QCG entered with a garbage membase
		//
		// The guest fault that follows is not in the artifact at all: it is the next QCG block
		// forming a guest address off that membase.
		//
		// The repair is to stop letting the register allocator choose that order. `entrysp` is now
		// an ORDINARY GPR input, so every operand -- including a spilled membase -- is materialized
		// while the frame is still intact, and the stack switch is the FIRST instruction of the asm
		// body, immediately before the patch-point payload. Nothing needs restoring afterwards
		// because this asm does not return.
		auto code_str = "movq $2, %rsp\n" + MakeGbrAsmString(gip, !segment->InSegment(gip));
		char const *constraint = "{r13},{rbp},r,~{memory},~{dirflag},~{fpsr},~{flags}";
		auto asmp = llvm::InlineAsm::get(g.qcg_gbr_patch_fnty, code_str, constraint, true, false);
		auto call = lb->CreateCall(asmp, {statev, membasev, entrysp});
		call->setTailCall(true);
		call->setDoesNotReturn();
		call->setDoesNotThrow();
		lb->CreateRetVoid();
	} else {
		constexpr std::string_view intrin_name = "intr_gbr";

		llvm::Function *intrin = cmodule.getFunction(intrin_name);
		if (!intrin) {
			auto ftype = llvm::FunctionType::get(
			    lb->getVoidTy(), {lb->getPtrTy(), lb->getPtrTy(), lb->getInt32Ty()}, false);
			intrin = llvm::Function::Create(ftype, llvm::Function::ExternalLinkage, intrin_name,
							cmodule);
			intrin->setCallingConv(llvm::CallingConv::GHC);
			intrin->setDoesNotReturn();
			// Merging allowed

			g.intrin_fns.insert({intrin_name, Expand_gbr});
		}

		auto call = lb->CreateCall(intrin, {statev, membasev, constv<32>(gip)});
		call->setCallingConv(llvm::CallingConv::GHC);
		call->setTailCall();
		lb->CreateUnreachable();
	}
}

QIRToLLVM::QIRToLLVM(LLVMGenCtx &g_, CodeSegment *segment_, qir::Region *region_, u32 region_ip_)
    : LLVMGen(g_, g_.cmodule.getFunction(MakeAotSymbol(region_ip_))), region(region_)
{
	region_ip = region_ip_;
}

llvm::Function *QIRToLLVM::Run()
{
	auto lirb = llvm::IRBuilder<>(llvm::BasicBlock::Create(lctx, "entry", func));
	lb = &lirb;
	llvm::Value *region_cycle_t0 = nullptr;
	u32 region_cycle_slot = ~0u;
	// EmitTrace();

	CreateVGPRLocs(region->GetVRegsInfo());
	// One entry-block slot per compiled function.  Creating these allocas in
	// Emit_rvvfpbegin/Emit_rvvfpend placed them inside hot loop blocks; alloca is
	// dynamic there and accumulated stack space on every iteration until fdtd
	// crossed rvdbt's switched-stack guard page.  A single slot is sufficient
	// because FP regions cannot be nested.
	rvv_mxcsr_slot = lb->CreateAlloca(lb->getInt32Ty(), nullptr, "rvv.mxcsr");

	if (dbt::config::aot_work_counter) {
		// DVET: one relaxed increment per region entry (single guest thread; both trial variants carry
		// the SAME instrumentation so the epoch work-rate comparison is unbiased)
		auto *wep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
						 offsetof(CPUState, work_counter));
		auto *wv = lb->CreateAlignedLoad(lb->getInt64Ty(), wep, llvm::Align(alignof(u64)));
		lb->CreateAlignedStore(lb->CreateAdd(wv, lb->getInt64(1)), wep, llvm::Align(alignof(u64)));
	}

	if (dbt::config::aot_region_hit_count) {
		// 2026-07-28 A-line causal diagnostic: same insertion point/discipline as aot_work_counter
		// above, but per-region -- a compile-time-assigned dense slot (direct array indexing, no
		// hash, no collision, matching tcache.h's gbrind_ctx1_slots discipline), one static
		// next-slot counter shared across this single-threaded batch compile.
		static u32 next_region_hit_slot = 0;
		if (next_region_hit_slot < CPUState::REGION_HIT_SLOTS) {
			u32 slot = next_region_hit_slot++;
			if (dbt::config::aot_region_hit_map_out) {
				static std::ofstream map_out(dbt::config::aot_region_hit_map_out);
				map_out << slot << " " << std::hex << region_ip << std::dec << "\n";
			}
			auto *hep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
							  offsetof(CPUState, region_entry_hits) + slot * sizeof(u64));
			auto *hv = lb->CreateAlignedLoad(lb->getInt64Ty(), hep, llvm::Align(alignof(u64)));
			lb->CreateAlignedStore(lb->CreateAdd(hv, lb->getInt64(1)), hep, llvm::Align(alignof(u64)));
		}
	}

	if (dbt::config::aot_region_cycle_count) {
		static u32 next_region_cycle_slot = 0;
		if (next_region_cycle_slot < CPUState::REGION_HIT_SLOTS) {
			region_cycle_slot = next_region_cycle_slot++;
			if (dbt::config::aot_region_hit_map_out) {
				static std::ofstream cycle_map_out(dbt::config::aot_region_hit_map_out);
				cycle_map_out << region_cycle_slot << " " << std::hex << region_ip << std::dec << "\n";
			}
			auto rdtsc = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::readcyclecounter);
			region_cycle_t0 = lb->CreateCall(rdtsc);
		}
	}

	if (dbt::config::sr_activation_invariant && region->num_insns > 0) {
		// Line-B activation invariant (LINEB_GATE_IMPLEMENTATION_PLAN.md): one increment per region entry,
		// by the region's static instruction count -- keeps exec_instr_seen consistent with the QCG-side
		// instrumentation (QEmit::EmitInstrSeenIncr) so total guest execution mass is tracked across BOTH
		// tiers, not just whichever compiled this particular region.
		auto *iep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
						  offsetof(CPUState, exec_instr_seen));
		auto *iv = lb->CreateAlignedLoad(lb->getInt64Ty(), iep, llvm::Align(alignof(u64)));
		lb->CreateAlignedStore(lb->CreateAdd(iv, lb->getInt64(region->num_insns)), iep,
					llvm::Align(alignof(u64)));
	}

	id2bb.clear();
	llvm::BasicBlock *first_bb = nullptr;
	std::unordered_map<u32, llvm::BasicBlock *> entry2bb; // Round-41: group-entry guest ip -> its LLVM block
	for (auto &bb : region->GetBlocks()) {
		auto id = bb.GetId();
		auto *lbb = llvm::BasicBlock::Create(lctx, "bb." + std::to_string(bb.GetId()), func);
		if (id == 0) // TODO: start bb in qir
			first_bb = lbb;
		if (bb.entry_ip) { // tagged ip-range entry block (translator)
			entry2bb[bb.entry_ip] = lbb;
			entry2bb_m[bb.entry_ip] = lbb;
		}
		id2bb.insert({id, lbb});
	}
	if (!internal_dispatch_targets.empty()) {
		auto fn_name = std::string(func->getName());
		g.fn2internal_dispatch_targets[fn_name] = internal_dispatch_targets;
		g.fn2entry_blocks[fn_name] = entry2bb_m;
	}
	// LaneB fix: P3 (`internal_dispatch_targets`, edge-region-merge) blocks are pulled into this
	// function with ZERO real CFG predecessors -- the only thing that will ever reference them
	// (Expand_gbrind's internal switch, llvmgen.cpp ~683) does not run until the FINAL
	// intrinsic-expansion pass, several full O3 module-optimization iterations later (see
	// dbt/aot/llvmaot.cpp's n_expands loop). In between, LLVM's own unreachable-block elimination
	// (part of every one of those earlier iterations' default pipeline) deletes any block with no
	// real predecessor -- confirmed via DBT_DIAG_MERGE_SWITCH: entry2bb_m ends up holding a
	// dangling/reused BasicBlock* by the time Expand_gbrind runs, which is the exact use-after-free
	// behind the verifier-stage SIGSEGV/SIGABRT/SIGILL non-determinism this mechanism showed on
	// every real-workload config tried. Fix: give these blocks a REAL, permanent predecessor edge
	// right here, at Run()-time, while every BasicBlock* is guaranteed live -- by folding them into
	// the SAME entry `state->ip` switch the (unrelated, but structurally identical and already
	// working) Round-41 `merge_entries` multi-entry-worker mechanism below already uses. The added
	// cases are never actually taken by any real caller (no caller sets state->ip to an
	// internal-only merge target before entering THIS function's entry) -- their only job is to
	// keep the block provably CFG-reachable from func's entry for the whole pipeline, so it is
	// still there (and still verifier-clean) when Expand_gbrind later builds the real dispatch
	// switch at the actual gbrind call site. Functions with neither feature active take the
	// unchanged `CreateBr(first_bb)` path -- byte-identical default behavior.
	if (merge_entries.size() > 1 || !internal_dispatch_targets.empty()) {
		// Round-41 region-merge: multi-entry worker. Route the requested guest ip (set by dispatch in
		// state->ip before entering AOT) to the matching region-entry block via a switch.
		auto *ipp = MakeStateEP(VType::I32, offsetof(CPUState, ip));
		auto *ipv = lb->CreateLoad(lb->getInt32Ty(), ipp, "merge.ip");
		unsigned n_cases = (unsigned)(merge_entries.size() + internal_dispatch_targets.size());
		// Design 8 diagnostic trace (--aot-link-multientry-trace): a small counting shim in front
		// of the default arm and each merge_entries case, proving (not assuming) which path a
		// real run actually takes. Gated so the default (flag off) switch is byte-identical.
		auto emit_count_incr = [&](llvm::IRBuilder<> *ib, u32 offs) {
			auto *cp = ib->CreateConstInBoundsGEP1_64(ib->getInt8Ty(), statev, offs);
			auto *cpp = ib->CreateBitCast(cp, llvm::PointerType::getUnqual(ib->getInt64Ty()));
			auto *cv = ib->CreateAlignedLoad(ib->getInt64Ty(), cpp, llvm::Align(alignof(u64)));
			ib->CreateAlignedStore(ib->CreateAdd(cv, ib->getInt64(1)), cpp, llvm::Align(alignof(u64)));
		};
		auto *default_target = first_bb;
		if (dbt::config::aot_link_multientry_trace) {
			auto *shim = llvm::BasicBlock::Create(lctx, "mtrace.default", func);
			llvm::IRBuilder<> sb(shim);
			emit_count_incr(&sb, offsetof(CPUState, dbg_multientry_default_hits));
			sb.CreateBr(first_bb);
			default_target = shim;
		}
		auto *sw = lb->CreateSwitch(ipv, default_target, n_cases ? n_cases : 1);
		std::vector<u32> case_weights;
		for (u32 e : merge_entries) {
			auto it = entry2bb.find(e);
			if (it != entry2bb.end() && it->second != first_bb) {
				auto *case_target = it->second;
				if (dbt::config::aot_link_multientry_trace) {
					auto *shim = llvm::BasicBlock::Create(lctx, "mtrace.case", func);
					llvm::IRBuilder<> sb(shim);
					emit_count_incr(&sb, offsetof(CPUState, dbg_multientry_switch_hits));
					sb.CreateBr(case_target);
					case_target = shim;
				}
				sw->addCase(llvm::ConstantInt::get(lb->getInt32Ty(), e), case_target);
				// T5c-0: ground truth for the wrapper-safety check in llvmaot.cpp.
				g.fn2merge_cases[std::string(func->getName())].insert(e);
				case_weights.push_back((u32)std::min<u64>(LookupExecCount(e) + 1, ~0u));
			}
		}
		for (u32 tgt : internal_dispatch_targets) {
			auto it = entry2bb.find(tgt);
			if (it != entry2bb.end() && it->second != first_bb) {
				sw->addCase(llvm::ConstantInt::get(lb->getInt32Ty(), tgt), it->second);
				// A-line move-not-copy: exact ground truth of which internal-target entry
				// cases exist; llvmaot.cpp's thunk verification reads this.
				g.fn2switch_cases[std::string(func->getName())].insert(tgt);
				case_weights.push_back((u32)std::min<u64>(LookupExecCount(tgt) + 1, ~0u));
			}
		}
		// DC-9-style real weights: bias toward the default (normal, non-wrapper) entry using the
		// SAME always-on objprof exec_count data, so the branch predictor learns the overwhelmingly
		// common outcome instead of treating this check as unpredictable. +1 floor avoids the
		// all-zero case createBranchWeights rejects; never changes correctness, only prediction.
		if (dbt::config::aot_brcc_real_weights && !case_weights.empty()) {
			auto mdb = llvm::MDBuilder(lctx);
			std::vector<u32> weights;
			weights.push_back((u32)std::min<u64>(LookupExecCount(region_ip) + 1, ~0u));
			weights.insert(weights.end(), case_weights.begin(), case_weights.end());
			sw->setMetadata(llvm::LLVMContext::MD_prof, mdb.createBranchWeights(weights));
		}
	} else {
		lb->CreateBr(first_bb);
	}

	for (auto &bb : region->GetBlocks()) {
		auto lbb = id2bb.find(bb.GetId())->second;
		lb->SetInsertPoint(lbb);
		qbb = &bb;

		auto &ilist = bb.ilist;
		for (auto iit = ilist.begin(); iit != ilist.end(); ++iit) {
			// C5.2b: while a typed chunk group is open the insertion point is its
			// guard-HIT block, so anything emitted there runs only when the guard passed
			// -- while the guard-miss arm ran the helper instead. Only the body opcodes
			// that frame is built from may appear. See TChunkCheckBodyOp.
			if (tchunk_open) {
				TChunkCheckBodyOp(&*iit);
			}
			Visitor(this).visit(&*iit);
		}
		// A group that outlives its block would leave the join block unterminated and the
		// next block's instructions appended to the hit path.
		if (tchunk_open) {
			Panic("llvmgen: typed chunk group left open at the end of a block");
		}
	}

	if (region_cycle_t0) {
		auto rdtsc = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::readcyclecounter);
		for (auto &bb : *func) {
			auto *term = bb.getTerminator();
			if (!llvm::isa<llvm::ReturnInst>(term) && !llvm::isa<llvm::UnreachableInst>(term))
				continue;
			llvm::Instruction *before = term;
			if (auto *call = llvm::dyn_cast_or_null<llvm::CallInst>(term->getPrevNode());
			    call && (call->isTailCall() || llvm::isa<llvm::UnreachableInst>(term)))
				before = call;
			llvm::IRBuilder<> eb(before);
			auto *t1 = eb.CreateCall(rdtsc);
			auto *raw = eb.CreateConstInBoundsGEP1_32(eb.getInt8Ty(), statev,
				offsetof(CPUState, region_entry_hits) + region_cycle_slot * sizeof(u64));
			auto *cep = eb.CreateBitCast(raw, llvm::PointerType::getUnqual(eb.getInt64Ty()));
			auto *old = eb.CreateAlignedLoad(eb.getInt64Ty(), cep, llvm::Align(alignof(u64)));
			eb.CreateAlignedStore(eb.CreateAdd(old, eb.CreateSub(t1, region_cycle_t0)), cep,
				llvm::Align(alignof(u64)));
		}
	}

	assert(!verifyFunction(*func, &llvm::errs()));
	return func;
}

void QIRToLLVM::CreateVGPRLocs(qir::VRegsInfo *vinfo)
{
	vlocs.clear();
	vlocs_nglobals = vinfo->NumGlobals();

	for (RegN i = 0; i < vlocs_nglobals; ++i) {
		auto *info = vinfo->GetGlobalInfo(i);
		auto state_ep = MakeStateEP(info->type, info->state_offs);
		state_ep->setName(std::string("@") + info->name);
		vlocs.push_back(state_ep);
	}

	for (RegN i = vlocs_nglobals; i < vinfo->NumAll(); ++i) {
		auto type = vinfo->GetLocalType(i);
		auto name = "%" + std::to_string(i);
		auto state_ep = lb->CreateAlloca(MakeType(type), constv<32>(VTypeToSize(type)), name);
		vlocs.push_back(state_ep);
	}
}

llvm::Type *QIRToLLVM::MakeType(VType type)
{
	switch (type) {
	case VType::I8:
		return lb->getInt8Ty();
	case VType::I16:
		return lb->getInt16Ty();
	case VType::I32:
		return lb->getInt32Ty();
	// P4: ONE derivation for every host vector width. VTypeToSize is the single byte-count
	// authority (qir.h) and i64 lanes are how this backend has always spelled a raw chunk, so
	// V128/V256/V512 become <2/4/8 x i64> from the same expression -- no per-width branch, and a
	// vector VType that ever gains a new width is carried automatically.
	case VType::V128:
	case VType::V256:
	case VType::V512:
		return llvm::FixedVectorType::get(lb->getInt64Ty(), VTypeToSize(type) / 8);
	case VType::MASK64:
		return lb->getInt64Ty();
	default:
		unreachable("");
	}
}

llvm::PointerType *QIRToLLVM::MakePtrType(VType type)
{
	switch (type) {
	case VType::I8:
		return llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(lctx));
	case VType::I16:
		return llvm::PointerType::getUnqual(llvm::Type::getInt16Ty(lctx));
	case VType::I32:
		return llvm::PointerType::getUnqual(llvm::Type::getInt32Ty(lctx));
	// P4: same single derivation as MakeType, so the pointee can never disagree with the value.
	case VType::V128:
	case VType::V256:
	case VType::V512:
		return llvm::PointerType::getUnqual(
		    llvm::FixedVectorType::get(llvm::Type::getInt64Ty(lctx), VTypeToSize(type) / 8));
	case VType::MASK64:
		return llvm::PointerType::getUnqual(llvm::Type::getInt64Ty(lctx));
	default:
		unreachable("");
	}
}

llvm::Value *QIRToLLVM::LoadVOperand(qir::VOperand op)
{
	auto type = op.GetType();
	if (op.IsConst()) {
		return MakeConst(op.GetType(), op.GetConst());
	}
	auto [state_ep, is_global] = MakeVOperandEP(op);
	auto load = lb->CreateAlignedLoad(MakeType(type), state_ep, llvm::Align(VTypeToSize(type)));
	if (is_global) {
		AScopeState(load);
	}
	return load;
}

void QIRToLLVM::StoreVOperand(qir::VOperand op, llvm::Value *val)
{
	auto type = op.GetType();
	auto [state_ep, is_global] = MakeVOperandEP(op);
	auto store = lb->CreateAlignedStore(val, state_ep, llvm::Align(VTypeToSize(type)));
	if (is_global) {
		AScopeState(store);
	}
}

std::pair<llvm::Value *, bool> QIRToLLVM::MakeVOperandEP(VOperand op)
{
	assert(!op.IsConst());
	if (op.IsVGPR()) {
		return std::make_pair(vlocs[op.GetVGPR()], op.GetVGPR() < vlocs_nglobals);
	}
	if (op.IsGSlot()) {
		return std::make_pair(MakeStateEP(op.GetType(), op.GetSlotOffs()), true);
	}
	unreachable("");
}

llvm::Value *QIRToLLVM::MakeStateEP(VType type, u32 offs)
{
	return LLVMGen::MakeStateEP(MakePtrType(type), offs);
}

llvm::Value *QIRToLLVM::MakeVMemLoc(VType type, llvm::Value *addr)
{
	return LLVMGen::MakeVMemLoc(MakePtrType(type), addr);
}

llvm::ConstantInt *QIRToLLVM::MakeConst(VType type, u64 val)
{
	return llvm::ConstantInt::get(lctx, llvm::APInt(VTypeToSize(type) * 8, val));
}

llvm::Value *QIRToLLVM::RvvStateLoad(VType type, u32 offs, llvm::Align align)
{
	auto *p = MakeStateEP(type, offs);
	// CPUState is aligned, but a partial VLEN-128 vector window can begin at +8.
	return AScopeState(lb->CreateAlignedLoad(MakeType(type), p,
						      llvm::commonAlignment(align, offs)));
}

void QIRToLLVM::RvvStateStore(VType type, u32 offs, llvm::Value *value, llvm::Align align)
{
	// ORDER ITEM 3: noticed HERE rather than in each emitter, so a body that writes `vec.vstart`
	// cannot be forgotten by the frame-level check at `end`. See `tchunk_body_wrote_vstart`.
	if (tchunk_open &&
	    offs == (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)))
		tchunk_body_wrote_vstart = true;
	auto *p = MakeStateEP(type, offs);
	AScopeState(lb->CreateAlignedStore(value, p,
						 llvm::commonAlignment(align, offs)));
}

llvm::Value *QIRToLLVM::RvvGuard(u32 expected_vtype, u32 evl, bool fp, bool partial,
				 bool check_vstart)
{
	u32 const vo = offsetof(CPUState, vec);
	auto *ok = lb->CreateICmpEQ(RvvStateLoad(VType::I32,
		vo + offsetof(rv32::VectorState, vlenb), llvm::Align(4)),
		lb->getInt32(config::vlen_bits / 8));
	ok = lb->CreateAnd(ok, lb->CreateICmpEQ(RvvStateLoad(VType::I32,
		vo + offsetof(rv32::VectorState, vtype), llvm::Align(4)), lb->getInt32(expected_vtype)));
	auto *vl = RvvStateLoad(VType::I32, vo + offsetof(rv32::VectorState, vl), llvm::Align(4));
	ok = lb->CreateAnd(ok, partial ? lb->CreateICmpULE(vl, lb->getInt32(evl))
				      : lb->CreateICmpEQ(vl, lb->getInt32(evl)));
	if (check_vstart)
		ok = lb->CreateAnd(ok, lb->CreateICmpEQ(RvvStateLoad(VType::I32,
			vo + offsetof(rv32::VectorState, vstart), llvm::Align(4)), lb->getInt32(0)));
	if (fp) {
		u32 const fo = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
		auto *fcsr = RvvStateLoad(VType::I32, fo, llvm::Align(4));
		auto *frm = lb->CreateAnd(lb->CreateLShr(fcsr, lb->getInt32(5)), lb->getInt32(7));
		ok = lb->CreateAnd(ok, lb->CreateICmpULE(frm, lb->getInt32(rv32::FRM_RUP)));
	}
	return ok;
}

// W7. THE VTYPE-INDEPENDENT GUARD: `vlenb == expected && vstart == 0`, and nothing else.
//
// It is a separate function from RvvGuard rather than a flag on it, because the two express
// different facts and the difference is the point. RvvGuard always emits a vtype compare and a vl
// compare; a whole-register transfer is governed by NEITHER (RVV 1.0 16.6 -- the vmv<nr>r.v
// instructions move NREG entire registers and are independent of vl and LMUL). Emitting a
// `vl == VLMAX` test for such a frame would send architecturally ordinary executions to the helper
// and, worse, would state in the emitted code that the operation depends on a quantity it does not.
//
// `vlenb` is the one width fact the body depends on: the translator has already turned the runtime
// VLEN into a fixed chunk count and a fixed set of CPUState displacements, so this compare is what
// proves the VLEN compiled for is the VLEN executing. `vstart == 0` is the body's other
// precondition -- see Emit_vwholemove for why the nonzero case is deliberately not admitted.
llvm::Value *QIRToLLVM::RvvVlenbVstartGuard(u32 expected_vlenb)
{
	if (expected_vlenb != config::vlen_bits / 8) {
		Panic("llvmgen: vlenb frame guard disagrees with this artifact's compile-time VLEN");
	}
	u32 const vo = offsetof(CPUState, vec);
	auto *ok = lb->CreateICmpEQ(RvvStateLoad(VType::I32,
		vo + offsetof(rv32::VectorState, vlenb), llvm::Align(4)),
		lb->getInt32(expected_vlenb));
	return lb->CreateAnd(ok, lb->CreateICmpEQ(RvvStateLoad(VType::I32,
		vo + offsetof(rv32::VectorState, vstart), llvm::Align(4)), lb->getInt32(0)));
}

// C1 (2026-09-17). THE WHOLE-REGISTER MEMORY GUARD, AND WHY IT IS THREE TESTS RATHER THAN ONE.
//
// `vl<NREG>re<EEW>.v` / `vs<NREG>r.v` transfer NREG whole registers. Before this checkpoint the
// LLVM fast arm of Emit_rvvload/Emit_rvvstore tested `vlenb` ALONE and then transferred the entire
// group starting at `addr`. Two architectural preconditions were therefore unchecked, and every
// OTHER arm in this repository checks or handles both:
//
//   1. VSTART. RVV 1.0 7.9: elements below `vstart` are NOT transferred -- for a load the register
//      prefix is preserved, for a store the memory prefix is preserved -- and the restart unit of a
//      whole-register MEMORY transfer is the ENCODED EEW (unlike the register move, whose unit is
//      SEW). `rvv_ref::whole_reg_load`/`whole_reg_store` implement exactly that with `start_byte`;
//      QCG's RvvQcgWholeRegAdmit frame carries GuardKind::VlenbVstartBaseLimit, which tests
//      `vstart == 0` and sends a restarted transfer to the fallback; RvvTryIntegerFamily's frame
//      carries GuardKind::VlenbRestartable, whose body handles a nonzero vstart. The LLVM arm did
//      neither: at `vstart = k` it re-loaded the whole group (clobbering the preserved register
//      prefix) or re-stored it (writing guest bytes the instruction must not write), and then
//      cleared vstart as if it had completed the whole transfer. `vstart` is a writable CSR, so a
//      guest reaches this with `csrw vstart, k` -- it does not require a trap.
//
//   2. THE 4 GiB GUEST WINDOW. The transfer is `nregs * VLEN/8` bytes from `addr`. The helper wraps
//      each byte inside the 32-bit guest space (`guest_span_wraps` -> `guest_*_bytes_wrapped`) and
//      QCG's frame bounds `base` by `2^32 - transfer length`. The LLVM arm zero-extended `addr` and
//      indexed off `membase`, so a transfer straddling the top of the guest space read or wrote
//      past the window instead of wrapping.
//
// This backend has no restart body and no wrapping body, so -- exactly as W7 did for the register
// move -- the native arm is RESTRICTED to the cases it can express and everything else takes the
// unchanged helper, which is correct for both. That is a narrower fast arm, never a wrong one.
//
// `total_bytes` is the node's own `evl` (nregs * VLEN/8). The bound is `addr <= 2^32 - total`,
// written as the unsigned compare `addr <= (u32)(0 - total)`: for any `total` in [1, 2^32) that
// constant IS `2^32 - total`, and `total` is at least 16 here.
llvm::Value *QIRToLLVM::RvvWholeRegMemGuard(llvm::Value *addr, u32 total_bytes)
{
	if (total_bytes == 0) {
		Panic("llvmgen: whole-register transfer with a zero byte count");
	}
	u32 const vo = offsetof(CPUState, vec);
	auto *ok = lb->CreateICmpEQ(RvvStateLoad(VType::I32,
		vo + offsetof(rv32::VectorState, vlenb), llvm::Align(4)),
		lb->getInt32(config::vlen_bits / 8));
	ok = lb->CreateAnd(ok, lb->CreateICmpEQ(RvvStateLoad(VType::I32,
		vo + offsetof(rv32::VectorState, vstart), llvm::Align(4)), lb->getInt32(0)));
	return lb->CreateAnd(ok, lb->CreateICmpULE(addr, lb->getInt32(0u - total_bytes)));
}

// ORDER ITEM 3 (2026-09-19). THE ARCHITECTURAL MASK, DERIVED IN ONE PLACE.
//
// RVV 1.0 5.3: the mask is always v0, one BIT per element, element `e` at bit `e % 8` of byte
// `e / 8` -- independent of SEW, LMUL and VLEN. Guest and host are both little-endian, so a 16-bit
// load of the containing aligned group has element `e` at bit position `e % 16` of the value.
//
// THE WINDOW COMES FROM THE CONTRACT (`rvvcontract::MaskWindowForUnit`) rather than being open-coded
// here, and it FAILS CLOSED: a lane count whose unit would straddle the group returns `bits == 0`
// and Panics, instead of silently reading a neighbouring unit's bits as its own. Admission has
// already refused such a shape, so the Panic is a restatement, not a live path.
//
// IT IS A FUNCTION RATHER THAN TWO COPIES because two consumers need exactly the same set: the
// destination publication (`Emit_vstatechunkstore`) and the FP operand neutralisation
// (`Emit_vchunkfalu` and its siblings). If those two disagreed about which elements are active, an
// inactive lane would be suppressed in one and computed in the other -- which for FP means a flag
// in the guest `fcsr` for an element the instruction must not touch.
llvm::Value *QIRToLLVM::RvvArchMaskForUnit(u32 lanes, u32 element_base)
{
	auto const win = rv32::rvvcontract::MaskWindowForUnit(element_base, lanes);
	if (!win.bits || win.bits != 16)
		Panic("llvmgen: architectural mask unit is not a describable mask window");
	u32 const v0_offs = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
	if ((size_t)v0_offs + win.byte_offset + win.bits / 8u > sizeof(CPUState))
		Panic("llvmgen: architectural mask window lies outside CPUState");
	// v0 unconditionally: the base carries no register-index term, so nothing here depends on vd.
	auto *group = RvvStateLoad(VType::I16, v0_offs + win.byte_offset, llvm::Align(1));
	// THE SHIFT IS FAIL-CLOSED, NOT LOAD-BEARING TODAY, and that is stated rather than left to be
	// discovered: `RvvHostChunkGeometryForSew` makes a unit `min(VLEN/8, 64)` bytes, so a frame has
	// more than one unit only when that is 64, which at SEW 32 means `lanes == 16` and every
	// element base is a multiple of the 16-bit group. At SEW 64 `lanes == 8` and units 1, 3, 5 ...
	// DO carry a shift, so this is live for the e64 FP families.
	llvm::Value *bits = win.bit_shift
		? lb->CreateLShr(group, lb->getInt16((u16)win.bit_shift))
		: (llvm::Value *)group;
	bits = lb->CreateTrunc(bits, llvm::IntegerType::get(lctx, lanes));
	return lb->CreateBitCast(bits, llvm::FixedVectorType::get(lb->getInt1Ty(), lanes));
}

llvm::Value *QIRToLLVM::RvvActiveLaneMask(u32 lanes, u32 element_base, bool architectural_mask,
					  bool vstart_floor)
{
	// ONE VALUE PER (unit, kind) PER FRAME -- see the memo's declaration in llvmgen.h. The block
	// check is what makes reuse unconditionally safe: a cached value is returned only when the
	// emitter is still inserting into the block that defined it, so it always dominates its use.
	LaneMaskKey const key{lanes, element_base, architectural_mask, vstart_floor};
	for (auto const &e : tchunk_lane_masks)
		if (e.key == key && e.block == lb->GetInsertBlock())
			return e.value;
	auto *vl = RvvStateLoad(VType::I32,
				offsetof(CPUState, vec) + offsetof(rv32::VectorState, vl),
				llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 i = 0; i < lanes; ++i)
		idx.push_back(lb->getInt32(element_base + i));
	llvm::Value *m = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
					   lb->CreateVectorSplat(lanes, vl));
	// The contract's active predicate is the CONJUNCTION of all three.
	if (architectural_mask)
		m = lb->CreateAnd(m, RvvArchMaskForUnit(lanes, element_base));
	// ORDER ITEM 3, RESTART: the FLOOR. Emitted only when the frame's guard does NOT prove
	// `vstart == 0` -- otherwise it would be a runtime compare of a value the guard has already
	// pinned, and the contract's `PredicateIsSound` is satisfied either way. RVV 1.0 3.7: elements
	// below `vstart` are left UNDISTURBED, which for a body that publishes through a predicated
	// store means exactly "not written".
	if (vstart_floor) {
		auto *vstart = RvvStateLoad(
		    VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		    llvm::Align(4));
		llvm::SmallVector<llvm::Constant *, 64> idx2;
		for (u32 i = 0; i < lanes; ++i)
			idx2.push_back(lb->getInt32(element_base + i));
		// UGE, not UGT: element `vstart` itself IS active.
		m = lb->CreateAnd(m, lb->CreateICmpUGE(llvm::ConstantVector::get(idx2),
						       lb->CreateVectorSplat(lanes, vstart)));
	}
	tchunk_lane_masks.push_back({key, lb->GetInsertBlock(), m});
	return m;
}

// C5-FP (2026-09-18). WHY INACTIVE FP LANES MUST BE NEUTRALISED, AND WHY THE VALUE IS +1.0.
//
// The destination store is already predicated, so an inactive lane's RESULT never reaches guest
// state. That is not sufficient for FP. `RvvFpBracketCloseBody` executes `stmxcsr` and ORs the host
// MXCSR sticky bits into the guest `fcsr`, so an exception raised while COMPUTING a lane the
// instruction must not touch becomes an architecturally visible guest flag. RVV requires inactive
// elements to raise nothing.
//
// LLVM's VP intrinsics do not solve this on x86: measured on the installed LLVM 20.1.8, a masked
// `llvm.vp.fadd` lowers to an UNMASKED `vaddps` (and `llvm.vp.fma` to an unmasked `vfmadd213ps`),
// because the default FP environment says exceptions are not observed. There are no constrained VP
// intrinsics at all. So predication has to be applied to the OPERANDS.
//
// +1.0, NOT +0.0, and that distinction is the whole point. For every operation this backend lowers
// natively, `(+1.0) op (+1.0)` is exactly representable and raises nothing:
//
//   fadd 1+1 = 2   fsub 1-1 = +0   fmul 1*1 = 1   fdiv 1/1 = 1   fma 1*1+1 = 2   fsqrt sqrt(1) = 1
//
// `+0.0` fails for exactly one of them -- `(+0)/(+0)` raises NV -- and `VF6_VFDIV` IS in
// `vfalu_llvm_constrained_vv_supported`, so division is admitted and cannot be waved away. No
// operand is zero, no result is NaN, Inf or subnormal, and +1.0 is normal so DAZ/FTZ cannot change
// it; therefore no NV, DZ, OF, UF or NX can originate in an inactive lane.
llvm::Value *QIRToLLVM::RvvNeutralizeInactiveFP(llvm::Value *v, llvm::Value *mask,
						llvm::FixedVectorType *fty)
{
	auto *one = llvm::ConstantFP::get(fty->getElementType(), 1.0);
	auto *ones = llvm::ConstantVector::getSplat(fty->getElementCount(), one);
	return lb->CreateSelect(mask, v, ones);
}

void QIRToLLVM::RvvStoreGroup(u8 reg, u8 active_chunks, VOperandSpan values, u8 first_operand)
{
	u8 const per_reg = (u8)(config::vlen_bits / 512);
	for (u8 c = 0; c < active_chunks; ++c) {
		u8 const r = reg + c / per_reg, sub = c % per_reg;
		u32 const off = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) +
				r * rv32::VLEN_MAX_BYTES + sub * 64;
		RvvStateStore(VType::V512, off, LoadVOperand(values[first_operand + c]), llvm::Align(16));
	}
}

std::array<llvm::Value *, 4> QIRToLLVM::RvvLoadGroup(u8 reg, u8 active_chunks)
{
	std::array<llvm::Value *, 4> out{};
	u8 const per_reg = (u8)(config::vlen_bits / 512);
	for (u8 c = 0; c < active_chunks; ++c) {
		u8 const r = reg + c / per_reg, sub = c % per_reg;
		u32 const off = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) +
				r * rv32::VLEN_MAX_BYTES + sub * 64;
		out[c] = RvvStateLoad(VType::V512, off, llvm::Align(16));
	}
	return out;
}

void QIRToLLVM::RvvCallFallback(RuntimeStubId stub, u32 raw)
{
	lb->CreateCall(g.qcg_helper_fnty, MakeRStub(stub, g.qcg_helper_fnty), {statev, lb->getInt32(raw)});
}

void QIRToLLVM::RvvCount(bool direct)
{
	if (!config::rvv_vector_ssa_counters)
		return;
	u32 const off = direct ? offsetof(CPUState, rvv_direct_hits) : offsetof(CPUState, rvv_direct_fallbacks);
	auto *p = MakeStateEP(VType::MASK64, off);
	auto *old = lb->CreateAlignedLoad(lb->getInt64Ty(), p, llvm::Align(8));
	lb->CreateAlignedStore(lb->CreateAdd(old, lb->getInt64(1)), p, llvm::Align(8));
}

llvm::Value *QIRToLLVM::RvvCanonicalize(llvm::Value *raw, u8 sew, VType chunk_ty)
{
	// W5: every quantity below comes from the chunk's own VType. At a 64-byte chunk this is
	// byte-for-byte the expression it replaces; at 16/32 bytes it is <4|8 x float> / <2|4 x double>
	// and the select and the bitcast follow. A width that is not a host vector width, or one that
	// does not hold a whole number of elements, is refused here rather than rounded -- the callers
	// check the same thing, and this is the function whose lane count would be silently wrong.
	if (!IsVectorVType(chunk_ty) || sew == 0 || VTypeToSize(chunk_ty) % sew != 0)
		Panic("llvmgen: canonical-NaN select on a chunk width that is not a whole number of elements");
	u32 const lanes = VTypeToSize(chunk_ty) / sew;
	auto *fty = llvm::FixedVectorType::get(sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), lanes);
	auto *v = lb->CreateBitCast(raw, fty);
	auto *isnan = lb->CreateFCmpUNO(v, v);
	llvm::Constant *lane = sew == 4
		? llvm::ConstantFP::get(lctx, llvm::APFloat(llvm::APFloat::IEEEsingle(),
			llvm::APInt(32, rv32::F32_CANONICAL_NAN)))
		: llvm::ConstantFP::get(lctx, llvm::APFloat(llvm::APFloat::IEEEdouble(),
			llvm::APInt(64, rv32::F64_CANONICAL_NAN)));
	auto *canon = llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes), lane);
	return lb->CreateBitCast(lb->CreateSelect(isnan, canon, v), MakeType(chunk_ty));
}

llvm::CmpInst::Predicate QIRToLLVM::MakeCC(CondCode cc)
{
	switch (cc) {
	case CondCode::EQ:
		return llvm::CmpInst::Predicate::ICMP_EQ;
	case CondCode::NE:
		return llvm::CmpInst::Predicate::ICMP_NE;
	case CondCode::LE:
		return llvm::CmpInst::Predicate::ICMP_SLE;
	case CondCode::LT:
		return llvm::CmpInst::Predicate::ICMP_SLT;
	case CondCode::GE:
		return llvm::CmpInst::Predicate::ICMP_SGE;
	case CondCode::GT:
		return llvm::CmpInst::Predicate::ICMP_SGT;
	case CondCode::LEU:
		return llvm::CmpInst::Predicate::ICMP_ULE;
	case CondCode::LTU:
		return llvm::CmpInst::Predicate::ICMP_ULT;
	case CondCode::GEU:
		return llvm::CmpInst::Predicate::ICMP_UGE;
	case CondCode::GTU:
		return llvm::CmpInst::Predicate::ICMP_UGT;
	default:
		unreachable("");
	}
}

llvm::BasicBlock *QIRToLLVM::MapBB(Block *bb)
{
	return id2bb.find(bb->GetId())->second;
}

void QIRToLLVM::EmitTrace()
{
	auto qcg_trace_type = llvm::FunctionType::get(lb->getVoidTy(), {lb->getPtrTy()}, false);
	lb->CreateCall(qcg_trace_type, MakeRStub(RuntimeStubId::id_trace, qcg_trace_type), {statev});
}

// OPAQUE_BOUNDARY mechanism ladder (2026-08-21, default off, DIAGNOSTIC ONLY): true if `name`
// appears in the colon-separated `spec`. Ordinary hcall dispatch (MakeRStub, below) loads the
// callee as a function POINTER from CPUState::stub_tab at runtime -- an indirect call whose
// target LLVM's CallBase::getCalledFunction() can never resolve, so no amount of linked-in
// bitcode could ever make it inlinable. Two independent allowlists use this same matcher:
// dbt::config::aot_diag_direct_funcs (A1/A2/A3: switch dispatch from indirect to a direct named
// call, independent of whether a body is ever linked in) and aot_diag_inline_funcs (A3 only:
// among functions that DO have a linked body, force alwaysinline). Kept as two lists, not one,
// specifically so A1 (direct call, no body) and A2 (direct call, linked body, still not inlined)
// are reachable as distinct configurations -- see CAUSAL_MEDIATION_STUDY.md's ladder.
static bool DiagNameInList(char const *spec, std::string_view name)
{
	if (!spec)
		return false;
	std::string_view sv(spec);
	size_t pos = 0;
	while (pos <= sv.size()) {
		size_t next = sv.find(':', pos);
		auto piece = sv.substr(pos, next == std::string_view::npos ? std::string_view::npos : next - pos);
		if (piece == name)
			return true;
		if (next == std::string_view::npos)
			break;
		pos = next + 1;
	}
	return false;
}

void QIRToLLVM::Emit_hcall(qir::InstHcall *ins)
{
	llvm::Value *callee = MakeRStub(ins->stub, g.qcg_helper_fnty);
	if (dbt::config::aot_diag_direct_funcs) {
		std::string_view name = GetRuntimeStubName(ins->stub);
		if (DiagNameInList(dbt::config::aot_diag_direct_funcs, name)) {
			// Direct-by-name call to a same-signature declaration in cmodule, instead of
			// the indirect stub_tab load above. Semantically identical today (this
			// declaration is still just a declaration until llvmaot.cpp's later link
			// step supplies a body) -- the only thing this changes is that the callee is
			// now a concrete llvm::Function*, which is what makes it a legal inlining
			// candidate once a body exists.
			// GetRuntimeStubName returns the bare X-macro name (e.g. "rv32_vfma"); the
			// real, linkable C++ symbol is qcgstub_##name (runtime_stubs.cpp:
			// `extern "C" void qcgstub_##name()`, `qcgstub_rv32_vfma` etc.) -- the
			// allowlists (--aot-diag-direct-funcs/--aot-diag-inline-funcs) are matched
			// against the bare name, but the LLVM symbol must be the prefixed one to ever
			// resolve against bitcode compiled from the real source.
			callee = cmodule.getOrInsertFunction("qcgstub_" + std::string(name), g.qcg_helper_fnty)
				     .getCallee();
		}
	}
	lb->CreateCall(g.qcg_helper_fnty, callee, {statev, LoadVOperand(ins->i(0))});
	if (--qbb->ilist.end() == ins) {
		lb->CreateRetVoid();
	}
}

// Normally RVVAddV remains a QCG-only inline operation and LLVM lowers it to its helper. T7a marks
// one node as `llvm_wide`: the exact accepted unmasked e32/m1/full-VL vadd.vv, deliberately kept as
// ONE original operation in QIR. That arm emits one FixedVectorType with vlmax i32 lanes. At VLEN
// 1024 this is `<32 x i32>` -- no 512-bit partition exists in QIR or in the generated pre-legalizer
// IR. The x86 backend alone decides how to legalize it. The default-off flag leaves the accepted
// V512-chunk route byte-for-byte on its old path.
void QIRToLLVM::Emit_rvvaddv(qir::InstRVVAddV *ins)
{
	if (ins->llvm_wide) {
		if (!config::aot_use_llvm || !config::rvv_llvm_wide_vadd || ins->sew_bytes != 4 ||
		    ins->emul_regs != 1 || (ins->vlmax != 16 && ins->vlmax != 32) ||
		    ins->chunks_per_reg != ins->vlmax / 4) {
			Panic("llvmgen: malformed T7a wide vadd node");
		}

		auto *fast = llvm::BasicBlock::Create(lctx, "rvv.wide.direct", func);
		auto *slow = llvm::BasicBlock::Create(lctx, "rvv.wide.fallback", func);
		auto *done = llvm::BasicBlock::Create(lctx, "rvv.wide.done", func);
		lb->CreateCondBr(RvvGuard(ins->vtype, ins->vlmax, /*fp=*/false), fast, slow);

		lb->SetInsertPoint(fast);
		auto *wide_ty = llvm::FixedVectorType::get(lb->getInt32Ty(), ins->vlmax);
		u32 const vreg_base = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
		u32 const slot = rv32::VLEN_MAX_BYTES;
		auto state_ptr = [&](u8 reg) {
			return lb->CreateGEP(lb->getInt8Ty(), statev,
					     lb->getInt64(vreg_base + (u32)reg * slot));
		};
		// Both complete source values are materialized before the destination store. The state
		// alias scope preserves that ordering for vd==vs1/vs2 as well as the disjoint case.
		auto *a = AScopeState(lb->CreateAlignedLoad(wide_ty, state_ptr(ins->vs2), llvm::Align(16)));
		auto *b = AScopeState(lb->CreateAlignedLoad(wide_ty, state_ptr(ins->vs1), llvm::Align(16)));
		auto *sum = lb->CreateAdd(a, b);
		AScopeState(lb->CreateAlignedStore(sum, state_ptr(ins->vd), llvm::Align(16)));
		RvvCount(true);
		lb->CreateBr(done);

		lb->SetInsertPoint(slow);
		RvvCount(false);
		RvvCallFallback(ins->stub, ins->raw);
		lb->CreateBr(done);

		lb->SetInsertPoint(done);
		if (--qbb->ilist.end() == ins) {
			lb->CreateRetVoid();
		}
		return;
	}
	lb->CreateCall(g.qcg_helper_fnty, MakeRStub(ins->stub, g.qcg_helper_fnty),
		       {statev, llvm::ConstantInt::get(lb->getInt32Ty(), ins->raw)});
	if (--qbb->ilist.end() == ins) {
		lb->CreateRetVoid();
	}
}

// ROUTING ISOLATION ONLY -- no lowering, and unreachable by construction.
//
// QIRToLLVM declares one Emit_<op> per entry of QIR_OPS_LIST (llvmgen.h), so adding an opcode
// without defining its member here is a link error. These three definitions exist solely to
// satisfy that, and they fail closed: RV32Translator::RvvQcgDiagChunkAdmit() returns 0 whenever
// config::aot_use_llvm is set, so the diagnostic chunk group is never built on an LLVM path and
// this Panic cannot fire. Lowering it here to a helper call instead would be actively wrong --
// the group is three-plus nodes for ONE guest instruction, so a per-node call would execute the
// guest add several times.
#define RVV_DIAG_CHUNK_LLVM_UNSUPPORTED(name, cls)                                                           \
	void QIRToLLVM::Emit_##name(qir::cls *)                                                              \
	{                                                                                                    \
		Panic("diagnostic RVV chunk group reached the LLVM backend");                                \
	}
RVV_DIAG_CHUNK_LLVM_UNSUPPORTED(rvvdiagchunkbegin, InstRVVDiagChunkBegin)
RVV_DIAG_CHUNK_LLVM_UNSUPPORTED(rvvdiagchunkadd, InstRVVDiagChunkAdd)
RVV_DIAG_CHUNK_LLVM_UNSUPPORTED(rvvdiagchunkend, InstRVVDiagChunkEnd)
#undef RVV_DIAG_CHUNK_LLVM_UNSUPPORTED

// T1f: THE TYPED V512 CHUNK OPS ARE NOW ALL ROUTED, so the fail-closed list that used to live here
// is gone -- with `vchunkand` lowered there is no member left to name, and a macro that expands to
// nothing is not a safety net.
//
// WHAT IT USED TO DO, AND WHAT STILL DOES IT. `RVV_CHUNK_LLVM_UNSUPPORTED` defined one Emit_ member
// per unrouted `vchunk*` op whose body was `Panic("typed V512 chunk op reached the LLVM backend")`.
// It was never expected to fire: it existed so that a routing change made WITHOUT its lowering would
// abort loudly instead of being silently absorbed -- lowering a 512-bit chunk to a scalar loop or a
// per-node helper call would make an AOT build disagree with the JIT it is supposed to match, and a
// per-node helper call would execute the guest instruction once per node. Two mechanisms still
// enforce exactly that, and they are the reason removing this list is safe rather than merely tidy:
//
//   * TChunkCheckBodyOp Panics on ANY opcode inside an open typed chunk group that is not on its
//     whitelist, so a future `vchunk*` op added without being whitelisted still aborts;
//   * TChunkAluLower Panics on any SEW the admission predicates do not admit, so a widened gate
//     without a widened lowering still aborts rather than substituting a lane width.
//
// The diagnostic trio keeps its own separate RVV_DIAG_CHUNK_LLVM_UNSUPPORTED above; that group is
// untouched by T1f and is still unroutable on this backend by design.
//
// THE HISTORY IS KEPT DELIBERATELY, because it is the rule the next opcode must follow. `vchunksub`
// left the list at S3.10a with (a) a lowering via TChunkAluLower, (b) an `Op::_vchunksub` entry in
// TChunkCheckBodyOp's whitelist and (c) an LLVM admission gate. `vchunkmul` left it at T1b with
// those three plus the two AOT plumbing edits an artifact needs to reach any of them -- an `elfaot`
// option and a `kRvvRouteContract` row (aot_boot.cpp) -- which S3.10a had omitted, leaving
// `vsub.vv` reachable by nothing until T1c added them. `vchunkxor` (T1d), `vchunkor` (T1e) and
// `vchunkand` (T1f) each arrived with all five at once. They are required together: a lowering
// without the whitelist entry Panics on the group's body check, a gate without a lowering Panics,
// and all three without the plumbing produce a route no artifact can ever take.

// S3.4: the direct-state `vsetvli` lowering for the LLVM/AOT tier.
//
// WHY THIS EXISTS. S3.3 showed the frozen add hot loop still reaches three translation-time helper
// boundaries on the LLVM path -- vsetvli, vle32.v, vse32.v -- while the QCG path has none, which
// makes any three-mode comparison a comparison of helper coverage rather than of code quality.
// This closes the FIRST of the three and nothing else.
//
// SCOPE is exactly RvvLLVMSetVLAdmit's: legal immediate-vtype `vsetvli` forms admitted by
// RvvQcgSetupShapeAdmit, with rd == x0 && rs1 == x0 excluded. The latter keep-VL form still
// needs a conditional vill result, which this straight-line node does not express. Unsupported
// vtypes and that form retain the semantic helper.
//
// rs1 == x0 needs nothing here: the translator hands it the architectural AVL = ~0u, and the same
// unsigned select below returns VLMAX for it. rd == x0 likewise needs nothing: StoreVOperand
// targets a temp instead of a guest global, so no architectural register is written.
//
// SEMANTICS, and they must equal the interpreter's and the QCG emitter's exactly:
//   vl              = UNSIGNED min(AVL, VLMAX)
//   guest rd        = vl
//   vec.vtype       = the node's translation-time immediate
//   vec.vl          = vl
//   vec.vstart      = 0
//   vec.vlenb       = VLEN/8
// The min is UNSIGNED and that is semantic, not stylistic: rvdbt's interpreter computes it on u32,
// and a signed compare agrees below 2^31 and returns AVL for the entire top half of the domain.
// `CreateICmpULT` is therefore load-bearing -- do not "simplify" it to an SLT.
//
// NO HELPER CALL, and no runtime guard. Every condition except AVL was decided at translation time,
// and min is exact over AVL's whole 2^32 domain, so there is no data predicate a guard could prove.
// The AVL is read through LoadVOperand from the guest rs1 global, so a RUNTIME AVL can never be
// folded to VLMAX; only a genuinely translation-time-constant AVL could fold, which is correct.
//
// rd == rs1 IS SAFE BY CONSTRUCTION HERE, unlike in the QCG emitter where it needed a fixed scratch
// register: the AVL is loaded into an SSA value before the result is stored, so the store to rd
// cannot clobber an operand that has not been read yet.
//
// Every CPUState access goes through MakeStateEP + the state alias scope via RvvStateStore, so no
// offset is hardcoded here and the stores keep the same aliasing contract as every other RVV state
// write in this backend.
// C2a (2026-09-17). `vsetvl` WITH THE VTYPE IN A GPR.
//
// The immediate forms (`vsetvli` / `vsetivli`) have had an LLVM lowering since S3.4
// (Emit_rvvsetvl): their vtype is a translation-time constant, so VLMAX is too. This form takes
// vtype from a register, so VLMAX is only known at run time and the vtype may be ILLEGAL. That is
// the whole of the difference, and it is why this needs a table lookup rather than a constant.
//
// THIS IS A FAITHFUL PORT OF QEmit::Emit_rvvsetvlreg, not a re-derivation. Same rules, same order
// (RVV 1.0 6.2 / 6.4):
//   * a vtype value above 255 is illegal -- checked on the WHOLE RV32 word, because masking to 8
//     bits would silently accept a reserved high bit or vill;
//   * otherwise VLMAX comes from `rv32::vlmax_table_for(VLEN)`, the SAME table QCG indexes, and a
//     zero entry means an unsupported vtype, i.e. illegal;
//   * `keep_vl` (the `rd == x0 && rs1 == x0` form) keeps the current `vl` and is illegal when the
//     new VLMAX cannot hold it; otherwise `vl = min(AVL, VLMAX)`;
//   * illegal sets `vtype := vill`, `vl := 0`, `rd := 0`;
//   * every path writes `vstart := 0`, and both sources are consumed before `rd` is written so
//     `rd == rs1` and `rd == rs2` are safe.
//
// THE TABLE IS A MODULE CONSTANT, NOT A BAKED HOST POINTER. QCG embeds the 256-entry table in the
// generated code for the same reason: an AOT artifact is compiled in `elfaot` and executed in
// `elfrun`, a DIFFERENT process, so a host address captured at compile time would be meaningless
// there. A private unnamed_addr constant lands in the artifact's own rodata and is
// position-independent.
//
// BRANCHLESS, a deliberate difference from QCG's label-based form. The architectural result is
// identical; the one place it shows is `vlenb`, which QCG leaves untouched on the illegal path
// while this stores back the value it just read -- same final state, one redundant store.
void QIRToLLVM::Emit_rvvsetvlreg(qir::InstRVVSetVLReg *ins)
{
	auto const *table = rv32::vlmax_table_for(ins->vlenb * 8);
	if (!table) {
		Panic("llvmgen: runtime vsetvl at an unsupported VLEN");
	}
	auto *i16ty = lb->getInt16Ty();
	auto *arr_ty = llvm::ArrayType::get(i16ty, rv32::VlmaxTable::SIZE);
	std::string const name = "rvv.vlmax." + std::to_string(ins->vlenb * 8);
	auto *gv = cmodule.getNamedGlobal(name);
	if (!gv) {
		llvm::SmallVector<llvm::Constant *, rv32::VlmaxTable::SIZE> entries;
		for (u32 i = 0; i < rv32::VlmaxTable::SIZE; ++i)
			entries.push_back(llvm::ConstantInt::get(i16ty, table->vlmax[i]));
		gv = new llvm::GlobalVariable(cmodule, arr_ty, /*isConstant=*/true,
					      llvm::GlobalValue::PrivateLinkage,
					      llvm::ConstantArray::get(arr_ty, entries), name);
		gv->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
		gv->setAlignment(llvm::Align(2));
	}

	auto *avl = LoadVOperand(ins->i(0));
	auto *vt = LoadVOperand(ins->i(1));

	auto *in_range = lb->CreateICmpULE(vt, lb->getInt32(rv32::VlmaxTable::SIZE - 1));
	// Clamp the index so the GEP stays in bounds on the illegal path too; `in_range` still
	// decides the result, so the clamp changes no architectural outcome.
	auto *idx = lb->CreateSelect(in_range, vt, lb->getInt32(0));
	auto *slot = lb->CreateInBoundsGEP(arr_ty, gv, {lb->getInt32(0), idx});
	auto *vlmax =
	    lb->CreateZExt(lb->CreateAlignedLoad(i16ty, slot, llvm::Align(2)), lb->getInt32Ty());
	llvm::Value *valid = lb->CreateAnd(in_range, lb->CreateICmpNE(vlmax, lb->getInt32(0)));

	u32 const vo = offsetof(CPUState, vec);
	llvm::Value *new_vl;
	if (ins->keep_vl) {
		auto *cur =
		    RvvStateLoad(VType::I32, vo + offsetof(rv32::VectorState, vl), llvm::Align(4));
		valid = lb->CreateAnd(valid, lb->CreateICmpUGE(vlmax, cur));
		new_vl = cur;
	} else {
		new_vl = lb->CreateSelect(lb->CreateICmpULT(avl, vlmax), avl, vlmax);
	}
	auto *vl_out = lb->CreateSelect(valid, new_vl, lb->getInt32(0));

	// rd is written AFTER both sources have been read, so rd == rs1 / rd == rs2 are safe.
	StoreVOperand(ins->o(0), vl_out);

	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vtype),
		      lb->CreateSelect(valid, vt, lb->getInt32(rv32::VTYPE_VILL_BIT)), llvm::Align(4));
	auto *cur_vlenb =
	    RvvStateLoad(VType::I32, vo + offsetof(rv32::VectorState, vlenb), llvm::Align(4));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vlenb),
		      lb->CreateSelect(valid, lb->getInt32(ins->vlenb), cur_vlenb), llvm::Align(4));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vl), vl_out, llvm::Align(4));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vstart), lb->getInt32(0),
		      llvm::Align(4));
}

void QIRToLLVM::Emit_rvvsetvl(qir::InstRVVSetVL *ins)
{
	auto *avl = LoadVOperand(ins->i(0));
	auto *vlmax = lb->getInt32(ins->vlmax);
	auto *vl = lb->CreateSelect(lb->CreateICmpULT(avl, vlmax), avl, vlmax);

	// The guest rd global. Stored AFTER the AVL has been read, which is what makes rd == rs1 safe.
	StoreVOperand(ins->o(0), vl);

	u32 const vo = offsetof(CPUState, vec);
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vtype), lb->getInt32(ins->vtype),
		      llvm::Align(4));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vl), vl, llvm::Align(4));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vstart), lb->getInt32(0),
		      llvm::Align(4));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vlenb), lb->getInt32(ins->vlenb),
		      llvm::Align(4));
}

// ---------------------------------------------------------------------------------------------
// C5.2b: the typed V512 chunk group for integer `vadd.vv`, lowered for the LLVM/AOT tier.
//
// SCOPE, and it is exactly the shape RvvQcgTypedChunkAdmit admits and no more: e32, LMUL=1,
// unmasked, vl == VLMAX, vstart == 0, at VLEN 512 or 1024, under `--rvv-vector-ssa`. Every other
// SEW, LMUL, mask setting, VLEN and architectural state keeps the pre-existing helper path, at
// translation time (the admission test) or at run time (the guard emitted here).
//
// SHAPE. `begin` opens the frame, `end` closes it, and the four-node body in between is the SAME
// QIR the accepted pure-QCG route builds -- one shared builder, RvvEmitTypedChunkGroup:
//
//     bb.N:                            ; guard, from the live CPUState
//       %ok = vlenb==VLEN/8 & vtype==<const> & vl==VLMAX & vstart==0
//       br i1 %ok, label %rvv.tchunk.direct, label %rvv.tchunk.fallback
//     rvv.tchunk.fallback:             ; exactly one call, and no typed body at all
//       call void %rv32_vadd_vv(ptr %state, i32 <raw guest word>)
//       br label %rvv.tchunk.done
//     rvv.tchunk.direct:               ; VLEN=1024 shown; VLEN=512 is the c=0 half alone
//       %s2.0 = load <8 x i64>, ptr @vec.vreg + vs2*128 + 0
//       %s1.0 = load <8 x i64>, ptr @vec.vreg + vs1*128 + 0
//       %s2.1 = load <8 x i64>, ptr @vec.vreg + vs2*128 + 64
//       %s1.1 = load <8 x i64>, ptr @vec.vreg + vs1*128 + 64
//       %d.0  = add <16 x i32> %s2.0, %s1.0
//       %d.1  = add <16 x i32> %s2.1, %s1.1
//               store <8 x i64> %d.0, ptr @vec.vreg + vd*128 + 0
//               store <8 x i64> %d.1, ptr @vec.vreg + vd*128 + 64
//       br label %rvv.tchunk.done
//     rvv.tchunk.done:
//
// TWO INDEPENDENT CHUNKS, NOT ONE WIDE VECTOR. The partition into 512-bit chunks is made in QIR, by
// the translator, and handed to LLVM one chunk to one `<16 x i32>` value. This backend does not
// build a `<32 x i32>` and it does not rely on LLVM's type legalizer to split one: at VLEN=1024
// there are two adds over four independently loaded values, with no def-use edge between chunk 0
// and chunk 1. Do not describe this as automatic wide-vector legalization.
//
// WHY THE FALLBACK ARM IS EMITTED AT `begin` AND NOT AT `end`. The AsmJit emitter has to place its
// fallback after the body, because its guard is a forward jump to a label it can only bind once the
// body is behind it (qemit.cpp). LLVM has no such constraint -- a basic block is addressable before
// it is filled -- so the arm is written where the branch that reaches it is created, which keeps
// `begin` a complete statement of the frame's control flow. Semantics are identical: one guard, one
// helper call on the miss, one join.
//
// LEGAL OPERAND OVERLAP is preserved by the same argument as in QCG, and it survives here because
// the QIR order survives: `begin` emits no memory access, every chunk's two source LOADS are
// emitted before any destination STORE (RvvEmitTypedChunkGroup builds load-major), and each chunk's
// 64-byte window is disjoint from the other's. So vd==vs1, vd==vs2 and vd==vs1==vs2 all read the
// pre-instruction bytes. Nothing in this function reorders the body: it emits one LLVM instruction
// per QIR node, in list order.
//
// NO GLOBAL SYNC IS NEEDED around the frame, unlike QCG. QIRToLLVM keeps no guest global in a host
// register: `CreateVGPRLocs` maps every global to a CPUState address and each access is an ordinary
// load/store there, which is exactly why `Emit_hcall` needs no sync either. The fallback helper and
// the typed body therefore see the same architectural state on both arms.
//
// The translator DOES still allocate a QIR virtual register per chunk value (it must -- the same
// QIR feeds QRegAlloc on the QCG path), so `CreateVGPRLocs` makes an entry-block alloca for each.
// Those allocas are never referenced here, because the values are carried as llvm::Value* in
// `tchunk_vals` rather than through LoadVOperand/StoreVOperand, and an alloca with no uses does not
// survive the first optimisation pass. That absence is the "real SSA value" property and it is
// asserted directly by the focused test (qmc/llvmgen/vaddvv_typedchunk_llvm_test.cpp): every memory
// access in the fast arm addresses CPUState, and there is no alloca traffic at all.
void QIRToLLVM::TChunkAccount()
{
	if (!tchunk_open) {
		Panic("llvmgen: typed V512 chunk op outside a typed chunk group");
	}
	++tchunk_seen;
}

void QIRToLLVM::TChunkDef(qir::VOperand op, llvm::Value *val)
{
	if (!op.IsVVPR() || !IsVectorVType(op.GetType())) {
		Panic("llvmgen: typed chunk result is not a virtual vector register");
	}
	if (!tchunk_vals.insert({op.GetVVPR(), val}).second) {
		Panic("llvmgen: typed chunk value defined twice in one group");
	}
}

llvm::Value *QIRToLLVM::TChunkUse(qir::VOperand op)
{
	if (!op.IsVVPR() || !IsVectorVType(op.GetType())) {
		Panic("llvmgen: typed chunk operand is not a virtual vector register");
	}
	auto it = tchunk_vals.find(op.GetVVPR());
	if (it == tchunk_vals.end()) {
		// A typed chunk value is defined and consumed inside one group, in one block. Reading
		// one that this group did not define would mean the value crosses the guard branch,
		// where the fallback arm never defined it.
		Panic("llvmgen: typed chunk operand was not defined in this group");
	}
	return it->second;
}

void QIRToLLVM::TChunkCheckBodyOp(qir::Inst *ins)
{
	switch (ins->GetOpcode()) {
	case Op::_vstatechunkload:
	case Op::_vchunkadd:
	case Op::_vwideaddssa: // T7b, one wide vadd over the frame's V512 SSA values
	case Op::_vchunksub:   // S3.10a, the vsub.vv frame's lane operation
	case Op::_vchunkmul:   // T1b, the vmul.vv frame's lane operation
	case Op::_vchunkxor:   // T1d, the vxor.vv frame's lane operation
	case Op::_vchunkor:    // T1e, the vor.vv frame's lane operation
	case Op::_vchunkand:   // T1f, the vand.vv frame's lane operation
	case Op::_vchunkload:  // S3.5, the vle32.v frame's guest-memory read half
	case Op::_vchunkstore: // S3.6, the vse32.v frame's guest-memory write half
	// Native-3, the `.vx` frame's scalar operand. Whitelisted for the same reason as every row
	// above and with the same consequence if it were missing: the group's body check would Panic
	// rather than silently absorb an op with no lowering.
	case Op::_vchunkbroadcast:
	case Op::_vstatechunkstore:
	// F1, the typed FP frame's nodes; F2's `vchunkfbroadcast` (the OPFVF scalar's frame-scope
	// splat); F3's `vchunkfma` (the fused lane op); W5F's `vchunkfsqrt` (the one-operand square
	// root). The remaining FP body nodes -- vchunkfcmpstate, vchunkfwidencvt, vchunkmaskset,
	// vchunkactive -- are deliberately NOT here: they have no lowering, and this check is the
	// first and cheapest place a frame that contains one fails, ahead of the individual Emit_
	// Panics.
	case Op::_rvvqcgfpbegin:
	case Op::_rvvqcgfpend:
	case Op::_vchunkfalu:
	case Op::_vchunkfbroadcast:
	case Op::_vchunkfma:
	case Op::_vchunkfsqrt:
	case Op::_vfreducenative: // W6, the ordered floating reduction's scalar left fold
	case Op::_vreducenative:  // C6, the integer reductions' chunk fold
	case Op::_vmasklogic:	  // C6, one 64-bit word of the mask logical family
	case Op::_vchunkindex:	  // C6, one chunk of `vid.v`
	case Op::_vmaskscalar:	  // C6, `vcpop.m` / `vfirst.m`
	case Op::_vmaskprefix:	  // C6, `vmsbf.m` / `vmsif.m` / `vmsof.m`
	case Op::_vmaskiota:	  // C6, `viota.m`
	case Op::_vcompressnative: // C6, `vcompress.vm`
	case Op::_vgathernative:  // C6, `vrgather` and the four slides
	case Op::_vmemorynative:  // C7, the strided vector memory forms
	case Op::_vwholemove:	  // W7, the whole-register move's fixed-width copy
	case Op::_vscalarmove:	  // C2b, the scalar <-> vector element-0 transfers
	case Op::_vchunksll:	  // C3, the immediate left shift's lane operation
	case Op::_vchunksrl:	  // C3, the immediate logical right shift's lane operation
	case Op::_vchunkextend:	  // C3, one unit of the integer extension family
	case Op::_vchunkwiden:	  // C3, one unit of the widening integer family
	case Op::_vchunknarrowshift: // C3, one unit of the narrowing-shift family
	case Op::_vchunknarrowclip: // order item 4, one unit of the narrowing-clip family
	case Op::_vchunkfclass:	  // C4, one unit of `vfclass.v`
	case Op::_vchunkfestimate: // order item 4, one unit of `vfrsqrt7.v` / `vfrec7.v`
	case Op::_vchunkfmerge:	  // order item 4, one unit of `vfmerge.vfm` / `vfmv.v.f`
	case Op::_vchunkfwidencvt: // order item 4, the widening FP family's f32 -> f64 convert
	case Op::_vchunksatadd:	  // order item 4, one lane op of the saturating add/sub family
	case Op::_vchunkadc:	  // order item 4, one lane op of the carry/borrow family
	case Op::_vchunkavg:	  // order item 4, one lane op of the fixed-point averaging family
	case Op::_vchunkfracmul:  // order item 4, one lane op of the fractional multiply
	case Op::_vchunkitof:	  // C4, one unit of the same-width integer-to-float conversions
	case Op::_vchunkftoi:	  // C4, one unit of the rtz float-to-integer conversions
	case Op::_vchunkftof:	  // C4, one unit of the widening float-to-float conversion
	case Op::_vchunkpartialalu: // W31, one chunk of an integer compare (the eight compare Kinds
				    // only -- Emit_vchunkpartialalu still Panics on the other 44, so
				    // admitting the op here does not admit the rest of its surface)
	case Op::_rvvtypedchunkend:
		return;
	default:
		Panic("llvmgen: non-typed instruction inside an open typed chunk group");
	}
}

void QIRToLLVM::Emit_rvvtypedchunkbegin(qir::InstRVVTypedChunkBegin *ins)
{
	if (tchunk_open) {
		Panic("llvmgen: typed chunk group opened inside another group");
	}
	// The authoritative ordered member list is carried by end. Defer the fallback body
	// until then, so a guard miss cannot silently execute only the first guest instruction.
	using GuardKind = qir::InstRVVTypedChunkBegin::GuardKind;
	bool const partial = ins->guard_kind == GuardKind::VTypeIntegerNoRestart;
	// F1: the FP frame's kind. It is the ONLY FP kind accepted here, and that is the whole of the
	// backend's FP admission: VTypePartialVlVstartFrmRNE (the QCG FP run's kind) tests
	// `vl <= VLMAX` and is refused, because this backend's FP body has no per-chunk mask and no
	// tail fill. RvvEmitVectorRunGroup forces every LLVM FP run to this kind for that reason; the
	// Panic below is the fail-closed proof of it rather than a second copy of the rule.
	bool const fp_rne = ins->guard_kind == GuardKind::VTypeVlVstartFrmRNE;
	// C5-FP: the PARTIAL FP kind -- exact vtype, `vl <= VLMAX`, `vstart == 0`, `frm == RNE`. Its
	// guard is the full-VL FP one with `vl == VLMAX` weakened to `<=`; admitting it is only safe
	// because the FP lane emitters neutralise inactive operands (see RvvNeutralizeInactiveFP),
	// which each of them checks for itself rather than trusting this site.
	bool const fp_rne_partial = ins->guard_kind == GuardKind::VTypePartialVlVstartFrmRNE;
	// C6-FRM (2026-09-20): the same two frames with the rounding test widened to `frm <= RUP`.
	// They take `RvvGuard`'s `fp` arm instead of the `frm == RNE` block below -- see the kinds'
	// declaration in qir.h for why RMM is excluded rather than admitted.
	bool const fp_host = ins->guard_kind == GuardKind::VTypeVlVstartFrmHostRound;
	bool const fp_host_partial = ins->guard_kind == GuardKind::VTypePartialVlVstartFrmHostRound;
	// W7: the vtype-independent whole-register kind. `VlenbRestartable` (kind 13) is NOT admitted
	// here and must not be conflated with this one: its contract is that the BODY handles a
	// nonzero vstart, which this backend has no lowering for. Admitting kind 13 with this guard
	// would silently drop the prestart region of a restarted transfer.
	bool const vlenb_vstart = ins->guard_kind == GuardKind::VlenbVstart;
	// C2b: GuardKind::VTypeInteger -- exact vtype and `vl <= VLMAX`, with vstart left to the BODY.
	// Admitted because the scalar-move body reads `vec.vstart` and implements the architectural
	// rule itself (RVV 1.0 16.1: `vmv.s.x` writes nothing when `vstart >= vl`; `vmv.x.s` ignores
	// both). It is NOT a general licence: every body node still has to have a lowering, and the
	// ones that do not still Panic, so admitting this kind cannot widen any other family.
	bool const vtype_body_restart = ins->guard_kind == GuardKind::VTypeInteger;
	// W32 (2026-09-21): the UNIT-STRIDE MEMORY kind -- exact vtype, `vl <= VLMAX`, `vstart == 0`,
	// AND the guest base register in range. It is the kind the QCG partial-VL `vle`/`vse` frames
	// already carry, reused here rather than duplicated, because the two backends need the same
	// PREDICATE and the kind names a predicate. What differs is the BODY: QCG splits vl == VLMAX
	// from vl < VLMAX into two arms (`rvvtypedchunkpartial`, which this backend still Panics on),
	// while this backend emits ONE body whose load and store both derive their lane mask from the
	// live `vec.vl`/`vec.vstart`, so full VL is the all-ones case of the same code.
	//
	// THE BASE TEST IS NOT OPTIONAL HERE AND IS THE REASON THIS KIND RATHER THAN
	// `VTypeIntegerNoRestart`. The body forms `membase + zext(base) + disp` with a HOST-pointer
	// displacement, which does not wrap at 2^32, while the reference computes each element's
	// address as `(u32)(base + e * eew)`, which does. `base <= 2^32 - VLEN/8` is what makes the
	// two agree, and it is the same constant and the same unsigned comparison QEmit emits for
	// this kind. Without it a base in the top VLEN/8 bytes of the guest space would read past
	// rvdbt's 4 GiB reservation instead of wrapping to address 0.
	bool const mem_partial = ins->guard_kind == GuardKind::VTypeVlOrPartialVstartBaseLimit;
	if (!partial && !fp_rne && !fp_rne_partial && !fp_host && !fp_host_partial &&
	    !vlenb_vstart && !vtype_body_restart && !mem_partial &&
	    ins->guard_kind != GuardKind::VTypeVlVstart)
		Panic("llvmgen: typed frame guard has no lowering in this backend");
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.tchunk.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.tchunk.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.tchunk.done", func);

	// Same four runtime conditions the AsmJit guard checks (vtype, vl, vstart), plus the vlenb
	// check RvvGuard already applies to every other typed RVV frame in this backend -- an artifact
	// carries ONE compile-time VLEN, so a runtime VLEN that disagrees must take the helper.
	// SEW, LMUL and the unmasked form are translation-time facts, decided by the admission test.
	// W7: the vlenb kind reads NEITHER vtype NOR vl, so it cannot go through RvvGuard, whose
	// vtype/vlmax arguments are zero for this kind's constructor by design.
	llvm::Value *guard =
	    vlenb_vstart
		? RvvVlenbVstartGuard(ins->vlenb)
		: RvvGuard(ins->vtype, ins->vlmax, /*fp=*/fp_host || fp_host_partial,
			   partial || vtype_body_restart || fp_rne_partial || fp_host_partial ||
			       mem_partial,
			   /*check_vstart=*/!vtype_body_restart);
	if (mem_partial) {
		// W32. `base <= base_limit`, unsigned, fail-closed to the helper -- the same test,
		// the same operand and the same direction as QEmit's `cmp eax, base_limit ; ja
		// fallback` for this kind. The bound QIR cannot apply is applied here, exactly as the
		// two AsmJit base-limit sites do it: QIR checks only that the offset is representable
		// in its u16 field, and whether the four bytes it names lie inside CPUState is
		// decidable only in a backend.
		if ((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState))
			Panic("llvmgen: base-limit guard offset lies outside CPUState");
		if (ins->base_limit == 0)
			Panic("llvmgen: base-limit guard has a zero bound");
		auto *base = RvvStateLoad(VType::I32, ins->base_state_offs, llvm::Align(4));
		guard = lb->CreateAnd(guard,
				      lb->CreateICmpULE(base, lb->getInt32(ins->base_limit)));
	}
	if (fp_rne || fp_rne_partial) {
		// F1. `frm == RNE`, AND THAT IS THE KIND'S OWN TEST RATHER THAN RvvGuard's `fp` ARM.
		//
		// The two are NOT interchangeable and the difference is one of admitted population.
		// `RvvGuard(..., fp=true)` emits `frm <= FRM_RUP`, i.e. it admits RNE/RTZ/RDN/RUP and
		// relies on the bracket mapping whichever one is live onto MXCSR.RC. QEmit's guard for
		// GuardKind::VTypeVlVstartFrmRNE emits `test dword[fcsr], 0xe0 ; jnz fallback`, i.e.
		// frm == RNE and nothing else. Emitting the weaker test for a node that declares the
		// stronger kind would make the two backends' frames cover different executions from the
		// same QIR, which every later arm-equivalence argument rests on not happening.
		//
		// Widening this to `frm <= RUP` is defensible on its own terms -- the bracket really
		// does install the live frm and the lane ops really are `round.dynamic` -- but it is a
		// change to which executions take the fast arm, so it needs its own evidence and is not
		// smuggled in here.
		u32 const fo = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
		auto *fcsr = RvvStateLoad(VType::I32, fo, llvm::Align(4));
		guard = lb->CreateAnd(guard, lb->CreateICmpEQ(
		    lb->CreateAnd(fcsr, lb->getInt32(0xe0)), lb->getInt32(0)));
	}
	lb->CreateCondBr(guard, fast, slow);

	lb->SetInsertPoint(fast);
	tchunk_done = done;
	tchunk_fallback = slow;
	tchunk_members = ins->n_members;
	tchunk_open = true;
	tchunk_expected = ins->n_typed;
	tchunk_seen = 0;
	// F1. Does this frame's guard already prove `vl == VLMAX && vstart == 0`? Read through the
	// SHARED qir.h predicate the translator uses, so the two cannot drift, and NOT multiplied by
	// config::rvv_qcg_full_vl_fast_body the way QEmit's `rvv_typed_chunk_full_vl` is: that flag
	// picks between two QCG bodies, one of them masked, while this backend has only the unmasked
	// one. Emit_vchunkfalu refuses to lower without it.
	tchunk_full_vl = qir::InstRVVTypedChunkBegin::GuardProvesFullVl(ins->guard_kind);
	// ORDER ITEM 3, RESTART: `vtype_body_restart` is exactly "the guard does not test vstart", the
	// same local the guard call above is built from, so the body's floor conjunct and the guard's
	// omission of the vstart compare are ONE fact rather than two that must be kept equal.
	tchunk_body_restart = vtype_body_restart;
	tchunk_body_wrote_vstart = false;
	// ORDER ITEM 3: per-frame, for the reason the memo's declaration gives -- the cached value
	// closes over a LOAD of `vec.vl` that is only known-live inside its own frame.
	tchunk_lane_masks.clear();
	tchunk_vals.clear();
}

void QIRToLLVM::Emit_vstatechunkload(qir::InstVStateChunkLoad *ins)
{
	TChunkAccount();
	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h.
	// Fail closed, exactly as QEmit does: reading past the end of CPUState is out of bounds.
	// P4: the window is the destination value's width (ins->Bytes()), not the 64-byte maximum --
	// the same generic rule QEmit::Emit_vstatechunkload has used since M2C.
	if ((size_t)ins->offs + ins->Bytes() > sizeof(CPUState)) {
		Panic("llvmgen: vstatechunkload window lies outside CPUState");
	}
	// The 16-byte base guarantee is reduced by RvvStateLoad for an offset window.
	TChunkDef(ins->o(0), RvvStateLoad(ins->o(0).GetType(), ins->offs, llvm::Align(16)));
}

// S3.10a: THE ONE INTEGER-ALU LANE OPERATION OF A TYPED CHUNK GROUP.
//
// The frame around this -- guard, fallback arm, join, CPUState windows, SSA value bookkeeping -- was
// already operation-independent before this checkpoint: Emit_rvvtypedchunkbegin reads vtype, vlmax,
// raw and stub off the node and does not know which opcode it is serving. The only per-opcode part
// of a typed integer-ALU frame is this single instruction, so this is where the family is
// parameterized and nowhere else.
//
// OPERAND ORDER IS SEMANTIC AND IS NOT NEGOTIATED HERE. `a` is the node's i(0) and `b` its i(1), and
// RvvEmitTypedAluChunkGroupCore builds every member with i(0) = the vs2 chunk and i(1) = the vs1
// chunk. `vsub.vv vd, vs2, vs1` is `vd[i] = vs2[i] - vs1[i]`, so `CreateSub(a, b)` is the correct
// direction and a swap here would be a silent miscompile that the commutative members would not
// reveal. The focused test drives an asymmetric fixture specifically to catch that.
//
// NO nuw/nsw ON ANY MEMBER. RVV integer add, subtract and multiply are all modulo 2^SEW, so
// attaching either flag would hand LLVM permission to fold an overflowing lane to poison. The
// IRBuilder's Create* default to neither; this comment exists so that stays a decision rather than
// an accident. It is at its sharpest for the T1b multiply: `vmul.vv` returns the LOW SEW bits of the
// product (rv32_vector_lower.h's vimul low-half arm), so lane overflow is not an edge case but the
// ORDINARY behaviour of the instruction on any input pair whose product exceeds 32 bits, and `nsw`
// there would poison lanes a conforming guest legitimately produces.
//
// SEW=32 ONLY, deliberately narrower than QEmit's vpaddb/w/d/q and vpsubb/w/d/q tables: SEW=32 is
// the whole set RvvAluChunkShapeAdmit admits, so any other width arriving here is a routing change
// made without extending this lowering. Substituting a different lane width would be a silent
// miscompile, so it is a hard failure instead. For the multiply SEW=32 is additionally the whole set
// RvvGenericChunkShapeAdmit admits at any VLEN, and on the QCG side it is a HOST fact rather than an
// evidence-scope decision (no packed byte multiply on x86; vpmullw is AVX512BW and vpmullq AVX512DQ,
// neither covered by that route's AVX512F probe). This backend has no such constraint -- `mul
// <N x iM>` is legal at every width -- but it must not admit a width the route's own predicate
// refuses, so the same single check serves both.
llvm::Value *QIRToLLVM::TChunkAluLower(TChunkAluOp op, u8 sew_bytes, qir::VOperand ia,
				       qir::VOperand ib)
{
	if (sew_bytes != 4) {
		Panic("llvmgen: typed ALU chunk op with an unsupported SEW");
	}
	// P4: the lane count follows the chunk's own width instead of the literal 16. At a 64-byte
	// chunk this is <16 x i32> byte-for-byte as before; at 32/16 bytes it is <8 x i32>/<4 x i32>.
	// ONE expression covers every width -- there is no per-width body here or below.
	VType const chunk_ty = ia.GetType();
	if (!IsVectorVType(chunk_ty) || ib.GetType() != chunk_ty) {
		Panic("llvmgen: typed ALU chunk operands disagree on width");
	}
	u32 const lanes = VTypeToSize(chunk_ty) / sew_bytes;
	auto *lanety = llvm::FixedVectorType::get(lb->getInt32Ty(), lanes);
	auto *a = lb->CreateBitCast(TChunkUse(ia), lanety);
	auto *b = lb->CreateBitCast(TChunkUse(ib), lanety);
	llvm::Value *r = nullptr;
	switch (op) {
	case TChunkAluOp::Add:
		r = lb->CreateAdd(a, b);
		break;
	case TChunkAluOp::Sub:
		r = lb->CreateSub(a, b);
		break;
	case TChunkAluOp::Mul:
		// T1b. `mul <16 x i32>` is the LOW 32 bits of each lane product, which is exactly what
		// RVV's `vmul.vv` defines and exactly what the QCG twin's `vpmulld` computes. It is NOT
		// a widening multiply and must never become one: `vmulh.vv`/`vmulhu.vv` are different
		// funct6 values that rv32_decode.h keeps in the generic `vimul` family, so a widening
		// lowering here would compute a different instruction's result for this one.
		r = lb->CreateMul(a, b);
		break;
	case TChunkAluOp::Or:
		// T1e. The second BITWISE member, and the lane width is architecturally irrelevant to it
		// for the xor's reason: an unmasked 512-bit or is the same 512 bits at every SEW, which
		// is why the QCG twin emits one `vpord` regardless. It is emitted at the family's
		// <16 x i32> lane type anyway, for the two reasons stated on the xor below.
		//
		// THIS IS THE SECOND OF THE THREE ADJACENT BITWISE VALUES TO BE ROUTED, so the two ways
		// to get it wrong are no longer symmetric. `CreateXor` here would steal the ACCEPTED T1d
		// route's operation and compute an XOR for a guest OR -- a regression of a shipped
		// route, not merely a new bug -- while `CreateAnd` would compute an AND for a guest OR
		// using an operation that has no LLVM lowering at all. Both produce working,
		// structurally perfect, wrong-valued code that no shape check would notice, so the
		// focused test gates the opcode directly and counts the other two at zero.
		r = lb->CreateOr(a, b);
		break;
	case TChunkAluOp::And:
		// T1f. The third and last BITWISE member, and the lane width is architecturally
		// irrelevant to it for the xor's and or's reason: an unmasked 512-bit and is the same
		// 512 bits at every SEW, which is why the QCG twin emits one `vpandd` regardless. It is
		// emitted at the family's <16 x i32> lane type anyway, for the reasons stated on the xor
		// below.
		//
		// THIS IS THE THIRD OF THE THREE ADJACENT BITWISE VALUES TO BE ROUTED, so a mistake here
		// no longer adds an unrouted bug -- it TAKES a shipped route's operation. `CreateOr`
		// would compute an OR for a guest AND (stealing T1e's) and `CreateXor` an XOR for a
		// guest AND (stealing T1d's); either produces working, structurally perfect,
		// wrong-valued code that no shape check would notice. The focused test gates the emitted
		// opcode directly, counts the other two at zero, and requires both neighbours' routes to
		// still produce their own frames.
		r = lb->CreateAnd(a, b);
		break;
	case TChunkAluOp::Xor:
		// T1d. The first BITWISE member to reach this backend, and the lane width is
		// architecturally irrelevant to it: an unmasked 512-bit xor is the same 512 bits at
		// every SEW, which is why the QCG twin emits one `vpxord` regardless. It is emitted
		// here at the family's <16 x i32> lane type anyway rather than at `<8 x i64>` or the
		// raw V512 type, for two reasons: every member of this function must produce a value of
		// the same type for TChunkDef's bitcast back to V512 to be uniform, and keeping the
		// lane type honest means a future SEW widening changes the admission predicate and this
		// switch together instead of silently reinterpreting lanes.
		//
		// THREE NEAR-IDENTICAL BITWISE OPERATIONS EXIST AND ONLY THIS ONE IS ROUTED. `vor.vv`
		// and `vand.vv` sit at adjacent funct6 values (VF6_VAND 001001, VF6_VOR 001010,
		// VF6_VXOR 001011) and still have no LLVM lowering, so `CreateOr` or `CreateAnd` here
		// would produce working, structurally perfect, wrong-valued code that no shape check
		// would notice. The focused test gates the opcode directly and counts the other two at
		// zero.
		r = lb->CreateXor(a, b);
		break;
	}
	if (r == nullptr) {
		Panic("llvmgen: typed ALU chunk op with an unhandled operation");
	}
	return lb->CreateBitCast(r, MakeType(chunk_ty));
}

void QIRToLLVM::Emit_vchunkadd(qir::InstVChunkAdd *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkAluLower(TChunkAluOp::Add, ins->sew_bytes, ins->i(0), ins->i(1)));
}

void QIRToLLVM::Emit_vwideaddssa(qir::InstRVVWideAddSSA *ins)
{
	TChunkAccount();
	if (!config::aot_use_llvm || !config::rvv_llvm_wide_vadd_ssa || ins->sew_bytes != 4 ||
	    (ins->active_chunks != 1 && ins->active_chunks != 2)) {
		Panic("llvmgen: malformed T7b fair-wide vadd node");
	}
	auto *chunk_ty = llvm::FixedVectorType::get(lb->getInt32Ty(), 16);
	auto chunk = [&](u8 input) { return lb->CreateBitCast(TChunkUse(ins->i(input)), chunk_ty); };
	llvm::Value *a, *b;
	if (ins->active_chunks == 1) {
		a = chunk(0);
		b = chunk(4);
	} else {
		llvm::SmallVector<int, 32> concat;
		for (int lane = 0; lane < 32; ++lane)
			concat.push_back(lane);
		a = lb->CreateShuffleVector(chunk(0), chunk(1), concat, "rvv.wide.vs2");
		b = lb->CreateShuffleVector(chunk(4), chunk(5), concat, "rvv.wide.vs1");
	}
	// This is the single original RVV operation. The joins/splits are representation plumbing;
	// only LLVM's target legalizer may partition this add into host-width arithmetic operations.
	auto *sum = lb->CreateAdd(a, b, "rvv.wide.add");
	if (ins->active_chunks == 1) {
		TChunkDef(ins->o(0), lb->CreateBitCast(sum, MakeType(VType::V512)));
	} else {
		auto *wide_ty = llvm::cast<llvm::FixedVectorType>(sum->getType());
		auto *poison = llvm::PoisonValue::get(wide_ty);
		llvm::SmallVector<int, 16> lo, hi;
		for (int lane = 0; lane < 16; ++lane) {
			lo.push_back(lane);
			hi.push_back(16 + lane);
		}
		TChunkDef(ins->o(0), lb->CreateBitCast(lb->CreateShuffleVector(sum, poison, lo),
						       MakeType(VType::V512)));
		TChunkDef(ins->o(1), lb->CreateBitCast(lb->CreateShuffleVector(sum, poison, hi),
						       MakeType(VType::V512)));
	}
	for (u8 c = ins->active_chunks; c < 4; ++c)
		TChunkDef(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
}

// S3.10a. The first non-add member of the family to reach this backend. Everything that makes it
// correct is shared with the add above; what is specific to it is that its operation does not
// commute, which is handled by the fixed i(0)=vs2 / i(1)=vs1 order the shared QIR core builds.
void QIRToLLVM::Emit_vchunksub(qir::InstVChunkSub *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkAluLower(TChunkAluOp::Sub, ins->sew_bytes, ins->i(0), ins->i(1)));
}

// T1b. The vmul.vv member. Everything that makes it correct is shared with the add and the sub
// above; what is specific to it is stated at TChunkAluOp::Mul in TChunkAluLower -- low-half, not
// widening, and no wrap flag on an operation whose lanes ordinarily overflow.
//
// Multiplication COMMUTES, so unlike the sub a reversed operand pair is unobservable here. That is
// precisely why the order is not restated in this function: it is fixed once for the whole family by
// RvvEmitTypedAluChunkGroupCore (i(0) = the vs2 chunk, i(1) = the vs1 chunk), and a per-opcode copy
// would be a second place for the non-commutative member's rule to drift.
void QIRToLLVM::Emit_vchunkmul(qir::InstVChunkMul *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkAluLower(TChunkAluOp::Mul, ins->sew_bytes, ins->i(0), ins->i(1)));
}

// T1d. The vxor.vv member, and the first bitwise one. Everything that makes it correct is shared
// with the three members above; what is specific to it is stated at TChunkAluOp::Xor in
// TChunkAluLower -- lane-width-irrelevant semantics, and two unrouted funct6 neighbours whose
// operations a wrong `Create*` here would silently substitute.
//
// XOR COMMUTES, so unlike the sub a reversed operand pair is unobservable. That is precisely why the
// order is not restated in this function: it is fixed once for the whole family by
// RvvEmitTypedAluChunkGroupCore (i(0) = the vs2 chunk, i(1) = the vs1 chunk), and a per-opcode copy
// would be a second place for the non-commutative member's rule to drift.
void QIRToLLVM::Emit_vchunkxor(qir::InstVChunkXor *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkAluLower(TChunkAluOp::Xor, ins->sew_bytes, ins->i(0), ins->i(1)));
}

// T1e. The vor.vv member. Everything that makes it correct is shared with the four members above;
// what is specific to it is stated at TChunkAluOp::Or in TChunkAluLower -- lane-width-irrelevant
// semantics, one ACCEPTED neighbour whose operation a wrong `Create*` would steal, and one unrouted
// neighbour below it.
//
// OR COMMUTES, so operand order is unobservable and is not restated here; it is fixed once for the
// whole family by RvvEmitTypedAluChunkGroupCore (i(0) = the vs2 chunk, i(1) = the vs1 chunk).
void QIRToLLVM::Emit_vchunkor(qir::InstVChunkOr *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkAluLower(TChunkAluOp::Or, ins->sew_bytes, ins->i(0), ins->i(1)));
}

// T1f. The vand.vv member, and the last op of the typed integer element-wise family to reach this
// backend. Everything that makes it correct is shared with the five members above; what is specific
// to it is stated at TChunkAluOp::And in TChunkAluLower -- lane-width-irrelevant semantics, and TWO
// accepted neighbour routes whose operations a wrong `Create*` here would steal.
//
// AND COMMUTES, so operand order is unobservable and is not restated here; it is fixed once for the
// whole family by RvvEmitTypedAluChunkGroupCore (i(0) = the vs2 chunk, i(1) = the vs1 chunk).
void QIRToLLVM::Emit_vchunkand(qir::InstVChunkAnd *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkAluLower(TChunkAluOp::And, ins->sew_bytes, ins->i(0), ins->i(1)));
}

// Native-3. THE SCALAR OPERAND OF AN RVV `.vx` INSTRUCTION, and the first typed chunk op in this
// backend that is neither a lane operation nor a 512-bit memory access.
//
//   scalar = load i32 CPUState[offs], !alias.scope state       ; the guest GPR named by rs1
//   splat  = shufflevector (insertelement poison, scalar, 0), poison, zeroinitializer
//   chunk  = bitcast <16 x i32> splat to <8 x i64>
//
// `CreateVectorSplat` is the IRBuilder spelling of those two instructions and is used rather than a
// hand-built pair so the shape cannot drift from what LLVM's own folders expect.
//
// THE SCALAR COMES FROM CPUState AND THAT IS EXACT, NOT AN APPROXIMATION -- the same fact
// Emit_vchunkload rests on. On this backend every guest global IS a CPUState address
// (CreateVGPRLocs maps each one to MakeStateEP(info->state_offs)), so reading rs1 at its
// translation-time constant offset reads the identical location LoadVOperand would. RvvStateLoad
// additionally puts it in the state alias scope, which is where every other RVV state read lives.
// (The QCG emitter reads the same slot for a different reason: QRegAlloc::CallOp has just spilled
// every global there because `rvvtypedchunkbegin` carries HAS_CALLS. Same address, two independent
// justifications -- and for rs1 == x0 the same answer, because that slot is never written.)
//
// NO SIGN OR ZERO EXTENSION, AND THAT IS SEMANTIC. rv32_vector_lower.h computes the `.vx` operand as
// `(u64)(i64)(i32)rs1_val` and then masks it to SEW bits; at SEW=32 on RV32 the mask returns the
// original 32-bit word, so the correct lowering is the raw i32 and any extension here would be
// either a no-op or a bug at some other width. The width is pinned to 4 below rather than assumed.
//
// SEW=4 ONLY, deliberately, and for the reason TChunkAluLower states for its own single width: this
// is the whole set RvvVxMulAccShapeAdmit admits, so any other value arriving here is a routing
// change made without extending this lowering, and substituting a different lane count would be a
// silent miscompile rather than a visible failure.
void QIRToLLVM::Emit_vchunkbroadcast(qir::InstVChunkBroadcast *ins)
{
	TChunkAccount();
	if (ins->is_imm) {
		Panic("llvmgen: immediate vchunkbroadcast is QCG-only (A6 route refuses --aot-use-llvm)");
	}
	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h.
	// Fail closed, exactly as QEmit does: reading past the end of CPUState is out of bounds.
	if ((size_t)ins->offs + qir::InstVChunkBroadcast::SCALAR_BYTES > sizeof(CPUState)) {
		Panic("llvmgen: vchunkbroadcast scalar lies outside CPUState");
	}
	if (ins->sew_bytes != 4) {
		Panic("llvmgen: vchunkbroadcast with an unsupported SEW");
	}
	// W5: the lane count is the chunk's own, as in TChunkAluLower. SEW stays 4 (the row above).
	VType const chunk_ty = ins->o(0).GetType();
	if (!IsVectorVType(chunk_ty) || VTypeToSize(chunk_ty) % ins->sew_bytes != 0)
		Panic("llvmgen: vchunkbroadcast chunk is not a whole number of elements of this SEW");
	auto *scalar = RvvStateLoad(VType::I32, ins->offs, llvm::Align(4));
	auto *splat = lb->CreateVectorSplat(VTypeToSize(chunk_ty) / ins->sew_bytes, scalar);
	TChunkDef(ins->o(0), lb->CreateBitCast(splat, MakeType(chunk_ty)));
}

// F2 (2026-09-16). THE `.vf` SCALAR OPERAND OF A TYPED FP FRAME: one F register, read once for the
// whole frame and splatted into a chunk value.
//
// WHY IT IS FRAME-SCOPE AND NOT PER MEMBER OR PER CHUNK. The splat is chunk-independent -- every
// lane of every chunk gets the same doubleword -- and no member of a run can write an F register
// (rv32_vrun.h states that argument), so the run former emits exactly one of these per DISTINCT
// live-in F register, before any lane op. This function therefore has no chunk index and needs
// none.
//
// NaN-BOXING AT SEW=32, AND IT IS SEMANTIC RATHER THAN DEFENSIVE. RV32D stores an f32 in a 64-bit F
// register NaN-boxed: the upper 32 bits are all ones. A value whose upper half is anything else is
// NOT a valid binary32 and the architecture requires it to read as the CANONICAL quiet NaN, not as
// its own low half. So:
//
//   raw64 = load i64 CPUState[fpu.f[rs1]]
//   hi    = trunc (lshr raw64, 32)                       ; the box
//   lo    = trunc raw64
//   lane  = bitcast (select (hi == 0xffffffff), lo, 0x7fc00000) to float
//
// At SEW=64 there is no box: the whole doubleword IS the operand and is bitcast straight to double.
// This is the same rule three other places in this tree implement -- QEmit::Emit_vchunkfbroadcast's
// `cmp eax, -1 ; je boxed` arm (the AsmJit twin of this node), QIRToLLVM::Emit_rvvsplatf (the
// P-vector-SSA family's splat), and the `rv32_vfalu` helper this frame falls back to -- and getting
// it wrong here would make the fast arm and the fallback arm disagree on an unboxed operand.
//
// THE TWO WIDTHS THE FRAME CAN ASK FOR, AND THE ONE IT CANNOT. `sew_bytes == 0` is the
// two-vtype frame, whose element width QEmit resolves at RUN TIME with a `cmp vtype, 0xd9` branch.
// An LLVM lane type is a translation-time `<N x float|double>`; there is no arm to select, which is
// why RvvLLVMFaluChunkAdmit refuses an unobserved vtype and why this fails closed rather than
// guessing.
void QIRToLLVM::Emit_vchunkfbroadcast(qir::InstVChunkFBroadcast *ins)
{
	TChunkAccount();
	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h.
	// Fail closed, exactly as QEmit does: reading past the end of CPUState is out of bounds.
	if ((size_t)ins->offs + sizeof(u64) > sizeof(CPUState))
		Panic("llvmgen: vchunkfbroadcast scalar lies outside CPUState");
	if (ins->sew_bytes != 4 && ins->sew_bytes != 8)
		Panic("llvmgen: vchunkfbroadcast with an unsupported SEW");
	// W5: the splat's lane count follows the chunk width; the NaN-boxing rule above is a property
	// of the F register and does not depend on it.
	VType const chunk_ty = ins->o(0).GetType();
	if (!IsVectorVType(chunk_ty) || VTypeToSize(chunk_ty) % ins->sew_bytes != 0)
		Panic("llvmgen: vchunkfbroadcast chunk is not a whole number of elements of this SEW");
	auto *raw64 = RvvStateLoad(VType::MASK64, ins->offs, llvm::Align(8));
	llvm::Value *lane;
	if (ins->sew_bytes == 4) {
		auto *hi = lb->CreateTrunc(lb->CreateLShr(raw64, lb->getInt64(32)), lb->getInt32Ty());
		auto *lo = lb->CreateTrunc(raw64, lb->getInt32Ty());
		lo = lb->CreateSelect(lb->CreateICmpEQ(hi, lb->getInt32(~0u)), lo,
				      lb->getInt32(rv32::F32_CANONICAL_NAN));
		lane = lb->CreateBitCast(lo, lb->getFloatTy());
	} else {
		lane = lb->CreateBitCast(raw64, lb->getDoubleTy());
	}
	auto *splat = lb->CreateVectorSplat(VTypeToSize(chunk_ty) / ins->sew_bytes, lane);
	TChunkDef(ins->o(0), lb->CreateBitCast(splat, MakeType(chunk_ty)));
}

// F1: forward declaration only. The DEFINITION, and the argument for each of its four rows, stays
// with the P-vector-SSA family's Emit_rvvfalu below -- one map, two callers, so the typed frame and
// the per-instruction route can never lower the same funct6 to different arithmetic.
static llvm::Intrinsic::ID RvvFaluConstrainedIntrinsic(u8 funct6);

// F1 (2026-09-16). THE TYPED FP FRAME'S LANE OPERATION ON THIS BACKEND.
//
// It is the FP counterpart of Emit_vchunkadd and its five integer siblings, and it is the same
// shape: one operation over the frame's chunk SSA values, no memory access, no control flow. The
// arithmetic itself is NOT new here -- it is the identical constrained intrinsic, with the identical
// metadata, that `Emit_rvvfalu` (the P-vector-SSA family) has emitted since S3.x, taken from the
// SAME `RvvFaluConstrainedIntrinsic` map so the two families cannot compute different things for
// the same funct6. What IS new is the frame it sits in: one guard and one FP bracket for the whole
// admitted sequence instead of one per guest instruction.
//
// THE FIVE REFUSALS BELOW ARE THE BODY'S PRECONDITIONS, and each is discharged by admission
// upstream. They are restated here because this function has no mask, no tail fill and no merge
// seed, so if any of them were false the emitted code would be silently wrong rather than absent:
//
//   masked (vm == 0)      -- would need v0 folded into a lane mask. RvvLLVMFaluChunkAdmit refuses.
//   kmask != 0            -- names a `vchunkmaskset` opmask register this backend never emits
//                            (--rvv-qcg-fp-shared-mask is refused for LLVM FP runs in
//                            RvvTranslateVectorRun). A non-zero value would mean the frame planned
//                            masks the body then did not consume.
//   sew_bytes not 4 or 8  -- 0 is the two-vtype frame, whose element width is resolved at RUN TIME
//                            by QEmit's `switch`. An LLVM lane type is translation-time.
//   chunk not whole elems -- W5: the lane count is VTypeToSize(chunk)/SEW, so the chunk must be a
//                            host vector width holding a whole number of elements. It no longer
//                            has to be 64 bytes: 16/32-byte chunks are the same lowering.
//   !tchunk_full_vl       -- THE LOAD-BEARING ONE. Every element of the chunk is computed and every
//                            byte of it is stored, so "the whole chunk is active body elements"
//                            must already be proved. `tchunk_full_vl` is
//                            InstRVVTypedChunkBegin::GuardProvesFullVl of the frame's own guard
//                            kind -- the same predicate the translator consults -- and it is NOT
//                            multiplied by config::rvv_qcg_full_vl_fast_body the way QEmit's
//                            `rvv_typed_chunk_full_vl` is. That flag selects between two QCG
//                            bodies, one of which is masked; this backend has only the unmasked
//                            one, so for it the guard's proof is the requirement, not an
//                            optimisation opportunity.
//
// NaN CANONICALISATION IS NOT OPTIONAL AND IS NOT THE INTRINSIC'S JOB. RISC-V requires an
// arithmetic result that IS a NaN to be the canonical quiet NaN; x86 quiets the incoming NaN and
// keeps its payload (rv32_fpu.h). The helper arm this frame falls back to canonicalises, so the
// fast arm must too, or the two arms would return different bits for the same inputs.
//
// OPERAND ORDER IS SEMANTIC. `i(0)` is the vs2 chunk and `i(1)` the vs1 chunk, fixed for the whole
// family by RvvEmitTypedFpChunkBody, and `vfsub.vv vd, vs2, vs1` is `vs2 - vs1`. Commutative
// members would not reveal a swap; the focused test drives vfsub specifically.
void QIRToLLVM::Emit_vchunkfalu(qir::InstVChunkFALU *ins)
{
	TChunkAccount();
	// ORDER ITEM 3 (2026-09-19): FP PREDICATION. The masked form is lowered when the route's switch
	// admitted it, and still refused otherwise -- `RvvLLVMFaluChunkAdmit` is the only producer that
	// can set this flag on the LLVM arm, so with the switch off this Panic is exactly the refusal
	// it was. The lowering is NOT "a masked store": see the neutralisation below.
	// C7-FWMASK: the widening group emits this node at the WIDE sew inside its own frame, so
	// its switch satisfies the same gate. The masked lowering below is unchanged and shared.
	if (ins->masked && !config::rvv_llvm_fp_masked && !config::rvv_llvm_fwiden_masked)
		Panic("llvmgen: masked vchunkfalu has no lowering in this backend");
	if (ins->kmask)
		Panic("llvmgen: vchunkfalu names a shared opmask this backend never emits");
	if (ins->sew_bytes != 4 && ins->sew_bytes != 8)
		Panic("llvmgen: vchunkfalu with an unsupported SEW");
	// C5-FP: a frame that does not prove full VL is admitted ONLY when the operands of inactive
	// lanes are neutralised, because the FP bracket makes an inactive lane's exception visible in
	// the guest fcsr. Without the switch this is still the hard refusal it was.
	// ORDER ITEM 3: `|| ins->masked` is not a loosening of this refusal, it is the refusal saying
	// what it always meant. The message reads "unmasked", and the condition did not test it: a
	// MASKED frame takes the partial guard kind by construction (a masked body must neutralise), so
	// without this term a masked frame Panicked whenever `--rvv-llvm-fp-partial-vl` happened to be
	// off -- which is exactly the configuration the FP-mask route is meant to work in on its own.
	// What the refusal protects is unchanged: a body that neither proves full VL nor neutralises.
	// C7-FWPVL: the widening group emits this node at the WIDE sew inside its own frame.
	if (!tchunk_full_vl && !config::rvv_llvm_fp_partial_vl &&
	    !config::rvv_llvm_fwiden_partial_vl && !config::rvv_llvm_fwiden_masked &&
	    !ins->masked)
		Panic("llvmgen: unmasked vchunkfalu in a frame whose guard does not prove full VL");
	// W5: the chunk's own width, one expression for all three host widths, exactly as
	// TChunkAluLower has done for the integer family since P4. What must still hold is that the
	// chunk is a HOST vector width and a whole number of elements of this SEW -- a 16-byte chunk at
	// e64 is two doubles, a 16-byte chunk at a SEW that did not divide it would be neither.
	VType const chunk_ty = ins->o(0).GetType();
	if (!IsVectorVType(chunk_ty) || VTypeToSize(chunk_ty) % ins->sew_bytes != 0)
		Panic("llvmgen: vchunkfalu chunk is not a whole number of elements of this SEW");
	if (ins->i(0).GetType() != chunk_ty || ins->i(1).GetType() != chunk_ty)
		Panic("llvmgen: vchunkfalu operands disagree on width");
	auto *fty = llvm::FixedVectorType::get(ins->sew_bytes == 4 ? lb->getFloatTy()
							          : lb->getDoubleTy(),
					       VTypeToSize(chunk_ty) / ins->sew_bytes);
	llvm::Value *a = lb->CreateBitCast(TChunkUse(ins->i(0)), fty);
	llvm::Value *b = lb->CreateBitCast(TChunkUse(ins->i(1)), fty);
	// `|| ins->masked` IS FAIL-CLOSED, NOT LOAD-BEARING TODAY, and it is labelled so rather than
	// left to be discovered: a mutation that deletes it survives the focused test. The reason is
	// the guard-kind coupling at the translator -- `RvvEmitTypedFaluChunkGroup` selects
	// `VTypePartialVlVstartFrmRNE` for EVERY masked frame, so `tchunk_full_vl` is already false
	// whenever `ins->masked` is true. That coupling is itself load-bearing and IS tested ([F1]
	// asserts the kind, and a mutation that gives a masked frame the full-VL kind fails 60 cells).
	// This term exists so that a future producer pairing a masked node with a full-VL frame gets a
	// neutralised body rather than a silent guest `fcsr` flag for an element it must not touch.
	if (!tchunk_full_vl || ins->masked) {
		// C5-FP: inactive lanes compute (+1.0) op (+1.0), which raises nothing for every
		// operation this route lowers -- including fdiv, where +0.0 would raise NV.
		//
		// ORDER ITEM 3: "INACTIVE" IS NOW THE WHOLE PREDICATE. `RvvActiveLaneMask(..., masked)`
		// returns `(e < vl) && v0[e]`, so a masked-off element is neutralised for exactly the
		// same reason a tail element is -- computing it would raise a flag the FP bracket folds
		// into the guest `fcsr` for an element the instruction must not touch. The two
		// suppression reasons are UNIONed here (neutralise if either applies), which is the
		// mirror image of the float-source conversions' asymmetric composition: there the
		// result is saturated and the flag raised only for `invalid AND active`, here there is
		// no derived flag and both reasons suppress.
		//
		// THE SAME MASK VALUE reaches the destination store, because that store's predicate is
		// built by the same `RvvArchMaskForUnit` from the same element base. If the two were
		// derived separately and disagreed, an element could be suppressed in one and computed
		// in the other -- silently, since the store would still look correct.
		u32 const lanes = VTypeToSize(chunk_ty) / ins->sew_bytes;
		auto *mask = RvvActiveLaneMask(lanes, (u32)ins->chunk * lanes, ins->masked);
		a = RvvNeutralizeInactiveFP(a, mask, fty);
		b = RvvNeutralizeInactiveFP(b, mask, fty);
	}
	auto *r = RvvConstrainedFPCall(RvvFaluConstrainedIntrinsic(ins->funct6), fty, {a, b});
	TChunkDef(ins->o(0), RvvCanonicalize(lb->CreateBitCast(r, MakeType(chunk_ty)),
					     ins->sew_bytes, chunk_ty));
}
// P7L-B1: the dependency probe is emitted only inside a QCG vector-run frame, and
// RvvTranslateVectorRun refuses every run while config::aot_use_llvm is set, so this is
// unreachable by construction rather than merely unimplemented.
void QIRToLLVM::Emit_vchunkdep(qir::InstVChunkDep *) { Panic("QCG-only dep probe reached LLVM"); }
// A3: the partial-vl arm is emitted only by the pure-QCG translator (config::rvv_qcg_partial_vl
// requires !aot_use_llvm at the one site that creates these nodes), so these are unreachable.
void QIRToLLVM::Emit_vchunkmaskset(qir::InstVChunkMaskSet *) { Panic("QCG-only partial-vl op reached LLVM"); }
// S1-1/S1-3: the active-VL bound is a QCG frame's internal control flow (an asmjit label bound by
// Emit_rvvqcgfpend or, for an integer frame, Emit_rvvtypedchunkend). Nothing in this backend has
// such a frame, and both routes that create the node -- RvvEmitTypedFaluChunkGroup/
// RvvEmitTypedFmaChunkGroup and RvvTryIntegerFamily -- return false outright when
// `config::aot_use_llvm` is set, so this is unreachable by construction rather than merely
// unimplemented.
void QIRToLLVM::Emit_vchunkactive(qir::InstVChunkActive *) { Panic("QCG-only active-vl bound reached LLVM"); }
// ===============================================================================================
// W31 (2026-09-21): THE EIGHT INTEGER COMPARE KINDS OF `InstVChunkPartialAlu`, ON THE LLVM ARM.
//
// THIS EMITTER IMPLEMENTS EIGHT OF FIFTY-TWO KINDS AND STILL PANICS ON THE OTHER FORTY-FOUR, which
// is the fail-closed proof that `RvvTryLLVMIntCompare` is the only producer that can reach this
// backend. The five other producers of this node in rv32_qir.cpp are all inside pure-QCG routes
// (`RvvTryIntegerFamily` and its neighbours refuse every `aot_use_llvm` compile), so the reachable
// surface grows by exactly the compare family and by nothing else. Before W31 every kind Panicked,
// so this change can only REMOVE aborts.
//
// WHAT ONE NODE IS. One chunk of a compare: read `lanes = chunk_bytes / sew` source elements,
// compare them against source 1 at SEW, and commit `lanes` MASK BITS at element index
// `element_base`. Source 1 is another chunk window (`.vv`), a splat of a GPR word (`.vx`) or a
// splat of the node's immediate (`.vi`).
//
// THE BIT ORDER IS THE GUEST'S, and it is the one place this could be wrong invisibly. A
// `bitcast <N x i1> to iN` puts vector element 0 in the LEAST significant bit on a little-endian
// target, and the guest's `mask_get(vd, e)` reads bit `e % 8` of byte `e / 8`. The two agree --
// the same argument `Emit_vmasklogic` makes for its `<64 x i1>`.
//
// THE DESTINATION IS A BLEND, NEVER A STORE. `rvv_ref::vicmp` iterates `[vstart, vl)` and
// `continue`s on an inactive element, so bits before `vstart`, at or beyond `vl`, and at masked-off
// elements must come out of the RMW unchanged. Storing the computed word instead would clobber a
// live mask above `vl` -- and, when `vd == v0`, would clobber the mask bits this instruction's own
// LATER chunks still have to read. That second case is why the v0 load below happens before the
// store and why both are ordinary `AScopeState` accesses: every state access shares one alias
// scope, so LLVM may not reorder a load past a store it cannot prove disjoint.
//
// THE MASK ALGEBRA IS SCALAR i64, DELIBERATELY. `[vstart, vl)` could be built as `<N x i1>` like
// the sibling element routes, but `v0` arrives as packed bits in CPUState and would then need a
// bits-to-`<N x i1>` conversion at a non-byte-aligned bit offset. Doing the whole thing in i64 --
// which is what `QEmit::EmitRvvBodyMask` plus the compare tail of `QEmit::Emit_vchunkpartialalu`
// do -- keeps the two backends' mask expression literally the same formula.
//
// THE `.vx` SPLAT IS NOT THE RAW GPR WORD. `vialu_rhs` sign-extends x[rs1] from XLEN to 64 and then
// truncates to SEW, so the lowering is `sext i32 -> i64` then trunc to iSEW -- which for SEW <= 4
// is a plain truncation of the word and for SEW == 8 is a sign extension. QEmit emits exactly this
// (`movsxd rax, dword[slot]` then `vpbroadcast{b,w,q}`), and getting it backwards at SEW 8 is a
// silent miscompile on every negative scalar.
void QIRToLLVM::Emit_vchunkpartialalu(qir::InstVChunkPartialAlu *ins)
{
	TChunkAccount();
	using Kind = qir::InstVChunkPartialAlu::Kind;
	using Src1 = qir::InstVChunkPartialAlu::Src1;
	auto const op = (Kind)ins->op;
	if (op < Kind::Eq || op > Kind::GtS)
		Panic("QCG-only partial-vl op reached LLVM");
	if (!ins->architectural_mask)
		Panic("llvmgen: mask result needs architectural write mask");
	u32 const sew = ins->sew_bytes, bytes = ins->chunk_bytes;
	if (sew == 0 || bytes % sew != 0)
		Panic("llvmgen: compare chunk has an impossible shape");
	u32 const lanes = bytes / sew;
	u32 const bit = ins->element_base % 8u;
	// The 64-bit window this chunk's bits live in. `lanes + bit > 64` would drop the high lanes
	// on the shift below; the admission proves it cannot happen, and this is the proof's other
	// half rather than a comment about it.
	if (lanes > 64u || lanes + bit > 64u)
		Panic("llvmgen: compare chunk does not fit one mask word");
	u32 const dst_off = ins->rd_offs + ins->element_base / 8u;
	if ((size_t)dst_off + sizeof(u64) > sizeof(CPUState) ||
	    (size_t)ins->rs2_offs + bytes > sizeof(CPUState))
		Panic("llvmgen: compare window lies outside CPUState");
	if ((Src1)ins->src1_kind == Src1::Vector &&
	    (size_t)ins->rs1_offs + bytes > sizeof(CPUState))
		Panic("llvmgen: compare source window lies outside CPUState");
	if ((Src1)ins->src1_kind == Src1::GprWord &&
	    (size_t)ins->rs1_offs + 4u > sizeof(CPUState))
		Panic("llvmgen: compare GPR word lies outside CPUState");
	if ((Src1)ins->src1_kind == Src1::FprBoxed)
		Panic("llvmgen: compare has no floating source kind");

	auto *i64ty = lb->getInt64Ty();
	auto *lane_ty = llvm::IntegerType::get(lctx, 8u * sew);
	auto *vec_ty = llvm::FixedVectorType::get(lane_ty, lanes);
	auto chunk_at = [&](u32 offs) {
		return AScopeState(lb->CreateAlignedLoad(
		    vec_ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vec_ty), offs),
		    llvm::commonAlignment(llvm::Align(bytes), offs)));
	};
	auto word_at = [&](u32 offs) {
		return AScopeState(lb->CreateAlignedLoad(
		    i64ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), offs),
		    llvm::commonAlignment(llvm::Align(8), offs)));
	};

	// BOTH SOURCES BEFORE ANY DESTINATION BIT IS WRITTEN. `vd == vs2` is legal (the mask
	// destination may coincide with a source group's base) and the mask bits of this chunk land
	// inside that source window at small element indices, so the order is load-bearing.
	llvm::Value *a = chunk_at(ins->rs2_offs);
	llvm::Value *b;
	if ((Src1)ins->src1_kind == Src1::Vector) {
		b = chunk_at(ins->rs1_offs);
	} else {
		llvm::Value *scalar;
		if ((Src1)ins->src1_kind == Src1::GprWord) {
			scalar = AScopeState(lb->CreateAlignedLoad(
			    lb->getInt32Ty(),
			    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
						 ins->rs1_offs),
			    llvm::commonAlignment(llvm::Align(4), ins->rs1_offs)));
		} else {
			scalar = lb->getInt32(ins->imm);
		}
		// sext to 64 then truncate to SEW -- `vialu_rhs`'s "truncate below XLEN, sign-extend
		// above XLEN", in that order, so SEW 8 gets the sign and SEW 1/2/4 get the low bits.
		auto *wide = lb->CreateSExt(scalar, i64ty);
		b = lb->CreateVectorSplat(lanes, lb->CreateTrunc(wide, lane_ty));
	}

	// SIGNEDNESS IS THE PREDICATE. RVV compares at SEW width, and the reference sign-extends
	// from SEW for the signed forms (`vicmp_apply`'s `sx`), which is what an `icmp s*` on
	// `<N x iSEW>` already means -- so there is no separate extension step and no place for the
	// two to disagree. Picking the unsigned predicate for a signed form is a silent miscompile
	// with an identical instruction count, which is why the focused test evaluates both over
	// negative operands rather than reading the opcode name.
	llvm::Value *cmp;
	switch (op) {
	case Kind::Eq:  cmp = lb->CreateICmpEQ(a, b); break;
	case Kind::Ne:  cmp = lb->CreateICmpNE(a, b); break;
	case Kind::LtU: cmp = lb->CreateICmpULT(a, b); break;
	case Kind::LtS: cmp = lb->CreateICmpSLT(a, b); break;
	case Kind::LeU: cmp = lb->CreateICmpULE(a, b); break;
	case Kind::LeS: cmp = lb->CreateICmpSLE(a, b); break;
	case Kind::GtU: cmp = lb->CreateICmpUGT(a, b); break;
	default:        cmp = lb->CreateICmpSGT(a, b); break; // Kind::GtS
	}
	auto *cmp_bits = lb->CreateZExt(
	    lb->CreateBitCast(cmp, llvm::IntegerType::get(lctx, lanes)), i64ty);

	// THE BODY MASK: lane i is element `element_base + i`, active iff it is in `[vstart, vl)` and,
	// when `vm == 0`, iff its v0 bit is set. Built as `<lanes x i1>` over constant indices --
	// which is exactly `EmitRvvBodyMask`'s two `bzhi` prefixes, written as a predicate instead of
	// as arithmetic -- and then taken into the scalar domain where v0 already lives.
	u32 const vo = offsetof(CPUState, vec);
	auto *vl = RvvStateLoad(VType::I32, vo + offsetof(rv32::VectorState, vl), llvm::Align(4));
	auto *vstart =
	    RvvStateLoad(VType::I32, vo + offsetof(rv32::VectorState, vstart), llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 l = 0; l < lanes; ++l)
		idx.push_back(lb->getInt32(ins->element_base + l));
	auto *idxv = llvm::ConstantVector::get(idx);
	auto *in_body = lb->CreateAnd(lb->CreateICmpULT(idxv, lb->CreateVectorSplat(lanes, vl)),
				      lb->CreateICmpUGE(idxv, lb->CreateVectorSplat(lanes, vstart)));
	llvm::Value *m = lb->CreateZExt(
	    lb->CreateBitCast(in_body, llvm::IntegerType::get(lctx, lanes)), i64ty);
	if (ins->masked) {
		// v0's bits for these elements, read BEFORE the destination is touched. The byte
		// index is `element_base / 8` and the residual bit offset is shifted out, which is
		// `EmitRvvBodyMask`'s `shr rax, base % 8` exactly.
		u32 const v0_off = (u32)(vo + offsetof(rv32::VectorState, vreg)) + ins->element_base / 8u;
		if ((size_t)v0_off + sizeof(u64) > sizeof(CPUState))
			Panic("llvmgen: compare mask source lies outside CPUState");
		llvm::Value *v0 = word_at(v0_off);
		if (bit)
			v0 = lb->CreateLShr(v0, lb->getInt64(bit));
		m = lb->CreateAnd(m, v0);
	}

	// THE READ-MODIFY-WRITE. `w` carries the computed bits of the ACTIVE lanes only; every other
	// bit of the word comes from its current value.
	llvm::Value *w = lb->CreateAnd(cmp_bits, m);
	if (bit) {
		w = lb->CreateShl(w, lb->getInt64(bit));
		m = lb->CreateShl(m, lb->getInt64(bit));
	}
	auto *old = word_at(dst_off);
	auto *out = lb->CreateOr(w, lb->CreateAnd(old, lb->CreateNot(m)));
	AScopeState(lb->CreateAlignedStore(
	    out, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), dst_off),
	    llvm::commonAlignment(llvm::Align(8), dst_off)));

	// The frame's single `vstart = 0`, on the last chunk (the LastChunkNode convention).
	if (ins->finish_instruction)
		RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vstart), lb->getInt32(0),
			      llvm::Align(4));
}
// ===============================================================================================
// C6 (2026-09-19): THE MASK LOGICAL OPERATIONS `vmand` / `vmnand` / `vmandn` / `vmxor` / `vmor` /
// `vmnor` / `vmorn` / `vmxnor`, ON THE LLVM ARM.
//
// THE NODE IS THE QCG ARM'S, REUSED, as the integer reduction's was: `InstVMaskLogic` is already
// one 64-bit mask word with the destination, both sources and the word's first bit index, and
// `Emit_vmasklogic` Panicking here was the only missing half.
//
// A MASK REGISTER IS ONE REGISTER WHATEVER THE LMUL, and these instructions are bit-wise over it --
// SEW does not participate at all. So there is no chunk geometry to derive: word `c` of `vd` is a
// function of word `c` of `vs2` and `vs1`, and the only element-indexed quantity is which BITS of
// that word the instruction is allowed to change.
//
// BITS AT OR BEYOND `vl` ARE UNDISTURBED. The reference writes only `[vstart, vl)` and leaves the
// rest of `vd` as it found it, so the destination word is a blend and not a store of the computed
// value. Storing the whole word would be the obvious shortcut and would clobber a mask a compiler
// is still using above `vl`.
//
// THE ACTIVE-BIT MASK IS BUILT AS `<64 x i1>` AND BITCAST, which is the same idiom the element
// routes use for their store predicates -- and it is correct for the same reason the guest's own
// `mask_get` is: LLVM's bitcast puts vector element 0 in the LEAST significant bit on a
// little-endian target, and the guest reads bit `e % 8` of byte `e / 8`. The two orderings agree,
// which is worth stating because a mask register is the one place they could disagree invisibly.
//
// OPERAND ORDER IS `vs2` OP `vs1`, and six of the eight are symmetric so a swap is invisible in
// them; it shows up only in `vmandn` (vs2 AND NOT vs1) and `vmorn`.
void QIRToLLVM::Emit_vmasklogic(qir::InstVMaskLogic *ins)
{
	TChunkAccount();
	if (ins->op > 7)
		Panic("llvmgen: mask logical op outside the eight funct6 values");
	auto *i64ty = lb->getInt64Ty();
	auto word = [&](u32 off) {
		return AScopeState(lb->CreateAlignedLoad(
		    i64ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), off),
		    llvm::Align(8)));
	};
	// BOTH SOURCES BEFORE THE DESTINATION. `vd` may legally alias either, and RVV 1.0 lets it:
	// reading it after the computation would still be correct here, but reading the sources
	// first is the invariant the rest of this backend keeps and it costs nothing.
	auto *x = word(ins->rs2);
	auto *y = word(ins->rs1);
	auto *d = word(ins->rd);
	llvm::Value *r;
	switch (ins->op) { // op is funct6 - VF6_VMANDN, so the order is the encoding's
	case 0: r = lb->CreateAnd(x, lb->CreateNot(y)); break;			     // vmandn
	case 1: r = lb->CreateAnd(x, y); break;					     // vmand
	case 2: r = lb->CreateOr(x, y); break;					     // vmor
	case 3: r = lb->CreateXor(x, y); break;					     // vmxor
	case 4: r = lb->CreateOr(x, lb->CreateNot(y)); break;			     // vmorn
	case 5: r = lb->CreateNot(lb->CreateAnd(x, y)); break;			     // vmnand
	case 6: r = lb->CreateNot(lb->CreateOr(x, y)); break;			     // vmnor
	default: r = lb->CreateNot(lb->CreateXor(x, y)); break;			     // vmxnor
	}
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 i = 0; i < 64; ++i)
		idx.push_back(lb->getInt32(ins->base + i));
	auto *active = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
					 lb->CreateVectorSplat(64, vl));
	auto *m = lb->CreateBitCast(active, i64ty);
	auto *out = lb->CreateOr(lb->CreateAnd(r, m), lb->CreateAnd(d, lb->CreateNot(m)));
	AScopeState(lb->CreateAlignedStore(
	    out, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), ins->rd),
	    llvm::Align(8)));
	if (ins->finish)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
}
// ===============================================================================================
// C6 (2026-09-19): `vcpop.m` AND `vfirst.m` -- A MASK REDUCED TO A SCALAR IN A GPR.
//
// THE ONLY TWO RVV INSTRUCTIONS IN THIS CHECKPOINT WHOSE DESTINATION IS AN INTEGER REGISTER, which
// is the whole reason they share a node: everything about them is the same except the reduction.
// `vcpop` counts the active set bits; `vfirst` returns the index of the lowest active set bit, or
// -1 when there is none.
//
// BOTH READ `[0, vl)`, NOT `[vstart, vl)`. That is the reference's loop and it is deliberate: RVV
// 1.0 requires `vstart == 0` for these (they raise an illegal-instruction exception otherwise), so
// there is no prestart to honour -- the frame's `VTypeIntegerNoRestart` guard sends any other case
// to the helper rather than the body pretending to handle it.
//
// `vfirst` SCANS THE WORDS BACKWARDS. Each word's candidate overwrites the running answer, so the
// LOWEST word that has a set bit is the one left standing -- which is the first element, not the
// last. Scanning forwards and taking the first hit would need a branch; this is branch-free and
// says the same thing. `llvm.cttz` is called with `is_zero_poison = false` and its result is used
// only where the word is non-zero anyway.
//
// `rd == x0` WRITES NOTHING. x0 is hardwired zero, so the store is skipped entirely rather than
// written and discarded.
void QIRToLLVM::Emit_vmaskscalar(qir::InstVMaskScalar *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked vcpop.m / vfirst.m has no lowering in this backend");
	if (ins->vlmax == 0 || ins->vlmax > 4096u)
		Panic("llvmgen: mask scalar reduction with no guarded element count");
	auto *i64ty = lb->getInt64Ty();
	u32 const words = (ins->vlmax + 63u) / 64u;
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	auto active = [&](u32 c) {
		llvm::SmallVector<llvm::Constant *, 64> idx;
		for (u32 i = 0; i < 64; ++i)
			idx.push_back(lb->getInt32(c * 64u + i));
		return lb->CreateBitCast(lb->CreateICmpULT(llvm::ConstantVector::get(idx),
							   lb->CreateVectorSplat(64, vl)),
					 i64ty);
	};
	auto word = [&](u32 c) {
		return AScopeState(lb->CreateAlignedLoad(
		    i64ty,
		    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), ins->source + c * 8u),
		    llvm::Align(8)));
	};
	llvm::Value *out;
	if (!ins->first) {
		auto *fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::ctpop,
								   {i64ty});
		llvm::Value *n = llvm::ConstantInt::get(i64ty, 0);
		for (u32 c = 0; c < words; ++c)
			n = lb->CreateAdd(n, lb->CreateCall(fn, {lb->CreateAnd(word(c), active(c))}));
		out = lb->CreateTrunc(n, lb->getInt32Ty());
	} else {
		auto *fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::cttz,
								   {i64ty});
		llvm::Value *r = lb->getInt32(0xffffffffu); // -1: no active set bit
		for (u32 k = words; k-- > 0;) {
			auto *w = lb->CreateAnd(word(k), active(k));
			auto *tz = lb->CreateCall(fn, {w, lb->getInt1(false)});
			auto *cand = lb->CreateAdd(lb->CreateTrunc(tz, lb->getInt32Ty()),
						   lb->getInt32(k * 64u));
			r = lb->CreateSelect(
			    lb->CreateICmpNE(w, llvm::ConstantInt::get(i64ty, 0)), cand, r);
		}
		out = r;
	}
	if (ins->rd != 0)
		RvvStateStore(VType::I32, (u32)offsetof(CPUState, gpr) + (u32)ins->rd * 4u, out,
			      llvm::Align(4));
}
// ===============================================================================================
// C6 (2026-09-19): `viota.m` -- THE PREFIX SUM OF A MASK.
//
// `vd[e]` IS THE NUMBER OF ACTIVE SET BITS STRICTLY BEFORE `e`. Unlike its three sub-encoding
// siblings `vmsbf`/`vmsif`/`vmsof`, which are comparisons against a single index, this is a running
// count -- and it is the only genuinely CUMULATIVE cross-element computation in this checkpoint.
//
// THE COUNT IS SPLIT INTO A SCALAR PREFIX AND A VECTOR ONE, which is what makes it parallel:
//
//     vd[base + i] = popcount(source bits [0, base))  +  popcount(source bits [base, base + i))
//                    \_____ one scalar per chunk _____/    \____ one vector ctpop per chunk ____/
//
// The first term is a constant for the whole chunk. The second is `ctpop(splat(w) & M)` where `w`
// is the chunk's own `lanes` source bits and `M` is the CONSTANT vector `[(1<<i) - 1]` -- so the
// per-lane prefix falls out of one masked population count with no scan at all.
//
// THE INTERMEDIATE IS ALWAYS i64, NEVER THE ELEMENT TYPE. At SEW 8 a chunk holds 64 lanes and the
// lane-63 mask is `(1<<63) - 1`, which does not fit in an `i8`; computing in the element type would
// silently truncate the MASK rather than the RESULT. The truncation to SEW happens once, at the
// end, which is where the reference's `elem_put` puts it.
//
// NO ACTIVE-LANE MASK ON THE SOURCE, and this is a statement rather than an omission. For any
// element `e` that is actually stored, `e < vl`, and every bit this counts has index below `e` --
// hence also below `vl`. Bits at or beyond `vl` can therefore never enter a stored lane's count.
// Lanes at or beyond `vl` may compute nonsense; the store mask discards them.
//
// A CHUNK NEVER STRADDLES A 64-BIT WORD. `lanes` is `bytes / sew` with `bytes` in {16, 32, 64} and
// `sew` in {1, 2, 4, 8}, so it is a power of two no greater than 64, and `base` is a multiple of
// it. That is what lets `w` be extracted with one shift and one mask.
void QIRToLLVM::Emit_vmaskiota(qir::InstVMaskIota *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked viota.m has no lowering in this backend");
	u32 const sew = ins->sew;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: viota.m with an unsupported SEW");
	if (ins->vlmax == 0 || ins->vlmax > 4096u)
		Panic("llvmgen: viota.m with no guarded element count");
	u32 const regbytes = ins->regbytes;
	u32 const bytes = std::min(64u, regbytes);
	if (bytes % sew != 0)
		Panic("llvmgen: viota.m chunk is not a whole number of elements");
	u32 const lanes = bytes / sew;
	if (lanes == 0 || lanes > 64u || (lanes & (lanes - 1u)) != 0)
		Panic("llvmgen: viota.m chunk lane count is not a power of two in [1, 64]");
	u32 const slot = rv32::VLEN_MAX_BYTES;
	auto *i64ty = lb->getInt64Ty();
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto *wty = llvm::FixedVectorType::get(i64ty, lanes);
	auto *ctpop = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::ctpop,
							      {i64ty});
	auto *ctpopv = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::ctpop,
							       {wty});
	auto sword = [&](u32 c) {
		return AScopeState(lb->CreateAlignedLoad(
		    i64ty,
		    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), ins->source + c * 8u),
		    llvm::Align(8)));
	};
	// The per-lane prefix masks, `(1 << i) - 1`. Lane 0 counts nothing, which is why `viota`'s
	// first element is 0 and not the first mask bit.
	llvm::SmallVector<llvm::Constant *, 64> pm;
	for (u32 i = 0; i < lanes; ++i)
		pm.push_back(llvm::ConstantInt::get(
		    i64ty, i == 64u ? ~0ull : (((u64)1 << i) - 1u)));
	auto *pmask = llvm::ConstantVector::get(pm);

	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	llvm::Value *running = llvm::ConstantInt::get(i64ty, 0);
	u32 last_full_word = ~0u;
	for (u32 base = 0; base < ins->vlmax; base += lanes) {
		u32 const wi = base / 64u, sh = base % 64u;
		// Accumulate whole source words that are now entirely behind `base`. Each is added
		// once: `wi` only advances, and `last_full_word` records how far we have gone.
		for (u32 k = (last_full_word == ~0u) ? 0u : last_full_word + 1u; k < wi; ++k)
			running = lb->CreateAdd(running, lb->CreateCall(ctpop, {sword(k)}));
		if (wi > 0)
			last_full_word = wi - 1u;
		auto *cur = sword(wi);
		// The part of THIS word already behind `base`, plus the chunk's own bits.
		auto *before = lb->CreateAdd(
		    running,
		    lb->CreateCall(ctpop, {lb->CreateAnd(cur, llvm::ConstantInt::get(
							       i64ty, sh == 0 ? 0ull
									      : (((u64)1 << sh) - 1u)))}));
		auto *w = lb->CreateAnd(
		    lb->CreateLShr(cur, llvm::ConstantInt::get(i64ty, sh)),
		    llvm::ConstantInt::get(i64ty, lanes == 64u ? ~0ull : (((u64)1 << lanes) - 1u)));
		auto *counts = lb->CreateAdd(
		    lb->CreateCall(ctpopv, {lb->CreateAnd(lb->CreateVectorSplat(lanes, w), pmask)}),
		    lb->CreateVectorSplat(lanes, before));
		llvm::SmallVector<llvm::Constant *, 64> idx;
		for (u32 i = 0; i < lanes; ++i)
			idx.push_back(lb->getInt32(base + i));
		auto *mask = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
					       lb->CreateVectorSplat(lanes, vl));
		u32 const byte = base * sew;
		u32 const off = ins->rd + (byte / regbytes) * slot + byte % regbytes;
		AScopeState(lb->CreateMaskedStore(
		    lb->CreateTrunc(counts, vty),
		    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), off), llvm::Align(16),
		    mask));
	}
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}
// C2b (2026-09-17). THE FOUR SCALAR <-> VECTOR ELEMENT-0 TRANSFERS.
//
//   vmv.s.x   GPR -> vd[0]      vmv.x.s   vs2[0] -> GPR
//   vfmv.s.f  FPR -> vd[0]      vfmv.f.s  vs2[0] -> FPR
//
// A faithful port of QEmit::Emit_vscalarmove; the rules below are RVV 1.0 16.1 as that emitter
// already implements them, not a second reading of the spec.
//
// ACTIVE-ELEMENT RULE, and it is ASYMMETRIC. The to-vector direction writes vd[0] only when
// `vstart < vl`; at `vstart >= vl` (which includes `vl == 0`) the destination is left completely
// unchanged. The from-vector direction reads vs2[0] regardless of vl and vstart -- `vmv.x.s` is
// defined to ignore both, and notably it still reads element 0 when `vl == 0`. BOTH directions
// clear `vstart` on completion, including the to-vector no-op path.
//
// This is why the frame carries GuardKind::VTypeInteger ("exact vtype, vl <= VLMAX, body handles
// vstart") rather than a kind that excludes a nonzero vstart: for this family the body IS the
// architectural rule, so excluding vstart at the guard would send correct executions to the helper
// for no reason.
//
// SIGN EXTENSION AND NaN BOXING, the two places a width mistake is silent:
//   * `vmv.x.s` with SEW < XLEN SIGN-extends the element into the 32-bit GPR (SEW 8 and 16 here);
//     with SEW > XLEN it takes the LOW XLEN bits. So SEW 8/16 load-and-sext, SEW 32/64 load 32.
//   * `vmv.s.x` with SEW > XLEN SIGN-extends the 32-bit GPR into the element. `x0` reads as zero.
//   * `vfmv.f.s` at SEW 32 NaN-BOXES the result into the 64-bit F register (high half all ones).
//   * `vfmv.s.f` at SEW 32 UN-boxes: an F value that is not properly NaN-boxed (high half not all
//     ones) reads as the canonical quiet NaN. Done with INTEGER operations only -- no FP compare and
//     no FP arithmetic, so this raises no exception and needs no rounding mode, exactly as the QCG
//     body does it.
//
// BRANCHLESS, like the other C-series lowerings. The conditional to-vector write is expressed as
// load-select-store of the destination element, so an inactive transfer stores the bytes that were
// already there. Same architectural state as QCG's branch; one redundant store on the inactive path.
//
// STATE BOUNDARY. Reads: `vec.vstart`, `vec.vl` (to-vector only), and either `vreg[vs2]` element 0
// or the scalar register. Writes: either `vreg[vd]` element 0 or the scalar register, plus
// `vec.vstart = 0`. No CSR other than vstart, no guest memory, no fault. `x0` is never written.
void QIRToLLVM::Emit_vscalarmove(qir::InstVScalarMove *ins)
{
	TChunkAccount();
	u32 const vo = offsetof(CPUState, vec);
	u32 const elem =
	    vo + offsetof(rv32::VectorState, vreg) + (u32)ins->vreg * rv32::VLEN_MAX_BYTES;
	u32 const scalar =
	    ins->floating ? (u32)(offsetof(CPUState, fpu) + offsetof(rv32::FPUState, f)) +
				(u32)ins->greg * 8u
			  : (u32)offsetof(CPUState, gpr) + (u32)ins->greg * 4u;
	u32 const vstart_o = vo + offsetof(rv32::VectorState, vstart);
	if (ins->sew != 1 && ins->sew != 2 && ins->sew != 4 && ins->sew != 8) {
		Panic("llvmgen: scalar vector move with an unsupported SEW");
	}
	if (ins->floating && ins->sew < 4) {
		Panic("llvmgen: floating scalar vector move below SEW 32");
	}
	auto *i32ty = lb->getInt32Ty();
	auto *i64ty = lb->getInt64Ty();
	// qir::VType has no 64-bit scalar (it stops at I32), so the SEW-64 element and the 64-bit F
	// register are accessed through MakeStateEP with an explicit LLVM type -- the same way
	// Emit_vfreducenative reaches its f64 lanes. AScopeState keeps the identical aliasing
	// contract RvvStateLoad/RvvStateStore attach, so these are not a second, weaker state path.
	auto load64 = [&](u32 off, unsigned align) {
		return (llvm::Value *)AScopeState(lb->CreateAlignedLoad(
		    i64ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), off),
		    llvm::Align(align)));
	};
	auto store64 = [&](u32 off, llvm::Value *v, unsigned align) {
		AScopeState(lb->CreateAlignedStore(
		    v, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), off),
		    llvm::Align(align)));
	};
	auto narrow_ty = [&](u8 sew) {
		return sew == 1 ? VType::I8 : sew == 2 ? VType::I16 : VType::I32;
	};

	if (ins->to_vector) {
		// Active only while `vstart < vl`; otherwise the destination element is untouched.
		auto *vstart = RvvStateLoad(VType::I32, vstart_o, llvm::Align(4));
		auto *vl = RvvStateLoad(VType::I32, vo + offsetof(rv32::VectorState, vl),
					llvm::Align(4));
		auto *active = lb->CreateICmpULT(vstart, vl);

		llvm::Value *val = nullptr; // width == ins->sew, as an integer
		if (ins->floating) {
			auto *f = load64(scalar, 8);
			if (ins->sew == 4) {
				// NaN-unboxing, integer-only: a high half that is not all ones means
				// the F value is not a valid boxed f32, and reads as canonical qNaN.
				auto *hi = lb->CreateTrunc(lb->CreateLShr(f, lb->getInt64(32)), i32ty);
				auto *boxed = lb->CreateICmpEQ(hi, lb->getInt32(0xffffffffu));
				val = lb->CreateSelect(boxed, lb->CreateTrunc(f, i32ty),
						       lb->getInt32(0x7fc00000u));
			} else {
				val = f;
			}
		} else if (ins->greg == 0) {
			// x0 reads as zero; no GPR load at all.
			val = llvm::ConstantInt::get(ins->sew == 8 ? i64ty : i32ty, 0);
		} else {
			auto *g = RvvStateLoad(VType::I32, scalar, llvm::Align(4));
			// SEW > XLEN sign-extends the 32-bit GPR into the element.
			val = ins->sew == 8 ? lb->CreateSExt(g, i64ty) : (llvm::Value *)g;
		}
		if (ins->sew == 8) {
			auto *old = load64(elem, 16);
			store64(elem, lb->CreateSelect(active, val, old), 16);
		} else {
			VType const ety = narrow_ty(ins->sew);
			auto *narrowed = lb->CreateTrunc(val, MakeType(ety));
			auto *old = RvvStateLoad(ety, elem, llvm::Align(16));
			RvvStateStore(ety, elem, lb->CreateSelect(active, narrowed, old),
				      llvm::Align(16));
		}
	} else if (ins->floating) {
		// vfmv.f.s: read element 0, NaN-box at SEW 32. vl and vstart are not consulted.
		llvm::Value *out;
		if (ins->sew == 4) {
			auto *e = RvvStateLoad(VType::I32, elem, llvm::Align(16));
			out = lb->CreateOr(lb->CreateZExt(e, i64ty),
					   lb->getInt64(0xffffffff00000000ull));
		} else {
			out = load64(elem, 16);
		}
		store64(scalar, out, 8);
	} else if (ins->greg != 0) {
		// vmv.x.s: sign-extend when SEW < XLEN, low 32 bits when SEW >= XLEN. x0 is never
		// written, which is why this arm is skipped entirely for greg == 0.
		llvm::Value *out;
		if (ins->sew == 1)
			out = lb->CreateSExt(RvvStateLoad(VType::I8, elem, llvm::Align(16)), i32ty);
		else if (ins->sew == 2)
			out = lb->CreateSExt(RvvStateLoad(VType::I16, elem, llvm::Align(16)), i32ty);
		else
			out = RvvStateLoad(VType::I32, elem, llvm::Align(16));
		RvvStateStore(VType::I32, scalar, out, llvm::Align(4));
	}
	// Cleared on every path, including the to-vector inactive one.
	RvvStateStore(VType::I32, vstart_o, lb->getInt32(0), llvm::Align(4));
}
// ===============================================================================================
// C6 (2026-09-19): `vcompress.vm` -- PACK THE SELECTED ELEMENTS INTO THE LOW END OF `vd`.
//
// THE WRITE INDEX RUNS BEHIND THE READ INDEX, which is what makes this the one C6 family that is
// not a per-element function of its inputs: element `e` of the source lands at position
// `viota(vs1)[e]` of the destination, a running count. Every other family here could be written as
// "lane i of the output from lane i of the input"; this one cannot.
//
// LLVM HAS THE OPERATION EXACTLY: `llvm.masked.compressstore` stores the selected lanes of a vector
// CONTIGUOUSLY from a pointer, which is the definition of `vcompress`. So the emitter does not
// build a scan at all -- it walks the source in chunks, carrying only the SCALAR count of elements
// already written, and lets one compressstore per chunk place them.
//
// LMUL 1 ONLY, AND THE REASON IS ADDRESSING RATHER THAN SEMANTICS. The destination position is a
// RUNTIME value, so the store address is `vd_base + n * sew`. Inside one register that is a plain
// byte offset; across a register GROUP it is not, because consecutive logical bytes jump by a
// 512-byte slot every `regbytes`. Supporting a group means splitting each compressstore at a
// runtime-determined register boundary, which is a different and much larger lowering. Recorded as
// a limit; LMUL > 1 keeps the unchanged helper.
//
// `vs1` IS THE SELECTOR, NOT A MASK, so `vm` is part of the opcode and there is no masked form to
// refuse. Elements of `vd` at or beyond the compressed count are UNDISTURBED -- compressstore
// writes exactly `popcount(active)` elements and touches nothing after them, which is the
// reference's `[0, n)` exactly.
void QIRToLLVM::Emit_vcompressnative(qir::InstVCompress *ins)
{
	TChunkAccount();
	u32 const sew = ins->sew;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: vcompress with an unsupported SEW");
	if (ins->vlmax == 0 || ins->vlmax > 4096u)
		Panic("llvmgen: vcompress with no guarded element count");
	u32 const regbytes = ins->regbytes;
	u32 const bytes = std::min(64u, regbytes);
	if (bytes % sew != 0)
		Panic("llvmgen: vcompress chunk is not a whole number of elements");
	u32 const lanes = bytes / sew;
	if (lanes == 0 || lanes > 64u || (lanes & (lanes - 1u)) != 0)
		Panic("llvmgen: vcompress chunk lane count is not a power of two in [1, 64]");
	// The route admits LMUL 1 only, so the whole destination lies in one register slot; this is
	// the emitter's own fail-closed restatement of that.
	if ((u32)ins->vlmax * sew > regbytes)
		Panic("llvmgen: vcompress destination spans a register group");
	u32 const base_off = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const slot = rv32::VLEN_MAX_BYTES;
	auto *i64ty = lb->getInt64Ty();
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto *bty = llvm::FixedVectorType::get(lb->getInt1Ty(), lanes);
	auto *ctpop = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::ctpop,
							      {i64ty});
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	u32 const dst = base_off + (u32)ins->rd * slot;
	llvm::Value *n = lb->getInt32(0); // elements written so far
	for (u32 first = 0; first < ins->vlmax; first += lanes) {
		// The selector's bits for this chunk, out of its own 64-bit word. `first` is a
		// multiple of `lanes`, a power of two no greater than 64, so the range never
		// straddles a word.
		u32 const wi = first / 64u, sh = first % 64u;
		auto *sw = AScopeState(lb->CreateAlignedLoad(
		    i64ty,
		    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty),
					 base_off + (u32)ins->mask * slot + wi * 8u),
		    llvm::Align(8)));
		auto *selbits = lb->CreateTrunc(
		    lb->CreateLShr(sw, llvm::ConstantInt::get(i64ty, sh)),
		    llvm::IntegerType::get(lctx, lanes));
		auto *sel = lb->CreateBitCast(selbits, bty);
		llvm::SmallVector<llvm::Constant *, 64> idx;
		for (u32 i = 0; i < lanes; ++i)
			idx.push_back(lb->getInt32(first + i));
		auto *active = lb->CreateAnd(
		    sel, lb->CreateICmpULT(llvm::ConstantVector::get(idx),
					   lb->CreateVectorSplat(lanes, vl)));
		auto *data = AScopeState(lb->CreateAlignedLoad(
		    vty,
		    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty),
					 base_off + (u32)ins->data * slot + first * sew),
		    llvm::Align(16)));
		// `dst + n * sew`, byte-addressed: the destination position is a runtime value.
		auto *p = lb->CreateInBoundsGEP(
		    lb->getInt8Ty(), lb->CreateConstInBoundsGEP1_32(lb->getInt8Ty(), statev, dst),
		    lb->CreateMul(n, lb->getInt32(sew)));
		AScopeState(lb->CreateMaskedCompressStore(data, p, llvm::MaybeAlign(sew), active));
		n = lb->CreateAdd(
		    n, lb->CreateTrunc(
			   lb->CreateCall(ctpop, {lb->CreateZExt(
						     lb->CreateBitCast(
							 active,
							 llvm::IntegerType::get(lctx, lanes)),
						     i64ty)}),
			   lb->getInt32Ty()));
	}
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}
// ===============================================================================================
// C6 (2026-09-19): THE INTEGER REDUCTIONS `vredsum` / `vredand` / `vredor` / `vredxor` /
// `vredminu` / `vredmin` / `vredmaxu` / `vredmax`, ON THE LLVM ARM.
//
// THE NODE IS THE QCG ARM'S, REUSED RATHER THAN CLONED. `InstVReduce` already carries exactly the
// geometry this needs -- `rd`, `data`, `seed`, `sew`, the funct6 as `op`, `regbytes`, `vlmax` and
// `masked` -- and `Emit_vreducenative` was the only thing missing on this side. Adding a parallel
// node would have duplicated a shape the two backends agree on.
//
// WHY THIS IS A CHUNK FOLD AND NOT ONE BIG REDUCE. The group can be 512 elements wide at SEW 8 and
// LMUL 8, and it is not contiguous: consecutive elements cross into the next register file slot
// every `regbytes`. Folding chunk by chunk, with the SAME `(data + logical/regbytes) * 512 +
// logical % regbytes` addressing the QCG arm uses, keeps one derivation of where an element lives.
//
// ALL EIGHT OPERATIONS ARE ASSOCIATIVE AND COMMUTATIVE, INCLUDING `vredsum` -- modular addition is
// associative -- so the per-chunk results may be combined in any order. That is what makes the
// chunk fold legal here and NOT legal for `vfredosum`, whose whole point is a specified order; the
// two reductions sit next to each other in this file and the difference is worth stating.
//
// INACTIVE ELEMENTS ARE NEUTRALISED, NOT SKIPPED. A lane at or past `vl` is replaced by the
// operation's identity -- 0 for sum/or/xor, all-ones for and/minu, the signed max for min, the
// signed min for max -- which is the same table the QCG body broadcasts. Neutralising rather than
// masking the reduce is what lets one `llvm.vector.reduce.*` per chunk do the work.
//
// `vl == 0` WRITES NOTHING. RVV 1.0 says the reduction is a no-op then, NOT "write the seed", so
// the destination store is predicated. Storing the seed would be the natural-looking error and is
// wrong for exactly the case a compiler emits when a loop's trip count reaches zero.
//
// MASKED AND WIDENING FORMS KEEP THE HELPER: `op >= 8` is `vwredsumu`/`vwredsum`, whose accumulator
// is 2*SEW, and this route admits neither.
void QIRToLLVM::Emit_vreducenative(qir::InstVReduce *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked integer reduction has no lowering in this backend");
	if (ins->op >= 8)
		Panic("llvmgen: widening integer reduction has no lowering in this backend");
	u32 const sew = ins->sew;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: integer reduction at an unsupported SEW");
	if (ins->vlmax == 0)
		Panic("llvmgen: integer reduction with no guarded element count");
	u32 const regbytes = ins->regbytes;
	u32 const bytes = std::min(64u, regbytes);
	if (bytes % sew != 0)
		Panic("llvmgen: integer reduction chunk is not a whole number of elements");
	u32 const lanes = bytes / sew;
	u32 const base = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const slot = rv32::VLEN_MAX_BYTES;
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);

	// The identity element, per operation. Same table as the QCG body's `neutral`.
	u64 const top = (u64)1 << (sew * 8u - 1u);
	u64 const all = top | (top - 1u);
	u64 const neutral = (ins->op == 1 || ins->op == 4) ? all
			    : ins->op == 5			 ? top - 1u
			    : ins->op == 7			 ? top
							 : 0u;
	llvm::Intrinsic::ID id;
	switch (ins->op) {
	case 0: id = llvm::Intrinsic::vector_reduce_add; break;
	case 1: id = llvm::Intrinsic::vector_reduce_and; break;
	case 2: id = llvm::Intrinsic::vector_reduce_or; break;
	case 3: id = llvm::Intrinsic::vector_reduce_xor; break;
	case 4: id = llvm::Intrinsic::vector_reduce_umin; break;
	case 5: id = llvm::Intrinsic::vector_reduce_smin; break;
	case 6: id = llvm::Intrinsic::vector_reduce_umax; break;
	default: id = llvm::Intrinsic::vector_reduce_smax; break;
	}
	auto combine = [&](llvm::Value *a, llvm::Value *b) -> llvm::Value * {
		switch (ins->op) {
		case 0: return lb->CreateAdd(a, b);
		case 1: return lb->CreateAnd(a, b);
		case 2: return lb->CreateOr(a, b);
		case 3: return lb->CreateXor(a, b);
		case 4: return lb->CreateSelect(lb->CreateICmpULT(b, a), b, a);
		case 5: return lb->CreateSelect(lb->CreateICmpSLT(b, a), b, a);
		case 6: return lb->CreateSelect(lb->CreateICmpUGT(b, a), b, a);
		default: return lb->CreateSelect(lb->CreateICmpSGT(b, a), b, a);
		}
	};

	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	// The seed is element 0 of vs1, at SEW, read once before any combination.
	llvm::Value *acc = lb->CreateAlignedLoad(
	    ety, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ety), base + (u32)ins->seed * slot),
	    llvm::Align(sew));
	for (u32 first = 0; first < ins->vlmax; first += lanes) {
		u32 const logical = first * sew;
		u32 const off = base + ((u32)ins->data + logical / regbytes) * slot +
				logical % regbytes;
		auto *v = AScopeState(lb->CreateAlignedLoad(
		    vty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), off),
		    llvm::Align(16)));
		llvm::SmallVector<llvm::Constant *, 64> idx;
		for (u32 i = 0; i < lanes; ++i)
			idx.push_back(lb->getInt32(first + i));
		auto *active = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
						 lb->CreateVectorSplat(lanes, vl));
		auto *n = llvm::ConstantVector::getSplat(
		    llvm::ElementCount::getFixed(lanes), llvm::ConstantInt::get(ety, neutral));
		auto *fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, id, {vty});
		acc = combine(acc, lb->CreateCall(fn, {lb->CreateSelect(active, v, n)}));
	}
	// vl == 0: vd[0] is UNCHANGED. A one-lane masked store says that directly, instead of
	// reading vd[0] back and selecting -- which would make the no-op case depend on the
	// destination's prior value being loadable.
	auto *sty = llvm::FixedVectorType::get(ety, 1);
	auto *live = lb->CreateICmpNE(vl, lb->getInt32(0));
	AScopeState(lb->CreateMaskedStore(
	    lb->CreateInsertElement(llvm::UndefValue::get(sty), acc, (u64)0),
	    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(sty), base + (u32)ins->rd * slot),
	    llvm::Align(sew),
	    lb->CreateInsertElement(
		llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(1), lb->getInt1(false)),
		live, (u64)0)));
}
// ===============================================================================================
// C6 (2026-09-19): `vid.v` -- WRITE EACH ELEMENT'S OWN INDEX.
//
// THE SIMPLEST CROSS-ELEMENT INSTRUCTION IN THE ISA, and the one that makes the geometry explicit:
// the value written to element `e` IS `e`, so a wrong element base or a wrong lane stride is not a
// subtle numeric error here -- it is directly readable in the destination. That is why the node
// carries `base`: the unit's first architectural element index is the datum, not merely an index
// into it.
//
// Elements at or beyond `vl` are UNDISTURBED, which the masked store expresses.
//
// NOT CROSS-LANE AT ALL despite living in the cross-element chapter: there is no dependency between
// elements and no source register.
void QIRToLLVM::Emit_vchunkindex(qir::InstVChunkIndex *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked vid.v has no lowering in this backend");
	u32 const sew = ins->sew, bytes = ins->bytes;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: vid.v with an unsupported SEW");
	if (bytes % sew != 0)
		Panic("llvmgen: vid.v chunk is not a whole number of elements");
	if ((size_t)ins->rd + bytes > sizeof(CPUState))
		Panic("llvmgen: vid.v window lies outside CPUState");
	u32 const lanes = bytes / sew;
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	// The indices, at SEW. They TRUNCATE at small SEW, and that is the architectural answer: at
	// SEW 8 element 256 holds 0, because the element cannot represent its own index. The
	// reference's `elem_put(..., e)` does exactly the same masking.
	llvm::SmallVector<llvm::Constant *, 64> vals, idx;
	for (u32 i = 0; i < lanes; ++i) {
		vals.push_back(llvm::ConstantInt::get(ety, (u64)(ins->base + i), /*signed=*/false));
		idx.push_back(lb->getInt32(ins->base + i));
	}
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	auto *mask = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
				       lb->CreateVectorSplat(lanes, vl));
	AScopeState(lb->CreateMaskedStore(
	    llvm::ConstantVector::get(vals),
	    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rd), llvm::Align(16),
	    mask));
	if (ins->finish)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
}
// C4 (2026-09-18). `vfclass.v`: ONE UNIT OF THE 10-BIT ONE-HOT CLASSIFICATION.
//
// IT IS AN INTEGER BODY, AND THAT IS THE POINT. This is an OPFVV encoding, but RVV 1.0 13.14
// defines the result purely from the operand's BIT FIELDS -- sign, exponent, significand -- with no
// rounding and no exception (`rv32_frame_semantics.h:231` states the second fact independently). So
// there is no constrained intrinsic here, no MXCSR bracket, and no `frm` term in the frame's guard:
// an RTZ execution and an RNE execution of `vfclass.v` produce identical bits, and sending one of
// them to the helper would be a cost with no semantics behind it.
//
// THE BIT LAYOUT IS THE REFERENCE'S, TRANSCRIBED RATHER THAN REDERIVED. `f32_classify` /
// `f64_classify` (rv32_fpu.h) are the authority and this is the same decision tree in the same
// order, vectorised:
//
//     exp == max && man != 0  -> man's QUIET bit set ? 1<<9 (qNaN) : 1<<8 (sNaN)
//     exp == max              -> sign ? 1<<0 (-inf)       : 1<<7 (+inf)
//     exp == 0   && man == 0  -> sign ? 1<<3 (-0)         : 1<<4 (+0)
//     exp == 0                -> sign ? 1<<2 (-subnormal) : 1<<5 (+subnormal)
//     otherwise               -> sign ? 1<<1 (-normal)    : 1<<6 (+normal)
//
// The nesting order matters: the NaN test must precede the infinity test (both have `exp == max`)
// and the zero test must precede the subnormal test (both have `exp == 0`). Written as nested
// selects in that exact order, so the structure is checkable against the reference line by line.
//
// THE SIGN IS READ AS A SIGNED COMPARE, not a shift-and-mask, because `icmp slt x, 0` is the sign
// bit for both widths with no width-dependent constant -- and it is an INTEGER compare, so unlike
// an `fcmp` it cannot itself raise anything on a signalling NaN operand. That is not a stylistic
// choice: an `fcmp`-based classification of an sNaN would raise NV, which this instruction must not
// do, and it is exactly the mistake this comment exists to prevent.
//
// ONE MASKED STORE, from this unit's own element base against the live `vl` -- so a partial VL
// writes no byte of an inactive lane. There is nothing to neutralise on the operand side the way
// the FP lane families need: classification raises nothing, so computing an inactive lane has no
// architectural effect at all and only its store has to be suppressed.
//
// `vstart` IS THE GUARD'S JOB HERE, NOT THE BODY'S. This body has no prestart term, so its frame
// must carry `GuardKind::VTypeIntegerNoRestart` (`vl <= VLMAX` AND `vstart == 0`) and never
// `VTypeInteger`, whose contract says the body handles vstart and for which this backend's frame
// guard emits no vstart compare at all. See RvvTryLLVMFClass.
void QIRToLLVM::Emit_vchunkfclass(qir::InstVChunkFClass *ins)
{
	TChunkAccount();
	// C5-MASK-FP: the architectural mask is a CONJUNCT of the shared active-lane predicate,
	// not a separate mechanism. It reaches both obligations through that one value -- the
	// destination's masked store and every flag predicate, which are already ANDed with it.
	if (ins->sew != 4 && ins->sew != 8)
		Panic("llvmgen: vfclass with an unsupported SEW");
	if (ins->bytes % ins->sew != 0)
		Panic("llvmgen: vfclass chunk is not a whole number of elements of this SEW");
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (size_t)ins->rs + ins->bytes > sizeof(CPUState))
		Panic("llvmgen: vfclass window lies outside CPUState");
	u32 const lanes = (u32)ins->bytes / ins->sew;
	u32 const bits = 8u * ins->sew;
	u32 const man_bits = ins->sew == 4 ? 23u : 52u;
	u64 const exp_max = ins->sew == 4 ? 0xffull : 0x7ffull;
	u64 const man_mask = ((u64)1 << man_bits) - 1u;
	u64 const quiet_bit = (u64)1 << (man_bits - 1u);

	auto *ety = llvm::IntegerType::get(lctx, bits);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto splat = [&](u64 v) {
		return llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes),
						      llvm::ConstantInt::get(ety, v));
	};
	auto *src = AScopeState(lb->CreateAlignedLoad(
	    vty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rs), llvm::Align(16)));

	auto *neg = lb->CreateICmpSLT(src, splat(0));
	auto *exp = lb->CreateAnd(lb->CreateLShr(src, splat(man_bits)), splat(exp_max));
	auto *man = lb->CreateAnd(src, splat(man_mask));
	auto *exp_is_max = lb->CreateICmpEQ(exp, splat(exp_max));
	auto *exp_is_zero = lb->CreateICmpEQ(exp, splat(0));
	auto *man_is_zero = lb->CreateICmpEQ(man, splat(0));
	auto *is_quiet = lb->CreateICmpNE(lb->CreateAnd(man, splat(quiet_bit)), splat(0));
	auto pick = [&](u32 neg_bit, u32 pos_bit) {
		return lb->CreateSelect(neg, splat(1ull << neg_bit), splat(1ull << pos_bit));
	};
	llvm::Value *res =
	    lb->CreateSelect(lb->CreateAnd(exp_is_max, lb->CreateNot(man_is_zero)),
			     lb->CreateSelect(is_quiet, splat(1ull << 9), splat(1ull << 8)),
	    lb->CreateSelect(exp_is_max, pick(0, 7),
	    lb->CreateSelect(lb->CreateAnd(exp_is_zero, man_is_zero), pick(3, 4),
	    lb->CreateSelect(exp_is_zero, pick(2, 5), pick(1, 6)))));

	// This unit's active-lane predicate. THIS WAS BUILT INLINE, which is why the
	// architectural term had nowhere to go. The shared helper computes the identical
	// `element < vl` comparison when `masked` is false and ANDs `v0` into it when true --
	// and it memoises per (unit, kind, block), which the inline form could not.
	// `vfclass` raises NO flags, so the store predicate is the whole obligation here.
	// (The same inline block still appears in four other emitters; deduplicating those is
	// a separate change and is NOT made here.)
	auto *mask = RvvActiveLaneMask(lanes, ins->base, ins->masked);
	AScopeState(lb->CreateMaskedStore(
	    res, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rd), llvm::Align(16),
	    mask));

	if (ins->finish)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
}
// C4 (2026-09-18). SAME-WIDTH INTEGER -> FLOAT: `vfcvt.f.x.v` and `vfcvt.f.xu.v`.
//
// THE INTRINSIC IS THE CONSTRAINED ONE, AND THAT IS A CORRECTNESS REQUIREMENT ON THIS TARGET, not a
// style rule. Measured on the installed LLVM 20.1.8 (see RvvTryLLVMIntToFloat for the full
// comparison): a plain `uitofp <8 x i64> -> <8 x double>` at `-mattr=+avx512f` lowers to
// `vporq` + `vsubpd` -- the magic-constant trick -- and that closing subtraction of two equal values
// yields `-0.0` under roundTowardNegative, which is exactly the `vfcvt.f.xu.v(0) == -0.0` defect
// `rv32_vector_lower.h` already records against the host path. The constrained form emits
// `vcvtuqq2pd` with AVX512DQ and per-lane `vcvtusi2sd` without it; neither subtracts.
//
// NO CANONICALISATION AND NO SATURATION, because neither can arise. Every integer converts to a
// finite float: the only inexactness is rounding, which raises NX and is exactly what the frame's
// bracket folds into `fcsr`. There is no NaN to canonicalise (unlike every float-SOURCE conversion,
// which is why those are a different route) and no out-of-range case to saturate.
//
// SIGNEDNESS IS THE NODE'S, AND IT SELECTS THE INTRINSIC, not a pre-extension: the source element
// width equals the destination width on this route, so `sitofp`/`uitofp` differ only in how the
// same bits are interpreted.
//
// FULL VL IS REQUIRED. The frame carries `GuardKind::VTypeVlVstartFrmRNE`, so `tchunk_full_vl` is
// true and this body writes the whole chunk unmasked. It refuses otherwise rather than silently
// converting inactive lanes -- those would raise NX into the guest `fcsr` through the bracket,
// which is the same hazard the FP lane families neutralise operands for.
void QIRToLLVM::Emit_vchunkitof(qir::InstVChunkIToF *ins)
{
	TChunkAccount();
	// C5-MASK-FP: the architectural mask is a CONJUNCT of the shared active-lane predicate,
	// not a separate mechanism. It reaches both obligations through that one value -- the
	// destination's masked store and every flag predicate, which are already ANDed with it.
	if (ins->sew != 4 && ins->sew != 8)
		Panic("llvmgen: integer-to-float with an unsupported SEW");
	// C4: `src_sew` may be NARROWER than the destination (`vfwcvt.f.x{,u}.v`: i16 -> f32 and
	// i32 -> f64). It is never wider on this backend -- the narrowing integer-to-float kinds are
	// not admitted -- and `constrained.{si,ui}tofp` takes the two widths as its overload pair, so
	// the only thing the width difference changes is the SOURCE WINDOW's size.
	if (ins->src_sew > ins->sew)
		Panic("llvmgen: narrowing integer-to-float has no lowering in this backend");
	if (ins->src_sew != 2 && ins->src_sew != 4 && ins->src_sew != 8)
		Panic("llvmgen: integer-to-float with an unsupported source width");
	if (ins->bytes % ins->sew != 0)
		Panic("llvmgen: integer-to-float chunk is not a whole number of elements of this SEW");
	// ORDER ITEM 3: a frame that does not prove full VL is admitted ONLY with the partial-VL
	// switch, and then the body owes the tail policy the shared contract requires.
	if (!tchunk_full_vl && !config::rvv_llvm_fcvt_partial_vl)
		Panic("llvmgen: integer-to-float in a frame whose guard does not prove full VL");
	u32 const lanes = (u32)ins->bytes / ins->sew;
	u32 const src_bytes = lanes * ins->src_sew;
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (size_t)ins->rs + src_bytes > sizeof(CPUState))
		Panic("llvmgen: integer-to-float window lies outside CPUState");
	auto *ity = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, 8u * ins->src_sew), lanes);
	auto *fty = llvm::FixedVectorType::get(
	    ins->sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), lanes);
	llvm::Value *src = AScopeState(lb->CreateAlignedLoad(
	    ity, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ity), ins->rs), llvm::Align(16)));
	// PARTIAL VL (order item 3). Two obligations, and the second is the one a masked store alone
	// would miss:
	//   * the DESTINATION is published through an active-lane masked store, so inactive elements
	//     are left UNDISTURBED -- legal under both `vta` and `vtu` (contract piece 3);
	//   * the OPERAND of an inactive lane is neutralised to integer 0 first. This conversion runs
	//     inside the FP bracket, which ORs host MXCSR into the guest `fcsr`, so an inactive lane
	//     whose integer is not exactly representable would raise NX and become architecturally
	//     visible. Integer 0 converts to +0.0 exactly and raises nothing, which is the whole
	//     reason 0 is the right neutral here rather than the +1.0 the FP lane families use.
	llvm::Value *mask = nullptr;
	if (!tchunk_full_vl || ins->masked) {
		mask = RvvActiveLaneMask(lanes, ins->base, ins->masked);
		src = lb->CreateSelect(mask, src, llvm::Constant::getNullValue(ity));
	}
	// BOTH overload types, result first: `.v<N>f<W>.v<N>i<W>`. See RvvConstrainedFPCallN.
	auto *r = RvvConstrainedFPCallN(ins->is_signed
					    ? llvm::Intrinsic::experimental_constrained_sitofp
					    : llvm::Intrinsic::experimental_constrained_uitofp,
					{fty, ity}, {src});
	auto *dst_ep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(fty), ins->rd);
	if (mask)
		AScopeState(lb->CreateMaskedStore(r, dst_ep, llvm::Align(16), mask));
	else
		AScopeState(lb->CreateAlignedStore(r, dst_ep, llvm::Align(16)));
}
// C4 (2026-09-18). ROUND-TOWARD-ZERO FLOAT -> INTEGER, and the order of operations IS the
// semantics. See RvvTryLLVMFloatToInt for the contract, which is `softfp::cvt_to_int_width`.
//
// THE SHAPE IS: classify with integer ops -> neutralise invalid lanes -> convert -> select the
// architectural result -> raise NV explicitly. It is NOT convert-then-select, for two independent
// reasons either of which is sufficient: a `fptosi`/`fptoui` of a NaN or an out-of-range value is
// POISON (selecting it away afterwards does not undo that), and the host conversion instruction
// raises the invalid flag for exactly those lanes into a frame whose bracket ORs host MXCSR into the
// guest `fcsr` -- which would destroy the architectural NV/NX exclusivity.
//
// FLAG DERIVATION, and why it comes out exactly right:
//   * every lane the contract calls invalid is replaced by `+0.0`, which converts exactly to 0 and
//     raises nothing -- so those lanes contribute NO host flag at all;
//   * the surviving lanes are in range by construction, so the hardware conversion raises NX on
//     exactly the ones that are inexact, which is what the contract asks for;
//   * NV is OR-ed into `fcsr` here, once per unit, iff any lane of this unit was invalid.
// Result: NV alone on invalid lanes, NX alone on inexact in-range lanes, nothing on exact ones.
//
// THE CLASSIFICATION USES NO `fcmp`. An `fcmp` against a SIGNALLING NaN raises the host invalid
// flag, and this route is supposed to be deriving that flag itself; a stray host NV would be
// indistinguishable from a derived one. Everything below is integer arithmetic on the bit pattern,
// which raises nothing. For IEEE binary formats the magnitude order agrees with the unsigned integer
// order of the sign-cleared bits, which is what makes the range tests exact.
//
// THE RANGE TESTS, for truncation (`.rtz`), with W the element width in bits:
//   signed   out of range iff  (!neg && |v| >= 2^(W-1)) || (neg && |v| > 2^(W-1))
//            -- `-2^(W-1)` itself IS representable, hence the strict `>` on the negative side;
//   unsigned out of range iff  (neg && |v| >= 1) || (!neg && |v| >= 2^W)
//            -- NOT "negative": a negative value that truncates to magnitude 0, e.g. -0.5, is IN
//               RANGE and yields 0 with NX, which is the contract's `a.sign && ip != 0` rule.
// Infinities and NaNs have sign-cleared bits >= the infinity pattern, which exceeds every bound
// above, so they fall into the out-of-range arm automatically and need no separate test for the
// RESULT; NaN needs one only because its result is `sat_max` regardless of sign.
//
// EVERY BOUNDARY CONSTANT IS DERIVED from the format's exponent bias and significand width, never
// written per width, so a SEW this route later admits cannot pick up a stale literal.
void QIRToLLVM::Emit_vchunkftoi(qir::InstVChunkFToI *ins)
{
	TChunkAccount();
	// C5-MASK-FP: the architectural mask is a CONJUNCT of the shared active-lane predicate,
	// not a separate mechanism. It reaches both obligations through that one value -- the
	// destination's masked store and every flag predicate, which are already ANDed with it.
	if (ins->sew != 4 && ins->sew != 8)
		Panic("llvmgen: float-to-integer with an unsupported destination width");
	if (ins->src_sew != 4 && ins->src_sew != 8)
		Panic("llvmgen: float-to-integer with an unsupported source width");
	if (ins->src_sew > ins->sew)
		Panic("llvmgen: narrowing float-to-integer has no lowering in this backend");
	if (ins->bytes % ins->sew != 0)
		Panic("llvmgen: float-to-integer chunk is not a whole number of elements of this SEW");
	if (!tchunk_full_vl && !config::rvv_llvm_fcvt_partial_vl)
		Panic("llvmgen: float-to-integer in a frame whose guard does not prove full VL");

	// TWO WIDTHS, AND KEEPING THEM APART IS THE WHOLE OF THE WIDENING SUPPORT.
	//
	//   `src_sew` is the SOURCE FLOAT width. Every bit-level constant below -- the significand
	//     width, the exponent bias, the infinity pattern, the sign bit -- belongs to IT, because
	//     the classification and the range tests read the OPERAND's bits.
	//   `sew` is the DESTINATION INTEGER width. `sat_max`/`sat_min` and the range BOUNDS
	//     (`2^(dbits-1)`, `2^dbits`) belong to IT, because the contract's range is the target
	//     type's range.
	//
	// For the same-width forms the two coincide and everything below is what it was. For
	// `vfwcvt.{x,xu,rtz.*}.f.v` they do not: the only admitted pair is f32 -> i64, so the bounds
	// are `2^63`/`2^64` expressed as f32 EXPONENTS (63 and 64 are well inside f32's range, which
	// is why they can be written as exact bit patterns at all).
	u32 const lanes = (u32)ins->bytes / ins->sew;
	u32 const sbits = 8u * ins->src_sew, dbits = 8u * ins->sew;
	u32 const src_bytes = lanes * ins->src_sew;
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (size_t)ins->rs + src_bytes > sizeof(CPUState))
		Panic("llvmgen: float-to-integer window lies outside CPUState");
	u32 const man_bits = ins->src_sew == 4 ? 23u : 52u;
	u32 const exp_bias = ins->src_sew == 4 ? 127u : 1023u;
	auto *ety = llvm::IntegerType::get(lctx, sbits);	  // source bit pattern
	auto *dety = llvm::IntegerType::get(lctx, dbits);	  // destination integer
	auto *ity = llvm::FixedVectorType::get(ety, lanes);
	auto *dity = llvm::FixedVectorType::get(dety, lanes);
	auto *fty = llvm::FixedVectorType::get(
	    ins->src_sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), lanes);
	auto splat = [&](u64 v) {
		return llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes),
						      llvm::ConstantInt::get(ety, v));
	};
	auto dsplat = [&](u64 v) {
		return llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes),
						      llvm::ConstantInt::get(dety, v));
	};
	// The bit pattern of +2^k in the SOURCE format, and that format's infinity pattern.
	auto pow2_bits = [&](u32 k) { return (u64)(exp_bias + k) << man_bits; };
	u64 const inf_bits = (u64)((1ull << (sbits - 1u - man_bits)) - 1u) << man_bits;
	u64 const sign_bit = 1ull << (sbits - 1u);		  // SOURCE sign bit
	u64 const dall = dbits == 64 ? ~0ull : ((1ull << dbits) - 1u);
	u64 const dsign = 1ull << (dbits - 1u);			  // DESTINATION sign bit
	u64 const sat_max = ins->is_signed ? dsign - 1u : dall;
	u64 const sat_min = ins->is_signed ? dsign : 0u;

	auto *srcf = AScopeState(lb->CreateAlignedLoad(
	    fty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(fty), ins->rs), llvm::Align(16)));
	auto *raw = lb->CreateBitCast(srcf, ity);
	auto *absb = lb->CreateAnd(raw, splat(~sign_bit & (sbits == 64 ? ~0ull : ((1ull << sbits) - 1u))));
	auto *neg = lb->CreateICmpNE(lb->CreateAnd(raw, splat(sign_bit)), splat(0));
	auto *is_nan = lb->CreateICmpUGT(absb, splat(inf_bits));
	auto *is_inf = lb->CreateICmpEQ(absb, splat(inf_bits));
	auto *zero_f = llvm::ConstantFP::get(fty, 0.0);

	// THE frm-ROUNDED PAIR ROUNDS FIRST, AND THAT CHANGES WHERE BOTH FLAGS COME FROM.
	//
	// `fptosi`/`fptoui` truncate by definition, so `vfcvt.x.f.v` / `.xu.f.v` need an explicit
	// rounding step. Measured on the installed LLVM 20.1.8:
	//   constrained.nearbyint, round.dynamic -> `vrndscaleps $12` : uses MXCSR.RC AND SUPPRESSES
	//                                                                the precision exception
	//   constrained.rint,      round.dynamic -> `vrndscaleps $4`  : uses MXCSR.RC and RAISES it
	// `nearbyint` is the right one -- `rint` would raise an NX this route must decide for itself --
	// but the consequence is that NOTHING in the sequence raises NX any more: the rounded value is
	// integral, so the following truncating conversion is exact. So on this arm NX is DERIVED and
	// OR-ed into `fcsr` alongside NV, rather than being left to the hardware as it is for `.rtz`.
	//
	// THE OPERAND IS NEUTRALISED BEFORE THE ROUNDING TOO, not just before the conversion: a
	// signalling NaN reaching `vrndscaleps` raises the host invalid flag, which is the same stray
	// flag the integer-only classification exists to avoid.
	//
	// AND THE RANGE TEST THEN APPLIES TO THE ROUNDED VALUE, which is the whole reason the order
	// matters: `2147483647.5` is out of range under RNE and in range under RTZ, and the contract
	// keys off the rounded result.
	// PARTIAL VL, COMPOSED WITH THE INVALID-LANE NEUTRALISATION RATHER THAN ADDED BESIDE IT.
	//
	// Two different reasons to suppress a lane meet here and they must not be conflated:
	//   ARCHITECTURALLY INVALID (NaN, infinity, out of range) -- the contract says the RESULT is a
	//     saturated value and the FLAG is NV;
	//   INACTIVE (element index >= vl) -- the instruction does not touch the element at all: no
	//     result, and NO FLAG of any kind, not even the NV an invalid value would otherwise raise.
	//
	// So the two compose asymmetrically:
	//   NEUTRALISE on `invalid || inactive`  -- both must be kept away from the host operation;
	//   RAISE on `invalid && active`         -- an inactive NaN must NOT produce NV.
	// Writing `invalid` into the flag derivation without the `&& active` is the bug this comment
	// exists to prevent: it is invisible at full VL and wrong at every shorter one.
	llvm::Value *active = nullptr;
	if (!tchunk_full_vl || ins->masked)
		active = RvvActiveLaneMask(lanes, ins->base, ins->masked);
	auto with_inactive = [&](llvm::Value *m) {
		return active ? lb->CreateOr(m, lb->CreateNot(active)) : m;
	};
	auto only_active = [&](llvm::Value *m) {
		return active ? lb->CreateAnd(m, active) : m;
	};

	llvm::Value *rounded = srcf, *rbits = raw, *rneg = neg;
	llvm::Value *inexact = nullptr;
	if (!ins->rtz) {
		// The rounding step sees the inactive lanes too, and `vrndscaleps` raises invalid on a
		// signalling NaN, so they are neutralised here as well -- not only before the convert.
		auto *pre_bad = with_inactive(lb->CreateOr(is_nan, is_inf));
		auto *safe1 = lb->CreateSelect(pre_bad, zero_f, srcf);
		rounded = RvvConstrainedFPCallN(llvm::Intrinsic::experimental_constrained_nearbyint,
						{fty}, {safe1});
		rbits = lb->CreateBitCast(rounded, ity);
		rneg = lb->CreateICmpNE(lb->CreateAnd(rbits, splat(sign_bit)), splat(0));
		// Inexact as a BIT comparison, so it raises nothing. Rounding preserves the sign of a
		// zero, so `-0.5 -> -0.0` differs in bits (inexact, correct) while `-0.0 -> -0.0` does
		// not. The `pre_bad` lanes were replaced by +0.0 above and are excluded below anyway.
		inexact = lb->CreateICmpNE(rbits, raw);
	}
	auto *rabs = lb->CreateAnd(rbits, splat(~sign_bit & (sbits == 64 ? ~0ull : ((1ull << sbits) - 1u))));

	llvm::Value *oor = nullptr;
	if (ins->is_signed) {
		auto *lim = splat(pow2_bits(dbits - 1u));
		oor = lb->CreateSelect(rneg, lb->CreateICmpUGT(rabs, lim),
				       lb->CreateICmpUGE(rabs, lim));
	} else {
		// `neg && magnitude != 0` is the contract's `a.sign && ip != 0`, not "is negative".
		auto *neg_bad = lb->CreateAnd(
		    rneg, lb->CreateICmpUGE(rabs, splat(pow2_bits(0))));
		auto *pos_bad = lb->CreateAnd(
		    lb->CreateNot(rneg), lb->CreateICmpUGE(rabs, splat(pow2_bits(dbits))));
		oor = lb->CreateOr(neg_bad, pos_bad);
	}
	// On the rounded arm the infinities were already replaced by +0.0, so `oor` no longer sees
	// them; they stay invalid through `is_inf`. On the rtz arm `oor` catches them directly because
	// their sign-cleared bits exceed every bound.
	auto *invalid = lb->CreateOr(lb->CreateOr(is_nan, is_inf), oor);

	// NEUTRALISE, then convert. No lane reaching the conversion is NaN or out of range, so the
	// result is never poison. On the `.rtz` arm the only host flag it can raise is NX on a
	// genuinely inexact lane, which is exactly what that arm wants.
	auto *safe = lb->CreateSelect(with_inactive(invalid), zero_f, rounded);
	auto *conv = RvvConstrainedFPCallNoRound(
	    ins->is_signed ? llvm::Intrinsic::experimental_constrained_fptosi
		           : llvm::Intrinsic::experimental_constrained_fptoui,
	    {dity, fty}, {safe});

	// The architectural results. Out of range (and infinity) is sign-directed; NaN is `sat_max` in
	// BOTH directions, which is why it is selected last and unconditionally.
	// The ORIGINAL sign, not the rounded one: on the frm arm the infinities were replaced by
	// +0.0 before rounding, so only `neg` still knows which way an infinity pointed. For a finite
	// out-of-range value rounding cannot change the sign, so the two agree there.
	auto *oor_val = lb->CreateSelect(neg, dsplat(sat_min), dsplat(sat_max));
	// SELECTS ON `invalid`, NOT ON `oor`, AND THE DIFFERENCE IS A BUG THE VALUE ORACLE CAUGHT.
	// On the `.rtz` arm the two coincide: an infinity's sign-cleared bits exceed every bound, so
	// `oor` already covers it. On the frm arm the infinities are replaced by +0.0 BEFORE the
	// rounding, so the rounded value is 0 and `oor` is false for them -- selecting on `oor` there
	// returned the converted 0 instead of the saturated value. `invalid` is the union that holds
	// on both arms.
	auto *res = lb->CreateSelect(is_nan, dsplat(sat_max),
				     lb->CreateSelect(invalid, oor_val, conv));
	auto *dst_ep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(dity), ins->rd);
	if (active)
		AScopeState(lb->CreateMaskedStore(res, dst_ep, llvm::Align(16), active));
	else
		AScopeState(lb->CreateAlignedStore(res, dst_ep, llvm::Align(16)));

	// NV, derived from the contract rather than from the host: set iff ANY lane of this unit was
	// invalid. `fcsr` accumulates by OR, and the frame's bracket will OR the host's NX on top, so
	// the two sources compose without either clobbering the other.
	auto *mask_ty = llvm::IntegerType::get(lctx, lanes);
	auto any = [&](llvm::Value *m) {
		return lb->CreateICmpNE(lb->CreateBitCast(m, mask_ty),
					llvm::ConstantInt::get(mask_ty, 0));
	};
	auto *any_invalid = any(only_active(invalid));
	llvm::Value *flags = lb->CreateSelect(any_invalid, lb->getInt32(rv32::FFLAG_NV),
					      lb->getInt32(0));
	if (inexact) {
		// NX only where the lane is NOT invalid -- the two are mutually exclusive in the
		// contract, and every NV path in `cvt_to_int_width` returns before its inexact test.
		auto *any_inexact = any(only_active(lb->CreateAnd(inexact, lb->CreateNot(invalid))));
		flags = lb->CreateOr(flags, lb->CreateSelect(any_inexact,
							    lb->getInt32(rv32::FFLAG_NX),
							    lb->getInt32(0)));
	}
	u32 const fcsr_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
	auto *fcsr = RvvStateLoad(VType::I32, fcsr_off, llvm::Align(4));
	RvvStateStore(VType::I32, fcsr_off, lb->CreateOr(fcsr, flags), llvm::Align(4));
}
// C4 (2026-09-19). WIDENING FLOAT -> FLOAT: `vfwcvt.f.f.v` (f32 -> f64).
//
// A BARE `fpext` IS NOT A CORRECT LOWERING, and "widening a finite float is exact" is not the
// contract. `softfp::cvt_fmt` canonicalises BOTH NaN kinds to the TARGET format's canonical quiet
// NaN and raises NV for a signalling one; the host path agrees, ending in `f64_canon`. x86's
// `vcvtps2pd` does neither -- it quiets an sNaN while PRESERVING its payload, and passes a qNaN
// through unchanged. So the NaN lanes are selected to the canonical value after the conversion.
//
// NO OPERAND NEUTRALISATION HERE, and that is argued rather than inherited from the float-to-integer
// routes:
//   * `fpext` is TOTAL -- every input, NaN included, has a defined result -- so there is no poison
//     to avoid;
//   * the host's flags already match the contract exactly (invalid for a signalling NaN, nothing
//     for a quiet one), so there is no lane whose host flag has to be suppressed.
// NV is nevertheless DERIVED for the sNaN lanes, so the flag is visible in the emitted IR and
// checkable by a test that cannot observe host MXCSR. It is the same bit either way.
//
// THE sNaN TEST IS INTEGER. `fcmp uno` would raise the host invalid flag on exactly the lanes this
// code is classifying, and distinguishing quiet from signalling needs the mantissa's top bit
// anyway, which is a bit test.
void QIRToLLVM::Emit_vchunkftof(qir::InstVChunkFToF *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked float-width conversion has no lowering in this backend");
	// ORDER ITEM 4 (2026-09-19): ROUND-TO-ODD is lowered, in INTEGER IR, by the arm below.
	if (ins->rod && !config::rvv_llvm_fcvt_rod)
		Panic("llvmgen: round-to-odd narrowing has no lowering in this backend");
	if (ins->rod && ins->sew != 4)
		Panic("llvmgen: round-to-odd is a narrowing form only");
	if (ins->sew != 8 && ins->sew != 4)
		Panic("llvmgen: float-width conversion with an unsupported destination width");
	if (ins->bytes % ins->sew != 0)
		Panic("llvmgen: float-width chunk is not a whole number of destination elements");
	if (!tchunk_full_vl && !config::rvv_llvm_fcvt_partial_vl)
		Panic("llvmgen: float-width conversion in a frame whose guard does not prove full VL");
	// `sew` is the DESTINATION width, so 8 widens f32 -> f64 and 4 narrows f64 -> f32. The unit's
	// lane count always comes from the destination window; the source window is the other size.
	bool const widen = ins->sew == 8;
	u32 const lanes = (u32)ins->bytes / ins->sew;
	u32 const src_bytes = lanes * (widen ? 4u : 8u);
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (size_t)ins->rs + src_bytes > sizeof(CPUState))
		Panic("llvmgen: float-width conversion window lies outside CPUState");

	u32 const sbits_w = widen ? 32u : 64u, dbits_w = widen ? 64u : 32u;
	auto *sfty = llvm::FixedVectorType::get(widen ? lb->getFloatTy() : lb->getDoubleTy(), lanes);
	auto *dfty = llvm::FixedVectorType::get(widen ? lb->getDoubleTy() : lb->getFloatTy(), lanes);
	auto *sity = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, sbits_w), lanes);
	auto *dity = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, dbits_w), lanes);
	auto ssplat = [&](u64 v) {
		return llvm::ConstantVector::getSplat(
		    llvm::ElementCount::getFixed(lanes),
		    llvm::ConstantInt::get(llvm::IntegerType::get(lctx, sbits_w), v));
	};
	// Derived from the SOURCE format, never written per width: exponent all ones with a non-zero
	// significand is a NaN, and the significand's top bit is the quiet bit.
	u32 const s_man = widen ? 23u : 52u;
	u64 const s_inf = (u64)((1ull << (sbits_w - 1u - s_man)) - 1u) << s_man;
	u64 const s_abs = (sbits_w == 64 ? ~0ull : ((1ull << sbits_w) - 1u)) >> 1;
	u64 const s_quiet = 1ull << (s_man - 1u);

	llvm::Value *src = AScopeState(lb->CreateAlignedLoad(
	    sfty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(sfty), ins->rs),
	    llvm::commonAlignment(llvm::Align(16), ins->rs)));
	auto *sbits = lb->CreateBitCast(src, sity);
	auto *absb = lb->CreateAnd(sbits, ssplat(s_abs));
	auto *is_nan = lb->CreateICmpUGT(absb, ssplat(s_inf));
	auto *is_quiet = lb->CreateICmpNE(lb->CreateAnd(sbits, ssplat(s_quiet)), ssplat(0));
	auto *is_snan = lb->CreateAnd(is_nan, lb->CreateNot(is_quiet));

	// PARTIAL VL, AND IT CHANGES THIS ROUTE'S ARGUMENT RATHER THAN JUST ADDING A MASK.
	//
	// At full VL this body deliberately does NOT neutralise: `fpext`/`fptrunc` are total, and the
	// host's flags agree with the contract on every lane (invalid for a signalling NaN, nothing
	// for a quiet one; and for narrowing, OF/UF/NX exactly where `round_pack` wants them). THAT
	// ARGUMENT DEPENDS ON EVERY LANE BEING ACTIVE. An INACTIVE lane must raise nothing at all, and
	// the host would happily raise invalid for a signalling NaN sitting in it, or -- on the
	// narrowing side -- overflow or underflow for whatever value it holds. So partial VL is
	// exactly the case where this route does need a neutralisation, and `+0.0` is the value:
	// widening it is exact and narrowing it is exact, so neither can raise.
	llvm::Value *active = nullptr;
	if (!tchunk_full_vl) {
		active = RvvActiveLaneMask(lanes, ins->base);
		src = lb->CreateSelect(active, src, llvm::ConstantFP::get(sfty, 0.0));
	}

	// ===========================================================================================
	// ORDER ITEM 4 (2026-09-19): `vfncvt.rod.f.f.w` -- ROUND-TO-ODD, f64 -> f32, IN INTEGER IR.
	//
	// WHY NOT A HOST CONVERSION WITH A REQUESTED ROUNDING MODE. That was the obvious design and it
	// is WRONG ON THIS TARGET, measured rather than assumed on the installed LLVM 20.1.8:
	//
	//     constrained.fptrunc <8 x double> ... round.towardzero, fpexcept.strict -> vcvtpd2ps
	//     constrained.fptrunc <8 x double> ... round.dynamic,    fpexcept.strict -> vcvtpd2ps
	//     constrained.fadd    double       ... round.upward,     fpexcept.strict -> vaddsd
	//
	// -- byte-identical code for a requested mode and for the dynamic one, and no MXCSR write
	// anywhere. The x86 backend honours the metadata only by refusing to CONSTANT-FOLD; codegen
	// uses whatever MXCSR.RC holds, which inside this frame's bracket is the GUEST's `frm`. A ROD
	// arm built on `round.towardzero` would therefore compute `round_frm(x)` and then set the low
	// bit -- a silently wrong value whenever `frm != RTZ` and the conversion is inexact.
	//
	// (Nothing already shipped depends on that metadata: every constrained call in this file uses
	// `round.dynamic`, and the `rtz` float-to-integer routes get truncation from `fptosi`/`fptoui`,
	// which truncate BY DEFINITION and not by mode.)
	//
	// SO THE CONVERSION IS DONE IN INTEGER IR, which is host-independent and, for this operation,
	// not even difficult: round-to-odd is "truncate toward zero, then force the low significand bit
	// whenever anything was discarded" (`softfp::round_pack`, the `FRM_ROD` arms). Both halves are
	// bit operations.
	//
	// ONE SIGNIFICAND FORMULA FOR NORMALS AND SUBNORMALS. `value = sig * 2^(E-52)` with
	// `sig = (e ? (1<<52)|m : m)` and `E = (e ? e-1023 : -1022)`, so the f64 subnormal case is the
	// same expression with the implicit bit absent -- no second path. The number of significand bits
	// to DROP is then 29 for an f32-normal result and `-97 - E` for an f32-subnormal one, and the
	// dropped bits are the sticky test.
	//
	// THE THREE BOUNDARIES, each of which the reference fixes and each of which is easy to get
	// wrong by one:
	//   * OVERFLOW is `E >= 128`, not `E >= 127`. Truncation never overflows at E == 127 -- the
	//     largest f32 is `(2 - 2^-23) * 2^127` -- so a ROD result at that exponent is at most
	//     0x7F7FFFFF and raises nothing. At `E >= 128` round-to-odd gives FLT_MAX (it "never
	//     produces an infinity from a finite value", `round_pack`'s `to_inf = false` arm) with
	//     OF|NX, and FLT_MAX's low bit is ALREADY 1, so forcing it is a no-op there.
	//   * UNDERFLOW TO ZERO IS IMPOSSIBLE for a nonzero input: truncation gives a zero significand
	//     and the odd-bit force turns it into the smallest subnormal. That is the whole point of
	//     round-to-odd, and it is why `q | inexact` is applied to the SUBNORMAL field too.
	//   * A SHIFT OF 64 OR MORE IS POISON in LLVM, so the shift is clamped and the two results it
	//     would have produced (quotient 0, sticky `sig != 0`) are selected in explicitly.
	//
	// FLAGS ARE DERIVED BY THE BODY, and contract piece 7's clause for that is discharged more
	// strongly here than anywhere else: the clause asks that the host cannot raise a CONTRADICTORY
	// flag for the same lane, and this body performs NO host floating-point operation at all, so
	// the host cannot raise anything. That is also why ROD needs no inactive-lane neutralisation --
	// integer operations raise nothing, exactly as for the integer element-wise family.
	if (ins->rod) {
		auto isplat = [&](u64 v) {
			return llvm::ConstantVector::getSplat(
			    llvm::ElementCount::getFixed(lanes),
			    llvm::ConstantInt::get(llvm::IntegerType::get(lctx, 64), v));
		};
		auto *sb = lb->CreateBitCast(src, sity);
		auto *absv = lb->CreateAnd(sb, isplat(0x7FFFFFFFFFFFFFFFull));
		auto *e64 = lb->CreateLShr(absv, isplat(52));
		auto *m64 = lb->CreateAnd(absv, isplat(0xFFFFFFFFFFFFFull));
		auto *sub_src = lb->CreateICmpEQ(e64, isplat(0)); // f64 subnormal or zero
		auto *sig = lb->CreateSelect(sub_src, m64,
					     lb->CreateOr(m64, isplat(1ull << 52)));
		// Unbiased exponent as a SIGNED value; the subnormal case shares the formula by using
		// the smallest normal exponent with an absent implicit bit.
		auto *E = lb->CreateSelect(sub_src, isplat((u64)(i64)-1022),
					   lb->CreateSub(e64, isplat(1023)));
		auto *normal_dst = lb->CreateICmpSGE(E, isplat((u64)(i64)-126));
		auto *shift = lb->CreateSelect(
		    normal_dst, isplat(29),
		    lb->CreateSub(isplat((u64)(i64)-97), E)); // -97 - E
		// TWO INDEPENDENT GUARDS AGAINST THE POISON SHIFT, and the mutation run says exactly
		// that: removing EITHER alone survives the differential (the clamp alone makes the
		// shift legal and `sig >> 63` is 0 for every `sig < 2^53`; the select alone discards
		// the poison arm), and removing BOTH fails 578 cells. They are kept as a pair because
		// the emitted code is not the folded one: a poison `lshr` that the optimiser is free
		// to propagate is a miscompile risk no constant-fold test can observe.
		auto *shift_ge64 = lb->CreateICmpSGE(shift, isplat(64));
		auto *shc = lb->CreateSelect(shift_ge64, isplat(63), shift);
		auto *q = lb->CreateSelect(shift_ge64, isplat(0), lb->CreateLShr(sig, shc));
		auto *dropped = lb->CreateSelect(
		    shift_ge64, sig,
		    lb->CreateAnd(sig, lb->CreateSub(lb->CreateShl(isplat(1), shc), isplat(1))));
		auto *inexact = lb->CreateICmpNE(dropped, isplat(0));
		auto *odd = lb->CreateSelect(inexact, isplat(1), isplat(0));
		// f32-normal: exponent field E + 127, significand the low 23 bits of q (q's bit 23 is
		// the implicit one). f32-subnormal: exponent field 0, significand q (always < 2^23).
		auto *field_n = lb->CreateOr(lb->CreateAnd(q, isplat(0x7FFFFF)), odd);
		auto *expf = lb->CreateShl(lb->CreateAdd(E, isplat(127)), isplat(23));
		auto *mag_n = lb->CreateOr(lb->CreateAnd(expf, isplat(0x7F800000)), field_n);
		auto *mag_s = lb->CreateOr(q, odd);
		llvm::Value *mag = lb->CreateSelect(normal_dst, mag_n, mag_s);
		auto *ovf = lb->CreateICmpSGT(E, isplat(127));
		mag = lb->CreateSelect(ovf, isplat(0x7F7FFFFF), mag);
		// Infinity passes through; NaN is replaced by the canonical qNaN below, as for the
		// rounding arm, so the NaN lanes' magnitude here is irrelevant.
		auto *is_inf = lb->CreateICmpEQ(absv, isplat(0x7FF0000000000000ull));
		mag = lb->CreateSelect(is_inf, isplat(0x7F800000), mag);
		auto *sign32 = lb->CreateLShr(lb->CreateAnd(sb, isplat(1ull << 63)), isplat(32));
		auto *bits64 = lb->CreateOr(mag, sign32);
		auto *rod_res = lb->CreateTrunc(bits64, dity);

		llvm::Value *rod_active = nullptr;
		if (!tchunk_full_vl)
			rod_active = RvvActiveLaneMask(lanes, ins->base);
		auto *rod_canon = llvm::ConstantVector::getSplat(
		    llvm::ElementCount::getFixed(lanes),
		    llvm::ConstantInt::get(llvm::IntegerType::get(lctx, 32),
					   (u64)rv32::F32_CANONICAL_NAN));
		auto *rod_out = lb->CreateSelect(is_nan, rod_canon, rod_res);
		auto *rod_ep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(dity), ins->rd);
		llvm::Align const dst_align = llvm::commonAlignment(llvm::Align(16), ins->rd);
		if (rod_active)
			AScopeState(lb->CreateMaskedStore(rod_out, rod_ep, dst_align, rod_active));
		else
			AScopeState(lb->CreateAlignedStore(rod_out, rod_ep, dst_align));

		// THE FLAG DERIVATION, and every conjunct is load-bearing:
		//   NX  inexact, or overflow -- but NOT for a NaN or an infinity, where "dropped" is a
		//       meaningless artefact of treating the payload as a significand;
		//   OF  E >= 128 on a finite input (which then also carries NX);
		//   UF  a SUBNORMAL result that is inexact -- tininess after rounding, the rule
		//       `round_pack` states and the one the hardware arm relies on for the non-ROD form;
		//   NV  a signalling NaN, computed by the shared code below this block.
		// An INACTIVE lane contributes nothing, exactly as for the rounding arm.
		auto *finite = lb->CreateNot(lb->CreateICmpUGE(absv, isplat(0x7FF0000000000000ull)));
		auto *nx = lb->CreateAnd(finite, lb->CreateOr(inexact, ovf));
		auto *of = lb->CreateAnd(finite, ovf);
		auto *uf = lb->CreateAnd(finite,
					 lb->CreateAnd(lb->CreateNot(normal_dst), inexact));
		if (rod_active) {
			nx = lb->CreateAnd(nx, rod_active);
			of = lb->CreateAnd(of, rod_active);
			uf = lb->CreateAnd(uf, rod_active);
		}
		auto *rod_mask_ty = llvm::IntegerType::get(lctx, lanes);
		auto any = [&](llvm::Value *v) {
			return lb->CreateICmpNE(lb->CreateBitCast(v, rod_mask_ty),
						llvm::ConstantInt::get(rod_mask_ty, 0));
		};
		auto *rod_snan = rod_active ? lb->CreateAnd(is_snan, rod_active) : is_snan;
		llvm::Value *fl = lb->getInt32(0);
		fl = lb->CreateOr(fl, lb->CreateSelect(any(nx), lb->getInt32(rv32::FFLAG_NX),
						       lb->getInt32(0)));
		fl = lb->CreateOr(fl, lb->CreateSelect(any(of), lb->getInt32(rv32::FFLAG_OF),
						       lb->getInt32(0)));
		fl = lb->CreateOr(fl, lb->CreateSelect(any(uf), lb->getInt32(rv32::FFLAG_UF),
						       lb->getInt32(0)));
		fl = lb->CreateOr(fl, lb->CreateSelect(any(rod_snan), lb->getInt32(rv32::FFLAG_NV),
						       lb->getInt32(0)));
		u32 const rod_fcsr = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
		auto *cur = RvvStateLoad(VType::I32, rod_fcsr, llvm::Align(4));
		RvvStateStore(VType::I32, rod_fcsr, lb->CreateOr(cur, fl), llvm::Align(4));
		return;
	}

	// WIDENING IS EXACT AND TAKES NO ROUNDING OPERAND; NARROWING ROUNDS AND TAKES ONE. The
	// narrowing direction's NX, OF|NX and UF|NX all come from the hardware `vcvtpd2ps`, which
	// agrees with `softfp::round_pack` including tininess-after-rounding; only the NaN VALUE
	// differs, which is the one thing the select below corrects.
	llvm::Value *cvt =
	    widen ? RvvConstrainedFPCallNoRound(llvm::Intrinsic::experimental_constrained_fpext,
						{dfty, sfty}, {src})
		  : RvvConstrainedFPCallN(llvm::Intrinsic::experimental_constrained_fptrunc,
					  {dfty, sfty}, {src});
	auto *canon = llvm::ConstantVector::getSplat(
	    llvm::ElementCount::getFixed(lanes),
	    llvm::ConstantInt::get(llvm::IntegerType::get(lctx, dbits_w),
				   widen ? rv32::F64_CANONICAL_NAN
					 : (u64)rv32::F32_CANONICAL_NAN));
	auto *res = lb->CreateSelect(is_nan, canon, lb->CreateBitCast(cvt, dity));
	auto *dst_ep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(dity), ins->rd);
	llvm::Align const dst_align = llvm::commonAlignment(llvm::Align(16), ins->rd);
	if (active)
		AScopeState(lb->CreateMaskedStore(res, dst_ep, dst_align, active));
	else
		AScopeState(lb->CreateAlignedStore(res, dst_ep, dst_align));

	auto *mask_ty = llvm::IntegerType::get(lctx, lanes);
	// An INACTIVE signalling NaN raises nothing: the instruction never touched that element.
	auto *snan_active = active ? lb->CreateAnd(is_snan, active) : is_snan;
	auto *any_snan = lb->CreateICmpNE(lb->CreateBitCast(snan_active, mask_ty),
					  llvm::ConstantInt::get(mask_ty, 0));
	u32 const fcsr_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
	auto *fcsr = RvvStateLoad(VType::I32, fcsr_off, llvm::Align(4));
	RvvStateStore(VType::I32, fcsr_off,
		      lb->CreateOr(fcsr, lb->CreateSelect(any_snan, lb->getInt32(rv32::FFLAG_NV),
							  lb->getInt32(0))),
		      llvm::Align(4));
}
// ===============================================================================================
// C6 (2026-09-20): THE REGISTER GATHER AND THE SLIDES -- `vrgather`, `vslideup`, `vslidedown`,
// `vslide1up`, `vslide1down`.
//
// FIVE INSTRUCTIONS, ONE NODE, AND ONE LOWERING -- because they differ only in WHICH source element
// each destination element reads. Write them side by side and the family collapses:
//
//     vrgather     vd[e] = vs2[idx[e]]      idx from vs1[e], a GPR, or an immediate
//     vslideup     vd[e] = vs2[e - off]     and e < off is UNDISTURBED, not zeroed
//     vslidedown   vd[e] = vs2[e + off]
//     vslide1up    vd[e] = vs2[e - 1]       with vd[0] = the scalar
//     vslide1down  vd[e] = vs2[e + 1]       with vd[vl-1] = the scalar
//
// So the emitter computes an INDEX VECTOR, a VALIDITY mask (is the source element readable?) and a
// STORE mask (may this destination element be written?), and the five differ in nothing else.
//
// OUT-OF-RANGE READS ARE ZERO, NOT CLAMPED AND NOT WRAPPED. `vrgather` with an index at or beyond
// VLMAX reads zero; so does `vslidedown` past VLMAX. That falls out of `masked.gather`'s passthru
// operand rather than needing a branch -- which is also how the two slide1 forms get their scalar
// into the vacated end, since the vacated lane is exactly the one whose source is unreadable.
//
// THE TWO BOUNDARIES ARE DIFFERENT AND BOTH MATTER. `vslidedown` and `vrgather` bound the SOURCE
// index by VLMAX; `vslide1down` bounds it by `vl` -- its scalar lands at `vl - 1`, not at
// VLMAX - 1. Using VLMAX for `vslide1down` would put the scalar in a lane the instruction must not
// write and leave `vl - 1` holding a stale element.
//
// INDEX ARITHMETIC IS DONE IN 64 BITS. `e + off` with `off` from a GPR can exceed 32 bits, and the
// reference computes `(u64)e + off` before comparing against VLMAX; doing it in `i32` would wrap a
// huge offset back into range and gather a real element where the spec says zero.
//
// LMUL 1 ONLY. At LMUL 1 the source group is ONE register, so element `i` is at `src + i * sew` and
// the gather's address vector is a single scaled index. Across a group it is not: consecutive
// logical elements jump a 512-byte slot every `regbytes`, so the address would need a divide and a
// second term per lane. Recorded as a limit; LMUL > 1 keeps the unchanged helper.
void QIRToLLVM::Emit_vgathernative(qir::InstVGather *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked gather/slide has no lowering in this backend");
	u32 const sew = ins->sew, isew = ins->isew;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: gather/slide with an unsupported SEW");
	if (isew != 1 && isew != 2 && isew != 4 && isew != 8)
		Panic("llvmgen: gather/slide with an unsupported index EEW");
	if (ins->slide > 4 || ins->mode > 3 || (ins->mode == 3 && ins->slide < 3))
		Panic("llvmgen: gather/slide shape outside the node's own envelope");
	if (ins->vlmax == 0 || ins->vlmax > 4096u)
		Panic("llvmgen: gather/slide with no guarded element count");
	u32 const regbytes = ins->regbytes;
	if ((u32)ins->vlmax * sew > regbytes)
		Panic("llvmgen: gather/slide source spans a register group");
	u32 const bytes = std::min(64u, regbytes);
	if (bytes % sew != 0)
		Panic("llvmgen: gather/slide chunk is not a whole number of elements");
	u32 const lanes = bytes / sew;
	u32 const base_off = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const slot = rv32::VLEN_MAX_BYTES;
	auto *i32ty = lb->getInt32Ty();
	auto *i64ty = lb->getInt64Ty();
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto *v64 = llvm::FixedVectorType::get(i64ty, lanes);
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	auto *vl64 = lb->CreateZExt(vl, i64ty);
	auto *vlmax64 = llvm::ConstantInt::get(i64ty, ins->vlmax);

	// The scalar operand, at 64 bits. For the slides it is the OFFSET (`.vx`) or the fill
	// (`.vx`/`.vf` on the slide1 forms); for `vrgather.vx` it is the index itself. An immediate
	// is unsigned here -- it is an index or a distance, never a signed addend.
	llvm::Value *scalar64 = nullptr;
	if (ins->mode == 1)
		scalar64 = lb->CreateZExt(
		    RvvStateLoad(VType::I32, (u32)offsetof(CPUState, gpr) + (u32)ins->index * 4u,
				 llvm::Align(4)),
		    i64ty);
	else if (ins->mode == 2)
		scalar64 = llvm::ConstantInt::get(i64ty, ins->index);
	// THE SLIDE1 FILL, and it is NOT a plain load of `ety` bytes from the register file. Two
	// rules, both the reference's (`rv32_interp.cpp`'s `vslide1` caller), and getting either
	// wrong is a miscompile rather than a missed optimisation:
	//
	//   `.vx`  scalar = (u64)(i64)(i32)gpr[rs1]   -- the 32-bit GPR SIGN-EXTENDED to SEW
	//   `.vf`  scalar = sew == 4 ? f32_unbox(f[rs1]) : f[rs1]   -- NaN-UNBOXED at SEW 32
	//
	// AN EARLIER VERSION OF THIS CODE DID NEITHER, and the comment here asserted the opposite --
	// that the fill "is read at SEW and NOT NaN-unboxed". At SEW 64 the `.vx` form then loaded
	// EIGHT bytes from a FOUR-byte GPR slot, taking `gpr[rs1+1]` as the fill's high half: an
	// out-of-slot read and a wrong value. Official ACT4 `Vx64-vslide1down.vx` and
	// `Vx64-vslide1up.vx` passed under QCG and aborted the AOT run on an unknown Linux syscall,
	// which is what a corrupted element looks like once it reaches the test's own control flow.
	// The `.vf` half was wrong too, if less loudly: an f32 that is not properly NaN-boxed must
	// read as the canonical quiet NaN, not as its low half.
	llvm::Value *fill = llvm::ConstantInt::get(ety, 0);
	if (ins->slide >= 3) {
		if (ins->mode == 3) {
			u32 const off = (u32)(offsetof(CPUState, fpu) +
					      offsetof(rv32::FPUState, f)) +
					(u32)ins->index * 8u;
			auto *f = AScopeState(lb->CreateAlignedLoad(
			    i64ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), off),
			    llvm::Align(8)));
			if (sew == 4) {
				// Integer-only unboxing, the same expression the scalar-move
				// emitter uses: a high half that is not all ones is not a valid
				// boxed f32 and reads as the canonical qNaN.
				auto *hi = lb->CreateTrunc(lb->CreateLShr(f, lb->getInt64(32)),
							   lb->getInt32Ty());
				auto *boxed = lb->CreateICmpEQ(hi, lb->getInt32(0xffffffffu));
				fill = lb->CreateSelect(boxed,
							lb->CreateTrunc(f, lb->getInt32Ty()),
							lb->getInt32(0x7fc00000u));
			} else {
				fill = f;
			}
		} else {
			// ALWAYS a 32-bit GPR read, then widened to SEW. `gpr[0]` is maintained as
			// zero, so `x0` needs no special case.
			auto *g = RvvStateLoad(VType::I32,
					       (u32)offsetof(CPUState, gpr) + (u32)ins->index * 4u,
					       llvm::Align(4));
			fill = sew == 8   ? lb->CreateSExt(g, i64ty)
			       : sew == 4 ? (llvm::Value *)g
					  : (llvm::Value *)lb->CreateTrunc(g, ety);
		}
	}

	for (u32 first = 0; first < ins->vlmax; first += lanes) {
		llvm::SmallVector<llvm::Constant *, 64> ec;
		for (u32 i = 0; i < lanes; ++i)
			ec.push_back(llvm::ConstantInt::get(i64ty, first + i));
		auto *e64 = llvm::ConstantVector::get(ec); // this chunk's element indices
		llvm::Value *idx = nullptr;		   // source element index, 64-bit
		llvm::Value *readable = nullptr;	   // is that source element defined?
		llvm::Value *storable = lb->CreateICmpULT(e64, lb->CreateVectorSplat(lanes, vl64));
		switch (ins->slide) {
		case 0: { // vrgather
			if (ins->mode == 0) {
				auto *ity = llvm::IntegerType::get(lctx, isew * 8u);
				auto *ivty = llvm::FixedVectorType::get(ity, lanes);
				auto *iv = AScopeState(lb->CreateAlignedLoad(
				    ivty,
				    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ivty),
							 base_off + (u32)ins->index * slot +
							     first * isew),
				    llvm::Align(16)));
				idx = lb->CreateZExt(iv, v64);
			} else {
				idx = lb->CreateVectorSplat(lanes, scalar64);
			}
			readable = lb->CreateICmpULT(idx, lb->CreateVectorSplat(lanes, vlmax64));
			break;
		}
		case 1: // vslideup: e - off, and e < off is UNDISTURBED
			idx = lb->CreateSub(e64, lb->CreateVectorSplat(lanes, scalar64));
			readable = lb->CreateICmpUGE(e64, lb->CreateVectorSplat(lanes, scalar64));
			storable = lb->CreateAnd(storable, readable);
			break;
		case 2: // vslidedown: e + off, past VLMAX reads zero
			idx = lb->CreateAdd(e64, lb->CreateVectorSplat(lanes, scalar64));
			readable = lb->CreateICmpULT(idx, lb->CreateVectorSplat(lanes, vlmax64));
			break;
		case 3: // vslide1up: e - 1, and element 0 takes the scalar
			idx = lb->CreateSub(e64, llvm::ConstantInt::get(v64, 1));
			readable = lb->CreateICmpUGT(e64, llvm::ConstantInt::get(v64, 0));
			break;
		default: // vslide1down: e + 1, and the LAST ACTIVE element takes the scalar
			idx = lb->CreateAdd(e64, llvm::ConstantInt::get(v64, 1));
			// `vl`, NOT VLMAX: the fill lands at `vl - 1`.
			readable = lb->CreateICmpULT(idx, lb->CreateVectorSplat(lanes, vl64));
			break;
		}
		auto *take = lb->CreateAnd(readable, storable);
		// The address vector. NOT `inbounds`: a masked-off lane's index may be anything,
		// and an out-of-bounds `inbounds` GEP is poison even when never dereferenced.
		auto *src = lb->CreateConstInBoundsGEP1_32(
		    lb->getInt8Ty(), statev, base_off + (u32)ins->data * slot);
		auto *ptrs = lb->CreateGEP(lb->getInt8Ty(), src,
					   lb->CreateMul(idx, llvm::ConstantInt::get(v64, sew)));
		// The passthru is the value of an UNREADABLE lane: zero for the gather and the
		// slides, the scalar for the two slide1 forms, whose vacated end is exactly the lane
		// whose source does not exist.
		auto *passthru = ins->slide >= 3 ? lb->CreateVectorSplat(lanes, fill)
						 : llvm::ConstantAggregateZero::get(vty);
		auto *got = AScopeState(
		    lb->CreateMaskedGather(vty, ptrs, llvm::Align(sew), take, passthru));
		AScopeState(lb->CreateMaskedStore(
		    got,
		    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty),
					 base_off + (u32)ins->rd * slot + first * sew),
		    llvm::Align(16), storable));
	}
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}

// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE 7-BIT ESTIMATES -- `vfrsqrt7.v` and `vfrec7.v` -- IN INTEGER IR.
//
// THESE ARE NOT IEEE OPERATIONS, and that is the first thing the lowering has to get right.
// `rv32_vector_lower.h` states it: RVV 1.0 specifies them by an EXACT 128-entry lookup table, so
// two conforming implementations produce identical bits. Substituting a host reciprocal or
// reciprocal-square-root -- or `llvm.sqrt` plus a divide -- would be a SEMANTIC REPLACEMENT, not a
// lowering, and would differ from the reference in the low bits of every result. So there is no
// constrained-FP call here and no FP bracket: the body is bit manipulation plus a table index, and
// the flags it raises (DZ, NV, and for `vfrec7` also OF|NX) are ORed into `fcsr` explicitly.
//
// THE TABLE IS A PRIVATE MODULE CONSTANT, NOT A HOST POINTER. `InstVFEstimate::table` carries a host
// address, which is right for QCG and fatal for an artifact compiled by `elfaot` and executed by
// `elfrun`. The bytes are copied from the same `VFRSQRT7_TAB` / `VFREC7_TAB` the reference indexes,
// so a transcription error is impossible by construction -- there is one copy of the table.
//
// STRUCTURE: everything is vector integer IR except the LOOKUP, which is one scalar
// `getelementptr` + `load i8` per lane. Portable LLVM has no dynamic vector permute other than
// `llvm.masked.gather`, and a gather buys nothing at 128 bytes; an AVX512-VBMI `vpermi2b` form is a
// measurement for later, recorded in the plan rather than guessed at here.
//
// SUBNORMAL NORMALISATION IS A COUNT-LEADING-ZEROS, NOT A LOOP. The reference shifts until the
// hidden bit is set; `llvm.ctlz` gives the same shift in one operation per lane. `sig` is known
// non-zero on that path (the zero case is handled before it), so `is_zero_poison` is false and the
// result is defined.
void QIRToLLVM::Emit_vchunkfestimate(qir::InstVChunkFEstimate *ins)
{
	TChunkAccount();
	// C5-MASK-FP: the architectural mask is a CONJUNCT of the shared active-lane predicate,
	// not a separate mechanism. It reaches both obligations through that one value -- the
	// destination's masked store and every flag predicate, which are already ANDed with it.
	if (ins->sew != 4 && ins->sew != 8)
		Panic("llvmgen: RVV estimate with an unsupported SEW");
	if (ins->bytes % ins->sew != 0)
		Panic("llvmgen: RVV estimate chunk is not a whole number of elements of this SEW");
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (size_t)ins->rs + ins->bytes > sizeof(CPUState))
		Panic("llvmgen: RVV estimate window lies outside CPUState");

	u32 const lanes = (u32)ins->bytes / ins->sew;
	u32 const bits = 8u * ins->sew;
	u32 const mant = ins->sew == 4 ? 23u : 52u;
	u32 const expb = ins->sew == 4 ? 8u : 11u;
	u64 const bias = ins->sew == 4 ? 127u : 1023u;
	u64 const emask = ((u64)1 << expb) - 1u;
	u64 const man_mask = ((u64)1 << mant) - 1u;
	u64 const quiet = (u64)1 << (mant - 1u);
	u64 const sbit = (u64)1 << (mant + expb);
	u64 const qnan = ins->sew == 4 ? (u64)rv32::F32_CANONICAL_NAN : rv32::F64_CANONICAL_NAN;

	auto *ety = llvm::IntegerType::get(lctx, bits);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto splat = [&](u64 v) {
		return llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes),
						      llvm::ConstantInt::get(ety, v));
	};
	auto *src = AScopeState(lb->CreateAlignedLoad(
	    vty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rs), llvm::Align(16)));

	auto *sign = lb->CreateAnd(src, splat(sbit));
	auto *sign_set = lb->CreateICmpNE(sign, splat(0));
	auto *e = lb->CreateAnd(lb->CreateLShr(src, splat(mant)), splat(emask));
	auto *sig = lb->CreateAnd(src, splat(man_mask));
	auto *e_is_max = lb->CreateICmpEQ(e, splat(emask));
	auto *e_is_zero = lb->CreateICmpEQ(e, splat(0));
	auto *sig_zero = lb->CreateICmpEQ(sig, splat(0));
	auto *is_nan = lb->CreateAnd(e_is_max, lb->CreateNot(sig_zero));
	auto *is_snan = lb->CreateAnd(
	    is_nan, lb->CreateICmpEQ(lb->CreateAnd(sig, splat(quiet)), splat(0)));
	auto *is_inf = lb->CreateAnd(e_is_max, sig_zero);
	auto *is_zero = lb->CreateAnd(e_is_zero, sig_zero);
	auto *is_sub = lb->CreateAnd(e_is_zero, lb->CreateNot(sig_zero));

	// NORMALISATION. `n` is the reference's loop count: the MSB of `sig` sits at `bits-1-lz`, and
	// the hidden bit must reach `mant`, so `n = mant - (bits-1-lz)`. With `sig != 0` on this path
	// the count is defined. Non-subnormal lanes take `n = 0`, which leaves `sig`/`e` unchanged.
	auto *ctlz = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::ctlz, {vty});
	auto *safe_sig = lb->CreateSelect(sig_zero, splat(1), sig); // keep ctlz defined for zero lanes
	auto *lz = lb->CreateCall(ctlz, {safe_sig, lb->getFalse()});
	// SIGN-EXTEND THE CONSTANT EXPLICITLY. `mant + 1 - bits` is NEGATIVE (-8 at SEW 32, -11 at
	// SEW 64) and both operands are `u32`, so writing it inline makes a large positive value and
	// every subnormal lane indexes the table with garbage -- which is exactly what the first run of
	// the differential reported, as a wrong significand with a RIGHT exponent.
	i64 const nbase = (i64)mant + 1 - (i64)bits;
	auto *n_raw = lb->CreateAdd(splat((u64)nbase), lz);
	auto *n = lb->CreateSelect(is_sub, n_raw, splat(0));
	auto *norm_sig = lb->CreateAnd(lb->CreateShl(sig, n), splat(man_mask));
	auto *norm_e = lb->CreateSelect(is_sub, lb->CreateSub(splat(1), n), e);

	// THE 7-BIT INDEX. `vfrsqrt7` uses the low exponent bit and the top SIX significand bits;
	// `vfrec7` uses the top SEVEN. Both are indices into a 128-entry table.
	llvm::Value *index =
	    ins->sqrt ? lb->CreateOr(lb->CreateShl(lb->CreateAnd(norm_e, splat(1)), splat(6)),
				     lb->CreateLShr(norm_sig, splat(mant - 6u)))
		      : lb->CreateLShr(norm_sig, splat(mant - 7u));

	// The table, as a private constant, and one scalar byte load per lane.
	u8 const *tab = ins->sqrt ? rv32::rvv_ref::VFRSQRT7_TAB : rv32::rvv_ref::VFREC7_TAB;
	llvm::SmallVector<uint8_t, 128> tv(tab, tab + 128);
	auto *tab_init = llvm::ConstantDataArray::get(lctx, llvm::ArrayRef<uint8_t>(tv));
	auto *tab_gv = new llvm::GlobalVariable(cmodule, tab_init->getType(), /*isConstant=*/true,
						llvm::GlobalValue::PrivateLinkage, tab_init,
						ins->sqrt ? ".rvv.vfrsqrt7.tab" : ".rvv.vfrec7.tab");
	tab_gv->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
	llvm::Value *looked = llvm::UndefValue::get(vty);
	for (u32 i = 0; i < lanes; ++i) {
		auto *idx_i = lb->CreateExtractElement(index, lb->getInt32(i));
		auto *idx64 = lb->CreateZExtOrTrunc(idx_i, lb->getInt64Ty());
		auto *ep = lb->CreateInBoundsGEP(tab_init->getType(), tab_gv,
						 {lb->getInt64(0), idx64});
		auto *by = lb->CreateAlignedLoad(lb->getInt8Ty(), ep, llvm::Align(1));
		looked = lb->CreateInsertElement(looked, lb->CreateZExt(by, ety), lb->getInt32(i));
	}
	auto *out_sig = lb->CreateShl(looked, splat(mant - 7u));

	llvm::Value *res = nullptr;
	llvm::Value *dz = is_zero, *nv = is_snan, *of = nullptr, *nx = nullptr;
	if (ins->sqrt) {
		// out_exp = (3 * bias - 1 - e) / 2, and the dividend is positive for every admitted
		// exponent, so the division is a logical shift.
		auto *oe = lb->CreateLShr(lb->CreateSub(splat(3u * bias - 1u), norm_e), splat(1));
		auto *normal = lb->CreateOr(lb->CreateShl(oe, splat(mant)), out_sig);
		// The special-value tree, in the reference's own order:
		//   NaN                    -> canonical qNaN (NV for a signalling one)
		//   -inf                   -> canonical qNaN, NV
		//   +inf                   -> +0
		//   +/-0                   -> +/-inf, DZ
		//   any other negative     -> canonical qNaN, NV
		auto *neg_other = lb->CreateAnd(sign_set, lb->CreateNot(lb->CreateOr(
						    is_nan, lb->CreateOr(is_inf, is_zero))));
		nv = lb->CreateOr(nv, lb->CreateAnd(is_inf, sign_set));
		nv = lb->CreateOr(nv, neg_other);
		auto *zero_res = lb->CreateOr(sign, splat(emask << mant)); // +/-inf
		res = lb->CreateSelect(is_nan, splat(qnan),
		      lb->CreateSelect(lb->CreateAnd(is_inf, sign_set), splat(qnan),
		      lb->CreateSelect(is_inf, splat(0),
		      lb->CreateSelect(is_zero, zero_res,
		      lb->CreateSelect(neg_other, splat(qnan), normal)))));
	} else {
		// `vfrec7`'s two overflow paths, both of which the reference derives from the SUBNORMAL
		// input's leading-zero count and from the output exponent respectively.
		//
		//   lead > 1        the reciprocal is beyond the format entirely: OF|NX, and the value
		//                   is +/-inf or +/-MAX depending on the GUEST's rounding mode -- read
		//                   from `fcsr` here rather than pinned at the guard, so an RTZ/RDN/RUP
		//                   execution is not sent to the helper for a mode this route handles.
		//   out_exp <= 0    the reciprocal is subnormal: the hidden bit becomes explicit and the
		//                   significand shifts right by `1 - out_exp`. Below -1 it is OF|NX and
		//                   +/-inf, unconditionally.
		auto *lead = lb->CreateSub(n, splat(1));
		auto *lead_big = lb->CreateAnd(is_sub, lb->CreateICmpSGT(lead, splat(1)));
		u32 const fcsr_o = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
		auto *fcsr_now = RvvStateLoad(VType::I32, fcsr_o, llvm::Align(4));
		auto *frm = lb->CreateAnd(lb->CreateLShr(fcsr_now, lb->getInt32(5)), lb->getInt32(7));
		auto *frm_v = lb->CreateVectorSplat(lanes, lb->CreateZExtOrTrunc(frm, ety));
		auto *rne = lb->CreateICmpEQ(frm_v, splat(rv32::FRM_RNE));
		auto *rmm = lb->CreateICmpEQ(frm_v, splat(rv32::FRM_RMM));
		auto *rup = lb->CreateICmpEQ(frm_v, splat(rv32::FRM_RUP));
		auto *rdn = lb->CreateICmpEQ(frm_v, splat(rv32::FRM_RDN));
		auto *to_inf = lb->CreateOr(
		    lb->CreateOr(rne, rmm),
		    lb->CreateOr(lb->CreateAnd(rup, lb->CreateNot(sign_set)),
				 lb->CreateAnd(rdn, sign_set)));
		auto *inf_mag = splat(emask << mant);
		auto *max_mag = splat(((emask - 1u) << mant) | man_mask);
		auto *ovf_res = lb->CreateOr(sign, lb->CreateSelect(to_inf, inf_mag, max_mag));

		auto *oe = lb->CreateSub(splat(2u * bias - 1u), norm_e);
		auto *oe_le0 = lb->CreateICmpSLE(oe, splat(0));
		auto *oe_lt_m1 = lb->CreateICmpSLT(oe, splat((u64)(i64)-1));
		auto *shifted = lb->CreateLShr(lb->CreateOr(out_sig, splat((u64)1 << mant)),
					       lb->CreateSub(splat(1), oe));
		auto *sub_res = lb->CreateOr(sign, shifted);           // exponent field 0
		auto *norm_res = lb->CreateOr(sign,
					      lb->CreateOr(lb->CreateShl(oe, splat(mant)), out_sig));
		auto *finite_res =
		    lb->CreateSelect(oe_lt_m1, lb->CreateOr(sign, inf_mag),
				     lb->CreateSelect(oe_le0, sub_res, norm_res));
		auto *ovf_late = lb->CreateAnd(lb->CreateNot(lead_big), oe_lt_m1);
		of = lb->CreateOr(lead_big, ovf_late);
		nx = of;
		auto *zero_res = lb->CreateOr(sign, inf_mag);
		res = lb->CreateSelect(is_nan, splat(qnan),
		      lb->CreateSelect(is_inf, sign,               // +/-inf -> +/-0
		      lb->CreateSelect(is_zero, zero_res,
		      lb->CreateSelect(lead_big, ovf_res, finite_res))));
		// The `of`/`nx` predicates above describe FINITE inputs only; a NaN, an infinity or a
		// zero takes one of the earlier arms and raises what that arm raises and nothing else.
		auto *finite = lb->CreateNot(lb->CreateOr(is_nan, lb->CreateOr(is_inf, is_zero)));
		of = lb->CreateAnd(of, finite);
		nx = of;
	}

	// This unit's active-lane predicate, from the LIVE vl: lane i is element `base + i`.
	auto *active = RvvActiveLaneMask(lanes, ins->base, ins->masked);
	AScopeState(lb->CreateMaskedStore(
	    res, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rd), llvm::Align(16),
	    active));

	// FLAGS. An INACTIVE lane raises nothing -- the instruction never touched that element -- so
	// every predicate is ANDed with the active mask before it is reduced, exactly as the
	// float-to-integer routes do.
	auto *mask_ty = llvm::IntegerType::get(lctx, lanes);
	auto any = [&](llvm::Value *v) {
		return lb->CreateICmpNE(lb->CreateBitCast(lb->CreateAnd(v, active), mask_ty),
					llvm::ConstantInt::get(mask_ty, 0));
	};
	llvm::Value *fl = lb->getInt32(0);
	fl = lb->CreateOr(fl, lb->CreateSelect(any(nv), lb->getInt32(rv32::FFLAG_NV),
					       lb->getInt32(0)));
	fl = lb->CreateOr(fl, lb->CreateSelect(any(dz), lb->getInt32(rv32::FFLAG_DZ),
					       lb->getInt32(0)));
	if (of)
		fl = lb->CreateOr(fl, lb->CreateSelect(any(of), lb->getInt32(rv32::FFLAG_OF),
						       lb->getInt32(0)));
	if (nx)
		fl = lb->CreateOr(fl, lb->CreateSelect(any(nx), lb->getInt32(rv32::FFLAG_NX),
						       lb->getInt32(0)));
	u32 const fcsr_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
	auto *cur = RvvStateLoad(VType::I32, fcsr_off, llvm::Align(4));
	RvvStateStore(VType::I32, fcsr_off, lb->CreateOr(cur, fl), llvm::Align(4));

	if (ins->finish)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
}


// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): `vfmerge.vfm` / `vfmv.v.f`.
//
// THE MASK IS AN OPERAND HERE, NOT A WRITE ENABLE. `vfmerge` writes EVERY body element --
// `vd[i] = v0[i] ? f[rs1] : vs2[i]` -- so `v0` feeds a SELECT, while the store is predicated on the
// ordinary active-lane rule (`e < vl`, with `vstart == 0` proved by the guard). Those are two
// different uses of the same register and they are deliberately built from two different helpers:
// `RvvArchMaskForUnit` for the operand, `RvvActiveLaneMask` for the commit. Using the write-enable
// form for both would leave `vs2`'s value out of the destination entirely.
//
// NO FP MACHINERY. This is a typed select and a broadcast: it rounds nothing, raises nothing, and
// needs no bracket. The SEW-32 NaN un-boxing is done with integer operations only, exactly as C2b's
// `vfmv.s.f` does and for the same reason -- an FP compare would raise NV on a signalling payload
// that this instruction must move unchanged.
void QIRToLLVM::Emit_vchunkfmerge(qir::InstVChunkFMerge *ins)
{
	TChunkAccount();
	if (ins->sew != 4 && ins->sew != 8)
		Panic("llvmgen: RVV float merge with an unsupported SEW");
	if (ins->bytes % ins->sew != 0)
		Panic("llvmgen: RVV float merge chunk is not a whole number of elements");
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (ins->merge && (size_t)ins->rs2 + ins->bytes > sizeof(CPUState)) ||
	    (size_t)ins->fo + sizeof(u64) > sizeof(CPUState))
		Panic("llvmgen: RVV float merge window lies outside CPUState");

	u32 const lanes = (u32)ins->bytes / ins->sew;
	u32 const bits = 8u * ins->sew;
	auto *ety = llvm::IntegerType::get(lctx, bits);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);

	// The F register is 64 bits wide whatever the SEW (RV32D), so the scalar is read as i64 and
	// narrowed. At SEW 32 an improperly NaN-boxed value reads as the canonical qNaN.
	auto *raw64 = AScopeState(lb->CreateAlignedLoad(
	    lb->getInt64Ty(), LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
						   ins->fo),
	    llvm::Align(8)));
	llvm::Value *scalar;
	if (ins->sew == 4) {
		auto *boxed = lb->CreateICmpEQ(
		    lb->CreateAnd(raw64, lb->getInt64(0xFFFFFFFF00000000ull)),
		    lb->getInt64(0xFFFFFFFF00000000ull));
		scalar = lb->CreateSelect(boxed, lb->CreateTrunc(raw64, ety),
					  llvm::ConstantInt::get(ety, rv32::F32_CANONICAL_NAN));
	} else {
		scalar = raw64;
	}
	llvm::Value *val = lb->CreateVectorSplat(lanes, scalar);
	if (ins->merge) {
		auto *old = AScopeState(lb->CreateAlignedLoad(
		    vty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rs2),
		    llvm::Align(16)));
		val = lb->CreateSelect(RvvArchMaskForUnit(lanes, ins->base), val, old);
	}
	AScopeState(lb->CreateMaskedStore(
	    val, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty), ins->rd), llvm::Align(16),
	    RvvActiveLaneMask(lanes, ins->base)));
	if (ins->finish)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
}

void QIRToLLVM::Emit_vfestimate(qir::InstVFEstimate *) { Panic("QCG-only estimate reached LLVM"); }
// ===============================================================================================
// C7 (2026-09-20): THE STRIDED AND INDEXED VECTOR MEMORY FORMS -- `vlse`/`vsse` and
// `vluxei`/`vloxei`/`vsuxei`/`vsoxei`.
//
// THE FIRST C7 DELIVERY, and the first route in this backend whose addresses are GUEST addresses
// rather than CPUState offsets. What distinguishes the strided family from the unit-stride one
// already lowered here is that consecutive elements are NOT contiguous: the address progression is
// `base + e * stride` with the stride from a scalar register, so a negative stride walks backwards
// and a zero stride reads the same address for every element. Both are legal and both are exercised.
//
// THE ADDRESS IS COMPUTED IN 32 BITS AND IS ALLOWED TO WRAP. The reference computes
// `base + e * (u32)stride` in `u32`, so a stride that carries past 2^32 wraps into the low address
// space -- and the guest's address space IS 32-bit. Computing the progression in 64 bits would not
// wrap and would address memory the guest cannot name. The zero-extension to the host pointer width
// happens AFTER the wrap, which is the same order `MakeVMemLoc` uses for a scalar address.
//
// ONE `masked.gather` / `masked.scatter` PER CHUNK. The element addresses are a vector, so the
// access is a gather by construction -- and the mask is the active-element predicate, which is what
// keeps a lane at or beyond `vl` from touching memory at all. That matters here in a way it does
// not for a register operation: an out-of-range lane would be a real access to a real address, so
// "compute it and discard it" is not available.
//
// THE INDEXED FORMS ARE THE SAME LOWERING WITH A DIFFERENT OFFSET VECTOR -- read from a vector
// register at the INDEX EEW instead of computed from a scalar stride. Everything else is shared:
// the 32-bit wrap, the active-element mask, the undisturbed destination tail.
//
// ORDERED INDEXED STORES ARE NOT ADMITTED, AND THAT IS A SEMANTIC LIMIT RATHER THAN AN EFFORT ONE.
// `vsoxei` requires that when two indices name the SAME address, the LAST element in order wins.
// `llvm.masked.scatter` leaves the order among enabled lanes unspecified, so it cannot express
// that. `vsuxei` -- the UNORDERED store -- has exactly the scatter's guarantee and is admitted, and
// both indexed LOADS are admitted because a load writes no memory and its order is unobservable.
//
// THE UNADMITTED MODES FAIL CLOSED. Unit-stride has its own lowering (`Emit_vchunkload` /
// `Emit_vstatechunkstore`), and the indexed, mask-byte, whole-register and segmented forms are not
// lowered here yet; each Panics rather than falling through to the strided address arithmetic,
// which would compute plausible addresses for the wrong instruction.
void QIRToLLVM::Emit_vmemorynative(qir::InstVMemory *ins)
{
	TChunkAccount();
	if (ins->mode != 1 && ins->mode != 2)
		Panic("llvmgen: only the strided and indexed vector memory modes are lowered here");
	if (ins->masked)
		Panic("llvmgen: masked strided vector memory has no lowering in this backend");
	if (ins->nf != 1)
		Panic("llvmgen: segmented strided vector memory has no lowering in this backend");
	u32 const eew = ins->sew;
	if (eew != 1 && eew != 2 && eew != 4 && eew != 8)
		Panic("llvmgen: strided vector memory with an unsupported EEW");
	u32 const regbytes = ins->regbytes;
	if (ins->vlmax == 0)
		Panic("llvmgen: strided vector memory with no guarded element count");
	// The route admits only a data group that fits ONE register; restate it fail-closed.
	if ((u32)ins->vlmax * eew > regbytes)
		Panic("llvmgen: strided vector memory data group spans a register group");
	u32 const bytes = std::min(64u, regbytes);
	if (bytes % eew != 0)
		Panic("llvmgen: strided vector memory chunk is not a whole number of elements");
	u32 const lanes = bytes / eew;
	u32 const base_off = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const slot = rv32::VLEN_MAX_BYTES;
	auto *i32ty = lb->getInt32Ty();
	auto *i64ty = lb->getInt64Ty();
	auto *ety = llvm::IntegerType::get(lctx, eew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto *v32 = llvm::FixedVectorType::get(i32ty, lanes);
	auto *v64 = llvm::FixedVectorType::get(i64ty, lanes);
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	auto *gbase = RvvStateLoad(VType::I32,
				   (u32)offsetof(CPUState, gpr) + (u32)ins->base * 4u,
				   llvm::Align(4));
	// `x0` reads zero, and a stride of zero is legal: every element then touches the SAME
	// address. The GPR file's slot 0 holds zero, so no special case is needed -- stated because
	// "stride 0 must be rejected" is a plausible and wrong instinct.
	llvm::Value *gstride = nullptr;
	if (ins->mode == 1)
		gstride = RvvStateLoad(VType::I32,
				       (u32)offsetof(CPUState, gpr) + (u32)ins->index * 4u,
				       llvm::Align(4));
	for (u32 first = 0; first < ins->vlmax; first += lanes) {
		llvm::SmallVector<llvm::Constant *, 64> ec;
		for (u32 i = 0; i < lanes; ++i)
			ec.push_back(llvm::ConstantInt::get(i32ty, first + i));
		auto *e32 = llvm::ConstantVector::get(ec);
		// THE OFFSET VECTOR IS THE ONLY THING THE TWO MODES DISAGREE ON.
		//
		//   strided  offset[e] = e * stride          the stride from a scalar register
		//   indexed  offset[e] = vs2[e]              a BYTE offset from a vector register
		//
		// Both are added to the same base and both wrap in 32 bits. The indexed offset is
		// read at the INDEX EEW, which is independent of the data EEW -- that separation is
		// the whole point of the indexed forms -- and is then narrowed to 32 bits exactly as
		// the reference's `(u32)off` cast does, so a 64-bit index contributes only its low
		// half.
		llvm::Value *offs;
		if (ins->mode == 1) {
			offs = lb->CreateMul(e32, lb->CreateVectorSplat(lanes, gstride));
		} else {
			u32 const isew = ins->isew;
			auto *ity = llvm::IntegerType::get(lctx, isew * 8u);
			auto *ivty = llvm::FixedVectorType::get(ity, lanes);
			auto *iv = AScopeState(lb->CreateAlignedLoad(
			    ivty,
			    LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ivty),
						 base_off + (u32)ins->index * slot + first * isew),
			    llvm::Align(16)));
			// Narrow to 32 bits exactly as the reference's `(u32)off` cast does: a
			// 64-bit index contributes only its low half, and a narrower one is
			// zero-extended (an index is a byte offset, never signed).
			offs = isew == 4   ? iv
			       : isew > 4  ? lb->CreateTrunc(iv, v32)
					   : lb->CreateZExt(iv, v32);
		}
		// `base + offset`, ALL IN 32 BITS so it wraps exactly as the guest's does.
		auto *addr = lb->CreateAdd(lb->CreateVectorSplat(lanes, gbase), offs);
		llvm::Value *ptrs;
		if constexpr (config::zero_membase) {
			ptrs = lb->CreateIntToPtr(
			    lb->CreateZExt(addr, v64),
			    llvm::FixedVectorType::get(
				llvm::PointerType::getUnqual(lb->getContext()), lanes));
		} else {
			ptrs = lb->CreateGEP(lb->getInt8Ty(), membasev, lb->CreateZExt(addr, v64));
		}
		auto *active = lb->CreateICmpULT(e32, lb->CreateVectorSplat(lanes, vl));
		auto *reg = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(vty),
						 base_off + (u32)ins->data * slot + first * eew);
		if (!ins->store) {
			// Align 1: the guest chooses the address and RVV imposes no alignment on a
			// strided element.
			auto *got = AScopeVMem(lb->CreateMaskedGather(
			    vty, ptrs, llvm::Align(1), active,
			    llvm::ConstantAggregateZero::get(vty)));
			// Elements at or beyond `vl` are UNDISTURBED in the destination register.
			AScopeState(lb->CreateMaskedStore(got, reg, llvm::Align(16), active));
		} else {
			auto *v = AScopeState(lb->CreateAlignedLoad(vty, reg, llvm::Align(16)));
			AScopeVMem(lb->CreateMaskedScatter(v, ptrs, llvm::Align(1), active));
		}
	}
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}
// W7 (2026-09-17): THE WHOLE-REGISTER MOVE `vmv<nr>r.v`.
//
// WHAT THE INSTRUCTION IS. RVV 1.0 section 16.6: `vmv1r.v` / `vmv2r.v` / `vmv4r.v` / `vmv8r.v` copy
// NREG whole vector registers. They are NOT element-wise: vl, LMUL, the mask register and the
// tail/mask policy bits play no part, and a complete transfer always moves NREG*VLEN bits. The only
// element-indexed quantity is `vstart`, whose unit here is the CURRENT SEW (this is the one place
// register moves differ from the whole-register MEMORY transfers, which use the encoded EEW).
//
// WHY THE FRAME'S GUARD IS `vlenb == expected && vstart == 0` (GuardKind::VlenbVstart).
//
//   * It is vtype-independent, which is what the operation is. Reusing a full-VL element-wise kind
//     (VTypeVlVstart) would make the fast arm conditional on `vl == VLMAX`, a quantity this
//     instruction is defined not to consult -- it would refuse ordinary executions and would encode
//     a false dependence. The semantic contract for this checkpoint forbids exactly that.
//   * `vstart == 0` is a DELIBERATE RESTRICTION OF THE NATIVE ENVELOPE, not an oversight. A
//     restartable body must convert `vstart` to a byte offset with the run-time `vtype.vsew` and
//     copy a byte-granular suffix -- QCG's Emit_vwholemove does precisely that, and the
//     `whole_reg_move` helper in rv32_vector_lower.h is its reference. That region is left to those
//     two, unchanged, because (a) the RVV 1.0 ratified text (v20240411) and the current ISA main
//     draft word the `vstart >= evl` case differently, so a second, independently written body is a
//     good way to manufacture a QCG/LLVM divergence in exactly the contested region, and (b) the
//     existing helper IS this project's recorded contract there. GuardKind::VlenbRestartable is the
//     kind that promises a restart-aware body; Emit_rvvtypedchunkbegin refuses it, and this route
//     never builds it.
//
// WHY A VTYPE-INDEPENDENT GUARD IS SOUND FOR THIS BODY. At `vstart == 0` both existing arms reduce
// to the same vtype-free transfer: QCG computes `vstart << vsew == 0` and copies
// `[0, nregs*regbytes)`; `whole_reg_move` computes `start == 0`, so every register's `offset` is 0
// and it copies `bytes` from each. The result is the full NREG*VLEN bits and does not depend on
// SEW, so nothing the guard omits can change it. That is the whole justification, and it is why the
// restriction above is what makes the omission safe rather than an unrelated simplification.
//
// STATE BOUNDARY, EXPLICITLY. Reads: `vec.vlenb` and `vec.vstart` (guard), and `regbytes` bytes of
// each of `vreg[src .. src+nregs)`. Writes: `regbytes` bytes of each of `vreg[rd .. rd+nregs)`, and
// `vec.vstart = 0`. No other CPUState field, no CSR, no guest memory, no fault, no trap. There is
// no mask read because the instruction has no mask operand (`vm` is 1 by decode).
//
// THE 512-BYTE PHYSICAL SLOT IS NOT THE ARCHITECTURAL REGISTER. CPUState reserves
// `rv32::VLEN_MAX_BYTES` for every vector register while only `VLEN/8` bytes of each slot are live,
// so a register group is NOT contiguous in CPUState. This copies exactly `regbytes` bytes per
// register and then steps a whole slot -- padding between the live prefix and the next register is
// never read and never written.
//
// OVERLAP IS IMPOSSIBLE, AND IS CHECKED RATHER THAN ASSUMED. `vd` and `vs2` are both required to be
// multiples of NREG (InstVWholeMove's constructor enforces it, and so does
// rv32::whole_reg_group_legal in the admission test), so two distinct aligned blocks of NREG
// registers are disjoint. That is what makes a per-chunk load-then-store legal without buffering
// the whole group; the explicit refusal below means a future change to either alignment rule fails
// here instead of miscompiling. `rd == src` copies nothing -- the architectural effect is then
// exactly `vstart = 0`, which is what QCG and the helper also do.
void QIRToLLVM::Emit_vwholemove(qir::InstVWholeMove *ins)
{
	TChunkAccount();
	u32 const regbytes = ins->regbytes;
	if (regbytes != config::vlen_bits / 8) {
		Panic("llvmgen: whole-register move width disagrees with this artifact's VLEN");
	}
	if (ins->rd != ins->src &&
	    (u32)ins->rd < (u32)ins->src + ins->nregs && (u32)ins->src < (u32)ins->rd + ins->nregs) {
		Panic("llvmgen: whole-register move groups overlap without being identical");
	}
	// One host vector chunk is the whole register when the register is narrower than 64 bytes,
	// and 64 bytes otherwise; VectorVTypeForBytes fails closed on anything else. `regbytes` is a
	// power of two in [16, 512] by InstVWholeMove's constructor, so the division is exact.
	u32 const chunk_bytes = regbytes < 64 ? regbytes : 64u;
	u32 const chunks_per_reg = regbytes / chunk_bytes;
	VType const chunk_ty = qir::VectorVTypeForBytes(chunk_bytes);
	// A representability bound, not a tuning knob: NREG <= 8 and a register is at most
	// VLEN_MAX_BYTES, so the product cannot exceed this by construction. It exists so that a
	// later widening of either bound fails here rather than expanding an unbounded straight-line
	// copy into one block.
	static constexpr u32 kMaxWholeMoveChunks = 8u * (rv32::VLEN_MAX_BYTES / 64u);
	if ((u32)ins->nregs * chunks_per_reg > kMaxWholeMoveChunks) {
		Panic("llvmgen: whole-register move exceeds the admitted chunk count");
	}
	u32 const vregs = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	if (ins->rd != ins->src) {
		for (u32 r = 0; r < ins->nregs; ++r) {
			u32 const sbase = vregs + (ins->src + r) * rv32::VLEN_MAX_BYTES;
			u32 const dbase = vregs + (ins->rd + r) * rv32::VLEN_MAX_BYTES;
			for (u32 c = 0; c < chunks_per_reg; ++c) {
				u32 const off = c * chunk_bytes;
				// Align 16, not `chunk_bytes`: VectorState::vreg is alignas(16) and
				// VLEN_MAX_BYTES is a multiple of 16, so 16 is the alignment actually
				// guaranteed -- the same bound RvvLoadGroup/RvvStoreGroup use for their
				// identical CPUState windows.
				RvvStateStore(chunk_ty, dbase + off,
					      RvvStateLoad(chunk_ty, sbase + off, llvm::Align(16)),
					      llvm::Align(16));
			}
		}
	}
	// The architectural `vstart = 0`. The guard has already proved vstart is zero, so this store
	// is redundant TODAY -- it is emitted anyway because it is a real architectural effect of the
	// instruction and the contract requires the state boundary to be visible in the IR. If the
	// guard is ever weakened, the effect stays correct here instead of silently disappearing.
	RvvStateStore(VType::I32,
		      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}
// W6 (2026-09-17): THE ORDERED FLOATING REDUCTION.
//
// A STRICT LEFT FOLD, SPELLED OUT. RVV's `vfredosum.vs` is seed, then element 0, then element 1,
// ... each step one IEEE addition in the dynamic rounding mode. This emits exactly that chain of
// scalar `llvm.experimental.constrained.fadd` calls. It deliberately does NOT use
// `llvm.vector.reduce.fadd`: LLVM has no CONSTRAINED reduction intrinsic, so a reduce intrinsic
// could not carry `round.dynamic` + `fpexcept.strict`, and its unordered form would be a different
// function entirely. There are no low/high partial sums recombined here and no reassociation --
// the accumulator dependence is the operation.
//
// THE ADDRESSING IS THE GUEST'S, NOT A FLAT ARRAY. A register group is logically contiguous but
// rvdbt stores each vector register in its own `VLEN_MAX_BYTES` slot, so element i of the group
// lives at `(data + i*sew / regbytes) * slot + (i*sew % regbytes)` -- the same arithmetic the QCG
// body computes at run time, done here at translation time because the guard has already proved
// `vl == VLMAX`.
//
// WHAT THE GUARD MAKES UNREACHABLE. `vl == 0` (architecturally: leave the destination alone) cannot
// arrive, because VLMAX is at least one for every supported vtype and the frame guard proves
// `vl == VLMAX`; such an execution takes the ordered fallback instead. Masked, widening and
// min/max shapes are refused in admission, so the three Panics below are enforcement of an
// envelope, not unimplemented cases.
void QIRToLLVM::Emit_vfreducenative(qir::InstVFReduce *ins)
{
	// One typed member of the open group, exactly as every other typed body op accounts itself.
	TChunkAccount();
	if (ins->masked || ins->wide || ins->op != 0)
		Panic("llvmgen: floating reduction shape outside the admitted LLVM envelope");
	if (ins->vlmax == 0)
		Panic("llvmgen: ordered floating reduction with no guarded element count");
	if (ins->sew != 4 && ins->sew != 8)
		Panic("llvmgen: ordered floating reduction at an unsupported SEW");

	u32 const base = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const slot = rv32::VLEN_MAX_BYTES;
	u32 const regbytes = ins->regbytes;
	auto *fty = ins->sew == 4 ? lb->getFloatTy() : lb->getDoubleTy();
	// A scalar element, not a chunk: the typed-pointer idiom, since the QIR value types this
	// backend carries are vectors and masks and there is no scalar FP VType to name here.
	auto elem = [&](u32 off) {
		return lb->CreateAlignedLoad(fty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(fty), off),
					     llvm::Align((u64)ins->sew));
	};

	// The seed is element 0 of vs1, read once, before any addition.
	llvm::Value *acc = elem(base + (u32)ins->seed * slot);

	for (u32 i = 0; i < ins->vlmax; ++i) {
		u32 const byte = i * ins->sew;
		u32 const off = base + ((u32)ins->data + byte / regbytes) * slot + byte % regbytes;
		acc = RvvConstrainedFPCall(llvm::Intrinsic::experimental_constrained_fadd, fty,
					   {acc, elem(off)});
	}

	// The same canonical quiet NaN the helper arm produces through vf_write -> f{32,64}_canon.
	// The QCG body canonicalises only after an actual addition, so that an all-masked reduction
	// copies the seed bit-exactly; here at least one addition always happens (unmasked, vl == VLMAX
	// >= 1), so the canonicalisation is unconditional and the two arms still agree.
	//
	// PURE INTEGER CLASSIFICATION, NOT AN FP COMPARE. An `fcmp` here would be an UNCONSTRAINED
	// floating-point operation inside a function this route marks strictfp -- the one thing the
	// constrained-intrinsic discipline exists to exclude -- and it would introduce a comparison
	// whose exception behaviour is not covered by the frame's bracket. So the test is done on the
	// bits, exactly as the QCG body does it: mask the sign off and compare the magnitude against
	// the infinity encoding as an UNSIGNED INTEGER; anything greater is a NaN.
	auto *ity = ins->sew == 4 ? lb->getInt32Ty() : lb->getInt64Ty();
	auto *bits = lb->CreateBitCast(acc, ity);
	auto *absbits = lb->CreateAnd(bits, llvm::ConstantInt::get(
		ity, ins->sew == 4 ? 0x7fffffffull : 0x7fffffffffffffffull));
	auto *isnan = lb->CreateICmpUGT(absbits, llvm::ConstantInt::get(
		ity, ins->sew == 4 ? 0x7f800000ull : 0x7ff0000000000000ull));
	auto *out = lb->CreateSelect(isnan, llvm::ConstantInt::get(
		ity, ins->sew == 4 ? (u64)rv32::F32_CANONICAL_NAN : (u64)rv32::F64_CANONICAL_NAN), bits);

	// RVV writes the scalar result to element 0 of vd and leaves the rest of vd alone. Stored as
	// the integer it now is -- the destination is bytes, and this keeps the FP value out of any
	// further unconstrained operation.
	lb->CreateAlignedStore(out, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ity),
							base + (u32)ins->rd * slot),
			       llvm::Align((u64)ins->sew));
}
// ===============================================================================================
// C6 (2026-09-19): THE MASK PREFIX FAMILY `vmsbf.m` / `vmsif.m` / `vmsof.m`.
//
// SET-BEFORE-FIRST, SET-INCLUDING-FIRST, SET-ONLY-FIRST. All three are functions of ONE number --
// the index `f` of the first active set bit -- and once that is known each destination bit is a
// comparison against it:
//
//     vmsbf: bit e = (e <  f)      vmsif: bit e = (e <= f)      vmsof: bit e = (e == f)
//
// which is why this is not the serial scan the reference writes. The reference's `seen` flag and
// these three comparisons describe the same function; the flag form is the readable one for a
// scalar loop and the comparison form is the one a vector unit can evaluate in parallel.
//
// `f` IS COMPUTED EXACTLY AS `vfirst.m` COMPUTES IT, including the backwards word scan, and the
// "no active set bit" answer is the SAME sentinel: all-ones. That is not a coincidence to be
// tidied away -- read as UNSIGNED, `0xffffffff` is larger than any element index, so
// `e < f` and `e <= f` are true everywhere and `e == f` is false everywhere, which is precisely
// what the spec says for an empty mask. The sentinel does the work; there is no special case.
//
// BITS AT OR BEYOND `vl` ARE UNDISTURBED, so each word is a BLEND, exactly as the mask logical
// family's is.
void QIRToLLVM::Emit_vmaskprefix(qir::InstVMaskPrefix *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked mask-prefix op has no lowering in this backend");
	if (ins->kind > 2)
		Panic("llvmgen: mask-prefix op outside the three sub-encodings");
	if (ins->vlmax == 0 || ins->vlmax > 4096u)
		Panic("llvmgen: mask-prefix op with no guarded element count");
	auto *i64ty = lb->getInt64Ty();
	u32 const words = (ins->vlmax + 63u) / 64u;
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	auto indices = [&](u32 c) {
		llvm::SmallVector<llvm::Constant *, 64> idx;
		for (u32 i = 0; i < 64; ++i)
			idx.push_back(lb->getInt32(c * 64u + i));
		return llvm::ConstantVector::get(idx);
	};
	auto word = [&](u32 off, u32 c) {
		return AScopeState(lb->CreateAlignedLoad(
		    i64ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), off + c * 8u),
		    llvm::Align(8)));
	};
	// `f`: the first ACTIVE set bit, all-ones when there is none.
	//
	// THE ACTIVE-LANE AND BELOW IS PROVABLY REDUNDANT, AND IS KEPT ANYWAY. If a set bit exists
	// below `vl` the two scans agree. If none does, the unmasked scan finds some `j >= vl` where
	// the masked one finds the sentinel -- and for every `e < vl`, `e < j` and `e <= j` hold and
	// `e == j` does not, which is exactly what the sentinel gives. No destination bit can differ,
	// and the mutation gate confirms it: removing the AND is inert, so it is recorded there as a
	// second CONTROL rather than as an uncaught defect.
	//
	// It stays because the redundancy is CONDITIONAL: it holds only because the destination blend
	// below is also masked by `idx < vl`. The AND says what `f` is meant to be -- the first bit of
	// the ACTIVE mask -- and becomes load-bearing the moment that blend changes. Contrast
	// `Emit_vmaskscalar`, where the same AND is load-bearing today, because `vfirst`'s result goes
	// to a GPR with no blend in front of it.
	auto *ctz = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::cttz,
							    {i64ty});
	llvm::Value *f = lb->getInt32(0xffffffffu);
	for (u32 k = words; k-- > 0;) {
		auto *act = lb->CreateBitCast(
		    lb->CreateICmpULT(indices(k), lb->CreateVectorSplat(64, vl)), i64ty);
		auto *w = lb->CreateAnd(word(ins->source, k), act);
		auto *cand = lb->CreateAdd(
		    lb->CreateTrunc(lb->CreateCall(ctz, {w, lb->getInt1(false)}), lb->getInt32Ty()),
		    lb->getInt32(k * 64u));
		f = lb->CreateSelect(lb->CreateICmpNE(w, llvm::ConstantInt::get(i64ty, 0)), cand, f);
	}
	// SOURCE WORDS ARE ALL READ BEFORE ANY DESTINATION WORD IS WRITTEN -- above, in the scan.
	// `vd == vs2` is refused by the node (`rd == source` Panics), but the ordering is what makes
	// the result independent of it either way.
	auto *fs = lb->CreateVectorSplat(64, f);
	for (u32 c = 0; c < words; ++c) {
		auto *idx = indices(c);
		llvm::Value *bits;
		switch (ins->kind) {
		case 0: bits = lb->CreateICmpULT(idx, fs); break;  // vmsbf
		case 1: bits = lb->CreateICmpULE(idx, fs); break;  // vmsif
		default: bits = lb->CreateICmpEQ(idx, fs); break;  // vmsof
		}
		auto *m = lb->CreateBitCast(
		    lb->CreateICmpULT(idx, lb->CreateVectorSplat(64, vl)), i64ty);
		auto *r = lb->CreateBitCast(bits, i64ty);
		auto *d = word(ins->rd, c);
		auto *out = lb->CreateOr(lb->CreateAnd(r, m), lb->CreateAnd(d, lb->CreateNot(m)));
		AScopeState(lb->CreateAlignedStore(
		    out, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(i64ty), ins->rd + c * 8u),
		    llvm::Align(8)));
	}
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}
// C3 (2026-09-18). THE INTEGER EXTENSION FAMILY `vzext.vf{2,4,8}` / `vsext.vf{2,4,8}`.
//
// One unit of the frame: read `bytes * src_sew / dst_sew` source bytes as `<lanes x i(8*src_sew)>`,
// widen each lane to `i(8*dst_sew)`, and commit `bytes` destination bytes under this unit's active
// mask. `lanes = bytes / dst_sew`, which is the DESTINATION element count -- RVV leaves element
// INDEXING alone, so destination element i comes from source element i and `vl` counts elements at
// the destination width. Using the source width here would multiply the element stride by the
// extension factor and mask the wrong lanes.
//
// SIGNEDNESS IS THE WHOLE OPERATION. `vsext` sign-extends and `vzext` zero-extends; the node's
// `sign` flag picks `sext` or `zext` and getting it backwards is a silent miscompile on every
// negative (or high-bit-set) source lane, with an identical instruction count.
//
// THE ACTIVE MASK IS THIS UNIT'S, NOT THE CHUNK-INDEX ONE. The node carries `base`, the unit's first
// architectural element index (`rvvfinal::ElementBase`), so the predicate is `base + i < vec.vl`
// read at run time. A unit whose base is at or beyond `vl` writes nothing.
//
// MASKED FORMS ARE REFUSED, and the refusal is real rather than a comment: this backend has no
// lowering for the architectural mask register at all (`Emit_vchunkmaskset` Panics), so a masked
// extension keeps the unchanged `rv32_vext` helper. The admission predicate must therefore not offer
// one; this Panic is the fail-closed proof that it does not.
//
// `finish` IS THE FRAME'S vstart WRITE. This family uses the LastChunkNode convention: exactly the
// last unit carries `vstart = 0`. Emitting it anywhere else -- or on every unit -- would disagree
// with the geometry the finalizer checked.
void QIRToLLVM::Emit_vchunkextend(qir::InstVChunkExtend *ins)
{
	TChunkAccount();
	if (ins->masked) {
		Panic("llvmgen: masked integer extension has no lowering in this backend");
	}
	u32 const input_bytes = (u32)ins->bytes * ins->src_sew / ins->dst_sew;
	if ((size_t)ins->rd + ins->bytes > sizeof(CPUState) ||
	    (size_t)ins->rs2 + input_bytes > sizeof(CPUState)) {
		Panic("llvmgen: extension window lies outside CPUState");
	}
	if (ins->src_sew >= ins->dst_sew || ins->bytes % ins->dst_sew != 0) {
		Panic("llvmgen: integer extension has an impossible shape");
	}
	u32 const lanes = (u32)ins->bytes / ins->dst_sew;
	auto *src_ty = llvm::FixedVectorType::get(
	    llvm::IntegerType::get(lctx, 8u * ins->src_sew), lanes);
	auto *dst_ty = llvm::FixedVectorType::get(
	    llvm::IntegerType::get(lctx, 8u * ins->dst_sew), lanes);

	auto *src = AScopeState(lb->CreateAlignedLoad(
	    src_ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(src_ty), ins->rs2),
	    llvm::Align(16)));
	auto *wide = ins->sign ? lb->CreateSExt(src, dst_ty) : lb->CreateZExt(src, dst_ty);

	// This unit's active-lane predicate, from the LIVE vl: lane i is element `base + i`.
	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 i = 0; i < lanes; ++i)
		idx.push_back(lb->getInt32(ins->base + i));
	auto *mask = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
				       lb->CreateVectorSplat(lanes, vl));
	AScopeState(lb->CreateMaskedStore(
	    wide, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(dst_ty), ins->rd),
	    llvm::Align(16), mask));

	if (ins->finish) {
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
	}
}
// C3 (2026-09-18). THE WIDENING INTEGER FAMILY: `vwadd`, `vwsub`, `vwmul`, `vwmacc` and their
// unsigned / mixed-sign / `.wv` / `.wx` variants.
//
// One unit: destination element width is `ds = 2 * sew`, so `lanes = bytes / ds` is the DESTINATION
// element count -- the same rule the extension family follows and for the same reason (RVV leaves
// element indexing alone, and `vl` counts destination elements).
//
// THE TWO SOURCES ARE EXTENDED INDEPENDENTLY, which is the whole point of the mixed-sign forms.
// `sign2` governs vs2 and `sign1` governs vs1; `vwaddu.wv` and friends set `wide2`, meaning vs2 is
// ALREADY at the destination width and must be loaded, not extended. Getting either signedness or
// the `wide2` flag wrong is a silent miscompile with an identical instruction count, which is what
// the focused test reads out of the IR rather than counting.
//
// THE `.vx` SCALAR IS NOT SIMPLY THE GPR WORD. RVV takes the low SEW bits of the XLEN register and
// then extends them to the destination width, so the lowering is truncate-to-`sew` then
// sext/zext-to-`ds` -- uniformly, for every SEW. That reproduces QEmit exactly: `movsx rax, al` /
// `movsx rax, ax` / `movsxd rax, eax` for the signed cases and `and 0xff` / `and 0xffff` / the
// implicit 32-bit zero extension for the unsigned ones. `zero` is the `rs1 == x0` case, which reads
// as zero without touching the register file.
//
// `vwmacc` ACCUMULATES INTO THE OLD DESTINATION: the node's `op == Macc` adds the current `vd`
// AFTER the product, exactly as QEmit emits a second `vpadd` from the destination window. It is
// therefore the one kind of this family that READS vd, and the read happens before the masked
// commit below.
//
// NO nuw/nsw ANYWHERE. A widened product cannot overflow its 2*SEW destination, but a `vwmacc`
// accumulate certainly can, and RVV wraps. The IRBuilder defaults to no flags; this comment exists
// so that stays a decision rather than an accident.
//
// MASKED FORMS ARE REFUSED -- no architectural-mask lowering exists in this backend -- and `finish`
// carries the frame's single `vstart = 0` under the LastChunkNode convention, exactly as in the
// extension family.
void QIRToLLVM::Emit_vchunkwiden(qir::InstVChunkWiden *ins)
{
	using N = qir::InstVChunkWiden;
	TChunkAccount();
	if (ins->masked) {
		Panic("llvmgen: masked integer widening has no lowering in this backend");
	}
	u32 const ss = ins->sew, ds = 2u * ins->sew, bytes = ins->bytes;
	if (ss != 1 && ss != 2 && ss != 4) {
		Panic("llvmgen: integer widening with an unsupported source SEW");
	}
	if (bytes % ds != 0) {
		Panic("llvmgen: integer widening chunk is not a whole number of destination elements");
	}
	if ((size_t)ins->rd + bytes > sizeof(CPUState) ||
	    (size_t)ins->rs2 + (ins->wide2 ? bytes : bytes / 2) > sizeof(CPUState) ||
	    (size_t)ins->rs1 + (ins->scalar ? 4u : bytes / 2) > sizeof(CPUState)) {
		Panic("llvmgen: widening window lies outside CPUState");
	}
	u32 const lanes = bytes / ds;
	auto *src_ty = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, 8u * ss), lanes);
	auto *dst_ty = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, 8u * ds), lanes);
	auto *dst_lane = llvm::IntegerType::get(lctx, 8u * ds);

	auto load_vec = [&](llvm::Type *ty, u32 off) {
		return AScopeState(lb->CreateAlignedLoad(
		    ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ty), off), llvm::Align(16)));
	};
	auto widen = [&](u32 off, bool sign) -> llvm::Value * {
		auto *v = load_vec(src_ty, off);
		return sign ? lb->CreateSExt(v, dst_ty) : lb->CreateZExt(v, dst_ty);
	};

	// vs2: already wide for the `.wv`/`.wx` forms, extended otherwise.
	llvm::Value *a = ins->wide2 ? load_vec(dst_ty, ins->rs2) : widen(ins->rs2, ins->sign2);

	// vs1: a broadcast scalar for `.vx`, an extended vector otherwise.
	llvm::Value *b;
	if (ins->scalar) {
		llvm::Value *word = ins->zero ? (llvm::Value *)lb->getInt32(0)
					      : RvvStateLoad(VType::I32, ins->rs1, llvm::Align(4));
		// low SEW bits, then extend to the destination width -- see the block comment.
		auto *narrow = lb->CreateTrunc(word, llvm::IntegerType::get(lctx, 8u * ss));
		auto *ext = ins->sign1 ? lb->CreateSExt(narrow, dst_lane)
				       : lb->CreateZExt(narrow, dst_lane);
		b = lb->CreateVectorSplat(lanes, ext);
	} else {
		b = widen(ins->rs1, ins->sign1);
	}

	llvm::Value *r;
	switch (ins->op) {
	case N::Add:
		r = lb->CreateAdd(a, b);
		break;
	case N::Sub:
		r = lb->CreateSub(a, b);
		break;
	case N::Mul:
	case N::Macc:
		r = lb->CreateMul(a, b);
		break;
	default:
		Panic("llvmgen: integer widening with an unknown lane operation");
	}
	if (ins->op == N::Macc) {
		// reads the OLD destination, before the commit below
		r = lb->CreateAdd(r, load_vec(dst_ty, ins->rd));
	}

	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 i = 0; i < lanes; ++i)
		idx.push_back(lb->getInt32(ins->base + i));
	auto *mask = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
				       lb->CreateVectorSplat(lanes, vl));
	AScopeState(lb->CreateMaskedStore(
	    r, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(dst_ty), ins->rd), llvm::Align(16),
	    mask));

	if (ins->finish) {
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
	}
}
// C3 (2026-09-18). THE NARROWING SHIFTS `vnsrl` / `vnsra`.
//
// `vnclip` IS NOT HERE and keeps its helper: the QCG route lowers it through
// `InstVChunkPartialAlu` (Kind::ClipU/ClipS), the 52-kind partial-arm node whose LLVM emitter
// Panics. Saturation is therefore listed as INCOMPLETE native support rather than approximated.
//
// SHAPE. `sew` on this node is the DESTINATION element width in bytes and `bytes` is the WIDE
// SOURCE chunk; the destination occupies `bytes/2`. So the source element width is `ss = 2*sew` and
// `lanes = bytes/ss` is, once again, the destination element count -- the quantity `vl` counts.
//
// THE SHIFT AMOUNT IS REDUCED MODULO 2*SEW, i.e. modulo the SOURCE width, not the destination's.
// RVV 1.0 12.3: a narrowing shift uses the low lg2(2*SEW) bits. QEmit spells that as a
// shift-left-then-right pair by `ss*8 - lg2(ss*8)` for the vector form and an `and` for the scalar
// and immediate forms; both are the same mask, and this emits the `and` uniformly. Using SEW here
// instead of 2*SEW would silently drop the top bit of a legal shift count.
//
// SIGNEDNESS: `arith` selects `ashr` (vnsra) over `lshr` (vnsrl). The narrowing store TRUNCATES --
// `vpmovwb`/`vpmovdw`/`vpmovqd` in QEmit -- so this is `trunc`, never a saturating pack; that
// distinction is exactly what separates `vnsrl`/`vnsra` from `vnclip`.
//
// Masked forms are refused (no architectural-mask lowering) and `finish` carries the frame's single
// `vstart = 0`, as in the other C3 families.
void QIRToLLVM::Emit_vchunknarrowshift(qir::InstVChunkNarrowShift *ins)
{
	TChunkAccount();
	if (ins->masked) {
		Panic("llvmgen: masked narrowing shift has no lowering in this backend");
	}
	u32 const ds = ins->sew, ss = 2u * ins->sew, bytes = ins->bytes;
	if (ds != 1 && ds != 2 && ds != 4) {
		Panic("llvmgen: narrowing shift with an unsupported destination SEW");
	}
	if (bytes % ss != 0) {
		Panic("llvmgen: narrowing shift chunk is not a whole number of source elements");
	}
	if ((size_t)ins->rd + bytes / 2 > sizeof(CPUState) ||
	    (size_t)ins->rs2 + bytes > sizeof(CPUState) ||
	    (size_t)ins->rs1 + (ins->src == 0 ? bytes / 2 : 4u) > sizeof(CPUState)) {
		Panic("llvmgen: narrowing shift window lies outside CPUState");
	}
	u32 const lanes = bytes / ss;
	auto *wide_ty = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, 8u * ss), lanes);
	auto *narrow_ty = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, 8u * ds), lanes);
	auto *wide_lane = llvm::IntegerType::get(lctx, 8u * ss);

	auto load_vec = [&](llvm::Type *ty, u32 off) {
		return AScopeState(lb->CreateAlignedLoad(
		    ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ty), off), llvm::Align(16)));
	};
	auto *a = load_vec(wide_ty, ins->rs2);

	// The shift amount, at the SOURCE width, reduced modulo 2*SEW.
	llvm::Value *amt;
	if (ins->src == 0) {
		amt = lb->CreateZExt(load_vec(narrow_ty, ins->rs1), wide_ty);
	} else {
		llvm::Value *word = ins->src == 1
					? RvvStateLoad(VType::I32, ins->rs1, llvm::Align(4))
					: (llvm::Value *)lb->getInt32(ins->imm);
		auto *lane = ss >= 4 ? lb->CreateZExt(word, wide_lane)
				     : (llvm::Value *)lb->CreateTrunc(word, wide_lane);
		amt = lb->CreateVectorSplat(lanes, lane);
	}
	amt = lb->CreateAnd(amt, lb->CreateVectorSplat(
				     lanes, llvm::ConstantInt::get(wide_lane, 8u * ss - 1u)));

	auto *shifted = ins->arith ? lb->CreateAShr(a, amt) : lb->CreateLShr(a, amt);
	// TRUNCATING narrow, not a saturating pack -- see the block comment.
	auto *narrowed = lb->CreateTrunc(shifted, narrow_ty);

	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 i = 0; i < lanes; ++i)
		idx.push_back(lb->getInt32(ins->base + i));
	auto *mask = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
				       lb->CreateVectorSplat(lanes, vl));
	AScopeState(lb->CreateMaskedStore(
	    narrowed, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(narrow_ty), ins->rd),
	    llvm::Align(16), mask));

	if (ins->finish) {
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
	}
}
// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE NARROWING CLIP -- `vnclipu.w*` / `vnclip.w*`.
//
// LAST OF THE FIVE NARROW FIXED-POINT NODES, and the only one that is all three mechanisms at once:
// a 2*SEW source narrowed to SEW, a `vxrm` rounding shift, and a saturating clip into `vxsat`.
//
// THE SHIFT IS A RUNTIME VECTOR. `.wv` takes one amount per element, so this is the caller that
// forced `RvvRoundoffIncrement` to be generalised from a compile-time shift to a value. Generalising
// it rather than giving the clip its own rounding rule is the whole reason the four families still
// agree; the constant callers now forward into the same code.
//
// THE SIGNEDNESS PICKS BOTH THE EXTENSION AND THE BOUNDS, and they are not independent.
// `vnclipu` reads the wide source UNSIGNED, shifts LOGICALLY, and clips to [0, 2^SEW - 1] -- the
// low bound cannot be crossed, so only the high one is tested. `vnclip` reads it SIGNED, shifts
// ARITHMETICALLY, and clips to both signed bounds. Mixing a signed shift with unsigned bounds, or
// the reverse, produces plausible output on small operands and is wrong at the extremes.
//
// AND THE SHIFT HERE IS OBSERVABLE, unlike the averaging family's. That node's `ashr`-vs-`lshr`
// distinction vanished under the truncation back to SEW; here the result is taken from the HIGH
// bits of a variable shift, so the two differ in the delivered value.
void QIRToLLVM::Emit_vchunknarrowclip(qir::InstVChunkNarrowClip *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked narrowing clip has no lowering in this backend");
	u32 const ds = ins->sew, ss = 2u * ins->sew, bytes = ins->bytes;
	if (ds != 1 && ds != 2 && ds != 4)
		Panic("llvmgen: narrowing clip with an unsupported destination SEW");
	if (bytes % ss != 0)
		Panic("llvmgen: narrowing clip chunk is not a whole number of source elements");
	if ((size_t)ins->rd + bytes / 2 > sizeof(CPUState) ||
	    (size_t)ins->rs2 + bytes > sizeof(CPUState) ||
	    (size_t)ins->rs1 + (ins->src == 0 ? bytes / 2 : 4u) > sizeof(CPUState))
		Panic("llvmgen: narrowing clip window lies outside CPUState");
	u32 const lanes = bytes / ss;
	auto *wide_lane = llvm::IntegerType::get(lctx, 8u * ss);
	auto *wide_ty = llvm::FixedVectorType::get(wide_lane, lanes);
	auto *narrow_ty = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, 8u * ds), lanes);

	auto load_vec = [&](llvm::Type *ty, u32 off) {
		return AScopeState(lb->CreateAlignedLoad(
		    ty, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(ty), off), llvm::Align(16)));
	};
	auto *a = load_vec(wide_ty, ins->rs2);

	// The shift amount, at the SOURCE width, reduced modulo 2*SEW -- the same derivation the
	// narrowing shift uses, because it is the same ISA rule.
	llvm::Value *amt;
	if (ins->src == 0) {
		amt = lb->CreateZExt(load_vec(narrow_ty, ins->rs1), wide_ty);
	} else {
		llvm::Value *word = ins->src == 1
					? RvvStateLoad(VType::I32, ins->rs1, llvm::Align(4))
					: (llvm::Value *)lb->getInt32(ins->imm);
		auto *lane = ss >= 4 ? lb->CreateZExt(word, wide_lane)
				     : (llvm::Value *)lb->CreateTrunc(word, wide_lane);
		amt = lb->CreateVectorSplat(lanes, lane);
	}
	amt = lb->CreateAnd(amt, lb->CreateVectorSplat(
				     lanes, llvm::ConstantInt::get(wide_lane, 8u * ss - 1u)));

	auto wsplat = [&](llvm::APInt const &c) {
		return llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes),
						      llvm::ConstantInt::get(wide_lane, c));
	};
	auto *shifted = ins->is_signed ? lb->CreateAShr(a, amt) : lb->CreateLShr(a, amt);
	auto *r = lb->CreateAdd(shifted, RvvRoundoffIncrement(a, amt));
	llvm::Value *hi, *lo, *clamped;
	if (ins->is_signed) {
		auto *smax = wsplat(llvm::APInt::getSignedMaxValue(8u * ds).sext(8u * ss));
		auto *smin = wsplat(llvm::APInt::getSignedMinValue(8u * ds).sext(8u * ss));
		hi = lb->CreateICmpSGT(r, smax);
		lo = lb->CreateICmpSLT(r, smin);
		clamped = lb->CreateSelect(hi, smax, lb->CreateSelect(lo, smin, r));
	} else {
		auto *umax = wsplat(llvm::APInt::getMaxValue(8u * ds).zext(8u * ss));
		hi = lb->CreateICmpUGT(r, umax);
		// THE LOW BOUND CANNOT BE CROSSED, and this is a statement rather than an omission:
		// the source is read unsigned, the shift is logical and the increment is 0 or 1, so
		// `r` is never negative. The reference tests only the high bound for the same reason.
		lo = llvm::ConstantVector::getSplat(
		    llvm::ElementCount::getFixed(lanes), lb->getInt1(false));
		clamped = lb->CreateSelect(hi, umax, r);
	}
	auto *narrowed = lb->CreateTrunc(clamped, narrow_ty);

	auto *vl = RvvStateLoad(VType::I32, offsetof(CPUState, vec) +
					       offsetof(rv32::VectorState, vl), llvm::Align(4));
	llvm::SmallVector<llvm::Constant *, 64> idx;
	for (u32 i = 0; i < lanes; ++i)
		idx.push_back(lb->getInt32(ins->base + i));
	auto *mask = lb->CreateICmpULT(llvm::ConstantVector::get(idx),
				       lb->CreateVectorSplat(lanes, vl));
	// `vxsat` IS GATED BY THE SAME PREDICATE THE STORE IS. A lane past `vl` is not operated on,
	// so its clip must not reach the architectural flag -- the rule the saturating add/sub and
	// the fractional multiply already follow, applied to this family's own store mask rather
	// than to a separately derived one.
	auto *mask_ty = llvm::IntegerType::get(lctx, lanes);
	auto *any = lb->CreateICmpNE(
	    lb->CreateBitCast(lb->CreateAnd(lb->CreateOr(hi, lo), mask), mask_ty),
	    llvm::ConstantInt::get(mask_ty, 0));
	u32 const vxsat_off = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vxsat));
	auto *cur = RvvStateLoad(VType::I32, vxsat_off, llvm::Align(4));
	RvvStateStore(VType::I32, vxsat_off,
		      lb->CreateOr(cur, lb->CreateSelect(any, lb->getInt32(1), lb->getInt32(0))),
		      llvm::Align(4));

	AScopeState(lb->CreateMaskedStore(
	    narrowed, LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(narrow_ty), ins->rd),
	    llvm::Align(16), mask));

	if (ins->finish)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
}

void QIRToLLVM::Emit_rvvtypedchunkpartial(qir::InstRVVTypedChunkPartial *) { Panic("QCG-only partial-vl op reached LLVM"); }
void QIRToLLVM::Emit_rvvrunscalar(qir::InstRVVRunScalar *)
{
	Panic("QCG-only scalar RVV-run member reached LLVM");
}

// P7N-B. QCG-ONLY, and the Panic is the enforcement rather than a note. The shift route's admission
// predicate requires !aot_use_llvm, so the LLVM backend can never construct these nodes; if one ever
// arrives here it means an admission gate was widened without a lowering being written, and a
// silent wrong answer is the alternative to this abort.
// C3 (2026-09-18). THE TWO IMMEDIATE-SHIFT LANE OPERATIONS, `vsll.vi` and `vsrl.vi`.
//
// SHIFT-COUNT MASKING IS ALREADY DONE, AND IS RE-CHECKED RATHER THAN RE-APPLIED. RVV 1.0 12.6: a
// shift uses only the low lg2(SEW) bits of the amount. `InstVChunkSll`/`InstVChunkSrl` reduce it in
// their CONSTRUCTOR (`shamt & (8*sew_bytes - 1)`), so by the time a node reaches a backend the
// amount is already in range. Re-masking here would hide a producer that forgot; QEmit Panics on an
// unreduced amount for exactly that reason and this does the same. It also means the shift can
// never be a poison-producing over-shift, which is what lets the plain `shl`/`lshr` below be used
// without a clamp.
//
// SIGNEDNESS. `vsll` is a logical left shift and `vsrl` a logical (zero-filling) right shift, so
// these are `shl` and `lshr`. `vsra` -- the ARITHMETIC right shift -- has no node here and keeps its
// helper; substituting `ashr` for either of these would be a silent miscompile on any negative lane.
//
// NO POISON-GENERATING FLAGS. `shl` gets neither `nuw` nor `nsw` and `lshr` does not get `exact`:
// RVV discards the bits shifted out, so a lane that overflows on the left or drops set bits on the
// right is ORDINARY behaviour, and any of those three flags would hand LLVM permission to fold such
// a lane to poison. The IRBuilder defaults to none; this comment exists so that stays a decision.
//
// LANE WIDTH is the chunk's own, exactly as TChunkAluLower derives it -- one expression for all
// three host widths, no per-width body, and a SEW the emitter cannot lower is a Panic rather than a
// substituted width.
llvm::Value *QIRToLLVM::TChunkShiftLower(bool left, u8 sew_bytes, u8 shamt, qir::VOperand src)
{
	if (sew_bytes != 4) {
		Panic("llvmgen: chunk shift with an unsupported SEW");
	}
	if (shamt >= 8u * sew_bytes) {
		Panic("llvmgen: chunk shift amount was not reduced modulo SEW");
	}
	VType const chunk_ty = src.GetType();
	if (!IsVectorVType(chunk_ty)) {
		Panic("llvmgen: chunk shift source is not a vector value");
	}
	u32 const lanes = VTypeToSize(chunk_ty) / sew_bytes;
	auto *lanety = llvm::FixedVectorType::get(lb->getInt32Ty(), lanes);
	auto *a = lb->CreateBitCast(TChunkUse(src), lanety);
	auto *amount = lb->CreateVectorSplat(lanes, lb->getInt32(shamt));
	auto *r = left ? lb->CreateShl(a, amount) : lb->CreateLShr(a, amount);
	return lb->CreateBitCast(r, MakeType(chunk_ty));
}

void QIRToLLVM::Emit_vchunksll(qir::InstVChunkSll *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkShiftLower(/*left=*/true, ins->sew_bytes, ins->shamt, ins->i(0)));
}

void QIRToLLVM::Emit_vchunksrl(qir::InstVChunkSrl *ins)
{
	TChunkAccount();
	TChunkDef(ins->o(0), TChunkShiftLower(/*left=*/false, ins->sew_bytes, ins->shamt, ins->i(0)));
}
// F3 (2026-09-16). THE TYPED FP FRAME'S FUSED LANE OPERATION.
//
// ONE `llvm.experimental.constrained.fma` PER LANE OP, AND THAT IS A CORRECTNESS REQUIREMENT
// RATHER THAN AN OPTIMISATION. RVV's fused forms round ONCE, over the infinitely precise product
// plus addend; the helper this frame falls back to computes them with `std::fma` /
// `softfp::op_fma`, which also rounds once. A separate `fmul` and `fadd` rounds TWICE and is a
// DIFFERENT FUNCTION -- it differs from the fused result on ordinary inputs, not only at the edges
// -- so the two arms of this frame would disagree. There is no mul+add decomposition anywhere
// below, and `llvm.experimental.constrained.fmuladd` (which LLVM is permitted to split) is
// deliberately NOT the intrinsic used: only `.fma` is contractually single-rounded.
//
// THE OPERAND NAMES, taken from the node and NOT re-derived: `i(0)` is the OLD vd, `i(1)` is `b`
// (the vs1 chunk in `.vv`, the frame-scope F broadcast in `.vf`) and `i(2)` is `a` (the vs2 chunk).
// RvvEmitChunkLaneOp binds them that way for both operand forms, which is why this function needs
// to know nothing about funct3.
//
// THE EIGHT FORMS. RVV's leading `n` negates the PRODUCT; the trailing `add`/`sub` names the
// ADDEND's sign. The rows below are the SEMANTICS as rv32_vector_lower.h's helper computes them,
// which is also exactly the table QEmit::Emit_vchunkfma carries:
//
//   RVV        helper                    this backend: constrained.fma(x, y, z) = x*y + z
//   vfmadd     fma( d, b,  a)            ( d, b,  a)
//   vfnmadd    fma(-d, b, -a)            (-d, b, -a)
//   vfmsub     fma( d, b, -a)            ( d, b, -a)
//   vfnmsub    fma(-d, b,  a)            (-d, b,  a)
//   vfmacc     fma( b, a,  d)            ( b, a,  d)
//   vfnmacc    fma(-b, a, -d)            (-b, a, -d)
//   vfmsac     fma( b, a, -d)            ( b, a, -d)
//   vfnmsac    fma(-b, a,  d)            (-b, a,  d)
//
// The first four are the group where vd is a MULTIPLICAND (x86's 213 order); the last four are the
// group where vd is the ADDEND (x86's 231 order). This backend does not choose an operand ORDER at
// all -- it states the three arguments, and the x86 backend picks 213 or 231 for itself.
//
// *** THE x86 NAMING TRAP DOES NOT APPLY HERE, AND THAT IS WHY THIS TABLE IS WRITTEN IN HELPER
// TERMS. *** QEmit has to translate these rows into AsmJit opcode names, where RVV's `n...sub` is
// x86's `nmadd` and RVV's `n...add` is x86's `nmsub` -- a systematic spelling inversion that
// silently flips the addend's sign if the identically-named opcode is reached for. Naming no host
// opcode is what keeps this function out of that trap. It was nevertheless checked rather than
// assumed: `llc -mattr=+avx512f,+fma` on the IR this function emits selects `vfnmadd213ps` for
// vfnmsub and `vfnmsub231ps` for vfnmacc -- character for character the two opcodes QEmit's table
// names for those rows.
//
// NEGATION IS `fneg`, NOT A CONSTRAINED OPERATION, AND LLVM 20 HAS NO CONSTRAINED SPELLING OF IT.
// The experimental.constrained.* set in this LLVM (IntrinsicEnums.inc) contains fadd/fsub/fmul/
// fdiv/frem/fma/fmuladd/fcmp/fcmps/fpext/fptrunc/fptosi/fptoui/floor -- and no fneg. That is not a
// gap: IEEE 754 negate is a sign-bit operation, it is unaffected by the rounding mode and raises no
// exception, not even on a signalling NaN, so there is nothing for a constrained form to carry. The
// same is true of both other implementations of these rows: the helper's `-d` is a C++ unary minus
// (a sign-bit flip) and QEmit's negation is encoded in the FMA opcode itself. Checked, not assumed:
// `opt -passes=verify` accepts `fneg` inside a strictfp function, `-O3` preserves it, and the x86
// backend folds it into the FMA opcode as shown above.
//
// The PRECONDITIONS are Emit_vchunkfalu's, for its reasons: no mask of any kind exists in this
// body, so `masked`, a shared opmask, a run-time SEW, a non-64-byte chunk and a frame whose guard
// does not prove full VL are all refused rather than handled.
void QIRToLLVM::Emit_vchunkfma(qir::InstVChunkFMA *ins)
{
	TChunkAccount();
	// C7-FWMASK: the masked form, for the widening family's FMA members.
	if (ins->masked && !config::rvv_llvm_fwiden_masked)
		Panic("llvmgen: masked vchunkfma has no lowering in this backend");
	if (ins->kmask)
		Panic("llvmgen: vchunkfma names a shared opmask this backend never emits");
	if (ins->sew_bytes != 4 && ins->sew_bytes != 8)
		Panic("llvmgen: vchunkfma with an unsupported SEW");
	// C5-FP: same rule as vchunkfalu/vchunkfsqrt -- a frame that does not prove full VL is
	// admitted only when the inactive lanes' operands are neutralised. Hard refusal without it.
	// C7-FWPVL: the widening group emits this node at the WIDE sew inside its own frame, so
	// the fwiden switch satisfies the same fail-closed gate. It widens nothing by itself: a
	// body only ever sees a partial vl if its FRAME took a partial kind, and every route
	// gates that on its own switch.
	// C7-FWMASK: a MASKED frame necessarily takes a PARTIAL kind (see the frame-kind
	// decision in RvvEmitTypedFWidenChunkGroup), so the masked switch must satisfy the
	// partial-VL gate too -- the two are one path, not two.
	if (!tchunk_full_vl && !config::rvv_llvm_fp_partial_vl &&
	    !config::rvv_llvm_fwiden_partial_vl && !config::rvv_llvm_fwiden_masked)
		Panic("llvmgen: unmasked vchunkfma in a frame whose guard does not prove full VL");
	// W5: as in Emit_vchunkfalu -- a host vector width holding whole elements, not a literal 64.
	VType const chunk_ty = ins->o(0).GetType();
	if (!IsVectorVType(chunk_ty) || VTypeToSize(chunk_ty) % ins->sew_bytes != 0)
		Panic("llvmgen: vchunkfma chunk is not a whole number of elements of this SEW");
	for (u8 i = 0; i < 3; ++i) {
		if (ins->i(i).GetType() != chunk_ty)
			Panic("llvmgen: vchunkfma operands disagree on width");
	}
	auto *fty = llvm::FixedVectorType::get(ins->sew_bytes == 4 ? lb->getFloatTy()
								  : lb->getDoubleTy(),
					       VTypeToSize(chunk_ty) / ins->sew_bytes);
	llvm::Value *d = lb->CreateBitCast(TChunkUse(ins->i(0)), fty); // the OLD vd
	llvm::Value *b = lb->CreateBitCast(TChunkUse(ins->i(1)), fty); // vs1 chunk, or the .vf broadcast
	llvm::Value *a = lb->CreateBitCast(TChunkUse(ins->i(2)), fty); // vs2 chunk
	// C5-FP (2026-09-18). ALL THREE OPERANDS OF AN INACTIVE LANE BECOME +1.0, AHEAD OF THE SIGN
	// MAPPING.
	//
	// THE POSITION IS A PRESENTATION CHOICE, NOT A CORRECTNESS REQUIREMENT, and saying so is the
	// point: `fneg` is a sign-bit flip that rounds nothing and raises nothing, so neutralising
	// after the `switch` would compute `fma(1,1,1) = 2.0` for every form and be equally safe.
	// Neutralising HERE is preferred only because it keeps one table -- the guest's three operands,
	// once -- instead of eight, and because the sign mapping then reads exactly as the ISA states
	// it. The focused test detects a move by the operand COUNT per chunk, which is a structural
	// difference, not a semantic divergence; that distinction is recorded rather than dressed up.
	//
	// WHAT IS LOAD-BEARING is that the claim covers ALL EIGHT fused forms this node lowers --
	// unlike Family A's node, which admits `vfmadd` alone. Every one is exact,
	// normal-or-exact-zero, and raises nothing:
	//
	//   vfmadd   1*1 + 1 =  2.0      vfmacc   1*1 + 1 =  2.0
	//   vfnmadd -(1*1) - 1 = -2.0    vfnmacc -(1*1) - 1 = -2.0
	//   vfmsub   1*1 - 1 = +0.0      vfmsac   1*1 - 1 = +0.0
	//   vfnmsub -(1*1) + 1 = +0.0    vfnmsac -(1*1) + 1 = +0.0
	//
	// (the four zeros are exact cancellations, which raise nothing; under roundTowardNegative IEEE
	// 754 §6.3 makes them -0.0, still exact and still discarded by the predicated store).
	//
	// NO DESTINATION MERGE IS NEEDED, unlike Family A's `Emit_rvvfma`. This frame is state-backed:
	// `Emit_vstatechunkstore` already emits a `llvm.masked.store` from the chunk's own element
	// base, so an inactive lane's result never reaches guest state and the old bytes are simply
	// never written. Family A had to merge only because its destination is a live SSA value with
	// no store to predicate.
	// C7-FWMASK: `|| ins->masked` and the `ins->masked` argument are ONE change. The argument
	// is what turns this into `(e < vl) && v0[e]`; without it a masked frame would neutralise
	// only the tail and let a masked-off lane's operand raise a flag the bracket folds into the
	// guest `fcsr` for an element the instruction must not touch.
	if (!tchunk_full_vl || ins->masked) {
		u32 const lanes = VTypeToSize(chunk_ty) / ins->sew_bytes;
		auto *mask = RvvActiveLaneMask(lanes, (u32)ins->chunk * lanes, ins->masked);
		d = RvvNeutralizeInactiveFP(d, mask, fty);
		b = RvvNeutralizeInactiveFP(b, mask, fty);
		a = RvvNeutralizeInactiveFP(a, mask, fty);
	}
	auto neg = [&](llvm::Value *v) { return lb->CreateFNeg(v); };
	llvm::Value *x = nullptr, *y = nullptr, *z = nullptr;
	switch (ins->funct6) {
	case rv32::VF6_VFMADD:  x = d;      y = b; z = a;      break; //  d*b + a
	case rv32::VF6_VFNMADD: x = neg(d); y = b; z = neg(a); break; // -(d*b) - a
	case rv32::VF6_VFMSUB:  x = d;      y = b; z = neg(a); break; //  d*b - a
	case rv32::VF6_VFNMSUB: x = neg(d); y = b; z = a;      break; // -(d*b) + a
	case rv32::VF6_VFMACC:  x = b;      y = a; z = d;      break; //  b*a + d
	case rv32::VF6_VFNMACC: x = neg(b); y = a; z = neg(d); break; // -(b*a) - d
	case rv32::VF6_VFMSAC:  x = b;      y = a; z = neg(d); break; //  b*a - d
	case rv32::VF6_VFNMSAC: x = neg(b); y = a; z = d;      break; // -(b*a) + d
	default:
		// Unreachable in a consistent build: RvvLLVMFmaChunkAdmit gates on `vfma_supported`,
		// which IS the contiguous range these eight cover. A funct6 arriving here means an
		// admission row was widened without a sign mapping being written, and a silently
		// substituted operation is the alternative to this abort.
		Panic("llvmgen: unsupported vchunkfma funct6");
	}
	auto *r = RvvConstrainedFPCall(llvm::Intrinsic::experimental_constrained_fma, fty, {x, y, z});
	// The same canonicalisation every other FP lane op in this frame performs, and it must be:
	// the helper arm canonicalises through vf_write -> f{32,64}_canon, so any NaN this arm
	// produces has to become the same canonical quiet NaN.
	TChunkDef(ins->o(0),
		  RvvCanonicalize(lb->CreateBitCast(r, MakeType(chunk_ty)), ins->sew_bytes,
				  chunk_ty));
}
// W5F (2026-09-17). THE TYPED FP FRAME'S SQUARE ROOT ON THIS BACKEND.
//
// It is the one-operand counterpart of Emit_vchunkfalu and is the same shape: one operation over the
// frame's chunk value, no memory access, no control flow, then the canonical-NaN select.
//
// THE INTRINSIC IS `llvm.experimental.constrained.sqrt`, not `llvm.sqrt`, and not an estimate
// sequence. RVV 1.0 13.8 defines `vfsqrt.v` as the correctly-rounded IEEE square root, which is
// what the reference implements (`softfp::op_sqrt`, rv32_softfp.h) and what x86's vsqrtp{s,d} --
// LLVM's lowering for this intrinsic -- computes. The 14-bit estimate instructions (vrsqrt14ps and
// friends) are a different function with different flags and are never a legal lowering for this
// node; the node's own comment in qir.h says so, and this is the emitter that would otherwise be
// where that mistake was made. `round.dynamic` + `fpexcept.strict` carry the frame's bracket:
// rounding comes from the MXCSR `Emit_rvvqcgfpbegin` installed, and the exceptions this operation
// raises are the ones `Emit_rvvqcgfpend` folds into `fcsr.fflags`.
//
// THE CANONICALISATION IS LOAD-BEARING, AND MORE SO HERE THAN FOR THE ARITHMETIC OPS. For a
// negative operand the architecture requires NV and the CANONICAL quiet NaN; x86 raises #I and
// returns its own "real indefinite" QNaN, whose SIGN BIT IS SET (0xFFC00000 / 0xFFF8...), which is
// a different bit pattern from RISC-V's canonical 0x7FC00000 / 0x7FF8.... For a NaN operand x86
// quiets the input and preserves its payload, where the reference returns the canonical NaN. The
// helper arm this frame falls back to canonicalises in both cases (`op_sqrt` returns `f.qnan`), so
// the fast arm must too or the two arms disagree on the bits for the same input. The FLAGS are
// already right without any help: the invalid-operation case is raised by the hardware operation
// itself and folded by the bracket.
//
// sqrt(-0) = -0 and sqrt(+inf) = +inf need nothing here: both x86 and the reference produce them,
// and neither is a NaN, so the select below leaves them alone.
//
// THE FOUR REFUSALS ARE THIS BODY'S PRECONDITIONS, each discharged by RvvLLVMSqrtChunkAdmit or by
// the frame's guard upstream. They are restated because this function has no mask, no tail fill and
// no merge seed, so if any were false the emitted code would be silently wrong rather than absent.
void QIRToLLVM::Emit_vchunkfsqrt(qir::InstVChunkFSqrt *ins)
{
	TChunkAccount();
	if (ins->masked)
		Panic("llvmgen: masked vchunkfsqrt has no lowering in this backend");
	if (ins->kmask)
		Panic("llvmgen: vchunkfsqrt names a shared opmask this backend never emits");
	if (ins->sew_bytes != 4 && ins->sew_bytes != 8)
		Panic("llvmgen: vchunkfsqrt with an unsupported SEW");
	// C5-FP: as for vchunkfalu, a frame that does not prove full VL is admitted ONLY when the
	// inactive lanes' operand is neutralised. Without the switch this is the hard refusal it was.
	if (!tchunk_full_vl && !config::rvv_llvm_fp_partial_vl)
		Panic("llvmgen: unmasked vchunkfsqrt in a frame whose guard does not prove full VL");
	VType const chunk_ty = ins->o(0).GetType();
	if (!IsVectorVType(chunk_ty) || VTypeToSize(chunk_ty) % ins->sew_bytes != 0)
		Panic("llvmgen: vchunkfsqrt chunk is not a whole number of elements of this SEW");
	if (ins->i(0).GetType() != chunk_ty)
		Panic("llvmgen: vchunkfsqrt operands disagree on width");
	auto *fty = llvm::FixedVectorType::get(ins->sew_bytes == 4 ? lb->getFloatTy()
								  : lb->getDoubleTy(),
					       VTypeToSize(chunk_ty) / ins->sew_bytes);
	llvm::Value *a = lb->CreateBitCast(TChunkUse(ins->i(0)), fty);
	if (!tchunk_full_vl) {
		// C5-FP: `sqrt(+1.0) = 1.0` -- exact, normal, and raising nothing in any of the four
		// rounding modes this frame's guard admits. It matters here for a reason the arithmetic
		// ops do not have: `vfsqrt` of a NEGATIVE operand raises NV, so an inactive lane holding
		// any negative value -- not just a signalling NaN -- would set a guest flag the
		// instruction must not set. Only ONE operand exists, so there is one select per chunk.
		u32 const lanes = VTypeToSize(chunk_ty) / ins->sew_bytes;
		a = RvvNeutralizeInactiveFP(a, RvvActiveLaneMask(lanes, (u32)ins->chunk * lanes), fty);
	}
	auto *r = RvvConstrainedFPCall(llvm::Intrinsic::experimental_constrained_sqrt, fty, {a});
	TChunkDef(ins->o(0), RvvCanonicalize(lb->CreateBitCast(r, MakeType(chunk_ty)),
					     ins->sew_bytes, chunk_ty));
}
void QIRToLLVM::Emit_vchunkfcmpstate(qir::InstVChunkFCmpState *) { Panic("QCG-only vfcmp op reached LLVM"); }
// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE ONE MISSING NODE OF THE WIDENING FP FAMILY.
//
// WHY THIS IS THE WHOLE DELIVERY FOR `vfwarith`. The QCG route already decomposes that family into
// nodes this backend ALREADY lowers -- `vstatechunkload`, `vchunkfbroadcast`, `vchunkfalu`,
// `vchunkfma`, `vstatechunkstore` -- and exactly one it did not: this widening convert. So the LLVM
// arm is this emitter plus a guard kind, not a second copy of the family's frame. That is also why
// the reference's own definition survives intact: it widens both operands EXACTLY and then performs
// ONE operation at the wide width, and emitting the convert separately is that definition.
//
// THE SOURCE IS NOT ALWAYS THE WINDOW. Below a 32-byte destination the f32 window would be 8 bytes
// and QIR has no 8-byte vector type, so the frame loads 16 bytes whose LOW HALF is the window --
// which is precisely what `vcvtps2pd` does. The shuffle below takes that low half explicitly rather
// than relying on the instruction selector to ignore the rest, because the IR has to MEAN the same
// thing as the assembly at every width, not just at the one where they coincide.
//
// FULL VL AND UNMASKED ONLY, and the node's own comment says why that is the honest restriction
// rather than a missing feature: it carries `masked` because the CONVERSION must see the active
// mask -- an inactive lane holding a signalling NaN would otherwise raise NV for an element the
// instruction never touched. A frame whose guard proves `vl == VLMAX` and whose encoding is
// unmasked has no such lane, so the convert needs no predicate. Anything else keeps the helper.
//
// `fpext` f32 -> f64 IS EXACT, so it takes no rounding operand -- `RvvConstrainedFPCallNoRound` --
// and the only flag it can raise is NV for a signalling NaN, which is what the reference raises too.
// The NaN VALUE is not canonicalised here on purpose: this is an intermediate operand, and the
// `vchunkfalu` / `vchunkfma` that consumes it canonicalises its own result.
// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE CARRY/BORROW FAMILY -- `vadc` and `vsbc`.
//
// `v0` IS A DATA OPERAND, NOT A MASK, and that is the whole of what makes this family different
// from every genuinely masked one in this checkpoint. `vadc` computes `vs2 + vs1 + v0[i]` and writes
// EVERY body element. So `v0`'s bits are fetched with the SAME `RvvArchMaskForUnit` the masked
// routes use -- one derivation of where a mask bit lives, shared -- and then ZERO-EXTENDED into the
// lane type as an addend, instead of being ANDed into a store predicate.
//
// The truncation to SEW is the lane type's: an `add` of `<N x iSEW>` wraps, which is exactly the
// reference's `& sew_mask`.
//
// IT RAISES NOTHING. No saturation, no sticky flag, no FP: this is the pure counterpart of the
// saturating node above, which is why its QIR flags are `0` and not SIDEEFF.
void QIRToLLVM::Emit_vchunkadc(qir::InstVChunkAdc *ins)
{
	TChunkAccount();
	VType const ct = ins->o(0).GetType();
	if (!IsVectorVType(ct) || ins->i(0).GetType() != ct || ins->i(1).GetType() != ct)
		Panic("llvmgen: vchunkadc operands disagree on width");
	u32 const sew = ins->sew_bytes;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: vchunkadc with an unsupported SEW");
	u32 const bytes = VTypeToSize(ct);
	if (bytes % sew != 0)
		Panic("llvmgen: vchunkadc chunk is not a whole number of elements of this SEW");
	u32 const lanes = bytes / sew;
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	// vs2 op vs1, the shared body's order and the reference's (`a` is vs2). Load-bearing for the
	// borrow form and invisible for the carry one.
	auto *a = lb->CreateBitCast(TChunkUse(ins->i(0)), vty);
	auto *b = lb->CreateBitCast(TChunkUse(ins->i(1)), vty);
	auto *c = lb->CreateZExt(RvvArchMaskForUnit(lanes, ins->element_base), vty);
	llvm::Value *r = ins->sub ? lb->CreateSub(lb->CreateSub(a, b), c)
				  : lb->CreateAdd(lb->CreateAdd(a, b), c);
	TChunkDef(ins->o(0), lb->CreateBitCast(r, MakeType(ct)));
}

// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE RVV 1.0 FIXED-POINT ROUNDING RULE, EMITTED ONCE.
//
// This is the spec's `roundoff_unsigned(v, d) = (v >> d) + r` -- specifically the `r`. Four families
// round by it (`vaadd`/`vasub`, `vsmul`, `vssrl`/`vssra`, `vnclip`) and they must agree, so it is a
// helper rather than four copies. `rv32_vector_lower.h`'s `rounding_incr` is the same statement for
// the helper arm, and the focused test differentials this IR against the reference that calls it.
//
// `vxrm` IS LOADED FROM LIVE STATE, NOT BAKED IN. It is a writable CSR and a genuine input: the same
// instruction on the same operands yields four different results across its four values. Every arm
// is computed and one is selected, so there is no branch and no assumption about which mode a guest
// happens to be in.
//
// The bit names follow the spec: `lsb` is v[d-1], the bit about to be shifted out; `rest` is
// v[d-2:0] != 0, the bits below it; `bitd` is v[d], the bit that survives. Everything is computed in
// the ELEMENT TYPE as a 0/1 value, so the result adds directly to the shifted vector.
llvm::Value *QIRToLLVM::RvvRoundoffIncrement(llvm::Value *v, u32 shift)
{
	auto *vty = llvm::cast<llvm::FixedVectorType>(v->getType());
	auto *ety = llvm::cast<llvm::IntegerType>(vty->getElementType());
	// `shift == 0` shifts nothing out, so there is nothing to round. The spec's function is
	// defined for it and returns 0; saying so here keeps the callers from special-casing.
	if (shift == 0)
		return llvm::ConstantAggregateZero::get(vty);
	if (shift >= ety->getBitWidth())
		Panic("llvmgen: fixed-point rounding shift is wider than the element");
	// FORWARDED, NOT DUPLICATED. The general form below handles a constant splat identically --
	// IRBuilder's constant folder collapses the zero-shift guard and the vxrm comparisons it adds
	// -- so the two callers with a compile-time shift emit exactly what they did before this was
	// generalised for `vnclip`.
	return RvvRoundoffIncrement(
	    v, llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(vty->getNumElements()),
					      llvm::ConstantInt::get(ety, shift)));
}

llvm::Value *QIRToLLVM::RvvRoundoffIncrement(llvm::Value *v, llvm::Value *shift)
{
	auto *vty = llvm::cast<llvm::FixedVectorType>(v->getType());
	auto *ety = llvm::cast<llvm::IntegerType>(vty->getElementType());
	if (shift->getType() != vty)
		Panic("llvmgen: fixed-point rounding shift has the wrong vector type");
	auto *zero = llvm::ConstantAggregateZero::get(vty);
	auto splat = [&](u64 c) {
		return llvm::ConstantVector::getSplat(
		    llvm::ElementCount::getFixed(vty->getNumElements()),
		    llvm::ConstantInt::get(ety, c));
	};
	auto *one = splat(1);
	// `shift - 1` WRAPS TO ALL-ONES WHEN THE SHIFT IS ZERO, and that is deliberate rather than
	// overlooked: all-ones is `width - 1`, a LEGAL shift amount, so nothing here is poison. The
	// zero case is then discarded by the final select. Clamping instead would cost a second
	// select on the hot path to produce a value that is thrown away.
	auto *sh1 = lb->CreateSub(shift, one);
	// LOGICAL shifts: these extract BITS of the two's-complement pattern, matching the
	// reference's cast of the value to an unsigned before indexing it. An arithmetic shift here
	// would replicate the sign bit into `bitd` for a negative value -- which `vasubu` produces.
	auto *lsb = lb->CreateAnd(lb->CreateLShr(v, sh1), one);
	auto *bitd = lb->CreateAnd(lb->CreateLShr(v, shift), one);
	// The sticky term: `v[d-2:0] != 0`. With a variable shift this cannot be skipped the way the
	// constant form skipped it for `shift < 2` -- some lanes may have a shift of 1 and others
	// thirty-one -- so the mask is built per lane. For a lane with shift 1 the mask is 0 and the
	// term is 0, which is exactly what the constant form's special case produced.
	auto *low = lb->CreateAnd(v, lb->CreateSub(lb->CreateShl(one, sh1), one));
	auto *rest = lb->CreateZExt(lb->CreateICmpNE(low, zero), vty);
	// vxrm = 0 rnu, 1 rne, 2 rdn, 3 rod. Masked to two bits: the CSR write path already does
	// this, so the AND is belt-and-braces rather than load-bearing -- but an out-of-range value
	// reaching the chain below would silently select `rod`, which is the worst failure mode of
	// the four to notice.
	u32 const vxrm_off = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vxrm));
	auto *vxrm = lb->CreateAnd(RvvStateLoad(VType::I32, vxrm_off, llvm::Align(4)), lb->getInt32(3));
	auto *rnu = lsb;
	auto *rne = lb->CreateAnd(lsb, lb->CreateOr(rest, bitd));
	auto *rod = lb->CreateAnd(lb->CreateOr(lsb, rest), lb->CreateXor(bitd, one));
	auto *is0 = lb->CreateICmpEQ(vxrm, lb->getInt32(0));
	auto *is1 = lb->CreateICmpEQ(vxrm, lb->getInt32(1));
	auto *is2 = lb->CreateICmpEQ(vxrm, lb->getInt32(2));
	auto *inc = lb->CreateSelect(is0, rnu,
				     lb->CreateSelect(is1, rne, lb->CreateSelect(is2, zero, rod)));
	// A lane whose shift is zero shifts nothing out and rounds by nothing.
	return lb->CreateSelect(lb->CreateICmpEQ(shift, zero), zero, inc);
}

// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE FRACTIONAL MULTIPLY -- `vsmul.vv` / `vsmul.vx`.
//
// FOURTH OF THE FIVE NARROW FIXED-POINT NODES, and the FIRST caller of `RvvRoundoffIncrement` at a
// shift greater than one. `vaadd` shifts by 1, where the spec's `v[d-2:0] != 0` sticky term is an
// empty bit range and is never observed; here the shift is SEW-1, so that term carries thirty bits
// and the shared rule is exercised for real. This is the payoff for having written it once.
//
// THE SHIFT IS SEW-1, NOT SEW. RVV 1.0 12.3 treats both operands as Q(SEW-1) signed fractions and
// keeps the high half of the 2*SEW product, so the rounding right shift is by SEW-1. Shifting by
// SEW is the plausible-looking error and halves every result.
//
// SATURATION HAS EXACTLY ONE INPUT PAIR. MIN*MIN is +1.0 in that format -- one ulp above the
// representable maximum -- and nothing else can leave the range. Both bounds are still tested,
// because the comparison is two instructions and an asymmetric clamp is the kind of thing that
// survives review; but any claim about `vxsat` from this route rests on that one pair being fed.
//
// `vxsat` IS ORed, NEVER ASSIGNED, and gated by the unit's active-lane predicate -- the same rule
// and the same helper as the saturating add/sub node, not a second spelling of it.
void QIRToLLVM::Emit_vchunkfracmul(qir::InstVChunkFracMul *ins)
{
	TChunkAccount();
	VType const ct = ins->o(0).GetType();
	if (!IsVectorVType(ct) || ins->i(0).GetType() != ct || ins->i(1).GetType() != ct)
		Panic("llvmgen: vchunkfracmul operands disagree on width");
	u32 const sew = ins->sew_bytes;
	// SEW 8 would need a `<N x i128>` product, a legalisation shape this backend has no evidence
	// for; the route admits SEW 32 only, so this is its own envelope stated fail-closed.
	if (sew != 1 && sew != 2 && sew != 4)
		Panic("llvmgen: vchunkfracmul with an unsupported SEW");
	u32 const bytes = VTypeToSize(ct);
	if (bytes % sew != 0)
		Panic("llvmgen: vchunkfracmul chunk is not a whole number of elements of this SEW");
	u32 const lanes = bytes / sew;
	u32 const ebits = sew * 8u;
	auto *ety = llvm::IntegerType::get(lctx, ebits);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto *wety = llvm::IntegerType::get(lctx, ebits * 2u);
	auto *wty = llvm::FixedVectorType::get(wety, lanes);
	// BOTH OPERANDS ARE SIGNED. `vsmul` has no unsigned form: RVV 1.0 defines the fractional
	// multiply for signed fractions only, which is why there is no kind field on this node.
	auto *a = lb->CreateSExt(lb->CreateBitCast(TChunkUse(ins->i(0)), vty), wty);
	auto *b = lb->CreateSExt(lb->CreateBitCast(TChunkUse(ins->i(1)), vty), wty);
	// Exact in 2*SEW for SEW-wide signed inputs. No `nsw`: it would be true and buys nothing,
	// and a poison value feeding a sticky architectural flag is the failure this file already
	// records once, at the saturating add/sub node.
	auto *prod = lb->CreateMul(a, b);
	auto *r = lb->CreateAdd(lb->CreateAShr(prod, ebits - 1u),
				RvvRoundoffIncrement(prod, ebits - 1u));
	auto splat = [&](llvm::APInt const &c) {
		return llvm::ConstantVector::getSplat(llvm::ElementCount::getFixed(lanes),
						      llvm::ConstantInt::get(wety, c));
	};
	auto *smax = splat(llvm::APInt::getSignedMaxValue(ebits).sext(ebits * 2u));
	auto *smin = splat(llvm::APInt::getSignedMinValue(ebits).sext(ebits * 2u));
	auto *hi = lb->CreateICmpSGT(r, smax);
	auto *lo = lb->CreateICmpSLT(r, smin);
	auto *clamped = lb->CreateSelect(hi, smax, lb->CreateSelect(lo, smin, r));
	// C5-MASK: as in the saturating add/sub -- a masked-off lane's clip must not set `vxsat`.
	auto *active = RvvActiveLaneMask(lanes, ins->element_base, ins->masked,
					 tchunk_body_restart);
	auto *mask_ty = llvm::IntegerType::get(lctx, lanes);
	auto *any = lb->CreateICmpNE(
	    lb->CreateBitCast(lb->CreateAnd(lb->CreateOr(hi, lo), active), mask_ty),
	    llvm::ConstantInt::get(mask_ty, 0));
	u32 const vxsat_off = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vxsat));
	auto *cur = RvvStateLoad(VType::I32, vxsat_off, llvm::Align(4));
	RvvStateStore(VType::I32, vxsat_off,
		      lb->CreateOr(cur, lb->CreateSelect(any, lb->getInt32(1), lb->getInt32(0))),
		      llvm::Align(4));
	TChunkDef(ins->o(0), lb->CreateBitCast(lb->CreateTrunc(clamped, vty), MakeType(ct)));
}

// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE FIXED-POINT AVERAGING FAMILY -- `vaaddu`/`vaadd`/`vasubu`/`vasub`.
//
// THIRD OF THE FIVE NARROW FIXED-POINT NODES, and the one that introduces `vxrm` to this backend.
//
// THE ARITHMETIC IS DONE WIDE, AND THAT IS THE POINT. RVV 1.0 12.2 defines the result as
// `roundoff(vs2 +/- vs1, 1)` where the sum is formed in SEW+1 bits -- so it cannot overflow, and the
// bit shifted out is a real bit of a real sum rather than something reconstructed after a wrap.
// Doing it in 2*SEW is the straightforward way to have SEW+1 available, and it is structurally the
// same computation the reference performs in `__int128`.
//
// THE SHIFT IS ARITHMETIC AND THE EXTENSION IS NOT ALWAYS SIGNED. `vasubu` extends its operands
// ZERO but can still produce a NEGATIVE difference, and the spec's `>>` on that difference is an
// arithmetic shift -- floor division. The reference gets this by computing in signed `__int128`;
// this gets it by zero-extending the operands and then using `ashr` on the exact difference.
//
// AND THE `lshr` VERSION OF THIS LINE IS NOT OBSERVABLE HERE, which was measured rather than
// assumed and is recorded because the opposite is the natural thing to believe. For a negative
// 2*SEW sum `-k`, `ashr 1` is `-ceil(k/2)` and `lshr 1` is `2^(2*SEW-1) - ceil(k/2)`; those differ
// only ABOVE bit SEW, and the result is TRUNCATED to SEW. The rounding increment reads individual
// bits with `lshr` in both cases, so it does not differ either. A mutation swapping this `ashr` for
// an `lshr` passes a 38,688-lane differential against the reference; only the structural check in
// `rvv_llvm_avg_test` [V4] catches it.
//
// It stays `ashr` anyway, for two reasons worth separating. It is what the spec says, so the line
// reads as the semantics rather than as an accident of this width. And `vnclip` -- which is meant
// to reuse `RvvRoundoffIncrement` -- shifts by a VARIABLE amount and takes its result from the high
// bits, where the difference is very much observable; a house style of "logical is fine here" would
// carry into the one place it is not.
//
// NO `nuw`/`nsw` ON THE WIDE ADD OR SUB. The 2*SEW type cannot overflow for SEW-wide inputs, so the
// flags would be true -- but they would also be an assertion the optimiser may exploit, and this
// value is deliberately allowed to be negative. Nothing is gained and a poison path is opened.
void QIRToLLVM::Emit_vchunkavg(qir::InstVChunkAvg *ins)
{
	TChunkAccount();
	VType const ct = ins->o(0).GetType();
	if (!IsVectorVType(ct) || ins->i(0).GetType() != ct || ins->i(1).GetType() != ct)
		Panic("llvmgen: vchunkavg operands disagree on width");
	u32 const sew = ins->sew_bytes;
	// SEW 8 is absent deliberately: its wide type would be `<N x i128>`, which legalises into a
	// shape this backend has no evidence for. The route admits SEW 32 only, so this is a
	// fail-closed statement of the emitter's own envelope rather than a limit anyone can reach.
	if (sew != 1 && sew != 2 && sew != 4)
		Panic("llvmgen: vchunkavg with an unsupported SEW");
	u32 const bytes = VTypeToSize(ct);
	if (bytes % sew != 0)
		Panic("llvmgen: vchunkavg chunk is not a whole number of elements of this SEW");
	u32 const lanes = bytes / sew;
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	auto *wty = llvm::FixedVectorType::get(llvm::IntegerType::get(lctx, sew * 16u), lanes);
	// vs2 op vs1, the shared body's order and the reference's (`a` is vs2). Load-bearing for the
	// two subtracting kinds.
	auto *a = lb->CreateBitCast(TChunkUse(ins->i(0)), vty);
	auto *b = lb->CreateBitCast(TChunkUse(ins->i(1)), vty);
	using Kind = qir::InstVChunkAvg::Kind;
	bool const sign = ins->kind == Kind::AddS || ins->kind == Kind::SubS;
	bool const sub = ins->kind == Kind::SubU || ins->kind == Kind::SubS;
	auto *ax = sign ? lb->CreateSExt(a, wty) : lb->CreateZExt(a, wty);
	auto *bx = sign ? lb->CreateSExt(b, wty) : lb->CreateZExt(b, wty);
	auto *sum = sub ? lb->CreateSub(ax, bx) : lb->CreateAdd(ax, bx);
	auto *r = lb->CreateAdd(lb->CreateAShr(sum, 1), RvvRoundoffIncrement(sum, 1));
	TChunkDef(ins->o(0), lb->CreateBitCast(lb->CreateTrunc(r, vty), MakeType(ct)));
}

// ===============================================================================================
// ORDER ITEM 4 (2026-09-19): THE SATURATING INTEGER ADD/SUB FAMILY.
//
// FIRST OF THE FIVE NARROW NODES THE PLAN'S FIXED-POINT PROPOSAL NAMES, and it is the one whose
// arithmetic LLVM already has exactly: `uadd.sat`, `sadd.sat`, `usub.sat`, `ssub.sat` are the four
// operations RVV 1.0 12.1 defines, bound by bound. There is no approximation here and no hand-built
// saturation tree -- which matters, because saturation is precisely the semantics the plan says must
// not be approximated.
//
// `vxsat` IS THE PART LLVM DOES NOT GIVE, and it is derived rather than guessed: a lane saturated
// exactly when the saturating result DIFFERS from the wrapping one. That equivalence is exact for
// all four operations (saturation is the only thing that can make them differ), it needs no
// per-kind reasoning, and it costs one ordinary add/sub and one compare.
//
// IT IS STICKY AND IT IS ORed, NEVER ASSIGNED. RVV 1.0 keeps `vxsat` set until software clears it,
// so a frame in which no lane saturates must leave a previously-set flag alone. Writing a computed
// 0/1 would clear it -- the same failure shape as assigning `fcsr` instead of accumulating it.
//
// INACTIVE LANES CANNOT SATURATE INTO THE FLAG. The comparison is ANDed with the unit's active-lane
// predicate before it is reduced, so a tail or masked-off element whose operands happen to overflow
// contributes nothing -- the same rule every flag-deriving route in this checkpoint follows.
void QIRToLLVM::Emit_vchunksatadd(qir::InstVChunkSatAdd *ins)
{
	TChunkAccount();
	VType const ct = ins->o(0).GetType();
	if (!IsVectorVType(ct) || ins->i(0).GetType() != ct || ins->i(1).GetType() != ct)
		Panic("llvmgen: vchunksatadd operands disagree on width");
	u32 const sew = ins->sew_bytes;
	if (sew != 1 && sew != 2 && sew != 4 && sew != 8)
		Panic("llvmgen: vchunksatadd with an unsupported SEW");
	u32 const bytes = VTypeToSize(ct);
	if (bytes % sew != 0)
		Panic("llvmgen: vchunksatadd chunk is not a whole number of elements of this SEW");
	u32 const lanes = bytes / sew;
	auto *ety = llvm::IntegerType::get(lctx, sew * 8u);
	auto *vty = llvm::FixedVectorType::get(ety, lanes);
	// OPERAND ORDER IS vs2 op vs1, the order the shared chunk body builds and the order the
	// reference computes (`a` is vs2). It is load-bearing for the two SUBTRACTING kinds and
	// invisible for the two adding ones, which is why it is stated rather than left to the reader.
	auto *a = lb->CreateBitCast(TChunkUse(ins->i(0)), vty);
	auto *b = lb->CreateBitCast(TChunkUse(ins->i(1)), vty);
	using Kind = qir::InstVChunkSatAdd::Kind;
	llvm::Intrinsic::ID id;
	bool sub;
	switch (ins->kind) {
	case Kind::AddU: id = llvm::Intrinsic::uadd_sat; sub = false; break;
	case Kind::AddS: id = llvm::Intrinsic::sadd_sat; sub = false; break;
	case Kind::SubU: id = llvm::Intrinsic::usub_sat; sub = true; break;
	default:	 id = llvm::Intrinsic::ssub_sat; sub = true; break;
	}
	auto *fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, id, {vty});
	auto *sat = lb->CreateCall(fn, {a, b});
	// The WRAPPING result, for the flag only. NO nuw/nsw: wrapping is the whole point of this
	// value, and either flag would make the difference below POISON on exactly the lanes it exists
	// to detect.
	//
	// THIS ONE IS NOT FALSIFIABLE BY THE FOCUSED TEST, and that is recorded rather than left
	// implicit: a mutation adding `nsw` SURVIVES `rvv_llvm_satadd_test`, because poison's effect
	// is whatever the optimiser chooses to make of it and the constant folder happens to resolve
	// it to the same word. It is still a real latent miscompile -- a poison value reaching an
	// architectural sticky flag -- so the absence of the flags is a CORRECTNESS REQUIREMENT here
	// and not a missed optimisation, and it is written down because no check will catch its
	// removal.
	auto *wrap = sub ? lb->CreateSub(a, b) : lb->CreateAdd(a, b);
	auto *diff = lb->CreateICmpNE(sat, wrap);
	// C5-MASK: `vxsat` IS GATED BY `v0` TOO WHEN THE FORM IS MASKED. A masked-off lane is not
	// operated on, so a saturation it would have produced must not reach the sticky flag -- and
	// unlike the destination, which the store simply does not write, the flag has no second
	// chance to be corrected. Same predicate helper as the destination's, so the two cannot
	// disagree about which lanes are active.
	auto *active = RvvActiveLaneMask(lanes, ins->element_base, ins->masked,
					 tchunk_body_restart);
	auto *mask_ty = llvm::IntegerType::get(lctx, lanes);
	auto *any = lb->CreateICmpNE(
	    lb->CreateBitCast(lb->CreateAnd(diff, active), mask_ty),
	    llvm::ConstantInt::get(mask_ty, 0));
	u32 const vxsat_off = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vxsat));
	auto *cur = RvvStateLoad(VType::I32, vxsat_off, llvm::Align(4));
	RvvStateStore(VType::I32, vxsat_off,
		      lb->CreateOr(cur, lb->CreateSelect(any, lb->getInt32(1), lb->getInt32(0))),
		      llvm::Align(4));
	TChunkDef(ins->o(0), lb->CreateBitCast(sat, MakeType(ct)));
}

void QIRToLLVM::Emit_vchunkfwidencvt(qir::InstVChunkFWidenCvt *ins)
{
	TChunkAccount();
	// C7-FWMASK: the masked form. The neutralisation below already derives its predicate from
	// `RvvActiveLaneMask(..., ins->masked)`, i.e. `(e < vl) && v0[e]`, so the ONLY thing this
	// node needed was to stop refusing. Fail-closed without the switch.
	if (ins->masked && !config::rvv_llvm_fwiden_masked)
		Panic("llvmgen: masked widening convert has no lowering in this backend");
	// C7-FWPVL (2026-09-20): PARTIAL VL FOR THE WIDENING BODY. This node was the ONE blocker --
	// `vstatechunkstore` already publishes through an active-lane masked store, and `vchunkfalu`
	// and `vchunkfma` already neutralise inactive operands. Fail-closed: without the switch the
	// Panic stands, so a frame kind can never quietly outrun the body.
	// C7-FWMASK: a MASKED frame necessarily takes a PARTIAL kind (see the frame-kind
	// decision in RvvEmitTypedFWidenChunkGroup), so the masked switch must satisfy the
	// partial-VL gate too -- the two are one path, not two.
	if (!tchunk_full_vl && !config::rvv_llvm_fwiden_partial_vl &&
	    !config::rvv_llvm_fwiden_masked)
		Panic("llvmgen: widening convert in a frame whose guard does not prove full VL");
	VType const dt = ins->o(0).GetType(), st = ins->i(0).GetType();
	if (!IsVectorVType(dt) || !IsVectorVType(st))
		Panic("llvmgen: vchunkfwidencvt operands are not vector values");
	u32 const dbytes = VTypeToSize(dt), sbytes = VTypeToSize(st);
	if (dbytes % 8u != 0 || sbytes % 4u != 0)
		Panic("llvmgen: vchunkfwidencvt widths are not whole f64/f32 lanes");
	u32 const lanes = dbytes / 8u, src_lanes = sbytes / 4u;
	// The node's own contract: the source value is `max(16, dst/2)` bytes, so it holds AT LEAST
	// `lanes` f32 elements and at most twice that. Restated here because a caller that bypassed
	// the constructor would otherwise shuffle out of range.
	if (src_lanes < lanes || sbytes != (dbytes / 2u < 16u ? 16u : dbytes / 2u))
		Panic("llvmgen: vchunkfwidencvt source is not this destination's f32 window");

	auto *sfty = llvm::FixedVectorType::get(lb->getFloatTy(), src_lanes);
	auto *wfty = llvm::FixedVectorType::get(lb->getFloatTy(), lanes);
	auto *dfty = llvm::FixedVectorType::get(lb->getDoubleTy(), lanes);
	llvm::Value *src = lb->CreateBitCast(TChunkUse(ins->i(0)), sfty);
	if (src_lanes != lanes) {
		llvm::SmallVector<int, 16> idx;
		for (u32 i = 0; i < lanes; ++i)
			idx.push_back((int)i);
		src = lb->CreateShuffleVector(src, llvm::PoisonValue::get(sfty), idx);
	}
	// C7-FWPVL: NEUTRALISE INACTIVE LANES BEFORE THE CONVERSION, for the same reason
	// `Emit_vchunkfalu` does and with the same value. An f32 -> f64 widening is exact for every
	// finite input and raises nothing -- EXCEPT on a SIGNALLING NaN, which raises NV. So a tail
	// lane holding an sNaN would set the guest `fcsr` for an element the instruction must not
	// touch, and the destination store being predicated would NOT undo it: the flag has no second
	// chance. +1.0f widens to 1.0 exactly and raises nothing.
	//
	// THE LANE COUNT IS THE DESTINATION'S. `lanes` is f64 lanes and the element base is
	// `chunk * lanes`, which is the same base `Emit_vstatechunkstore` uses for this chunk's
	// predicate -- the two must agree or an element could be computed in one and suppressed in
	// the other.
	if (!tchunk_full_vl || ins->masked) {
		auto *mask = RvvActiveLaneMask(lanes, (u32)ins->chunk * lanes, ins->masked);
		src = RvvNeutralizeInactiveFP(src, mask, wfty);
	}
	auto *w = RvvConstrainedFPCallNoRound(llvm::Intrinsic::experimental_constrained_fpext,
					      {dfty, wfty}, {src});
	TChunkDef(ins->o(0), lb->CreateBitCast(w, MakeType(dt)));
}
// F1 (2026-09-16). THE TYPED FRAME'S FP BRACKET -- ONE PAIR FOR THE WHOLE FRAME.
//
// It is NOT the same node as `rvvfpbegin`/`rvvfpend` above, and the difference is not cosmetic:
//
//   * NO GUARD OF ITS OWN. `rvvfpbegin` carries an `evl` and a vtype and guards itself, because on
//     the P-vector-SSA path each FP op guards itself too and the bracket has to agree with them.
//     This node is emitted INSIDE the frame's guarded arm (Emit_rvvtypedchunkbegin set the insert
//     point to `fast` before the body), so the frame's single guard -- which includes `frm == RNE`
//     -- has already been proved. A second guard here would be dead code that could only disagree.
//   * IT IS A TYPED BODY OP. `TChunkAccount()` is what makes `end`'s
//     `tchunk_seen == tchunk_expected` check cover it, matching QEmit, where both emitters do
//     `rvv_typed_chunk_seen += rvv_typed_chunk_open`. The translator counts them too: the falu
//     frame's declared `n_typed` is `4 * nchunks + 2`, and that `+ 2` is exactly this pair.
//   * `begin` FOLDS AN INHERITED BRACKET FIRST, and this one IS load-bearing rather than
//     defensive. `fround_run_open` is SHARED state, not this backend's private flag: the scalar FP
//     helpers (`rv32_fpop`, `rv32_fmadd`, ... -- every scalar FP instruction in a translated block
//     is a helper call) leave it TRUE across instructions when --rvv-scalar-fround-run is on
//     (`FRound::finish` returns without restoring while `continued`), and the vector helper fast
//     path does the same through `fround_run_close_or_continue`. `TbExitCloseOpenFroundRun` closes
//     it at every TB exit, but that function is called ONLY from the interpreter's block loop
//     (rv32_interp.cpp) -- a JIT/AOT block has no such close. So a translated block really can
//     reach this node with a bracket open and MXCSR holding someone else's rounding mode plus
//     unharvested exception bits. Opening unconditionally would then (a) overwrite
//     `fround_run_saved_mxcsr` with the inherited MXCSR, losing the original resting value, and
//     (b) clear the accrued exception bits without ever OR-ing them into `fcsr`, losing guest
//     fflags. QEmit::Emit_rvvqcgfpbegin has folded it since P7M-A for this reason; this is the
//     same fold, in the same place, and it is why this function is not simply `Emit_rvvfpbegin`
//     without the guard.
//   * `end` CLOSES UNCONDITIONALLY and then clears `vec.vstart`. Unconditional because `begin` is
//     the only path into this frame's body and it always leaves the bracket open; the `vstart`
//     write is inside the frame's guarded arm and after the bracket closes, which is exactly where
//     QEmit::Emit_rvvqcgfpend puts it. The P-vector-SSA `rvvfpend` writes no `vstart` at all --
//     there, each op writes its own.
//
// THE GUARD-MISS ARM SEES NEITHER NODE. `Emit_rvvtypedchunkbegin` branches straight from the guard
// to the fallback block, so a miss never executes `begin`, never touches MXCSR, and lets the
// ordered helpers manage the bracket exactly as they do without this frame.
void QIRToLLVM::Emit_rvvqcgfpbegin(qir::InstRVVQCGFPBegin *)
{
	TChunkAccount();
	u32 const open_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_open);
	auto *open = RvvStateLoad(VType::I8, open_off, llvm::Align(1));
	auto *fold = llvm::BasicBlock::Create(lctx, "rvv.tchunk.fp.fold", func);
	auto *fresh = llvm::BasicBlock::Create(lctx, "rvv.tchunk.fp.fresh", func);
	lb->CreateCondBr(lb->CreateICmpNE(open, lb->getInt8(0)), fold, fresh);
	lb->SetInsertPoint(fold);
	RvvFpBracketCloseBody();
	lb->CreateBr(fresh);
	lb->SetInsertPoint(fresh);
	RvvFpBracketOpenBody();
}

void QIRToLLVM::Emit_rvvqcgfpend(qir::InstRVVQCGFPEnd *)
{
	TChunkAccount();
	RvvFpBracketCloseBody();
	RvvStateStore(VType::I32,
		      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
}

// ---------------------------------------------------------------------------------------------
// S3.5: the guest-memory read half of the typed `vle32.v` frame, lowered for the LLVM/AOT tier.
//
// WHY THIS EXISTS. S3.3 left the LLVM/AOT hot loop with three translation-time helper boundaries --
// vsetvli, vle32.v, vse32.v -- while the QCG path has had none since S2.9. S3.4 closed the first.
// This closes the SECOND and only the second: `vse32.v` keeps its rv32_vse helper, `vchunkstore`
// keeps its Panic above, and nothing here may be reused to remove that boundary as a side effect.
//
// SCOPE is exactly RvvLLVMVleChunkAdmit's, which is RvvVleChunkShapeAdmit plus
// --rvv-qcg-typed-chunk-vle and --rvv-vector-ssa: exact unmasked unit-stride `vle32.v`, EEW=32 from
// the encoding, SEW=32/LMUL=1 (hence EMUL=1) from vtype, base register != x0, at VLEN 512 or 1024,
// with a non-Ref --rvv-lowering. vl == VLMAX, vstart == 0 and the runtime VLEN are RUNTIME state and
// are decided by the guard `rvvtypedchunkbegin` already emits; on a miss the frame calls exactly the
// pre-existing rv32_vle helper, once. Masked loads, other EEWs, vlse/vleff/vlxei/vlNre/vlseg/vlm,
// EMUL != 1 and an x0 base never build this node at all.
//
// THE ADDRESS, AND IT IS THE WHOLE OF WHAT MAKES THIS OP DIFFERENT FROM `vstatechunkload`.
//
//   base32 = load i32 CPUState[base_state_offs]            ; the guest GPR named by rs1
//   ep     = membase + zext i64 base32                     ; MakeVMemLoc -- the ONE guest-memory
//                                                          ; mapping this backend has
//   ep     = ep + disp                                     ; chunk 1 only, a HOST-pointer byte GEP
//   chunk  = load <8 x i64>, align 1, !alias.scope avmem
//
// THE BASE COMES FROM CPUState AND THAT IS EXACT, NOT AN APPROXIMATION. On this backend every guest
// global IS a CPUState address -- CreateVGPRLocs maps each one to MakeStateEP(info->state_offs) and
// every access is an ordinary load/store there -- so reading rs1 at its translation-time constant
// offset reads the identical location LoadVOperand would. (The QCG emitter reads the same slot for a
// different reason: QRegAlloc::CallOp has just spilled every global there because
// `rvvtypedchunkbegin` carries HAS_CALLS. Same address, two independent justifications.)
//
// `disp` IS A HOST-POINTER DISPLACEMENT, ADDED AFTER THE ZERO-EXTENSION, and that is a semantic
// requirement rather than a convenience -- the same one qir.h states for the AsmJit emitter. Chunk 1
// of a VLEN=1024 register is [base + 64] in 64-bit host arithmetic and does NOT wrap modulo 2^32,
// which is exactly what rvv_chunked::copy_chunked does on a host pointer (rv32_vector_lower.h). So
// this route and the helper arm it replaces agree on all 2^32 base addresses, including the top 64.
// Folding the displacement into the i32 base before the zext would wrap and silently disagree there.
// Do not "simplify" it into an add on `base32`.
//
// THE GEP IS DELIBERATELY NOT `inbounds`. `MakeVMemLoc` does not mark its own membase GEP inbounds
// either, and it must not: a guest address near the top of the 32-bit space plus 64 bytes may leave
// the mapping object, and `inbounds` would make that undefined behaviour rather than the ordinary
// out-of-range guest access the helper arm would also perform. Fault behaviour is therefore the
// mapping's, unchanged: an unmapped guest page faults on this load exactly as it faults inside
// rv32_vle, at the same guest address, with `state->ip` already materialised by the TRANSLATOR
// macro's PreSideeff because Op::_vle carries Flags::MayTrap.
//
// ALIGNMENT IS 1. A guest base address carries no 64-byte alignment guarantee, so this is the
// unaligned form -- the IR counterpart of the emitter's `vmovdqu64`. Claiming more would let LLVM
// select an aligned move and fault on a legal guest program.
//
// ALIAS SCOPE IS `avmem`, NOT `astate`, and the two halves of this frame are in DIFFERENT scopes on
// purpose: this load reads GUEST memory and the `vstatechunkstore` that consumes it writes CPUState.
// That is the same partition every scalar Emit_vmload/Emit_vmstore in this backend already asserts,
// and it is true for the reason S2.7 records -- CPUState is not in the guest address space. The
// pre-existing rv32_vle helper call this replaces was opaque and clobbered everything; the load that
// replaces it is precise. Note what this does NOT relax: the vse32.v helper call still standing in
// the same loop carries no scope metadata at all, so scoped-noalias cannot disambiguate it from this
// load and the read-then-write order of the frozen mixed loop's `(a6)` pair is preserved.
void QIRToLLVM::Emit_vchunkload(qir::InstVChunkLoad *ins)
{
	TChunkAccount();
	// The DIRECT addressing form has no route into this backend and no lowering here. Its only
	// callers are the pure-QCG mechanism tests (qir.h), and absorbing it silently would mean
	// lowering an address this function never validated. Fail closed.
	if (ins->base_state_offs == qir::InstVChunkLoad::NO_STATE_BASE) {
		Panic("llvmgen: direct-form vchunkload reached the LLVM backend");
	}
	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h --
	// the same division of labour QEmit::Emit_vchunkload implements, and for the stronger reason it
	// gives: reading past the end of CPUState would take the guest ADDRESS from unrelated host
	// memory and then dereference it.
	if ((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState)) {
		Panic("llvmgen: vchunkload indirect base lies outside CPUState");
	}
	// W5 RESTATES THE NODE'S OWN RULE INSTEAD OF THE TWO DISPLACEMENTS THAT USED TO EXIST.
	//
	// It was `disp % 64 == 0 && disp <= 64` -- chunk 0 of either VLEN and chunk 1 of VLEN 1024 --
	// which described the routes that existed, not this node. InstVChunkLoad's constructor has
	// enforced the general rule since A17: the displacement is a whole number of THIS load's own
	// width and the window ends inside the storage reservation. Restating that rule here (rather
	// than a narrower literal) is what lets a 16/32-byte chunk at VLEN 128/256 and chunk 2/3 of a
	// VLEN-2048 register reach a lowering, while a shape outside it still fails loudly.
	VType const chunk_ty = ins->o(0).GetType();
	if (!IsVectorVType(chunk_ty)) {
		Panic("llvmgen: vchunkload destination is not a vector value");
	}
	u32 const width = VTypeToSize(chunk_ty);
	if (ins->disp % width != 0 ||
	    ins->disp + width > qir::MAX_REG_CHUNKS * qir::InstVChunkLoad::CHUNK_BYTES) {
		Panic("llvmgen: vchunkload displacement is not an admitted chunk offset");
	}

	auto *base = RvvStateLoad(VType::I32, ins->base_state_offs, llvm::Align(4));
	llvm::Value *ep = MakeVMemLoc(chunk_ty, base);
	if (ins->disp) {
		ep = lb->CreateGEP(lb->getInt8Ty(), ep, lb->getInt64(ins->disp));
	}
	// W32 (2026-09-21): THE PARTIAL-VL ARM, and the reason it must be a MASKED load rather than a
	// full-width load followed by a select.
	//
	// `rvv_ref::load_unit_stride` reads elements `[vstart, vl)` one at a time and touches NOTHING
	// else. At `vl < VLMAX` the bytes from `vl * EEW` to `VLEN/8` may be on a page the guest never
	// mapped -- the guest is entitled to issue `vle32.v` with `vl` set so the access stops exactly
	// at the end of an array that ends at a page boundary. A plain full-width load would fault
	// there, and rvdbt's SIGSEGV handler panics rather than delivering a guest trap, so the
	// failure mode is a dead process on a legal program, not a wrong value.
	//
	// `llvm.masked.load` is specified to not perform the load for a false mask lane, so no
	// exception can arise from it -- that guarantee is the whole reason this node can be admitted
	// at partial VL at all. It is the same guarantee AVX-512's `k`-masked `vmovdqu32` gives, which
	// is what QEmit emits for this node's masked arm (`j.k(k7).z().vmovdqu32`).
	//
	// THE PASSTHROUGH IS ZERO, matching QEmit's `.z()` zero-masking. The value is unobservable
	// either way -- every lane this load leaves inactive is a lane the matching
	// `vstatechunkstore` also refuses to publish -- but a defined value keeps the IR free of
	// poison for a reader, and costs nothing.
	//
	// THE MASK IS THE FRAME'S, NOT A SECOND DERIVATION OF IT. `RvvActiveLaneMask` memoises one
	// value per (unit, kind) per frame, so this load's predicate and its chunk's store predicate
	// are literally the same `llvm::Value *`. A load that read a lane the store then refused to
	// publish would be harmless; a load that SKIPPED a lane the store published would write the
	// passthrough zero into guest state, and that is the failure this sharing makes unreachable.
	if (ins->active_sew) {
		if (width % ins->active_sew != 0)
			Panic("llvmgen: vchunkload active width does not divide the chunk");
		u32 const lanes = width / ins->active_sew;
		auto *lane_ty = llvm::IntegerType::get(lctx, ins->active_sew * 8u);
		auto *vector_ty = llvm::FixedVectorType::get(lane_ty, lanes);
		// The unit-stride family is admitted only for `vm == 1` (RvvVleChunkShape tests the
		// encoding), so there is no architectural-mask conjunct to apply here.
		llvm::Value *mask = RvvActiveLaneMask(lanes, (u32)ins->chunk * lanes,
						      /*architectural_mask=*/false,
						      tchunk_body_restart);
		auto *loaded = AScopeVMem(lb->CreateMaskedLoad(
		    vector_ty, ep, llvm::Align(1), mask,
		    llvm::Constant::getNullValue(vector_ty)));
		TChunkDef(ins->o(0), lb->CreateBitCast(loaded, MakeType(chunk_ty)));
		return;
	}
	TChunkDef(ins->o(0),
		  AScopeVMem(lb->CreateAlignedLoad(MakeType(chunk_ty), ep, llvm::Align(1))));
}

void QIRToLLVM::Emit_vstatechunkstore(qir::InstVStateChunkStore *ins)
{
	TChunkAccount();
	// Fail closed for the stronger reason QEmit gives: writing past the end of CPUState would
	// corrupt unrelated host memory.
	// P4: the node's own width, as above.
	if ((size_t)ins->offs + ins->Bytes() > sizeof(CPUState)) {
		Panic("llvmgen: vstatechunkstore window lies outside CPUState");
	}
	if (ins->active_sew) {
		u32 const lanes = ins->Bytes() / ins->active_sew;
		auto *lane_ty = llvm::IntegerType::get(lctx, ins->active_sew * 8);
		auto *vector_ty = llvm::FixedVectorType::get(lane_ty, lanes);
		u32 const element_base = (u32)ins->chunk * lanes;
		// ORDER ITEM 3: THE ARCHITECTURAL MASK CONJUNCT.
		//
		// The contract's active predicate is `(vstart <= e) && (e < vl) && architectural_mask(e)`
		// (rv32_rvv_contract.h piece 2). The `vl` bound is the compare just above and the
		// `vstart` floor is the frame guard's (`VTypeIntegerNoRestart` proves `vstart == 0`), so
		// this is the third conjunct and the only one that reads guest state per element.
		//
		// IT IS ANDed INTO THE SAME PREDICATE RATHER THAN APPLIED AS A SECOND STORE, which is what
		// makes `PredicateIsSound` checkable on one value: a masked-off element and a tail element
		// are both simply not written, so the destination is preserved -- legal under all four of
		// vta/vtu x vma/vmu, exactly as piece 3 records for the tail.
		//
		// THE WINDOW COMES FROM THE CONTRACT, not from arithmetic open-coded here, and it fails
		// closed: `MaskWindowForUnit` returns `bits == 0` for any lane count whose unit would
		// straddle the load, and a unit that read a neighbouring unit's bits as its own would be a
		// silently wrong answer rather than a crash.
		//
		// NOTHING ELSE IN THE BODY IS MASKED, and for this family that is the whole argument: the
		// integer lane operations raise no exception and set no flag, so computing an inactive
		// element is unobservable and only the COMMIT has to be predicated. Every other lane
		// emitter in this file still Panics on `masked` precisely because that argument does not
		// carry to them -- an FP lane would raise a host exception the bracket folds into `fcsr`.
		// For the FP families it DOES carry, and that is exactly why this predicate is built by
		// the SHARED `RvvActiveLaneMask` rather than open-coded here: within a frame it returns
		// the same `llvm::Value *` the FP operand neutralisation used for this unit, so the
		// neutralised set and the published set are one value and cannot drift apart. The
		// open-coded copy this replaced agreed with it -- which is precisely the condition under
		// which a later edit to one of them goes unnoticed.
		// ORDER ITEM 3: the floor is FRAME-scoped, not node-scoped -- it is a property of the
		// guard, and every node in the frame needs it or none does. Taking it from
		// `tchunk_body_restart` rather than from a node flag is what makes it impossible for one
		// unit of a restartable frame to be published without it.
		llvm::Value *mask =
		    RvvActiveLaneMask(lanes, element_base, ins->masked, tchunk_body_restart);
		// Masked-out lanes do not access memory, preserving all inactive guest state,
		// including the VL=0 case. Integer intermediates remain ordinary vector SSA.
		AScopeState(lb->CreateMaskedStore(lb->CreateBitCast(TChunkUse(ins->i(0)), vector_ty),
			MakeStateEP(ins->i(0).GetType(), ins->offs),
			llvm::commonAlignment(llvm::Align(16), ins->offs), mask));
	} else {
		if (ins->masked)
			Panic("llvmgen: masked state store without an active-lane predicate");
		RvvStateStore(ins->i(0).GetType(), ins->offs, TChunkUse(ins->i(0)), llvm::Align(16));
	}
}

// ---------------------------------------------------------------------------------------------
// S3.6: the guest-memory write half of the typed `vse32.v` frame, lowered for the LLVM/AOT tier.
//
// WHY THIS EXISTS. S3.3 left the LLVM/AOT hot loop with three translation-time helper boundaries.
// S3.4 closed `vsetvli`, S3.5 closed `vle32.v`'s taken path, and this closes the THIRD and last one
// the frozen add loop has. It is the first of the three that WRITES guest memory, which is the whole
// of what separates it from Emit_vchunkload: a wrong address, length or source register here
// overwrites another buffer, the stack or a code page instead of corrupting a vector register.
//
// SCOPE is exactly RvvLLVMVseChunkAdmit's: exact unmasked unit-stride `vse32.v`, EEW=32 from the
// encoding, SEW=32/LMUL=1 (hence EMUL=1) from vtype, base register != x0, at VLEN 512 or 1024, with
// a non-Ref --rvv-lowering, under BOTH --rvv-qcg-typed-chunk-vse and --rvv-vector-ssa. vl == VLMAX,
// vstart == 0 and the runtime VLEN are decided by the guard `rvvtypedchunkbegin` already emits; on a
// miss the frame calls exactly the pre-existing rv32_vse helper, once.
//
// THE ADDRESS IS THE LOAD'S, BYTE FOR BYTE, and that is deliberate rather than incidental -- the two
// halves of one guest instruction pair must not compute a guest address two different ways:
//
//   base32 = load i32 CPUState[base_state_offs]            ; the guest GPR named by rs1
//   ep     = membase + zext i64 base32                     ; MakeVMemLoc, the one guest mapping
//   ep     = ep + disp                                     ; chunk 1 only, a HOST-pointer byte GEP
//            store <8 x i64> %chunk, ptr ep, align 1, !alias.scope avmem
//
// The zero-extension precedes the displacement for the reason qir.h gives and which is STRICTER on
// this side: [base + 64] must not wrap modulo 2^32, because a wrap here would not read the wrong
// bytes, it would WRITE 64 bytes to the bottom of the guest address space. The GEP is not `inbounds`
// for the load's reason.
//
// THE SOURCE IS A TYPED CHUNK VALUE, NOT A RE-READ. `TChunkUse` resolves the operand to the
// llvm::Value* this frame's own `vstatechunkload` defined, so the bytes stored are the ones read out
// of vs3's CPUState window at the top of this frame -- inside the guard, after
// RvvEmitTypedVseChunkGroup's chunk-cache commit. Nothing re-reads CPUState between the two.
//
// ORDERING IS THE NEW OBLIGATION, and it is discharged by the alias scope rather than by luck.
// After S3.5 the same loop can contain a DIRECT `vle32.v` whose guest-memory load is a real
// llvm::LoadInst, and the frozen mixed loop reads and writes the same pointer in one strip step.
// Both accesses carry `!alias.scope !{avmem}` and `!noalias !{astate, aother}`. ScopedNoAliasAA can
// only return NoAlias when one access's noalias set CONTAINS the other's scope; avmem is in neither
// noalias set, so the pair is may-alias and LLVM must preserve their order. That is the correct
// answer -- they genuinely may alias -- and it is why this store must NOT be given a scope of its
// own however tempting the extra freedom looks. The focused test asserts the relation directly on
// the emitted MDNodes rather than trusting this paragraph.
//
// ALIGNMENT IS 1, for the load's reason: a guest base address carries no 64-byte alignment
// guarantee, and claiming more would let LLVM select an aligned store and fault on a legal guest
// program. Fault behaviour is otherwise the mapping's, unchanged: an unmapped or read-only guest
// page faults on this store exactly as it faults inside rv32_vse, at the same guest address, with
// `state->ip` already materialised because Op::_vse carries Flags::MayTrap.
void QIRToLLVM::Emit_vchunkstore(qir::InstVChunkStore *ins)
{
	TChunkAccount();
	// The DIRECT addressing form has no route into this backend and no lowering here, exactly as
	// for the load. Absorbing it silently would mean writing guest memory at an address this
	// function never validated.
	if (ins->base_state_offs == qir::InstVChunkStore::NO_STATE_BASE) {
		Panic("llvmgen: direct-form vchunkstore reached the LLVM backend");
	}
	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h.
	// Fail closed for the stronger reason QEmit gives on this side: reading past the end of
	// CPUState would take the guest ADDRESS from unrelated host memory and then WRITE 64 bytes to
	// it.
	if ((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState)) {
		Panic("llvmgen: vchunkstore indirect base lies outside CPUState");
	}
	// W5: the node's own rule, as on the load side. On this side getting it wrong WRITES guest
	// memory, so the width used for the bound is the width of the data actually being stored.
	VType const chunk_ty = ins->i(1).GetType();
	if (!IsVectorVType(chunk_ty)) {
		Panic("llvmgen: vchunkstore data is not a vector value");
	}
	u32 const width = VTypeToSize(chunk_ty);
	if (ins->disp % width != 0 ||
	    ins->disp + width > qir::MAX_REG_CHUNKS * qir::InstVChunkStore::CHUNK_BYTES) {
		Panic("llvmgen: vchunkstore displacement is not an admitted chunk offset");
	}

	// i(1) is the DATA and i(0) is the indirect form's unread placeholder -- the operand order the
	// QIR node declares. Reading them the other way round would store an address into guest memory.
	auto *data = TChunkUse(ins->i(1));
	auto *base = RvvStateLoad(VType::I32, ins->base_state_offs, llvm::Align(4));
	llvm::Value *ep = MakeVMemLoc(chunk_ty, base);
	if (ins->disp) {
		ep = lb->CreateGEP(lb->getInt8Ty(), ep, lb->getInt64(ins->disp));
	}
	AScopeVMem(lb->CreateAlignedStore(data, ep, llvm::Align(1)));
}

void QIRToLLVM::Emit_rvvtypedchunkend(qir::InstRVVTypedChunkEnd *ins)
{
	if (!tchunk_open) {
		Panic("llvmgen: typed chunk group end without begin");
	}
	if (tchunk_seen != tchunk_expected) {
		Panic("llvmgen: typed chunk group body is not the shape begin declared");
	}
	if (ins->n_members != tchunk_members)
		Panic("llvmgen: typed frame member counts disagree");
	// Direct-hit counter after the body, the same placement Emit_rvvtypedchunkend uses in QEmit.
	RvvCount(true);
	// ORDER ITEM 3, RESTART: the frame epilogue's `vec.vstart = 0` write, ON THE FAST PATH ONLY.
	//
	// RVV 1.0 3.7 requires every vector instruction to reset `vstart` to 0 on completion. Every
	// frame before this one discharged that by having a guard that PROVED `vstart == 0`, so the
	// architectural post-state already held and no write was needed -- which is why this emitter
	// had none. A frame that admits a nonzero `vstart` must write it, and it must write it here:
	// after the body, before the join, and NOT on the fallback arm, where the helper performs the
	// whole instruction including its own `vstart` reset (a second write there would be harmless
	// but would make "exactly one clear on the taken path" -- contract piece 5,
	// `VStartClearCountIsSound` -- false).
	//
	// THE FLAG IS THE FRAME'S OWN DECLARATION, not a re-derivation from the guard kind. QCG's
	// twin cross-checks the same field against the bounds it actually emitted; here the producer
	// that sets it is the restart route, and a frame that admits a nonzero vstart without setting
	// it would leave the NEXT vector instruction reading a stale value -- so the begin emitter
	// refuses that combination outright (see the Panic at the guard-kind dispatch).
	// THE FRAME-LEVEL INVARIANT, checked before the write so the write cannot satisfy it. A frame
	// whose guard admits a nonzero `vstart` must reset it somewhere on the fast path: either a body
	// node does (the scalar-move family, whose body IS the architectural rule) or the epilogue
	// does. Neither would leave the NEXT vector instruction reading a stale `vstart` -- a bug with
	// no local symptom, which is exactly the kind this check exists for.
	if (tchunk_body_restart && !ins->frame_clears_vstart && !tchunk_body_wrote_vstart)
		Panic("llvmgen: restartable typed frame never resets vec.vstart");
	if (ins->frame_clears_vstart)
		RvvStateStore(VType::I32,
			      offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
			      lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(tchunk_done);
	lb->SetInsertPoint(tchunk_fallback);
	RvvCount(false);
	for (u8 i = 0; i < ins->n_members; ++i) {
		auto const &member = ins->members[i];
		if (ins->n_members > 1)
			RvvStateStore(VType::I32, offsetof(CPUState, ip), lb->getInt32(member.pc), llvm::Align(4));
		RvvCallFallback(member.stub, member.raw);
	}
	lb->CreateBr(tchunk_done);
	lb->SetInsertPoint(tchunk_done);

	tchunk_open = false;
	tchunk_expected = 0;
	tchunk_seen = 0;
	tchunk_vals.clear();
	tchunk_done = nullptr;
	tchunk_fallback = nullptr;
	tchunk_members = 0;
	tchunk_full_vl = false; // F1: per-frame, exactly like every field above it
	tchunk_body_restart = false; // order item 3: per-frame, same reason
	tchunk_body_wrote_vstart = false;
	tchunk_lane_masks.clear(); // order item 3: per-frame, for the same reason

	// Same tail rule Emit_rvvaddv (the op this frame replaces for the very same guest instruction)
	// applies: if this is the last node of the block, the join needs a terminator.
	if (--qbb->ilist.end() == ins) {
		lb->CreateRetVoid();
	}
}

// M6B. THE TWO CCRF OPS HAVE NO LOWERING HERE, AND CANNOT REACH HERE.
//
// `QIR_OPS_LIST` gives this backend one `Emit_` per QIR op and the Visitor dispatches every one of
// them, so an op with no definition is a LINK error, not a silent gap -- which is exactly what it
// was: `elfaot` failed to link on these two symbols while `elfrun` (which never pulls this object)
// built fine, so the whole offline LLVM compiler was unbuildable.
//
// A Panic is the right definition rather than a placeholder lowering. Both ops are constructed in
// exactly one place each -- RvvEmitWholeRegChunkGroup and the vx-mulacc path, dbt/guest/rv32_qir.cpp
// -- and both are gated behind RvvQcgWholeRegAdmit / RvvQcgVxMulAccShape, which refuse whenever
// config::aot_use_llvm. So on an LLVM compile no ccrf node is ever built, and this Panic is the
// FAIL-CLOSED PROOF of that rather than a case anyone expects to hit. It is the same shape and the
// same fail-closed arrangement as unsupported typed-frame bodies: the translator refuses
// to construct the thing, and the backend refuses to lower it if the translator ever stops.
//
// ccrf_llvm_unreachable_test.cpp asserts the predicates really do refuse, and fails if either is
// flipped. Giving these a real lowering is NOT in M6B's scope and would need the sequential-CCRF
// component model this backend does not have.
void QIRToLLVM::Emit_ccrfchunk(qir::InstCCRFChunk *)
{
	Panic("llvmgen: CCRF chunk has no lowering in this backend");
}

void QIRToLLVM::Emit_ccrfcompute(qir::InstCCRFComputeRegion *)
{
	Panic("llvmgen: CCRF compute region has no lowering in this backend");
}

void QIRToLLVM::Emit_rvvread(qir::InstRVVRead *ins)
{
	u32 const off = ins->i(0).GetConst();
	auto type = ins->o(0).GetType();
	StoreVOperand(ins->o(0), RvvStateLoad(type, off, llvm::Align(ins->bytes == 64 ? 16 : ins->bytes)));
}

void QIRToLLVM::Emit_rvvwrite(qir::InstRVVWrite *ins)
{
	u32 const off = ins->i(0).GetConst();
	auto type = ins->i(1).GetType();
	RvvStateStore(type, off, LoadVOperand(ins->i(1)), llvm::Align(ins->bytes == 64 ? 16 : ins->bytes));
}

void QIRToLLVM::Emit_rvvsplatf(qir::InstRVVSplatF *ins)
{
	u32 const off = ins->i(0).GetConst();
	auto *raw64 = RvvStateLoad(VType::MASK64, off, llvm::Align(8));
	llvm::Value *lane;
	if (ins->sew == 4) {
		auto *hi = lb->CreateTrunc(lb->CreateLShr(raw64, lb->getInt64(32)), lb->getInt32Ty());
		auto *lo = lb->CreateTrunc(raw64, lb->getInt32Ty());
		lo = lb->CreateSelect(lb->CreateICmpEQ(hi, lb->getInt32(~0u)), lo,
				      lb->getInt32(rv32::F32_CANONICAL_NAN));
		lane = lb->CreateBitCast(lo, lb->getFloatTy());
	} else {
		lane = lb->CreateBitCast(raw64, lb->getDoubleTy());
	}
	auto *splat = lb->CreateVectorSplat(64 / ins->sew, lane);
	StoreVOperand(ins->o(0), lb->CreateBitCast(splat, MakeType(VType::V512)));
}

// F1 (2026-09-16). THE HOST FP CONTROL/EXCEPTION BRACKET, EXTRACTED -- the straight-line body only,
// with no control flow and no guard of its own.
//
// It existed twice before F1 in different shapes: once here as `Emit_rvvfpbegin`/`Emit_rvvfpend`
// (the P-vector-SSA family) and once in QEmit as `Emit_rvvqcgfpbegin`/`EmitCloseRvvFpBracket` (the
// typed-frame family). F1 needs a THIRD instance -- the typed frame's bracket on this backend --
// and a third hand-written MXCSR->fflags table is exactly the drift this extraction prevents.
//
// WHAT IS *NOT* IN HERE, AND THAT IS THE WHOLE REASON THE TWO CALLERS STAY DISTINCT: neither
// function creates a block, a branch or a guard, and neither reads `fround_run_open`. Those are the
// callers' differences, and they are real ones -- see each caller.
//
// EVERY CONSTANT IS THE ONE THE PREVIOUS CODE USED, character for character: the frm->MXCSR.RC map
// (RVV 0,1,2,3 -> MXCSR 0x0000, 0x6000, 0x2000, 0x4000), the `~(0x6000 | 0x3f)` mask that clears RC
// and the accrued exception bits while retaining the exception MASKS, and the five MXCSR->fflags
// rows (IE->NV, ZE->DZ, OE->OF, UE->UF, PE->NX).
void QIRToLLVM::RvvFpBracketOpenBody()
{
	auto *slot = rvv_mxcsr_slot;
	auto st = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::x86_sse_stmxcsr);
	auto ld = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::x86_sse_ldmxcsr);
	lb->CreateCall(st, {slot});
	auto *saved = lb->CreateLoad(lb->getInt32Ty(), slot);
	u32 const saved_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_saved_mxcsr);
	RvvStateStore(VType::I32, saved_off, saved, llvm::Align(4));
	u32 const fcsr_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
	auto *fcsr = RvvStateLoad(VType::I32, fcsr_off, llvm::Align(4));
	auto *frm = lb->CreateAnd(lb->CreateLShr(fcsr, lb->getInt32(5)), lb->getInt32(7));
	auto *rc = lb->CreateSelect(lb->CreateICmpEQ(frm, lb->getInt32(1)), lb->getInt32(0x6000),
		lb->CreateSelect(lb->CreateICmpEQ(frm, lb->getInt32(2)), lb->getInt32(0x2000),
			lb->CreateSelect(lb->CreateICmpEQ(frm, lb->getInt32(3)), lb->getInt32(0x4000),
					 lb->getInt32(0))));
	auto *configured = lb->CreateOr(lb->CreateAnd(saved, lb->getInt32(~(0x6000u | 0x3fu))), rc);
	lb->CreateStore(configured, slot);
	lb->CreateCall(ld, {slot});
	u32 const open_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_open);
	RvvStateStore(VType::I8, open_off, lb->getInt8(1), llvm::Align(1));
}

void QIRToLLVM::RvvFpBracketCloseBody()
{
	auto *slot = rvv_mxcsr_slot;
	auto st = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::x86_sse_stmxcsr);
	auto ld = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::x86_sse_ldmxcsr);
	lb->CreateCall(st, {slot});
	auto *mx = lb->CreateLoad(lb->getInt32Ty(), slot);
	llvm::Value *flags = lb->getInt32(0);
	auto addflag = [&](u32 mxbit, u32 rvbit) {
		auto *set = lb->CreateICmpNE(lb->CreateAnd(mx, lb->getInt32(mxbit)), lb->getInt32(0));
		flags = lb->CreateOr(flags, lb->CreateSelect(set, lb->getInt32(rvbit), lb->getInt32(0)));
	};
	addflag(1u << 0, rv32::FFLAG_NV);
	addflag(1u << 2, rv32::FFLAG_DZ);
	addflag(1u << 3, rv32::FFLAG_OF);
	addflag(1u << 4, rv32::FFLAG_UF);
	addflag(1u << 5, rv32::FFLAG_NX);
	u32 const fcsr_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr);
	RvvStateStore(VType::I32, fcsr_off,
		      lb->CreateOr(RvvStateLoad(VType::I32, fcsr_off, llvm::Align(4)), flags), llvm::Align(4));
	u32 const saved_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_saved_mxcsr);
	lb->CreateStore(RvvStateLoad(VType::I32, saved_off, llvm::Align(4)), slot);
	lb->CreateCall(ld, {slot});
	u32 const open_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_open);
	RvvStateStore(VType::I8, open_off, lb->getInt8(0), llvm::Align(1));
}

// UNCHANGED BY F1 -- the control flow, the guard and the emitted order are what they were; only the
// straight-line body moved into the helper above. In particular this function still opens the
// bracket UNCONDITIONALLY on its guarded arm, without first folding an inherited bracket. That is a
// pre-existing exposure shared with every other P-vector-SSA FP op (see Emit_rvvqcgfpbegin below,
// which does NOT share it and states why); widening it here would be a semantic change to an
// accepted route, so it is recorded rather than repaired in this checkpoint.
void QIRToLLVM::Emit_rvvfpbegin(qir::InstRVVFPBegin *ins)
{
	u32 const vt = ins->i(0).GetConst();
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.fp.begin", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.fp.begin.done", func);
	lb->CreateCondBr(RvvGuard(vt, ins->evl, true, ins->partial_vl), fast, done);
	lb->SetInsertPoint(fast);
	RvvFpBracketOpenBody();
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_rvvfpend(qir::InstRVVFPEnd *)
{
	u32 const open_off = offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fround_run_open);
	auto *open = RvvStateLoad(VType::I8, open_off, llvm::Align(1));
	auto *close = llvm::BasicBlock::Create(lctx, "rvv.fp.end", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.fp.end.done", func);
	lb->CreateCondBr(lb->CreateICmpNE(open, lb->getInt8(0)), close, done);
	lb->SetInsertPoint(close);
	RvvFpBracketCloseBody();
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_rvvload(qir::InstRVVLoad *ins)
{
	u32 const vo = offsetof(CPUState, vec);
	// C1: `addr` is materialised BEFORE the branch because the guard now tests it. See
	// RvvWholeRegMemGuard for why vlenb alone was not a sufficient precondition.
	auto *addr = LoadVOperand(ins->i(0));
	auto *guard_ok = RvvWholeRegMemGuard(addr, ins->evl);
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.load.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.load.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.load.done", func);
	lb->CreateCondBr(guard_ok, fast, slow);
	lb->SetInsertPoint(fast);
	RvvCount(true);
	for (u8 c = 0; c < ins->active_chunks; ++c) {
		auto *ca = lb->CreateAdd(addr, lb->getInt32(c * 64));
		auto *p = LLVMGen::MakeVMemLoc(MakePtrType(VType::V512), ca);
		StoreVOperand(ins->o(c), AScopeVMem(lb->CreateAlignedLoad(MakeType(VType::V512), p, llvm::Align(1))));
	}
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vstart), lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(done);
	lb->SetInsertPoint(slow);
	RvvCount(false);
	RvvCallFallback(ins->stub, ins->raw);
	auto vals = RvvLoadGroup(ins->vd, ins->active_chunks);
	for (u8 c = 0; c < ins->active_chunks; ++c)
		StoreVOperand(ins->o(c), vals[c]);
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_rvvstore(qir::InstRVVStore *ins)
{
	u32 const vo = offsetof(CPUState, vec);
	// C1: same three-test guard as the load; the two must not state different preconditions for
	// the same transfer, which is why they share RvvWholeRegMemGuard.
	auto *addr = LoadVOperand(ins->i(0));
	auto *guard_ok = RvvWholeRegMemGuard(addr, ins->evl);
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.store.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.store.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.store.done", func);
	lb->CreateCondBr(guard_ok, fast, slow);
	lb->SetInsertPoint(fast);
	RvvCount(true);
	for (u8 c = 0; c < ins->active_chunks; ++c) {
		auto *ca = lb->CreateAdd(addr, lb->getInt32(c * 64));
		auto *p = LLVMGen::MakeVMemLoc(MakePtrType(VType::V512), ca);
		AScopeVMem(lb->CreateAlignedStore(LoadVOperand(ins->i(1 + c)), p, llvm::Align(1)));
	}
	RvvStateStore(VType::I32, vo + offsetof(rv32::VectorState, vstart), lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(done);
	lb->SetInsertPoint(slow);
	RvvCount(false);
	RvvStoreGroup(ins->vs3, ins->active_chunks, ins->inputs(), 1);
	RvvCallFallback(ins->stub, ins->raw);
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_rvvfcmp(qir::InstRVVFCmp *ins)
{
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.fcmp.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.fcmp.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.fcmp.done", func);
	lb->CreateCondBr(RvvGuard(ins->vtype, ins->evl, true), fast, slow);
	lb->SetInsertPoint(fast);
	RvvCount(true);
	auto *fty = llvm::FixedVectorType::get(ins->sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), 64 / ins->sew);
	auto cmpfn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule,
		llvm::Intrinsic::experimental_constrained_fcmps, {fty});
	auto *pred = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "ogt"));
	auto *except = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "fpexcept.strict"));
	llvm::Value *mask = lb->getInt64(0);
	for (u8 c = 0; c < ins->active_chunks; ++c) {
		auto *a = lb->CreateBitCast(LoadVOperand(ins->i(c)), fty);
		auto *b = lb->CreateBitCast(LoadVOperand(ins->i(4)), fty);
		auto *bits = lb->CreateCall(cmpfn, {a, b, pred, except});
		auto *packed_ty = llvm::IntegerType::get(lctx, 64 / ins->sew);
		auto *packed = lb->CreateZExt(lb->CreateBitCast(bits, packed_ty), lb->getInt64Ty());
		mask = lb->CreateOr(mask, lb->CreateShl(packed, lb->getInt64(c * (64 / ins->sew))));
	}
	StoreVOperand(ins->o(0), mask);
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(done);
	lb->SetInsertPoint(slow);
	RvvCount(false);
	RvvStoreGroup(ins->vs2, ins->active_chunks, ins->inputs(), 0);
	RvvCallFallback(ins->stub, ins->raw);
	u32 const moff = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) +
			  ins->vd * rv32::VLEN_MAX_BYTES;
	StoreVOperand(ins->o(0), RvvStateLoad(VType::MASK64, moff, llvm::Align(8)));
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_rvvmerge(qir::InstRVVMerge *ins)
{
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.merge.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.merge.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.merge.done", func);
	lb->CreateCondBr(RvvGuard(ins->vtype, ins->evl, false), fast, slow);
	lb->SetInsertPoint(fast);
	RvvCount(true);
	auto *rawty = MakeType(VType::V512);
	auto *mask = LoadVOperand(ins->i(8));
	for (u8 c = 0; c < ins->active_chunks; ++c) {
		u32 const lanes = 64 / ins->sew;
		auto *packed_ty = llvm::IntegerType::get(lctx, lanes);
		auto *part = lb->CreateTrunc(lb->CreateLShr(mask, lb->getInt64(c * lanes)), packed_ty);
		auto *vpred = lb->CreateBitCast(part, llvm::FixedVectorType::get(lb->getInt1Ty(), lanes));
		auto *fty = llvm::FixedVectorType::get(ins->sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), lanes);
		auto *a = lb->CreateBitCast(LoadVOperand(ins->i(c)), fty);
		auto *b = lb->CreateBitCast(LoadVOperand(ins->i(4 + c)), fty);
		StoreVOperand(ins->o(c), lb->CreateBitCast(lb->CreateSelect(vpred, b, a), rawty));
	}
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(rawty));
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(done);
	lb->SetInsertPoint(slow);
	RvvCount(false);
	RvvStoreGroup(ins->vs2, ins->active_chunks, ins->inputs(), 0);
	RvvStoreGroup(ins->vs1, ins->active_chunks, ins->inputs(), 4);
	u32 const moff = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	RvvStateStore(VType::MASK64, moff, LoadVOperand(ins->i(8)), llvm::Align(8));
	RvvCallFallback(ins->stub, ins->raw);
	auto vals = RvvLoadGroup(ins->vd, ins->active_chunks);
	for (u8 c = 0; c < ins->active_chunks; ++c)
		StoreVOperand(ins->o(c), vals[c]);
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(rawty));
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

// F1 (2026-09-16). ONE CONSTRAINED-FP CALL, BUILT ONE WAY.
//
// `round.dynamic` + `fpexcept.strict` is the pair that makes the call mean "one IEEE operation per
// element in whatever rounding mode MXCSR currently holds, and its exceptions are observable". The
// mode is installed by the enclosing bracket and the exceptions are harvested by it, so neither is
// ever a per-opcode decision -- which is why this helper takes neither as a parameter.
//
// STRICTFP, AND WHAT WAS ACTUALLY CHECKED RATHER THAN ASSUMED (LLVM 20.1.8, the version this tree
// builds against):
//   * the Verifier does NOT reject a constrained intrinsic call in a function without the
//     attribute -- checked directly with `opt -passes=verify` on both forms;
//   * `opt -passes='default<O3>'` leaves both forms' calls intact, because the intrinsic's own
//     declaration carries `strictfp` and `memory(inaccessiblemem: readwrite)`.
// So this is NOT a bug fix for an observed miscompile. It is the construction LLVM's own IRBuilder
// performs whenever it is in constrained-FP mode -- `setConstrainedFPFunctionAttr()` adds the
// function attribute and `setConstrainedFPCallAttr()` the call-site one (IRBuilder.h) -- and
// setting it makes the IR correct by declaration rather than correct by what today's pass pipeline
// happens to do with it.
//
// APPLIED TO THE F1 FRAME'S CALLS ONLY. `Emit_rvvfalu` and `Emit_rvvfma` (the P-vector-SSA family)
// deliberately still build their calls inline and are byte-for-byte what they were, so a region
// containing only that family emits exactly the IR it emitted before F1. A region that ALSO
// contains an F1 frame gains the function-level attribute -- that is function scope and cannot be
// otherwise -- but no operand, metadata or call-site attribute of the older family's calls changes,
// and the two checks above say the attribute is inert for them at this LLVM version.
// C4 (2026-09-18). THE MULTI-TYPE FORM, AND WHY IT HAD TO EXIST.
//
// `Intrinsic::getOrInsertDeclaration`'s third argument is the list of types the intrinsic is
// OVERLOADED on, in declaration order. The arithmetic intrinsics this file used until C4
// (`fadd`/`fsub`/`fmul`/`fdiv`/`fma`/`sqrt`) are overloaded on ONE type, so a single-element list
// was right and the single-type entry point below is still right for them. The conversions are NOT:
// `llvm.experimental.constrained.sitofp` and `.uitofp` are overloaded on the RESULT type AND the
// OPERAND type -- the mangled name is `.v8f64.v8i64`. Passing only the result type builds a
// declaration whose type list does not match the intrinsic's signature, and the malformed
// declaration segfaults `llvm::TypeFinder` the first time anything walks the module's types (it
// crashed `Module::print`; the Verifier and any pass pipeline would have been next). The function
// itself still printed and the call still carried the right intrinsic ID, so every IR-inspection
// assertion passed while the module was unprintable -- which is how this was found.
llvm::Value *QIRToLLVM::RvvConstrainedFPCallN(llvm::Intrinsic::ID id,
					      llvm::ArrayRef<llvm::Type *> overload_tys,
					      llvm::ArrayRef<llvm::Value *> args)
{
	auto fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, id, overload_tys);
	auto *round = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "round.dynamic"));
	auto *except = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "fpexcept.strict"));
	llvm::SmallVector<llvm::Value *, 4> call_args(args.begin(), args.end());
	call_args.push_back(round);
	call_args.push_back(except);
	auto *call = lb->CreateCall(fn, call_args);
	call->addFnAttr(llvm::Attribute::StrictFP);
	if (!func->hasFnAttribute(llvm::Attribute::StrictFP))
		func->addFnAttr(llvm::Attribute::StrictFP);
	return call;
}

llvm::Value *QIRToLLVM::RvvConstrainedFPCall(llvm::Intrinsic::ID id, llvm::Type *fty,
					     llvm::ArrayRef<llvm::Value *> args)
{
	return RvvConstrainedFPCallN(id, {fty}, args);
}

llvm::Value *QIRToLLVM::RvvConstrainedFPCallNoRound(llvm::Intrinsic::ID id,
						    llvm::ArrayRef<llvm::Type *> overload_tys,
						    llvm::ArrayRef<llvm::Value *> args)
{
	auto fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, id, overload_tys);
	auto *except = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "fpexcept.strict"));
	llvm::SmallVector<llvm::Value *, 3> call_args(args.begin(), args.end());
	call_args.push_back(except);
	auto *call = lb->CreateCall(fn, call_args);
	call->addFnAttr(llvm::Attribute::StrictFP);
	if (!func->hasFnAttribute(llvm::Attribute::StrictFP))
		func->addFnAttr(llvm::Attribute::StrictFP);
	return call;
}

// The funct6 -> constrained-intrinsic map for the vector-vector FP arithmetic family, and the
// FAIL-CLOSED end of the admission rule in rv32_vector_lower.h. `TRANSLATOR(vfalu)` builds an
// `InstRVVFALU` only for a funct6 `vfalu_llvm_constrained_vv_supported` accepts, so the default arm
// is unreachable in a consistent build -- which is exactly why it Panics instead of guessing. A
// funct6 that gained an admission row without gaining an intrinsic row here would be a loud
// translation failure, never a silently substituted operation.
//
// F1: it now has a SECOND caller, QIRToLLVM::Emit_vchunkfalu (the typed FP frame). One map, two
// families -- so the per-instruction route and the frame route cannot lower the same funct6 to
// different arithmetic.
//
// Each row is an exact identity, not an approximation: RVV's vfadd/vfsub/vfmul/vfdiv compute one
// IEEE 754 operation per active element in the dynamic rounding mode, which is what
// `llvm.experimental.constrained.f{add,sub,mul,div}` with `round.dynamic` + `fpexcept.strict`
// denotes. The rounding mode itself is installed once per frame by `Emit_rvvfpbegin` (guest `frm`
// -> MXCSR RC) and the raised exceptions are accrued back to `fcsr` by `Emit_rvvfpend`, so nothing
// about the mode or the flags is per-opcode.
static llvm::Intrinsic::ID RvvFaluConstrainedIntrinsic(u8 funct6)
{
	switch (funct6) {
	case rv32::VF6_VFADD:
		return llvm::Intrinsic::experimental_constrained_fadd;
	case rv32::VF6_VFSUB:
		return llvm::Intrinsic::experimental_constrained_fsub;
	case rv32::VF6_VFMUL:
		return llvm::Intrinsic::experimental_constrained_fmul;
	case rv32::VF6_VFDIV:
		return llvm::Intrinsic::experimental_constrained_fdiv;
	default:
		Panic("llvmgen: rvvfalu funct6 has no constrained arithmetic lowering");
	}
}

void QIRToLLVM::Emit_rvvfalu(qir::InstRVVFALU *ins)
{
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.falu.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.falu.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.falu.done", func);
	lb->CreateCondBr(RvvGuard(ins->vtype, ins->evl, true, ins->partial_vl), fast, slow);
	lb->SetInsertPoint(fast);
	RvvCount(true);
	auto *fty = llvm::FixedVectorType::get(ins->sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), 64 / ins->sew);
	auto fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, RvvFaluConstrainedIntrinsic(ins->funct6), {fty});
	auto *round = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "round.dynamic"));
	auto *except = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "fpexcept.strict"));
	// OPERAND ORDER IS THE ENCODING'S, AND IT IS THE SAME FOR ALL FOUR ROWS. Every admitted
	// `.vv` form is `vd[i] = vs2[i] OP vs1[i]`, so `a` (the vs2 chunk) is argument 0 and `b` (the
	// vs1 chunk) is argument 1 -- which is why non-commutative `fsub`/`fdiv` need no special case
	// and why the reverse forms `vfrsub`/`vfrdiv`, which swap them, are refused at admission
	// rather than handled by a flag here.
	//
	// ONE CALL PER CHUNK, AND THE CHUNKS ARE INDEPENDENT. `active_chunks` is 1 at VLEN 512 and 2
	// at VLEN 1024; iteration `c` reads only chunk `c` of each source and defines only chunk `c`
	// of the destination, so there is no def-use edge between the two calls at VLEN 1024.
	//
	// C5-FP FAMILY A (2026-09-18), THE PARTIAL-VL ARM. Three separate obligations, and none of
	// them is discharged by either of the other two:
	//
	//   1. THE OPERANDS of an inactive lane are forced to +1.0, because the enclosing bracket ORs
	//      the host MXCSR sticky bits into `fcsr` and an exception raised while COMPUTING a lane
	//      the instruction must not touch would be architecturally visible. See
	//      RvvNeutralizeInactiveFP; the value is +1.0 and not +0.0 because `(+0)/(+0)` raises NV
	//      and `VF6_VFDIV` is one of the four funct6 this node lowers.
	//   2. THE DESTINATION lane is merged back from the OLD vd. Family B could skip this because
	//      its store is predicated; here the destination is a residency value with no store to
	//      predicate, so an unmerged chunk would publish computed garbage for elements at or above
	//      `vl`. Preserving is legal under BOTH tail policies (`vta` permits it, `vtu` requires
	//      it) and is byte-identical to `rvv_ref::vfalu`, whose loop simply stops at `vl`.
	//   3. THE MERGE IS AFTER CANONICALISATION, NOT BEFORE. `RvvCanonicalize` runs an `fcmp uno`
	//      over the whole chunk and rewrites any NaN lane to the RISC-V canonical quiet NaN.
	//      Applied to an already-merged chunk it would rewrite a PRESERVED lane that happened to
	//      hold a non-canonical or signalling NaN -- a silent corruption of bytes the instruction
	//      must not write. So the computed value is canonicalised first and the select is the last
	//      thing that touches the chunk. `select` is a bitwise lane choice, not an FP operation:
	//      it raises nothing and cannot quiet the preserved bits.
	//
	// EACH CHUNK'S MASK STARTS AT ITS OWN ELEMENT BASE. Chunk `c` holds group elements
	// `[c*lanes, (c+1)*lanes)` at every admitted (VLEN, SEW, LMUL): at VLEN 512 a register is one
	// chunk, at VLEN 1024 it is two and `RvvReadGroup` maps chunk `c` to register `c/2` sub-chunk
	// `c%2`, which is the same linear element order. A lane-0 mask would be right for chunk 0 and
	// wrong for every other one.
	for (u8 c = 0; c < ins->active_chunks; ++c) {
		u32 const lanes = 64u / ins->sew;
		llvm::Value *mask = ins->partial_vl ? RvvActiveLaneMask(lanes, c * lanes) : nullptr;
		auto *a = lb->CreateBitCast(LoadVOperand(ins->i(4 + c)), fty);
		auto *b = lb->CreateBitCast(LoadVOperand(ins->i(8 + c)), fty);
		if (mask) {
			a = RvvNeutralizeInactiveFP(a, mask, fty);
			b = RvvNeutralizeInactiveFP(b, mask, fty);
		}
		auto *r = lb->CreateCall(fn, {a, b, round, except});
		llvm::Value *val = RvvCanonicalize(lb->CreateBitCast(r, MakeType(VType::V512)),
						   ins->sew, VType::V512);
		if (mask) {
			auto *old = lb->CreateBitCast(LoadVOperand(ins->i(c)), fty);
			val = lb->CreateBitCast(
			    lb->CreateSelect(mask, lb->CreateBitCast(val, fty), old),
			    MakeType(VType::V512));
		}
		StoreVOperand(ins->o(c), val);
	}
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(done);
	lb->SetInsertPoint(slow);
	RvvCount(false);
	// C5-FP FAMILY A: THE FALLBACK ARM HAS TO PUBLISH vd TOO, AND ONLY NOW.
	//
	// A full-VL helper call overwrites every element of vd, so vd's prior CPUState content was
	// dead and this arm never stored it. A PARTIAL-VL helper call does not: `rvv_ref::vfalu` runs
	// `for (e = vstart; e < vl; ++e)` and leaves the rest of vd exactly as it found it in
	// CPUState. The residency may be holding a DIRTY value for vd that CPUState has never seen, so
	// without this store the helper would preserve stale bytes and `RvvLoadGroup` below would read
	// them straight back into the residency. This is why `oldd` is an operand of the node rather
	// than something the fast arm loads for itself.
	if (ins->partial_vl)
		RvvStoreGroup(ins->vd, ins->active_chunks, ins->inputs(), 0);
	RvvStoreGroup(ins->vs2, ins->active_chunks, ins->inputs(), 4);
	RvvStoreGroup(ins->vs1, ins->active_chunks, ins->inputs(), 8);
	RvvCallFallback(ins->stub, ins->raw);
	auto vals = RvvLoadGroup(ins->vd, ins->active_chunks);
	for (u8 c = 0; c < ins->active_chunks; ++c)
		StoreVOperand(ins->o(c), vals[c]);
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_rvvfma(qir::InstRVVFMA *ins)
{
	auto *fast = llvm::BasicBlock::Create(lctx, "rvv.fma.direct", func);
	auto *slow = llvm::BasicBlock::Create(lctx, "rvv.fma.fallback", func);
	auto *done = llvm::BasicBlock::Create(lctx, "rvv.fma.done", func);
	lb->CreateCondBr(RvvGuard(ins->vtype, ins->evl, true, ins->partial_vl), fast, slow);
	lb->SetInsertPoint(fast);
	RvvCount(true);
	auto *fty = llvm::FixedVectorType::get(ins->sew == 4 ? lb->getFloatTy() : lb->getDoubleTy(), 64 / ins->sew);
	auto fn = llvm::Intrinsic::getOrInsertDeclaration(&cmodule, llvm::Intrinsic::experimental_constrained_fma, {fty});
	auto *round = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "round.dynamic"));
	auto *except = llvm::MetadataAsValue::get(lctx, llvm::MDString::get(lctx, "fpexcept.strict"));
	// C5-FP FAMILY A (2026-09-18), THE PARTIAL-VL ARM FOR THE FUSED FORM.
	//
	// ONE funct6 AND ONE ONLY. `TRANSLATOR(vfma)`'s Family A arm requires
	// `i.funct6() == VF6_VFMADD`, so the neutrality argument has exactly one operation to cover:
	// `fma(+1.0, +1.0, +1.0) = 2.0`, exactly representable, normal, and raising nothing in any of
	// the four rounding modes the guard admits (`frm <= FRM_RUP`). The other seven fused forms and
	// every other funct6 reach the `rv32_vfma` helper and are NOT covered by that argument.
	//
	// THREE OPERANDS ARE NEUTRALISED, INCLUDING THE `.vf` BROADCAST. `i(12)` is not a scalar at
	// this point: `Create_rvvsplatf` has already materialised the F register into a full V512
	// broadcast, so it is a lane operand exactly like the other two and an inactive lane would
	// multiply a real value by it. Leaving it alone would raise flags from lanes the instruction
	// must not touch -- the same defect the neutralisation exists to prevent, and one that
	// neutralising only `d` and `a` would hide behind a passing operand count.
	//
	// THE MERGE USES THE UN-NEUTRALISED `d`. `oldd` is doing two jobs here that it does not do in
	// `vfalu`: it is a MULTIPLICAND of the fused operation and it is the value inactive lanes must
	// keep. The neutralised copy feeds the call; the original feeds the merge. Using the
	// neutralised one would publish +1.0 into every inactive lane of vd.
	for (u8 c = 0; c < ins->active_chunks; ++c) {
		u32 const lanes = 64u / ins->sew;
		llvm::Value *mask = ins->partial_vl ? RvvActiveLaneMask(lanes, c * lanes) : nullptr;
		auto *d = lb->CreateBitCast(LoadVOperand(ins->i(c)), fty);
		auto *a = lb->CreateBitCast(LoadVOperand(ins->i(4 + c)), fty);
		auto *b = lb->CreateBitCast(LoadVOperand(ins->is_vf ? ins->i(12) : ins->i(8 + c)), fty);
		llvm::Value *dn = d, *an = a, *bn = b;
		if (mask) {
			dn = RvvNeutralizeInactiveFP(d, mask, fty);
			an = RvvNeutralizeInactiveFP(a, mask, fty);
			bn = RvvNeutralizeInactiveFP(b, mask, fty);
		}
		// vfmadd: vd = fma(vd_old, vs1, vs2), one rounding.
		auto *r = lb->CreateCall(fn, {dn, bn, an, round, except});
		llvm::Value *val = RvvCanonicalize(lb->CreateBitCast(r, MakeType(VType::V512)),
						   ins->sew, VType::V512);
		// Canonicalise first, merge last -- see Emit_rvvfalu for why the other order silently
		// rewrites a preserved non-canonical or signalling NaN.
		if (mask)
			val = lb->CreateBitCast(
			    lb->CreateSelect(mask, lb->CreateBitCast(val, fty), d),
			    MakeType(VType::V512));
		StoreVOperand(ins->o(c), val);
	}
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
	RvvStateStore(VType::I32, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart),
		      lb->getInt32(0), llvm::Align(4));
	lb->CreateBr(done);
	lb->SetInsertPoint(slow);
	RvvCount(false);
	// C5-FP Family A: this arm ALREADY published vd, and that is the condition `Emit_rvvfalu`'s
	// fallback had to be given. It is unconditional here because `vfmadd` reads vd in every
	// execution, partial or not, so a partial-VL helper call that preserves vd's elements at and
	// above `vl` from CPUState is already reading bytes this store made current. Nothing to add.
	RvvStoreGroup(ins->vd, ins->active_chunks, ins->inputs(), 0);
	RvvStoreGroup(ins->vs2, ins->active_chunks, ins->inputs(), 4);
	if (!ins->is_vf)
		RvvStoreGroup(ins->vs1, ins->active_chunks, ins->inputs(), 8);
	RvvCallFallback(ins->stub, ins->raw);
	auto vals = RvvLoadGroup(ins->vd, ins->active_chunks);
	for (u8 c = 0; c < ins->active_chunks; ++c)
		StoreVOperand(ins->o(c), vals[c]);
	for (u8 c = ins->active_chunks; c < 4; ++c)
		StoreVOperand(ins->o(c), llvm::Constant::getNullValue(MakeType(VType::V512)));
	lb->CreateBr(done);
	lb->SetInsertPoint(done);
}

void QIRToLLVM::Emit_br(qir::InstBr *ins)
{
	auto qbb_s = qbb->GetSuccs().at(0);

	lb->CreateBr(MapBB(qbb_s));
}

// DC-9 fix candidate (--aot-brcc-real-weights): exec_count is collected by objprof for EVERY
// executed guest block regardless of edge kind (direct/conditional/indirect), always on, zero
// extra cost -- this just looks it up. Linear scan over pages is compile-time only (called once
// per guest brcc during AOT lowering, never at guest runtime), so its cost is irrelevant next to
// the LLVM O3 passes that follow. Returns 0 if the ip was never seen as an executed block entry.
static u64 LookupExecCount(u32 ip)
{
	for (auto const &page : dbt::objprof::GetProfile()) {
		u32 page_vaddr = page.pageno << dbt::mmu::PAGE_BITS;
		if (ip - page_vaddr >= dbt::mmu::PAGE_SIZE)
			continue;
		u32 idx = dbt::objprof::PageData::po2idx(ip - page_vaddr);
		return page.exec_count[idx];
	}
	return 0;
}

// A-line Round 48 (--aot-gbrind-hitrate-file / --aot-gbrind-hitrate-weights): loads a
// --gbrind-hitrate-out dump once. Keyed by the SAME dbt::tcache::gbrind_hitrate_hash(src_ip) the
// QCG-side collector already hashed with -- the dump only stores the hash (not the source ip, not
// generally invertible), so a lookup here re-hashes the querying source's OWN ip identically. This
// is the exact same accepted collision tradeoff shadow_edge2_cache already makes (two sources
// sharing a hashed slot get merged hit/miss counts) -- never wrong, only occasionally
// less-precise for the rare colliding pair.
static std::unordered_map<u32, std::pair<u64, u64>> const &GbrindHitrateMap()
{
	static std::unordered_map<u32, std::pair<u64, u64>> m;
	static bool loaded = false;
	if (!loaded) {
		loaded = true;
		if (dbt::config::aot_gbrind_hitrate_file && dbt::config::aot_gbrind_hitrate_file[0]) {
			std::ifstream f(dbt::config::aot_gbrind_hitrate_file);
			u32 slot_hash;
			u64 hit, miss;
			while (f >> std::hex >> slot_hash >> std::dec >> hit >> miss)
				m[slot_hash] = {hit, miss};
			log_qir("gbrind-hitrate profile: %zu hashed slots loaded", m.size());
		}
	}
	return m;
}

void QIRToLLVM::Emit_brcc(qir::InstBrcc *ins)
{
	auto lhs = LoadVOperand(ins->i(0));
	auto rhs = LoadVOperand(ins->i(1));
	auto cmp = lb->CreateCmp(MakeCC(ins->cc), lhs, rhs);

	auto bb_t = MapBB(qbb->GetSuccs().at(0));
	auto bb_f = MapBB(qbb->GetSuccs().at(1));

	llvm::MDNode *weights = g.md_unlikely;
	if (unlikely(dbt::config::aot_brcc_real_weights)) {
		u64 t_cnt = LookupExecCount(ins->t_ip);
		u64 f_cnt = LookupExecCount(ins->f_ip);
		if (t_cnt || f_cnt) {
			// +1 on both sides: a structural floor (createBranchWeights rejects an all-zero pair),
			// not a tuned constant -- it never changes which side is heavier, only avoids the
			// degenerate 0:0 case for a branch whose targets were both otherwise unexecuted.
			auto mdb = llvm::MDBuilder(lctx);
			weights = mdb.createBranchWeights((u32)std::min<u64>(t_cnt + 1, ~0u),
							   (u32)std::min<u64>(f_cnt + 1, ~0u));
			if (getenv("DC9_DEBUG"))
				fprintf(stderr, "DC9_WEIGHT t_ip=%08x t_cnt=%llu f_ip=%08x f_cnt=%llu\n", ins->t_ip,
					(unsigned long long)t_cnt, ins->f_ip, (unsigned long long)f_cnt);
		}
		// else: neither target has profile data (shouldn't happen for an executed brcc under a
		// real AOT profile, but stay safe) -- fall through to the unchanged static hint.
	}

	lb->CreateCondBr(cmp, bb_t, bb_f, weights);
}

void QIRToLLVM::Emit_gbr(qir::InstGBr *ins)
{
	auto gip = ins->tpc.GetConst();
	CreateQCGGbr(gip, false);
}

// LaneA cyclic-merge fix (2026-07-23): the common (edge-specialize + L1-cache + slowpath) tail of
// gbrind lowering, factored out so it can be emitted EITHER inline at a single call site (the
// unchanged default/no-merge behavior, byte-identical to before this fix) OR once as a shared
// per-function block that every internal-merge gbrind call site branches into (see the
// `internal_dispatch_targets` block in Expand_gbrind below, and the comment on
// LLVMGen::internal_gbrind_tail_bb in llvmgen.h). Everything in here is a function of `gipv` and
// function-generic state (gen.statev, gen.g, ...) only -- no call-site-local SSA value is
// referenced -- so sharing it behind a PHI on `gipv` is semantics-preserving.
static void Expand_gbrind_EdgeSpecializeAndSlowpath(LLVMGen &gen, llvm::Value *gipv,
						      llvm::MDNode *vp_md = nullptr,
						      llvm::MDNode *site_id_md = nullptr,
						      llvm::MDNode *order1_md = nullptr,
						      llvm::MDNode *marginal_md = nullptr,
						      llvm::MDNode *static_table_md = nullptr,
						      llvm::MDNode *vtable_narrow_md = nullptr,
						      llvm::MDNode *indexed_table_md = nullptr,
						      llvm::Value *indexv = nullptr, u32 src_ip = 0)
{
	auto *lb = gen.lb;
	// A-line round 28 Gate 1: relaxed load-add-store CPUState counter bump, same pattern as
	// aot_count_gbrind above -- zero cost unless the relevant oracle is actually on. Moved to the
	// top of the function (Round 44) so the indexed-dispatch block below can use it too.
	auto bump_ctr = [&](size_t off) {
		auto *gep = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()), off);
		auto *gv = lb->CreateAlignedLoad(lb->getInt64Ty(), gep, llvm::Align(alignof(u64)));
		lb->CreateAlignedStore(lb->CreateAdd(gv, lb->getInt64(1)), gep, llvm::Align(alignof(u64)));
	};

	// A-line Round 44: index-preserving compact host dispatch. Structurally different from
	// static_table_md below (which switches on the RESOLVED, scattered guest ADDRESS and hopes
	// LLVM's SelectionDAG recognizes a jump table -- it structurally cannot, for non-dense case
	// values, see ROUND43's finding) -- this switches on the ORIGINAL, small, dense INDEX instead,
	// with an EXPLICITLY-CONSTRUCTED compile-time host-address table, so density/O(1) codegen is
	// guaranteed by construction, not hoped for. IR shape: one icmp (bounds check) + one branch +
	// one GEP + one load + one indirect call -- O(1) control-flow IR regardless of table size N;
	// the table itself is O(N) constant DATA (a global array), not O(N) control-flow instructions.
	// Falls back to the unchanged generic gbrind path (falls through to the code below) if the
	// index is out of bounds OR the resolved entry isn't independently AOT-admitted (same Consumer
	// C concern as every other oracle here -- never a license to assume every target is compiled).
	if (indexed_table_md && indexv) {
		llvm::SmallVector<u32, 32> table_targets;
		for (unsigned i = 0; i < indexed_table_md->getNumOperands(); ++i) {
			auto *cv = llvm::cast<llvm::ConstantAsMetadata>(indexed_table_md->getOperand(i))->getValue();
			table_targets.push_back((u32)llvm::cast<llvm::ConstantInt>(cv)->getZExtValue());
		}
		u32 table_len = (u32)table_targets.size();
		// Resolve each entry to its AOT-compiled host function NOW (compile time) -- entries that
		// aren't independently admitted get a null sentinel, checked at the load site below (the
		// Consumer C fallback: never assume every proven-reachable target is actually compiled).
		llvm::SmallVector<llvm::Constant *, 32> host_entries;
		bool any_admitted = false;
		u32 n_admitted = 0;
		for (u32 t : table_targets) {
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(t));
			if (tfn) {
				host_entries.push_back(tfn);
				any_admitted = true;
				n_admitted++;
			} else {
				host_entries.push_back(llvm::ConstantPointerNull::get(lb->getPtrTy()));
			}
		}
		// A-line Round 45: compile-time-only (zero profile) worst-case cost dominance proof.
		// n_admitted/table_len is a STRUCTURAL fact (which proven candidates are already
		// independently AOT-compiled), not a runtime observation. When n_admitted == table_len,
		// EVERY in-bounds index this dispatch could ever see (the SAME bound the guest's own code
		// already enforces before reaching here) resolves to a real, non-null host entry -- the
		// fallback path (out-of-bounds or null) becomes structurally unreachable for any correctly-
		// bounded guest execution, so the extra bounds+load+null-check overhead is paid exactly
		// once per dispatch with NO possibility of ALSO paying the original path's cost on top
		// (Round 45's causal finding: sqlite_super's regression came from exactly this double-
		// payment on its 44.1%-miss sites). See config.h's aot_indexed_dispatch_require_full_
		// coverage comment for the gate itself.
		if (getenv("DBT_INDEXEDDISPATCH_LOG_SITES")) {
			fprintf(stderr, "INDEXEDDISPATCH_COVERAGE table_len=%u n_admitted=%u full=%d\n", table_len,
				n_admitted, (int)(n_admitted == table_len));
			// Round 46: per-slot admitted bitmap -- needed to tell whether non-admitted slots are
			// scattered (a contiguous-subrange gate would not help much) or clustered (it would),
			// a structural fact distinct from the aggregate count above.
			fprintf(stderr, "INDEXEDDISPATCH_BITMAP");
			for (u32 i = 0; i < table_len; ++i)
				fprintf(stderr, " %d", host_entries[i]->isNullValue() ? 0 : 1);
			fprintf(stderr, "\n");
		}
		if (dbt::config::aot_indexed_dispatch_require_full_coverage && n_admitted != table_len)
			any_admitted = false; // gate closed -- fall through to the unchanged generic path entirely
		if (any_admitted) {
			bump_ctr(offsetof(CPUState, gbrind_indexeddispatch_covered));
			auto *arr_ty = llvm::ArrayType::get(lb->getPtrTy(), table_len);
			auto *table_init = llvm::ConstantArray::get(arr_ty, host_entries);
			auto *table_gv = new llvm::GlobalVariable(gen.cmodule, arr_ty, /*isConstant=*/true,
								    llvm::GlobalValue::PrivateLinkage, table_init,
								    "gbrind_indexed_table");
			auto *oob_bb = llvm::BasicBlock::Create(gen.lctx);
			auto *check_null_bb = llvm::BasicBlock::Create(gen.lctx);
			auto *hit_bb = llvm::BasicBlock::Create(gen.lctx);
			oob_bb->insertInto(gen.func);
			check_null_bb->insertInto(gen.func);
			hit_bb->insertInto(gen.func);
			auto *in_bounds = lb->CreateICmpULT(indexv, gen.constv<32>(table_len));
			lb->CreateCondBr(in_bounds, check_null_bb, oob_bb);

			lb->SetInsertPoint(check_null_bb);
			auto *gep = lb->CreateInBoundsGEP(arr_ty, table_gv, {gen.constv<32>(0), indexv});
			auto *entry = lb->CreateAlignedLoad(lb->getPtrTy(), gep, llvm::Align(alignof(uptr)));
			auto *is_null = lb->CreateICmpEQ(entry, llvm::ConstantPointerNull::get(lb->getPtrTy()));
			lb->CreateCondBr(is_null, oob_bb, hit_bb);

			lb->SetInsertPoint(hit_bb);
			bump_ctr(offsetof(CPUState, gbrind_indexeddispatch_hits));
			{
				auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
							     offsetof(CPUState, ip));
				lb->CreateAlignedStore(gipv, ipp, llvm::Align(alignof(u32)));
			}
			gen.CreateQCGFnCall(entry);

			lb->SetInsertPoint(oob_bb);
			// falls through to the unchanged generic gbrind path below (L1 cache + slowpath) --
			// same fallback every other oracle here uses on a miss.
		}
	}

	// A-line round 28 Gate 1 (default off, ORACLE ONLY -- exhaustive-truth-for-the-measured-run,
	// never a deployable method): per-SOURCE order-1 context guard. Reads/updates THIS SITE'S OWN
	// tcache::gbrind_ctx1_slots[slot] entry (decoded from order1_md's first operand) -- never
	// CPUState::last_brind_target, never shared with any other gbrind site. For each (prev,
	// predicted_target) pair this source's exhaustive trace actually observed (order1_md's
	// remaining operands, in pairs), a guard fires only when BOTH the runtime slot matches that
	// prev value AND the actual computed target matches the prediction -- a genuine two-part
	// verification, not an unconditional substitution. Exact same block-construction pattern as
	// the pre-existing aot_edge_specialize/aot_context_edge_specialize blocks immediately below
	// (fresh BasicBlock::Create + CreateCondBr + direct call in the hit block, fall through
	// otherwise) -- deliberately NOT the Round-26 predecessor-redirect/clone approach that had
	// real PHI/dominance bugs; this approach never touches any predecessor edge.
	if (order1_md) {
		bump_ctr(offsetof(CPUState, gbrind_order1_covered));
		auto *slot_cv = llvm::cast<llvm::ConstantAsMetadata>(order1_md->getOperand(0))->getValue();
		u32 slot = (u32)llvm::cast<llvm::ConstantInt>(slot_cv)->getZExtValue();
		// AOT-compiled code runs in a DIFFERENT PROCESS than elfaot compiled it in (elfrun, not
		// elfaot) -- baking (uptr)tcache::gbrind_ctx1_slots.data() as computed HERE (elfaot's own
		// address space) would be meaningless/unsafe there. Load the pointer FIELD from CPUState
		// instead (populated by elfrun's own in-process CPUState construction), exactly matching
		// l1_brind_cache/majority_cache's existing AOT-side pattern -- never a baked address for
		// this tier (JIT/QCG code, a different code generator entirely, is the only place that
		// technique is valid, since it compiles IN elfrun's own process).
		auto *slots_ptr_ep = gen.MakeStateEP(lb->getPtrTy(), offsetof(CPUState, gbrind_ctx1_slots));
		auto *slots_base = lb->CreateAlignedLoad(lb->getPtrTy(), slots_ptr_ep, llvm::Align(alignof(uptr)));
		auto *slot_base = lb->CreateInBoundsGEP(lb->getInt32Ty(), slots_base, gen.constv<32>(slot));
		auto *runtime_prev = lb->CreateAlignedLoad(lb->getInt32Ty(), slot_base, llvm::Align(alignof(u32)));
		gen.AScopeOther(runtime_prev);
		lb->CreateAlignedStore(gipv, slot_base, llvm::Align(alignof(u32))); // update THIS site's own history
		for (unsigned i = 1; i + 1 < order1_md->getNumOperands(); i += 2) {
			auto *prev_cv = llvm::cast<llvm::ConstantAsMetadata>(order1_md->getOperand(i))->getValue();
			auto *tgt_cv = llvm::cast<llvm::ConstantAsMetadata>(order1_md->getOperand(i + 1))->getValue();
			u32 P = (u32)llvm::cast<llvm::ConstantInt>(prev_cv)->getZExtValue();
			u32 T = (u32)llvm::cast<llvm::ConstantInt>(tgt_cv)->getZExtValue();
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(T));
			if (!tfn)
				continue; // predicted target not admitted as an AOT fn -- cannot direct-call; skip
			auto *hit = llvm::BasicBlock::Create(gen.lctx);
			auto *cont = llvm::BasicBlock::Create(gen.lctx);
			hit->insertInto(gen.func);
			cont->insertInto(gen.func);
			auto *g = lb->CreateAnd(lb->CreateICmpEQ(runtime_prev, gen.constv<32>(P)),
						 lb->CreateICmpEQ(gipv, gen.constv<32>(T)));
			lb->CreateCondBr(g, hit, cont);
			lb->SetInsertPoint(hit);
			bump_ctr(offsetof(CPUState, gbrind_order1_hits));
			{
				auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
							     offsetof(CPUState, ip));
				lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
			}
			gen.CreateQCGFnCall(tfn);
			lb->SetInsertPoint(cont);
		}
	}

	// A-line round 29 Gate 1 (default off, ORACLE ONLY): per-SOURCE MARGINAL (context-free) guard.
	// Deliberately carries NO runtime state -- no slot load, no prev compare, no history-update
	// store -- just one compile-time-constant compare of gipv against this source's exhaustive
	// majority target. Built to test whether removing order-1's two runtime-state operations (which
	// data analysis showed are paid at every covered dispatch even for the 73%/53% of sources that
	// only ever had ONE observed target, i.e. context added nothing there) lets the same class of
	// branch-miss win clear the execution-only ceiling that the order-1 guard failed to clear.
	if (marginal_md) {
		bump_ctr(offsetof(CPUState, gbrind_marginal_covered));
		auto *tgt_cv = llvm::cast<llvm::ConstantAsMetadata>(marginal_md->getOperand(0))->getValue();
		u32 T = (u32)llvm::cast<llvm::ConstantInt>(tgt_cv)->getZExtValue();
		auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(T));
		if (tfn) {
			auto *hit = llvm::BasicBlock::Create(gen.lctx);
			auto *cont = llvm::BasicBlock::Create(gen.lctx);
			hit->insertInto(gen.func);
			cont->insertInto(gen.func);
			lb->CreateCondBr(lb->CreateICmpEQ(gipv, gen.constv<32>(T)), hit, cont);
			lb->SetInsertPoint(hit);
			bump_ctr(offsetof(CPUState, gbrind_marginal_hits));
			{
				auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
							     offsetof(CPUState, ip));
				lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
			}
			gen.CreateQCGFnCall(tfn);
			lb->SetInsertPoint(cont);
		}
	}

	// A-line round 32 Gate 2 (default off, ORACLE ONLY): per-SOURCE static jump-table guard, lowered
	// as a REAL llvm::SwitchInst -- the structural difference from order-1/marginal's hand-rolled
	// sequential compare chains (Rounds 28-30, killed on economics). The target set here is not a
	// profile-derived guess: it was read directly from the guest ELF's own read-only memory offline
	// (r32_bootstrap_tool.py), verified immutable against the guest's actual mapped segment
	// permissions, and is PROVEN COMPLETE for this source (not just the most-observed subset) --
	// see qir.h's InstGBrind::static_table_targets comment. LLVM's own SelectionDAG chooses jump-
	// table codegen (O(1)) over a compare chain when the case set is dense enough, reusing existing,
	// well-tested backend infrastructure instead of hand-rolling dispatch cost analysis.
	// Round 51: when --aot-static-table-alwaysinline is on, QIRToLLVM::Emit_gbrind already built
	// this exact guard EAGERLY (with an inlinable, non-musttail call) before this deferred pass
	// ever runs -- skip here to avoid constructing the SAME switch twice (once eager+inlinable,
	// once deferred+musttail) for the same site.
	if (static_table_md && !dbt::config::aot_static_table_alwaysinline) {
		bump_ctr(offsetof(CPUState, gbrind_statictable_covered));
		llvm::SmallVector<std::pair<u32, llvm::Function *>, 8> cases;
		for (unsigned i = 0; i < static_table_md->getNumOperands(); ++i) {
			auto *cv = llvm::cast<llvm::ConstantAsMetadata>(static_table_md->getOperand(i))->getValue();
			u32 T = (u32)llvm::cast<llvm::ConstantInt>(cv)->getZExtValue();
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(T));
			if (tfn)
				cases.emplace_back(T, tfn);
		}
		if (!cases.empty()) {
			auto *cont = llvm::BasicBlock::Create(gen.lctx);
			auto *default_bb = cont; // no admitted target for a table entry -> generic slowpath
			auto *sw_bb = lb->GetInsertBlock();
			auto *sw = lb->CreateSwitch(gipv, default_bb, (unsigned)cases.size());
			cont->insertInto(gen.func);
			for (auto const &[T, tfn] : cases) {
				auto *hit = llvm::BasicBlock::Create(gen.lctx);
				hit->insertInto(gen.func);
				sw->addCase(gen.constv<32>(T), hit);
				lb->SetInsertPoint(hit);
				bump_ctr(offsetof(CPUState, gbrind_statictable_hits));
				{
					auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
								     offsetof(CPUState, ip));
					lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
				}
				gen.CreateQCGFnCall(tfn); // this path only runs when alwaysinline is off (see outer guard above)
			}
			(void)sw_bb;
			lb->SetInsertPoint(cont);
		}
	}

	// A-line Round 33 (default off, ORACLE ONLY): per-SOURCE C++ virtual-call RTTI-narrowed target
	// set, lowered the SAME way as static_table_md immediately above (a real llvm::SwitchInst,
	// default case falls to `cont` i.e. the unchanged generic gbrind slowpath) -- but this set is
	// NOT proven-complete (qir.h's InstGBrind::vtable_narrow_targets comment), so unlike
	// static_table_md a miss here is an ordinary, expected outcome, not evidence of a bug.
	if (vtable_narrow_md) {
		bump_ctr(offsetof(CPUState, gbrind_vtablenarrow_covered));
		llvm::SmallVector<std::pair<u32, llvm::Function *>, 8> cases;
		for (unsigned i = 0; i < vtable_narrow_md->getNumOperands(); ++i) {
			auto *cv = llvm::cast<llvm::ConstantAsMetadata>(vtable_narrow_md->getOperand(i))->getValue();
			u32 T = (u32)llvm::cast<llvm::ConstantInt>(cv)->getZExtValue();
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(T));
			// Round 36 Consumer C pilot instrumentation (compile-time only, no runtime cost):
			// count how often a resolved candidate is dropped here purely because its target
			// function isn't independently admitted yet -- see rv32_qir.h's Stats comment.
			dbt::vtable_narrow::g_stats.consumer_candidate_total++;
			if (tfn) {
				dbt::vtable_narrow::g_stats.consumer_candidate_admitted++;
				cases.emplace_back(T, tfn);
			}
		}
		// A-line Round 36 Consumer B compile-cost ATTRIBUTION diagnostic (env-gated, not a
		// shipped feature -- same convention as DBT_VTABLENARROW_LOG_SITES etc.): truncate the
		// case list to at most DBT_VN_MAXCAND entries so a compile-time A/B run can attribute how
		// much of vtable_narrow's LLVM-compile-cost delta comes specifically from small/wide-poly
		// sites' multi-case SwitchInst, vs the exact-singleton sites' single-guard cost. Dropped
		// cases fall through to the existing, unchanged generic gbrind slowpath -- the SAME
		// fallback path an ordinary miss already takes, so this cannot change correctness.
		if (char const *cap_s = getenv("DBT_VN_MAXCAND")) {
			size_t cap = (size_t)strtoul(cap_s, nullptr, 10);
			if (cases.size() > cap)
				cases.resize(cap);
		}
		// A-line Round 36 Consumer A' (default off, --aot-vtable-narrow-zeroguard-singleton):
		// when there is EXACTLY ONE candidate, skip the compare/branch entirely -- an
		// UNCONDITIONAL CreateQCGFnCall, the SAME same-LLVM-function guarded-call primitive
		// every "hit" case above already uses (not a new, separately-risky mechanism -- see
		// rv32_qir.cpp's TRANSLATOR(jalr) comment for why the QIR-level MakeGBr/Create_gbr
		// region-jump alternative was tried and killed as unsound). No gipv compare, no `cont`
		// fallback block, no miss path at all: if the size-1 RTTI proof is wrong for even one
		// call, this call is simply wrong (no safety net) -- this is the entire POINT of "zero
		// guard" and is why it is a separate, explicitly-flagged mechanism, not the default.
		if (cases.size() == 1 && dbt::config::aot_vtable_narrow_zeroguard_singleton) {
			auto const &[T, tfn] = cases[0];
			bump_ctr(offsetof(CPUState, gbrind_vtablenarrow_hits));
			{
				auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
							     offsetof(CPUState, ip));
				lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
			}
			gen.CreateQCGFnCall(tfn);
			return;
		}
		if (!cases.empty()) {
			auto *cont = llvm::BasicBlock::Create(gen.lctx);
			auto *sw = lb->CreateSwitch(gipv, cont, (unsigned)cases.size());
			cont->insertInto(gen.func);
			for (auto const &[T, tfn] : cases) {
				auto *hit = llvm::BasicBlock::Create(gen.lctx);
				hit->insertInto(gen.func);
				sw->addCase(gen.constv<32>(T), hit);
				lb->SetInsertPoint(hit);
				bump_ctr(offsetof(CPUState, gbrind_vtablenarrow_hits));
				{
					auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
								     offsetof(CPUState, ip));
					lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
				}
				gen.CreateQCGFnCall(tfn);
			}
			lb->SetInsertPoint(cont);
		}
	}

	// Round-46 edge specialization: guarded DIRECT fastpath for the top-K profiled hot targets. A direct
	// call to a known AOT function lets LLVM inline/optimize ACROSS the indirect edge (the L1-cache path
	// below calls an opaque code pointer). Miss -> falls through to the unchanged L1-cache+slowpath.
	if (dbt::config::aot_edge_specialize) {
		for (uint32_t T : dbt::config::aot_edge_targets) {
			// Round-46 P6 under-admit gate: skip targets already naturally admitted (prof mx >= threshold).
			// Their warm-AOT indirect call is near-free; specializing them only adds guard + harmful inline
			// of large handlers -> regression (P4 raw: sqlite +4.5%, antlr4 +19.4%). Specialize ONLY the
			// under-admitted hot targets the freq rule missed (e.g. wasm3 swtable handlers) -> complements
			// admission instead of duplicating it. Tests the prof quantity, fixing the P5 scale mis-fire.
			if (dbt::config::aot_edge_underadmit_gate && dbt::config::aot_natural_admitted.count(T))
				continue;
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(T));
			if (!tfn)
				continue; // target not admitted as an AOT fn -> cannot direct-call; skip
			auto *hit = llvm::BasicBlock::Create(gen.lctx);
			auto *cont = llvm::BasicBlock::Create(gen.lctx);
			hit->insertInto(gen.func);
			cont->insertInto(gen.func);
			lb->CreateCondBr(lb->CreateICmpEQ(gipv, gen.constv<32>(T)), hit, cont);
			lb->SetInsertPoint(hit);
			// Alias-entry multi-entry contract: refresh state->ip to the actual target before
			// this direct call, same reasoning as CreateQCGGbr's store (see its comment).
			{
				auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
							    offsetof(CPUState, ip));
				lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
			}
			gen.CreateQCGFnCall(tfn); // direct musttail GHC call (same cc as the existing fastpath)
			lb->SetInsertPoint(cont);
		}
	}

	auto slowp_bb = llvm::BasicBlock::Create(gen.lctx);
	auto fastp_bb = llvm::BasicBlock::Create(gen.lctx);
	slowp_bb->insertInto(gen.func);
	fastp_bb->insertInto(gen.func);

	llvm::Value *entry_ep;
	{
		auto cache_ep = gen.MakeStateEP(lb->getPtrTy(), offsetof(CPUState, l1_brind_cache));
		auto cachev = lb->CreateAlignedLoad(lb->getPtrTy(), cache_ep, llvm::Align(alignof(uptr)));
		gen.AScopeState(cachev);

		llvm::Value *hashv = lb->CreateLShr(gipv, gen.constv<32>(2));
		hashv = lb->CreateAnd(hashv, gen.constv<32>((1ull << tcache::L1_CACHE_BITS) - 1));

		entry_ep = lb->CreateInBoundsGEP(gen.g.brind_cache_entry_ty, cachev, hashv);
		auto entry_gip_ep = lb->CreateStructGEP(gen.g.brind_cache_entry_ty, entry_ep, 0);
		auto entry_gipv =
		    lb->CreateAlignedLoad(lb->getInt32Ty(), entry_gip_ep, llvm::Align(alignof(u32)));
		gen.AScopeOther(entry_gipv);

		// A-line Round 48: this L1-cache-check branch is the ONE always-on, unconditional decision
		// point every indirect dispatch in this compiler goes through -- `md_unlikely` claims
		// P(miss)~=7.7% for EVERY site, the exact same class of blanket-wrong static assumption
		// DC-9 found for guest conditional branches (Round 44/45's own sqlite_super site measured a
		// REAL 44.1% miss rate, nearly 6x the blanket hint). Unlike DC-9 (guest brcc, exec_count),
		// this uses a genuinely different, Round-48-new per-source acquisition (gbrind_hitrate_cache
		// hit/miss counts) since Wendell has no representation of per-source indirect target
		// concentration at all -- the gap this round's audit named.
		llvm::MDNode *weights = gen.g.md_unlikely;
		if (unlikely(dbt::config::aot_gbrind_hitrate_weights) && src_ip) {
			auto const &hr = GbrindHitrateMap();
			if (auto it = hr.find(tcache::gbrind_hitrate_hash(src_ip)); it != hr.end()) {
				u64 hit = it->second.first, miss = it->second.second;
				if (hit || miss) {
					// weights are (branch-taken, branch-not-taken); the branch here is
					// ICmpNE(entry_gipv,gipv) (true = miss = taken -> slowp_bb), so
					// (miss+1, hit+1) -- same +1 structural floor DC-9 uses, never changes
					// which side is heavier, only avoids createBranchWeights' 0:0 rejection.
					auto mdb = llvm::MDBuilder(gen.lctx);
					weights = mdb.createBranchWeights((u32)std::min<u64>(miss + 1, ~0u),
									   (u32)std::min<u64>(hit + 1, ~0u));
					if (getenv("GBRIND_HITRATE_DEBUG"))
						fprintf(stderr, "GBRIND_HITRATE_WEIGHT src_ip=%08x hit=%llu miss=%llu\n",
							src_ip, (unsigned long long)hit, (unsigned long long)miss);
				}
			}
		}
		lb->CreateCondBr(lb->CreateICmpNE(entry_gipv, gipv), slowp_bb, fastp_bb, weights);
	}

	{
		lb->SetInsertPoint(fastp_bb);

		auto entry_code_ep = lb->CreateStructGEP(gen.g.brind_cache_entry_ty, entry_ep, 1);
		auto entry_codev =
		    lb->CreateAlignedLoad(lb->getPtrTy(), entry_code_ep, llvm::Align(alignof(uptr)));
		gen.AScopeOther(entry_codev);

		// Alias-entry multi-entry contract: the L1 cache only stores raw code pointers, not
		// which guest ip they correspond to beyond `gipv` itself (already verified == the
		// cached entry's gip on this path). Refresh state->ip so a multi-entry callee's own
		// switch sees the correct requested entry.
		{
			auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
						    offsetof(CPUState, ip));
			lb->CreateAlignedStore(gipv, ipp, llvm::Align(alignof(u32)));
		}
		// A-line round 23 Gate 1 Row 5 (oracle-only): the L1-cache-hit fast path is the ONLY
		// dispatch shape in this whole lowering that is a genuine indirect CallInst through a
		// runtime-computed callee (entry_codev) -- CreateQCGGbr's known-target paths always call a
		// statically-resolved llvm::Function, and the generic-unresolved paths use InlineAsm or an
		// opaque intrinsic. Attaching real !VP metadata HERE (not at the intrinsic call site,
		// which never survives as a real indirect CallInst past Expand_gbrind's own lowering) is
		// the only point where LLVM's PGOIndirectCallPromotion pass has anything legal to consume.
		auto *fastp_call = gen.CreateQCGFnCall(entry_codev);
		if (vp_md)
			fastp_call->setMetadata(llvm::LLVMContext::MD_prof, vp_md);
		if (site_id_md)
			fastp_call->setMetadata("dbt_gbrind_site_id", site_id_md);
	}

	// A-line 2026-07-27 (--gbrind-hitrate-collect, AOT-tier extension): the existing per-source
	// hit/miss counter (tcache::gbrind_hitrate_cache, dbt/qmc/qcg/qemit.cpp's Emit_gbrind) only
	// ever increments in QCG-tier codegen -- the AOT/LLVM lowering here never wrote to it, so
	// --gbrind-hitrate-collect silently measured nothing for any AOT-admitted dispatch site (the
	// gap found while building the wasm3 runtime-coverage decision-regret evidence this cycle).
	// Reuses the SAME data structure, hash, and --gbrind-hitrate-out dump path -- just extends
	// the write side to this tier. `src_ip` is a compile-time constant here (a jalr always
	// terminates its TB), so the slot's absolute host address is baked as an immediate, the same
	// technique shadow_edge2_cache/gbrind_hitrate_cache's own QCG-tier writer already uses.
	if (unlikely(dbt::config::gbrind_hitrate_collect) && src_ip) {
		auto &slot = tcache::gbrind_hitrate_cache[tcache::gbrind_hitrate_hash(src_ip)];
		auto emit_inc = [&](llvm::Value *field_ptr) {
			auto *ep = lb->CreateIntToPtr(gen.constv<64>((uptr)field_ptr), lb->getPtrTy());
			auto *v = lb->CreateAlignedLoad(lb->getInt64Ty(), ep, llvm::Align(alignof(u64)));
			lb->CreateAlignedStore(lb->CreateAdd(v, lb->getInt64(1)), ep, llvm::Align(alignof(u64)));
		};
		auto *save_bb = lb->GetInsertBlock();
		lb->SetInsertPoint(fastp_bb, fastp_bb->begin());
		emit_inc((llvm::Value *)&slot.hit);
		lb->SetInsertPoint(save_bb);
	}

	{
		lb->SetInsertPoint(slowp_bb);
		if (unlikely(dbt::config::gbrind_hitrate_collect) && src_ip) {
			auto &slot = tcache::gbrind_hitrate_cache[tcache::gbrind_hitrate_hash(src_ip)];
			auto *ep = lb->CreateIntToPtr(gen.constv<64>((uptr)&slot.miss), lb->getPtrTy());
			auto *v = lb->CreateAlignedLoad(lb->getInt64Ty(), ep, llvm::Align(alignof(u64)));
			lb->CreateAlignedStore(lb->CreateAdd(v, lb->getInt64(1)), ep, llvm::Align(alignof(u64)));
		}
		auto target = lb->CreateCall(
		    gen.g.qcg_stub_brind_fnty,
		    gen.MakeRStub(RuntimeStubId::id_brind, gen.g.qcg_stub_brind_fnty), {gen.statev, gipv});
		gen.CreateQCGFnCall(target);
	}
}

// A-line round 26 Part A/Track C helper: gipv is never a bare LoadInst in practice -- RISC-V
// jalr's "clear bit 0" ISA requirement means it is (load state->reg) `and` -2, confirmed via
// GBRIND_EXPAND_PREDS diagnostic (55/56 real sites on expat: an `and` of a `load`; the remaining
// site is a PHI, conservatively rejected below). Recursively clones a chain of side-effect-free,
// single-non-constant-operand instructions (a LoadInst from CPUState memory, or a unary/binary-
// with-one-constant-operand instruction wrapping one) into `insertBefore`'s block. Returns the
// cloned root value, or nullptr if the chain contains anything not provably safe to re-execute
// (e.g. a PHI, a call, a multi-variable-operand instruction) -- callers must treat nullptr as
// "do not replicate this site," never as a license to reuse the original (cross-block-dominance-
// violating) value.
static llvm::Value *CloneSimpleValueChain(llvm::IRBuilder<> *lb, llvm::Value *v)
{
	// Values that trivially dominate every block in the function -- safe to reuse AS-IS, no
	// cloning needed (this is what the original bug missed: a load's POINTER OPERAND, e.g. a GEP
	// into CPUState computed from the state argument, also needs this same treatment, not just
	// the load itself).
	if (llvm::isa<llvm::Argument>(v) || llvm::isa<llvm::Constant>(v) || llvm::isa<llvm::GlobalValue>(v))
		return v;
	auto *load = llvm::dyn_cast<llvm::LoadInst>(v);
	if (load) {
		auto *cloned_ptr = CloneSimpleValueChain(lb, load->getPointerOperand());
		if (!cloned_ptr)
			return nullptr;
		return lb->CreateAlignedLoad(load->getType(), cloned_ptr, load->getAlign());
	}
	if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(v)) {
		auto *cloned_base = CloneSimpleValueChain(lb, gep->getPointerOperand());
		if (!cloned_base)
			return nullptr;
		llvm::SmallVector<llvm::Value *, 4> idxs;
		for (auto &idx : gep->indices()) {
			if (!llvm::isa<llvm::Constant>(idx.get()))
				return nullptr; // non-constant index -- not the MakeStateEP pattern, bail
			idxs.push_back(idx.get());
		}
		return lb->CreateGEP(gep->getSourceElementType(), cloned_base, idxs, "", gep->isInBounds());
	}
	auto *inst = llvm::dyn_cast<llvm::Instruction>(v);
	if (!inst || inst->mayHaveSideEffects() || inst->getNumOperands() != 2)
		return nullptr;
	auto *bin = llvm::dyn_cast<llvm::BinaryOperator>(inst);
	if (!bin || !llvm::isa<llvm::Constant>(bin->getOperand(1)))
		return nullptr;
	auto *cloned_lhs = CloneSimpleValueChain(lb, bin->getOperand(0));
	if (!cloned_lhs)
		return nullptr;
	auto *cloned = llvm::cast<llvm::BinaryOperator>(bin->clone());
	cloned->setOperand(0, cloned_lhs);
	lb->Insert(cloned);
	return cloned;
}

static bool Expand_gbrind(LLVMGen &gen, llvm::CallInst *call, bool must_expand)
{
	auto gipv = call->getArgOperand(2);
	auto *lb = gen.lb;

	if (auto const_gipv = llvm::dyn_cast<llvm::Constant>(gipv)) {
		auto gip = llvm::cast<llvm::ConstantInt>(const_gipv)->getZExtValue();
		log_qir("Optimized gbrind->gbr(%08x) in %s", gip, gen.func->getName());
		dbt::config::gbrind_constfold_count++;
		dbt::config::gbrind_total_expand_count++;
		if (dbt::config::aot_log_gbrind_constfold)
			fprintf(stderr, "GBRIND_SITE FOLDED target=%08x in %s\n", (unsigned)gip,
				gen.func->getName().str().c_str());
		lb->GetInsertBlock()->getTerminator()->eraseFromParent();
		gen.CreateQCGGbr(gip, must_expand);
		return true;
	}

	// A-line round 25 Track B free-oracle test (default off, diagnostic only): classify gipv's
	// post-O3 IR shape when it did NOT const-fold above, to check whether the "PHI/select of
	// per-edge constants" pattern this candidate needs actually survives rvdbt's CPUState-memory
	// guest-register model far enough to reach here. Static site counts only -- no dynamic
	// weighting, no codegen change, purely observational.
	if (dbt::config::aot_log_gipv_shape) {
		char const *shape = "other";
		if (auto *phi = llvm::dyn_cast<llvm::PHINode>(gipv)) {
			bool all_const = true, any_const = false;
			for (auto &use : phi->incoming_values()) {
				if (llvm::isa<llvm::Constant>(use.get()))
					any_const = true;
				else
					all_const = false;
			}
			shape = all_const ? "phi_all_const" : any_const ? "phi_mixed" : "phi_no_const";
		} else if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(gipv)) {
			bool ta = llvm::isa<llvm::Constant>(sel->getTrueValue());
			bool fa = llvm::isa<llvm::Constant>(sel->getFalseValue());
			shape = (ta && fa) ? "select_all_const" : (ta || fa) ? "select_mixed" : "select_no_const";
		} else if (llvm::isa<llvm::LoadInst>(gipv)) {
			shape = "load";
		}
		fprintf(stderr, "GIPV_SHAPE site=%s shape=%s\n", gen.func->getName().str().c_str(), shape);
	}

	if (!must_expand) {
		return false;
	}

	// ORACLE-ONLY benefit/tax separation (CORRECTION_ORACLE_OVERCLAIM.md part C, CROSSPAGE_ORACLE_
	// REACHABILITY.md): when set, replace the ENTIRE dispatch (constfold path already handled above)
	// with an UNCONDITIONAL direct call to the configured target -- no guard compare, no cache lookup,
	// no slowpath. This BREAKS CORRECTNESS for any traffic that isn't actually that target, by design;
	// it measures the pure best-case benefit of "if the guard/cache always hit for free" with ZERO
	// guard-check tax, uncontaminated by the real guard's minority-traffic cost. NEVER default-on,
	// NEVER a deployable mode. A correctness-checked run using this flag is EXPECTED to fail
	// correctness on any input that doesn't always hit the one configured target -- that failure is
	// how its use is confirmed, not a bug.
	if (dbt::config::aot_edge_oracle_unconditional && !dbt::config::aot_edge_targets.empty()) {
		auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(dbt::config::aot_edge_targets[0]));
		if (tfn) {
			lb->GetInsertBlock()->getTerminator()->eraseFromParent();
			gen.CreateQCGFnCall(tfn);
			return true;
		}
	}

	// A-line round 25 Track A Treatment 1 (ORACLE-ONLY, default off): same house style as the
	// block immediately above, but per-SOURCE (via the dbt_return_oracle metadata Emit_gbrind
	// attaches) instead of one global target -- the perfect/free ceiling for the static-fan-in
	// RETURN candidate. Breaks correctness by design for any traffic not matching the marked
	// single known target; measurement-only, never deployable.
	if (dbt::config::aot_return_oracle_unconditional) {
		if (auto *tag = call->getMetadata("dbt_return_oracle")) {
			auto *cv = llvm::cast<llvm::ConstantAsMetadata>(tag->getOperand(0))->getValue();
			u32 target_ip = (u32)llvm::cast<llvm::ConstantInt>(cv)->getZExtValue();
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(target_ip));
			if (tfn) {
				lb->GetInsertBlock()->getTerminator()->eraseFromParent();
				gen.CreateQCGFnCall(tfn);
				return true;
			}
		}
	}

	dbt::config::gbrind_total_expand_count++;
	if (dbt::config::aot_log_gbrind_constfold)
		fprintf(stderr, "GBRIND_SITE UNFOLDED in %s\n", gen.func->getName().str().c_str());
	lb->GetInsertBlock()->getTerminator()->eraseFromParent();
	if (dbt::config::aot_count_gbrind) {
		// A-line surface (a): count how many indirect dispatches EXECUTE inside AOT code (each pays the
		// AOT-side probe+indirect-call sequence, invisible to the runtime brind_slow counter). Same
		// relaxed load-add-store pattern as the DVET work counter; artifact is measurement-only.
		auto *gep = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
					    offsetof(CPUState, gbrind_counter));
		auto *gv = lb->CreateAlignedLoad(lb->getInt64Ty(), gep, llvm::Align(alignof(u64)));
		lb->CreateAlignedStore(lb->CreateAdd(gv, lb->getInt64(1)), gep, llvm::Align(alignof(u64)));
	}

	// path-history exec-proof: CONTEXT-keyed (2-level) specialization. Read the GLOBAL previous indirect target
	// (the path context), UPDATE it to the current target, then for each hot (prev P -> predicted T) context emit
	// a guarded DIRECT musttail call: `if (prev_old==P && gip==T) T_aot()`. The conjunction makes the guard fire
	// only on the path-predicted edge (higher precision than the 1-level `gip==T` on polymorphic sites). Miss ->
	// falls through to the unchanged L1-cache+slowpath (correctness preserved on ANY target). Global prev
	// (CPUState::last_brind_target) is the minimal prototype; the store happens on every expansion so the context
	// is always current. Default path (flag off) never touches the slot -> baseline byte-identical.
	if (dbt::config::aot_context_edge_specialize) {
		auto prev_ep = gen.MakeStateEP(lb->getPtrTy(), offsetof(CPUState, last_brind_target));
		auto prev_old = lb->CreateAlignedLoad(lb->getInt32Ty(), prev_ep, llvm::Align(alignof(u32)));
		gen.AScopeOther(prev_old);
		lb->CreateAlignedStore(gipv, prev_ep, llvm::Align(alignof(u32))); // update path context for next dispatch
		for (auto const &[P, T] : dbt::config::aot_context_edges) {
			auto *tfn = gen.cmodule.getFunction(MakeAotSymbol(T));
			if (!tfn)
				continue; // predicted target not admitted as an AOT fn -> cannot direct-call; skip
			auto *hit = llvm::BasicBlock::Create(gen.lctx);
			auto *cont = llvm::BasicBlock::Create(gen.lctx);
			hit->insertInto(gen.func);
			cont->insertInto(gen.func);
			auto *g = lb->CreateAnd(lb->CreateICmpEQ(prev_old, gen.constv<32>(P)),
						lb->CreateICmpEQ(gipv, gen.constv<32>(T)));
			lb->CreateCondBr(g, hit, cont);
			lb->SetInsertPoint(hit);
			// Alias-entry multi-entry contract, same reasoning as the other guarded fastpaths.
			{
				auto *ipp = gen.MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
							    offsetof(CPUState, ip));
				lb->CreateAlignedStore(gen.constv<32>(T), ipp, llvm::Align(alignof(u32)));
			}
			gen.CreateQCGFnCall(tfn); // direct musttail GHC call (same cc as the existing fastpath)
			lb->SetInsertPoint(cont);
		}
	}

	// P3 single-entry edge-directed region merge: the majority-coverage handler entries are INTERNAL
	// blocks of this function -- dispatch to them is an intra-function switch (jump table on ITTAGE-class
	// hardware, no guard chains, no call overhead, full LLVM cross-block optimization). Miss -> falls
	// through to the unchanged L1-cache+slowpath. Single entry: the Round-41 GHC-GHC wall never arises.
	//
	// LaneA cyclic-merge fix (2026-07-23): this used to build the switch + fall through into an
	// INLINE copy of the edge-specialize/L1-cache/slowpath tail AT EVERY internal gbrind call site --
	// i.e. once per merged region's own indirect branch (N call sites for an N-node merge group), each
	// emitting a full, structurally-identical copy of "switch over all internal_dispatch_targets ->
	// entry2bb_m[tgt]". For a genuinely CYCLIC merge group (internal targets that are themselves also
	// merge sources, so the target blocks gain predecessors from MANY of these redundant switches),
	// this manufactures an irreducible (multi-entry) loop in the LLVM CFG: confirmed via
	// DBT_IR_DUMP_DIR-gated dumps (see docs/DIVERGENCE_EVIDENCE.md) that the subsequent default-O3
	// pass (SimpleLoopUnswitch, needing to convert the irreducible region to reducible form) node-
	// splits a single target block into ~10 ".us"-suffixed clones -- ONE PER PRE-EXISTING REDUNDANT
	// SWITCH -- and remaps the N pre-existing switches to those clones INCONSISTENTLY (a MAJORITY
	// correct, 1-2 stale/wrong per target, confirmed against objdump of the compiled artifact), which
	// is a genuine miscompilation (wrong guest control transfer -> guest memory fault at runtime).
	// Fix: emit the switch + tail only ONCE per function (into a fresh, function-owned block) and have
	// EVERY internal call site fall through to it via a plain unconditional branch, carrying its own
	// `gipv` through a PHI. This removes the redundant N-copy encoding -- there is only ever ONE
	// dispatch instance for LLVM's loop-legalization to (self-consistently, if at all) clone, instead
	// of N independently-diverging ones. The non-merge path below (internal_dispatch_targets empty,
	// the overwhelming common case) is completely unchanged -- byte-identical to before this fix.
	if (!gen.internal_dispatch_targets.empty()) {
		// 18th-cycle splice-PHI fix v2 (root cause of the "PHINode should have one entry for each
		// predecessor" crash on expat/pcre2/tinyxml2/pugixml): intrinsic expansion runs AFTER O3
		// iterations have inserted PHIs (GVN-PRE %.pre values) into the entry2bb_m blocks and any
		// prior tail's successors. At that point BOTH prior strategies are unsound:
		//   (a) branching into a persisted tail (10th-cycle fix) leaves the tail's O3-created
		//       non-gipv PHIs without an incoming for the new edge;
		//   (b) building a FRESH switch here (the code this replaces) does addCase into
		//       PHI-bearing entry2bb_m blocks, breaking every PHI in them.
		// The only safe internal switch is the Run()-time eager one (Emit_gbrind, built pre-O3,
		// where no PHIs can exist yet). Every original merge-function gbrind site goes through
		// that eager path and never reaches this intrinsic expansion; a site that DOES land here
		// belongs to a function body LLVM inlined into this merge function between passes. Such
		// late sites take the external dispatch path, which is always semantically valid (the
		// same lowering every non-merge function uses); they merely forgo the intra-function
		// switch fast path. Non-merge functions (targets empty) are byte-identical as before.
		Expand_gbrind_EdgeSpecializeAndSlowpath(gen, gipv);
		return true;
	}

	// A-line round 23 Gate 1 Row 5 (oracle-only): scope matches Row 4's precedent exactly -- ONLY
	// this stock/unguarded fallthrough (not the internal-merge path above, not any guard-mechanism
	// call site) forwards the !prof metadata Emit_gbrind may have attached to the intrinsic call.
	llvm::MDNode *vp_md = dbt::config::aot_gbrind_vp_metadata
				  ? call->getMetadata(llvm::LLVMContext::MD_prof)
				  : nullptr;
	llvm::MDNode *site_id_md = dbt::config::aot_log_gbrind_site_identity
					? call->getMetadata("dbt_gbrind_site_id")
					: nullptr;
	// A-line Round 48: src_ip is always attached (see Emit_gbrind); only read it when the consumer
	// is actually on, matching every other oracle-gated md read here. A-line 2026-07-27: also
	// gated on gbrind_hitrate_collect now that the AOT-tier writer (below) needs src_ip too --
	// previously this read was reachable only via aot_gbrind_hitrate_weights, so the new AOT-tier
	// counter writer always saw src_ip=0 and silently never incremented anything.
	u32 src_ip = 0;
	if (dbt::config::aot_gbrind_hitrate_weights || dbt::config::gbrind_hitrate_collect) {
		if (auto *src_ip_md = call->getMetadata("dbt_gbrind_src_ip")) {
			auto *cv = llvm::cast<llvm::ConstantAsMetadata>(src_ip_md->getOperand(0))->getValue();
			src_ip = (u32)llvm::cast<llvm::ConstantInt>(cv)->getZExtValue();
		}
	}
	llvm::MDNode *order1_md = dbt::config::aot_order1_context_oracle
					  ? call->getMetadata("dbt_order1_context")
					  : nullptr;
	llvm::MDNode *marginal_md = dbt::config::aot_marginal_context_oracle
					    ? call->getMetadata("dbt_marginal_context")
					    : nullptr;
	llvm::MDNode *static_table_md = dbt::config::aot_static_table_oracle
						 ? call->getMetadata("dbt_static_table")
						 : nullptr;
	llvm::MDNode *vtable_narrow_md = dbt::config::aot_vtable_narrow_oracle
						  ? call->getMetadata("dbt_vtable_narrow")
						  : nullptr;

	// A-line round 26 Part A/Track C (default off, ORACLE, not a claimed contribution -- known
	// baseline is Ertl/Gregg dispatch replication / context threading): give each STATIC
	// predecessor of this dispatch its own physical host indirect-transfer site instead of
	// sharing one, while changing NOTHING about the lookup/targets/guard (no target guard, no
	// offline profile). Isolates whether predictor-CONTEXT loss (many guest control-flow paths
	// forced through one host branch PC) has full-single-run value, independent of the
	// already-closed target-frequency-guarding family. Correctness-safe by construction: gipv's
	// defining instruction is always a fresh re-load of the SAME CPUState memory location (side-
	// effect-free, safe to duplicate); if that assumption doesn't hold for a given site (gipv is
	// not a plain LoadInst), this conservatively falls back to the unchanged shared dispatch for
	// that site rather than risk a miscompile.
	if (dbt::config::aot_log_gbrind_site_identity) {
		auto *entry_bb0 = lb->GetInsertBlock();
		auto *gipv_inst = llvm::dyn_cast<llvm::Instruction>(gipv);
		fprintf(stderr, "GBRIND_EXPAND_PREDS func=%s n=%u gipv_kind=%s\n",
			gen.func->getName().str().c_str(),
			(unsigned)std::distance(llvm::pred_begin(entry_bb0), llvm::pred_end(entry_bb0)),
			gipv_inst ? gipv_inst->getOpcodeName() : "not-an-instruction");
	}
	if (dbt::config::aot_gbrind_context_replicate) {
		// A-line round 27 QUARANTINE: this oracle has a known, unresolved SEMANTIC miscompile
		// (wrong guest output on expat -- SHA mismatch, not caught by LLVM's verifier, two OTHER
		// structural bugs in this same mechanism WERE caught and fixed by the verifier; a third
		// remains). Its own premise (cross-source host-PC sharing) was independently falsified by
		// GBRIND_SITE_IDENTITY (Round 26) before this bug was even found -- not worth debugging
		// further. Hard-fail rather than silently produce wrong output if anyone re-enables this
		// flag before it is properly fixed (or removed). See ROUND26_SOURCECONTEXT_AND_TRACKC_
		// RESOLVED.md and ROUND27_TEMPORAL_CONTEXT_ENTROPY_AND_BASELINE_AUDIT.md.
		dbt::Panic("aot_gbrind_context_replicate is quarantined: known unresolved miscompile, "
			   "premise already falsified -- do not use");
		auto *entry_bb = lb->GetInsertBlock();
		if (entry_bb->hasNPredecessorsOrMore(2)) {
			llvm::SmallVector<llvm::BasicBlock *, 8> preds(llvm::predecessors(entry_bb));
			unsigned n_cloned = 0;
			// Keep ONE predecessor (the last) on the original block/gipv -- built below,
			// unchanged. Give every OTHER predecessor its own fresh clone, IF gipv's whole
			// defining chain is provably safe to re-execute (CloneSimpleValueChain returns
			// nullptr and this loop skips that predecessor, leaving it on the ORIGINAL shared
			// block, otherwise -- conservative, never a license to violate dominance).
			for (size_t i = 0; i + 1 < preds.size(); ++i) {
				auto *clone_bb = llvm::BasicBlock::Create(gen.lctx, entry_bb->getName() + ".ctxdup",
									    gen.func);
				lb->SetInsertPoint(clone_bb);
				auto *cloned_gipv = CloneSimpleValueChain(lb, gipv);
				if (!cloned_gipv) {
					clone_bb->eraseFromParent();
					continue;
				}
				preds[i]->getTerminator()->replaceSuccessorWith(entry_bb, clone_bb);
				// CRITICAL: entry_bb may carry OTHER PHI nodes (e.g. GVN-created values)
				// entirely unrelated to gipv, each still expecting an incoming edge from
				// preds[i] -- removePredecessor() fixes up every one of them. The clone
				// never references those values (Expand_gbrind_EdgeSpecializeAndSlowpath
				// is self-contained: only gen.statev + the cloned gipv chain), so removing
				// the edge, not replicating those values, is the correct and sufficient fix.
				entry_bb->removePredecessor(preds[i]);
				Expand_gbrind_EdgeSpecializeAndSlowpath(gen, cloned_gipv, vp_md, site_id_md);
				n_cloned++;
			}
			if (n_cloned > 0) {
				dbt::config::gbrind_context_replicate_sites++;
				dbt::config::gbrind_context_replicate_clones += n_cloned;
			}
			lb->SetInsertPoint(entry_bb);
		}
	}
	llvm::MDNode *indexed_table_md = dbt::config::aot_indexed_dispatch_oracle
						  ? call->getMetadata("dbt_indexed_dispatch")
						  : nullptr;
	llvm::Value *indexv = indexed_table_md ? call->getArgOperand(3) : nullptr;
	Expand_gbrind_EdgeSpecializeAndSlowpath(gen, gipv, vp_md, site_id_md, order1_md, marginal_md, static_table_md,
						 vtable_narrow_md, indexed_table_md, indexv, src_ip);
	return true;
}

void QIRToLLVM::Emit_gbrind(qir::InstGBrind *ins)
{
	auto gipv = LoadVOperand(ins->i(0));

	// A-line Round 51 (--aot-static-table-alwaysinline), EAGER construction fix for Round 50's
	// root-caused defect: Round 50 attached llvm::Attribute::AlwaysInline inside the DEFERRED
	// Expand_gbrind_EdgeSpecializeAndSlowpath pass (materialized several full-O3 passes later,
	// same "final intrinsic expansion" timing as intr_gbrind) -- but LLVM's AlwaysInlinerPass runs
	// EARLIER, as part of the normal O3 pipeline, so the attribute was attached after the only
	// pass that reads it had already finished; the call stayed a real, stack-growing call and
	// broke the trampoline's sp_unwindptr invariant (jitabi.cpp:332). Exactly the same class of
	// bug, and the same fix, as the LaneA cyclic-merge fix immediately below (internal_dispatch_
	// targets): build the guard+inlinable-call IR HERE, at Run()-time, BEFORE any O3 pass runs, so
	// AlwaysInlinerPass actually sees and acts on the real call. static_table_targets is a plain
	// QIR instruction field (not metadata) -- already fully available here, no round-trip needed.
	// A-line Round 64: isolate the switch-to-proven-candidates CONSUMER from the INLINING decision
	// that Round 54 causally attributed the whole guard+inline family's compile-cost regression to
	// ("compile cost overhead scales with TOTAL DUPLICATED BYTES" -- inlining specifically, not the
	// mere presence of a switch). `aot_static_table_alwaysinline` always inlines each target's FIRST
	// occurrence; this NEVER inlines ANY target -- every case uses the existing, already-validated,
	// zero-duplication `CreateQCGFnCall` (ordinary musttail, the same primitive an L1-cache hit or a
	// resolved direct call already uses elsewhere in this codebase). Tests whether replacing the
	// generic gbrind runtime dispatch (hash+compare+fallback-call, subject to real hardware branch
	// misprediction for genuinely polymorphic/data-driven sites, confirmed via direct PMU sampling on
	// a real site this round) with a statically-SOUND (not guessed) switch to `static_table_resolve`'s
	// PROVEN-exhaustive candidate set nets a win when compile cost is held to its structural minimum
	// (zero body duplication, matching what ANY other non-inlining consumer in this file already
	// costs). Mutually exclusive with `aot_static_table_alwaysinline` (default off, independent flag).
	// A-line Round 66 (--aot-static-table-target-optnone, default off, independent of switch_
	// noinline/alwaysinline below): Round 65's phase-timing breakdown found compile cost is
	// dominated (71-74%) by LLVM's optimize+expand pass run across EVERY admitted function, not by
	// anything either consumer below adds (their own IR-construction delta is <5% of compile) --
	// so no gate on THIS SITE's dispatch mechanism can move that needle. static_table_resolve's
	// candidate TARGETS are, on some real workloads, a substantial fraction of ALL admitted
	// functions (measured, not assumed: expat 181/489=37%, pcre2_super 294/643=46%, vs libyaml
	// 36/482=7.5%, interpreter_bench 10/171=5.8%, antlr4_generated 22/2245=1%) -- marking them
	// OptimizeNone+NoInline changes the SHARED baseline compile cost of this structurally-
	// identified function class directly, independent of whether any switch fires at this site.
	// Applied here (not only inside the consumers below) so it also takes effect with EITHER
	// consumer off, or with alwaysinline on (an optnone callee can still be later spliced by
	// Round 51's direct llvm::InlineFunction call -- inlining an unoptimized body is legal, if
	// unusual; not this round's concern, since alwaysinline's own compile cost is already closed
	// as regressive on inlining-tax grounds regardless).
	if (dbt::config::aot_static_table_target_optnone && ins->static_table_targets &&
	    !ins->static_table_targets->empty()) {
		for (u32 T : *ins->static_table_targets) {
			auto *tfn = cmodule.getFunction(MakeAotSymbol(T));
			if (tfn) {
				tfn->addFnAttr(llvm::Attribute::OptimizeNone);
				tfn->addFnAttr(llvm::Attribute::NoInline);
			}
		}
	}
	if (dbt::config::aot_static_table_switch_noinline && ins->static_table_targets &&
	    !ins->static_table_targets->empty()) {
		llvm::SmallVector<std::pair<u32, llvm::Function *>, 8> noinline_cases;
		for (u32 T : *ins->static_table_targets) {
			auto *tfn = cmodule.getFunction(MakeAotSymbol(T));
			if (tfn)
				noinline_cases.emplace_back(T, tfn);
		}
		if (!noinline_cases.empty()) {
			// A-line Round 64 refinement: the alwaysinline variant's per-site/per-case
			// gbrind_statictable_covered/hits counters are DIAGNOSTIC-only (measurement/
			// verification, never read by any correctness path) -- omitted here to hold this
			// variant's own compile cost to its structural minimum (switch + mandatory
			// state->ip store + musttail call only), isolating whether that residual
			// bookkeeping was itself a material fraction of Round 64's measured +4.25% compile
			// -cost delta, not assumed.
			auto *cont = llvm::BasicBlock::Create(lctx, "", func);
			auto *sw = lb->CreateSwitch(gipv, cont, (unsigned)noinline_cases.size());
			for (auto const &[T, tfn] : noinline_cases) {
				auto *hit = llvm::BasicBlock::Create(lctx, "", func);
				sw->addCase(constv<32>(T), hit);
				lb->SetInsertPoint(hit);
				{
					auto *ipp = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
								 offsetof(CPUState, ip));
					lb->CreateAlignedStore(constv<32>(T), ipp, llvm::Align(alignof(u32)));
				}
				CreateQCGFnCall(tfn); // zero-duplication dispatch, never inlined
			}
			// Miss (out-of-table or non-admitted entry) falls through to the SAME unchanged generic
			// gbrind path below, exactly as the alwaysinline variant already does.
			lb->SetInsertPoint(cont);
		}
	}
	if (dbt::config::aot_static_table_alwaysinline && ins->static_table_targets &&
	    !ins->static_table_targets->empty()) {
		// A-line Round 54 Hypothesis 1 (replaces Round 52's retracted duplicate-SLOT filter --
		// that filter operated on `static_table_targets`, which `TryResolve` ALREADY returns
		// deduplicated, so it was a structural no-op by construction, not merely empirically inert
		// on the tested workloads; re-read and confirmed this round). The real, confirmed risk is
		// CROSS-SITE sharing: the SAME target address can be independently resolved (and
		// independently admitted) at MORE THAN ONE distinct gbrind site (verified in real data:
		// pcre2_super's two sites' target lists share an address). Round 54's causal accounting
		// found compile-cost overhead scales with TOTAL DUPLICATED BYTES (copies x callee size,
		// not admission rate or table size) -- so inlining the same target at every site that
		// reaches it multiplies cost with no added per-copy benefit. Cap total duplication at
		// exactly ONE inlined copy per target, program-wide (`g.already_inlined_targets`): the
		// first site to reach a given target inlines it as before; every subsequent site
		// (`already_inlined_targets.count(T)`) still gets a real, correct, GUARDED dispatch to
		// that exact target, but via the existing, zero-duplication-cost `CreateQCGFnCall`
		// (ordinary musttail, exactly like the deferred/generic path) instead of a second
		// `CreateInlinableQCGFnCall`. This is a structural invariant (a hard cap of 1), not a
		// size/workload-tuned threshold -- it is a no-op on any table with no cross-site sharing
		// (the common case, confirmed: none of this round's 3 tested workloads' ADMITTED targets
		// were actually shared across sites in the measured runs, so this predicts NO CHANGE
		// there -- a falsifiable null, not assumed).
		llvm::SmallVector<std::pair<u32, llvm::Function *>, 8> cases;
		llvm::SmallVector<std::pair<u32, llvm::Function *>, 8> guarded_noinline_cases;
		for (u32 T : *ins->static_table_targets) {
			auto *tfn = cmodule.getFunction(MakeAotSymbol(T));
			if (!tfn)
				continue;
			if (g.already_inlined_targets.count(T)) {
				guarded_noinline_cases.emplace_back(T, tfn);
			} else {
				cases.emplace_back(T, tfn);
				g.already_inlined_targets.insert(T);
			}
		}
		if (!cases.empty() || !guarded_noinline_cases.empty()) {
			auto *gep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
						 offsetof(CPUState, gbrind_statictable_covered));
			auto *gv = lb->CreateAlignedLoad(lb->getInt64Ty(), gep, llvm::Align(alignof(u64)));
			lb->CreateAlignedStore(lb->CreateAdd(gv, lb->getInt64(1)), gep, llvm::Align(alignof(u64)));

			auto *cont = llvm::BasicBlock::Create(lctx, "", func);
			auto *sw = lb->CreateSwitch(gipv, cont, (unsigned)(cases.size() + guarded_noinline_cases.size()));
			auto build_hit = [&](u32 T, llvm::Function *tfn, bool inlinable) {
				auto *hit = llvm::BasicBlock::Create(lctx, "", func);
				sw->addCase(constv<32>(T), hit);
				lb->SetInsertPoint(hit);
				auto *hgep = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt64Ty()),
							  offsetof(CPUState, gbrind_statictable_hits));
				auto *hgv = lb->CreateAlignedLoad(lb->getInt64Ty(), hgep, llvm::Align(alignof(u64)));
				lb->CreateAlignedStore(lb->CreateAdd(hgv, lb->getInt64(1)), hgep,
							llvm::Align(alignof(u64)));
				{
					auto *ipp = LLVMGen::MakeStateEP(llvm::PointerType::getUnqual(lb->getInt32Ty()),
								 offsetof(CPUState, ip));
					lb->CreateAlignedStore(constv<32>(T), ipp, llvm::Align(alignof(u32)));
				}
				if (inlinable)
					CreateInlinableQCGFnCall(tfn);
				else
					CreateQCGFnCall(tfn); // already inlined once elsewhere -- no duplication here
			};
			for (auto const &[T, tfn] : cases)
				build_hit(T, tfn, true);
			for (auto const &[T, tfn] : guarded_noinline_cases)
				build_hit(T, tfn, false);
			// Miss (out-of-table or non-admitted entry) falls through to the SAME unchanged
			// generic gbrind path below -- `cont` is now the current insert point, so the
			// existing deferred/intrinsic construction runs exactly as it always has for
			// every other site, reusing that code unchanged rather than duplicating it.
			lb->SetInsertPoint(cont);
		}
	}

	// LaneA cyclic-merge fix (2026-07-23), REAL root cause: for a merge-enabled function
	// (internal_dispatch_targets non-empty), build the internal-dispatch switch + tail EAGERLY,
	// right here at Run()-time -- NOT via the deferred intr_gbrind intrinsic that Expand_gbrind only
	// materializes in the FINAL n_expands iteration, several full-O3 passes later.
	//
	// Evidence (docs/DIVERGENCE_EVIDENCE.md, IR dumps on a minimal real 2-node cycle 0x12e90<->0x16998
	// pulled straight from wasm3_swtable's own profile): with the deferred design, iterations 0..2 see
	// ONLY h9's fake keepalive entry-ip-switch edges (entry->bb.0, entry->bb.1) -- so LLVM's GVN/LICM
	// legally (for THAT CFG) hoists/CSEs each block's redundant `load state->a0` up into the shared
	// dominating `entry` block, producing ONE shared SSA value used by both bb.0 and bb.1. That hoist
	// is INVALID once the REAL internal edge bb.0->bb.1 exists (bb.0 STORES a new value into
	// state->a0 before reaching bb.1 on that path) -- but the hoist was already baked into the IR back
	// in iteration 0, and the real edge is only added in the final iteration, so nothing ever
	// reconsiders it. The stale shared value then flows into the gbrind dispatch itself, producing a
	// garbage guest target (observed: state->ip=4) and the guest memory fault. This is the SAME CLASS
	// of bug as h9's original UAF (an early O3 iteration commits to a decision based on a CFG that is
	// still missing edges the final iteration will add) but manifests as VALUE staleness instead of
	// BLOCK liveness -- fixed the same way: make the real edges exist from iteration 0, not just the
	// final one. entry2bb_m/internal_dispatch_targets are already fully populated before this point
	// (Run()'s own per-block creation loop runs first), so everything needed is available here.
	// Functions with internal_dispatch_targets empty (the overwhelming common case) are entirely
	// unaffected -- they still take the original deferred-intrinsic path below, byte-identical.
	if (!internal_dispatch_targets.empty()) {
		if (!internal_gbrind_tail_bb) {
			auto *saved_bb = lb->GetInsertBlock();
			auto saved_it = lb->GetInsertPoint();

			internal_gbrind_tail_bb = llvm::BasicBlock::Create(lctx, "internal_gbrind_tail", func);
			lb->SetInsertPoint(internal_gbrind_tail_bb);
			internal_gbrind_gipv_phi = lb->CreatePHI(lb->getInt32Ty(), 2, "internal_gbrind.gipv");

			auto *cont_sw = llvm::BasicBlock::Create(lctx, "", func);
			auto *sw = lb->CreateSwitch(internal_gbrind_gipv_phi, cont_sw,
						     (unsigned)internal_dispatch_targets.size());
			for (u32 tgt : internal_dispatch_targets) {
				auto it = entry2bb_m.find(tgt);
				if (it != entry2bb_m.end())
					sw->addCase(llvm::cast<llvm::ConstantInt>(constv<32>(tgt)), it->second);
			}
			lb->SetInsertPoint(cont_sw);
			Expand_gbrind_EdgeSpecializeAndSlowpath(*this, internal_gbrind_gipv_phi);

			lb->SetInsertPoint(saved_bb, saved_it);
		}
		internal_gbrind_gipv_phi->addIncoming(gipv, lb->GetInsertBlock());
		lb->CreateBr(internal_gbrind_tail_bb);
		return;
	}

	constexpr std::string_view intrin_name = "intr_gbrind";

	llvm::Function *intrin = cmodule.getFunction(intrin_name);
	if (!intrin) {
		// A-line Round 44: 4th param carries the index-preserving compact-dispatch INDEX as a
		// genuine SSA value (not metadata -- metadata cannot hold a non-constant value safely
		// across the later expansion pass; a real argument use keeps it alive/correctly updated
		// through any intervening LLVM transform, the same way gipv itself already is). Always
		// present in the intrinsic's type (so there is exactly one signature module-wide); a
		// dummy 0 is passed when this round's oracle is inactive -- byte-identical codegen for
		// every other consumer, since Expand_gbrind only reads it behind indexed_table_md.
		auto ftype = llvm::FunctionType::get(
		    lb->getVoidTy(), {lb->getPtrTy(), lb->getPtrTy(), lb->getInt32Ty(), lb->getInt32Ty()}, false);
		intrin = llvm::Function::Create(ftype, llvm::Function::ExternalLinkage, intrin_name, cmodule);
		intrin->setCallingConv(llvm::CallingConv::GHC);
		intrin->setDoesNotReturn();
		intrin->addFnAttr(llvm::Attribute::NoMerge);

		g.intrin_fns.insert({intrin_name, Expand_gbrind});
	}

	llvm::Value *indexv = constv<32>(0);
	if (ins->indexed_targets && !ins->indexed_targets->empty())
		indexv = LoadVOperand(ins->i(1));
	auto call = lb->CreateCall(intrin, {statev, membasev, gipv, indexv});
	call->setCallingConv(llvm::CallingConv::GHC);
	call->setTailCall();
	// A-line round 26 (default off, diagnostic only): tag this specific gbrind QIR instruction
	// with a monotonic, globally-unique id -- ground truth for "how many logical guest gbrind
	// sites exist" (dbt::config::g_gbrind_site_id_next), independent of and cross-checkable
	// against whatever LLVM's own optimizer does to the resulting host code afterward. Survives
	// to Expand_gbrind_EdgeSpecializeAndSlowpath's fastpath call the same way !prof/
	// dbt_return_oracle already do (metadata rides along through cloning/expansion).
	if (dbt::config::aot_log_gbrind_site_identity) {
		auto *tag = llvm::MDNode::get(
		    lctx, {llvm::ConstantAsMetadata::get(lb->getInt32(dbt::config::g_gbrind_site_id_next++))});
		call->setMetadata("dbt_gbrind_site_id", tag);
	}
	// A-line Round 48: this SOURCE's own compile-time-constant guest ip (InstGBrind::src_ip, always
	// populated -- see qir.h), attached as metadata so Expand_gbrind can key a --aot-gbrind-hitrate-
	// file lookup at LLVM-emission time. Attached unconditionally (zero cost -- one more constant
	// metadata operand on an already-metadata-bearing call); only READING it is oracle-gated
	// (--aot-gbrind-hitrate-weights).
	{
		auto *tag = llvm::MDNode::get(lctx, {llvm::ConstantAsMetadata::get(lb->getInt32(ins->src_ip))});
		call->setMetadata("dbt_gbrind_src_ip", tag);
	}
	// A-line round 23 Gate 1 Row 5 (oracle-only, default off): attach real LLVM !VP metadata
	// (IPVK_IndirectCallTarget format, GUIDs via llvm::GlobalValue::getGUID on the exact AOT
	// symbol name -- no Function needs to exist yet) here on the intrinsic call, since this
	// metadata survives the later clone/expansion into Expand_gbrind_EdgeSpecializeAndSlowpath's
	// real indirect musttail call (see that function's own comment on WHY that's the only site
	// with a legal indirect CallInst to promote). Does not touch codegen unless
	// --aot-gbrind-vp-metadata is set: metadata alone changes nothing without the ICP pass and
	// the forwarding read in Expand_gbrind.
	if (dbt::config::aot_gbrind_vp_metadata && ins->known_targets && ins->known_target_counts &&
	    !ins->known_targets->empty() && ins->known_targets->size() == ins->known_target_counts->size()) {
		auto const &tgts = *ins->known_targets;
		auto const &cnts = *ins->known_target_counts;
		llvm::SmallVector<llvm::Metadata *, 8> ops;
		ops.push_back(llvm::MDString::get(lctx, "VP"));
		ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32(/*IPVK_IndirectCallTarget=*/0)));
		u64 total = 0;
		for (u32 c : cnts)
			total += c;
		ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt64(total)));
		for (size_t i = 0; i < tgts.size(); ++i) {
			// LLVM 21 renamed the static StringRef overload; the member getGUID() (no args)
			// took its place, so the old spelling stops compiling rather than silently
			// changing meaning. Same function, same hash. AOT-only metadata path.
#if LLVM_VERSION_MAJOR >= 21
			u64 guid = llvm::GlobalValue::getGUIDAssumingExternalLinkage(
			    MakeAotSymbol(tgts[i]));
#else
			u64 guid = llvm::GlobalValue::getGUID(MakeAotSymbol(tgts[i]));
#endif
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt64(guid)));
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt64(cnts[i])));
		}
		call->setMetadata(llvm::LLVMContext::MD_prof, llvm::MDNode::get(lctx, ops));
	}
	// A-line round 25 Track A Treatment 1 (ORACLE-ONLY, default off): mark a RETURN-class
	// (jalr_class==2) site with a SINGLE known target for --aot-return-oracle-unconditional's
	// consumer at Expand_gbrind. Only a marker (the one target ip) -- correctness-breaking
	// unconditional substitution happens at expansion time, matching
	// aot_edge_oracle_unconditional's existing house style, never here.
	if (dbt::config::aot_return_oracle_unconditional && ins->jalr_class == 2 && ins->known_targets &&
	    ins->known_targets->size() == 1) {
		auto *tag = llvm::MDNode::get(
		    lctx, {llvm::ConstantAsMetadata::get(lb->getInt32((*ins->known_targets)[0]))});
		call->setMetadata("dbt_return_oracle", tag);
	}
	// A-line round 28 Gate 1 (ORACLE-ONLY, default off): this SOURCE's own exhaustive order-1
	// transition data -- [slot_id, prev_0, target_0, prev_1, target_1, ...], per-SITE, never
	// broadcast. Consumed only at the ONE stock/unguarded Expand_gbrind fallthrough (matching Row
	// 4/5's exact scope precedent), which builds a guard chain reading/updating THIS site's own
	// tcache::gbrind_ctx1_slots[slot_id] entry -- never CPUState::last_brind_target.
	if (dbt::config::aot_order1_context_oracle && ins->order1_prev && ins->order1_target &&
	    !ins->order1_prev->empty() && ins->order1_prev->size() == ins->order1_target->size()) {
		llvm::SmallVector<llvm::Metadata *, 8> ops;
		ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32(ins->order1_slot)));
		for (size_t i = 0; i < ins->order1_prev->size(); ++i) {
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32((*ins->order1_prev)[i])));
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32((*ins->order1_target)[i])));
		}
		call->setMetadata("dbt_order1_context", llvm::MDNode::get(lctx, ops));
	}
	// A-line round 29 Gate 1 (ORACLE-ONLY, default off): this SOURCE's exhaustive MARGINAL
	// (context-free) majority target -- a single constant, no runtime state. Same scope precedent
	// as order1 above (consumed only at the stock/unguarded Expand_gbrind fallthrough).
	if (dbt::config::aot_marginal_context_oracle && ins->has_marginal_target) {
		auto *tag = llvm::MDNode::get(lctx,
					       {llvm::ConstantAsMetadata::get(lb->getInt32(ins->marginal_target))});
		call->setMetadata("dbt_marginal_context", tag);
	}
	// A-line round 32 Gate 2 (ORACLE-ONLY, default off): this SOURCE's PROVEN-COMPLETE static
	// jump-table target set (qir.h's InstGBrind::static_table_targets comment). Same scope
	// precedent as order1/marginal above.
	if (dbt::config::aot_static_table_oracle && ins->static_table_targets &&
	    !ins->static_table_targets->empty()) {
		llvm::SmallVector<llvm::Metadata *, 8> ops;
		for (u32 t : *ins->static_table_targets)
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32(t)));
		call->setMetadata("dbt_static_table", llvm::MDNode::get(lctx, ops));
	}
	// A-line Round 33 (ORACLE-ONLY, default off): this SOURCE's RTTI-narrowed C++ virtual-call
	// candidate target set (qir.h's InstGBrind::vtable_narrow_targets comment). Same scope
	// precedent as static_table above -- non-empty is required since an empty narrowed set carries
	// no information (falls to the generic path regardless, no metadata needed).
	if (dbt::config::aot_vtable_narrow_oracle && ins->vtable_narrow_targets &&
	    !ins->vtable_narrow_targets->empty()) {
		llvm::SmallVector<llvm::Metadata *, 8> ops;
		for (u32 t : *ins->vtable_narrow_targets)
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32(t)));
		call->setMetadata("dbt_vtable_narrow", llvm::MDNode::get(lctx, ops));
	}
	// A-line Round 44 (ORACLE-ONLY, default off): this SOURCE's index-preserving compact-dispatch
	// table -- RAW, index-ordered (NOT deduplicated, unlike dbt_static_table above), so a compact
	// lowering can reproduce the guest's exact table[index] semantics. All entries are compile-
	// time constants (the proven table contents), so metadata is safe here (unlike the index
	// itself, which is a real argument -- see above).
	if (dbt::config::aot_indexed_dispatch_oracle && ins->indexed_targets && !ins->indexed_targets->empty()) {
		llvm::SmallVector<llvm::Metadata *, 8> ops;
		for (u32 t : *ins->indexed_targets)
			ops.push_back(llvm::ConstantAsMetadata::get(lb->getInt32(t)));
		call->setMetadata("dbt_indexed_dispatch", llvm::MDNode::get(lctx, ops));
	}
	lb->CreateUnreachable();
}

void QIRToLLVM::Emit_vmload(qir::InstVMLoad *ins)
{
	// TODO: alignment in qir
	llvm::MaybeAlign align = true ? llvm::MaybeAlign{} : llvm::Align(VTypeToSize(ins->sz));
	auto gaddr = LoadVOperand(ins->i(0));
	if (dbt::config::count_const_vmload) {
		dbt::config::g_vmload_total++;
		if (llvm::isa<llvm::ConstantInt>(gaddr))
			dbt::config::g_vmload_const_addr++;
	}
	auto mem_ep = MakeVMemLoc(ins->sz, gaddr);
	llvm::Value *val = AScopeVMem(lb->CreateAlignedLoad(MakeType(ins->sz), mem_ep, align));
	auto type = ins->o(0).GetType();
	if (type != ins->sz) {
		if (ins->sgn == VSign::S) {
			val = lb->CreateSExt(val, MakeType(type));
		} else {
			val = lb->CreateZExt(val, MakeType(type));
		}
	}
	StoreVOperand(ins->o(0), val);
}

void QIRToLLVM::Emit_vmstore(qir::InstVMStore *ins)
{
	auto val = LoadVOperand(ins->i(1));
	auto type = ins->i(1).GetType();
	if (type != ins->sz) {
		val = lb->CreateTrunc(val, MakeType(type));
	}
	llvm::MaybeAlign align = true ? llvm::MaybeAlign{} : llvm::Align(VTypeToSize(ins->sz));
	auto mem_ep = MakeVMemLoc(ins->sz, LoadVOperand(ins->i(0)));
	AScopeVMem(lb->CreateAlignedStore(val, mem_ep, align));
}

void QIRToLLVM::Emit_vmload2(qir::InstVMLoad2 *ins)
{
	log_qir("emit vmload2 in llvmgen");
	Panic("TODO: emit vmload2 in llvmgen");
}

void QIRToLLVM::Emit_vmload4(qir::InstVMLoad4 *ins)
{
	log_qir("emit vmload4 in llvmgen");
	Panic("TODO: emit vmload4 in llvmgen");
}

void QIRToLLVM::Emit_vmstore2(qir::InstVMStore2 *ins)
{
	log_qir("emit vmstore2 in llvmgen");
	Panic("TODO: emit vmstore2 in llvmgen");
}

void QIRToLLVM::Emit_vmstore4(qir::InstVMStore4 *ins)
{
	log_qir("emit vmstore4 in llvmgen");
	Panic("TODO: emit vmstore4 in llvmgen");
}	
void QIRToLLVM::Emit_setcc(qir::InstSetcc *ins)
{
	auto cmp = lb->CreateICmp(MakeCC(ins->cc), LoadVOperand(ins->i(0)), LoadVOperand(ins->i(1)));
	StoreVOperand(ins->o(0), lb->CreateZExt(cmp, lb->getInt32Ty()));
}

void QIRToLLVM::Emit_mov(qir::InstUnop *ins)
{
	auto val = LoadVOperand(ins->i(0));
	StoreVOperand(ins->o(0), val);
}

void QIRToLLVM::EmitBinop(llvm::Instruction::BinaryOps opc, qir::InstBinop *ins)
{
	auto res = lb->CreateBinOp(opc, LoadVOperand(ins->i(0)), LoadVOperand(ins->i(1)));
	StoreVOperand(ins->o(0), res);
}

void QIRToLLVM::Emit_add(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::Add, ins);
}

void QIRToLLVM::Emit_sub(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::Sub, ins);
}

void QIRToLLVM::Emit_and(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::And, ins);
}

void QIRToLLVM::Emit_or(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::Or, ins);
}

void QIRToLLVM::Emit_xor(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::Xor, ins);
}

// RV32 sll/srl/sra hardware masks the shift amount to low 5 bits.
// LLVM IR shl/lshr/ashr treat shift >= bit-width as poison, which can
// propagate through branch conditions and let LLVM eliminate loop exit
// checks. Explicitly AND the shift amount with 31 to preserve RV32 semantics.
void QIRToLLVM::EmitShift(llvm::Instruction::BinaryOps opc, qir::InstBinop *ins)
{
	auto lhs = LoadVOperand(ins->i(0));
	auto rhs = LoadVOperand(ins->i(1));
	auto mask = llvm::ConstantInt::get(rhs->getType(), 31);
	auto amt = lb->CreateAnd(rhs, mask);
	auto res = lb->CreateBinOp(opc, lhs, amt);
	StoreVOperand(ins->o(0), res);
}

void QIRToLLVM::Emit_sra(qir::InstBinop *ins)
{
	EmitShift(llvm::Instruction::BinaryOps::AShr, ins);
}

void QIRToLLVM::Emit_srl(qir::InstBinop *ins)
{
	EmitShift(llvm::Instruction::BinaryOps::LShr, ins);
}

void QIRToLLVM::Emit_sll(qir::InstBinop *ins)
{
	EmitShift(llvm::Instruction::BinaryOps::Shl, ins);
}

void QIRToLLVM::Emit_mul(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::Mul, ins);
}

void QIRToLLVM::Emit_mulh(qir::InstBinop *ins)
{
	// Sign extend both operands to 64-bit
	auto op1 = lb->CreateSExt(LoadVOperand(ins->i(0)), lb->getInt64Ty());
	auto op2 = lb->CreateSExt(LoadVOperand(ins->i(1)), lb->getInt64Ty());
	// Multiply the 64-bit values
	auto res = lb->CreateMul(op1, op2);
	// Shift right and truncate back to 32-bit
	auto shifted = lb->CreateAShr(res, lb->getInt64(32));
	StoreVOperand(ins->o(0), lb->CreateTrunc(shifted, lb->getInt32Ty()));
}

void QIRToLLVM::Emit_mulhsu(qir::InstBinop *ins)
{
	// Sign extend first operand, zero extend second operand
	auto op1 = lb->CreateSExt(LoadVOperand(ins->i(0)), lb->getInt64Ty());
	auto op2 = lb->CreateZExt(LoadVOperand(ins->i(1)), lb->getInt64Ty());
	auto res = lb->CreateMul(op1, op2);
	auto shifted = lb->CreateAShr(res, lb->getInt64(32));
	StoreVOperand(ins->o(0), lb->CreateTrunc(shifted, lb->getInt32Ty()));
}

void QIRToLLVM::Emit_mulhu(qir::InstBinop *ins)
{
	// Zero extend both operands
	auto op1 = lb->CreateZExt(LoadVOperand(ins->i(0)), lb->getInt64Ty());
	auto op2 = lb->CreateZExt(LoadVOperand(ins->i(1)), lb->getInt64Ty());
	auto res = lb->CreateMul(op1, op2);
	auto shifted = lb->CreateLShr(res, lb->getInt64(32));
	StoreVOperand(ins->o(0), lb->CreateTrunc(shifted, lb->getInt32Ty()));
}

void QIRToLLVM::Emit_div(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::SDiv, ins);
}

void QIRToLLVM::Emit_divu(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::UDiv, ins);
}

void QIRToLLVM::Emit_rem(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::SRem, ins);
}

void QIRToLLVM::Emit_remu(qir::InstBinop *ins)
{
	EmitBinop(llvm::Instruction::BinaryOps::URem, ins);
}
} // namespace dbt::qir
