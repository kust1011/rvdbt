// C5.2b: focused test for the typed `vadd.vv` V512 chunk group as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG siblings.
// dbt/qmc/qcg/vaddvv_typedchunk_route_test.cpp routes the same guest instruction pair through the
// same real translator, but every one of its checks stops at QIR, post-QRegAlloc operands, or
// objdump-decoded AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see
// whether the LLVM/AOT tier admits the route at all, and before C5.2b it did not: every op of the
// group Panic'd in llvmgen.cpp and RvvQcgTypedChunkAdmit returned 0 for every `aot_use_llvm`
// compile, so the AOT artifact for a vector guest contained an opaque helper call and zero
// vector-typed values (see this experiment's C5.2a audit).
//
// This file therefore drives the REAL LLVM path end to end and inspects the REAL generated
// llvm::Function:
//
//     encoded guest words
//       -> qir::CompilerGenRegionIR   (the real RV32Translator, dbt/qmc/compile.cpp)
//       -> qir::QIRToLLVM::Run()      (the real LLVM backend, dbt/qmc/llvmgen/llvmgen.cpp)
//       -> llvm::Function, walked instruction by instruction below
//
// Nothing here runs a guest, mmaps code, creates a TargetMachine, runs an optimisation pipeline or
// emits an object file. The IR inspected is the IR QIRToLLVM produces, before any LLVM pass, which
// is exactly the layer where "did the translator hand LLVM two independent 512-bit chunks or an
// opaque call" is decided. Consequently NO claim about host instructions, ZMM registers, scheduling
// or speed is made or implied by any check in this file.
//
// SCOPE OF THE ADMITTED ROUTE (unchanged by this checkpoint, and re-asserted here in both
// directions): integer `vadd.vv`, e32, LMUL=1, unmasked, vl == VLMAX, vstart == 0, VLEN 512 or
// 1024, `--rvv-vector-ssa` on. Wrong vtype, partial vl and a wrong runtime VLEN are RUNTIME states
// and are handled by the emitted guard, so what is proved for them here is the guard itself: which
// four CPUState fields it compares, against which constants, and that the miss arm is one call to
// the pre-existing `rv32_vadd_vv` helper with no typed body. Masked encodings, other SEWs, LMUL>1,
// unsupported VLENs and the route's off-state are TRANSLATION-time decisions and are proved by
// their absence: no guard frame, no `add <16 x i32>`, and the pre-existing helper lowering instead.
//
// ONE-TO-ONE CHUNK MAPPING, NOT AUTOMATIC LEGALIZATION. At VLEN=1024 the checks below require TWO
// `<16 x i32>` adds over four independently loaded values with no def-use edge between them -- the
// partition into 512-bit chunks is made by the translator in QIR and handed to LLVM one chunk to
// one value. `CheckNoWideVector` additionally asserts no `<32 x i32>` value exists anywhere in the
// function, so a future change that silently started relying on LLVM's type legalizer to split a
// wide vector would fail here rather than be mistaken for this route.
//
// HOST NOTE. Unlike the QCG route test, this file does NOT set
// `--rvv-qcg-typed-chunk-force-emit`. It does not need to: the LLVM arm of RvvQcgTypedChunkAdmit
// carries no `__builtin_cpu_supports("avx512f")` row, because `add <16 x i32>` is legal for every
// x86-64 subtarget and LLVM lowers it to one ZMM, two YMM or four XMM adds according to the target
// the artifact is compiled for. `CheckLlvmRouteNeedsNoForceEmit` pins that: the route admits on
// this workstation, whose silicon has no AVX-512F at all.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Guest encodings. Built from the instruction fields rather than pasted, and cross-checked against
// the exact words the accepted C0/C1 evidence ELF executes (see the QCG route test's file header):
//   11b58: 09057557   vsetvli a0, a0, e32, m1, tu, ma
//   11b70: 021101d7   vadd.vv v3, v1, v2
// ---------------------------------------------------------------------------------------------

constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
// vadd.vv vd, vs2, vs1 (OPIVV): funct6=0b000000, vm, vs2[24:20], vs1[19:15], funct3=0, vd[11:7],
// opcode 0x57. vm=1 is unmasked; vm=0 is the masked form, which rv32_decode.h routes to the generic
// `vialu` family and never to this route.
constexpr u32 EncodeVaddVV(u32 vd, u32 vs2, u32 vs1, u32 vm = 1)
{
	return (vm << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}

constexpr u32 INSN_VSETVLI = 0x09057557u;      // vsetvli a0, a0, e32, m1, tu, ma
constexpr u32 INSN_VADD_VV = 0x021101d7u;      // vadd.vv v3, v1, v2
constexpr u32 VS2_REG = 1, VS1_REG = 2, VD_REG = 3;

// The vtype INSN_VSETVLI above actually sets -- e32, m1, tu, ma. Written out because the guard must
// carry the OBSERVED vtype, which is NOT the ta,ma constant the unknown-vtype candidate proposes.
constexpr u32 VTYPE_E32_M1_TU_MA = Zimm11(/*vsew=*/2, /*vlmul=*/0, /*vta=*/0, /*vma=*/1);
constexpr u32 VTYPE_E64_M1 = Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M2 = Zimm11(/*vsew=*/2, /*vlmul=*/1, /*vta=*/1, /*vma=*/1);
constexpr u32 INSN_VSETVLI_E64 = EncodeVsetvli(VTYPE_E64_M1);
constexpr u32 INSN_VSETVLI_E32_M2 = EncodeVsetvli(VTYPE_E32_M2);
constexpr u32 INSN_VADD_VV_MASKED = EncodeVaddVV(VD_REG, VS2_REG, VS1_REG, /*vm=*/0);

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VLENB = ST_VEC + (u32)offsetof(rv32::VectorState, vlenb);

// Chunk `c` of guest vector register `reg`: bytes [64c, 64c+64) of that register's own slot. The
// exact formula RvvEmitTypedChunkGroup uses.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

// Every config field this backend reads that could change the emitted IR, pinned to its default so
// a stale value from an earlier case cannot silently alter a later one. Diagnostic/instrumentation
// switches are included because each of them injects extra instructions into the entry block.
void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_diag_chunk_force_emit = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_llvm_wide_vadd = false;
	config::rvv_llvm_wide_vadd_ssa = false;
	config::aot_work_counter = false;
	config::aot_region_hit_count = false;
	config::aot_region_cycle_count = false;
	config::sr_activation_invariant = false;
	config::aot_link_multientry_merge = false;
	config::aot_link_multientry_trace = false;
	config::aot_link_alias_merge = false;
	config::aot_jumptable_multientry = false;
	config::aot_diag_direct_funcs = nullptr;
	config::aot_diag_inline_funcs = nullptr;
	config::aot_brcc_real_weights = false;
}

// Owns everything the inspected llvm::Function points into: the Module holds the IR, the arena
// holds the QIR Region, and LLVMGenCtx must outlive QIRToLLVM. LLVMContext is the process-wide
// thread_local qir::g_llvm_ctx, exactly as in llvmaot.cpp.
struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
	Region *region = nullptr;
};

// Translate `n` guest words at ip 0,4,... through the REAL translator and then through the REAL
// LLVM backend. `vlen_bits` and `ssa` are the only two axes the admitted route depends on; the
// caller may set any additional config field after ResetConfig() and before calling.
Built BuildLLVM(u32 const *words, unsigned n, u32 vlen_bits)
{
	Built b;
	config::vlen_bits = vlen_bits;

	b.arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(b.arena.get(), job);

	b.mod = std::make_unique<llvm::Module>("c5_2b_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, b.region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm of the route: aot_use_llvm on, and the route's own switch is --rvv-vector-ssa.
// --rvv-qcg-typed-chunk is deliberately left OFF, which is itself part of the claim: the QCG
// evidence switch neither opens nor is required by the LLVM route.
Built BuildLLVMRoute(u32 const *words, unsigned n, u32 vlen_bits, bool ssa = true, bool wide = false,
		     bool fair_wide = false)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_llvm_wide_vadd = wide;
	config::rvv_llvm_wide_vadd_ssa = fair_wide;
	return BuildLLVM(words, n, vlen_bits);
}

// ---------------------------------------------------------------------------------------------
// IR inspection helpers.
// ---------------------------------------------------------------------------------------------

llvm::Value *StripCasts(llvm::Value *v)
{
	while (auto *c = llvm::dyn_cast<llvm::BitCastInst>(v)) {
		v = c->getOperand(0);
	}
	return v;
}

bool IsV16I32(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 16 && vt->getElementType()->isIntegerTy(32);
}

bool IsV32I32(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 32 && vt->getElementType()->isIntegerTy(32);
}

// A 512-bit chunk value as QIRToLLVM::MakeType(V512) spells it.
bool IsV8I64(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 8 && vt->getElementType()->isIntegerTy(64);
}

std::vector<llvm::BasicBlock *> BlocksNamed(llvm::Function *fn, char const *prefix)
{
	std::vector<llvm::BasicBlock *> out;
	for (auto &bb : *fn) {
		if (bb.getName().starts_with(prefix)) {
			out.push_back(&bb);
		}
	}
	return out;
}

// True and *offs set if `ptr` is `getelementptr inbounds i8, ptr %state, <const>` -- the one shape
// LLVMGen::MakeStateEP produces for a CPUState field. Bitcasts are transparent under opaque
// pointers but stripped anyway so the helper does not depend on that.
bool StateOffsetOf(llvm::Value *ptr, llvm::Value *statev, u64 *offs)
{
	auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(StripCasts(ptr));
	if (!gep || gep->getPointerOperand() != statev || gep->getNumIndices() != 1) {
		return false;
	}
	auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
	if (!idx || !gep->getSourceElementType()->isIntegerTy(8)) {
		return false;
	}
	*offs = idx->getZExtValue();
	return true;
}

unsigned CountCalls(llvm::BasicBlock *bb)
{
	unsigned n = 0;
	for (auto &ins : *bb) {
		n += llvm::isa<llvm::CallInst>(&ins);
	}
	return n;
}

unsigned CountAddV16I32(llvm::BasicBlock *bb)
{
	unsigned n = 0;
	for (auto &ins : *bb) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		n += bo && bo->getOpcode() == llvm::Instruction::Add && IsV16I32(bo->getType());
	}
	return n;
}

unsigned CountAddV16I32(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		n += CountAddV16I32(&bb);
	}
	return n;
}

// Every value in the function whose type is <32 x i32>. Must be empty: this route partitions in
// QIR and hands LLVM one <16 x i32> per chunk; it never builds a wide vector for the legalizer.
unsigned CountV32I32Values(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			n += IsV32I32(ins.getType());
			for (auto &op : ins.operands()) {
				n += IsV32I32(op->getType());
			}
		}
	}
	return n;
}

struct ChunkOp {
	llvm::Instruction *ins = nullptr;
	u64 offs = 0;
};

// The 64-byte CPUState vector-register windows this block loads and stores, in program order.
void CollectChunkMemOps(llvm::BasicBlock *bb, llvm::Value *statev, std::vector<ChunkOp> *loads,
			std::vector<ChunkOp> *stores)
{
	for (auto &ins : *bb) {
		u64 offs = 0;
		if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
			if (IsV8I64(ld->getType()) && StateOffsetOf(ld->getPointerOperand(), statev, &offs)) {
				loads->push_back({ld, offs});
			}
		} else if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
			if (IsV8I64(st->getValueOperand()->getType()) &&
			    StateOffsetOf(st->getPointerOperand(), statev, &offs)) {
				stores->push_back({st, offs});
			}
		}
	}
}

// The guard is `and`ed pairwise, so the four comparisons are the leaves of an `and` tree rooted at
// the conditional branch's condition. Collect them as (state offset, expected constant) pairs.
void CollectGuardCmps(llvm::Value *cond, llvm::Value *statev, std::vector<std::pair<u64, u64>> *out,
		      unsigned *n_other)
{
	if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(cond);
	    bo && bo->getOpcode() == llvm::Instruction::And) {
		CollectGuardCmps(bo->getOperand(0), statev, out, n_other);
		CollectGuardCmps(bo->getOperand(1), statev, out, n_other);
		return;
	}
	auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(cond);
	if (!cmp || cmp->getPredicate() != llvm::CmpInst::ICMP_EQ) {
		++*n_other;
		return;
	}
	auto *ld = llvm::dyn_cast<llvm::LoadInst>(cmp->getOperand(0));
	auto *k = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
	u64 offs = 0;
	if (!ld || !k || !StateOffsetOf(ld->getPointerOperand(), statev, &offs)) {
		++*n_other;
		return;
	}
	out->push_back({offs, k->getZExtValue()});
}

bool HasGuardCmp(std::vector<std::pair<u64, u64>> const &cmps, u64 offs, u64 val)
{
	return std::find(cmps.begin(), cmps.end(), std::make_pair(offs, val)) != cmps.end();
}

// The one call shape RvvCallFallback emits: call <void(ptr,i32)> %stub(ptr %state, i32 <raw>).
bool IsHelperCallWithRaw(llvm::Instruction *ins, llvm::Value *statev, u32 raw)
{
	auto *call = llvm::dyn_cast<llvm::CallInst>(ins);
	if (!call || call->arg_size() != 2 || call->getArgOperand(0) != statev) {
		return false;
	}
	auto *k = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
	return k && k->getBitWidth() == 32 && (u32)k->getZExtValue() == raw;
}

std::string PrintFn(llvm::Function *fn)
{
	std::string s;
	llvm::raw_string_ostream os(s);
	fn->print(os);
	return s;
}

void CheckNotAdmitted(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, bool ssa,
		      char const *why, bool wide = false, bool fair_wide = false);

// T7a: prove the experimental arm keeps one decoded vadd.vv as one InstRVVAddV and one LLVM
// integer-vector add. This is deliberately checked in the existing real translator/backend fixture,
// beside the accepted chunk baseline, rather than in a standalone LLVM construction.
void CheckWideRepresentation(u32 vlen_bits, u32 lanes, bool with_vsetvli = true)
{
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(with_vsetvli ? words : words + 1, with_vsetvli ? 2 : 1, vlen_bits,
				 /*ssa=*/true, /*wide=*/true);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	unsigned wide_qir = 0, typed_begin = 0, chunk_add = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			typed_begin += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
			chunk_add += ins.GetOpcode() == Op::_vchunkadd;
			if (ins.GetOpcode() == Op::_rvvaddv) {
				auto *w = static_cast<InstRVVAddV *>(&ins);
				wide_qir += w->llvm_wide;
				CHECK(w->raw == INSN_VADD_VV);
				CHECK_EQ(w->vlmax, lanes);
				CHECK_EQ(w->sew_bytes, 4u);
			}
		}
	}
	CHECK_EQ(wide_qir, 1u);
	CHECK_EQ(typed_begin, 0u);
	CHECK_EQ(chunk_add, 0u);

	auto fasts = BlocksNamed(b.fn, "rvv.wide.direct");
	auto slows = BlocksNamed(b.fn, "rvv.wide.fallback");
	CHECK_EQ(fasts.size(), (size_t)1);
	CHECK_EQ(slows.size(), (size_t)1);
	if (fasts.size() != 1 || slows.size() != 1)
		return;

	auto is_wide_i32 = [lanes](llvm::Type *ty) {
		auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(ty);
		return vt && vt->getNumElements() == lanes && vt->getElementType()->isIntegerTy(32);
	};
	unsigned adds = 0, loads = 0, stores = 0, helper_calls = 0;
	for (auto &ins : *fasts[0]) {
		if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins))
			adds += bo->getOpcode() == llvm::Instruction::Add && is_wide_i32(bo->getType());
		if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins))
			loads += is_wide_i32(ld->getType());
		if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
			stores += is_wide_i32(st->getValueOperand()->getType());
	}
	for (auto &ins : *slows[0])
		helper_calls += IsHelperCallWithRaw(&ins, b.fn->getArg(0), INSN_VADD_VV);
	CHECK_EQ(adds, 1u);
	CHECK_EQ(loads, 2u);
	CHECK_EQ(stores, 1u);
	CHECK_EQ(helper_calls, 1u);

	printf("  wide vlen=%u: 1 rvvaddv QIR, 1 <%u x i32> add, 2 loads, 1 store, 1 fallback%s\n",
	       vlen_bits, lanes, with_vsetvli ? "" : ", unknown-vtype candidate");
}

void CheckWideIsolation()
{
	// Outside the exact width envelope the switch cannot mark a node wide. At VLEN 2048 the
	// observed instruction remains the old rvvaddv/helper path; at VLEN 256 likewise.
	for (u32 vlen : {256u, 2048u}) {
		u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
		Built b = BuildLLVMRoute(words, 2, vlen, /*ssa=*/true, /*wide=*/true);
		unsigned marked = 0;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_rvvaddv)
					marked += static_cast<InstRVVAddV *>(&ins)->llvm_wide;
		CHECK_EQ(marked, 0u);
	}
	for (u32 vlen : {512u, 1024u}) {
		u32 e64[2] = {INSN_VSETVLI_E64, INSN_VADD_VV};
		CheckNotAdmitted("wide e64,m1", e64, 2, vlen, true,
				 "wide switch does not widen SEW admission", /*wide=*/true);
		u32 m2[2] = {INSN_VSETVLI_E32_M2, INSN_VADD_VV};
		CheckNotAdmitted("wide e32,m2", m2, 2, vlen, true,
				 "wide switch does not widen LMUL admission", /*wide=*/true);
		u32 masked[2] = {INSN_VSETVLI, INSN_VADD_VV_MASKED};
		CheckNotAdmitted("wide masked", masked, 2, vlen, true,
				 "wide switch does not admit vm=0", /*wide=*/true);
	}
	printf("  wide switch refused VLEN 256/2048 and e64/m2/masked shapes\n");
}

// T7b: retain the same one-operation LLVM representation without leaving the accepted typed SSA
// frame. Unlike T7a, the wide node consumes the frame's existing V512 producer values and returns
// V512 values to its existing stores. Thus the direct arm has the same CPUState memory operations
// as the chunk baseline and no helper/call boundary; only the arithmetic representation differs.
void CheckFairWideRepresentation(u32 vlen_bits, unsigned nchunks, u32 lanes,
				 bool with_vsetvli = true)
{
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(with_vsetvli ? words : words + 1, with_vsetvli ? 2 : 1, vlen_bits,
				 /*ssa=*/true, /*wide=*/false, /*fair_wide=*/true);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	unsigned fair_qir = 0, old_wide_qir = 0, chunk_add = 0, begins = 0, ends = 0;
	unsigned qloads = 0, qstores = 0, qreads = 0, qwrites = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			begins += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
			ends += ins.GetOpcode() == Op::_rvvtypedchunkend;
			chunk_add += ins.GetOpcode() == Op::_vchunkadd;
			qloads += ins.GetOpcode() == Op::_vstatechunkload;
			qstores += ins.GetOpcode() == Op::_vstatechunkstore;
			qreads += ins.GetOpcode() == Op::_rvvread;
			qwrites += ins.GetOpcode() == Op::_rvvwrite;
			if (ins.GetOpcode() == Op::_rvvaddv)
				old_wide_qir += static_cast<InstRVVAddV *>(&ins)->llvm_wide;
			if (ins.GetOpcode() == Op::_vwideaddssa) {
				auto *w = static_cast<InstRVVWideAddSSA *>(&ins);
				++fair_qir;
				CHECK_EQ(w->raw, INSN_VADD_VV);
				CHECK_EQ(w->active_chunks, nchunks);
				CHECK_EQ(w->sew_bytes, 4u);
			}
		}
	}
	CHECK_EQ(fair_qir, 1u);
	CHECK_EQ(old_wide_qir, 0u);
	CHECK_EQ(chunk_add, 0u);
	CHECK_EQ(begins, 1u);
	CHECK_EQ(ends, 1u);
	CHECK_EQ(qloads, 2u * nchunks);
	CHECK_EQ(qstores, nchunks);
	// A commit/reset boundary would materialize as rvvwrite/rvvread around the operation.
	CHECK_EQ(qreads, 0u);
	CHECK_EQ(qwrites, 0u);

	auto fasts = BlocksNamed(b.fn, "rvv.tchunk.direct");
	auto slows = BlocksNamed(b.fn, "rvv.tchunk.fallback");
	CHECK_EQ(fasts.size(), (size_t)1);
	CHECK_EQ(slows.size(), (size_t)1);
	if (fasts.size() != 1 || slows.size() != 1)
		return;
	auto *fast = fasts[0];
	auto *slow = slows[0];
	unsigned adds = 0;
	for (auto &ins : *fast) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		if (bo && bo->getOpcode() == llvm::Instruction::Add) {
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(bo->getType());
			adds += vt && vt->getNumElements() == lanes &&
				vt->getElementType()->isIntegerTy(32);
			if (vt && vt->getNumElements() == lanes) {
				CHECK(!bo->hasNoUnsignedWrap());
				CHECK(!bo->hasNoSignedWrap());
			}
		}
	}
	CHECK_EQ(adds, 1u);
	CHECK_EQ(CountCalls(fast), 0u);

	std::vector<ChunkOp> loads, stores;
	CollectChunkMemOps(fast, b.fn->getArg(0), &loads, &stores);
	CHECK_EQ(loads.size(), (size_t)(2 * nchunks));
	CHECK_EQ(stores.size(), (size_t)nchunks);
	if (loads.size() == 2 * nchunks && stores.size() == nchunks) {
		for (unsigned c = 0; c < nchunks; ++c) {
			CHECK_EQ(loads[2 * c].offs, (u64)ChunkOffs(VS2_REG, c));
			CHECK_EQ(loads[2 * c + 1].offs, (u64)ChunkOffs(VS1_REG, c));
			CHECK_EQ(stores[c].offs, (u64)ChunkOffs(VD_REG, c));
		}
		CHECK(loads.back().ins->comesBefore(stores.front().ins));
	}
	unsigned helper_calls = 0;
	for (auto &ins : *slow)
		helper_calls += IsHelperCallWithRaw(&ins, b.fn->getArg(0), INSN_VADD_VV);
	CHECK_EQ(helper_calls, 1u);
	printf("  fair-wide vlen=%u: 1 <%u x i32> add, %zu source loads/%zu stores, "
	       "0 rvvread/rvvwrite, 0 direct calls%s\n",
	       vlen_bits, lanes, loads.size(), stores.size(),
	       with_vsetvli ? "" : ", unknown-vtype candidate");
}

void CheckFairWideIsolation()
{
	for (u32 vlen : {256u, 2048u}) {
		u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
		Built b = BuildLLVMRoute(words, 2, vlen, true, false, true);
		unsigned fair = 0;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				fair += ins.GetOpcode() == Op::_vwideaddssa;
		CHECK_EQ(fair, 0u);
	}
	for (u32 vlen : {512u, 1024u}) {
		u32 e64[2] = {INSN_VSETVLI_E64, INSN_VADD_VV};
		CheckNotAdmitted("fair-wide e64,m1", e64, 2, vlen, true,
				 "fair-wide does not widen SEW admission", false, true);
		u32 m2[2] = {INSN_VSETVLI_E32_M2, INSN_VADD_VV};
		CheckNotAdmitted("fair-wide e32,m2", m2, 2, vlen, true,
				 "fair-wide does not widen LMUL admission", false, true);
		u32 masked[2] = {INSN_VSETVLI, INSN_VADD_VV_MASKED};
		CheckNotAdmitted("fair-wide masked", masked, 2, vlen, true,
				 "fair-wide does not admit vm=0", false, true);
	}
	// If both experimental switches are set, the SSA-preserving route deliberately wins.
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(words, 2, 1024, true, true, true);
	unsigned fair = 0, old_wide = 0;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist) {
			fair += ins.GetOpcode() == Op::_vwideaddssa;
			if (ins.GetOpcode() == Op::_rvvaddv)
				old_wide += static_cast<InstRVVAddV *>(&ins)->llvm_wide;
		}
	CHECK_EQ(fair, 1u);
	CHECK_EQ(old_wide, 0u);
	printf("  fair-wide refused VLEN 256/2048 and e64/m2/masked; fair-wide wins dual-enable\n");
}

// ---------------------------------------------------------------------------------------------
// The admitted route.
// ---------------------------------------------------------------------------------------------

// Full structural check of one admitted VLEN. `nchunks` is 1 at VLEN=512 and 2 at VLEN=1024;
// `vlmax` is VLEN/32 at e32,LMUL=1.
// `with_vsetvli` selects which of the two admission entries the case exercises:
//   true  -- an in-block `vsetvli` pins the vtype, and the guard must carry THAT observation
//            (e32,m1,tu,ma == 0x090, the exact vtype the C1 microkernel sets);
//   false -- the block contains the `vadd.vv` alone, so nothing was observed and the C3.1f
//            candidate (e32,m1,ta,ma) is proposed and proved by the same runtime guard.
// `expect_vtype` is the constant the guard must compare against in each case; passing it in is what
// makes a silently substituted vtype a failure rather than a tautology.
void CheckAdmitted(char const *tag, u32 vlen_bits, unsigned nchunks, u32 vlmax, u32 vd, u32 vs2,
		   u32 vs1, bool with_vsetvli = true, u32 expect_vtype = VTYPE_E32_M1_TU_MA)
{
	printf("%s: vlen=%u nchunks=%u vlmax=%u vtype=0x%03x vadd.vv v%u, v%u, v%u%s\n", tag,
	       vlen_bits, nchunks, vlmax, expect_vtype, vd, vs2, vs1,
	       with_vsetvli ? "" : " (no in-block vsetvli)");
	u32 const insn = EncodeVaddVV(vd, vs2, vs1);
	u32 words[2] = {INSN_VSETVLI, insn};
	unsigned const n = with_vsetvli ? 2 : 1;
	Built b = BuildLLVMRoute(with_vsetvli ? words : words + 1, n, vlen_bits);
	auto *statev = b.fn->getArg(0);

	// The IR is well formed. `Run()`'s own verifyFunction call is inside an assert(), which is
	// compiled out of this Release build, so it is repeated here unconditionally.
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	auto fasts = BlocksNamed(b.fn, "rvv.tchunk.direct");
	auto slows = BlocksNamed(b.fn, "rvv.tchunk.fallback");
	auto dones = BlocksNamed(b.fn, "rvv.tchunk.done");
	CHECK_EQ(fasts.size(), (size_t)1);
	CHECK_EQ(slows.size(), (size_t)1);
	CHECK_EQ(dones.size(), (size_t)1);
	if (fasts.size() != 1 || slows.size() != 1 || dones.size() != 1) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}
	auto *fast = fasts[0], *slow = slows[0], *done = dones[0];

	// ---- guard CFG ------------------------------------------------------------------------
	// One predecessor, and it ends in a two-way branch to exactly these two arms.
	auto *guard_bb = fast->getSinglePredecessor();
	CHECK(guard_bb != nullptr);
	CHECK(slow->getSinglePredecessor() == guard_bb);
	if (!guard_bb || slow->getSinglePredecessor() != guard_bb) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}
	auto *br = llvm::dyn_cast<llvm::BranchInst>(guard_bb->getTerminator());
	CHECK(br != nullptr && br->isConditional());
	if (!br || !br->isConditional()) {
		return;
	}
	CHECK(br->getSuccessor(0) == fast);
	CHECK(br->getSuccessor(1) == slow);
	// Both arms join, and nothing else reaches the join.
	CHECK(llvm::cast<llvm::BranchInst>(fast->getTerminator())->isUnconditional());
	CHECK(fast->getSingleSuccessor() == done);
	CHECK(slow->getSingleSuccessor() == done);
	CHECK_EQ(std::distance(llvm::pred_begin(done), llvm::pred_end(done)), (ptrdiff_t)2);

	// ---- guard CONTENT --------------------------------------------------------------------
	// Exactly the four runtime conditions, each against the right CPUState field and the right
	// translation-time constant. This is what sends a wrong vtype, a partial vl, a non-zero
	// vstart or a wrong runtime VLEN to the helper arm.
	{
		std::vector<std::pair<u64, u64>> cmps;
		unsigned n_other = 0;
		CollectGuardCmps(br->getCondition(), statev, &cmps, &n_other);
		CHECK_EQ(n_other, 0u);
		CHECK_EQ(cmps.size(), (size_t)4);
		CHECK(HasGuardCmp(cmps, ST_VLENB, vlen_bits / 8));
		CHECK(HasGuardCmp(cmps, ST_VTYPE, expect_vtype));
		CHECK(HasGuardCmp(cmps, ST_VL, vlmax));
		CHECK(HasGuardCmp(cmps, ST_VSTART, 0));
		printf("  guard: vlenb==%u vtype==0x%03x vl==%u vstart==0 (%zu cmps, %u other)\n",
		       vlen_bits / 8, expect_vtype, vlmax, cmps.size(), n_other);
	}

	// ---- fast arm -------------------------------------------------------------------------
	// No helper call on the taken direct path. This is the single most load-bearing check in the
	// file: it is exactly the property the pre-C5.2b artifact failed.
	CHECK_EQ(CountCalls(fast), 0u);
	CHECK_EQ(CountAddV16I32(fast), (unsigned)nchunks);
	CHECK_EQ(CountAddV16I32(b.fn), (unsigned)nchunks); // and nowhere else in the function

	std::vector<ChunkOp> loads, stores;
	CollectChunkMemOps(fast, statev, &loads, &stores);
	CHECK_EQ(loads.size(), (size_t)(2 * nchunks));
	CHECK_EQ(stores.size(), (size_t)nchunks);
	if (loads.size() != 2 * nchunks || stores.size() != nchunks) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}

	// State offsets, load-major order: chunk c's vs2 then vs1 window, for every chunk, then the
	// chunks' vd windows. Chunk 0 is bytes [0,64) of a register's slot, chunk 1 bytes [64,128).
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(loads[2 * c].offs, (u64)ChunkOffs(vs2, c));
		CHECK_EQ(loads[2 * c + 1].offs, (u64)ChunkOffs(vs1, c));
		CHECK_EQ(stores[c].offs, (u64)ChunkOffs(vd, c));
	}

	// REAL SSA VALUES, NOT A SPILL SLOT. Every memory access in the fast arm addresses CPUState
	// (a GEP off %state); none of them touches an alloca. The chunk values themselves are carried
	// as llvm::Value* by QIRToLLVM::tchunk_vals, so the six V512 entry-block allocas
	// CreateVGPRLocs makes for the group's virtual registers stay completely unused (and are
	// deleted by the first optimisation pass). If a future change routed these values through
	// LoadVOperand/StoreVOperand instead, this check -- and the per-chunk def-use check below --
	// would fail.
	{
		unsigned n_non_state_mem = 0;
		for (auto &ins : *fast) {
			llvm::Value *p = nullptr;
			if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				p = ld->getPointerOperand();
			} else if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				p = st->getPointerOperand();
			}
			if (!p) {
				continue;
			}
			u64 off = 0;
			n_non_state_mem += !StateOffsetOf(p, statev, &off);
		}
		CHECK_EQ(n_non_state_mem, 0u);
		CHECK_EQ(std::count_if(fast->begin(), fast->end(),
				       [](llvm::Instruction const &i) { return llvm::isa<llvm::AllocaInst>(&i); }),
			 (long)0);
	}

	// LEGAL OPERAND OVERLAP: every source load is emitted before every destination store, so
	// vd==vs1, vd==vs2 and vd==vs1==vs2 all read the pre-instruction bytes. Checked as a real
	// order relation in the block, not inferred from the offsets.
	CHECK(loads.back().ins->comesBefore(stores.front().ins));

	// ---- per-chunk dataflow ----------------------------------------------------------------
	// Each add consumes exactly its own chunk's two loads (order-independent: addition is
	// commutative and the design does not promise which operand slot a source lands in), and its
	// result is what that chunk's store writes.
	std::vector<llvm::Instruction *> adds;
	for (auto &ins : *fast) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		if (bo && bo->getOpcode() == llvm::Instruction::Add && IsV16I32(bo->getType())) {
			adds.push_back(bo);
		}
	}
	CHECK_EQ(adds.size(), (size_t)nchunks);
	if (adds.size() != nchunks) {
		return;
	}
	// Modulo-2^32 semantics: no nuw/nsw may be attached to an RVV integer add.
	for (auto *a : adds) {
		auto *bo = llvm::cast<llvm::BinaryOperator>(a);
		CHECK(!bo->hasNoUnsignedWrap());
		CHECK(!bo->hasNoSignedWrap());
	}
	for (unsigned c = 0; c < nchunks; ++c) {
		llvm::Value *want_a = loads[2 * c].ins;
		llvm::Value *want_b = loads[2 * c + 1].ins;
		llvm::Value *got_a = StripCasts(adds[c]->getOperand(0));
		llvm::Value *got_b = StripCasts(adds[c]->getOperand(1));
		CHECK((got_a == want_a && got_b == want_b) || (got_a == want_b && got_b == want_a));
		CHECK(StripCasts(llvm::cast<llvm::StoreInst>(stores[c].ins)->getValueOperand()) == adds[c]);
	}

	// ---- chunk independence ----------------------------------------------------------------
	// Distinct low/high SSA values: at VLEN=1024 the four loaded chunks are four pairwise
	// distinct values, the two adds are distinct, and neither add is reachable from the other.
	{
		std::vector<llvm::Value *> defs;
		for (auto &l : loads) {
			defs.push_back(l.ins);
		}
		for (auto *a : adds) {
			defs.push_back(a);
		}
		std::sort(defs.begin(), defs.end());
		CHECK_EQ((size_t)std::distance(defs.begin(), std::unique(defs.begin(), defs.end())),
			 (size_t)(3 * nchunks));
	}
	if (nchunks == 2) {
		// No def-use edge between the chunks, in either direction, at either add's operands.
		for (unsigned c = 0; c < 2; ++c) {
			for (unsigned k = 0; k < 2; ++k) {
				CHECK(StripCasts(adds[c]->getOperand(k)) != adds[1 - c]);
			}
		}
		// And the two chunks' windows really are disjoint 64-byte ranges.
		CHECK_EQ(stores[1].offs - stores[0].offs, (u64)64);
	}
	CHECK_EQ(CountV32I32Values(b.fn), 0u); // no wide vector handed to the legalizer

	// ---- fallback arm ----------------------------------------------------------------------
	// Exactly one call, it is the pre-existing helper for this instruction word, and it is not
	// accompanied by any typed body.
	CHECK_EQ(CountCalls(slow), 1u);
	CHECK_EQ(CountAddV16I32(slow), 0u);
	{
		std::vector<ChunkOp> sl, ss;
		CollectChunkMemOps(slow, statev, &sl, &ss);
		CHECK_EQ(sl.size(), (size_t)0);
		CHECK_EQ(ss.size(), (size_t)0);
		unsigned n_helper = 0;
		for (auto &ins : *slow) {
			n_helper += IsHelperCallWithRaw(&ins, statev, insn);
		}
		CHECK_EQ(n_helper, 1u);
	}
	// The stub the fallback loads is the pre-existing rv32_vadd_vv helper, read by name off the
	// MakeRStub load rather than assumed from the QIR node.
	{
		llvm::CallInst *call = nullptr;
		for (auto &ins : *slow) {
			if (auto *c = llvm::dyn_cast<llvm::CallInst>(&ins)) {
				call = c;
			}
		}
		CHECK(call != nullptr);
		auto *stub_ld = call ? llvm::dyn_cast<llvm::LoadInst>(call->getCalledOperand()) : nullptr;
		CHECK(stub_ld != nullptr);
		if (stub_ld) {
			CHECK(stub_ld->getName().starts_with(
			    GetRuntimeStubName(RuntimeStubId::id_rv32_vadd_vv)));
			u64 off = 0;
			CHECK(StateOffsetOf(stub_ld->getPointerOperand(), statev, &off));
			CHECK_EQ(off, (u64)(offsetof(CPUState, stub_tab) +
					    RuntimeStubTab::offs(RuntimeStubId::id_rv32_vadd_vv)));
		}
	}

	printf("  OK: fast=%u add<16 x i32>, 0 calls, %zu loads/%zu stores at exact windows; "
	       "fallback=1 rv32_vadd_vv call, 0 typed ops; 0 <32 x i32> values\n",
	       CountAddV16I32(fast), loads.size(), stores.size());
}

// ---------------------------------------------------------------------------------------------
// Non-admission. Each case must produce NO guard frame and NO vector add, and must still lower the
// guest instruction -- through the pre-existing helper path -- so nothing is silently dropped.
// ---------------------------------------------------------------------------------------------

void CheckNotAdmitted(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, bool ssa,
		      char const *why, bool wide, bool fair_wide)
{
	printf("%s: %s\n", tag, why);
	Built b = BuildLLVMRoute(words, n, vlen_bits, ssa, wide, fair_wide);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.wide.direct").size(), (size_t)0);
	CHECK_EQ(CountAddV16I32(b.fn), 0u);
	CHECK_EQ(CountV32I32Values(b.fn), 0u);
	// No typed chunk op survived into QIR either -- the decision is made by the admission test,
	// not absorbed by the backend.
	unsigned n_typed_qir = 0, n_wide_qir = 0, n_fair_qir = 0, n_calls = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvaddv)
				n_wide_qir += static_cast<InstRVVAddV *>(&ins)->llvm_wide;
			n_fair_qir += ins.GetOpcode() == Op::_vwideaddssa;
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
			case Op::_vstatechunkload:
			case Op::_vchunkadd:
			case Op::_vstatechunkstore:
			case Op::_rvvtypedchunkend:
				++n_typed_qir;
				break;
			default:
				break;
			}
		}
	}
	CHECK_EQ(n_typed_qir, 0u);
	CHECK_EQ(n_wide_qir, 0u);
	CHECK_EQ(n_fair_qir, 0u);
	for (auto &bb : *b.fn) {
		n_calls += CountCalls(&bb);
	}
	// The vector instruction still reaches SOME lowering: at minimum one call per guest
	// instruction in the region (helper or the region-exit intrinsic).
	CHECK(n_calls >= n);
	printf("  no chunk/wide guard, no vector add, %u typed QIR ops, %u wide QIR ops, %u calls\n",
	       n_typed_qir, n_wide_qir, n_calls);
}

// The route's off-state under AOT: --rvv-vector-ssa=0 must leave the artifact exactly as it was
// before C5.2b -- the pre-existing `rvvaddv` node, lowered to a helper call.
void CheckRouteOff(u32 vlen_bits)
{
	printf("route-off (--rvv-vector-ssa=0): vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/false);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(CountAddV16I32(b.fn), 0u);
	unsigned n_rvvaddv = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n_rvvaddv += ins.GetOpcode() == Op::_rvvaddv;
		}
	}
	CHECK_EQ(n_rvvaddv, 1u); // the pre-C5.2b route, untouched
	unsigned n_raw_calls = 0;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			n_raw_calls += IsHelperCallWithRaw(&ins, b.fn->getArg(0), INSN_VADD_VV);
		}
	}
	CHECK_EQ(n_raw_calls, 1u); // exactly the helper lowering of rvvaddv
	printf("  rvvaddv kept, one rv32_vadd_vv helper call, no guard frame\n");
}

// The QCG evidence switch cannot open the LLVM route, in either direction. Both halves matter:
// a --rvv-qcg-typed-chunk-only AOT compile must stay helper-lowered (so no accepted QCG arm's flag
// silently changes an artifact), and the QCG path must be unaffected by --rvv-vector-ssa.
void CheckSwitchSeparation(u32 vlen_bits)
{
	printf("switch separation: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};

	// (a) AOT + --rvv-qcg-typed-chunk=1, --rvv-vector-ssa=0 -> NOT admitted.
	{
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = false;
		config::rvv_qcg_typed_chunk = true;
		config::rvv_qcg_typed_chunk_force_emit = true;
		Built b = BuildLLVM(words, 2, vlen_bits);
		CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
		CHECK_EQ(CountAddV16I32(b.fn), 0u);
	}
	// (b) QCG + --rvv-vector-ssa=1, --rvv-qcg-typed-chunk=0 -> NOT admitted (QIR level; the QCG
	//     backend is not run here).
	{
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = true;
		config::rvv_qcg_typed_chunk = false;
		config::rvv_qcg_typed_chunk_force_emit = true;
		config::vlen_bits = vlen_bits;
		MemArena arena(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		unsigned n_begin = 0;
		for (auto &bb : region->GetBlocks()) {
			for (auto &ins : bb.ilist) {
				n_begin += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
			}
		}
		CHECK_EQ(n_begin, 0u);
	}
	// (c) QCG + --rvv-qcg-typed-chunk=1 -> STILL admitted: the accepted QCG route is unchanged.
	{
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = false;
		config::rvv_qcg_typed_chunk = true;
		config::rvv_qcg_typed_chunk_force_emit = true;
		config::vlen_bits = vlen_bits;
		MemArena arena(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		unsigned n_begin = 0, n_add = 0;
		for (auto &bb : region->GetBlocks()) {
			for (auto &ins : bb.ilist) {
				n_begin += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
				n_add += ins.GetOpcode() == Op::_vchunkadd;
			}
		}
		CHECK_EQ(n_begin, 1u);
		CHECK_EQ(n_add, (unsigned)(vlen_bits / 512));
	}
	printf("  QCG switch does not open the LLVM route; SSA switch does not open the QCG route; "
	       "QCG route unchanged\n");
}

// The LLVM arm carries no host AVX-512 probe: it admits on this workstation, which has none.
// (`__builtin_cpu_supports` is a real runtime CPUID query, so this is a live fact, not an #ifdef.)
void CheckLlvmRouteNeedsNoForceEmit()
{
	printf("host-feature independence:\n");
#if defined(__x86_64__) || defined(__i386__)
	bool const host_avx512 = __builtin_cpu_supports("avx512f");
#else
	bool const host_avx512 = false;
#endif
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_force_emit = false; // explicitly NOT bypassing anything
	Built b = BuildLLVM(words, 2, 512);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	CHECK_EQ(CountAddV16I32(b.fn), 1u);
	printf("  admitted with force_emit=0 on a host with avx512f=%d\n", (int)host_avx512);
}

// SEPARATE FINDING (see the matching comment in rv32_qir.cpp's TRANSLATOR(vadd_vv)).
//
// Establishing where the `--rvv-vector-ssa` chunk-value cache (rvv_chunk_dirty / RvvCommit) has to
// be flushed is unavoidable for this route: RvvEmitTypedChunkGroup must flush it, because both arms
// of its guard frame address CPUState::vec directly. Doing that made visible that the NEIGHBOURING
// non-admitted route did not. `Create_rvvaddv` lowers to a bare helper call in llvmgen and nothing
// committed the cache before it, so under --llvm=1 --rvv-vector-ssa=1 the helper could read stale
// architectural state.
//
// The guest sequence below is the smallest one that reaches it:
//
//     vsetvli a0, a0, e64, m1, ta, ma      (helper; TranslateHelper commits and resets)
//     vl1re32.v v1, (a0)                   (typed rvvload; RvvDefineGroup marks v1 dirty; vlNre
//                                           is vtype-independent, so e64 survives it)
//     vadd.vv  v3, v1, v2                  (e64 -> NOT admitted -> Create_rvvaddv -> helper)
//
// BEFORE the fix the QIR was `... rvvload, mov, rvvaddv, rvvwrite[, rvvwrite], gbr` -- the commit
// landed AFTER the helper, at the block exit (MakeGBr). This asserts the property directly: one
// `rvvwrite` per dirty chunk must appear strictly BETWEEN the `rvvload` and the `rvvaddv`.
// It also prints the whole opcode sequence, so the shape can be read rather than inferred.
void CheckRvvAddvCommitBoundary(u32 vlen_bits, unsigned nchunks)
{
	// vl1re32.v v1, (a0): opcode 0x07, nf=0, mew=0, mop=00, vm=1, lumop=0b01000, rs1=a0=10,
	// width=0b110 (32-bit), vd=1.
	constexpr u32 INSN_VL1RE32 = (1u << 25) | (0b01000u << 20) | (10u << 15) | (0b110u << 12) |
				     (1u << 7) | 0x07u;
	u32 words[3] = {INSN_VSETVLI_E64, INSN_VL1RE32, INSN_VADD_VV};
	Built b = BuildLLVMRoute(words, 3, vlen_bits);
	printf("\n----- PROBE rvvaddv commit boundary (vlen=%u, --rvv-vector-ssa=1) -----\n", vlen_bits);
	printf("  guest: vsetvli e64,m1 (0x%08x) ; vl1re32.v v1,(a0) (0x%08x) ; vadd.vv v3,v1,v2 (0x%08x)\n",
	       INSN_VSETVLI_E64, INSN_VL1RE32, INSN_VADD_VV);
	std::vector<Op> ops;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			ops.push_back(ins.GetOpcode());
		}
	}
	for (size_t k = 0; k < ops.size(); ++k) {
		printf("  %2zu  %s\n", k, GetOpNameStr(ops[k]));
	}
	// The sequence must contain exactly the two nodes this case is about, once each.
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvload), (long)1);
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvaddv), (long)1);
	// e64 must NOT be admitted to the typed route -- otherwise this case is not testing the
	// rvvaddv path at all.
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvtypedchunkbegin), (long)0);
	auto ld = std::find(ops.begin(), ops.end(), Op::_rvvload);
	auto av = std::find(ops.begin(), ops.end(), Op::_rvvaddv);
	CHECK(ld < av);
	if (ld >= av) {
		return;
	}
	// One commit per dirty chunk, strictly between the load and the helper-lowered add.
	CHECK_EQ(std::count(ld, av, Op::_rvvwrite), (long)nchunks);
	printf("  OK: %u rvvwrite commit(s) between rvvload and rvvaddv\n", nchunks);
}

// Prints the whole generated function for one configuration. Evidence only -- no CHECK depends on
// it -- so the exact IR the assertions above are read from can be preserved and reviewed by hand.
void DumpIR(char const *tag, u32 vlen_bits, bool ssa)
{
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(words, 2, vlen_bits, ssa);
	printf("\n----- IR DUMP %s (vlen=%u, --rvv-vector-ssa=%d) -----\n%s", tag, vlen_bits, (int)ssa,
	       PrintFn(b.fn).c_str());
}

void DumpWideIR(u32 vlen_bits)
{
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/true, /*wide=*/true);
	printf("\n----- IR DUMP wide (vlen=%u) -----\n%s", vlen_bits, PrintFn(b.fn).c_str());
}

void DumpFairWideIR(u32 vlen_bits)
{
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/true, /*wide=*/false,
				 /*fair_wide=*/true);
	printf("\n----- IR DUMP fair-wide SSA (vlen=%u) -----\n%s", vlen_bits, PrintFn(b.fn).c_str());
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i) {
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	}
	printf("C5.2b typed vadd.vv LLVM route test\n");

	// Sanity: the field-built encodings reproduce the exact words the accepted evidence ELF runs.
	CHECK_EQ(EncodeVaddVV(VD_REG, VS2_REG, VS1_REG), INSN_VADD_VV);
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M1_TU_MA), INSN_VSETVLI);

	printf("\n== admitted: VLEN=512, one chunk ==\n");
	CheckAdmitted("v512", 512, 1, 16, VD_REG, VS2_REG, VS1_REG);
	printf("\n== admitted: VLEN=1024, two independent chunks ==\n");
	CheckAdmitted("v1024", 1024, 2, 32, VD_REG, VS2_REG, VS1_REG);

	printf("\n== admitted: unknown-vtype candidate (no in-block vsetvli) ==\n");
	CheckAdmitted("v512 unknown-vtype", 512, 1, 16, VD_REG, VS2_REG, VS1_REG,
		      /*with_vsetvli=*/false, rv32::VTYPE_E32_M1_TA_MA);
	CheckAdmitted("v1024 unknown-vtype", 1024, 2, 32, VD_REG, VS2_REG, VS1_REG,
		      /*with_vsetvli=*/false, rv32::VTYPE_E32_M1_TA_MA);

	printf("\n== admitted: legal operand overlap ==\n");
	// The three architecturally legal overlaps, at both widths. Nothing about the shape may
	// change: same offsets, same load-before-store order, same per-chunk def-use.
	CheckAdmitted("v512 vd==vs2", 512, 1, 16, /*vd=*/1, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v512 vd==vs1", 512, 1, 16, /*vd=*/2, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v512 vd==vs1==vs2", 512, 1, 16, /*vd=*/1, /*vs2=*/1, /*vs1=*/1);
	CheckAdmitted("v1024 vd==vs2", 1024, 2, 32, /*vd=*/1, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v1024 vd==vs1", 1024, 2, 32, /*vd=*/2, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v1024 vd==vs1==vs2", 1024, 2, 32, /*vd=*/1, /*vs2=*/1, /*vs1=*/1);

	printf("\n== off-state and switch separation ==\n");
	CheckRouteOff(512);
	CheckRouteOff(1024);
	CheckSwitchSeparation(512);
	CheckSwitchSeparation(1024);
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== T7a single-operation wide LLVM representation ==\n");
	CheckWideRepresentation(512, 16);
	CheckWideRepresentation(1024, 32);
	CheckWideRepresentation(512, 16, /*with_vsetvli=*/false);
	CheckWideRepresentation(1024, 32, /*with_vsetvli=*/false);
	CheckWideIsolation();

	printf("\n== T7b single-operation wide LLVM representation in typed SSA ==\n");
	CheckFairWideRepresentation(512, 1, 16);
	CheckFairWideRepresentation(1024, 2, 32);
	CheckFairWideRepresentation(512, 1, 16, /*with_vsetvli=*/false);
	CheckFairWideRepresentation(1024, 2, 32, /*with_vsetvli=*/false);
	CheckFairWideIsolation();

	printf("\n== separate finding: the rvvaddv helper's SSA commit boundary ==\n");
	CheckRvvAddvCommitBoundary(512, 1);
	CheckRvvAddvCommitBoundary(1024, 2);

	printf("\n== non-admitted shapes stay on the helper path ==\n");
	{
		u32 w[2] = {INSN_VSETVLI_E64, INSN_VADD_VV};
		CheckNotAdmitted("e64,m1", w, 2, 512, true, "unsupported SEW (e64): observed vtype wins");
		CheckNotAdmitted("e64,m1", w, 2, 1024, true, "unsupported SEW (e64): observed vtype wins");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32_M2, INSN_VADD_VV};
		CheckNotAdmitted("e32,m2", w, 2, 512, true, "unsupported LMUL (m2)");
		CheckNotAdmitted("e32,m2", w, 2, 1024, true, "unsupported LMUL (m2)");
	}
	{
		u32 w[2] = {INSN_VSETVLI, INSN_VADD_VV_MASKED};
		CheckNotAdmitted("masked", w, 2, 512, true, "masked vadd.vv (vm=0) is not this opcode");
		CheckNotAdmitted("masked", w, 2, 1024, true, "masked vadd.vv (vm=0) is not this opcode");
	}
	{
		u32 w[2] = {INSN_VSETVLI, INSN_VADD_VV};
		CheckNotAdmitted("vlen256", w, 2, 256, true, "VLEN outside the admitted {512,1024}");
		CheckNotAdmitted("vlen128", w, 2, 128, true, "VLEN outside the admitted {512,1024}");
	}

	if (dump_ir) {
		DumpIR("route-on", 512, true);
		DumpIR("route-on", 1024, true);
		DumpIR("route-off", 512, false);
		DumpIR("route-off", 1024, false);
		DumpWideIR(512);
		DumpWideIR(1024);
		DumpFairWideIR(512);
		DumpFairWideIR(1024);
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
