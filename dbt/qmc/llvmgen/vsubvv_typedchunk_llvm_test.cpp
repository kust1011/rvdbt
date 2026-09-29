// S3.10a: focused test for the typed `vsub.vv` V512 chunk group as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG sibling.
// dbt/qmc/qcg/vsubvv_typedchunk_route_test.cpp routes the same guest instruction pair through the
// same real translator, but every one of its checks stops at QIR, post-QRegAlloc operands, or
// objdump-decoded AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see
// whether the LLVM/AOT tier admits the route at all, and before S3.10a it did not: `vchunksub`
// Panic'd in llvmgen.cpp and RvvQcgTypedSubChunkAdmit returned 0 for every `aot_use_llvm` compile.
// That sibling's `aot_use_llvm` row has been rewritten accordingly (see its comment); the POSITIVE
// LLVM case is here, because only here is the real llvm::Function available to inspect.
//
// This file drives the REAL LLVM path end to end and inspects the REAL generated llvm::Function:
//
//     encoded guest words
//       -> qir::CompilerGenRegionIR   (the real RV32Translator, dbt/qmc/compile.cpp)
//       -> qir::QIRToLLVM::Run()      (the real LLVM backend, dbt/qmc/llvmgen/llvmgen.cpp)
//       -> llvm::Function, walked instruction by instruction below
//
// Nothing here runs a guest, mmaps code, creates a TargetMachine, runs an optimisation pipeline or
// emits an object file. The IR inspected is the IR QIRToLLVM produces, before any LLVM pass.
// Consequently NO claim about host instructions, ZMM registers, scheduling, artifacts or speed is
// made or implied by any check in this file.
//
// WHY vsub AND NOT ANOTHER SIBLING. It is the only member of the family whose operation does not
// commute. `vsub.vv vd, vs2, vs1` is `vd[i] = vs2[i] - vs1[i]`, so a reversed operand pair is a
// silent miscompile that no structural check -- "is there a sub", "does it write vd", "are the
// windows right" -- would notice. Its checks are therefore written as a STRICT operand-position
// assertion (CheckAdmitted below), not the order-independent one the commutative add's test uses.
//
// WHAT WOULD FAIL HERE, stated so each assertion has a named failure it catches:
//   * operand reversal (CreateSub(b, a))            -> the strict operand-position check
//   * wrong operation (CreateAdd instead of Sub)    -> the opcode check plus zero-Add-in-function
//   * nsw/nuw attached                              -> the wrap-flag check
//   * missing precise-state boundary                -> CheckSsaCommitBoundary
//   * `Op::_vchunksub` missing from TChunkCheckBodyOp's whitelist -> the backend Panics while
//     building any admitted case, so the process aborts and the test cannot report success
//   * either LLVM gate switch dropped               -> CheckGateNeedsBothSwitches
//   * a sibling opcode routed by accident, or an
//     intentionally-routed one silently losing its
//     route                                         -> CheckSiblingsStillFailClosed (T1b made that
//     table fully positive: vmul.vv (T1b), vxor.vv (T1d), vor.vv (T1e) and vand.vv (T1f) all
//     have their own LLVM gates now, so every row asserts a route still opens)
//   * the elfaot option or the route-contract row
//     dropped, i.e. the route becoming unreachable
//     from an artifact again                        -> CheckAotPlumbing (T1c)

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h" // GetRuntimeStubName / GetOpNameStr, for naming what was found

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
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
// Guest encodings. Built from the instruction fields rather than pasted, then cross-checked against
// the exact constants the accepted S2.1 QCG route test uses for the same instructions.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
// vsub.vv vd, vs2, vs1 (OPIVV): funct6=0b000010, vm, vs2[24:20], vs1[19:15], funct3=0, vd[11:7],
// opcode 0x57. vm=1 is unmasked; vm=0 is the masked form, which rv32_decode.h routes to the generic
// `vialu` family and never to this route.
constexpr u32 EncodeVsubVV(u32 vd, u32 vs2, u32 vs1, u32 vm = 1)
{
	return (0b000010u << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}
constexpr u32 EncodeVaddVV(u32 vd, u32 vs2, u32 vs1)
{
	return (1u << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}
// The three siblings that must STILL fail closed, at their own funct6 values. vand=001001,
// vor=001010, vxor=001011, vmul=100101 (OPMVV, funct3=2).
constexpr u32 EncodeOpivv(u32 f6, u32 vd, u32 vs2, u32 vs1)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}
constexpr u32 EncodeVmulVV(u32 vd, u32 vs2, u32 vs1)
{
	return (0b100101u << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (2u << 12) | (vd << 7) |
	       0x57u;
}

constexpr u32 VTYPE_E32_M1_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E64_M1_TA_MA = Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M2_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/1, /*vta=*/1, /*vma=*/1);

constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 INSN_VSUB_VV = 0x0a1101d7u;       // vsub.vv v3, v1, v2
constexpr u32 INSN_VSUB_VV_MASKED = 0x081101d7u;

constexpr u32 VS2_REG = 1, VS1_REG = 2, VD_REG = 3;

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VLENB = ST_VEC + (u32)offsetof(rv32::VectorState, vlenb);

// Chunk `c` of guest vector register `reg`: bytes [64c, 64c+64) of that register's own slot. The
// exact formula RvvEmitTypedAluChunkGroupCore uses.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

// Every config field the route reads, pinned so a stale value from an earlier case cannot silently
// alter a later one. The sibling route switches are pinned OFF so a stray add/mul/logical frame can
// never be mistaken for a sub one.
void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_sub_force_emit = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_diag_chunk_force_emit = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::aot_use_llvm = false;
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

struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
	Region *region = nullptr;
};

Built BuildLLVM(u32 const *words, unsigned n, u32 vlen_bits)
{
	Built b;
	config::vlen_bits = vlen_bits;

	b.arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(b.arena.get(), job);

	b.mod = std::make_unique<llvm::Module>("s3_10a_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, b.region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm of the route: aot_use_llvm on, and BOTH of the route's switches on. The QCG
// force-emit switch is deliberately left off -- the LLVM gate carries no host-feature probe, which
// CheckLlvmRouteNeedsNoForceEmit pins on a host with no AVX-512F at all.
Built BuildLLVMRoute(u32 const *words, unsigned n, u32 vlen_bits, bool ssa = true, bool flag = true)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_qcg_typed_chunk_sub = flag;
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

// Counts one specific v16i32 binary opcode. Used in both directions: the sub count is what the
// route must produce, and the ADD count is what it must NOT produce (a wrong-operation mutation).
unsigned CountBinOpV16I32(llvm::BasicBlock *bb, llvm::Instruction::BinaryOps opc)
{
	unsigned n = 0;
	for (auto &ins : *bb) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		n += bo && bo->getOpcode() == opc && IsV16I32(bo->getType());
	}
	return n;
}

unsigned CountBinOpV16I32(llvm::Function *fn, llvm::Instruction::BinaryOps opc)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		n += CountBinOpV16I32(&bb, opc);
	}
	return n;
}

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

// ---------------------------------------------------------------------------------------------
// The admitted route.
// ---------------------------------------------------------------------------------------------

// Full structural check of one admitted VLEN. `nchunks` is 1 at VLEN=512 and 2 at VLEN=1024;
// `vlmax` is VLEN/32 at e32,LMUL=1.
void CheckAdmitted(char const *tag, u32 vlen_bits, unsigned nchunks, u32 vlmax, u32 vd, u32 vs2,
		   u32 vs1)
{
	printf("%s: vlen=%u nchunks=%u vlmax=%u  vsub.vv v%u, v%u, v%u\n", tag, vlen_bits, nchunks,
	       vlmax, vd, vs2, vs1);
	u32 const insn = EncodeVsubVV(vd, vs2, vs1);
	u32 words[2] = {INSN_VSETVLI_E32M1, insn};
	Built b = BuildLLVMRoute(words, 2, vlen_bits);
	auto *statev = b.fn->getArg(0);

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

	// ---- guard CFG -------------------------------------------------------------------------
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
	CHECK(fast->getSingleSuccessor() == done);
	CHECK(slow->getSingleSuccessor() == done);
	CHECK_EQ(std::distance(llvm::pred_begin(done), llvm::pred_end(done)), (ptrdiff_t)2);

	// ---- guard CONTENT ---------------------------------------------------------------------
	{
		std::vector<std::pair<u64, u64>> cmps;
		unsigned n_other = 0;
		CollectGuardCmps(br->getCondition(), statev, &cmps, &n_other);
		CHECK_EQ(n_other, 0u);
		CHECK_EQ(cmps.size(), (size_t)4);
		CHECK(HasGuardCmp(cmps, ST_VLENB, vlen_bits / 8));
		CHECK(HasGuardCmp(cmps, ST_VTYPE, VTYPE_E32_M1_TA_MA));
		CHECK(HasGuardCmp(cmps, ST_VL, vlmax));
		CHECK(HasGuardCmp(cmps, ST_VSTART, 0));
	}

	// ---- fast arm --------------------------------------------------------------------------
	CHECK_EQ(CountCalls(fast), 0u);
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Sub), (unsigned)nchunks);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Sub), (unsigned)nchunks);
	// WRONG-OPERATION GATE. A CreateAdd in place of CreateSub would satisfy every structural
	// check in this file; this is what refuses it.
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Add), 0u);

	std::vector<ChunkOp> loads, stores;
	CollectChunkMemOps(fast, statev, &loads, &stores);
	CHECK_EQ(loads.size(), (size_t)(2 * nchunks));
	CHECK_EQ(stores.size(), (size_t)nchunks);
	if (loads.size() != 2 * nchunks || stores.size() != nchunks) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}

	// State offsets, load-major order: chunk c's vs2 then vs1 window, for every chunk, then the
	// chunks' vd windows.
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(loads[2 * c].offs, (u64)ChunkOffs(vs2, c));
		CHECK_EQ(loads[2 * c + 1].offs, (u64)ChunkOffs(vs1, c));
		CHECK_EQ(stores[c].offs, (u64)ChunkOffs(vd, c));
	}

	// REAL SSA VALUES, NOT A SPILL SLOT: every memory access in the fast arm addresses CPUState.
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

	// LEGAL OPERAND OVERLAP: every source load precedes every destination store, so vd==vs1,
	// vd==vs2 and vd==vs1==vs2 all read the pre-instruction bytes.
	CHECK(loads.back().ins->comesBefore(stores.front().ins));

	// ---- per-chunk dataflow, WITH STRICT OPERAND POSITIONS ----------------------------------
	std::vector<llvm::BinaryOperator *> subs;
	for (auto &ins : *fast) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		if (bo && bo->getOpcode() == llvm::Instruction::Sub && IsV16I32(bo->getType())) {
			subs.push_back(bo);
		}
	}
	CHECK_EQ(subs.size(), (size_t)nchunks);
	if (subs.size() != nchunks) {
		return;
	}
	// WRAPPING: RVV integer subtract is modulo 2^SEW, so neither flag may be attached. With
	// <16 x i32> lanes and no nsw/nuw, LLVM's own semantics for `sub` ARE mod 2^32 -- which is
	// what makes the architectural `return a - b;` of vialu_apply exact rather than approximate.
	for (auto *s : subs) {
		CHECK(!s->hasNoUnsignedWrap());
		CHECK(!s->hasNoSignedWrap());
	}
	// THE NON-COMMUTATIVITY GATE, and the reason this file exists. Operand 0 must be the vs2
	// chunk (the minuend) and operand 1 the vs1 chunk. Unlike the add's test this is NOT
	// order-independent: swapping them computes vs1 - vs2, which is a different function of the
	// same inputs and would pass every other check here.
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK(StripCasts(subs[c]->getOperand(0)) == loads[2 * c].ins);     // vs2 chunk c
		CHECK(StripCasts(subs[c]->getOperand(1)) == loads[2 * c + 1].ins); // vs1 chunk c
		CHECK(StripCasts(llvm::cast<llvm::StoreInst>(stores[c].ins)->getValueOperand()) == subs[c]);
	}

	// ---- chunk independence -----------------------------------------------------------------
	{
		std::vector<llvm::Value *> defs;
		for (auto &l : loads) {
			defs.push_back(l.ins);
		}
		for (auto *s : subs) {
			defs.push_back(s);
		}
		std::sort(defs.begin(), defs.end());
		CHECK_EQ((size_t)std::distance(defs.begin(), std::unique(defs.begin(), defs.end())),
			 (size_t)(3 * nchunks));
	}
	if (nchunks == 2) {
		for (unsigned c = 0; c < 2; ++c) {
			for (unsigned k = 0; k < 2; ++k) {
				CHECK(StripCasts(subs[c]->getOperand(k)) != subs[1 - c]);
			}
		}
		CHECK_EQ(stores[1].offs - stores[0].offs, (u64)64);
	}
	CHECK_EQ(CountV32I32Values(b.fn), 0u); // no wide vector handed to the legalizer

	// ---- fallback arm ------------------------------------------------------------------------
	CHECK_EQ(CountCalls(slow), 1u);
	CHECK_EQ(CountBinOpV16I32(slow, llvm::Instruction::Sub), 0u);
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
	// The stub is the PRE-EXISTING rv32_vialu helper, read by name off the MakeRStub load.
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
			    GetRuntimeStubName(RuntimeStubId::id_rv32_vialu)));
			u64 off = 0;
			CHECK(StateOffsetOf(stub_ld->getPointerOperand(), statev, &off));
			CHECK_EQ(off, (u64)(offsetof(CPUState, stub_tab) +
					    RuntimeStubTab::offs(RuntimeStubId::id_rv32_vialu)));
		}
	}

	printf("  OK: %u sub<16 x i32> (0 add), operand0=vs2 operand1=vs1, no wrap flags, 0 calls on "
	       "the fast arm; fallback = 1 rv32_vialu call\n",
	       (unsigned)subs.size());
}

// ---------------------------------------------------------------------------------------------
// Non-admission.
// ---------------------------------------------------------------------------------------------

void CheckNotAdmitted(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, char const *why,
		      bool ssa = true, bool flag = true)
{
	printf("%s: %s\n", tag, why);
	Built b = BuildLLVMRoute(words, n, vlen_bits, ssa, flag);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Sub), 0u);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Add), 0u);
	CHECK_EQ(CountV32I32Values(b.fn), 0u);
	unsigned n_typed_qir = 0, n_calls = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
			case Op::_vstatechunkload:
			case Op::_vchunksub:
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
	for (auto &bb : *b.fn) {
		n_calls += CountCalls(&bb);
	}
	// The vector instruction still reaches SOME lowering rather than being dropped.
	CHECK(n_calls >= n);
	printf("  no guard frame, no v16i32 sub, %u typed QIR ops, %u calls\n", n_typed_qir, n_calls);
}

// BOTH switches are required, and neither alone suffices. This is the row that pins S3.10a's gate
// choice: --rvv-vector-ssa must not sweep vsub.vv into the route on its own.
void CheckGateNeedsBothSwitches(u32 vlen_bits)
{
	printf("gate needs both switches: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, INSN_VSUB_VV};
	CheckNotAdmitted("  ssa-off", words, 2, vlen_bits, "--rvv-vector-ssa=0 (per-op flag on)",
			 /*ssa=*/false, /*flag=*/true);
	CheckNotAdmitted("  flag-off", words, 2, vlen_bits,
			 "--rvv-qcg-typed-chunk-sub=0 (vector-SSA on)", /*ssa=*/true, /*flag=*/false);
}

// The pure-QCG admission is UNCHANGED by S3.10a, in both directions. Checked at QIR level, which is
// the layer the accepted S2.1 evidence was taken at.
void CheckQcgUnchanged(u32 vlen_bits)
{
	printf("pure-QCG admission unchanged: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, INSN_VSUB_VV};
	auto count = [&](Region *r, Op op) {
		unsigned n = 0;
		for (auto &bb : r->GetBlocks()) {
			for (auto &ins : bb.ilist) {
				n += ins.GetOpcode() == op;
			}
		}
		return n;
	};
	// (a) QCG + the route's own flag -> STILL admitted, and vector-SSA is irrelevant to it.
	for (bool ssa : {false, true}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = ssa;
		config::rvv_qcg_typed_chunk_sub = true;
		config::rvv_qcg_typed_chunk_sub_force_emit = true;
		config::vlen_bits = vlen_bits;
		MemArena arena(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		CHECK_EQ(count(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(count(region, Op::_vchunksub), (unsigned)(vlen_bits / 512));
	}
	// (b) QCG without the flag -> not admitted, whatever vector-SSA says.
	for (bool ssa : {false, true}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = ssa;
		config::rvv_qcg_typed_chunk_sub = false;
		config::vlen_bits = vlen_bits;
		MemArena arena(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		CHECK_EQ(count(region, Op::_rvvtypedchunkbegin), 0u);
	}
	printf("  QCG route admits on its own flag alone; vector-SSA neither opens nor closes it\n");
}

// THE PRECISE-STATE BOUNDARY, which the sub's builder did NOT have before S3.10a.
//
// Both arms of the frame address CPUState::vec directly, and PreSideeff does not flush the
// --rvv-vector-ssa chunk cache for an OP-V opcode. So the handler must commit every dirty chunk
// BEFORE the frame. The smallest guest sequence that reaches it:
//
//     vsetvli a0, a0, e32, m1, ta, ma   (helper; TranslateHelper commits and resets)
//     vl1re32.v v1, (a0)                (typed rvvload; RvvDefineGroup marks v1 dirty)
//     vsub.vv  v3, v1, v2               (ADMITTED -> the typed frame)
//
// The assertion is positional: one `rvvwrite` per dirty chunk must appear strictly BETWEEN the
// `rvvload` and the `rvvtypedchunkbegin`. Deleting the commit from RvvEmitTypedAluChunkGroupCore
// moves them after the frame (to the block exit) and fails this.
void CheckSsaCommitBoundary(u32 vlen_bits, unsigned nchunks)
{
	printf("precise-state boundary: vlen=%u\n", vlen_bits);
	constexpr u32 INSN_VL1RE32 = (1u << 25) | (0b01000u << 20) | (10u << 15) | (0b110u << 12) |
				     (1u << 7) | 0x07u;
	u32 words[3] = {INSN_VSETVLI_E32M1, INSN_VL1RE32, INSN_VSUB_VV};
	Built b = BuildLLVMRoute(words, 3, vlen_bits);
	std::vector<Op> ops;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			ops.push_back(ins.GetOpcode());
		}
	}
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvload), (long)1);
	// The frame really is the ADMITTED one -- otherwise this case would be testing the helper
	// path instead of the boundary the typed frame owns.
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvtypedchunkbegin), (long)1);
	auto ld = std::find(ops.begin(), ops.end(), Op::_rvvload);
	auto tb = std::find(ops.begin(), ops.end(), Op::_rvvtypedchunkbegin);
	CHECK(ld < tb);
	if (ld >= tb) {
		for (size_t k = 0; k < ops.size(); ++k) {
			printf("  %2zu  %s\n", k, GetOpNameStr(ops[k]));
		}
		return;
	}
	CHECK_EQ(std::count(ld, tb, Op::_rvvwrite), (long)nchunks);
	printf("  OK: %u rvvwrite commit(s) strictly between rvvload and rvvtypedchunkbegin\n", nchunks);
}

// The siblings' status on this backend, each row asserting what that opcode's OWN predicate does.
//
// FOUR CHECKPOINTS HAVE MOVED ONE ROW EACH, AND WITH T1f THE TABLE IS ENTIRELY POSITIVE. `vmul.vv`
// left the fail-closed group at T1b, `vxor.vv` at T1d, `vor.vv` at T1e and `vand.vv` at T1f, each
// having gained a gate, a lowering and a whitelist entry, so each expected frame count moved from 0
// to 1. The table is kept rather than deleted because its meaning has inverted rather than expired:
// it no longer shows which siblings are closed, it shows that all four still OPEN under their own
// switch while this file\'s own route keeps producing the only `sub <16 x i32>` in the function --
// i.e. that a later checkpoint has not silently taken one of them away.
void CheckSiblingsStillFailClosed(u32 vlen_bits)
{
	printf("siblings: vlen=%u\n", vlen_bits);
	struct Row {
		char const *name;
		u32 word;
		bool *flag;
		u32 setvli;
		unsigned want_frames; // T1f: every row is 1 -- the whole family is routed now
	} rows[] = {
	    {"vmul.vv", EncodeVmulVV(VD_REG, VS2_REG, VS1_REG), &config::rvv_qcg_typed_chunk_mul,
	     INSN_VSETVLI_E32M1, 1},
	    {"vxor.vv", EncodeOpivv(0b001011u, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_xor, INSN_VSETVLI_E32M1, 1},
	    {"vor.vv", EncodeOpivv(0b001010u, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_or, INSN_VSETVLI_E32M1, 1},
	    {"vand.vv", EncodeOpivv(0b001001u, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_and, INSN_VSETVLI_E32M1, 1},
	};
	for (auto const &r : rows) {
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		*r.flag = true;
		u32 words[2] = {r.setvli, r.word};
		Built b = BuildLLVM(words, 2, vlen_bits);
		CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
		unsigned n_begin = 0;
		for (auto &bb : b.region->GetBlocks()) {
			for (auto &ins : bb.ilist) {
				n_begin += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
			}
		}
		CHECK_EQ(n_begin, r.want_frames);
		CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)(r.want_frames ? 3 : 0));
		// Whatever it did, it did not produce a SUB: this file's own route stays the only source
		// of `sub <16 x i32>` in the tree it inspects.
		CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Sub), 0u);
		printf("  %-8s own flag + --rvv-vector-ssa + AOT -> %u typed frame(s)%s\n", r.name,
		       r.want_frames, r.want_frames ? " (routed elsewhere)" : "");
	}
}

// The LLVM arm carries no host AVX-512 probe: it admits on this workstation, which has none.
void CheckLlvmRouteNeedsNoForceEmit()
{
	printf("host-feature independence:\n");
#if defined(__x86_64__) || defined(__i386__)
	bool const host_avx512 = __builtin_cpu_supports("avx512f");
#else
	bool const host_avx512 = false;
#endif
	u32 words[2] = {INSN_VSETVLI_E32M1, INSN_VSUB_VV};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = false; // explicitly NOT bypassing anything
	Built b = BuildLLVM(words, 2, 512);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Sub), 1u);
	printf("  admitted with force_emit=0 on a host with avx512f=%d\n", (int)host_avx512);
}

// ---------------------------------------------------------------------------------------------
// T1c. AOT REACHABILITY.
//
// Everything above proves the route exists in the translator and in the backend. None of it proves
// an ARTIFACT can ever take it -- and until T1c none could. S3.10a shipped the lowering, the
// TChunkCheckBodyOp whitelist entry and RvvLLVMSubChunkAdmit, then added neither an `elfaot` option
// nor a `kRvvRouteContract` row, so `config::rvv_qcg_typed_chunk_sub` was false in every freshly
// exec'd elfaot and stayed false: the offline compiler had no way to set it, and the same-run
// background builder had no way to inherit the parent's value. Every check in this file passed
// throughout, because every one of them sets the config field directly in-process.
//
// That is the gap this function closes, and it is the analogue of the accepted T1b check in
// qmc/llvmgen/vmulvv_typedchunk_llvm_test.cpp. It reads the production sources rather than a copy of
// them, so it is weaker than executing elfaot; what it forecloses is exactly the failure that
// already happened once here.
// ---------------------------------------------------------------------------------------------

std::string ReadFile(char const *rel)
{
	std::string const path = std::string(DBT_SOURCE_ROOT) + "/" + rel;
	std::ifstream f(path);
	if (!f) {
		fprintf(stderr, "  FAIL cannot open %s\n", path.c_str());
		++g_failures;
		return {};
	}
	std::ostringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

void CheckAotPlumbing()
{
	printf("AOT reachability (source-level):\n");
	// (a) elfaot must declare the option AND assign it to the config field the gate reads. Both
	// halves are load-bearing: an option that parses into an ElfAotOptions field nothing copies
	// into dbt::config would leave the route exactly as unreachable as having no option at all.
	std::string const aot = ReadFile("dbt/elfaot.cpp");
	CHECK(aot.find("\"rvv-qcg-typed-chunk-sub\"") != std::string::npos);
	CHECK(aot.find("dbt::config::rvv_qcg_typed_chunk_sub = opts.rvv_qcg_typed_chunk_sub;") !=
	      std::string::npos);
	printf("  elfaot: --rvv-qcg-typed-chunk-sub declared and assigned to config\n");

	// (b) the same-run route contract must carry it, so a background builder spawned by elfrun
	// inherits the parent's live value instead of elfaot's default. Checked INSIDE the table's own
	// braces, so a mention in the surrounding commentary cannot satisfy it.
	std::string const boot = ReadFile("dbt/aot/aot_boot.cpp");
	auto const tbl = boot.find("kRvvRouteContract[]");
	CHECK(tbl != std::string::npos);
	auto const tbl_end = boot.find("};", tbl);
	CHECK(tbl_end != std::string::npos);
	if (tbl != std::string::npos && tbl_end != std::string::npos) {
		std::string const body = boot.substr(tbl, tbl_end - tbl);
		CHECK(body.find("\"rvv-qcg-typed-chunk-sub\"") != std::string::npos);
		CHECK(body.find("&config::rvv_qcg_typed_chunk_sub") != std::string::npos);
	}
	printf("  aot_boot: kRvvRouteContract carries the flag to every spawn site\n");

	// (c) the propagation audit's mirror of the contract must list it too -- its own comment says
	// the two are updated together and that its G8 gate fails if they drift. T5f: the mirror row
	// carries the row's KIND as a third field, and this route's kind is `Route` -- cross-backend
	// policy, rendered from the parent's live value. The one row that is NOT a Route is
	// --rvv-vector-ssa, the LLVM child's lowering substrate; see kRvvRouteContract's T5f block.
	std::string const audit = ReadFile("scripts/vlen_propagation_audit.py");
	CHECK(audit.find("(\"rvv-qcg-typed-chunk-sub\", \"rvv_qcg_typed_chunk_sub\", \"Route\")") !=
	      std::string::npos);
	printf("  vlen_propagation_audit.py: ROUTE_FLAGS mirror updated in lockstep\n");

	// (d) the flag the three above name is the flag the gate reads. Asserted by construction: this
	// binary links the real translator, every admitted case in this file was produced with exactly
	// `config::rvv_qcg_typed_chunk_sub = true`, and CheckGateNeedsBothSwitches shows setting it
	// false closes the route.
	printf("  the named flag IS the gate input (CheckGateNeedsBothSwitches proves both polarities)\n");
}

void DumpIR(char const *tag, u32 vlen_bits)
{
	u32 words[2] = {INSN_VSETVLI_E32M1, INSN_VSUB_VV};
	Built b = BuildLLVMRoute(words, 2, vlen_bits);
	printf("\n----- IR DUMP %s (vlen=%u) -----\n%s", tag, vlen_bits, PrintFn(b.fn).c_str());
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i) {
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	}
	printf("S3.10a typed vsub.vv LLVM route test\n");

	// The field-built encodings reproduce the exact constants the accepted S2.1 QCG test uses.
	CHECK_EQ(EncodeVsubVV(VD_REG, VS2_REG, VS1_REG), INSN_VSUB_VV);
	CHECK_EQ(EncodeVsubVV(VD_REG, VS2_REG, VS1_REG, /*vm=*/0), INSN_VSUB_VV_MASKED);
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M1_TA_MA), INSN_VSETVLI_E32M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E64_M1_TA_MA), INSN_VSETVLI_E64M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M2_TA_MA), INSN_VSETVLI_E32M2);

	printf("\n== admitted: VLEN=512, one chunk ==\n");
	CheckAdmitted("v512", 512, 1, 16, VD_REG, VS2_REG, VS1_REG);
	printf("\n== admitted: VLEN=1024, two independent chunks ==\n");
	CheckAdmitted("v1024", 1024, 2, 32, VD_REG, VS2_REG, VS1_REG);

	printf("\n== admitted: the three legal operand overlaps ==\n");
	// vd==vs2 is the shape the frozen mixed kernel actually contains (`vsub.vv v8, v8, v10`), and
	// it is the one where a reversed operand pair still writes the register a shallow check would
	// look at. All three are checked at both widths.
	CheckAdmitted("v512 vd==vs2", 512, 1, 16, /*vd=*/1, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v512 vd==vs1", 512, 1, 16, /*vd=*/2, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v512 vd==vs1==vs2", 512, 1, 16, /*vd=*/1, /*vs2=*/1, /*vs1=*/1);
	CheckAdmitted("v1024 vd==vs2", 1024, 2, 32, /*vd=*/1, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v1024 vd==vs1", 1024, 2, 32, /*vd=*/2, /*vs2=*/1, /*vs1=*/2);
	CheckAdmitted("v1024 vd==vs1==vs2", 1024, 2, 32, /*vd=*/1, /*vs2=*/1, /*vs1=*/1);

	printf("\n== gates ==\n");
	CheckGateNeedsBothSwitches(512);
	CheckGateNeedsBothSwitches(1024);
	CheckQcgUnchanged(512);
	CheckQcgUnchanged(1024);
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== precise-state boundary ==\n");
	CheckSsaCommitBoundary(512, 1);
	CheckSsaCommitBoundary(1024, 2);

	printf("\n== siblings stay fail-closed ==\n");
	CheckSiblingsStillFailClosed(512);
	CheckSiblingsStillFailClosed(1024);

	printf("\n== non-admitted shapes stay on the helper path ==\n");
	{
		u32 w[2] = {INSN_VSETVLI_E64M1, INSN_VSUB_VV};
		CheckNotAdmitted("e64,m1", w, 2, 512, "unsupported SEW (e64)");
		CheckNotAdmitted("e64,m1", w, 2, 1024, "unsupported SEW (e64)");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M2, INSN_VSUB_VV};
		CheckNotAdmitted("e32,m2", w, 2, 512, "unsupported LMUL (m2)");
		CheckNotAdmitted("e32,m2", w, 2, 1024, "unsupported LMUL (m2)");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M1, INSN_VSUB_VV_MASKED};
		CheckNotAdmitted("masked", w, 2, 512, "masked vsub.vv (vm=0) is not this opcode");
		CheckNotAdmitted("masked", w, 2, 1024, "masked vsub.vv (vm=0) is not this opcode");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M1, INSN_VSUB_VV};
		// W5 (2026-09-17): 128 and 256 were here as "VLEN outside the admitted {512,1024}", and
		// that set was RvvSSAEnabled()'s, not this route's. The LLVM arm's width now comes from
		// RvvRouteChunkShape -> RvvHostChunkGeometryForSew, so a register that tiles into whole
		// host chunks is admitted at 128/256 too. The row is kept, at the width the GEOMETRY still
		// refuses: VLEN 384 is 48 bytes per register, which is not one of the three host vector
		// widths, so it has no chunk shape at all. Positive five-width coverage -- the chunk count,
		// the chunk type and the fallback at each width -- is asserted in
		// rvv_llvm_five_width_geometry_test rather than restated in every per-opcode file.
		CheckNotAdmitted("vlen384", w, 2, 384, "VLEN 384 has no host chunk shape");
	}

	printf("\n== AOT reachability ==\n");
	CheckAotPlumbing();

	if (dump_ir) {
		DumpIR("route-on", 512);
		DumpIR("route-on", 1024);
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
