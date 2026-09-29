// T1b: focused test for the typed `vmul.vv` V512 chunk group as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG sibling.
// dbt/qmc/qcg/vmulvv_typedchunk_route_test.cpp routes the same guest instruction pair through the
// same real translator, but every one of its checks stops at QIR, post-QRegAlloc operands, or
// objdump-decoded AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see
// whether the LLVM/AOT tier admits the route at all, and before T1b it did not: `vchunkmul` Panic'd
// in llvmgen.cpp and RvvQcgTypedMulChunkAdmit returned 0 for every `aot_use_llvm` compile.
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
// WHAT IS SPECIFIC TO THE MULTIPLY, and therefore what this file checks that its add/sub siblings
// cannot:
//
//   * LOW-HALF, NOT WIDENING. `vmul.vv` writes the low SEW bits of each lane product;
//     `vmulh`/`vmulhu`/`vmulhsu` are different funct6 values that stay in the generic `vimul`
//     family. A widening lowering (`mul <16 x i64>` over sext/zext operands, then a truncate) would
//     produce the same architectural answer for small inputs and a DIFFERENT one for large ones, so
//     CheckAdmitted requires the multiply's type to be exactly <16 x i32> and requires the function
//     to contain no sext/zext/trunc and no v8i64/v16i64 arithmetic at all.
//   * NO WRAP FLAGS, and here the stake is higher than for add/sub. Lane overflow is the ORDINARY
//     case for a 32-bit multiply, not an edge case, so `nsw` would poison lanes a conforming guest
//     routinely produces. Checked per multiply instruction.
//   * THE SHAPE HALF IS RvvGenericChunkShapeAdmit, which admits k=1/2/4/8, while T1b's scope is
//     VLEN 512/1024. Nothing in RvvLLVMMulChunkAdmit re-states that narrowing; RvvSSAEnabled() is
//     what enforces it. CheckWideVlenNotAdmittedOnLlvm asserts the CONSEQUENCE at VLEN 2048/4096 --
//     no typed frame on this backend -- and CheckQcgKeepsWideVlen asserts the pure-QCG arm still
//     reaches k=4/k=8, so the two arms' different reach is pinned in both directions.
//
// WHAT WOULD FAIL HERE, stated so each assertion has a named failure it catches:
//   * wrong operation (CreateAdd/CreateSub instead of Mul) -> the opcode check plus the
//     zero-Add/zero-Sub-in-function check
//   * a widening multiply                                  -> CheckAdmitted's no-cast/no-wide-vector
//     assertions
//   * nsw/nuw attached                                     -> the wrap-flag check
//   * missing precise-state boundary                       -> CheckSsaCommitBoundary
//   * `Op::_vchunkmul` missing from TChunkCheckBodyOp's whitelist -> the backend Panics while
//     building any admitted case, so the process aborts and the test cannot report success
//   * either LLVM gate switch dropped                      -> CheckGateNeedsBothSwitches
//   * partial vl or a wrong vtype admitted by the guard    -> CheckGuardRejectsPartialVl
//   * the elfaot option or the route-contract row dropped  -> CheckAotPlumbing
//   * a sibling opcode routed by accident                  -> CheckSiblingsStillFailClosed

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
// Guest encodings. Built from the instruction fields rather than pasted, then cross-checked in
// main() against the exact constants the accepted P3.5a QCG route test uses for the same
// instructions.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
// vmul.vv vd, vs2, vs1 (OPMVV): funct6=0b100101, vm, vs2[24:20], vs1[19:15], funct3=0b010,
// vd[11:7], opcode 0x57. vm=1 is unmasked; vm=0 is the masked form, which rv32_decode.h routes to
// the generic `vimul` family and never to this route.
constexpr u32 EncodeVmulVV(u32 vd, u32 vs2, u32 vs1, u32 vm = 1)
{
	return (0b100101u << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (0b010u << 12) |
	       (vd << 7) | 0x57u;
}
// The OPMVV neighbours that must STILL reach the generic vimul helper: vmulh=100111,
// vmulhu=100100, vmulhsu=100110. Sharing this test's funct3 group makes them the encodings a
// widened funct6 predicate would capture first.
constexpr u32 EncodeOpmvv(u32 f6, u32 vd, u32 vs2, u32 vs1)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0b010u << 12) | (vd << 7) | 0x57u;
}
// The OPIVV siblings that must STILL fail closed on this backend: vand=001001, vor=001010,
// vxor=001011.
constexpr u32 EncodeOpivv(u32 f6, u32 vd, u32 vs2, u32 vs1)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}
constexpr u32 EncodeVsubVV(u32 vd, u32 vs2, u32 vs1)
{
	return (0b000010u << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}

constexpr u32 VTYPE_E32_M1_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E64_M1_TA_MA = Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M2_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/1, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_MF2_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/7, /*vta=*/1, /*vma=*/1);

constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma

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
// alter a later one. The sibling route switches are pinned OFF so a stray add/sub/logical frame can
// never be mistaken for a mul one.
void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_mul_force_emit = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_diag_chunk_force_emit = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = false;
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

	b.mod = std::make_unique<llvm::Module>("t1b_test", g_llvm_ctx);
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
	config::rvv_qcg_typed_chunk_mul = flag;
	return BuildLLVM(words, n, vlen_bits);
}

// Builds the region ONLY (no LLVM backend), so a case whose expected outcome is "a `vchunkmul` node
// reaches a backend that cannot lower it" can be inspected without aborting the process.
Region *BuildRegionOnly(MemArena *arena, u32 const *words, unsigned n, u32 vlen_bits)
{
	config::vlen_bits = vlen_bits;
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(arena, job);
}

unsigned CountQirOp(Region *r, Op op)
{
	unsigned n = 0;
	for (auto &bb : r->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += ins.GetOpcode() == op;
		}
	}
	return n;
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

bool IsV8I64(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 8 && vt->getElementType()->isIntegerTy(64);
}

// Any fixed vector whose total width exceeds one 512-bit chunk. The frame partitions in QIR and
// hands LLVM one chunk per value, so nothing this wide may exist -- that is what separates this
// lowering from "let the type legalizer split a <32 x i32>".
bool IsWiderThanChunk(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	if (!vt || !vt->getElementType()->isIntegerTy()) {
		return false;
	}
	return vt->getNumElements() * vt->getElementType()->getIntegerBitWidth() > 512;
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

// Counts one specific v16i32 binary opcode. Used in both directions: the Mul count is what the
// route must produce, and the Add/Sub counts are what it must NOT produce (a wrong-operation
// mutation that every structural check in this file would otherwise accept).
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

// Any integer multiply in the function, at ANY vector type. Used to prove the ONLY multiply present
// is the <16 x i32> one -- a widening lowering would add a wider one.
unsigned CountAllVectorMuls(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
			n += bo && bo->getOpcode() == llvm::Instruction::Mul &&
			     bo->getType()->isVectorTy();
		}
	}
	return n;
}

unsigned CountWideVectorValues(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			n += IsWiderThanChunk(ins.getType());
			for (auto &op : ins.operands()) {
				n += IsWiderThanChunk(op->getType());
			}
		}
	}
	return n;
}

// sext/zext/trunc over vectors. A widening multiply would need at least one of each; the low-half
// lowering needs none.
unsigned CountVectorExtOrTrunc(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			if (!llvm::isa<llvm::SExtInst>(&ins) && !llvm::isa<llvm::ZExtInst>(&ins) &&
			    !llvm::isa<llvm::TruncInst>(&ins)) {
				continue;
			}
			n += ins.getType()->isVectorTy();
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

struct GuardCmp {
	u64 offs;
	u64 val;
	llvm::CmpInst::Predicate pred;
};

void CollectGuardCmps(llvm::Value *cond, llvm::Value *statev, std::vector<GuardCmp> *out,
		      unsigned *n_other)
{
	if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(cond);
	    bo && bo->getOpcode() == llvm::Instruction::And) {
		CollectGuardCmps(bo->getOperand(0), statev, out, n_other);
		CollectGuardCmps(bo->getOperand(1), statev, out, n_other);
		return;
	}
	auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(cond);
	if (!cmp) {
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
	out->push_back({offs, k->getZExtValue(), cmp->getPredicate()});
}

bool HasGuardCmp(std::vector<GuardCmp> const &cmps, u64 offs, u64 val)
{
	for (auto const &c : cmps) {
		if (c.offs == offs && c.val == val && c.pred == llvm::CmpInst::ICMP_EQ) {
			return true;
		}
	}
	return false;
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
	printf("%s: vlen=%u nchunks=%u vlmax=%u  vmul.vv v%u, v%u, v%u\n", tag, vlen_bits, nchunks,
	       vlmax, vd, vs2, vs1);
	u32 const insn = EncodeVmulVV(vd, vs2, vs1);
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
	// Four EQUALITY compares and nothing else. Equality is the load-bearing part for the partial-vl
	// obligation: it makes VLMAX the ONLY accepted vl, so every vl in [0, VLMAX) -- i.e. every
	// partial strip step -- takes the fallback edge. CheckGuardRejectsPartialVl states that
	// separately as its own named case.
	{
		std::vector<GuardCmp> cmps;
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
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Mul), (unsigned)nchunks);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Mul), (unsigned)nchunks);
	// WRONG-OPERATION GATE. A CreateAdd or CreateSub in place of CreateMul would satisfy every
	// other structural check in this file; this is what refuses it.
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Add), 0u);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Sub), 0u);
	// LOW-HALF GATE. The only multiply anywhere in the function is the <16 x i32> one, there is no
	// vector sext/zext/trunc, and no value wider than one 512-bit chunk exists. A widening lowering
	// (extend to i64, multiply, truncate) would break all three and is architecturally WRONG here:
	// vmul.vv returns the low SEW bits, and the high half belongs to vmulh/vmulhu/vmulhsu, which
	// are different funct6 values that stay on the generic vimul helper.
	CHECK_EQ(CountAllVectorMuls(b.fn), (unsigned)nchunks);
	CHECK_EQ(CountVectorExtOrTrunc(b.fn), 0u);
	CHECK_EQ(CountWideVectorValues(b.fn), 0u);

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

	// ---- per-chunk dataflow -----------------------------------------------------------------
	std::vector<llvm::BinaryOperator *> muls;
	for (auto &ins : *fast) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		if (bo && bo->getOpcode() == llvm::Instruction::Mul && IsV16I32(bo->getType())) {
			muls.push_back(bo);
		}
	}
	CHECK_EQ(muls.size(), (size_t)nchunks);
	if (muls.size() != nchunks) {
		return;
	}
	// WRAPPING: RVV integer multiply is modulo 2^SEW, so neither flag may be attached. This matters
	// more here than for the add and the sub: for a 32-bit multiply lane overflow is the ORDINARY
	// case rather than an edge case, so `nsw` would hand LLVM permission to poison lanes that a
	// conforming guest routinely produces. With <16 x i32> lanes and no nsw/nuw, LLVM's own
	// semantics for `mul` ARE mod 2^32 -- which is what makes the architectural low-half result
	// exact rather than approximate.
	for (auto *m : muls) {
		CHECK(!m->hasNoUnsignedWrap());
		CHECK(!m->hasNoSignedWrap());
	}
	// Operand SET, not ordered pair: multiplication commutes, so unlike the sub's test a swap here
	// is unobservable and asserting an order would be asserting a convention rather than a
	// semantic. What must hold is that each chunk's multiply consumes exactly that chunk's own two
	// loads and that its result is what that chunk's store writes.
	for (unsigned c = 0; c < nchunks; ++c) {
		auto *a = StripCasts(muls[c]->getOperand(0));
		auto *bb2 = StripCasts(muls[c]->getOperand(1));
		bool const pair_ok = (a == loads[2 * c].ins && bb2 == loads[2 * c + 1].ins) ||
				     (a == loads[2 * c + 1].ins && bb2 == loads[2 * c].ins);
		CHECK(pair_ok);
		CHECK(StripCasts(llvm::cast<llvm::StoreInst>(stores[c].ins)->getValueOperand()) == muls[c]);
	}

	// ---- chunk independence -----------------------------------------------------------------
	{
		std::vector<llvm::Value *> defs;
		for (auto &l : loads) {
			defs.push_back(l.ins);
		}
		for (auto *m : muls) {
			defs.push_back(m);
		}
		std::sort(defs.begin(), defs.end());
		CHECK_EQ((size_t)std::distance(defs.begin(), std::unique(defs.begin(), defs.end())),
			 (size_t)(3 * nchunks));
	}
	if (nchunks == 2) {
		for (unsigned c = 0; c < 2; ++c) {
			for (unsigned k = 0; k < 2; ++k) {
				CHECK(StripCasts(muls[c]->getOperand(k)) != muls[1 - c]);
			}
		}
		CHECK_EQ(stores[1].offs - stores[0].offs, (u64)64);
	}

	// ---- fallback arm ------------------------------------------------------------------------
	CHECK_EQ(CountCalls(slow), 1u);
	CHECK_EQ(CountBinOpV16I32(slow, llvm::Instruction::Mul), 0u);
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
	// The stub is the PRE-EXISTING rv32_vimul helper, read by name off the MakeRStub load.
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
			    GetRuntimeStubName(RuntimeStubId::id_rv32_vimul)));
			u64 off = 0;
			CHECK(StateOffsetOf(stub_ld->getPointerOperand(), statev, &off));
			CHECK_EQ(off, (u64)(offsetof(CPUState, stub_tab) +
					    RuntimeStubTab::offs(RuntimeStubId::id_rv32_vimul)));
		}
	}

	printf("  OK: %u mul<16 x i32> (0 add, 0 sub, 0 ext/trunc, 0 wide vectors), no wrap flags, "
	       "0 calls on the fast arm; fallback = 1 rv32_vimul call\n",
	       (unsigned)muls.size());
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
	CHECK_EQ(CountAllVectorMuls(b.fn), 0u);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Add), 0u);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Sub), 0u);
	CHECK_EQ(CountWideVectorValues(b.fn), 0u);
	unsigned n_typed_qir = 0, n_calls = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
			case Op::_vstatechunkload:
			case Op::_vchunkmul:
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
	printf("  no guard frame, no vector mul, %u typed QIR ops, %u calls\n", n_typed_qir, n_calls);
}

// BOTH switches are required, and neither alone suffices. This is the row that pins T1b's gate
// choice: --rvv-vector-ssa must not sweep vmul.vv into the route on its own, the way it does for
// vadd.vv.
void CheckGateNeedsBothSwitches(u32 vlen_bits)
{
	printf("gate needs both switches: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
	CheckNotAdmitted("  ssa-off", words, 2, vlen_bits, "--rvv-vector-ssa=0 (per-op flag on)",
			 /*ssa=*/false, /*flag=*/true);
	CheckNotAdmitted("  flag-off", words, 2, vlen_bits,
			 "--rvv-qcg-typed-chunk-mul=0 (vector-SSA on)", /*ssa=*/true, /*flag=*/false);
}

// THE PARTIAL-VL OBLIGATION, stated as its own case rather than left implicit in the guard-content
// check. RvvGenericChunkShapeAdmit has no tail chunk and the frame emits none, so a strip step whose
// vl is short MUST take the helper. The emitted guard is what enforces that, and this reads the
// enforcement out of the IR: the vl compare is an EQUALITY against exactly VLMAX, so the set of
// accepted vl values is the singleton {VLMAX} and every partial vl in [0, VLMAX) branches to the
// fallback arm -- which contains exactly one rv32_vimul call and no vector multiply.
//
// A mutation that made the compare `ICMP_ULE` (accepting any vl <= VLMAX) would pass every other
// check in this file, and would silently multiply 64 bytes for a guest that asked for fewer lanes.
void CheckGuardRejectsPartialVl(u32 vlen_bits, u32 vlmax)
{
	printf("partial vl -> helper: vlen=%u vlmax=%u\n", vlen_bits, vlmax);
	u32 const insn = EncodeVmulVV(VD_REG, VS2_REG, VS1_REG);
	u32 words[2] = {INSN_VSETVLI_E32M1, insn};
	Built b = BuildLLVMRoute(words, 2, vlen_bits);
	auto *statev = b.fn->getArg(0);

	auto fasts = BlocksNamed(b.fn, "rvv.tchunk.direct");
	auto slows = BlocksNamed(b.fn, "rvv.tchunk.fallback");
	CHECK_EQ(fasts.size(), (size_t)1);
	CHECK_EQ(slows.size(), (size_t)1);
	if (fasts.size() != 1 || slows.size() != 1) {
		return;
	}
	auto *br = llvm::dyn_cast<llvm::BranchInst>(fasts[0]->getSinglePredecessor()->getTerminator());
	CHECK(br != nullptr && br->isConditional());
	if (!br || !br->isConditional()) {
		return;
	}

	std::vector<GuardCmp> cmps;
	unsigned n_other = 0;
	CollectGuardCmps(br->getCondition(), statev, &cmps, &n_other);
	CHECK_EQ(n_other, 0u);

	// Exactly one compare reads vec.vl, its predicate is EQ, and its constant is VLMAX.
	unsigned n_vl = 0;
	for (auto const &c : cmps) {
		if (c.offs != ST_VL) {
			continue;
		}
		++n_vl;
		CHECK(c.pred == llvm::CmpInst::ICMP_EQ);
		CHECK_EQ(c.val, (u64)vlmax);
	}
	CHECK_EQ(n_vl, 1u);

	// The guard's FALSE edge is the helper arm, and it is a complete architectural execution of
	// this exact guest word -- so a partial-vl strip step produces the architectural result.
	CHECK(br->getSuccessor(1) == slows[0]);
	CHECK_EQ(CountCalls(slows[0]), 1u);
	CHECK_EQ(CountAllVectorMuls(slows[0]->getParent()) - CountBinOpV16I32(fasts[0], llvm::Instruction::Mul),
		 0u);
	unsigned n_helper = 0;
	for (auto &ins : *slows[0]) {
		n_helper += IsHelperCallWithRaw(&ins, statev, insn);
	}
	CHECK_EQ(n_helper, 1u);
	printf("  OK: vl compare is ICMP_EQ vs %u, so every vl in [0,%u) takes the 1-call rv32_vimul "
	       "arm; no multiply exists outside the fast arm\n",
	       vlmax, vlmax);
}

// The pure-QCG admission is UNCHANGED by T1b, in both directions. Checked at QIR level, which is the
// layer the accepted P3.5a evidence was taken at.
void CheckQcgUnchanged(u32 vlen_bits)
{
	printf("pure-QCG admission unchanged: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
	// (a) QCG + the route's own flag -> STILL admitted, and vector-SSA is irrelevant to it.
	for (bool ssa : {false, true}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = ssa;
		config::rvv_qcg_typed_chunk_mul = true;
		config::rvv_qcg_typed_chunk_mul_force_emit = true;
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkmul), (unsigned)(vlen_bits / 512));
	}
	// (b) QCG without the flag -> not admitted, whatever vector-SSA says.
	for (bool ssa : {false, true}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = ssa;
		config::rvv_qcg_typed_chunk_mul = false;
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 0u);
	}
	printf("  QCG route admits on its own flag alone; vector-SSA neither opens nor closes it\n");
}

// THE TWO ARMS HAVE DIFFERENT VLEN REACH, AND BOTH DIRECTIONS ARE PINNED.
//
// RvvLLVMMulChunkAdmit shares RvvGenericChunkShapeAdmit with its QCG twin, which admits k=1/2/4/8,
// and deliberately does NOT re-state T1b's VLEN 512/1024 scope -- RvvSSAEnabled() already refuses
// every other width. These two checks assert that consequence rather than the absent copy:
//
//   (a) VLEN 2048/4096 with EVERY switch on produces NO typed frame on the LLVM arm. If someone
//       later "fixed" RvvSSAEnabled to accept wider VLENs without extending this route's evidence,
//       this fails.
//   (b) the pure-QCG arm still reaches k=4 and k=8 at those same widths, so T1b did not narrow the
//       accepted HM.2a admission as a side effect.
// W5 (2026-09-17) INVERTED THIS CHECK. It read "the LLVM arm is VLEN {512,1024} only", which was
// RvvSSAEnabled()'s width list rather than anything about this route; W5 moved the LLVM arm's width
// decision to RvvRouteChunkShape, so a whole-chunk register is admitted at 2048 and 4096 with
// exactly the k the QCG arm reaches. The function is kept, asserting the count rather than a zero,
// because "both arms reach the same k" is the property that would break if either gate went back to
// a literal set -- and CheckQcgKeepsWideVlen below is still the other half of the pair.
void CheckWideVlenAdmittedOnLlvm()
{
	printf("LLVM arm at wide whole-chunk VLENs: k = VLEN/512 body ops:\n");
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
	for (u32 vlen : {2048u, 4096u}) {
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		config::rvv_qcg_typed_chunk_mul = true;
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkmul), vlen / 512u);
		printf("  vlen=%u: one typed frame, %u body ops\n", vlen, vlen / 512u);
	}
}

void CheckQcgKeepsWideVlen()
{
	printf("pure-QCG arm keeps its k=4/k=8 reach:\n");
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
	for (u32 vlen : {2048u, 4096u}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_qcg_typed_chunk_mul = true;
		config::rvv_qcg_typed_chunk_mul_force_emit = true;
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkmul), vlen / 512);
		printf("  vlen=%u: %u vchunkmul nodes on the pure-QCG arm, unchanged by T1b\n", vlen,
		       vlen / 512);
	}
}

// THE PRECISE-STATE BOUNDARY. Both arms of the frame address CPUState::vec directly, and PreSideeff
// does not flush the --rvv-vector-ssa chunk cache for an OP-V opcode. So the handler must commit
// every dirty chunk BEFORE the frame. The smallest guest sequence that reaches it:
//
//     vsetvli a0, a0, e32, m1, ta, ma   (helper; TranslateHelper commits and resets)
//     vl1re32.v v1, (a0)                (typed rvvload; RvvDefineGroup marks v1 dirty)
//     vmul.vv  v3, v1, v2               (ADMITTED -> the typed frame)
//
// The assertion is positional: one `rvvwrite` per dirty chunk must appear strictly BETWEEN the
// `rvvload` and the `rvvtypedchunkbegin`. This is inherited from the shared
// RvvEmitTypedAluChunkGroupCore rather than re-implemented, and the check exists because "the
// multiply uses the shared core" is a claim that a later edit could quietly stop being true.
void CheckSsaCommitBoundary(u32 vlen_bits, unsigned nchunks)
{
	printf("precise-state boundary: vlen=%u\n", vlen_bits);
	constexpr u32 INSN_VL1RE32 = (1u << 25) | (0b01000u << 20) | (10u << 15) | (0b110u << 12) |
				     (1u << 7) | 0x07u;
	u32 words[3] = {INSN_VSETVLI_E32M1, INSN_VL1RE32, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
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

// The siblings T1b did NOT route must still fail closed: their own flag on, vector-SSA on, AOT on
// -- and no typed frame, because they have no LLVM gate. T1d moved vxor.vv out of that set. If one of them silently
// acquired a route, its `vchunk*` node would reach the backend and Panic; this catches the QIR-level
// cause first. vsub.vv is included as a POSITIVE control: it has had an LLVM gate since S3.10a, so
// it must still admit, which is what makes the three negative rows mean "no route" rather than "the
// harness cannot admit anything".
void CheckSiblingsStillFailClosed(u32 vlen_bits)
{
	printf("siblings unchanged: vlen=%u\n", vlen_bits);
	struct Row {
		char const *name;
		u32 word;
		bool *flag;
		unsigned want_frames;
	} rows[] = {
	    // T1d gave vxor.vv its own LLVM gate, lowering and whitelist entry, so this row is now a
	    // POSITIVE one. It stays in the table for the reason vsub.vv does: without it the two
	    // remaining zeros could be satisfied by a harness that admits nothing at all.
	    {"vxor.vv", EncodeOpivv(0b001011u, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_xor, 1},
	    // T1e gave vor.vv its own LLVM route, so this row is positive too; vand.vv is the last
	    // bitwise member without one.
	    {"vor.vv", EncodeOpivv(0b001010u, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_or, 1},
	    // T1f routed vand.vv, the last of the family, so this row is positive too and no
	    // negative row remains in this table.
	    {"vand.vv", EncodeOpivv(0b001001u, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_and, 1},
	    {"vsub.vv", EncodeVsubVV(VD_REG, VS2_REG, VS1_REG), &config::rvv_qcg_typed_chunk_sub, 1},
	};
	for (auto const &r : rows) {
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		*r.flag = true;
		u32 words[2] = {INSN_VSETVLI_E32M1, r.word};
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), r.want_frames);
		CHECK_EQ(CountQirOp(region, Op::_vchunkmul), 0u);
		printf("  %-8s own flag + --rvv-vector-ssa + AOT -> %u typed frame(s)%s\n", r.name,
		       r.want_frames, r.want_frames ? " (positive control)" : "");
	}
}

// The OPMVV neighbours of VF6_VMUL stay on the generic vimul helper. These share this route's funct3
// group, so a funct6 predicate one bit loose would capture them and compute a LOW-half product where
// the guest asked for a HIGH-half one -- structurally perfect, numerically wrong.
void CheckMulhNeighboursStillHelper(u32 vlen_bits)
{
	printf("vmulh/vmulhu/vmulhsu stay on the helper: vlen=%u\n", vlen_bits);
	struct Row {
		char const *name;
		u32 f6;
	} rows[] = {{"vmulhu.vv", 0b100100u}, {"vmulhsu.vv", 0b100110u}, {"vmulh.vv", 0b100111u}};
	for (auto const &r : rows) {
		u32 words[2] = {INSN_VSETVLI_E32M1, EncodeOpmvv(r.f6, VD_REG, VS2_REG, VS1_REG)};
		Built b = BuildLLVMRoute(words, 2, vlen_bits);
		CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkmul), 0u);
		CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
		CHECK_EQ(CountAllVectorMuls(b.fn), 0u);
		printf("  %-11s (funct6=%06o) -> no typed frame, no vector mul\n", r.name, r.f6);
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
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = false; // explicitly NOT bypassing anything
	Built b = BuildLLVM(words, 2, 512);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Mul), 1u);
	printf("  admitted with force_emit=0 on a host with avx512f=%d\n", (int)host_avx512);
}

// ---------------------------------------------------------------------------------------------
// AOT REACHABILITY. Everything above proves the route exists in the translator and the backend; none
// of it proves an ARTIFACT can ever take it. That needs two things outside this translation unit --
// an `elfaot` option that can set the flag, and a `kRvvRouteContract` row that carries the parent's
// value to every background builder -- and their absence is exactly the defect T1a recorded for
// vsub.vv (a complete, tested, unreachable LLVM route).
//
// This reads the production sources rather than a copy of them. It is a source-level check, so it is
// weaker than executing elfaot; what it forecloses is precisely the failure mode that already
// happened once, where the lowering landed and the plumbing did not.
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
	// (a) elfaot must declare the option AND assign it to the config field the gate reads.
	std::string const aot = ReadFile("dbt/elfaot.cpp");
	CHECK(aot.find("\"rvv-qcg-typed-chunk-mul\"") != std::string::npos);
	CHECK(aot.find("dbt::config::rvv_qcg_typed_chunk_mul = opts.rvv_qcg_typed_chunk_mul;") !=
	      std::string::npos);
	printf("  elfaot: --rvv-qcg-typed-chunk-mul declared and assigned to config\n");

	// (b) the same-run route contract must carry it, so a background builder spawned by elfrun
	// inherits the parent's live value instead of elfaot's default.
	std::string const boot = ReadFile("dbt/aot/aot_boot.cpp");
	auto const tbl = boot.find("kRvvRouteContract[]");
	CHECK(tbl != std::string::npos);
	auto const tbl_end = boot.find("};", tbl);
	CHECK(tbl_end != std::string::npos);
	if (tbl != std::string::npos && tbl_end != std::string::npos) {
		std::string const body = boot.substr(tbl, tbl_end - tbl);
		CHECK(body.find("\"rvv-qcg-typed-chunk-mul\"") != std::string::npos);
		CHECK(body.find("&config::rvv_qcg_typed_chunk_mul") != std::string::npos);
	}
	printf("  aot_boot: kRvvRouteContract carries the flag to every spawn site\n");

	// (c) the propagation audit's mirror of the contract must list it too -- its own comment says
	// the two are updated together and that it fails if they drift.
	std::string const audit = ReadFile("scripts/vlen_propagation_audit.py");
	CHECK(audit.find("(\"rvv-qcg-typed-chunk-mul\", \"rvv_qcg_typed_chunk_mul\", \"Route\")") !=
	      std::string::npos);
	printf("  vlen_propagation_audit.py: ROUTE_FLAGS mirror updated in lockstep\n");

	// (d) the flag the three above name is the flag the gate reads. Asserted by construction: this
	// binary links the real translator, and every admitted case in this file was produced with
	// exactly `config::rvv_qcg_typed_chunk_mul = true`, while CheckGateNeedsBothSwitches shows
	// setting it false closes the route.
	printf("  the named flag IS the gate input (CheckGateNeedsBothSwitches proves both polarities)\n");
}

void DumpIR(char const *tag, u32 vlen_bits)
{
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
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
	printf("T1b typed vmul.vv LLVM route test\n");

	// The field-built encodings reproduce the exact constants the accepted P3.5a QCG test uses.
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M1_TA_MA), INSN_VSETVLI_E32M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E64_M1_TA_MA), INSN_VSETVLI_E64M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M2_TA_MA), INSN_VSETVLI_E32M2);
	// vmul.vv v3, v1, v2 -- the exact word dbt/qmc/qcg/vmulvv_typedchunk_route_test.cpp uses.
	CHECK_EQ(EncodeVmulVV(VD_REG, VS2_REG, VS1_REG), 0x961121d7u);

	printf("\n== admitted: VLEN=512, one chunk ==\n");
	CheckAdmitted("v512", 512, 1, 16, VD_REG, VS2_REG, VS1_REG);
	printf("\n== admitted: VLEN=1024, two independent chunks ==\n");
	CheckAdmitted("v1024", 1024, 2, 32, VD_REG, VS2_REG, VS1_REG);

	printf("\n== admitted: the three legal operand overlaps ==\n");
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
	CheckWideVlenAdmittedOnLlvm();
	CheckQcgKeepsWideVlen();
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== guard: partial vl takes the helper ==\n");
	CheckGuardRejectsPartialVl(512, 16);
	CheckGuardRejectsPartialVl(1024, 32);

	printf("\n== precise-state boundary ==\n");
	CheckSsaCommitBoundary(512, 1);
	CheckSsaCommitBoundary(1024, 2);

	printf("\n== siblings and funct6 neighbours ==\n");
	CheckSiblingsStillFailClosed(512);
	CheckSiblingsStillFailClosed(1024);
	CheckMulhNeighboursStillHelper(512);
	CheckMulhNeighboursStillHelper(1024);

	printf("\n== non-admitted shapes stay on the helper path ==\n");
	{
		u32 w[2] = {INSN_VSETVLI_E64M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
		CheckNotAdmitted("e64,m1", w, 2, 512, "unsupported SEW (e64)");
		CheckNotAdmitted("e64,m1", w, 2, 1024, "unsupported SEW (e64)");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M2, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
		CheckNotAdmitted("e32,m2", w, 2, 512, "unsupported LMUL (m2)");
		CheckNotAdmitted("e32,m2", w, 2, 1024, "unsupported LMUL (m2)");
	}
	{
		u32 w[2] = {EncodeVsetvli(VTYPE_E32_MF2_TA_MA),
			    EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
		CheckNotAdmitted("e32,mf2", w, 2, 512, "fractional LMUL (mf2)");
		CheckNotAdmitted("e32,mf2", w, 2, 1024, "fractional LMUL (mf2)");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG, /*vm=*/0)};
		CheckNotAdmitted("masked", w, 2, 512, "masked vmul.vv (vm=0) is not this opcode");
		CheckNotAdmitted("masked", w, 2, 1024, "masked vmul.vv (vm=0) is not this opcode");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M1, EncodeVmulVV(VD_REG, VS2_REG, VS1_REG)};
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
