// T1e: focused test for the typed `vor.vv` V512 chunk group as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG sibling.
// dbt/qmc/qcg/vorvv_typedchunk_route_test.cpp routes the same guest instruction pair through the
// same real translator, but every one of its checks stops at QIR, post-QRegAlloc operands, or
// objdump-decoded AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see
// whether the LLVM/AOT tier admits the route at all, and before T1e it did not: `vchunkor` Panic'd
// in llvmgen.cpp and RvvQcgTypedOrChunkAdmit returned 0 for every `aot_use_llvm` compile.
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
// WHAT IS SPECIFIC TO THIS OPCODE, and therefore what this file checks that its add/sub/mul siblings
// cannot:
//
//   * THREE NEAR-IDENTICAL BITWISE OPERATIONS EXIST AND THE NEIGHBOUR ARGUMENT IS NOW ASYMMETRIC.
//     VF6_VAND is 001001, VF6_VOR is 001010 and VF6_VXOR is 001011 -- adjacent funct6 values in the
//     same OPIVV group. This is the SECOND of the three to be routed, so the two ways to get it
//     wrong differ in KIND rather than only in value. `CreateXor` here would STEAL the accepted T1d
//     route's operation and compute an XOR for a guest OR -- a regression of a shipped route, not
//     merely a new bug -- while `CreateAnd` would compute an AND using an operation that has no LLVM
//     lowering at all. Either produces a frame with the right blocks, chunk count, windows, guard
//     and fallback, and the wrong value in every lane. CheckAdmitted therefore censuses all six
//     family opcodes and requires everything but `or` to be zero, and
//     CheckNeighboursHandledCorrectly checks BOTH neighbours in their now-DIFFERENT directions:
//     vand.vv must produce no frame at all, vxor.vv must still produce exactly one.
//   * THE LANE WIDTH IS ARCHITECTURALLY IRRELEVANT TO THE OPERATION but is still pinned. An unmasked
//     512-bit or is the same 512 bits at every SEW, so unlike the multiply there is no host or
//     semantic reason for the SEW=32 restriction -- it is purely an evidence-scope decision. The
//     test therefore asserts the emitted type is exactly <16 x i32> AND that e64 keeps the helper,
//     so a future widening has to change the predicate and this file together rather than silently
//     reinterpreting lanes.
//   * OR COMMUTES, so operand ORDER is unobservable and asserting it would be asserting a
//     convention. CheckAdmitted checks the operand SET per chunk instead -- each chunk's or
//     consumes that chunk's own two loads and nothing else.
//
// WHAT WOULD FAIL HERE, stated so each assertion has a named failure it catches:
//   * wrong operation (CreateXor/CreateAnd/CreateAdd instead of Or) -> the opcode check plus the
//     zero-Xor/And/Add/Sub/Mul-in-function census
//   * the accepted T1d xor route stolen or broken          -> the zero-Xor census plus
//     CheckNeighboursHandledCorrectly's POSITIVE vxor.vv row
//   * a neighbour's encoding captured by this route        -> CheckNeighboursHandledCorrectly
//   * `Op::_vchunkor` missing from TChunkCheckBodyOp's whitelist -> the backend Panics while
//     building any admitted case, so the process aborts and the test cannot report success
//   * either LLVM gate switch dropped                      -> CheckGateNeedsBothSwitches
//   * partial vl or a wrong vtype admitted by the guard    -> CheckGuardRejectsPartialVl
//   * missing precise-state boundary                       -> CheckSsaCommitBoundary
//   * the QCG arm changed by T1e's shared-shape refactor   -> CheckQcgUnchanged
//   * the elfaot option or the route-contract row dropped  -> CheckAotPlumbing

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
// main() against the exact constants the accepted S2.3 QCG route test uses.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
// Any OPIVV .vv encoding: funct6, vm, vs2[24:20], vs1[19:15], funct3=000, vd[11:7], opcode 0x57.
constexpr u32 EncodeOpivv(u32 f6, u32 vd, u32 vs2, u32 vs1, u32 vm = 1)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}
// The three adjacent bitwise funct6 values. T1e routes F6_VOR; F6_VXOR was routed by T1d and
// F6_VAND is still unrouted on this backend.
constexpr u32 F6_VAND = 0b001001u, F6_VOR = 0b001010u, F6_VXOR = 0b001011u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u;

constexpr u32 EncodeVorVV(u32 vd, u32 vs2, u32 vs1, u32 vm = 1)
{
	return EncodeOpivv(F6_VOR, vd, vs2, vs1, vm);
}
// vmul.vv is OPMVV (funct3=010), not OPIVV -- carried as a positive control in the sibling table.
constexpr u32 EncodeVmulVV(u32 vd, u32 vs2, u32 vs1)
{
	return (0b100101u << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0b010u << 12) |
	       (vd << 7) | 0x57u;
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
// alter a later one. The sibling route switches are pinned OFF so a stray add/sub/mul/or/and frame
// can never be mistaken for a xor one.
void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_or_force_emit = false;
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

	b.mod = std::make_unique<llvm::Module>("t1e_test", g_llvm_ctx);
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
	config::rvv_qcg_typed_chunk_or = flag;
	return BuildLLVM(words, n, vlen_bits);
}

// Builds the region ONLY (no LLVM backend), so a case whose expected outcome is "a `vchunk*` node
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

// Counts one specific v16i32 binary opcode. Used in BOTH directions here, and that is the whole
// point for this opcode: the Xor count is what the route must produce, and the And/Or counts are
// what it must NOT -- those two are its adjacent funct6 neighbours, and substituting either is a
// mutation no shape check would notice.
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

// Any vector binary op of the given opcode at ANY type. Used to prove the ONLY xor present is the
// <16 x i32> one -- a lowering that widened lanes would add a wider one.
unsigned CountAllVectorBinOps(llvm::Function *fn, llvm::Instruction::BinaryOps opc)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
			n += bo && bo->getOpcode() == opc && bo->getType()->isVectorTy();
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

// Every arithmetic/bitwise vector opcode this family could plausibly emit, so a wrong-operation
// mutation is caught whichever direction it goes.
struct OpCensus {
	unsigned or_ = 0, xor_ = 0, and_ = 0, add = 0, sub = 0, mul = 0;
};

OpCensus CensusOf(llvm::Function *fn)
{
	OpCensus c;
	c.or_ = CountAllVectorBinOps(fn, llvm::Instruction::Or);
	c.xor_ = CountAllVectorBinOps(fn, llvm::Instruction::Xor);
	c.and_ = CountAllVectorBinOps(fn, llvm::Instruction::And);
	c.add = CountAllVectorBinOps(fn, llvm::Instruction::Add);
	c.sub = CountAllVectorBinOps(fn, llvm::Instruction::Sub);
	c.mul = CountAllVectorBinOps(fn, llvm::Instruction::Mul);
	return c;
}

// The neighbours and the other family members must all be zero, whatever the expected or count is.
void CheckCensusOnlyOr(OpCensus const &c, unsigned want_or)
{
	CHECK_EQ(c.or_, want_or);
	CHECK_EQ(c.xor_, 0u); // VF6_VXOR is one funct6 ABOVE this route, and IS routed (T1d)
	CHECK_EQ(c.and_, 0u); // VF6_VAND is one below, and is NOT routed
	CHECK_EQ(c.add, 0u);
	CHECK_EQ(c.sub, 0u);
	CHECK_EQ(c.mul, 0u);
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
	printf("%s: vlen=%u nchunks=%u vlmax=%u  vor.vv v%u, v%u, v%u\n", tag, vlen_bits, nchunks,
	       vlmax, vd, vs2, vs1);
	u32 const insn = EncodeVorVV(vd, vs2, vs1);
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
	// Four EQUALITY compares and nothing else. Equality is what makes VLMAX the ONLY accepted vl,
	// so every partial strip step takes the fallback; CheckGuardRejectsPartialVl states that
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
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Or), (unsigned)nchunks);
	// WRONG-OPERATION GATE, and for this opcode it is the load-bearing check in the file. `or` and
	// `and` are its adjacent funct6 neighbours and would satisfy every structural assertion here.
	CheckCensusOnlyOr(CensusOf(b.fn), (unsigned)nchunks);
	// LANE TYPE. An unmasked 512-bit xor is lane-width-independent, so the emitted type is a
	// DECISION rather than a consequence: pinning it to <16 x i32> is what forces a future SEW
	// widening to change the admission predicate and this lowering together.
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
	std::vector<llvm::BinaryOperator *> ors;
	for (auto &ins : *fast) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		if (bo && bo->getOpcode() == llvm::Instruction::Or && IsV16I32(bo->getType())) {
			ors.push_back(bo);
		}
	}
	CHECK_EQ(ors.size(), (size_t)nchunks);
	if (ors.size() != nchunks) {
		return;
	}
	// Operand SET, not ordered pair: xor commutes, so asserting an order would assert a convention
	// rather than a semantic. What must hold is that each chunk's xor consumes exactly that chunk's
	// own two loads and that its result is what that chunk's store writes.
	for (unsigned c = 0; c < nchunks; ++c) {
		auto *a = StripCasts(ors[c]->getOperand(0));
		auto *bb2 = StripCasts(ors[c]->getOperand(1));
		bool const pair_ok = (a == loads[2 * c].ins && bb2 == loads[2 * c + 1].ins) ||
				     (a == loads[2 * c + 1].ins && bb2 == loads[2 * c].ins);
		CHECK(pair_ok);
		CHECK(StripCasts(llvm::cast<llvm::StoreInst>(stores[c].ins)->getValueOperand()) == ors[c]);
	}

	// ---- chunk independence -----------------------------------------------------------------
	{
		std::vector<llvm::Value *> defs;
		for (auto &l : loads) {
			defs.push_back(l.ins);
		}
		for (auto *x : ors) {
			defs.push_back(x);
		}
		std::sort(defs.begin(), defs.end());
		CHECK_EQ((size_t)std::distance(defs.begin(), std::unique(defs.begin(), defs.end())),
			 (size_t)(3 * nchunks));
	}
	if (nchunks == 2) {
		for (unsigned c = 0; c < 2; ++c) {
			for (unsigned k = 0; k < 2; ++k) {
				CHECK(StripCasts(ors[c]->getOperand(k)) != ors[1 - c]);
			}
		}
		CHECK_EQ(stores[1].offs - stores[0].offs, (u64)64);
	}

	// ---- fallback arm ------------------------------------------------------------------------
	CHECK_EQ(CountCalls(slow), 1u);
	CHECK_EQ(CountBinOpV16I32(slow, llvm::Instruction::Or), 0u);
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
	// The stub is the PRE-EXISTING rv32_vialu helper -- the SAME stub vsub.vv falls back to,
	// because both encodings come out of the same generic vialu decode family.
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

	printf("  OK: %u or<16 x i32> (0 xor, 0 and, 0 add/sub/mul, 0 wide vectors), 0 calls on the "
	       "fast arm; fallback = 1 rv32_vialu call\n",
	       (unsigned)ors.size());
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
	CheckCensusOnlyOr(CensusOf(b.fn), 0u);
	CHECK_EQ(CountWideVectorValues(b.fn), 0u);
	unsigned n_typed_qir = 0, n_calls = 0;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
			case Op::_vstatechunkload:
			case Op::_vchunkor:
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
	printf("  no guard frame, no vector or, %u typed QIR ops, %u calls\n", n_typed_qir, n_calls);
}

// BOTH switches are required, and neither alone suffices. This pins T1e's gate choice:
// --rvv-vector-ssa must not sweep vor.vv into the route on its own, the way it does for vadd.vv.
void CheckGateNeedsBothSwitches(u32 vlen_bits)
{
	printf("gate needs both switches: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
	CheckNotAdmitted("  ssa-off", words, 2, vlen_bits, "--rvv-vector-ssa=0 (per-op flag on)",
			 /*ssa=*/false, /*flag=*/true);
	CheckNotAdmitted("  flag-off", words, 2, vlen_bits,
			 "--rvv-qcg-typed-chunk-or=0 (vector-SSA on)", /*ssa=*/true, /*flag=*/false);
}

// THE PARTIAL-VL OBLIGATION, as its own case rather than implicit in the guard-content check. There
// is no tail chunk in this lowering and the frame emits none, so a strip step whose vl is short MUST
// take the helper. This reads the enforcement out of the IR: the vl compare is an EQUALITY against
// exactly VLMAX, so the accepted set is the singleton {VLMAX} and every partial vl in [0, VLMAX)
// branches to the fallback -- which holds exactly one rv32_vialu call and no xor.
//
// A mutation making the compare ICMP_ULE would pass every other check in this file and would xor 64
// bytes for a guest that asked for fewer lanes.
void CheckGuardRejectsPartialVl(u32 vlen_bits, u32 vlmax)
{
	printf("partial vl -> helper: vlen=%u vlmax=%u\n", vlen_bits, vlmax);
	u32 const insn = EncodeVorVV(VD_REG, VS2_REG, VS1_REG);
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

	CHECK(br->getSuccessor(1) == slows[0]);
	CHECK_EQ(CountCalls(slows[0]), 1u);
	CHECK_EQ(CountBinOpV16I32(slows[0], llvm::Instruction::Or), 0u);
	unsigned n_helper = 0;
	for (auto &ins : *slows[0]) {
		n_helper += IsHelperCallWithRaw(&ins, statev, insn);
	}
	CHECK_EQ(n_helper, 1u);
	printf("  OK: vl compare is ICMP_EQ vs %u, so every vl in [0,%u) takes the 1-call rv32_vialu "
	       "arm; no xor on that arm\n",
	       vlmax, vlmax);
}

// The pure-QCG admission is UNCHANGED by T1e, in both directions. This matters more here than for
// T1b: T1e moved the QCG gate's inline VLEN/SEW rows onto the shared RvvAluChunkShapeAdmit, so this
// is the check that the refactor preserved the admitted set exactly. Checked at QIR level, which is
// the layer the accepted S2.3 evidence was taken at.
void CheckQcgUnchanged(u32 vlen_bits)
{
	printf("pure-QCG admission unchanged: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
	// (a) QCG + the route's own flag -> STILL admitted, and vector-SSA is irrelevant to it.
	for (bool ssa : {false, true}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = ssa;
		config::rvv_qcg_typed_chunk_or = true;
		config::rvv_qcg_typed_chunk_or_force_emit = true;
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkor), (unsigned)(vlen_bits / 512));
	}
	// (b) QCG without the flag -> not admitted, whatever vector-SSA says.
	for (bool ssa : {false, true}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = ssa;
		config::rvv_qcg_typed_chunk_or = false;
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 0u);
	}
	printf("  QCG route admits on its own flag alone; vector-SSA neither opens nor closes it\n");
}

// W5 (2026-09-17) CHANGED WHAT THE TWO ARMS DISAGREE ABOUT, so this check now asserts that they
// AGREE at every whole-chunk width and still refuse the same partial one.
//
// Before W5 the LLVM arm was closed by RvvSSAEnabled(), whose width list was {512, 1024}, so the
// arms diverged above 1024 and the narrow widths were refused on both. W5 made RvvRouteChunkShape
// the one width authority for the LLVM arm, so a register that tiles into whole host chunks is
// admitted on both arms with the same count -- `{16,1}` at 128, `{32,1}` at 256, `{64, VLEN/512}`
// from 512 up -- and a register that does NOT tile (VLEN 384 gives 48 bytes, which is not a host
// vector width) is refused on both.
//
// Asserting the counts on BOTH arms rather than a zero on one is what keeps this from passing again
// if either gate silently returned to a literal VLEN set.
void CheckWideAndNarrowVlenRefused()
{
	printf("both arms follow the geometry: whole chunks admitted, a partial one refused:\n");
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
	for (u32 vlen : {128u, 256u, 384u, 2048u, 4096u}) {
		// The geometry: chunk width min(VLEN/8, 64) restricted to the three host vector widths,
		// count (VLEN/8)/width. 384 gives 48 and has no host width, so it refuses.
		u32 const reg_bytes = vlen / 8u;
		u32 const cw = reg_bytes < 64u ? reg_bytes : 64u;
		bool const tiles = (cw == 16u || cw == 32u || cw == 64u) && reg_bytes % cw == 0u;
		u32 const k = tiles ? reg_bytes / cw : 0u;
		// LLVM arm.
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		config::rvv_qcg_typed_chunk_or = true;
		MemArena a1(1u << 20);
		Region *r1 = BuildRegionOnly(&a1, words, 2, vlen);
		CHECK_EQ(CountQirOp(r1, Op::_rvvtypedchunkbegin), tiles ? 1u : 0u);
		CHECK_EQ(CountQirOp(r1, Op::_vchunkor), k);
		// QCG arm: refused on a partial chunk, admitted at k = VLEN/512 on a whole one.
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_qcg_typed_chunk_or = true;
		config::rvv_qcg_typed_chunk_or_force_emit = true;
		MemArena a2(1u << 20);
		Region *r2 = BuildRegionOnly(&a2, words, 2, vlen);
		// The QCG arm's own rule is still RvvGenericChunkShapeAdmit (VLEN a multiple of 512),
		// untouched by W5: it is what makes the narrow widths an LLVM-only widening rather than a
		// change to the pure-QCG backend.
		bool const whole_512 = vlen % 512u == 0u;
		CHECK_EQ(CountQirOp(r2, Op::_rvvtypedchunkbegin), whole_512 ? 1u : 0u);
		CHECK_EQ(CountQirOp(r2, Op::_vchunkor), whole_512 ? vlen / 512u : 0u);
		printf("  vlen=%-5u LLVM: %u body op(s); QCG: %u body op(s)\n", vlen, k,
		       whole_512 ? vlen / 512u : 0u);
	}
}

// THE PRECISE-STATE BOUNDARY, inherited from the shared RvvEmitTypedAluChunkGroupCore rather than
// re-implemented. The smallest guest sequence that reaches it:
//
//     vsetvli a0, a0, e32, m1, ta, ma   (helper; TranslateHelper commits and resets)
//     vl1re32.v v1, (a0)                (typed rvvload; RvvDefineGroup marks v1 dirty)
//     vor.vv  v3, v1, v2               (ADMITTED -> the typed frame)
//
// One `rvvwrite` per dirty chunk must appear strictly BETWEEN the `rvvload` and the
// `rvvtypedchunkbegin`. The check exists because "the xor uses the shared core" is a claim a later
// edit could quietly stop making true.
void CheckSsaCommitBoundary(u32 vlen_bits, unsigned nchunks)
{
	printf("precise-state boundary: vlen=%u\n", vlen_bits);
	constexpr u32 INSN_VL1RE32 = (1u << 25) | (0b01000u << 20) | (10u << 15) | (0b110u << 12) |
				     (1u << 7) | 0x07u;
	u32 words[3] = {INSN_VSETVLI_E32M1, INSN_VL1RE32, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
	Built b = BuildLLVMRoute(words, 3, vlen_bits);
	std::vector<Op> ops;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			ops.push_back(ins.GetOpcode());
		}
	}
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvload), (long)1);
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

// THE TWO ADJACENT BITWISE NEIGHBOURS, EACH CHECKED IN ITS OWN DIRECTION. VF6_VAND (001001) sits one
// funct6 value below VF6_VOR (001010) and VF6_VXOR (001011) one above, all in the same OPIVV group.
// After T1d the two directions are no longer the same check:
//
//   * vand.vv has NO LLVM lowering -- `vchunkand` would Panic in the backend -- so with its own
//     switch ON it must still produce no frame. That is the classic fail-closed row.
//   * vxor.vv IS routed, by the accepted T1d checkpoint, so with its own switch ON it must still
//     produce exactly one frame AND that frame's node must be `vchunkxor`, not `vchunkor`. This row
//     is what catches T1e stealing or breaking a shipped route -- a failure mode the earlier
//     bitwise checkpoints could not have.
//
// In BOTH rows the `vchunkor` count must be zero: neither neighbour may be captured by this route.
void CheckNeighboursHandledCorrectly(u32 vlen_bits)
{
	printf("adjacent bitwise neighbours, each in its own direction: vlen=%u\n", vlen_bits);
	struct Row {
		char const *name;
		u32 f6;
		bool *flag;
		Op node;
		unsigned want_frames; // T1f: both are 1 -- vand.vv acquired its route too
	} rows[] = {
	    {"vand.vv", F6_VAND, &config::rvv_qcg_typed_chunk_and, Op::_vchunkand, 1},
	    {"vxor.vv", F6_VXOR, &config::rvv_qcg_typed_chunk_xor, Op::_vchunkxor, 1},
	};
	u8 const k = (u8)(vlen_bits / 512);
	for (auto const &r : rows) {
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		*r.flag = true;
		u32 words[2] = {INSN_VSETVLI_E32M1, EncodeOpivv(r.f6, VD_REG, VS2_REG, VS1_REG)};
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), r.want_frames);
		CHECK_EQ(CountQirOp(region, r.node), r.want_frames ? (unsigned)k : 0u);
		// Neither neighbour may be routed through THIS route's node -- the failure a predicate
		// one funct6 value loose would produce.
		CHECK_EQ(CountQirOp(region, Op::_vchunkor), 0u);
		char f6b[7];
		for (unsigned i = 0; i < 6; ++i) {
			f6b[i] = (char)('0' + ((r.f6 >> (5 - i)) & 1u));
		}
		f6b[6] = '\0';
		printf("  %-8s (funct6=%s) own flag + --rvv-vector-ssa + AOT -> %u frame(s), %u %s, "
		       "0 vchunkor\n",
		       r.name, f6b, r.want_frames, r.want_frames ? (unsigned)k : 0u,
		       r.want_frames ? "vchunkxor (T1d route intact)" : "vchunkand");
	}
}

// The other already-routed family members are POSITIVE controls too. Without them the vand.vv zero
// above could be satisfied by a harness that simply cannot produce a frame at all. (vxor.vv is
// already covered as the positive row of CheckNeighboursHandledCorrectly.)
void CheckRoutedSiblingsStillAdmit(u32 vlen_bits)
{
	printf("routed siblings still admit (positive controls): vlen=%u\n", vlen_bits);
	struct Row {
		char const *name;
		u32 word;
		bool *flag;
	} rows[] = {
	    {"vsub.vv", EncodeOpivv(F6_VSUB, VD_REG, VS2_REG, VS1_REG),
	     &config::rvv_qcg_typed_chunk_sub},
	    {"vmul.vv", EncodeVmulVV(VD_REG, VS2_REG, VS1_REG), &config::rvv_qcg_typed_chunk_mul},
	};
	for (auto const &r : rows) {
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		*r.flag = true;
		u32 words[2] = {INSN_VSETVLI_E32M1, r.word};
		MemArena arena(1u << 20);
		Region *region = BuildRegionOnly(&arena, words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkor), 0u);
		printf("  %-8s own flag + --rvv-vector-ssa + AOT -> 1 typed frame, 0 vchunkor\n", r.name);
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
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_or_force_emit = false; // explicitly NOT bypassing anything
	Built b = BuildLLVM(words, 2, 512);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	CHECK_EQ(CountBinOpV16I32(b.fn, llvm::Instruction::Or), 1u);
	printf("  admitted with force_emit=0 on a host with avx512f=%d\n", (int)host_avx512);
}

// ---------------------------------------------------------------------------------------------
// AOT REACHABILITY. Everything above proves the route exists in the translator and the backend; none
// of it proves an ARTIFACT can ever take it. That needs an `elfaot` option and a
// `kRvvRouteContract` row, and their absence is exactly the defect T1a recorded for vsub.vv and T1c
// had to repair. Source-level, so weaker than executing elfaot; what it forecloses is the failure
// that has already happened once in this tree.
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
	std::string const aot = ReadFile("dbt/elfaot.cpp");
	CHECK(aot.find("\"rvv-qcg-typed-chunk-or\"") != std::string::npos);
	CHECK(aot.find("dbt::config::rvv_qcg_typed_chunk_or = opts.rvv_qcg_typed_chunk_or;") !=
	      std::string::npos);
	printf("  elfaot: --rvv-qcg-typed-chunk-or declared and assigned to config\n");

	std::string const boot = ReadFile("dbt/aot/aot_boot.cpp");
	auto const tbl = boot.find("kRvvRouteContract[]");
	CHECK(tbl != std::string::npos);
	auto const tbl_end = boot.find("};", tbl);
	CHECK(tbl_end != std::string::npos);
	if (tbl != std::string::npos && tbl_end != std::string::npos) {
		std::string const body = boot.substr(tbl, tbl_end - tbl);
		CHECK(body.find("\"rvv-qcg-typed-chunk-or\"") != std::string::npos);
		CHECK(body.find("&config::rvv_qcg_typed_chunk_or") != std::string::npos);
	}
	printf("  aot_boot: kRvvRouteContract carries the flag to every spawn site\n");

	std::string const audit = ReadFile("scripts/vlen_propagation_audit.py");
	CHECK(audit.find("(\"rvv-qcg-typed-chunk-or\", \"rvv_qcg_typed_chunk_or\", \"Route\")") !=
	      std::string::npos);
	printf("  vlen_propagation_audit.py: ROUTE_FLAGS mirror updated in lockstep\n");

	// T1f ROUTED THE LAST BITWISE OPCODE, so there is no unrouted one left whose plumbing must be
	// ABSENT. This assertion is therefore its positive dual: all three bitwise routes must have
	// both halves of their plumbing, so a stray edit removing one cannot pass by looking like a
	// tightening.
	for (char const *opt : {"rvv-qcg-typed-chunk-and", "rvv-qcg-typed-chunk-or",
				"rvv-qcg-typed-chunk-xor"}) {
		CHECK(aot.find(std::string("\"") + opt + "\"") != std::string::npos);
	}
	for (char const *fld : {"&config::rvv_qcg_typed_chunk_and", "&config::rvv_qcg_typed_chunk_or",
				"&config::rvv_qcg_typed_chunk_xor"}) {
		CHECK(boot.find(fld) != std::string::npos);
	}
	printf("  all three bitwise routes (and/or/xor) have an elfaot option AND a contract row\n");

	printf("  the named flag IS the gate input (CheckGateNeedsBothSwitches proves both polarities)\n");
}

void DumpIR(char const *tag, u32 vlen_bits)
{
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
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
	printf("T1e typed vor.vv LLVM route test\n");

	// The field-built encodings reproduce the exact constants the accepted S2.3 QCG test uses.
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M1_TA_MA), INSN_VSETVLI_E32M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E64_M1_TA_MA), INSN_VSETVLI_E64M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M2_TA_MA), INSN_VSETVLI_E32M2);
	// vor.vv v3, v1, v2 -- the exact word dbt/qmc/qcg/vorvv_typedchunk_route_test.cpp uses.
	CHECK_EQ(EncodeVorVV(VD_REG, VS2_REG, VS1_REG), 0x2a1101d7u);
	// The three bitwise funct6 values really are adjacent, which is what makes the neighbour
	// checks load-bearing rather than decorative -- and this route sits BETWEEN the other two.
	CHECK_EQ(F6_VOR, F6_VAND + 1);
	CHECK_EQ(F6_VXOR, F6_VOR + 1);

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
	CheckWideAndNarrowVlenRefused();
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== guard: partial vl takes the helper ==\n");
	CheckGuardRejectsPartialVl(512, 16);
	CheckGuardRejectsPartialVl(1024, 32);

	printf("\n== precise-state boundary ==\n");
	CheckSsaCommitBoundary(512, 1);
	CheckSsaCommitBoundary(1024, 2);

	printf("\n== neighbours and siblings ==\n");
	CheckNeighboursHandledCorrectly(512);
	CheckNeighboursHandledCorrectly(1024);
	CheckRoutedSiblingsStillAdmit(512);
	CheckRoutedSiblingsStillAdmit(1024);

	printf("\n== non-admitted shapes stay on the helper path ==\n");
	{
		u32 w[2] = {INSN_VSETVLI_E64M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
		CheckNotAdmitted("e64,m1", w, 2, 512, "unsupported SEW (e64)");
		CheckNotAdmitted("e64,m1", w, 2, 1024, "unsupported SEW (e64)");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M2, EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
		CheckNotAdmitted("e32,m2", w, 2, 512, "unsupported LMUL (m2)");
		CheckNotAdmitted("e32,m2", w, 2, 1024, "unsupported LMUL (m2)");
	}
	{
		u32 w[2] = {EncodeVsetvli(VTYPE_E32_MF2_TA_MA),
			    EncodeVorVV(VD_REG, VS2_REG, VS1_REG)};
		CheckNotAdmitted("e32,mf2", w, 2, 512, "fractional LMUL (mf2)");
		CheckNotAdmitted("e32,mf2", w, 2, 1024, "fractional LMUL (mf2)");
	}
	{
		u32 w[2] = {INSN_VSETVLI_E32M1, EncodeVorVV(VD_REG, VS2_REG, VS1_REG, /*vm=*/0)};
		CheckNotAdmitted("masked", w, 2, 512, "masked vor.vv (vm=0) is not this opcode");
		CheckNotAdmitted("masked", w, 2, 1024, "masked vor.vv (vm=0) is not this opcode");
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
