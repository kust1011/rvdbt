// S3.6: focused test for the typed `vse32.v` V512 chunk frame as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG sibling.
// dbt/qmc/qcg/vse32v_typedchunk_route_test.cpp routes the same guest words through the same real
// translator, but every one of its checks stops at QIR, post-QRegAlloc operands or objdump-decoded
// AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see whether the
// LLVM/AOT tier admits the route at all, and before S3.6 it did not: `vchunkstore` Panic'd in
// llvmgen.cpp and RvvQcgTypedVseChunkAdmit returned 0 for every `aot_use_llvm` compile.
//
// This file drives the REAL LLVM path end to end and inspects the REAL generated llvm::Function:
//
//     encoded guest words
//       -> qir::CompilerGenRegionIR   (the real RV32Translator, dbt/qmc/compile.cpp)
//       -> qir::QIRToLLVM::Run()      (the real LLVM backend, dbt/qmc/llvmgen/llvmgen.cpp)
//       -> llvm::Function, walked instruction by instruction below
//
// Nothing here runs a guest, mmaps code, creates a TargetMachine, runs an optimisation pipeline or
// emits an object file, and NO guest memory is ever actually written -- the store is inspected as
// IR. Consequently NO claim about host instructions, ZMM registers, scheduling or speed is made.
//
// THE FOUR PROPERTIES THIS FILE OWNS, and the fourth is the one no earlier checkpoint could have
// checked because it needs TWO direct guest-memory accesses to exist at once:
//
//   1. SOURCE. Each chunk stored must be the value this frame's own `vstatechunkload` read out of
//      vs3's 64-byte CPUState window -- not vd's, not a neighbouring register's, not a re-read.
//      `vse32.v` encodes its SOURCE register in the V format's `rd` field, so "stored the wrong
//      register" is the single most available way to get this route wrong, and CheckAdmitted pins
//      the window offset against vs3 explicitly.
//
//   2. ADDRESS AND CHUNK OFFSET. The store's pointer must trace, through the ONE guest-memory
//      mapping this backend has, back to a 32-bit CPUState read at exactly
//      `offsetof(CPUState, gpr) + 4*rs1`, with chunk 1 at a HOST-pointer byte displacement of +64
//      applied AFTER the zero-extension. On the write side a wrap here would not read the wrong
//      bytes, it would WRITE 64 bytes to the bottom of the guest address space.
//
//   3. ALIAS AND ALIGNMENT. The guest store carries the `vmem` scope and alignment 1; the frame's
//      CPUState accesses carry the `state` scope and their own alignment. Compared as MDNode
//      identities taken out of the IR.
//
//   4. LOAD/STORE ORDERING. After S3.5 the same loop can hold a DIRECT `vle32.v` load and this
//      direct store, and they may genuinely alias -- the frozen mixed loop reads and writes the
//      same pointer in one strip step. CheckLoadStoreOrdering asserts the exact metadata relation
//      that makes reordering illegal: ScopedNoAliasAA returns NoAlias only when one access's
//      `noalias` set CONTAINS the other's `alias.scope`, so the test requires that neither
//      containment holds between the load and the store, while BOTH remain provably disjoint from
//      the frame's CPUState traffic. A lowering that gave the store a scope of its own would gain
//      illegal freedom and fail here.
//
// SCOPE, re-asserted in both directions: exact unmasked unit-stride `vse32.v`, EEW=32 from the
// encoding, SEW=32/LMUL=1/EMUL=1 from vtype, base register != x0, VLEN 512 or 1024, non-Ref
// `--rvv-lowering`, with BOTH `--rvv-qcg-typed-chunk-vse` and `--rvv-vector-ssa`. Everything else is
// proved by its absence: no guard frame, no 64-byte guest store, and the pre-existing helper.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
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
// Guest encodings, built from the instruction fields rather than pasted.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
// The full V-format unit-stride STORE-FP encoding. `vs3` occupies the rd field -- that is the RVV
// 1.0 layout and the one confusion this route must not make.
constexpr u32 EncodeVse(u32 vs3, u32 rs1, u32 width = 0b110u /*EEW 32*/, u32 vm = 1, u32 sumop = 0,
			u32 mop = 0, u32 mew = 0, u32 nf = 0)
{
	return (nf << 29) | (mew << 28) | (mop << 26) | (vm << 25) | (sumop << 20) | (rs1 << 15) |
	       (width << 12) | (vs3 << 7) | 0b0100111u;
}
constexpr u32 EncodeVle(u32 vd, u32 rs1)
{
	return (1u << 25) | (rs1 << 15) | (0b110u << 12) | (vd << 7) | 0b0000111u;
}

constexpr u32 VTYPE_E32_M1_TU_MA = Zimm11(2, 0, 0, 1);
constexpr u32 VTYPE_E64_M1 = Zimm11(3, 0, 1, 1);
constexpr u32 VTYPE_E32_M2 = Zimm11(2, 1, 1, 1);
constexpr u32 INSN_VSETVLI = EncodeVsetvli(VTYPE_E32_M1_TU_MA);
constexpr u32 INSN_VSETVLI_E64 = EncodeVsetvli(VTYPE_E64_M1);
constexpr u32 INSN_VSETVLI_E32_M2 = EncodeVsetvli(VTYPE_E32_M2);

constexpr u32 VS3_REG = 8, RS1_REG = 14; // v8, a4
constexpr u32 INSN_VSE32 = EncodeVse(VS3_REG, RS1_REG);

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VLENB = ST_VEC + (u32)offsetof(rv32::VectorState, vlenb);

constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}
constexpr u32 GprOffs(u32 r)
{
	return (u32)offsetof(CPUState, gpr) + 4u * r;
}

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_vle = false;
	config::rvv_qcg_typed_chunk_vle_force_emit = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_typed_chunk_vse_force_emit = false;
	config::rvv_qcg_direct_setvl = false;
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
	b.mod = std::make_unique<llvm::Module>("s3_6_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, b.region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm: aot_use_llvm on, plus BOTH switches RvvLLVMVseChunkAdmit requires.
Built BuildLLVMRoute(u32 const *words, unsigned n, u32 vlen_bits, bool ssa = true, bool vse_sw = true,
		     bool vle_sw = false)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_qcg_typed_chunk_vse = vse_sw;
	config::rvv_qcg_typed_chunk_vle = vle_sw;
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

bool IsV8I64(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 8 && vt->getElementType()->isIntegerTy(64);
}

bool IsV32I32(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 32 && vt->getElementType()->isIntegerTy(32);
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

// THE ADDRESS CHAIN, reconstructed from the IR rather than assumed. Identical to the load's, on
// purpose: the two halves of one guest instruction pair must compute a guest address the same way.
struct GuestAddr {
	u64 state_offs = 0;
	u64 disp = 0;
	llvm::LoadInst *base_load = nullptr;
};

bool DecodeGuestAddr(llvm::Value *p, llvm::Value *statev, llvm::Value *membasev, GuestAddr *out)
{
	*out = GuestAddr{};
	p = StripCasts(p);
	if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	    gep && gep->getPointerOperand() != membasev && gep->getNumIndices() == 1 &&
	    gep->getSourceElementType()->isIntegerTy(8)) {
		auto *k = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
		if (!k) {
			return false;
		}
		out->disp = k->getZExtValue();
		p = StripCasts(gep->getPointerOperand());
	}
	llvm::Value *addr = nullptr;
	if (auto *i2p = llvm::dyn_cast<llvm::IntToPtrInst>(p)) {
		addr = i2p->getOperand(0);
	} else if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
		   gep && gep->getPointerOperand() == membasev && gep->getNumIndices() == 1 &&
		   gep->getSourceElementType()->isIntegerTy(8)) {
		addr = gep->getOperand(1);
	} else {
		return false;
	}
	auto *ze = llvm::dyn_cast<llvm::ZExtInst>(addr);
	if (!ze || !ze->getSrcTy()->isIntegerTy(32)) {
		return false;
	}
	// The zext's operand must BE the CPUState load. An `add i32 %base, 64` here would wrap.
	auto *ld = llvm::dyn_cast<llvm::LoadInst>(ze->getOperand(0));
	if (!ld || !ld->getType()->isIntegerTy(32)) {
		return false;
	}
	if (!StateOffsetOf(ld->getPointerOperand(), statev, &out->state_offs)) {
		return false;
	}
	out->base_load = ld;
	return true;
}

struct GuestStore {
	llvm::StoreInst *ins = nullptr;
	GuestAddr addr;
};
struct StateLoad {
	llvm::LoadInst *ins = nullptr;
	u64 offs = 0;
};

// Every 64-byte CPUState read and every 64-byte GUEST-memory write in `bb`, in program order.
void CollectFrameMemOps(llvm::BasicBlock *bb, llvm::Value *statev, llvm::Value *membasev,
			std::vector<StateLoad> *sloads, std::vector<GuestStore> *gstores,
			unsigned *n_unclassified)
{
	for (auto &ins : *bb) {
		if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
			if (!IsV8I64(ld->getType())) {
				continue;
			}
			u64 soff = 0;
			GuestAddr a;
			if (StateOffsetOf(ld->getPointerOperand(), statev, &soff)) {
				sloads->push_back({ld, soff});
			} else if (DecodeGuestAddr(ld->getPointerOperand(), statev, membasev, &a)) {
				++*n_unclassified; // a guest-memory READ is not part of a store frame
			} else {
				++*n_unclassified;
			}
		} else if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
			if (!IsV8I64(st->getValueOperand()->getType())) {
				continue;
			}
			u64 soff = 0;
			GuestAddr a;
			if (DecodeGuestAddr(st->getPointerOperand(), statev, membasev, &a)) {
				gstores->push_back({st, a});
			} else if (StateOffsetOf(st->getPointerOperand(), statev, &soff)) {
				++*n_unclassified; // a CPUState 64-byte WRITE is out of scope here
			} else {
				++*n_unclassified;
			}
		}
	}
}

unsigned CountGuestChunkStores(llvm::Function *fn, llvm::Value *statev, llvm::Value *membasev)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			GuestAddr a;
			n += st && IsV8I64(st->getValueOperand()->getType()) &&
			     DecodeGuestAddr(st->getPointerOperand(), statev, membasev, &a);
		}
	}
	return n;
}

unsigned CountGuestChunkLoads(llvm::Function *fn, llvm::Value *statev, llvm::Value *membasev)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins);
			GuestAddr a;
			n += ld && IsV8I64(ld->getType()) &&
			     DecodeGuestAddr(ld->getPointerOperand(), statev, membasev, &a);
		}
	}
	return n;
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

std::string HelperStubName(llvm::CallInst *call)
{
	auto *ld = llvm::dyn_cast<llvm::LoadInst>(call->getCalledOperand());
	return ld ? ld->getName().str() : std::string();
}

unsigned CountTypedQirOps(Region *region)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
			case Op::_vchunkload:
			case Op::_vchunkstore:
			case Op::_vstatechunkload:
			case Op::_vstatechunkstore:
			case Op::_rvvtypedchunkend:
				++n;
				break;
			default:
				break;
			}
		}
	}
	return n;
}

unsigned CountQirOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += ins.GetOpcode() == op;
		}
	}
	return n;
}

// The set of scope MDNodes an `!alias.scope` or `!noalias` operand list names.
std::set<llvm::MDNode *> ScopeSet(llvm::Instruction *ins, unsigned kind)
{
	std::set<llvm::MDNode *> out;
	auto *md = ins->getMetadata(kind);
	if (!md) {
		return out;
	}
	for (auto const &op : md->operands()) {
		if (auto *n = llvm::dyn_cast<llvm::MDNode>(op.get())) {
			out.insert(n);
		}
	}
	return out;
}

// ScopedNoAliasAA returns NoAlias for (A, B) only when B's `noalias` set contains every scope in
// A's `alias.scope` set. This is that predicate, spelled out so the ordering check below can state
// exactly which containment must NOT hold.
bool ProvablyNoAlias(llvm::Instruction *a, llvm::Instruction *b)
{
	auto a_scope = ScopeSet(a, llvm::LLVMContext::MD_alias_scope);
	auto b_noalias = ScopeSet(b, llvm::LLVMContext::MD_noalias);
	if (a_scope.empty()) {
		return false;
	}
	return std::includes(b_noalias.begin(), b_noalias.end(), a_scope.begin(), a_scope.end());
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

void CheckAdmitted(char const *tag, u32 vlen_bits, unsigned nchunks, u32 vlmax, u32 vs3, u32 rs1,
		   bool with_vsetvli = true, u32 expect_vtype = VTYPE_E32_M1_TU_MA)
{
	printf("%s: vlen=%u nchunks=%u vlmax=%u vtype=0x%03x vse32.v v%u, (x%u)%s\n", tag, vlen_bits,
	       nchunks, vlmax, expect_vtype, vs3, rs1, with_vsetvli ? "" : " (no in-block vsetvli)");
	u32 const insn = EncodeVse(vs3, rs1);
	u32 words[2] = {INSN_VSETVLI, insn};
	unsigned const n = with_vsetvli ? 2 : 1;
	Built b = BuildLLVMRoute(with_vsetvli ? words : words + 1, n, vlen_bits);
	auto *statev = b.fn->getArg(0);
	auto *membasev = b.fn->getArg(1);

	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	// The QIR really is the S2.7 frame: one begin, `nchunks` CPUState reads, `nchunks` guest
	// writes, one end -- and NO vchunkload, which would be the load route.
	CHECK_EQ(CountQirOp(b.region, Op::_rvvtypedchunkbegin), 1u);
	CHECK_EQ(CountQirOp(b.region, Op::_vstatechunkload), (unsigned)nchunks);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), (unsigned)nchunks);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkload), 0u);
	CHECK_EQ(CountQirOp(b.region, Op::_vstatechunkstore), 0u);

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

	// ---- guard CFG --------------------------------------------------------------------------
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

	// ---- guard CONTENT ----------------------------------------------------------------------
	// On a STORE the `vl == VLMAX` comparison is the only thing standing between a partial-vl
	// guest write and a 64-byte block write over data the guest still owns.
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

	// ---- fast arm ---------------------------------------------------------------------------
	CHECK_EQ(CountCalls(fast), 0u);

	std::vector<StateLoad> sloads;
	std::vector<GuestStore> gstores;
	unsigned n_unclassified = 0;
	CollectFrameMemOps(fast, statev, membasev, &sloads, &gstores, &n_unclassified);
	CHECK_EQ(n_unclassified, 0u);
	CHECK_EQ(sloads.size(), (size_t)nchunks);
	CHECK_EQ(gstores.size(), (size_t)nchunks);
	CHECK_EQ(CountGuestChunkStores(b.fn, statev, membasev), (unsigned)nchunks);
	CHECK_EQ(CountGuestChunkLoads(b.fn, statev, membasev), 0u); // no load route in this fixture
	if (sloads.size() != nchunks || gstores.size() != nchunks) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}

	// ---- PROPERTY 1: SOURCE ------------------------------------------------------------------
	// Each chunk is read from vs3's own 64-byte window, and each store writes exactly that value.
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(sloads[c].offs, (u64)ChunkOffs(vs3, c));
		CHECK(StripCasts(gstores[c].ins->getValueOperand()) == sloads[c].ins);
	}

	// ---- PROPERTY 2: ADDRESS AND CHUNK OFFSET -------------------------------------------------
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(gstores[c].addr.state_offs, (u64)GprOffs(rs1));
		CHECK_EQ(gstores[c].addr.disp, (u64)(64u * c));
	}

	// All CPUState reads precede all guest writes: the whole source register is captured before
	// the first guest byte is written.
	CHECK(sloads.back().ins->comesBefore(gstores.front().ins));

	// ---- PROPERTY 3: ALIAS AND ALIGNMENT ------------------------------------------------------
	{
		auto *state_scope = sloads[0].ins->getMetadata(llvm::LLVMContext::MD_alias_scope);
		CHECK(state_scope != nullptr);
		for (unsigned c = 0; c < nchunks; ++c) {
			auto *st = gstores[c].ins;
			CHECK_EQ(st->getAlign().value(), (u64)1);
			auto *vmem_scope = st->getMetadata(llvm::LLVMContext::MD_alias_scope);
			CHECK(vmem_scope != nullptr);
			CHECK(vmem_scope != state_scope);
			CHECK(st->getMetadata(llvm::LLVMContext::MD_noalias) != nullptr);
			// The frame's CPUState traffic and its guest write are PROVABLY disjoint --
			// that direction must hold, and it is what lets LLVM keep the vreg reads out
			// of the store's way.
			CHECK(ProvablyNoAlias(sloads[c].ins, st));
			CHECK(ProvablyNoAlias(st, sloads[c].ins));
			auto *bl = gstores[c].addr.base_load;
			CHECK(bl->getMetadata(llvm::LLVMContext::MD_alias_scope) == state_scope);
			CHECK_EQ(bl->getAlign().value(), (u64)4);
			CHECK_EQ(sloads[c].ins->getAlign().value(), (u64)16);
		}
	}

	// ---- no alloca, no wide vector -------------------------------------------------------------
	CHECK_EQ(std::count_if(fast->begin(), fast->end(),
			       [](llvm::Instruction const &i) { return llvm::isa<llvm::AllocaInst>(&i); }),
		 (long)0);
	CHECK_EQ([&] {
		unsigned n = 0;
		for (auto &bb : *b.fn) {
			for (auto &ins : bb) {
				n += IsV32I32(ins.getType());
			}
		}
		return n;
	}(), 0u);

	// ---- chunk independence ---------------------------------------------------------------------
	if (nchunks == 2) {
		CHECK(sloads[0].ins != sloads[1].ins);
		CHECK(gstores[0].ins != gstores[1].ins);
		CHECK_EQ(sloads[1].offs - sloads[0].offs, (u64)64);
		CHECK_EQ(gstores[1].addr.disp - gstores[0].addr.disp, (u64)64);
		// Neither store's address or data depends on the other store.
		CHECK(gstores[1].addr.base_load != (llvm::LoadInst *)sloads[0].ins);
		CHECK(StripCasts(gstores[0].ins->getValueOperand()) !=
		      StripCasts(gstores[1].ins->getValueOperand()));
	}

	// ---- fallback arm ------------------------------------------------------------------------
	CHECK_EQ(CountCalls(slow), 1u);
	{
		std::vector<StateLoad> sl;
		std::vector<GuestStore> gs;
		unsigned nu = 0;
		CollectFrameMemOps(slow, statev, membasev, &sl, &gs, &nu);
		CHECK_EQ(sl.size(), (size_t)0);
		CHECK_EQ(gs.size(), (size_t)0);
		llvm::CallInst *call = nullptr;
		unsigned n_helper = 0;
		for (auto &ins : *slow) {
			n_helper += IsHelperCallWithRaw(&ins, statev, insn);
			if (auto *c = llvm::dyn_cast<llvm::CallInst>(&ins)) {
				call = c;
			}
		}
		CHECK_EQ(n_helper, 1u);
		CHECK(call != nullptr);
		if (call) {
			CHECK(HelperStubName(call).starts_with(
			    GetRuntimeStubName(RuntimeStubId::id_rv32_vse)));
		}
	}

	printf("  OK: fast=%zu guest 64B store(s) at [gpr[x%u] + %s] from vreg[v%u], 0 calls; "
	       "fallback=1 rv32_vse call\n",
	       gstores.size(), rs1, nchunks == 2 ? "{0,64}" : "{0}", vs3);
}

// ---------------------------------------------------------------------------------------------
// PROPERTY 4: LOAD/STORE ORDERING, with BOTH memory routes on.
//
// This is the case that did not exist before S3.6: a direct `vle32.v` load and a direct `vse32.v`
// store in one region, over pointers that may be the same. The check is the exact ScopedNoAliasAA
// predicate -- NoAlias is returned only when one access's `noalias` set contains the other's
// `alias.scope` -- asserted in BOTH directions to be false for the load/store pair, and true for
// each of them against the frame's CPUState traffic.
// ---------------------------------------------------------------------------------------------

void CheckLoadStoreOrdering(u32 vlen_bits, unsigned nchunks, u32 base_load_reg, u32 base_store_reg)
{
	printf("load/store ordering: vlen=%u  vle32.v v8,(x%u) ; vse32.v v8,(x%u)\n", vlen_bits,
	       base_load_reg, base_store_reg);
	u32 const insn_vle = EncodeVle(VS3_REG, base_load_reg);
	u32 const insn_vse = EncodeVse(VS3_REG, base_store_reg);
	u32 words[3] = {INSN_VSETVLI, insn_vle, insn_vse};
	Built b = BuildLLVMRoute(words, 3, vlen_bits, /*ssa=*/true, /*vse_sw=*/true, /*vle_sw=*/true);
	auto *statev = b.fn->getArg(0);
	auto *membasev = b.fn->getArg(1);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	// Both routes really are direct -- otherwise this case is not testing what it claims.
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkload), (unsigned)nchunks);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), (unsigned)nchunks);
	CHECK_EQ(CountGuestChunkLoads(b.fn, statev, membasev), (unsigned)nchunks);
	CHECK_EQ(CountGuestChunkStores(b.fn, statev, membasev), (unsigned)nchunks);

	std::vector<llvm::LoadInst *> gloads;
	std::vector<llvm::StoreInst *> gstores;
	std::vector<llvm::Instruction *> state_ops;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			GuestAddr a;
			u64 soff = 0;
			if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				if (IsV8I64(ld->getType()) &&
				    DecodeGuestAddr(ld->getPointerOperand(), statev, membasev, &a)) {
					gloads.push_back(ld);
				} else if (IsV8I64(ld->getType()) &&
					   StateOffsetOf(ld->getPointerOperand(), statev, &soff)) {
					state_ops.push_back(ld);
				}
			} else if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				if (IsV8I64(st->getValueOperand()->getType()) &&
				    DecodeGuestAddr(st->getPointerOperand(), statev, membasev, &a)) {
					gstores.push_back(st);
				} else if (IsV8I64(st->getValueOperand()->getType()) &&
					   StateOffsetOf(st->getPointerOperand(), statev, &soff)) {
					state_ops.push_back(st);
				}
			}
		}
	}
	CHECK_EQ(gloads.size(), (size_t)nchunks);
	CHECK_EQ(gstores.size(), (size_t)nchunks);
	CHECK(!state_ops.empty());
	if (gloads.size() != nchunks || gstores.size() != nchunks) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}

	// THE ORDERING PROPERTY. Neither direction may be provably-noalias: the guest load and the
	// guest store share one scope, so ScopedNoAliasAA cannot separate them and LLVM must keep
	// their order. A store given its own scope would make one of these true and would be free to
	// move above the load.
	for (auto *ld : gloads) {
		for (auto *st : gstores) {
			CHECK(!ProvablyNoAlias(ld, st));
			CHECK(!ProvablyNoAlias(st, ld));
			// Same scope set, concretely.
			CHECK(ScopeSet(ld, llvm::LLVMContext::MD_alias_scope) ==
			      ScopeSet(st, llvm::LLVMContext::MD_alias_scope));
		}
	}
	// ... while both remain provably disjoint from the frames' CPUState traffic, in both
	// directions. That is what this checkpoint must NOT lose in exchange.
	for (auto *op : state_ops) {
		for (auto *ld : gloads) {
			CHECK(ProvablyNoAlias(op, ld));
			CHECK(ProvablyNoAlias(ld, op));
		}
		for (auto *st : gstores) {
			CHECK(ProvablyNoAlias(op, st));
			CHECK(ProvablyNoAlias(st, op));
		}
	}
	// Program order in the emitted IR: every guest load precedes every guest store.
	for (auto *ld : gloads) {
		for (auto *st : gstores) {
			CHECK(ld->getParent() != st->getParent() ? true
								 : ld->comesBefore(st));
		}
	}
	printf("  %zu guest load(s) and %zu guest store(s) share one alias scope (may-alias, so not "
	       "reorderable); both provably disjoint from %zu CPUState vector access(es)\n",
	       gloads.size(), gstores.size(), state_ops.size());
}

// ---------------------------------------------------------------------------------------------
// Non-admission.
// ---------------------------------------------------------------------------------------------

void CheckNotAdmitted(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, char const *why,
		      bool ssa = true, bool vse_sw = true, void (*extra)() = nullptr)
{
	printf("%s: %s\n", tag, why);
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_qcg_typed_chunk_vse = vse_sw;
	if (extra) {
		extra();
	}
	Built b = BuildLLVM(words, n, vlen_bits);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(CountTypedQirOps(b.region), 0u);
	CHECK_EQ(CountGuestChunkStores(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	unsigned n_calls = 0;
	for (auto &bb : *b.fn) {
		n_calls += CountCalls(&bb);
	}
	CHECK(n_calls >= n);
	printf("  no guard frame, 0 typed QIR ops, 0 guest 64B stores, %u call(s)\n", n_calls);
}

void CheckKeepsVseHelper(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, u32 insn,
			 char const *why, bool ssa = true, bool vse_sw = true)
{
	printf("%s: %s\n", tag, why);
	Built b = BuildLLVMRoute(words, n, vlen_bits, ssa, vse_sw);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(CountTypedQirOps(b.region), 0u);
	CHECK_EQ(CountGuestChunkStores(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	unsigned n_vse = 0;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			if (!IsHelperCallWithRaw(&ins, b.fn->getArg(0), insn)) {
				continue;
			}
			n_vse += HelperStubName(llvm::cast<llvm::CallInst>(&ins))
				     .starts_with(GetRuntimeStubName(RuntimeStubId::id_rv32_vse));
		}
	}
	CHECK_EQ(n_vse, 1u);
	printf("  exactly one rv32_vse helper call for 0x%08x, no typed frame\n", insn);
}

// Neither switch alone opens the LLVM route, the LOAD switch does not open it either, and the QCG
// route is unchanged. The middle one is the over-admission gate this checkpoint most needs: the two
// memory routes are on separate flags precisely so a wrong guest-memory byte stays attributable.
void CheckSwitchSeparation(u32 vlen_bits)
{
	printf("switch separation: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI, INSN_VSE32};

	// (a) --rvv-vector-ssa alone: NOT admitted.
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, true, /*vse_sw=*/false);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), 0u);
	}
	// (b) --rvv-qcg-typed-chunk-vse alone (no vector SSA): NOT admitted.
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/false, true);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), 0u);
	}
	// (c) the LOAD switch does not open the STORE route.
	{
		ResetConfig();
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		config::rvv_qcg_typed_chunk_vle = true;
		config::rvv_qcg_typed_chunk_vse = false;
		Built b = BuildLLVM(words, 2, vlen_bits);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), 0u);
		CHECK_EQ(CountGuestChunkStores(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	}
	// (d) the pure-QCG route is unchanged.
	{
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = true;
		config::rvv_qcg_typed_chunk_vse = true;
		config::rvv_qcg_typed_chunk_vse_force_emit = true;
		config::vlen_bits = vlen_bits;
		MemArena arena(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkstore), (unsigned)(vlen_bits / 512));
	}
	printf("  neither switch alone admits; the load switch does not open the store route; the "
	       "accepted S2.7 QCG route is unchanged\n");
}

void CheckLlvmRouteNeedsNoForceEmit()
{
	printf("host-feature independence:\n");
#if defined(__x86_64__) || defined(__i386__)
	bool const host_avx512 = __builtin_cpu_supports("avx512f");
#else
	bool const host_avx512 = false;
#endif
	u32 words[2] = {INSN_VSETVLI, INSN_VSE32};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_vse = true;
	config::rvv_qcg_typed_chunk_vse_force_emit = false;
	Built b = BuildLLVM(words, 2, 512);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	CHECK_EQ(CountGuestChunkStores(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 1u);
	printf("  admitted with force_emit=0 on a host with avx512f=%d\n", (int)host_avx512);
}

// ---------------------------------------------------------------------------------------------
// THE CHUNK-CACHE BOUNDARY, at QIR level, because that is the only level where it is visible.
//
// This frame READS vs3's CPUState window. Under `--rvv-vector-ssa` the translator may still be
// holding vs3's architectural value as an uncommitted QIR chunk value (RvvReadGroup/RvvDefineGroup's
// rvv_chunk_* cache), and `PreSideeff` deliberately does not flush it for a vector opcode. If
// RvvEmitTypedVseChunkGroup did not commit first, the writeback would land AFTER the frame (at the
// block exit, MakeGBr) and BOTH arms would write stale bytes to guest memory -- the typed body
// through `vstatechunkload` and the guard-miss helper through the same window. It is therefore not
// something a runtime guard could catch, which is why it is asserted structurally here.
//
// The smallest guest sequence that reaches it, and the same shape the vadd LLVM test uses for its
// own boundary probe:
//
//     vsetvli a0, a0, e32, m1, tu, ma      (helper; TranslateHelper commits and resets)
//     vl1re32.v v8, (a5)                   (typed rvvload; RvvDefineGroup marks v8 dirty --
//                                           vlNre is vtype-independent, so e32 survives it)
//     vse32.v  v8, (a4)                    (admitted -> this frame, which must commit v8 first)
//
// The assertion is an ORDER relation on the constructed QIR: exactly `nchunks` `rvvwrite` commits
// must appear strictly BETWEEN the `rvvload` and the `rvvtypedchunkbegin`. Deleting the two
// statements moves them past the frame and fails this.
void CheckStoreCommitBoundary(u32 vlen_bits, unsigned nchunks)
{
	// vl1re32.v v8, (a5): opcode 0x07, nf=0, mew=0, mop=00, vm=1, lumop=0b01000, rs1=15,
	// width=0b110, vd=8.
	constexpr u32 INSN_VL1RE32 = (1u << 25) | (0b01000u << 20) | (15u << 15) | (0b110u << 12) |
				     (VS3_REG << 7) | 0x07u;
	u32 words[3] = {INSN_VSETVLI, INSN_VL1RE32, INSN_VSE32};
	Built b = BuildLLVMRoute(words, 3, vlen_bits);
	printf("chunk-cache boundary: vlen=%u  vsetvli ; vl1re32.v v%u,(a5) ; vse32.v v%u,(a4)\n",
	       vlen_bits, VS3_REG, VS3_REG);

	std::vector<Op> ops;
	for (auto &bb : b.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			ops.push_back(ins.GetOpcode());
		}
	}
	// The case must really be the one it claims to be: a dirty-defining load, then this frame.
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvload), (long)1);
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_rvvtypedchunkbegin), (long)1);
	CHECK_EQ(std::count(ops.begin(), ops.end(), Op::_vchunkstore), (long)nchunks);
	auto ld = std::find(ops.begin(), ops.end(), Op::_rvvload);
	auto bg = std::find(ops.begin(), ops.end(), Op::_rvvtypedchunkbegin);
	CHECK(ld < bg);
	if (ld >= bg) {
		for (size_t k = 0; k < ops.size(); ++k) {
			printf("  %2zu  %s\n", k, GetOpNameStr(ops[k]));
		}
		return;
	}
	// One commit per dirty chunk, strictly between the load and the frame.
	long const n_commit = std::count(ld, bg, Op::_rvvwrite);
	CHECK_EQ(n_commit, (long)nchunks);
	// ... and none left over after the frame, which is where they would land without the boundary.
	CHECK_EQ(std::count(bg, ops.end(), Op::_rvvwrite), (long)0);
	printf("  OK: %ld rvvwrite commit(s) between rvvload and rvvtypedchunkbegin, 0 after it\n",
	       n_commit);
}

void DumpIR(char const *tag, u32 vlen_bits, bool vse_sw, bool vle_sw)
{
	u32 words[3] = {INSN_VSETVLI, EncodeVle(VS3_REG, RS1_REG), INSN_VSE32};
	Built b = BuildLLVMRoute(words, 3, vlen_bits, true, vse_sw, vle_sw);
	printf("\n----- IR DUMP %s (vlen=%u, vse-route=%d, vle-route=%d) -----\n%s", tag, vlen_bits,
	       (int)vse_sw, (int)vle_sw, PrintFn(b.fn).c_str());
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i) {
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	}
	printf("S3.6 typed vse32.v LLVM route test\n");

	// vse32.v v8, (a4): vm=1<<25, rs1=14<<15, width=0b110<<12, vs3=8<<7, opcode STORE-FP.
	CHECK_EQ(INSN_VSE32, 0x02076427u);
	CHECK_EQ(INSN_VSETVLI, 0x09057557u);

	printf("\n== admitted: VLEN=512, one chunk ==\n");
	CheckAdmitted("v512", 512, 1, 16, VS3_REG, RS1_REG);
	printf("\n== admitted: VLEN=1024, two independent chunks ==\n");
	CheckAdmitted("v1024", 1024, 2, 32, VS3_REG, RS1_REG);

	printf("\n== admitted: unknown-vtype candidate (no in-block vsetvli) ==\n");
	CheckAdmitted("v512 unknown-vtype", 512, 1, 16, VS3_REG, RS1_REG, false,
		      rv32::VTYPE_E32_M1_TA_MA);
	CheckAdmitted("v1024 unknown-vtype", 1024, 2, 32, VS3_REG, RS1_REG, false,
		      rv32::VTYPE_E32_M1_TA_MA);

	printf("\n== admitted: source-register and base-register edge cases ==\n");
	CheckAdmitted("v512 vs3=v0", 512, 1, 16, 0, RS1_REG);
	CheckAdmitted("v512 vs3=v31", 512, 1, 16, 31, RS1_REG);
	CheckAdmitted("v1024 vs3=v0", 1024, 2, 32, 0, RS1_REG);
	CheckAdmitted("v1024 vs3=v31", 1024, 2, 32, 31, RS1_REG);
	CheckAdmitted("v512 rs1=x1", 512, 1, 16, VS3_REG, 1);
	CheckAdmitted("v512 rs1=x31", 512, 1, 16, VS3_REG, 31);
	CheckAdmitted("v1024 rs1=x1", 1024, 2, 32, VS3_REG, 1);
	CheckAdmitted("v1024 rs1=x31", 1024, 2, 32, VS3_REG, 31);
	CheckAdmitted("v1024 vs3=v31 rs1=x31", 1024, 2, 32, 31, 31);

	printf("\n== ordering: a direct vle32.v and a direct vse32.v in one region ==\n");
	// Distinct base registers, and then the ALIASING case the frozen mixed loop actually has:
	// the same guest pointer read and written in one strip step.
	CheckLoadStoreOrdering(512, 1, /*load base=*/15, /*store base=*/14);
	CheckLoadStoreOrdering(1024, 2, /*load base=*/15, /*store base=*/14);
	CheckLoadStoreOrdering(512, 1, /*load base=*/14, /*store base=*/14);
	CheckLoadStoreOrdering(1024, 2, /*load base=*/14, /*store base=*/14);

	printf("\n== the source register's chunk-cache boundary ==\n");
	CheckStoreCommitBoundary(512, 1);
	CheckStoreCommitBoundary(1024, 2);

	printf("\n== off-state and switch separation ==\n");
	CheckSwitchSeparation(512);
	CheckSwitchSeparation(1024);
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== non-admitted: the route's own switches ==\n");
	{
		u32 w[2] = {INSN_VSETVLI, INSN_VSE32};
		for (u32 v : {512u, 1024u}) {
			CheckKeepsVseHelper("route-off", w, 2, v, INSN_VSE32,
					    "--rvv-qcg-typed-chunk-vse=0", true, false);
			CheckKeepsVseHelper("ssa-off", w, 2, v, INSN_VSE32, "--rvv-vector-ssa=0", false,
					    true);
		}
	}

	printf("\n== non-admitted: encodings that must never become a 64-byte block write ==\n");
	for (u32 v : {512u, 1024u}) {
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVse(VS3_REG, RS1_REG, 0b110u, /*vm=*/0)};
			CheckKeepsVseHelper("masked", w, 2, v, w[1],
					    "a masked vse32.v must leave inactive elements untouched");
		}
		for (auto [width, name] : {std::pair<u32, char const *>{0b000u, "vse8.v"},
					   {0b101u, "vse16.v"},
					   {0b111u, "vse64.v"}}) {
			u32 w[2] = {INSN_VSETVLI, EncodeVse(VS3_REG, RS1_REG, width)};
			CheckKeepsVseHelper(name, w, 2, v, w[1],
					    "a narrower/wider EEW writes a different byte count");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVse(VS3_REG, RS1_REG, 0b110u, 1, 0, /*mop=*/2)};
			CheckNotAdmitted("vsse32.v", w, 2, v, "strided (mop=10) is not unit-stride");
		}
		{
			u32 w[2] = {INSN_VSETVLI,
				    EncodeVse(VS3_REG, RS1_REG, 0b110u, 1, /*sumop=*/0b01000u)};
			CheckNotAdmitted("vs1r.v", w, 2, v, "whole-register store ignores vl/vtype");
		}
		{
			u32 w[2] = {INSN_VSETVLI,
				    EncodeVse(VS3_REG, RS1_REG, 0b000u, 1, /*sumop=*/0b01011u)};
			CheckNotAdmitted("vsm.v", w, 2, v, "mask store writes ceil(vl/8) bytes");
		}
		{
			u32 w[2] = {INSN_VSETVLI,
				    EncodeVse(VS3_REG, RS1_REG, 0b110u, 1, 0, 0, 0, /*nf=*/1)};
			CheckNotAdmitted("vsseg2e32.v", w, 2, v, "segment store reads a register group");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVse(VS3_REG, RS1_REG, 0b110u, 1, 0, 0, /*mew=*/1)};
			CheckNotAdmitted("mew=1", w, 2, v, "mew is reserved and must fail closed");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVse(VS3_REG, /*rs1=*/0)};
			CheckKeepsVseHelper("base-x0", w, 2, v, w[1],
					    "x0 is not a tracked global, so its CPUState slot is not live");
		}
	}

	printf("\n== non-admitted: vtype, VLEN and lowering-mode shapes ==\n");
	for (u32 v : {512u, 1024u}) {
		{
			u32 w[2] = {INSN_VSETVLI_E64, INSN_VSE32};
			CheckKeepsVseHelper("e64,m1", w, 2, v, INSN_VSE32,
					    "SEW=64 with EEW=32 is EMUL=1/2, not 1");
		}
		{
			u32 w[2] = {INSN_VSETVLI_E32_M2, INSN_VSE32};
			CheckKeepsVseHelper("e32,m2", w, 2, v, INSN_VSE32, "LMUL>1 is a register group");
		}
	}
	{
		u32 w[2] = {INSN_VSETVLI, INSN_VSE32};
		// W5 (2026-09-17): 128 and 256 were here as "VLEN outside the admitted {512,1024}", and
		// that set was RvvSSAEnabled()'s, not this route's. The LLVM arm's width now comes from
		// RvvRouteChunkShape -> RvvHostChunkGeometryForSew, so a register that tiles into whole
		// host chunks is admitted at 128/256 too. The row is kept, at the width the GEOMETRY still
		// refuses: VLEN 384 is 48 bytes per register, which is not one of the three host vector
		// widths, so it has no chunk shape at all. Positive five-width coverage -- the chunk count,
		// the chunk type and the fallback at each width -- is asserted in
		// rvv_llvm_five_width_geometry_test rather than restated in every per-opcode file.
		CheckKeepsVseHelper("vlen384", w, 2, 384, INSN_VSE32, "VLEN 384 has no host chunk shape");
		CheckNotAdmitted("rvv-lowering=Ref", w, 2, 512,
				 "the scalar reference arm wraps element addresses modulo 2^32", true,
				 true, [] { config::rvv_lowering = 0; });
		CheckNotAdmitted("rvv-lowering=Ref", w, 2, 1024,
				 "the scalar reference arm wraps element addresses modulo 2^32", true,
				 true, [] { config::rvv_lowering = 0; });
		CheckNotAdmitted("rvv-verify", w, 2, 512,
				 "--rvv-verify's destination-range diagnostic cannot see emitted code",
				 true, true, [] { config::rvv_verify = true; });
		CheckNotAdmitted("rvv-verify", w, 2, 1024,
				 "--rvv-verify's destination-range diagnostic cannot see emitted code",
				 true, true, [] { config::rvv_verify = true; });
		CheckNotAdmitted("rvv-direct=0", w, 2, 512, "the QCG lowering master switch is off", true,
				 true, [] { config::rvv_direct = false; });
		CheckNotAdmitted("rvv-direct=0", w, 2, 1024, "the QCG lowering master switch is off", true,
				 true, [] { config::rvv_direct = false; });
	}

	if (dump_ir) {
		DumpIR("both-routes-on", 512, true, true);
		DumpIR("both-routes-on", 1024, true, true);
		DumpIR("store-route-off", 512, false, true);
		DumpIR("store-route-off", 1024, false, true);
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
