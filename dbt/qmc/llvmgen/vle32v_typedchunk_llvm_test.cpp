// S3.5: focused test for the typed `vle32.v` V512 chunk frame as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG sibling.
// dbt/qmc/qcg/vle32v_typedchunk_route_test.cpp routes the same guest words through the same real
// translator, but every one of its checks stops at QIR, post-QRegAlloc operands or objdump-decoded
// AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see whether the
// LLVM/AOT tier admits the route at all, and before S3.5 it did not: `vchunkload` Panic'd in
// llvmgen.cpp and RvvQcgTypedVleChunkAdmit returned 0 for every `aot_use_llvm` compile, so an AOT
// artifact for the frozen workload reached an opaque `rv32_vle` helper call for every guest load.
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
// emits an object file. The IR inspected is the IR QIRToLLVM produces, before any LLVM pass.
// Consequently NO claim about host instructions, ZMM registers, scheduling or speed is made or
// implied by any check in this file.
//
// THE THREE PROPERTIES THAT ARE NEW HERE, none of which the vadd LLVM test could have checked,
// because the vadd frame never leaves CPUState:
//
//   1. ADDRESS SOURCE. The 64-byte load's pointer must trace, through the ONE guest-memory mapping
//      this backend has (LLVMGen::MakeVMemLoc), back to a 32-bit CPUState read at exactly
//      `offsetof(CPUState, gpr) + 4*rs1`. `CheckAdmitted` reconstructs that whole chain from the IR
//      and compares the offset against rs1, so reading a neighbouring slot, reading vd's slot, or
//      taking the address from anywhere else is a failure rather than a different-looking success.
//
//   2. CHUNK BYTE OFFSET, AND THE ARITHMETIC IT IS DONE IN. Chunk 1 of a VLEN=1024 register must be
//      a HOST-pointer byte displacement of +64 applied AFTER the zero-extension -- never an i32 add
//      on the guest base, which would wrap modulo 2^32 and disagree with rvv_chunked::copy_chunked
//      on the top 64 guest addresses (qir.h, S2.5 section 4.3). The check is structural: the zext's
//      operand must BE the CPUState load, so any i32 arithmetic folded in between fails.
//
//   3. ALIAS AND MEMORY SEMANTICS. The guest-memory load must carry the `vmem` alias scope and
//      alignment 1; the CPUState accesses of the same frame (the base read and the destination
//      write) must carry the `state` scope and their own alignment. The scopes are compared as
//      MDNode identities taken out of the IR, so a lowering that put the guest load in the state
//      scope -- or claimed 64-byte alignment on an address the guest never promised to align --
//      fails here.
//
// SCOPE OF THE ADMITTED ROUTE, re-asserted in both directions: exact unmasked unit-stride
// `vle32.v`, EEW=32 from the encoding, SEW=32/LMUL=1/EMUL=1 from vtype, base register != x0, VLEN
// 512 or 1024, non-Ref `--rvv-lowering`, with BOTH `--rvv-qcg-typed-chunk-vle` and
// `--rvv-vector-ssa`. vl == VLMAX, vstart == 0 and the runtime VLEN are RUNTIME state handled by the
// emitted guard, so what is proved for them here is the guard itself. Everything else is a
// TRANSLATION-time decision and is proved by its absence: no guard frame, no 64-byte guest load, and
// the pre-existing helper lowering instead.
//
// `vse32.v` WAS DELIBERATELY STILL A HELPER ON THIS BACKEND when this checkpoint shipped, and
// CheckVseStaysHelper pinned that as a positive assertion rather than an omission. S3.6 gave the
// store its own route on its own separate switch, so that function has been narrowed to the claim
// that survives and that this file actually owns: `--rvv-qcg-typed-chunk-vle` alone does not open
// the store route. See its own comment.

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
// Guest encodings, built from the instruction fields rather than pasted. The frozen S1.1-fix1
// workload's mixed kernel executes `vle32.v v8, (a5)` and friends; the field builders below are
// cross-checked against one such word in main().
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
// vsetvli a0, a0, <zimm11>
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}

// The full V-format unit-stride LOAD-FP encoding, every field exposed so the negative matrix can
// move exactly one of them at a time. Defaults are the admitted shape.
constexpr u32 EncodeVle(u32 vd, u32 rs1, u32 width = 0b110u /*EEW 32*/, u32 vm = 1, u32 lumop = 0,
			u32 mop = 0, u32 mew = 0, u32 nf = 0)
{
	return (nf << 29) | (mew << 28) | (mop << 26) | (vm << 25) | (lumop << 20) | (rs1 << 15) |
	       (width << 12) | (vd << 7) | 0b0000111u;
}
// vse32.v vs3, (rs1) -- STORE-FP, the mirror encoding. Present only so its route can be shown to be
// UNCHANGED by this checkpoint.
constexpr u32 EncodeVse(u32 vs3, u32 rs1)
{
	return (1u << 25) | (rs1 << 15) | (0b110u << 12) | (vs3 << 7) | 0b0100111u;
}

constexpr u32 VTYPE_E32_M1_TU_MA = Zimm11(/*vsew=*/2, /*vlmul=*/0, /*vta=*/0, /*vma=*/1);
constexpr u32 VTYPE_E64_M1 = Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M2 = Zimm11(/*vsew=*/2, /*vlmul=*/1, /*vta=*/1, /*vma=*/1);
constexpr u32 INSN_VSETVLI = EncodeVsetvli(VTYPE_E32_M1_TU_MA);
constexpr u32 INSN_VSETVLI_E64 = EncodeVsetvli(VTYPE_E64_M1);
constexpr u32 INSN_VSETVLI_E32_M2 = EncodeVsetvli(VTYPE_E32_M2);

constexpr u32 VD_REG = 8, RS1_REG = 15; // v8, a5 -- the frozen mixed kernel's own pair
constexpr u32 INSN_VLE32 = EncodeVle(VD_REG, RS1_REG);

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VLENB = ST_VEC + (u32)offsetof(rv32::VectorState, vlenb);

// Chunk `c` of guest vector register `reg`: bytes [64c, 64c+64) of that register's own slot.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}
// The CPUState slot of guest GPR `r`, in the SAME layout RV32Translator::GetStateInfo declares its
// globals with -- and the offset RvvEmitTypedVleChunkGroup puts on the node.
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
	config::rvv_lowering = 1; // non-Ref; 0 is the scalar reference arm the route excludes
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

	b.mod = std::make_unique<llvm::Module>("s3_5_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, b.region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm of the route: aot_use_llvm on, and BOTH of the two switches
// RvvLLVMVleChunkAdmit requires. Each is separately defeatable by the negative matrix below, which
// is the point of requiring two.
Built BuildLLVMRoute(u32 const *words, unsigned n, u32 vlen_bits, bool ssa = true, bool vle_sw = true)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
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

// A 512-bit chunk value as QIRToLLVM::MakeType(V512) spells it.
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

// True and *offs set if `ptr` is `getelementptr inbounds i8, ptr %state, <const>` -- the one shape
// LLVMGen::MakeStateEP produces for a CPUState field.
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

// THE ADDRESS CHAIN, reconstructed from the IR rather than assumed.
//
// The exact shape Emit_vchunkload builds, in both membase configurations:
//
//   zero_membase : [gep i8 %p, i64 <disp>] <- inttoptr (zext i32 %base to i64)
//   otherwise    : [gep i8 %p, i64 <disp>] <- gep i8 %membase, (zext i32 %base to i64)
//
// with `%base = load i32, ptr (gep i8 %state, <state_offs>)`. The outer displacement GEP is present
// only for chunk 1. Returns false for anything else -- including an i32 add folded into the base,
// which is what makes the wrap-freedom of the second chunk's address a checkable property.
struct GuestAddr {
	u64 state_offs = 0;
	u64 disp = 0;
	llvm::LoadInst *base_load = nullptr;
};

bool DecodeGuestAddr(llvm::Value *p, llvm::Value *statev, llvm::Value *membasev, GuestAddr *out)
{
	*out = GuestAddr{};
	p = StripCasts(p);
	// Optional host-pointer byte displacement (chunk 1 only).
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
	// THE ZERO-EXTENSION IS LOAD-BEARING: the guest base is 32 bits and becomes a host address by
	// zero extension, and the chunk displacement is added strictly after it.
	auto *ze = llvm::dyn_cast<llvm::ZExtInst>(addr);
	if (!ze || !ze->getSrcTy()->isIntegerTy(32)) {
		return false;
	}
	// ... and its operand must BE the CPUState load. An `add i32 %base, 64` here would wrap.
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

struct GuestLoad {
	llvm::LoadInst *ins = nullptr;
	GuestAddr addr;
};
struct StateStore {
	llvm::StoreInst *ins = nullptr;
	u64 offs = 0;
};

// Every 64-byte GUEST-memory load and every 64-byte CPUState store in `bb`, in program order.
void CollectFrameMemOps(llvm::BasicBlock *bb, llvm::Value *statev, llvm::Value *membasev,
			std::vector<GuestLoad> *gloads, std::vector<StateStore> *sstores,
			unsigned *n_unclassified)
{
	for (auto &ins : *bb) {
		if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
			if (!IsV8I64(ld->getType())) {
				continue;
			}
			GuestAddr a;
			u64 soff = 0;
			if (DecodeGuestAddr(ld->getPointerOperand(), statev, membasev, &a)) {
				gloads->push_back({ld, a});
			} else if (StateOffsetOf(ld->getPointerOperand(), statev, &soff)) {
				++*n_unclassified; // a CPUState 64-byte READ has no place in this frame
			} else {
				++*n_unclassified;
			}
		} else if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
			if (!IsV8I64(st->getValueOperand()->getType())) {
				continue;
			}
			u64 soff = 0;
			if (StateOffsetOf(st->getPointerOperand(), statev, &soff)) {
				sstores->push_back({st, soff});
			} else {
				++*n_unclassified; // a 64-byte GUEST-memory WRITE is out of scope here
			}
		}
	}
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

// The stub name a helper call resolves to, read off the MakeRStub load rather than assumed.
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

void CheckAdmitted(char const *tag, u32 vlen_bits, unsigned nchunks, u32 vlmax, u32 vd, u32 rs1,
		   bool with_vsetvli = true, u32 expect_vtype = VTYPE_E32_M1_TU_MA)
{
	printf("%s: vlen=%u nchunks=%u vlmax=%u vtype=0x%03x vle32.v v%u, (x%u)%s\n", tag, vlen_bits,
	       nchunks, vlmax, expect_vtype, vd, rs1, with_vsetvli ? "" : " (no in-block vsetvli)");
	u32 const insn = EncodeVle(vd, rs1);
	u32 words[2] = {INSN_VSETVLI, insn};
	unsigned const n = with_vsetvli ? 2 : 1;
	Built b = BuildLLVMRoute(with_vsetvli ? words : words + 1, n, vlen_bits);
	auto *statev = b.fn->getArg(0);
	auto *membasev = b.fn->getArg(1);

	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	// The QIR really is the S2.6 frame: one begin, `nchunks` vchunkloads, `nchunks` state stores,
	// one end -- and NO vchunkstore, which would be the vse route this checkpoint does not touch.
	CHECK_EQ(CountQirOp(b.region, Op::_rvvtypedchunkbegin), 1u);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkload), (unsigned)nchunks);
	CHECK_EQ(CountQirOp(b.region, Op::_vstatechunkstore), (unsigned)nchunks);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), 0u);
	CHECK_EQ(CountQirOp(b.region, Op::_vstatechunkload), 0u);

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
	// The four runtime conditions. On a MEMORY route the `vl == VLMAX` one is what stands between
	// a partial-vl load and a 64-byte block move.
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
	// No helper call on the taken direct path -- the property the pre-S3.5 artifact failed.
	CHECK_EQ(CountCalls(fast), 0u);

	std::vector<GuestLoad> gloads;
	std::vector<StateStore> sstores;
	unsigned n_unclassified = 0;
	CollectFrameMemOps(fast, statev, membasev, &gloads, &sstores, &n_unclassified);
	CHECK_EQ(n_unclassified, 0u);
	CHECK_EQ(gloads.size(), (size_t)nchunks);
	CHECK_EQ(sstores.size(), (size_t)nchunks);
	// And nowhere else in the function.
	CHECK_EQ(CountGuestChunkLoads(b.fn, statev, membasev), (unsigned)nchunks);
	if (gloads.size() != nchunks || sstores.size() != nchunks) {
		fprintf(stderr, "%s", PrintFn(b.fn).c_str());
		return;
	}

	// ---- PROPERTY 1: ADDRESS SOURCE ----------------------------------------------------------
	// Every chunk's base is read from the guest GPR named by rs1, at its own CPUState slot.
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(gloads[c].addr.state_offs, (u64)GprOffs(rs1));
	}

	// ---- PROPERTY 2: CHUNK BYTE OFFSET -------------------------------------------------------
	// Chunk c is at host-pointer displacement 64c, applied after the zero-extension. Chunk 0 has
	// no displacement at all -- an unconditional GEP would still be correct but would not be the
	// shape S2.6 audited, and at VLEN=512 nothing may be emitted at displacement 64.
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(gloads[c].addr.disp, (u64)(64u * c));
	}

	// ---- destination windows -----------------------------------------------------------------
	for (unsigned c = 0; c < nchunks; ++c) {
		CHECK_EQ(sstores[c].offs, (u64)ChunkOffs(vd, c));
		// The store writes exactly the value that chunk's load produced.
		CHECK(StripCasts(sstores[c].ins->getValueOperand()) == gloads[c].ins);
	}
	// All guest reads precede all CPUState writes -- the frame's stated order.
	CHECK(gloads.back().ins->comesBefore(sstores.front().ins));

	// ---- PROPERTY 3: ALIAS AND MEMORY SEMANTICS ----------------------------------------------
	// The guest load is unaligned and lives in a DIFFERENT alias scope from the frame's CPUState
	// accesses. Compared as MDNode identities out of the IR, so this cannot be satisfied by a
	// lowering that puts everything in one scope.
	{
		auto *state_scope = sstores[0].ins->getMetadata(llvm::LLVMContext::MD_alias_scope);
		CHECK(state_scope != nullptr);
		for (unsigned c = 0; c < nchunks; ++c) {
			auto *ld = gloads[c].ins;
			CHECK_EQ(ld->getAlign().value(), (u64)1);
			auto *vmem_scope = ld->getMetadata(llvm::LLVMContext::MD_alias_scope);
			CHECK(vmem_scope != nullptr);
			CHECK(vmem_scope != state_scope);
			CHECK(ld->getMetadata(llvm::LLVMContext::MD_noalias) != nullptr);
			// The base read is a CPUState access and must be in the state scope, i.e. the
			// SAME scope as the destination store and a different one from the data load.
			auto *bl = gloads[c].addr.base_load;
			CHECK(bl->getMetadata(llvm::LLVMContext::MD_alias_scope) == state_scope);
			CHECK_EQ(bl->getAlign().value(), (u64)4);
			CHECK_EQ(sstores[c].ins->getAlign().value(), (u64)16);
		}
	}

	// ---- no alloca traffic, no wide vector ----------------------------------------------------
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

	// ---- chunk independence -------------------------------------------------------------------
	if (nchunks == 2) {
		CHECK(gloads[0].ins != gloads[1].ins);
		// Neither load's address depends on the other load's result.
		CHECK(gloads[1].addr.base_load != gloads[0].ins);
		CHECK(gloads[0].addr.base_load != gloads[1].ins);
		// Disjoint 64-byte windows on both sides.
		CHECK_EQ(gloads[1].addr.disp - gloads[0].addr.disp, (u64)64);
		CHECK_EQ(sstores[1].offs - sstores[0].offs, (u64)64);
		// The two destination stores consume different values.
		CHECK(StripCasts(sstores[0].ins->getValueOperand()) !=
		      StripCasts(sstores[1].ins->getValueOperand()));
	}

	// ---- fallback arm ---------------------------------------------------------------------------
	// Exactly one call, it is the pre-existing rv32_vle helper for this instruction word, and no
	// typed body accompanies it.
	CHECK_EQ(CountCalls(slow), 1u);
	{
		std::vector<GuestLoad> sl;
		std::vector<StateStore> ss;
		unsigned nu = 0;
		CollectFrameMemOps(slow, statev, membasev, &sl, &ss, &nu);
		CHECK_EQ(sl.size(), (size_t)0);
		CHECK_EQ(ss.size(), (size_t)0);
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
			    GetRuntimeStubName(RuntimeStubId::id_rv32_vle)));
		}
	}

	printf("  OK: fast=%zu guest 64B load(s) at [gpr[x%u] + %s], 0 calls; %zu CPUState store(s) at "
	       "vreg[v%u]; fallback=1 rv32_vle call\n",
	       gloads.size(), rs1, nchunks == 2 ? "{0,64}" : "{0}", sstores.size(), vd);
}

// ---------------------------------------------------------------------------------------------
// Non-admission. Each case must produce NO guard frame, NO typed QIR op and NO 64-byte guest load,
// and must still lower the guest instruction through the pre-existing helper path.
// ---------------------------------------------------------------------------------------------

void CheckNotAdmitted(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, char const *why,
		      bool ssa = true, bool vle_sw = true, void (*extra)() = nullptr)
{
	printf("%s: %s\n", tag, why);
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_qcg_typed_chunk_vle = vle_sw;
	if (extra) {
		extra();
	}
	Built b = BuildLLVM(words, n, vlen_bits);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(CountTypedQirOps(b.region), 0u);
	CHECK_EQ(CountGuestChunkLoads(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	unsigned n_calls = 0;
	for (auto &bb : *b.fn) {
		n_calls += CountCalls(&bb);
	}
	CHECK(n_calls >= n);
	printf("  no guard frame, 0 typed QIR ops, 0 guest 64B loads, %u call(s)\n", n_calls);
}

// The exact helper that a non-admitted `vle32.v` must still reach, named. Stronger than
// CheckNotAdmitted's "some call": it pins WHICH stub, so a non-admission that silently dropped the
// instruction or reached a different helper fails.
void CheckKeepsVleHelper(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, u32 insn,
			 char const *why, bool ssa = true, bool vle_sw = true)
{
	printf("%s: %s\n", tag, why);
	Built b = BuildLLVMRoute(words, n, vlen_bits, ssa, vle_sw);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.").size(), (size_t)0);
	CHECK_EQ(CountTypedQirOps(b.region), 0u);
	CHECK_EQ(CountGuestChunkLoads(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	unsigned n_vle = 0;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			if (!IsHelperCallWithRaw(&ins, b.fn->getArg(0), insn)) {
				continue;
			}
			n_vle += HelperStubName(llvm::cast<llvm::CallInst>(&ins))
				     .starts_with(GetRuntimeStubName(RuntimeStubId::id_rv32_vle));
		}
	}
	CHECK_EQ(n_vle, 1u);
	printf("  exactly one rv32_vle helper call for 0x%08x, no typed frame\n", insn);
}

// THIS ROUTE'S SWITCH DOES NOT OPEN THE STORE ROUTE. Asserted positively rather than left implicit:
// the store route shares this frame's guard, its chunk arithmetic and its CPUState windows, so
// "the load route accidentally took the store too" is a real risk and this is the check for it.
//
// S3.6 UPDATE, and the change is a narrowing of the claim rather than its removal. When this file
// was written the store had NO LLVM lowering at all, so the case could set the store's own switch
// and still require a helper. S3.6 gave `vse32.v` a real route on its own separate flag
// (RvvLLVMVseChunkAdmit), so that configuration now legitimately builds a store frame and this case
// was FAILING -- which is the check working, not breaking. What survives, and is the property this
// file actually owns, is the SWITCH SEPARATION: `--rvv-qcg-typed-chunk-vle` alone must leave every
// `vse32.v` on the pre-existing helper. The store route's own positive evidence lives in
// qmc/llvmgen/vse32v_typedchunk_llvm_test.cpp, where it belongs.
void CheckVseStaysHelper(u32 vlen_bits)
{
	printf("the load switch alone leaves vse32.v a helper: vlen=%u\n", vlen_bits);
	u32 const insn_vse = EncodeVse(/*vs3=*/VD_REG, /*rs1=*/RS1_REG);
	u32 words[3] = {INSN_VSETVLI, INSN_VLE32, insn_vse};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_vle = true;
	config::rvv_qcg_typed_chunk_vse = false; // the store route's OWN switch stays off
	config::rvv_qcg_typed_chunk_vse_force_emit = true;
	Built b = BuildLLVM(words, 3, vlen_bits);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	// The load frame IS built; the store frame is NOT.
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkload), (unsigned)(vlen_bits / 512));
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkstore), 0u);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	unsigned n_vse = 0;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			if (!IsHelperCallWithRaw(&ins, b.fn->getArg(0), insn_vse)) {
				continue;
			}
			n_vse += HelperStubName(llvm::cast<llvm::CallInst>(&ins))
				     .starts_with(GetRuntimeStubName(RuntimeStubId::id_rv32_vse));
		}
	}
	CHECK_EQ(n_vse, 1u);
	printf("  one typed load frame, zero vchunkstore, exactly one rv32_vse helper call\n");
}

// Neither switch alone opens the LLVM route, and the LLVM switches do not open the QCG route. The
// first half is the over-admission gate: `--rvv-vector-ssa` is what the vadd route already answers
// to, so a route that forgot its own switch would be admitted by every existing AOT arm.
void CheckSwitchSeparation(u32 vlen_bits)
{
	printf("switch separation: vlen=%u\n", vlen_bits);
	u32 words[2] = {INSN_VSETVLI, INSN_VLE32};

	// (a) --rvv-vector-ssa alone: NOT admitted.
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/true, /*vle_sw=*/false);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkload), 0u);
		CHECK_EQ(CountGuestChunkLoads(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	}
	// (b) --rvv-qcg-typed-chunk-vle alone (no vector SSA): NOT admitted.
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/false, /*vle_sw=*/true);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkload), 0u);
		CHECK_EQ(CountGuestChunkLoads(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 0u);
	}
	// (c) The pure-QCG route is unchanged: same switch, aot_use_llvm off, still admits at QIR
	//     level. (The AsmJit backend is not run here; force_emit stands in for the host probe,
	//     which this workstation's silicon would fail.)
	{
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_vector_ssa = true; // and the SSA switch does not disturb it either way
		config::rvv_qcg_typed_chunk_vle = true;
		config::rvv_qcg_typed_chunk_vle_force_emit = true;
		config::vlen_bits = vlen_bits;
		MemArena arena(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		CHECK_EQ(CountQirOp(region, Op::_rvvtypedchunkbegin), 1u);
		CHECK_EQ(CountQirOp(region, Op::_vchunkload), (unsigned)(vlen_bits / 512));
	}
	printf("  neither switch alone admits on LLVM; the accepted S2.6 QCG route is unchanged\n");
}

// The LLVM arm carries no host AVX-512 probe, and must not: it emits a plain 64-byte load, which
// LLVM legalizes for whatever subtarget the artifact is compiled for. Admission must therefore NOT
// depend on the compile host's CPUID. (`__builtin_cpu_supports` is a live runtime query.)
void CheckLlvmRouteNeedsNoForceEmit()
{
	printf("host-feature independence:\n");
#if defined(__x86_64__) || defined(__i386__)
	bool const host_avx512 = __builtin_cpu_supports("avx512f");
#else
	bool const host_avx512 = false;
#endif
	u32 words[2] = {INSN_VSETVLI, INSN_VLE32};
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_typed_chunk_vle = true;
	config::rvv_qcg_typed_chunk_vle_force_emit = false; // explicitly NOT bypassing anything
	Built b = BuildLLVM(words, 2, 512);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), (size_t)1);
	CHECK_EQ(CountGuestChunkLoads(b.fn, b.fn->getArg(0), b.fn->getArg(1)), 1u);
	printf("  admitted with force_emit=0 on a host with avx512f=%d\n", (int)host_avx512);
}

void DumpIR(char const *tag, u32 vlen_bits, bool ssa, bool vle_sw)
{
	u32 words[2] = {INSN_VSETVLI, INSN_VLE32};
	Built b = BuildLLVMRoute(words, 2, vlen_bits, ssa, vle_sw);
	printf("\n----- IR DUMP %s (vlen=%u, --rvv-vector-ssa=%d, --rvv-qcg-typed-chunk-vle=%d) -----\n%s",
	       tag, vlen_bits, (int)ssa, (int)vle_sw, PrintFn(b.fn).c_str());
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i) {
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	}
	printf("S3.5 typed vle32.v LLVM route test\n");

	// Sanity: the field builder reproduces a real `vle32.v v8, (a5)` word, and the vtype builder
	// reproduces the e32,m1,tu,ma vsetvli the C1 microkernel sets.
	// vle32.v v8, (a5): vm=1<<25, rs1=15<<15, width=0b110<<12, vd=8<<7, opcode LOAD-FP 0b0000111.
	CHECK_EQ(INSN_VLE32, 0x0207e407u);
	CHECK_EQ(INSN_VSETVLI, 0x09057557u);

	printf("\n== admitted: VLEN=512, one chunk ==\n");
	CheckAdmitted("v512", 512, 1, 16, VD_REG, RS1_REG);
	printf("\n== admitted: VLEN=1024, two independent chunks ==\n");
	CheckAdmitted("v1024", 1024, 2, 32, VD_REG, RS1_REG);

	printf("\n== admitted: unknown-vtype candidate (no in-block vsetvli) ==\n");
	CheckAdmitted("v512 unknown-vtype", 512, 1, 16, VD_REG, RS1_REG, /*with_vsetvli=*/false,
		      rv32::VTYPE_E32_M1_TA_MA);
	CheckAdmitted("v1024 unknown-vtype", 1024, 2, 32, VD_REG, RS1_REG, /*with_vsetvli=*/false,
		      rv32::VTYPE_E32_M1_TA_MA);

	printf("\n== admitted: base-register and destination edge cases ==\n");
	// Every base slot must be tracked exactly: the lowest legal base (x1), the highest (x31), and
	// the lowest/highest destination registers, at both widths. The destination sweep is what
	// catches a window formula that is right for v8 and wrong at the ends of vec.vreg.
	CheckAdmitted("v512 rs1=x1", 512, 1, 16, VD_REG, 1);
	CheckAdmitted("v512 rs1=x31", 512, 1, 16, VD_REG, 31);
	CheckAdmitted("v1024 rs1=x1", 1024, 2, 32, VD_REG, 1);
	CheckAdmitted("v1024 rs1=x31", 1024, 2, 32, VD_REG, 31);
	CheckAdmitted("v512 vd=v0", 512, 1, 16, 0, RS1_REG);
	CheckAdmitted("v512 vd=v31", 512, 1, 16, 31, RS1_REG);
	CheckAdmitted("v1024 vd=v0", 1024, 2, 32, 0, RS1_REG);
	CheckAdmitted("v1024 vd=v31", 1024, 2, 32, 31, RS1_REG);
	// Base and destination both at an extreme, together.
	CheckAdmitted("v1024 vd=v31 rs1=x31", 1024, 2, 32, 31, 31);

	printf("\n== switch separation: the load switch alone does not open the store route ==\n");
	CheckVseStaysHelper(512);
	CheckVseStaysHelper(1024);

	printf("\n== off-state and switch separation ==\n");
	CheckSwitchSeparation(512);
	CheckSwitchSeparation(1024);
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== non-admitted: the route's own switches ==\n");
	{
		u32 w[2] = {INSN_VSETVLI, INSN_VLE32};
		for (u32 v : {512u, 1024u}) {
			CheckKeepsVleHelper("route-off", w, 2, v, INSN_VLE32,
					    "--rvv-qcg-typed-chunk-vle=0", true, false);
			CheckKeepsVleHelper("ssa-off", w, 2, v, INSN_VLE32, "--rvv-vector-ssa=0", false,
					    true);
		}
	}

	printf("\n== non-admitted: encoding shapes that must never become a 64-byte block move ==\n");
	for (u32 v : {512u, 1024u}) {
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVle(VD_REG, RS1_REG, 0b110u, /*vm=*/0)};
			CheckKeepsVleHelper("masked", w, 2, v, w[1],
					    "masked vle32.v must leave inactive elements undisturbed");
		}
		for (auto [width, name] : {std::pair<u32, char const *>{0b000u, "vle8.v"},
					   {0b101u, "vle16.v"},
					   {0b111u, "vle64.v"}}) {
			u32 w[2] = {INSN_VSETVLI, EncodeVle(VD_REG, RS1_REG, width)};
			CheckKeepsVleHelper(name, w, 2, v, w[1], "wrong EEW moves a different byte count");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVle(VD_REG, RS1_REG, 0b110u, 1, 0, /*mop=*/2)};
			CheckNotAdmitted("vlse32.v", w, 2, v, "strided (mop=10) is not unit-stride");
		}
		{
			u32 w[2] = {INSN_VSETVLI,
				    EncodeVle(VD_REG, RS1_REG, 0b110u, 1, /*lumop=*/0b10000u)};
			CheckNotAdmitted("vle32ff.v", w, 2, v, "fault-only-first has its own semantics");
		}
		{
			u32 w[2] = {INSN_VSETVLI,
				    EncodeVle(VD_REG, RS1_REG, 0b110u, 1, /*lumop=*/0b01000u)};
			CheckNotAdmitted("vl1re32.v", w, 2, v, "whole-register load ignores vl/vtype");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVle(VD_REG, RS1_REG, 0b000u, 1, /*lumop=*/0b01011u)};
			CheckNotAdmitted("vlm.v", w, 2, v, "mask load moves ceil(vl/8) bytes");
		}
		{
			u32 w[2] = {INSN_VSETVLI,
				    EncodeVle(VD_REG, RS1_REG, 0b110u, 1, 0, 0, 0, /*nf=*/1)};
			CheckNotAdmitted("vlseg2e32.v", w, 2, v, "segment load writes a register group");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVle(VD_REG, RS1_REG, 0b110u, 1, 0, 0, /*mew=*/1)};
			CheckNotAdmitted("mew=1", w, 2, v, "mew is reserved and must fail closed");
		}
		{
			u32 w[2] = {INSN_VSETVLI, EncodeVle(VD_REG, /*rs1=*/0)};
			CheckKeepsVleHelper("base-x0", w, 2, v, w[1],
					    "x0 is not a tracked global, so its CPUState slot is not live");
		}
	}

	printf("\n== non-admitted: vtype, VLEN and lowering-mode shapes ==\n");
	for (u32 v : {512u, 1024u}) {
		{
			u32 w[2] = {INSN_VSETVLI_E64, INSN_VLE32};
			CheckKeepsVleHelper("e64,m1", w, 2, v, INSN_VLE32,
					    "SEW=64 with EEW=32 is EMUL=1/2, not 1");
		}
		{
			u32 w[2] = {INSN_VSETVLI_E32_M2, INSN_VLE32};
			CheckKeepsVleHelper("e32,m2", w, 2, v, INSN_VLE32, "LMUL>1 is a register group");
		}
	}
	{
		u32 w[2] = {INSN_VSETVLI, INSN_VLE32};
		// W5 (2026-09-17): 128 and 256 were here as "VLEN outside the admitted {512,1024}", and
		// that set was RvvSSAEnabled()'s, not this route's. The LLVM arm's width now comes from
		// RvvRouteChunkShape -> RvvHostChunkGeometryForSew, so a register that tiles into whole
		// host chunks is admitted at 128/256 too. The row is kept, at the width the GEOMETRY still
		// refuses: VLEN 384 is 48 bytes per register, which is not one of the three host vector
		// widths, so it has no chunk shape at all. Positive five-width coverage -- the chunk count,
		// the chunk type and the fallback at each width -- is asserted in
		// rvv_llvm_five_width_geometry_test rather than restated in every per-opcode file.
		CheckKeepsVleHelper("vlen384", w, 2, 384, INSN_VLE32, "VLEN 384 has no host chunk shape");
		CheckNotAdmitted("rvv-lowering=Ref", w, 2, 512,
				 "the scalar reference arm wraps element addresses modulo 2^32", true,
				 true, [] { config::rvv_lowering = 0; });
		CheckNotAdmitted("rvv-lowering=Ref", w, 2, 1024,
				 "the scalar reference arm wraps element addresses modulo 2^32", true,
				 true, [] { config::rvv_lowering = 0; });
		CheckNotAdmitted("rvv-verify", w, 2, 512, "--rvv-verify cannot see emitted code", true,
				 true, [] { config::rvv_verify = true; });
		CheckNotAdmitted("rvv-verify", w, 2, 1024, "--rvv-verify cannot see emitted code", true,
				 true, [] { config::rvv_verify = true; });
		CheckNotAdmitted("rvv-direct=0", w, 2, 512, "the QCG lowering master switch is off", true,
				 true, [] { config::rvv_direct = false; });
		CheckNotAdmitted("rvv-direct=0", w, 2, 1024, "the QCG lowering master switch is off", true,
				 true, [] { config::rvv_direct = false; });
	}

	if (dump_ir) {
		DumpIR("route-on", 512, true, true);
		DumpIR("route-on", 1024, true, true);
		DumpIR("route-off", 512, true, false);
		DumpIR("route-off", 1024, true, false);
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
