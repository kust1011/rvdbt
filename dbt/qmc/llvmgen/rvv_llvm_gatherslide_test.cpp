// C6 (2026-09-20): `vrgather` AND THE SLIDES -- `vslideup`, `vslidedown`, `vslide1up`,
// `vslide1down`.
//
// FIVE INSTRUCTIONS, ONE NODE, ONE EMITTER, TWO SWITCHES. They are tested together because they
// share a lowering and separately because they must not share a flag: the file runs each route with
// ONLY its own switch on, so a section that passes because the OTHER route fired would fail.
//
// WHAT A SHARED LOWERING GETS WRONG, and what each section is therefore for:
//   * THE TWO BOUNDARIES ARE DIFFERENT. `vslidedown` and `vrgather` bound the source index by
//     VLMAX; `vslide1down` bounds it by `vl` -- its scalar lands at `vl - 1`, not VLMAX - 1. Using
//     one bound for both is the single most likely defect in a shared emitter, and [S3] is the
//     only section that can see it.
//   * `vslideup` LEAVES ELEMENTS BELOW THE OFFSET UNDISTURBED, it does not zero them. [S4] asserts
//     that against the destination's prior fill.
//   * AN OUT-OF-RANGE GATHER INDEX READS ZERO -- not clamped to VLMAX-1, not wrapped modulo VLMAX.
//     [G3] feeds VLMAX, VLMAX+1 and 0xffffffff, which separate all three readings.
//
// THE HARNESS FOLDS `masked.gather` ITSELF. Constant folding does not know the intrinsic, and the
// address operand is a GEP with a SCALAR base and a VECTOR index, so neither
// `accumulateConstantOffset` nor the chain walker used elsewhere applies. The pre-pass below
// resolves the base through the chain, reads the index vector as a constant, and serves each
// enabled lane from the register-file image -- which is also what makes the passthru observable.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace testcompat = dbt::qir::testcompat;

namespace
{
namespace rvv32 = dbt::rv32;

unsigned g_fail = 0;
#define CHECK(c)                                                                                   \
	do {                                                                                       \
		if (!(c)) {                                                                        \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                      \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)
#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto x_ = (long long)(a);                                                          \
		auto y_ = (long long)(b);                                                          \
		if (x_ != y_) {                                                                    \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, x_, y_);                                                        \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

llvm::LLVMContext &g_ctx = dbt::qir::g_llvm_ctx;

constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
// vta | vma | vsew << 3 | vlmul; LMUL 1 throughout.
constexpr u32 kVT[4] = {0xc0u, 0xc8u, 0xd0u, 0xd8u}; // e8, e16, e32, e64
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 4u, kVs2 = 8u, kVs1 = 12u;
// The GPR / F register used as the `.vx` and `.vf` operand. Not x10, which `vsetvli` reads.
constexpr u32 kScalarReg = 3u;
constexpr u32 F3_MV = 2u, F3_IV = 0u;

constexpr u32 R(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool vm = true)
{
	return (f6 << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
// funct6: vmandn 24, vmand 25, vmor 26, vmxor 27, vmorn 28, vmnand 29, vmnor 30, vmxnor 31.
constexpr u32 F6_BASE = 24u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6gatherslide", g_ctx) {}
};

// EACH ROUTE IS ENABLED ALONE. `which`: 0 neither (the routes-off arm), 1 gather, 2 slide. Turning
// both on would let a section pass because the other route fired.
void Configure(u32 vlen, unsigned which)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_vrgather = which == 1u;
	config::rvv_llvm_vslide = which == 2u;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	// OFF: the direct-state `vsetvli` route is admitted for exactly `e32, m1`, and with it on
	// `vec.vl` at SEW 32 is not a state LOAD this harness can pin.
	config::rvv_qcg_direct_setvl = false;
}

void Translate(Built &b)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

struct Qir {
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0;
	int guard_kind = -1;
	unsigned op = 99, slide = 99, sew = 0, isew = 0;
	std::vector<u32> bases;
};
// vmsbf 1, vmsof 2, vmsif 3 in the encoding; 0 before / 1 including / 2 only-first on the node.

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vgathernative) {
				auto *n = static_cast<InstVGather *>(&ins);
				++q.nodes;
				q.op = n->mode;
				q.slide = n->slide;
				q.sew = n->sew;
				q.isew = n->isew;
			} else if (ins.GetOpcode() == Op::_hcall) {
				++q.hcalls;
			}
		}
	return q;
}

llvm::Value *StripToBase(llvm::Value *p)
{
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p))
		p = g->getPointerOperand();
	return p;
}

// THE POINTER HERE IS A CHAIN, AND ITS SECOND LINK IS DYNAMIC IN THE IR. `vcompress` stores at
// `vd_base + n * sew` where `n` is a running count, so the emitter builds a constant GEP to the
// register and then a second GEP by a computed byte offset. `accumulateConstantOffset` on the outer
// GEP alone sees only the outer index; the whole chain has to be walked, and it resolves only
// because `n` folds to a constant once the source is pinned.
u32 StateOffsetChain(llvm::Value *p, llvm::Value *state, llvm::DataLayout const &DL)
{
	u64 total = 0;
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p)) {
		llvm::APInt ap(64, 0);
		if (!g->accumulateConstantOffset(DL, ap))
			return ~0u;
		total += ap.getZExtValue();
		p = g->getPointerOperand();
	}
	return p == state ? (u32)total : ~0u;
}

u32 StateOffset(llvm::Value *p, llvm::Value *state)
{
	if (StripToBase(p) != state || p == state)
		return ~0u;
	auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	if (!g)
		return ~0u;
	llvm::APInt ap(64, 0);
	if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
		return ~0u;
	return (u32)ap.getZExtValue();
}

constexpr u32 kVregOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
constexpr u32 kVregBytes = 32u * rvv32::VLEN_MAX_BYTES;
constexpr u32 kVlOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
constexpr u32 kGprOff = (u32)offsetof(CPUState, gpr);
constexpr u32 kFpOff = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, f));

// Resolve a GEP chain of CONSTANT offsets down to `state`, as elsewhere in these files.
u32 ChainOffset(llvm::Value *p, llvm::Value *state, llvm::DataLayout const &DL)
{
	u64 total = 0;
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p)) {
		llvm::APInt ap(64, 0);
		if (!g->accumulateConstantOffset(DL, ap))
			return ~0u;
		total += ap.getZExtValue();
		p = g->getPointerOperand();
	}
	return p == state ? (u32)total : ~0u;
}

// FOLD `llvm.masked.gather` AGAINST THE REGISTER-FILE IMAGE.
//
// Constant folding does not know this intrinsic. Its address operand is a GEP with a SCALAR base
// and a VECTOR index -- `accumulateConstantOffset` refuses that, and the plain chain walker sees
// only the base -- so the base and the index are resolved separately here and each ENABLED lane is
// served from `mem`. A disabled lane takes the passthru, which is how the out-of-range-reads-zero
// rule and the slide1 fill become observable at all.
bool FoldGathers(llvm::Function *fn, llvm::Value *state, std::vector<u8> const &mem, u32 vregoff,
		 u32 vregbytes)
{
	auto const &DL = fn->getParent()->getDataLayout();
	bool again = false;
	for (auto &bb : *fn)
		for (auto it = bb.begin(); it != bb.end();) {
			llvm::Instruction &I = *it++;
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&I);
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_gather)
				continue;
			// ALREADY FOLDED. `replaceAllUsesWith` does not remove the call, so without
			// this (and the erase below) the driving loop sees the same gather on every
			// pass, reports progress every time and never terminates -- which is exactly
			// what happened: the FIRST cell hung, not a large one.
			if (ii->use_empty())
				continue;
			auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(ii->getArgOperand(0));
			if (!gep || gep->getNumOperands() != 2)
				continue;
			u32 const base = ChainOffset(gep->getPointerOperand(), state, DL);
			auto *iv = llvm::dyn_cast<llvm::Constant>(gep->getOperand(1));
			// THROUGH THE COMPAT HEADER: the gather's alignment is an ARGUMENT on LLVM 20
			// and a parameter attribute on LLVM 22, so the mask and passthru sit one
			// position apart between them.
			auto *mk = llvm::dyn_cast<llvm::Constant>(testcompat::MaskedGatherMask(ii));
			auto *pt =
			    llvm::dyn_cast<llvm::Constant>(testcompat::MaskedGatherPassThru(ii));
			if (base == ~0u || !iv || !mk || !pt)
				continue;
			auto *vt = llvm::cast<llvm::FixedVectorType>(ii->getType());
			u32 const lb8 = vt->getScalarSizeInBits() / 8u;
			llvm::SmallVector<llvm::Constant *, 64> out;
			bool ok = true;
			for (u32 i = 0; i < vt->getNumElements() && ok; ++i) {
				auto *m = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    mk->getAggregateElement(i));
				auto *o = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    iv->getAggregateElement(i));
				auto *p = pt->getAggregateElement(i);
				if (!m || !o || !p) { ok = false; break; }
				if (!m->isOne()) {
					out.push_back(llvm::cast<llvm::Constant>(p));
					continue;
				}
				u64 const off = (u64)base + o->getZExtValue();
				if (off < vregoff || off + lb8 > (u64)vregoff + vregbytes) {
					ok = false;
					break;
				}
				llvm::APInt w(vt->getScalarSizeInBits(), 0);
				for (u32 k = 0; k < lb8; ++k)
					w |= llvm::APInt(vt->getScalarSizeInBits(),
							 mem[off - vregoff + k])
					     << (8u * k);
				out.push_back(llvm::ConstantInt::get(vt->getElementType(), w));
			}
			if (!ok)
				continue;
			ii->replaceAllUsesWith(llvm::ConstantVector::get(out));
			// Erase it: it reads memory, so nothing else will, and leaving it behind is
			// what made the fixpoint loop non-terminating.
			ii->eraseFromParent();
			again = true;
		}
	return again;
}

void FoldToFixpoint(llvm::Function *fn)
{
	auto const &DL = fn->getParent()->getDataLayout();
	for (bool again = true; again;) {
		again = false;
		for (auto &bb : *fn)
			for (auto it = bb.begin(); it != bb.end();) {
				llvm::Instruction &I = *it++;
				if (I.isTerminator() || I.mayHaveSideEffects() || I.use_empty())
					continue;
				if (auto *c = llvm::ConstantFoldInstruction(&I, DL)) {
					I.replaceAllUsesWith(c);
					again = true;
				}
			}
	}
}

struct Folded {
	bool ok = false;
	std::vector<u8> mem;
};

// `scalar` pins the GPR (and the F register) this file uses as the `.vx` / `.vf` operand. Without
// it the offset or fill stays symbolic and nothing folds -- the guest program here is just a
// `vsetvli` and the instruction under test, so no GPR has a value.
Folded FoldUnit(Built &b, std::vector<u8> const &initial, u32 vl, u64 scalar = 0,
		u64 fpbits = 0)
{
	Folded out;
	out.mem = initial;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o == kVlOff) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vl));
				continue;
			}
			// THE TWO SCALAR SLOTS MUST BE PINNED SEPARATELY. They were once served
			// the same value, which is why `.vf` could not be tested at all: the
			// register file holds a 32-bit GPR and a 64-bit F register, and the
			// instruction's rule for turning each into a SEW-wide fill is different.
			if (o == kGprOff + kScalarReg * 4u) {
				l->replaceAllUsesWith(
				    llvm::ConstantInt::get(l->getType(), scalar));
				continue;
			}
			if (o == kFpOff + kScalarReg * 8u) {
				l->replaceAllUsesWith(
				    llvm::ConstantInt::get(l->getType(), fpbits));
				continue;
			}
			if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
				continue;
			// BOTH the scalar seed load and the vector chunk loads come from here. The
			// seed is a plain integer at SEW, not a vector, so a filter on vector types
			// would leave it symbolic and nothing would fold.
			if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType())) {
				u32 const lb8 = vt->getScalarSizeInBits() / 8u;
				llvm::SmallVector<llvm::Constant *, 64> cv;
				for (u32 i = 0; i < vt->getNumElements(); ++i) {
					llvm::APInt w(vt->getScalarSizeInBits(), 0);
					for (u32 k = 0; k < lb8; ++k)
						w |= llvm::APInt(vt->getScalarSizeInBits(),
								 out.mem[o - kVregOff + i * lb8 + k])
						     << (8u * k);
					cv.push_back(llvm::ConstantInt::get(vt->getElementType(), w));
				}
				l->replaceAllUsesWith(llvm::ConstantVector::get(cv));
			} else if (auto *it = llvm::dyn_cast<llvm::IntegerType>(l->getType())) {
				u32 const lb8 = it->getBitWidth() / 8u;
				llvm::APInt w(it->getBitWidth(), 0);
				for (u32 k = 0; k < lb8; ++k)
					w |= llvm::APInt(it->getBitWidth(),
							 out.mem[o - kVregOff + k])
					     << (8u * k);
				l->replaceAllUsesWith(llvm::ConstantInt::get(it, w));
			}
		}
	// The gather has to be folded INSIDE the fixpoint: its address operand only becomes constant
	// after the index arithmetic folds, and its result feeds the store's value, which has to fold
	// afterwards. One pass of each is not enough when a chunk's index depends on a loaded vector.
	for (bool again = true; again;) {
		FoldToFixpoint(fn);
		again = FoldGathers(fn, state, out.mem, kVregOff, kVregBytes);
	}

	bool got = false;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			// THIS FAMILY STORES A PLAIN WORD, NOT A MASKED VECTOR. The blend is done in
			// the value -- `(computed & active) | (old & ~active)` -- because bits beyond
			// `vl` must be UNDISTURBED and there is no per-bit store predicate to express
			// that. A harness that only wrote back `masked.store` results saw no store at
			// all here and reported "did not fold" for every cell.
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				u32 const so = StateOffset(st->getPointerOperand(), state);
				if (so == ~0u || so < kVregOff || so >= kVregOff + kVregBytes)
					continue;
				auto *cv = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand());
				if (!cv)
					return out;
				u32 const w8 = cv->getBitWidth() / 8u;
				for (u32 k = 0; k < w8; ++k)
					out.mem[so - kVregOff + k] =
					    (u8)cv->getValue().lshr(8u * k).getZExtValue();
				got = true;
				continue;
			}
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (ii && ii->getIntrinsicID() == llvm::Intrinsic::masked_compressstore) {
				// value, ptr, mask -- and the selected lanes land CONTIGUOUSLY from
				// the pointer, which is the whole operation.
				auto const &DL = fn->getParent()->getDataLayout();
				u32 const o = StateOffsetChain(ii->getArgOperand(1), state, DL);
				if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
					return out;
				auto *c = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
				auto *m = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(2));
				if (!c || !m)
					return out;
				auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
				u32 const lb8 = vt->getScalarSizeInBits() / 8u;
				u32 put = 0;
				for (u32 i = 0; i < vt->getNumElements(); ++i) {
					auto *mk = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    m->getAggregateElement(i));
					auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    c->getAggregateElement(i));
					if (!mk || !e)
						return out;
					if (!mk->isOne())
						continue;
					llvm::APInt w = e->getValue();
					for (u32 k = 0; k < lb8; ++k)
						out.mem[o - kVregOff + put * lb8 + k] =
						    (u8)w.lshr(8u * k).getZExtValue();
					++put;
				}
				got = true;
				continue;
			}
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
				continue;
			u32 const o = StateOffset(ii->getArgOperand(1), state);
			if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
				continue;
			auto *c = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
			auto *m = llvm::dyn_cast<llvm::Constant>(testcompat::MaskedStoreMask(ii));
			if (!c || !m)
				return out;
			auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
			u32 const lb8 = vt->getScalarSizeInBits() / 8u;
			for (u32 i = 0; i < vt->getNumElements(); ++i) {
				auto *mk = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    m->getAggregateElement(i));
				auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    c->getAggregateElement(i));
				if (!mk || !e)
					return out;
				if (!mk->isOne())
					continue; // vl == 0: memory keeps its old bytes
				llvm::APInt w = e->getValue();
				for (u32 k = 0; k < lb8; ++k)
					out.mem[o - kVregOff + i * lb8 + k] =
					    (u8)w.lshr(8u * k).getZExtValue();
			}
			got = true;
		}
	out.ok = got;
	return out;
}

// A mask register is written as raw BYTES: its EEW is 1 and the guest's accessor is bit-indexed.
// `kVs2` is the DATA, `kVs1` the index vector (for `vrgather.vv`). The data is element-distinctive
// -- byte `i` is `7i+1` -- so a value arriving at the wrong destination NAMES the source element it
// came from, which is what separates a right-multiset-wrong-position lowering from a correct one.
// The whole file is filled first so the destination's prior value is recognisable everywhere.
std::vector<u8> BuildImage(std::vector<u32> const &indices, u32 isew, u8 fill)
{
	std::vector<u8> mem(kVregBytes, fill);
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i)
		mem[kVs2 * rvv32::VLEN_MAX_BYTES + i] = (u8)(i * 7u + 1u);
	for (u32 e = 0; e * isew + isew <= rvv32::VLEN_MAX_BYTES && e < indices.size(); ++e)
		for (u32 k = 0; k < isew; ++k)
			mem[kVs1 * rvv32::VLEN_MAX_BYTES + e * isew + k] =
			    (u8)(indices[e] >> (8u * k));
	return mem;
}

std::vector<u8> RefGather(u32 vl, u32 vlen, u32 sew, u32 vlmax, rvv32::VSrc src, u64 scalar,
			  bool ei16, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::vrgather(*vs, kVd, kVs2, kVs1, src, scalar, ei16, /*vm=*/true, vlen, vl, sew,
				 vlmax);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

// slide: 1 up, 2 down, 3 slide1up, 4 slide1down.
std::vector<u8> RefSlide(u32 kind, u32 vl, u32 vlen, u32 sew, u32 vlmax, u64 scalar,
			 std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	if (kind == 1)
		rvv32::rvv_ref::vslideup(*vs, kVd, kVs2, scalar, /*vm=*/true, vlen, vl, sew);
	else if (kind == 2)
		rvv32::rvv_ref::vslidedown(*vs, kVd, kVs2, scalar, /*vm=*/true, vlen, vl, sew,
					   vlmax);
	else
		rvv32::rvv_ref::vslide1(*vs, kind == 4, kVd, kVs2, scalar, /*vm=*/true, vlen, vl,
					sew);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

// vrgather: funct6 12 (.vv f3 0, .vi f3 3, .vx f3 4); vrgatherei16: funct6 14, f3 0.
constexpr u32 GatherWord(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool vm = true)
{
	return (f6 << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
// slides: funct6 14 up / 15 down; f3 3 .vi, 4 .vx (slideup/down), 5 .vf, 6 .vx (slide1).
constexpr u32 SlideWord(bool down, u32 f3, u32 vs2, u32 s, u32 vd, bool vm = true)
{
	return ((down ? 15u : 14u) << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (s << 15) |
	       (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 kVT_E32M2 = 0xd1u;

std::vector<u32> Indices(u32 n, u32 vlmax, unsigned kind)
{
	std::vector<u32> v(n);
	for (u32 e = 0; e < n; ++e)
		switch (kind) {
		case 0: v[e] = (vlmax - 1u) - (e % vlmax); break;     // reverse
		case 1: v[e] = (e * 5u + 3u) % vlmax; break;	     // scattered
		case 2: v[e] = 0; break;			     // broadcast element 0
		default: v[e] = e; break;			     // identity
		}
	return v;
}

void SectionGatherAdmission()
{
	printf("[G1] vrgather admission, the register rules, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	struct Form { u32 f6, f3, mode; };
	Form const forms[] = {{12u, 0u, 0u}, {12u, 4u, 1u}, {12u, 3u, 2u}, {14u, 0u, 0u}};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (auto const &f : forms) {
				// vrgatherei16 needs the index EMUL in range: at SEW 8 the index
				// group would be EMUL 2, which is not one register at LMUL 1.
				Configure(vlen, 1u);
				u32 const s1 = f.f3 == 0u ? kVs1 : (f.f3 == 4u ? kScalarReg : 5u);
				Built b({Vsetvli(kVT[si]), GatherWord(f.f6, f.f3, kVs2, s1, kVd),
					 kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.slide, 0u);
				CHECK_EQ(q.op, f.mode);
				CHECK_EQ(q.sew, 1u << si);
				CHECK_EQ(q.isew, f.f6 == 14u ? 2u : (1u << si));
				Configure(vlen, 0u);
				Built off({Vsetvli(kVT[si]), GatherWord(f.f6, f.f3, kVs2, s1, kVd),
					   kJalr});
				Translate(off);
				CHECK_EQ(ScanQir(off.region).nodes, 0u);
				CHECK(ScanQir(off.region).hcalls >= 1u);
			}
	printf("       %u admitted form/SEW/width cells\n", admitted);
	CHECK(admitted > 0);

	struct Row { char const *why; u32 vt; u32 word; };
	Row const rows[] = {
	    {"LMUL 2 (an addressing limit)", kVT_E32M2, GatherWord(12u, 0u, 8u, 12u, 4u)},
	    {"masked (vm == 0)", kVT[2], GatherWord(12u, 0u, kVs2, kVs1, kVd, /*vm=*/false)},
	    {"vd overlaps vs2", kVT[2], GatherWord(12u, 0u, kVd, kVs1, kVd)},
	    {"vd overlaps the index group", kVT[2], GatherWord(12u, 0u, kVs2, kVd, kVd)},
	    {"OPFVV funct3", kVT[2], GatherWord(12u, 1u, kVs2, kVs1, kVd)},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, 1u);
			Built b({Vsetvli(r.vt), r.word, kJalr});
			Translate(b);
			if (ScanQir(b.region).nodes) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
		}
	// THE SLIDE SWITCH MUST NOT ADMIT A GATHER. Two routes, one node: a shared flag would make
	// every section below ambiguous about which route produced it.
	for (u32 vlen : {256u, 512u}) {
		Configure(vlen, 2u);
		Built b({Vsetvli(kVT[2]), GatherWord(12u, 0u, kVs2, kVs1, kVd), kJalr});
		Translate(b);
		if (ScanQir(b.region).nodes) {
			printf("  FAIL the slide switch admitted a gather (vlen=%u)\n", vlen);
			++g_fail;
		}
	}
}

void SectionGather()
{
	printf("[G2] vrgather against rvv_ref::vrgather, whole register image\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 1u)
				vls.push_back(vlmax / 2u + 1u);
			for (unsigned kind = 0; kind < 4; ++kind) {
				std::vector<u32> const idx = Indices(vlmax, vlmax, kind);
				std::vector<u8> const initial = BuildImage(idx, sew, 0xa7u);
				for (u32 vl : vls) {
					// .vv
					Configure(vlen, 1u);
					Built b({Vsetvli(kVT[si]),
						 GatherWord(12u, 0u, kVs2, kVs1, kVd), kJalr});
					Translate(b);
					if (!ScanQir(b.region).nodes || !b.fn)
						continue;
					Folded const f = FoldUnit(b, initial, vl);
					if (!f.ok) {
						printf("  FAIL vv kind=%u vlen=%u sew=%u vl=%u: did "
						       "not fold\n",
						       kind, vlen, sew * 8u, vl);
						++g_fail;
						continue;
					}
					std::vector<u8> const r = RefGather(
					    vl, vlen, sew, vlmax, rvv32::VSrc::VV, 0, false,
					    initial);
					if (f.mem != r) {
						for (u32 i = 0; i < kVregBytes; ++i)
							if (f.mem[i] != r[i]) {
								printf("  FAIL vv kind=%u vlen=%u "
								       "sew=%u vl=%u: byte %u "
								       "emitted %02x, reference "
								       "%02x\n",
								       kind, vlen, sew * 8u, vl, i,
								       f.mem[i], r[i]);
								++g_fail;
								break;
							}
					}
					++cells;
				}
			}
			// .vx and .vi: one index for every lane.
			for (u32 s : {0u, 1u, vlmax > 2u ? vlmax - 1u : 0u}) {
				std::vector<u8> const initial =
				    BuildImage(Indices(vlmax, vlmax, 3), sew, 0xa7u);
				Configure(vlen, 1u);
				Built bx({Vsetvli(kVT[si]),
					  GatherWord(12u, 4u, kVs2, kScalarReg, kVd), kJalr});
				Translate(bx);
				if (!ScanQir(bx.region).nodes || !bx.fn)
					continue;
				Folded const fx = FoldUnit(bx, initial, vlmax, s);
				std::vector<u8> const rx = RefGather(vlmax, vlen, sew, vlmax,
								     rvv32::VSrc::VX, s, false,
								     initial);
				if (!fx.ok || fx.mem != rx) {
					printf("  FAIL vx s=%u vlen=%u sew=%u\n", s, vlen,
					       sew * 8u);
					++g_fail;
				}
				++cells;
				if (s < 32u) {
					Configure(vlen, 1u);
					Built bi({Vsetvli(kVT[si]),
						  GatherWord(12u, 3u, kVs2, s, kVd), kJalr});
					Translate(bi);
					if (!ScanQir(bi.region).nodes || !bi.fn)
						continue;
					Folded const fi = FoldUnit(bi, initial, vlmax);
					std::vector<u8> const ri =
					    RefGather(vlmax, vlen, sew, vlmax, rvv32::VSrc::VI, s,
						      false, initial);
					if (!fi.ok || fi.mem != ri) {
						printf("  FAIL vi s=%u vlen=%u sew=%u\n", s, vlen,
						       sew * 8u);
						++g_fail;
					}
					++cells;
				}
			}
		}
	printf("       %u cells compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [G3] AN OUT-OF-RANGE INDEX READS ZERO -- not clamped to VLMAX-1, not wrapped modulo VLMAX.
//
// The three candidate readings give three different answers, and the values below separate all of
// them: VLMAX (clamp -> element VLMAX-1, wrap -> element 0, correct -> 0), VLMAX+1 (wrap ->
// element 1) and 0xffffffff.
void SectionGatherOutOfRange()
{
	printf("[G3] an out-of-range gather index reads ZERO\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			// Indices alternate between a legal one and an out-of-range one, so the same
			// run shows both behaviours and a wholesale failure cannot look like a pass.
			std::vector<u32> idx(vlmax);
			for (u32 e = 0; e < vlmax; ++e)
				idx[e] = (e % 4u == 0u)	  ? vlmax
					 : (e % 4u == 1u) ? vlmax + 1u
					 : (e % 4u == 2u) ? 0xffffffffu
							  : (e % vlmax);
			// AT SEW 8 AN INDEX ELEMENT HOLDS 8 BITS, so `vlmax`, `vlmax + 1` and
			// 0xffffffff are all written TRUNCATED -- and a truncated index may land back
			// IN range, at which point the lane is supposed to read a real element and
			// the zero assertion below is simply false.
			//
			// The condition is `vlmax <= 254`, and each of the three values needs it:
			// `vlmax` itself is representable and out of range only for `vlmax <= 255`;
			// `vlmax + 1` wraps to 0 at `vlmax == 255`; 0xffffffff truncates to 255,
			// which exceeds `vlmax` only for `vlmax <= 255`. So 254 is the binding one.
			//
			// The first version had this guard BACKWARDS (`vlmax <= 255` -> skip), which
			// ran exactly the one configuration where it does not hold -- VLEN 2048, SEW
			// 8, VLMAX 256, where index 256 truncates to 0 and reads element 0. The
			// reference agreed (it truncates identically, so [G2]'s comparison passed);
			// only this section's direct claim was wrong.
			if (sew == 1u && vlmax > 254u)
				continue;
			std::vector<u8> const initial = BuildImage(idx, sew, 0xa7u);
			Configure(vlen, 1u);
			Built b({Vsetvli(kVT[si]), GatherWord(12u, 0u, kVs2, kVs1, kVd), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			Folded const f = FoldUnit(b, initial, vlmax);
			std::vector<u8> const r =
			    RefGather(vlmax, vlen, sew, vlmax, rvv32::VSrc::VV, 0, false, initial);
			if (!f.ok) {
				printf("  FAIL vlen=%u sew=%u: did not fold\n", vlen, sew * 8u);
				++g_fail;
				continue;
			}
			if (f.mem != r) {
				printf("  FAIL vlen=%u sew=%u: differs from the reference\n", vlen,
				       sew * 8u);
				++g_fail;
			}
			// And state it directly: the out-of-range lanes must be ZERO, not the
			// element a clamp or a wrap would have produced.
			u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
			for (u32 e = 0; e < vlmax; ++e) {
				if (e % 4u == 3u)
					continue;
				bool zero = true;
				for (u32 k = 0; k < sew; ++k)
					if (f.mem[dst + e * sew + k] != 0u)
						zero = false;
				if (!zero) {
					printf("  FAIL vlen=%u sew=%u: out-of-range lane %u is not "
					       "zero\n",
					       vlen, sew * 8u, e);
					++g_fail;
					break;
				}
			}
			++checked;
		}
	printf("       %u out-of-range cells\n", checked);
	CHECK(checked > 0);
}

void SectionSlideAdmission()
{
	printf("[S1] slide admission, the overlap asymmetry, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	struct Form { bool down; u32 f3; u32 slide; u32 mode; };
	Form const forms[] = {
	    {false, 3u, 1u, 2u}, {false, 4u, 1u, 1u}, {true, 3u, 2u, 2u}, {true, 4u, 2u, 1u},
	    {false, 6u, 3u, 1u}, {true, 6u, 4u, 1u},  {false, 5u, 3u, 3u}, {true, 5u, 4u, 3u},
	};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (auto const &f : forms) {
				Configure(vlen, 2u);
				u32 const s = f.f3 == 3u ? 5u : kScalarReg;
				Built b({Vsetvli(kVT[si]), SlideWord(f.down, f.f3, kVs2, s, kVd),
					 kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.slide, f.slide);
				CHECK_EQ(q.op, f.mode);
				Configure(vlen, 0u);
				Built off({Vsetvli(kVT[si]), SlideWord(f.down, f.f3, kVs2, s, kVd),
					   kJalr});
				Translate(off);
				CHECK_EQ(ScanQir(off.region).nodes, 0u);
				CHECK(ScanQir(off.region).hcalls >= 1u);
			}
	printf("       %u admitted form/SEW/width cells\n", admitted);
	CHECK(admitted > 0);

	for (u32 vlen : {256u, 512u}) {
		// THE OVERLAP RULE IS ASYMMETRIC, and that asymmetry is the ISA's: a slide UP writes
		// an element it has not yet read, a slide DOWN does not.
		Configure(vlen, 2u);
		Built up({Vsetvli(kVT[2]), SlideWord(false, 4u, kVd, kScalarReg, kVd), kJalr});
		Translate(up);
		if (ScanQir(up.region).nodes) {
			printf("  FAIL vslideup with vd == vs2 was admitted (vlen=%u)\n", vlen);
			++g_fail;
		}
		Configure(vlen, 2u);
		Built dn({Vsetvli(kVT[2]), SlideWord(true, 4u, kVd, kScalarReg, kVd), kJalr});
		Translate(dn);
		if (!ScanQir(dn.region).nodes) {
			printf("  FAIL vslidedown with vd == vs2 was REFUSED (vlen=%u); the ISA "
			       "permits it\n",
			       vlen);
			++g_fail;
		}
		Configure(vlen, 2u);
		Built m({Vsetvli(kVT[2]), SlideWord(false, 4u, kVs2, kScalarReg, kVd, false), kJalr});
		Translate(m);
		if (ScanQir(m.region).nodes) {
			printf("  FAIL masked slide was admitted (vlen=%u)\n", vlen);
			++g_fail;
		}
		Configure(vlen, 2u);
		Built l2({Vsetvli(kVT_E32M2), SlideWord(false, 4u, 8u, kScalarReg, 4u), kJalr});
		Translate(l2);
		if (ScanQir(l2.region).nodes) {
			printf("  FAIL LMUL 2 slide was admitted (vlen=%u)\n", vlen);
			++g_fail;
		}
		// And the gather switch must not admit a slide.
		Configure(vlen, 1u);
		Built g({Vsetvli(kVT[2]), SlideWord(false, 4u, kVs2, kScalarReg, kVd), kJalr});
		Translate(g);
		if (ScanQir(g.region).nodes) {
			printf("  FAIL the gather switch admitted a slide (vlen=%u)\n", vlen);
			++g_fail;
		}
	}
}

void SectionSlide()
{
	printf("[S2/S3/S4] the slides against their references, whole register image\n");
	unsigned cells = 0, undisturbed = 0;
	struct Form { char const *name; bool down; u32 f3; u32 kind; };
	Form const forms[] = {
	    {"vslideup.vx", false, 4u, 1u},
	    {"vslidedown.vx", true, 4u, 2u},
	    {"vslide1up.vx", false, 6u, 3u},
	    {"vslide1down.vx", true, 6u, 4u},
	};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			std::vector<u8> const initial =
			    BuildImage(Indices(vlmax, vlmax, 3), sew, 0xa7u);
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 1u)
				vls.push_back(vlmax / 2u + 1u);
			// Offsets: none, one, inside, at VLMAX and past it -- the last two are where
			// vslidedown's zero-fill and vslideup's undisturbed prefix live.
			std::vector<u32> offs = {0u, 1u, vlmax / 2u, vlmax, vlmax + 3u};
			for (auto const &f : forms)
				for (u32 vl : vls)
					for (u32 off : offs) {
						// The slide1 forms take a FILL, not an offset; run
						// them once per `vl` with a distinctive value.
						//
						// THE FILL IS A 32-BIT GPR, SIGN-EXTENDED TO SEW.
						// This file originally passed a full 64-bit
						// constant as both the register value and the
						// reference's scalar, which encoded the SAME wrong
						// assumption the emitter had -- so it agreed with a
						// lowering that read eight bytes out of a four-byte
						// GPR slot, and official ACT4 `Vx64-vslide1*.vx`
						// caught what both missed. The guest rule is
						// `(u64)(i64)(i32)gpr[rs1]`.
						// NEGATIVE ON PURPOSE. The first version of this
						// used 0x5a5a5a5a, which is positive, so it could
						// not tell a sign-extension from a zero-extension
						// -- the very property the SEW-64 defect turned on.
						u32 const gpr = f.kind >= 3u ? 0xdeadbeefu : off;
						u64 const s = f.kind >= 3u
								  ? (u64)(i64)(i32)gpr
								  : (u64)off;
						if (f.kind >= 3u && off != 0u)
							continue;
						Configure(vlen, 2u);
						Built b({Vsetvli(kVT[si]),
							 SlideWord(f.down, f.f3, kVs2, kScalarReg,
								   kVd),
							 kJalr});
						Translate(b);
						if (!ScanQir(b.region).nodes || !b.fn)
							continue;
						Folded const fd = FoldUnit(b, initial, vl, gpr);
						if (!fd.ok) {
							printf("  FAIL %s vlen=%u sew=%u vl=%u "
							       "off=%u: did not fold\n",
							       f.name, vlen, sew * 8u, vl, off);
							++g_fail;
							continue;
						}
						std::vector<u8> const r = RefSlide(
						    f.kind, vl, vlen, sew, vlmax, s, initial);
						if (fd.mem != r) {
							for (u32 i = 0; i < kVregBytes; ++i)
								if (fd.mem[i] != r[i]) {
									printf("  FAIL %s vlen=%u "
									       "sew=%u vl=%u off=%u: "
									       "byte %u emitted %02x, "
									       "reference %02x\n",
									       f.name, vlen, sew * 8u,
									       vl, off, i, fd.mem[i],
									       r[i]);
									++g_fail;
									break;
								}
						}
						// [S4] vslideup leaves elements BELOW the offset
						// undisturbed, not zeroed. Stated against the fill.
						if (f.kind == 1u && off > 0u) {
							u32 const dst =
							    kVd * rvv32::VLEN_MAX_BYTES;
							u32 const lim = std::min(off, vl);
							for (u32 e = 0; e < lim; ++e)
								for (u32 k = 0; k < sew; ++k)
									if (fd.mem[dst + e * sew + k] !=
									    0xa7u) {
										printf(
										    "  FAIL "
										    "vslideup vlen=%u "
										    "sew=%u off=%u: "
										    "element %u below "
										    "the offset was "
										    "written\n",
										    vlen, sew * 8u,
										    off, e);
										++g_fail;
										e = lim;
										break;
									}
							++undisturbed;
						}
						++cells;
					}
		}
	printf("       %u cells compared, %u with a checked undisturbed prefix\n", cells,
	       undisturbed);
	CHECK(cells > 0);
	CHECK(undisturbed > 0);
}

// [S3] THE TWO BOUNDARIES ARE DIFFERENT, STATED DIRECTLY.
//
// `vslide1down`'s fill lands at `vl - 1`. `vslidedown` reads zero at VLMAX. A shared emitter that
// used VLMAX for both would put `vslide1down`'s scalar at VLMAX - 1 -- a lane the instruction must
// not write -- and leave `vl - 1` holding a stale element. This runs at `vl < VLMAX`, which is the
// only configuration where the two bounds differ.
// [S5] `vfslide1up.vf` / `vfslide1down.vf` -- THE FP SCALAR FILL.
//
// This section exists because of a REAL ESCAPE. The `.vf` forms are admitted by the route at SEW 32
// and 64, and nothing in this file used to reach them: every form above is `.vx`. The `.vx` path
// shipped with a fill that loaded the SEW width straight out of the register file, which at SEW 64
// reads EIGHT bytes from a FOUR-byte GPR slot and takes `gpr[rs1+1]` as the high half -- official
// ACT4 `Vx64-vslide1down.vx-00` / `-vslide1up.vx-00` aborted on it while every focused check here
// passed. The `.vf` fill has its own separate rule and had no coverage at all.
//
// THE RULE IS THE INTERPRETER'S, AT ITS CALL SITE -- `rv32_interp.cpp`:
//     `.vf`: sew == 4 ? f32_unbox(fpu.f[rs1]) : fpu.f[rs1]
//     `.vx`: (u64)(i64)(i32)gpr[rs1]
// `rvv_ref::vslide1` takes the fill ALREADY COMPUTED, so the reference cannot check this for us;
// the expectation below calls `f32_unbox` itself rather than spelling out a constant, so it cannot
// drift from the function the guest actually uses.
void SectionSlideFP()
{
	printf("[S5] the .vf scalar fill is NaN-unboxed at SEW 32, taken whole at SEW 64\n");
	unsigned cells = 0, unboxed_seen = 0;
	struct Form { char const *name; bool down; u32 kind; };
	Form const forms[] = {{"vfslide1up.vf", false, 3u}, {"vfslide1down.vf", true, 4u}};
	// A properly boxed single, and a 64-bit pattern that is NOT a boxed single -- the second
	// must become the canonical NaN, which is the whole of the unboxing rule.
	u64 const fps[] = {0xffffffff3f800000ull, 0x0123456789abcdefull};
	for (u32 vlen : {128u, 256u, 512u, 1024u})
		for (u32 si = 2; si < 4; ++si) { // SEW 32 and 64 only: what the route admits
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			std::vector<u8> const initial =
			    BuildImage(Indices(vlmax, vlmax, 3), sew, 0x5du);
			std::vector<u32> vls = {vlmax, 1u};
			if (vlmax > 1u)
				vls.push_back(vlmax / 2u + 1u);
			for (auto const &f : forms)
				for (u64 fp : fps)
					for (u32 vl : vls) {
						u64 const want = sew == 4u
								     ? (u64)dbt::rv32::f32_unbox(fp)
								     : fp;
						if (sew == 4u && want == 0x7fc00000ull)
							++unboxed_seen;
						Configure(vlen, 2u);
						Built b({Vsetvli(kVT[si]),
							 SlideWord(f.down, 5u, kVs2, kScalarReg,
								   kVd),
							 kJalr});
						Translate(b);
						if (!ScanQir(b.region).nodes || !b.fn)
							continue;
						Folded const fd = FoldUnit(b, initial, vl,
									   /*scalar=*/0, fp);
						if (!fd.ok) {
							printf("  FAIL %s vlen=%u sew=%u vl=%u "
							       "fp=%016llx: did not fold\n",
							       f.name, vlen, sew * 8u, vl,
							       (unsigned long long)fp);
							++g_fail;
							continue;
						}
						std::vector<u8> const r =
						    RefSlide(f.kind, vl, vlen, sew, vlmax, want,
							     initial);
						++cells;
						if (fd.mem != r) {
							for (u32 i = 0; i < kVregBytes; ++i)
								if (fd.mem[i] != r[i]) {
									printf("  FAIL %s vlen=%u "
									       "sew=%u vl=%u "
									       "fp=%016llx: byte "
									       "%u got %02x want "
									       "%02x\n",
									       f.name, vlen,
									       sew * 8u, vl,
									       (unsigned long long)
										   fp,
									       i, fd.mem[i], r[i]);
									break;
								}
							++g_fail;
						}
					}
		}
	printf("       %u .vf cells, %u of them exercising the unboxing failure\n", cells,
	       unboxed_seen);
	// A vacuous row here would hide exactly the defect the section was written for.
	CHECK(cells != 0u);
	CHECK(unboxed_seen != 0u);
}

void SectionSlide1Boundary()
{
	printf("[S3] vslide1down's fill lands at vl-1, not VLMAX-1\n");
	unsigned checked = 0;
	// A 32-BIT GPR, sign-extended to SEW by the instruction -- see the note in [S2].
	u32 const fillgpr = 0xbc3c3c3cu; // negative: see the note in [S2]
	u64 const fill = (u64)(i64)(i32)fillgpr;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			if (vlmax < 4u)
				continue;
			u32 const vl = vlmax / 2u;
			std::vector<u8> const initial =
			    BuildImage(Indices(vlmax, vlmax, 3), sew, 0xa7u);
			Configure(vlen, 2u);
			Built b({Vsetvli(kVT[si]), SlideWord(true, 6u, kVs2, kScalarReg, kVd),
				 kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			Folded const f = FoldUnit(b, initial, vl, fillgpr);
			if (!f.ok) {
				printf("  FAIL vlen=%u sew=%u: did not fold\n", vlen, sew * 8u);
				++g_fail;
				continue;
			}
			u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
			// The fill is at vl-1 ...
			for (u32 k = 0; k < sew; ++k)
				if (f.mem[dst + (vl - 1u) * sew + k] !=
				    (u8)(fill >> (8u * k))) {
					printf("  FAIL vlen=%u sew=%u: element vl-1 (%u) is not "
					       "the fill\n",
					       vlen, sew * 8u, vl - 1u);
					++g_fail;
					break;
				}
			// ... and VLMAX-1 was not written at all.
			for (u32 k = 0; k < sew; ++k)
				if (f.mem[dst + (vlmax - 1u) * sew + k] != 0xa7u) {
					printf("  FAIL vlen=%u sew=%u: element VLMAX-1 (%u) was "
					       "written; the fill used the wrong bound\n",
					       vlen, sew * 8u, vlmax - 1u);
					++g_fail;
					break;
				}
			++checked;
		}
	printf("       %u boundary cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[V] the emitted modules verify\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			Configure(vlen, 1u);
			Built g({Vsetvli(kVT[si]), GatherWord(12u, 0u, kVs2, kVs1, kVd), kJalr});
			Translate(g);
			std::string e1;
			llvm::raw_string_ostream s1(e1);
			if (llvm::verifyModule(g.module, &s1)) {
				printf("  FAIL gather vlen=%u sew=%u: %s\n", vlen, 8u << si,
				       e1.c_str());
				++g_fail;
			}
			Configure(vlen, 2u);
			Built s({Vsetvli(kVT[si]), SlideWord(true, 6u, kVs2, kScalarReg, kVd),
				 kJalr});
			Translate(s);
			std::string e2;
			llvm::raw_string_ostream s2(e2);
			if (llvm::verifyModule(s.module, &s2)) {
				printf("  FAIL slide vlen=%u sew=%u: %s\n", vlen, 8u << si,
				       e2.c_str());
				++g_fail;
			}
		}
}

} // namespace

int main()
{
	// Unbuffered: this file runs thousands of translations and a redirected, block-buffered
	// stdout shows NOTHING until it finishes, which is indistinguishable from a hang.
	setvbuf(stdout, nullptr, _IONBF, 0);
	printf("rvv_llvm_gatherslide_test: C6, vrgather and the slides\n");
	SectionGatherAdmission();
	SectionGather();
	SectionGatherOutOfRange();
	SectionSlideAdmission();
	SectionSlide();
	SectionSlideFP();
	SectionSlide1Boundary();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
