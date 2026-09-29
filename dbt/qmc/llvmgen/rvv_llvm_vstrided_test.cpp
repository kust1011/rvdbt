// C7 (2026-09-20): THE STRIDED VECTOR MEMORY FORMS -- `vlse<EEW>.v` and `vsse<EEW>.v`.
//
// THE FIRST ROUTE IN THIS CHECKPOINT WHOSE ADDRESSES ARE GUEST ADDRESSES, so this is also the first
// harness here that has to model GUEST MEMORY as well as the register file. It does: a byte image
// indexed by guest address, served to `masked.gather` and written by `masked.scatter`, with the
// SAME image handed to the reference as its `vmem`. That is what makes this a value differential
// rather than a check on the shape of an address computation.
//
// WHAT IS ACTUALLY AT RISK HERE, and the section for each:
//   * THE PROGRESSION IS NOT CONTIGUOUS. `base + e * stride`, and the stride is a scalar register:
//     a NEGATIVE stride walks backwards, a ZERO stride makes every element touch the same address.
//     [M2] runs both, plus an element-sized and an oversized stride.
//   * THE ADDRESS IS 32-BIT AND WRAPS. The guest's address space is 32 bits and the reference
//     computes `base + e * (u32)stride` in `u32`. A 64-bit progression would not wrap and would
//     address memory the guest cannot name. [M4] asserts the resolved address vector directly --
//     it runs at `vl == 0`, where every lane is masked off and NOTHING is accessed, so the
//     addresses can be examined at values no image could hold.
//   * A LANE AT OR BEYOND `vl` MUST NOT TOUCH MEMORY. For a register operation an out-of-range
//     lane can be computed and discarded; here it would be a real access to a real address. [M3]
//     checks the store direction against an untouched image.
//
// SECTIONS:
//   [M1] Admission and inertness: EEW 8/16/32/64, load and store; unit-stride and indexed refused
//        (they share the stub family and are different lowerings), masked refused, LMUL 2 refused.
//   [M2] The differential against `rvv_ref::load_strided` / `store_strided`, over guest memory AND
//        the register image.
//   [M3] A store writes ONLY the elements below `vl`.
//   [M4] The address progression wraps at 32 bits.
//   [M5] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
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
// ONE data register: the encoding's `vd` for a load and `vs3` for a store are the same field.
constexpr u32 kData = 8u;
// The index vector register for the indexed forms.
constexpr u32 kIdx = 12u;
// The base and stride GPRs. Not x10, which `vsetvli` reads.
constexpr u32 kBaseReg = 5u, kStrideReg = 6u;
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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c7vstrided", g_ctx) {}
};

// `which`: 0 is the routes-off arm, 1 is STRIDED only, 2 is INDEXED only. The two families share
// one emitter but keep separate switches, so enabling exactly one at a time also checks that
// neither admits the other's forms.
void Configure(u32 vlen, unsigned which)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_vstrided = which == 1u;
	config::rvv_llvm_vindexed = which == 2u;
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
			} else if (ins.GetOpcode() == Op::_vmemorynative) {
				auto *n = static_cast<InstVMemory *>(&ins);
				++q.nodes;
				q.op = n->mode;
				q.slide = n->store;
				q.sew = n->sew;
				q.isew = n->nf;
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

// ---- guest memory -----------------------------------------------------------------------------
//
// A byte image indexed by GUEST ADDRESS. The emitted code computes `membase + addr` and the
// reference computes `vmem[addr]`, so handing the same buffer to both makes the two arms agree on
// what memory IS -- which is the whole point of doing this as a differential.
constexpr u32 kGuestBytes = 1u << 20; // 1 MiB: every address [M2] touches lies inside
constexpr u32 kGuestBase = 0x00010000u;

std::vector<u8> BuildGuest()
{
	std::vector<u8> g(kGuestBytes, 0);
	for (u32 i = 0; i < kGuestBytes; ++i)
		g[i] = (u8)(i * 31u + 7u); // distinctive: a value names the address it came from
	return g;
}

struct RefOut {
	std::vector<u8> regs, guest;
};

// The register-file image: the data register carries a recognisable pattern so a STORE's source is
// identifiable in guest memory, and everything else is a fill so an untouched element shows.
std::vector<u8> BuildRegs(u8 fill)
{
	std::vector<u8> mem(kVregBytes, fill);
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i)
		mem[kData * rvv32::VLEN_MAX_BYTES + i] = (u8)(i * 11u + 3u);
	return mem;
}

// The index vector, written at the INDEX EEW. The offsets are deliberately NOT monotone and
// include a REPEAT, so a lowering that quietly treated them as a stride, or that resolved
// duplicate scatter addresses by position rather than by value, would differ.
std::vector<u8> BuildRegsIndexed(u8 fill, u32 ieew, u32 lanes)
{
	std::vector<u8> mem = BuildRegs(fill);
	for (u32 e = 0; e < lanes; ++e) {
		// Offsets stay inside the guest image and inside the 8-bit index range so the same
		// table serves every index EEW.
		u32 const off = ((e * 37u) % 29u) * 4u;
		for (u32 k = 0; k < ieew; ++k)
			mem[kIdx * rvv32::VLEN_MAX_BYTES + e * ieew + k] = (u8)(off >> (8u * k));
	}
	return mem;
}

RefOut RefIndexed(bool store, u32 vl, u32 vlen, u32 sew, u32 ieew, std::vector<u8> const &regs,
		  std::vector<u8> const &guest)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], regs.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	RefOut o{regs, guest};
	if (store)
		rvv32::rvv_ref::store_indexed(*vs, kData, kIdx, o.guest.data(), kGuestBase, vlen,
					      vl, sew, ieew, /*vm=*/true);
	else
		rvv32::rvv_ref::load_indexed(*vs, kData, kIdx, o.guest.data(), kGuestBase, vlen, vl,
					     sew, ieew, /*vm=*/true);
	o.regs.assign(kVregBytes, 0);
	std::memcpy(o.regs.data(), &vs->vreg[0][0], kVregBytes);
	return o;
}

RefOut RefStrided(bool store, u32 vl, u32 vlen, u32 eew, i32 stride, std::vector<u8> const &regs,
		  std::vector<u8> const &guest)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], regs.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	RefOut o{regs, guest};
	// `vmem` is the image's base and the guest address is the index into it, which is exactly
	// the relationship `membase + addr` gives the emitted code.
	if (store)
		rvv32::rvv_ref::store_strided(*vs, kData, o.guest.data(), kGuestBase, stride, vlen,
					      vl, eew, /*vm=*/true);
	else
		rvv32::rvv_ref::load_strided(*vs, kData, o.guest.data(), kGuestBase, stride, vlen,
					     vl, eew, /*vm=*/true);
	o.regs.assign(kVregBytes, 0);
	std::memcpy(o.regs.data(), &vs->vreg[0][0], kVregBytes);
	return o;
}

// ---- the fold harness ---------------------------------------------------------------------------

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

u32 ChainOffset(llvm::Value *p, llvm::Value *root, llvm::DataLayout const &DL)
{
	u64 total = 0;
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p)) {
		llvm::APInt ap(64, 0);
		if (!g->accumulateConstantOffset(DL, ap))
			return ~0u;
		total += ap.getZExtValue();
		p = g->getPointerOperand();
	}
	return p == root ? (u32)total : ~0u;
}

struct Folded {
	bool ok = false;
	std::vector<u8> regs, guest;
	// THE RESOLVED GUEST ADDRESSES, recorded for EVERY lane including masked-off ones. [M4] reads
	// them at `vl == 0`, where nothing is accessed and the addresses can therefore be examined at
	// values no image could hold.
	std::vector<u64> addrs;
};

// Resolve a vector of guest pointers to per-lane byte addresses. The emitter builds
// `gep i8, %membase, <N x i64>` (or `inttoptr` under `zero_membase`), so the base is the function's
// SECOND argument and the index vector is the address -- a shape neither `accumulateConstantOffset`
// nor the scalar chain walker handles, because the index is a vector.
bool GuestAddrs(llvm::Value *ptrs, llvm::Value *membase, std::vector<u64> &out)
{
	out.clear();
	// THE SHAPE THIS BUILD ACTUALLY PRODUCES. With `zero_membase` the emitter builds
	// `inttoptr` per lane, and once the address vector folds LLVM presents the whole operand as a
	// CONSTANT VECTOR of `inttoptr` constant expressions -- not an instruction at all, so neither
	// of the two forms below matches it. That is what "did not fold" meant on the first run:
	// every cell, because the very first thing the resolver looked for was never there.
	if (auto *cv = llvm::dyn_cast<llvm::Constant>(ptrs)) {
		auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(cv->getType());
		if (vt && vt->getElementType()->isPointerTy()) {
			for (u32 i = 0; i < vt->getNumElements(); ++i) {
				auto *e = cv->getAggregateElement(i);
				// GUEST ADDRESS ZERO IS NOT AN `inttoptr` EXPRESSION. LLVM
				// canonicalises `inttoptr (i64 0 to ptr)` to the null pointer
				// constant, so a lane whose address WRAPPED to exactly 0 arrives as
				// `ConstantPointerNull`. That is why only the one [M4] case that
				// actually reaches 0 failed to resolve while the other three did:
				// zero is a legitimate guest address here, not an absence.
				if (llvm::isa_and_nonnull<llvm::ConstantPointerNull>(e)) {
					out.push_back(0);
					continue;
				}
				auto *ce = llvm::dyn_cast_or_null<llvm::ConstantExpr>(e);
				if (!ce || ce->getOpcode() != llvm::Instruction::IntToPtr)
					return false;
				auto *ci = llvm::dyn_cast<llvm::ConstantInt>(ce->getOperand(0));
				if (!ci)
					return false;
				out.push_back(ci->getZExtValue());
			}
			return true;
		}
	}
	llvm::Constant *iv = nullptr;
	if (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(ptrs)) {
		if (g->getNumOperands() != 2 || g->getPointerOperand() != membase)
			return false;
		iv = llvm::dyn_cast<llvm::Constant>(g->getOperand(1));
	} else if (auto *ip = llvm::dyn_cast<llvm::IntToPtrInst>(ptrs)) {
		iv = llvm::dyn_cast<llvm::Constant>(ip->getOperand(0));
	}
	if (!iv)
		return false;
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(iv->getType());
	if (!vt)
		return false;
	for (u32 i = 0; i < vt->getNumElements(); ++i) {
		auto *c = llvm::dyn_cast_or_null<llvm::ConstantInt>(iv->getAggregateElement(i));
		if (!c)
			return false;
		out.push_back(c->getZExtValue());
	}
	return true;
}

Folded FoldUnit(Built &b, std::vector<u8> const &regs0, std::vector<u8> const &guest0, u32 vl,
		u32 base, i32 stride)
{
	Folded out;
	out.regs = regs0;
	out.guest = guest0;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	llvm::Value *membase = fn->arg_size() > 1 ? fn->getArg(1) : nullptr;
	auto const &DL = fn->getParent()->getDataLayout();

	// Pin the live state this route reads: `vl`, and the two GPRs.
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			u32 const o = ChainOffset(l->getPointerOperand(), state, DL);
			if (o == kVlOff)
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vl));
			else if (o == kGprOff + kBaseReg * 4u)
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), base));
			else if (o == kGprOff + kStrideReg * 4u)
				l->replaceAllUsesWith(
				    llvm::ConstantInt::get(l->getType(), (u32)stride));
			else if (o != ~0u && o >= kVregOff && o < kVregOff + kVregBytes) {
				// The STORE direction reads its source register plainly.
				if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType())) {
					u32 const lb8 = vt->getScalarSizeInBits() / 8u;
					llvm::SmallVector<llvm::Constant *, 64> cv;
					for (u32 i = 0; i < vt->getNumElements(); ++i) {
						llvm::APInt w(vt->getScalarSizeInBits(), 0);
						for (u32 k = 0; k < lb8; ++k)
							w |= llvm::APInt(
								 vt->getScalarSizeInBits(),
								 out.regs[o - kVregOff + i * lb8 + k])
							     << (8u * k);
						cv.push_back(
						    llvm::ConstantInt::get(vt->getElementType(), w));
					}
					l->replaceAllUsesWith(llvm::ConstantVector::get(cv));
				}
			}
		}

	bool touched = false;
	for (bool again = true; again;) {
		FoldToFixpoint(fn);
		again = false;
		for (auto &bb : *fn)
			for (auto it = bb.begin(); it != bb.end();) {
				llvm::Instruction &I = *it++;
				auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&I);
				if (!ii)
					continue;
				auto const id = ii->getIntrinsicID();
				bool const isgather = id == llvm::Intrinsic::masked_gather;
				bool const isscatter = id == llvm::Intrinsic::masked_scatter;
				if (!isgather && !isscatter)
					continue;
				std::vector<u64> addrs;
				llvm::Value *ptrs =
				    isgather ? ii->getArgOperand(0) : ii->getArgOperand(1);
				if (!GuestAddrs(ptrs, membase, addrs))
					continue;
				auto *mk = llvm::dyn_cast<llvm::Constant>(
				    isgather ? testcompat::MaskedGatherMask(ii)
					     : testcompat::MaskedScatterMask(ii));
				if (!mk)
					continue;
				// RECORD THE ADDRESSES BEFORE ANYTHING ELSE, including before the
				// already-folded check below. At `vl == 0` the mask is all-false and
				// LLVM's own folder may already have collapsed the gather to its
				// passthru, leaving the call with no uses -- and [M4] runs at exactly
				// that `vl`, because it is the only way to examine addresses at values
				// no image could hold. Skipping first meant one case reported "no
				// address vector resolved" while the others happened not to be folded.
				if (out.addrs.empty())
					out.addrs = addrs;
				if (isgather && ii->use_empty())
					continue; // nothing left to produce; do not set `again`
				if (isgather) {
					auto *pt = llvm::dyn_cast<llvm::Constant>(
					    testcompat::MaskedGatherPassThru(ii));
					auto *vt =
					    llvm::cast<llvm::FixedVectorType>(ii->getType());
					u32 const lb8 = vt->getScalarSizeInBits() / 8u;
					llvm::SmallVector<llvm::Constant *, 64> vals;
					bool okl = pt != nullptr;
					for (u32 i = 0; i < vt->getNumElements() && okl; ++i) {
						auto *m = llvm::dyn_cast_or_null<llvm::ConstantInt>(
						    mk->getAggregateElement(i));
						if (!m) { okl = false; break; }
						if (!m->isOne()) {
							vals.push_back(llvm::cast<llvm::Constant>(
							    pt->getAggregateElement(i)));
							continue;
						}
						if (addrs[i] + lb8 > out.guest.size()) {
							okl = false;
							break;
						}
						llvm::APInt w(vt->getScalarSizeInBits(), 0);
						for (u32 k = 0; k < lb8; ++k)
							w |= llvm::APInt(vt->getScalarSizeInBits(),
									 out.guest[addrs[i] + k])
							     << (8u * k);
						vals.push_back(llvm::ConstantInt::get(
						    vt->getElementType(), w));
					}
					if (!okl)
						continue;
					ii->replaceAllUsesWith(llvm::ConstantVector::get(vals));
					ii->eraseFromParent();
				} else {
					auto *v = llvm::dyn_cast<llvm::Constant>(
					    ii->getArgOperand(0));
					if (!v)
						continue;
					auto *vt =
					    llvm::cast<llvm::FixedVectorType>(v->getType());
					u32 const lb8 = vt->getScalarSizeInBits() / 8u;
					bool okl = true;
					for (u32 i = 0; i < vt->getNumElements(); ++i) {
						auto *m = llvm::dyn_cast_or_null<llvm::ConstantInt>(
						    mk->getAggregateElement(i));
						auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
						    v->getAggregateElement(i));
						if (!m || !e) { okl = false; break; }
						if (!m->isOne())
							continue;
						if (addrs[i] + lb8 > out.guest.size()) {
							okl = false;
							break;
						}
						for (u32 k = 0; k < lb8; ++k)
							out.guest[addrs[i] + k] =
							    (u8)e->getValue()
								.lshr(8u * k)
								.getZExtValue();
					}
					if (!okl)
						continue;
					ii->eraseFromParent();
				}
				touched = true;
				again = true;
			}
	}
	FoldToFixpoint(fn);

	// The LOAD direction's destination write.
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
				continue;
			u32 const o = ChainOffset(ii->getArgOperand(1), state, DL);
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
					continue;
				for (u32 k = 0; k < lb8; ++k)
					out.regs[o - kVregOff + i * lb8 + k] =
					    (u8)e->getValue().lshr(8u * k).getZExtValue();
			}
			touched = true;
		}
	out.ok = touched;
	return out;
}

// ---- encodings ----------------------------------------------------------------------------------
// width: 0b000 EEW 8, 0b101 16, 0b110 32, 0b111 64. mop 2 is strided.
constexpr u32 kWidth[4] = {0b000u, 0b101u, 0b110u, 0b111u};
constexpr u32 MemWord(bool store, u32 width, u32 mop, u32 rs2, u32 rs1, u32 vd, bool vm = true)
{
	return (0u << 29) | (0u << 28) | (mop << 26) | ((vm ? 1u : 0u) << 25) | (rs2 << 20) |
	       (rs1 << 15) | (width << 12) | (vd << 7) | (store ? 0x27u : 0x07u);
}

void SectionAdmission()
{
	printf("[M1] admission, the mop rule, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (u32 wi = 0; wi <= si; ++wi) // EEW <= SEW: the group fits one register
				for (bool store : {false, true}) {
					Configure(vlen, 1u);
					Built b({Vsetvli(kVT[si]),
						 MemWord(store, kWidth[wi], 2u, kStrideReg, kBaseReg,
							 kData),
						 kJalr});
					Translate(b);
					Qir const q = ScanQir(b.region);
					if (!q.nodes)
						continue;
					++admitted;
					CHECK_EQ(q.frames, 1u);
					CHECK_EQ((int)q.guard_kind,
						 (int)GK::VTypeIntegerNoRestart);
					CHECK_EQ(q.op, 1u);	    // mode 1 == strided
					CHECK_EQ(q.slide, store);   // the node's `store` flag
					CHECK_EQ(q.isew, 1u);	    // nf == 1
					CHECK_EQ(q.sew, 1u << wi);
					Configure(vlen, 0u);
					Built off({Vsetvli(kVT[si]),
						   MemWord(store, kWidth[wi], 2u, kStrideReg,
							   kBaseReg, kData),
						   kJalr});
					Translate(off);
					CHECK_EQ(ScanQir(off.region).nodes, 0u);
					CHECK(ScanQir(off.region).hcalls >= 1u);
				}
	printf("       %u admitted EEW/SEW/width/direction cells\n", admitted);
	CHECK(admitted > 0);

	struct Row { char const *why; u32 vt; u32 word; };
	Row const rows[] = {
	    // The unit-stride and indexed forms share this stub family and are DIFFERENT lowerings.
	    {"unit-stride (mop 0)", kVT[2], MemWord(false, kWidth[2], 0u, 0u, kBaseReg, kData)},
	    {"indexed-unordered (mop 1)", kVT[2],
	     MemWord(false, kWidth[2], 1u, 12u, kBaseReg, kData)},
	    {"indexed-ordered (mop 3)", kVT[2], MemWord(false, kWidth[2], 3u, 12u, kBaseReg, kData)},
	    {"masked (vm == 0)", kVT[2],
	     MemWord(false, kWidth[2], 2u, kStrideReg, kBaseReg, kData, /*vm=*/false)},
	    {"LMUL 2", 0xd1u, MemWord(false, kWidth[2], 2u, kStrideReg, kBaseReg, 8u)},
	    // EEW 64 at SEW 32 gives a two-register destination group.
	    {"EEW > SEW (a two-register group)", kVT[2],
	     MemWord(false, kWidth[3], 2u, kStrideReg, kBaseReg, kData)},
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
}

void SectionDifferential()
{
	printf("[M2/M3] guest memory AND the register image against the reference\n");
	unsigned cells = 0, stores_checked = 0;
	std::vector<u8> const guest0 = BuildGuest();
	std::vector<u8> const regs0 = BuildRegs(0xa7u);
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (u32 wi = 0; wi <= si; ++wi) {
				u32 const eew = 1u << wi, sew = 1u << si;
				u32 const vlmax = vlen / (8u * sew);
				std::vector<u32> vls = {vlmax, 0u, 1u};
				if (vlmax > 3u)
					vls.push_back(3u);
				if (vlmax > 1u)
					vls.push_back(vlmax / 2u + 1u);
				// STRIDES: element-sized, wider, ZERO (every element at the same
				// address) and NEGATIVE (walking backwards). All legal.
				std::vector<i32> strides = {(i32)eew, (i32)(eew * 3u), 0,
							    -(i32)eew, -(i32)(eew * 2u)};
				for (bool store : {false, true})
					for (u32 vl : vls)
						for (i32 st : strides) {
							Configure(vlen, 1u);
							Built b({Vsetvli(kVT[si]),
								 MemWord(store, kWidth[wi], 2u,
									 kStrideReg, kBaseReg, kData),
								 kJalr});
							Translate(b);
							if (!ScanQir(b.region).nodes || !b.fn)
								continue;
							Folded const f =
							    FoldUnit(b, regs0, guest0, vl,
								     kGuestBase, st);
							if (!f.ok) {
								printf("  FAIL %s vlen=%u sew=%u "
								       "eew=%u vl=%u stride=%d: did "
								       "not fold\n",
								       store ? "vsse" : "vlse", vlen,
								       sew * 8u, eew * 8u, vl, st);
								++g_fail;
								continue;
							}
							RefOut const r = RefStrided(
							    store, vl, vlen, eew, st, regs0, guest0);
							if (f.regs != r.regs ||
							    f.guest != r.guest) {
								printf("  FAIL %s vlen=%u sew=%u "
								       "eew=%u vl=%u stride=%d: "
								       "%s differs\n",
								       store ? "vsse" : "vlse", vlen,
								       sew * 8u, eew * 8u, vl, st,
								       f.regs != r.regs
									   ? "the register image"
									   : "guest memory");
								++g_fail;
							}
							// [M3] A STORE WRITES ONLY THE ELEMENTS
							// BELOW `vl`. Counting the bytes that
							// differ from the untouched image is the
							// direct statement; a lane at or beyond
							// `vl` touching memory would show as an
							// extra changed byte even where the
							// reference agrees by accident.
							if (store && st != 0) {
								u32 diff = 0;
								for (u32 k = 0; k < guest0.size(); ++k)
									diff += f.guest[k] != guest0[k];
								u32 const want =
								    std::min(vl, vlmax) * eew;
								if (diff > want) {
									printf("  FAIL vsse vlen=%u "
									       "eew=%u vl=%u "
									       "stride=%d: %u guest "
									       "bytes changed, at most "
									       "%u may\n",
									       vlen, eew * 8u, vl, st,
									       diff, want);
									++g_fail;
								}
								++stores_checked;
							}
							++cells;
						}
			}
	printf("       %u cells compared, %u store extents checked\n", cells, stores_checked);
	CHECK(cells > 0);
	CHECK(stores_checked > 0);
}

// [M4] THE ADDRESS PROGRESSION WRAPS AT 32 BITS.
//
// Run at `vl == 0`: every lane is masked off, NOTHING is accessed, and the resolved address vector
// can therefore be examined at values no image could hold. A 64-bit progression would leave the
// high bits in place and the comparison below would fail on the first wrapping lane.
// [M7]/[M8] THE INDEXED FORMS, which share this emitter: the two modes differ only in the offset
// vector. `vsoxei` -- the ORDERED store -- must be REFUSED, and that refusal is the point: LLVM's
// `masked.scatter` leaves the order among enabled lanes unspecified, so it cannot express "the last
// element in order wins" when two indices name the same address. The index table includes a REPEAT
// precisely so that a lowering which ignored the distinction would be visible somewhere.
void SectionIndexed()
{
	printf("[M7/M8] the indexed forms: admission, the vsoxei refusal, and the differential\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0, cells = 0;
	std::vector<u8> const guest0 = BuildGuest();
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (u32 wi = 0; wi < 3; ++wi) { // index EEW 8/16/32 on RV32
				u32 const sew = 1u << si, ieew = 1u << wi;
				if (ieew > sew)
					continue; // the index group must fit one register
				u32 const vlmax = vlen / (8u * sew);
				std::vector<u8> const regs0 =
				    BuildRegsIndexed(0xa7u, ieew, vlmax);
				// mop 1 unordered, mop 3 ordered. Loads: both. Stores: unordered only.
				struct Form { bool store; u32 mop; bool want; };
				Form const forms[] = {{false, 1u, true},
						      {false, 3u, true},
						      {true, 1u, true},
						      {true, 3u, false}};
				for (auto const &f : forms) {
					Configure(vlen, 2u);
					Built b({Vsetvli(kVT[si]),
						 MemWord(f.store, kWidth[wi], f.mop, kIdx, kBaseReg,
							 kData),
						 kJalr});
					Translate(b);
					Qir const q = ScanQir(b.region);
					if (!f.want) {
						if (q.nodes) {
							printf("  FAIL vsoxei (ordered store) was "
							       "admitted (vlen=%u sew=%u ieew=%u); "
							       "masked.scatter cannot order "
							       "overlapping indices\n",
							       vlen, sew * 8u, ieew * 8u);
							++g_fail;
						}
						continue;
					}
					if (!q.nodes || !b.fn)
						continue;
					++admitted;
					CHECK_EQ(q.frames, 1u);
					CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
					CHECK_EQ(q.op, 2u); // mode 2 == indexed
					CHECK_EQ(q.sew, sew);
					for (u32 vl : {vlmax, 0u, 1u, vlmax / 2u + 1u}) {
						Configure(vlen, 2u);
						Built c({Vsetvli(kVT[si]),
							 MemWord(f.store, kWidth[wi], f.mop, kIdx,
								 kBaseReg, kData),
							 kJalr});
						Translate(c);
						if (!ScanQir(c.region).nodes || !c.fn)
							continue;
						Folded const fd =
						    FoldUnit(c, regs0, guest0, vl, kGuestBase, 0);
						if (!fd.ok) {
							printf("  FAIL indexed %s vlen=%u sew=%u "
							       "ieew=%u vl=%u: did not fold\n",
							       f.store ? "store" : "load", vlen,
							       sew * 8u, ieew * 8u, vl);
							++g_fail;
							continue;
						}
						RefOut const r = RefIndexed(f.store, vl, vlen, sew,
									    ieew, regs0, guest0);
						if (fd.regs != r.regs || fd.guest != r.guest) {
							printf("  FAIL indexed %s vlen=%u sew=%u "
							       "ieew=%u vl=%u: %s differs\n",
							       f.store ? "store" : "load", vlen,
							       sew * 8u, ieew * 8u, vl,
							       fd.regs != r.regs
								   ? "the register image"
								   : "guest memory");
							++g_fail;
						}
						++cells;
					}
					Configure(vlen, 0u);
					Built off({Vsetvli(kVT[si]),
						   MemWord(f.store, kWidth[wi], f.mop, kIdx,
							   kBaseReg, kData),
						   kJalr});
					Translate(off);
					CHECK_EQ(ScanQir(off.region).nodes, 0u);
				}
			}
	printf("       %u admitted indexed forms, %u cells compared\n", admitted, cells);
	CHECK(admitted > 0);
	CHECK(cells > 0);
}

void SectionWrap()
{
	printf("[M4] the address progression wraps at 32 bits\n");
	std::vector<u8> const guest0 = BuildGuest();
	std::vector<u8> const regs0 = BuildRegs(0xa7u);
	unsigned checked = 0;
	struct Case { u32 base; i32 stride; };
	Case const cases[] = {
	    {0x00000100u, (i32)0x40000000},  // wraps at element 4
	    {0x00000100u, (i32)0x80000000},  // wraps at every odd element
	    {0x00000004u, -16},		     // underflows immediately
	    {0xfffffff0u, 4},		     // carries past the top
	};
	for (u32 vlen : {128u, 512u})
		for (auto const &c : cases) {
			Configure(vlen, 1u);
			Built b({Vsetvli(kVT[2]),
				 MemWord(false, kWidth[2], 2u, kStrideReg, kBaseReg, kData), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			Folded const f = FoldUnit(b, regs0, guest0, 0u, c.base, c.stride);
			if (f.addrs.empty()) {
				printf("  FAIL base=%08x stride=%d: no address vector resolved\n",
				       c.base, c.stride);
				++g_fail;
				continue;
			}
			for (u32 e = 0; e < f.addrs.size(); ++e) {
				u64 const want = (u64)(u32)(c.base + e * (u32)c.stride);
				if (f.addrs[e] != want) {
					printf("  FAIL base=%08x stride=%d lane %u: address %llx, "
					       "expected %llx -- the progression did not wrap at 32 "
					       "bits\n",
					       c.base, c.stride, e,
					       (unsigned long long)f.addrs[e],
					       (unsigned long long)want);
					++g_fail;
					break;
				}
			}
			++checked;
		}
	printf("       %u wrap cells\n", checked);
	CHECK(checked > 0);
}

// [M6] `vstart` IS CLEARED IN THE EMITTED IR.
//
// As a DIFFERENCE, routes-on minus routes-off: the program's `vsetvli` has its own LLVM route which
// clears `vstart` too, but only at the vtype that route is admitted for, so an absolute count is
// wrong for some configurations for a reason unrelated to this family.
void SectionVstart()
{
	printf("[M6] vstart is cleared once per frame (routes-on minus routes-off)\n");
	u32 const kVstartOff =
	    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	auto count = [&](Built &b) {
		unsigned zeroes = 0;
		if (!b.fn)
			return zeroes;
		llvm::Value *state = b.fn->getArg(0);
		auto const &DL = b.fn->getParent()->getDataLayout();
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
				if (!st ||
				    ChainOffset(st->getPointerOperand(), state, DL) != kVstartOff)
					continue;
				auto *cv = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand());
				if (cv && cv->isZero())
					++zeroes;
			}
		return zeroes;
	};
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (bool store : {false, true}) {
				Configure(vlen, 1u);
				Built on({Vsetvli(kVT[si]),
					  MemWord(store, kWidth[si], 2u, kStrideReg, kBaseReg, kData),
					  kJalr});
				Translate(on);
				if (!ScanQir(on.region).nodes || !on.fn)
					continue;
				Configure(vlen, 0u);
				Built off({Vsetvli(kVT[si]),
					   MemWord(store, kWidth[si], 2u, kStrideReg, kBaseReg,
						   kData),
					   kJalr});
				Translate(off);
				unsigned const a = count(on), b = count(off);
				if (a != b + 1u) {
					printf("  FAIL vlen=%u sew=%u store=%d: routes-on has %u "
					       "stores of 0 to vec.vstart and routes-off has %u\n",
					       vlen, 8u << si, (int)store, a, b);
					++g_fail;
				}
				++checked;
			}
	printf("       %u vstart cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[M5] the emitted modules verify\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (bool store : {false, true}) {
				Configure(vlen, 1u);
				Built b({Vsetvli(kVT[si]),
					 MemWord(store, kWidth[si], 2u, kStrideReg, kBaseReg, kData),
					 kJalr});
				Translate(b);
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL vlen=%u sew=%u store=%d: %s\n", vlen,
					       8u << si, (int)store, err.c_str());
					++g_fail;
				}
			}
}

} // namespace

int main()
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	printf("rvv_llvm_vstrided_test: C7, the strided vector memory forms\n");
	SectionAdmission();
	SectionDifferential();
	SectionIndexed();
	SectionWrap();
	SectionVstart();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
