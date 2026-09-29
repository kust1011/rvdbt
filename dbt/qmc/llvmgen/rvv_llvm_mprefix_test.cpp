// C6 (2026-09-19): THE MASK PREFIX FAMILY `vmsbf.m` / `vmsif.m` / `vmsof.m`.
//
// ALL THREE ARE FUNCTIONS OF ONE NUMBER -- the index `f` of the first ACTIVE set bit -- so the
// emitter evaluates three comparisons against it rather than the reference's serial `seen` flag.
// The two forms describe the same function, and this file exists to hold them to that.
//
// THE CASES THAT SEPARATE THEM ARE NARROW AND ARE ENUMERATED DELIBERATELY:
//   * an EMPTY mask (no set bit below `vl`), where `vmsbf`/`vmsif` set every active bit and
//     `vmsof` sets none -- the case the all-ones sentinel has to get right without a special case;
//   * the first set bit at element 0, where `vmsbf` sets NOTHING and `vmsif`/`vmsof` set only
//     bit 0 -- the case that separates `<` from `<=`;
//   * a first set bit in a LATE word, where a scan that forgot the word offset lands elsewhere;
//   * a set bit BELOW `vl` and another ABOVE it, where only the first counts;
//   * a mask that is set ONLY above `vl`, which is the same as empty.
//
// SECTIONS:
//   [P1] Admission and inertness, including `viota` (sub 16) being REFUSED -- it shares the stub.
//   [P2] The differential against `rvv_ref::vmsetop`, whole register image.
//   [P3] Bits at or beyond `vl` are undisturbed.
//   [P4] The three operations DISAGREE where the spec says they must: at the first set bit.
//   [P5] The module verifies.

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
constexpr u32 kVd = 4u, kVs2 = 8u, kVs1 = 12u;
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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6mprefix", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_mprefix = on;
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
	unsigned op = 99;
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
			} else if (ins.GetOpcode() == Op::_vmaskprefix) {
				auto *n = static_cast<InstVMaskPrefix *>(&ins);
				++q.nodes;
				q.op = n->kind;
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

Folded FoldUnit(Built &b, std::vector<u8> const &initial, u32 vl)
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
	FoldToFixpoint(fn);

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
std::vector<u8> BuildImage(std::vector<u8> const &src, std::vector<u8> const &dfill)
{
	std::vector<u8> mem(kVregBytes, 0);
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i) {
		mem[kVs2 * rvv32::VLEN_MAX_BYTES + i] = src[i % src.size()];
		mem[kVd * rvv32::VLEN_MAX_BYTES + i] = dfill[i % dfill.size()];
	}
	return mem;
}

std::vector<u8> RefPrefix(u32 sub, u32 vl, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::vmsetop(*vs, sub, kVd, kVs2, /*vm=*/true, vl);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

struct OpRow { char const *name; u32 sub; u32 kind; };
OpRow const kOps[] = {
    {"vmsbf", 1u, 0u},
    {"vmsof", 2u, 2u},
    {"vmsif", 3u, 1u},
};

// funct6 20 (VMUNARY0), OPMVV; the sub-encoding sits in the vs1 field.
constexpr u32 P(u32 sub, u32 vs2, u32 vd, bool vm = true, u32 f3 = 2u)
{
	return (20u << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}

void SectionAdmission()
{
	printf("[P1] admission, the three sub-encodings, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), P(o.sub, kVs2, kVd), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ(q.nodes, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				// THE SUB-ENCODING TO KIND MAPPING IS NOT THE IDENTITY: the ISA
				// numbers them vmsbf 1, vmsof 2, vmsif 3 and the node numbers them
				// before 0, including 1, only-first 2. A swapped pair here gives a
				// working instruction with the wrong meaning.
				CHECK_EQ(q.op, o.kind);
				Configure(vlen, false);
				Built off({Vsetvli(kVT[si]), P(o.sub, kVs2, kVd), kJalr});
				Translate(off);
				CHECK_EQ(ScanQir(off.region).nodes, 0u);
				CHECK(ScanQir(off.region).hcalls >= 1u);
			}
	printf("       %u admitted op/SEW/width cells\n", admitted);
	CHECK_EQ(admitted, 60u);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    // viota shares this stub and funct6 and is a DIFFERENT computation entirely.
	    {"viota (sub 16) shares the stub", P(16u, kVs2, kVd)},
	    {"masked (vm == 0)", P(1u, kVs2, kVd, /*vm=*/false)},
	    {"vd == vs2", P(1u, kVs2, kVs2)},
	    {"OPIVV funct3", P(1u, kVs2, kVd, true, 0u)},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT[2]), r.word, kJalr});
			Translate(b);
			if (ScanQir(b.region).nodes) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
		}
}

// THE PATTERNS ARE THE POINT. Each names the distinction it is the only one to make.
struct Pat { char const *name; std::vector<u8> bytes; };
std::vector<Pat> Patterns()
{
	std::vector<Pat> ps = {
	    {"empty (no set bit at all)", {0x00u}},
	    {"first bit at element 0", {0x01u}},
	    {"first bit at element 1", {0x02u}},
	    {"first bit at element 7", {0x80u}},
	    {"dense", {0xffu}},
	    {"alternating", {0xaau}},
	    {"byte index", {0x00u, 0x00u, 0x10u, 0x00u, 0x00u, 0x08u, 0x00u, 0x40u}},
	};
	// First set bit at element 70 -- word 1, so a scan that forgot the word offset answers 6.
	std::vector<u8> late(9, 0x00u);
	late[8] = 0x40u;
	ps.push_back({"first bit in word 1", late});
	// First set bit at element 200 -- word 3.
	std::vector<u8> later(26, 0x00u);
	later[25] = 0x01u;
	ps.push_back({"first bit in word 3", later});
	return ps;
}

void SectionDifferential()
{
	printf("[P2/P3] the whole register image against rvv_ref::vmsetop\n");
	unsigned cells = 0;
	auto const ps = Patterns();
	std::vector<u8> const fill = {0x96u, 0x69u, 0xaau, 0x55u};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const vlmax = vlen / (8u << si);
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 64u)
				vls.push_back(65u);
			if (vlmax > 1u)
				vls.push_back(vlmax / 2u + 1u);
			for (auto const &o : kOps)
				for (auto const &p : ps)
					for (u32 vl : vls) {
						Configure(vlen, true);
						Built b({Vsetvli(kVT[si]), P(o.sub, kVs2, kVd),
							 kJalr});
						Translate(b);
						if (!ScanQir(b.region).nodes || !b.fn)
							continue;
						std::vector<u8> const initial =
						    BuildImage(p.bytes, fill);
						Folded const f = FoldUnit(b, initial, vl);
						if (!f.ok) {
							printf("  FAIL %s %s vlen=%u sew=%u vl=%u: "
							       "did not fold\n",
							       o.name, p.name, vlen, 8u << si, vl);
							++g_fail;
							continue;
						}
						std::vector<u8> const r =
						    RefPrefix(o.sub, vl, initial);
						if (f.mem != r) {
							unsigned shown = 0;
							for (u32 i = 0;
							     i < kVregBytes && shown < 2; ++i)
								if (f.mem[i] != r[i]) {
									printf("  FAIL %s %s vlen=%u "
									       "sew=%u vl=%u: vreg "
									       "byte %u emitted %02x, "
									       "reference %02x\n",
									       o.name, p.name, vlen,
									       8u << si, vl, i,
									       f.mem[i], r[i]);
									++shown;
									++g_fail;
								}
						}
						// [P3] bits at or beyond vl keep the fill.
						u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
						for (u32 e = vl;
						     e < rvv32::VLEN_MAX_BYTES * 8u; ++e) {
							u32 const got =
							    (f.mem[dst + e / 8u] >> (e % 8u)) & 1u;
							u32 const was =
							    (initial[dst + e / 8u] >> (e % 8u)) &
							    1u;
							if (got != was) {
								printf("  FAIL %s %s vlen=%u sew=%u "
								       "vl=%u: bit %u beyond vl "
								       "changed\n",
								       o.name, p.name, vlen,
								       8u << si, vl, e);
								++g_fail;
								break;
							}
						}
						++cells;
					}
		}
	printf("       %u cells compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [P4] THE THREE DISAGREE AT THE FIRST SET BIT, AND THAT IS THE WHOLE FAMILY.
//
// With the first set bit at element `k` and `vl` above it:
//   vmsbf sets [0, k)   -- bit k CLEAR
//   vmsif sets [0, k]   -- bit k SET
//   vmsof sets {k}      -- bit k SET, bit 0 clear when k > 0
// A route that computed `<=` for all three, or `<` for all three, would agree with the reference on
// an EMPTY mask and disagree only here.
void SectionDisagreement()
{
	printf("[P4] the three operations disagree at the first set bit\n");
	u32 const vlen = 512u, si = 2u, vlmax = vlen / (8u << si);
	unsigned checked = 0;
	for (u32 k : {0u, 1u, 7u, 8u}) {
		if (k >= vlmax)
			continue;
		std::vector<u8> src((k / 8u) + 1u, 0x00u);
		src[k / 8u] = (u8)(1u << (k % 8u));
		u8 bits[3] = {0, 0, 0};
		bool ok = true;
		for (u32 oi = 0; oi < 3; ++oi) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT[si]), P(kOps[oi].sub, kVs2, kVd), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn) {
				ok = false;
				break;
			}
			Folded const f = FoldUnit(b, BuildImage(src, {0x00u}), vlmax);
			if (!f.ok) {
				ok = false;
				break;
			}
			u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
			bits[oi] = (u8)((f.mem[dst + k / 8u] >> (k % 8u)) & 1u);
		}
		if (!ok) {
			printf("  FAIL k=%u: did not fold\n", k);
			++g_fail;
			continue;
		}
		// kOps order is vmsbf, vmsof, vmsif.
		if (bits[0] != 0u) {
			printf("  FAIL k=%u: vmsbf set the bit AT the first set bit\n", k);
			++g_fail;
		}
		if (bits[1] != 1u) {
			printf("  FAIL k=%u: vmsof did not set the bit at the first set bit\n", k);
			++g_fail;
		}
		if (bits[2] != 1u) {
			printf("  FAIL k=%u: vmsif did not set the bit at the first set bit\n", k);
			++g_fail;
		}
		++checked;
	}
	printf("       %u first-bit positions\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[P5] the emitted module verifies\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), P(o.sub, kVs2, kVd), kJalr});
				Translate(b);
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL %s vlen=%u sew=%u: %s\n", o.name, vlen,
					       8u << si, err.c_str());
					++g_fail;
				}
			}
}

} // namespace

int main()
{
	printf("rvv_llvm_mprefix_test: C6, the mask prefix family\n");
	SectionAdmission();
	SectionDifferential();
	SectionDisagreement();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
