// C6 (2026-09-19): THE MASK LOGICAL OPERATIONS ON THE LLVM ARM -- `vmand` and its seven siblings.
//
// WHAT MAKES THIS FAMILY DIFFERENT FROM EVERY OTHER ROUTE IN THIS CHECKPOINT: a mask register is
// ONE register whatever the LMUL, the operations are bit-wise over it, and SEW does not participate
// at all. There is no chunk geometry. The only element-indexed quantity is WHICH BITS the
// instruction is allowed to change -- and bits at or beyond `vl` are UNDISTURBED, so the
// destination word is a blend rather than a store of the computed value.
//
// THE BIT ORDER IS THE ONE THING THAT COULD BE WRONG INVISIBLY. LLVM's bitcast from `<64 x i1>`
// puts vector element 0 in the LEAST significant bit on a little-endian target; the guest's
// `mask_get` reads bit `e % 8` of byte `e / 8`. They agree -- but a test that only ever used
// symmetric masks, or `vl` at a multiple of 64, would not notice if they did not. Every section
// below uses an asymmetric bit pattern and `vl` values that fall INSIDE a word.
//
// SECTIONS:
//   [L1] Admission and inertness: all eight funct6 values at several VLENs and SEWs, one node per
//        64-bit word with the right first-bit index, exactly one `vstart` write per frame, and the
//        route inert with its flag off.
//   [L2] THE DIFFERENTIAL against `rvv_ref::vmlogic` through a real `VectorState`, comparing the
//        WHOLE register image, over all eight operations and `vl` values inside, at and past a
//        word boundary.
//   [L3] BITS BEYOND `vl` ARE UNDISTURBED -- asserted against the initial image directly, not only
//        against the reference.
//   [L4] `vmandn` AND `vmorn` ARE NOT SYMMETRIC. Six of the eight are, so an operand swap is
//        invisible in them; this section runs the two that can see it, with sources that differ.
//   [L5] The module verifies.

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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6mlogic", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_mlogic = on;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = true;
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

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vmasklogic) {
				auto *n = static_cast<InstVMaskLogic *>(&ins);
				++q.nodes;
				q.op = n->op;
				q.bases.push_back(n->base);
				q.finishes += n->finish;
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

// A mask register is written as raw BYTES, not through elem_put: its EEW is 1 and the guest's own
// accessor is bit-indexed, so bytes are the honest unit here.
std::vector<u8> BuildImage(std::vector<u8> const &s2, std::vector<u8> const &s1,
			   std::vector<u8> const &d)
{
	std::vector<u8> mem(kVregBytes, 0);
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i) {
		mem[kVs2 * rvv32::VLEN_MAX_BYTES + i] = s2[i % s2.size()];
		mem[kVs1 * rvv32::VLEN_MAX_BYTES + i] = s1[i % s1.size()];
		mem[kVd * rvv32::VLEN_MAX_BYTES + i] = d[i % d.size()];
	}
	return mem;
}

std::vector<u8> RefLogic(u32 f6, u32 vl, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::vmlogic(*vs, f6, kVd, kVs2, kVs1, vl);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

struct OpRow { char const *name; u32 f6; };
OpRow const kOps[] = {
    {"vmandn", 24u}, {"vmand", 25u},  {"vmor", 26u},	{"vmxor", 27u},
    {"vmorn", 28u},  {"vmnand", 29u}, {"vmnor", 30u},	{"vmxnor", 31u},
};

void SectionAdmission()
{
	printf("[L1] admission, the eight operations, word geometry, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.op, o.f6 - F6_BASE);
				// ONE NODE PER 64-BIT WORD OF VLMAX, and VLMAX here is SEW-derived
				// even though the destination is not: `vl` counts ELEMENTS.
				u32 const vlmax = vlen / (8u << si);
				CHECK_EQ(q.nodes, (vlmax + 63u) / 64u);
				for (u32 c = 0; c < q.bases.size(); ++c)
					CHECK_EQ(q.bases[c], c * 64u);
				// Exactly one vstart write per frame, on the last word.
				CHECK_EQ(q.finishes, 1u);
				Configure(vlen, false);
				Built off({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(off);
				CHECK_EQ(ScanQir(off.region).nodes, 0u);
				CHECK(ScanQir(off.region).hcalls >= 1u);
			}
	printf("       %u admitted op/SEW/width cells\n", admitted);
	CHECK_EQ(admitted, 160u);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    // The vm bit is part of the opcode for this family; a cleared bit is not this family.
	    {"vm == 0 (not a mask-logical encoding)", R(25u, F3_MV, kVs2, kVs1, kVd, false)},
	    {"OPIVV funct3", R(25u, F3_IV, kVs2, kVs1, kVd)},
	    {"funct6 below the family", R(23u, F3_MV, kVs2, kVs1, kVd)},
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

// ASYMMETRIC SOURCE PATTERNS. A mask test with equal or complementary sources cannot see an
// operand swap, and one whose bytes are all 0x00/0xff cannot see a bit-order error.
std::vector<u8> const kS2 = {0xa5u, 0x3cu, 0x0fu, 0xf0u, 0x01u, 0x80u, 0x7eu, 0xdbu};
std::vector<u8> const kS1 = {0x5au, 0xc3u, 0x33u, 0x99u, 0xffu, 0x00u, 0x18u, 0x24u};
std::vector<u8> const kVdFill = {0x96u, 0x69u, 0xaau, 0x55u, 0x11u, 0xeeu, 0x42u, 0xbdu};

void RunCell(char const *label, u32 f6, u32 vlen, u32 si, u32 vl, unsigned *cells)
{
	Configure(vlen, true);
	Built b({Vsetvli(kVT[si]), R(f6, F3_MV, kVs2, kVs1, kVd), kJalr});
	Translate(b);
	if (!ScanQir(b.region).nodes || !b.fn)
		return;
	std::vector<u8> const initial = BuildImage(kS2, kS1, kVdFill);
	Folded const f = FoldUnit(b, initial, vl);
	if (!f.ok) {
		printf("  FAIL %s vlen=%u sew=%u vl=%u: did not fold\n", label, vlen, 8u << si, vl);
		++g_fail;
		return;
	}
	std::vector<u8> const r = RefLogic(f6, vl, initial);
	if (f.mem != r) {
		unsigned shown = 0;
		for (u32 i = 0; i < kVregBytes && shown < 3; ++i)
			if (f.mem[i] != r[i]) {
				printf("  FAIL %s vlen=%u sew=%u vl=%u: vreg byte %u (v%u+%u) "
				       "emitted %02x, reference %02x\n",
				       label, vlen, 8u << si, vl, i, i / rvv32::VLEN_MAX_BYTES,
				       i % rvv32::VLEN_MAX_BYTES, f.mem[i], r[i]);
				++shown;
				++g_fail;
			}
	}
	++*cells;
}

void SectionDifferential()
{
	printf("[L2] the whole register image against rvv_ref::vmlogic\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const vlmax = vlen / (8u << si);
			// `vl` INSIDE a word, AT a word boundary, one, zero and full. A test that
			// only used multiples of 64 could not see a wrong blend within a word --
			// which is the one place the bit order is observable.
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 64u)
				vls.push_back(64u);
			if (vlmax > 65u)
				vls.push_back(65u);
			if (vlmax > 1u)
				vls.push_back(vlmax - 1u);
			for (auto const &o : kOps)
				for (u32 vl : vls)
					RunCell(o.name, o.f6, vlen, si, vl, &cells);
		}
	printf("       %u cells compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [L3] BITS AT OR BEYOND `vl` ARE UNDISTURBED.
//
// Stated against the INITIAL image, not only against the reference: every byte of `vd` from bit
// `vl` upwards must still hold the fill. A route that stored the whole computed word would pass a
// differential only if the reference did the same, and the point is that it does not.
void SectionUndisturbed()
{
	printf("[L3] bits at or beyond vl keep their prior value\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const vlmax = vlen / (8u << si);
			if (vlmax < 8u)
				continue;
			u32 const vl = vlmax / 2u + 3u; // deliberately not a multiple of 8
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(b);
				if (!ScanQir(b.region).nodes || !b.fn)
					continue;
				std::vector<u8> const initial = BuildImage(kS2, kS1, kVdFill);
				Folded const f = FoldUnit(b, initial, vl);
				if (!f.ok) {
					printf("  FAIL %s vlen=%u sew=%u: did not fold\n", o.name,
					       vlen, 8u << si);
					++g_fail;
					continue;
				}
				u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
				for (u32 e = vl; e < rvv32::VLEN_MAX_BYTES * 8u; ++e) {
					u32 const got = (f.mem[dst + e / 8u] >> (e % 8u)) & 1u;
					u32 const was = (initial[dst + e / 8u] >> (e % 8u)) & 1u;
					if (got != was) {
						printf("  FAIL %s vlen=%u sew=%u vl=%u: bit %u "
						       "beyond vl changed %u -> %u\n",
						       o.name, vlen, 8u << si, vl, e, was, got);
						++g_fail;
						break;
					}
				}
				++checked;
			}
		}
	printf("       %u undisturbed-tail cells\n", checked);
	CHECK(checked > 0);
}

// [L4] `vmandn` AND `vmorn` SEE AN OPERAND SWAP; THE OTHER SIX DO NOT.
//
// `vmandn` is vs2 AND NOT vs1. Running it with the sources exchanged must give a DIFFERENT result,
// and the same run through the reference confirms which of the two is right. The six symmetric
// operations are listed here too -- with the expectation that they do NOT change -- so the section
// states the asymmetry rather than merely exercising it.
void SectionOperandOrder()
{
	printf("[L4] vmandn and vmorn are not symmetric; the other six are\n");
	u32 const vlen = 256u, si = 2u, vlmax = vlen / (8u << si);
	unsigned checked = 0;
	for (auto const &o : kOps) {
		bool const asymmetric = o.f6 == 24u || o.f6 == 28u; // vmandn, vmorn
		Configure(vlen, true);
		Built a({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
		Translate(a);
		if (!ScanQir(a.region).nodes || !a.fn)
			continue;
		Folded const fa = FoldUnit(a, BuildImage(kS2, kS1, kVdFill), vlmax);
		Configure(vlen, true);
		Built c({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs1, kVs2, kVd), kJalr});
		Translate(c);
		Folded const fb = FoldUnit(c, BuildImage(kS2, kS1, kVdFill), vlmax);
		if (!fa.ok || !fb.ok) {
			printf("  FAIL %s: did not fold\n", o.name);
			++g_fail;
			continue;
		}
		bool same = true;
		u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
		for (u32 i = 0; i < (vlmax + 7u) / 8u; ++i)
			if (fa.mem[dst + i] != fb.mem[dst + i])
				same = false;
		if (asymmetric && same) {
			printf("  FAIL %s: exchanging the sources changed nothing -- the operand "
			       "order is not reaching the operation\n",
			       o.name);
			++g_fail;
		}
		if (!asymmetric && !same) {
			printf("  FAIL %s: this operation is symmetric but exchanging the sources "
			       "changed the result\n",
			       o.name);
			++g_fail;
		}
		++checked;
	}
	printf("       %u operand-order cells\n", checked);
	CHECK_EQ(checked, 8u);
}

// [L6] `vstart` IS CLEARED IN THE EMITTED IR.
//
// ADDED AFTER THE MUTATION GATE FOUND THE HOLE. `[L1]` checks the QIR node's `finish` FLAG, which
// is not the same claim: an emitter that ignored the flag would still set it. The mutation that
// drops the `vstart` store survived every other section, because the fold harness reads the vector
// register file and nothing else.
//
// IT IS MEASURED AS A DIFFERENCE, ROUTES-ON MINUS ROUTES-OFF, and that is not fussiness. The
// program also contains a `vsetvli`, which has its OWN LLVM route and clears `vstart` itself -- but
// only at SEW 32, where that route is admitted. Counting stores in the whole function therefore
// gives 2 at SEW 32 and 1 elsewhere, and an absolute expectation would have been wrong for three
// of the twelve configurations for a reason that has nothing to do with this family. The routes-off
// arm contains the same `vsetvli` and no mask-logic frame, so the difference is exactly this
// family's contribution.
void SectionVstart()
{
	printf("[L6] vstart is cleared once per frame (routes-on minus routes-off)\n");
	u32 const kVstartOff =
	    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	auto count = [&](Built &b) {
		unsigned zeroes = 0;
		if (!b.fn)
			return zeroes;
		llvm::Value *state = b.fn->getArg(0);
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
				if (!st || StateOffset(st->getPointerOperand(), state) != kVstartOff)
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
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built on({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(on);
				if (!ScanQir(on.region).nodes || !on.fn)
					continue;
				Configure(vlen, false);
				Built off({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(off);
				unsigned const a = count(on), b = count(off);
				if (a != b + 1u) {
					printf("  FAIL %s vlen=%u sew=%u: routes-on has %u stores of "
					       "0 to vec.vstart and routes-off has %u; the frame "
					       "should add exactly one\n",
					       o.name, vlen, 8u << si, a, b);
					++g_fail;
				}
				++checked;
			}
	printf("       %u vstart cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[L5] the emitted module verifies\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
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
	printf("rvv_llvm_mlogic_test: C6, the mask logical operations\n");
	SectionAdmission();
	SectionDifferential();
	SectionUndisturbed();
	SectionOperandOrder();
	SectionVstart();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
