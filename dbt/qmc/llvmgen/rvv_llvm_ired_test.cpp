// C6 (2026-09-19): THE INTEGER REDUCTIONS ON THE LLVM ARM -- `vred*`.
//
// THE FIRST CROSS-ELEMENT FAMILY here that is not an ordered FP reduction, and the distinction that
// makes it tractable is the one this file is built around: all eight operations are ASSOCIATIVE AND
// COMMUTATIVE, so the group may be folded chunk by chunk and the partials combined in any order.
// `vfredosum`, which lives beside it in the emitter, may not do that at all.
//
// THE HARNESS WORKS ON A MEMORY IMAGE, as the narrowing clip's does, because this node is an
// offset-carrying `InstNoOperands` that loads its own source and stores its own destination. Every
// state load in the vector-register window is served from a byte image of `vreg` and every store is
// written back into it, so the harness reproduces MEMORY and the node's own offsets decide what
// lands where. Comparing the WHOLE image is what catches a scalar result written to the wrong
// element or the wrong register -- neither of which a check on `vd[0]` alone would see.
//
// SECTIONS:
//   [R1] Admission and inertness: all eight funct6 values at four SEWs and five VLENs, masked
//        refused, the OPIVV encoding refused, and the route inert with its flag off.
//   [R2] THE DIFFERENTIAL against `rvv_ref::vred` through a real `VectorState`, over all eight
//        operations, four SEWs, five VLENs and several `vl` values.
//   [R3] `vl == 0` WRITES NOTHING. RVV 1.0 makes the reduction a no-op rather than a seed store,
//        and storing the seed is the natural-looking error -- it is what a loop whose trip count
//        reached zero would hit.
//   [R4] THE SEED PARTICIPATES. Changing only `vs1[0]` must change the result; a route that
//        dropped the seed would pass any differential whose seed happened to be the identity.
//   [R5] The module verifies.

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

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6ired", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_ired = on;
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
	unsigned frames = 0, nodes = 0, hcalls = 0;
	int guard_kind = -1;
	unsigned op = 99, sew = 0, vlmax = 0;
	bool masked = true;
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
			} else if (ins.GetOpcode() == Op::_vreducenative) {
				auto *n = static_cast<InstVReduce *>(&ins);
				++q.nodes;
				q.op = n->op;
				q.sew = n->sew;
				q.vlmax = n->vlmax;
				q.masked = n->masked;
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

std::vector<u8> BuildImage(u32 vlen, u32 sew, std::vector<u64> const &data, u64 seed, u32 lanes)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	for (u32 e = 0; e < lanes; ++e) {
		vs->elem_put(kVs2, e, sew, vlen, data[e]);
		vs->elem_put(kVd, e, sew, vlen, 0xdeadbeefcafef00dull);
		vs->elem_put(kVs1, e, sew, vlen, 0xa5a5a5a5a5a5a5a5ull);
	}
	vs->elem_put(kVs1, 0, sew, vlen, seed);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

std::vector<u8> RefRed(u32 f6, u32 vl, u32 vlen, u32 sew, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::vred(*vs, f6, kVd, kVs2, kVs1, /*vm=*/true, vlen, vl, sew);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

struct OpRow { char const *name; u32 f6; };
OpRow const kOps[] = {
    {"vredsum", 0u},  {"vredand", 1u},  {"vredor", 2u},   {"vredxor", 3u},
    {"vredminu", 4u}, {"vredmin", 5u},  {"vredmaxu", 6u}, {"vredmax", 7u},
};

void SectionAdmission()
{
	printf("[R1] admission, the eight operations, refusals, and inertness\n");
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
				CHECK_EQ(q.nodes, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				// EACH FUNCT6 CARRIES ITS OWN OPERATION. A swapped pair here would
				// silently compute a different reduction.
				CHECK_EQ(q.op, o.f6);
				CHECK_EQ(q.sew, 1u << si);
				CHECK_EQ(q.masked, false);
				CHECK_EQ(q.vlmax, vlen / (8u << si));
				Configure(vlen, false);
				Built off({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(off);
				CHECK_EQ(ScanQir(off.region).nodes, 0u);
				CHECK(ScanQir(off.region).hcalls >= 1u);
			}
	printf("       %u admitted op/SEW/width cells\n", admitted);
	// Eight operations x four SEWs x five widths; a missing cell makes a row below vacuous.
	CHECK_EQ(admitted, 160u);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    {"masked (vm == 0)", R(0u, F3_MV, kVs2, kVs1, kVd, false)},
	    {"OPIVV funct3 (a different instruction)", R(0u, F3_IV, kVs2, kVs1, kVd)},
	    {"funct6 past the reduction family", R(8u, F3_MV, kVs2, kVs1, kVd)},
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

void RunCell(char const *label, u32 f6, u32 vlen, u32 si, u32 vl, std::vector<u64> const &data,
	     u64 seed, unsigned *cells)
{
	u32 const sew = 1u << si;
	Configure(vlen, true);
	Built b({Vsetvli(kVT[si]), R(f6, F3_MV, kVs2, kVs1, kVd), kJalr});
	Translate(b);
	if (!ScanQir(b.region).nodes || !b.fn)
		return;
	u32 const lanes = vlen / (8u * sew);
	std::vector<u8> const initial = BuildImage(vlen, sew, data, seed, lanes);
	Folded const f = FoldUnit(b, initial, vl);
	if (!f.ok) {
		printf("  FAIL %s vlen=%u sew=%u vl=%u: did not fold\n", label, vlen, sew * 8u, vl);
		++g_fail;
		return;
	}
	std::vector<u8> const r = RefRed(f6, vl, vlen, sew, initial);
	if (f.mem != r) {
		unsigned shown = 0;
		for (u32 i = 0; i < kVregBytes && shown < 3; ++i)
			if (f.mem[i] != r[i]) {
				printf("  FAIL %s vlen=%u sew=%u vl=%u: vreg byte %u (v%u+%u) "
				       "emitted %02x, reference %02x\n",
				       label, vlen, sew * 8u, vl, i, i / rvv32::VLEN_MAX_BYTES,
				       i % rvv32::VLEN_MAX_BYTES, f.mem[i], r[i]);
				++shown;
				++g_fail;
			}
	}
	++*cells;
}

void SectionDifferential()
{
	printf("[R2] the whole register image against rvv_ref::vred\n");
	unsigned cells = 0;
	// Values spanning both signs at every SEW, so the signed and unsigned min/max pairs are
	// genuinely distinguished: at SEW 8 a lane of 0x80 is -128 signed and 128 unsigned.
	std::vector<u64> const dp = {
	    0x0000000000000000ull, 0xffffffffffffffffull, 0x8000000000000000ull,
	    0x7fffffffffffffffull, 0x0123456789abcdefull, 0xfedcba9876543210ull,
	    0x0000000000000001ull, 0x000000000000007full, 0x0000000000000080ull,
	    0x00000000000000ffull, 0x5555555555555555ull, 0xaaaaaaaaaaaaaaaaull,
	    0x0000000100000001ull, 0xffff0000ffff0000ull, 0x0000ffff0000ffffull,
	    0x8000800080008000ull};
	u64 const seeds[] = {0x0000000000000003ull, 0xffffffffffffffffull, 0x8000000000000000ull};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, total = vlen / (8u * sew);
			std::vector<u64> data(total);
			for (u32 e = 0; e < total; ++e)
				data[e] = dp[e % dp.size()] ^ ((u64)e * 0x9e3779b97f4a7c15ull);
			for (auto const &o : kOps)
				for (u64 seed : seeds)
					// vl values: full, half, one, and a value that is not a
					// multiple of the chunk's lane count.
					for (u32 vl : {total, total / 2u, 1u, total > 3u ? 3u : 1u})
						RunCell(o.name, o.f6, vlen, si, vl, data, seed,
							&cells);
		}
	printf("       %u cells compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [R3] `vl == 0` WRITES NOTHING.
//
// The reference returns early and leaves `vd[0]` alone. A route that stored the seed, or the
// identity, or anything at all would differ here and NOWHERE ELSE -- every other `vl` writes.
void SectionZeroVl()
{
	printf("[R3] vl == 0 leaves vd untouched\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, total = vlen / (8u * sew);
			std::vector<u64> data(total);
			for (u32 e = 0; e < total; ++e)
				data[e] = 0x0123456789abcdefull ^ e;
			for (auto const &o : kOps) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), R(o.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
				Translate(b);
				if (!ScanQir(b.region).nodes || !b.fn)
					continue;
				std::vector<u8> const initial =
				    BuildImage(vlen, sew, data, 0x37u, total);
				Folded const f = FoldUnit(b, initial, 0u);
				if (!f.ok) {
					printf("  FAIL %s vlen=%u sew=%u: did not fold\n", o.name,
					       vlen, sew * 8u);
					++g_fail;
					continue;
				}
				// Against the initial image directly, not only against the
				// reference: this states the property rather than deferring it.
				if (f.mem != initial) {
					printf("  FAIL %s vlen=%u sew=%u: vl == 0 wrote to vd\n",
					       o.name, vlen, sew * 8u);
					++g_fail;
				}
				CHECK(RefRed(o.f6, 0u, vlen, sew, initial) == initial);
				++checked;
			}
		}
	printf("       %u zero-vl cells\n", checked);
	CHECK(checked > 0);
}

// [R4] THE SEED PARTICIPATES.
//
// `vs1[0]` is an operand of the reduction, not a placeholder. Two runs differing ONLY in the seed
// must differ in the result -- for `vredsum` always, and for the others on a seed chosen to be
// outside the data's range so it cannot be absorbed.
void SectionSeed()
{
	printf("[R4] the seed is an operand: changing it changes the result\n");
	u32 const vlen = 256u, si = 2u, sew = 4u, total = vlen / (8u * sew);
	std::vector<u64> data(total);
	for (u32 e = 0; e < total; ++e)
		data[e] = 0x00001000ull + e; // small positive values at SEW 32
	struct SeedPair { u32 f6; u64 a, b; };
	// For each operation a pair the reduction cannot absorb: the seed decides the answer.
	SeedPair const pairs[] = {
	    {0u, 0x00000001ull, 0x00000002ull},	 // sum
	    // AND: the second seed must clear a bit the DATA still has. 0x0000ffff does not --
	    // every element is 0x00001000 + e, so the data's own AND already has zero above bit
	    // 15 and both seeds give the same answer. That pair made [R4] fail against a correct
	    // route; it was the pair that was wrong, not the assertion. 0xffffefff clears bit 12,
	    // which every element sets.
	    {1u, 0xffffffffull, 0xffffefffull},	 // and
	    {2u, 0x00000000ull, 0xffff0000ull},	 // or
	    {3u, 0x00000000ull, 0x0f0f0f0full},	 // xor
	    {4u, 0xffffffffull, 0x00000001ull},	 // minu: the second is below every element
	    {5u, 0x7fffffffull, 0x80000000ull},	 // min: the second is the signed minimum
	    {6u, 0x00000000ull, 0xffffffffull},	 // maxu
	    {7u, 0x80000000ull, 0x7fffffffull},	 // max
	};
	unsigned checked = 0;
	for (auto const &p : pairs) {
		Configure(vlen, true);
		Built ba({Vsetvli(kVT[si]), R(p.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
		Translate(ba);
		if (!ScanQir(ba.region).nodes || !ba.fn)
			continue;
		Folded const fa = FoldUnit(ba, BuildImage(vlen, sew, data, p.a, total), total);
		Configure(vlen, true);
		Built bb({Vsetvli(kVT[si]), R(p.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
		Translate(bb);
		Folded const fb = FoldUnit(bb, BuildImage(vlen, sew, data, p.b, total), total);
		if (!fa.ok || !fb.ok) {
			printf("  FAIL f6=%u: did not fold\n", p.f6);
			++g_fail;
			continue;
		}
		u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
		bool same = true;
		for (u32 k = 0; k < sew; ++k)
			if (fa.mem[dst + k] != fb.mem[dst + k])
				same = false;
		if (same) {
			printf("  FAIL f6=%u: two different seeds gave the same result -- the "
			       "seed is not reaching the reduction\n",
			       p.f6);
			++g_fail;
		}
		++checked;
	}
	printf("       %u seed pairs\n", checked);
	CHECK_EQ(checked, 8u);
}

// [R6] THE IDENTITY OF AN INACTIVE LANE MUST NOT BECOME THE ANSWER.
//
// ADDED AFTER THE MUTATION GATE FOUND THE HOLE. Setting `vredmin`'s neutral element to 0 instead of
// the signed maximum SURVIVED [R2] entirely, and the reason is worth stating: [R2]'s data spans
// both signs at every SEW, so a genuinely negative element is almost always active and a spurious
// 0 among the inactive lanes is absorbed by the minimum. At `vl == vlmax` there are no inactive
// lanes at all.
//
// Here `vl` is `vlmax - 1`, so EXACTLY ONE lane is inactive, and the data for each operation is
// chosen so that one lane holding the WRONG identity changes the result: all-positive elements for
// the signed minimum, all-negative for the signed maximum, and for the bitwise and additive
// operations any identity but the right one perturbs the fold.
void SectionInactiveIdentity()
{
	printf("[R6] a wrong identity for the inactive lanes must change the answer\n");
	struct Row { u32 f6; u64 v; u64 seed; char const *why; };
	Row const rows[] = {
	    {0u, 0x00000001ull, 0x00000000ull, "sum: any non-zero identity is added"},
	    {1u, 0x00001010ull, 0xffffffffull, "and: a zero identity clears everything"},
	    {2u, 0x00001010ull, 0x00000000ull, "or: an all-ones identity saturates"},
	    {3u, 0x00001010ull, 0x00000000ull, "xor: one lane of a wrong identity flips it in"},
	    {4u, 0x00001010ull, 0xfffffffeull, "minu: a zero identity wins outright"},
	    {5u, 0x00001010ull, 0x7ffffffeull, "min: all elements positive, so 0 would win"},
	    {6u, 0x00001010ull, 0x00000001ull, "maxu: an all-ones identity wins outright"},
	    {7u, 0xfffff010ull, 0x80000001ull, "max: all elements negative, so 0 would win"},
	};
	unsigned checked = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u})
		for (u32 si : {0u, 2u}) { // SEW 8 and 32
			u32 const sew = 1u << si, total = vlen / (8u * sew);
			if (total < 2u)
				continue;
			for (auto const &r : rows) {
				std::vector<u64> data(total, r.v);
				unsigned cells = 0;
				RunCell(r.why, r.f6, vlen, si, total - 1u, data, r.seed, &cells);
				checked += cells;
			}
		}
	printf("       %u inactive-identity cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[R5] the emitted module verifies\n");
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
	printf("rvv_llvm_ired_test: C6, the integer reductions\n");
	SectionAdmission();
	SectionDifferential();
	SectionZeroVl();
	SectionSeed();
	SectionInactiveIdentity();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
