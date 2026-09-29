// ORDER ITEM 4 (2026-09-19): THE CARRY/BORROW FAMILY ON THE LLVM ARM -- `vadc` and `vsbc`.
//
// THE SECOND OF THE FIVE NARROW NODES the fixed-point proposal names, and the one whose entry
// flagged that its second operand is `v0` as a REAL OPERAND rather than a mask. That distinction is
// what this file exists to pin: `vadc` writes EVERY body element and adds `v0[i]` as the carry-in,
// so an implementation that used `v0` as a write enable would leave half the destination untouched
// AND drop the carry from the other half -- two wrongs that a test using an all-ones `v0` would see
// neither of. Every section below uses a NON-TRIVIAL `v0`.
//
// SECTIONS:
//   [A1] Admission and inertness: the `vm == 0` encodings only (the `vm == 1` ones of this funct6
//        are `vmadc`/`vmsbc`, whose destination is a MASK register), `vd != v0`, no `v0` data
//        source, and `.vim` refused because this backend has no immediate broadcast.
//   [A2] THE DIFFERENTIAL against `rvv_ref::vadc` driven through a real `VectorState`, over
//        operands and carry patterns chosen so the carry changes the answer in both directions,
//        plus a pseudo-random sweep.
//   [A3] EVERY BODY ELEMENT IS WRITTEN. With a `v0` that is zero in some lanes, the destination's
//        pre-value must still be overwritten there -- which is the direct check that `v0` was used
//        as an operand and not as a predicate.
//   [A4] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
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
#include <memory>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVs2 = 8u, kVs1 = 9u, kVd = 10u;
constexpr u32 F3_VV = 0b000u, F3_VX = 0b100u, F3_VI = 0b011u;

constexpr u32 OpSat(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool masked = false)
{
	return (f6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4adc", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_adc = on;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_llvm_masked = false;
	config::rvv_llvm_restart = false;
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
	unsigned frames = 0, nodes = 0, hcalls = 0, stores = 0;
	int guard_kind = -1;
	int kind = -1;
	std::vector<u32> bases;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				break;
			case Op::_vchunkadc: {
				auto *n = static_cast<InstVChunkAdc *>(&ins);
				++q.nodes;
				q.kind = (int)n->sub;
				q.bases.push_back(n->element_base);
				break;
			}
			case Op::_vstatechunkstore: ++q.stores; break;
			case Op::_hcall: ++q.hcalls; break;
			default: break;
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
constexpr u32 kVlOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
u32 VRegOff(u32 r) { return kVregOff + r * rvv32::VLEN_MAX_BYTES; }

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
					continue;
				}
				auto *bc = llvm::dyn_cast<llvm::BitCastInst>(&I);
				if (!bc || !bc->getType()->isIntegerTy())
					continue;
				auto *st = llvm::dyn_cast<llvm::FixedVectorType>(
				    bc->getOperand(0)->getType());
				if (!st || !st->getElementType()->isIntegerTy(1))
					continue;
				auto *c0 = llvm::dyn_cast<llvm::Constant>(bc->getOperand(0));
				if (!c0)
					continue;
				llvm::APInt acc(st->getNumElements(), 0);
				bool all = true;
				for (unsigned k = 0; k < st->getNumElements(); ++k) {
					auto *el = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    c0->getAggregateElement(k));
					if (!el) { all = false; break; }
					if (el->isOne())
						acc.setBit(k);
				}
				if (!all)
					continue;
				bc->replaceAllUsesWith(llvm::ConstantInt::get(bc->getType(), acc));
				again = true;
			}
	}
}

struct Folded {
	bool ok = false;
	std::vector<u32> lanes;
};

Folded FoldUnit(Built &b, u32 lanes_total, u32 vl, std::vector<u32> const &va,
		std::vector<u32> const &vb, std::vector<u8> const &v0)
{
	Folded out;
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
			// v0's bits, read as a 16-bit group by the shared window helper.
			if (l->getType()->isIntegerTy(16) && o != ~0u && o >= kVregOff &&
			    o < kVregOff + rvv32::VLEN_MAX_BYTES) {
				u32 const bo = o - kVregOff;
				u32 const w = (u32)v0[bo] | ((u32)v0[bo + 1] << 8);
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), w));
				continue;
			}
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt)
				continue;
			bool const is_a = o >= VRegOff(kVs2) && o < VRegOff(kVs2) + 512u;
			bool const is_b = o >= VRegOff(kVs1) && o < VRegOff(kVs1) + 512u;
			if (!is_a && !is_b)
				continue;
			// THE CHUNK IS LOADED AS <N x i64>, NOT <N x i32>. A filter on a 32-bit lane
			// type skipped every source load and the whole body then stayed symbolic --
			// which is what "did not fold" meant on the first run of this file. The
			// constant is therefore built from the load's OWN lane width, packing the
			// SEW-32 elements the guest sees into whatever lanes the emitter chose.
			u32 const lane_bits = vt->getScalarSizeInBits();
			if (lane_bits % 32u != 0)
				continue;
			u32 const per_lane = lane_bits / 32u;
			u32 const base = (o - VRegOff(is_a ? kVs2 : kVs1)) / 4u;
			auto const &src = is_a ? va : vb;
			llvm::SmallVector<llvm::Constant *, 16> cv;
			for (u32 i = 0; i < vt->getNumElements(); ++i) {
				llvm::APInt w(lane_bits, 0);
				for (u32 k = 0; k < per_lane; ++k)
					w |= llvm::APInt(lane_bits, src[base + i * per_lane + k])
					     << (32u * k);
				cv.push_back(llvm::ConstantInt::get(vt->getElementType(), w));
			}
			l->replaceAllUsesWith(llvm::ConstantVector::get(cv));
		}
	FoldToFixpoint(fn);

	out.lanes.assign(lanes_total, 0);
	bool got = false;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
					u32 const o = StateOffset(ii->getArgOperand(1), state);
					if (o < VRegOff(kVd) || o >= VRegOff(kVd) + 512u)
						continue;
					auto *c = llvm::dyn_cast<llvm::Constant>(
					    ii->getArgOperand(0));
					if (!c)
						return out;
					u32 const base = (o - VRegOff(kVd)) / 4u;
					auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
					// The STORE is <N x i32> (its `active_sew` is 4), unlike the
					// loads; handled generically anyway so a width change here
					// cannot silently read the wrong elements.
					u32 const lb2 = vt->getScalarSizeInBits(), per = lb2 / 32u;
					for (u32 i = 0; i < vt->getNumElements(); ++i) {
						auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
						    c->getAggregateElement(i));
						if (!e)
							return out;
						llvm::APInt w = e->getValue().zextOrTrunc(lb2);
						for (u32 k = 0; k < per; ++k)
							out.lanes[base + i * per + k] =
							    (u32)(w.lshr(32u * k).getZExtValue() &
								  0xffffffffu);
					}
					got = true;
					continue;
				}
		}
	out.ok = got;
	return out;
}

// THE REFERENCE, driven through a real VectorState. `rvv_ref::vadc` is the function the helper arm
// calls, and `v0` is written as raw bytes so the carry pattern is the guest's own bit layout.
struct Ref {
	std::vector<u32> lanes;
};
Ref RefAdc(bool sub, u32 vl, u32 vlen, std::vector<u32> const &va, std::vector<u32> const &vb,
	   std::vector<u8> const &v0)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	vs->vl = vl;
	vs->vstart = 0;
	u32 const lanes = vlen / 32u;
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES && i < v0.size(); ++i)
		vs->vreg[0][i] = v0[i];
	for (u32 e = 0; e < lanes; ++e) {
		vs->elem_put(kVs2, e, 4, vlen, va[e]);
		vs->elem_put(kVs1, e, 4, vlen, vb[e]);
		vs->elem_put(kVd, e, 4, vlen, 0xdeadbeefu);
	}
	rvv32::rvv_ref::vadc(*vs, sub ? rvv32::VF6_VSBC : rvv32::VF6_VADC, rvv32::VSrc::VV, kVd, kVs2,
			     kVs1, 0, 0, /*carry_in=*/true, vlen, vl, 4);
	Ref r;
	for (u32 e = 0; e < lanes; ++e)
		r.lanes.push_back((u32)vs->elem_u(kVd, e, 4, vlen));
	return r;
}

struct KindRow { char const *name; u32 f6; bool sub; };
KindRow const kKinds[] = {
    {"vadc", rvv32::VF6_VADC, false},
    {"vsbc", rvv32::VF6_VSBC, true},
};

void SectionAdmission()
{
	printf("[A1] admission, the vm rule, the refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds)
			for (u32 f3 : {F3_VV, F3_VX}) {
				Configure(vlen, true);
				// `vm == 0` is the carry-in form; OpSat's `masked` argument clears the
				// bit, which for THIS family means "there is a carry-in", not "masked".
				Built b({Vsetvli(kVT_E32M1),
					 OpSat(k.f6, f3, kVs2, f3 == F3_VV ? kVs1 : 3u, kVd, true),
					 kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.stores, q.nodes);
				u32 const lanes = std::min(vlen / 8u, 64u) / 4u;
				for (u32 c = 0; c < q.bases.size(); ++c)
					CHECK_EQ(q.bases[c], c * lanes);
				Configure(vlen, false);
				Built o({Vsetvli(kVT_E32M1),
					 OpSat(k.f6, f3, kVs2, f3 == F3_VV ? kVs1 : 3u, kVd, true),
					 kJalr});
				Translate(o);
				CHECK_EQ(ScanQir(o.region).nodes, 0u);
				CHECK(ScanQir(o.region).hcalls >= 1u);
			}
	printf("       %u admitted kind/form/width cells\n", admitted);
	CHECK(admitted > 0);

	struct Ref2 { char const *why; u32 word; };
	Ref2 const rows[] = {
	    // `vm == 1` of this funct6 is `vmadc.vv`, whose destination is a MASK register.
	    {"vmadc (vm == 1, mask destination)",
	     OpSat(rvv32::VF6_VADC, F3_VV, kVs2, kVs1, kVd, false)},
	    {"vmadc funct6 proper", OpSat(rvv32::VF6_VMADC, F3_VV, kVs2, kVs1, kVd, true)},
	    {"vmsbc funct6 proper", OpSat(rvv32::VF6_VMSBC, F3_VV, kVs2, kVs1, kVd, true)},
	    {"vd == v0 (RVV 1.0 12.4 reserves it)",
	     OpSat(rvv32::VF6_VADC, F3_VV, kVs2, kVs1, 0u, true)},
	    {"vs2 == v0 (v0 is read at EEW 1 as the carry)",
	     OpSat(rvv32::VF6_VADC, F3_VV, 0u, kVs1, kVd, true)},
	    {"vs1 == v0", OpSat(rvv32::VF6_VADC, F3_VV, kVs2, 0u, kVd, true)},
	    {".vim (no immediate broadcast in this backend)",
	     OpSat(rvv32::VF6_VADC, F3_VI, kVs2, 3u, kVd, true)},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
			Translate(b);
			if (ScanQir(b.region).nodes) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
			CHECK(ScanQir(b.region).hcalls >= 1u);
		}
}

void RunDifferential(char const *label, std::vector<u32> const &pa, std::vector<u32> const &pb,
		     std::vector<u8> const &v0, unsigned *cells)
{
	// 1024 AND 2048 ARE NOT DECORATION. At SEW 32 a unit is `min(VLEN/8, 64)` bytes, so a frame
	// has more than ONE unit only above VLEN 512 -- and with one unit, "the carry came from unit
	// 0's window" and "the carry came from this unit's window" are the same statement. A mutation
	// that hard-codes unit 0 survived this file until these two widths were added.
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			u32 const total = vlen / 32u;
			for (u32 vl : {total, total / 2u}) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT_E32M1),
					 OpSat(k.f6, F3_VV, kVs2, kVs1, kVd, true), kJalr});
				Translate(b);
				if (!ScanQir(b.region).nodes || !b.fn)
					continue;
				std::vector<u32> va, vb;
				for (u32 e = 0; e < total; ++e) {
					va.push_back(pa[e % pa.size()]);
					vb.push_back(pb[e % pb.size()]);
				}
				Folded const f = FoldUnit(b, total, vl, va, vb, v0);
				if (!f.ok) {
					printf("  FAIL %s %s vlen=%u vl=%u: did not fold\n", label,
					       k.name, vlen, vl);
					++g_fail;
					continue;
				}
				Ref const r = RefAdc(k.sub, vl, vlen, va, vb, v0);
				for (u32 e = 0; e < vl; ++e) {
					if (f.lanes[e] != r.lanes[e]) {
						printf("  FAIL %s %s vlen=%u vl=%u e=%u a=%08x "
						       "b=%08x c=%d: emitted %08x, reference %08x\n",
						       label, k.name, vlen, vl, e, va[e], vb[e],
						       (int)((v0[e / 8] >> (e % 8)) & 1), f.lanes[e],
						       r.lanes[e]);
						++g_fail;
					}
					++*cells;
				}
				// [A3] EVERY BODY ELEMENT IS WRITTEN, including the ones whose carry
				// bit is zero. `0xdeadbeef` surviving in an active lane would be the
				// signature of `v0` used as a write enable.
				for (u32 e = 0; e < vl; ++e)
					if (f.lanes[e] == 0xdeadbeefu && r.lanes[e] != 0xdeadbeefu) {
						printf("  FAIL %s %s vlen=%u vl=%u e=%u: the lane was "
						       "not written -- v0 used as a predicate?\n",
						       label, k.name, vlen, vl, e);
						++g_fail;
					}
			}
		}
}

void SectionDifferential()
{
	printf("[A2/A3] every lane against rvv_ref::vadc, with a NON-TRIVIAL v0\n");
	unsigned cells = 0;
	// Operands where the carry changes the answer in both directions: sums at the wrap boundary
	// and differences at zero.
	std::vector<u32> const a = {0xffffffffu, 0x00000000u, 0x7fffffffu, 0x80000000u,
				    0x00000001u, 0xfffffffeu, 0x12345678u, 0xdeadbeefu,
				    0x00000000u, 0xffffffffu, 0x40000000u, 0xc0000000u,
				    0x00000005u, 0x00000004u, 0x7ffffffeu, 0x80000001u};
	std::vector<u32> const b = {0x00000000u, 0xffffffffu, 0x00000001u, 0xffffffffu,
				    0xffffffffu, 0x00000001u, 0x9abcdef0u, 0x0badf00du,
				    0x00000001u, 0x00000000u, 0x40000000u, 0xc0000000u,
				    0x00000005u, 0x00000005u, 0x00000001u, 0x00000001u};
	struct Pat { char const *name; u8 (*fill)(u32); };
	Pat const pats[] = {
	    {"alternating", [](u32) -> u8 { return 0x55; }},
	    {"zeros", [](u32) -> u8 { return 0x00; }},
	    {"ones", [](u32) -> u8 { return 0xff; }},
	    {"byte-index", [](u32 i) -> u8 { return (u8)(i * 37u + 1u); }},
	};
	for (auto const &p : pats) {
		std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0);
		for (u32 i = 0; i < v0.size(); ++i)
			v0[i] = p.fill(i);
		RunDifferential(p.name, a, b, v0, &cells);
	}
	u64 x = 0x2545f4914f6cdd1dull;
	std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0);
	for (unsigned round = 0; round < 16; ++round) {
		std::vector<u32> pa, pb;
		for (unsigned i = 0; i < 16; ++i) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			pa.push_back((u32)x);
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			pb.push_back((u32)x);
		}
		for (u32 i = 0; i < v0.size(); ++i) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			v0[i] = (u8)x;
		}
		RunDifferential("sweep", pa, pb, v0, &cells);
	}
	printf("       %u lanes compared against the reference\n", cells);
	CHECK(cells > 0);
}

void SectionVerify()
{
	printf("[A4] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpSat(k.f6, F3_VV, kVs2, kVs1, kVd, true), kJalr});
			Translate(b);
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL %s vlen=%u: %s\n", k.name, vlen, err.c_str());
				++g_fail;
			}
		}
}

} // namespace

int main()
{
	printf("rvv_llvm_adc_test: order item 4, the carry/borrow family\n");
	SectionAdmission();
	SectionDifferential();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
