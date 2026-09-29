// ORDER ITEM 4 (2026-09-19): THE SATURATING INTEGER ADD/SUB FAMILY ON THE LLVM ARM.
//
// THE FIRST OF THE FIVE NARROW NODES the fixed-point proposal names. The family was recorded as
// BLOCKED because QCG emits it -- together with the averaging, round-shift, clip and
// fractional-multiply families -- through `vchunkpartialalu`, a 52-kind mega-node this backend does
// not lower. The proposal was one node per semantic family so that each could be reviewed on its
// own saturation rule; this file is that review for the first one.
//
// THE CENTRAL CHECK IS A DIFFERENTIAL AGAINST THE REFERENCE `rvv_ref::vsatadd` ITSELF, driven
// through a real `VectorState`, not against an expectation written here. Saturation is exactly the
// kind of semantics the plan says must not be approximated, and a hand table would encode one
// reading of the spec twice.
//
// SECTIONS:
//   [S1] Admission, frame shape and inertness, including the ISA rule that `.vi` has only the two
//        ADDING forms -- `vssubu.vi` and `vssub.vi` are not defined and must keep the helper.
//   [S2] THE FOUR KINDS ARE FOUR DIFFERENT INTRINSICS. A mis-selected pair (signed where unsigned
//        was meant, or add where sub was) produces perfectly valid IR with different bounds, so the
//        intrinsic actually emitted is read out of the module and matched to the funct6.
//   [S3] THE DIFFERENTIAL: every lane value against `rvv_ref::vsatadd`, over operands chosen so
//        every bound is reached from both directions, plus a pseudo-random sweep.
//   [S4] `vxsat` IS STICKY AND DERIVED. It must be ORed, never assigned -- a frame in which nothing
//        saturates must leave a previously-set flag alone -- and it must be set exactly when the
//        reference sets it, which is checked against the reference's own `vs.vxsat`.
//   [S5] INACTIVE LANES CANNOT SATURATE INTO THE FLAG: with `vl` short, a lane beyond it whose
//        operands overflow must contribute nothing.
//   [S6] The module verifies.

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

// C5-MASK: v0's bytes for the masked section. File-scope because `FoldUnit` serves the mask
// groups and the section chooses the pattern; an all-ones or all-zero mask would make the
// vxsat-gating claim below vacuous, so the section sets an alternating one.
std::vector<u8> g_v0(rvv32::VLEN_MAX_BYTES, 0xffu);

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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4sat", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_satadd = on;
	// C5-MASK: the shared fixed-point mask switch, on whenever the family's own route is.
	config::rvv_llvm_fixed_masked = on;
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
			case Op::_vchunksatadd: {
				auto *n = static_cast<InstVChunkSatAdd *>(&ins);
				++q.nodes;
				q.kind = (int)n->kind;
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
constexpr u32 kVxsatOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vxsat));
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
	int vxsat_bit = -1; // the value ORed in: 0 or 1
	bool ored = false;  // the store's value is `or(load, x)` and not an assignment
};

Folded FoldUnit(Built &b, u32 lanes_total, u32 vl, std::vector<u32> const &va,
		std::vector<u32> const &vb)
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
			// C5-MASK: v0's bits, read as a 16-bit group by the shared window helper.
			// Without this the masked store's predicate stays symbolic and nothing folds.
			if (l->getType()->isIntegerTy(16) && o != ~0u && o >= kVregOff &&
			    o < kVregOff + rvv32::VLEN_MAX_BYTES) {
				u32 const bo = o - kVregOff;
				u32 const w = (u32)g_v0[bo] | ((u32)g_v0[bo + 1] << 8);
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), w));
				continue;
			}
			if (o == kVxsatOff) {
				// A DISTINCTIVE PRIOR VALUE WITH A BIT THE EMITTER NEVER WRITES.
				// Pinning it to 0 -- which the first version did -- makes `or(0, x)`
				// fold to `x` and destroys the very distinction [S4] exists to draw:
				// an OR and an assignment then produce the same word. With 0x80 in
				// place, bit 7 survives an OR and disappears under an assignment.
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), 0x80u));
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

	// The destination's PRIOR value, so an unwritten lane is recognisable as preserved rather
	// than reading as a zero the instruction never produced.
	out.lanes.assign(lanes_total, 0xdeadbeefu);
	bool got = false, any_store = false, all_ored = true;
	int bits = 0;
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
					// C5-MASK: HONOUR THE STORE'S OWN MASK. This harness was
					// written when the route was unmasked-only, where the
					// predicate was `e < vl` and a lane the test cared about was
					// always written -- so it wrote every lane of the value
					// vector and ignored the mask entirely. Under a masked form
					// that silently overwrites the elements the instruction must
					// PRESERVE, which is precisely the property [S7] exists to
					// check: it reported the route writing masked-off lanes when
					// the route was doing the right thing.
					auto *m = llvm::dyn_cast<llvm::Constant>(
					    testcompat::MaskedStoreMask(ii));
					if (!m)
						return out;
					for (u32 i = 0; i < vt->getNumElements(); ++i) {
						auto *mk = llvm::dyn_cast_or_null<llvm::ConstantInt>(
						    m->getAggregateElement(i));
						auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
						    c->getAggregateElement(i));
						if (!mk || !e)
							return out;
						if (!mk->isOne())
							continue; // preserved, not written
						llvm::APInt w = e->getValue().zextOrTrunc(lb2);
						for (u32 k = 0; k < per; ++k)
							out.lanes[base + i * per + k] =
							    (u32)(w.lshr(32u * k).getZExtValue() &
								  0xffffffffu);
					}
					got = true;
					continue;
				}
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st || StateOffset(st->getPointerOperand(), state) != kVxsatOff)
				continue;
			// THE PRIOR BIT MUST SURVIVE. With the prior value pinned to 0x80, an OR
			// leaves bit 7 set and an assignment clears it, so `ored` is a measurement of
			// the stickiness rule and not of the instruction's spelling (which the folder
			// is free to change).
			//
			// AND THE BIT IS ACCUMULATED, NOT TAKEN FROM THE LAST STORE (2026-09-19). A
			// multi-chunk frame stores once per chunk, and because this harness pins EVERY
			// load in that chain to 0x80, each store carries only ITS OWN chunk's
			// contribution -- constant folding does not forward a store to a later load.
			// The architectural flag is their OR. This was found in the `vsmul` harness,
			// which is the same code: there it produced four spurious failures. Here it
			// was merely LATENT, because until today this differential ran only
			// one-chunk widths.
			any_store = true;
			if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand())) {
				u64 const w = ci->getZExtValue();
				all_ored = all_ored && (w & 0x80u) != 0;
				bits |= (int)(w & 1u);
			} else if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(
				       st->getValueOperand())) {
				all_ored = all_ored && bo->getOpcode() == llvm::Instruction::Or;
			} else {
				all_ored = false;
			}
		}
	if (any_store) {
		out.ored = all_ored;
		out.vxsat_bit = bits;
	}
	out.ok = got;
	return out;
}

// THE REFERENCE, driven through a real VectorState. `rvv_ref::vsatadd` is the function the helper
// arm calls, so this is a differential and not a second reading of the spec.
struct Ref {
	std::vector<u32> lanes;
	u32 vxsat = 0;
};
// C5-MASK: `vm` and `v0` are parameters now. `vm == true` is the unmasked form every earlier
// section uses; the masked section passes false and the mask bytes, which the reference reads from
// register 0 exactly as the guest does.
Ref RefSat(u32 f6, u32 vl, u32 vlen, std::vector<u32> const &va, std::vector<u32> const &vb,
	   bool masked = false, std::vector<u8> const &v0 = {})
{
	auto vs = std::make_unique<rvv32::VectorState>();
	vs->vl = vl;
	vs->vstart = 0;
	vs->vxsat = 0;
	u32 const lanes = vlen / 32u;
	for (u32 e = 0; e < lanes; ++e) {
		vs->elem_put(kVs2, e, 4, vlen, va[e]);
		vs->elem_put(kVs1, e, 4, vlen, vb[e]);
		vs->elem_put(kVd, e, 4, vlen, 0xdeadbeefu);
	}
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES && i < v0.size(); ++i)
		vs->vreg[0][i] = v0[i];
	rvv32::rvv_ref::vsatadd(*vs, f6, rvv32::VSrc::VV, kVd, kVs2, kVs1, 0, 0, /*vm=*/!masked,
				vlen, vl, 4);
	Ref r;
	r.vxsat = vs->vxsat;
	for (u32 e = 0; e < lanes; ++e)
		r.lanes.push_back((u32)vs->elem_u(kVd, e, 4, vlen));
	return r;
}

struct KindRow { char const *name; u32 f6; llvm::Intrinsic::ID id; };
KindRow const kKinds[] = {
    {"vsaddu", rvv32::VF6_VSADDU, llvm::Intrinsic::uadd_sat},
    {"vsadd", rvv32::VF6_VSADD, llvm::Intrinsic::sadd_sat},
    {"vssubu", rvv32::VF6_VSSUBU, llvm::Intrinsic::usub_sat},
    {"vssub", rvv32::VF6_VSSUB, llvm::Intrinsic::ssub_sat},
};

void SectionAdmission()
{
	printf("[S1] admission, frame shape, inertness, and the .vi ISA rule\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds)
			for (u32 f3 : {F3_VV, F3_VX, F3_VI}) {
				// `.vi` KEEPS THE HELPER IN ALL FOUR KINDS, and for a backend reason
				// rather than an ISA one: the IMMEDIATE form of `vchunkbroadcast` has
				// no LLVM lowering, so this backend cannot build that splat. Recorded
				// as incomplete native support. (The ISA separately has no
				// `vssubu.vi`/`vssub.vi` at all, which is why those two are named.)
				bool const vi_sub = f3 == F3_VI;
				Configure(vlen, true);
				Built b({Vsetvli(kVT_E32M1),
					 OpSat(k.f6, f3, kVs2, f3 == F3_VV ? kVs1 : 3u, kVd), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (vi_sub) {
					// RVV 1.0 does not define vssubu.vi / vssub.vi.
					if (q.nodes) {
						printf("  FAIL %s.vi admitted, but this backend has "
						       "no immediate broadcast\n", k.name);
						++g_fail;
					}
					continue;
				}
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
					 OpSat(k.f6, f3, kVs2, f3 == F3_VV ? kVs1 : 3u, kVd), kJalr});
				Translate(o);
				CHECK_EQ(ScanQir(o.region).nodes, 0u);
				CHECK(ScanQir(o.region).hcalls >= 1u);
			}
	printf("       %u admitted kind/form/width cells\n", admitted);
	CHECK(admitted > 0);
	// C5-MASK: a masked form is now ADMITTED -- but only under the shared fixed-point mask
	// switch, and never with `v0` as the destination. Both directions are asserted, so the
	// switch cannot become a no-op and the 5.3 rule cannot be dropped.
	Configure(512u, true);
	Built m({Vsetvli(kVT_E32M1), OpSat(rvv32::VF6_VSADD, F3_VV, kVs2, kVs1, kVd, true), kJalr});
	Translate(m);
	CHECK_EQ(ScanQir(m.region).nodes, 1u);
	Configure(512u, true);
	config::rvv_llvm_fixed_masked = false;
	Built m2({Vsetvli(kVT_E32M1), OpSat(rvv32::VF6_VSADD, F3_VV, kVs2, kVs1, kVd, true), kJalr});
	Translate(m2);
	CHECK_EQ(ScanQir(m2.region).nodes, 0u);
	Configure(512u, true);
	Built m3({Vsetvli(kVT_E32M1), OpSat(rvv32::VF6_VSADD, F3_VV, kVs2, kVs1, 0u, true), kJalr});
	Translate(m3);
	CHECK_EQ(ScanQir(m3.region).nodes, 0u); // vd == v0 under a mask: RVV 1.0 5.3
}

void SectionIntrinsicSelection()
{
	printf("[S2] each funct6 emits ITS OWN saturating intrinsic, not a sibling's\n");
	for (u32 vlen : {256u, 512u})
		for (auto const &k : kKinds) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpSat(k.f6, F3_VV, kVs2, kVs1, kVd), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (!q.nodes || !b.fn)
				continue;
			unsigned mine = 0, others = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb)
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						auto id = ii->getIntrinsicID();
						if (id == k.id)
							++mine;
						else
							for (auto const &o : kKinds)
								if (o.id == id && o.id != k.id)
									++others;
					}
			CHECK_EQ(mine, q.nodes);
			CHECK_EQ(others, 0u);
		}
}

void RunDifferential(char const *label, std::vector<u32> const &pa, std::vector<u32> const &pb,
		     unsigned *cells)
{
	// 1024 AND 2048 WERE ADDED 2026-09-19, WITH THE FIX BELOW. At SEW 32 a unit is
	// `min(VLEN/8, 64)` bytes, so every width this list originally held is a ONE-CHUNK frame --
	// and `vxsat` is accumulated across chunks. The flag half of this differential had therefore
	// never run against the chain it is supposed to describe.
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			u32 const total = vlen / 32u;
			for (u32 vl : {total, total / 2u}) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT_E32M1),
					 OpSat(k.f6, F3_VV, kVs2, kVs1, kVd), kJalr});
				Translate(b);
				if (!ScanQir(b.region).nodes || !b.fn)
					continue;
				std::vector<u32> va, vb;
				for (u32 e = 0; e < total; ++e) {
					va.push_back(pa[e % pa.size()]);
					vb.push_back(pb[e % pb.size()]);
				}
				Folded const f = FoldUnit(b, total, vl, va, vb);
				if (!f.ok) {
					printf("  FAIL %s %s vlen=%u vl=%u: did not fold\n", label,
					       k.name, vlen, vl);
					++g_fail;
					continue;
				}
				Ref const r = RefSat(k.f6, vl, vlen, va, vb);
				for (u32 e = 0; e < vl; ++e) {
					if (f.lanes[e] != r.lanes[e]) {
						printf("  FAIL %s %s vlen=%u vl=%u e=%u "
						       "a=%08x b=%08x: emitted %08x, reference %08x\n",
						       label, k.name, vlen, vl, e, va[e], vb[e],
						       f.lanes[e], r.lanes[e]);
						++g_fail;
					}
					++*cells;
				}
				// [S4] the flag: same value as the reference, and ORed not assigned.
				CHECK(f.ored);
				if (f.vxsat_bit >= 0 && (u32)f.vxsat_bit != r.vxsat) {
					printf("  FAIL %s %s vlen=%u vl=%u: vxsat %d, reference %u\n",
					       label, k.name, vlen, vl, f.vxsat_bit, r.vxsat);
					++g_fail;
				}
			}
		}
}

void SectionDifferential()
{
	printf("[S3/S4/S5] every lane and vxsat against rvv_ref::vsatadd\n");
	unsigned cells = 0;
	// Operands chosen so every bound is reached from both directions, and so the SHORT-vl runs
	// place a saturating pair beyond `vl` -- which is what [S5] needs: an inactive lane that
	// overflows must not set the flag.
	std::vector<u32> const a = {0x00000000u, 0xffffffffu, 0x7fffffffu, 0x80000000u,
				    0x00000001u, 0xfffffffeu, 0x40000000u, 0xc0000000u,
				    0x7ffffffeu, 0x80000001u, 0x12345678u, 0xdeadbeefu,
				    0x00000002u, 0xfffffff0u, 0x7f000000u, 0x81000000u};
	std::vector<u32> const b = {0x00000001u, 0x00000001u, 0x00000001u, 0xffffffffu,
				    0xffffffffu, 0x00000002u, 0x40000000u, 0xc0000000u,
				    0x00000003u, 0xfffffffdu, 0x9abcdef0u, 0x0badf00du,
				    0xfffffffeu, 0x00000020u, 0x7f000000u, 0x81000000u};
	RunDifferential("boundary", a, b, &cells);
	u64 x = 0x853c49e6748fea9bull;
	for (unsigned round = 0; round < 24; ++round) {
		std::vector<u32> pa, pb;
		for (unsigned i = 0; i < 16; ++i) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			pa.push_back((u32)x);
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			pb.push_back((u32)x);
		}
		RunDifferential("sweep", pa, pb, &cells);
	}
	printf("       %u lanes compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [S7] C5-MASK: THE MASKED FORMS, AND THE RULE THAT IS NOT THE STORE'S.
//
// Admitting `vm == 0` costs the DESTINATION nothing -- the shared store predicate has ANDed in the
// architectural mask since order item 3. What it does cost is the STICKY FLAG: a masked-off lane
// that would saturate must not set `vxsat`, and unlike the destination, which is simply not
// written, the flag has no second chance to be corrected.
//
// So this section feeds an ALTERNATING mask over operands that saturate in EVERY lane. The
// reference and the route must then agree that `vxsat` is set (the active lanes saturate too) AND
// that the masked-off destination elements keep their prior value. The case that isolates the flag
// is the second one: operands that saturate ONLY in lanes the mask turns off, where the correct
// answer is `vxsat` UNCHANGED and a route that ignored the mask in its reduction would set it.
void SectionMasked()
{
	printf("[S7] the masked forms: destination preserved, and vxsat gated by v0\n");
	unsigned checked = 0, isolated = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			u32 const total = vlen / 32u;
			// ALTERNATING, so neither an all-active nor an all-inactive reading passes.
			for (u32 i = 0; i < g_v0.size(); ++i)
				g_v0[i] = 0x55u;
			std::vector<u32> va(total), vb(total);
			// (a) every lane saturates.
			for (u32 e = 0; e < total; ++e) {
				va[e] = 0xffffffffu;
				vb[e] = 0xffffffffu;
			}
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpSat(k.f6, F3_VV, kVs2, kVs1, kVd, /*masked=*/true), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			Folded const f = FoldUnit(b, total, total, va, vb);
			if (!f.ok) {
				printf("  FAIL %s vlen=%u: masked form did not fold\n", k.name, vlen);
				++g_fail;
				continue;
			}
			Ref const r = RefSat(k.f6, total, vlen, va, vb, /*masked=*/true, g_v0);
			for (u32 e = 0; e < total; ++e)
				if (f.lanes[e] != r.lanes[e]) {
					printf("  FAIL %s vlen=%u e=%u: masked value %08x, "
					       "reference %08x\n",
					       k.name, vlen, e, f.lanes[e], r.lanes[e]);
					++g_fail;
					break;
				}
			if (f.vxsat_bit >= 0 && (u32)f.vxsat_bit != r.vxsat) {
				printf("  FAIL %s vlen=%u: masked vxsat %d, reference %u\n", k.name,
				       vlen, f.vxsat_bit, r.vxsat);
				++g_fail;
			}
			++checked;

			// (b) THE ISOLATING CASE: saturating operands ONLY in masked-OFF lanes. The
			// active lanes are 0 + 0, which cannot saturate under any of the four kinds,
			// so the correct `vxsat` is UNCHANGED -- and a reduction that ignored `v0`
			// would set it.
			for (u32 e = 0; e < total; ++e) {
				bool const on = ((g_v0[e / 8u] >> (e % 8u)) & 1u) != 0;
				va[e] = on ? 0u : 0xffffffffu;
				vb[e] = on ? 0u : 0xffffffffu;
			}
			Configure(vlen, true);
			Built c({Vsetvli(kVT_E32M1),
				 OpSat(k.f6, F3_VV, kVs2, kVs1, kVd, /*masked=*/true), kJalr});
			Translate(c);
			if (!ScanQir(c.region).nodes || !c.fn)
				continue;
			Folded const g = FoldUnit(c, total, total, va, vb);
			Ref const rr = RefSat(k.f6, total, vlen, va, vb, /*masked=*/true, g_v0);
			if (!g.ok) {
				printf("  FAIL %s vlen=%u: isolating case did not fold\n", k.name,
				       vlen);
				++g_fail;
				continue;
			}
			CHECK_EQ(rr.vxsat, 0u); // the reference agrees nothing active saturates
			if (g.vxsat_bit > 0) {
				printf("  FAIL %s vlen=%u: vxsat was set by a MASKED-OFF saturating "
				       "lane; the flag is not gated by v0\n",
				       k.name, vlen);
				++g_fail;
			}
			++isolated;
		}
	// Restore the all-active mask so any later section is unaffected.
	for (u32 i = 0; i < g_v0.size(); ++i)
		g_v0[i] = 0xffu;
	printf("       %u masked cells, %u with the flag isolated\n", checked, isolated);
	CHECK(checked > 0);
	CHECK(isolated > 0);
}

void SectionVerify()
{
	printf("[S6] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpSat(k.f6, F3_VV, kVs2, kVs1, kVd), kJalr});
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
	printf("rvv_llvm_satadd_test: order item 4, the saturating integer add/sub family\n");
	SectionAdmission();
	SectionIntrinsicSelection();
	SectionDifferential();
	SectionMasked();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
