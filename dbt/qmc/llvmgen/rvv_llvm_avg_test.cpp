// ORDER ITEM 4 (2026-09-19): THE FIXED-POINT AVERAGING FAMILY ON THE LLVM ARM -- `vaadd`/`vasub`.
//
// THE THIRD OF THE FIVE NARROW NODES, and the one that introduces `vxrm` to this backend. That is
// what this file is mostly about. `vxrm` is a writable CSR and a REAL ARCHITECTURAL INPUT: the same
// encoding on the same operands produces four different answers across its four values, so a route
// that hard-coded any one of them would be right on a quarter of guests and silently wrong on the
// rest. A differential that only ever ran at the reset value of 0 would not notice.
//
// SECTIONS:
//   [V1] Admission and inertness: OPMVV/OPMVX only (funct3 2 and 6 -- `vaaddu` shares its funct6
//        with `vwaddu`, which is a WIDENING instruction under a different funct3), unmasked only,
//        and the route inert with its flag off.
//   [V2] THE DIFFERENTIAL against `rvv_ref::vavg` driven through a real `VectorState`, over all
//        four kinds, both `vl`s, five VLENs and ALL FOUR `vxrm` VALUES.
//   [V3] `vxrm` IS A REAL INPUT: one crafted operand vector on which the four rounding modes give
//        four pairwise-distinct results. This is the assertion that fails if any mode is baked in;
//        the differential alone would also catch it, but this states the property directly and
//        fails with a legible message.
//   [V4] The mechanism in the IR: `vec.vxrm` is LOADED (not folded away at build time), the wide
//        arithmetic is 2*SEW, and the right shift is ARITHMETIC -- `vasubu` produces negative
//        differences and the spec shifts them with floor semantics.
//   [V5] The module verifies.

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
// OPMVV and OPMVX. NOT OPIVV/OPIVX: this family lives on funct3 2 and 6, and the funct3 is what
// separates `vaaddu` (0b001000, OPMVV) from `vwaddu` (the same funct6, OPIVV's neighbour on the
// widening side). Admitting on funct6 alone would let a widening instruction into this body.
constexpr u32 F3_MV = 0b010u, F3_MX = 0b110u, F3_IV = 0b000u, F3_IX = 0b100u;

constexpr u32 OpAvg(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool vm = true)
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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4avg", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_avg = on;
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
			case Op::_vchunkavg:
				++q.nodes;
				q.kind = (int)static_cast<InstVChunkAvg *>(&ins)->kind;
				break;
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
constexpr u32 kVxrmOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vxrm));
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

// `vxrm` IS SUBSTITUTED HERE, and that is the one thing this harness does that its siblings do not.
// The emitter reads the CSR from live state, so before folding every load from `vec.vxrm` is pinned
// to the mode under test. If the emitter ever stopped reading it -- the exact defect [V3] exists to
// catch -- this substitution would have nothing to replace and all four modes would fold alike.
Folded FoldUnit(Built &b, u32 lanes_total, u32 vl, u32 vxrm, std::vector<u32> const &va,
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
			if (o == kVxrmOff) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vxrm));
				continue;
			}
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt)
				continue;
			bool const is_a = o >= VRegOff(kVs2) && o < VRegOff(kVs2) + 512u;
			bool const is_b = o >= VRegOff(kVs1) && o < VRegOff(kVs1) + 512u;
			if (!is_a && !is_b)
				continue;
			// The chunk's own lane width, not an assumed 32: the emitter picks the
			// vector type and a filter on i32 would silently skip every source load.
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
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
				continue;
			u32 const o = StateOffset(ii->getArgOperand(1), state);
			if (o < VRegOff(kVd) || o >= VRegOff(kVd) + 512u)
				continue;
			auto *c = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
			if (!c)
				return out;
			u32 const base = (o - VRegOff(kVd)) / 4u;
			auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
			u32 const lb2 = vt->getScalarSizeInBits(), per = lb2 / 32u;
			for (u32 i = 0; i < vt->getNumElements(); ++i) {
				auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    c->getAggregateElement(i));
				if (!e)
					return out;
				llvm::APInt w = e->getValue().zextOrTrunc(lb2);
				for (u32 k = 0; k < per; ++k)
					out.lanes[base + i * per + k] =
					    (u32)(w.lshr(32u * k).getZExtValue() & 0xffffffffu);
			}
			got = true;
		}
	out.ok = got;
	return out;
}

// THE REFERENCE, driven through a real VectorState. `rvv_ref::vavg` is the function the helper arm
// calls, and `vxrm` is set on the state exactly as a guest's `csrw vxrm` would leave it.
std::vector<u32> RefAvg(u32 f6, u32 vxrm, u32 vl, u32 vlen, std::vector<u32> const &va,
			std::vector<u32> const &vb)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	vs->vl = vl;
	vs->vstart = 0;
	vs->vxrm = vxrm;
	u32 const lanes = vlen / 32u;
	for (u32 e = 0; e < lanes; ++e) {
		vs->elem_put(kVs2, e, 4, vlen, va[e]);
		vs->elem_put(kVs1, e, 4, vlen, vb[e]);
		vs->elem_put(kVd, e, 4, vlen, 0xdeadbeefu);
	}
	rvv32::rvv_ref::vavg(*vs, f6, rvv32::VSrc::VV, kVd, kVs2, kVs1, 0, 0, /*vm=*/true, vlen, vl,
			     4);
	std::vector<u32> r;
	for (u32 e = 0; e < lanes; ++e)
		r.push_back((u32)vs->elem_u(kVd, e, 4, vlen));
	return r;
}

struct KindRow { char const *name; u32 f6; int kind; };
KindRow const kKinds[] = {
    {"vaaddu", rvv32::VF6_VAADDU, 0},
    {"vaadd", rvv32::VF6_VAADD, 1},
    {"vasubu", rvv32::VF6_VASUBU, 2},
    {"vasub", rvv32::VF6_VASUB, 3},
};
char const *kModes[] = {"rnu", "rne", "rdn", "rod"};

void SectionAdmission()
{
	printf("[V1] admission, the funct3 rule, the refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds)
			for (u32 f3 : {F3_MV, F3_MX}) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT_E32M1),
					 OpAvg(k.f6, f3, kVs2, f3 == F3_MV ? kVs1 : 3u, kVd), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.stores, q.nodes);
				// EACH FUNCT6 SELECTS ITS OWN KIND. A swapped pair here would change
				// both the extension and the operation, so it is named explicitly.
				CHECK_EQ(q.kind, k.kind);
				Configure(vlen, false);
				Built o({Vsetvli(kVT_E32M1),
					 OpAvg(k.f6, f3, kVs2, f3 == F3_MV ? kVs1 : 3u, kVd), kJalr});
				Translate(o);
				CHECK_EQ(ScanQir(o.region).nodes, 0u);
				CHECK(ScanQir(o.region).hcalls >= 1u);
			}
	printf("       %u admitted kind/form/width cells\n", admitted);
	CHECK(admitted > 0);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    // funct3 0/4 with the SAME funct6 is the OPIVV/OPIVX encoding space -- for 0b001000 that
	    // is `vwaddu`, a WIDENING instruction whose destination group is twice this one. Letting
	    // it into an equal-width body would write half the register group it owes.
	    {"OPIVV funct3 (vwaddu's space, not vaaddu's)",
	     OpAvg(rvv32::VF6_VAADDU, F3_IV, kVs2, kVs1, kVd)},
	    {"OPIVX funct3", OpAvg(rvv32::VF6_VAADDU, F3_IX, kVs2, kVs1, kVd)},
	    // Masked: this route has no architectural-mask lowering for this family.
	    {"masked (vm == 0)", OpAvg(rvv32::VF6_VAADD, F3_MV, kVs2, kVs1, kVd, false)},
	    // A funct6 outside the family, in the right funct3 space.
	    {"funct6 not in the averaging family", OpAvg(0b000001u, F3_MV, kVs2, kVs1, kVd)},
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
		}
}

void RunDifferential(char const *label, std::vector<u32> const &pa, std::vector<u32> const &pb,
		     unsigned *cells)
{
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			u32 const total = vlen / 32u;
			for (u32 vl : {total, total / 2u})
				// ALL FOUR MODES, EVERY CELL. Running only the reset value of 0
				// would leave three quarters of this family's semantics unmeasured.
				for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
					Configure(vlen, true);
					Built b({Vsetvli(kVT_E32M1),
						 OpAvg(k.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
					Translate(b);
					if (!ScanQir(b.region).nodes || !b.fn)
						continue;
					std::vector<u32> va, vb;
					for (u32 e = 0; e < total; ++e) {
						va.push_back(pa[e % pa.size()]);
						vb.push_back(pb[e % pb.size()]);
					}
					Folded const f = FoldUnit(b, total, vl, vxrm, va, vb);
					if (!f.ok) {
						printf("  FAIL %s %s %s vlen=%u vl=%u: did not fold\n",
						       label, k.name, kModes[vxrm], vlen, vl);
						++g_fail;
						continue;
					}
					std::vector<u32> const r =
					    RefAvg(k.f6, vxrm, vl, vlen, va, vb);
					for (u32 e = 0; e < vl; ++e) {
						if (f.lanes[e] != r[e]) {
							printf("  FAIL %s %s %s vlen=%u vl=%u e=%u "
							       "a=%08x b=%08x: emitted %08x, "
							       "reference %08x\n",
							       label, k.name, kModes[vxrm], vlen, vl,
							       e, va[e], vb[e], f.lanes[e], r[e]);
							++g_fail;
						}
						++*cells;
					}
				}
		}
}

void SectionDifferential()
{
	printf("[V2] every lane against rvv_ref::vavg, across ALL FOUR vxrm values\n");
	unsigned cells = 0;
	// Operands chosen so the rounding bit matters and the sign paths are exercised: odd sums
	// (something to round), sums at the SEW boundary (the SEW+1 bit must be real), and
	// differences that go NEGATIVE for the unsigned kinds -- which is where an `lshr` in place
	// of the spec's arithmetic shift would show.
	std::vector<u32> const a = {0x00000003u, 0x00000001u, 0xffffffffu, 0x00000000u,
				    0x7fffffffu, 0x80000000u, 0x00000002u, 0x00000005u,
				    0xfffffffdu, 0x00000004u, 0x12345678u, 0xdeadbeefu,
				    0x80000001u, 0x7ffffffeu, 0x00000007u, 0xaaaaaaabu};
	std::vector<u32> const b = {0x00000000u, 0x00000000u, 0xffffffffu, 0x00000001u,
				    0x7fffffffu, 0x80000000u, 0x00000003u, 0x00000002u,
				    0x00000002u, 0xfffffffbu, 0x9abcdef0u, 0x0badf00du,
				    0x00000001u, 0x00000001u, 0x00000002u, 0x55555555u};
	RunDifferential("crafted", a, b, &cells);
	u64 x = 0x9e3779b97f4a7c15ull;
	for (unsigned round = 0; round < 12; ++round) {
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

// [V3] THE ASSERTION THAT FAILS IF ANY ROUNDING MODE IS BAKED IN.
//
// The two operand pairs below are picked so that the four modes disagree in a way that separates
// all four. With `vaaddu` and vs1 == 0:
//   vs2 = 3: sum 3 -> rnu 2, rne 2, rdn 1, rod 1
//   vs2 = 1: sum 1 -> rnu 1, rne 0, rdn 0, rod 1
// so the PAIR (result at 3, result at 1) is (2,1), (2,0), (1,0), (1,1) -- pairwise distinct. A
// route that hard-coded any single mode collapses at least two of the four into each other.
void SectionVxrmIsAnInput()
{
	printf("[V3] vxrm is a real input: four modes, four distinct answers\n");
	u32 const vlen = 256u, total = vlen / 32u;
	std::vector<u32> va(total), vb(total, 0u);
	for (u32 e = 0; e < total; ++e)
		va[e] = (e % 2) ? 1u : 3u;
	u32 seen[4][2] = {};
	bool ran = false;
	for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpAvg(rvv32::VF6_VAADDU, F3_MV, kVs2, kVs1, kVd),
			 kJalr});
		Translate(b);
		if (!ScanQir(b.region).nodes || !b.fn)
			continue;
		Folded const f = FoldUnit(b, total, total, vxrm, va, vb);
		if (!f.ok) {
			printf("  FAIL vxrm=%s: did not fold\n", kModes[vxrm]);
			++g_fail;
			continue;
		}
		ran = true;
		seen[vxrm][0] = f.lanes[0]; // vs2 == 3
		seen[vxrm][1] = f.lanes[1]; // vs2 == 1
		printf("       %s: avg(3,0) = %u, avg(1,0) = %u\n", kModes[vxrm], f.lanes[0],
		       f.lanes[1]);
	}
	CHECK(ran);
	if (!ran)
		return;
	for (u32 i = 0; i < 4; ++i)
		for (u32 j = i + 1; j < 4; ++j)
			if (seen[i][0] == seen[j][0] && seen[i][1] == seen[j][1]) {
				printf("  FAIL %s and %s produced the SAME pair (%u,%u) -- the "
				       "rounding mode is not reaching the arithmetic\n",
				       kModes[i], kModes[j], seen[i][0], seen[i][1]);
				++g_fail;
			}
}

void SectionMechanism()
{
	printf("[V4] the mechanism in the IR: a vxrm load, 2*SEW arithmetic, an ARITHMETIC shift\n");
	for (u32 vlen : {256u, 1024u})
		for (auto const &k : kKinds) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpAvg(k.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			unsigned vxrm_loads = 0, wide_ashr = 0, wide_lshr_of_sum = 0, ext = 0;
			llvm::Value *state = b.fn->getArg(0);
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
						if (StateOffset(l->getPointerOperand(), state) ==
						    kVxrmOff)
							++vxrm_loads;
						continue;
					}
					auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(
					    ins.getType());
					if (!vt || vt->getScalarSizeInBits() != 64u)
						continue;
					// The wide type is 2*SEW = 64 bits at SEW 32.
					if (llvm::isa<llvm::SExtInst>(&ins) ||
					    llvm::isa<llvm::ZExtInst>(&ins))
						++ext;
					if (ins.getOpcode() == llvm::Instruction::AShr)
						++wide_ashr;
					// A LOGICAL shift of the SUM is the defect this counts. The
					// rounding helper's own `lshr`s are of the same wide value, so
					// this only counts the one whose result is ADDED to the
					// increment -- i.e. feeds an `add` that also has a `select`.
					if (ins.getOpcode() == llvm::Instruction::LShr)
						for (auto *u : ins.users())
							if (auto *bo = llvm::dyn_cast<
								llvm::BinaryOperator>(u))
								if (bo->getOpcode() ==
								    llvm::Instruction::Add)
									++wide_lshr_of_sum;
				}
			// vxrm IS READ. Zero loads means the mode was decided at build time.
			if (!vxrm_loads) {
				printf("  FAIL %s vlen=%u: vec.vxrm is never loaded\n", k.name, vlen);
				++g_fail;
			}
			// Both operands are extended to the wide type, once per chunk.
			CHECK(ext >= 2u);
			// The sum's shift is arithmetic.
			if (!wide_ashr) {
				printf("  FAIL %s vlen=%u: no arithmetic shift of the wide sum\n",
				       k.name, vlen);
				++g_fail;
			}
			if (wide_lshr_of_sum) {
				printf("  FAIL %s vlen=%u: a LOGICAL shift feeds the rounding add "
				       "-- floor semantics lost for negative differences\n",
				       k.name, vlen);
				++g_fail;
			}
		}
}

void SectionVerify()
{
	printf("[V5] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpAvg(k.f6, F3_MV, kVs2, kVs1, kVd), kJalr});
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
	printf("rvv_llvm_avg_test: order item 4, the fixed-point averaging family\n");
	SectionAdmission();
	SectionDifferential();
	SectionVxrmIsAnInput();
	SectionMechanism();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
