// ORDER ITEM 4 (2026-09-19): THE FRACTIONAL MULTIPLY ON THE LLVM ARM -- `vsmul.vv` / `vsmul.vx`.
//
// FOURTH OF THE FIVE NARROW FIXED-POINT NODES, and the first that rounds at a shift greater than
// one. `vaadd` shifts by 1, where the spec's sticky `v[d-2:0] != 0` term is an EMPTY bit range;
// here the shift is SEW-1 and that term carries thirty bits, so the shared `RvvRoundoffIncrement`
// is exercised for real rather than in its degenerate case.
//
// SATURATION HERE HAS EXACTLY ONE INPUT PAIR -- MIN*MIN, which is +1.0 in Q(SEW-1) and one ulp
// above the maximum. That makes `vxsat` trivially easy to get a false PASS on: a differential over
// random operands never saturates, so it would agree with a route that could not set the flag at
// all. [P3] therefore feeds MIN*MIN deliberately AND asserts the flag stays clear when it is
// absent, which is the assertion that fails for a route that sets `vxsat` unconditionally.
//
// SECTIONS:
//   [P1] Admission and inertness: OPIVV/OPIVX only, unmasked only, no `.vi` (the ISA defines
//        none), and the route inert with its flag off.
//   [P2] THE DIFFERENTIAL against `rvv_ref::vsmul` through a real `VectorState` -- values AND
//        `vxsat` -- over both `vl`s, five VLENs and ALL FOUR `vxrm` values.
//   [P3] MIN*MIN IS THE ONLY SATURATING PAIR, in both directions.
//   [P4] `vxsat` is ORed into the sticky flag, never assigned. The prior value is pinned to 0x80,
//        because pinning it to 0 makes `or(0, x)` fold to `x` and destroys the distinction.
//   [P5] The module verifies.

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
// OPIVV and OPIVX -- back to the integer funct3 space after the averaging family's OPMVV/OPMVX.
// `F3_VI` and `F3_MV` exist only to be REFUSED in [P1].
constexpr u32 F3_IV = 0b000u, F3_IX = 0b100u, F3_VI = 0b011u, F3_MV = 0b010u;

constexpr u32 OpSmul(u32 f3, u32 vs2, u32 vs1, u32 vd, bool vm = true)
{
	return (rvv32::VF6_VSMUL << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) |
	       (f3 << 12) | (vd << 7) | 0x57u;
}
char const *kModes[] = {"rnu", "rne", "rdn", "rod"};

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4smul", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_smul = on;
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
			case Op::_vchunkfracmul:
				++q.nodes;
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
	bool ored = false;  // the prior 0x80 survived, i.e. this was an OR and not an assignment
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
			if (o == kVxsatOff) {
				// A DISTINCTIVE PRIOR VALUE WITH A BIT THE EMITTER NEVER WRITES.
				// Pinning it to 0 makes `or(0, x)` fold to `x`, which destroys the
				// very distinction [P4] exists to draw: an OR and an assignment
				// then produce the same word. With 0x80 in place, bit 7 survives an
				// OR and disappears under an assignment.
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
	// THE FLAG IS ACCUMULATED ACROSS CHUNKS, NOT READ OFF THE LAST STORE.
	//
	// A frame above VLEN 512 has more than one chunk, and each chunk's node loads `vxsat`, ORs
	// its own contribution and stores it -- a chain. This harness pins EVERY load in that chain
	// to 0x80, so each store reports only THAT chunk's contribution in isolation rather than the
	// running total (constant folding does not forward a store to a later load). The
	// architectural flag is therefore the OR of them all.
	//
	// Taking the last store instead -- which the first version of this file did -- reads the LAST
	// chunk's contribution and calls it the instruction's. That gave four spurious failures at
	// VLEN 1024 and 2048, where element 0 saturated and the final chunk did not.
	bool any_store = false, all_ored = true;
	int bits = 0;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st || StateOffset(st->getPointerOperand(), state) != kVxsatOff)
				continue;
			any_store = true;
			if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand())) {
				u64 const w = ci->getZExtValue();
				all_ored = all_ored && (w & 0x80u) != 0;
				bits |= (int)(w & 1u);
			} else if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(
				       st->getValueOperand())) {
				// Not folded to a constant: the OR is still visible as an opcode,
				// which is all [P4] needs, but the bit itself is not readable.
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

// THE REFERENCE, driven through a real VectorState. `rvv_ref::vsmul` is the function the helper arm
// calls; `vxrm` is set as a guest's `csrw vxrm` would leave it and `vxsat` starts CLEAR, so the
// flag read back afterwards is attributable to this instruction alone.
struct Ref {
	std::vector<u32> lanes;
	u32 vxsat = 0;
};
Ref RefSmul(u32 vxrm, u32 vl, u32 vlen, std::vector<u32> const &va, std::vector<u32> const &vb)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	vs->vl = vl;
	vs->vstart = 0;
	vs->vxrm = vxrm;
	vs->vxsat = 0;
	u32 const lanes = vlen / 32u;
	for (u32 e = 0; e < lanes; ++e) {
		vs->elem_put(kVs2, e, 4, vlen, va[e]);
		vs->elem_put(kVs1, e, 4, vlen, vb[e]);
		vs->elem_put(kVd, e, 4, vlen, 0xdeadbeefu);
	}
	rvv32::rvv_ref::vsmul(*vs, rvv32::VSrc::VV, kVd, kVs2, kVs1, 0, /*vm=*/true, vlen, vl, 4);
	Ref r;
	for (u32 e = 0; e < lanes; ++e)
		r.lanes.push_back((u32)vs->elem_u(kVd, e, 4, vlen));
	r.vxsat = vs->vxsat;
	return r;
}

void SectionAdmission()
{
	printf("[P1] admission, the funct3 rule, the refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 f3 : {F3_IV, F3_IX}) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpSmul(f3, kVs2, f3 == F3_IV ? kVs1 : 3u, kVd), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (!q.nodes)
				continue;
			++admitted;
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK_EQ(q.stores, q.nodes);
			Configure(vlen, false);
			Built o({Vsetvli(kVT_E32M1),
				 OpSmul(f3, kVs2, f3 == F3_IV ? kVs1 : 3u, kVd), kJalr});
			Translate(o);
			CHECK_EQ(ScanQir(o.region).nodes, 0u);
			CHECK(ScanQir(o.region).hcalls >= 1u);
		}
	printf("       %u admitted form/width cells\n", admitted);
	CHECK(admitted > 0);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    {".vi (RVV 1.0 defines no immediate fractional multiply)",
	     OpSmul(F3_VI, kVs2, 3u, kVd)},
	    {"masked (vm == 0)", OpSmul(F3_IV, kVs2, kVs1, kVd, false)},
	    {"OPMVV funct3 (a different instruction entirely)", OpSmul(F3_MV, kVs2, kVs1, kVd)},
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
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		u32 const total = vlen / 32u;
		for (u32 vl : {total, total / 2u})
			for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT_E32M1), OpSmul(F3_IV, kVs2, kVs1, kVd), kJalr});
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
					printf("  FAIL %s %s vlen=%u vl=%u: did not fold\n", label,
					       kModes[vxrm], vlen, vl);
					++g_fail;
					continue;
				}
				Ref const r = RefSmul(vxrm, vl, vlen, va, vb);
				for (u32 e = 0; e < vl; ++e) {
					if (f.lanes[e] != r.lanes[e]) {
						printf("  FAIL %s %s vlen=%u vl=%u e=%u a=%08x "
						       "b=%08x: emitted %08x, reference %08x\n",
						       label, kModes[vxrm], vlen, vl, e, va[e],
						       vb[e], f.lanes[e], r.lanes[e]);
						++g_fail;
					}
					++*cells;
				}
				// [P2] vxsat, against the reference's own flag.
				if (f.vxsat_bit >= 0 && (u32)f.vxsat_bit != r.vxsat) {
					printf("  FAIL %s %s vlen=%u vl=%u: vxsat %d, reference %u\n",
					       label, kModes[vxrm], vlen, vl, f.vxsat_bit, r.vxsat);
					++g_fail;
				}
				// [P4] STICKY, NOT ASSIGNED.
				if (!f.ored) {
					printf("  FAIL %s %s vlen=%u vl=%u: vxsat was ASSIGNED, not "
					       "ORed -- a previously set flag would be cleared\n",
					       label, kModes[vxrm], vlen, vl);
					++g_fail;
				}
			}
	}
}

void SectionDifferential()
{
	printf("[P2/P4] every lane and vxsat against rvv_ref::vsmul, across ALL FOUR vxrm values\n");
	unsigned cells = 0;
	// Operands that make the rounding bits matter: the sticky range below bit 30 is nonzero for
	// most of these, which is the term `vaadd`'s shift of 1 could never reach.
	std::vector<u32> const a = {0x80000000u, 0x7fffffffu, 0x00000001u, 0xffffffffu,
				    0x40000000u, 0xc0000000u, 0x12345678u, 0xdeadbeefu,
				    0x00000000u, 0x7ffffffeu, 0x80000001u, 0x55555555u,
				    0xaaaaaaabu, 0x00010001u, 0xffff0000u, 0x0000ffffu};
	std::vector<u32> const b = {0x80000000u, 0x7fffffffu, 0xffffffffu, 0x00000001u,
				    0x40000000u, 0x40000000u, 0x9abcdef0u, 0x0badf00du,
				    0x7fffffffu, 0x00000003u, 0x00000005u, 0x55555555u,
				    0x55555555u, 0x0001ffffu, 0x0000ffffu, 0xffff0000u};
	RunDifferential("crafted", a, b, &cells);
	u64 x = 0xda3e39cb94b95bdbull;
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

// [P3] MIN*MIN IS THE ONLY SATURATING PAIR, AND THE FLAG MUST STAY CLEAR WITHOUT IT.
//
// The second half is the half that matters. A route that ORed a constant 1 into `vxsat` would pass
// every value check and the saturating case too; only the NO-saturation case can fail it.
void SectionSaturation()
{
	printf("[P3] MIN*MIN saturates and sets vxsat; nothing else does\n");
	u32 const vlen = 256u, total = vlen / 32u;
	struct Case { char const *name; u32 a, b; u32 want_sat; };
	Case const cases[] = {
	    {"MIN*MIN (the only overflow)", 0x80000000u, 0x80000000u, 1u},
	    {"MIN*MAX", 0x80000000u, 0x7fffffffu, 0u},
	    {"MAX*MAX", 0x7fffffffu, 0x7fffffffu, 0u},
	    {"MIN*1", 0x80000000u, 0x00000001u, 0u},
	    {"MIN*-1", 0x80000000u, 0xffffffffu, 0u},
	    {"zero", 0x00000000u, 0x80000000u, 0u},
	};
	for (auto const &c : cases)
		for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
			std::vector<u32> va(total, c.a), vb(total, c.b);
			Configure(vlen, true);
			Built bb({Vsetvli(kVT_E32M1), OpSmul(F3_IV, kVs2, kVs1, kVd), kJalr});
			Translate(bb);
			if (!ScanQir(bb.region).nodes || !bb.fn)
				continue;
			Folded const f = FoldUnit(bb, total, total, vxrm, va, vb);
			Ref const r = RefSmul(vxrm, total, vlen, va, vb);
			if (!f.ok) {
				printf("  FAIL %s %s: did not fold\n", c.name, kModes[vxrm]);
				++g_fail;
				continue;
			}
			// The reference is the authority on both; `want_sat` states the expectation
			// independently, so a reference that drifted would not silently take the
			// check with it.
			CHECK_EQ(r.vxsat, c.want_sat);
			if (f.vxsat_bit >= 0 && (u32)f.vxsat_bit != c.want_sat) {
				printf("  FAIL %s %s: emitted vxsat %d, expected %u\n", c.name,
				       kModes[vxrm], f.vxsat_bit, c.want_sat);
				++g_fail;
			}
			if (f.lanes[0] != r.lanes[0]) {
				printf("  FAIL %s %s: emitted %08x, reference %08x\n", c.name,
				       kModes[vxrm], f.lanes[0], r.lanes[0]);
				++g_fail;
			}
		}
}

// [P3b] A SATURATING PAIR THAT IS OUTSIDE `vl` MUST NOT SET THE FLAG.
//
// ADDED AFTER THE MUTATION GATE FOUND THE HOLE. The `inactive lanes counted in the flag` mutation
// -- dropping the active-lane AND from the `vxsat` reduction -- SURVIVED the first version of this
// file, and it survived for a reason worth writing down: [P3] fills every lane with the same
// operand pair, and [P2]'s only saturating pair sits at element 0, which is active at every `vl`
// it runs. Neither could ever present a saturating lane that the instruction does not operate on.
//
// Here the body is a non-saturating 1*1 and MIN*MIN is placed ONLY at elements at or above `vl`.
// The architectural answer is that `vxsat` stays clear; a route that reduces over all lanes of the
// unit sets it.
void SectionTailSaturation()
{
	printf("[P3b] a saturating pair beyond vl must NOT set vxsat\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		u32 const total = vlen / 32u, vl = total / 2u;
		if (vl == 0)
			continue;
		std::vector<u32> va(total, 1u), vb(total, 1u);
		for (u32 e = vl; e < total; ++e) {
			va[e] = 0x80000000u;
			vb[e] = 0x80000000u;
		}
		for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpSmul(F3_IV, kVs2, kVs1, kVd), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			Folded const f = FoldUnit(b, total, vl, vxrm, va, vb);
			Ref const r = RefSmul(vxrm, vl, vlen, va, vb);
			if (!f.ok) {
				printf("  FAIL vlen=%u %s: did not fold\n", vlen, kModes[vxrm]);
				++g_fail;
				continue;
			}
			// The reference agrees the flag stays clear -- stated so a drifting reference
			// could not quietly take this check with it.
			CHECK_EQ(r.vxsat, 0u);
			if (f.vxsat_bit > 0) {
				printf("  FAIL vlen=%u vl=%u %s: vxsat set by a lane BEYOND vl -- the "
				       "flag is not gated by the active-lane predicate\n",
				       vlen, vl, kModes[vxrm]);
				++g_fail;
			}
			++checked;
		}
	}
	printf("       %u tail-saturation cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[P5] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpSmul(F3_IV, kVs2, kVs1, kVd), kJalr});
		Translate(b);
		std::string err;
		llvm::raw_string_ostream es(err);
		if (llvm::verifyModule(b.module, &es)) {
			printf("  FAIL vlen=%u: %s\n", vlen, err.c_str());
			++g_fail;
		}
	}
}

} // namespace

int main()
{
	printf("rvv_llvm_smul_test: order item 4, the fractional multiply\n");
	SectionAdmission();
	SectionDifferential();
	SectionSaturation();
	SectionTailSaturation();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
