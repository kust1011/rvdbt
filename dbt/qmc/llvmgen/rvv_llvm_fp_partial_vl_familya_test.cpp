// C5-FP FAMILY A (2026-09-18). PARTIAL VL FOR THE P-VECTOR-SSA FP LANE ROUTE, VLEN 512 AND 1024.
//
// WHY A SECOND FILE. `rvv_llvm_fp_partial_vl_test.cpp` covers Family B, the typed-chunk frame, and
// it says in its own header that at VLEN 512/1024 `TRANSLATOR(vfalu)` is taken by Family A and no
// typed frame is built at all -- so that file exercises 128/256/2048 and those two widths were
// INCOMPLETE native support. This file is that gap. It is a different representation, not a
// different width of the same one, and the three things it has to prove are different:
//
//   [1] THE OPERANDS of an inactive lane are +1.0. Same obligation as Family B, same reason: the
//       bracket ORs host MXCSR sticky bits into `fcsr`, so an exception raised computing a lane the
//       instruction must not touch is architecturally visible. +1.0 and not +0.0 because
//       `(+0)/(+0)` raises NV and `vfdiv` IS admitted.
//   [2] THE DESTINATION is merged from the OLD vd. Family B stores through a predicated
//       `Emit_vstatechunkstore` and needs no merge; here the destination is an SSA residency value
//       with no store to predicate, so without the merge the tail elements would be published as
//       computed garbage. Failure path: a route that neutralises operands and stops there would
//       pass every check Family B's file makes and still corrupt vd above `vl`.
//   [3] THE MERGE IS AFTER CANONICALISATION. `RvvCanonicalize` rewrites any NaN lane of the chunk
//       to the canonical quiet NaN; run on an already-merged chunk it would rewrite a PRESERVED
//       lane that held a non-canonical or signalling NaN. Section 3 reads the def-use chain and
//       fails if the merge's computed arm is the raw constrained call rather than the canonical
//       select.
//
// AND TWO THINGS THAT ONLY EXIST ON THIS ROUTE:
//
//   [4] THE FP BRACKET. `Emit_rvvfpbegin` guarded `vl == VLMAX`. At `vl < VLMAX` it would not open,
//       and the partial-VL body would then have run `round.dynamic` arithmetic under the HOST
//       rounding mode with every flag it raised dropped instead of reaching `fcsr`. The bracket's
//       guard is widened with the same switch, and section 4 fails if the lane guard is partial
//       while the bracket guard is not -- which is exactly the shape a "just the arithmetic"
//       implementation would have.
//   [5] THE FALLBACK ARM PUBLISHES vd. A partial-VL helper call preserves vd's elements at and
//       above `vl` FROM CPUState, and the residency may hold a dirty vd CPUState has never seen.
//       Section 5 fails if the fallback block does not store the vd group before the call.
//
// It never executes what it builds and needs no AVX-512 host; the emitted x86 is checked in the
// report via llc on the dumped module.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstdlib>
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

llvm::LLVMContext g_ctx;

// THE FOUR funct6 THIS ROUTE LOWERS, AND THEY ARE THE WHOLE POPULATION. `Emit_rvvfalu` switches on
// `RvvFaluConstrainedIntrinsic`, whose only rows are these four, and the translator admits a funct6
// only if `vfalu_llvm_constrained_vv_supported` returns true -- which is the same four. So the
// +1.0 neutrality argument has to hold for fadd, fsub, fmul and fdiv and nothing else has to be
// argued about; every one of the six cases below is driven through this file.
constexpr u32 F6_VFADD = 0u, F6_VFSUB = 2u, F6_VFMUL = 0b100100u, F6_VFDIV = 0b100000u;
constexpr u32 OpFVV(u32 f6, u32 vs2, u32 vs1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (1u << 12) | (vd << 7) | 0x57u;
}
// The fused form Family A admits, and it is the ONLY one: `TRANSLATOR(vfma)` requires
// `funct6 == VF6_VFMADD`. `.vv` is funct3 0b001; `.vf` is 0b101 and its rs1 field names an F
// register, which `Create_rvvsplatf` broadcasts to a full V512 before the node ever sees it.
constexpr u32 F6_VFMADD = 0b101000u;
constexpr u32 OpFVF(u32 f6, u32 vs2, u32 rs1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (rs1 << 15) | (0b101u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 10u, kVs2 = 8u, kVs1 = 9u;

u32 VRegOff(u32 reg, u32 sub)
{
	return (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg) +
		     reg * rvv32::VLEN_MAX_BYTES + sub * 64u);
}

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c5fpA", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool fp_partial)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_llvm_fp_partial_vl = fp_partial;
	// `TRANSLATOR(vfma)`'s Family A arm refuses outright without this; it records that the
	// code-generation host has hardware FMA, without which LLVM lowers a strict constrained FMA
	// to a libc call.
	config::rvv_vector_ssa_host_fma = true;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_full_vl_fast_body = false;
}

void Translate(Built &b, bool backend)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!backend)
		return;
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

struct Qir {
	unsigned family_a = 0;	 // Op::_rvvfalu -- the P-vector-SSA route
	unsigned family_a_fma = 0; // Op::_rvvfma -- the fused P-vector-SSA route
	unsigned frames = 0;	 // Op::_rvvtypedchunkbegin -- Family B, must be absent here
	unsigned lane_ops = 0;	 // Op::_vchunkfalu -- likewise
	unsigned active_nodes = 0;
	unsigned brackets = 0;
	unsigned reads = 0; // Op::_rvvread -- how many chunk loads the translator materialised
	int falu_partial = -1;
	int fma_partial = -1;
	int fma_is_vf = -1;
	int bracket_partial = -1;
	unsigned falu_chunks = 0;
	// Whether the node's oldd slots (inputs 0..3) are distinct from its vs2 slots (4..7).
	int oldd_distinct = -1;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvfalu: {
				auto *f = static_cast<InstRVVFALU *>(&ins);
				++q.family_a;
				q.falu_partial = f->partial_vl ? 1 : 0;
				q.falu_chunks = f->active_chunks;
				// VOperand has no operator==; the chunk values are virtual VPRs, so
				// the virtual register index is the identity that matters.
				auto same = [](VOperand x, VOperand y) {
					if (!x.IsVirtualReg() || !y.IsVirtualReg())
						return false;
					return x.GetRegClass() == y.GetRegClass() &&
					       x.GetVirtualReg() == y.GetVirtualReg();
				};
				bool distinct = false;
				for (u8 c = 0; c < f->active_chunks; ++c)
					if (!same(f->i(c), f->i(4 + c)))
						distinct = true;
				q.oldd_distinct = distinct ? 1 : 0;
				break;
			}
			case Op::_rvvfma: {
				auto *m = static_cast<InstRVVFMA *>(&ins);
				++q.family_a_fma;
				q.fma_partial = m->partial_vl ? 1 : 0;
				q.fma_is_vf = m->is_vf ? 1 : 0;
				q.falu_chunks = m->active_chunks;
				break;
			}
			case Op::_rvvfpbegin:
				++q.brackets;
				q.bracket_partial =
				    static_cast<InstRVVFPBegin *>(&ins)->partial_vl ? 1 : 0;
				break;
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				break;
			case Op::_vchunkfalu:
				++q.lane_ops;
				break;
			case Op::_vchunkactive:
				++q.active_nodes;
				break;
			case Op::_rvvread:
				++q.reads;
				break;
			default:
				break;
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

// The constant byte offset of a CPUState access, or ~0u if the pointer is not a constant GEP off
// the state argument.
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

// Follow bitcasts back to the value that actually produced these bits.
llvm::Value *StripCasts(llvm::Value *v)
{
	while (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(v))
		v = bc->getOperand(0);
	return v;
}

bool IsConstantSplatFP(llvm::Value *v, double want)
{
	auto *c = llvm::dyn_cast<llvm::Constant>(v);
	if (!c || !c->getType()->isFPOrFPVectorTy())
		return false;
	auto *sp = c->getSplatValue();
	auto *cf = sp ? llvm::dyn_cast<llvm::ConstantFP>(sp) : nullptr;
	return cf && cf->isExactlyValue(want);
}

bool IsNaNSplat(llvm::Value *v)
{
	auto *c = llvm::dyn_cast<llvm::Constant>(v);
	if (!c || !c->getType()->isFPOrFPVectorTy())
		return false;
	auto *sp = c->getSplatValue();
	auto *cf = sp ? llvm::dyn_cast<llvm::ConstantFP>(sp) : nullptr;
	return cf && cf->getValueAPF().isNaN();
}

struct IRFacts {
	unsigned constrained_calls = 0;
	unsigned neutral_one = 0;  // select(mask, operand, splat +1.0)
	unsigned neutral_zero = 0; // ... splat +0.0 -- must never happen, vfdiv raises NV
	unsigned canon_selects = 0;   // select(isnan, canonical-NaN splat, v)
	unsigned merge_selects = 0;   // select(mask, computed, old vd) -- neither arm constant
	unsigned merge_after_canon = 0;	     // ... whose computed arm IS the canonical select
	unsigned merge_old_from_vd = 0;	     // ... whose preserved arm loads vreg[vd]
	unsigned merge_mask_is_neutral_mask = 0; // ... sharing the chunk's neutralisation predicate
	unsigned vl_cmp_eq = 0, vl_cmp_ule = 0;  // how every vl compare in the module is spelled
	// Per select condition, the constant index vector it compares against vl.
	std::vector<std::pair<llvm::Value *, std::vector<u32>>> mask_indices;
	// Stores in the `rvv.falu.fallback` block, by CPUState offset.
	bool fallback_stores_vd = false, fallback_stores_vs2 = false, fallback_stores_vs1 = false;
};

std::vector<u32> MaskIndexVector(llvm::Value *cond)
{
	std::vector<u32> idx;
	auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(cond);
	if (!cmp)
		return idx;
	auto *cv = llvm::dyn_cast<llvm::Constant>(cmp->getOperand(0));
	auto *vt = cv ? llvm::dyn_cast<llvm::FixedVectorType>(cv->getType()) : nullptr;
	if (!vt)
		return idx;
	for (u32 k = 0; k < vt->getNumElements(); ++k)
		if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(cv->getAggregateElement(k)))
			idx.push_back((u32)ci->getZExtValue());
	return idx;
}

IRFacts ScanIR(llvm::Function *fn, u32 vd, u32 vs2, u32 vs1)
{
	IRFacts f;
	llvm::Value *state = fn->getArg(0);
	u32 const vl_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
	// A chunk operand is NOT a direct CPUState load: `Emit_rvvread` loads `vreg[r]` once into a
	// QIR vreg slot (an alloca) and every consumer loads the alloca. So to say "this preserved
	// arm is the old vd" the chain alloca <- store <- load vreg[vd] has to be followed. Matching
	// on a direct state load instead would have made the check vacuously false -- which is how
	// this was found.
	std::vector<std::pair<llvm::Value *, u32>> vloc_src;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
				if (llvm::isa<llvm::AllocaInst>(st->getPointerOperand()))
					if (auto *src = llvm::dyn_cast<llvm::LoadInst>(
						StripCasts(st->getValueOperand()))) {
						u32 const o =
						    StateOffset(src->getPointerOperand(), state);
						if (o != ~0u)
							vloc_src.emplace_back(
							    st->getPointerOperand(), o);
					}
	auto vloc_offset = [&](llvm::Value *ptr) {
		for (auto const &e : vloc_src)
			if (e.first == ptr)
				return e.second;
		return ~0u;
	};
	// Which SSA values are a load of `vec.vl`, so a compare against one can be recognised.
	std::vector<llvm::Value *> vl_loads;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins))
				if (StateOffset(l->getPointerOperand(), state) == vl_off)
					vl_loads.push_back(l);
	auto is_vl_derived = [&](llvm::Value *v) {
		v = StripCasts(v);
		for (auto *l : vl_loads) {
			if (v == l)
				return true;
			// the splat the lane mask compares against
			if (auto *sv = llvm::dyn_cast<llvm::ShuffleVectorInst>(v))
				if (auto *iv = llvm::dyn_cast<llvm::InsertElementInst>(
					StripCasts(sv->getOperand(0))))
					if (StripCasts(iv->getOperand(1)) == l)
						return true;
		}
		return false;
	};

	for (auto &bb : *fn) {
		// BOTH families' fallback blocks. Scoping this to `rvv.falu.fallback` alone would have
		// made every fused-route fallback assertion silently vacuous -- that block is named
		// `rvv.fma.fallback` -- which is exactly how the placeholder this replaced went unnoticed.
		bool const is_fallback = bb.getName().starts_with("rvv.falu.fallback") ||
					 bb.getName().starts_with("rvv.fma.fallback");
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				auto const id = ii->getIntrinsicID();
				if (id == llvm::Intrinsic::experimental_constrained_fadd ||
				    id == llvm::Intrinsic::experimental_constrained_fsub ||
				    id == llvm::Intrinsic::experimental_constrained_fmul ||
				    id == llvm::Intrinsic::experimental_constrained_fdiv ||
				    id == llvm::Intrinsic::experimental_constrained_fma)
					++f.constrained_calls;
				continue;
			}
			if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(&ins)) {
				// Only the SCALAR vl compares are the guard's; the lane mask is a
				// vector compare and is accounted separately.
				if (!cmp->getType()->isVectorTy() &&
				    (is_vl_derived(cmp->getOperand(0)) ||
				     is_vl_derived(cmp->getOperand(1)))) {
					if (cmp->getPredicate() == llvm::CmpInst::ICMP_EQ)
						++f.vl_cmp_eq;
					else if (cmp->getPredicate() == llvm::CmpInst::ICMP_ULE)
						++f.vl_cmp_ule;
				}
				continue;
			}
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				if (!is_fallback)
					continue;
				u32 const off = StateOffset(st->getPointerOperand(), state);
				for (u32 sub = 0; sub < 2; ++sub) {
					if (off == VRegOff(vd, sub))
						f.fallback_stores_vd = true;
					if (off == VRegOff(vs2, sub))
						f.fallback_stores_vs2 = true;
					if (off == VRegOff(vs1, sub))
						f.fallback_stores_vs1 = true;
				}
				continue;
			}
			auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins);
			if (!sel)
				continue;
			llvm::Value *t = sel->getTrueValue(), *fa = sel->getFalseValue();
			if (IsNaNSplat(t)) {
				++f.canon_selects;
				continue;
			}
			if (IsConstantSplatFP(fa, 1.0)) {
				++f.neutral_one;
				f.mask_indices.emplace_back(sel->getCondition(),
							    MaskIndexVector(sel->getCondition()));
				continue;
			}
			if (IsConstantSplatFP(fa, 0.0)) {
				++f.neutral_zero;
				continue;
			}
			if (llvm::isa<llvm::Constant>(t) || llvm::isa<llvm::Constant>(fa))
				continue;
			// Neither arm constant: this is the destination merge.
			++f.merge_selects;
			auto *computed = llvm::dyn_cast<llvm::SelectInst>(StripCasts(t));
			if (computed && IsNaNSplat(computed->getTrueValue()))
				++f.merge_after_canon;
			auto *old = llvm::dyn_cast<llvm::LoadInst>(StripCasts(fa));
			if (old) {
				u32 off = StateOffset(old->getPointerOperand(), state);
				if (off == ~0u)
					off = vloc_offset(old->getPointerOperand());
				for (u32 sub = 0; sub < 2; ++sub)
					if (off == VRegOff(vd, sub))
						++f.merge_old_from_vd;
			}
			for (auto const &m : f.mask_indices)
				if (m.first == sel->getCondition()) {
					++f.merge_mask_is_neutral_mask;
					break;
				}
		}
	}
	return f;
}

struct Case {
	char const *name;
	u32 f6;
	u32 vt;
};
constexpr Case kCases[] = {
    {"vfadd.vv e32", F6_VFADD, kVT_E32M1}, {"vfsub.vv e32", F6_VFSUB, kVT_E32M1},
    {"vfmul.vv e32", F6_VFMUL, kVT_E32M1}, {"vfdiv.vv e32", F6_VFDIV, kVT_E32M1},
    {"vfadd.vv e64", F6_VFADD, kVT_E64M1}, {"vfdiv.vv e64", F6_VFDIV, kVT_E64M1},
};
constexpr size_t kNCases = sizeof(kCases) / sizeof(kCases[0]);

// ------------------------------------------------------------------------------------------
// [1][2][3] The body: neutralised operands, a destination merge, and the merge after the
// canonical-NaN select rather than before it.
void SectionBody()
{
	printf("[A-1..3] neutralised operands, destination merge, merge AFTER canonicalisation\n");
	unsigned admitted[kNCases] = {};
	for (u32 vlen : {512u, 1024u})
		for (size_t ci = 0; ci < kNCases; ++ci) {
			auto const &c = kCases[ci];
			Configure(vlen, true, /*fp_partial=*/true);
			Built b({Vsetvli(c.vt), OpFVV(c.f6, kVs2, kVs1, kVd), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C5FPA_TRACE"))
				printf("   trace vlen=%u %-14s rvvfalu=%u frames=%u vchunkfalu=%u "
				       "chunks=%u partial=%d oldd_distinct=%d\n",
				       vlen, c.name, q.family_a, q.frames, q.lane_ops, q.falu_chunks,
				       q.falu_partial, q.oldd_distinct);
			if (!q.family_a)
				continue;
			++admitted[ci];
			// Family A really is the owner at these widths: no typed frame exists.
			CHECK_EQ(q.frames, 0u);
			CHECK_EQ(q.lane_ops, 0u);
			CHECK_EQ(q.active_nodes, 0u);
			CHECK_EQ(q.falu_partial, 1);
			// the oldd operands are a real vd read, not the vs2 aliases
			CHECK_EQ(q.oldd_distinct, 1);

			IRFacts ir = ScanIR(b.fn, kVd, kVs2, kVs1);
			unsigned const chunks = q.falu_chunks;
			CHECK_EQ(chunks, vlen / 512u);
			// [1] both operands of every chunk op are neutralised, with +1.0
			CHECK_EQ(ir.neutral_one, 2u * chunks);
			CHECK_EQ(ir.neutral_zero, 0u);
			CHECK_EQ(ir.constrained_calls, chunks);
			// [2] one destination merge per chunk, preserving a load of vreg[vd]
			CHECK_EQ(ir.merge_selects, chunks);
			CHECK_EQ(ir.merge_old_from_vd, chunks);
			// ... under the SAME predicate that neutralised that chunk's operands, which
			// is what ties the merge to the chunk's own element base
			CHECK_EQ(ir.merge_mask_is_neutral_mask, chunks);
			// [3] the merged-in value is the canonicalised result, not the raw call
			CHECK_EQ(ir.canon_selects, chunks);
			CHECK_EQ(ir.merge_after_canon, chunks);
			// each chunk's mask starts at its own element base [c*lanes, +lanes)
			{
				unsigned const lanes =
				    (unsigned)(64u / (c.vt == kVT_E64M1 ? 8u : 4u));
				unsigned bad = 0;
				for (size_t s = 0; s < ir.mask_indices.size(); ++s) {
					auto const &idx = ir.mask_indices[s].second;
					if (idx.size() != lanes) {
						++bad;
						continue;
					}
					u32 const base = (u32)(s / 2) * lanes;
					for (size_t k = 0; k < idx.size(); ++k)
						if (idx[k] != base + (u32)k) {
							++bad;
							break;
						}
				}
				if (bad) {
					printf("  FAIL %s vlen=%u: %u masks do not start at their "
					       "chunk's element base\n", c.name, vlen, bad);
					++g_fail;
				}
			}
		}
	for (size_t ci = 0; ci < kNCases; ++ci)
		if (admitted[ci] == 0) {
			printf("  FAIL '%s' was never admitted by Family A -- its rows are vacuous\n",
			       kCases[ci].name);
			++g_fail;
		}
}

// [4] The bracket's guard is widened with the same switch. A body that admits `vl <= VLMAX` inside
// a bracket that only opens at `vl == VLMAX` computes in the host rounding mode and drops its
// flags, so "every vl compare in the module is ULE" is the assertion, not "the falu one is".
void SectionBracket()
{
	printf("[A-4] the FP bracket guard is widened with the body, never one without the other\n");
	for (u32 vlen : {512u, 1024u})
		for (int on = 0; on < 2; ++on) {
			Configure(vlen, true, /*fp_partial=*/on == 1);
			Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFDIV, kVs2, kVs1, kVd), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (!q.family_a)
				continue;
			CHECK_EQ(q.brackets, 1u);
			CHECK_EQ(q.bracket_partial, on);
			CHECK_EQ(q.falu_partial, on);
			IRFacts ir = ScanIR(b.fn, kVd, kVs2, kVs1);
			// two guards in this module: the bracket's and the falu's
			if (on) {
				CHECK_EQ(ir.vl_cmp_eq, 0u);
				CHECK_EQ(ir.vl_cmp_ule, 2u);
			} else {
				CHECK_EQ(ir.vl_cmp_ule, 0u);
				CHECK_EQ(ir.vl_cmp_eq, 2u);
			}
		}
}

// [5] The fallback arm publishes vd. `rvv_ref::vfalu` preserves elements at and above `vl` from
// CPUState, and the residency can hold a dirty vd; without this store the helper would preserve
// stale bytes and they would be read straight back in.
void SectionFallbackPublishesVd()
{
	printf("[A-5] the fallback arm stores vd before the helper call when VL may be partial\n");
	for (u32 vlen : {512u, 1024u})
		for (int on = 0; on < 2; ++on) {
			Configure(vlen, true, /*fp_partial=*/on == 1);
			Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFADD, kVs2, kVs1, kVd), kJalr});
			Translate(b, true);
			if (!ScanQir(b.region).family_a)
				continue;
			IRFacts ir = ScanIR(b.fn, kVd, kVs2, kVs1);
			CHECK(ir.fallback_stores_vs2);
			CHECK(ir.fallback_stores_vs1);
			CHECK_EQ(ir.fallback_stores_vd, on == 1);
		}
}

// [6] Off is inert: no selects beyond canonicalisation, no vd read materialised, EQ guards.
void SectionOffIsInert()
{
	printf("[A-6] switch off: full-VL guards, no merge, and no vd chunk read at all\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned reads[2] = {0, 0};
		for (int on = 0; on < 2; ++on) {
			Configure(vlen, true, /*fp_partial=*/on == 1);
			Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFMUL, kVs2, kVs1, kVd), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (!q.family_a)
				continue;
			reads[on] = q.reads;
			if (on)
				continue;
			CHECK_EQ(q.falu_partial, 0);
			CHECK_EQ(q.oldd_distinct, 0);
			IRFacts ir = ScanIR(b.fn, kVd, kVs2, kVs1);
			CHECK_EQ(ir.neutral_one, 0u);
			CHECK_EQ(ir.neutral_zero, 0u);
			CHECK_EQ(ir.merge_selects, 0u);
			CHECK_EQ(ir.canon_selects, q.falu_chunks);
		}
		// The vd group is read ONLY when the switch is on: one extra rvvread per chunk.
		if (reads[0] || reads[1])
			CHECK_EQ(reads[1] - reads[0], vlen / 512u);
	}
}

// ------------------------------------------------------------------------------------------
// [8] THE FUSED FORM. Same three obligations, one operand more, and one trap of its own: the `.vf`
// broadcast is a LANE operand by the time the node sees it, so it has to be neutralised like the
// other two. A route that neutralised only `d` and `a` would still show "selects present" to any
// count that did not know the operand arity, which is why this section asserts 3 per chunk.
struct FmaCase {
	char const *name;
	u32 vt;
	bool is_vf;
};
constexpr FmaCase kFmaCases[] = {
    {"vfmadd.vv e32", kVT_E32M1, false}, {"vfmadd.vv e64", kVT_E64M1, false},
    {"vfmadd.vf e32", kVT_E32M1, true},  {"vfmadd.vf e64", kVT_E64M1, true},
};
constexpr size_t kNFma = sizeof(kFmaCases) / sizeof(kFmaCases[0]);

void SectionFma()
{
	printf("[A-8] vfmadd: three neutralised operands incl. the .vf broadcast, merge from old vd\n");
	unsigned admitted[kNFma] = {};
	for (u32 vlen : {512u, 1024u})
		for (size_t ci = 0; ci < kNFma; ++ci) {
			auto const &c = kFmaCases[ci];
			Configure(vlen, true, /*fp_partial=*/true);
			u32 const op = c.is_vf ? OpFVF(F6_VFMADD, kVs2, kVs1, kVd)
					       : OpFVV(F6_VFMADD, kVs2, kVs1, kVd);
			Built b({Vsetvli(c.vt), op, kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C5FPA_TRACE"))
				printf("   trace vlen=%u %-14s rvvfma=%u frames=%u chunks=%u partial=%d "
				       "is_vf=%d\n", vlen, c.name, q.family_a_fma, q.frames,
				       q.falu_chunks, q.fma_partial, q.fma_is_vf);
			if (!q.family_a_fma)
				continue;
			++admitted[ci];
			CHECK_EQ(q.frames, 0u);
			CHECK_EQ(q.active_nodes, 0u);
			CHECK_EQ(q.fma_partial, 1);
			CHECK_EQ(q.fma_is_vf, c.is_vf ? 1 : 0);
			// the bracket is widened for the fused route too
			CHECK_EQ(q.bracket_partial, 1);

			IRFacts ir = ScanIR(b.fn, kVd, kVs2, kVs1);
			unsigned const chunks = q.falu_chunks;
			CHECK_EQ(chunks, vlen / 512u);
			// THREE operands per chunk, not two -- including the `.vf` broadcast
			CHECK_EQ(ir.neutral_one, 3u * chunks);
			CHECK_EQ(ir.neutral_zero, 0u);
			CHECK_EQ(ir.constrained_calls, chunks);
			// one merge per chunk, preserving the OLD vd (the un-neutralised multiplicand)
			CHECK_EQ(ir.merge_selects, chunks);
			CHECK_EQ(ir.merge_old_from_vd, chunks);
			CHECK_EQ(ir.merge_mask_is_neutral_mask, chunks);
			CHECK_EQ(ir.canon_selects, chunks);
			CHECK_EQ(ir.merge_after_canon, chunks);
			// The fallback arm publishes vd, and on this route it does so unconditionally
			// because `vfmadd` reads vd in every execution. vs2 likewise; vs1 only in the
			// `.vv` form, because the `.vf` slots 8..11 are aliases of oldd and the helper
			// reads the scalar from the F register itself.
			CHECK(ir.fallback_stores_vd);
			CHECK(ir.fallback_stores_vs2);
			CHECK_EQ(ir.fallback_stores_vs1, !c.is_vf);
			// per-chunk element bases
			{
				unsigned const lanes =
				    (unsigned)(64u / (c.vt == kVT_E64M1 ? 8u : 4u));
				unsigned bad = 0;
				for (size_t sidx = 0; sidx < ir.mask_indices.size(); ++sidx) {
					auto const &idx = ir.mask_indices[sidx].second;
					if (idx.size() != lanes) {
						++bad;
						continue;
					}
					u32 const base = (u32)(sidx / 3) * lanes; // three per chunk
					for (size_t k = 0; k < idx.size(); ++k)
						if (idx[k] != base + (u32)k) {
							++bad;
							break;
						}
				}
				if (bad) {
					printf("  FAIL %s vlen=%u: %u fused masks do not start at their "
					       "chunk's element base\n", c.name, vlen, bad);
					++g_fail;
				}
			}
		}
	for (size_t ci = 0; ci < kNFma; ++ci)
		if (admitted[ci] == 0) {
			printf("  FAIL '%s' was never admitted by Family A -- its rows are vacuous\n",
			       kFmaCases[ci].name);
			++g_fail;
		}
}

// [9] Off is inert for the fused route too: no neutralisation, no merge, EQ guards. `oldd` is read
// either way here -- `vfmadd` needs it as a multiplicand -- so unlike vfalu the QIR read count is
// expected to be IDENTICAL, which is what this asserts rather than a difference.
void SectionFmaOffIsInert()
{
	printf("[A-9] switch off: fused route keeps full-VL guards, no merge, same operand reads\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned reads[2] = {0, 0};
		bool seen[2] = {false, false};
		for (int on = 0; on < 2; ++on) {
			Configure(vlen, true, /*fp_partial=*/on == 1);
			Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFMADD, kVs2, kVs1, kVd), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (!q.family_a_fma)
				continue;
			seen[on] = true;
			reads[on] = q.reads;
			IRFacts ir = ScanIR(b.fn, kVd, kVs2, kVs1);
			if (on) {
				CHECK_EQ(q.fma_partial, 1);
				CHECK_EQ(ir.neutral_one, 3u * q.falu_chunks);
				CHECK_EQ(ir.merge_selects, q.falu_chunks);
				CHECK_EQ(ir.vl_cmp_eq, 0u);
				CHECK_EQ(ir.vl_cmp_ule, 2u);
			} else {
				CHECK_EQ(q.fma_partial, 0);
				CHECK_EQ(ir.neutral_one, 0u);
				CHECK_EQ(ir.neutral_zero, 0u);
				CHECK_EQ(ir.merge_selects, 0u);
				CHECK_EQ(ir.canon_selects, q.falu_chunks);
				CHECK_EQ(ir.vl_cmp_ule, 0u);
				CHECK_EQ(ir.vl_cmp_eq, 2u);
			}
		}
		if (seen[0] && seen[1])
			CHECK_EQ(reads[0], reads[1]);
	}
}

// [7] The QCG arm does not depend on this switch.
void SectionQcgUntouched()
{
	printf("[A-7] QCG admission does not depend on the C5-FP switch\n");
	unsigned kinds[2] = {0, 0};
	for (int k = 0; k < 2; ++k) {
		Configure(1024u, /*llvm*/ false, /*fp_partial=*/k == 1);
		Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFADD, kVs2, kVs1, kVd), kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		kinds[k] = q.frames * 100u + q.lane_ops * 10u + q.family_a;
	}
	CHECK_EQ(kinds[0], kinds[1]);
}

void DumpIR()
{
	char const *path = getenv("C5FPA_DUMP_IR");
	if (!path)
		return;
	// VLEN 1024, so the dump has TWO chunks and the per-chunk element bases are visible. At any
	// width Family B does not own, this is the only route that exists.
	Configure(1024u, true, true);
	Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFDIV, kVs2, kVs1, kVd), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

void DumpFmaIR()
{
	char const *path = getenv("C5FPA_DUMP_IR_FMA");
	if (!path)
		return;
	// The `.vf` form at VLEN 1024: two chunks, and the broadcast operand visible as a third
	// neutralised lane vector rather than as a scalar.
	Configure(1024u, true, true);
	Built b({Vsetvli(kVT_E32M1), OpFVF(F6_VFMADD, kVs2, kVs1, kVd), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (fused IR dumped to %s)\n", path);
}

} // namespace

int main()
{
	printf("rvv_llvm_fp_partial_vl_familya_test\n");
	SectionBody();
	SectionBracket();
	SectionFallbackPublishesVd();
	SectionOffIsInert();
	SectionQcgUntouched();
	SectionFma();
	SectionFmaOffIsInert();
	DumpIR();
	DumpFmaIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
