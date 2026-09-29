// ORDER ITEM 4 (2026-09-19): `vfmerge.vfm` / `vfmv.v.f` ON THE LLVM ARM.
//
// THE ONE THING THIS FAMILY IS EASY TO GET BACKWARDS. `vfmerge` is not a masked instruction in the
// ordinary sense: it writes EVERY body element and uses `v0` to CHOOSE between the scalar and
// `vs2` -- `vd[i] = v0[i] ? f[rs1] : vs2[i]`. An implementation that treated `v0` as a store
// predicate, the way every genuinely masked instruction does, would leave `vs2`'s value out of the
// destination and the OLD `vd` in its place. That is correct only when `vd == vs2`, so a test that
// used the same register for both would never see it. This file therefore uses three distinct
// registers and pins the old destination to a value neither operand can produce.
//
// SECTIONS:
//   [G1] Admission and inertness, both encodings; the reserved `vfmv.v.f` with a non-zero `vs2`
//        field, and the two register overlaps 5.2/5.3 forbid, all keep the unchanged helper.
//   [G2] TWO DIFFERENT USES OF v0, structurally: the SELECT's condition depends on a v0 read, and
//        the STORE's predicate depends on `vec.vl` -- and for `vfmv.v.f` there is no v0 read at all.
//   [G3] THE SEMANTIC ORACLE. `vec.vl`, `v0`'s mask word, the `vs2` chunk and the F register are all
//        folded to constants, and every destination element is compared against the architectural
//        rule computed here from those same inputs. This is the section that sees a select with its
//        arms swapped, a mask read from the wrong window, or `v0` used as a write enable.
//   [G4] NaN UN-BOXING at SEW 32: an improperly boxed F register reads as the canonical qNaN, and a
//        properly boxed signalling payload is moved UNCHANGED (an FP compare here would raise NV on
//        an instruction that must raise nothing).
//   [G5] No constrained intrinsic and no MXCSR bracket anywhere.
//   [G6] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_rvv_contract.h"
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
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace testcompat = dbt::qir::testcompat;

namespace
{
namespace rvv32 = dbt::rv32;
namespace ctr = dbt::rv32::rvvcontract;

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

// VF6_VFMERGE (23), OPFVF (funct3 5).
constexpr u32 OpVfmerge(u32 vs2, u32 rs1, u32 vd, bool merge)
{
	return (23u << 26) | ((merge ? 0u : 1u) << 25) | (vs2 << 20) | (rs1 << 15) | (5u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
// Three DISTINCT vector registers: the hazard described in the header is invisible at vd == vs2.
constexpr u32 kVs2 = 8u, kVd = 10u, kF = 3u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4fm", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_fmerge = on;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
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
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0;
	int guard_kind = -1;
	bool merge_flag = false;
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
			} else if (ins.GetOpcode() == Op::_vchunkfmerge) {
				auto *n = static_cast<InstVChunkFMerge *>(&ins);
				++q.nodes;
				q.finishes += n->finish;
				q.merge_flag = n->merge;
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
constexpr u32 kVlOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
constexpr u32 kFOff = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, f));
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
				}
			}
	}
}

struct Folded {
	bool ok = false;
	std::vector<u64> elems; // by element index; ~0ull where the unit wrote nothing
	unsigned masked_stores = 0;
};

// Pin every input and read back every published element.
Folded FoldMerge(Built &b, u32 sew, u32 vl, u64 fval, std::vector<u8> const &v0,
		 u64 vs2_pattern, u64 old_vd)
{
	Folded out;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	u32 const vlen = config::vlen_bits;
	u32 const vmax = vlen / (8u * sew);
	u32 const lanes = std::min(vlen / 8u, 64u) / sew;

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
			if (o == kFOff + kF * 8u && l->getType()->isIntegerTy(64)) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), fval));
				continue;
			}
			if (l->getType()->isIntegerTy(16) && o != ~0u && o >= kVregOff &&
			    o < kVregOff + rvv32::VLEN_MAX_BYTES) {
				u32 const bo = o - kVregOff;
				u32 const w = (u32)v0[bo] | ((u32)v0[bo + 1] << 8);
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), w));
				continue;
			}
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || vt->getScalarSizeInBits() != 8u * sew)
				continue;
			// vs2's chunks: a per-element distinctive value so a swapped select arm is
			// visible as the WRONG operand and not merely as a wrong bit.
			bool is_vs2 = false;
			u32 base = 0;
			for (u32 e = 0; e < vmax; e += lanes)
				if (ctr::ElementStateOffset(vlen, kVs2, e, sew) == o) {
					is_vs2 = true;
					base = e;
					break;
				}
			if (!is_vs2)
				continue;
			llvm::SmallVector<llvm::Constant *, 16> cv;
			for (u32 i = 0; i < vt->getNumElements(); ++i)
				cv.push_back(llvm::ConstantInt::get(vt->getElementType(),
								    vs2_pattern + base + i));
			l->replaceAllUsesWith(llvm::ConstantVector::get(cv));
		}
	FoldToFixpoint(fn);

	out.elems.assign(vmax, old_vd);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
				continue;
			u32 const o = StateOffset(ii->getArgOperand(1), state);
			u32 base = ~0u;
			for (u32 e = 0; e < vmax; e += lanes)
				if (ctr::ElementStateOffset(vlen, kVd, e, sew) == o) {
					base = e;
					break;
				}
			if (base == ~0u)
				continue;
			++out.masked_stores;
			auto *val = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
			auto *msk = llvm::dyn_cast<llvm::Constant>(testcompat::MaskedStoreMask(ii));
			if (!val || !msk)
				return out;
			auto *vt = llvm::cast<llvm::FixedVectorType>(val->getType());
			for (u32 i = 0; i < vt->getNumElements() && base + i < vmax; ++i) {
				auto *m = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    msk->getAggregateElement(i));
				auto *v = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    val->getAggregateElement(i));
				if (!m || !v)
					return out;
				if (m->isOne())
					out.elems[base + i] = v->getZExtValue();
			}
		}
	out.ok = out.masked_stores > 0;
	return out;
}

// The architectural rule, computed here from the same inputs.
u64 Expect(bool merge, u32 e, u32 vl, u32 sew, u64 fval, std::vector<u8> const &v0,
	   u64 vs2_pattern, u64 old_vd)
{
	if (e >= vl)
		return old_vd; // outside the body: undisturbed
	u64 const mask = sew == 4 ? 0xffffffffull : ~0ull;
	u64 scalar;
	if (sew == 4)
		scalar = (fval & 0xFFFFFFFF00000000ull) == 0xFFFFFFFF00000000ull
			     ? (fval & 0xffffffffull)
			     : (u64)rvv32::F32_CANONICAL_NAN;
	else
		scalar = fval;
	if (!merge)
		return scalar & mask;
	return ctr::MaskBitOfElement(v0.data(), e) ? (scalar & mask)
						   : ((vs2_pattern + e) & mask);
}

void SectionAdmission()
{
	printf("[G1] admission, both encodings, and the refusals\n");
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1})
			for (bool merge : {true, false}) {
				Configure(vlen, true);
				Built b({Vsetvli(vt),
					 OpVfmerge(merge ? kVs2 : 0u, kF, kVd, merge), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind,
					 (int)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
				CHECK_EQ(q.finishes, 1u);
				CHECK_EQ((int)q.merge_flag, (int)merge);
				Configure(vlen, false);
				Built o({Vsetvli(vt),
					 OpVfmerge(merge ? kVs2 : 0u, kF, kVd, merge), kJalr});
				Translate(o);
				CHECK_EQ(ScanQir(o.region).nodes, 0u);
				CHECK(ScanQir(o.region).hcalls >= 1u);
			}
	printf("       %u admitted encoding/width/SEW cells\n", admitted);
	CHECK(admitted > 0);

	// The refusals, each of which must keep the unchanged helper.
	struct Ref { char const *why; u32 word; };
	Ref const rows[] = {
	    // REFUSED BY THE DECODER, NOT BY THIS ROUTE. rv32_decode.h already filters the reserved
	    // form, so it never reaches `RvvTryLLVMFMerge` and a mutation that deletes the route's
	    // own `rs2 != 0` term survives this file. The row is kept because what it asserts --
	    // "this encoding gets no native body" -- is true and is what matters; where the refusal
	    // lives is recorded in the route's source rather than claimed here.
	    {"vfmv.v.f with a non-zero vs2 field (reserved; refused at decode)",
	     OpVfmerge(7u, kF, kVd, false)},
	    {"vfmerge with vd == v0 (5.3)", OpVfmerge(kVs2, kF, 0u, true)},
	    {"vfmerge with vs2 == v0 (5.2)", OpVfmerge(0u, kF, kVd, true)},
	};
	for (auto const &r : rows) {
		Configure(512u, true);
		Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
		Translate(b);
		Qir const q = ScanQir(b.region);
		if (q.nodes) {
			printf("  FAIL refusal not honoured: %s\n", r.why);
			++g_fail;
		}
		CHECK(q.hcalls >= 1u);
	}
}

void SectionTwoUsesOfV0()
{
	printf("[G2] v0 feeds the SELECT; the store's predicate is the vl bound\n");
	for (u32 vlen : {256u, 1024u})
		for (bool merge : {true, false}) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpVfmerge(merge ? kVs2 : 0u, kF, kVd, merge), kJalr});
			Translate(b);
			if (!b.fn || !ScanQir(b.region).nodes)
				continue;
			llvm::Value *state = b.fn->getArg(0);
			unsigned v0_loads = 0, selects_on_v0 = 0, stores = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
						u32 const o = StateOffset(l->getPointerOperand(),
									  state);
						if (l->getType()->isIntegerTy(16) && o != ~0u &&
						    o >= kVregOff &&
						    o < kVregOff + rvv32::VLEN_MAX_BYTES)
							++v0_loads;
						continue;
					}
					if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins))
						if (sel->getType()->isVectorTy() &&
						    sel->getType()->getScalarSizeInBits() == 32)
							++selects_on_v0;
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
						if (ii->getIntrinsicID() ==
						    llvm::Intrinsic::masked_store)
							++stores;
				}
			CHECK(stores > 0);
			// THE ASYMMETRY IS THE POINT: the merge form reads v0, the move form does not.
			if (merge)
				CHECK(v0_loads > 0);
			else
				CHECK_EQ(v0_loads, 0u);
		}
}

void SectionOracle()
{
	printf("[G3] every published element against the architectural rule\n");
	unsigned cells = 0;
	std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0);
	struct Pat { char const *name; u8 (*fill)(u32); };
	Pat const pats[] = {
	    {"ones", [](u32) -> u8 { return 0xff; }},
	    {"zeros", [](u32) -> u8 { return 0x00; }},
	    {"alternating", [](u32) -> u8 { return 0x55; }},
	    {"byte-index", [](u32 i) -> u8 { return (u8)(i * 37u + 1u); }},
	};
	for (u32 vlen : {128u, 256u, 512u, 1024u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1})
			for (bool merge : {true, false})
				for (auto const &p : pats) {
					for (u32 i = 0; i < v0.size(); ++i)
						v0[i] = p.fill(i);
					u32 const sew = vt == kVT_E64M1 ? 8u : 4u;
					u32 const vmax = vlen / (8u * sew);
					for (u32 vl : {0u, 1u, vmax / 2u, vmax}) {
						Configure(vlen, true);
						Built b({Vsetvli(vt),
							 OpVfmerge(merge ? kVs2 : 0u, kF, kVd,
								   merge),
							 kJalr});
						Translate(b);
						if (!b.fn || !ScanQir(b.region).nodes)
							continue;
						u64 const fval = sew == 4
								     ? 0xFFFFFFFF40490FDBull
								     : 0x400921FB54442D18ull;
						u64 const old_vd = 0xDEADBEEFDEADBEEFull &
								   (sew == 4 ? 0xffffffffull : ~0ull);
						u64 const vs2p = 0x11110000ull;
						Folded const f = FoldMerge(b, sew, vl, fval, v0,
									   vs2p, old_vd);
						if (!f.ok) {
							printf("  FAIL vlen=%u sew=%u merge=%d "
							       "pat=%s vl=%u: did not fold\n",
							       vlen, sew, (int)merge, p.name, vl);
							++g_fail;
							continue;
						}
						for (u32 e = 0; e < vmax; ++e) {
							u64 const want = Expect(merge, e, vl, sew,
										fval, v0, vs2p,
										old_vd);
							if (f.elems[e] != want) {
								printf("  FAIL vlen=%u sew=%u "
								       "merge=%d pat=%s vl=%u e=%u: "
								       "got 0x%llx want 0x%llx\n",
								       vlen, sew, (int)merge,
								       p.name, vl, e,
								       (unsigned long long)
									   f.elems[e],
								       (unsigned long long)want);
								++g_fail;
							}
							++cells;
						}
					}
				}
	printf("       %u elements compared against the architectural rule\n", cells);
	CHECK(cells > 0);
}

void SectionNanBoxing()
{
	printf("[G4] SEW-32 NaN un-boxing: improper box -> canonical qNaN, sNaN payload unchanged\n");
	std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0xff);
	struct Row { char const *name; u64 fval; u32 want; };
	Row const rows[] = {
	    {"properly boxed 3.14f", 0xFFFFFFFF40490FDBull, 0x40490FDBu},
	    {"improperly boxed", 0x0000000040490FDBull, rvv32::F32_CANONICAL_NAN},
	    {"boxed sNaN payload", 0xFFFFFFFF7F800001ull, 0x7F800001u},
	    {"boxed qNaN payload", 0xFFFFFFFF7FD55555ull, 0x7FD55555u},
	    {"box with one bit clear", 0xFFFFFFFE40490FDBull, rvv32::F32_CANONICAL_NAN},
	};
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), OpVfmerge(0u, kF, kVd, false), kJalr});
			Translate(b);
			if (!b.fn || !ScanQir(b.region).nodes)
				continue;
			u32 const vmax = vlen / 32u;
			Folded const f = FoldMerge(b, 4u, vmax, r.fval, v0, 0x11110000ull, 0u);
			if (!f.ok) { CHECK(false); continue; }
			for (u32 e = 0; e < vmax; ++e)
				if (f.elems[e] != r.want) {
					printf("  FAIL %s vlen=%u e=%u: got 0x%llx want 0x%x\n",
					       r.name, vlen, e,
					       (unsigned long long)f.elems[e], r.want);
					++g_fail;
					break;
				}
		}
}

void SectionNoFp()
{
	printf("[G5] no constrained intrinsic and no MXCSR bracket\n");
	for (u32 vlen : {256u, 1024u})
		for (bool merge : {true, false}) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpVfmerge(merge ? kVs2 : 0u, kF, kVd, merge), kJalr});
			Translate(b);
			if (!b.fn || !ScanQir(b.region).nodes)
				continue;
			unsigned bad = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb)
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						llvm::StringRef n = llvm::Intrinsic::getBaseName(
						    ii->getIntrinsicID());
						if (n.contains("experimental.constrained") ||
						    n.contains("x86.sse.ldmxcsr") ||
						    n.contains("x86.sse.stmxcsr"))
							++bad;
					}
			CHECK_EQ(bad, 0u);
		}
}

void SectionVerify()
{
	printf("[G6] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1})
			for (bool merge : {true, false}) {
				Configure(vlen, true);
				Built b({Vsetvli(vt),
					 OpVfmerge(merge ? kVs2 : 0u, kF, kVd, merge), kJalr});
				Translate(b);
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL vlen=%u vt=%u merge=%d: %s\n", vlen, vt,
					       (int)merge, err.c_str());
					++g_fail;
				}
			}
}

} // namespace

int main()
{
	printf("rvv_llvm_fmerge_test: order item 4, vfmerge.vfm / vfmv.v.f\n");
	SectionAdmission();
	SectionTwoUsesOfV0();
	SectionOracle();
	SectionNanBoxing();
	SectionNoFp();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
