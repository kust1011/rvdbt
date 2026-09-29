// C4 (2026-09-18). `vfclass.v` ON THE LLVM ARM.
//
// WHAT MAKES THIS FILE DIFFERENT FROM THE OTHER C3/C4 IR TESTS. Every other route in this series is
// checked structurally -- "the right intrinsic appears", "the operand is extended with sext not
// zext". A structural check is the wrong instrument for `vfclass.v`: its body is a five-way nested
// select over bit fields, and a transcription error (NaN tested after infinity, the quiet bit off
// by one, a sign pair swapped) produces IR of exactly the right SHAPE with the wrong VALUES. So
// section 3 does not inspect the tree. It CONSTANT-FOLDS it:
//
//   * replace the unit's source load with a constant vector of crafted bit patterns;
//   * fold the function until the masked store's value operand is itself a constant;
//   * compare every lane against `dbt::rv32::f32_classify` / `f64_classify` -- the reference this
//     repository's interpreter and helper already use.
//
// That is a real differential oracle against the reference, computed at build time, needing no
// execution and no AVX-512 host. Its failure path is the one that matters: any wrong bit, any
// misordered test, any swapped sign pair changes a lane and the comparison names it.
//
// SECTIONS:
//   [1] Admission and frame shape: one `_vchunkfclass` per chunk, guard kind
//       `VTypeIntegerNoRestart`, no `vchunkactive`, and nothing at all when the switch is off.
//   [2] NO FP MACHINERY. Zero constrained intrinsics, zero `x86_sse_{ld,st}mxcsr`, and no `fcsr`
//       load anywhere in the module. This is the assertion behind the claim that an OPFVV
//       instruction can be an integer body: if the route had been copied from the vfsqrt arm it
//       would have a bracket and an `frm` guard term, and this section fails.
//   [3] THE SEMANTIC ORACLE described above, at SEW 32 and SEW 64.
//   [4] `vstart` is proved by the GUARD, not handled by the body: the frame's guard must contain a
//       `vstart == 0` compare. Under `GuardKind::VTypeInteger` -- which the QCG arm correctly uses
//       because QEmit's body does handle vstart -- llvmgen emits NO vstart compare, and this body
//       has no prestart term, so a restarted execution would rewrite elements `[0, vstart)`.
//   [5] Partial VL: one masked store per unit whose predicate counts from THAT unit's element base.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_fpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstdlib>
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

llvm::LLVMContext g_ctx;

// `vfclass.v vd, vs2`: VFUNARY1 funct6, vs1 field = 10000 (the sub-opcode), funct3 = 0b001 (OPFVV),
// vm = 1 (unmasked).
constexpr u32 OpVfclass(u32 vs2, u32 vd, bool unmasked = true)
{
	return (0b010011u << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (16u << 15) |
	       (1u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 10u, kVs2 = 8u;

u32 VRegOff(u32 reg) { return (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg) +
				   reg * rvv32::VLEN_MAX_BYTES); }

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c4fclass", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_fclass = on;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	// C5-MASK-FP, reset so one section cannot leak a masked admission into the next.
	config::rvv_llvm_fp_cvt_masked = false;
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
	unsigned frames = 0, units = 0, active_nodes = 0, hcalls = 0;
	int guard_kind = -1;
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
			} else if (ins.GetOpcode() == Op::_vchunkfclass) {
				++q.units;
				q.bases.push_back(static_cast<InstVChunkFClass *>(&ins)->base);
			} else if (ins.GetOpcode() == Op::_vchunkactive) {
				++q.active_nodes;
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

// ------------------------------------------------------------------------------------------
void SectionShape()
{
	printf("[C4FC-1] admission, one unit per chunk, VTypeIntegerNoRestart, nothing when off\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
			Configure(vlen, true, /*on=*/true);
			Built b({Vsetvli(vt), OpVfclass(kVs2, kVd), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C4FC_TRACE"))
				printf("   trace vlen=%u vt=0x%x frames=%u units=%u kind=%d\n", vlen,
				       vt, q.frames, q.units, q.guard_kind);
			if (!q.frames)
				continue;
			++admitted;
			CHECK_EQ(q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			// Explicitly NOT the kind the QCG arm uses -- see section 4.
			CHECK(q.guard_kind != (int)GK::VTypeInteger);
			CHECK_EQ(q.active_nodes, 0u);
			unsigned const sew = vt == kVT_E64M1 ? 8u : 4u;
			unsigned const bytes = vlen / 8u < 64u ? vlen / 8u : 64u;
			unsigned const lanes = bytes / sew;
			CHECK_EQ(q.units, (vlen / 8u * 1u + bytes - 1u) / bytes);
			// Unit c covers elements [c*lanes, (c+1)*lanes).
			for (size_t c = 0; c < q.bases.size(); ++c)
				CHECK_EQ(q.bases[c], (u32)c * lanes);
		}
	CHECK(admitted > 0);

	// Off: no frame at all, and the instruction reaches the helper.
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, true, /*on=*/false);
		Built b({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.units, 0u);
		CHECK(q.hcalls > 0u);
	}
}

void SectionNoFpMachinery()
{
	printf("[C4FC-2] no constrained intrinsic, no MXCSR bracket, no fcsr read\n");
	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
	for (u32 vlen : {256u, 1024u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
			Configure(vlen, true, /*on=*/true);
			Built b({Vsetvli(vt), OpVfclass(kVs2, kVd), kJalr});
			Translate(b, true);
			if (!ScanQir(b.region).frames)
				continue;
			unsigned constrained = 0, mxcsr = 0, fcsr_loads = 0;
			llvm::Value *state = b.fn->getArg(0);
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						auto const id = ii->getIntrinsicID();
						llvm::StringRef n =
						    llvm::Intrinsic::getBaseName(id);
						if (n.contains("experimental.constrained"))
							++constrained;
						if (id == llvm::Intrinsic::x86_sse_ldmxcsr ||
						    id == llvm::Intrinsic::x86_sse_stmxcsr)
							++mxcsr;
					}
					if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins))
						if (StateOffset(l->getPointerOperand(), state) ==
						    fcsr_off)
							++fcsr_loads;
				}
			CHECK_EQ(constrained, 0u);
			CHECK_EQ(mxcsr, 0u);
			CHECK_EQ(fcsr_loads, 0u);
		}
}

// ------------------------------------------------------------------------------------------
// [3] THE ORACLE. Fold the emitted tree over crafted inputs and compare against the reference.
llvm::Constant *FoldStoredValue(llvm::Function *fn, llvm::Value *state, u32 src_off,
				std::vector<u64> const &pattern, u32 sew, u32 lanes)
{
	auto const &DL = fn->getParent()->getDataLayout();

	// MATCH THE LOAD STRUCTURALLY, NOT BY TYPE POINTER. LLVM types are uniqued PER CONTEXT, and
	// the emitted module does not share this file's `g_ctx` -- a `<8 x i32>` built here compares
	// unequal to the identical-printing `<8 x i32>` in the module. That is how this was found: the
	// oracle reported "did not fold" for every cell while the dumped IR was correct. Everything
	// below is therefore derived from the load's OWN type, which also removes the chance of
	// building the replacement constant in the wrong context.
	llvm::LoadInst *src = nullptr;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || vt->getNumElements() != lanes ||
			    vt->getScalarSizeInBits() != 8u * sew)
				continue;
			if (StateOffset(l->getPointerOperand(), state) != src_off)
				continue;
			src = l;
			break;
		}
		if (src)
			break;
	}
	if (!src)
		return nullptr;

	auto *vty = llvm::cast<llvm::FixedVectorType>(src->getType());
	auto *ety = vty->getElementType();
	llvm::SmallVector<llvm::Constant *, 64> lanes_c;
	for (u32 i = 0; i < lanes; ++i)
		lanes_c.push_back(llvm::ConstantInt::get(ety, pattern[i % pattern.size()]));
	src->replaceAllUsesWith(llvm::ConstantVector::get(lanes_c));

	// Fold to a fixpoint: every instruction whose operands are all constants.
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
	// The masked store's value operand is what the unit publishes.
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store)
					if (auto *c = llvm::dyn_cast<llvm::Constant>(
						ii->getArgOperand(0)))
						return c;
	return nullptr;
}

void SectionOracle()
{
	printf("[C4FC-3] constant-fold oracle vs f32_classify / f64_classify\n");
	// One representative of every class the classifier distinguishes, plus boundary values that a
	// misordered test would misclassify: the largest subnormal, the smallest normal, an sNaN whose
	// payload has the quiet bit clear but other mantissa bits set, and a qNaN with a payload.
	struct Pat { char const *name; u32 p32; u64 p64; };
	Pat const pats[] = {
	    {"+0",            0x00000000u, 0x0000000000000000ull},
	    {"-0",            0x80000000u, 0x8000000000000000ull},
	    {"+normal(1.0)",  0x3f800000u, 0x3ff0000000000000ull},
	    {"-normal(-1.0)", 0xbf800000u, 0xbff0000000000000ull},
	    {"+min normal",   0x00800000u, 0x0010000000000000ull},
	    {"-min normal",   0x80800000u, 0x8010000000000000ull},
	    {"+max subnormal",0x007fffffu, 0x000fffffffffffffull},
	    {"-max subnormal",0x807fffffu, 0x800fffffffffffffull},
	    {"+min subnormal",0x00000001u, 0x0000000000000001ull},
	    {"-min subnormal",0x80000001u, 0x8000000000000001ull},
	    {"+inf",          0x7f800000u, 0x7ff0000000000000ull},
	    {"-inf",          0xff800000u, 0xfff0000000000000ull},
	    {"qNaN",          0x7fc00000u, 0x7ff8000000000000ull},
	    {"qNaN payload",  0x7fd55555u, 0x7ffaaaaaaaaaaaaaull},
	    {"sNaN",          0x7f800001u, 0x7ff0000000000001ull},
	    {"sNaN payload",  0x7fa55555u, 0x7ff4aaaaaaaaaaaaull},
	    {"-qNaN",         0xffc00000u, 0xfff8000000000000ull},
	    {"-sNaN",         0xff800001u, 0xfff0000000000001ull},
	};
	constexpr size_t kN = sizeof(pats) / sizeof(pats[0]);

	// EVERY PATTERN MUST REACH A LANE. A unit has `lanes` lanes and there are more patterns than
	// that at the narrow widths, so one fold per cell would silently never test the last few --
	// which is exactly what the first version of this section did: it compared 36 lanes and never
	// once classified `-qNaN` or `-sNaN`. The pattern window is therefore ROTATED and the function
	// re-translated per rotation, and `seen[]` records which patterns were actually compared so a
	// gap fails the run instead of passing quietly.
	unsigned checked = 0;
	bool seen[kN] = {};
	for (u32 vlen : {256u, 1024u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
			u32 const sew = vt == kVT_E64M1 ? 8u : 4u;
			u32 const bytes = vlen / 8u < 64u ? vlen / 8u : 64u;
			u32 const lanes = bytes / sew;
			for (size_t start = 0; start < kN; start += lanes) {
				Configure(vlen, true, /*on=*/true);
				Built b({Vsetvli(vt), OpVfclass(kVs2, kVd), kJalr});
				Translate(b, true);
				if (!ScanQir(b.region).frames)
					break;
				std::vector<u64> pattern;
				for (u32 i = 0; i < lanes; ++i) {
					size_t const k = (start + i) % kN;
					pattern.push_back(sew == 4 ? (u64)pats[k].p32 : pats[k].p64);
				}
				auto *folded = FoldStoredValue(b.fn, b.fn->getArg(0), VRegOff(kVs2),
							       pattern, sew, lanes);
				if (!folded) {
					printf("  FAIL vlen=%u sew=%u start=%zu: the unit did not fold "
					       "to a constant -- the oracle could not run\n", vlen, sew,
					       start);
					++g_fail;
					continue;
				}
				for (u32 i = 0; i < lanes; ++i) {
					auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    folded->getAggregateElement(i));
					if (!ci) {
						printf("  FAIL vlen=%u sew=%u lane %u did not fold\n",
						       vlen, sew, i);
						++g_fail;
						continue;
					}
					size_t const k = (start + i) % kN;
					u64 const in = pattern[i];
					u64 const want = sew == 4 ? rvv32::f32_classify((u32)in)
								  : rvv32::f64_classify(in);
					u64 const got = ci->getZExtValue();
					++checked;
					seen[k] = true;
					if (got != want) {
						printf("  FAIL vlen=%u sew=%u %-16s in=0x%llx "
						       "emitted=0x%llx reference=0x%llx\n", vlen, sew,
						       pats[k].name, (unsigned long long)in,
						       (unsigned long long)got,
						       (unsigned long long)want);
						++g_fail;
					}
				}
			}
		}
	for (size_t k = 0; k < kN; ++k)
		if (!seen[k]) {
			printf("  FAIL pattern '%s' was never compared -- the oracle has a gap\n",
			       pats[k].name);
			++g_fail;
		}
	printf("       %u lanes compared against the reference classifier\n", checked);
	CHECK(checked > 0);
}

void SectionVstartIsGuarded()
{
	printf("[C4FC-4] the frame guard proves vstart == 0 (the body has no prestart term)\n");
	u32 const vstart_off =
	    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, true, /*on=*/true);
		Built b({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd), kJalr});
		Translate(b, true);
		if (!ScanQir(b.region).frames)
			continue;
		llvm::Value *state = b.fn->getArg(0);
		// A vstart LOAD that feeds an equality compare against 0 -- i.e. a guard term, not the
		// epilogue's `vstart = 0` store.
		unsigned guard_terms = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
				if (!l || StateOffset(l->getPointerOperand(), state) != vstart_off)
					continue;
				for (auto *u : l->users())
					if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(u))
						if (cmp->getPredicate() == llvm::CmpInst::ICMP_EQ)
							++guard_terms;
			}
		CHECK_EQ(guard_terms, 1u);
	}
}

void SectionPartialVl()
{
	printf("[C4FC-5] one masked store per unit, predicated from that unit's element base\n");
	for (u32 vlen : {1024u, 2048u}) {
		Configure(vlen, true, /*on=*/true);
		Built b({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		if (!q.frames)
			continue;
		unsigned stores = 0;
		std::vector<std::vector<u32>> idxs;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
				if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				++stores;
				std::vector<u32> v;
				if (auto *cmp =
					llvm::dyn_cast<llvm::ICmpInst>(testcompat::MaskedStoreMask(ii)))
					if (auto *cv = llvm::dyn_cast<llvm::Constant>(
						cmp->getOperand(0)))
						if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(
							cv->getType()))
							for (u32 k = 0; k < vt->getNumElements();
							     ++k)
								if (auto *c = llvm::dyn_cast<
									llvm::ConstantInt>(
									cv->getAggregateElement(k)))
									v.push_back(
									    (u32)c->getZExtValue());
				idxs.push_back(v);
			}
		CHECK_EQ(stores, q.units);
		for (size_t c = 0; c < idxs.size() && c < q.bases.size(); ++c) {
			CHECK(!idxs[c].empty());
			for (size_t k = 0; k < idxs[c].size(); ++k)
				CHECK_EQ(idxs[c][k], q.bases[c] + (u32)k);
		}
	}
}

void DumpIR()
{
	char const *path = getenv("C4FC_DUMP_IR");
	if (!path)
		return;
	Configure(1024u, true, true);
	Built b({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

} // namespace

// [C4FC-6] THE ARCHITECTURAL MASK. `vfclass` raises NO flags, so unlike the other three families in
// this group the store predicate is the WHOLE obligation -- there is no second place for the mask
// to be needed and no sticky state to get wrong. The claim is therefore structural and exact: with
// `vm == 0` the store's predicate must stop being the bare `vl` comparison and become a CONJUNCTION
// of that comparison with a value read out of v0.
//
// This family also had a defect of its own that the mask exposed: it built its `vl` mask INLINE
// instead of calling the shared predicate helper, so the architectural term had nowhere to go. The
// assertion below is what distinguishes the repaired form from the old one.
void SectionMaskedArchMask()
{
	printf("[C4FC-6] architectural mask: the store predicate becomes vl AND v0\n");
	unsigned masked_cells = 0, unmasked_cells = 0;
	u32 const v0_base = VRegOff(0);
	for (u32 vlen : {1024u, 2048u}) {
		// (a) UNMASKED: the predicate is a bare comparison, no v0 anywhere. This is the
		// baseline the masked case must differ from -- without it, an assertion that the
		// masked form "contains an and" could be satisfied by something already present.
		Configure(vlen, true, /*on=*/true);
		Built um({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd), kJalr});
		Translate(um, true);
		if (ScanQir(um.region).frames) {
			for (auto &bb : *um.fn)
				for (auto &ins : bb) {
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii || ii->getIntrinsicID() !=
							   llvm::Intrinsic::masked_store)
						continue;
					CHECK(llvm::isa<llvm::ICmpInst>(
					    testcompat::MaskedStoreMask(ii)));
					++unmasked_cells;
				}
		}

		// (b) MASKED: the predicate is an `and`, one side of which traces to a load from
		// v0's register.
		Configure(vlen, true, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built b({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd, /*unmasked=*/false), kJalr});
		Translate(b, true);
		CHECK(ScanQir(b.region).frames != 0); // the masked form must be ADMITTED
		llvm::Value *state = b.fn->getArg(0);
		unsigned stores = 0, with_v0 = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
				if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				++stores;
				auto *m = llvm::dyn_cast<llvm::BinaryOperator>(
				    testcompat::MaskedStoreMask(ii));
				if (!m || m->getOpcode() != llvm::Instruction::And)
					continue;
				// Walk both operands for a load inside v0's register.
				bool found = false;
				for (unsigned k = 0; k < 2 && !found; ++k) {
					llvm::SmallVector<llvm::Value *, 8> work{m->getOperand(k)};
					llvm::SmallPtrSet<llvm::Value *, 8> seen;
					while (!work.empty() && !found) {
						llvm::Value *v = work.pop_back_val();
						if (!seen.insert(v).second)
							continue;
						if (auto *l = llvm::dyn_cast<llvm::LoadInst>(v)) {
							u32 const o = StateOffset(
							    l->getPointerOperand(), state);
							if (o != ~0u && o >= v0_base &&
							    o < v0_base + rvv32::VLEN_MAX_BYTES)
								found = true;
							continue;
						}
						if (auto *u = llvm::dyn_cast<llvm::User>(v))
							for (auto &op : u->operands())
								work.push_back(op);
					}
				}
				if (found)
					++with_v0;
			}
		CHECK(stores != 0);
		CHECK_EQ(with_v0, stores); // EVERY unit's store, not just the first
		masked_cells += stores;

		// (c) REFUSALS: switch off, and vd == v0.
		Configure(vlen, true, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = false;
		Built off({Vsetvli(kVT_E32M1), OpVfclass(kVs2, kVd, /*unmasked=*/false), kJalr});
		Translate(off, true);
		CHECK_EQ(ScanQir(off.region).frames, 0u);

		Configure(vlen, true, /*on=*/true);
		config::rvv_llvm_fp_cvt_masked = true;
		Built v0d({Vsetvli(kVT_E32M1), OpVfclass(kVs2, /*vd=*/0u, /*unmasked=*/false),
			   kJalr});
		Translate(v0d, true);
		CHECK_EQ(ScanQir(v0d.region).frames, 0u);
	}
	printf("       %u masked unit stores all predicated on v0, %u unmasked kept bare\n",
	       masked_cells, unmasked_cells);
	CHECK(masked_cells != 0);
	CHECK(unmasked_cells != 0);
}

int main()
{
	printf("rvv_llvm_fclass_test\n");
	SectionShape();
	SectionNoFpMachinery();
	SectionOracle();
	SectionVstartIsGuarded();
	SectionPartialVl();
	SectionMaskedArchMask();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
