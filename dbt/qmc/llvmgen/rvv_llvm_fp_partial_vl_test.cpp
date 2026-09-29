// C5-FP (2026-09-18). PARTIAL VL FOR THE LLVM/AOT TYPED FP LANE FAMILY.
//
// Unlike the integer families, a masked STORE is not sufficient here: `RvvFpBracketCloseBody`
// executes `stmxcsr` and ORs the host MXCSR sticky bits into the guest `fcsr`, so an exception
// raised while COMPUTING an inactive lane becomes architecturally visible. LLVM's VP intrinsics do
// not help on this target -- a masked `llvm.vp.fadd` lowers to an UNMASKED `vaddps` on the installed
// LLVM 20.1.8 -- so predication is applied to the OPERANDS.
//
// SECTIONS:
//   [1] With the switch on, the FP frame takes GuardKind::VTypePartialVlVstartFrmRNE and each lane
//       operation's BOTH operands are selects. Failure path: admitting the partial guard kind
//       without neutralising, which would raise flags for inactive lanes and which a guard-kind-only
//       check would pass.
//   [2] THE NEUTRAL VALUE IS +1.0, NOT +0.0 -- read out of the IR. This is the assertion that
//       matters: `+0.0` is neutral for add/sub/mul/fma/sqrt but `(+0)/(+0)` raises NV, and `vfdiv`
//       IS admitted (`vfalu_llvm_constrained_vv_supported`). A +0.0 splat would pass every
//       structural check and raise a spurious guest NV flag on any short-vl division.
//   [3] The select's condition is derived from a RUNTIME load of `vec.vl`, not a constant, AND each
//       chunk's mask starts at ITS OWN element base. The base check was added after a mutation
//       (mask built from lane 0) passed without it -- at VLEN 2048 a frame has four chunks, and a
//       lane-0 mask would compute the later chunks' inactive lanes with real operands.
//   [4] The constrained intrinsic is still used (round.dynamic / fpexcept.strict preserved) and the
//       destination store is still active-lane masked.
//   [5] No `vchunkactive` is ever produced -- it has no LLVM lowering; `policy_enabled` is forced
//       false on this arm.
//   [6] Inert when off: the full-VL guard kind returns, no selects, exactly the pre-C5-FP frame.
//   [7] QCG is unaffected either way.
//
// SCOPE, MEASURED RATHER THAN ASSUMED. Two LLVM FP families exist. At VLEN 512/1024
// `TRANSLATOR(vfalu)` is taken by FAMILY A (the P-vector-SSA path, `Create_rvvfalu`) and no typed
// frame is built at all -- traced: `frames=0 vchunkfalu=0 rvvfalu=1`. Family B (the typed chunk
// path, `_vchunkfalu`) owns the operation at the OTHER widths. This file therefore exercises
// 128/256/2048, and partial-VL FP at 512/1024 remains INCOMPLETE native support: it needs the same
// operand neutralisation inside `Emit_rvvfalu`, which is recorded as the next FP subtask rather
// than claimed here.
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

constexpr u32 F6_VFADD = 0u, F6_VFSUB = 2u, F6_VFMUL = 0b100100u, F6_VFDIV = 0b100000u;
constexpr u32 OpFVV(u32 f6, u32 vs2, u32 vs1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (1u << 12) | (vd << 7) | 0x57u;
}
// `vfsqrt.v vd, vs2`: VFUNARY1 (funct6 0b010011), funct3 0b001, and the vs1 FIELD is the
// sub-opcode 0b00000 -- 0b00100/0b00101 are the 7-bit ESTIMATES and 0b10000 is vfclass, none of
// which this route admits.
// The EIGHT fused forms. Family B's `Emit_vchunkfma` lowers all of them through one constrained
// fma plus a per-funct6 sign mapping, so unlike Family A -- which admits `vfmadd` alone -- the
// neutrality argument has eight rows to satisfy, not one.
constexpr u32 kFusedF6[] = {0b101000u, 0b101001u, 0b101010u, 0b101011u,
			    0b101100u, 0b101101u, 0b101110u, 0b101111u};
constexpr char const *kFusedName[] = {"vfmadd", "vfnmadd", "vfmsub",  "vfnmsub",
				      "vfmacc", "vfnmacc", "vfmsac", "vfnmsac"};
constexpr u32 OpVfsqrt(u32 vs2, u32 vd)
{
	return (0b010011u << 26) | (1u << 25) | (vs2 << 20) | (0u << 15) | (1u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c5fp", g_ctx) {}
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
	// `RvvLLVMSqrtChunkAdmit` reads THIS switch alone and not the umbrella, so the vfsqrt rows
	// are vacuous without it.
	config::rvv_qcg_typed_chunk_fsqrt = true;
	// `RvvLLVMFmaChunkAdmit` reads its own switch, and the fused route additionally requires the
	// code-generation host to have hardware FMA.
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_vector_ssa_host_fma = true;
	config::rvv_llvm_fp_partial_vl = fp_partial;
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
	unsigned fma_ops = 0; // Op::_vchunkfma -- the fused typed lane op
	unsigned frames = 0, lane_ops = 0, hcalls = 0, active_nodes = 0, family_a = 0;
	unsigned sqrt_ops = 0; // Op::_vchunkfsqrt -- the ONE-source FP lane op
	int guard_kind = -1;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind = (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vchunkfalu) {
				++q.lane_ops;
			} else if (ins.GetOpcode() == Op::_vchunkfsqrt) {
				++q.sqrt_ops;
			} else if (ins.GetOpcode() == Op::_vchunkfma) {
				++q.fma_ops;
			} else if (ins.GetOpcode() == Op::_rvvfalu) {
				++q.family_a;
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

struct IRFacts {
	unsigned fp_selects = 0;       // selects whose false arm is an FP splat
	unsigned neutral_one = 0;      // ... of +1.0
	unsigned neutral_zero = 0;     // ... of +0.0  (must never happen: fdiv)
	unsigned constrained_calls = 0;
	unsigned masked_stores = 0;
	bool cond_reads_vl = false;
	// One entry per neutralising select: the index vector its condition compares against vl.
	std::vector<std::vector<u32>> sel_indices;
};

IRFacts ScanIR(llvm::Function *fn)
{
	IRFacts f;
	llvm::Value *state = fn->getArg(0);
	u32 const vl_off = offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				auto const id = ii->getIntrinsicID();
				if (id == llvm::Intrinsic::masked_store)
					++f.masked_stores;
				else if (id == llvm::Intrinsic::experimental_constrained_sqrt ||
					 id == llvm::Intrinsic::experimental_constrained_fma ||
					 id == llvm::Intrinsic::experimental_constrained_fadd ||
					 id == llvm::Intrinsic::experimental_constrained_fsub ||
					 id == llvm::Intrinsic::experimental_constrained_fmul ||
					 id == llvm::Intrinsic::experimental_constrained_fdiv)
					++f.constrained_calls;
				continue;
			}
			if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(&ins)) {
				auto *fa = llvm::dyn_cast<llvm::Constant>(sel->getFalseValue());
				if (!fa || !fa->getType()->isFPOrFPVectorTy())
					continue;
				++f.fp_selects;
				if (auto *sp = fa->getSplatValue())
					if (auto *cf = llvm::dyn_cast<llvm::ConstantFP>(sp)) {
						if (cf->isExactlyValue(1.0))
							++f.neutral_one;
						else if (cf->isZero())
							++f.neutral_zero;
					}
				// The select's predicate: `<indices> ult splat(vl)`. Recording the index
				// vector is what makes the per-chunk ELEMENT BASE checkable -- a mask built
				// from lane 0 instead of `chunk*lanes` would compute later chunks' inactive
				// lanes with real operands, and no count-based check would notice.
				if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition())) {
					std::vector<u32> idx;
					if (auto *cv = llvm::dyn_cast<llvm::Constant>(cmp->getOperand(0)))
						if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(cv->getType()))
							for (u32 k = 0; k < vt->getNumElements(); ++k)
								if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(
									cv->getAggregateElement(k)))
									idx.push_back((u32)ci->getZExtValue());
					f.sel_indices.push_back(idx);
				}
				continue;
			}
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				llvm::Value *p = l->getPointerOperand();
				if (StripToBase(p) != state || p == state)
					continue;
				llvm::APInt ap(64, 0);
				auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
				if (g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap) &&
				    (u32)ap.getZExtValue() == vl_off)
					f.cond_reads_vl = true;
			}
		}
	return f;
}

// ------------------------------------------------------------------------------------------
void SectionOn()
{
	printf("[C5FP-1..5] partial FP guard kind, +1.0 neutralisation, runtime vl, no vchunkactive\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Case { char const *name; u32 f6; u32 vt; };
	Case const cases[] = {
	    {"vfadd.vv e32", F6_VFADD, kVT_E32M1}, {"vfsub.vv e32", F6_VFSUB, kVT_E32M1},
	    {"vfmul.vv e32", F6_VFMUL, kVT_E32M1}, {"vfdiv.vv e32", F6_VFDIV, kVT_E32M1},
	    {"vfadd.vv e64", F6_VFADD, kVT_E64M1}, {"vfdiv.vv e64", F6_VFDIV, kVT_E64M1},
	};
	unsigned admitted[sizeof(cases) / sizeof(cases[0])] = {};
	for (u32 vlen : {128u, 256u, 2048u})
		for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci) {
			auto const &c = cases[ci];
			Configure(vlen, true, /*fp_partial=*/true);
			Built b({Vsetvli(c.vt), OpFVV(c.f6, 8, 9, 10), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C5FP_TRACE"))
				printf("   trace vlen=%u %-14s frames=%u vchunkfalu=%u rvvfalu=%u hcall=%u\n",
				       vlen, c.name, q.frames, q.lane_ops, q.family_a, q.hcalls);
			if (!q.frames || !q.lane_ops)
				continue;
			++admitted[ci];
			// [1] the partial FP kind
			CHECK_EQ(q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
			CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
			// [5] never a node this backend cannot lower
			CHECK_EQ(q.active_nodes, 0u);

			IRFacts ir = ScanIR(b.fn);
			// [1] BOTH operands of every lane op are neutralised
			CHECK_EQ(ir.fp_selects, 2u * q.lane_ops);
			// [2] the neutral value is +1.0 and NEVER +0.0
			CHECK_EQ(ir.neutral_one, ir.fp_selects);
			CHECK_EQ(ir.neutral_zero, 0u);
			// [3] the predicate comes from a runtime vl load ...
			CHECK(ir.cond_reads_vl);
			// ... and each chunk's neutralisation mask starts at ITS OWN element base.
			// The two selects of chunk c share one index vector [c*lanes, (c+1)*lanes).
			CHECK_EQ(ir.sel_indices.size(), ir.fp_selects);
			{
				unsigned bad = 0, lanes = 0;
				for (auto const &idx : ir.sel_indices)
					if (!idx.empty())
						lanes = (unsigned)idx.size();
				for (size_t s = 0; s < ir.sel_indices.size(); ++s) {
					auto const &idx = ir.sel_indices[s];
					if (idx.empty() || lanes == 0)
						continue;
					// selects are emitted two per chunk, in chunk order
					u32 const base = (u32)(s / 2) * lanes;
					for (size_t k = 0; k < idx.size(); ++k)
						if (idx[k] != base + (u32)k) {
							++bad;
							break;
						}
				}
				if (bad) {
					printf("  FAIL %s: %u neutralisation masks do not start at their "
					       "chunk's element base\n", c.name, bad);
					++g_fail;
				}
			}
			// [4] still a constrained intrinsic, still a masked store
			CHECK_EQ(ir.constrained_calls, q.lane_ops);
			CHECK(ir.masked_stores > 0u);
		}
	for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci)
		if (admitted[ci] == 0) {
			printf("  FAIL '%s' was never admitted -- its rows are vacuous\n", cases[ci].name);
			++g_fail;
		}
}

void SectionOffIsInert()
{
	printf("[C5FP-6] switch off: full-VL kind, no selects\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {128u, 256u, 2048u}) {
		Configure(vlen, true, /*fp_partial=*/false);
		Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFADD, 8, 9, 10), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		if (!q.frames)
			continue;
		CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
		IRFacts ir = ScanIR(b.fn);
		CHECK_EQ(ir.fp_selects, 0u);
		CHECK_EQ(q.active_nodes, 0u);
	}
}

// [C5FP-8] vfsqrt.v: ONE operand, so one neutralising select per chunk -- and the reason the value
// must be +1.0 is sharper here than for the arithmetic ops. `sqrt` of a NEGATIVE operand raises NV,
// so an inactive lane holding any negative value at all would set a guest flag the instruction must
// not set; it does not take a NaN or a zero to break this one.
void SectionSqrt()
{
	printf("[C5FP-8] vfsqrt.v partial VL: one neutralised operand per chunk, +1.0\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
			Configure(vlen, true, /*fp_partial=*/true);
			Built b({Vsetvli(vt), OpVfsqrt(8, 10), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C5FP_TRACE"))
				printf("   trace vlen=%u vt=0x%x frames=%u vchunkfsqrt=%u\n", vlen, vt,
				       q.frames, q.sqrt_ops);
			if (!q.frames || !q.sqrt_ops)
				continue;
			++admitted;
			CHECK_EQ(q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
			CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
			CHECK_EQ(q.active_nodes, 0u);

			IRFacts ir = ScanIR(b.fn);
			// ONE operand, so one select per lane op -- not two as for the binary family
			CHECK_EQ(ir.fp_selects, q.sqrt_ops);
			CHECK_EQ(ir.neutral_one, ir.fp_selects);
			CHECK_EQ(ir.neutral_zero, 0u);
			CHECK(ir.cond_reads_vl);
			CHECK_EQ(ir.constrained_calls, q.sqrt_ops);
			CHECK(ir.masked_stores > 0u);
			// each chunk's mask starts at its own element base; ONE select per chunk here
			{
				unsigned lanes = 0, bad = 0;
				for (auto const &idx : ir.sel_indices)
					if (!idx.empty())
						lanes = (unsigned)idx.size();
				for (size_t si = 0; si < ir.sel_indices.size(); ++si) {
					auto const &idx = ir.sel_indices[si];
					if (idx.empty() || lanes == 0)
						continue;
					u32 const base = (u32)si * lanes;
					for (size_t k = 0; k < idx.size(); ++k)
						if (idx[k] != base + (u32)k) {
							++bad;
							break;
						}
				}
				if (bad) {
					printf("  FAIL vfsqrt vlen=%u: %u masks do not start at their "
					       "chunk's element base\n", vlen, bad);
					++g_fail;
				}
			}
		}
	if (!admitted) {
		printf("  FAIL vfsqrt was never admitted -- section 8 is vacuous\n");
		++g_fail;
	}
}

// [C5FP-9] and it is inert when the switch is off: the full-VL kind returns and no select appears.
void SectionSqrtOffIsInert()
{
	printf("[C5FP-9] vfsqrt.v: switch off restores the full-VL guard kind and drops the select\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {256u, 512u, 1024u}) {
		Configure(vlen, true, /*fp_partial=*/false);
		Built b({Vsetvli(kVT_E32M1), OpVfsqrt(8, 10), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		if (!q.frames || !q.sqrt_ops)
			continue;
		CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
		IRFacts ir = ScanIR(b.fn);
		CHECK_EQ(ir.fp_selects, 0u);
		CHECK_EQ(ir.constrained_calls, q.sqrt_ops);
	}
}

// [C5FP-10] The fused typed frame, all eight funct6. THREE neutralised operands per chunk, applied
// BEFORE the sign mapping -- `fneg` raises nothing, so negating a neutral operand keeps it neutral,
// which is what makes one argument cover all eight forms. No destination merge here: this frame is
// state-backed and `Emit_vstatechunkstore` already predicates the write.
void SectionFusedChunk()
{
	printf("[C5FP-10] vchunkfma partial VL: 3 neutralised operands x 8 fused forms\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted[8] = {};
	for (u32 vlen : {256u, 1024u, 2048u})
		for (size_t k = 0; k < 8; ++k) {
			Configure(vlen, true, /*fp_partial=*/true);
			Built b({Vsetvli(kVT_E32M1), OpFVV(kFusedF6[k], 8, 9, 10), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C5FP_TRACE"))
				printf("   trace vlen=%u %-8s frames=%u fma_ops=%u\n", vlen,
				       kFusedName[k], q.frames, q.fma_ops);
			if (!q.frames || !q.fma_ops)
				continue;
			++admitted[k];
			CHECK_EQ(q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
			CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
			CHECK_EQ(q.active_nodes, 0u);
			IRFacts ir = ScanIR(b.fn);
			// THREE operands per lane op -- d, b and a
			CHECK_EQ(ir.fp_selects, 3u * q.fma_ops);
			CHECK_EQ(ir.neutral_one, ir.fp_selects);
			CHECK_EQ(ir.neutral_zero, 0u);
			CHECK(ir.cond_reads_vl);
			CHECK_EQ(ir.constrained_calls, q.fma_ops);
			// the write is predicated, which is why no merge is emitted
			CHECK(ir.masked_stores > 0u);
			{
				unsigned lanes = 0, bad = 0;
				for (auto const &idx : ir.sel_indices)
					if (!idx.empty())
						lanes = (unsigned)idx.size();
				for (size_t si = 0; si < ir.sel_indices.size(); ++si) {
					auto const &idx = ir.sel_indices[si];
					if (idx.empty() || lanes == 0)
						continue;
					u32 const base = (u32)(si / 3) * lanes; // three per chunk
					for (size_t j = 0; j < idx.size(); ++j)
						if (idx[j] != base + (u32)j) {
							++bad;
							break;
						}
				}
				if (bad) {
					printf("  FAIL %s vlen=%u: %u fused masks do not start at "
					       "their chunk's element base\n", kFusedName[k], vlen, bad);
					++g_fail;
				}
			}
		}
	for (size_t k = 0; k < 8; ++k)
		if (!admitted[k]) {
			printf("  FAIL fused form '%s' was never admitted -- its rows are vacuous\n",
			       kFusedName[k]);
			++g_fail;
		}
}

// [C5FP-11] and inert when off.
void SectionFusedChunkOffIsInert()
{
	printf("[C5FP-11] vchunkfma: switch off restores the full-VL kind and drops the selects\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, true, /*fp_partial=*/false);
		Built b({Vsetvli(kVT_E32M1), OpFVV(kFusedF6[5], 8, 9, 10), kJalr}); // vfnmacc
		Translate(b, true);
		Qir q = ScanQir(b.region);
		if (!q.frames || !q.fma_ops)
			continue;
		CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
		IRFacts ir = ScanIR(b.fn);
		CHECK_EQ(ir.fp_selects, 0u);
		CHECK_EQ(ir.constrained_calls, q.fma_ops);
	}
}

void SectionQcgUntouched()
{
	printf("[C5FP-7] QCG admission does not depend on the C5-FP switch\n");
	int kinds[2] = {-1, -1};
	for (int k = 0; k < 2; ++k) {
		Configure(1024u, /*llvm*/ false, /*fp_partial=*/k == 1);
		Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFADD, 8, 9, 10), kJalr});
		Translate(b, false);
		kinds[k] = ScanQir(b.region).guard_kind;
	}
	CHECK_EQ(kinds[0], kinds[1]);
}

void DumpIR()
{
	char const *path = getenv("C5FP_DUMP_IR");
	if (!path)
		return;
	// VLEN 2048, not 512: at 512 Family A owns vfalu and the module would contain NO
	// neutralisation at all -- i.e. the dump would not be the code this test validates.
	Configure(2048u, true, true);
	Built b({Vsetvli(kVT_E32M1), OpFVV(F6_VFDIV, 8, 9, 10), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

void DumpSqrtIR()
{
	char const *path = getenv("C5FP_DUMP_IR_SQRT");
	if (!path)
		return;
	// VLEN 1024: two chunks, so the per-chunk element bases are visible in the dump.
	Configure(1024u, true, true);
	Built b({Vsetvli(kVT_E32M1), OpVfsqrt(8, 10), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (sqrt IR dumped to %s)\n", path);
}

} // namespace

int main()
{
	printf("rvv_llvm_fp_partial_vl_test\n");
	SectionOn();
	SectionOffIsInert();
	SectionQcgUntouched();
	SectionSqrt();
	SectionSqrtOffIsInert();
	SectionFusedChunk();
	SectionFusedChunkOffIsInert();
	DumpIR();
	DumpSqrtIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
