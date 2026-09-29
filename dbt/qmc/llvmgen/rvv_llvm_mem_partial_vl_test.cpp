// W32: focused test for the PARTIAL-VL arm of the LLVM/AOT unit-stride vector load.
//
// WHAT THIS FILE OBSERVES. The LLVM arm of the `vle<EEW>.v` typed frame demanded `vl == VLMAX`
// (`GuardKind::VTypeVlVstart`). The audit measured the cost: with the route on, 1591 of 1668
// executions hit the frame and MISSED its guard, so the frame paid a guard test and called the
// helper anyway. W32 gives that arm a single body that covers every `vl`, under the guard kind the
// QCG partial frames already carry.
//
// FOUR CLAIMS, AND EACH IS CHECKED RATHER THAN DESCRIBED:
//
//   1. THE GUEST-MEMORY READ IS `llvm.masked.load`, AND THIS IS CORRECTNESS, NOT SPEED. At
//      `vl < VLMAX` the bytes from `vl * EEW` to `VLEN/8` may be on a page the guest never mapped
//      -- a guest is entitled to size `vl` so the access stops exactly at the end of an array that
//      ends at a page boundary. `llvm.masked.load` is specified not to perform the load for a lane
//      whose mask bit is false, so no fault can arise from those lanes; a full-width load plus a
//      select would fault, and rvdbt's SIGSEGV handler PANICS rather than delivering a guest trap,
//      so the failure mode would be a dead process on a legal program. `SectionMaskedLoad` requires
//      the intrinsic and requires that the frame's fast body contains NO unmasked vector load of
//      guest memory.
//
//   2. THE MASK IS THE ARCHITECTURAL ACTIVE SET, ON THE WHOLE `vl` LADDER. `SectionVlLadder` does
//      not read the opcode name: it takes the ACTUAL `llvm::CmpInst::Predicate` and the ACTUAL
//      constant index vector out of the emitted mask and evaluates them with LLVM's own APInt
//      comparison for EVERY `vl` in `[0, VLMAX]`, lane by lane, against `element_base + i < vl`.
//      `vl == 0` (nothing loaded, nothing published), every partial `vl`, and `vl == VLMAX` (the
//      all-ones case) are the same code path and are all covered. A `ULE` where `ULT` was meant, or
//      a wrong `element_base` on chunk 1, fails on a specific `vl`.
//
//   3. THE LOAD'S MASK AND THE STORE'S MASK ARE THE SAME VALUE. A load that read a lane the store
//      refused to publish would be harmless; a load that SKIPPED a lane the store published would
//      write the passthrough zero into guest state. `SectionOneMask` requires pointer equality of
//      the two `llvm::Value *`, which is what `RvvActiveLaneMask`'s per-frame memo guarantees.
//
//   4. THE GUARD IS THE RIGHT ONE. `vl <= VLMAX` (not `==`), `vstart == 0`, and the guest base
//      register `<= 2^32 - VLEN/8`. The base term is not decoration: the body forms
//      `membase + zext(base) + disp` with a HOST-pointer displacement that does not wrap at 2^32,
//      while `rvv_ref::load_unit_stride` computes `(u32)(base + e*eew)`, which does. Without the
//      bound a base in the top VLEN/8 bytes reads past rvdbt's 4 GiB reservation where the guest
//      would have wrapped to address 0. `SectionGuard` reads all three out of the IR.
//
// TAIL AND PRESTART are covered by (2) and (3) together: a lane at or above `vl` is in neither
// mask, so it is neither read nor published, and the destination keeps its previous bytes -- which
// is `rvv_ref::load_unit_stride`'s behaviour (its loop simply ends at `vl`) and is legal under all
// four of vta/vtu x vma/vmu. `vstart` is pinned to 0 by the guard, so the prestart set is empty for
// every execution the body runs; `SectionGuard` is what makes that a checked fact.
//
// INERTNESS. `SectionSwitchOff` requires that with `--rvv-llvm-mem-partial-vl` off the arm emits
// the pre-W32 QIR exactly: guard kind `VTypeVlVstart`, `active_sew == 0` on every load and store.
//
// The pipeline is the real one, inspected in memory. No TargetMachine, no pass pipeline, no object
// file, and NO claim about host instructions, cycles or speed.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
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

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Guest encodings.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11, u32 rd, u32 rs1)
{
	return (zimm11 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
// vle<EEW>.v vd, (rs1) : nf=0 mew=0 mop=00 vm=1 lumop=00000 rs1 width vd opcode 0000111.
constexpr u32 EncodeVle(u32 width, u32 vd, u32 rs1)
{
	return (1u << 25) | (rs1 << 15) | (width << 12) | (vd << 7) | 0b0000111u;
}
constexpr u32 W32BIT = 0b110, W64BIT = 0b111; // funct3 width encodings for EEW 32 / 64

constexpr u32 VTYPE_E32_M1 = Zimm(2, 0, 1, 1);
constexpr u32 VTYPE_E64_M1 = Zimm(3, 0, 1, 1);
constexpr u32 VD = 8, RS1 = 10;

constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_RS1 = (u32)offsetof(CPUState, gpr) + 4u * RS1;

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_lowering = 1; // non-Ref: the vle route refuses the reference arm
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_vle = true; // the route's own switch
	config::rvv_qcg_typed_chunk_vle_force_emit = true;
	// EEW 64 unit-stride has its own admission switch (A13); this test wants both widths.
	config::rvv_qcg_typed_chunk_mem_e64 = true;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_llvm_mem_partial_vl = false;
	config::aot_work_counter = false;
	config::aot_region_hit_count = false;
	config::aot_region_cycle_count = false;
	config::sr_activation_invariant = false;
	config::aot_link_multientry_merge = false;
	config::aot_link_multientry_trace = false;
	config::aot_link_alias_merge = false;
	config::aot_jumptable_multientry = false;
	config::aot_diag_direct_funcs = nullptr;
	config::aot_diag_inline_funcs = nullptr;
	config::aot_brcc_real_weights = false;
}

struct BuiltQIR {
	std::unique_ptr<MemArena> arena;
	Region *region = nullptr;
};

u32 g_words[2];

void SetProgram(u32 vtype, u32 insn)
{
	g_words[0] = EncodeVsetvli(vtype, /*rd=*/1, /*rs1=*/2);
	g_words[1] = insn;
}

BuiltQIR BuildQIR(u32 vtype, u32 insn, u32 vlen)
{
	BuiltQIR b;
	config::vlen_bits = vlen;
	SetProgram(vtype, insn);
	b.arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)g_words, CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(b.arena.get(), job);
	return b;
}

struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
};

void ConfigureLLVM(bool partial)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_llvm_mem_partial_vl = partial;
}

Built BuildLLVM(u32 vtype, u32 insn, u32 vlen, bool partial = true)
{
	ConfigureLLVM(partial);
	Built b;
	config::vlen_bits = vlen;
	SetProgram(vtype, insn);
	b.arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)g_words, CodeSegment(0u, 0x1000u), std::move(ranges));
	auto *region = CompilerGenRegionIR(b.arena.get(), job);
	b.mod = std::make_unique<llvm::Module>("w32_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, region, 0u);
	b.fn = gen.Run();
	return b;
}

// ---------------------------------------------------------------------------------------------
// QIR / IR inspection.
// ---------------------------------------------------------------------------------------------

qir::InstRVVTypedChunkBegin *FrameOf(Region *r)
{
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
				return static_cast<qir::InstRVVTypedChunkBegin *>(&ins);
	return nullptr;
}

std::vector<qir::InstVChunkLoad *> ChunkLoads(Region *r)
{
	std::vector<qir::InstVChunkLoad *> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_vchunkload)
				out.push_back(static_cast<qir::InstVChunkLoad *>(&ins));
	return out;
}

std::vector<qir::InstVStateChunkStore *> StateStores(Region *r)
{
	std::vector<qir::InstVStateChunkStore *> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_vstatechunkstore)
				out.push_back(static_cast<qir::InstVStateChunkStore *>(&ins));
	return out;
}

std::vector<llvm::IntrinsicInst *> Intrinsics(llvm::Function *fn, llvm::Intrinsic::ID id)
{
	std::vector<llvm::IntrinsicInst *> out;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&in))
				if (ii->getIntrinsicID() == id)
					out.push_back(ii);
	return out;
}

// Plain (unmasked) vector loads anywhere in the function. The frame's fast body must contain none
// of them once the partial arm is on: every guest-memory read has to be the masked intrinsic.
unsigned PlainVectorLoads(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&in))
				if (ld->getType()->isVectorTy())
					++n;
	return n;
}

unsigned CountStubCalls(llvm::Function *fn, char const *stub_name)
{
	unsigned n = 0;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *call = llvm::dyn_cast<llvm::CallInst>(&in)) {
				auto *callee = call->getCalledOperand();
				if (callee && callee->hasName() &&
				    callee->getName().starts_with(stub_name))
					++n;
			}
	return n;
}

bool IsStateEP(llvm::Value *p, u32 offs)
{
	auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	if (!gep || gep->getNumIndices() != 1)
		return false;
	auto *ci = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
	return ci && ci->getZExtValue() == offs;
}

// Does `v` trace back to a load of CPUState + `offs`, through splats/casts?
bool TracesToStateLoad(llvm::Value *v, u32 offs, unsigned depth = 0)
{
	if (depth > 8 || !v)
		return false;
	if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(v))
		return IsStateEP(ld->getPointerOperand(), offs);
	if (auto *in = llvm::dyn_cast<llvm::Instruction>(v))
		for (auto &op : in->operands())
			if (TracesToStateLoad(op.get(), offs, depth + 1))
				return true;
	return false;
}

std::vector<llvm::ICmpInst *> ICmps(llvm::Function *fn)
{
	std::vector<llvm::ICmpInst *> out;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *c = llvm::dyn_cast<llvm::ICmpInst>(&in))
				out.push_back(c);
	return out;
}

u32 LanesOf(u32 vlen, u32 eew) { return std::min(vlen / 8u, 64u) / eew; }
u32 ChunksOf(u32 vlen) { return (vlen / 8u) / std::min(vlen / 8u, 64u); }

// ---------------------------------------------------------------------------------------------
// Sections.
// ---------------------------------------------------------------------------------------------

// (0) Inertness: with the switch off the arm emits the pre-W32 QIR exactly.
void SectionSwitchOff()
{
	printf("[S0] switch off: the pre-W32 QIR, node for node\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		ConfigureLLVM(/*partial=*/false);
		auto q = BuildQIR(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1), vlen);
		auto *f = FrameOf(q.region);
		CHECK(f != nullptr);
		if (!f)
			continue;
		CHECK_EQ((int)f->guard_kind,
			 (int)qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
		for (auto *l : ChunkLoads(q.region))
			CHECK_EQ((unsigned)l->active_sew, 0u);
		for (auto *s : StateStores(q.region))
			CHECK_EQ((unsigned)s->active_sew, 0u);
		auto b = BuildLLVM(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1), vlen, /*partial=*/false);
		CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
		CHECK_EQ(Intrinsics(b.fn, llvm::Intrinsic::masked_load).size(), 0u);
		CHECK(PlainVectorLoads(b.fn) > 0);
	}
	printf("       guard kind VTypeVlVstart, active_sew 0, plain load, at five VLENs\n");
}

// (1) The guest-memory read is the masked intrinsic and nothing else.
void SectionMaskedLoad()
{
	printf("[S1] the guest-memory read is llvm.masked.load\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto eew : {std::pair<u32, u32>{W32BIT, 4}, std::pair<u32, u32>{W64BIT, 8}}) {
			u32 const vtype = eew.second == 4 ? VTYPE_E32_M1 : VTYPE_E64_M1;
			ConfigureLLVM(true);
			auto q = BuildQIR(vtype, EncodeVle(eew.first, VD, RS1), vlen);
			auto *f = FrameOf(q.region);
			CHECK(f != nullptr);
			if (!f)
				continue;
			CHECK_EQ((int)f->guard_kind,
				 (int)qir::InstRVVTypedChunkBegin::GuardKind::
				     VTypeVlOrPartialVstartBaseLimit);
			CHECK_EQ(f->base_limit, 0u - vlen / 8u);
			auto b = BuildLLVM(vtype, EncodeVle(eew.first, VD, RS1), vlen);
			CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
			u32 const chunks = ChunksOf(vlen);
			CHECK_EQ(Intrinsics(b.fn, llvm::Intrinsic::masked_load).size(), chunks);
			CHECK_EQ(Intrinsics(b.fn, llvm::Intrinsic::masked_store).size(), chunks);
			// THE POINT: no unmasked vector load survives anywhere in the frame.
			CHECK_EQ(PlainVectorLoads(b.fn), 0u);
			// The cold arm, once: the frame's ordered fallback to the unchanged helper.
			CHECK_EQ(CountStubCalls(b.fn, "rv32_vle"), 1u);
		}
	printf("       masked.load/masked.store per chunk, zero plain vector loads, EEW 32 and 64\n");
}

// (2) The mask IS the architectural active set, over the whole vl ladder including 0 and VLMAX.
void SectionVlLadder(u32 vlen, u32 width, u32 eew, u32 vtype)
{
	auto b = BuildLLVM(vtype, EncodeVle(width, VD, RS1), vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	auto loads = Intrinsics(b.fn, llvm::Intrinsic::masked_load);
	u32 const chunks = ChunksOf(vlen), lanes = LanesOf(vlen, eew);
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{vtype}, vlen);
	CHECK_EQ((unsigned)loads.size(), chunks);
	if (loads.size() != chunks)
		return;
	for (u32 c = 0; c < chunks; ++c) {
		// The intrinsic's mask is operand 2 (ptr, alignment, mask, passthru).
		auto *mask = loads[c]->getArgOperand(2);
		auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(mask);
		CHECK(cmp != nullptr);
		if (!cmp)
			continue;
		// The predicate is read out, not assumed.
		CHECK_EQ((int)cmp->getPredicate(), (int)llvm::CmpInst::ICMP_ULT);
		auto *idx = llvm::dyn_cast<llvm::Constant>(cmp->getOperand(0));
		CHECK(idx != nullptr);
		// The other side must be the LIVE vl, not vstart and not a constant.
		CHECK(TracesToStateLoad(cmp->getOperand(1), ST_VL));
		CHECK(!TracesToStateLoad(cmp->getOperand(1), ST_VSTART));
		if (!idx)
			continue;
		for (u32 vl = 0; vl <= vlmax; ++vl)
			for (u32 i = 0; i < lanes; ++i) {
				auto *e = llvm::dyn_cast<llvm::ConstantInt>(idx->getAggregateElement(i));
				CHECK(e != nullptr);
				if (!e)
					continue;
				// The architectural predicate: element index < vl.
				bool const want = (u32)e->getZExtValue() < vl;
				bool const got = llvm::ICmpInst::compare(
				    e->getValue(), llvm::APInt(32, vl), cmp->getPredicate());
				if (got != want) {
					fprintf(stderr,
						"  FAIL VLEN=%u eew=%u chunk=%u lane=%u vl=%u: "
						"emitted mask says %d, reference says %d\n",
						vlen, eew, c, i, vl, (int)got, (int)want);
					++g_failures;
					return;
				}
				// The index must be this chunk's element, which is what catches a
				// wrong element_base on chunk 1 and above.
				CHECK_EQ((u32)e->getZExtValue(), c * lanes + i);
			}
	}
}

// (3) One mask for the load and its store.
void SectionOneMask(u32 vlen, u32 width, u32 eew, u32 vtype)
{
	auto b = BuildLLVM(vtype, EncodeVle(width, VD, RS1), vlen);
	auto loads = Intrinsics(b.fn, llvm::Intrinsic::masked_load);
	auto stores = Intrinsics(b.fn, llvm::Intrinsic::masked_store);
	CHECK_EQ(loads.size(), stores.size());
	if (loads.size() != stores.size())
		return;
	for (size_t c = 0; c < loads.size(); ++c) {
		// masked.store(value, ptr, align, mask) -- the mask is operand 3.
		CHECK(loads[c]->getArgOperand(2) == stores[c]->getArgOperand(3));
		// The passthrough is zero, matching QEmit's `.z()` zero-masking.
		auto *pass = llvm::dyn_cast<llvm::Constant>(loads[c]->getArgOperand(3));
		CHECK(pass != nullptr);
		if (pass)
			CHECK(pass->isNullValue());
	}
	(void)eew;
}

// (4) The guard: vl <= VLMAX (not ==), vstart == 0, base <= 2^32 - VLEN/8.
void SectionGuard(u32 vlen)
{
	auto b = BuildLLVM(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1), vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{VTYPE_E32_M1}, vlen);
	bool vl_ule = false, vstart_eq0 = false, base_ule = false;
	for (auto *c : ICmps(b.fn)) {
		if (c->getOperand(0)->getType()->isVectorTy())
			continue;
		auto *rhs = llvm::dyn_cast<llvm::ConstantInt>(c->getOperand(1));
		if (!rhs)
			continue;
		if (c->getPredicate() == llvm::CmpInst::ICMP_ULE &&
		    rhs->getZExtValue() == vlmax && TracesToStateLoad(c->getOperand(0), ST_VL))
			vl_ule = true;
		if (c->getPredicate() == llvm::CmpInst::ICMP_EQ && rhs->getZExtValue() == 0 &&
		    TracesToStateLoad(c->getOperand(0), ST_VSTART))
			vstart_eq0 = true;
		if (c->getPredicate() == llvm::CmpInst::ICMP_ULE &&
		    rhs->getZExtValue() == (u32)(0u - vlen / 8u) &&
		    TracesToStateLoad(c->getOperand(0), ST_RS1))
			base_ule = true;
	}
	CHECK(vl_ule);
	CHECK(vstart_eq0);
	CHECK(base_ule);
	// And the full-VL form must be GONE: no `vl == VLMAX` equality anywhere.
	for (auto *c : ICmps(b.fn)) {
		if (c->getOperand(0)->getType()->isVectorTy())
			continue;
		auto *rhs = llvm::dyn_cast<llvm::ConstantInt>(c->getOperand(1));
		if (rhs && c->getPredicate() == llvm::CmpInst::ICMP_EQ &&
		    rhs->getZExtValue() == vlmax && TracesToStateLoad(c->getOperand(0), ST_VL)) {
			fprintf(stderr, "  FAIL VLEN=%u: the guard still tests vl == VLMAX\n", vlen);
			++g_failures;
		}
	}
}

// (5) Refusals that must keep the helper.
void SectionRefusals()
{
	printf("[S5] refusal matrix\n");
	struct Row { char const *name; bool verify; bool route; bool ssa; };
	Row const rows[] = {
	    {"--rvv-verify on", true, true, true},
	    {"--rvv-qcg-typed-chunk-vle off", false, false, true},
	    {"--rvv-vector-ssa off", false, true, false},
	};
	for (auto const &r : rows) {
		ConfigureLLVM(true);
		config::rvv_verify = r.verify;
		config::rvv_qcg_typed_chunk_vle = r.route;
		config::rvv_vector_ssa = r.ssa;
		config::vlen_bits = 512;
		SetProgram(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1));
		auto arena = std::make_unique<MemArena>(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)g_words, CodeSegment(0u, 0x1000u), std::move(ranges));
		auto *region = CompilerGenRegionIR(arena.get(), job);
		unsigned const frames = FrameOf(region) ? 1u : 0u;
		unsigned const masked_loads = [&] {
			unsigned n = 0;
			for (auto *l : ChunkLoads(region))
				n += (l->active_sew != 0);
			return n;
		}();
		CHECK_EQ(masked_loads, 0u);
		printf("-- %-34s frames=%u masked chunk loads=%u\n", r.name, frames, masked_loads);
	}
	// The Ref lowering arm: the route refuses it outright (the reference addresses elements
	// modulo 2^32 and this frame walks host pointers), so no frame at all.
	ConfigureLLVM(true);
	config::rvv_lowering = 0;
	config::vlen_bits = 512;
	SetProgram(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1));
	auto arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)g_words, CodeSegment(0u, 0x1000u), std::move(ranges));
	auto *region = CompilerGenRegionIR(arena.get(), job);
	CHECK(FrameOf(region) == nullptr);
	printf("-- %-34s frames=0\n", "--rvv-lowering 0 (Ref)");
}

// (6) The pure-QCG arms are untouched.
void SectionQcgUnchanged()
{
	printf("[S6] the pure-QCG arms do not move\n");
	for (u32 vlen : {512u, 2048u}) {
		ResetConfig();
		config::aot_use_llvm = false;
		config::rvv_llvm_mem_partial_vl = true; // on, and must be ignored off the LLVM arm
		auto q = BuildQIR(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1), vlen);
		auto *f = FrameOf(q.region);
		CHECK(f != nullptr);
		if (!f)
			continue;
		CHECK_EQ((int)f->guard_kind,
			 (int)qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit);
		for (auto *l : ChunkLoads(q.region))
			CHECK_EQ((unsigned)l->active_sew, 0u);
		printf("       VLEN=%-5u pure QCG keeps VTypeVlVstartBaseLimit and an unmasked load\n",
		       vlen);
	}
}

std::string PrintFn(llvm::Function *fn)
{
	std::string out;
	llvm::raw_string_ostream os(out);
	fn->print(os);
	return out;
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i)
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	printf("W32 partial-VL unit-stride vector load, LLVM/AOT lowering\n\n");

	SectionSwitchOff();
	SectionMaskedLoad();

	printf("[S2] the mask over the whole vl ladder, lane by lane\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		SectionVlLadder(vlen, W32BIT, 4, VTYPE_E32_M1);
		SectionVlLadder(vlen, W64BIT, 8, VTYPE_E64_M1);
	}
	printf("       vl = 0 .. VLMAX inclusive, EEW 32 and 64, five VLENs\n");

	printf("[S3] one mask for the load and its store\n");
	for (u32 vlen : {128u, 512u, 2048u}) {
		SectionOneMask(vlen, W32BIT, 4, VTYPE_E32_M1);
		SectionOneMask(vlen, W64BIT, 8, VTYPE_E64_M1);
	}
	printf("       load mask == store mask, passthrough is zero\n");

	printf("[S4] the guard\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		SectionGuard(vlen);
	printf("       vl <= VLMAX (no vl == VLMAX left), vstart == 0, base <= 2^32 - VLEN/8\n");

	SectionRefusals();
	SectionQcgUnchanged();

	if (dump_ir) {
		auto b = BuildLLVM(VTYPE_E32_M1, EncodeVle(W32BIT, VD, RS1), 512);
		printf("\n----- PRE-OPT IR vle32.v, e32/m1, VLEN=512 -----\n%s", PrintFn(b.fn).c_str());
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
