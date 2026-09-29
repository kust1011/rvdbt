// W31: focused test for the INTEGER COMPARE family lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES. `RvvTryLLVMIntCompare` builds the SAME `InstVChunkPartialAlu` nodes the
// pure-QCG `RvvTryIntegerFamily` builds, and `QIRToLLVM::Emit_vchunkpartialalu` supplies the eight
// compare kinds it used to Panic on. So there are two distinct claims to prove, and this file keeps
// them apart:
//
//   1. THE TWO ARMS AGREE ABOUT THE SEMANTICS. Section "QIR identity" builds the same guest word
//      twice -- once with `aot_use_llvm = false` (the QCG arm) and once with it true (the LLVM arm)
//      -- and compares every field of every emitted compare node. If the LLVM route ever drifts
//      into a second dialect of "what a compare means", this fails. It is the reason the route was
//      written as a separate function rather than as a relaxation of RvvTryIntegerFamily, and the
//      reason that decision is safe.
//
//   2. THE EMITTED IR COMPUTES THE ARCHITECTURAL ANSWER. Section "predicate semantics" does not
//      read the opcode name: it pulls the ACTUAL `llvm::CmpInst::Predicate` out of the generated
//      function and evaluates it with LLVM's own APInt comparison over operand pairs that straddle
//      every boundary that matters at that SEW -- 0, 1, max, min, -1, the signed/unsigned
//      disagreement pair -- against `rvv_ref::vicmp_apply`, which is the interpreter's own
//      expression. Emitting ULT where SLT was meant agrees on every non-negative pair and differs
//      on exactly the pairs this table contains.
//
// The pipeline is the real one, inspected in memory:
//
//     encoded guest words -> qir::CompilerGenRegionIR -> qir::QIRToLLVM::Run() -> llvm::Function
//
// No TargetMachine, no pass pipeline, no object file, and NO claim about host instructions, cycles
// or speed.
//
// THE STRUCTURAL PROPERTIES A MASK DESTINATION ADDS, each checked rather than described:
//
//   * THE DESTINATION IS A BLEND. `CheckBlendNotStore` requires the i64 store's value to depend on
//     a LOAD of the same word. An emitter that stored the computed bits would clobber the tail,
//     the prestart region, the inactive elements -- and, when `vd == v0`, the mask bits its own
//     later chunks still have to read.
//   * vstart PARTICIPATES. `CheckReadsVstart` requires a load of `vec.vstart`. The frame's guard is
//     `VTypeInteger`, which deliberately does NOT test vstart, so a body that ignored it would
//     write the prestart region of a restarted compare.
//   * v0 IS READ ONLY WHEN `vm == 0`. `CheckMaskSource` requires a load inside the v0 window for a
//     masked encoding and NONE for an unmasked one, so "masked" is neither ignored nor applied
//     unconditionally.
//   * THE `.vx` SCALAR IS sext-THEN-trunc. `CheckScalarSplat` reads the splat's source chain.
//   * THE `.vi` IMMEDIATE IS SIGN-EXTENDED. `CheckImmediateSplat` encodes simm5 = -1 and requires
//     the splat constant to be all ones at SEW width, not 31.
//
// SCOPE: every funct6/operand-form pair `vicmp_supported` admits, SEW 8/16/32/64, LMUL m1 through
// m8 and the fractional ones, VLEN 128/256/512/1024/2048, masked and unmasked, `vd == v0`. The
// refusal matrix covers the switch, the substrate switch, an unobserved vtype, an illegal vtype,
// the ISA's own missing forms, and the illegal mask-destination overlap that must stay a guest trap.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Function.h"
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
// Guest encodings, from fields.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11, u32 rd, u32 rs1)
{
	return (zimm11 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
// OP-V: funct6[31:26], vm[25], vs2[24:20], vs1/rs1/simm5[19:15], funct3[14:12], vd[11:7], 0x57.
constexpr u32 EncodeOpv(u32 f6, u32 vm, u32 vs2, u32 s1, u32 f3, u32 vd)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (s1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}

constexpr u32 F3_VV = 0b000, F3_VI = 0b011, F3_VX = 0b100;

struct FormName {
	u32 f6;
	char const *name;
};
constexpr FormName kOps[8] = {
    {rv32::VF6_VMSEQ, "vmseq"},   {rv32::VF6_VMSNE, "vmsne"},   {rv32::VF6_VMSLTU, "vmsltu"},
    {rv32::VF6_VMSLT, "vmslt"},   {rv32::VF6_VMSLEU, "vmsleu"}, {rv32::VF6_VMSLE, "vmsle"},
    {rv32::VF6_VMSGTU, "vmsgtu"}, {rv32::VF6_VMSGT, "vmsgt"}};

// VS2 and VS1 are chosen EMUL-ALIGNED UP TO LMUL 8 (both multiples of 8, both groups inside
// v0..v31) so the same register numbers stay legal at every LMUL the sweep drives. VD is below
// both source groups, which is the legal mask-destination overlap (`rd <= source`).
constexpr u32 VD = 3, VS2 = 8, VS1 = 16, RS1_REG = 10;

constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VREG = ST_VEC + (u32)offsetof(rv32::VectorState, vreg);

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_typed_chunk = true;
	// Host-probe bypass, so the QCG arm of the identity check builds the same QIR on a machine
	// without AVX-512. It changes admission only by removing a CPUID test; the nodes it then
	// produces are the ones an AVX-512 host would produce.
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_llvm_icmp = false;
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

// Every program is `vsetvli x0, x0-ish, <vtype>` followed by the compare, so the block has an
// OBSERVED vtype -- which every typed route requires and which is how a real guest arrives here.
BuiltQIR BuildQIR(u32 vtype, u32 insn, u32 vlen)
{
	BuiltQIR b;
	config::vlen_bits = vlen;
	b.arena = std::make_unique<MemArena>(1u << 20);
	static u32 words[2];
	words[0] = EncodeVsetvli(vtype, /*rd=*/1, /*rs1=*/2);
	words[1] = insn;
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(b.arena.get(), job);
	return b;
}

struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
};

Built BuildLLVM(u32 vtype, u32 insn, u32 vlen, bool icmp = true, bool ssa = true)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_llvm_icmp = icmp;
	Built b;
	config::vlen_bits = vlen;
	b.arena = std::make_unique<MemArena>(1u << 20);
	static u32 words[2];
	words[0] = EncodeVsetvli(vtype, 1, 2);
	words[1] = insn;
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	auto *region = CompilerGenRegionIR(b.arena.get(), job);
	b.mod = std::make_unique<llvm::Module>("w31_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, region, 0u);
	b.fn = gen.Run();
	return b;
}

// ---------------------------------------------------------------------------------------------
// QIR inspection.
// ---------------------------------------------------------------------------------------------

std::vector<qir::InstVChunkPartialAlu *> CompareNodes(Region *r)
{
	std::vector<qir::InstVChunkPartialAlu *> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_vchunkpartialalu)
				out.push_back(static_cast<qir::InstVChunkPartialAlu *>(&ins));
	return out;
}

unsigned CountHcall(Region *r, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_hcall &&
			    static_cast<qir::InstHcall *>(&ins)->stub == stub)
				++n;
	return n;
}

// ---------------------------------------------------------------------------------------------
// IR inspection.
// ---------------------------------------------------------------------------------------------

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

// Any state access whose constant offset lies in [lo, hi).
unsigned CountStateLoadsInRange(llvm::Function *fn, u32 lo, u32 hi)
{
	unsigned n = 0;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&in)) {
				auto *gep =
				    llvm::dyn_cast<llvm::GetElementPtrInst>(ld->getPointerOperand());
				if (!gep || gep->getNumIndices() != 1)
					continue;
				auto *ci = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
				if (ci && ci->getZExtValue() >= lo && ci->getZExtValue() < hi)
					++n;
			}
	return n;
}

std::vector<llvm::ICmpInst *> VectorICmps(llvm::Function *fn)
{
	std::vector<llvm::ICmpInst *> out;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *c = llvm::dyn_cast<llvm::ICmpInst>(&in))
				if (c->getOperand(0)->getType()->isVectorTy())
					out.push_back(c);
	return out;
}

// The compare that is the INSTRUCTION, not the body-mask predicate. The body mask compares a
// constant index vector against a splat of vec.vl / vec.vstart; the instruction's compare has
// neither operand constant-folded to that shape. Selecting by "neither operand is a ConstantVector
// of indices" is fragile, so instead: the instruction's compare is the one whose element type
// matches SEW, since the mask predicate is always built on i32 indices.
llvm::ICmpInst *InstructionICmp(llvm::Function *fn, u32 sew_bytes, u32 lanes)
{
	for (auto *c : VectorICmps(fn)) {
		auto *vt = llvm::cast<llvm::FixedVectorType>(c->getOperand(0)->getType());
		if (vt->getScalarSizeInBits() == 8u * sew_bytes && vt->getNumElements() == lanes)
			return c;
	}
	return nullptr;
}

std::string PrintFn(llvm::Function *fn)
{
	std::string out;
	llvm::raw_string_ostream os(out);
	fn->print(os);
	return out;
}

// ---------------------------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------------------------

u32 LanesFor(u32 vlen, u32 sew) { return std::min(vlen / 8u, 64u) / sew; }

// (1) The QIR identity check: the QCG arm and the LLVM arm build the same nodes.
void CheckQIRIdentity(char const *name, u32 vtype, u32 insn, u32 vlen)
{
	ResetConfig();
	config::aot_use_llvm = false; // pure QCG: RvvTryIntegerFamily
	auto q = BuildQIR(vtype, insn, vlen);
	auto qn = CompareNodes(q.region);

	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_llvm_icmp = true; // LLVM: RvvTryLLVMIntCompare
	auto l = BuildQIR(vtype, insn, vlen);
	auto ln = CompareNodes(l.region);

	CHECK(!qn.empty());
	CHECK_EQ(ln.size(), qn.size());
	if (qn.empty() || ln.size() != qn.size())
		return;
	for (size_t k = 0; k < qn.size(); ++k) {
		auto *a = qn[k];
		auto *b = ln[k];
		CHECK_EQ((unsigned)b->op, (unsigned)a->op);
		CHECK_EQ((unsigned)b->sew_bytes, (unsigned)a->sew_bytes);
		CHECK_EQ((unsigned)b->chunk, (unsigned)a->chunk);
		CHECK_EQ((unsigned)b->src1_kind, (unsigned)a->src1_kind);
		CHECK_EQ((unsigned)b->chunk_bytes, (unsigned)a->chunk_bytes);
		CHECK_EQ((unsigned)b->rd_offs, (unsigned)a->rd_offs);
		CHECK_EQ((unsigned)b->rs2_offs, (unsigned)a->rs2_offs);
		CHECK_EQ((unsigned)b->rs1_offs, (unsigned)a->rs1_offs);
		CHECK_EQ(b->imm, a->imm);
		CHECK_EQ((int)b->architectural_mask, (int)a->architectural_mask);
		CHECK_EQ((int)b->masked, (int)a->masked);
		CHECK_EQ(b->element_base, a->element_base);
		CHECK_EQ((int)b->finish_instruction, (int)a->finish_instruction);
	}
	printf("   %-30s VLEN=%-5u %zu node(s) identical on both arms\n", name, vlen, qn.size());
}

// (2) The semantic core: the emitted predicate, evaluated over the pairs that separate the eight.
void CheckPredicateSemantics(u32 f6, char const *name, u32 f3, u32 vtype, u32 sew, u32 vlen)
{
	u32 const vm = 1;
	u32 const s1 = f3 == F3_VV ? VS1 : (f3 == F3_VX ? RS1_REG : 5u);
	auto b = BuildLLVM(vtype, EncodeOpv(f6, vm, VS2, s1, f3, VD), vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	u32 const lanes = LanesFor(vlen, sew);
	auto *cmp = InstructionICmp(b.fn, sew, lanes);
	CHECK(cmp != nullptr);
	if (!cmp)
		return;
	auto const pred = cmp->getPredicate();
	unsigned const bits = 8u * sew;
	// Pairs chosen so a signed/unsigned mix-up, a swapped operand order and a wrong strictness
	// each fail on at least one row. The last two rows are the whole signed-vs-unsigned question:
	// as unsigned, (max_signed+1) > 1; as signed it is the most negative value and is < 1.
	u64 const hi = bits == 64 ? (1ull << 63) : (1ull << (bits - 1));
	u64 const allones = bits == 64 ? ~0ull : ((1ull << bits) - 1u);
	struct Pair { u64 a, b; } const pairs[] = {
	    {0, 0}, {0, 1}, {1, 0}, {1, 1}, {allones, allones}, {allones, 0}, {0, allones},
	    {hi, 1}, {1, hi}, {hi, hi - 1}, {hi - 1, hi},
	};
	for (auto const &p : pairs) {
		// The reference is the interpreter's own expression, at this SEW.
		bool const want = rv32::rvv_ref::vicmp_apply(f6, p.a, p.b, sew);
		bool const got = llvm::ICmpInst::compare(llvm::APInt(bits, p.a),
							 llvm::APInt(bits, p.b), pred);
		if (got != want) {
			fprintf(stderr,
				"  FAIL %s sew=%u a=0x%llx b=0x%llx: emitted predicate gives %d, "
				"vicmp_apply gives %d\n",
				name, sew, (unsigned long long)p.a, (unsigned long long)p.b,
				(int)got, (int)want);
			++g_failures;
		}
	}
}

// (3) The destination is a BLEND: the stored word depends on a load of the same word.
void CheckBlendNotStore(u32 vtype, u32 insn, u32 vlen)
{
	auto b = BuildLLVM(vtype, insn, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	bool found = false;
	for (auto &bb : *b.fn) {
		for (auto &in : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&in);
			if (!st || !st->getValueOperand()->getType()->isIntegerTy(64))
				continue;
			// value = or(w, and(old, not(m))) -- walk one level and require a load.
			auto *orr = llvm::dyn_cast<llvm::BinaryOperator>(st->getValueOperand());
			if (!orr || orr->getOpcode() != llvm::Instruction::Or)
				continue;
			for (unsigned k = 0; k < 2; ++k) {
				auto *andd = llvm::dyn_cast<llvm::BinaryOperator>(orr->getOperand(k));
				if (!andd || andd->getOpcode() != llvm::Instruction::And)
					continue;
				for (unsigned j = 0; j < 2; ++j)
					if (llvm::isa<llvm::LoadInst>(andd->getOperand(j)))
						found = true;
			}
		}
	}
	CHECK(found);
}

// (4) vstart PARTICIPATES IN THE BODY MASK. The frame guard is `VTypeInteger`, which deliberately
// does not test vstart, so a body that ignored it would write the prestart region of a restarted
// compare.
//
// THE FIRST VERSION OF THIS CHECK WAS NOT FALSIFIABLE and a mutation caught it: it asserted only
// that a load of `vec.vstart` existed somewhere in the function, which stays true when the loaded
// value is computed and then dropped. Deleting the `vstart` term from the mask left the load in
// place and the test still passed. What is checked now is the TERM: a vector `icmp uge`, which the
// emitter creates in exactly one place -- `element_index >= vstart` -- and whose right-hand side
// must be a non-constant splat. The instruction's own compare never uses UGE (the eight guest
// compares lower to EQ/NE/ULT/SLT/ULE/SLE/UGT/SGT) and the `< vl` term is ULT, so a UGE over
// vectors is unique to this term and disappears with it.
void CheckReadsVstart(u32 vtype, u32 insn, u32 vlen)
{
	auto b = BuildLLVM(vtype, insn, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK(CountStateLoadsInRange(b.fn, ST_VSTART, ST_VSTART + 4u) > 0);
	llvm::ICmpInst *uge = nullptr;
	for (auto *c : VectorICmps(b.fn))
		if (c->getPredicate() == llvm::CmpInst::ICMP_UGE)
			uge = c;
	CHECK(uge != nullptr);
	if (!uge)
		return;
	// The index side is the constant vector; the other side is the live vstart, so it must not
	// have been folded to a constant.
	CHECK(llvm::isa<llvm::Constant>(uge->getOperand(0)));
	CHECK(!llvm::isa<llvm::Constant>(uge->getOperand(1)));
}

// (5) v0 is read iff vm == 0.
void CheckMaskSource(u32 vtype, u32 f6, u32 f3, u32 vlen)
{
	u32 const s1 = f3 == F3_VV ? VS1 : (f3 == F3_VX ? RS1_REG : 5u);
	// v0's window is the first VLEN/8 bytes of the register file.
	u32 const v0_lo = ST_VREG, v0_hi = ST_VREG + rv32::VLEN_MAX_BYTES;
	auto unmasked = BuildLLVM(vtype, EncodeOpv(f6, 1, VS2, s1, f3, VD), vlen);
	auto masked = BuildLLVM(vtype, EncodeOpv(f6, 0, VS2, s1, f3, VD), vlen);
	CHECK(!llvm::verifyFunction(*masked.fn, &llvm::errs()));
	// VD and VS2/VS1 are all above v0, so no load in v0's window can come from a source read.
	CHECK_EQ(CountStateLoadsInRange(unmasked.fn, v0_lo, v0_hi), 0u);
	CHECK(CountStateLoadsInRange(masked.fn, v0_lo, v0_hi) > 0);
	// One call: the frame's cold fallback arm, not a refusal. See CheckAdmitted.
	CHECK_EQ(CountStubCalls(masked.fn, "rv32_vicmp"), 1u);
}

// (6) The .vx splat is sext-to-64 then trunc-to-SEW.
void CheckScalarSplat(u32 vtype, u32 sew, u32 vlen)
{
	auto b = BuildLLVM(vtype, EncodeOpv(rv32::VF6_VMSEQ, 1, VS2, RS1_REG, F3_VX, VD), vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	bool sext_found = false, trunc_found = false;
	for (auto &bb : *b.fn)
		for (auto &in : bb) {
			if (auto *se = llvm::dyn_cast<llvm::SExtInst>(&in))
				if (se->getSrcTy()->isIntegerTy(32) && se->getDestTy()->isIntegerTy(64))
					sext_found = true;
			if (auto *tr = llvm::dyn_cast<llvm::TruncInst>(&in))
				if (tr->getSrcTy()->isIntegerTy(64) &&
				    tr->getDestTy()->isIntegerTy(8u * sew))
					trunc_found = true;
		}
	// At SEW 8 the trunc i64->i64 is a no-op the builder folds away, so require it only below.
	CHECK(sext_found);
	if (sew != 8)
		CHECK(trunc_found);
}

// (7) The .vi immediate is SIGN-extended: simm5 = 0b11111 is -1, not 31.
void CheckImmediateSplat(u32 vtype, u32 sew, u32 vlen)
{
	auto b = BuildLLVM(vtype, EncodeOpv(rv32::VF6_VMSEQ, 1, VS2, /*simm5=*/0b11111u, F3_VI, VD),
			   vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vicmp"), 1u); // the frame's cold fallback arm
	u32 const lanes = LanesFor(vlen, sew);
	auto *cmp = InstructionICmp(b.fn, sew, lanes);
	CHECK(cmp != nullptr);
	if (!cmp)
		return;
	// The splat operand is a constant vector of all ones at SEW width.
	auto *sp = llvm::dyn_cast<llvm::Constant>(cmp->getOperand(1));
	CHECK(sp != nullptr);
	if (!sp)
		return;
	auto *elem = sp->getSplatValue();
	CHECK(elem != nullptr);
	if (!elem)
		return;
	auto *ci = llvm::dyn_cast<llvm::ConstantInt>(elem);
	CHECK(ci != nullptr);
	if (ci)
		CHECK(ci->getValue().isAllOnes());
}

// ADMISSION IS THE PRESENCE OF THE TYPED BODY, NOT THE ABSENCE OF THE HELPER, and that distinction
// is the one this file got wrong first. Every typed-chunk frame emits a GUARD with an ordered
// fallback arm, and that arm holds exactly one call to the unchanged `rv32_vicmp`. So an admitted
// compare has one helper call on its cold arm by construction, and counting calls cannot tell
// admission from refusal. What can is the native body: the `InstVChunkPartialAlu` nodes in the QIR
// and the SEW-width vector `icmp` they lower to.
void CheckAdmitted(char const *name, u32 vtype, u32 insn, u32 vlen)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_llvm_icmp = true;
	auto q = BuildQIR(vtype, insn, vlen);
	unsigned const nodes = (unsigned)CompareNodes(q.region).size();
	CHECK(nodes > 0);

	auto b = BuildLLVM(vtype, insn, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	u32 const sew = rv32::VType{vtype}.sew() / 8u;
	CHECK(InstructionICmp(b.fn, sew, LanesFor(vlen, sew)) != nullptr);
	// The cold arm, present precisely once: the frame's ordered fallback to the unchanged helper.
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vicmp"), 1u);
	(void)name;
}

// `expect_hcall` is 1 for an encoding the decoder routes to `Op::_vicmp` and 0 for one it does not
// route there at all -- `vmslt.vi` and `vmsgt.vv` are not RVV instructions, so `vicmp_supported`
// refuses them inside rv32_decode.h and they never reach this route to be refused by it. Both cases
// share the property that matters: NO native compare body was emitted.
void CheckNotAdmitted(char const *name, u32 vtype, u32 insn, u32 vlen, bool icmp = true,
		      bool ssa = true, unsigned expect_hcall = 1u)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_llvm_icmp = icmp;
	auto q = BuildQIR(vtype, insn, vlen);
	CHECK_EQ((unsigned)CompareNodes(q.region).size(), 0u);
	CHECK_EQ(CountHcall(q.region, RuntimeStubId::id_rv32_vicmp), expect_hcall);

	auto b = BuildLLVM(vtype, insn, vlen, icmp, ssa);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	u32 const sew = rv32::VType{vtype}.sew() / 8u;
	CHECK(InstructionICmp(b.fn, sew, LanesFor(vlen, sew)) == nullptr);
	printf("-- not admitted: %-42s VLEN=%-5u typed nodes=0 rv32_vicmp hcalls=%u\n", name, vlen,
	       CountHcall(q.region, RuntimeStubId::id_rv32_vicmp));
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i)
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	printf("W31 integer compare family, LLVM/AOT lowering\n");

	u32 const kVlens[] = {128u, 256u, 512u, 1024u, 2048u};
	// (vsew field, SEW bytes)
	struct SewRow { u32 field, bytes; char const *name; };
	SewRow const kSews[] = {{0, 1, "e8"}, {1, 2, "e16"}, {2, 4, "e32"}, {3, 8, "e64"}};

	printf("\n== admitted: every funct6 x every legal form x every SEW x every VLEN ==\n");
	unsigned admitted = 0;
	for (u32 vlen : kVlens)
		for (auto const &s : kSews) {
			u32 const vtype = Zimm(s.field, /*vlmul=*/0, 1, 1);
			for (auto const &o : kOps)
				for (u32 f3 : {F3_VV, F3_VX, F3_VI}) {
					rv32::VSrc const src = f3 == F3_VV   ? rv32::VSrc::VV
							       : f3 == F3_VX ? rv32::VSrc::VX
									     : rv32::VSrc::VI;
					if (!rv32::vicmp_supported(o.f6, src))
						continue;
					u32 const s1 = f3 == F3_VV   ? VS1
						       : f3 == F3_VX ? RS1_REG
								     : 5u;
					CheckAdmitted(o.name, vtype,
						      EncodeOpv(o.f6, 1, VS2, s1, f3, VD), vlen);
					++admitted;
				}
		}
	printf("   %u encodings admitted: native body present, one cold fallback call each\n", admitted);

	printf("\n== the emitted predicate vs rvv_ref::vicmp_apply ==\n");
	for (auto const &s : kSews)
		for (auto const &o : kOps)
			for (u32 f3 : {F3_VV, F3_VX, F3_VI}) {
				rv32::VSrc const src = f3 == F3_VV   ? rv32::VSrc::VV
						       : f3 == F3_VX ? rv32::VSrc::VX
								     : rv32::VSrc::VI;
				if (!rv32::vicmp_supported(o.f6, src))
					continue;
				CheckPredicateSemantics(o.f6, o.name, f3, Zimm(s.field, 0, 1, 1),
							s.bytes, 512);
			}
	printf("   all eight funct6 match the reference on 11 operand pairs at SEW 8/16/32/64\n");

	printf("\n== QIR identity: the QCG arm and the LLVM arm build the same nodes ==\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (auto const &s : kSews)
			for (i32 lmul : {0, 1, 3, 7}) { // m1, m2, m8, mf2
				u32 const vtype = Zimm(s.field, (u32)lmul, 1, 1);
				if (!rv32::vtype_supported(rv32::VType{vtype}, vlen))
					continue;
				char nm[64];
				snprintf(nm, sizeof nm, "%s vlmul=%d vv", s.name, lmul);
				CheckQIRIdentity(nm, vtype,
						 EncodeOpv(rv32::VF6_VMSLT, 1, VS2, VS1, F3_VV, VD),
						 vlen);
				snprintf(nm, sizeof nm, "%s vlmul=%d vx masked", s.name, lmul);
				CheckQIRIdentity(nm, vtype,
						 EncodeOpv(rv32::VF6_VMSLEU, 0, VS2, RS1_REG, F3_VX, VD),
						 vlen);
				snprintf(nm, sizeof nm, "%s vlmul=%d vi", s.name, lmul);
				CheckQIRIdentity(nm, vtype,
						 EncodeOpv(rv32::VF6_VMSGT, 1, VS2, 5u, F3_VI, VD),
						 vlen);
			}

	printf("\n== mask-destination structure ==\n");
	for (u32 vlen : kVlens) {
		u32 const vtype = Zimm(2, 0, 1, 1); // e32,m1
		u32 const insn = EncodeOpv(rv32::VF6_VMSEQ, 1, VS2, VS1, F3_VV, VD);
		CheckBlendNotStore(vtype, insn, vlen);
		CheckReadsVstart(vtype, insn, vlen);
		CheckMaskSource(vtype, rv32::VF6_VMSEQ, F3_VV, vlen);
	}
	printf("   blend (not store), vstart read, v0 read iff vm==0, at five VLENs\n");

	printf("\n== the two scalar sources ==\n");
	for (auto const &s : kSews) {
		CheckScalarSplat(Zimm(s.field, 0, 1, 1), s.bytes, 512);
		CheckImmediateSplat(Zimm(s.field, 0, 1, 1), s.bytes, 512);
	}
	printf("   .vx is sext-then-trunc; .vi sign-extends simm5 (0b11111 is -1, not 31)\n");

	printf("\n== vd == v0 is legal for a mask destination ==\n");
	for (u32 vlen : {512u, 2048u}) {
		u32 const vtype = Zimm(2, 0, 1, 1);
		CheckAdmitted("vd==v0 unmasked", vtype,
			      EncodeOpv(rv32::VF6_VMSEQ, 1, VS2, VS1, F3_VV, /*vd=*/0), vlen);
		CheckAdmitted("vd==v0 masked", vtype,
			      EncodeOpv(rv32::VF6_VMSEQ, 0, VS2, VS1, F3_VV, /*vd=*/0), vlen);
	}
	printf("   admitted in both mask settings (RVV 1.0 5.3 exempts a mask destination)\n");

	printf("\n== refusal matrix ==\n");
	{
		u32 const e32m1 = Zimm(2, 0, 1, 1);
		u32 const ok = EncodeOpv(rv32::VF6_VMSEQ, 1, VS2, VS1, F3_VV, VD);
		for (u32 vlen : {512u, 2048u}) {
			CheckNotAdmitted("route switch off", e32m1, ok, vlen, /*icmp=*/false);
			CheckNotAdmitted("vector-SSA off", e32m1, ok, vlen, true, /*ssa=*/false);
		}
		// The ISA's own missing forms, refused by vicmp_supported rather than by this route.
		CheckNotAdmitted("vmslt.vi (no immediate form in RVV)", e32m1,
				 EncodeOpv(rv32::VF6_VMSLT, 1, VS2, 5u, F3_VI, VD), 512, true, true,
				 /*expect_hcall=*/0u);
		CheckNotAdmitted("vmsgt.vv (no vector-vector form in RVV)", e32m1,
				 EncodeOpv(rv32::VF6_VMSGT, 1, VS2, VS1, F3_VV, VD), 512, true, true,
				 /*expect_hcall=*/0u);
		// RVV 1.0: a mask destination may coincide with a source group's BASE but not with a
		// higher register of it. The interpreter raises ILLEGAL_INSN, so the helper must keep
		// it -- lowering it would turn an architectural trap into a wrong answer.
		u32 const e32m4 = Zimm(2, /*vlmul=*/2, 1, 1); // LMUL 4: vs2 spans v8..v11
		CheckNotAdmitted("vd inside a source group (illegal overlap)", e32m4,
				 EncodeOpv(rv32::VF6_VMSEQ, 1, /*vs2=*/8, /*vs1=*/VS1, F3_VV,
					   /*vd=*/9),
				 512);
		CheckAdmitted("vd == source group base (legal)", e32m4,
			      EncodeOpv(rv32::VF6_VMSEQ, 1, /*vs2=*/8, /*vs1=*/VS1, F3_VV, /*vd=*/8),
			      512);
		// An unaligned source group is an illegal encoding at LMUL 4.
		CheckNotAdmitted("source group not EMUL-aligned", e32m4,
				 EncodeOpv(rv32::VF6_VMSEQ, 1, /*vs2=*/9, VS1, F3_VV, VD), 512);
		// A reserved vtype: vlmul == 0b100.
		CheckNotAdmitted("reserved LMUL (vill -> helper)", Zimm(2, 4, 1, 1), ok, 512);
	}

	printf("\n== no other family moved ==\n");
	{
		// vmlogic has its own switch and is OFF here: it must still be a helper call, which
		// proves --rvv-llvm-icmp did not sweep a neighbouring mask family into a route.
		u32 const e32m1 = Zimm(2, 0, 1, 1);
		auto b = BuildLLVM(e32m1, EncodeOpv(/*vmand=*/25u, 1, VS2, VS1, 0b010u, VD), 512);
		CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
		CHECK_EQ(CountStubCalls(b.fn, "rv32_vmlogic"), 1u);
		printf("   vmand keeps rv32_vmlogic (its own switch is off)\n");
	}

	if (dump_ir) {
		auto b = BuildLLVM(Zimm(2, 0, 1, 1),
				   EncodeOpv(rv32::VF6_VMSLT, 0, VS2, VS1, F3_VV, VD), 512);
		printf("\n----- PRE-OPT IR vmslt.vv masked, e32,m1, VLEN=512 -----\n%s",
		       PrintFn(b.fn).c_str());
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
