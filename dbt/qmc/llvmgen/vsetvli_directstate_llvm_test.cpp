// S3.4: focused test for the direct-state `vsetvli` route as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES. dbt/qmc/qcg/vsetvli_directstate_route_test.cpp already proves the S2.9
// route through QIR, QRegAlloc and the emitted AsmJit bytes -- all of which are the pure-QCG
// backend. None of its checks can see whether the LLVM/AOT tier admits the route at all, and before
// S3.4 it did not: RvvQcgSetVLAdmit returned false for every `aot_use_llvm` compile and
// llvmgen.cpp Panic'd on the op, so the AOT artifact for the frozen add loop carried an opaque
// `rv32_vsetvli` helper call once per strip step.
//
// This file drives the REAL pipeline end to end and inspects the REAL generated llvm::Function:
//
//     encoded guest words
//       -> qir::CompilerGenRegionIR   (the real RV32Translator)
//       -> qir::QIRToLLVM::Run()      (the real LLVM backend)
//       -> llvm::Function, walked instruction by instruction below
//
// Nothing here runs a guest, creates a TargetMachine, runs an optimisation pipeline or emits an
// object file. NO claim about host instructions, cycles or speed is made or implied.
//
// THE SEMANTIC CLAIM, and how it is proved rather than asserted. `vl = UNSIGNED min(AVL, VLMAX)`
// is a semantic requirement: rvdbt's interpreter computes it on u32, so a SIGNED compare would
// agree on every AVL below 2^31 and return AVL -- up to 0xffffffff -- on the whole top half of the
// domain. CheckUnsignedMinSemantics does not merely look at the predicate: it takes the ACTUAL
// llvm::CmpInst::Predicate and the ACTUAL select arm order out of the emitted IR and evaluates them
// with llvm::ICmpInst::compare over eight AVL values that straddle every boundary that matters
// (0, 1, VLMAX-1, VLMAX, VLMAX+1, 0x7fffffff, 0x80000000, 0xffffffff), comparing each against the
// u32 reference. Emitting an SLT, or swapping the select's arms, fails it.
//
// SCOPE: legal immediate-vtype `vsetvli` forms accepted by the QCG setup rule, except the
// rd == x0 && rs1 == x0 keep-VL form. Both --rvv-qcg-direct-setvl and --rvv-vector-ssa are
// required. Invalid vtypes, keep-VL, and disabled routes retain the semantic helper.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
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
// Guest encodings, built from fields rather than pasted.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
// vsetvli rd, rs1, vtypei : zimm11[30:20], rs1[19:15], funct3=0b111, rd[11:7], opcode 0x57.
constexpr u32 EncodeVsetvli(u32 zimm11, u32 rd, u32 rs1)
{
	return (zimm11 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
// vsetvl rd, rs1, rs2 : funct7=0b1000000, rs2[24:20], rs1, funct3=0b111, rd, opcode 0x57.
constexpr u32 EncodeVsetvl(u32 rd, u32 rs1, u32 rs2)
{
	return (0b1000000u << 25) | (rs2 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
// vsetivli rd, uimm, vtypei : bits[31:30] = 0b11.
constexpr u32 EncodeVsetivli(u32 zimm10, u32 rd, u32 uimm)
{
	return (0b11u << 30) | (zimm10 << 20) | (uimm << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}

constexpr u32 VTYPE_E32_M1_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M1_TU_MA = Zimm11(2, 0, /*vta=*/0, 1);
constexpr u32 VTYPE_E32_M1_TA_MU = Zimm11(2, 0, 1, /*vma=*/0);
constexpr u32 VTYPE_E64_M1_TA_MA = Zimm11(/*vsew=*/3, 0, 1, 1);
constexpr u32 VTYPE_E32_M2_TA_MA = Zimm11(2, /*vlmul=*/1, 1, 1);
constexpr u32 VTYPE_E8_MF8_TA_MA = Zimm11(0, /*vlmul=*/5, 1, 1);
constexpr u32 VTYPE_E64_M8_TA_MA = Zimm11(3, /*vlmul=*/3, 1, 1);

constexpr u32 RD_A1 = 11, RS1_A0 = 10;
// The admitted instruction, with rd and rs1 DISTINCT.
constexpr u32 INSN_OK = EncodeVsetvli(VTYPE_E32_M1_TA_MA, RD_A1, RS1_A0);
// The admitted instruction with rd == rs1, which is the form the frozen S1 guest actually emits.
constexpr u32 INSN_OK_ALIASED = EncodeVsetvli(VTYPE_E32_M1_TA_MA, RS1_A0, RS1_A0);

constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VLENB = ST_VEC + (u32)offsetof(rv32::VectorState, vlenb);

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
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

struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
};

Built BuildLLVM(u32 const *words, unsigned n, u32 vlen_bits)
{
	Built b;
	config::vlen_bits = vlen_bits;
	b.arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	auto *region = CompilerGenRegionIR(b.arena.get(), job);

	b.mod = std::make_unique<llvm::Module>("s3_4_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm of the route: aot_use_llvm on, and BOTH of its switches independently settable
// so the negative matrix can turn exactly one of them off.
Built BuildRoute(u32 const *words, unsigned n, u32 vlen_bits, bool setvl = true, bool ssa = true)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_qcg_direct_setvl = setvl;
	config::rvv_vector_ssa = ssa;
	return BuildLLVM(words, n, vlen_bits);
}

// ---------------------------------------------------------------------------------------------
// IR inspection.
// ---------------------------------------------------------------------------------------------

std::vector<llvm::SelectInst *> Selects(llvm::Function *fn)
{
	std::vector<llvm::SelectInst *> out;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *s = llvm::dyn_cast<llvm::SelectInst>(&in))
				out.push_back(s);
	return out;
}

// A helper call is a call whose callee is the value MakeRStub loaded, and MakeRStub names that load
// after the stub it resolves (GetRuntimeStubName). Counting by callee NAME rather than by "any
// call" keeps unrelated calls the backend may emit out of the count.
unsigned CountStubCalls(llvm::Function *fn, char const *stub_name)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &in : bb) {
			auto *call = llvm::dyn_cast<llvm::CallInst>(&in);
			if (!call)
				continue;
			auto *callee = call->getCalledOperand();
			if (callee && callee->hasName() && callee->getName().starts_with(stub_name))
				++n;
		}
	}
	return n;
}

// Stores of a 32-bit value to CPUState + `offs`, found through the GEP the backend builds. Returns
// the stored values in program order.
std::vector<llvm::Value *> StoresToStateOffset(llvm::Function *fn, u32 offs)
{
	std::vector<llvm::Value *> out;
	for (auto &bb : *fn) {
		for (auto &in : bb) {
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&in);
			if (!st)
				continue;
			auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(st->getPointerOperand());
			if (!gep || gep->getNumIndices() != 1)
				continue;
			auto *ci = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
			if (ci && ci->getZExtValue() == offs)
				out.push_back(st->getValueOperand());
		}
	}
	return out;
}

u64 ConstOf(llvm::Value *v)
{
	auto *ci = llvm::dyn_cast<llvm::ConstantInt>(v);
	return ci ? ci->getZExtValue() : ~0ull;
}

// ---------------------------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------------------------

// Native-1's rs1 == x0 case, which has a DIFFERENT and stronger expected shape.
//
// With rs1 == x0 the architectural AVL is the constant ~0u, so `min(~0u, VLMAX)` is VLMAX at
// translation time and LLVM folds the compare and the select away. Asserting "exactly one select"
// here would fail on correct output; asserting nothing would accept a route that had quietly
// stopped writing state. So this checks the fold's RESULT instead: no select, no compare, no helper
// call, and vec.vl written with the literal VLMAX for this VLEN -- which is exactly the value the
// unfolded form would have produced, and is wrong at the other width, so the check is width-exact.
void CheckAdmittedConstAVL(char const *name, u32 insn, u32 vlen)
{
	printf("-- admitted %s VLEN=%u (constant AVL = ~0u)\n", name, vlen);
	u32 words[1] = {insn};
	auto b = BuildRoute(words, 1, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	u32 const vtype = (insn >> 20) & 0x7ffu;
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{vtype}, vlen);
	CHECK_EQ(Selects(b.fn).size(), 0u);
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vsetvli"), 0u);

	auto vtype_st = StoresToStateOffset(b.fn, ST_VTYPE);
	auto vl_st = StoresToStateOffset(b.fn, ST_VL);
	auto vstart_st = StoresToStateOffset(b.fn, ST_VSTART);
	auto vlenb_st = StoresToStateOffset(b.fn, ST_VLENB);
	CHECK_EQ(vtype_st.size(), 1u);
	CHECK_EQ(vl_st.size(), 1u);
	CHECK_EQ(vstart_st.size(), 1u);
	CHECK_EQ(vlenb_st.size(), 1u);
	if (vtype_st.size() == 1)
		CHECK_EQ(ConstOf(vtype_st[0]), (u64)vtype);
	if (vl_st.size() == 1)
		CHECK_EQ(ConstOf(vl_st[0]), (u64)vlmax); // the whole point: vl == VLMAX, folded
	if (vstart_st.size() == 1)
		CHECK_EQ(ConstOf(vstart_st[0]), 0ull);
	if (vlenb_st.size() == 1)
		CHECK_EQ(ConstOf(vlenb_st[0]), (u64)(vlen / 8u));
	printf("   AVL folded: vec.vl <- VLMAX=%u as a constant, 0 selects, 0 helper calls\n", vlmax);
}

// The admitted case: exactly one select computing the min, the four state fields written with the
// right constants, and ZERO rv32_vsetvli helper calls.
void CheckAdmitted(char const *name, u32 insn, u32 vlen)
{
	printf("-- admitted %s VLEN=%u\n", name, vlen);
	u32 words[1] = {insn};
	auto b = BuildRoute(words, 1, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	auto sels = Selects(b.fn);
	CHECK_EQ(sels.size(), 1u);
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vsetvli"), 0u);
	if (sels.size() != 1)
		return;
	auto *sel = sels[0];
	auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
	CHECK(cmp != nullptr);
	if (!cmp)
		return;

	u32 const vtype = (insn >> 20) & 0x7ffu;
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{vtype}, vlen);
	// The min's bound is the ADMITTED VLEN's VLMAX, not VLEN_MAX's -- the trap S2.5 named.
	CHECK_EQ(ConstOf(cmp->getOperand(1)), (u64)vlmax);
	CHECK_EQ(ConstOf(sel->getFalseValue()), (u64)vlmax);
	// The true arm is the AVL, i.e. the same value the compare's LHS is.
	CHECK(sel->getTrueValue() == cmp->getOperand(0));
	// UNSIGNED, and this is semantic. See CheckUnsignedMinSemantics for the domain proof.
	CHECK_EQ((int)cmp->getPredicate(), (int)llvm::CmpInst::ICMP_ULT);

	// The four architectural state writes, each with the value the node carries.
	auto vtype_st = StoresToStateOffset(b.fn, ST_VTYPE);
	auto vl_st = StoresToStateOffset(b.fn, ST_VL);
	auto vstart_st = StoresToStateOffset(b.fn, ST_VSTART);
	auto vlenb_st = StoresToStateOffset(b.fn, ST_VLENB);
	CHECK_EQ(vtype_st.size(), 1u);
	CHECK_EQ(vl_st.size(), 1u);
	CHECK_EQ(vstart_st.size(), 1u);
	CHECK_EQ(vlenb_st.size(), 1u);
	if (vtype_st.size() == 1)
		CHECK_EQ(ConstOf(vtype_st[0]), (u64)vtype);
	if (vl_st.size() == 1)
		CHECK(vl_st[0] == sel); // vec.vl is the min itself, not a re-read
	if (vstart_st.size() == 1)
		CHECK_EQ(ConstOf(vstart_st[0]), 0ull);
	if (vlenb_st.size() == 1)
		CHECK_EQ(ConstOf(vlenb_st[0]), (u64)(vlen / 8u));
	printf("   one ULT+select min against VLMAX=%u, vtype/vl/vstart/vlenb written, 0 helper calls\n",
	       vlmax);
}

// The semantic core. The predicate and the arm order are read OUT of the emitted IR and evaluated
// over the eight AVL values with LLVM's own APInt comparison, so this fails if the emitter ever
// uses a signed compare or swaps the select arms.
void CheckUnsignedMinSemantics(u32 vlen)
{
	printf("-- unsigned min over the whole AVL domain, VLEN=%u\n", vlen);
	u32 words[1] = {INSN_OK};
	auto b = BuildRoute(words, 1, vlen);
	auto sels = Selects(b.fn);
	CHECK_EQ(sels.size(), 1u);
	if (sels.size() != 1)
		return;
	auto *sel = sels[0];
	auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
	CHECK(cmp != nullptr);
	if (!cmp)
		return;
	bool const true_arm_is_avl = sel->getTrueValue() == cmp->getOperand(0);
	CHECK(true_arm_is_avl);
	u32 const vlmax = (u32)ConstOf(cmp->getOperand(1));
	CHECK_EQ((u64)vlmax, (u64)(vlen / 32u));

	u32 const avls[] = {0u, 1u, vlmax - 1u, vlmax, vlmax + 1u,
			    0x7fffffffu, 0x80000000u, 0xffffffffu};
	for (u32 avl : avls) {
		// The reference is rvdbt's own: HANDLER(vsetvli) computes this on u32.
		u32 const want = avl < vlmax ? avl : vlmax;
		// The emitted predicate and arms, evaluated exactly as written.
		bool const cond = llvm::ICmpInst::compare(llvm::APInt(32, avl), llvm::APInt(32, vlmax),
							  cmp->getPredicate());
		u32 const got = cond ? (true_arm_is_avl ? avl : vlmax) : (u32)ConstOf(sel->getFalseValue());
		if (got != want) {
			fprintf(stderr, "  FAIL AVL=0x%08x: emitted min gives %u, u32 reference is %u\n",
				avl, got, want);
			++g_failures;
		}
	}
	printf("   0, 1, VLMAX-1, VLMAX, VLMAX+1, 0x7fffffff, 0x80000000, 0xffffffff all match u32 min\n");
}

// rd == rs1. The AVL must be read before the result is stored; in SSA that is an ordering property
// of the emitted instruction list, so it is checked there.
void CheckAliasedRdRs1(u32 vlen)
{
	printf("-- rd == rs1, VLEN=%u\n", vlen);
	u32 words[1] = {INSN_OK_ALIASED};
	auto b = BuildRoute(words, 1, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	auto sels = Selects(b.fn);
	CHECK_EQ(sels.size(), 1u);
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vsetvli"), 0u);
	if (sels.size() != 1)
		return;
	auto *sel = sels[0];
	auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
	CHECK(cmp != nullptr);
	if (!cmp)
		return;
	// The AVL operand is produced strictly before the select, and the select is what every later
	// consumer (rd and vec.vl) reads. An emitter that stored rd first and then read the AVL would
	// have the AVL definition AFTER the select, which cannot happen in valid SSA -- verifyFunction
	// above is what makes that a real check rather than a restatement.
	auto *avl_def = llvm::dyn_cast<llvm::Instruction>(cmp->getOperand(0));
	if (avl_def) {
		CHECK(avl_def->comesBefore(cmp));
	}
	auto vl_st = StoresToStateOffset(b.fn, ST_VL);
	CHECK_EQ(vl_st.size(), 1u);
	if (vl_st.size() == 1)
		CHECK(vl_st[0] == sel);
	printf("   aliased form admits, AVL read precedes the result, vec.vl is the min\n");
}

// Not admitted: exactly one pre-existing helper call and no select, no state writes.
void CheckNotAdmitted(char const *name, u32 insn, u32 vlen, char const *stub, bool setvl = true,
		      bool ssa = true)
{
	u32 words[1] = {insn};
	auto b = BuildRoute(words, 1, vlen, setvl, ssa);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	unsigned const n_sel = (unsigned)Selects(b.fn).size();
	unsigned const n_stub = CountStubCalls(b.fn, stub);
	unsigned const n_vtype = (unsigned)StoresToStateOffset(b.fn, ST_VTYPE).size();
	unsigned const n_vlenb = (unsigned)StoresToStateOffset(b.fn, ST_VLENB).size();
	CHECK_EQ(n_sel, 0u);
	CHECK_EQ(n_stub, 1u);
	CHECK_EQ(n_vtype, 0u);
	CHECK_EQ(n_vlenb, 0u);
	printf("-- not admitted: %-34s VLEN=%u  selects=%u %s calls=%u state writes=%u\n", name, vlen,
	       n_sel, stub, n_stub, n_vtype + n_vlenb);
}

// W30: `vsetivli` reaches its OWN gate now, not this one. Kept in this file as a one-line boundary
// marker -- the helper call is gone and the state writes are there -- so that a regression which
// re-refused the immediate-AVL opcode fails here too and not only in the dedicated file. The
// semantic detail (uimm5 ladder, rd == x0, vill) lives in vsetivli_directstate_llvm_test.cpp.
void CheckAdmittedVsetivli(u32 insn, u32 vlen)
{
	u32 words[1] = {insn};
	auto b = BuildRoute(words, 1, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	unsigned const n_stub = CountStubCalls(b.fn, "rv32_vsetivli");
	unsigned const n_vtype = (unsigned)StoresToStateOffset(b.fn, ST_VTYPE).size();
	unsigned const n_vlenb = (unsigned)StoresToStateOffset(b.fn, ST_VLENB).size();
	CHECK_EQ(n_stub, 0u);
	CHECK_EQ(n_vtype, 1u);
	CHECK_EQ(n_vlenb, 1u);
	printf("-- admitted (W30, own gate): %-23s VLEN=%u  rv32_vsetivli calls=%u state writes=%u\n",
	       "vsetivli (immediate AVL)", vlen, n_stub, n_vtype + n_vlenb);
}

// The PRE-optimization IR, i.e. exactly what QIRToLLVM produced. elfaot's --aot-dump-llvm-ir is
// post-pipeline by construction, so this is the only place the un-optimized form is observable.
std::string PrintFn(llvm::Function *fn)
{
	std::string out;
	llvm::raw_string_ostream os(out);
	fn->print(os);
	return out;
}

void DumpIR(char const *tag, u32 insn, u32 vlen, bool setvl)
{
	u32 words[1] = {insn};
	auto b = BuildRoute(words, 1, vlen, setvl);
	printf("\n----- PRE-OPT IR %s (vlen=%u, --rvv-qcg-direct-setvl=%d) -----\n%s", tag, vlen,
	       (int)setvl, PrintFn(b.fn).c_str());
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i)
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	printf("S3.4 direct-state vsetvli, LLVM/AOT lowering\n");

	printf("\n== admitted shape ==\n");
	CheckAdmitted("rd != rs1", INSN_OK, 512);
	CheckAdmitted("rd != rs1", INSN_OK, 1024);
	CheckAdmitted("rd == rs1", INSN_OK_ALIASED, 512);
	CheckAdmitted("rd == rs1", INSN_OK_ALIASED, 1024);

	printf("\n== unsigned AVL semantics ==\n");
	CheckUnsignedMinSemantics(512);
	CheckUnsignedMinSemantics(1024);

	printf("\n== rd == rs1 ordering ==\n");
	CheckAliasedRdRs1(512);
	CheckAliasedRdRs1(1024);

	printf("\n== legal shape and refusal matrix ==\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		CheckNotAdmitted("route switch off", INSN_OK, vlen, "rv32_vsetvli", /*setvl=*/false);
		CheckNotAdmitted("vector-SSA off", INSN_OK, vlen, "rv32_vsetvli", true, /*ssa=*/false);
		CheckAdmitted("e64,m1,ta,ma", EncodeVsetvli(VTYPE_E64_M1_TA_MA, RD_A1, RS1_A0), vlen);
		CheckAdmitted("e32,m2,ta,ma", EncodeVsetvli(VTYPE_E32_M2_TA_MA, RD_A1, RS1_A0), vlen);
		CheckAdmitted("e8,mf8,ta,ma", EncodeVsetvli(VTYPE_E8_MF8_TA_MA, RD_A1, RS1_A0), vlen);
		CheckAdmitted("e64,m8,ta,ma", EncodeVsetvli(VTYPE_E64_M8_TA_MA, RD_A1, RS1_A0), vlen);
		CheckAdmitted("e32,m1,tu,ma", EncodeVsetvli(VTYPE_E32_M1_TU_MA, RD_A1, RS1_A0), vlen);
		CheckAdmitted("e32,m1,ta,mu", EncodeVsetvli(VTYPE_E32_M1_TA_MU, RD_A1, RS1_A0), vlen);
		CheckNotAdmitted("reserved vtype", EncodeVsetvli(VTYPE_E32_M1_TA_MA | 0x100u,
				 RD_A1, RS1_A0), vlen, "rv32_vsetvli");
		// Native-1: each x0 on its own is now ADMITTED on the LLVM arm too, and only the
		// conjunction is refused. Checked as admitted here, in the same sweep that refuses
		// the third, so the boundary is one readable block rather than two distant claims.
		CheckAdmitted("rd == x0 (Native-1)", EncodeVsetvli(VTYPE_E32_M1_TA_MA, 0, RS1_A0),
			      vlen);
		CheckAdmittedConstAVL("rs1 == x0 (Native-1)",
				      EncodeVsetvli(VTYPE_E32_M1_TA_MA, RD_A1, 0), vlen);
		CheckNotAdmitted("rd == x0 && rs1 == x0 (reserved keep-vl)",
				 EncodeVsetvli(VTYPE_E32_M1_TA_MA, 0, 0), vlen, "rv32_vsetvli");
		CheckNotAdmitted("vsetvl (vtype from a GPR)", EncodeVsetvl(RD_A1, RS1_A0, 12), vlen,
				 "rv32_vsetvl");
		// W30 (2026-09-21) FLIPPED THIS ROW, and it is the only assertion in this file that
		// moved. `vsetivli` now has its own LLVM/AOT gate (RvvLLVMSetIVLIAdmit), so the
		// correct claim here is no longer "refused" but "handled by the OTHER opcode's gate,
		// and therefore not by this file's". What this file still owns is that the register
		// form's own rules did not leak: the keep-VL row above stays refused. The admitted
		// shape, the uimm5 semantics and the vill boundary of `vsetivli` are proved in
		// qmc/llvmgen/vsetivli_directstate_llvm_test.cpp; asserting them again here would be
		// two copies of one rule.
		CheckAdmittedVsetivli(EncodeVsetivli(VTYPE_E32_M1_TA_MA, RD_A1, 4), vlen);
	}

	printf("\n== smaller legal VLENs ==\n");
	CheckAdmitted("VLEN=256", INSN_OK, 256);
	CheckAdmitted("VLEN=128", INSN_OK, 128);

	if (dump_ir) {
		DumpIR("route-on rd!=rs1", INSN_OK, 512, true);
		DumpIR("route-on rd!=rs1", INSN_OK, 1024, true);
		DumpIR("route-on rd==rs1", INSN_OK_ALIASED, 512, true);
		DumpIR("route-on rd==rs1", INSN_OK_ALIASED, 1024, true);
		DumpIR("route-off", INSN_OK, 512, false);
		DumpIR("route-off", INSN_OK, 1024, false);
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
