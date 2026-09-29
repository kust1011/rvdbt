// W30: focused test for the direct-state `vsetivli` route as lowered by the LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, AND WHY IT IS A DIFFERENT FILE FROM THE vsetvli ONE. S3.4 gave the
// LLVM/AOT backend a lowering for `rvvsetvl` and fed it from `vsetvli` only. `vsetivli` is a
// different Op in rv32_decode.h (bits 31:30 == 0b11), so it never reached that gate, and its own
// gate RvvQcgSetIVLIAdmit refuses every `aot_use_llvm` compile by construction -- which is why
// vsetvli_directstate_llvm_test.cpp used to assert, correctly for its day, that `vsetivli` was NOT
// admitted. W30 adds RvvLLVMSetIVLIAdmit and this file is the evidence for it; the sibling file's
// row was flipped from "not admitted" to "admitted" in the same change.
//
// Same layer and same discipline as the sibling: the REAL pipeline, end to end, inspected in
// memory.
//
//     encoded guest words
//       -> qir::CompilerGenRegionIR   (the real RV32Translator)
//       -> qir::QIRToLLVM::Run()      (the real LLVM backend)
//       -> llvm::Function, walked instruction by instruction below
//
// Nothing here runs a guest, creates a TargetMachine, runs an optimisation pipeline or emits an
// object file. NO claim about host instructions, cycles or speed is made or implied.
//
// THE SEMANTIC CLAIM AND HOW EACH PART IS FALSIFIABLE.
//
//   AVL IS uimm5, NOT A GPR. `vsetivli`'s bits 19:15 are a zero-extended 5-bit immediate; in
//   `vsetvli` the same five bits are rs1. An implementation that copied the vsetvli arm would read
//   x[uimm5] instead. CheckAdmitted fails such an implementation twice over: `vec.vl` would not be
//   a ConstantInt at all (so the exact-value check fails), and LoadsFromStateOffset asserts ZERO
//   loads from the CPUState slot of x[uimm5] -- with uimm5 = 10 chosen so that slot is a real,
//   distinct guest register.
//
//   vl = UNSIGNED min(uimm5, VLMAX), evaluated as a constant. Because the AVL is a constant, LLVM
//   folds the emitter's compare+select at construction, so there is no ICmp/Select left to read the
//   predicate out of (that is the vsetvli test's job, on the register form). What survives IS the
//   answer, so CheckUimm5Ladder drives a ladder of uimm5 values straddling VLMAX -- 0, 1, VLMAX-1,
//   VLMAX, VLMAX+1, 31 -- at vtypes and VLENs chosen so VLMAX lands INSIDE the 0..31 uimm5 domain
//   (e64,m1 gives VLMAX 2 at VLEN 128) and also ABOVE it (e32,m1 gives VLMAX 64 at VLEN 2048), and
//   compares the emitted constant against HANDLER(vsetivli)'s own u32 expression. A saturating bug
//   and a non-saturating bug each fail on one side of that pair.
//
//   rd == x0 WRITES NO GUEST REGISTER but still writes all four vec fields. CheckAdmittedRdX0
//   asserts both halves; an emitter that skipped the vec writes, or that wrote x0's slot, fails.
//
//   AN ILLEGAL vtypei KEEPS THE HELPER. That is this change's entire vill story: the route is not
//   widened to the vill write set (rd <- 0, vl <- 0, vtype <- VILL, vlenb untouched), so an
//   unsupported vtypei must still produce exactly one rv32_vsetivli call and zero state writes.
//
// SCOPE: legal immediate-vtype `vsetivli` forms, at every VLEN the node can represent. Both
// --rvv-qcg-direct-setvl and --rvv-vector-ssa are required. Illegal vtypes, unrepresentable VLENs
// and disabled routes retain the semantic helper. No other instruction family is touched, which the
// last block checks directly.

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

constexpr u32 Zimm(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
// vsetivli rd, uimm, vtypei : bits[31:30]=0b11, zimm10[29:20], uimm5[19:15], funct3=0b111,
// rd[11:7], opcode 0x57.
constexpr u32 EncodeVsetivli(u32 zimm10, u32 rd, u32 uimm5)
{
	return (0b11u << 30) | (zimm10 << 20) | (uimm5 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
// vsetvli rd, rs1, vtypei : zimm11[30:20], rs1[19:15], funct3=0b111, rd[11:7], opcode 0x57.
constexpr u32 EncodeVsetvli(u32 zimm11, u32 rd, u32 rs1)
{
	return (zimm11 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
// vsetvl rd, rs1, rs2 : funct7=0b1000000 -- vtype from a GPR, a different Op entirely.
constexpr u32 EncodeVsetvl(u32 rd, u32 rs1, u32 rs2)
{
	return (0b1000000u << 25) | (rs2 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}

constexpr u32 VTYPE_E32_M1_TA_MA = Zimm(/*vsew=*/2, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M1_TU_MA = Zimm(2, 0, /*vta=*/0, 1);
constexpr u32 VTYPE_E32_M1_TA_MU = Zimm(2, 0, 1, /*vma=*/0);
constexpr u32 VTYPE_E64_M1_TA_MA = Zimm(/*vsew=*/3, 0, 1, 1);
constexpr u32 VTYPE_E32_M2_TA_MA = Zimm(2, /*vlmul=*/1, 1, 1);
constexpr u32 VTYPE_E8_MF8_TA_MA = Zimm(0, /*vlmul=*/5, 1, 1);
constexpr u32 VTYPE_E64_M8_TA_MA = Zimm(3, /*vlmul=*/3, 1, 1);
// vlmul == 0b100 is the reserved encoding; vtype_supported() rejects it at every VLEN.
constexpr u32 VTYPE_RESERVED_LMUL = Zimm(2, /*vlmul=*/4, 1, 1);
// SEW 128 (vsew == 4) is not an encoding vtype_supported() accepts either.
constexpr u32 VTYPE_RESERVED_SEW = Zimm(/*vsew=*/4, 0, 1, 1);

constexpr u32 RD_A1 = 11;
// uimm5 = 10. Deliberately a value that is ALSO a legal register number, so "did it read x10?" is a
// question with a distinguishable answer (see LoadsFromStateOffset in CheckAdmitted).
constexpr u32 UIMM_10 = 10;
constexpr u32 INSN_OK = EncodeVsetivli(VTYPE_E32_M1_TA_MA, RD_A1, UIMM_10);

constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);
constexpr u32 ST_VSTART = ST_VEC + (u32)offsetof(rv32::VectorState, vstart);
constexpr u32 ST_VLENB = ST_VEC + (u32)offsetof(rv32::VectorState, vlenb);
constexpr u32 ST_GPR(u32 r) { return (u32)offsetof(CPUState, gpr) + 4u * r; }

// The architectural reference, restated from HANDLER(vsetivli) rather than from the emitter.
u32 RefVl(u32 vtypei, u32 uimm5, u32 vlen)
{
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{vtypei}, vlen);
	return uimm5 < vlmax ? uimm5 : vlmax;
}

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

	b.mod = std::make_unique<llvm::Module>("w30_test", g_llvm_ctx);
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

// The GEP shape QIRToLLVM::MakeStateEP builds: one constant index off the state pointer.
bool IsStateEP(llvm::Value *p, u32 offs)
{
	auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	if (!gep || gep->getNumIndices() != 1)
		return false;
	auto *ci = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
	return ci && ci->getZExtValue() == offs;
}

std::vector<llvm::Value *> StoresToStateOffset(llvm::Function *fn, u32 offs)
{
	std::vector<llvm::Value *> out;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&in))
				if (IsStateEP(st->getPointerOperand(), offs))
					out.push_back(st->getValueOperand());
	return out;
}

unsigned LoadsFromStateOffset(llvm::Function *fn, u32 offs)
{
	unsigned n = 0;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&in))
				if (IsStateEP(ld->getPointerOperand(), offs))
					++n;
	return n;
}

std::vector<llvm::SelectInst *> Selects(llvm::Function *fn)
{
	std::vector<llvm::SelectInst *> out;
	for (auto &bb : *fn)
		for (auto &in : bb)
			if (auto *s = llvm::dyn_cast<llvm::SelectInst>(&in))
				out.push_back(s);
	return out;
}

// ~0ull means "not a constant", which every caller treats as a failure rather than as a value.
u64 ConstOf(llvm::Value *v)
{
	auto *ci = llvm::dyn_cast<llvm::ConstantInt>(v);
	return ci ? ci->getZExtValue() : ~0ull;
}

// ---------------------------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------------------------

// The admitted case with rd != x0. Because the AVL is a CONSTANT, the emitter's ULT+select folds at
// construction, so the shape to assert is the fold's result: no helper call, the four vec fields
// written with the architectural constants, and the guest rd global written with the same vl.
void CheckAdmitted(char const *name, u32 vtypei, u32 uimm5, u32 vlen)
{
	u32 words[1] = {EncodeVsetivli(vtypei, RD_A1, uimm5)};
	auto b = BuildRoute(words, 1, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	u32 const want_vl = RefVl(vtypei, uimm5, vlen);
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vsetivli"), 0u);
	// A constant AVL leaves nothing to select between; a non-folded select here would mean the
	// AVL reached the emitter as a runtime value, which for this opcode is already wrong.
	CHECK_EQ(Selects(b.fn).size(), 0u);

	auto vtype_st = StoresToStateOffset(b.fn, ST_VTYPE);
	auto vl_st = StoresToStateOffset(b.fn, ST_VL);
	auto vstart_st = StoresToStateOffset(b.fn, ST_VSTART);
	auto vlenb_st = StoresToStateOffset(b.fn, ST_VLENB);
	auto rd_st = StoresToStateOffset(b.fn, ST_GPR(RD_A1));
	CHECK_EQ(vtype_st.size(), 1u);
	CHECK_EQ(vl_st.size(), 1u);
	CHECK_EQ(vstart_st.size(), 1u);
	CHECK_EQ(vlenb_st.size(), 1u);
	CHECK_EQ(rd_st.size(), 1u);
	if (vtype_st.size() == 1)
		CHECK_EQ(ConstOf(vtype_st[0]), (u64)vtypei);
	if (vl_st.size() == 1)
		CHECK_EQ(ConstOf(vl_st[0]), (u64)want_vl);
	if (vstart_st.size() == 1)
		CHECK_EQ(ConstOf(vstart_st[0]), 0ull);
	if (vlenb_st.size() == 1)
		CHECK_EQ(ConstOf(vlenb_st[0]), (u64)(vlen / 8u));
	if (rd_st.size() == 1)
		CHECK_EQ(ConstOf(rd_st[0]), (u64)want_vl);

	// THE uimm5-IS-NOT-rs1 CHECK. bits 19:15 hold `uimm5`; in vsetvli they hold rs1. An arm that
	// reused the vsetvli operand rule would emit a load of x[uimm5] here.
	CHECK_EQ(LoadsFromStateOffset(b.fn, ST_GPR(uimm5)), 0u);

	printf("-- admitted %-18s VLEN=%-5u uimm5=%-2u  vl=%-3u vtype/vl/vstart/vlenb+rd written, "
	       "0 helper calls, 0 loads of x%u\n",
	       name, vlen, uimm5, want_vl, uimm5);
}

// rd == x0: the four vec writes still happen, and NO guest register is written. x0 is not a tracked
// global, so "wrote x0's slot" would show up as a store to ST_GPR(0).
void CheckAdmittedRdX0(u32 vtypei, u32 uimm5, u32 vlen)
{
	u32 words[1] = {EncodeVsetivli(vtypei, /*rd=*/0, uimm5)};
	auto b = BuildRoute(words, 1, vlen);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	u32 const want_vl = RefVl(vtypei, uimm5, vlen);
	CHECK_EQ(CountStubCalls(b.fn, "rv32_vsetivli"), 0u);
	auto vtype_st = StoresToStateOffset(b.fn, ST_VTYPE);
	auto vl_st = StoresToStateOffset(b.fn, ST_VL);
	auto vstart_st = StoresToStateOffset(b.fn, ST_VSTART);
	auto vlenb_st = StoresToStateOffset(b.fn, ST_VLENB);
	CHECK_EQ(vtype_st.size(), 1u);
	CHECK_EQ(vl_st.size(), 1u);
	CHECK_EQ(vstart_st.size(), 1u);
	CHECK_EQ(vlenb_st.size(), 1u);
	if (vl_st.size() == 1)
		CHECK_EQ(ConstOf(vl_st[0]), (u64)want_vl);
	if (vlenb_st.size() == 1)
		CHECK_EQ(ConstOf(vlenb_st[0]), (u64)(vlen / 8u));
	// No architectural register write, for any r -- x0 included.
	for (u32 r = 0; r < 32; ++r)
		CHECK_EQ(StoresToStateOffset(b.fn, ST_GPR(r)).size(), 0u);
	printf("-- admitted rd == x0        VLEN=%-5u uimm5=%-2u  vl=%-3u four vec writes, "
	       "no guest register written\n",
	       vlen, uimm5, want_vl);
}

// The semantic core: `vl = min(uimm5, VLMAX)` over a ladder that straddles VLMAX on BOTH sides of
// the uimm5 domain. The caller picks (vtype, VLEN) so VLMAX is inside 0..31 for one case and above
// it for the other; a saturating and a non-saturating defect each fail on one of the two.
void CheckUimm5Ladder(char const *name, u32 vtypei, u32 vlen)
{
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{vtypei}, vlen);
	printf("-- uimm5 ladder %-14s VLEN=%-5u VLMAX=%u\n", name, vlen, vlmax);
	u32 ladder[6] = {0u, 1u, vlmax ? vlmax - 1u : 0u, vlmax, vlmax + 1u, 31u};
	for (u32 avl : ladder) {
		if (avl > 31u) // outside the 5-bit field; not an encodable AVL for this opcode
			continue;
		u32 words[1] = {EncodeVsetivli(vtypei, RD_A1, avl)};
		auto b = BuildRoute(words, 1, vlen);
		CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
		auto vl_st = StoresToStateOffset(b.fn, ST_VL);
		CHECK_EQ(vl_st.size(), 1u);
		CHECK_EQ(CountStubCalls(b.fn, "rv32_vsetivli"), 0u);
		if (vl_st.size() != 1)
			continue;
		u64 const got = ConstOf(vl_st[0]);
		u64 const want = RefVl(vtypei, avl, vlen);
		if (got != want) {
			fprintf(stderr, "  FAIL uimm5=%u: emitted vl=%llu, HANDLER(vsetivli) gives %llu\n",
				avl, (unsigned long long)got, (unsigned long long)want);
			++g_failures;
		}
	}
	printf("   0, 1, VLMAX-1, VLMAX, VLMAX+1, 31 (those that fit uimm5) all match the u32 reference\n");
}

// Not admitted: exactly one pre-existing helper call, no state writes.
void CheckNotAdmitted(char const *name, u32 insn, u32 vlen, char const *stub, bool setvl = true,
		      bool ssa = true)
{
	u32 words[1] = {insn};
	auto b = BuildRoute(words, 1, vlen, setvl, ssa);
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));
	unsigned const n_stub = CountStubCalls(b.fn, stub);
	unsigned const n_vtype = (unsigned)StoresToStateOffset(b.fn, ST_VTYPE).size();
	unsigned const n_vl = (unsigned)StoresToStateOffset(b.fn, ST_VL).size();
	unsigned const n_vlenb = (unsigned)StoresToStateOffset(b.fn, ST_VLENB).size();
	CHECK_EQ(n_stub, 1u);
	CHECK_EQ(n_vtype, 0u);
	CHECK_EQ(n_vl, 0u);
	CHECK_EQ(n_vlenb, 0u);
	printf("-- not admitted: %-38s VLEN=%-5u %s calls=%u state writes=%u\n", name, vlen, stub,
	       n_stub, n_vtype + n_vl + n_vlenb);
}

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
	printf("W30 direct-state vsetivli, LLVM/AOT lowering\n");

	// EVERY SUPPORTED VLEN, including 2048, which is where the audit measured the loss.
	u32 const kVlens[] = {128u, 256u, 512u, 1024u, 2048u};

	printf("\n== admitted shape, every supported VLEN ==\n");
	for (u32 vlen : kVlens) {
		CheckAdmitted("e32,m1,ta,ma", VTYPE_E32_M1_TA_MA, UIMM_10, vlen);
		CheckAdmitted("e64,m1,ta,ma", VTYPE_E64_M1_TA_MA, UIMM_10, vlen);
		CheckAdmitted("e32,m2,ta,ma", VTYPE_E32_M2_TA_MA, UIMM_10, vlen);
		CheckAdmitted("e8,mf8,ta,ma", VTYPE_E8_MF8_TA_MA, UIMM_10, vlen);
		CheckAdmitted("e64,m8,ta,ma", VTYPE_E64_M8_TA_MA, UIMM_10, vlen);
		CheckAdmitted("e32,m1,tu,ma", VTYPE_E32_M1_TU_MA, UIMM_10, vlen);
		CheckAdmitted("e32,m1,ta,mu", VTYPE_E32_M1_TA_MU, UIMM_10, vlen);
	}

	printf("\n== vl = min(uimm5, VLMAX), both sides of the uimm5 domain ==\n");
	// VLMAX inside 0..31: e64,m1 gives 2 at VLEN 128 and 4 at VLEN 256, so the ladder really
	// saturates. VLMAX above 31: e32,m1 gives 64 at VLEN 2048, so nothing saturates and the
	// emitted vl must track uimm5 exactly.
	CheckUimm5Ladder("e64,m1", VTYPE_E64_M1_TA_MA, 128);
	CheckUimm5Ladder("e64,m1", VTYPE_E64_M1_TA_MA, 256);
	CheckUimm5Ladder("e32,m1", VTYPE_E32_M1_TA_MA, 512);
	CheckUimm5Ladder("e32,m1", VTYPE_E32_M1_TA_MA, 2048);
	CheckUimm5Ladder("e8,mf8", VTYPE_E8_MF8_TA_MA, 128); // VLMAX = 2, the narrowest legal group

	printf("\n== rd == x0 ==\n");
	for (u32 vlen : kVlens)
		CheckAdmittedRdX0(VTYPE_E32_M1_TA_MA, UIMM_10, vlen);
	// The form the vsetvli gate must NOT be reused for: rd == x0 AND the 19:15 field == 0. For
	// vsetvli that pair is the reserved keep-VL encoding; for vsetivli it is `vsetivli x0, 0`,
	// which is legal and must lower.
	CheckAdmittedRdX0(VTYPE_E32_M1_TA_MA, /*uimm5=*/0, 512);
	CheckAdmittedRdX0(VTYPE_E32_M1_TA_MA, /*uimm5=*/0, 2048);

	printf("\n== refusal matrix ==\n");
	for (u32 vlen : kVlens) {
		CheckNotAdmitted("route switch off", INSN_OK, vlen, "rv32_vsetivli", /*setvl=*/false);
		CheckNotAdmitted("vector-SSA off", INSN_OK, vlen, "rv32_vsetivli", true, /*ssa=*/false);
		// vill stays with the helper: this change does not widen the route to the illegal-vtype
		// write set (rd <- 0, vl <- 0, vtype <- VILL).
		CheckNotAdmitted("reserved LMUL (vill -> helper)",
				 EncodeVsetivli(VTYPE_RESERVED_LMUL, RD_A1, UIMM_10), vlen,
				 "rv32_vsetivli");
		CheckNotAdmitted("reserved SEW (vill -> helper)",
				 EncodeVsetivli(VTYPE_RESERVED_SEW, RD_A1, UIMM_10), vlen,
				 "rv32_vsetivli");
	}
	// SEW > LMUL*ELEN is the spec's fractional-LMUL rule; vtype_supported refuses it, so it is a
	// vill case too. e64,mf2 needs SEW <= LMUL*64 = 32.
	CheckNotAdmitted("e64,mf2 (SEW > LMUL*ELEN)",
			 EncodeVsetivli(Zimm(/*vsew=*/3, /*vlmul=*/7, 1, 1), RD_A1, UIMM_10), 512,
			 "rv32_vsetivli");

	printf("\n== VLENs the node cannot represent keep the helper (no translation Panic) ==\n");
	// vlenb must be a power of two in [16, MAX_REG_CHUNKS*64]. 768/8 = 96 is not; 8192/8 = 1024
	// is past the storage reservation. Both must refuse in the gate, not abort in the emitter.
	CheckNotAdmitted("VLEN=768 (vlenb not a power of two)", INSN_OK, 768, "rv32_vsetivli");
	CheckNotAdmitted("VLEN=8192 (past the reservation)", INSN_OK, 8192, "rv32_vsetivli");

	printf("\n== no other family moved ==\n");
	for (u32 vlen : {512u, 2048u}) {
		// vsetvl takes its vtype from a GPR and is a different Op; it must still be a helper.
		CheckNotAdmitted("vsetvl (vtype from a GPR)", EncodeVsetvl(RD_A1, 10, 12), vlen,
				 "rv32_vsetvl");
		// vsetvli's own reserved keep-VL form must still be refused -- W30 must not have
		// leaked the immediate-AVL shape row into the register-form gate.
		CheckNotAdmitted("vsetvli keep-VL (rd==x0 && rs1==x0)",
				 EncodeVsetvli(VTYPE_E32_M1_TA_MA, 0, 0), vlen, "rv32_vsetvli");
	}

	if (dump_ir) {
		DumpIR("route-on rd!=x0", INSN_OK, 512, true);
		DumpIR("route-on rd!=x0", INSN_OK, 2048, true);
		DumpIR("route-on rd==x0", EncodeVsetivli(VTYPE_E32_M1_TA_MA, 0, UIMM_10), 512, true);
		DumpIR("route-off", INSN_OK, 512, false);
	}

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures != 0;
}
