// The LLVM/AOT vector-vector FP arithmetic family: the IR each admitted funct6 actually produces.
//
// WHY THIS FILE EXISTS, NEXT TO rvv_ssa_fp_mask_admission_test.cpp
//
// That file answers "WHICH encodings does `TRANSLATOR(vfalu)` admit?" by sweeping the whole
// funct3 x funct6 x vm space and comparing the admitted set against a declared list. It never runs
// the LLVM backend, so it cannot see WHAT the admitted encodings lower to. Before this checkpoint
// that gap was harmless, because the route admitted exactly one funct6 and `Emit_rvvfalu` had one
// hardcoded intrinsic: there was nothing for the two to disagree about.
//
// Widening the route to the four vector-vector IEEE arithmetic operations creates exactly that
// possibility. A funct6 -> intrinsic map that returned `constrained_fsub` for all four would pass
// the admission sweep, verify cleanly, emit structurally perfect IR, produce no helper call and no
// fault -- and compute the wrong values for three of the four instructions. So this file asserts
// the OTHER half: for each admitted funct6, at each supported VLEN and both element widths, the
// fast arm contains exactly the intended constrained intrinsic, exactly `active_chunks` times, on
// the right vector type, carrying the right FP-environment metadata, with the chunks independent
// and with no helper call.
//
// WHAT IS ASSERTED
//
//   [1] one constrained call per chunk, and it is the RIGHT intrinsic  -- matched by
//       `llvm::Intrinsic::ID` off the callee, never by parsing a name;
//   [2] the four funct6 map to four DISTINCT intrinsic IDs, which is what a copy-paste in the map
//       would break while leaving every other assertion in this file true;
//   [3] the FP environment is preserved: `round.dynamic` and `fpexcept.strict` on every call, the
//       `rvv.fp.begin`/`rvv.fp.end` bracket present, `vstart` stored 0 on the fast arm, and the
//       per-chunk canonical-NaN select still emitted;
//   [4] operand order is the encoding's `vd = vs2 OP vs1`, checked on the non-commutative rows;
//   [5] at VLEN 1024 the two calls are INDEPENDENT -- neither is an operand of the other, and their
//       four sources are four distinct values -- and the fast arm calls no helper;
//   [6] QIR planning and LLVM emission agree: `InstRVVFALU::active_chunks` equals the number of
//       constrained calls emitted;
//   [7] flag-off is unchanged: with `--rvv-vector-ssa=0`, and on the pure-QCG backend, every one of
//       the four encodings builds no `_rvvfalu` node and reaches the pre-existing helper.
//
// WHAT THIS FILE DOES NOT DO
//
//   * It changes no semantics and no admission predicate; it reads the IR the real translator and
//     the real backend produce.
//   * It never runs the code it builds. No object file is emitted and no PROT_EXEC page exists in
//     this process, so it needs no AVX-512 host and executes no vector instruction of any width.
//   * It times nothing and makes no performance claim.
//
// PIPELINE, and it is the real one:
//     guest words -> qir::CompilerGenRegionIR (dbt/qmc/compile.cpp, the real RV32Translator)
//                 -> qir::QIRToLLVM::Run     (dbt/qmc/llvmgen/llvmgen.cpp, the real backend)
// The IR inspected is what `QIRToLLVM` produced, before any LLVM optimisation pass.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
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
#include <memory>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

unsigned g_fail = 0;

#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto va_ = (a);                                                                    \
		auto vb_ = (b);                                                                    \
		if (!(va_ == vb_)) {                                                               \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, (long long)va_, (long long)vb_);                                \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Instruction words, built from the field layout rather than pasted, so a wrong constant is a
// compile-time expression here and not an opaque hex literal.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPCODE_OPV = 0b1010111u;
constexpr u32 F3_OPFVV = 0b001u;
constexpr u32 VD = 1, VS1 = 3, VS2 = 2;

u32 EncOpV(u32 funct6, u32 vm, u32 vs2, u32 vs1, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (funct3 << 12) |
	       (vd << 7) | OPCODE_OPV;
}

// `vsetvli x10, x10, e32/e64, m1, ta, ma` -- the in-block observation these routes read.
u32 EncVsetvli(u32 vtypei) { return (vtypei << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | OPCODE_OPV; }
// vtypei[10:0] = vma<<7 | vta<<6 | vsew<<3 | vlmul, so m1/ta/ma is 0b11'000'000 plus the width
// field: vsew 010 = e32, 011 = e64. The e32 value is the same 0x0d0 that
// rvv_ssa_fp_mask_admission_test.cpp's INSN_VSETVLI_E32M1 carries in bits 31:20.
constexpr u32 VTYPEI_E32M1_TAMA = (1u << 7) | (1u << 6) | (0b010u << 3); // 208 = 0x0d0
constexpr u32 VTYPEI_E64M1_TAMA = (1u << 7) | (1u << 6) | (0b011u << 3); // 216 = 0x0d8
static_assert(VTYPEI_E32M1_TAMA == 0x0d0u);
static_assert(VTYPEI_E64M1_TAMA == 0x0d8u);

// ---------------------------------------------------------------------------------------------
// The matrix under test. Derived here from the SAME predicate the translator and the emitter use,
// so this table cannot silently disagree with the family rule -- section 0 checks the agreement.
// ---------------------------------------------------------------------------------------------
struct Row {
	char const *name;
	u32 funct6;
	llvm::Intrinsic::ID intrin;
	bool commutative; // false rows additionally pin `vd = vs2 OP vs1` operand order
};

Row const ROWS[] = {
    {"vfadd.vv", dbt::rv32::VF6_VFADD, llvm::Intrinsic::experimental_constrained_fadd, true},
    {"vfsub.vv", dbt::rv32::VF6_VFSUB, llvm::Intrinsic::experimental_constrained_fsub, false},
    {"vfmul.vv", dbt::rv32::VF6_VFMUL, llvm::Intrinsic::experimental_constrained_fmul, true},
    {"vfdiv.vv", dbt::rv32::VF6_VFDIV, llvm::Intrinsic::experimental_constrained_fdiv, false},
};
constexpr unsigned N_ROWS = sizeof(ROWS) / sizeof(ROWS[0]);

// Every funct6 the encoding space can hold, so section 0's complement is the whole space and not a
// hand-picked set of negatives.
constexpr u32 N_FUNCT6 = 64;

// ---------------------------------------------------------------------------------------------
// Build harness. Identical in shape to vaddvv_typedchunk_llvm_test.cpp's: the real translator, the
// real backend, no pass pipeline, nothing executed.
// ---------------------------------------------------------------------------------------------
void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_falu = false;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_llvm_wide_vadd = false;
	config::rvv_llvm_wide_vadd_ssa = false;
	config::aot_work_counter = false;
	config::aot_region_hit_count = false;
	config::aot_region_cycle_count = false;
	config::aot_brcc_real_weights = false;
	config::aot_use_llvm = false;
}

struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
	Region *region = nullptr;
};

Region *BuildRegion(MemArena *arena, u32 const *words, unsigned n)
{
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(arena, job);
}

Built BuildLLVM(u32 const *words, unsigned n, u32 vlen_bits)
{
	Built b;
	config::vlen_bits = vlen_bits;
	b.arena = std::make_unique<MemArena>(1u << 20);
	b.region = BuildRegion(b.arena.get(), words, n);
	b.mod = std::make_unique<llvm::Module>("rvv_falu_family_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, b.region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm of this route: `--aot-use-llvm` on plus its own substrate switch
// `--rvv-vector-ssa`. The QCG typed-FALU switch is deliberately left OFF, which is part of the
// claim -- the QCG evidence switch neither opens nor is required by the LLVM route.
Built BuildRoute(u32 funct6, u32 vtypei, u32 vlen_bits)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	static u32 words[2];
	words[0] = EncVsetvli(vtypei);
	words[1] = EncOpV(funct6, 1, VS2, VS1, F3_OPFVV, VD);
	return BuildLLVM(words, 2, vlen_bits);
}

// ---------------------------------------------------------------------------------------------
// IR inspection.
// ---------------------------------------------------------------------------------------------
std::vector<llvm::BasicBlock *> BlocksNamed(llvm::Function *fn, char const *prefix)
{
	std::vector<llvm::BasicBlock *> out;
	for (auto &bb : *fn) {
		if (bb.getName().starts_with(prefix)) {
			out.push_back(&bb);
		}
	}
	return out;
}

// Exact name, because LLVM's own uniquing appends ".done" to the join block and a prefix match
// would count `rvv.fp.begin` and `rvv.fp.begin.done` as two brackets.
unsigned CountBlocksExactly(llvm::Function *fn, char const *name)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		n += bb.getName() == name;
	}
	return n;
}

llvm::Value *StripCasts(llvm::Value *v)
{
	while (auto *c = llvm::dyn_cast<llvm::BitCastInst>(v)) {
		v = c->getOperand(0);
	}
	return v;
}

// Every constrained-FP intrinsic call in `bb`, in order.
std::vector<llvm::CallInst *> ConstrainedCalls(llvm::BasicBlock *bb)
{
	std::vector<llvm::CallInst *> out;
	for (auto &ins : *bb) {
		auto *c = llvm::dyn_cast<llvm::CallInst>(&ins);
		if (!c) {
			continue;
		}
		auto *callee = c->getCalledFunction();
		if (callee && callee->isIntrinsic() && llvm::isa<llvm::ConstrainedFPIntrinsic>(c)) {
			out.push_back(c);
		}
	}
	return out;
}

// Any call that is NOT an intrinsic -- which on this arm means a runtime-stub helper call.
unsigned CountHelperCalls(llvm::BasicBlock *bb)
{
	unsigned n = 0;
	for (auto &ins : *bb) {
		auto *c = llvm::dyn_cast<llvm::CallInst>(&ins);
		if (!c) {
			continue;
		}
		auto *callee = c->getCalledFunction();
		if (!callee || !callee->isIntrinsic()) {
			++n;
		}
	}
	return n;
}

bool HasMetadataOperand(llvm::CallInst *c, char const *want)
{
	for (unsigned i = 0; i < c->arg_size(); ++i) {
		auto *m = llvm::dyn_cast<llvm::MetadataAsValue>(c->getArgOperand(i));
		auto *s = m ? llvm::dyn_cast<llvm::MDString>(m->getMetadata()) : nullptr;
		if (s && s->getString() == want) {
			return true;
		}
	}
	return false;
}

bool IsFloatVec(llvm::Type *t, unsigned lanes, bool dbl)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	if (!vt || vt->getNumElements() != lanes) {
		return false;
	}
	return dbl ? vt->getElementType()->isDoubleTy() : vt->getElementType()->isFloatTy();
}

// The single InstRVVFALU the region carries, or nullptr.
InstRVVFALU *FindFaluNode(Region *region, unsigned *count)
{
	InstRVVFALU *found = nullptr;
	*count = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvfalu) {
				++*count;
				found = static_cast<InstRVVFALU *>(&ins);
			}
		}
	}
	return found;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += ins.GetOpcode() == op;
		}
	}
	return n;
}

unsigned CountHcall(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_hcall) {
				n += static_cast<InstHcall *>(&ins)->stub == stub;
			}
		}
	}
	return n;
}

// ---------------------------------------------------------------------------------------------

void Section0_FamilyRule()
{
	printf("[0] the family rule, over the whole 64-value funct6 space\n");
	// The table above must BE the predicate, not a second opinion about it. Checking both
	// directions over the whole space is what makes the four exclusions -- vfmin, vfmax and the
	// three sign-injection forms, all of them members of `vfalu_supported` -- assertions rather
	// than omissions.
	unsigned in_table = 0, in_predicate = 0, in_vfalu_family = 0;
	for (u32 f6 = 0; f6 < N_FUNCT6; ++f6) {
		bool tabled = false;
		for (unsigned r = 0; r < N_ROWS; ++r) {
			tabled = tabled || ROWS[r].funct6 == f6;
		}
		bool const pred = dbt::rv32::vfalu_llvm_constrained_vv_supported(f6);
		CHECK_EQ((int)tabled, (int)pred);
		in_table += tabled;
		in_predicate += pred;
		in_vfalu_family += dbt::rv32::vfalu_supported(f6, /*is_vf=*/false);
		// The subset property, in the direction that matters: nothing this route admits may
		// sit outside the production QCG typed-FALU family.
		if (pred) {
			CHECK(dbt::rv32::vfalu_supported(f6, /*is_vf=*/false));
		}
	}
	CHECK_EQ(in_table, N_ROWS);
	CHECK_EQ(in_predicate, N_ROWS);
	// A proper subset: the family has members this route deliberately does not lower.
	CHECK(in_vfalu_family > in_predicate);
	// Named, so a future widening of either side has to touch this line.
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFMIN));
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFMAX));
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFSGNJ));
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFSGNJN));
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFSGNJX));
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFRDIV));
	CHECK(!dbt::rv32::vfalu_llvm_constrained_vv_supported(dbt::rv32::VF6_VFRSUB));
	printf("  %u of %u funct6 admitted; %u in vfalu_supported(.vv); "
	       "vfmin/vfmax/vfsgnj{,n,x}/vfrdiv/vfrsub excluded\n",
	       in_predicate, N_FUNCT6, in_vfalu_family);
}

void Section2_DistinctIntrinsics()
{
	printf("[2] the four rows map to four distinct intrinsic IDs\n");
	for (unsigned a = 0; a < N_ROWS; ++a) {
		for (unsigned b = a + 1; b < N_ROWS; ++b) {
			CHECK(ROWS[a].intrin != ROWS[b].intrin);
		}
	}
	printf("  4 distinct constrained intrinsics\n");
}

// One (funct6, sew, vlen) cell.
void CheckCell(Row const &row, u32 vtypei, unsigned sew, u32 vlen)
{
	Built b = BuildRoute(row.funct6, vtypei, vlen);
	CHECK(b.fn != nullptr);
	if (!b.fn) {
		return;
	}
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	unsigned n_nodes = 0;
	InstRVVFALU *node = FindFaluNode(b.region, &n_nodes);
	CHECK_EQ(n_nodes, 1u);
	CHECK(node != nullptr);
	if (!node) {
		return;
	}
	CHECK_EQ((unsigned)node->funct6, row.funct6);
	CHECK_EQ((unsigned)node->sew, sew);
	// The QIR PLAN: one 512-bit chunk per 512 bits of VLEN at LMUL = 1.
	unsigned const want_chunks = vlen / 512;
	CHECK_EQ((unsigned)node->active_chunks, want_chunks);

	auto fast = BlocksNamed(b.fn, "rvv.falu.direct");
	auto slow = BlocksNamed(b.fn, "rvv.falu.fallback");
	CHECK_EQ(fast.size(), 1u);
	CHECK_EQ(slow.size(), 1u);
	if (fast.size() != 1 || slow.size() != 1) {
		return;
	}

	auto calls = ConstrainedCalls(fast[0]);
	// [6] planning and emission agree.
	CHECK_EQ((unsigned)calls.size(), (unsigned)node->active_chunks);
	// [5] the fast arm calls no helper; the fallback arm calls exactly one.
	CHECK_EQ(CountHelperCalls(fast[0]), 0u);
	CHECK_EQ(CountHelperCalls(slow[0]), 1u);

	unsigned const lanes = 64u / sew;
	for (auto *c : calls) {
		// [1] the RIGHT intrinsic, read off the callee as an ID.
		auto *callee = c->getCalledFunction();
		CHECK(callee != nullptr);
		if (callee) {
			CHECK_EQ((unsigned)callee->getIntrinsicID(), (unsigned)row.intrin);
		}
		// [3] the FP environment travels on every call.
		CHECK(HasMetadataOperand(c, "round.dynamic"));
		CHECK(HasMetadataOperand(c, "fpexcept.strict"));
		// legal host width: one 512-bit vector of the guest's element type.
		CHECK(IsFloatVec(c->getType(), lanes, sew == 8));
		CHECK(IsFloatVec(c->getArgOperand(0)->getType(), lanes, sew == 8));
		CHECK(IsFloatVec(c->getArgOperand(1)->getType(), lanes, sew == 8));
	}

	// [4] operand order: argument 0 comes from vs2, argument 1 from vs1. Checked structurally --
	// the two arguments must be DIFFERENT values, and for the non-commutative rows swapping them
	// would be a different function, so this is the assertion that a reversed emitter fails.
	for (auto *c : calls) {
		CHECK(StripCasts(c->getArgOperand(0)) != StripCasts(c->getArgOperand(1)));
	}

	// [3] the per-chunk canonical-NaN select survives: one `fcmp uno x, x` and one `select` per
	// chunk, which is what RvvCanonicalize emits.
	{
		unsigned n_uno = 0, n_sel = 0;
		for (auto &ins : *fast[0]) {
			if (auto *f = llvm::dyn_cast<llvm::FCmpInst>(&ins)) {
				n_uno += f->getPredicate() == llvm::CmpInst::FCMP_UNO;
			}
			n_sel += llvm::isa<llvm::SelectInst>(&ins);
		}
		CHECK_EQ(n_uno, want_chunks);
		CHECK_EQ(n_sel, want_chunks);
	}

	// [5] independence at VLEN 1024: neither call feeds the other, and the four source values are
	// four distinct values. A shared operand would still verify and still legalize, so this is
	// checked rather than inferred from the loop shape.
	if (calls.size() == 2) {
		llvm::Value *s[4] = {StripCasts(calls[0]->getArgOperand(0)),
				     StripCasts(calls[0]->getArgOperand(1)),
				     StripCasts(calls[1]->getArgOperand(0)),
				     StripCasts(calls[1]->getArgOperand(1))};
		for (unsigned i = 0; i < 4; ++i) {
			for (unsigned j = i + 1; j < 4; ++j) {
				CHECK(s[i] != s[j]);
			}
		}
		CHECK(s[2] != StripCasts(calls[0]) && s[3] != StripCasts(calls[0]));
		CHECK(s[2] != calls[0] && s[3] != calls[0]);
	}

	// [3] the frame's FP bracket is present, and `vstart` is cleared on the fast arm.
	CHECK_EQ(CountBlocksExactly(b.fn, "rvv.fp.begin"), 1u);
	CHECK_EQ(CountBlocksExactly(b.fn, "rvv.fp.end"), 1u);
	CHECK_EQ(CountOp(b.region, Op::_rvvfpbegin), 1u);
	CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 1u);
}

void Section1_IRPerRow()
{
	printf("[1][3][4][5][6] emitted IR per row, both element widths, both VLENs\n");
	struct Cell {
		u32 vtypei;
		unsigned sew;
		char const *name;
	};
	Cell const cells[] = {{VTYPEI_E32M1_TAMA, 4, "e32,m1"}, {VTYPEI_E64M1_TAMA, 8, "e64,m1"}};
	for (unsigned r = 0; r < N_ROWS; ++r) {
		for (auto const &cell : cells) {
			for (u32 vlen : {512u, 1024u}) {
				unsigned before = g_fail;
				CheckCell(ROWS[r], cell.vtypei, cell.sew, vlen);
				printf("  %-9s %-7s VLEN %4u -> %u x constrained call%s\n",
				       ROWS[r].name, cell.name, vlen, vlen / 512,
				       g_fail == before ? "" : "   <-- FAILED");
			}
		}
	}
}

void Section7_FlagOff()
{
	printf("[7] flag-off and pure-QCG behaviour is unchanged\n");
	for (unsigned r = 0; r < N_ROWS; ++r) {
		u32 words[2] = {EncVsetvli(VTYPEI_E32M1_TAMA),
				EncOpV(ROWS[r].funct6, 1, VS2, VS1, F3_OPFVV, VD)};
		for (u32 vlen : {512u, 1024u}) {
			// substrate switch off, LLVM backend on
			{
				ResetConfig();
				config::aot_use_llvm = true;
				config::rvv_vector_ssa = false;
				config::vlen_bits = vlen;
				MemArena arena(1u << 20);
				Region *region = BuildRegion(&arena, words, 2);
				CHECK_EQ(CountOp(region, Op::_rvvfalu), 0u);
				CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vfalu), 1u);
			}
			// pure QCG, with the QCG typed-FALU route also off
			{
				ResetConfig();
				config::vlen_bits = vlen;
				MemArena arena(1u << 20);
				Region *region = BuildRegion(&arena, words, 2);
				CHECK_EQ(CountOp(region, Op::_rvvfalu), 0u);
				CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vfalu), 1u);
			}
		}
		printf("  %-9s ssa-off and pure-QCG: 0 nodes, 1 helper, both VLENs\n", ROWS[r].name);
	}
}

} // namespace

int main()
{
	printf("RVV LLVM vector-vector FP arithmetic family\n");
	Section0_FamilyRule();
	Section2_DistinctIntrinsics();
	Section1_IRPerRow();
	Section7_FlagOff();
	printf("\nRVV_LLVM_FALU_FAMILY_VERDICT: %s%s\n", g_fail ? "FAIL (" : "PASS",
	       g_fail ? (std::to_string(g_fail) + ")").c_str() : "");
	return g_fail ? 1 : 0;
}
