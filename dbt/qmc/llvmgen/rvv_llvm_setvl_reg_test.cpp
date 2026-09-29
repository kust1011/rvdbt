// C2a (2026-09-17). `vsetvl` WITH THE VTYPE IN A GPR, ON THE LLVM/AOT ARM.
//
// The immediate forms (`vsetvli`/`vsetivli`) have been LLVM-native since S3.4 because their vtype
// is a translation-time constant, so VLMAX is too. The register form is the one case where VLMAX is
// a RUN-TIME lookup and the vtype may be ILLEGAL, which is why it needed its own lowering rather
// than a relaxed gate.
//
// SECTIONS, and what each one fails on:
//   [1] With the switch on, the route builds the `rvvsetvlreg` node instead of a helper call, and
//       the emitted function writes ALL FOUR architectural fields (vtype, vl, vstart, vlenb) plus
//       the destination GPR. Failure path: a lowering that forgot `vstart` (the field every RVV
//       configuration instruction must clear) or `vlenb`.
//   [2] THE TABLE IS THE REFERENCE TABLE. The module constant the lowering emits is compared
//       entry-for-entry against `rv32::vlmax_table_for(VLEN)`. This is the assertion that matters:
//       a table that was truncated, byte-swapped, built for the wrong VLEN, or indexed with the
//       wrong element type would still produce perfectly well-formed IR and pass every structural
//       check. Nothing else in this file would catch it.
//   [3] Inert when off: the switch off reproduces the pre-C2a behaviour exactly -- a helper call,
//       no node, and NO table constant left in the module.
//   [4] QCG is untouched: with the LLVM backend off the route still takes the QCG path regardless
//       of the C2a switch, so the switch cannot change QCG admission.
//
// WHAT IT DOES NOT DO. It never executes what it builds and needs no AVX-512 host. It does not
// assert the RUN-TIME result of an illegal vtype -- that is the helper's and QCG's behaviour, and
// section 2 is what ties this lowering to the same table they use.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdio>
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

// `vsetvl rd, rs1, rs2`: funct7 = 1000000, funct3 = 111, opcode 1010111.
constexpr u32 Vsetvl(u32 rd, u32 rs1, u32 rs2)
{
	return (0b1000000u << 25) | (rs2 << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | 0x57u;
}
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c2a", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool route)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_llvm_setvl_reg = route;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_vector_run = false;
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
	unsigned setvlreg = 0, setvl = 0, hcalls = 0;
	bool keep_vl = false;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvsetvlreg) {
				++q.setvlreg;
				q.keep_vl = static_cast<InstRVVSetVLReg *>(&ins)->keep_vl;
			} else if (ins.GetOpcode() == Op::_rvvsetvl) {
				++q.setvl;
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

// Which constant CPUState offsets does the function STORE to?
std::vector<u32> StoredOffsets(llvm::Function *fn)
{
	std::vector<u32> out;
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *s = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!s)
				continue;
			llvm::Value *p = s->getPointerOperand();
			if (StripToBase(p) != state)
				continue;
			if (p == state) { out.push_back(0); continue; }
			llvm::APInt ap(64, 0);
			auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
			if (g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
				out.push_back((u32)ap.getZExtValue());
		}
	return out;
}

bool Has(std::vector<u32> const &v, u32 x)
{
	for (u32 y : v)
		if (y == x)
			return true;
	return false;
}

constexpr u32 kVec = offsetof(CPUState, vec);
constexpr u32 kVtype = kVec + offsetof(rvv32::VectorState, vtype);
constexpr u32 kVl = kVec + offsetof(rvv32::VectorState, vl);
constexpr u32 kVstart = kVec + offsetof(rvv32::VectorState, vstart);
constexpr u32 kVlenb = kVec + offsetof(rvv32::VectorState, vlenb);

// ------------------------------------------------------------------------------------------
void SectionOn()
{
	printf("[C2a-1,2] native node, all four state fields, and the REFERENCE vlmax table\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u}) {
		Configure(vlen, true, true);
		Built b({Vsetvl(10, 11, 12), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		// [1] the node was built and no helper call remains
		CHECK_EQ(q.setvlreg, 1u);
		CHECK_EQ(q.hcalls, 0u);
		CHECK(!q.keep_vl);

		auto st = StoredOffsets(b.fn);
		CHECK(Has(st, kVtype));
		CHECK(Has(st, kVl));
		CHECK(Has(st, kVstart)); // every RVV configuration instruction clears vstart
		CHECK(Has(st, kVlenb));

		// [2] the emitted table IS the reference table, entry for entry.
		auto const *ref = rvv32::vlmax_table_for(vlen);
		CHECK(ref != nullptr);
		auto *gv = b.module.getNamedGlobal("rvv.vlmax." + std::to_string(vlen));
		CHECK(gv != nullptr);
		if (!gv || !ref)
			continue;
		CHECK(gv->isConstant());
		// LLVM canonicalises a plain integer array to ConstantDataArray, so read it through
		// the sequential interface rather than assuming ConstantArray.
		auto *init = llvm::dyn_cast<llvm::ConstantDataSequential>(gv->getInitializer());
		CHECK(init != nullptr);
		if (!init)
			continue;
		auto *aty = llvm::dyn_cast<llvm::ArrayType>(init->getType());
		CHECK(aty != nullptr);
		if (!aty)
			continue;
		CHECK_EQ(aty->getNumElements(), rvv32::VlmaxTable::SIZE);
		CHECK_EQ(aty->getElementType()->getIntegerBitWidth(), 16u);
		unsigned bad = 0, nonzero = 0;
		for (u32 i = 0; i < rvv32::VlmaxTable::SIZE; ++i) {
			if ((u16)init->getElementAsInteger(i) != ref->vlmax[i])
				++bad;
			if (ref->vlmax[i])
				++nonzero;
		}
		CHECK_EQ(bad, 0u);
		// a table that is entirely zero would compare equal to a zero reference; require the
		// reference itself to describe some legal vtypes, so the comparison has content.
		CHECK(nonzero > 0u);
	}

	// the keep-vl form (rd == x0 && rs1 == x0) is recognised as such
	Configure(512u, true, true);
	Built k({Vsetvl(0, 0, 12), kJalr});
	Translate(k, true);
	Qir qk = ScanQir(k.region);
	CHECK_EQ(qk.setvlreg, 1u);
	CHECK(qk.keep_vl);
}

void SectionOffIsInert()
{
	printf("[C2a-3] switch off: helper call, no node, no table left in the module\n");
	for (u32 vlen : {512u, 1024u}) {
		Configure(vlen, true, false);
		Built b({Vsetvl(10, 11, 12), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.setvlreg, 0u);
		CHECK(q.hcalls > 0u);
		CHECK(b.module.getNamedGlobal("rvv.vlmax." + std::to_string(vlen)) == nullptr);
	}
}

void SectionQcgUntouched()
{
	printf("[C2a-4] QCG admission does not depend on the C2a switch\n");
	for (bool route : {false, true}) {
		Configure(1024u, /*llvm*/ false, route);
		Built b({Vsetvl(10, 11, 12), kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		// QCG lowers this natively either way; the C2a switch must not change that.
		CHECK_EQ(q.setvlreg, 1u);
		CHECK_EQ(q.hcalls, 0u);
	}
}

} // namespace

int main()
{
	printf("rvv_llvm_setvl_reg_test\n");
	SectionOn();
	SectionOffIsInert();
	SectionQcgUntouched();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
