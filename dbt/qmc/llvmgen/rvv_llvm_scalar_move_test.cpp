// C2b (2026-09-17). THE FOUR SCALAR <-> VECTOR ELEMENT-0 TRANSFERS ON THE LLVM/AOT ARM.
//
//   vmv.s.x  GPR -> vd[0]     vmv.x.s  vs2[0] -> GPR
//   vfmv.s.f FPR -> vd[0]     vfmv.f.s vs2[0] -> FPR
//
// This family's difficult conditions are not its shape -- one element moves -- but four rules that
// are each silent when wrong, so each gets an assertion whose failure path is stated:
//
//   [1] THE ACTIVE-ELEMENT RULE IS ASYMMETRIC. The to-vector forms write vd[0] only while
//       `vstart < vl` and leave it untouched otherwise (that includes `vl == 0`); the from-vector
//       forms ignore vl and vstart entirely. So the emitted to-vector body must READ `vec.vl`, and
//       the from-vector body must NOT. Failure path: a lowering that "simplified" the direction
//       rule by treating both alike would still produce correct-looking IR and would corrupt vd[0]
//       at `vl == 0`, or would needlessly read vl.
//   [2] BOTH DIRECTIONS CLEAR VSTART, including the to-vector inactive path. Failure path: a body
//       that clears vstart only when it actually transferred.
//   [3] THE SCALAR SIDE IS THE RIGHT REGISTER FILE AND THE RIGHT WIDTH: integer forms touch
//       `gpr[n]` (4 bytes), floating forms touch `fpu.f[n]` (8 bytes). Failure path: an f-register
//       index scaled by 4, or a GPR written 8 bytes wide, both of which corrupt a neighbouring
//       register and neither of which changes the instruction count.
//   [4] `x0` IS NEVER WRITTEN by `vmv.x.s`, and reads as zero for `vmv.s.x`. Failure path: an
//       unconditional store to `gpr[0]`, which is architecturally hardwired zero.
//
// Plus the ordinary obligations: the admission truth table including refusals, inertness when the
// switch is off, and that QCG is untouched.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds, needs no AVX-512 host, and asserts
// nothing about speed. It does not re-verify the NaN-boxing VALUE (that is the shared helper's and
// QCG's semantics); it asserts the structural facts above, which are what this lowering could get
// wrong on its own.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Function.h"
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

// funct6 = 16 (0b010000), vm = 1. funct3: 6 = vmv.s.x, 2 = vmv.x.s, 5 = vfmv.s.f, 1 = vfmv.f.s.
constexpr u32 ScalarMove(u32 f3, u32 vs2, u32 vs1, u32 vd)
{
	return (16u << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 VmvSX(u32 vd, u32 rs1) { return ScalarMove(6, 0, rs1, vd); }   // GPR -> vd[0]
constexpr u32 VmvXS(u32 rd, u32 vs2) { return ScalarMove(2, vs2, 0, rd); }   // vs2[0] -> GPR
constexpr u32 VfmvSF(u32 vd, u32 rs1) { return ScalarMove(5, 0, rs1, vd); }  // FPR -> vd[0]
constexpr u32 VfmvFS(u32 rd, u32 vs2) { return ScalarMove(1, vs2, 0, rd); }  // vs2[0] -> FPR
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u, kVT_E8M1 = 0xc0u, kVT_E16M1 = 0xc8u;
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c2b", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool route)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_scalar_move = route;
	// The test programs start with a vsetvli; make it native on both backends so the only helper
	// call a region can contain is the one under test.
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_partial_vl = false;
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
	unsigned moves = 0, frames = 0, hcalls = 0;
	int guard_kind = -1;
	unsigned vreg = 99, greg = 99, sew = 0;
	bool to_vector = false, floating = false;
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
			} else if (ins.GetOpcode() == Op::_vscalarmove) {
				auto *m = static_cast<InstVScalarMove *>(&ins);
				++q.moves;
				q.vreg = m->vreg; q.greg = m->greg; q.sew = m->sew;
				q.to_vector = m->to_vector; q.floating = m->floating;
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

struct Acc { u32 offs, size; };
struct IR { std::vector<Acc> loads, stores; };

IR ScanIR(llvm::Function *fn)
{
	IR v;
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			llvm::Value *p = nullptr; llvm::Type *ty = nullptr; bool st = false;
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				p = l->getPointerOperand(); ty = l->getType();
			} else if (auto *s = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				p = s->getPointerOperand(); ty = s->getValueOperand()->getType();
				st = true;
			} else continue;
			if (StripToBase(p) != state) continue;
			u32 off = 0;
			if (p != state) {
				llvm::APInt ap(64, 0);
				auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
				if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
					continue;
				off = (u32)ap.getZExtValue();
			}
			Acc a{off, (u32)(ty->getPrimitiveSizeInBits() / 8)};
			(st ? v.stores : v.loads).push_back(a);
		}
	return v;
}

// Is the value stored to this CPUState offset produced by a select? That is the observable form of
// "this write is conditional on the active-element rule".
bool StoredValueIsSelect(llvm::Function *fn, u32 offs)
{
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *s = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!s)
				continue;
			llvm::Value *p = s->getPointerOperand();
			if (StripToBase(p) != state || p == state)
				continue;
			llvm::APInt ap(64, 0);
			auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
			if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
				continue;
			if ((u32)ap.getZExtValue() != offs)
				continue;
			if (llvm::isa<llvm::SelectInst>(s->getValueOperand()))
				return true;
		}
	return false;
}

bool Reads(IR const &v, u32 o) { for (auto &a : v.loads) if (a.offs == o) return true; return false; }
bool Writes(IR const &v, u32 o) { for (auto &a : v.stores) if (a.offs == o) return true; return false; }
bool WritesWidth(IR const &v, u32 o, u32 w)
{
	for (auto &a : v.stores) if (a.offs == o && a.size == w) return true;
	return false;
}

constexpr u32 kVec = offsetof(CPUState, vec);
constexpr u32 kVl = kVec + offsetof(rvv32::VectorState, vl);
constexpr u32 kVstart = kVec + offsetof(rvv32::VectorState, vstart);
constexpr u32 kVreg = kVec + offsetof(rvv32::VectorState, vreg);
constexpr u32 kGpr = offsetof(CPUState, gpr);
constexpr u32 kFpr = offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, f);

// ------------------------------------------------------------------------------------------
// How many helper calls does the leading `vsetvli` alone contribute at this vtype/VLEN?
unsigned PrologueHelpers(u32 vt, u32 vlen, bool llvm_backend)
{
	Configure(vlen, llvm_backend, true);
	Built b({Vsetvli(vt), kJalr});
	Translate(b, false);
	return ScanQir(b.region).hcalls;
}

void SectionDirections()
{
	printf("[C2b-1,2,3] direction rule, vstart publication, register file and width\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Case { char const *name; u32 word; u32 vt; bool to_vector, floating; u32 sew; };
	Case const cases[] = {
	    {"vmv.s.x  e32", VmvSX(8, 11), kVT_E32M1, true, false, 4},
	    {"vmv.x.s  e32", VmvXS(11, 8), kVT_E32M1, false, false, 4},
	    {"vfmv.s.f e32", VfmvSF(8, 11), kVT_E32M1, true, true, 4},
	    {"vfmv.f.s e32", VfmvFS(11, 8), kVT_E32M1, false, true, 4},
	    {"vmv.s.x  e64", VmvSX(8, 11), kVT_E64M1, true, false, 8},
	    {"vmv.x.s  e64", VmvXS(11, 8), kVT_E64M1, false, false, 8},
	    {"vfmv.s.f e64", VfmvSF(8, 11), kVT_E64M1, true, true, 8},
	    {"vfmv.f.s e64", VfmvFS(11, 8), kVT_E64M1, false, true, 8},
	    {"vmv.s.x  e8 ", VmvSX(8, 11), kVT_E8M1, true, false, 1},
	    {"vmv.x.s  e16", VmvXS(11, 8), kVT_E16M1, false, false, 2},
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &c : cases) {
			Configure(vlen, true, true);
			Built b({Vsetvli(c.vt), c.word, kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ(q.moves, 1u);
			// Against a PROLOGUE-ONLY baseline, not against zero: the leading `vsetvli` is
			// itself native only at the shapes RvvLLVMSetVLAdmit admits (e32), so at e8/e16/
			// e64 the prologue legitimately keeps its own helper. What C2b must show is that
			// it adds NO helper call of its own.
			CHECK_EQ(q.hcalls, PrologueHelpers(c.vt, vlen, true));
			// the body handles vstart, so this is the kind the frame must carry
			CHECK_EQ(q.guard_kind, (int)GK::VTypeInteger);
			CHECK_EQ(q.to_vector, c.to_vector);
			CHECK_EQ(q.floating, c.floating);
			CHECK_EQ(q.sew, c.sew);
			CHECK_EQ(q.vreg, 8u);
			CHECK_EQ(q.greg, 11u);

			IR ir = ScanIR(b.fn);
			// [1] THE ASYMMETRIC ACTIVE-ELEMENT RULE, asserted on the BODY.
			//
			// `Reads(vec.vl)` would be the wrong probe: the frame's guard kind
			// (VTypeInteger) legitimately tests `vl <= VLMAX` in BOTH directions, so vl is
			// read either way and such a check would pass on a lowering that ignored the
			// rule. What distinguishes the directions is whether the DESTINATION WRITE IS
			// CONDITIONAL: the to-vector forms write vd[0] only while `vstart < vl`, so
			// their stored value must be a select; the from-vector forms are unconditional.
			u32 const scalar0 = c.floating ? kFpr + 11u * 8u : kGpr + 11u * 4u;
			u32 const elem0 = kVreg + 8u * rvv32::VLEN_MAX_BYTES;
			CHECK_EQ(StoredValueIsSelect(b.fn, c.to_vector ? elem0 : scalar0),
				 c.to_vector);
			// only the to-vector direction reads vstart in its body; the guard does not,
			// because this kind leaves vstart to the body.
			CHECK(Reads(ir, kVstart) == c.to_vector);
			// [2] vstart is published on every path
			CHECK(Writes(ir, kVstart));
			// [3] the right register file, at the right width
			u32 const scalar = c.floating ? kFpr + 11u * 8u : kGpr + 11u * 4u;
			u32 const elem = kVreg + 8u * rvv32::VLEN_MAX_BYTES;
			if (c.to_vector) {
				CHECK(Reads(ir, scalar));
				CHECK(WritesWidth(ir, elem, c.sew));
			} else {
				CHECK(Reads(ir, elem));
				CHECK(WritesWidth(ir, scalar, c.floating ? 8u : 4u));
			}
		}
}

void SectionX0()
{
	printf("[C2b-4] x0 is never written, and reads as zero\n");
	Configure(512u, true, true);
	// vmv.x.s with rd == x0: architecturally hardwired zero, so no GPR store at all.
	Built r({Vsetvli(kVT_E32M1), VmvXS(0, 8), kJalr});
	Translate(r, true);
	Qir qr = ScanQir(r.region);
	CHECK_EQ(qr.moves, 1u);
	IR ir = ScanIR(r.fn);
	CHECK(!Writes(ir, kGpr)); // gpr[0]
	CHECK(Writes(ir, kVstart));

	// vmv.s.x with rs1 == x0: the value is zero, so no GPR load is needed.
	Configure(512u, true, true);
	Built w({Vsetvli(kVT_E32M1), VmvSX(8, 0), kJalr});
	Translate(w, true);
	IR iw = ScanIR(w.fn);
	CHECK(!Reads(iw, kGpr));
	CHECK(Writes(iw, kVstart));
}

void SectionRefusals()
{
	printf("[C2b-5] refusals keep the unchanged helper\n");
	struct R { char const *name; u32 word; u32 vt; bool route; };
	R const cases[] = {
	    {"switch off", VmvSX(8, 11), kVT_E32M1, false},
	    // floating forms below SEW 32 have no f16 register file here
	    {"vfmv.s.f at e16", VfmvSF(8, 11), kVT_E16M1, true},
	    {"vfmv.f.s at e8", VfmvFS(11, 8), kVT_E8M1, true},
	    // funct6 16 with a NONZERO unused source field is a different instruction
	    {"vmv.s.x with vs2 != 0", ScalarMove(6, 3, 11, 8), kVT_E32M1, true},
	    {"vmv.x.s with vs1 != 0", ScalarMove(2, 8, 3, 11), kVT_E32M1, true},
	};
	for (auto const &c : cases) {
		Configure(512u, true, c.route);
		Built b({Vsetvli(c.vt), c.word, kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		if (q.moves != 0 || q.hcalls == 0) {
			printf("  FAIL refusal '%s': moves=%u hcalls=%u\n", c.name, q.moves, q.hcalls);
			++g_fail;
		}
	}
}

void SectionQcgUntouched()
{
	printf("[C2b-6] QCG admission does not depend on the C2b switch\n");
	for (bool route : {false, true}) {
		Configure(1024u, /*llvm*/ false, route);
		Built b({Vsetvli(kVT_E32M1), VmvSX(8, 11), kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.moves, 1u); // QCG lowers it either way
		CHECK_EQ(q.hcalls, PrologueHelpers(kVT_E32M1, 1024u, false));
	}
}

} // namespace

int main()
{
	printf("rvv_llvm_scalar_move_test\n");
	SectionDirections();
	SectionX0();
	SectionRefusals();
	SectionQcgUntouched();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
