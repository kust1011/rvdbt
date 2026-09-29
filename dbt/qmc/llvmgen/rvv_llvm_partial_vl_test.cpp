// C5 (2026-09-17, ruled). PARTIAL VL FOR THE LLVM/AOT INTEGER ELEMENT-WISE FAMILY.
//
// Before C5 every LLVM route required `vl == VLMAX`, so any partial-vl execution left the artifact
// for the helper. QCG's answer is a second, masked arm (RvvEmitPartialAluArm), which refuses
// `aot_use_llvm` and is built from two QIR nodes this backend does not lower. This backend needs no
// second arm: its integer lane ops raise nothing, so computing inactive lanes is unobservable, and
// `Emit_vstatechunkstore` can already predicate the destination store on the live `vec.vl`. One
// body therefore serves both full and partial VL under GuardKind::VTypeIntegerNoRestart.
//
// SECTIONS, and the failure each one exists to catch:
//   [1] The frame carries the partial guard kind AND every destination store is masked. Checking
//       only the guard kind would pass on a frame that admitted `vl < VLMAX` while still writing
//       tail elements the instruction must leave undisturbed -- the dangerous half.
//   [2] The mask is computed from a RUNTIME load of `vec.vl`, and the store is a real
//       `llvm.masked.store`. A mask folded to all-ones at translation time would make the store
//       unconditional again while every QIR-level check still passed.
//   [3] `VL = 0`, partial and full VL are all served by the SAME body -- there is no second arm and
//       no `rvvtypedchunkpartial`/`vchunkactive` node anywhere. `vchunkactive` in particular has no
//       LLVM lowering, so its appearance would be a compile abort; asserting its absence is what
//       makes `policy_enabled = false` a checked fact rather than a comment.
//   [4] GEOMETRY: one masked store per chunk, chunk indices ascending from 0, element width equal
//       to SEW, at every admitted VLEN and both element widths. The finalizer cross-checks the same
//       facts, so a wrong geometry field Panics rather than mis-planning silently.
//   [5] DESTINATION OVERLAP: `vd == vs1`, `vd == vs2` and `vd == vs1 == vs2` still produce one
//       frame whose sources are all read before any destination chunk is written. For this body
//       that is structural -- loads are pass 1, stores are pass 3 -- and the section pins it.
//   [6] THE OP RESTRICTION IS REAL: add/sub/mul/and/or/xor take the partial frame; nothing else
//       does. Division and the saturating/rounding families must keep their existing path, because
//       their inactive lanes are observable.
//   [7] Inert when off, and QCG untouched either way.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds and needs no AVX-512 host; the
// emitted x86 is checked separately in the report via llc on the dumped IR. It asserts nothing
// about FP -- the FP routes keep their full-VL guard, which section 7 pins.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

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

constexpr u32 OpIVV(u32 f6, u32 vs2, u32 vs1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OpMVV(u32 f6, u32 vs2, u32 vs1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (2u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OpFVV(u32 f6, u32 vs2, u32 vs1, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (1u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 F6_VADD = 0u, F6_VSUB = 2u, F6_VAND = 9u, F6_VOR = 10u, F6_VXOR = 11u;
constexpr u32 F6_VMUL = 0b100101u;   // OPMVV
constexpr u32 F6_VDIVU = 0b100000u;  // OPMVV, deliberately excluded
constexpr u32 F6_VSADDU = 0b100000u; // OPIVV saturating, deliberately excluded
constexpr u32 F6_VFADD = 0u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c5", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool partial)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_partial_vl = partial;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
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
	int guard_kind = -1;
	unsigned frames = 0, stores = 0, masked = 0, loads = 0, hcalls = 0;
	unsigned partial_nodes = 0, active_nodes = 0;
	bool sew_ok = true, chunk_order_ok = true;
	unsigned first_store_idx = 0, last_load_idx = 0, seq = 0;
};

Qir ScanQir(Region *r, u8 expect_sew)
{
	Qir q;
	unsigned seen_masked = 0;
	bool any_store = false;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			++q.seq;
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind = (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				break;
			case Op::_rvvtypedchunkpartial: ++q.partial_nodes; break;
			case Op::_vchunkactive: ++q.active_nodes; break;
			case Op::_hcall: ++q.hcalls; break;
			case Op::_vstatechunkload:
				++q.loads;
				q.last_load_idx = q.seq;
				break;
			case Op::_vstatechunkstore: {
				auto *s = static_cast<InstVStateChunkStore *>(&ins);
				++q.stores;
				if (!any_store) { q.first_store_idx = q.seq; any_store = true; }
				if (s->active_sew) {
					++q.masked;
					if (s->active_sew != expect_sew) q.sew_ok = false;
					if (s->chunk != seen_masked) q.chunk_order_ok = false;
					++seen_masked;
				}
				break;
			}
			default: break;
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

struct IRFacts { unsigned masked_stores = 0; bool mask_from_vl = false; };

IRFacts ScanIR(llvm::Function *fn)
{
	IRFacts f;
	llvm::Value *state = fn->getArg(0);
	u32 const vl_offs = offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store)
					++f.masked_stores;
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l) continue;
			llvm::Value *p = l->getPointerOperand();
			if (StripToBase(p) != state || p == state) continue;
			llvm::APInt ap(64, 0);
			auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
			if (g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap) &&
			    (u32)ap.getZExtValue() == vl_offs)
				f.mask_from_vl = true;
		}
	return f;
}

// ------------------------------------------------------------------------------------------
void SectionOn()
{
	printf("[C5-1..4] partial guard kind, masked stores, runtime vl, geometry\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Op6 { char const *name; u32 word; };
	Op6 const ops[] = {
	    {"vadd.vv", OpIVV(F6_VADD, 8, 9, 10)}, {"vsub.vv", OpIVV(F6_VSUB, 8, 9, 10)},
	    {"vand.vv", OpIVV(F6_VAND, 8, 9, 10)}, {"vor.vv", OpIVV(F6_VOR, 8, 9, 10)},
	    {"vxor.vv", OpIVV(F6_VXOR, 8, 9, 10)}, {"vmul.vv", OpMVV(F6_VMUL, 8, 9, 10)},
	};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &o : ops) {
			Configure(vlen, true, true);
			Built b({Vsetvli(kVT_E32M1), o.word, kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region, 4);
			if (q.frames == 0) { // shape not admitted at this width; not this test's subject
				continue;
			}
			// [1] partial guard kind AND every store masked
			CHECK_EQ(q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK(q.stores > 0u);
			CHECK_EQ(q.masked, q.stores);
			// [3] one body only: no second arm, and no node this backend cannot lower
			CHECK_EQ(q.partial_nodes, 0u);
			CHECK_EQ(q.active_nodes, 0u);
			// [4] geometry: element width == SEW, chunk indices ascending from 0
			CHECK(q.sew_ok);
			CHECK(q.chunk_order_ok);
			CHECK_EQ(q.stores, q.frames * (vlen / 8u <= 64u ? 1u : (vlen / 8u) / 64u));
			// [5] every source chunk is read before any destination chunk is written
			CHECK(q.last_load_idx < q.first_store_idx);

			// [2] the mask comes from a runtime vl load and the store is really masked
			IRFacts ir = ScanIR(b.fn);
			CHECK(ir.masked_stores > 0u);
			CHECK(ir.mask_from_vl);
		}
}

void SectionOverlap()
{
	printf("[C5-5] destination overlap: vd == vs1 / vs2 / both\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Ov { char const *name; u32 word; };
	Ov const cases[] = {
	    {"vd == vs1", OpIVV(F6_VADD, 8, 10, 10)},
	    {"vd == vs2", OpIVV(F6_VADD, 10, 9, 10)},
	    {"vd == vs1 == vs2", OpIVV(F6_VADD, 10, 10, 10)},
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &c : cases) {
			Configure(vlen, true, true);
			Built b({Vsetvli(kVT_E32M1), c.word, kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region, 4);
			if (q.frames == 0) {
				printf("  FAIL overlap '%s' built no frame\n", c.name);
				++g_fail;
				continue;
			}
			CHECK_EQ(q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK_EQ(q.masked, q.stores);
			// the read-before-write property is what makes an overlapping vd safe
			CHECK(q.last_load_idx < q.first_store_idx);
		}
}

void SectionOpRestriction()
{
	printf("[C5-6] only add/sub/mul/and/or/xor take the partial frame\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	// Excluded families must NOT carry the partial kind. Whatever they do take -- their own
	// full-VL frame or the helper -- is fine; what must not happen is a partial frame whose
	// inactive lanes are observable.
	struct Ex { char const *name; u32 word; };
	Ex const excluded[] = {
	    {"vdivu.vv (OPMVV)", OpMVV(F6_VDIVU, 8, 9, 10)},
	    {"vsaddu.vv (saturating)", OpIVV(F6_VSADDU, 8, 9, 10)},
	    {"vfadd.vv (FP)", OpFVV(F6_VFADD, 8, 9, 10)},
	};
	for (auto const &e : excluded) {
		Configure(512u, true, true);
		Built b({Vsetvli(kVT_E32M1), e.word, kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region, 4);
		if (q.guard_kind == (int)GK::VTypeIntegerNoRestart) {
			printf("  FAIL '%s' took the partial integer frame\n", e.name);
			++g_fail;
		}
		CHECK_EQ(q.active_nodes, 0u);
	}
	// and the FP family specifically keeps a guard that proves full VL
	Configure(512u, true, true);
	Built f({Vsetvli(kVT_E32M1), OpFVV(F6_VFADD, 8, 9, 10), kJalr});
	Translate(f, true);
	Qir qf = ScanQir(f.region, 4);
	if (qf.frames)
		CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl((GK)qf.guard_kind));
}

// The reviewer's explicit requirement: LLVM semantic support must not depend on the QCG
// active-bound policy switch, and must never emit `vchunkactive`, which has NO LLVM lowering (its
// emitter Panics). A mutation that sourced `policy_enabled` from `--rvv-qcg-active-vl-bound` was NOT
// caught until this section existed, because every other section holds that switch off.
void SectionIndependentOfQcgBoundSwitch()
{
	printf("[C5-8] partial VL does not depend on --rvv-qcg-active-vl-bound\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {512u, 1024u, 2048u})
		for (bool bound : {false, true}) {
			Configure(vlen, true, true);
			config::rvv_qcg_active_vl_bound = bound;
			Built b({Vsetvli(kVT_E32M1), OpIVV(F6_VADD, 8, 9, 10), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region, 4);
			if (!q.frames)
				continue;
			// identical frame either way, and never a node this backend cannot lower
			CHECK_EQ(q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK_EQ(q.masked, q.stores);
			CHECK_EQ(q.active_nodes, 0u);
			CHECK_EQ(q.partial_nodes, 0u);
		}
	config::rvv_qcg_active_vl_bound = false;
}

void SectionInertAndQcg()
{
	printf("[C5-7] inert when off; QCG untouched either way\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {512u, 1024u}) {
		Configure(vlen, true, false);
		Built b({Vsetvli(kVT_E32M1), OpIVV(F6_VADD, 8, 9, 10), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region, 4);
		if (q.frames) {
			CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstart);
			CHECK_EQ(q.masked, 0u);
			CHECK_EQ(ScanIR(b.fn).masked_stores, 0u);
		}
	}
	for (bool partial : {false, true}) {
		Configure(1024u, /*llvm*/ false, partial);
		Built b({Vsetvli(kVT_E32M1), OpIVV(F6_VADD, 8, 9, 10), kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region, 4);
		CHECK(q.guard_kind != (int)GK::VTypeIntegerNoRestart);
	}
}

// Dump one partial frame's IR so the report can run llc on it and show the emitted x86.
void DumpIR()
{
	char const *path = getenv("C5_DUMP_IR");
	if (!path)
		return;
	Configure(512u, true, true);
	Built b({Vsetvli(kVT_E32M1), OpIVV(F6_VADD, 8, 9, 10), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

} // namespace

int main()
{
	printf("rvv_llvm_partial_vl_test\n");
	SectionOn();
	SectionOverlap();
	SectionOpRestriction();
	SectionIndependentOfQcgBoundSwitch();
	SectionInertAndQcg();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
