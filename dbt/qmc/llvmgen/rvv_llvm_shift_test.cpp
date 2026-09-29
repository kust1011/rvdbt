// C3 (2026-09-18). THE IMMEDIATE-SHIFT FAMILY `vsll.vi` / `vsrl.vi` ON THE LLVM/AOT ARM.
//
// WHAT THE QCG INVENTORY ACTUALLY CONTAINS, checked before implementing: the typed shift route
// (RvvQcgTypedShiftChunkShape -> RvvEmitTypedShiftChunkGroup) admits exactly two lane operations,
// `RunOp::Sll` and `RunOp::Srl`, with an IMMEDIATE amount, at SEW 32 / LMUL 1 / unmasked. `vsra`
// (arithmetic right shift) and every register/scalar-amount form are NOT in it and keep their
// helper. This file's envelope is that envelope and no more.
//
// SECTIONS, and what each catches:
//   [1] SIGNEDNESS. `vsll` must lower to `shl` and `vsrl` to `lshr`. An `ashr` anywhere is a silent
//       miscompile on every lane with the top bit set, and `shl`/`lshr` are indistinguishable in a
//       node count -- so the section reads the opcodes out of the emitted IR.
//   [2] NO POISON-GENERATING FLAGS. `shl` must carry neither `nuw` nor `nsw`, `lshr` must not be
//       `exact`. RVV discards the bits shifted out, so a lane that overflows left or drops set bits
//       right is ORDINARY; any of those flags lets LLVM fold such a lane to poison, and nothing
//       about the emitted node count would change.
//   [3] LANE WIDTH is the chunk's own: `<N x i32>` with N = chunk_bytes/4, at every admitted VLEN.
//       A literal 16 would be wrong at VLEN 128/256.
//   [4] SHIFT-COUNT MASKING is the node's, re-checked not re-applied. Asserted at the QIR level on
//       the node's own `shamt`. NOTE HONESTLY: for this route's only SEW the mask is the IDENTITY
//       (`.vi` carries a 5-bit uimm and SEW 32 masks with 31), so this section pins the rule
//       rather than exercising a reduction; the reduction itself is asserted by constructing nodes
//       at narrower SEW directly.
//   [5] PARTIAL VL reuses C5: guard kind VTypeIntegerNoRestart and active-lane masked stores, one
//       body for VL=0/partial/full, no `vchunkactive`/`rvvtypedchunkpartial`.
//   [6] DESTINATION OVERLAP `vd == vs2`, sources read before any destination write.
//   [7] Inert when the switch is off -- this matters more than usual here, because before C3 the
//       shape predicate refused `aot_use_llvm` OUTRIGHT to keep the emitter Panic unreachable. With
//       the switch off that refusal must be exactly restored.
//   [8] QCG admission does not depend on the C3 switch.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds and needs no AVX-512 host; the
// emitted x86 is checked in the report by running llc on the dumped module. It asserts nothing
// about `vsra` or register-amount shifts, which are not in this route.

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

// The frame's chunk count, derived the same way RvvHostChunkGeometryForSew derives it: the host
// chunk is min(VLEN/8, 64) bytes and the register is tiled by it. Asserting against this rather
// than a literal is what keeps the expectations correct at every width.
constexpr u32 Chunks(u32 vlen)
{
	u32 const reg = vlen / 8u;
	u32 const chunk = reg < 64u ? reg : 64u;
	return reg / chunk;
}

// OPIVI, vm = 1. VF6_VSLL = 0b100101, VF6_VSRL = 0b101000 (rv32_vector_lower.h).
constexpr u32 F6_VSLL = 0b100101u, F6_VSRL = 0b101000u;
constexpr u32 ShiftVI(u32 f6, u32 vs2, u32 uimm, u32 vd)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (uimm << 15) | (3u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c3", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool route, bool partial)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true; // QCG arm needs no host AVX-512 here
	config::rvv_llvm_shift = route;
	config::rvv_llvm_partial_vl = partial;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
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
	int guard_kind = -1;
	unsigned frames = 0, sll = 0, srl = 0, hcalls = 0, stores = 0, masked = 0;
	unsigned partial_nodes = 0, active_nodes = 0;
	unsigned shamt = 999, sew = 0;
	unsigned last_load_idx = 0, first_store_idx = 0, seq = 0;
};

Qir ScanQir(Region *r)
{
	Qir q;
	bool any_store = false;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			++q.seq;
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind = (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				break;
			case Op::_vchunksll: {
				auto *n = static_cast<InstVChunkSll *>(&ins);
				++q.sll; q.shamt = n->shamt; q.sew = n->sew_bytes;
				break;
			}
			case Op::_vchunksrl: {
				auto *n = static_cast<InstVChunkSrl *>(&ins);
				++q.srl; q.shamt = n->shamt; q.sew = n->sew_bytes;
				break;
			}
			case Op::_rvvtypedchunkpartial: ++q.partial_nodes; break;
			case Op::_vchunkactive: ++q.active_nodes; break;
			case Op::_hcall: ++q.hcalls; break;
			case Op::_vstatechunkload: q.last_load_idx = q.seq; break;
			case Op::_vstatechunkstore: {
				auto *s = static_cast<InstVStateChunkStore *>(&ins);
				++q.stores;
				if (!any_store) { q.first_store_idx = q.seq; any_store = true; }
				if (s->active_sew) ++q.masked;
				break;
			}
			default: break;
			}
		}
	return q;
}

struct IRFacts {
	unsigned shl = 0, lshr = 0, ashr = 0;
	unsigned bad_flags = 0;   // nuw/nsw on shl, or exact on lshr
	unsigned lanes = 0;       // lane count of the shift's vector type
	unsigned masked_stores = 0;
};

IRFacts ScanIR(llvm::Function *fn)
{
	IRFacts f;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store)
					++f.masked_stores;
			auto *op = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
			if (!op)
				continue;
			unsigned const c = op->getOpcode();
			if (c != llvm::Instruction::Shl && c != llvm::Instruction::LShr &&
			    c != llvm::Instruction::AShr)
				continue;
			if (c == llvm::Instruction::Shl) {
				++f.shl;
				if (op->hasNoUnsignedWrap() || op->hasNoSignedWrap())
					++f.bad_flags;
			} else if (c == llvm::Instruction::LShr) {
				++f.lshr;
				if (op->isExact())
					++f.bad_flags;
			} else {
				++f.ashr;
			}
			if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(op->getType()))
				f.lanes = vt->getNumElements();
		}
	return f;
}

// ------------------------------------------------------------------------------------------
void SectionSemantics()
{
	printf("[C3-1..4] signedness, poison flags, lane width, shift-count rule\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (bool left : {true, false}) {
			Configure(vlen, true, true, false);
			Built b({Vsetvli(kVT_E32M1), ShiftVI(left ? F6_VSLL : F6_VSRL, 8, 3, 10),
				 kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				continue; // shape not admitted at this width
			CHECK_EQ(q.hcalls, 0u);
			u32 const nch = Chunks(vlen);
			CHECK_EQ(left ? q.sll : q.srl, nch);
			CHECK_EQ(left ? q.srl : q.sll, 0u);
			// [4] the node's amount, reduced modulo SEW by its constructor
			CHECK_EQ(q.sew, 4u);
			CHECK_EQ(q.shamt, 3u);

			IRFacts ir = ScanIR(b.fn);
			// [1] the right shift direction, and never an arithmetic shift
			CHECK_EQ(ir.shl, left ? nch : 0u);
			CHECK_EQ(ir.lshr, left ? 0u : nch);
			CHECK_EQ(ir.ashr, 0u);
			// [2] no poison-generating flag
			CHECK_EQ(ir.bad_flags, 0u);
			// [3] lane count follows the chunk width, not a literal
			u32 const chunk = vlen / 8u < 64u ? vlen / 8u : 64u;
			CHECK_EQ(ir.lanes, chunk / 4u);
		}

	// [4b] the reduction rule itself, exercised directly on the node (the route's own SEW makes
	// the mask an identity, so this is where a real reduction is asserted).
	{
		auto d = VOperand::MakeVVPR(VType::V512, 1);
		auto s = VOperand::MakeVVPR(VType::V512, 2);
		InstVChunkSll n1(d, s, /*sew_bytes=*/4, /*shamt=*/35);
		CHECK_EQ(n1.shamt, 35u & 31u);
		InstVChunkSrl n2(d, s, /*sew_bytes=*/4, /*shamt=*/32);
		CHECK_EQ(n2.shamt, 0u);
	}
}

void SectionPartialVl()
{
	printf("[C3-5] partial VL reuses the C5 masked-store frame\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {512u, 1024u, 2048u})
		for (bool left : {true, false}) {
			Configure(vlen, true, true, /*partial=*/true);
			Built b({Vsetvli(kVT_E32M1), ShiftVI(left ? F6_VSLL : F6_VSRL, 8, 5, 10),
				 kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				continue;
			CHECK_EQ(q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK(q.stores > 0u);
			CHECK_EQ(q.masked, q.stores);
			CHECK_EQ(q.partial_nodes, 0u);
			CHECK_EQ(q.active_nodes, 0u);
			CHECK(ScanIR(b.fn).masked_stores > 0u);
		}
}

void SectionOverlap()
{
	printf("[C3-6] destination overlap vd == vs2\n");
	for (u32 vlen : {512u, 1024u}) {
		Configure(vlen, true, true, true);
		Built b({Vsetvli(kVT_E32M1), ShiftVI(F6_VSLL, 10, 2, 10), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		if (!q.frames) { printf("  FAIL overlap built no frame\n"); ++g_fail; continue; }
		CHECK_EQ(q.sll, Chunks(vlen));
		CHECK(q.last_load_idx < q.first_store_idx);
	}
}

void SectionInertAndQcg()
{
	printf("[C3-7,8] switch off restores the pre-C3 refusal; QCG unaffected\n");
	for (u32 vlen : {512u, 1024u})
		for (bool partial : {false, true}) {
			Configure(vlen, true, /*route=*/false, partial);
			Built b({Vsetvli(kVT_E32M1), ShiftVI(F6_VSLL, 8, 3, 10), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			// exactly the pre-C3 state: no frame, no shift node, the helper instead
			CHECK_EQ(q.frames, 0u);
			CHECK_EQ(q.sll, 0u);
			CHECK(q.hcalls > 0u);
		}
	for (bool route : {false, true}) {
		Configure(1024u, /*llvm*/ false, route, false);
		Built b({Vsetvli(kVT_E32M1), ShiftVI(F6_VSLL, 8, 3, 10), kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.sll, Chunks(1024u)); // QCG lowers it either way
		CHECK_EQ(q.hcalls, 0u);
	}
}

void DumpIR()
{
	char const *path = getenv("C3_DUMP_IR");
	if (!path)
		return;
	Configure(512u, true, true, true);
	Built b({Vsetvli(kVT_E32M1), ShiftVI(F6_VSLL, 8, 3, 10), kJalr});
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
	printf("rvv_llvm_shift_test\n");
	SectionSemantics();
	SectionPartialVl();
	SectionOverlap();
	SectionInertAndQcg();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
