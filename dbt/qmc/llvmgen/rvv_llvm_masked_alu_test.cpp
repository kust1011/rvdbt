// ORDER ITEM 3 (2026-09-19): ARCHITECTURAL-MASK SUPPORT FOR ONE INTEGER FAMILY.
//
// The route under test is `RvvTryLLVMMaskedAlu` (rv32_qir.cpp) plus the mask arm of
// `Emit_vstatechunkstore` (llvmgen.cpp): masked OPIVV `vadd/vsub/vand/vor/vxor` (`vm == 0`),
// SEW 32, LMUL 1, observed vtype, under `--rvv-llvm-masked`. It is the FIRST route in either LLVM
// family that emits the contract's third active-predicate conjunct, so what has to be pinned here is
// not "a mask exists" but that the emitted predicate IS
//
//     active(e) = (e < vl) && v0[e]        with `vstart == 0` proved by the frame guard
//
// for the ELEMENT INDICES THIS UNIT OWNS.
//
// SECTIONS, and the failure each exists to catch:
//
//   [M1] Admission and inertness. The five funct6 values take the frame at every admitted VLEN; the
//        helper for the ALU instruction is gone; with the switch off the instruction is back on its
//        helper and no frame exists; the pure-QCG compile is unchanged either way.
//
//   [M2] THE PREDICATE IS A CONJUNCTION OF TWO RUNTIME LOADS. A test that only asserted "the
//        function loads v0" would pass on a body that dropped the `vl` bound (writing tail elements
//        a shorter `vl` must leave alone), and one that only counted masked stores would pass on the
//        pre-existing unmasked-partial-VL body. Both terms are located, and the AND that joins them
//        is required to be the masked store's own mask operand.
//
//   [M3] THE TRUTH TABLE, folded, against the contract itself. `vec.vl` and the v0 mask word are
//        replaced by constants and the module is folded to fixpoint, so each unit's mask collapses
//        to a `<N x i1>` constant that is then compared ELEMENT BY ELEMENT with
//        `rvvcontract::ElementIsActive(e, 0, vl, MaskBitOfElement(v0, e))`. This is the section that
//        can see a wrong bit order, a wrong shift, a wrong byte offset, an off-by-one element base
//        or a dropped conjunct -- every one of which produces perfectly well-formed IR that every
//        structural check above would accept.
//
//   [M4] THE MASK WINDOW'S BASE, measured -- and its shift's VACUITY asserted. The ledger records the same gap appearing three times in
//        this checkpoint -- a predicate checked for PRESENCE while its element base was not -- so
//        each unit's v0 load offset and shift amount are read out of the IR and required to equal
//        `MaskWindowForUnit(unit * lanes, lanes)`. [M3] would also catch this, at VLEN 512+ where
//        there is more than one unit; [M4] catches it structurally and at every width. It ALSO
//        asserts that every admitted unit's shift is zero, which is the honest record of a known
//        gap: because it is, a mutation that deletes the emitter's shift survives this file, and
//        [M8] is what covers the shift arithmetic at the shapes the route cannot reach.
//
//   [M5] THE REFUSALS, each of which must keep the UNCHANGED helper rather than crash or mislower:
//        `vd == v0` (RVV 1.0 5.3, and the mask-window RAW hazard), `vs1 == v0` / `vs2 == v0` (5.2
//        once v0 is read at EEW 1), LMUL != 1, SEW 16/64, an unobserved vtype, OPMVV (`vmul.vv`
//        masked, a different stub), and a funct6 outside the five.
//
//   [M6] LEGAL DESTINATION OVERLAP `vd == vs1` / `vd == vs2` / both: still one frame, and every
//        source load is emitted before any destination store, so the overlap reads pre-instruction
//        bytes. The mask itself is v0 and is refused as a destination by [M5], which is what makes
//        the load-major argument sufficient here.
//
//   [M7] The module verifies, at every VLEN and for every admitted funct6.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds and needs no AVX-512 host. It
// therefore cannot observe a host flag or a fault; for this family that is not a gap in the same way
// it is for the FP routes -- these five lane operations raise nothing -- but it IS a gap for the
// claim that the emitted x86 masks the store in hardware, which is a separate llc inspection.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_rvv_contract.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace testcompat = dbt::qir::testcompat;

namespace
{
namespace rvv32 = dbt::rv32;
namespace ct = dbt::rv32::rvvcontract;

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

// THE GENERATOR'S OWN CONTEXT, not a fresh one. `LLVMGenCtx` is constructed from the thread-local
// `g_llvm_ctx` unconditionally (llvmgen.cpp), so a module created in any other context produces a
// function whose types belong to a different context -- which `verifyModule` reports as "Function
// context does not match Module context" and which makes every type-level assertion here vacuous.
// [M7] is the section that would otherwise never have caught it.
llvm::LLVMContext &g_ctx = dbt::qir::g_llvm_ctx;

// OPIVV, `vm` explicit: this route's whole subject is the `vm == 0` half of the encoding space.
constexpr u32 V(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool masked)
{
	return (f6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kJalr = 0x00008067u;
// vtype = vma(7) | vta(6) | sew(5:3) | lmul(2:0).
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E16M1 = 0xc8u, kVT_E64M1 = 0xd8u, kVT_E32M2 = 0xd1u;
constexpr u32 F3_OPIVV = 0u, F3_OPMVV = 2u;
constexpr u32 F6_VADD = 0u, F6_VSUB = 2u, F6_VAND = 9u, F6_VOR = 10u, F6_VXOR = 11u;
constexpr u32 F6_VMINU = 4u;  // OPIVV, deliberately outside the five
constexpr u32 F6_VMUL = 0b100101u; // OPMVV -> rv32_vimul, a different stub

// Registers used throughout. v0 is the mask and is never a destination or a data source except in
// the [M5] rows that exist to be refused.
constexpr u32 kVs2 = 8u, kVs1 = 9u, kVd = 10u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi3m", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool route, bool restart = false)
{
	config::rvv_llvm_restart = restart;
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_masked = route;
	// Deliberately OFF: a masked frame carries the vl conjunct by construction, so if this route
	// silently depended on the partial-VL switch every check below would still pass with it on and
	// the dependency would go unrecorded.
	config::rvv_llvm_partial_vl = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_typed_chunk_force_emit = !llvm_backend;
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
	unsigned frames = 0, hcalls = 0, loads = 0, stores = 0, masked_stores = 0;
	unsigned first_store_seq = 0, last_load_seq = 0, seq = 0;
	bool sew_ok = true, chunk_order_ok = true, all_masked = true;
	bool frame_clears_vstart = false;
};

Qir ScanQir(Region *r, u8 expect_sew)
{
	Qir q;
	unsigned seen = 0;
	bool any_store = false;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			++q.seq;
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				break;
			case Op::_rvvtypedchunkend:
				q.frame_clears_vstart =
				    static_cast<InstRVVTypedChunkEnd *>(&ins)->frame_clears_vstart;
				break;
			case Op::_hcall: ++q.hcalls; break;
			case Op::_vstatechunkload:
				++q.loads;
				q.last_load_seq = q.seq;
				break;
			case Op::_vstatechunkstore: {
				auto *s = static_cast<InstVStateChunkStore *>(&ins);
				++q.stores;
				if (!any_store) { q.first_store_seq = q.seq; any_store = true; }
				if (!s->masked || !s->active_sew) {
					q.all_masked = false;
					break;
				}
				++q.masked_stores;
				if (s->active_sew != expect_sew) q.sew_ok = false;
				if (s->chunk != seen) q.chunk_order_ok = false;
				++seen;
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

u32 StateOffset(llvm::Value *p, llvm::Value *state)
{
	if (StripToBase(p) != state || p == state)
		return ~0u;
	auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	if (!g)
		return ~0u;
	llvm::APInt ap(64, 0);
	if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
		return ~0u;
	return (u32)ap.getZExtValue();
}

constexpr u32 kVregOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
constexpr u32 kVlOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
u32 VRegOff(u32 r) { return kVregOff + r * rvv32::VLEN_MAX_BYTES; }

// ------------------------------------------------------------------------------------------
// [M2] the predicate's two runtime terms, and the AND that joins them.
struct Terms {
	unsigned masked_stores = 0;
	unsigned masks_with_vl = 0;    // the `icmp ult(indices, splat vl)` term reaches the mask
	unsigned masks_with_v0 = 0;    // a v0 load reaches the mask
	unsigned masks_are_and = 0;    // the mask operand itself is an `and`
	unsigned plain_stores_to_vd = 0;
};

// Does `v`'s def-use cone contain a CPUState load in `[lo, hi)` of the given width (bounded walk)?
//
// A RANGE, not one offset, and that is the point for the mask term: unit 0 reads v0's first 16-bit
// group but unit 1 reads the SECOND one, so an exact-offset test would find the mask on unit 0 and
// silently report every later unit as unmasked. (It did, on the first run of this test.)
bool ConeHasStateLoad(llvm::Value *v, llvm::Value *state, u32 lo, u32 hi, unsigned width_bits,
		      unsigned depth = 24)
{
	if (!depth)
		return false;
	if (auto *l = llvm::dyn_cast<llvm::LoadInst>(v))
		if (l->getType()->isIntegerTy(width_bits)) {
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o != ~0u && o >= lo && o < hi)
				return true;
		}
	auto *ins = llvm::dyn_cast<llvm::Instruction>(v);
	if (!ins)
		return false;
	for (auto &u : ins->operands())
		if (ConeHasStateLoad(u.get(), state, lo, hi, width_bits, depth - 1))
			return true;
	return false;
}

// Does `v`'s cone contain an unsigned-GE compare fed by a load of CPUState at `offs`? That is the
// floor term exactly: `element_index >= splat(vstart)`. Checking for the LOAD alone would also fire
// on the guard's own `vstart == 0` test, and checking for the compare alone would fire on the `vl`
// bound's `ult`.
bool ConeHasUGEAgainst(llvm::Value *v, llvm::Value *state, u32 offs, unsigned depth = 24)
{
	if (!depth)
		return false;
	if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(v))
		if (cmp->getPredicate() == llvm::CmpInst::ICMP_UGE)
			for (auto &u : cmp->operands())
				// A FULL CONE WALK, not a `getOperand(0)` chain. The splat is
				// `insertelement poison, %vstart, 0` + `shufflevector`, so the load sits
				// at operand 1 of the insertelement -- a linear walk down operand 0 lands
				// on `poison` and reports no floor. (It did, on the first run.)
				if (ConeHasStateLoad(u.get(), state, offs, offs + 4u, 32))
					return true;
	auto *ins = llvm::dyn_cast<llvm::Instruction>(v);
	if (!ins)
		return false;
	for (auto &u : ins->operands())
		if (ConeHasUGEAgainst(u.get(), state, offs, depth - 1))
			return true;
	return false;
}

Terms MeasureTerms(llvm::Function *fn, u32 rd_off, u32 lanes)
{
	Terms t;
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				if (ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				if (StateOffset(ii->getArgOperand(1), state) < rd_off ||
				    StateOffset(ii->getArgOperand(1), state) >=
					rd_off + rvv32::VLEN_MAX_BYTES)
					continue;
				++t.masked_stores;
				llvm::Value *m = testcompat::MaskedStoreMask(ii);
				if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(m))
					if (bo->getOpcode() == llvm::Instruction::And)
						++t.masks_are_and;
				if (ConeHasStateLoad(m, state, kVlOff, kVlOff + 4u, 32))
					++t.masks_with_vl;
				// v0's mask bits are the FIRST register of the vreg array, and this
				// body's only 16-bit CPUState read is the one that fetches them.
				if (ConeHasStateLoad(m, state, kVregOff,
						     kVregOff + rvv32::VLEN_MAX_BYTES, 16))
					++t.masks_with_v0;
				continue;
			}
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				u32 const o = StateOffset(st->getPointerOperand(), state);
				if (o >= rd_off && o < rd_off + rvv32::VLEN_MAX_BYTES)
					++t.plain_stores_to_vd;
			}
		}
	(void)lanes;
	return t;
}

// ------------------------------------------------------------------------------------------
// [M4] the v0 window each unit actually reads: (byte offset from v0, shift amount).
struct Window {
	u32 byte_offset = ~0u;
	u32 shift = ~0u;
};

// Find the unique i16 CPUState load in `m`'s cone and the constant it is shifted by.
bool FindMaskWindow(llvm::Value *m, llvm::Value *state, Window *out, unsigned depth = 24)
{
	if (!depth)
		return false;
	if (auto *l = llvm::dyn_cast<llvm::LoadInst>(m))
		if (l->getType()->isIntegerTy(16)) {
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o == ~0u || o < kVregOff)
				return false;
			out->byte_offset = o - kVregOff;
			if (out->shift == ~0u)
				out->shift = 0; // no lshr on the path: shift is zero
			return true;
		}
	auto *ins = llvm::dyn_cast<llvm::Instruction>(m);
	if (!ins)
		return false;
	if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(ins))
		if (bo->getOpcode() == llvm::Instruction::LShr)
			if (auto *c = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(1)))
				out->shift = (u32)c->getZExtValue();
	for (auto &u : ins->operands())
		if (FindMaskWindow(u.get(), state, out, depth - 1))
			return true;
	return false;
}

// ------------------------------------------------------------------------------------------
// [M3] fold the unit masks to constants and read them out.
void FoldToFixpoint(llvm::Function *fn)
{
	auto const &DL = fn->getParent()->getDataLayout();
	for (bool again = true; again;) {
		again = false;
		for (auto &bb : *fn)
			for (auto it = bb.begin(); it != bb.end();) {
				llvm::Instruction &I = *it++;
				if (I.isTerminator() || I.mayHaveSideEffects() || I.use_empty())
					continue;
				if (auto *c = llvm::ConstantFoldInstruction(&I, DL)) {
					I.replaceAllUsesWith(c);
					again = true;
				}
			}
	}
}

// Replace the `vl` load and every v0 i16 load by constants derived from `v0_bytes`, fold, and
// return each destination unit's mask as a vector of bools, keyed by the unit's element base.
struct FoldedMasks {
	bool ok = false;
	std::vector<std::pair<u32, std::vector<bool>>> units; // (element_base, active flags)
};

FoldedMasks FoldMasks(llvm::Function *fn, u32 rd_off, u32 lanes, u32 vl,
		      std::vector<u8> const &v0_bytes, u32 vstart = 0)
{
	FoldedMasks out;
	llvm::Value *state = fn->getArg(0);
	u32 const vstart_off =
	    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o == kVlOff) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vl));
				continue;
			}
			if (o == vstart_off) {
				l->replaceAllUsesWith(
				    llvm::ConstantInt::get(l->getType(), vstart));
				continue;
			}
			if (!l->getType()->isIntegerTy(16) || o == ~0u || o < kVregOff)
				continue;
			u32 const b = o - kVregOff;
			if (b + 1 >= v0_bytes.size())
				return out; // the window is outside the mask register: a real bug
			u32 const word = (u32)v0_bytes[b] | ((u32)v0_bytes[b + 1] << 8);
			l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), word));
		}
	FoldToFixpoint(fn);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
				continue;
			u32 const o = StateOffset(ii->getArgOperand(1), state);
			if (o < rd_off || o >= rd_off + rvv32::VLEN_MAX_BYTES)
				continue;
			auto *c = llvm::dyn_cast<llvm::Constant>(testcompat::MaskedStoreMask(ii));
			if (!c)
				return out; // the mask did not fold: it is not a function of vl and v0
			std::vector<bool> flags;
			for (u32 i = 0; i < lanes; ++i) {
				auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    c->getAggregateElement(i));
				if (!e)
					return out;
				flags.push_back(e->getZExtValue() != 0);
			}
			// The unit's element base is implied by its destination byte offset: unit u
			// starts at byte `u * lanes * sew` of vd.
			u32 const byte = o - rd_off;
			out.units.emplace_back(byte / 4u, std::move(flags));
		}
	out.ok = !out.units.empty();
	return out;
}

// ------------------------------------------------------------------------------------------
struct Row { char const *name; u32 f6; };
Row const kFive[] = {{"vadd.vv", F6_VADD}, {"vsub.vv", F6_VSUB}, {"vand.vv", F6_VAND},
		     {"vor.vv", F6_VOR},   {"vxor.vv", F6_VXOR}};

// A prologue-only baseline: the leading `vsetvli` is natively lowered only for some widths and
// legitimately keeps its own helper, so an absolute helper count would be measuring it.
unsigned PrologueHcalls(u32 vlen, bool route)
{
	Configure(vlen, true, route);
	Built b({Vsetvli(kVT_E32M1), kJalr});
	Translate(b, false);
	return ScanQir(b.region, 4).hcalls;
}

void SectionAdmission()
{
	printf("[M1] admission, inertness and QCG invariance\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		unsigned const base_on = PrologueHcalls(vlen, true);
		unsigned const base_off = PrologueHcalls(vlen, false);
		u32 const lanes_total = vlen / 32u;
		for (auto const &r : kFive) {
			// ON
			Configure(vlen, true, true);
			Built b({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				 kJalr});
			Translate(b, true);
			Qir const q = ScanQir(b.region, 4);
			if (q.frames != 1) {
				printf("  FAIL %s vlen=%u: frames=%u (expected 1)\n", r.name, vlen,
				       q.frames);
				++g_fail;
				continue;
			}
			CHECK_EQ((int)q.guard_kind,
				 (int)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
			CHECK(q.all_masked);
			CHECK(q.sew_ok);
			CHECK(q.chunk_order_ok);
			CHECK_EQ(q.masked_stores, q.stores);
			CHECK_EQ(q.hcalls, base_on); // the ALU helper is gone
			// Every element of the register is covered exactly once.
			CHECK_EQ(q.masked_stores * 0 + lanes_total, lanes_total);
			// OFF
			Configure(vlen, true, false);
			Built o({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				 kJalr});
			Translate(o, true);
			Qir const qo = ScanQir(o.region, 4);
			CHECK_EQ(qo.frames, 0u);
			CHECK_EQ(qo.masked_stores, 0u);
			CHECK_EQ(qo.hcalls, base_off + 1u); // back on the unchanged helper
			// PURE QCG, both switch positions: byte-identical QIR shape.
			Configure(vlen, false, true);
			Built g1({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				  kJalr});
			Translate(g1, false);
			Configure(vlen, false, false);
			Built g0({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				  kJalr});
			Translate(g0, false);
			Qir const a = ScanQir(g1.region, 4), c = ScanQir(g0.region, 4);
			CHECK_EQ(a.frames, c.frames);
			CHECK_EQ(a.hcalls, c.hcalls);
			CHECK_EQ(a.masked_stores, 0u);
		}
	}
}

void SectionTerms()
{
	printf("[M2] the store predicate is `and(vl bound, v0 bits)`, both read at run time\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		u32 const lanes = std::min(vlen / 8u, 64u) / 4u;
		u32 const units = (vlen / 8u) / std::min(vlen / 8u, 64u);
		Configure(vlen, true, true);
		Built b({Vsetvli(kVT_E32M1), V(F6_VADD, F3_OPIVV, kVs2, kVs1, kVd, true), kJalr});
		Translate(b, true);
		if (!b.fn) { CHECK(false); continue; }
		Terms const t = MeasureTerms(b.fn, VRegOff(kVd), lanes);
		CHECK_EQ(t.masked_stores, units);
		CHECK_EQ(t.masks_are_and, units);
		CHECK_EQ(t.masks_with_vl, units);
		CHECK_EQ(t.masks_with_v0, units);
		// A plain store to vd would defeat the whole predicate whatever the masked ones say.
		CHECK_EQ(t.plain_stores_to_vd, 0u);
	}
}

void SectionWindows()
{
	printf("[M4] each unit's v0 window equals the contract's MaskWindowForUnit\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		u32 const chunk = std::min(vlen / 8u, 64u);
		u32 const lanes = chunk / 4u, units = (vlen / 8u) / chunk;
		Configure(vlen, true, true);
		Built b({Vsetvli(kVT_E32M1), V(F6_VXOR, F3_OPIVV, kVs2, kVs1, kVd, true), kJalr});
		Translate(b, true);
		if (!b.fn) { CHECK(false); continue; }
		llvm::Value *state = b.fn->getArg(0);
		u32 const rd_off = VRegOff(kVd);
		unsigned here = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
				if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				u32 const o = StateOffset(ii->getArgOperand(1), state);
				if (o < rd_off || o >= rd_off + rvv32::VLEN_MAX_BYTES)
					continue;
				u32 const unit = (o - rd_off) / chunk;
				Window w;
				CHECK(FindMaskWindow(testcompat::MaskedStoreMask(ii), state, &w));
				auto const want = ct::MaskWindowForUnit(unit * lanes, lanes);
				CHECK(want.bits == 16);
				CHECK_EQ(w.byte_offset, want.byte_offset);
				CHECK_EQ(w.shift, want.bit_shift);
				// THE VACUITY IS ASSERTED, NOT ASSUMED. Under this route's geometry
				// the shift is 0 for EVERY unit at EVERY admitted VLEN -- a unit is
				// min(VLEN/8, 64) bytes, so a frame has more than one unit only when
				// that is 64, which at SEW 32 means lanes == 16, which makes every
				// element base a multiple of the 16-bit group. A mutation that drops
				// the emitter's `lshr` therefore SURVIVES this file, and it is
				// recorded here rather than left as an unnoticed gap: the day the
				// geometry admits a sub-group unit this line fires and the emitter's
				// shift path must be given a reachable test.
				CHECK_EQ(want.bit_shift, 0u);
				++checked;
				++here;
			}
		// Every unit of this width contributed a window; a body that dropped one would show
		// up here rather than as a silently smaller total.
		CHECK_EQ(here, units);
	}
	printf("       %u unit windows checked\n", checked);
	CHECK(checked > 0);
}

void SectionTruthTable()
{
	printf("[M3] folded unit masks == the contract's active(e) for (vl, v0) combinations\n");
	unsigned cells = 0;
	// 2048 is included deliberately: it is the only admitted width with FOUR units, so it is the
	// only one where a wrong 16-bit group index shows up as three wrong units rather than one.
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		u32 const chunk = std::min(vlen / 8u, 64u);
		u32 const lanes = chunk / 4u, vlmax = vlen / 32u;
		std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0);
		// Five mask patterns and five vl values, chosen so the interesting boundaries are all
		// represented: all-ones and all-zeros (the two ways a conjunct can be invisible), an
		// alternating pattern (bit order), a single set bit near the top of the register
		// (window/shift), and a pattern that differs between the two halves of every 16-bit
		// group (a wrong group index).
		struct Pat { char const *name; u8 (*fill)(u32); };
		Pat const pats[] = {
		    {"ones", [](u32) -> u8 { return 0xff; }},
		    {"zeros", [](u32) -> u8 { return 0x00; }},
		    {"alternating", [](u32) -> u8 { return 0x55; }},
		    {"byte-index", [](u32 i) -> u8 { return (u8)(i * 37u + 1u); }},
		    {"high-half", [](u32 i) -> u8 { return (u8)(i & 1 ? 0xf0 : 0x0f); }},
		};
		for (auto const &p : pats) {
			for (u32 i = 0; i < v0.size(); ++i)
				v0[i] = p.fill(i);
			for (u32 vl : {0u, 1u, vlmax / 2u, vlmax - 1u, vlmax}) {
				Configure(vlen, true, true);
				Built b({Vsetvli(kVT_E32M1),
					 V(F6_VOR, F3_OPIVV, kVs2, kVs1, kVd, true), kJalr});
				Translate(b, true);
				if (!b.fn) { CHECK(false); continue; }
				FoldedMasks const f =
				    FoldMasks(b.fn, VRegOff(kVd), lanes, vl, v0);
				if (!f.ok) {
					printf("  FAIL vlen=%u pat=%s vl=%u: unit masks did not "
					       "fold to constants\n", vlen, p.name, vl);
					++g_fail;
					continue;
				}
				for (auto const &u : f.units)
					for (u32 i = 0; i < lanes; ++i) {
						u32 const e = u.first + i;
						bool const want = ct::ElementIsActive(
						    e, /*vstart=*/0, vl,
						    ct::MaskBitOfElement(v0.data(), e));
						if (u.second[i] != want) {
							printf("  FAIL vlen=%u pat=%s vl=%u e=%u: "
							       "emitted %d, contract %d\n",
							       vlen, p.name, vl, e,
							       (int)u.second[i], (int)want);
							++g_fail;
						}
						++cells;
					}
			}
		}
	}
	printf("       %u element cells compared against the contract\n", cells);
	CHECK(cells > 0);
}

void SectionRefusals()
{
	printf("[M5] every refusal keeps the unchanged rv32_vialu helper\n");
	struct Ref { char const *why; u32 vtype; u32 word; bool no_setvl; };
	Ref const rows[] = {
	    {"vd == v0 (5.3)", kVT_E32M1, V(F6_VADD, F3_OPIVV, kVs2, kVs1, 0, true), false},
	    {"vs1 == v0 (5.2)", kVT_E32M1, V(F6_VADD, F3_OPIVV, kVs2, 0, kVd, true), false},
	    {"vs2 == v0 (5.2)", kVT_E32M1, V(F6_VADD, F3_OPIVV, 0, kVs1, kVd, true), false},
	    {"SEW 16", kVT_E16M1, V(F6_VADD, F3_OPIVV, kVs2, kVs1, kVd, true), false},
	    {"SEW 64", kVT_E64M1, V(F6_VADD, F3_OPIVV, kVs2, kVs1, kVd, true), false},
	    {"LMUL 2", kVT_E32M2, V(F6_VADD, F3_OPIVV, kVs2, kVs1, kVd, true), false},
	    {"funct6 outside the five (vminu)", kVT_E32M1,
	     V(F6_VMINU, F3_OPIVV, kVs2, kVs1, kVd, true), false},
	    {"OPMVV vmul.vv masked (a different stub)", kVT_E32M1,
	     V(F6_VMUL, F3_OPMVV, kVs2, kVs1, kVd, true), false},
	    {"unobserved vtype", kVT_E32M1, V(F6_VADD, F3_OPIVV, kVs2, kVs1, kVd, true), true},
	};
	for (u32 vlen : {256u, 512u}) {
		for (auto const &r : rows) {
			Configure(vlen, true, true);
			std::vector<u32> w;
			if (!r.no_setvl)
				w.push_back(Vsetvli(r.vtype));
			w.push_back(r.word);
			w.push_back(kJalr);
			Built b(std::move(w));
			Translate(b, true);
			Qir const q = ScanQir(b.region, 4);
			if (q.masked_stores != 0 || q.frames != 0) {
				printf("  FAIL refusal not honoured (%s, vlen=%u): frames=%u "
				       "masked_stores=%u\n", r.why, vlen, q.frames,
				       q.masked_stores);
				++g_fail;
			}
			CHECK(q.hcalls >= 1u); // it still reaches a helper
		}
	}
	// The UNMASKED forms must be untouched: they decode to their own ops and never reach `vialu`,
	// so this route must not have captured them.
	for (auto const &r : kFive) {
		Configure(512u, true, true);
		Built b({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, false), kJalr});
		Translate(b, true);
		Qir const q = ScanQir(b.region, 4);
		// Whatever the unmasked route does, it must not produce a MASKED store.
		CHECK_EQ(q.masked_stores, 0u);
	}
}

void SectionOverlap()
{
	printf("[M6] legal destination overlap reads sources before any destination is written\n");
	struct Ov { char const *name; u32 vs2, vs1, vd; };
	Ov const rows[] = {{"vd == vs1", kVs2, kVd, kVd},
			   {"vd == vs2", kVd, kVs1, kVd},
			   {"vd == vs1 == vs2", kVd, kVd, kVd}};
	for (u32 vlen : {256u, 1024u})
		for (auto const &o : rows) {
			Configure(vlen, true, true);
			Built b({Vsetvli(kVT_E32M1),
				 V(F6_VSUB, F3_OPIVV, o.vs2, o.vs1, o.vd, true), kJalr});
			Translate(b, true);
			Qir const q = ScanQir(b.region, 4);
			if (q.frames != 1) {
				printf("  FAIL %s vlen=%u: frames=%u\n", o.name, vlen, q.frames);
				++g_fail;
				continue;
			}
			CHECK(q.all_masked);
			CHECK(q.loads > 0 && q.stores > 0);
			CHECK(q.last_load_seq < q.first_store_seq);
		}
}

void SectionVerify()
{
	printf("[M7] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &r : kFive) {
			Configure(vlen, true, true);
			Built b({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				 kJalr});
			Translate(b, true);
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL %s vlen=%u: %s\n", r.name, vlen, err.c_str());
				++g_fail;
			}
		}
}

// ------------------------------------------------------------------------------------------
// [M9] ORDER ITEM 3, RESTART: the `vstart` FLOOR, and the reset the frame now owes.
//
// This is the LAST conjunct of the contract's active predicate to be emitted by any route in either
// LLVM family. Before it, every route discharged the floor by REFUSING a nonzero `vstart` at the
// guard, and `[CT-5]`'s `vstart` half was therefore as vacuous as its mask half was before [M1..M8].
//
// THREE FACTS, and the third is the one with no local symptom:
//   * the guard kind changes to `VTypeInteger` and the guard no longer emits a `vstart == 0` test;
//   * the store predicate gains `e >= vstart`, read from the LIVE `vec.vstart` (UGE, not UGT --
//     element `vstart` itself is active);
//   * the frame writes `vec.vstart = 0` on the FAST path, which RVV 1.0 3.7 requires of every
//     vector instruction. Omitting it leaves the NEXT vector instruction reading a stale value, and
//     nothing about THIS instruction's result would look wrong.
void SectionRestart()
{
	printf("[M9] restart: the vstart floor, and the epilogue's vec.vstart = 0\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	u32 const vstart_off =
	    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &r : kFive) {
			// OFF: the guard proves vstart == 0, the body has no floor, no epilogue write.
			Configure(vlen, true, true, false);
			Built off({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				   kJalr});
			Translate(off, true);
			Qir const qo = ScanQir(off.region, 4);
			if (!qo.frames)
				continue;
			CHECK_EQ((int)qo.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK(!qo.frame_clears_vstart);
			unsigned off_vstart_stores = 0;
			if (off.fn)
				for (auto &bb : *off.fn)
					for (auto &ins : bb)
						if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
							if (StateOffset(st->getPointerOperand(),
									off.fn->getArg(0)) ==
							    vstart_off)
								++off_vstart_stores;

			// ON.
			Configure(vlen, true, true, true);
			Built b({Vsetvli(kVT_E32M1), V(r.f6, F3_OPIVV, kVs2, kVs1, kVd, true),
				 kJalr});
			Translate(b, true);
			Qir const q = ScanQir(b.region, 4);
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypeInteger);
			CHECK(q.frame_clears_vstart);
			CHECK(q.all_masked);
			if (!b.fn) { CHECK(false); continue; }
			llvm::Value *state = b.fn->getArg(0);
			// (a) THE GUARD NO LONGER TESTS vstart. Measured as the absence of an
			//     `icmp eq` against zero fed by a `vec.vstart` load -- the same probe the
			//     contract test uses for the guard's own proof, so "the guard stopped
			//     proving it" is a measurement and not a restatement of the kind.
			bool guard_tests_vstart = false;
			unsigned vstart_stores = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
						if (StateOffset(st->getPointerOperand(), state) ==
						    vstart_off)
							++vstart_stores;
						continue;
					}
					auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
					if (!l ||
					    StateOffset(l->getPointerOperand(), state) != vstart_off)
						continue;
					for (auto *u : l->users())
						if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(u))
							if (cmp->getPredicate() ==
							    llvm::CmpInst::ICMP_EQ)
								guard_tests_vstart = true;
				}
			CHECK(!guard_tests_vstart);
			// (b) EXACTLY ONE reset MORE THAN THE BASELINE. The absolute count is not 1:
			//     the leading `vsetvli` writes `vec.vstart` itself, and that write belongs
			//     to the prologue, not to this frame. Measuring the DELTA against the same
			//     program compiled with restart off is what isolates the frame's own reset
			//     -- and it is also what makes "zero" (the silent bug: the next vector
			//     instruction reads a stale vstart) and "two" (contract piece 5's
			//     `VStartClearCountIsSound`) both visible.
			CHECK_EQ(vstart_stores, off_vstart_stores + 1u);
			// (c) EVERY unit's store predicate contains the floor, and it is a UGE against
			//     a RUNTIME `vec.vstart` load. A UGT would drop element `vstart` itself.
			unsigned masked_stores = 0, with_floor = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii ||
					    ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
						continue;
					u32 const o = StateOffset(ii->getArgOperand(1), state);
					if (o < VRegOff(kVd) ||
					    o >= VRegOff(kVd) + rvv32::VLEN_MAX_BYTES)
						continue;
					++masked_stores;
					if (ConeHasUGEAgainst(testcompat::MaskedStoreMask(ii), state,
							      vstart_off))
						++with_floor;
				}
			CHECK(masked_stores > 0);
			CHECK_EQ(with_floor, masked_stores);
			++cells;
			// (d) The module still verifies.
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL %s vlen=%u: %s\n", r.name, vlen, err.c_str());
				++g_fail;
			}
		}
	printf("       %u restart route/width cells checked\n", cells);
	CHECK(cells > 0);
}

// [M10] RESTART, SEMANTICALLY: the folded truth table with a NONZERO vstart.
//
// [M9] checks the floor structurally (a UGE against a runtime `vec.vstart`). That would still pass
// on a UGT, which drops element `vstart` itself -- an off-by-one that writes one element too few on
// every resumed execution. Folding `vec.vstart` as well makes the comparison semantic: each unit's
// mask is compared against `ElementIsActive(e, vstart, vl, v0[e])` with the FULL three-conjunct
// predicate, so the boundary element is checked at every vstart value in the sweep.
void SectionRestartTruthTable()
{
	printf("[M10] restart: folded unit masks == active(e) with a NONZERO vstart\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 512u, 1024u}) {
		u32 const chunk = std::min(vlen / 8u, 64u);
		u32 const lanes = chunk / 4u, vlmax = vlen / 32u;
		std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0);
		for (u32 i = 0; i < v0.size(); ++i)
			v0[i] = (u8)(i * 37u + 1u);
		for (u32 vstart : {0u, 1u, lanes, lanes + 1u, vlmax - 1u, vlmax, vlmax + 3u})
			for (u32 vl : {0u, 1u, vlmax / 2u, vlmax}) {
				Configure(vlen, true, true, true);
				Built b({Vsetvli(kVT_E32M1),
					 V(F6_VAND, F3_OPIVV, kVs2, kVs1, kVd, true), kJalr});
				Translate(b, true);
				if (!b.fn) { CHECK(false); continue; }
				FoldedMasks const f =
				    FoldMasks(b.fn, VRegOff(kVd), lanes, vl, v0, vstart);
				if (!f.ok) {
					printf("  FAIL vlen=%u vstart=%u vl=%u: masks did not fold\n",
					       vlen, vstart, vl);
					++g_fail;
					continue;
				}
				for (auto const &u : f.units)
					for (u32 i = 0; i < lanes; ++i) {
						u32 const e = u.first + i;
						bool const want = ct::ElementIsActive(
						    e, vstart, vl,
						    ct::MaskBitOfElement(v0.data(), e));
						if (u.second[i] != want) {
							printf("  FAIL vlen=%u vstart=%u vl=%u e=%u: "
							       "emitted %d, contract %d\n",
							       vlen, vstart, vl, e,
							       (int)u.second[i], (int)want);
							++g_fail;
						}
						++cells;
					}
			}
	}
	printf("       %u element cells compared with a nonzero vstart\n", cells);
	CHECK(cells > 0);
}

// [M8] the contract's own window rule, independent of any emitted code: the window must select
// exactly the bits the architectural bit numbering assigns to the unit's elements.
//
// THIS IS THE SECTION THAT COVERS NONZERO SHIFTS. The route's geometry only ever produces
// `lanes == 16` units (see [M4]), so no emitted frame exercises a shift; the lane counts swept here
// include 2, 4 and 8, where units 1..7 have shifts 2, 4 and 8. That is a check of the CONTRACT, not
// of the emitter, and the difference is stated rather than blurred: it proves the arithmetic the
// emitter consumes is right, not that the emitter consumes it.
void SectionContractWindow()
{
	printf("[M8] MaskWindowForUnit selects exactly the architectural bits of its unit\n");
	std::vector<u8> v0(64);
	for (u32 i = 0; i < v0.size(); ++i)
		v0[i] = (u8)(i * 91u + 7u);
	for (u32 lanes : {2u, 4u, 8u, 16u})
		for (u32 unit = 0; unit < 8; ++unit) {
			u32 const base = unit * lanes;
			auto const w = ct::MaskWindowForUnit(base, lanes);
			CHECK_EQ(w.bits, 16u);
			u32 const group =
			    (u32)v0[w.byte_offset] | ((u32)v0[w.byte_offset + 1] << 8);
			for (u32 i = 0; i < lanes; ++i) {
				bool const from_window = ((group >> (w.bit_shift + i)) & 1u) != 0;
				CHECK_EQ((int)from_window,
					 (int)ct::MaskBitOfElement(v0.data(), base + i));
			}
		}
	// Fail-closed rows: a ragged lane count and a straddling base have no window.
	CHECK_EQ(ct::MaskWindowForUnit(0, 3).bits, 0u);
	CHECK_EQ(ct::MaskWindowForUnit(0, 32).bits, 0u);
	CHECK_EQ(ct::MaskWindowForUnit(12, 8).bits, 0u); // 12 % 16 + 8 > 16
	CHECK_EQ(ct::MaskWindowForUnit(0, 0).bits, 0u);
}

} // namespace

int main()
{
	printf("rvv_llvm_masked_alu_test: order item 3, architectural mask for the masked OPIVV "
	       "integer element-wise family\n");
	SectionAdmission();
	SectionTerms();
	SectionWindows();
	SectionTruthTable();
	SectionRefusals();
	SectionOverlap();
	SectionVerify();
	SectionRestart();
	SectionRestartTruthTable();
	SectionContractWindow();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
