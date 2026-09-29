// ORDER ITEM 3 (2026-09-19): FP PREDICATION -- the architectural mask for the LLVM typed FP lane
// family (`vfadd`/`vfsub`/`vfmul`/`vfdiv`, `.vv` and `.vf`), under `--rvv-llvm-fp-masked`.
//
// WHY THIS IS NOT THE INTEGER ROUTE WITH A DIFFERENT OPCODE. For the integer family a predicated
// destination store is the WHOLE of masking: the lane operations raise nothing, so computing an
// element the instruction must not write is unobservable. That argument does not carry here.
// `RvvFpBracketCloseBody` executes `stmxcsr` and ORs the host sticky bits into the guest `fcsr`, so
// a masked-off lane that raised OF/UF/NX/NV WHILE BEING COMPUTED becomes architecturally visible
// even though its result never reaches guest state. The mask therefore has to reach the OPERANDS,
// not just the commit.
//
// SECTIONS, and the failure each exists to catch:
//
//   [F1] Admission and the guard kind. A masked frame must take the PARTIAL FP kind
//        (`VTypePartialVlVstartFrmRNE`): pairing a masked body with the full-VL kind would be legal
//        for the store, which carries its own predicate, and WRONG for the flags, because the body
//        neutralises only when the frame does not prove full VL or the node is masked. Off is inert.
//
//        THIS SECTION IS WHAT MAKES ONE EMITTER TERM UNREACHABLE, and the relationship is worth
//        naming because it decides where the coverage actually lives. Because every masked frame
//        takes the partial kind, `tchunk_full_vl` is already false whenever the node is masked, so
//        `Emit_vchunkfalu`'s `|| ins->masked` is redundant and a mutation that deletes it SURVIVES
//        this file. The fact that keeps the body correct is the guard kind asserted here -- and a
//        mutation that gives a masked frame the full-VL kind fails 60 cells of this section.
//
//   [F2] THE MASK REACHES THE OPERANDS. Both operands of the constrained FP call are selects, and
//        their condition is a value that depends on a v0 read. A test that checked only the masked
//        store would pass on a body that published correctly and still raised a flag for a
//        masked-off lane -- which is the entire failure mode this route exists to avoid.
//
//   [F3] IT IS THE **SAME** MASK VALUE. The select's condition and the masked store's mask operand
//        are required to be the identical `llvm::Value *`. Two separately derived predicates that
//        agree today are exactly how an element comes to be suppressed in one and computed in the
//        other after a later edit; identity is checkable, agreement is not.
//
//   [F4] THE TRUTH TABLE, folded. `vec.vl`, the v0 mask word and the source chunks are replaced by
//        constants and the module folded, so each operand collapses to a constant vector whose
//        inactive lanes must be exactly +1.0 and whose active lanes must be the source value --
//        compared element by element against `rvvcontract::ElementIsActive(e, 0, vl, v0[e])`.
//        This is the section that can see a wrong bit order, a wrong shift, a wrong element base,
//        or a neutralisation predicated on `vl` alone.
//
//   [F5] Refusals keep the unchanged `rv32_vfalu` helper: a funct6 outside {vfadd, vfsub, vfmul,
//        vfdiv}, and the switch off.
//
//   [F6] The module verifies.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds, so it cannot observe MXCSR. The
// claim "an inactive lane raises nothing" rests on the neutral VALUE being +1.0 -- which [F4]
// checks exactly -- plus the arithmetic fact that `(+1) op (+1)` is exact for all four operations.
// A runtime `fflags` differential is outstanding and is not claimed here.

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

// The generator's own context; a fresh one makes `verifyModule` reject every module. See the same
// note in rvv_llvm_masked_alu_test.cpp.
llvm::LLVMContext &g_ctx = dbt::qir::g_llvm_ctx;

constexpr u32 F6_VFADD = 0u, F6_VFSUB = 2u, F6_VFMUL = 0b100100u, F6_VFDIV = 0b100000u;
constexpr u32 F6_VFMIN = 0b000100u; // admitted by no LLVM FP route: one arithmetic op it is not
constexpr u32 OpF(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool masked)
{
	return (f6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 F3_OPFVV = 0b001u, F3_OPFVF = 0b101u;
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVs2 = 8u, kVs1 = 9u, kVd = 10u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi3fp", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool fp_masked)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_llvm_fp_masked = fp_masked;
	// Explicitly OFF: a masked frame must take the partial guard kind and neutralise on its own
	// account. With this on, every check below would still pass and the dependency would go
	// unrecorded.
	config::rvv_llvm_fp_partial_vl = false;
	config::rvv_llvm_masked = false;
	config::rvv_llvm_partial_vl = false;
	config::rvv_qcg_typed_chunk = !llvm_backend;
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
	unsigned frames = 0, falu = 0, hcalls = 0, stores = 0, masked_stores = 0;
	bool all_nodes_masked = true;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				break;
			case Op::_vchunkfalu: {
				auto *n = static_cast<InstVChunkFALU *>(&ins);
				++q.falu;
				if (!n->masked)
					q.all_nodes_masked = false;
				break;
			}
			case Op::_vstatechunkstore: {
				auto *s = static_cast<InstVStateChunkStore *>(&ins);
				++q.stores;
				if (s->masked && s->active_sew)
					++q.masked_stores;
				break;
			}
			case Op::_hcall: ++q.hcalls; break;
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

bool IsConstrainedFP(llvm::IntrinsicInst *ii)
{
	switch (ii->getIntrinsicID()) {
	case llvm::Intrinsic::experimental_constrained_fadd:
	case llvm::Intrinsic::experimental_constrained_fsub:
	case llvm::Intrinsic::experimental_constrained_fmul:
	case llvm::Intrinsic::experimental_constrained_fdiv:
		return true;
	default:
		return false;
	}
}

struct FpFacts {
	unsigned calls = 0;
	unsigned operands_are_selects = 0;
	unsigned select_conds_read_v0 = 0;
	unsigned select_conds_read_vl = 0;
	unsigned masked_stores = 0;
	unsigned select_cond_equals_store_mask = 0;
	unsigned plain_stores_to_vd = 0;
};

// [F2]/[F3]: the operands' select condition, and whether it IS the store's mask.
FpFacts MeasureFp(llvm::Function *fn, u32 rd_off)
{
	FpFacts f;
	llvm::Value *state = fn->getArg(0);
	std::vector<llvm::Value *> store_masks;
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
					u32 const o = StateOffset(ii->getArgOperand(1), state);
					if (o >= rd_off && o < rd_off + rvv32::VLEN_MAX_BYTES) {
						++f.masked_stores;
						store_masks.push_back(testcompat::MaskedStoreMask(ii));
					}
				}
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				u32 const o = StateOffset(st->getPointerOperand(), state);
				if (o >= rd_off && o < rd_off + rvv32::VLEN_MAX_BYTES)
					++f.plain_stores_to_vd;
				continue;
			}
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii || !IsConstrainedFP(ii))
				continue;
			++f.calls;
			bool both_selects = true;
			for (unsigned a = 0; a < 2; ++a) {
				auto *sel = llvm::dyn_cast<llvm::SelectInst>(ii->getArgOperand(a));
				if (!sel) {
					both_selects = false;
					continue;
				}
				llvm::Value *cond = sel->getCondition();
				if (ConeHasStateLoad(cond, state, kVregOff,
						     kVregOff + rvv32::VLEN_MAX_BYTES, 16))
					++f.select_conds_read_v0;
				if (ConeHasStateLoad(cond, state, kVlOff, kVlOff + 4u, 32))
					++f.select_conds_read_vl;
				for (auto *m : store_masks)
					if (m == cond) {
						++f.select_cond_equals_store_mask;
						break;
					}
			}
			if (both_selects)
				++f.operands_are_selects;
		}
	return f;
}

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

// ------------------------------------------------------------------------------------------
void SectionAdmission()
{
	printf("[F1] masked vfalu is admitted, takes the PARTIAL FP guard kind, and is inert off\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Row { char const *name; u32 f6; u32 f3; };
	Row const rows[] = {
	    {"vfadd.vv", F6_VFADD, F3_OPFVV}, {"vfsub.vv", F6_VFSUB, F3_OPFVV},
	    {"vfmul.vv", F6_VFMUL, F3_OPFVV}, {"vfdiv.vv", F6_VFDIV, F3_OPFVV},
	    {"vfadd.vf", F6_VFADD, F3_OPFVF}, {"vfmul.vf", F6_VFMUL, F3_OPFVF},
	};
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1})
			for (auto const &r : rows) {
				Configure(vlen, true, true);
				Built b({Vsetvli(vt), OpF(r.f6, r.f3, kVs2, kVs1, kVd, true), kJalr});
				Translate(b, true);
				Qir const q = ScanQir(b.region);
				if (!q.falu)
					continue; // this width/SEW is not in the route's envelope
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
				CHECK(q.all_nodes_masked);
				CHECK_EQ(q.masked_stores, q.stores);
				// OFF: back on the unchanged helper, no frame.
				Configure(vlen, true, false);
				Built o({Vsetvli(vt), OpF(r.f6, r.f3, kVs2, kVs1, kVd, true), kJalr});
				Translate(o, true);
				Qir const qo = ScanQir(o.region);
				CHECK_EQ(qo.falu, 0u);
				CHECK_EQ(qo.masked_stores, 0u);
				CHECK(qo.hcalls >= 1u);
			}
	printf("       %u admitted route/width/SEW cells\n", admitted);
	CHECK(admitted > 0);
}

void SectionOperandsArePredicated()
{
	printf("[F2/F3] the mask reaches the OPERANDS, and it is the SAME value as the store's\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vt : {kVT_E32M1, kVT_E64M1}) {
			Configure(vlen, true, true);
			Built b({Vsetvli(vt), OpF(F6_VFDIV, F3_OPFVV, kVs2, kVs1, kVd, true), kJalr});
			Translate(b, true);
			Qir const q = ScanQir(b.region);
			if (!q.falu || !b.fn)
				continue;
			++cells;
			FpFacts const f = MeasureFp(b.fn, VRegOff(kVd));
			CHECK_EQ(f.calls, q.falu);
			// BOTH operands of every call are neutralising selects.
			CHECK_EQ(f.operands_are_selects, f.calls);
			// Each of those 2 * calls conditions reads v0 AND vl ...
			CHECK_EQ(f.select_conds_read_v0, 2u * f.calls);
			CHECK_EQ(f.select_conds_read_vl, 2u * f.calls);
			// ... and IS one of the destination masked stores' mask operands.
			CHECK_EQ(f.select_cond_equals_store_mask, 2u * f.calls);
			CHECK_EQ(f.masked_stores, q.stores);
			CHECK_EQ(f.plain_stores_to_vd, 0u);
		}
	printf("       %u route/width/SEW cells checked\n", cells);
	CHECK(cells > 0);
}

void SectionTruthTable()
{
	printf("[F4] folded operands: inactive lanes are +1.0 exactly, per the contract's active(e)\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		u32 const chunk = std::min(vlen / 8u, 64u);
		u32 const lanes = chunk / 4u, vlmax = vlen / 32u;
		std::vector<u8> v0(rvv32::VLEN_MAX_BYTES, 0);
		struct Pat { char const *name; u8 (*fill)(u32); };
		Pat const pats[] = {
		    {"ones", [](u32) -> u8 { return 0xff; }},
		    {"zeros", [](u32) -> u8 { return 0x00; }},
		    {"alternating", [](u32) -> u8 { return 0x55; }},
		    {"byte-index", [](u32 i) -> u8 { return (u8)(i * 37u + 1u); }},
		};
		for (auto const &p : pats) {
			for (u32 i = 0; i < v0.size(); ++i)
				v0[i] = p.fill(i);
			for (u32 vl : {0u, 1u, vlmax / 2u, vlmax}) {
				Configure(vlen, true, true);
				Built b({Vsetvli(kVT_E32M1),
					 OpF(F6_VFMUL, F3_OPFVV, kVs2, kVs1, kVd, true), kJalr});
				Translate(b, true);
				if (!ScanQir(b.region).falu || !b.fn)
					continue;
				llvm::Function *fn = b.fn;
				llvm::Value *state = fn->getArg(0);
				// vl and the v0 group become constants.
				for (auto &bb : *fn)
					for (auto &ins : bb) {
						auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
						if (!l)
							continue;
						u32 const o = StateOffset(l->getPointerOperand(),
									  state);
						if (o == kVlOff) {
							l->replaceAllUsesWith(
							    llvm::ConstantInt::get(l->getType(), vl));
							continue;
						}
						if (!l->getType()->isIntegerTy(16) || o == ~0u ||
						    o < kVregOff)
							continue;
						u32 const bo = o - kVregOff;
						u32 const w = (u32)v0[bo] | ((u32)v0[bo + 1] << 8);
						l->replaceAllUsesWith(
						    llvm::ConstantInt::get(l->getType(), w));
					}
				// The vs2 source chunks become a distinctive constant: 3.0f, which is
				// neither the neutral +1.0 nor zero, so a lane that was NOT neutralised
				// is distinguishable from one that was.
				for (auto &bb : *fn)
					for (auto &ins : bb) {
						auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
						if (!l)
							continue;
						u32 const o = StateOffset(l->getPointerOperand(),
									  state);
						if (o < VRegOff(kVs2) ||
						    o >= VRegOff(kVs2) + rvv32::VLEN_MAX_BYTES)
							continue;
						auto *vt2 = llvm::dyn_cast<llvm::FixedVectorType>(
						    l->getType());
						if (!vt2)
							continue;
						// THE CHUNK IS LOADED AS <N x i64>, NOT <N x i32>, so a
						// per-lane 0x40400000 would set 3.0f in the EVEN
						// 32-bit elements and +0.0 in the odd ones -- which
						// looks exactly like a neutralisation bug at every
						// odd element index. (It did, on the first run.) The
						// pattern is therefore replicated to the load's own
						// lane width.
						u32 const lane_bits =
						    vt2->getScalarSizeInBits();
						llvm::APInt pat(lane_bits, 0);
						for (u32 k = 0; k < lane_bits / 32u; ++k)
							pat |= llvm::APInt(lane_bits, 0x40400000ull)
							       << (32u * k); // 3.0f
						llvm::SmallVector<llvm::Constant *, 64> cv;
						for (u32 i = 0; i < vt2->getNumElements(); ++i)
							cv.push_back(llvm::ConstantInt::get(
							    vt2->getElementType(), pat));
						l->replaceAllUsesWith(
						    llvm::ConstantVector::get(cv));
					}
				FoldToFixpoint(fn);
				// Read every constrained call's FIRST operand (the vs2 side) as a
				// constant vector and compare lane by lane.
				unsigned unit = 0;
				for (auto &bb : *fn)
					for (auto &ins : bb) {
						auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
						if (!ii || !IsConstrainedFP(ii))
							continue;
						auto *c = llvm::dyn_cast<llvm::Constant>(
						    ii->getArgOperand(0));
						if (!c) {
							printf("  FAIL vlen=%u pat=%s vl=%u unit=%u: "
							       "operand did not fold\n",
							       vlen, p.name, vl, unit);
							++g_fail;
							++unit;
							continue;
						}
						for (u32 i = 0; i < lanes; ++i) {
							u32 const e = unit * lanes + i;
							bool const active = ct::ElementIsActive(
							    e, 0, vl,
							    ct::MaskBitOfElement(v0.data(), e));
							auto *cf = llvm::dyn_cast_or_null<
							    llvm::ConstantFP>(
							    c->getAggregateElement(i));
							if (!cf) {
								printf("  FAIL vlen=%u pat=%s vl=%u "
								       "e=%u: lane is not a "
								       "constant\n",
								       vlen, p.name, vl, e);
								++g_fail;
								continue;
							}
							double const got =
							    cf->getValueAPF().convertToDouble();
							double const want = active ? 3.0 : 1.0;
							if (got != want) {
								printf("  FAIL vlen=%u pat=%s vl=%u "
								       "e=%u: operand %g, expected "
								       "%g (active=%d)\n",
								       vlen, p.name, vl, e, got,
								       want, (int)active);
								++g_fail;
							}
							++cells;
						}
						++unit;
					}
			}
		}
	}
	printf("       %u operand lanes compared against the contract\n", cells);
	CHECK(cells > 0);
}

void SectionRefusals()
{
	printf("[F5] a funct6 outside the four arithmetic ops keeps the unchanged helper\n");
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, true, true);
		Built b({Vsetvli(kVT_E32M1), OpF(F6_VFMIN, F3_OPFVV, kVs2, kVs1, kVd, true), kJalr});
		Translate(b, true);
		Qir const q = ScanQir(b.region);
		CHECK_EQ(q.falu, 0u);
		CHECK(q.hcalls >= 1u);
	}
	// The UNMASKED form must be unchanged by this switch: with fp-partial-vl off it keeps the
	// full-VL guard kind and an UNMASKED store, exactly as before.
	using GK = InstRVVTypedChunkBegin::GuardKind;
	for (u32 vlen : {128u, 256u, 2048u}) {
		Configure(vlen, true, true);
		Built b({Vsetvli(kVT_E32M1), OpF(F6_VFADD, F3_OPFVV, kVs2, kVs1, kVd, false), kJalr});
		Translate(b, true);
		Qir const q = ScanQir(b.region);
		if (!q.falu)
			continue;
		CHECK_EQ((int)q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		CHECK_EQ(q.masked_stores, 0u);
	}
}

void SectionVerify()
{
	printf("[F6] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 f6 : {F6_VFADD, F6_VFSUB, F6_VFMUL, F6_VFDIV}) {
			Configure(vlen, true, true);
			Built b({Vsetvli(kVT_E32M1), OpF(f6, F3_OPFVV, kVs2, kVs1, kVd, true), kJalr});
			Translate(b, true);
			if (!b.fn)
				continue;
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL vlen=%u f6=%u: %s\n", vlen, f6, err.c_str());
				++g_fail;
			}
		}
}

} // namespace

int main()
{
	printf("rvv_llvm_fp_masked_test: order item 3, FP predication for the typed FP lane family\n");
	SectionAdmission();
	SectionOperandsArePredicated();
	SectionTruthTable();
	SectionRefusals();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
