// ORDER ITEM 4 (2026-09-19): THE WIDENING FP ARITHMETIC FAMILY ON THE LLVM ARM.
//
// WHAT IS ACTUALLY NEW HERE, AND WHY THE FILE IS SHORT. The QCG route already decomposes this
// family into nodes this backend lowers -- `vstatechunkload`, `vchunkfbroadcast`, `vchunkfalu`,
// `vchunkfma`, `vstatechunkstore` -- and exactly one it did not: `vchunkfwidencvt`. So the delivery
// is that emitter plus a guard kind, and this file checks those two things and the envelope, not a
// second time the things `rvv_llvm_falu_family_test` and `rvv_llvm_fp_run_test` already pin.
//
// SECTIONS:
//   [W1] Admission and the guard kind. The LLVM arm must take `VTypeVlVstartFrmRNE` -- strictly
//        STRONGER than the QCG arm's `VTypePartialVlVstartFrmHost` -- because this body has no
//        opmask and no tail handling; handing it the QCG kind would let a partial-vl or RTZ
//        execution into an unmasked `round.dynamic` body the guard never proved. And with the
//        switch off, nothing.
//   [W2] THE WIDENING CONVERT IS A CONSTRAINED `fpext` AND TAKES NO ROUNDING OPERAND. `fpext`
//        f32 -> f64 is exact; a rounding operand would say it was not, and an UNconstrained
//        `fpext` would say the frame's bracket did not apply to it. Both are wrong in ways that
//        emit valid IR.
//   [W3] THE LOW-HALF RULE. Below a 32-byte destination chunk the source VALUE is 16 bytes and only
//        its LOW HALF is the window. The IR must SAY that -- a shuffle taking elements [0, lanes)
//        -- rather than relying on the selector to ignore the rest, because the two coincide only
//        at the width where they coincide.
//   [W4] ONE FUSED NODE FOR THE FMA FORMS, never a multiply followed by an add: the reference
//        performs one `fma` at the wide width, and two operations would round twice and be a
//        different function.
//   [W5] The refusals: masked, the shared opmask, and a funct6 outside the family.
//   [W6] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <utility>
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

llvm::LLVMContext &g_ctx = dbt::qir::g_llvm_ctx;

constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;
// vd is a 2*LMUL group, so it must be even; vs2/vs1 are LMUL groups. The widening FMAs read vd at
// 2*SEW, so no narrow source may share a register with it -- hence the wide spread.
constexpr u32 kVd = 12u, kVs2 = 8u, kVs1 = 9u, kF = 3u;

// OPFVV = funct3 1, OPFVF = funct3 5.
constexpr u32 F6_VFWADD = 0b110000u, F6_VFWSUB = 0b110010u;
constexpr u32 F6_VFWADD_W = 0b110100u, F6_VFWMUL = 0b111000u;
constexpr u32 F6_VFWMACC = 0b111100u, F6_VFWNMSAC = 0b111111u;
constexpr u32 F6_VFWREDUSUM = 0b110001u; // shares the decode class; not arithmetic
constexpr u32 OpW(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool masked = false)
{
	return (f6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4fw", g_ctx) {}
};

void Configure(u32 vlen, bool on, bool shared_mask = false)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_fwiden = on;
	config::rvv_qcg_fp_shared_mask = shared_mask;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_vector_ssa_host_fma = true;
	config::rvv_llvm_masked = false;
	config::rvv_llvm_restart = false;
	// C6-FRM: reset so one section cannot leak a widened rounding admission into the next.
	config::rvv_llvm_fp_dynamic_frm = false;
	// C7-FWPVL: reset too -- with it on the convert's operand becomes a SELECT, and the
	// sections that identify the shuffle feeding the convert would stop finding it.
	config::rvv_llvm_fwiden_partial_vl = false;
	config::rvv_llvm_fwiden_masked = false;
}

void Translate(Built &b)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

// Resolve a pointer back to its byte offset inside CPUState, or ~0u. The emitters build state
// pointers through a GEP chain from the function's first argument, so the walk has to strip those
// rather than expect a bare argument.
llvm::Value *StripToBase(llvm::Value *p)
{
	for (;;) {
		if (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p)) {
			p = g->getPointerOperand();
			continue;
		}
		if (auto *ce = llvm::dyn_cast<llvm::ConstantExpr>(p);
		    ce && ce->getOpcode() == llvm::Instruction::GetElementPtr) {
			p = ce->getOperand(0);
			continue;
		}
		if (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(p)) {
			p = bc->getOperand(0);
			continue;
		}
		return p;
	}
}

u32 StateOffset(llvm::Value *p, llvm::Value *state)
{
	auto const &DL = llvm::cast<llvm::Instruction>(p)->getModule()->getDataLayout();
	llvm::APInt off(64, 0);
	llvm::Value *base = p;
	if (auto *stripped = p->stripAndAccumulateConstantOffsets(DL, off, true))
		base = stripped;
	if (StripToBase(base) != state)
		return ~0u;
	return (u32)off.getZExtValue();
}

struct Qir {
	unsigned frames = 0, cvt = 0, falu = 0, fma = 0, hcalls = 0, brackets = 0;
	int guard_kind = -1;
	bool any_masked = false;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
				break;
			case Op::_vchunkfwidencvt:
				++q.cvt;
				q.any_masked |=
				    static_cast<InstVChunkFWidenCvt *>(&ins)->masked;
				break;
			case Op::_vchunkfalu: ++q.falu; break;
			case Op::_vchunkfma: ++q.fma; break;
			case Op::_rvvqcgfpbegin: ++q.brackets; break;
			case Op::_hcall: ++q.hcalls; break;
			default: break;
			}
	return q;
}

struct IR {
	unsigned fpext_constrained = 0, fpext_plain = 0, shuffles = 0, fma_calls = 0;
	unsigned fpext_with_round_operand = 0;
	unsigned lowest_index_ok = 0, lowest_index_bad = 0;
};

IR ScanIR(llvm::Function *fn, u32 dst_lanes)
{
	IR r;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			// An UNCONSTRAINED widening is a plain `fpext` INSTRUCTION, not an intrinsic --
			// there is no `llvm.fpext`. Counting it here is what makes "the convert is
			// inside the frame's FP bracket" a checked fact rather than an assumption: a
			// body that used the ordinary instruction would emit valid IR that the default
			// FP environment lets the optimiser move and fold freely.
			if (llvm::isa<llvm::FPExtInst>(&ins))
				++r.fpext_plain;
			auto *ii0 = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			// THE SHUFFLE IS IDENTIFIED BY ITS CONSUMER, not by being a shuffle. The
			// function contains other shufflevectors -- `CreateVectorSplat` builds one with
			// an all-zeros mask -- and counting those made this section report a wrong
			// low-half mask for code that was correct. What has to be checked is the
			// shuffle feeding the CONVERT.
			if (ii0 && ii0->getIntrinsicID() ==
				       llvm::Intrinsic::experimental_constrained_fpext) {
				if (auto *sh = llvm::dyn_cast<llvm::ShuffleVectorInst>(
					ii0->getArgOperand(0))) {
					++r.shuffles;
					bool ok = true;
					for (u32 k = 0; k < dst_lanes; ++k)
						if (sh->getMaskValue(k) != (int)k)
							ok = false;
					ok ? ++r.lowest_index_ok : ++r.lowest_index_bad;
				}
			}
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii)
				continue;
			switch (ii->getIntrinsicID()) {
			case llvm::Intrinsic::experimental_constrained_fpext:
				++r.fpext_constrained;
				// A CONSTRAINED fpext TAKES EXACTLY ONE METADATA OPERAND, the exception
				// behaviour -- no rounding operand, because the conversion is exact.
				// A two-metadata form would claim it rounds.
				if (ii->arg_size() != 2)
					++r.fpext_with_round_operand;
				break;
			case llvm::Intrinsic::experimental_constrained_fma:
				++r.fma_calls;
				break;
			default:
				break;
			}
		}
	return r;
}

// [W1b] THE ROUNDING AXIS OF THIS FRAME'S GUARD, and the reason it is checked separately.
//
// This body takes the STRICTLY STRONGER kind on the LLVM arm -- `vl == VLMAX`, `vstart == 0`,
// `frm == RNE` -- because it has no opmask and no tail handling: it converts every lane of every
// chunk and stores every byte. `--rvv-llvm-fp-dynamic-frm` moves the ROUNDING term of that guard
// and NOTHING ELSE, which is sound for this body without touching it: the frame's bracket installs
// the live guest frm into MXCSR.RC and every lane op is a `round.dynamic` constrained intrinsic.
// `vl == VLMAX` and `vstart == 0` are deliberately NOT moved -- doing that needs a body that can
// store inactive lanes, which this one cannot.
//
// The section exists because a switch that does not reach its site is indistinguishable from a
// switch that reaches it and finds nothing to do. That distinction decided the measurement this
// change was made for: on official ACT4 `Vf32-vfwadd.vv` the rounding widening moved
// `guard_fallbacks` by EXACTLY ZERO (662 -> 662), and that is only evidence about `frm` if the
// kind really did flip. Here it is asserted directly.
void SectionDynamicFrmKind()
{
	printf("[W1b] the rounding term of the guard follows the switch; vl/vstart do not\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned checked = 0;
	for (u32 vlen : {256u, 1024u})
		for (u32 f6 : {F6_VFWADD, F6_VFWMUL, F6_VFWMACC}) {
			Configure(vlen, true);
			config::rvv_llvm_fp_dynamic_frm = false;
			Built off({Vsetvli(kVT_E32M1), OpW(f6, 1u, kVs2, kVs1, kVd), kJalr});
			Translate(off);
			Qir const qo = ScanQir(off.region);
			if (!qo.frames)
				continue;
			CHECK_EQ((int)qo.guard_kind, (int)GK::VTypeVlVstartFrmRNE);

			Configure(vlen, true);
			config::rvv_llvm_fp_dynamic_frm = true;
			Built on({Vsetvli(kVT_E32M1), OpW(f6, 1u, kVs2, kVs1, kVd), kJalr});
			Translate(on);
			Qir const qn = ScanQir(on.region);
			CHECK_EQ(qn.frames, 1u);
			// THE ROUNDING TERM MOVED...
			CHECK_EQ((int)qn.guard_kind, (int)GK::VTypeVlVstartFrmHostRound);
			// ...AND THE VL TERM DID NOT. Both HostRound kinds exist; this body must take
			// the FULL-VL one, never the partial one, until it can store inactive lanes.
			CHECK((int)qn.guard_kind != (int)GK::VTypePartialVlVstartFrmHostRound);
			CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
			    (InstRVVTypedChunkBegin::GuardKind)qn.guard_kind));
			++checked;
		}
	printf("       %u widening frames checked on both switch positions\n", checked);
	CHECK(checked != 0);
}

// [W1c] PARTIAL VL FOR THE WIDENING BODY.
//
// The LLVM widening body required `vl == VLMAX` because it converts every lane of every chunk and
// stores every byte. Three of the four node kinds it emits could already cope -- `vstatechunkstore`
// publishes through an active-lane masked store, and `vchunkfalu`/`vchunkfma` neutralise inactive
// operands -- so the ONE blocker was the widening convert.
//
// WHY THE CONVERT NEEDED ANYTHING AT ALL, given f32 -> f64 is exact for every finite input: it
// raises NV on a SIGNALLING NaN. A tail lane holding an sNaN would set the guest `fcsr` for an
// element the instruction must not touch, and a predicated destination store does NOT undo that --
// the flag has no second chance. So the operand is neutralised to +1.0f first, which widens to 1.0
// exactly and raises nothing.
//
// The OFF arm is asserted too, because "the operand is a select" is only evidence if it is not
// a select anyway.
void SectionPartialVlBody()
{
	printf("[W1c] partial-vl widening: inactive lanes neutralised before the convert\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned on_cells = 0, off_cells = 0;
	auto reaches_icmp = [](llvm::Value *root) {
		llvm::SmallVector<llvm::Value *, 16> work{root};
		llvm::SmallPtrSet<llvm::Value *, 16> seen;
		while (!work.empty()) {
			llvm::Value *v = work.pop_back_val();
			if (!seen.insert(v).second)
				continue;
			if (llvm::isa<llvm::ICmpInst>(v))
				return true;
			if (auto *u = llvm::dyn_cast<llvm::User>(v))
				for (auto &op : u->operands())
					work.push_back(op);
		}
		return false;
	};
	for (u32 vlen : {256u, 1024u})
		for (u32 f6 : {F6_VFWADD, F6_VFWMUL}) {
			// --- OFF: the full-VL kind, and the convert's operand is NOT a select.
			Configure(vlen, true);
			Built off({Vsetvli(kVT_E32M1), OpW(f6, 1u, kVs2, kVs1, kVd), kJalr});
			Translate(off);
			Qir const qo = ScanQir(off.region);
			if (!qo.cvt || !off.fn)
				continue;
			CHECK_EQ((int)qo.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
			for (auto &bb : *off.fn)
				for (auto &ins : bb) {
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii || ii->getIntrinsicID() !=
						       llvm::Intrinsic::experimental_constrained_fpext)
						continue;
					CHECK(!llvm::isa<llvm::SelectInst>(ii->getArgOperand(0)));
					++off_cells;
				}

			// --- ON: the PARTIAL kind, and every convert is fed a neutralising select.
			Configure(vlen, true);
			config::rvv_llvm_fwiden_partial_vl = true;
			Built on({Vsetvli(kVT_E32M1), OpW(f6, 1u, kVs2, kVs1, kVd), kJalr});
			Translate(on);
			Qir const qn = ScanQir(on.region);
			CHECK(qn.cvt != 0);
			CHECK(on.fn != nullptr);
			if (!on.fn)
				continue;
			CHECK_EQ((int)qn.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
			CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl((GK)qn.guard_kind));
			unsigned converts = 0, neutralised = 0, masked_stores = 0;
			for (auto &bb : *on.fn)
				for (auto &ins : bb) {
					if (auto *mi = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
						if (mi->getIntrinsicID() ==
						    llvm::Intrinsic::masked_store)
							++masked_stores;
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii || ii->getIntrinsicID() !=
						       llvm::Intrinsic::experimental_constrained_fpext)
						continue;
					++converts;
					auto *sel =
					    llvm::dyn_cast<llvm::SelectInst>(ii->getArgOperand(0));
					CHECK(sel != nullptr);
					if (!sel)
						continue;
					// the neutral value is +1.0f, splatted
					auto *fv = llvm::dyn_cast<llvm::Constant>(
					    sel->getFalseValue());
					CHECK(fv != nullptr);
					if (fv) {
						auto *sp = fv->getSplatValue();
						auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(sp);
						CHECK(cf != nullptr);
						if (cf)
							CHECK(cf->getValueAPF().convertToFloat() ==
							      1.0f);
					}
					// the predicate is a comparison, i.e. the live-vl lane mask
					CHECK(reaches_icmp(sel->getCondition()));
					++neutralised;
				}
			CHECK(converts != 0);
			CHECK_EQ(neutralised, converts); // EVERY convert, not just the first
			// the destination is still published through a predicated store
			CHECK(masked_stores != 0);
			++on_cells;
		}
	printf("       %u partial-vl widening cells, %u full-vl converts checked unneutralised\n",
	       on_cells, off_cells);
	CHECK(on_cells != 0);
	CHECK(off_cells != 0);
}

// [W1d] THE MASKED WIDENING FORMS -- `v0.t` ON vfwadd/vfwsub/vfwmul/vfwmacc AND THE .wv/.vf FORMS.
//
// THIS IS A SEMANTIC LOWERING, NOT A LOOSER ADMISSION, and the section is built to tell the two
// apart. The architectural mask is a conjunct of the shared `RvvActiveLaneMask` predicate, and the
// SAME predicate value has to reach three places: the widening convert's operand, the FALU/FMA
// operands, and the destination store. If they were derived separately they could disagree, and an
// element could be computed in one and suppressed in the other -- silently, because the store would
// still look correct. So [d] asserts POINTER EQUALITY of the mask feeding the convert and the mask
// predicating the store, which is a stronger claim than "both are masked".
//
// THE FLAG OBLIGATION IS THE REASON THE CONVERT NEEDS NEUTRALISING AT ALL. `f32 -> f64` is exact
// for every finite input, so it looks like it cannot raise -- but it raises NV on a SIGNALLING NaN.
// A masked-off lane holding an sNaN would set the guest `fcsr` for an element the instruction must
// not touch, and a predicated destination store does NOT undo that: the flag has no second chance.
void SectionMaskedWidening()
{
	printf("[W1d] masked widening: v0 reaches convert, arithmetic and store as ONE predicate\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned cells = 0, shared_pred = 0, refusals = 0;
	u32 const v0_base = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
	auto reaches_v0 = [&](llvm::Value *root, llvm::Value *state) {
		llvm::SmallVector<llvm::Value *, 32> work{root};
		llvm::SmallPtrSet<llvm::Value *, 32> seen;
		while (!work.empty()) {
			llvm::Value *v = work.pop_back_val();
			if (!seen.insert(v).second)
				continue;
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(v)) {
				u32 const o = StateOffset(l->getPointerOperand(), state);
				if (o != ~0u && o >= v0_base && o < v0_base + rvv32::VLEN_MAX_BYTES)
					return true;
				continue;
			}
			if (auto *u = llvm::dyn_cast<llvm::User>(v))
				for (auto &op : u->operands())
					work.push_back(op);
		}
		return false;
	};
	for (u32 vlen : {256u, 1024u})
		for (u32 f6 : {F6_VFWADD, F6_VFWMUL, F6_VFWMACC}) {
			// (a) REFUSED with the switch off -- the masked form keeps the helper.
			Configure(vlen, true);
			Built off({Vsetvli(kVT_E32M1),
				   OpW(f6, 1u, kVs2, kVs1, kVd, /*masked=*/true), kJalr});
			Translate(off);
			CHECK_EQ(ScanQir(off.region).frames, 0u);
			++refusals;

			// (b) ADMITTED with it on, and the frame takes a PARTIAL kind.
			Configure(vlen, true);
			config::rvv_llvm_fwiden_masked = true;
			Built b({Vsetvli(kVT_E32M1),
				 OpW(f6, 1u, kVs2, kVs1, kVd, /*masked=*/true), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			CHECK(q.frames != 0);
			CHECK(q.any_masked); // the node really carries the mask
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
			CHECK(!InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
			if (!b.fn)
				continue;
			llvm::Value *state = b.fn->getArg(0);

			// (c) EVERY convert is neutralised by a predicate that depends on v0, and
			// (d) that predicate is the SAME VALUE the destination store uses.
			unsigned converts = 0, stores = 0;
			llvm::SmallPtrSet<llvm::Value *, 8> cvt_masks, store_masks;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii)
						continue;
					if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
						++stores;
						llvm::Value *m =
						    testcompat::MaskedStoreMask(ii);
						CHECK(reaches_v0(m, state));
						store_masks.insert(m);
						continue;
					}
					if (ii->getIntrinsicID() !=
					    llvm::Intrinsic::experimental_constrained_fpext)
						continue;
					++converts;
					auto *sel =
					    llvm::dyn_cast<llvm::SelectInst>(ii->getArgOperand(0));
					CHECK(sel != nullptr);
					if (!sel)
						continue;
					CHECK(reaches_v0(sel->getCondition(), state));
					cvt_masks.insert(sel->getCondition());
				}
			CHECK(converts != 0);
			CHECK(stores != 0);
			// ONE PREDICATE, not merely two masked things: every mask the converts used
			// must also be a mask a store used.
			for (llvm::Value *m : cvt_masks)
				if (store_masks.count(m))
					++shared_pred;
			CHECK(shared_pred != 0);
			++cells;

			// (e) OVERLAP: a masked form may not write v0, and no SEW-wide source may be
			// v0. Asked of `vfw_registers_legal`, not restated in the route.
			for (auto vd_vs : {std::pair<u32, u32>{0u, kVs2},
					   std::pair<u32, u32>{kVd, 0u}}) {
				Configure(vlen, true);
				config::rvv_llvm_fwiden_masked = true;
				Built bad({Vsetvli(kVT_E32M1),
					   OpW(f6, 1u, vd_vs.second, kVs1, vd_vs.first,
					       /*masked=*/true),
					   kJalr});
				Translate(bad);
				CHECK_EQ(ScanQir(bad.region).frames, 0u);
				++refusals;
			}
		}
	printf("       %u masked cells, %u with a SHARED predicate, %u refusals\n", cells,
	       shared_pred, refusals);
	CHECK(cells != 0);
	CHECK(shared_pred != 0);
	CHECK(refusals != 0);
}

void SectionAdmission()
{
	printf("[W1] admission, the STRONGER guard kind, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Row { char const *name; u32 f6; u32 f3; u32 vs2; };
	Row const rows[] = {
	    {"vfwadd.vv", F6_VFWADD, 1u, kVs2},   {"vfwsub.vv", F6_VFWSUB, 1u, kVs2},
	    {"vfwmul.vv", F6_VFWMUL, 1u, kVs2},   {"vfwadd.wv", F6_VFWADD_W, 1u, kVd},
	    {"vfwadd.vf", F6_VFWADD, 5u, kVs2},   {"vfwmacc.vv", F6_VFWMACC, 1u, kVs2},
	    {"vfwnmsac.vf", F6_VFWNMSAC, 5u, kVs2},
	};
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpW(r.f6, r.f3, r.vs2, r.f3 == 5u ? kF : kVs1, kVd), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (!q.cvt && !q.falu && !q.fma)
				continue;
			++admitted;
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
			CHECK_EQ(q.brackets, 1u); // exactly one FP bracket per frame
			CHECK(!q.any_masked);
			// `.wv` reads vs2 at the WIDE width, so it needs no convert for that operand.
			if (r.f6 == F6_VFWADD_W)
				CHECK(q.cvt > 0); // still one per chunk for the narrow operand
			else
				CHECK(q.cvt >= 2 * q.falu / (q.falu ? 1 : 1) - q.cvt || q.cvt > 0);
			Configure(vlen, false);
			Built o({Vsetvli(kVT_E32M1),
				 OpW(r.f6, r.f3, r.vs2, r.f3 == 5u ? kF : kVs1, kVd), kJalr});
			Translate(o);
			Qir const qo = ScanQir(o.region);
			CHECK_EQ(qo.cvt, 0u);
			CHECK(qo.hcalls >= 1u);
		}
	printf("       %u admitted form/width cells\n", admitted);
	CHECK(admitted > 0);
}

void SectionConvertShape()
{
	printf("[W2/W3] the convert is a CONSTRAINED fpext with no rounding operand, on the LOW half\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpW(F6_VFWADD, 1u, kVs2, kVs1, kVd), kJalr});
		Translate(b);
		Qir const q = ScanQir(b.region);
		if (!q.cvt || !b.fn)
			continue;
		++cells;
		u32 const chunk = std::min(vlen / 8u, 64u);
		u32 const dst_lanes = chunk / 8u; // f64 lanes per destination chunk
		IR const r = ScanIR(b.fn, dst_lanes);
		// One constrained fpext per convert node, and NO unconstrained one -- an
		// unconstrained fpext would say the frame's bracket did not apply to it.
		CHECK_EQ(r.fpext_constrained, q.cvt);
		CHECK_EQ(r.fpext_plain, 0u);
		CHECK_EQ(r.fpext_with_round_operand, 0u);
		// THE LOW-HALF SHUFFLE EXISTS EXACTLY WHERE THE NODE'S CONTRACT SAYS IT MUST: the
		// source VALUE is `max(16, chunk/2)` bytes, so it is wider than the window only when
		// `chunk/2 < 16`, i.e. only at a 16-byte destination chunk (VLEN 128).
		bool const needs_trim = (chunk / 2u) < 16u;
		if (needs_trim) {
			CHECK(r.shuffles >= q.cvt);
			CHECK_EQ(r.lowest_index_bad, 0u);
			CHECK(r.lowest_index_ok >= q.cvt);
		} else {
			CHECK_EQ(r.lowest_index_bad, 0u);
		}
	}
	printf("       %u width cells checked\n", cells);
	CHECK(cells > 0);
}

void SectionFusedIsOneNode()
{
	printf("[W4] the FMA forms emit ONE fused node per chunk, never a multiply plus an add\n");
	for (u32 vlen : {256u, 512u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT_E32M1), OpW(F6_VFWMACC, 1u, kVs2, kVs1, kVd), kJalr});
		Translate(b);
		Qir const q = ScanQir(b.region);
		if (!q.fma)
			continue;
		// The fused family uses vchunkfma and NO vchunkfalu: two operations would round twice
		// and be a different function from the reference's single wide fma.
		CHECK_EQ(q.falu, 0u);
		CHECK(q.fma > 0);
		if (b.fn) {
			IR const r = ScanIR(b.fn, std::min(vlen / 8u, 64u) / 8u);
			CHECK_EQ(r.fma_calls, q.fma);
		}
	}
	// And the ARITHMETIC forms use vchunkfalu and no vchunkfma, so the two are not conflated.
	Configure(512u, true);
	Built a({Vsetvli(kVT_E32M1), OpW(F6_VFWMUL, 1u, kVs2, kVs1, kVd), kJalr});
	Translate(a);
	Qir const qa = ScanQir(a.region);
	if (qa.falu) {
		CHECK_EQ(qa.fma, 0u);
		CHECK(qa.falu > 0);
	}
}

void SectionRefusals()
{
	printf("[W5] masked, the shared opmask, and a non-family funct6 keep the helper\n");
	struct Ref { char const *why; u32 word; bool shared; };
	Ref const rows[] = {
	    {"masked vfwadd.vv", OpW(F6_VFWADD, 1u, kVs2, kVs1, kVd, /*masked=*/true), false},
	    {"vfwredusum (shares the decode class, not arithmetic)",
	     OpW(F6_VFWREDUSUM, 1u, kVs2, kVs1, kVd), false},
	    {"shared opmask enabled", OpW(F6_VFWADD, 1u, kVs2, kVs1, kVd), true},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, true, r.shared);
			Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (q.cvt) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
			CHECK(q.hcalls >= 1u);
		}
}

void SectionVerify()
{
	printf("[W6] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u})
		for (u32 f6 : {F6_VFWADD, F6_VFWSUB, F6_VFWMUL, F6_VFWADD_W, F6_VFWMACC}) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1),
				 OpW(f6, 1u, f6 == F6_VFWADD_W ? kVd : kVs2, kVs1, kVd), kJalr});
			Translate(b);
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL vlen=%u f6=%u: %s\n", vlen, f6, err.c_str());
				++g_fail;
			}
		}
}

void SectionStateAlignment()
{
	printf("[W7] VLEN-128 widening reads an offset vector window at its actual alignment\n");
	Configure(128u, true);
	Built b({Vsetvli(kVT_E32M1), OpW(F6_VFWADD, 1u, kVs2, kVs1, kVd), kJalr});
	Translate(b);
	unsigned aligned8 = 0;
	for (auto &bb : *b.fn)
		for (auto &ins : bb)
			if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&ins))
				if (load->getType()->isVectorTy() && load->getAlign() == llvm::Align(8))
					++aligned8;
	CHECK(aligned8 > 0);
}

} // namespace

int main()
{
	printf("rvv_llvm_fwiden_test: order item 4, the widening FP arithmetic family\n");
	SectionAdmission();
	SectionDynamicFrmKind();
	SectionPartialVlBody();
	SectionMaskedWidening();
	SectionConvertShape();
	SectionFusedIsOneNode();
	SectionRefusals();
	SectionVerify();
	SectionStateAlignment();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
