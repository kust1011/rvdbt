// C4 (2026-09-18). SAME-WIDTH INTEGER -> FLOAT: `vfcvt.f.x.v` / `vfcvt.f.xu.v` ON THE LLVM ARM.
//
// THE ASSERTION THIS FILE EXISTS FOR is section 2: the lane operation must be
// `llvm.experimental.constrained.{si,ui}tofp`, and a plain `sitofp`/`uitofp` instruction must not
// appear anywhere. That is not a style preference. Measured on the installed LLVM 20.1.8, an
// unconstrained `uitofp <8 x i64> -> <8 x double>` at `-mattr=+avx512f` lowers to
// `vporq` + `vsubpd` -- the magic-constant trick -- and its closing subtraction of two equal values
// yields `-0.0` under roundTowardNegative. `rv32_vector_lower.h` already records that exact defect
// against the host path (`vfcvt.f.xu.v` of zero returning -0.0 where QEMU returns +0.0), which is
// why the reference routes integer-to-float through the softfloat core even on the host path. The
// constrained intrinsic emits `vcvtuqq2pd` (AVX512DQ) or per-lane `vcvtusi2sd` (AVX512F), neither of
// which subtracts. So "constrained, not plain" is the difference between reproducing a known
// QEMU-differential bug and not.
//
// SECTIONS:
//   [1] Admission and frame shape: one `_vchunkitof` per chunk, `GuardKind::VTypeVlVstartFrmRNE`,
//       no `vchunkactive`, and the FP bracket present.
//   [2] THE CONSTRAINED INTRINSIC, with `round.dynamic` + `fpexcept.strict`, and ZERO plain
//       `sitofp`/`uitofp` instructions.
//   [3] Signedness follows the encoding: sub-opcode 3 -> sitofp, 2 -> uitofp. Falsifiable by
//       swapping them, which no count-based check would notice.
//   [4] The widening (sub 8..15) and narrowing (sub 16..23) forms are REFUSED and keep the helper,
//       and so does the masked form -- the route's stated envelope, asserted rather than described.
//   [5] Lane geometry: the conversion's vector types are `<bytes/sew x iSEW*8>` ->
//       `<bytes/sew x float|double>`, and the destination store is unmasked (full VL is proved).

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_softfp.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_rvv_contract.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
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

// THE MODULE MUST BE BUILT IN THE CONTEXT THE GENERATOR ACTUALLY USES. `LLVMGenCtx`'s constructor
// is `: ctx(g_llvm_ctx)` -- it IGNORES the module it is handed and always builds types, metadata and
// functions in the process-global `g_llvm_ctx` (llvmgen.cpp:61). A test that creates its module in a
// private `LLVMContext` therefore ends up with a module whose CONTENTS belong to a different
// context: `verifyModule` reports "Function context does not match Module context", and type
// pointers compared across the boundary are unequal even when the types print identically. Using
// `g_llvm_ctx` here is what makes `CheckModuleIsWellFormed` below a real check rather than a
// generator of spurious errors. The other files in this series still use a private context and
// therefore cannot run the verifier; that is recorded in the ledger, not fixed here.
llvm::LLVMContext &g_ctx = g_llvm_ctx;

// VFUNARY0 (funct6 18), OPFVV (funct3 0b001). `sub` is the vs1 field: 0..7 same width, 8..15
// widening, 16..23 narrowing; `sub & 7` selects the operation (2 = f.xu, 3 = f.x).
constexpr u32 OpVfcvt(u32 sub, u32 vs2, u32 vd, bool unmasked = true)
{
	return (18u << 26) | ((unmasked ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) | (1u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 10u, kVs2 = 8u;

u32 VRegOff(u32 reg) { return (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg) +
				   reg * rvv32::VLEN_MAX_BYTES); }

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

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c4itof", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_fcvt_itof = on;
	// Reset the widening knob too: a flag one section sets and another never clears produces
	// false refusal rows (that exact leak was found in the float-width test).
	config::rvv_llvm_fcvt_itof_widen = false;
	config::rvv_llvm_fcvt_partial_vl = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	// C5-MASK-FP, reset so one section cannot leak a masked admission into the next.
	config::rvv_llvm_fp_cvt_masked = false;
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

struct Qir {
	unsigned frames = 0, units = 0, active_nodes = 0, hcalls = 0, brackets = 0;
	int guard_kind = -1;
	int is_signed = -1;
	unsigned sew = 0, bytes = 0;
	unsigned src_sew = 0;
	std::vector<u32> src_offs, dst_offs;
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
			case Op::_vchunkitof: {
				auto *n = static_cast<InstVChunkIToF *>(&ins);
				++q.units;
				q.is_signed = n->is_signed ? 1 : 0;
				q.sew = n->sew;
				q.bytes = n->bytes;
				q.src_sew = n->src_sew;
				q.src_offs.push_back(n->rs);
				q.dst_offs.push_back(n->rd);
				break;
			}
			case Op::_rvvqcgfpbegin:
				++q.brackets;
				break;
			case Op::_vchunkactive:
				++q.active_nodes;
				break;
			case Op::_hcall:
				++q.hcalls;
				break;
			default:
				break;
			}
		}
	return q;
}

// C4. THE CHECK THAT WOULD HAVE CAUGHT THE BUG THIS FILE SHIPPED WITH FOR ONE BUILD.
//
// `llvm.experimental.constrained.{si,ui}tofp` is overloaded on TWO types (result and operand). The
// first version of `Emit_vchunkitof` passed only one to `Intrinsic::getOrInsertDeclaration`, which
// builds a declaration whose type list does not match the intrinsic -- and EVERY assertion in this
// file still passed, because the call carried the right intrinsic ID and the right operand types.
// What it did instead was segfault `llvm::TypeFinder` the moment anything walked the module's
// types: `Module::print` crashed, and the Verifier or any real pass pipeline would have been next.
//
// So the structural assertions are not sufficient on their own and this runs alongside them:
// `verifyModule` on the emitted module, plus a forced print to a null stream, which is what drives
// TypeFinder. An IR-inspection test that never makes LLVM look at the whole module can pass while
// producing a module no backend could consume.
void CheckModuleIsWellFormed(Built &b, char const *what)
{
	std::string err;
	llvm::raw_string_ostream es(err);
	if (llvm::verifyModule(b.module, &es)) {
		printf("  FAIL %s: verifyModule rejected the emitted module:\n%s\n", what,
		       err.c_str());
		++g_fail;
	}
	// Forces llvm::TypeFinder over every type the module references.
	llvm::raw_null_ostream null_os;
	b.module.print(null_os, nullptr);
}

struct IRFacts {
	unsigned constrained_sitofp = 0, constrained_uitofp = 0;
	unsigned plain_casts = 0;   // sitofp / uitofp INSTRUCTIONS -- must be zero
	unsigned mxcsr = 0;	    // the FP bracket, which this route DOES need
	unsigned masked_stores = 0; // must be zero: full VL is proved
	bool round_dynamic = false, fpexcept_strict = false;
	unsigned src_lanes = 0, dst_lanes = 0, src_bits = 0, dst_bits = 0;
};

IRFacts ScanIR(llvm::Function *fn)
{
	IRFacts f;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (llvm::isa<llvm::SIToFPInst>(&ins) || llvm::isa<llvm::UIToFPInst>(&ins)) {
				++f.plain_casts;
				continue;
			}
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (!ii)
				continue;
			auto const id = ii->getIntrinsicID();
			if (id == llvm::Intrinsic::x86_sse_ldmxcsr ||
			    id == llvm::Intrinsic::x86_sse_stmxcsr) {
				++f.mxcsr;
				continue;
			}
			if (id == llvm::Intrinsic::masked_store) {
				++f.masked_stores;
				continue;
			}
			if (id != llvm::Intrinsic::experimental_constrained_sitofp &&
			    id != llvm::Intrinsic::experimental_constrained_uitofp)
				continue;
			if (id == llvm::Intrinsic::experimental_constrained_sitofp)
				++f.constrained_sitofp;
			else
				++f.constrained_uitofp;
			auto *sty = llvm::dyn_cast<llvm::FixedVectorType>(
			    ii->getArgOperand(0)->getType());
			auto *dty = llvm::dyn_cast<llvm::FixedVectorType>(ii->getType());
			if (sty) {
				f.src_lanes = sty->getNumElements();
				f.src_bits = sty->getScalarSizeInBits();
			}
			if (dty) {
				f.dst_lanes = dty->getNumElements();
				f.dst_bits = dty->getScalarSizeInBits();
			}
			// The two metadata operands carry the rounding and exception behaviour.
			for (unsigned k = 1; k < ii->arg_size(); ++k)
				if (auto *mv = llvm::dyn_cast<llvm::MetadataAsValue>(
					ii->getArgOperand(k)))
					if (auto *ms = llvm::dyn_cast<llvm::MDString>(
						mv->getMetadata())) {
						if (ms->getString() == "round.dynamic")
							f.round_dynamic = true;
						if (ms->getString() == "fpexcept.strict")
							f.fpexcept_strict = true;
					}
		}
	return f;
}

struct Case {
	char const *name;
	u32 sub;
	u32 vt;
	bool is_signed;
};
constexpr Case kCases[] = {
    {"vfcvt.f.xu.v e32", 2u, kVT_E32M1, false}, {"vfcvt.f.x.v  e32", 3u, kVT_E32M1, true},
    {"vfcvt.f.xu.v e64", 2u, kVT_E64M1, false}, {"vfcvt.f.x.v  e64", 3u, kVT_E64M1, true},
};
constexpr size_t kN = sizeof(kCases) / sizeof(kCases[0]);

void SectionShapeAndIntrinsic()
{
	printf("[C4IF-1..3,5] frame shape, CONSTRAINED intrinsic, signedness, lane geometry\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted[kN] = {};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (size_t ci = 0; ci < kN; ++ci) {
			auto const &c = kCases[ci];
			Configure(vlen, /*on=*/true);
			Built b({Vsetvli(c.vt), OpVfcvt(c.sub, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (getenv("C4IF_TRACE"))
				printf("   trace vlen=%u %-17s frames=%u units=%u kind=%d signed=%d\n",
				       vlen, c.name, q.frames, q.units, q.guard_kind, q.is_signed);
			if (!q.frames)
				continue;
			++admitted[ci];
			CheckModuleIsWellFormed(b, c.name);
			// [1] the FP frame kind, the bracket, and no unlowerable node
			CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
			CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind));
			CHECK_EQ(q.brackets, 1u);
			CHECK_EQ(q.active_nodes, 0u);
			CHECK_EQ(q.is_signed, c.is_signed ? 1 : 0);

			IRFacts ir = ScanIR(b.fn);
			// [2] constrained, with both metadata operands, and NO plain cast anywhere
			CHECK_EQ(ir.plain_casts, 0u);
			CHECK_EQ(ir.constrained_sitofp + ir.constrained_uitofp, q.units);
			CHECK(ir.round_dynamic);
			CHECK(ir.fpexcept_strict);
			// [3] signedness follows the encoding
			if (c.is_signed) {
				CHECK_EQ(ir.constrained_sitofp, q.units);
				CHECK_EQ(ir.constrained_uitofp, 0u);
			} else {
				CHECK_EQ(ir.constrained_uitofp, q.units);
				CHECK_EQ(ir.constrained_sitofp, 0u);
			}
			// the bracket really is emitted (contrast with vfclass, which must have none)
			CHECK(ir.mxcsr > 0u);
			// [5] geometry: same lane count both sides, widths from SEW, unmasked store
			CHECK_EQ(ir.src_bits, 8u * q.sew);
			CHECK_EQ(ir.dst_bits, 8u * q.sew);
			CHECK_EQ(ir.src_lanes, q.bytes / q.sew);
			CHECK_EQ(ir.dst_lanes, ir.src_lanes);
			CHECK_EQ(ir.masked_stores, 0u);
		}
	for (size_t ci = 0; ci < kN; ++ci)
		if (!admitted[ci]) {
			printf("  FAIL '%s' was never admitted -- its rows are vacuous\n",
			       kCases[ci].name);
			++g_fail;
		}
}

// ---------------------------------------------------------------------------------------------
// [C4IW] WIDENING integer -> float: `vfwcvt.f.x.v` / `vfwcvt.f.xu.v`.
//
// The flag logic is this file's same-width logic unchanged; what is new is the GEOMETRY. So the
// checks that matter here are the ones a same-width route would pass vacuously: the emitted LOAD
// must be the SOURCE width (not the destination), the intrinsic's overload pair must be
// (destination float, source int), and the two windows must advance at different rates.
constexpr u32 kSubWidenFXu = 10u, kSubWidenFX = 11u;
constexpr u32 kVT_E16M1 = 0xc8u;

void FoldToFixpointW(llvm::Function *fn)
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

void SectionWiden()
{
	printf("[C4IW-1] widening int->float: source-width load, overload pair, geometry, values\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct WCase { char const *name; u32 sub; u32 vt; u32 ssew; bool is_signed; };
	WCase const cases[] = {
	    {"vfwcvt.f.x.v  i16->f32", kSubWidenFX, kVT_E16M1, 2u, true},
	    {"vfwcvt.f.xu.v i16->f32", kSubWidenFXu, kVT_E16M1, 2u, false},
	    {"vfwcvt.f.x.v  i32->f64", kSubWidenFX, kVT_E32M1, 4u, true},
	    {"vfwcvt.f.xu.v i32->f64", kSubWidenFXu, kVT_E32M1, 4u, false},
	};
	unsigned admitted[4] = {}, values = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (size_t ci = 0; ci < 4; ++ci) {
			auto const &c = cases[ci];
			Configure(vlen, /*on=*/false);
			config::rvv_llvm_fcvt_itof_widen = true;
			Built b({Vsetvli(c.vt), OpVfcvt(c.sub, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				continue;
			++admitted[ci];
			{
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL %s: verifyModule rejected the module:\n%s\n",
					       c.name, err.c_str());
					++g_fail;
				}
				llvm::raw_null_ostream null_os;
				b.module.print(null_os, nullptr);
			}
			u32 const dsew = 2u * c.ssew;
			CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
			CHECK_EQ(q.sew, dsew);   // the node's sew is the DESTINATION width
			CHECK_EQ(q.is_signed, c.is_signed ? 1 : 0);
			u32 const lanes = q.bytes / dsew;

			// Structural: the LOAD is the source width and the overload pair is (dst, src).
			unsigned loads = 0, calls = 0, good_pair = 0, plain = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					if (llvm::isa<llvm::SIToFPInst>(&ins) ||
					    llvm::isa<llvm::UIToFPInst>(&ins))
						++plain;
					if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins))
						if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(
							l->getType()))
							if (vt->getNumElements() == lanes &&
							    vt->getElementType()->isIntegerTy() &&
							    vt->getScalarSizeInBits() == 8u * c.ssew)
								++loads;
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii)
						continue;
					auto const id = ii->getIntrinsicID();
					if (id != llvm::Intrinsic::experimental_constrained_sitofp &&
					    id != llvm::Intrinsic::experimental_constrained_uitofp)
						continue;
					++calls;
					auto *sty = llvm::dyn_cast<llvm::FixedVectorType>(
					    ii->getArgOperand(0)->getType());
					auto *dty = llvm::dyn_cast<llvm::FixedVectorType>(ii->getType());
					if (sty && dty && sty->getScalarSizeInBits() == 8u * c.ssew &&
					    dty->getScalarSizeInBits() == 8u * dsew &&
					    sty->getNumElements() == lanes &&
					    dty->getNumElements() == lanes)
						++good_pair;
				}
			CHECK_EQ(plain, 0u);
			CHECK_EQ(calls, q.units);
			CHECK_EQ(good_pair, q.units);
			CHECK_EQ(loads, q.units);

			// Geometry, from first principles: element `e` of a group lives in register
			// `base + (e*esize)/rb` at byte `(e*esize)%rb`, and the two esizes differ.
			u32 const rb = vlen / 8u;
			auto win = [&](u32 reg, u32 elem, u32 esize) {
				u32 const byte = elem * esize;
				return VRegOff(reg) + byte / rb * rvv32::VLEN_MAX_BYTES + byte % rb;
			};
			for (size_t u = 0; u < q.dst_offs.size(); ++u) {
				CHECK_EQ(q.dst_offs[u], win(kVd, (u32)u * lanes, dsew));
				CHECK_EQ(q.src_offs[u], win(kVs2, (u32)u * lanes, c.ssew));
			}

			// Value oracle: fold the source load to constants, substitute the conversion
			// with the C++ result of the SAME lane values, fold again and compare against
			// `cvt_from_int`. A wrong load width changes the lane values and shows up here.
			llvm::LoadInst *src = nullptr;
			for (auto &bb : *b.fn) {
				for (auto &ins : bb) {
					auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
					if (!l)
						continue;
					auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
					if (!vt || vt->getNumElements() != lanes ||
					    !vt->getElementType()->isIntegerTy() ||
					    vt->getScalarSizeInBits() != 8u * c.ssew)
						continue;
					if (StateOffset(l->getPointerOperand(),
							b.fn->getArg(0)) != VRegOff(kVs2))
						continue;
					src = l;
					break;
				}
				if (src)
					break;
			}
			if (!src)
				continue;
			// Boundary-ish integers for both widths, including the signed extremes.
			u64 const vals16[] = {0, 1, 0xffffu, 0x8000u, 0x7fffu, 0x5555u};
			u64 const vals32[] = {0, 1, 0xffffffffu, 0x80000000u, 0x7fffffffu, 0x12345678u};
			auto *sty = llvm::cast<llvm::FixedVectorType>(src->getType());
			llvm::SmallVector<llvm::Constant *, 64> in;
			std::vector<u64> raws;
			for (u32 l2 = 0; l2 < lanes; ++l2) {
				u64 const v = c.ssew == 2 ? vals16[l2 % 6] : vals32[l2 % 6];
				raws.push_back(v);
				in.push_back(llvm::ConstantInt::get(sty->getElementType(), v));
			}
			src->replaceAllUsesWith(llvm::ConstantVector::get(in));
			FoldToFixpointW(b.fn);
			llvm::IntrinsicInst *call = nullptr;
			for (auto &bb : *b.fn)
				for (auto &ins : bb)
					if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						auto const id = ii->getIntrinsicID();
						if (id == llvm::Intrinsic::experimental_constrained_sitofp ||
						    id == llvm::Intrinsic::experimental_constrained_uitofp) {
							call = ii;
							break;
						}
					}
			if (!call)
				continue;
			auto *op = llvm::dyn_cast<llvm::Constant>(call->getArgOperand(0));
			if (!op)
				continue;
			auto *dty = llvm::cast<llvm::FixedVectorType>(call->getType());
			llvm::SmallVector<llvm::Constant *, 64> cv;
			for (u32 l2 = 0; l2 < lanes; ++l2) {
				auto *ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(
				    op->getAggregateElement(l2));
				if (!ci)
					break;
				double d;
				if (c.is_signed)
					d = (double)ci->getValue().getSExtValue();
				else
					d = (double)ci->getValue().getZExtValue();
				cv.push_back(dsew == 4 ? llvm::ConstantFP::get(dty->getElementType(),
									      (double)(float)d)
						       : llvm::ConstantFP::get(dty->getElementType(), d));
			}
			if (cv.size() != lanes)
				continue;
			call->replaceAllUsesWith(llvm::ConstantVector::get(cv));
			FoldToFixpointW(b.fn);
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
					if (!st || StateOffset(st->getPointerOperand(),
							       b.fn->getArg(0)) != VRegOff(kVd))
						continue;
					auto *cc = llvm::dyn_cast<llvm::Constant>(st->getValueOperand());
					if (!cc)
						continue;
					for (u32 l2 = 0; l2 < lanes; ++l2) {
						auto *e = cc->getAggregateElement(l2);
						auto *cf = llvm::dyn_cast_or_null<llvm::ConstantFP>(e);
						if (!cf)
							continue;
						u64 const got =
						    cf->getValueAPF().bitcastToAPInt().getZExtValue();
						u64 const raw2 = raws[l2];
						u64 mag;
						bool sign;
						if (c.is_signed) {
							i64 const sv = c.ssew == 2
									   ? (i64)(i16)raw2
									   : (i64)(i32)raw2;
							sign = sv < 0;
							mag = sign ? (u64)(-sv) : (u64)sv;
						} else {
							sign = false;
							mag = raw2;
						}
						u32 fl = 0;
						u64 const want = rvv32::softfp::cvt_from_int(
						    mag, sign,
						    dsew == 4 ? rvv32::softfp::FMT32
							      : rvv32::softfp::FMT64,
						    rvv32::FRM_RNE, fl);
						++values;
						if (got != want) {
							printf("  FAIL vlen=%u %-24s lane %u in=0x%llx "
							       "emitted=0x%llx reference=0x%llx\n",
							       vlen, c.name, l2,
							       (unsigned long long)raw2,
							       (unsigned long long)got,
							       (unsigned long long)want);
							++g_fail;
						}
					}
				}
		}
	printf("       %u lanes compared against softfp::cvt_from_int\n", values);
	CHECK(values > 0);
	for (size_t ci = 0; ci < 4; ++ci)
		if (!admitted[ci]) {
			printf("  FAIL '%s' was never admitted -- its rows are vacuous\n",
			       cases[ci].name);
			++g_fail;
		}
	// SEW 8 and 64 are outside the shared predicate's admitted width pairs.
	for (u32 bad_vt : {0xc0u, 0xd8u}) {
		Configure(1024u, /*on=*/false);
		config::rvv_llvm_fcvt_itof_widen = true;
		Built b({Vsetvli(bad_vt), OpVfcvt(kSubWidenFX, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		CHECK_EQ(q.units, 0u);
		CHECK(q.hcalls > 0u);
	}
}

// ---------------------------------------------------------------------------------------------
// [C4IP] ORDER ITEM 3: PRODUCTION PARTIAL VL for the conversion route, checked against the shared
// contract's own rules rather than against a restatement of them.
//
// This is the first conversion route that actually DEPENDS on `rv32_rvv_contract.h` -- its element
// windows come from `ElementStateOffset` and its lane count from `UnitLanes` -- so the checks below
// are adoption evidence, not just agreement.
void SectionPartialVl()
{
	printf("[C4IP] conversion partial VL: partial guard, neutralised operand, masked publish\n");
	namespace ctr = dbt::rv32::rvvcontract;
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 sub : {2u, 3u}) {
			Configure(vlen, /*on=*/true);
			config::rvv_llvm_fcvt_partial_vl = true;
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				continue;
			++admitted;
			{
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL partial-VL itof: verifyModule rejected:\n%s\n",
					       err.c_str());
					++g_fail;
				}
				llvm::raw_null_ostream null_os;
				b.module.print(null_os, nullptr);
			}
			// The guard really stops proving full VL -- otherwise everything below is vacuous.
			CHECK_EQ(q.guard_kind, (int)GK::VTypePartialVlVstartFrmRNE);
			bool const full = InstRVVTypedChunkBegin::GuardProvesFullVl((GK)q.guard_kind);
			CHECK(!full);
			CHECK(ctr::TailHandlingRequired(full, /*unmasked=*/true));

			unsigned masked_stores = 0, plain_stores = 0, neutralised = 0, calls = 0;
			std::vector<u64> bases_seen;
			u32 const lanes = q.bytes / q.sew;
			CHECK_EQ(lanes, ctr::UnitLanes(vlen, q.sew, q.src_sew));
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
						if (StateOffset(st->getPointerOperand(),
								b.fn->getArg(0)) ==
						    ctr::ElementStateOffset(vlen, kVd, 0u, q.sew))
							++plain_stores;
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii)
						continue;
					if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
						if (StateOffset(ii->getArgOperand(1),
								b.fn->getArg(0)) ==
						    ctr::ElementStateOffset(vlen, kVd, 0u, q.sew))
							++masked_stores;
						continue;
					}
					auto const id = ii->getIntrinsicID();
					if (id != llvm::Intrinsic::experimental_constrained_sitofp &&
					    id != llvm::Intrinsic::experimental_constrained_uitofp)
						continue;
					++calls;
					// THE NEUTRALISATION: the operand is a select whose false arm is
					// the ZERO integer vector. Zero, not +1.0 -- an integer 0
					// converts to +0.0 exactly and raises nothing.
					if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(
						ii->getArgOperand(0))) {
						auto *fa = llvm::dyn_cast<llvm::Constant>(
						    sel->getFalseValue());
						if (fa && fa->isNullValue())
							++neutralised;
						// AND THE MASK MUST START AT THIS UNIT'S ELEMENT BASE.
						// Checking only that "a neutralising select exists" let a
						// lane-0 mask through -- the THIRD time this exact gap has
						// appeared in this checkpoint. At VLEN 2048 a frame has
						// several units, and a lane-0 mask would neutralise the
						// wrong elements of every unit after the first.
						if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(
							sel->getCondition()))
							if (auto *cv = llvm::dyn_cast<llvm::Constant>(
								cmp->getOperand(0)))
								if (auto *vt = llvm::dyn_cast<
									llvm::FixedVectorType>(
									cv->getType())) {
									bases_seen.push_back(
									    llvm::cast<llvm::ConstantInt>(
										cv->getAggregateElement(
										    0u))
										->getZExtValue());
									(void)vt;
								}
					}
				}
			CHECK_EQ(calls, q.units);
			CHECK_EQ(neutralised, q.units);
			// One mask per unit, each starting at that unit's own element base.
			CHECK_EQ(bases_seen.size(), q.units);
			for (size_t u = 0; u < bases_seen.size(); ++u)
				CHECK_EQ(bases_seen[u], (u64)u * lanes);
			// Publication is preserving, which is what the contract requires of a frame
			// that owes a tail policy.
			CHECK(masked_stores >= 1u);
			CHECK_EQ(plain_stores, 0u);
			CHECK(ctr::DestinationWriteIsSound(ctr::DestinationWrite::MaskedStore, full,
							   true));
		}
	printf("       %u partial-VL route/width cells checked\n", admitted);
	CHECK(admitted > 0);

	// Inert when off: the full-VL guard returns and the store is unmasked again.
	for (u32 vlen : {256u, 1024u}) {
		Configure(vlen, /*on=*/true); // resets rvv_llvm_fcvt_partial_vl to false
		Built b({Vsetvli(kVT_E32M1), OpVfcvt(3u, kVs2, kVd), kJalr});
		Translate(b);
		Qir q = ScanQir(b.region);
		if (!q.frames)
			continue;
		CHECK_EQ(q.guard_kind, (int)GK::VTypeVlVstartFrmRNE);
		unsigned masked = 0;
		for (auto &bb : *b.fn)
			for (auto &ins : bb)
				if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
					if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store)
						++masked;
		CHECK_EQ(masked, 0u);
	}
}

// [C4IF-FRM] THE FRAME'S ROUNDING ADMISSION, AT THIS ROUTE'S OWN FRAME-CONSTRUCTION SITE.
//
// This section exists because of a REAL MISS. `--rvv-llvm-fp-dynamic-frm` widens the FP conversion
// frame from `frm == RNE` to `frm <= FRM_RUP`, and it was implemented in `RvvOpenConversionFrame`
// -- which THIS ROUTE DOES NOT CALL. It builds its frame inline. The consequence was measurable on
// official ACT4: the switch moved float-to-integer by +30 and integer-to-float by EXACTLY 0, and
// `vfcvt.f.x.v` / `vfcvt.f.xu.v` held `guard_fallbacks = 40` in the full matrix while the ftoi
// forms fell to 10. A shared switch with two frame-construction sites needs a check at each one.
void SectionDynamicFrmKind()
{
	printf("[C4IF-FRM] this route's OWN frame honours the dynamic-frm switch\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned checked = 0;
	for (u32 vlen : {256u, 1024u})
		for (u32 sub : {2u, 3u})
			for (int partial = 0; partial < 2; ++partial) {
				Configure(vlen, /*on=*/true);
				config::rvv_llvm_fcvt_partial_vl = partial != 0;
				config::rvv_llvm_fp_dynamic_frm = false;
				Built off({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, kVd), kJalr});
				Translate(off);
				Qir qo = ScanQir(off.region);
				if (!qo.frames)
					continue;
				CHECK_EQ(qo.guard_kind, (int)(partial ? GK::VTypePartialVlVstartFrmRNE
								      : GK::VTypeVlVstartFrmRNE));

				Configure(vlen, /*on=*/true);
				config::rvv_llvm_fcvt_partial_vl = partial != 0;
				config::rvv_llvm_fp_dynamic_frm = true;
				Built on({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, kVd), kJalr});
				Translate(on);
				Qir qn = ScanQir(on.region);
				CHECK(qn.frames != 0);
				CHECK_EQ(qn.guard_kind,
					 (int)(partial ? GK::VTypePartialVlVstartFrmHostRound
						       : GK::VTypeVlVstartFrmHostRound));
				++checked;
			}
	printf("       %u itof frames checked on both switch positions\n", checked);
	CHECK(checked != 0);
}

void SectionRefusals()
{
	printf("[C4IF-4] widening, narrowing, masked and float-source forms keep the helper\n");
	struct R { char const *name; u32 sub; bool unmasked; };
	R const rows[] = {
	    {"vfwcvt.f.x.v  (widening, sub 11)", 11u, true},
	    {"vfwcvt.f.xu.v (widening, sub 10)", 10u, true},
	    {"vfncvt.f.x.w  (narrowing, sub 19)", 19u, true},
	    {"vfncvt.f.xu.w (narrowing, sub 18)", 18u, true},
	    {"vfcvt.x.f.v   (float source, sub 1)", 1u, true},
	    {"vfcvt.xu.f.v  (float source, sub 0)", 0u, true},
	    {"vfcvt.rtz.x.f.v (float source, sub 7)", 7u, true},
	    {"vfcvt.f.x.v MASKED", 3u, false},
	};
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			Configure(vlen, /*on=*/true);
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(r.sub, kVs2, kVd, r.unmasked), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			if (q.units != 0) {
				printf("  FAIL %s was admitted at vlen=%u; this route's envelope is "
				       "same-width unmasked integer-to-float only\n", r.name, vlen);
				++g_fail;
			}
			CHECK(q.hcalls > 0u);
		}
}

void SectionOffIsInert()
{
	printf("[C4IF-6] switch off: no frame, no unit, the instruction reaches the helper\n");
	for (u32 vlen : {256u, 1024u})
		for (size_t ci = 0; ci < kN; ++ci) {
			Configure(vlen, /*on=*/false);
			Built b({Vsetvli(kCases[ci].vt), OpVfcvt(kCases[ci].sub, kVs2, kVd), kJalr});
			Translate(b);
			Qir q = ScanQir(b.region);
			CHECK_EQ(q.units, 0u);
			CHECK(q.hcalls > 0u);
			IRFacts ir = ScanIR(b.fn);
			CHECK_EQ(ir.constrained_sitofp + ir.constrained_uitofp, 0u);
			CHECK_EQ(ir.plain_casts, 0u);
		}
}

void DumpIR()
{
	char const *path = getenv("C4IF_DUMP_IR");
	if (!path)
		return;
	// e64 unsigned at VLEN 1024: the exact shape whose UNCONSTRAINED form lowers to the
	// magic-constant trick, so the dump is the evidence that this route does not.
	if (char const *wp = getenv("C4IW_DUMP_IR")) {
		Configure(1024u, false);
		config::rvv_llvm_fcvt_itof_widen = true;
		Built wb({Vsetvli(kVT_E32M1), OpVfcvt(kSubWidenFX, kVs2, kVd), kJalr});
		Translate(wb);
		std::error_code wec;
		llvm::raw_fd_ostream wos(wp, wec);
		if (!wec)
			wb.module.print(wos, nullptr);
		printf("  (widening IR dumped to %s)\n", wp);
	}
	Configure(1024u, true);
	Built b({Vsetvli(kVT_E64M1), OpVfcvt(2u, kVs2, kVd), kJalr});
	Translate(b);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

} // namespace

// [C4IP-M] THE ARCHITECTURAL MASK for integer-to-float. This family's flag obligation is NX: an
// integer whose value is not exactly representable raises it, so a masked-off lane must not be
// allowed to contribute one. The emitter does not suppress the flag after the fact -- it
// NEUTRALISES THE OPERAND, selecting integer 0 for inactive lanes (0 converts to +0.0 exactly and
// raises nothing), which is why the check below is on the SELECT's condition and not on a flag
// word: if the architectural mask is missing from that condition, an inactive lane reaches the
// conversion with its real value and raises NX with nothing to stop it.
//
// Both obligations are asserted, and both must trace to a load out of v0: the neutralisation
// select AND the destination's store predicate.
void SectionMaskedArchMask()
{
	printf("[C4IP-M] architectural mask: neutralisation AND publish both depend on v0\n");
	u32 const v0_base = VRegOff(0);
	unsigned selects = 0, stores = 0;
	auto reaches_v0 = [&](llvm::Value *root, llvm::Value *state) {
		llvm::SmallVector<llvm::Value *, 16> work{root};
		llvm::SmallPtrSet<llvm::Value *, 16> seen;
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
	for (u32 vlen : {256u, 512u, 1024u})
		for (u32 sub : {2u, 3u}) {
			Configure(vlen, /*on=*/true);
			config::rvv_llvm_fp_cvt_masked = true;
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, kVd, /*unmasked=*/false),
				 kJalr});
			Translate(b);
			CHECK(ScanQir(b.region).frames != 0); // the masked form must be ADMITTED
			llvm::Value *state = b.fn->getArg(0);
			unsigned calls = 0;
			for (auto &bb : *b.fn)
				for (auto &ins : bb) {
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii)
						continue;
					if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
						CHECK(reaches_v0(testcompat::MaskedStoreMask(ii),
								 state));
						++stores;
						continue;
					}
					auto const id = ii->getIntrinsicID();
					if (id != llvm::Intrinsic::experimental_constrained_sitofp &&
					    id != llvm::Intrinsic::experimental_constrained_uitofp)
						continue;
					++calls;
					// The operand must be a select whose CONDITION depends on v0.
					auto *sel = llvm::dyn_cast<llvm::SelectInst>(
					    ii->getArgOperand(0));
					CHECK(sel != nullptr);
					if (!sel)
						continue;
					CHECK(reaches_v0(sel->getCondition(), state));
					++selects;
				}
			CHECK(calls != 0);

			// REFUSALS: switch off, and vd == v0.
			Configure(vlen, /*on=*/true);
			config::rvv_llvm_fp_cvt_masked = false;
			Built off({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, kVd, /*unmasked=*/false),
				   kJalr});
			Translate(off);
			CHECK_EQ(ScanQir(off.region).frames, 0u);

			Configure(vlen, /*on=*/true);
			config::rvv_llvm_fp_cvt_masked = true;
			Built v0d({Vsetvli(kVT_E32M1), OpVfcvt(sub, kVs2, /*vd=*/0u,
							       /*unmasked=*/false),
				   kJalr});
			Translate(v0d);
			CHECK_EQ(ScanQir(v0d.region).frames, 0u);
		}
	printf("       %u neutralisation selects and %u publishes, all v0-dependent\n", selects,
	       stores);
	CHECK(selects != 0);
	CHECK(stores != 0);
}

int main()
{
	printf("rvv_llvm_fcvt_itof_test\n");
	SectionShapeAndIntrinsic();
	SectionWiden();
	SectionPartialVl();
	SectionDynamicFrmKind();
	SectionMaskedArchMask();
	SectionRefusals();
	SectionOffIsInert();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
