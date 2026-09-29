#include "dbt/qmc/qcg/arch_traits.h"
#include <algorithm>
#include <numeric>

namespace dbt::qcg
{

struct RACtDef {
	RACtDef() = default;
	constexpr RACtDef(RegMask cr_) : cr(cr_) {}
	constexpr RACtDef(RegMask cr_, RACtImm ci_) : cr(cr_), ci(ci_) {}
	RegMask cr{0};
	RACtImm ci{RACtImm::NO};
};
struct RACtDefOrAlias : RACtDef {
	constexpr RACtDefOrAlias(RACtDef o) : RACtDef(o.cr, o.ci) {}
	constexpr RACtDefOrAlias(u8 alias_) : has_alias(true), alias(alias_) {}
	bool has_alias{};
	u8 alias{};
};

template <u8 N_OUT, u8 N_IN>
struct InstCt {
	using ct_desc = std::array<RAOpCt, N_OUT + N_IN>;
	using ct_order = std::array<u8, N_OUT + N_IN>;

	static constexpr InstCt Make(std::array<RACtDef, N_OUT> &&odef_set,
				     std::array<RACtDefOrAlias, N_IN> &&idef_set);

	ct_desc ct;
	ct_order order;
};

template <u8 N_OUT, u8 N_IN>
constexpr InstCt<N_OUT, N_IN> InstCt<N_OUT, N_IN>::Make(std::array<RACtDef, N_OUT> &&odef_set,
							std::array<RACtDefOrAlias, N_IN> &&idef_set)
{
	using ct_type = std::array<RAOpCt, N_OUT + N_IN>;
	ct_type ct;

	for (size_t oidx = 0; oidx < N_OUT; ++oidx) {
		auto odef = odef_set[oidx];
		ct[oidx] = {.cr = odef.cr, .ci = odef.ci};
	}

	for (size_t iidx = N_OUT; iidx < N_OUT + N_IN; ++iidx) {
		auto idef = idef_set[iidx - N_OUT];
		if (idef.has_alias) {
			auto aidx = idef.alias;
			ct[iidx] = ct[aidx];
			ct[iidx].SetAlias(aidx);
			ct[aidx].SetAlias(iidx);
		} else {
			ct[iidx] = {.cr = idef.cr, .ci = idef.ci};
		}
	}

	std::array<u8, N_OUT + N_IN> order;

	auto order_ct = [&](u8 start, u8 len) {
		auto order_cmp = [&](u8 i0, u8 i1) {
			return ct[i0 + start].cr.count() < ct[i1 + start].cr.count();
		};
		auto b = order.begin() + start;
		auto e = b + len;
		std::iota(b, e, 0);
		std::sort(b, e, order_cmp);
	};
	order_ct(0, N_OUT);
	order_ct(N_OUT, N_IN);

	return {ct, order};
}

namespace RACtGPR
{
constexpr auto R = ArchTraits::GPR_ALL;
constexpr auto R8 = ArchTraits::GPR_ALL;
constexpr auto CX = RegMask(0).Set(ArchTraits::RCX);
constexpr auto BX = RegMask(0).Set(ArchTraits::RBX);
constexpr auto SI = RegMask(0).Set(ArchTraits::RSI);
}; // namespace RACtGPR

#define GPR(X) RACtGPR::X
#define IMM(X) RACtImm::X
#define DEF(...) RACtDef(__VA_ARGS__)
#define ALIAS(X) RACtDefOrAlias(X)

// Add N$_ prefix for multiple-outs instructions
#define CT(name) static constinit auto CT_INFO_##name
CT(r_rs32) = InstCt<0, 2>::Make({}, {DEF(GPR(R)), DEF(GPR(R), IMM(S32))});
CT(si) = InstCt<0, 1>::Make({}, {DEF(GPR(SI))});
// A-line Round 44: gbrind's operand 1 (the index-preserving compact-dispatch index, oracle-only,
// default a harmless constant when unused -- see qir.h InstGBrind::indexed_targets). QCG tier
// never reads this operand (the consumer is LLVM-AOT-only, matching static_table_targets/
// vtable_narrow_targets's existing oracle-only scope), so it needs no forced register -- GPR(R)
// (any) + IMM(ANY) mirrors r_ri's existing flexible constraint, just sized for gbrind's now-2
// inputs so QRegAlloc::AllocOp's unconditional op_ct/op_order indexing stays in bounds.
CT(si_any) = InstCt<0, 2>::Make({}, {DEF(GPR(SI)), DEF(GPR(R), IMM(ANY))});
CT(r_ru32) = InstCt<1, 1>::Make({DEF(GPR(R))}, {DEF(GPR(R), IMM(U32))});
CT(r_ri) = InstCt<1, 1>::Make({DEF(GPR(R))}, {DEF(GPR(R), IMM(ANY))});
CT(ri_r) = InstCt<0, 2>::Make({}, {DEF(GPR(R), IMM(ANY)), DEF(GPR(R))});
CT(r8_r_rs32) = InstCt<1, 2>::Make({DEF(GPR(R8))}, {DEF(GPR(R)), DEF(GPR(R), IMM(S32))});
CT(r_0_rs32) = InstCt<1, 2>::Make({DEF(GPR(R))}, {ALIAS(0), DEF(GPR(R), IMM(S32))});
CT(r_0_ru32) = InstCt<1, 2>::Make({DEF(GPR(R))}, {ALIAS(0), DEF(GPR(R), IMM(U32))});
CT(r_0_cxi) = InstCt<1, 2>::Make({DEF(GPR(R))}, {ALIAS(0), DEF(GPR(CX), IMM(ANY))});
CT(ri_r2) = InstCt<0, 3>::Make({}, {DEF(GPR(R), IMM(ANY)), DEF(GPR(R)), DEF(GPR(R))});
CT(ri_r4) = InstCt<0, 5>::Make({}, {DEF(GPR(R), IMM(ANY)), DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R))});
CT(r2_ru32) = InstCt<2, 1>::Make({DEF(GPR(R)), DEF(GPR(R))}, {DEF(GPR(R), IMM(U32))});
CT(r4_ru32) = InstCt<4, 1>::Make({DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R))}, {DEF(GPR(R), IMM(U32))});
CT(r4_r8) = InstCt<4, 8>::Make(
    {DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R))},
    {DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R)),
     DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R))});
CT(r_r_bx) = InstCt<1, 2>::Make({DEF(GPR(R))}, {DEF(GPR(R)), DEF(GPR(BX))});
// Three independent registers, no alias and no immediate form: the shape of a non-destructive
// three-operand instruction. Used by vchunkadd, whose EVEX encoding writes a destination distinct
// from both sources, so unlike the scalar binops there is nothing for QSel to legalize.
CT(r_r_r) = InstCt<1, 2>::Make({DEF(GPR(R))}, {DEF(GPR(R)), DEF(GPR(R))});
// P7I. Four independent registers -- one result, three inputs -- and, like r_r_r above, NO ALIAS.
//
// The absence of ALIAS(0) is the one thing worth stating, because x86's 213 FMA form IS
// destructive: `vfmadd213pd out, b, a` reads and writes `out`. It is still not an alias here,
// because Emit_vchunkfma opens with `vmovdqu64 out, dold` exactly as Emit_vchunkfalu opens with
// `vmovdqu64 out, a` -- the QIR-level result is a fresh value and the host-level destructiveness
// is entirely inside the emitter, after the copy. Declaring ALIAS(0) would instead force the
// allocator to place `dold` and the result in the same register, which is neither needed nor
// what the emitted sequence does.
CT(r_r_r_r) = InstCt<1, 3>::Make({DEF(GPR(R))}, {DEF(GPR(R)), DEF(GPR(R)), DEF(GPR(R))});
// One unconstrained result and no inputs at all: the shape of an instruction whose only address is
// a fixed host register plus a translation-time constant. Used by vstatechunkload.
CT(r) = InstCt<1, 0>::Make({DEF(GPR(R))}, {});
// The mirror image: one unconstrained input and no result at all. Used by vstatechunkstore. The
// zero-output tables above are named for their inputs, which would make this one `r` as well --
// it is spelled `rin` only because CT(r) above already took that name for the one-result shape,
// and renaming an accepted table is not worth the churn.
CT(rin) = InstCt<0, 1>::Make({}, {DEF(GPR(R))});
// One result and one input, both register-only, no alias and NO IMMEDIATE FORM. Used by rvvsetvl.
// The absence of IMM is deliberate rather than an oversight: the emitter compares its input against
// a scratch register with `cmp` and then `cmov`s from it, and `cmov`'s source must be a register or
// memory -- an immediate operand would have no encoding. Declaring that in the table makes it a
// checked fact instead of an assumption, because QSel's constant-lowering loop then materialises any
// constant into a register before the emitter ever sees it.
CT(r_r) = InstCt<1, 1>::Make({DEF(GPR(R))}, {DEF(GPR(R))});
// P9. Two register-only inputs and NO result: `rin`'s shape with a second operand, for a node whose
// entire output is a CPUState write. Not `ri_r`, which is also <0,2> but declares an immediate form
// on the first operand -- both operands here are always V512 values and never constants, and saying
// so keeps QSel's constant-lowering loop out of a case that cannot arise.
CT(rin_r) = InstCt<0, 2>::Make({}, {DEF(GPR(R)), DEF(GPR(R))});
#undef CT

#undef GPR
#undef IMM
#undef DEF
#undef ALIAS

// TODO: verify, check cpuinfo
#define ARCH_OP_CT_LIST(CT)                                                                                  \
	CT(brcc, r_rs32)                                                                                     \
	CT(gbrind, si_any)                                                                                   \
	CT(vmload, r_ru32)                                                                                   \
	CT(vmstore, ri_r)                                                                                    \
	CT(vmload2, r2_ru32)                                                                                  \
	CT(vmload4, r4_ru32)                                                                                  \
	CT(vmstore2, ri_r2)                                                                               \
	CT(vmstore4, ri_r4)                                                                               \
	/* Typed V512 chunk ops. Every mask here is GPR_ALL ("any register of the operand's own    */     \
	/* class"), which is the only shape QRegAlloc::VPRConstraint accepts for a vector operand:  */     \
	/* these tables are indexed by GPR number, so a narrower mask could not describe a ZMM.     */     \
	CT(vchunkload, r_ru32)                                                                               \
	CT(vchunkadd, r_r_r)                                                                                 \
	CT(vwideaddssa, r4_r8)                                                                               \
	CT(vchunkmul, r_r_r)                                                                                 \
	/* Same table as the add and the multiply: EVEX's vpsub<w> is non-destructive, so there is  */     \
	/* nothing for QSel to legalize. The table says nothing about operand ORDER -- that is the  */     \
	/* emitter's obligation, and it matters here because subtraction does not commute.          */     \
	CT(vchunksub, r_r_r)                                                                                 \
	/* Same table again: vpxord is the same non-destructive three-operand EVEX shape.          */     \
	CT(vchunkxor, r_r_r)                                                                                 \
	/* And again for vpord, which differs from vpxord only in the operation it performs.       */     \
	CT(vchunkor, r_r_r)                                                                                  \
	/* And once more for vpandd, the third member of the same EVEX bitwise trio.               */     \
	CT(vchunkand, r_r_r)                                                                                 \
	/* P7N-B. ONE unconstrained vector result and ONE unconstrained vector input: EVEX's       */     \
	/* vpslld/vpsrld immediate forms are non-destructive two-operand, so there is nothing for  */     \
	/* QSel to legalize and no ALIAS constraint. The shift amount is a NODE FIELD, not an      */     \
	/* operand, so it does not appear in this table at all -- which is exactly why it cannot   */     \
	/* be spilled, reloaded or renamed.                                                        */     \
	CT(vchunksll, r_r)                                                                                   \
	CT(vchunksrl, r_r)                                                                                   \
	CT(vchunkstore, ri_r)                                                                                \
	CT(vstatechunkload, r)                                                                               \
	CT(vstatechunkstore, rin)                                                                            \
	/* Native-3. The SAME table as vstatechunkload, because it has the same shape: one         */     \
	/* unconstrained V512 result and no input at all, its only address being R_STATE plus a    */     \
	/* translation-time constant. It reads 4 bytes where that one reads 64, which is a fact    */     \
	/* about the emitter and not about register allocation.                                    */     \
	CT(vchunkbroadcast, r)                                                                               \
	CT(vchunkfbroadcast, r)                                                                              \
	CT(vchunkfalu, r_r_r)                                                                                \
	/* P7I fused FMA: the same all-unconstrained shape one operand wider. See CT(r_r_r_r).      */     \
	CT(vchunkfma, r_r_r_r)                                                                               \
	/* One destination, one source, both register-only V512 values -- the same table vchunksll  */     \
	/* uses, for the same shape. Emit_vchunkfsqrt opens with `vmovdqu64 out, s` exactly as      */     \
	/* Emit_vchunkfalu opens with `vmovdqu64 out, a`, so it declares no alias either.           */     \
	CT(vchunkfsqrt, r_r)                                                                                 \
	/* P9: two V512 sources in, nothing out -- the result is the mask bytes the emitter writes  */     \
	/* into CPUState. No alias to declare: neither source is modified.                          */     \
	CT(vchunkfcmpstate, rin_r)                                                                           \
	/* P10: one result, one source, both register-only. The widths differ (V512 out, V256 in) but */     \
	/* the table describes register CLASSES, not widths, so this is the same shape vchunksll uses. */     \
	CT(vchunkfwidencvt, r_r)                                                                             \
	/* P7L-B1 dependency probe: one unconstrained V512 result and two unconstrained V512      */     \
	/* inputs -- the same table as vchunkfalu, because vpblendmq is the same non-destructive   */     \
	/* three-operand EVEX shape. The table says nothing about operand ORDER, and order matters */     \
	/* here: the emitter must put `value` in SRC2 and `probe` in SRC1.                         */     \
	CT(vchunkdep, r_r_r)                                                                                 \
	/* rvvsetvl: one GPR result (the guest rd) and one GPR input (the AVL). Register-only on   */     \
	/* BOTH sides -- see CT(r_r) above for why the input may not have an immediate form.       */     \
	CT(rvvsetvl, r_r)                                                                                    \
	CT(rvvsetvlreg, r_r_r)                                                                              \
	CT(setcc, r8_r_rs32)                                                                                 \
	CT(mov, r_ri)                                                                                        \
	CT(add, r_0_rs32)                                                                                    \
	CT(sub, r_0_rs32)                                                                                    \
	CT(and, r_0_ru32)                                                                                    \
	CT(or, r_0_rs32)                                                                                     \
	CT(xor, r_0_rs32)                                                                                    \
	CT(sra, r_0_cxi)                                                                                     \
	CT(srl, r_0_cxi)                                                                                     \
	CT(sll, r_0_cxi)                             	                                                        \
	CT(mul, r_0_ru32)                                                                                    \
	CT(mulh, r_r_bx)                                                                                    \
	CT(mulhsu, r_r_bx)                                                                                 \
	CT(mulhu, r_r_bx)                                                                                   \
	CT(div, r_r_bx)                                                                                    \
	CT(divu, r_r_bx)                                                                                    \
	CT(rem, r_r_bx)                                                                                    \
	CT(remu, r_r_bx) 											

void ArchTraits::init()
{
	[[maybe_unused]] static auto x = []() {
#define CT(name, ctname)                                                                                     \
	{                                                                                                    \
		auto &info = qir::op_info[to_underlying(qir::Op::_##name)];                                  \
		info.ra_ct = CT_INFO_##ctname.ct.data();                                                     \
		info.ra_order = CT_INFO_##ctname.order.data();                                               \
	}
		ARCH_OP_CT_LIST(CT)
#undef CT
		return true;
	}();
}

bool ArchTraits::match_gp_const(qir::VType type, i64 val, RACtImm ct)
{
	if (to_underlying(ct & RACtImm::ANY)) {
		return true;
	}
	if (to_underlying(ct & RACtImm::U32) && static_cast<u32>(val) == val) {
		return true;
	}
	if (to_underlying(ct & RACtImm::S32) && static_cast<i32>(val) == val) {
		return true;
	}
	return false;
}

} // namespace dbt::qcg
