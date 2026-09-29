#pragma once

#include "dbt/guest/rv32_insn.h"
#include "dbt/guest/rv32_fpu_ops.h"        // OP-FP funct7 table shared with the semantics
#include "dbt/guest/rv32_vector_lower.h" // funct6 tables shared with the semantics

namespace dbt::rv32::insn
{

// RVV 1.0 11.4. vadc/vsbc take the carry/borrow-in from v0, which is a real OPERAND and not a
// mask, so their encodings FIX vm=0 and vm=1 is reserved (QEMU insn32.decode: `vadc_vvm 010000 0`,
// `vadc_vxm`, `vadc_vim`, `vsbc_vvm 010010 0`, `vsbc_vxm` -- bit 25 is a literal 0 in all five).
// Their mask-PRODUCING siblings vmadc/vmsbc are the opposite case and must not be caught here: for
// them vm=0 is the with-carry-in form and vm=1 the without-carry-in form, so both are legal
// (`vmadc_vvm 010001 .`, `vmsbc_vvm 010011 .`). vadc_form_supported keys on funct6 and source only,
// which is why the vm rule is applied at the routing site.
constexpr bool vadc_vm_legal(u32 funct6, u32 vm)
{
	return vm == 0 || (funct6 != VF6_VADC && funct6 != VF6_VSBC);
}

template <typename Provider>
struct Decoder {
	using DType = decltype(Provider::_ill);

	static DType Decode(void *insn)
	{
		auto in = *reinterpret_cast<DecodeParams *>(insn);
#define OP(name) return Provider::_##name;
#define OP_ILL OP(ill)

		switch (in.opcode()) {
		// ---- RVV 1.0, strictly matched implemented forms. Each family below checks the fields
		// that distinguish its legal encodings; anything outside those forms falls through to
		// OP_ILL, so an unsupported RVV encoding cannot execute silently (fail closed).
		case 0b1010111: /* OP-V */ {
			u32 const f6 = (in.raw >> 26) & 0x3f;
			u32 const vs1f = (in.raw >> 15) & 0x1f;
			switch (in.funct3()) {
			case 0b111: /* OPCFG: vsetvli / vsetivli / vsetvl */
				// vsetvli: bit31 == 0. vsetivli: bits[31:30] == 11 (immediate AVL).
				// vsetvl: bit31=1, bit30=0, vtype from a GPR (rs2) rather than an immediate.
				if ((in.raw >> 31) == 0)
					OP(vsetvli);
				if ((in.raw >> 30) == 0b11)
					OP(vsetivli);
				if ((in.raw >> 25) == 0b1000000)
					OP(vsetvl);
				OP_ILL;
			case 0b000: /* OPIVV */
				// vadd.vv unmasked is routed to its OWN op, not the generic family,
				// because that is the encoding with a direct QCG lowering (inline SSE2
				// emitted into the translation block, see QCG_DIRECT_LOWERING.md).
				// This is a CODEGEN routing decision, not a semantics special case: the
				// two paths are differentially verified against each other by the
				// --rvv-direct 0/1 A/B, and every other funct6 in the family -- including
				// masked vadd.vv -- goes to the generic helper below.
				if (f6 == VF6_VADD && ((in.raw >> 25) & 1) == 1)
					OP(vadd_vv);
				// vsub.vv unmasked is routed out of the generic family for exactly
				// the reason vadd.vv above is: it is the encoding with a direct
				// typed-QCG chunk lowering (S2.1, emitting vpsubd). This is a
				// CODEGEN routing decision, not a semantics special case --
				// H_vsub_vv forwards the same instruction word to the same
				// Impl_vialu body, so funct6 is still read from the word (and is
				// VF6_VSUB by decode). Every other encoding this branch could match
				// -- masked vsub.vv (vm=0), and vsub.vx in the OPIVX group below --
				// still falls through to OP(vialu).
				if (f6 == VF6_VSUB && ((in.raw >> 25) & 1) == 1)
					OP(vsub_vv);
				// vxor.vv unmasked is routed out of the generic family for the same
				// reason again (S2.2, emitting vpxord), and H_vxor_vv likewise
				// forwards the same word to the same Impl_vialu body.
				//
				// THIS SPLIT HAS ADJACENT NEIGHBOURS. VF6_VAND is 001001, VF6_VOR is
				// 001010 and VF6_VXOR is 001011, so a predicate written with `<=`, a
				// mask, or a mistyped constant would capture a guest AND or OR and run
				// it through an XOR emitter. The comparison is therefore an exact
				// equality against the shared VF6_VXOR constant from
				// rv32_vector_lower.h -- the same constant the reference helper's own
				// vialu_apply switches on -- and the route's focused test sweeps the
				// whole funct3 x funct6 x vm space to prove exactly one encoding
				// reaches Op::_vxor_vv. Since S2.3 the neighbour immediately below has
				// its own op too (vor_vv), which makes that sweep strictly more
				// load-bearing: the two ops must stay one funct6 value apart and
				// neither may absorb the other's encoding.
				if (f6 == VF6_VXOR && ((in.raw >> 25) & 1) == 1)
					OP(vxor_vv);
				// vor.vv unmasked is routed out of the generic family for the same
				// reason again (S2.3, emitting vpord), and H_vor_vv likewise
				// forwards the same word to the same Impl_vialu body.
				//
				// THIS IS THE SECOND OF THE THREE ADJACENT BITWISE VALUES TO LEAVE.
				// VF6_VAND is 001001, VF6_VOR is 001010 and VF6_VXOR is 001011. Two
				// of the three now have their own op, so the two ways to get this
				// wrong are no longer symmetric: a predicate one bit too LOW would
				// capture vand.vv and compute an OR for a guest AND, while one bit
				// too HIGH would steal the accepted S2.2 vxor.vv route and compute
				// an OR for a guest XOR -- a REGRESSION of an already-accepted
				// route, not merely a new bug. The comparison is therefore an exact
				// equality against the shared VF6_VOR constant from
				// rv32_vector_lower.h -- the same constant the reference helper's
				// own vialu_apply switches on -- and the route's focused test sweeps
				// the whole funct3 x funct6 x vm space to prove exactly one encoding
				// reaches Op::_vor_vv AND that all four earlier splits still keep
				// exactly one encoding each.
				if (f6 == VF6_VOR && ((in.raw >> 25) & 1) == 1)
					OP(vor_vv);
				// vand.vv unmasked is routed out of the generic family for the same
				// reason again (S2.4, emitting vpandd), and H_vand_vv likewise
				// forwards the same word to the same Impl_vialu body.
				//
				// THIS IS THE THIRD AND LAST OF THE THREE ADJACENT BITWISE VALUES TO
				// LEAVE. VF6_VAND is 001001, VF6_VOR is 001010 and VF6_VXOR is
				// 001011, and both values above this one are now ACCEPTED routes, so
				// an upward slip does not add a wrong route -- it TAKES an accepted
				// lowering away from vor.vv (or, two values up, from vxor.vv) and
				// computes an AND for a guest OR or XOR. Downward, 001000 is not an
				// OPIVV encoding this decoder implements at all, so a slip in that
				// direction fails closed to `ill` rather than mislowering anything.
				// The comparison is therefore an exact equality against the shared
				// VF6_VAND constant from rv32_vector_lower.h -- the same constant the
				// reference helper's own vialu_apply switches on -- and the route's
				// focused test sweeps the whole funct3 x funct6 x vm space to prove
				// exactly one encoding reaches Op::_vand_vv AND that all five earlier
				// splits still keep exactly one encoding each.
				//
				// THE FUNCT3 GROUP IS LOAD-BEARING HERE IN A WAY IT WAS NOT FOR THE
				// OTHER TWO. VF6_VAADD (OPMVV) is also 0b001001, so `vaadd.vv` shares
				// this exact funct6 and is distinguished ONLY by sitting in the
				// funct3=0b010 group rather than this one. A predicate that tested
				// funct6 without its group would capture it; the route's test carries
				// that encoding as a named negative row for exactly that reason.
				if (f6 == VF6_VAND && ((in.raw >> 25) & 1) == 1)
					OP(vand_vv);
				// vm=0 is vmerge (v0 selects, vs2 is a real operand); vm=1 is vmv.v.v,
				// which has NO vs2 operand, so that field is fixed to zero and a
				// non-zero vs2 with vm=1 is a reserved encoding (QEMU insn32.decode:
				// `vmv_v_v 010111 1 00000`). The merge form is unrestricted.
				if (f6 == VF6_VMERGE &&
				    (((in.raw >> 25) & 1) == 0 || ((in.raw >> 20) & 0x1f) == 0))
					OP(vmerge); // vmerge.vvm (vm=0) / vmv.v.v (vm=1)
				if (vicmp_supported(f6, VSrc::VV))
					OP(vicmp);
				if (vialu_form_supported(f6, VSrc::VV))
					OP(vialu);
				if (vsatadd_form_supported(f6, VSrc::VV))
					OP(vsatadd);
				if (vadc_form_supported(f6, VSrc::VV) &&
				    vadc_vm_legal(f6, (in.raw >> 25) & 1))
					OP(vadc);
				if (vsmul_supported(f6, VSrc::VV))
					OP(vsmul);
				if (vsshift_supported(f6))
					OP(vsshift);
				if (vnclip_supported(f6))
					OP(vnclip);
				if (vnshift_supported(f6))
					OP(vnshift);
				// funct6 001110 is vrgatherei16.vv here and vslideup.vx in OPIVX: the
				// same funct6 means different instructions in different funct3 groups.
				if (f6 == VF6_VRGATHER || f6 == VF6_VRGATHEREI16)
					OP(vrgather);
				if (vwred_supported(f6))
					OP(vwred);
				OP_ILL;
			case 0b100: /* OPIVX */
				// A6: exact unmasked vadd.vx -> its own op (direct typed-QCG route).
				if (f6 == VF6_VADD && ((in.raw >> 25) & 1) == 1)
					OP(vadd_vx);
				// vm=0 is vmerge (v0 selects, vs2 is a real operand); vm=1 is vmv.v.x,
				// which has NO vs2 operand, so that field is fixed to zero and a
				// non-zero vs2 with vm=1 is a reserved encoding (QEMU insn32.decode:
				// `vmv_v_x 010111 1 00000`). The merge form is unrestricted.
				if (f6 == VF6_VMERGE &&
				    (((in.raw >> 25) & 1) == 0 || ((in.raw >> 20) & 0x1f) == 0))
					OP(vmerge); // vmerge.vxm / vmv.v.x
				if (vicmp_supported(f6, VSrc::VX))
					OP(vicmp);
				if (vialu_form_supported(f6, VSrc::VX))
					OP(vialu);
				if (vsatadd_form_supported(f6, VSrc::VX))
					OP(vsatadd);
				if (vadc_form_supported(f6, VSrc::VX) &&
				    vadc_vm_legal(f6, (in.raw >> 25) & 1))
					OP(vadc);
				if (vsmul_supported(f6, VSrc::VX))
					OP(vsmul);
				if (vsshift_supported(f6))
					OP(vsshift);
				if (vnclip_supported(f6))
					OP(vnclip);
				if (vnshift_supported(f6))
					OP(vnshift);
				if (f6 == VF6_VSLIDEUP || f6 == VF6_VSLIDEDOWN)
					OP(vslide);
				if (f6 == VF6_VRGATHER)
					OP(vrgather);
				OP_ILL;
			case 0b011: /* OPIVI */
				// vmv<nr>r.v: funct6=100111, unmasked; vs1 field carries nr-1.
				if (f6 == 0b100111 && ((in.raw >> 25) & 1) == 1 &&
				    nregs_valid(vs1f + 1))
					OP(vmvNr);
				// P7N-B. Exact unmasked vsll.vi / vsrl.vi are routed out of the generic
				// family for exactly the reason the five `.vv` splits above are: these
				// are the encodings with a direct typed-QCG chunk lowering, emitting
				// vpslld / vpsrld. H_vsll_vi and H_vsrl_vi forward the same word to the
				// same Impl_vialu body, so this is a CODEGEN routing decision and not a
				// semantics special case.
				//
				// THE TWO CONSTANTS ARE NOT ADJACENT, unlike the bitwise trio: VF6_VSLL
				// is 100101 and VF6_VSRL is 101000, with VF6_VSRA at 101001 immediately
				// ABOVE the second. An `<=` or a mask here would capture vsra.vi and run
				// an ARITHMETIC shift through a LOGICAL shift emitter -- a silent
				// wrong-value bug, not a fault. Both comparisons are therefore exact
				// equalities against the shared constants from rv32_vector_lower.h, the
				// same constants the reference helper's own vialu_apply switches on, and
				// the focused test sweeps the whole funct3 x funct6 x vm space to prove
				// that exactly one encoding reaches each op and that vsra.vi still
				// reaches OP(vialu).
				// A6: exact unmasked vadd.vi -> its own op (direct typed-QCG route).
				if (f6 == VF6_VADD && ((in.raw >> 25) & 1) == 1)
					OP(vadd_vi);
				if (f6 == VF6_VSLL && ((in.raw >> 25) & 1) == 1)
					OP(vsll_vi);
				if (f6 == VF6_VSRL && ((in.raw >> 25) & 1) == 1)
					OP(vsrl_vi);
				// vm=0 is vmerge (v0 selects, vs2 is a real operand); vm=1 is vmv.v.i,
				// which has NO vs2 operand, so that field is fixed to zero and a
				// non-zero vs2 with vm=1 is a reserved encoding (QEMU insn32.decode:
				// `vmv_v_i 010111 1 00000`). The merge form is unrestricted.
				if (f6 == VF6_VMERGE &&
				    (((in.raw >> 25) & 1) == 0 || ((in.raw >> 20) & 0x1f) == 0))
					OP(vmerge); // vmerge.vim / vmv.v.i
				if (vicmp_supported(f6, VSrc::VI))
					OP(vicmp);
				if (vialu_form_supported(f6, VSrc::VI))
					OP(vialu);
				if (vsatadd_form_supported(f6, VSrc::VI))
					OP(vsatadd);
				if (vadc_form_supported(f6, VSrc::VI) &&
				    vadc_vm_legal(f6, (in.raw >> 25) & 1))
					OP(vadc);
				if (vsshift_supported(f6))
					OP(vsshift);
				if (vnclip_supported(f6))
					OP(vnclip);
				if (vnshift_supported(f6))
					OP(vnshift);
				if (f6 == VF6_VSLIDEUP || f6 == VF6_VSLIDEDOWN)
					OP(vslide);
				if (f6 == VF6_VRGATHER)
					OP(vrgather);
				OP_ILL;
			case 0b110: /* OPMVX: integer multiply / divide / multiply-accumulate */
				if (vimul_supported(f6))
					OP(vimul);
				if (vavg_supported(f6))
					OP(vavg);
				if (vwint_form_supported(f6, VSrc::VX))
					OP(vwint);
				// In OPMVX funct6 001110/001111 are vslide1up/vslide1down, NOT the
				// vslideup/vslidedown of the OPIVX group.
				if (f6 == VF6_VSLIDE1UP || f6 == VF6_VSLIDE1DOWN)
					OP(vslide);
				// vmv.s.x: funct6=010000 with vs2 == 00000, unmasked.
				if (f6 == VF6_VWXUNARY0 && ((in.raw >> 20) & 0x1f) == 0 &&
				    ((in.raw >> 25) & 1) == 1)
					OP(vmvsx);
				OP_ILL;
			case 0b001: /* OPFVV: vector-vector floating point */
			case 0b101: /* OPFVF: vector-scalar floating point (scalar from an F reg) */ {
				bool const is_vf = in.funct3() == 0b101;
				if (vfalu_supported(f6, is_vf))
					OP(vfalu);
				if (vfma_supported(f6))
					OP(vfma);
				if (vfcmp_supported(f6, is_vf))
					OP(vfcmp);
				// THE FP REDUCTIONS ARE OPFVV ONLY. Their four funct6 (000001, 000011,
				// 000101, 000111) are RESERVED in OPFVF -- the OPFVF values around them
				// are the even ones, vfadd/vfsub/vfmin/vfmax -- so testing funct6 alone
				// inside this shared case decoded four reserved encodings as reductions
				// with a scalar operand that does not exist. Same shape of rule as
				// vfwred_supported's `!is_vf` two lines below, which is why the widening
				// reductions never had this hole.
				if (!is_vf && vfred_supported(f6))
					OP(vfred);
				// funct6 110001/110011 are the widening REDUCTIONS vfwredusum.vs and
				// vfwredosum.vs, and like the narrow reductions above they exist in OPFVV
				// ONLY -- in OPFVF they are RESERVED. (An earlier comment here called them
				// widening arithmetic in OPFVF; QEMU insn32.decode has no funct3=101 row for
				// either value, and the defined OPFVF widening funct6 are the even ones:
				// 110000 vfwadd.vf, 110010 vfwsub.vf, 110100 vfwadd.wf, 110110 vfwsub.wf,
				// 111000 vfwmul.vf and the 1111xx accumulates.) The group must therefore be
				// consulted, not funct6 alone, which is what both predicates below do.
				if (vfwred_supported(f6, is_vf))
					OP(vfwred);
				if (vfwarith_supported(f6, is_vf))
					OP(vfwarith);
				if (f6 == VF6_VFUNARY0 && !is_vf && vfcvt_supported(vs1f))
					OP(vfcvt);
				if (f6 == VF6_VFUNARY1 && !is_vf && vfunary1_supported(vs1f))
					OP(vfunary1);
				if ((f6 == VF6_VSLIDE1UP || f6 == VF6_VSLIDE1DOWN) && is_vf)
					OP(vslide); // vfslide1up.vf / vfslide1down.vf
				// Same split as the integer merges above: vfmv.v.f (vm=1) has no vs2
				// operand and fixes the field to zero (`vfmv_v_f 010111 1 00000`).
				if (f6 == VF6_VFMERGE && is_vf &&
				    (((in.raw >> 25) & 1) == 0 || ((in.raw >> 20) & 0x1f) == 0))
					OP(vfmerge); // vfmerge.vfm (vm=0) / vfmv.v.f (vm=1)
				// vfmv.f.s: OPFVV, vs1==0, unmasked. vfmv.s.f: OPFVF, vs2==0, unmasked.
				if (f6 == VF6_VWFUNARY0 && !is_vf && vs1f == 0 &&
				    ((in.raw >> 25) & 1) == 1)
					OP(vfmvfs);
				if (f6 == VF6_VWFUNARY0 && is_vf && ((in.raw >> 20) & 0x1f) == 0 &&
				    ((in.raw >> 25) & 1) == 1)
					OP(vfmvsf);
				OP_ILL;
			}
			case 0b010: /* OPMVV */
				// vmul.vv unmasked is routed to its OWN op, not the generic vimul
				// family, for exactly the reason vadd.vv is routed out of OPIVV above:
				// that is the encoding with a direct typed-QCG chunk lowering (P3.5a).
				// This is a CODEGEN routing decision, not a semantics special case --
				// H_vmul_vv calls the same rvv_fast::try_imul / rvv_ref::vimul pair the
				// family handler calls, with the same funct6 read out of the same
				// instruction word. Every other encoding this branch could match --
				// masked vmul.vv (vm=0), and the whole VMULH*/VDIV*/VREM*/VMACC set at
				// any vm -- still falls through to OP(vimul) below.
				if (f6 == VF6_VMUL && ((in.raw >> 25) & 1) == 1)
					OP(vmul_vv);
				if (vimul_supported(f6))
					OP(vimul);
				// Reductions: vd[0] = vs1[0] OP fold(vs2 group).
				if (vred_supported(f6))
					OP(vred);
				// vmv.x.s: funct6=010000 with vs1 == 00000, unmasked.
				if (f6 == VF6_VWXUNARY0 && vs1f == 0 && ((in.raw >> 25) & 1) == 1)
					OP(vmvxs);
				// Mask-register logic is always unmasked (vm must be 1).
				if (vmlogic_supported(f6) && ((in.raw >> 25) & 1) == 1)
					OP(vmlogic);
				// vid.v: funct6=010100 with vs1 field == 10001 (VID sub-encoding) AND
				// vs2 == 0. Unlike its VMUNARY0 siblings -- vmsbf/vmsof/vmsif/viota all
				// READ a mask from vs2 -- vid.v has no source operand at all, so the
				// field is fixed to zero and a non-zero vs2 is a reserved encoding
				// (riscv-opcodes / QEMU insn32.decode: `vid_v 010100 . 00000 10001`).
				if (f6 == 0b010100 && vs1f == 0b10001 && ((in.raw >> 20) & 0x1f) == 0)
					OP(vid);
				// VWXUNARY0 also carries vcpop.m (vs1=10000) and vfirst.m (vs1=10001),
				// which read a mask and write a GPR. vmv.x.s above is vs1=00000.
				if (f6 == VF6_VWXUNARY0 && vmaskpop_supported(vs1f))
					OP(vmaskpop);
				// VMUNARY0: vmsbf/vmsof/vmsif and viota.
				if (f6 == VF6_VMUNARY0 && vmunary_supported(vs1f))
					OP(vmunary);
				if (f6 == VF6_VCOMPRESS && ((in.raw >> 25) & 1) == 1)
					OP(vcompress);
				if (vavg_supported(f6))
					OP(vavg);
				if (vwint_form_supported(f6, VSrc::VV))
					OP(vwint);
				// VXUNARY0: the vs1 field selects vsext/vzext .vf2/.vf4/.vf8.
				if (f6 == VF6_VXUNARY0 && vext_supported(vs1f))
					OP(vext);
				OP_ILL;
			default:
				OP_ILL;
			}
		}
		case 0b0000111: /* LOAD-FP: scalar flw/fld share this opcode with vector loads,
				   distinguished by the width field (funct3). */
			if (in.funct3() == 0b010)
				OP(flw);
			if (in.funct3() == 0b011)
				OP(fld);
			// width(funct3)=110 => EEW=32; nf(31:29)=000 (single reg); mew(28)=0;
			// mop(27:26)=00 (unit-stride); vm(25)=1 (unmasked); lumop(24:20)=00000.
			// Unit-stride load at ANY supported EEW (the width field selects it, not SEW):
			// nf=000 (single group), mew=0, mop=00 (unit-stride), lumop=00000.
			// vm may be 0 or 1 -- masked loads leave inactive elements undisturbed.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 && ((in.raw >> 26) & 0x3) == 0 &&
			    ((in.raw >> 20) & 0x1f) == 0)
				OP(vle);
			// vlm.v: lumop=01011. Moves ceil(vl/8) BYTES of one register and ignores
			// SEW/LMUL entirely, so it is NOT a special case of the unit-stride form.
			if (in.funct3() == 0b000 && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 && ((in.raw >> 26) & 0x3) == 0 &&
			    ((in.raw >> 25) & 1) == 1 && ((in.raw >> 20) & 0x1f) == 0b01011)
				OP(vlm);
			// Fault-only-first: mop=00, lumop=10000. Shares the unit-stride encoding
			// space, so it must be matched BEFORE the generic unit-stride test would
			// otherwise reject it on lumop.
			//
			// nf IS NOT CONSTRAINED HERE: nf != 0 is the fault-only-first SEGMENT form
			// (vlseg<nf>e<eew>ff.v, 7.8.1), which is the same instruction with nf fields
			// per element and the same trap rule, so it routes to the same handler rather
			// than to vlseg -- the fault/trim behaviour is what the handler exists for.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 28) & 1) == 0 &&
			    ((in.raw >> 26) & 0x3) == 0 && ((in.raw >> 20) & 0x1f) == 0b10000)
				OP(vleff);
			// Strided load: mop=10, rs2 = signed byte stride.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 && ((in.raw >> 26) & 0x3) == 0b10)
				OP(vlse);
			// vl<nf>re<eew>.v: whole-register load. mop=00, lumop=01000, vm=1; nf encodes
			// nregs-1. Width selects EEW but the transfer is whole-register either way.
			//
			// THE WIDTH FIELD IS STILL CHECKED. Only the four EEW encodings are defined for
			// this instruction (QEMU insn32.decode has vl<nr>re8/16/32/64 at width 000/101/
			// 110/111 and nothing else), and the two remaining values are not free: width=001
			// is the scalar Zfh `flh`, which this decoder does not implement and must fail
			// closed rather than execute as a vector whole-register move, and width=100 is
			// reserved. widths 010/011 never reach here -- flw/fld are matched above.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 28) & 1) == 0 &&
			    ((in.raw >> 26) & 0x3) == 0 &&
			    ((in.raw >> 25) & 1) == 1 && ((in.raw >> 20) & 0x1f) == 0b01000 &&
			    nregs_valid((((in.raw >> 29) & 0x7) + 1)))
				OP(vlNre);
			// Indexed (gather) load: mop=01 unordered, mop=11 ordered. nf=0 here; the
			// segment forms are handled below. The width field gives the INDEX EEW.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 &&
			    (((in.raw >> 26) & 0x3) == 0b01 || ((in.raw >> 26) & 0x3) == 0b11))
				OP(vlxei);
			// Segment load: nf != 0. Unit-stride (mop=00, lumop=00000), strided (mop=10)
			// and indexed (mop=01/11) segment forms all route here; the handler reads mop.
			// lumop must be 00000 for the unit-stride form -- 01000 is the whole-register
			// encoding handled above, and the fault-only-first lumop=10000 is NOT
			// implemented and must keep falling through to OP_ILL.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) != 0 &&
			    ((in.raw >> 28) & 1) == 0 &&
			    ((((in.raw >> 26) & 0x3) == 0b00 && ((in.raw >> 20) & 0x1f) == 0) ||
			     ((in.raw >> 26) & 0x3) == 0b10 || ((in.raw >> 26) & 0x3) == 0b01 ||
			     ((in.raw >> 26) & 0x3) == 0b11))
				OP(vlseg);
			OP_ILL;
		case 0b0100111: /* STORE-FP: scalar fsw/fsd share this opcode with vector stores. */
			if (in.funct3() == 0b010)
				OP(fsw);
			if (in.funct3() == 0b011)
				OP(fsd);
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 && ((in.raw >> 26) & 0x3) == 0 &&
			    ((in.raw >> 20) & 0x1f) == 0)
				OP(vse);
			// Strided store: mop=10, rs2 = signed byte stride.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 && ((in.raw >> 26) & 0x3) == 0b10)
				OP(vsse);
			// vsm.v: sumop=01011, same shape as vlm.v.
			if (in.funct3() == 0b000 && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 && ((in.raw >> 26) & 0x3) == 0 &&
			    ((in.raw >> 25) & 1) == 1 && ((in.raw >> 20) & 0x1f) == 0b01011)
				OP(vsm);
			// vs<nf>r.v: whole-register store. width=000, mop=00, sumop=01000, vm=1.
			if (in.funct3() == 0b000 && ((in.raw >> 28) & 1) == 0 &&
			    ((in.raw >> 26) & 0x3) == 0 && ((in.raw >> 25) & 1) == 1 &&
			    ((in.raw >> 20) & 0x1f) == 0b01000 &&
			    nregs_valid((((in.raw >> 29) & 0x7) + 1)))
				OP(vsNr);
			// Indexed (scatter) store: mop=01 unordered, mop=11 ordered, nf=0.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) == 0 &&
			    ((in.raw >> 28) & 1) == 0 &&
			    (((in.raw >> 26) & 0x3) == 0b01 || ((in.raw >> 26) & 0x3) == 0b11))
				OP(vsxei);
			// Segment store: nf != 0, in unit-stride, strided or indexed form.
			if (eew_width_supported(in.funct3()) && ((in.raw >> 29) & 0x7) != 0 &&
			    ((in.raw >> 28) & 1) == 0 &&
			    ((((in.raw >> 26) & 0x3) == 0b00 && ((in.raw >> 20) & 0x1f) == 0) ||
			     ((in.raw >> 26) & 0x3) == 0b10 || ((in.raw >> 26) & 0x3) == 0b01 ||
			     ((in.raw >> 26) & 0x3) == 0b11))
				OP(vsseg);
			OP_ILL;
		case 0b1010011: /* OP-FP: all scalar FP arithmetic, keyed by funct7 */
			if (fpop_supported(in.raw))
				OP(fpop);
			OP_ILL;
		case 0b1000011: /* MADD  */
			if (fma_fmt_supported(in.raw))
				OP(fmadd);
			OP_ILL;
		case 0b1000111: /* MSUB  */
			if (fma_fmt_supported(in.raw))
				OP(fmsub);
			OP_ILL;
		case 0b1001011: /* NMSUB */
			if (fma_fmt_supported(in.raw))
				OP(fnmsub);
			OP_ILL;
		case 0b1001111: /* NMADD */
			if (fma_fmt_supported(in.raw))
				OP(fnmadd);
			OP_ILL;
		case 0b0110111:
			OP(lui);
		case 0b0010111:
			OP(auipc);
		case 0b1101111:
			OP(jal);
		case 0b1100111:
			switch (in.funct3()) {
			case 0b000:
				OP(jalr);
			default:
				OP_ILL;
			}
		case 0b1100011: /* bcc */
			switch (in.funct3()) {
			case 0b000:
				OP(beq);
			case 0b001:
				OP(bne);
			case 0b100:
				OP(blt);
			case 0b101:
				OP(bge);
			case 0b110:
				OP(bltu);
			case 0b111:
				OP(bgeu);
			default:
				OP_ILL;
			}
		case 0b0000011: /* lX */
			switch (in.funct3()) {
			case 0b000:
				OP(lb);
			case 0b001:
				OP(lh);
			case 0b010:
				OP(lw);
			case 0b100:
				OP(lbu);
			case 0b101:
				OP(lhu);
			default:
				OP_ILL;
			}
		case 0b0100011: /* sX */
			switch (in.funct3()) {
			case 0b000:
				OP(sb);
			case 0b001:
				OP(sh);
			case 0b010:
				OP(sw);
			default:
				OP_ILL;
			}
		case 0b0010011: /* i-type arithm */
			switch (in.funct3()) {
			case 0b000:
				OP(addi);
			case 0b010:
				OP(slti);
			case 0b011:
				OP(sltiu);
			case 0b100:
				OP(xori);
			case 0b110:
				OP(ori);
			case 0b111:
				OP(andi);
			case 0b001:
				OP(slli);
			case 0b101:
				switch (in.funct7()) {
				case 0b0000000:
					OP(srli);
				case 0b0100000:
					OP(srai);
				default:
					OP_ILL;
				}
			default:
				OP_ILL;
			}
		case 0b0110011: /* r-type arithm */
			switch (in.funct3()) {
			case 0b000:
				switch (in.funct7()) {
				case 0b0000000:
					OP(add);
				case 0b0100000:
					OP(sub);
				case 0b0000001:
					OP(mul);
				default:
					OP_ILL;
				}
			case 0b001:
				switch (in.funct7()) {
				case 0b0000000:
					OP(sll);
				case 0b0000001:
					OP(mulh);
				default:
					OP_ILL;
				}
			case 0b010:
				switch (in.funct7()) {
				case 0b0000000:
					OP(slt);
				case 0b0000001:
					OP(mulhsu);
				default:
					OP_ILL;
				}
			case 0b011:
				switch (in.funct7()) {
				case 0b0000000:
					OP(sltu);
				case 0b0000001:
					OP(mulhu);
				default:
					OP_ILL;
				}
			case 0b100:
				switch (in.funct7()) {
				case 0b0000000:
					OP(xor);
				case 0b0000001:
					OP(div);
				default:
					OP_ILL;
				}
			case 0b101:
				switch (in.funct7()) {
				case 0b0000000:
					OP(srl);
				case 0b0100000:
					OP(sra);
				case 0b0000001:
					OP(divu);
				default:
					OP_ILL;
				}
			case 0b110:
				switch (in.funct7()) {
				case 0b0000000:
					OP(or);
				case 0b0000001:
					OP(rem);
				default:
					OP_ILL;
				}
			case 0b111:
				switch (in.funct7()) {
				case 0b0000000:
					OP(and);
				case 0b0000001:
					OP(remu);
				default:
					OP_ILL;
				}
			default:
				OP_ILL;
			}
		case 0b0001111:
			switch (in.funct3()) { // TODO: check other fields
			case 0b000:
				OP(fence);
			case 0b001:
				OP(fencei);
			default:
				OP_ILL;
			}
		case 0b1110011:
			switch (in.funct3()) {
				case 0b000:  // SYSTEM instructions (ecall/ebreak)
					switch (in.funct12()) {
						case 0b000000000000:
							OP(ecall);
						case 0b000000000001:
							OP(ebreak);
						case 0b001100000010:
							OP(mret);
						default:
							OP_ILL;
					}
				case 0b001:
					OP(csrrw);
				case 0b010:
					OP(csrrs);
				case 0b011:
					OP(csrrc);
				case 0b101:
					OP(csrrwi);
				case 0b110:
					OP(csrrsi);
				case 0b111:
					OP(csrrci);
				default:
					OP_ILL;
			}
		case 0b0101111:
			switch (in.funct3()) {
			case 0b010:
				switch (in.funct7() >> 2) {
				case 0b00010:
					OP(lrw);
				case 0b00011:
					OP(scw);
				case 0b00001:
					OP(amoswapw);
				case 0b00000:
					OP(amoaddw);
				case 0b00100:
					OP(amoxorw);
				case 0b01100:
					OP(amoandw);
				case 0b01000:
					OP(amoorw);
				case 0b10000:
					OP(amominw);
				case 0b10100:
					OP(amomaxw);
				case 0b11000:
					OP(amominuw);
				case 0b11100:
					OP(amomaxuw);
				default:
					OP_ILL;
				}
			default:
				OP_ILL;
			}
		default:
			OP_ILL;
		}
#undef OP
#undef OP_ILL
	}

private:
	Decoder() = delete;
	struct DecodeParams : public Base {
		INSN_FIELD(funct3);
		INSN_FIELD(funct7);
		INSN_FIELD(funct12);
		INSN_FIELD(rd)
		INSN_FIELD(rs1)
	};
};

} // namespace dbt::rv32::insn
