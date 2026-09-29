// Reserved RVV encodings the decoder used to accept, and the legal neighbours that must keep
// decoding exactly as before.
//
// Every row here is one encoding, checked through the SAME Decoder template the interpreter and the
// translator use -- not a copy of the rule. Three holes are closed, and each is paired with the
// legal encoding one field away from it, because the failure mode of a fix like this is not "the
// reserved word still decodes" but "the legal word stopped decoding":
//
//   1. THE FP REDUCTIONS ARE OPFVV ONLY. funct6 000001/000011/000101/000111 are vfredusum,
//      vfredosum, vfredmin, vfredmax in OPFVV (funct3 001) and are RESERVED in OPFVF (funct3 101),
//      where the implemented values are the EVEN neighbours vfadd/vfsub/vfmin/vfmax. The decoder
//      tested funct6 alone inside a case shared by both groups.
//   2. vid.v HAS NO SOURCE OPERAND, so its vs2 field is fixed to zero. Its VMUNARY0 siblings
//      vmsbf/vmsof/vmsif/viota DO read vs2, which is why the check belongs on this encoding alone.
//   3. vmv.v.v / vmv.v.x / vmv.v.i / vfmv.v.f (vm=1) HAVE NO vs2 OPERAND and fix that field to
//      zero; the vm=0 forms of the same funct6 are vmerge/vfmerge, where vs2 is a real operand and
//      nothing is restricted.
//   4. THE INTEGER MIN/MAX INSTRUCTIONS HAVE NO IMMEDIATE FORM (RVV 1.0 11.8): funct6 000100..
//      000111 exist as .vv and .vx only, so those four values in OPIVI are reserved. The decoder
//      admitted them through the generic vialu family, which is shared by all three sources.
//   5. vadc / vsbc TAKE v0 AS A CARRY OPERAND, NOT AS A MASK (11.4), and their encodings fix vm=0;
//      vm=1 is reserved for those two funct6. Their mask-producing siblings vmadc/vmsbc are the
//      opposite case -- vm=0 is with-carry-in, vm=1 without -- so both values are legal there.
//   6. THE WIDENING FP REDUCTIONS ARE OPFVV ONLY, exactly like the narrow ones in item 1: funct6
//      110001/110011 are vfwredusum.vs/vfwredosum.vs and are reserved in OPFVF, where the defined
//      widening values are the even neighbours vfwadd.vf/vfwsub.vf.
//   7. vl<nr>re<eew>.v IS DEFINED FOR FOUR WIDTHS ONLY (000/101/110/111). The decoder ignored the
//      width field, so width=001 -- the scalar Zfh `flh`, which this decoder does not implement --
//      and the reserved width=100 executed as whole-register vector loads.
//
// The authority for all of them is the official encoding table as carried by riscv-opcodes and by
// QEMU's target/riscv/insn32.decode, where `vid_v 010100 . 00000 10001`, `vmv_v_v 010111 1 00000`,
// `vfmv_v_f 010111 1 00000`, the four `vfred*_vs ... 001 ...` rows, `vadc_vvm 010000 0` / `vsbc_vvm
// 010010 0` against `vmadc_vvm 010001 .`, the absent `vminu_vi`/`vmax_vi` rows, the absent OPFVF
// rows for 110001/110011, and the `vl<nr>re8/16/32/64_v` set state exactly these fields.

#include "dbt/guest/rv32_decode.h"

#include <cstdio>
#include <cstdlib>

namespace dbt::qcg::test
{

using namespace dbt::rv32;

// The Op enum values themselves, so Decode returns the decoded opcode directly.
struct OpProvider {
#define OP(name, format_, flags_) static constexpr rv32::insn::Op _##name = rv32::insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

static rv32::insn::Op DecodeWord(u32 word)
{
	u32 w = word;
	return rv32::insn::Decoder<OpProvider>::Decode(&w);
}

// funct6[31:26] vm[25] vs2[24:20] vs1[19:15] funct3[14:12] vd[11:7] opcode=0x57
static constexpr u32 V(u32 f6, u32 vm, u32 vs2, u32 vs1, u32 f3, u32 vd)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}

static constexpr u32 F3_OPIVV = 0b000, F3_OPFVV = 0b001, F3_OPMVV = 0b010, F3_OPIVI = 0b011,
		     F3_OPIVX = 0b100, F3_OPFVF = 0b101;

// Vector memory encoding: nf[31:29] mew[28] mop[27:26] vm[25] lumop/rs2[24:20] rs1[19:15]
// width[14:12] vd[11:7] opcode. mew is always 0 here (the 128-bit EEW encoding is not defined).
static constexpr u32 OPC_LOADFP = 0b0000111, OPC_STOREFP = 0b0100111;
static constexpr u32 VMEM(u32 nf, u32 mop, u32 vm, u32 lumop, u32 width, u32 opcode)
{
	return (nf << 29) | (mop << 26) | (vm << 25) | (lumop << 20) | (2 << 15) | (width << 12) |
	       (3 << 7) | opcode;
}

int main()
{
	using Op32 = rv32::insn::Op;
	struct Row {
		char const *name;
		u32 word;
		Op32 want;
	};
	Row const rows[] = {
	    // 1. FP reductions: OPFVV decodes, OPFVF is reserved. The even funct6 next door are the
	    //    real OPFVF instructions and must be untouched.
	    {"vfredusum.vs (OPFVV)", V(VF6_VFREDUSUM, 1, 1, 2, F3_OPFVV, 3), Op32::_vfred},
	    {"funct6 000001 in OPFVF (reserved)", V(VF6_VFREDUSUM, 1, 1, 2, F3_OPFVF, 3), Op32::_ill},
	    {"vfredmax.vs (OPFVV)", V(VF6_VFREDMAX, 1, 1, 2, F3_OPFVV, 3), Op32::_vfred},
	    {"funct6 000111 in OPFVF (reserved)", V(VF6_VFREDMAX, 1, 1, 2, F3_OPFVF, 3), Op32::_ill},
	    {"vfmax.vf (OPFVF, the even neighbour)", V(VF6_VFMAX, 1, 1, 2, F3_OPFVF, 3), Op32::_vfalu},
	    {"vfmin.vf (OPFVF, the even neighbour)", V(VF6_VFMIN, 1, 1, 2, F3_OPFVF, 3), Op32::_vfalu},
	    {"vfredmin.vs masked (OPFVV)", V(VF6_VFREDMIN, 0, 1, 2, F3_OPFVV, 3), Op32::_vfred},

	    // 2. vid.v fixes vs2 to zero; viota.m, its sibling under the same funct6, reads vs2.
	    {"vid.v vs2=0", V(VF6_VMUNARY0, 1, 0, 0b10001, F3_OPMVV, 3), Op32::_vid},
	    {"vid.v masked, vs2=0", V(VF6_VMUNARY0, 0, 0, 0b10001, F3_OPMVV, 3), Op32::_vid},
	    {"vid.v with vs2=1 (reserved)", V(VF6_VMUNARY0, 1, 1, 0b10001, F3_OPMVV, 3), Op32::_ill},
	    {"viota.m vs2=5 (sibling keeps vs2)", V(VF6_VMUNARY0, 1, 5, 0b10000, F3_OPMVV, 3),
	     Op32::_vmunary},
	    {"vmsbf.m vs2=7 (sibling keeps vs2)", V(VF6_VMUNARY0, 1, 7, 0b00001, F3_OPMVV, 3),
	     Op32::_vmunary},

	    // 3. vm=1 is vmv.v.*, which fixes vs2 to zero; vm=0 is vmerge, where vs2 is an operand.
	    {"vmv.v.v vs2=0", V(VF6_VMERGE, 1, 0, 2, F3_OPIVV, 3), Op32::_vmerge},
	    {"vmv.v.v with vs2=3 (reserved)", V(VF6_VMERGE, 1, 3, 2, F3_OPIVV, 3), Op32::_ill},
	    {"vmerge.vvm vs2=3 (vm=0, unrestricted)", V(VF6_VMERGE, 0, 3, 2, F3_OPIVV, 3),
	     Op32::_vmerge},
	    {"vmv.v.x vs2=0", V(VF6_VMERGE, 1, 0, 2, F3_OPIVX, 3), Op32::_vmerge},
	    {"vmv.v.x with vs2=3 (reserved)", V(VF6_VMERGE, 1, 3, 2, F3_OPIVX, 3), Op32::_ill},
	    {"vmerge.vxm vs2=3 (vm=0)", V(VF6_VMERGE, 0, 3, 2, F3_OPIVX, 3), Op32::_vmerge},
	    {"vmv.v.i vs2=0", V(VF6_VMERGE, 1, 0, 2, F3_OPIVI, 3), Op32::_vmerge},
	    {"vmv.v.i with vs2=3 (reserved)", V(VF6_VMERGE, 1, 3, 2, F3_OPIVI, 3), Op32::_ill},
	    {"vmerge.vim vs2=3 (vm=0)", V(VF6_VMERGE, 0, 3, 2, F3_OPIVI, 3), Op32::_vmerge},
	    {"vfmv.v.f vs2=0", V(VF6_VFMERGE, 1, 0, 2, F3_OPFVF, 3), Op32::_vfmerge},
	    {"vfmv.v.f with vs2=2 (reserved)", V(VF6_VFMERGE, 1, 2, 2, F3_OPFVF, 3), Op32::_ill},
	    {"vfmerge.vfm vs2=2 (vm=0)", V(VF6_VFMERGE, 0, 2, 2, F3_OPFVF, 3), Op32::_vfmerge},

	    // 4. Integer min/max exist as .vv and .vx only; the OPIVI group is reserved for them.
	    //    vand.vi is the control: it is a vialu family member one funct6 group away that
	    //    DOES have an immediate form and must keep decoding.
	    {"vminu.vi (no immediate form, reserved)", V(VF6_VMINU, 1, 1, 2, F3_OPIVI, 3), Op32::_ill},
	    {"vmax.vi (no immediate form, reserved)", V(VF6_VMAX, 1, 1, 2, F3_OPIVI, 3), Op32::_ill},
	    {"vminu.vv (the .vv form is legal)", V(VF6_VMINU, 1, 1, 2, F3_OPIVV, 3), Op32::_vialu},
	    {"vmax.vx (the .vx form is legal)", V(VF6_VMAX, 1, 1, 2, F3_OPIVX, 3), Op32::_vialu},
	    {"vand.vi (immediate form exists)", V(VF6_VAND, 1, 1, 2, F3_OPIVI, 3), Op32::_vialu},

	    // 5. vadc/vsbc read v0 as a carry OPERAND and fix vm=0; vmadc/vmsbc take both vm values.
	    {"vadc.vvm with vm=1 (reserved)", V(VF6_VADC, 1, 1, 2, F3_OPIVV, 3), Op32::_ill},
	    {"vadc.vim with vm=1 (reserved)", V(VF6_VADC, 1, 1, 2, F3_OPIVI, 3), Op32::_ill},
	    {"vsbc.vxm with vm=1 (reserved)", V(VF6_VSBC, 1, 1, 2, F3_OPIVX, 3), Op32::_ill},
	    {"vadc.vvm vm=0 (the legal form)", V(VF6_VADC, 0, 1, 2, F3_OPIVV, 3), Op32::_vadc},
	    {"vsbc.vxm vm=0 (the legal form)", V(VF6_VSBC, 0, 1, 2, F3_OPIVX, 3), Op32::_vadc},
	    {"vmadc.vv vm=1 (sibling, both vm legal)", V(VF6_VMADC, 1, 1, 2, F3_OPIVV, 3), Op32::_vadc},
	    {"vmsbc.vv vm=1 (sibling, both vm legal)", V(VF6_VMSBC, 1, 1, 2, F3_OPIVV, 3), Op32::_vadc},

	    // 6. The WIDENING FP reductions are OPFVV only, exactly like the narrow ones in item 1.
	    {"funct6 110001 in OPFVF (reserved)", V(VF6_VFWREDUSUM, 1, 1, 2, F3_OPFVF, 3), Op32::_ill},
	    {"funct6 110011 in OPFVF (reserved)", V(VF6_VFWREDOSUM, 1, 1, 2, F3_OPFVF, 3), Op32::_ill},
	    {"vfwredusum.vs (OPFVV)", V(VF6_VFWREDUSUM, 1, 1, 2, F3_OPFVV, 3), Op32::_vfwred},
	    {"vfwadd.vf (the even neighbour, OPFVF)", V(VF6_VFWADD, 1, 1, 2, F3_OPFVF, 3),
	     Op32::_vfwarith},
	    {"vfwsub.vf (the even neighbour, OPFVF)", V(VF6_VFWSUB, 1, 1, 2, F3_OPFVF, 3),
	     Op32::_vfwarith},

	    // 7. vl<nr>re<eew>.v is defined for the four EEW widths only. width=001 is the scalar
	    //    Zfh flh and width=100 is reserved; neither is a whole-register vector load. The
	    //    store side (vs<nr>r.v, width=000 only) is the control that must not move.
	    {"vl1re32.v width=110", VMEM(0, 0, 1, 0b01000, 0b110, OPC_LOADFP), Op32::_vlNre},
	    {"vl8re8.v width=000", VMEM(7, 0, 1, 0b01000, 0b000, OPC_LOADFP), Op32::_vlNre},
	    {"whole-reg load width=001 (flh, reserved here)",
	     VMEM(0, 0, 1, 0b01000, 0b001, OPC_LOADFP), Op32::_ill},
	    {"whole-reg load width=100 (reserved)", VMEM(0, 0, 1, 0b01000, 0b100, OPC_LOADFP),
	     Op32::_ill},
	    {"vs1r.v width=000 (store side unchanged)", VMEM(0, 0, 1, 0b01000, 0b000, OPC_STOREFP),
	     Op32::_vsNr},
	};

	int bad = 0, legal = 0, reserved = 0;
	for (auto const &r : rows) {
		auto const got = DecodeWord(r.word);
		bool const ok = got == r.want;
		if (r.want == Op32::_ill)
			++reserved;
		else
			++legal;
		if (!ok) {
			++bad;
			printf("  MISMATCH %-40s word=%08x got=%d want=%d\n", r.name, r.word, (int)got,
			       (int)r.want);
		} else {
			printf("  ok  %-40s word=%08x -> %s\n", r.name, r.word,
			       r.want == Op32::_ill ? "ill (reserved)" : "decoded");
		}
	}
	// Both halves must be non-empty: a table of only-reserved rows could be satisfied by a
	// decoder that rejected everything, and a table of only-legal rows by the old one.
	if (!legal || !reserved) {
		printf("RESULT FAIL (legal=%d reserved=%d)\n", legal, reserved);
		return 1;
	}
	printf("%s (%d rows: %d legal, %d reserved, %d mismatches)\n", bad ? "RESULT FAIL" : "RESULT PASS",
	       (int)(sizeof(rows) / sizeof(rows[0])), legal, reserved, bad);
	return bad != 0;
}

} // namespace dbt::qcg::test

int main() { return dbt::qcg::test::main(); }
