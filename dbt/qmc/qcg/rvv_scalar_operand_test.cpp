#include "dbt/guest/rv32_vector_lower.h"
#include <cstdio>
using namespace dbt;
using namespace dbt::rv32;
[[gnu::noinline]] void CheckOperand(bool ok, char const *message) {
	if (!ok) Panic(message);
}
int main() {
	VectorState vs{};
	unsigned cases = 0;
	for (u32 bytes : {1u,2u,4u,8u}) {
		u64 const mask = bytes == 8 ? ~u64(0) : (u64(1) << (8 * bytes)) - 1;
		for (u32 scalar : {0u, 1u, 0x100u, 0x80000001u, 0xffffffffu}) {
			u64 expected = bytes == 8 && (scalar & 0x80000000u) ?
				(0xffffffff00000000ull | scalar) : u64(scalar) & mask;
			u64 got = rvv_ref::vialu_rhs(vs, VSrc::VX, 0, scalar, 0, 0, bytes, 512);
			CheckOperand(got == expected, "scalar width normalization");
			for (u64 a : {u64(0), u64(1), mask, mask >> 1}) {
				CheckOperand(rvv_ref::vialu_apply(VF6_VMINU,a,got,bytes) == std::min(a,expected) &&
				    rvv_ref::vialu_apply(VF6_VMAXU,a,got,bytes) == std::max(a,expected) &&
				    rvv_ref::vicmp_apply(VF6_VMSEQ,a,got,bytes) == (a == expected), "scalar compare regression");
				++cases;
			}
		}
	}
	for (u32 imm = 0; imm < 32; ++imm) {
		vs.elem_put(1, 0, 8, 512, 1);
		rvv_ref::vialu(vs, VF6_VSLL, VSrc::VI, 2, 1, 0, 0,
			i32(imm << 27) >> 27, true, 512, 1, 8);
		CheckOperand(vs.elem_u(2,0,8,512) == (u64(1) << imm), "unsigned shift immediate regression");
		++cases;
	}
	for (u32 bytes : {1u,2u,4u,8u}) for (u32 rm=0;rm<4;++rm) {
		u64 const sign=u64(1)<<(bytes*8-1),mask=bytes==8?~u64(0):sign*2-1;
		auto setup=[&](u64 a,u64 b) {
			vs.vstart=1;vs.vxrm=rm;vs.vxsat=0;
			vs.elem_put(1,1,bytes,512,a);vs.elem_put(2,1,bytes,512,b);
			vs.elem_put(3,0,bytes,512,0x5a);vs.elem_put(3,1,bytes,512,0xa5);
		};
		auto check=[&](u64 expected,bool sat) {
			CheckOperand(vs.elem_u(3,0,bytes,512)==0x5a,"fixed point preserves prestart");
			CheckOperand(vs.elem_u(3,1,bytes,512)==(expected&mask),"fixed point boundary result");
			CheckOperand(vs.vxsat==sat&&vs.vxrm==rm,"fixed point flags");++cases;
		};
		setup(mask,mask);
		rvv_ref::vavg(vs,VF6_VAADDU,VSrc::VV,3,1,2,0,0,true,512,2,bytes);check(mask,false);
		setup(sign,sign);
		rvv_ref::vavg(vs,VF6_VAADD,VSrc::VV,3,1,2,0,0,true,512,2,bytes);check(sign,false);
		setup(sign-1,sign);
		rvv_ref::vavg(vs,VF6_VASUB,VSrc::VV,3,1,2,0,0,true,512,2,bytes);check(sign-1+(rm<2),false);
		setup(0,mask);
		rvv_ref::vavg(vs,VF6_VASUBU,VSrc::VV,3,1,2,0,0,true,512,2,bytes);check(sign+(rm==0||rm==3),false);
		setup(sign,sign);
		rvv_ref::vsmul(vs,VSrc::VV,3,1,2,0,true,512,2,bytes);check(sign-1,true);
		setup(sign,sign-1);
		rvv_ref::vsmul(vs,VSrc::VV,3,1,2,0,true,512,2,bytes);check(u64(0)-(sign-1),false);
		setup(sign,0);
		rvv_ref::vsmul(vs,VSrc::VX,3,1,2,0xffffffffu,true,512,2,bytes);check(1,false);
		setup(sign,sign);vs.vreg[0].fill(0);
		rvv_ref::vsmul(vs,VSrc::VV,3,1,2,0,false,512,2,bytes);check(0xa5,false);
	}
	// ---- reduction register legality (shared predicate, rv32_vector.h) ------------------------
	// RVV 1.0 14 leaves the DESTINATION free -- it may be v0 and may overlap the sources -- while
	// operands read at different EEWs may not overlap: a masked reduction reads v0 at EEW=1, and a
	// widening reduction reads its seed at 2*SEW inside a data group read at SEW.
	{
		// vtype fields: [5:3] vsew (SEW = 8 << vsew), [2:0] vlmul (signed log2 LMUL).
		auto vtype=[](u32 vsew,u32 vlmul){ return VType{(vsew<<VTYPE_VSEW_SHIFT)|vlmul}; };
		VType const e32m1=vtype(VSEW_E32,VLMUL_M1), e32m4=vtype(VSEW_E32,0b010),
			    e64m1=vtype(0b011,VLMUL_M1);
		auto legal=[&](bool got,char const *what){ CheckOperand(got,what);++cases; };
		auto reserved=[&](bool got,char const *what){ CheckOperand(!got,what);++cases; };
		// Destination: unconstrained by 14, including on a masked reduction.
		legal(reduction_registers_legal(e32m1,false,0,4,2,false),"masked reduction may write v0");
		legal(reduction_registers_legal(e32m1,false,4,4,4,true),"reduction vd may overlap sources");
		legal(reduction_registers_legal(e32m4,true,1,4,2,true),"widening reduction vd is free");
		// Masked sources may not be v0 (EEW=1 mask vs SEW sources); unmasked they may.
		reserved(reduction_registers_legal(e32m1,false,3,0,2,false),"masked reduction vs2=v0");
		reserved(reduction_registers_legal(e32m1,false,3,4,0,false),"masked reduction vs1=v0");
		legal(reduction_registers_legal(e32m1,true,3,0,2,true),"unmasked reduction vs2=v0 is legal");
		legal(reduction_registers_legal(e32m1,false,3,4,0,true),"unmasked reduction vs1=v0 is legal");
		// Widening: the 2*SEW seed may not sit inside the SEW data group; outside it is legal,
		// and the same pair carries no rule for the single-width forms.
		reserved(reduction_registers_legal(e32m4,true,3,4,5,true),"widening seed inside data group");
		reserved(reduction_registers_legal(e32m4,true,3,4,4,true),"widening seed at group base");
		legal(reduction_registers_legal(e32m4,true,3,4,8,true),"widening seed outside data group");
		legal(reduction_registers_legal(e32m4,false,3,4,5,true),"single-width seed may overlap");
		// 2*SEW must exist, and the data group must be LMUL-aligned.
		reserved(reduction_registers_legal(e64m1,true,3,4,2,true),"widening 2*SEW exceeds ELEN");
		legal(reduction_registers_legal(e64m1,false,3,4,2,true),"single-width SEW=64 is legal");
		reserved(reduction_registers_legal(e32m4,false,3,5,2,true),"vs2 group misaligned at LMUL=4");
	}
	// ---- same-width integer source legality (shared predicate, rv32_vector.h) -----------------
	// A masked op reads v0 at EEW=1, so no VECTOR source may be v0. Scalar operands, mask
	// destinations and unmasked forms carry no rule -- the three cases this must not reject.
	{
		auto legal=[&](bool got,char const *what){ CheckOperand(got,what);++cases; };
		auto reserved=[&](bool got,char const *what){ CheckOperand(!got,what);++cases; };
		// masked .vv: neither source may be v0.
		reserved(same_width_sources_legal(0,2,true,false),"masked .vv reads v0 as vs2");
		reserved(same_width_sources_legal(4,0,true,false),"masked .vv reads v0 as vs1");
		legal(same_width_sources_legal(4,2,true,false),"masked .vv with non-v0 sources");
		// masked .vx/.vi: only vs2 carries the rule; the vs1 field is a GPR index or an
		// immediate, so rs1 = x0 (encoded 0) must stay legal.
		reserved(same_width_sources_legal(0,2,false,false),"masked .vx reads v0 as vs2");
		legal(same_width_sources_legal(4,0,false,false),"masked .vx with rs1 = x0");
		legal(same_width_sources_legal(4,31,false,false),"masked .vi with imm field 31");
		// unmasked: unrestricted, which is what keeps vmv.v.* (encoded vs2 = v0) legal.
		legal(same_width_sources_legal(0,0,true,true),"unmasked vmv.v.v with encoded vs2=v0");
		legal(same_width_sources_legal(0,0,false,true),"unmasked vmv.v.x with encoded vs2=v0");
	}
	printf("PASS scalar_operand_cases=%u\n", cases);
}
