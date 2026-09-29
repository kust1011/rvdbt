#pragma once
// T3a -- PER-ROUTE execution census for the nine element-wise RVV instructions.
//
// WHY THIS EXISTS. The pre-existing evidence counters cannot answer the question T3a asks. There
// are exactly two of them, both in CPUState and both AGGREGATE:
//
//   rvv_direct_hits       one `inc` at the join of EVERY typed frame, whatever opcode it held
//   rvv_direct_fallbacks  one `inc` on the guard-miss arm of EVERY typed frame
//
// So "did vand.vv specifically take the direct route, or did it fall back?" is not answerable from
// them: a run in which vand.vv fell back on every execution while the other five ALU ops stayed
// direct produces the same two numbers as several other mixtures. Worse, four of the six ALU
// opcodes share ONE helper -- `rv32_vialu` covers vsub, vand, vor and vxor -- so even counting
// helper entries per stub symbol would not separate them.
//
// This header adds the missing distinction and nothing else. It classifies an execution by the
// GUEST INSTRUCTION ENCODING, which is the only thing that separates the four vialu opcodes, and
// counts how many times each of the nine ran through the C++ handler instead of through emitted
// host code.
//
// WHAT A NON-ZERO COUNT MEANS. `note()` is called from `H_<name>` in rv32_interp.cpp, which is the
// single point BOTH paths into the C++ implementation go through: the JIT's `qcgstub_rv32_<name>`
// wrapper calls it, and Interpreter::Execute/ExecuteBlock call it. So for a given opcode:
//
//   handler_calls[op] == 0  and  the guest executed that op N > 0 times
//     =>  all N executions ran as emitted host code, i.e. the direct route
//
// and the direct count is exactly N - handler_calls[op]. There is no third path: an execution
// either ran in emitted code or it ran here.
//
// COST. Gated on config::rvv_route_census, default OFF, and the call site is behind
// `if constexpr (name_is_vector(#name))` so no scalar handler carries even the branch. Nothing in
// the JIT-emitted fast path changes, so every pinned disassembly golden stays byte-identical --
// this census is a property of the cold side only.
//
// This is instrumentation for a correctness/route claim. It is not a timing facility and nothing
// in T3a measures time.

#include "dbt/util/common.h"

namespace dbt::rv32::route_census
{

// The nine routes the closure's element-wise scope names, plus a catch-all so an unexpected vector
// instruction is counted rather than silently ignored.
enum Route : unsigned {
	R_vsetvli,
	R_vle32,
	R_vse32,
	R_vadd_vv,
	R_vsub_vv,
	R_vmul_vv,
	R_vand_vv,
	R_vor_vv,
	R_vxor_vv,
	R_vsll_vi,
	R_vsrl_vi,
	R_vmv_vx, // A2
	R_vadd_vx, // A6
	R_vmv_vi, // A7
	R_vmv_vv, // A7
	R_vadd_vi, // A6
	R_other_vector,
	R_COUNT,
};

inline char const *route_name(unsigned r)
{
	switch (r) {
	case R_vsetvli:
		return "vsetvli";
	case R_vle32:
		return "vle32.v";
	case R_vse32:
		return "vse32.v";
	case R_vadd_vv:
		return "vadd.vv";
	case R_vsub_vv:
		return "vsub.vv";
	case R_vmul_vv:
		return "vmul.vv";
	case R_vand_vv:
		return "vand.vv";
	case R_vor_vv:
		return "vor.vv";
	case R_vxor_vv:
		return "vxor.vv";
	case R_vsll_vi:
		return "vsll.vi";
	case R_vsrl_vi:
		return "vsrl.vi";
	case R_vmv_vx:
		return "vmv.v.x";
	case R_vadd_vx:
		return "vadd.vx";
	case R_vmv_vi:
		return "vmv.v.i";
	case R_vmv_vv:
		return "vmv.v.v";
	case R_vadd_vi:
		return "vadd.vi";
	default:
		return "other-vector";
	}
}

// Counts of executions that ran in C++ rather than in emitted host code.
inline u64 g_handler_calls[R_COUNT]{};

// Classify from the 32-bit guest encoding alone. Deliberately not from the handler name: the four
// OPIVV logical/arith opcodes that share `rv32_vialu` are separable only by funct6, so the encoding
// is the only source that can tell them apart. Fields per RVV 1.0.
inline Route classify(u32 raw)
{
	u32 const opcode = raw & 0x7fu;
	u32 const funct3 = (raw >> 12) & 0x7u;
	u32 const funct6 = (raw >> 26) & 0x3fu;

	if (opcode == 0x57u) { // OP-V
		if (funct3 == 0x7u) {
			// vsetvli has bit31 == 0; vsetivli (31:30 == 0b11) and vsetvl
			// (31:25 == 0b1000000) are different instructions.
			if ((raw >> 31) == 0u)
				return R_vsetvli;
			return R_other_vector;
		}
		// A2. OPIVX funct6 010111 with vm=1 is vmv.v.x (vm=0 is vmerge.vxm, a different
		// instruction that reads v0 and vs2; it stays other-vector).
		if (funct3 == 0x4u && funct6 == 0x17u && ((raw >> 25) & 1u) == 1u)
			return R_vmv_vx;
		// A7: vmv.v.i (OPIVI) / vmv.v.v (OPIVV): funct6 010111, vm=1, vs2=0 (vs2!=0 is reserved).
		if (funct6 == 0x17u && ((raw >> 25) & 1u) == 1u && ((raw >> 20) & 0x1fu) == 0u) {
			if (funct3 == 0x3u)
				return R_vmv_vi;
			if (funct3 == 0x0u)
				return R_vmv_vv;
		}
		// A6: unmasked vadd.vx (OPIVX) / vadd.vi (OPIVI), funct6 000000.
		if (funct3 == 0x4u && funct6 == 0x00u && ((raw >> 25) & 1u) == 1u)
			return R_vadd_vx;
		if (funct3 == 0x3u && funct6 == 0x00u && ((raw >> 25) & 1u) == 1u)
			return R_vadd_vi;
		if (funct3 == 0x0u) { // OPIVV
			switch (funct6) {
			case 0x00u:
				return R_vadd_vv;
			case 0x02u:
				return R_vsub_vv;
			case 0x09u:
				return R_vand_vv;
			case 0x0au:
				return R_vor_vv;
			case 0x0bu:
				return R_vxor_vv;
			default:
				return R_other_vector;
			}
		}
		// P7N-B. OPIVI (funct3 = 0b011): the two LOGICAL shift-immediate forms that have a
		// direct route. `vm` is deliberately NOT tested, for the reason the load/store rows
		// give: a masked vsll.vi is the same guest mnemonic and is NOT admitted to the direct
		// route, so counting it in the same bucket is exactly the disclosure that matters --
		// it makes a masked form show up as a helper call against a named row instead of
		// disappearing into `other-vector`. vsra.vi (0x29) is NOT here: it is an arithmetic
		// shift with no route.
		if (funct3 == 0x3u) {
			if (funct6 == 0x25u)
				return R_vsll_vi;
			if (funct6 == 0x28u)
				return R_vsrl_vi;
			return R_other_vector;
		}
		if (funct3 == 0x2u && funct6 == 0x25u) // OPMVV vmul.vv
			return R_vmul_vv;
		return R_other_vector;
	}

	// Unit-stride, unmasked-or-not, EEW=32 load/store: nf=0, mew=0, mop=00, lumop/sumop=00000.
	// width(funct3)=0b110 is EEW 32. `vm` is not tested -- a masked vle32.v would land in the
	// same bucket, which is what we want: it is the same guest mnemonic and it is NOT admitted to
	// the direct route, so counting it here is exactly the disclosure that matters.
	bool const unit_stride = ((raw >> 28) & 0x7u) == 0u	 // nf
				 && ((raw >> 26) & 0x3u) == 0u	 // mop
				 && ((raw >> 20) & 0x1fu) == 0u; // lumop / sumop
	if (opcode == 0x07u && funct3 == 0x6u && unit_stride)
		return R_vle32;
	if (opcode == 0x27u && funct3 == 0x6u && unit_stride)
		return R_vse32;
	return R_other_vector;
}

inline void note(u32 raw) { ++g_handler_calls[classify(raw)]; }

inline void reset()
{
	for (unsigned i = 0; i < R_COUNT; ++i)
		g_handler_calls[i] = 0;
}

} // namespace dbt::rv32::route_census
