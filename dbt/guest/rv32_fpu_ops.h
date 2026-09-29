#pragma once

// Which OP-FP / FMA encodings this substrate implements. Shared by the decoder and the
// semantics so an encoding the decoder admits is always one the handler implements; anything
// else falls through to `ill` and fails closed.

#include "dbt/guest/rv32_fpu.h"

namespace dbt::rv32
{

// funct7[6:2] selects the operation, funct7[1:0] selects the format (00=S single, 01=D double).
// Only S and D are implemented -- H (10) and Q (11) are separate standard extensions and are
// deliberately NOT admitted, rather than silently treated as S/D.
constexpr u32 fp_fmt(u32 raw) { return (raw >> 25) & 0x3; }
constexpr u32 fp_op5(u32 raw) { return (raw >> 27) & 0x1f; }
constexpr bool fp_fmt_supported(u32 raw) { return fp_fmt(raw) == 0b00 || fp_fmt(raw) == 0b01; }

enum : u32 {
	FPOP_ADD = 0b00000,
	FPOP_SUB = 0b00001,
	FPOP_MUL = 0b00010,
	FPOP_DIV = 0b00011,
	FPOP_SQRT = 0b01011,
	FPOP_SGNJ = 0b00100,  // fsgnj / fsgnjn / fsgnjx by funct3
	FPOP_MINMAX = 0b00101, // fmin / fmax by funct3
	FPOP_CVT_F_F = 0b01000, // fcvt.s.d / fcvt.d.s
	FPOP_CMP = 0b10100,	// fle / flt / feq by funct3
	FPOP_CVT_I_F = 0b11000, // fcvt.w.<fmt> / fcvt.wu.<fmt>
	FPOP_CVT_F_I = 0b11010, // fcvt.<fmt>.w / fcvt.<fmt>.wu
	FPOP_MV_X_F = 0b11100,	// fmv.x.w (funct3=000) / fclass (funct3=001)
	FPOP_MV_F_X = 0b11110,	// fmv.w.x
};

constexpr bool fma_fmt_supported(u32 raw) { return fp_fmt_supported(raw); }

constexpr bool fpop_supported(u32 raw)
{
	if (!fp_fmt_supported(raw))
		return false;
	u32 const f3 = (raw >> 12) & 0x7;
	u32 const rs2 = (raw >> 20) & 0x1f;
	switch (fp_op5(raw)) {
	case FPOP_ADD:
	case FPOP_SUB:
	case FPOP_MUL:
	case FPOP_DIV:
		return true;
	case FPOP_SQRT:
		return rs2 == 0;
	case FPOP_SGNJ:
		return f3 <= 0b010; // fsgnj / fsgnjn / fsgnjx
	case FPOP_MINMAX:
		return f3 <= 0b001;
	case FPOP_CMP:
		return f3 <= 0b010; // fle / flt / feq
	case FPOP_CVT_F_F:
		// fcvt.s.d has fmt=S and rs2=01; fcvt.d.s has fmt=D and rs2=00.
		return (fp_fmt(raw) == 0b00 && rs2 == 0b00001) ||
		       (fp_fmt(raw) == 0b01 && rs2 == 0b00000);
	case FPOP_CVT_I_F:
	case FPOP_CVT_F_I:
		return rs2 <= 1; // .w (0) and .wu (1); .l/.lu are RV64 only
	case FPOP_MV_X_F:
		// fmv.x.w is single-precision only in RV32 (no fmv.x.d without RV64).
		return (f3 == 0b000 && fp_fmt(raw) == 0b00 && rs2 == 0) || (f3 == 0b001 && rs2 == 0);
	case FPOP_MV_F_X:
		return f3 == 0b000 && fp_fmt(raw) == 0b00 && rs2 == 0;
	default:
		return false;
	}
}

} // namespace dbt::rv32
