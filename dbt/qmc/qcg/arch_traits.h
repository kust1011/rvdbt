#pragma once

#include "dbt/qmc/qcg/asmjit_deps.h"
#include "dbt/qmc/qir.h"

namespace dbt::qcg
{

struct RegMask {
	constexpr RegMask(u32 data_) : data(data_) {}

	constexpr bool Test(qir::RegN r) const
	{
		return data & (1u << r);
	}
	constexpr RegMask &Set(qir::RegN r)
	{
		data |= (1u << r);
		return *this;
	}
	constexpr RegMask &Clear(qir::RegN r)
	{
		data &= ~(1u << r);
		return *this;
	}
	constexpr u8 count() const
	{
		return std::popcount(data);
	}
	constexpr RegMask operator&(RegMask rh) const
	{
		return RegMask{data & rh.data};
	}
	constexpr RegMask operator|(RegMask rh) const
	{
		return RegMask{data | rh.data};
	}
	constexpr RegMask operator~() const
	{
		return RegMask{~data};
	}
	constexpr auto GetData() const
	{
		return data;
	}

private:
	u32 data;
};

enum class RACtImm : u8 {
	NO = 0 << 0,
	ANY = 1 << 0,
	// amd64
	S32 = 1 << 1,
	U32 = 1 << 2,
};
DEFINE_ENUM_CLASS_FLAGOPS(RACtImm)

struct RAOpCt {
	constexpr void SetAlias(u8 alias_)
	{
		has_alias = true;
		alias = alias_;
	}

	RegMask cr{0};
	RACtImm ci{};
	bool has_alias{};
	u8 alias{};
};

namespace ArchTraits
{
static constexpr u8 GPR_NUM = 16;

#define DEF_GPR(name, id) [[maybe_unused]] static constexpr auto name = asmjit::x86::Gp::kId##id;
// all gpr
DEF_GPR(RAX, Ax);
DEF_GPR(RCX, Cx);
DEF_GPR(RDX, Dx);
DEF_GPR(RBX, Bx);
DEF_GPR(RSP, Sp);
DEF_GPR(RBP, Bp);
DEF_GPR(RSI, Si);
DEF_GPR(RDI, Di);
DEF_GPR(R8, R8);
DEF_GPR(R9, R9);
DEF_GPR(R10, R10);
DEF_GPR(R11, R11);
DEF_GPR(R12, R12);
DEF_GPR(R13, R13);
DEF_GPR(R14, R14);
DEF_GPR(R15, R15);
#undef DEF_GPR

#define QMC_FIXED_REGS(X)                                                                                    \
	X(STATE, R13) /* ghccc0 */                                                                         \
	X(MEMBASE, RBP) /* ghccc1 */                                                                         \
	X(SP, RSP) /* todo: below is for rv32m in qemit, but not needed now bcs of rv32 interp handling */	\
	X(AX, RAX)                                                                                            \
	X(DX, RDX)

#define DEF_FIXED(name, reg) [[maybe_unused]] static constexpr auto name = reg;
QMC_FIXED_REGS(DEF_FIXED)
#undef DEF_FIXED

#define DEF_FIXED(name, reg) .Set(name)
static constexpr RegMask GPR_FIXED = RegMask(0) QMC_FIXED_REGS(DEF_FIXED);
#undef DEF_FIXED

static constexpr RegMask GPR_CALL_CLOBBER =
    RegMask(0).Set(RAX).Set(RDI).Set(RSI).Set(RDX).Set(RCX).Set(R8).Set(R9).Set(R10).Set(R11);

static constexpr RegMask GPR_ALL(((u32)1 << GPR_NUM) - 1);
static constexpr RegMask GPR_POOL = GPR_ALL & ~GPR_FIXED;
static constexpr RegMask GPR_CALL_SAVED = GPR_ALL & ~GPR_CALL_CLOBBER;

// ---------------------------------------------------------------------------------------------
// VPR: the AVX-512 vector register file (qir::RegClass::VPR, qir::VType::V512).
//
// A completely separate file from the GPRs above.  A VPR number is a ZMM number and has no
// relationship to the GPR number with the same value; the two are never mixed in one RegMask and
// never share an allocator map.  Every mask below is indexed by ZMM id.
// ---------------------------------------------------------------------------------------------
static constexpr u8 VPR_NUM = 32; // EVEX encodes zmm0-zmm31

// RegMask is exactly 32 bits wide, so the whole file fits with no room to spare.  Written as a
// literal because ((u32)1 << 32) is undefined behaviour.
static_assert(VPR_NUM == 32);
static_assert(bit_size<u32> == VPR_NUM, "RegMask cannot address the whole VPR file");
static constexpr RegMask VPR_ALL(0xffffffffu);

// zmm0/zmm1 are hardcoded scratch, through their xmm0/xmm1 aliases, in Emit_vmload4,
// Emit_rvvaddv and the diagnostic chunk arm.  Those emitters run outside the allocator's model
// and would silently destroy an allocated value, so the allocator must never hand them out.
// This mirrors GPR_FIXED's role for R_STATE/R_MEMBASE/R_SP.
static constexpr RegMask VPR_FIXED = RegMask(0).Set(0).Set(1);

// SysV AMD64 has no callee-saved vector register: zmm0-zmm31 are all caller-saved.  So a call
// boundary must deal with EVERY live VPR, which is why VPR_CALL_SAVED is empty rather than a
// subset -- there is no cheap half-measure available here as there is for the GPRs.
static constexpr RegMask VPR_CALL_CLOBBER = VPR_ALL;
static constexpr RegMask VPR_CALL_SAVED = RegMask(0);

static constexpr RegMask VPR_POOL = VPR_ALL & ~VPR_FIXED;

// 1024 bytes = 16 V512 slots.  DELIBERATELY NOT ENLARGED.
//
// While tracking the `vbor` VLEN-1024 abort this constant was raised to VPR_NUM*64 + GPR_NUM*8 on
// the argument that a call boundary must be able to spill the whole register file.  A direct A/B
// then showed the enlargement was NOT what fixed anything: with the real fix in place (the
// body-aware pressure cap in rv32_vrun.cpp) all twenty exact-five x four-width cells match the QEMU
// oracle at 1024 bytes just as they do at 2176.  It is left at 1024 rather than kept "because it
// seems safer": an unjustified enlargement costs JIT stack on every trampoline entry and hides the
// pressure bug it was masking.  QRegAlloc::FreeFrameSlot (slot recycling) is what keeps the demand
// proportional to peak simultaneous liveness rather than to region length.
static constexpr u16 spillframe_size = 1024;

// The spill frame is addressed as [R_SP + spillframe_sp_offs + slot_offs] with spillframe_sp_offs
// of 8 or 16 (QEmit), and the trampoline that reserves the frame guarantees no more than 16-byte
// alignment.  A 64-byte slot is therefore NOT 64-byte aligned at run time, so V512 spill/fill must
// use the unaligned form (vmovdqu64); vmovdqa64 would #GP.  See QEmit::Emit_mov.
static constexpr u16 vpr_spill_slot_size = 64;
static_assert(spillframe_size % vpr_spill_slot_size == 0);

bool match_gp_const(qir::VType type, i64 val, RACtImm ct);

void init();
} // namespace ArchTraits

} // namespace dbt::qcg
