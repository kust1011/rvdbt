#pragma once

// RVV 1.0 scalable-vector substrate for rv32.
//
// Design constraints (2026-08-17, RVV local substrate):
//   * VLEN is a RUNTIME parameter (`config::vlen_bits`), not a compile-time constant, so the
//     same guest binary runs at any legal VLEN. Only VLEN_MAX (the storage reservation) is
//     compile-time, so `CPUState` keeps a fixed layout that AOT-compiled code can address.
//   * SEW / LMUL / EMUL / element counts are ALWAYS derived from vtype, VLEN and the encoded
//     EEW at execution time. No workload-specific constant appears anywhere in this file.
//   * Anything outside the implemented subset must FAIL CLOSED (illegal-instruction trap or
//     vill), never silently produce a wrong result.
//
// Element layout follows the RVV spec: for effective element width EEW, a vector register
// holds VLEN/EEW elements, and element i of a group starting at register `base` lives in
// register `base + i / (VLEN/EEW)` at index `i % (VLEN/EEW)`.
//
// All the "shape" arithmetic below is done in signed log2 space (lmul_log2 / sew_log2 /
// emul_log2), which is how the spec itself defines the legality rules and avoids any
// fraction/rounding hazard.

#include "dbt/util/common.h"

#include <array>
#include <cassert>
#include <cstring>

namespace dbt::rv32
{

// Storage reservation. VLEN is runtime-configurable up to this bound.
//
// HM.2a raised this from 1024 to 4096. The checkpoint's whole point is that ONE guest binary runs
// at VLEN 512/1024/2048/4096 under ONE lowering, and a guest vector register has to physically
// exist at the widest of those before any of it is testable: `vreg` is the architectural register
// file, so the reservation -- not the runtime `config::vlen_bits` -- is what bounds the legal
// range in vlen_supported() below. Every other HM.2a change is downstream of this one; without it
// `--vlen 2048` and `--vlen 4096` are rejected by ukernel::InitMainThread and nothing at k=4 or
// k=8 exists to be correct or incorrect.
//
// TWO CONSEQUENCES, both deliberate and both recorded here rather than discovered later:
//
//   * CPUState grows by (4096-1024)/8 * 32 = 12,288 bytes. That moves every offset after `vec`
//     and therefore changes the AOT ABI signature, which is the intended fail-closed behaviour:
//     an artifact compiled against the old layout is refused by the centralized gate (aot.h)
//     instead of being loaded against a different register file.
//   * THE ORACLE SET NARROWS ABOVE 1024. QEMU refuses VLEN > 1024 ("Vector extension
//     implementation only supports VLEN in the range [128, 1024]"), so 2048 and 4096 have no
//     external differential oracle. They are checked against this substrate's own architectural
//     reference lowering, against the guest's own independent scalar reference, and against
//     cross-VLEN output identity instead. No claim in this tree may present a 2048/4096 result as
//     QEMU-verified.
static constexpr u32 VLEN_MAX_BITS = 4096;
static constexpr u32 VLEN_MAX_BYTES = VLEN_MAX_BITS / 8;
static constexpr u32 VREG_NUM = 32;

// ELEN: the widest element this implementation can actually compute on. The vadd.vv reference
// semantics implement SEW in {8,16,32,64}, so ELEN is 64 and NOT a free parameter -- the
// accepted --vlen range is derived from it (the spec requires VLEN >= ELEN), which is what
// keeps `--vlen` consistent with the implemented SEW set instead of accepting widths whose
// vtype space we could not honour.
static constexpr u32 ELEN_BITS = 64;

// Two independent lower bounds coincide at 128 and we take the stricter reading of both:
//   * the RVV 1.0 "V" standard extension (which is the profile implemented here: ELEN=64,
//     LMUL up to 8) requires VLEN >= 128; VLEN >= 64 is only legal for the Zve64* embedded
//     subsets, which have a narrower vtype space than this substrate accepts;
//   * the QEMU oracle refuses VLEN < 128 outright ("Vector extension implementation only
//     supports VLEN in the range [128, 1024]").
// Accepting 64 would mean shipping a width with no oracle at all, which is exactly the failure
// mode this experiment exists to avoid.
static constexpr u32 VLEN_MIN_BITS = 128;

// A legal guest VLEN for this implementation: power of two, VLEN_MIN <= VLEN <= VLEN_MAX.
// (Power-of-two + >= 128 implies both VLEN >= ELEN and the multiple-of-8 requirement.)
constexpr bool vlen_supported(u32 vlen_bits)
{
	return vlen_bits >= VLEN_MIN_BITS && vlen_bits <= VLEN_MAX_BITS &&
	       (vlen_bits & (vlen_bits - 1)) == 0;
}

// vtype layout (RVV 1.0, "vtype register layout"):
//   [2:0] vlmul, [5:3] vsew, [6] vta, [7] vma, [XLEN-2:8] reserved (must be 0), [XLEN-1] vill
static constexpr u32 VTYPE_VILL_BIT = 1u << 31;
// Bits [31:8]. Bit 31 is INCLUDED: vill is set BY the implementation, never supplied by the
// guest, so a vtype value that already has it set is a reserved encoding and must produce vill
// with vl=0 rather than being accepted with its low fields honoured. Only vsetvl can reach this
// -- vsetvli's zimm11 cannot express bit 31 -- which is why it went unnoticed until vsetvl was
// implemented; QEMU rejects such a value and returns vl=0.
static constexpr u32 VTYPE_RESERVED_MASK = 0xffffff00u;

// Field positions and encodings, named so a vtype value can be BUILT from the layout above rather
// than written as a literal. Used by the typed-chunk route when no vsetvli was seen in the block
// and the one admitted shape has to be proposed as a candidate (rv32_qir.cpp TRANSLATOR(vadd_vv)).
static constexpr u32 VTYPE_VSEW_SHIFT = 3;
static constexpr u32 VTYPE_VTA_BIT = 1u << 6;
static constexpr u32 VTYPE_VMA_BIT = 1u << 7;
static constexpr u32 VSEW_E32 = 0b010; // SEW = 8 << vsew, so 8 << 2 == 32
static constexpr u32 VLMUL_M1 = 0b000; // signed log2(LMUL) == 0
// The single vtype the typed V512 chunk method admits: SEW=32, LMUL=1, tail- and mask-agnostic.
// Built from the fields above, so it carries vill=0 and reserved=0 by construction.
static constexpr u32 VTYPE_E32_M1_TA_MA =
    VTYPE_VMA_BIT | VTYPE_VTA_BIT | (VSEW_E32 << VTYPE_VSEW_SHIFT) | VLMUL_M1;

struct VType {
	u32 raw;

	constexpr u32 vlmul_field() const { return raw & 0x7; }
	constexpr u32 vsew_field() const { return (raw >> 3) & 0x7; }
	constexpr bool vta() const { return (raw >> 6) & 1; }
	constexpr bool vma() const { return (raw >> 7) & 1; }
	constexpr bool vill() const { return (raw & VTYPE_VILL_BIT) != 0; }

	// Reserved bits [30:8] must be zero, else the vtype is reserved -> vill.
	constexpr bool reserved_clear() const { return (raw & VTYPE_RESERVED_MASK) == 0; }

	// SEW = 8 << vsew. vsew >= 4 is reserved.
	constexpr u32 sew() const { return 8u << vsew_field(); }
	constexpr u32 sew_log2() const { return vsew_field() + 3; }
	constexpr bool sew_valid() const { return vsew_field() <= 3; }

	// vlmul field encodes LMUL as a signed power of two:
	//   000=1, 001=2, 010=4, 011=8, 101=1/8, 110=1/4, 111=1/2   (100 is reserved)
	constexpr bool lmul_valid() const { return vlmul_field() != 0b100; }
	constexpr bool lmul_fractional() const { return vlmul_field() >= 0b101; }
	// Signed log2(LMUL): 000..011 -> 0..3, 101..111 -> -3..-1. Only valid if lmul_valid().
	constexpr i32 lmul_log2() const
	{
		i32 const f = (i32)vlmul_field();
		return (f & 0b100) ? f - 8 : f;
	}
};

// x scaled by 2^shift, shift signed. Integer only, no rounding hazard for our uses.
constexpr u32 shift_signed(u32 x, i32 shift)
{
	return shift >= 0 ? (x << shift) : (x >> (-shift));
}

// VLMAX = LMUL * VLEN / SEW, computed exactly in integers (no floating point, no magic numbers).
constexpr u32 compute_vlmax(VType vt, u32 vlen_bits)
{
	return shift_signed(vlen_bits >> vt.sew_log2(), vt.lmul_log2());
}

// A vtype is supported iff:
//   * SEW and LMUL fields are legal encodings;
//   * the reserved bits are zero;
//   * SEW <= LMUL * ELEN  (the spec's fractional-LMUL rule; for LMUL >= 1 this is SEW <= ELEN);
//   * the register group holds at least one element.
// Everything else sets vill -> fail closed.
constexpr bool vtype_supported(VType vt, u32 vlen_bits)
{
	if (!vt.sew_valid() || !vt.lmul_valid() || !vt.reserved_clear())
		return false;
	// SEW <= LMUL*ELEN, i.e. sew_log2 <= lmul_log2 + log2(ELEN).
	i32 const elen_log2 = 6; // ELEN_BITS == 64
	if ((i32)vt.sew_log2() > vt.lmul_log2() + elen_log2)
		return false;
	return compute_vlmax(vt, vlen_bits) != 0;
}

// ---------------------------------------------------------------------------------------------
// Register-group legality.
//
// EMUL = (EEW / SEW) * LMUL. For an instruction whose effective element width is EEW, the
// destination/source register group spans ceil(EMUL) registers and the register specifier must
// be a multiple of that span. EMUL outside [1/8, 8] is reserved -> illegal instruction.
// ---------------------------------------------------------------------------------------------

constexpr i32 compute_emul_log2(VType vt, u32 eew_log2)
{
	return vt.lmul_log2() + (i32)eew_log2 - (i32)vt.sew_log2();
}

constexpr bool emul_in_range(i32 emul_log2) { return emul_log2 >= -3 && emul_log2 <= 3; }

// Registers spanned by a group with the given EMUL (fractional EMUL still occupies one register).
constexpr u32 emul_group_regs(i32 emul_log2) { return emul_log2 <= 0 ? 1u : (1u << emul_log2); }

// A register specifier is legal for an EMUL iff it is EMUL-aligned AND the whole group fits in
// v0..v31. This is what stops an illegal group from being silently wrapped back into v0.
constexpr bool reg_group_legal(u32 base_reg, i32 emul_log2)
{
	u32 const regs = emul_group_regs(emul_log2);
	return (base_reg % regs) == 0 && (base_reg + regs) <= VREG_NUM;
}

// Locate one fixed-width host chunk inside an RVV architectural register group.
//
// CPUState reserves VLEN_MAX_BYTES for every architectural vector register, while only
// vlen_bits/8 bytes of each slot are live at a particular emulated VLEN.  Consequently an LMUL
// group is not contiguous in CPUState when VLEN < VLEN_MAX: crossing a runtime-register boundary
// must skip to the next fixed-size slot.  Keep that rule here so single-instruction lowering and
// cross-instruction dataflow cannot grow independent offset formulae.
struct GroupChunkLocation {
	u32 reg;
	u32 byte_in_reg;
};

constexpr GroupChunkLocation group_chunk_location(u32 base_reg, u32 vlen_bits, u32 chunk_bytes,
						   u32 chunk_index)
{
	u32 const reg_bytes = vlen_bits / 8u;
	u32 const logical_byte = chunk_index * chunk_bytes;
	return {base_reg + logical_byte / reg_bytes, logical_byte % reg_bytes};
}

constexpr u32 group_chunk_state_offset(u32 vreg_file_base, u32 base_reg, u32 vlen_bits,
					       u32 chunk_bytes, u32 chunk_index)
{
	auto const p = group_chunk_location(base_reg, vlen_bits, chunk_bytes, chunk_index);
	return vreg_file_base + p.reg * VLEN_MAX_BYTES + p.byte_in_reg;
}

// Vector memory `width` field (the instruction's funct3) selects the EFFECTIVE element width,
// independently of SEW. Returns log2(EEW in bytes), or -1 for an encoding this substrate does
// not implement (the FP widths and the reserved values).
//   000 -> 8b   101 -> 16b   110 -> 32b   111 -> 64b
constexpr i32 eew_log2_from_width(u32 width)
{
	switch (width) {
	case 0b000:
		return 3; // EEW=8   -> log2(bits)
	case 0b101:
		return 4; // EEW=16
	case 0b110:
		return 5; // EEW=32
	case 0b111:
		return 6; // EEW=64
	default:
		return -1;
	}
}
constexpr bool eew_width_supported(u32 width) { return eew_log2_from_width(width) >= 0; }

// Non-segment memory: width denotes data EEW for unit/strided access and index
// EEW for indexed access. Keep the same decision in QCG and the fallback.
constexpr bool vmemory_registers_legal(VType vt,u32 width,u32 mop,u32 data,u32 index,bool store,bool vm)
{
	i32 const ew=eew_log2_from_width(width);
	if(ew<0||mop>3) return false;
	bool const indexed=mop==1||mop==3;
	i32 const dm=indexed?vt.lmul_log2():compute_emul_log2(vt,ew);
	if(!emul_in_range(dm)||!reg_group_legal(data,dm)||(!store&&!vm&&data==0)) return false;
	if(!indexed) return true;
	i32 const im=compute_emul_log2(vt,ew);
	// Base V on this RV32 implementation uses 8/16/32-bit memory indices.
	if(ew==6||!emul_in_range(im)||!reg_group_legal(index,im)) return false;
	u32 const dn=emul_group_regs(dm),in=emul_group_regs(im);
	bool const overlap=data<index+in&&index<data+dn;
	if(!store&&overlap) {
		// RVV 1.0 section 5.2: widening the destination may overlap a
		// source of EMUL >= 1 only at the highest-numbered register.
		if(ew<vt.sew_log2()&&(im<0||data+dn!=index+in)) return false;
		if(ew>vt.sew_log2()&&data!=index) return false;
	}
	return true;
}

// vtype[7:0] -> VLMAX, as a table a dynamic vsetvl can index instead of recomputing.
//
// IT SPECIFIES NOTHING OF ITS OWN. Every entry is `vtype_supported ? compute_vlmax : 0`, so the
// admitted set and the width arithmetic stay in those two functions and this is only their values
// tabulated. A zero entry means "not a vtype this implementation accepts", and that is unambiguous
// rather than a sentinel choice: vtype_supported already refuses any configuration whose VLMAX
// would be zero, so no legal vtype can produce a zero here.
//
// THE HIGH BITS ARE THE CALLER'S. The index is vtype[7:0] -- vlmul, vsew, vta, vma -- and the table
// is built from VType values whose bits [31:8] are ZERO. A dynamic vsetvl must therefore check that
// the requested vtype has no reserved bit and no vill bit set before it may use a lookup; a value
// like 0x800000d1 indexes to the same entry as 0xd1 and would otherwise be accepted as legal.
//
// ONE TABLE PER VLEN. VLMAX = LMUL * VLEN / SEW, so the table is only meaningful for the VLEN it
// was built for; vlmax_table_for() returns the one for a supported VLEN and nullptr otherwise.
//
// Only SIX of the eight index bits matter -- vta and vma do not enter VLMAX -- so the table is four
// copies of a 64-entry one. It is kept at 256 so the consumer can mask with 0xff and index directly;
// masking with 0x3f against a 64-entry table would be equally correct and one quarter the size.
struct VlmaxTable {
	static constexpr u32 SIZE = 256;
	u16 vlmax[SIZE];
	constexpr u16 operator[](u32 vtype_low8) const { return vlmax[vtype_low8 & (SIZE - 1)]; }
};
// VLMAX peaks at LMUL=8, SEW=8, i.e. VLEN elements, so the widest supported VLEN must still fit.
static_assert(VLEN_MAX_BITS <= 0xffff, "a VLMAX entry must fit in u16");

constexpr VlmaxTable make_vlmax_table(u32 vlen_bits)
{
	VlmaxTable t{};
	for (u32 low = 0; low < VlmaxTable::SIZE; ++low) {
		VType const vt{low};
		t.vlmax[low] = vtype_supported(vt, vlen_bits) ? (u16)compute_vlmax(vt, vlen_bits) : (u16)0;
	}
	return t;
}

// The table for a VLEN this implementation accepts, or nullptr. The set is vlen_supported()'s --
// powers of two from VLEN_MIN_BITS to VLEN_MAX_BITS -- enumerated here because each one is its own
// constexpr object.
inline VlmaxTable const *vlmax_table_for(u32 vlen_bits)
{
	static constexpr VlmaxTable t128 = make_vlmax_table(128);
	static constexpr VlmaxTable t256 = make_vlmax_table(256);
	static constexpr VlmaxTable t512 = make_vlmax_table(512);
	static constexpr VlmaxTable t1024 = make_vlmax_table(1024);
	static constexpr VlmaxTable t2048 = make_vlmax_table(2048);
	static constexpr VlmaxTable t4096 = make_vlmax_table(4096);
	switch (vlen_bits) {
	case 128: return &t128;
	case 256: return &t256;
	case 512: return &t512;
	case 1024: return &t1024;
	case 2048: return &t2048;
	case 4096: return &t4096;
	default: return nullptr;
	}
}

// A ONE-SOURCE CONVERSION's registers (RVV 1.0 5.2/5.3): vfcvt and its widening/narrowing forms,
// where the destination and the source can have different EEW. Shared so a direct route and the
// helper admit the same encodings; the caller says only which of the three width relations the
// sub-encoding names, and the EMULs are derived here so the two callers cannot derive them apart.
//
//   * Same width: EMUL is LMUL on both sides and any overlap is legal.
//   * Widen: the destination is 2*SEW, so its EMUL is 2*LMUL and an overlap is legal only when the
//     source EMUL is at least 1 and the source is the HIGHEST-numbered part of the destination.
//   * Narrow: the SOURCE is 2*SEW, so the destination's EEW is the smaller one and an overlap is
//     legal only at the LOWEST-numbered part of the source -- vd == vs2 exactly, since the
//     destination group starts there.
//
// MASKED FORMS BAR v0 ON BOTH SIDES. 5.3 keeps the destination off v0, and once v0 is read as the
// mask (EEW=1) 5.2's one-register-one-source-EEW rule also bars it as the DATA source. QEMU 11.1
// enforces the second half through vext_check_input_eew's require_vm, reached from vext_check_ss /
// vext_check_ds / vext_check_sd; QEMU 9.0 had no such check, so this is a rule that arrived with a
// later revision rather than a fixed-point special case.
enum class VConvWidth : u8 { Same, Widen, Narrow };

constexpr bool convert_registers_legal(VType vt, VConvWidth width, u32 vd, u32 vs2, bool vm)
{
	i32 const lmul_log2 = vt.lmul_log2();
	i32 const dst_emul = width == VConvWidth::Widen ? lmul_log2 + 1 : lmul_log2;
	i32 const src_emul = width == VConvWidth::Narrow ? lmul_log2 + 1 : lmul_log2;
	// The doubled side must be an element width that exists.
	if (width != VConvWidth::Same && vt.sew() * 2 > ELEN_BITS)
		return false;
	if (!emul_in_range(dst_emul) || !emul_in_range(src_emul) ||
	    !reg_group_legal(vd, dst_emul) || !reg_group_legal(vs2, src_emul))
		return false;
	if (!vm && (vd == 0 || vs2 == 0))
		return false;
	u32 const dg = emul_group_regs(dst_emul), sg = emul_group_regs(src_emul);
	if (!(vd < vs2 + sg && vs2 < vd + dg))
		return true; // disjoint
	if (width == VConvWidth::Widen)
		return src_emul >= 0 && vs2 + sg == vd + dg;
	if (width == VConvWidth::Narrow)
		return vd == vs2;
	return true; // equal EEW: any overlap
}

// A SAME-WIDTH ONE-SOURCE instruction's registers: vfsqrt.v, vfclass.v, vfrec7.v, vfrsqrt7.v --
// everything whose destination and source are both LMUL groups at SEW. It is the conversion rule's
// Same case and nothing else, named so a caller that converts nothing does not have to read as one;
// there is one implementation of the rule, not two. QEMU reaches the same rule through
// opfv_check -> vext_check_ss.
constexpr bool same_width_registers_legal(VType vt, u32 vd, u32 vs2, bool vm)
{
	return convert_registers_legal(vt, VConvWidth::Same, vd, vs2, vm);
}

// SOURCE side of the different-EEW overlap rule (QEMU vext_check_input_eew, first clause): a masked
// op reads v0 at EEW=1, so no vector source group may be v0. Groups are aligned, so that is
// `reg == 0`. No rule for a scalar operand (`vs1_is_vector` false: x0 stays legal), none for the
// destination (mask results are exempt), and none when unmasked (keeps vmv.v.* with its encoded
// vs2 = v0 legal).
constexpr bool same_width_sources_legal(u32 vs2, u32 vs1, bool vs1_is_vector, bool vm)
{
	return vm || (vs2 != 0 && (!vs1_is_vector || vs1 != 0));
}

// A MASK-PRODUCING instruction's registers (RVV 1.0 5.2/5.3): the compares, whose destination is a
// single register holding one BIT per element while the sources are SEW-wide groups. Shared with
// every route that admits one, so the helper and a direct lowering cannot disagree.
//
// TWO RULES, and both are exceptions to what the surrounding families do:
//
//   * A MASKED FORM MAY WRITE v0. 5.3 forbids a masked instruction's destination from overlapping
//     the mask, "unless the destination vector register is being written with a mask value (e.g.,
//     comparisons)" -- which is exactly this case, so there is deliberately no `vm && vd == 0` test
//     here. QEMU's vext_check_ms omits require_vm for the same reason.
//   * THE DESTINATION EEW IS 1, SMALLER THAN THE SOURCES'. 5.2 then permits an overlap only in the
//     LOWEST-numbered part of the source group, and since the destination is a single register that
//     means vd == vs exactly. vd anywhere else inside [vs, vs + EMUL) is reserved -- the middle of
//     a group is the case a source-alignment check alone does not catch.
//
// `scalar_source` says vs1 is not a vector register (the .vf forms), so it carries no rule at all.
constexpr bool mask_result_registers_legal(VType vt, u32 vd, u32 vs2, u32 vs1, bool scalar_source)
{
	i32 const lmul_log2 = vt.lmul_log2();
	if (!emul_in_range(lmul_log2) || vd >= VREG_NUM || !reg_group_legal(vs2, lmul_log2) ||
	    (!scalar_source && !reg_group_legal(vs1, lmul_log2)))
		return false;
	u32 const regs = emul_group_regs(lmul_log2);
	auto source_ok = [&](u32 vs) { return vd == vs || vd < vs || vd >= vs + regs; };
	return source_ok(vs2) && (scalar_source || source_ok(vs1));
}

// RVV reductions: vs2 is an LMUL group; seed and result are single registers.
// Destination overlap (including masked vd=v0) is allowed. Sources read at
// different EEWs cannot overlap: mask/data, or widening seed/data. Shared by
// QCG and interpreter; matches QEMU reduction_check/reduction_widen_check.
constexpr bool reduction_registers_legal(VType vt, bool widening, u32 vd, u32 vs2, u32 vs1, bool vm)
{
	i32 const lmul_log2 = vt.lmul_log2();
	if (!emul_in_range(lmul_log2) || vd >= VREG_NUM || vs1 >= VREG_NUM ||
	    !reg_group_legal(vs2, lmul_log2))
		return false;
	if (!vm && (vs1 == 0 || vs2 == 0))
		return false; // masked: no source may overlap v0, which is read at EEW=1
	if (widening) {
		if (vt.sew() * 2 > ELEN_BITS)
			return false;
		u32 const regs = emul_group_regs(lmul_log2);
		if (vs1 >= vs2 && vs1 < vs2 + regs)
			return false; // seed at 2*SEW inside the data group at SEW
	}
	return true;
}

// Whole-register transfers move NR registers, NR in {1,2,4,8}, and require the register
// specifier to be NR-aligned. Independent of vtype -- see whole_reg_* in rv32_vector_lower.h.
// Do two register groups share any register? The slide-up and gather families forbid overlap
// because they read source elements after the destination has begun to be written.
constexpr bool group_overlaps(u32 a, u32 b, i32 lmul_log2)
{
	u32 const n = emul_group_regs(lmul_log2);
	return a < b + n && b < a + n;
}

constexpr bool nregs_valid(u32 nregs)
{
	return nregs == 1 || nregs == 2 || nregs == 4 || nregs == 8;
}
constexpr bool whole_reg_group_legal(u32 base_reg, u32 nregs)
{
	return nregs_valid(nregs) && (base_reg % nregs) == 0 && (base_reg + nregs) <= VREG_NUM;
}

// Architectural vector state. Fixed-size storage so the CPUState layout is stable for AOT.
struct VectorState {
	// 16-byte aligned so the P4 fixed-width lowering can use aligned 128-bit host accesses.
	alignas(16) std::array<std::array<u8, VLEN_MAX_BYTES>, VREG_NUM> vreg{};
	u32 vtype{VTYPE_VILL_BIT}; // reset state: vill set, so any vector op before vset* traps
	u32 vl{};
	u32 vstart{};
	// P15 candidate 7 (--rvv-fuse-pairs). When an integer element-wise VV op fuses with its
	// immediate successor, the successor's WORK is already done; it still dispatches, and this
	// one-shot marker tells it to retire without repeating the computation. Keeping the second
	// instruction in the dispatch stream makes the interpreter and the JIT stub path behave
	// identically, which advancing the PC inside the handler would not: under JIT the stub for
	// the successor has already been emitted and would run regardless.
	//
	// It must NOT be cleared at TB exit. Once the pair has fused, vd already holds op2's final
	// value; re-running op2 would apply it a second time to its own output. So if a block
	// boundary or an interruption lands between the pair, the marker has to survive it. This is
	// safe because the two are adjacent non-branch, non-faulting instruction words, so the next
	// vialu dispatched is always op2; `fused_skip_raw` is the backstop check.
	u32 fused_skip_pc{};
	u32 fused_skip_raw{};
	bool fused_skip_valid{};
	u32 vlenb{}; // VLEN/8, published to the guest via the read-only `vlenb` CSR
	// Fixed-point CSRs. vxrm selects one of four rounding rules for the averaging, scaling and
	// clipping instructions -- the same instruction yields four different answers depending on
	// it, so it is architectural input, not a mode flag. vxsat is STICKY: a saturating result
	// sets it and only an explicit CSR write clears it, so a later non-saturating operation
	// must not reset it.
	u32 vxrm{};
	u32 vxsat{};

	void Reset(u32 vlen_bits)
	{
		for (auto &r : vreg)
			r.fill(0);
		vtype = VTYPE_VILL_BIT;
		vl = 0;
		vstart = 0;
		vlenb = vlen_bits / 8;
		vxrm = 0;
		vxsat = 0;
	}

	// ---- mask access ------------------------------------------------------------------
	// A mask register holds ONE BIT PER ELEMENT, densely packed from bit 0 of byte 0 of the
	// register -- it is NOT laid out per SEW. Element i lives at byte i/8, bit i%8. Masks
	// therefore always occupy a single register regardless of LMUL, which is why mask
	// operands are never register groups.
	ALWAYS_INLINE bool mask_get(u32 reg, u32 i) const
	{
		return (vreg[reg][i >> 3] >> (i & 7)) & 1;
	}
	ALWAYS_INLINE void mask_set(u32 reg, u32 i, bool bit)
	{
		u8 &b = vreg[reg][i >> 3];
		u8 const m = (u8)(1u << (i & 7));
		b = bit ? (u8)(b | m) : (u8)(b & ~m);
	}

	// ---- element access at an arbitrary SEW ---------------------------------------------
	//
	// P13 BASELINE REPAIR (2026-08-18). These three accessors are on the inner loop of every
	// element-wise helper, so their code quality decides what an element-wise baseline costs.
	// The previous version was width-generic at RUNTIME in two ways that each cost more than
	// the semantics it was serving (measured: 30-80 cycles per element, against 0.32 for the
	// bulk-copy whole-register path -- experiments/2026-08-18-0659.../docs/A2_DYNAMIC_COST_PARETO.md):
	//
	//   * `index / per_reg` and `index % per_reg` compiled to two hardware DIVs per access,
	//     because `per_reg` is an ordinary runtime value. It is always a power of two --
	//     `vlen_bits/8` is a checked power of two >= 16 and `eew_bytes` is 1, 2, 4 or 8 -- so
	//     the same map is a shift and a mask. Nothing about the semantics changes.
	//   * `std::memcpy(&v, p, sew_bytes)` with a RUNTIME size compiled to a call to memcpy@plt
	//     for a 1-8 byte access. Switching on the width first makes each arm a constant-size
	//     `__builtin_memcpy`, which is one `mov` -- and stays strict-aliasing-clean, which a
	//     reinterpret_cast would not.
	//
	// This is implementation quality, not a research contribution: QEMU's element loop has
	// neither cost (flat register file, loop monomorphised on SEW at C-compile time). It is
	// done here so that a later lowering claim is measured against a credible baseline instead
	// of against the removal of a memcpy call.
	//
	// Returned zero-extended (u) or sign-extended (i) into 64 bits so op implementations can
	// be written once instead of once per SEW.
	ALWAYS_INLINE u64 elem_u(u32 base_reg, u32 index, u32 sew_bytes, u32 vlen_bits)
	{
		u8 const *p = elem_ptr(base_reg, index, sew_bytes, vlen_bits);
		u64 v = 0;
		switch (sew_bytes) {
		case 1:
			return *p;
		case 2: {
			u16 t;
			__builtin_memcpy(&t, p, 2);
			return t;
		}
		case 4: {
			u32 t;
			__builtin_memcpy(&t, p, 4);
			return t;
		}
		default:
			__builtin_memcpy(&v, p, 8);
			return v;
		}
	}
	ALWAYS_INLINE i64 elem_i(u32 base_reg, u32 index, u32 sew_bytes, u32 vlen_bits)
	{
		u64 const u = elem_u(base_reg, index, sew_bytes, vlen_bits);
		u32 const sh = 64 - 8 * sew_bytes;
		return (i64)(u << sh) >> sh;
	}
	ALWAYS_INLINE void elem_put(u32 base_reg, u32 index, u32 sew_bytes, u32 vlen_bits, u64 v)
	{
		u8 *p = elem_ptr(base_reg, index, sew_bytes, vlen_bits);
		switch (sew_bytes) {
		case 1:
			*p = (u8)v;
			return;
		case 2: {
			u16 t = (u16)v;
			__builtin_memcpy(p, &t, 2);
			return;
		}
		case 4: {
			u32 t = (u32)v;
			__builtin_memcpy(p, &t, 4);
			return;
		}
		default:
			__builtin_memcpy(p, &v, 8);
			return;
		}
	}

	// Element accessor. `eew_bytes` is the EFFECTIVE element width of the access, which for
	// vle32/vse32 is 4 regardless of SEW; the register-group stride follows from VLEN/EEW.
	//
	// NOTE: there is deliberately NO `% VREG_NUM` here. Wrapping an out-of-range group back
	// into v0 would silently corrupt v0 (the mask register) and produce a wrong answer instead
	// of a trap. Callers MUST have validated the group with reg_group_legal() and the element
	// index against VLMAX; the assert documents and checks that contract in debug builds.
	ALWAYS_INLINE u8 *elem_ptr(u32 base_reg, u32 index, u32 eew_bytes, u32 vlen_bits)
	{
		// elements per vector register, as a shift: both operands are powers of two.
		u32 const vlen_bytes = vlen_bits >> 3;
		assert((vlen_bytes & (vlen_bytes - 1)) == 0 && vlen_bytes >= eew_bytes);
		assert((eew_bytes & (eew_bytes - 1)) == 0 && eew_bytes != 0);
		u32 const per_reg_log2 =
		    (u32)__builtin_ctz(vlen_bytes) - (u32)__builtin_ctz(eew_bytes);
		u32 const reg = base_reg + (index >> per_reg_log2);
		u32 const off = (index & ((1u << per_reg_log2) - 1)) * eew_bytes;
		assert(reg < VREG_NUM);
		return &vreg[reg][off];
	}
};

} // namespace dbt::rv32

namespace dbt::rv32::rvv_gather
{
// C-beta substrate entry points. The implementation lives in its own -mavx2 translation unit and is
// reached only after this runtime CPUID check, so the SSE2 baseline never sees an AVX2 instruction.
extern "C" bool rvv_gather_e32_avx2(void *vs, unsigned vd, unsigned vs2, unsigned char *vmem,
				    unsigned base, unsigned vlen_bits, unsigned vl);
extern "C" unsigned long long g_gather_calls;
extern "C" unsigned long long g_gather_elems;
extern "C" unsigned long long g_gather_attempts;
extern "C" unsigned long long g_gather_unmapped;
inline bool host_has_avx2()
{
#ifdef RVDBT_DIAG_ASSUME_HOST_CAPS
	// OPAQUE_BOUNDARY diagnostic build only (never defined in the normal build): skip
	// __builtin_cpu_supports(). Its clang/glibc lowering references __cpu_model with a
	// relocation that plain `ld -shared`/ld.lld refuse when this TU is linked standalone into
	// an AOT .aot.so rather than compiled straight into the main executable -- a toolchain/ABI
	// limitation of the diagnostic's linking scheme, not something this macro works around for
	// the shipped binary. The diagnostic is only ever run on a host whose capability was
	// already confirmed out-of-band (recorded in the causal-mediation raw data).
	return true;
#else
	static bool const yes = __builtin_cpu_supports("avx2");
	return yes;
#endif
}
} // namespace dbt::rv32::rvv_gather
