#include "dbt/execute.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_runtime.h"
#include "dbt/guest/rv32_fpu_ops.h"
#include "dbt/guest/rv32_softfp.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/guest/rv32_seqtrace.h"
#include "dbt/guest/rv32_vector_census.h"
#include "dbt/guest/rv32_pc_census.h"
#include "dbt/guest/rv32_route_census.h"
#include "dbt/guest/rv32_vector_fast.h"
#include "dbt/mmu.h"
#include "dbt/config.h"
#include <atomic>
#include <cassert>
#include <unordered_map>
#include <cstdio>

#include <immintrin.h>

namespace dbt
{
thread_local CPUState *CPUState::tls_current{};

// Family-A value-stability probe (default-off): per-load-PC, is the loaded value STABLE (always == first seen)?
struct LoadVStat { u32 first; bool stable; unsigned long long count; };
static std::unordered_map<u32, LoadVStat> g_load_vstats;
void record_load_value(u32 pc, u32 v)
{
	auto &e = g_load_vstats[pc];
	if (e.count == 0) { e.first = v; e.stable = true; }
	else if (v != e.first) e.stable = false;
	e.count++;
}
void dump_load_values(char const *path)
{
	FILE *f = fopen(path, "w");
	if (!f) return;
	fprintf(f, "load_pc,stable,count,first_value\n");
	for (auto const &[pc, e] : g_load_vstats)
		fprintf(f, "%08x,%d,%llu,%08x\n", pc, (int)e.stable, e.count, e.first);
	fclose(f);
}
} // namespace dbt

namespace dbt::rv32
{

static void InsnNotImplemented(insn::Base insn, char const *name)
{
	log_dbt("ILLEGAL OPCODE: %s raw=%08x op=%03x", name, insn.raw, insn.opcode());
}

#define GET_GIP() (gip)
#define SET_GIP(gip_) (gip = gip_)
#define RAISE_TRAP(trapno_)                                                                                  \
	do {                                                                                                 \
		s->ip = GET_GIP();                                                                           \
		s->trapno = trapno_;                                                                         \
		RaiseTrap();                                                                                 \
	} while (0)

// HBody_##name is the original handler body. H_##name wraps it with the P13 dynamic RVV census.
// The census wrapper is emitted ONLY for handlers whose name starts with 'v' (every RVV handler,
// no scalar one -- see rvv_census::name_is_vector), and even there it is a single load of
// `config::rvv_census` plus a predicted-not-taken branch when the census is off. Wrapping H_
// rather than the QCG stub covers the interpreter and the JIT with one hook, since the stub
// calls H_.
#define HANDLER(name)                                                                                        \
	static ALWAYS_INLINE void Impl_##name(CPUState *s, u32 &gip, u8 *vmem, insn::Insn_##name i);         \
	static ALWAYS_INLINE void HBody_##name(CPUState *state, u32 &gip, u8 *vmem, u32 insn_raw)            \
	{                                                                                                    \
		insn::Insn_##name i{(u32)insn_raw};                                                          \
		static constexpr auto flags = decltype(i)::flags;                                            \
		[[maybe_unused]] u32 seqtrace_pc, seqtrace_vl_pre, seqtrace_vtype_pre;                       \
		if constexpr (seqtrace::kEnabled) {                                                          \
			seqtrace_pc = gip;                                                                   \
			seqtrace_vl_pre = state->vec.vl;                                                     \
			seqtrace_vtype_pre = state->vec.vtype;                                               \
		}                                                                                            \
		if constexpr (flags & insn::Flags::Trap || flags & insn::Flags::MayTrap) {                   \
			state->ip = GET_GIP();                                                               \
		}                                                                                            \
		Impl_##name(state, gip, vmem, i);                                                            \
		if constexpr (seqtrace::kEnabled) {                                                          \
			seqtrace::record(seqtrace_pc, #name, (bool)(flags & insn::Flags::Branch),            \
					 (bool)(flags & insn::Flags::MayTrap), insn_raw, seqtrace_vl_pre,    \
					 seqtrace_vtype_pre, state->vec.vl, state->vec.vtype);               \
		}                                                                                            \
		if constexpr (flags & insn::Flags::HasRd) {                                                  \
			state->gpr[0] = 0;                                                                   \
		}                                                                                            \
		if constexpr (flags & insn::Flags::Branch) {                                                 \
			state->ip = GET_GIP();                                                               \
		} else {                                                                                     \
			gip += 4;                                                                            \
		}                                                                                            \
	}                                                                                                    \
	static ALWAYS_INLINE void H_##name(CPUState *state, u32 &gip, u8 *vmem, u32 insn_raw)                \
	{                                                                                                    \
		/* T3a: this is the ONE point both paths into the C++ implementation pass through --  \
		 * the JIT's qcgstub_rv32_<name> wrapper above, and Interpreter::Execute/ExecuteBlock \
		 * below -- so a count taken here is exactly "this vector instruction did NOT run as  \
		 * emitted host code". Vector handlers only; off by default. */                       \
		if constexpr (rvv_census::name_is_vector(#name)) {                                    \
			if (unlikely(dbt::config::rvv_route_census))                                  \
				route_census::note(insn_raw);                                         \
			/* T5b-1: same hook, but keyed by guest PC and carrying the handler family,   \
			 * so a fallback can be attributed to the timed kernel or to the adapter.    \
			 * gip here is this instruction's own PC -- HBody_ advances it afterwards. */ \
			if (unlikely(dbt::config::rvv_pc_census))                                     \
				pc_census::note(gip, insn_raw, #name, state->vec.vl);                 \
		}                                                                                            \
		if constexpr (rvv_census::kCensusEnabled && rvv_census::name_is_vector(#name)) {                                           \
			if (unlikely(dbt::config::rvv_probe)) {                                              \
				rvv_census::probe_one(state->vec, gip, insn_raw);                            \
			}                                                                                    \
			if (unlikely(dbt::config::rvv_census)) {                                             \
				static int const fam = rvv_census::intern(#name);                            \
				rvv_census::Scope sc(fam, state->vec, insn_raw);                              \
				HBody_##name(state, gip, vmem, insn_raw);                                    \
				sc.finish();                                                                 \
				return;                                                                      \
			}                                                                                    \
		}                                                                                            \
		HBody_##name(state, gip, vmem, insn_raw);                                                    \
	}                                                                                                    \
	extern "C" void __attribute__((used)) qcgstub_rv32_##name(CPUState *state, u32 insn_raw)             \
	{                                                                                                    \
		u32 gip = state->ip;                                                                         \
		H_##name(state, gip, mmu::base, insn_raw);                                                   \
		state->ip = gip;                                                                             \
	}                                                                                                    \
	static ALWAYS_INLINE void Impl_##name(CPUState *s, u32 &gip, u8 *vmem, insn::Insn_##name i)

#define HANDLER_BCC(name, type, cond)                                                                        \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		bool pred = (type)s->gpr[i.rs1()] cond(type) s->gpr[i.rs2()];                                \
		if (!pred) {                                                                                 \
			SET_GIP(GET_GIP() + 4);                                                              \
			return;                                                                              \
		}                                                                                            \
		if (unlikely(i.imm() % 4)) {                                                                 \
			RAISE_TRAP(TrapCode::UNALIGNED_IP);                                                  \
		}                                                                                            \
		SET_GIP(GET_GIP() + i.imm());                                                                \
	}
#define HANDLER_Load(name, type)                                                                             \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		type _lv = unaligned_load<type>(vmem + (s->gpr[i.rs1()] + i.imm()));                         \
		if (unlikely(dbt::config::profile_load_values))                                              \
			dbt::record_load_value(gip, (u32)_lv);                                               \
		s->gpr[i.rd()] = _lv;                                                                        \
	}
#define HANDLER_Store(name, type)                                                                            \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		unaligned_store<type>(vmem + (s->gpr[i.rs1()] + i.imm()), s->gpr[i.rs2()]);                  \
	}
#define HANDLER_ArithmRR(name, type, op)                                                                     \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		s->gpr[i.rd()] = (type)s->gpr[i.rs1()] op(type) s->gpr[i.rs2()];                             \
	}
#define HANDLER_ArithmRI(name, type, op)                                                                     \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		s->gpr[i.rd()] = (type)s->gpr[i.rs1()] op(type) i.imm();                                     \
	}
#define HANDLER_Unimpl(name)                                                                                 \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		InsnNotImplemented(i, "uniplemented(" #name ")");                                            \
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                          \
	}

HANDLER(ill)
{
	InsnNotImplemented(i, "unknown");
	RAISE_TRAP(TrapCode::ILLEGAL_INSN);
}
HANDLER(lui)
{
	s->gpr[i.rd()] = i.imm();
}
HANDLER(auipc)
{
	s->gpr[i.rd()] = i.imm() + GET_GIP();
}
HANDLER(jal)
{
	if (unlikely(i.imm() % 4)) {
		RAISE_TRAP(TrapCode::UNALIGNED_IP);
	}
	s->gpr[i.rd()] = GET_GIP() + 4;
	SET_GIP(GET_GIP() + i.imm());
}
HANDLER(jalr)
{
	u32 target = (s->gpr[i.rs1()] + i.imm()) & ~(u32)1;
	if (unlikely(target % 4)) {
		RAISE_TRAP(TrapCode::UNALIGNED_IP);
	}
	s->gpr[i.rd()] = GET_GIP() + 4;
	SET_GIP(target);
}
HANDLER_BCC(beq, u32, ==);
HANDLER_BCC(bne, u32, !=);
HANDLER_BCC(blt, i32, <);
HANDLER_BCC(bge, i32, >=);
HANDLER_BCC(bltu, u32, <);
HANDLER_BCC(bgeu, u32, >=);
HANDLER_Load(lb, i8);
HANDLER_Load(lh, i16);
HANDLER_Load(lw, i32);
HANDLER_Load(lbu, u8);
HANDLER_Load(lhu, u16);
HANDLER_Store(sw, u32);
HANDLER_Store(sb, u8);
HANDLER_Store(sh, u16);
HANDLER_ArithmRI(addi, u32, +);
HANDLER_ArithmRI(slti, i32, <);
HANDLER_ArithmRI(sltiu, u32, <);
HANDLER_ArithmRI(xori, u32, ^);
HANDLER_ArithmRI(ori, u32, |);
HANDLER_ArithmRI(andi, u32, &);
HANDLER(slli)
{
	s->gpr[i.rd()] = (u32)s->gpr[i.rs1()] << i.imm();
}
HANDLER(srai)
{
	s->gpr[i.rd()] = (i32)s->gpr[i.rs1()] >> i.imm();
}
HANDLER(srli)
{
	s->gpr[i.rd()] = (u32)s->gpr[i.rs1()] >> i.imm();
}
HANDLER_ArithmRR(sub, u32, -);
HANDLER_ArithmRR(add, u32, +);
HANDLER(sll)
{
	s->gpr[i.rd()] = (u32)s->gpr[i.rs1()] << (s->gpr[i.rs2()] & 31);
}
HANDLER_ArithmRR(slt, i32, <);
HANDLER_ArithmRR(sltu, u32, <);
HANDLER_ArithmRR(xor, u32, ^);
HANDLER(sra)
{
	s->gpr[i.rd()] = (i32)s->gpr[i.rs1()] >> (s->gpr[i.rs2()] & 31);
}
HANDLER(srl)
{
	s->gpr[i.rd()] = (u32)s->gpr[i.rs1()] >> (s->gpr[i.rs2()] & 31);
}
HANDLER_ArithmRR(or, u32, |);
HANDLER_ArithmRR(and, u32, &);
HANDLER(fence) {}
HANDLER(fencei) {}
HANDLER(ecall)
{
	RAISE_TRAP(TrapCode::ECALL);
	RaiseTrap();
}

// ---------------------------------------------------------------------------------------------
// RVV 1.0 reference semantics (compiler-observed strip-mined integer subset).
//
// These HANDLER bodies are the SINGLE definition of vector semantics: the macro emits both the
// interpreter path and the `qcgstub_rv32_*` helper that JIT-compiled code calls, so the two can
// never diverge. VLEN is read from config at execution time; SEW/LMUL/element counts are derived
// from vtype. No workload constant appears here.
// ---------------------------------------------------------------------------------------------

// vsetvli rd, rs1, vtypei
//   AVL = (rs1 != x0) ? x[rs1] : (rd != x0) ? VLMAX(=~0 request) : keep current vl
//   vl  = min(AVL, VLMAX); rd <- vl; vtype <- vtypei (vill if unsupported)
HANDLER(vsetvli)
{
	u32 const vlen = dbt::config::vlen_bits;
	s->vec.vstart = 0; // Configuration instructions reset vstart even when they install vill.
	VType const vt{i.zimm11()};
	if (!vtype_supported(vt, vlen)) {
		// Reserved/unsupported vtype: architecturally sets vill and zeroes vl. Any later
		// vector op then traps (fail closed) rather than executing with a bogus width.
		s->vec.vtype = VTYPE_VILL_BIT;
		s->vec.vl = 0;
		if (i.rd())
			s->gpr[i.rd()] = 0;
		return;
	}
	u32 const vlmax = compute_vlmax(vt, vlen);
	bool const keep_vl = (i.rs1() == 0 && i.rd() == 0);
	u32 avl;
	if (i.rs1() != 0)
		avl = s->gpr[i.rs1()];
	else if (i.rd() != 0)
		avl = ~0u; // request VLMAX
	else
		avl = s->vec.vl; // rd=x0,rs1=x0: change vtype, keep vl
	u32 const vl = avl < vlmax ? avl : vlmax;
	// The rd=x0,rs1=x0 form is RESERVED when the retained vl would actually have to change
	// (i.e. the new VLMAX cannot hold the current vl). Note the condition is "vl changes",
	// NOT "VLMAX changes": widening VLMAX while vl still fits is legal and must not be
	// rejected -- guarded by case e1.
	//
	// The response is vill, not an immediate trap: that is what vill exists for, it is what
	// every other reserved-vtype path here already does (a1/a2/a3/a9), and it is bit-for-bit
	// what QEMU's strict mode does (reset_ill_vtype, tcg/vector_helper.c:52,119). Still fail
	// closed -- the next vector op sees vill and traps.
	if (unlikely(keep_vl && vl != s->vec.vl)) {
		s->vec.vtype = VTYPE_VILL_BIT;
		s->vec.vl = 0;
		s->vec.vstart = 0;
		return;
	}
	s->vec.vtype = vt.raw;
	s->vec.vl = vl;
	s->vec.vstart = 0;
	s->vec.vlenb = vlen / 8;
	if (i.rd())
		s->gpr[i.rd()] = vl;
}

HANDLER(vsetvl)
{
	u32 const vlen = dbt::config::vlen_bits;
	s->vec.vstart = 0;
	// vsetvl takes vtype from rs2 rather than from the zimm field. Everything downstream --
	// the vtype legality check, the AVL selection, and the reserved rd=x0/rs1=x0 rule -- is
	// identical. A GPR can hold bits above the vtype field; those are part of the value and
	// make it unsupported, which correctly sets vill rather than being masked off.
	VType const vt{s->gpr[i.rs2()]};
	if (!vtype_supported(vt, vlen)) {
		// Reserved/unsupported vtype: architecturally sets vill and zeroes vl. Any later
		// vector op then traps (fail closed) rather than executing with a bogus width.
		s->vec.vtype = VTYPE_VILL_BIT;
		s->vec.vl = 0;
		if (i.rd())
			s->gpr[i.rd()] = 0;
		return;
	}
	u32 const vlmax = compute_vlmax(vt, vlen);
	bool const keep_vl = (i.rs1() == 0 && i.rd() == 0);
	u32 avl;
	if (i.rs1() != 0)
		avl = s->gpr[i.rs1()];
	else if (i.rd() != 0)
		avl = ~0u; // request VLMAX
	else
		avl = s->vec.vl; // rd=x0,rs1=x0: change vtype, keep vl
	u32 const vl = avl < vlmax ? avl : vlmax;
	// The rd=x0,rs1=x0 form is RESERVED when the retained vl would actually have to change
	// (i.e. the new VLMAX cannot hold the current vl). Note the condition is "vl changes",
	// NOT "VLMAX changes": widening VLMAX while vl still fits is legal and must not be
	// rejected -- guarded by case e1.
	//
	// The response is vill, not an immediate trap: that is what vill exists for, it is what
	// every other reserved-vtype path here already does (a1/a2/a3/a9), and it is bit-for-bit
	// what QEMU's strict mode does (reset_ill_vtype, tcg/vector_helper.c:52,119). Still fail
	// closed -- the next vector op sees vill and traps.
	if (unlikely(keep_vl && vl != s->vec.vl)) {
		s->vec.vtype = VTYPE_VILL_BIT;
		s->vec.vl = 0;
		s->vec.vstart = 0;
		return;
	}
	s->vec.vtype = vt.raw;
	s->vec.vl = vl;
	s->vec.vstart = 0;
	s->vec.vlenb = vlen / 8;
	if (i.rd())
		s->gpr[i.rd()] = vl;
}

// Guard shared by every vector memory/arithmetic op:
//   * a valid, non-vill vtype must have been established;
//   * vl must be within the VLMAX that vtype implies. Not redundant paranoia -- this is what
//     bounds the element/chunk loops to the validated register group, so a corrupted or
//     guest-written vl can never index past the group into an unrelated vector register;
//   * vstart must be zero. This implementation has no resumable mid-instruction traps, so it
//     can NEVER produce a nonzero vstart itself, and RVV 1.0 explicitly permits raising an
//     illegal-instruction exception for a vstart value the implementation could not have
//     produced. `csrw vstart` is reachable from the guest, so without this the fixed-width
//     decomposition would silently start at element 0 and give a wrong answer.
#define RVV_REQUIRE_RUNNABLE_VTYPE(vt_out, vlen_out)                                                         \
	VType const vt_out{s->vec.vtype};                                                                    \
	u32 const vlen_out = dbt::config::vlen_bits;                                                         \
	do {                                                                                                 \
		if (unlikely(vt_out.vill() || !vtype_supported(vt_out, vlen_out) ||                          \
			     s->vec.vl > compute_vlmax(vt_out, vlen_out) || s->vec.vstart != 0)) {           \
			InsnNotImplemented(i, "rvv: vill/invalid vtype, vl > VLMAX, or vstart != 0");         \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

// Use only for implementations that explicitly preserve the prestart elements.
#define RVV_REQUIRE_RESTARTABLE_VTYPE(vt_out, vlen_out)                                                         \
	VType const vt_out{s->vec.vtype};                                                                    \
	u32 const vlen_out = dbt::config::vlen_bits;                                                         \
	do {                                                                                                 \
		if (unlikely(vt_out.vill() || !vtype_supported(vt_out, vlen_out) ||                          \
			     s->vec.vl > compute_vlmax(vt_out, vlen_out))) {                                 \
			InsnNotImplemented(i, "rvv: vill/invalid vtype or vl > VLMAX");                      \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

// Register-group legality for one operand at a given EMUL. An out-of-range EMUL or a
// misaligned / v31-overflowing group is a RESERVED encoding: raise illegal-instruction rather
// than wrapping the group (which would silently clobber v0, the mask register).
#define RVV_REQUIRE_LEGAL_GROUP(reg, emul_log2)                                                              \
	do {                                                                                                 \
		if (unlikely(!emul_in_range(emul_log2) || !reg_group_legal(reg, emul_log2))) {               \
			InsnNotImplemented(i, "rvv: illegal register group / EMUL out of range");             \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

// EEW of vle32/vse32 comes from the encoded width field, NOT from SEW.
// RVV 1.0: "The destination vector register group for a masked vector instruction cannot overlap
// the source mask register (v0), unless the destination is being written with a mask value."
// Violating it would make the mask change under the instruction that is reading it.
#define RVV_REQUIRE_MASK_NO_OVERLAP(vd, vm, emul_log2)                                                       \
	do {                                                                                                 \
		if (unlikely(!(vm) && (vd) == 0)) {                                                          \
			InsnNotImplemented(i, "rvv: masked op writes v0 (mask source overlap)");             \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

// Source side of the same rule: a masked op may not read v0 as a vector source.
// See same_width_sources_legal in rv32_vector.h.
#define RVV_REQUIRE_LEGAL_SOURCES(vs2, vs1, vs1_is_vector, vm)                                               \
	do {                                                                                                 \
		if (unlikely(!same_width_sources_legal(vs2, vs1, vs1_is_vector, vm))) {                      \
			InsnNotImplemented(i, "rvv: masked op reads v0 as a vector source");                 \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

// The reduction family's register rules, from the shared predicate in rv32_vector.h so the QCG
// route and this path admit exactly the same encodings. It subsumes the vs2 group check, the
// masked-source-v0 rule and (for the widening forms) the 2*SEW <= ELEN and seed/data overlap
// rules; it deliberately places NO constraint on vd, which RVV 1.0 14 lets overlap the sources
// and the mask.
#define RVV_REQUIRE_REDUCTION_REGS(vt_in, widening_in)                                                       \
	do {                                                                                                 \
		if (unlikely(!reduction_registers_legal(vt_in, widening_in, i.rd(), i.rs2(), i.rs1(),        \
							i.vm()))) {                                          \
			InsnNotImplemented(i, "rvv: reserved reduction register encoding (5.2/14)");         \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

static constexpr u32 RVV_EEW32_LOG2 = 5;

// Reported out of line so the fast path stays small. A verify mismatch means the fixed-width
// decomposition and the reference disagree, which invalidates every result from this run --
// abort rather than continue producing numbers.
void RvvVerifyFailed(char const *op, u32 vlen_bits, u32 vl, u32 elem_bytes)
{
	fprintf(stderr, "RVV_VERIFY_FAIL op=%s vlen=%u vl=%u elem_bytes=%u\n", op, vlen_bits, vl,
		elem_bytes);
	fflush(stderr);
	Panic("rvv: fixed-width lowering disagrees with the reference semantics");
}

// Unit-stride load/store at ANY EEW. The width field of the encoding selects EEW, which is
// INDEPENDENT of SEW -- that is the whole reason EMUL = (EEW/SEW)*LMUL exists and can differ
// from LMUL. Masked forms leave inactive elements undisturbed.
//
// The masked path is element-wise; the unmasked path goes through the width-parametric chunked
// decomposition. Both are the shared implementations, so they cannot drift.
HANDLER(vle)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const eew_log2 = eew_log2_from_width(i.funct3());
	u32 const eew_bytes = 1u << (eew_log2 - 3);
	i32 const emul_log2 = compute_emul_log2(vt, (u32)eew_log2);
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), emul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), emul_log2);
	u32 const base = s->gpr[i.rs1()];
	if (i.vm() && s->vec.vstart==0) {
		dispatch_load_unit_stride(s->vec, i.rd(), vmem, base, vlen, s->vec.vl, eew_bytes);
	} else if(i.vm()) {
		rvv_ref::load_unit_stride(s->vec,i.rd(),vmem,base,vlen,s->vec.vl,eew_bytes);
	} else {
		rvv_ref::load_unit_stride_masked(s->vec, i.rd(), vmem, base, vlen, s->vec.vl,
						 eew_bytes);
	}
	// Tail (e >= vl): tail-undisturbed. Legal under both ta and tu policies, and deterministic.
	s->vec.vstart = 0;
}

HANDLER(vse)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const eew_log2 = eew_log2_from_width(i.funct3());
	u32 const eew_bytes = 1u << (eew_log2 - 3);
	i32 const emul_log2 = compute_emul_log2(vt, (u32)eew_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), emul_log2); // rd field holds vs3 for stores
	u32 const base = s->gpr[i.rs1()];
	if (i.vm() && s->vec.vstart==0) {
		dispatch_store_unit_stride(s->vec, i.rd(), vmem, base, vlen, s->vec.vl, eew_bytes);
	} else if(i.vm()) {
		rvv_ref::store_unit_stride(s->vec,i.rd(),vmem,base,vlen,s->vec.vl,eew_bytes);
	} else {
		rvv_ref::store_unit_stride_masked(s->vec, i.rd(), vmem, base, vlen, s->vec.vl,
						  eew_bytes);
	}
	s->vec.vstart = 0;
}

// Strided load/store. The stride is x[rs2] interpreted as a SIGNED byte count; rs2 == x0 gives
// a zero stride, which is legal (every element reads/writes the same address).
HANDLER(vlse)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const eew_log2 = eew_log2_from_width(i.funct3());
	u32 const eew_bytes = 1u << (eew_log2 - 3);
	i32 const emul_log2 = compute_emul_log2(vt, (u32)eew_log2);
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), emul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), emul_log2);
	rvv_ref::load_strided(s->vec, i.rd(), vmem, s->gpr[i.rs1()], (i32)s->gpr[i.rs2()], vlen,
			      s->vec.vl, eew_bytes, i.vm());
	s->vec.vstart = 0;
}

// ---- fault-only-first load ---------------------------------------------------------------------
// On a fault at the first element this execution owns, the architectural response is the same as
// an ordinary load's: report the access fault. rvdbt has no recoverable memory-fault trap
// (TrapCode has no member for one, and the SIGSEGV handler panics), so the fault is delivered by
// performing the access that was predicted to fault -- which reaches the existing handler with
// the correct faulting address, exactly as a plain vle would. Every LATER element is trimmed
// instead, which is the case that needs no trap and is what the instruction exists for.
// Fault-only-first, non-segment (nf == 1) AND segment (7.8.1's vlseg<nf>e<eew>ff.v) -- one handler,
// because nf changes only how many contiguous fields one element occupies, not the trap rule that
// this instruction exists for. The shape and the register legality come from the SAME 7.8
// derivation the ordinary segment handler uses (mop == 0 there means `width` is the data EEW and a
// field group's EMUL is the width-derived one), so nf == 1 is that rule's degenerate case rather
// than a second set of checks.
HANDLER(vleff)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	VSegShape const seg = vseg_shape(i.funct3(), /*mop=*/0, (i.raw >> 29) & 0x7, vt);
	if (unlikely(!vseg_registers_legal(seg, i.rd(), i.rs2(), /*is_load=*/true, i.vm()))) {
		InsnNotImplemented(i, "rvv: fault-only-first reserved register encoding (7.8)");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	bool faulted = false;
	u32 fault_gaddr = 0;
	u32 const newvl = rvv_ref::load_fault_only_first(s->vec, i.rd(), vmem, s->gpr[i.rs1()], vlen,
							 s->vec.vl, s->vec.vstart, seg.data_eew,
							 i.vm(), faulted, fault_gaddr, seg.nf,
							 seg.field_regs);
	if (unlikely(faulted)) {
		// REPORTED, NOT PROVOKED. The earlier form touched the guest address and relied on the
		// host to fault; that is unsound twice over. The address must come from the probe
		// rather than from rs1 -- element 0 may straddle a page boundary, and a segment form's
		// first field can be readable while a later one is not -- and even with the right
		// address a touch is not a fault: x86 has no read-denying protection for a page mapped
		// PROT_WRITE, so the host mapping of a write-only guest page reads back fine and the
		// instruction would complete having done nothing at all.
		//
		// There is no guest-signal delivery and no memory-fault TrapCode in this substrate
		// (TrapCode is UNALIGNED_IP / ILLEGAL_INSN / EBREAK / ECALL), so a guest load fault
		// ends in ukernel's diagnose-and-terminate. mmu::ReportGuestFault is that same ending,
		// reached directly with the address the probe found and the reason it refused. vl and
		// vstart are left untouched, per the spec: the instruction did not complete.
		s->ip = GET_GIP();
		mmu::ReportGuestFault(s->ip, fault_gaddr,
				      mmu::page_mapped(fault_gaddr) ? "protection" : "unmapped");
	}
	s->vec.vl = newvl; // trimmed, or unchanged if every active element was mapped
	s->vec.vstart = 0;
}

// ---- indexed (gather/scatter) load and store ------------------------------------------------
// The width field gives the INDEX element width, not the data width -- data is at SEW. So the
// index group's EMUL is (index_EEW/SEW)*LMUL and the two sides can need different numbers of
// registers; both must be legal independently.
#define RVV_INDEXED_PROLOGUE()                                                                       \
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);                                                     \
	i32 const idx_eew_log2 = eew_log2_from_width(i.funct3());                                    \
	u32 const idx_eew = 1u << (idx_eew_log2 - 3);                                                \
	u32 const data_eew = vt.sew() / 8;                                                           \
	i32 const data_emul = vt.lmul_log2();                                                        \
	i32 const idx_emul = compute_emul_log2(vt, (u32)idx_eew_log2);                               \
	if (unlikely(!vmemory_registers_legal(vt,i.funct3(),(i.raw>>26)&3,i.rd(),i.rs2(),           \
					     (i.raw&0x7f)==0x27,i.vm()) ||                           \
		     !emul_in_range(idx_emul) || !reg_group_legal(i.rs2(), idx_emul) ||              \
		     !reg_group_legal(i.rd(), data_emul))) {                                         \
		InsnNotImplemented(i, "rvv: indexed access illegal index/data EMUL");                \
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
		return;                                                                              \
	}

HANDLER(vlxei)
{
	RVV_INDEXED_PROLOGUE();
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), data_emul);
	// C-beta substrate. mop (raw[27:26]): 01 = vluxei (UNORDERED), 11 = vloxei (ORDERED).
	// Only the unordered form may use a host gather, whose element access order is arbitrary.
	// The ordered form keeps the reference, which walks elements in index order.
	bool const unordered = ((i.raw >> 26) & 0x3) == 0b01;
	if (dbt::config::rvv_gather && unordered && i.vm() && s->vec.vstart == 0 &&
	    data_eew == 4 && idx_eew == 4 && data_emul == 0 && rvv_gather::host_has_avx2() &&
	    rvv_gather::rvv_gather_e32_avx2(&s->vec, i.rd(), i.rs2(), vmem, s->gpr[i.rs1()], vlen,
					    s->vec.vl)) {
		s->vec.vstart = 0;
		return;
	}
	rvv_ref::load_indexed(s->vec, i.rd(), i.rs2(), vmem, s->gpr[i.rs1()], vlen, s->vec.vl,
			      data_eew, idx_eew, i.vm());
	s->vec.vstart = 0;
}

HANDLER(vsxei)
{
	RVV_INDEXED_PROLOGUE();
	// A scatter has no destination register, so there is no vd/v0 overlap rule here: rd names
	// the DATA source vs3.
	rvv_ref::store_indexed(s->vec, i.rd(), i.rs2(), vmem, s->gpr[i.rs1()], vlen, s->vec.vl,
			       data_eew, idx_eew, i.vm());
	s->vec.vstart = 0;
}

// ---- segment load and store ---------------------------------------------------------------------
// nf fields per element, field f landing in register group (vd + f*EMUL).
//
// THE SHAPE IS NOT READ OFF THE ENCODING HERE, because two of the three addressing modes disagree
// about what `width` means: for unit-stride and strided it is the DATA EEW, and for the INDEXED
// forms it is the INDEX EEW while the data moves at SEW. vseg_shape owns that distinction and
// vseg_registers_legal owns 7.8's register rules (EMUL*NFIELDS <= 8, the run not passing v31, the
// masked-load v0 rule, the index group's own EMUL, RV32's refusal of EEW=64 indices, and an
// indexed load's destination being disjoint from the index group). Both are shared with any other
// caller, so a reserved encoding cannot be executed by one path and refused by another.
//
// RESTARTABLE, not RUNNABLE: the references below start at vstart and leave the prestart elements
// untouched, so a non-zero vstart is a legal execution rather than an illegal instruction. The
// stricter macro was refusing every segment access with vstart != 0 -- an over-refusal, not an
// encoding rule.
#define RVV_SEGMENT_PROLOGUE(reg, is_load)                                                           \
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);                                                     \
	u32 const mop = (i.raw >> 26) & 0x3;                                                         \
	VSegShape const seg = vseg_shape(i.funct3(), mop, (i.raw >> 29) & 0x7, vt);                  \
	if (unlikely(!vseg_registers_legal(seg, (reg), i.rs2(), (is_load), i.vm()))) {               \
		InsnNotImplemented(i, "rvv: segment access reserved register encoding (7.8)");       \
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
		return;                                                                              \
	}

HANDLER(vlseg)
{
	RVV_SEGMENT_PROLOGUE(i.rd(), true);
	if (seg.indexed) { // indexed segment: each segment's base comes from the index vector
		rvv_ref::load_segment_indexed(s->vec, i.rd(), i.rs2(), vmem, s->gpr[i.rs1()], vlen,
					      s->vec.vl, seg.data_eew, seg.index_eew, seg.nf,
					      seg.field_regs, i.vm(), s->vec.vstart);
	} else {
		// Unit-stride advances one whole SEGMENT per element; strided uses rs2's bytes.
		i32 const stride =
		    mop == 0b10 ? (i32)s->gpr[i.rs2()] : (i32)(seg.nf * seg.data_eew);
		rvv_ref::load_segment(s->vec, i.rd(), vmem, s->gpr[i.rs1()], stride, vlen, s->vec.vl,
				      seg.data_eew, seg.nf, seg.field_regs, i.vm(), s->vec.vstart);
	}
	s->vec.vstart = 0;
}

HANDLER(vsseg)
{
	// A store has no destination register, so the masked-v0 and index-overlap rules do not apply:
	// rd names the DATA source vs3.
	RVV_SEGMENT_PROLOGUE(i.rd(), false);
	if (seg.indexed) {
		rvv_ref::store_segment_indexed(s->vec, i.rd(), i.rs2(), vmem, s->gpr[i.rs1()], vlen,
					       s->vec.vl, seg.data_eew, seg.index_eew, seg.nf,
					       seg.field_regs, i.vm(), s->vec.vstart);
	} else {
		i32 const stride =
		    mop == 0b10 ? (i32)s->gpr[i.rs2()] : (i32)(seg.nf * seg.data_eew);
		rvv_ref::store_segment(s->vec, i.rd(), vmem, s->gpr[i.rs1()], stride, vlen,
				       s->vec.vl, seg.data_eew, seg.nf, seg.field_regs, i.vm(),
				       s->vec.vstart);
	}
	s->vec.vstart = 0;
}

HANDLER(vsse)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const eew_log2 = eew_log2_from_width(i.funct3());
	u32 const eew_bytes = 1u << (eew_log2 - 3);
	i32 const emul_log2 = compute_emul_log2(vt, (u32)eew_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), emul_log2); // rd holds vs3
	rvv_ref::store_strided(s->vec, i.rd(), vmem, s->gpr[i.rs1()], (i32)s->gpr[i.rs2()], vlen,
			       s->vec.vl, eew_bytes, i.vm());
	s->vec.vstart = 0;
}

// vadd.vv vd, vs2, vs1 -- element-wise add at the CURRENT SEW. All three operands use EEW=SEW,
// so their EMUL is LMUL and each must be an LMUL-aligned, in-range register group.
HANDLER(vadd_vv)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const emul_log2 = vt.lmul_log2(); // EEW == SEW => EMUL == LMUL
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), emul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs1(), emul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), emul_log2);
	u32 const sew_bytes = vt.sew() / 8;
	if (unlikely(sew_bytes != 1 && sew_bytes != 2 && sew_bytes != 4 && sew_bytes != 8)) {
		// Unreachable: vtype_supported() already rejects vsew >= 4. Kept as a hard
		// fail-closed backstop rather than a path that silently writes nothing.
		InsnNotImplemented(i, "rvv: unsupported SEW");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	if (s->vec.vstart)
		rvv_ref::vialu(s->vec, VF6_VADD, VSrc::VV, i.rd(), i.rs2(), i.rs1(), 0, 0,
			true, vlen, s->vec.vl, sew_bytes);
	else dispatch_add_vv(s->vec, i.rd(), i.rs2(), i.rs1(), vlen, s->vec.vl, sew_bytes);
	s->vec.vstart = 0;
}

// ---------------------------------------------------------------------------------------------
// RVV integer families.
//
// Each handler covers a whole encoding family keyed by funct6, so the legality discipline is
// written once rather than once per mnemonic:
//   * vtype must be valid and vl <= VLMAX, vstart == 0            (RVV_REQUIRE_RUNNABLE_VTYPE)
//   * every element-group operand must be LMUL-aligned and in range (RVV_REQUIRE_LEGAL_GROUP)
//   * a masked instruction (vm==0) must not write v0 unless it writes a MASK    (see below)
// Anything the decoder did not admit never arrives here and traps as `ill`.
// ---------------------------------------------------------------------------------------------

// vsetivli rd, uimm, vtypei -- same as vsetvli except AVL is a 5-bit zero-extended immediate,
// so it never reads a GPR and the "keep current vl" form does not exist.
HANDLER(vsetivli)
{
	u32 const vlen = dbt::config::vlen_bits;
	s->vec.vstart = 0;
	VType const vt{(u32)((i.raw >> 20) & 0x3ff)}; // vtypei is 10 bits in vsetivli
	if (!vtype_supported(vt, vlen)) {
		s->vec.vtype = VTYPE_VILL_BIT;
		s->vec.vl = 0;
		if (i.rd())
			s->gpr[i.rd()] = 0;
		return;
	}
	u32 const vlmax = compute_vlmax(vt, vlen);
	u32 const avl = (i.raw >> 15) & 0x1f; // uimm5, zero-extended
	u32 const vl = avl < vlmax ? avl : vlmax;
	s->vec.vtype = vt.raw;
	s->vec.vl = vl;
	s->vec.vstart = 0;
	s->vec.vlenb = vlen / 8;
	if (i.rd())
		s->gpr[i.rd()] = vl;
}

// Second-operand source, from funct3. All six operand groups must be covered, not just the three
// OPIV* ones: OPIVV=000, OPFVV=001, OPMVV=010 take the operand from vs1; OPIVI=011 from the
// immediate; OPIVX=100, OPFVF=101, OPMVX=110 from a scalar register. Reading this as a two-way
// test ("000 is VV, everything else that is not 011 is VX") is right for OPIV* and wrong for
// OPMVV, where it makes the second operand come from a GPR instead of vs1 -- the vector operand
// then reads as whatever x[rs1] happens to hold.
static ALWAYS_INLINE VSrc rvv_src_of(u32 funct3)
{
	if (funct3 == 0b011)
		return VSrc::VI;
	return (funct3 & 0b100) ? VSrc::VX : VSrc::VV;
}
// OPIVI's 5-bit immediate is SIGN-extended (RVV 1.0), and lives in the vs1 field.
static ALWAYS_INLINE i32 rvv_simm5(u32 raw)
{
	u32 const u = (raw >> 15) & 0x1f;
	return (i32)(u << 27) >> 27;
}

// P15 candidate 7. Decide from the two decoded instruction words alone whether the pair may fuse.
//
// The shape admitted is exactly the one whose intermediate is provably unobservable:
//   * both are OP-V integer element-wise .vv forms (funct3 == 0), unmasked;
//   * op1 writes vd; op2 reads vd AND writes the same vd, so op1's result is dead on op2's retire;
//   * op2's other source is not vd (otherwise it reads the intermediate twice, which is still
//     correct but is a different data flow than the fused kernel implements).
// No vsetvl* can sit between them because they are adjacent instruction words, so vtype, vl, SEW
// and LMUL are identical for both by construction. Nothing here inspects a mnemonic table, a
// workload, or a threshold.
//
// Returns false unless every condition holds; the caller then runs the unchanged single-op path.
struct FusePlan {
	bool ok;
	u32 f6_2;
	u32 op2_other;   // op2's source that is not the intermediate
	bool int_first;  // op2 computes (intermediate, other) rather than (other, intermediate)
	u32 pc2;         // guest PC of the consumer, so it can retire without repeating the work
};

// N18 correction: the first version of this predicate required the consumer to sit at pc+4. That
// is the SAME adjacency constraint whose removal was the whole correction in the BB census, and it
// gave the prototype zero coverage on all 25 guests. This version scans forward inside the block,
// letting instructions that provably cannot interfere pass, which is what the census measured.
//
// Legality of hoisting the consumer up past the skipped instructions: for each intervening
// instruction we require that it neither writes vd (which would change what the consumer reads),
// nor reads vd (which would observe the intermediate we are eliding), nor writes the consumer's
// other source. Any branch, any vsetvl* and anything not decodable ends the scan -- so vtype, vl,
// SEW and LMUL are identical for producer and consumer by construction, and no control-flow edge
// is crossed. Intervening scalar instructions are invisible here because the JIT lowers them
// natively; they cannot touch vector registers, so they cannot interfere.
static constexpr u32 RVV_FUSE_SCAN_INSNS = 8; // bounded so the scan cost stays O(1) per dispatch
static ALWAYS_INLINE FusePlan rvv_fusible_pair(u8 *vmem, u32 pc1, u32 raw1, u32 f3)
{
	FusePlan p{false, 0, 0, false, 0};
	// funct3 selects the class: 0 = OPIVV (integer vec-vec), 1 = OPFVV (FP vec-vec). Both
	// producer and consumer must be the SAME class, so one fused kernel handles the pair.
	auto opiv_vv_unmasked = [f3](u32 r) {
		return (r & 0x7f) == 0x57 && ((r >> 12) & 7) == f3 && ((r >> 25) & 1) == 1;
	};
	auto is_vector = [](u32 r) { return (r & 0x7f) == 0x57; };
	auto is_vset = [](u32 r) { return (r & 0x7f) == 0x57 && ((r >> 12) & 7) == 7; };
	if (!opiv_vv_unmasked(raw1))
		return p;
	u32 const vd1 = (raw1 >> 7) & 0x1f;
	// Registers written by instructions we skip over. The consumer's OTHER source must not be
	// among them, or hoisting the consumer up here would make it read a stale value. This has
	// to be accumulated during the scan because which register that is only becomes known when
	// the consumer is found.
	u32 skipped_writes = 0;
	for (u32 k = 1; k <= RVV_FUSE_SCAN_INSNS; k++) {
		u32 const pc2 = pc1 + 4 * k;
		if ((pc2 & ~mmu::PAGE_MASK) == 0) // do not walk off the page this block lives on
			return p;
		u32 const raw2 = *(u32 *)(vmem + pc2);
		if (is_vset(raw2))
			return p; // vtype/vl may change: any resident interpretation dies here
		if (opiv_vv_unmasked(raw2)) {
			u32 const vd2 = (raw2 >> 7) & 0x1f, vs2_2 = (raw2 >> 20) & 0x1f,
				  vs1_2 = (raw2 >> 15) & 0x1f;
			bool const reads = vs2_2 == vd1 || vs1_2 == vd1;
			if (reads) {
				// This is the consumer. It must also OVERWRITE vd, so the
				// intermediate is dead, and must read it exactly once.
				if (vd2 != vd1 || (vs2_2 == vd1) == (vs1_2 == vd1))
					return p;
				u32 const other = (vs2_2 == vd1) ? vs1_2 : vs2_2;
				if (skipped_writes & (1u << other))
					return p; // hoisting it here would read a stale operand
				p.int_first = vs2_2 == vd1;
				p.op2_other = other;
				p.f6_2 = (raw2 >> 26) & 0x3f;
				p.pc2 = pc2;
				p.ok = true;
				return p;
			}
			if (vd2 == vd1)
				return p; // vd rewritten before any consumer: nothing to fuse
			skipped_writes |= 1u << vd2;
			continue; // independent vector op: may be skipped over
		}
		if (is_vector(raw2))
			return p; // some other vector form: too coarse to reason about here
		return p;	  // non-vector word: end of what this decoder can vouch for
	}
	return p;
}

HANDLER(vialu)
{
	// P15 candidate 7: this instruction's work may already have been done by its predecessor.
	// Keyed on the consumer's own PC, not merely "the next vialu": the scan may skip over
	// independent vector ops, which dispatch between the pair and must not consume the marker.
	if (unlikely(s->vec.fused_skip_valid) && gip == s->vec.fused_skip_pc &&
	    i.raw == s->vec.fused_skip_raw) {
		s->vec.fused_skip_valid = false;
		s->vec.vstart = 0;
		return;
	}
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_SOURCES(i.rs2(), i.rs1(), src == VSrc::VV, i.vm());
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	// P15 candidate 7: try to fuse with the immediate successor before running this op alone.
	// Only the .vv form is admitted, and only when rvv_fusible_pair proves the intermediate is
	// unobservable. On success BOTH instructions are complete; the successor still dispatches
	// and retires via the marker above.
	if (dbt::config::rvv_fuse_pairs && dbt::config::rvv_fast && src == VSrc::VV && s->vec.vstart == 0) {
		if constexpr (rvv_fast::kFastStats)
			rvv_fast::g_fast.fuse_scan_attempted++;
		FusePlan const p = rvv_fusible_pair(vmem, gip, i.raw, /*OPIVV=*/0);
		if constexpr (rvv_fast::kFastStats)
			if (p.ok)
				rvv_fast::g_fast.fuse_scan_found++;
		if (p.ok &&
		    rvv_fast::try_ialu_fused(s->vec, i.funct6(), p.f6_2, i.rd(), i.rs2(), i.rs1(),
					     p.op2_other, p.int_first, vlen, s->vec.vl, vt.sew() / 8,
					     lmul_log2)) {
			s->vec.fused_skip_pc = p.pc2;
			s->vec.fused_skip_raw = *(u32 *)(vmem + p.pc2);
			s->vec.fused_skip_valid = true;
			s->vec.vstart = 0;
			return;
		}
	}
	// P13: try the integer element-wise CLASS fast path first. It refuses on its own
	// obligations (shape, unsupported (op, SEW)) and the reference below is then the whole
	// operation, so the two can never disagree by construction of the control flow.
	if (!(dbt::config::rvv_fast && s->vec.vstart == 0 &&
	      rvv_fast::try_ialu(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(),
				 s->gpr[i.rs1()], rvv_simm5(i.raw), i.vm(), vlen, s->vec.vl,
				 vt.sew() / 8, lmul_log2)))
		rvv_ref::vialu(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()],
			       rvv_simm5(i.raw), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// Comparisons write a MASK register: vd is a single register, not a group, and vd == v0 is
// legal even when masked (the "destination is a mask value" exception above).
HANDLER(vicmp)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	// Mask-result destination is exempt from 5.3, but the SOURCE rule still applies.
	RVV_REQUIRE_LEGAL_SOURCES(i.rs2(), i.rs1(), src == VSrc::VV, i.vm());
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	u32 const regs = emul_group_regs(lmul_log2);
	if ((i.rd() > i.rs2() && i.rd() < i.rs2() + regs) ||
	    (src == VSrc::VV && i.rd() > i.rs1() && i.rd() < i.rs1() + regs)) {
		InsnNotImplemented(i, "rvv: mask destination overlaps non-low source group");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vicmp(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()],
		       rvv_simm5(i.raw), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// Mask-register logic: all operands are single mask registers, never groups, never masked.
HANDLER(vmlogic)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	rvv_ref::vmlogic(s->vec, i.funct6(), i.rd(), i.rs2(), i.rs1(), s->vec.vl);
	s->vec.vstart = 0;
}

// vmerge.v{v,x,i}m (vm==0) and vmv.v.{v,x,i} (vm==1) share funct6=010111. For the vmv forms
// vs2 must be v0 in the encoding and is not read.
HANDLER(vmerge)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	// vmerge reads v0 as the selector but WRITES vd; vd==v0 would clobber the selector
	// mid-instruction, so the same no-overlap rule applies.
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	// The merge form (vm=0) may not READ v0 as data either; vmv.v.* (vm=1) is unrestricted.
	RVV_REQUIRE_LEGAL_SOURCES(i.rs2(), i.rs1(), src == VSrc::VV, i.vm());
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	if (!i.vm())
		RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	rvv_ref::vmerge_or_mv(s->vec, src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()],
			      rvv_simm5(i.raw), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

HANDLER(vid)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	rvv_ref::vid(s->vec, i.rd(), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

HANDLER(vimul)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	// OPMVV (funct3=010) takes vs1 as a vector; OPMVX (110) takes rs1 as a scalar.
	VSrc const src = i.funct3() == 0b010 ? VSrc::VV : VSrc::VX;
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_SOURCES(i.rs2(), i.rs1(), src == VSrc::VV, i.vm());
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	// Substrate: try the integer-multiply fast path first. It refuses on its own obligations and
	// the reference below is then the whole operation, so the two cannot disagree.
	if (!(dbt::config::rvv_fast && s->vec.vstart == 0 &&
	      rvv_fast::try_imul(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen,
				 s->vec.vl, vt.sew() / 8, lmul_log2)))
		rvv_ref::vimul(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()],
			       i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// Exact unmasked vmul.vv (P3.5a). rv32_decode.h gives this encoding its own op purely so the QIR
// translator can attach a typed-QCG chunk lowering to it; the SEMANTICS must not fork, so this
// does not restate the family's legality checks or its arithmetic. It forwards the SAME
// instruction word to the SAME Impl_vimul body above -- funct6 is still read from the word (and is
// VF6_VMUL by decode), funct3 still selects VSrc::VV, vm is still 1 -- so the interpreter cannot
// disagree with the family handler, and the typed route's --rvv-direct 0/1 A/B stays meaningful.
//
// The one observable difference is the census/seqtrace family label, which becomes "vmul_vv"
// rather than "vimul" for this encoding. That is the same split vadd.vv already makes against
// vialu, and rv32_seqtrace.h classifies the new name with the identical element-wise operand shape.
HANDLER(vmul_vv)
{
	Impl_vimul(s, gip, vmem, insn::Insn_vimul{i.raw});
}

// Exact unmasked vsub.vv (S2.1). Same device, same reasoning, and the same non-fork of semantics as
// vmul_vv directly above: rv32_decode.h gives this encoding its own op purely so the QIR translator
// can attach a typed-QCG chunk lowering to it, and this handler forwards the SAME instruction word
// to the SAME Impl_vialu body -- funct6 is still read from the word (and is VF6_VSUB by decode),
// funct3 still selects VSrc::VV, vm is still 1 -- so the interpreter cannot disagree with the family
// handler, and the --rvv-direct 0/1 A/B stays meaningful.
//
// FORWARDING, NOT COPYING, IS ALSO WHAT KEEPS THE P15 FUSION MARKER CORRECT. Impl_vialu both SETS
// `vec.fused_skip_*` (when it fuses with its successor) and CONSUMES it (keyed on the consumer's own
// gip and raw word). A vsub.vv can be either half of such a pair, so it must run the same body: an
// independent copy that skipped the marker check would re-execute an instruction whose work the
// predecessor already did. `gip` is passed through unchanged, which is what the marker is keyed on.
HANDLER(vsub_vv)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

// Exact unmasked vxor.vv (S2.2). Same device, same reasoning, same non-fork of semantics as
// vsub_vv directly above: the encoding gets its own op purely so the QIR translator can attach a
// typed-QCG chunk lowering to it, and this handler forwards the SAME instruction word to the SAME
// Impl_vialu body -- funct6 is still read from the word (and is VF6_VXOR by decode), funct3 still
// selects VSrc::VV, vm is still 1.
//
// That forwarding is what makes the interpreter incapable of disagreeing with the family handler,
// and it is worth more here than for the sub: vand.vv and vor.vv are the same family at adjacent
// funct6 values, so a COPIED body that hardcoded "xor" would turn a decoder slip into a wrong
// result instead of a wrong label. Forwarding also keeps the P15 fusion marker correct for the
// same reason it does for vsub_vv -- Impl_vialu both sets and consumes `vec.fused_skip_*`, keyed
// on `gip` and the raw word, and a vxor.vv can be either half of such a pair.
HANDLER(vxor_vv)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

// Exact unmasked vor.vv (S2.3). Same device, same reasoning, same non-fork of semantics as vxor_vv
// directly above: the encoding gets its own op purely so the QIR translator can attach a typed-QCG
// chunk lowering to it, and this handler forwards the SAME instruction word to the SAME Impl_vialu
// body -- funct6 is still read from the word (and is VF6_VOR by decode), funct3 still selects
// VSrc::VV, vm is still 1.
//
// Forwarding is worth even more here than it was for the xor. TWO of the three adjacent bitwise
// funct6 values now have their own op, so a copied body that hardcoded "or" could turn either a
// downward decoder slip (vand.vv) or an upward one (vxor.vv, an ALREADY-ACCEPTED route) into a
// wrong result instead of a wrong label -- and in the upward direction it would also silently
// disagree with the accepted S2.2 interpreter path. Forwarding also keeps the P15 fusion marker
// correct for the same reason it does for vxor_vv: Impl_vialu both sets and consumes
// `vec.fused_skip_*`, keyed on `gip` and the raw word, and a vor.vv can be either half of a pair.
HANDLER(vor_vv)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

// Exact unmasked vand.vv (S2.4). Same device, same reasoning, same non-fork of semantics as vor_vv
// directly above: the encoding gets its own op purely so the QIR translator can attach a typed-QCG
// chunk lowering to it, and this handler forwards the SAME instruction word to the SAME Impl_vialu
// body -- funct6 is still read from the word (and is VF6_VAND by decode), funct3 still selects
// VSrc::VV, vm is still 1.
//
// Forwarding is worth the most here of all three bitwise splits. ALL THREE adjacent funct6 values
// now have their own op, so a copied body that hardcoded "and" could turn an upward decoder slip
// into a wrong result for a guest OR (vor.vv) or XOR (vxor.vv) -- BOTH of which are already-accepted
// routes -- instead of a wrong label, and it would silently disagree with the accepted S2.2 and S2.3
// interpreter paths at the same time. Forwarding also keeps the P15 fusion marker correct for the
// same reason it does for vor_vv: Impl_vialu both sets and consumes `vec.fused_skip_*`, keyed on
// `gip` and the raw word, and a vand.vv can be either half of a pair.
HANDLER(vand_vv)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

// P7N-B. Exact unmasked vsll.vi / vsrl.vi. Same device, same reasoning, same non-fork of semantics
// as the five `.vv` splits above: the encodings get their own ops purely so the QIR translator can
// attach a typed-QCG chunk lowering to them, and these handlers forward the SAME instruction word
// to the SAME Impl_vialu body -- funct6 is still read from the word (and is VF6_VSLL / VF6_VSRL by
// decode), funct3 still selects VSrc::VI, vm is still 1.
//
// FORWARDING IS WORTH MORE HERE THAN FOR ANY EARLIER SPLIT, because of what sits next door.
// VF6_VSRA is 101001, one value above VF6_VSRL, and it is an ARITHMETIC shift: a copied body that
// hardcoded a logical shift would turn a one-bit decoder slip into a WRONG VALUE for every negative
// element, silently, rather than into a wrong label. Forwarding makes that class of divergence
// unrepresentable -- the shift kind is read from the word by the same switch the reference helper
// uses (vialu_apply, rv32_vector_lower.h) -- and it keeps the P15 fusion marker correct for the
// same reason it does for the others.
HANDLER(vsll_vi)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

HANDLER(vsrl_vi)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

// A6: the two scalar/immediate-source add splits forward to the same body for the same reason.
HANDLER(vadd_vx)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

HANDLER(vadd_vi)
{
	Impl_vialu(s, gip, vmem, insn::Insn_vialu{i.raw});
}

// Reductions: vs2 is a GROUP at LMUL, vs1 and vd are single registers (the scalar slot).
HANDLER(vred)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_REDUCTION_REGS(vt, /*widening=*/false);
	rvv_ref::vred(s->vec, i.funct6(), i.rd(), i.rs2(), i.rs1(), i.vm(), vlen, s->vec.vl,
		      vt.sew() / 8);
	s->vec.vstart = 0;
}

// vmv.s.x vd, rs1 -- write element 0 only. Per RVV 1.0 this is a no-op when vl == 0.
HANDLER(vmvsx)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	if (s->vec.vstart < s->vec.vl)
		s->vec.elem_put(i.rd(), 0, vt.sew() / 8, vlen, (u64)(i64)(i32)s->gpr[i.rs1()]);
	s->vec.vstart = 0;
}

// vmv.x.s rd, vs2 -- read element 0 into a GPR, sign-extended to XLEN. Defined even when vl==0.
HANDLER(vmvxs)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew_bytes = vt.sew() / 8;
	i64 const v = s->vec.elem_i(i.rs2(), 0, sew_bytes, vlen);
	if (i.rd())
		s->gpr[i.rd()] = (u32)(i32)v;
	s->vec.vstart = 0;
}

// ---------------------------------------------------------------------------------------------
// Vector floating point. Element width is SEW; only SEW=32/64 are FP widths in the base V
// extension, so anything else fails closed rather than being silently reinterpreted.
// ---------------------------------------------------------------------------------------------
#define RVV_REQUIRE_FP_SEW(sew_bytes)                                                                        \
	do {                                                                                                 \
		if (unlikely(!vf_sew_supported(sew_bytes))) {                                                \
			InsnNotImplemented(i, "rvv-fp: SEW is not a supported FP width (need 32 or 64)");     \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

// Vector FP has no rm field: every rounding-dependent vector FP instruction resolves through
// fcsr.frm, so a guest that parks a reserved value there makes them all illegal. Without this the
// operation would fall through to the host path and silently round in whatever mode was last set.
#define RVV_REQUIRE_FP_RM()                                                                          \
	do {                                                                                         \
		if (unlikely(fp_mode(s->fpu, FRM_DYN).path == FP_ILLEGAL)) {                         \
			InsnNotImplemented(i, "vector fp: reserved fcsr.frm");                       \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                          \
			return;                                                                      \
		}                                                                                    \
	} while (0)

// ---- integer extension: vsext/vzext (VXUNARY0) ------------------------------------------------
// The source EEW is SEW/f, so the source group's EMUL is LMUL/f and the two sides have DIFFERENT
// register-group alignment requirements. An EMUL that falls outside the legal range (or a source
// SEW below 8 bits) is illegal, not merely unusual.
// OPIVI's 5-bit immediate is SIGN-extended for the arithmetic families and ZERO-extended for
// the shift, slide and gather families. Using the wrong one silently changes the meaning of any
// immediate with bit 4 set, so both spellings exist explicitly.
static ALWAYS_INLINE u32 rvv_uimm5(u32 raw) { return (raw >> 15) & 0x1f; }

HANDLER(vext)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const dsew = vt.sew() / 8;
	u32 const div = vext_divisor(i.rs1());
	if (unlikely(dsew < div)) { // source would be narrower than 8 bits
		InsnNotImplemented(i, "rvv: vext source EEW < 8");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	u32 const ssew = dsew / div;
	i32 const dlmul = vt.lmul_log2();
	i32 const slmul = dlmul - (div == 8 ? 3 : div == 4 ? 2 : 1);
	if (unlikely(!emul_in_range(slmul) || !reg_group_legal(i.rd(), dlmul) ||
		     !reg_group_legal(i.rs2(), slmul))) {
		InsnNotImplemented(i, "rvv: vext illegal source EMUL / register group");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), dlmul);
	u32 const dg = emul_group_regs(dlmul), sg = emul_group_regs(slmul);
	bool const overlap = i.rd() < i.rs2() + sg && i.rs2() < i.rd() + dg;
	if ((overlap && (slmul < 0 || i.rs2() + sg != i.rd() + dg)) || (!i.vm() && i.rs2() == 0)) {
		InsnNotImplemented(i, "rvv: extension has illegal mixed-width overlap");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vext(s->vec, vext_is_signed(i.rs1()), i.rd(), i.rs2(), i.vm(), vlen, s->vec.vl,
		      dsew, ssew);
	s->vec.vstart = 0;
}

// ---- slides ------------------------------------------------------------------------------------
// vslideup and vslide1up move data toward higher element numbers, so the destination must not
// overlap the source group -- the spec makes that overlap illegal rather than implementation
// defined, and an in-place implementation would read elements it had already overwritten.
HANDLER(vslide)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	u32 const sew = vt.sew() / 8;
	u32 const f3 = i.funct3();
	bool const down = i.funct6() == VF6_VSLIDEDOWN;
	bool const one = (f3 == 0b110) || (f3 == 0b101); // OPMVX / OPFVF: vslide1*
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (!i.vm() && i.rs2()==0) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	if (unlikely(!down && group_overlaps(i.rd(), i.rs2(), lmul_log2))) {
		InsnNotImplemented(i, "rvv: vslideup/vslide1up vd must not overlap vs2");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	if (one) {
		// The filled element comes from an X register for vslide1*, an F register for
		// vfslide1*; the F form must be NaN-boxed the same way any scalar FP read is.
		u64 scalar;
		if (f3 == 0b101) {
			RVV_REQUIRE_FP_SEW(sew);
			scalar = sew == 4 ? (u64)f32_unbox(s->fpu.f[i.rs1()]) : s->fpu.f[i.rs1()];
		} else {
			scalar = (u64)(i64)(i32)s->gpr[i.rs1()];
		}
		rvv_ref::vslide1(s->vec, down, i.rd(), i.rs2(), scalar, i.vm(), vlen, s->vec.vl, sew);
	} else {
		// OPIVX takes the offset from a GPR, OPIVI from the ZERO-extended 5-bit immediate.
		u64 const off = f3 == 0b011 ? (u64)rvv_uimm5(i.raw) : (u64)s->gpr[i.rs1()];
		if (down)
			rvv_ref::vslidedown(s->vec, i.rd(), i.rs2(), off, i.vm(), vlen, s->vec.vl,
					    sew, compute_vlmax(vt, vlen));
		else
			rvv_ref::vslideup(s->vec, i.rd(), i.rs2(), off, i.vm(), vlen, s->vec.vl, sew);
	}
	s->vec.vstart = 0;
}

// ---- register gather -----------------------------------------------------------------------------
// vd must not overlap vs2 or the index source: a gather reads arbitrary source elements, so an
// overlapping destination would read values it had already written.
HANDLER(vrgather)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	u32 const sew = vt.sew() / 8;
	VSrc const src = rvv_src_of(i.funct3());
	bool const ei16 = i.funct6() == VF6_VRGATHEREI16;
	// vrgatherei16's index operand has a fixed EEW of 16, so its EMUL is (16/SEW)*LMUL and can
	// differ from the data group's.
	i32 const ilmul = ei16 ? lmul_log2 + 1 - (i32)__builtin_ctz(sew) : lmul_log2;
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV) {
		if (unlikely(!emul_in_range(ilmul) || !reg_group_legal(i.rs1(), ilmul))) {
			InsnNotImplemented(i, "rvv: vrgatherei16 illegal index EMUL");
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);
			return;
		}
		u32 const dg=emul_group_regs(lmul_log2), ig=emul_group_regs(ilmul);
		if (ei16 && sew!=2 && i.rs2()<i.rs1()+ig && i.rs1()<i.rs2()+dg) {
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);
			return;
		}
		if (unlikely(i.rd()<i.rs1()+ig && i.rs1()<i.rd()+dg)) {
			InsnNotImplemented(i, "rvv: vrgather vd must not overlap the index group");
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);
			return;
		}
	}
	if (!i.vm() && (i.rs2()==0 || (src==VSrc::VV && i.rs1()==0))) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	if (unlikely(group_overlaps(i.rd(), i.rs2(), lmul_log2))) {
		InsnNotImplemented(i, "rvv: vrgather vd must not overlap vs2");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	u64 const scalar = i.funct3() == 0b011 ? (u64)rvv_uimm5(i.raw) : (u64)s->gpr[i.rs1()];
	rvv_ref::vrgather(s->vec, i.rd(), i.rs2(), i.rs1(), src, scalar, ei16, i.vm(), vlen,
			  s->vec.vl, sew, compute_vlmax(vt, vlen));
	s->vec.vstart = 0;
}

// ---- fixed-point saturating add/subtract ------------------------------------------------------
HANDLER(vsatadd)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	if (!i.vm() && (i.rs2() == 0 || (src == VSrc::VV && i.rs1() == 0))) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vsatadd(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()],
			 rvv_simm5(i.raw), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// ---- fixed-point averaging (reads vxrm) --------------------------------------------------------
HANDLER(vavg)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	if (!i.vm() && (i.rs2() == 0 || (src == VSrc::VV && i.rs1() == 0))) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vavg(s->vec, i.funct6(), src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()],
		      rvv_simm5(i.raw), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// ---- widening integer add/sub/multiply/multiply-accumulate ---------------------------------------
// Widening must validate mixed-width overlaps, not just group alignment.
HANDLER(vwint)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	VSrc const src = rvv_src_of(i.funct3());
	u32 const f6 = i.funct6();
	if (unlikely(!vwint_form_supported(f6, src) ||
		!vwint_registers_legal(vt, f6, src, i.rd(), i.rs2(), i.rs1(), i.vm()))) {
		InsnNotImplemented(i, "rvv: widening integer illegal 2*SEW group");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vwint(s->vec, f6, src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()], i.vm(), vlen,
		       s->vec.vl, sew);
	s->vec.vstart = 0;
}

// ---- vsmul: fractional multiply (reads vxrm, sets vxsat) --------------------------------------
HANDLER(vsmul)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	if (!i.vm() && (i.rs2() == 0 || (src == VSrc::VV && i.rs1() == 0))) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vsmul(s->vec, src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()], i.vm(), vlen,
		       s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// ---- mask load / store: ceil(vl/8) bytes of ONE register, independent of SEW and LMUL ---------
HANDLER(vlm)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	rvv_ref::load_mask_reg(s->vec, i.rd(), vmem, s->gpr[i.rs1()], vlen, s->vec.vl);
	s->vec.vstart = 0;
}
HANDLER(vsm)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	rvv_ref::store_mask_reg(s->vec, i.rd(), vmem, s->gpr[i.rs1()], vlen, s->vec.vl);
	s->vec.vstart = 0;
}

// ---- vector FP widening arithmetic / FMA ------------------------------------------------------
HANDLER(vfwarith)
{
	// RESTARTABLE, not RUNNABLE: the reference below starts its loop at vstart and leaves the
	// prestart elements untouched, so a non-zero vstart is a legal execution here rather than an
	// illegal instruction. The stricter macro was refusing every vfwadd/vfwsub/vfwmul with
	// vstart != 0 -- an over-refusal, not an encoding rule; QEMU executes those.
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_FP_RM();
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	i32 const lmul_log2 = vt.lmul_log2();
	bool const is_vf = i.funct3() == 0b101;
	u32 const f6 = i.funct6();
	// 2*SEW must fit ELEN, and the register encoding must be one RVV 1.0 5.2 defines. The second
	// half is vfw_registers_legal, which is THIS FAMILY'S ONE COPY of 5.2 and is also what the
	// direct QCG route admits on -- a reserved encoding must not be executed by one path and
	// refused by the other, and having two spellings of the rule is how that happens.
	//
	// It replaces three separate tests that were each correct and together incomplete: the group
	// alignment of vd/vs2/vs1, the "a masked op may not write v0" rule, and nothing at all for the
	// overlap rules. The gap it closes is the one-register-one-source-EEW rule, under which
	// `vfwmacc.vv v8, v24, v9` is reserved (vd is read at 2*SEW and vs2 at SEW) while the same
	// shape as `vfwadd.vv v8, v9, v24` stays legal, because there vd is written and never read.
	if (unlikely(sew * 2 > ELEN_BITS / 8 ||
		     !vfw_registers_legal(f6, is_vf, lmul_log2, i.rd(), i.rs2(), i.rs1(), i.vm()))) {
		InsnNotImplemented(i, "rvv-fp: widening arithmetic reserved register encoding (5.2)");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vfwarith(s->vec, s->fpu, f6, is_vf, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen,
			  s->vec.vl, sew, s->vec.vstart);
	s->vec.vstart = 0;
}

HANDLER(vfwred)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_FP_RM();
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	RVV_REQUIRE_REDUCTION_REGS(vt, /*widening=*/true);
	rvv_ref::vfwred(s->vec, s->fpu, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen, s->vec.vl, sew);
	s->vec.vstart = 0;
}

// ---- carry / borrow ------------------------------------------------------------------------
// v0 is a carry operand, not a write mask. Only mask-result forms can write v0.
HANDLER(vadc)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	u32 const f6 = i.funct6();
	bool const carry_in = i.vm() == 0; // vm=0 selects the carry-in form, not "masked"
	bool const writes_mask = f6 == VF6_VMADC || f6 == VF6_VMSBC;
	u32 const regs = emul_group_regs(lmul_log2);
	if (writes_mask && ((i.rd() > i.rs2() && i.rd() < i.rs2() + regs) ||
	    (src == VSrc::VV && i.rd() > i.rs1() && i.rd() < i.rs1() + regs))) {
		InsnNotImplemented(i, "rvv: carry mask overlaps non-low source group");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (!writes_mask)
		RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	// vadc/vsbc write an element group; with a carry-in that group must not be v0, which is
	// simultaneously the carry source.
	if (unlikely(!writes_mask && carry_in && i.rd() == 0)) {
		InsnNotImplemented(i, "rvv: vadc/vsbc vd must not be v0 when v0 is the carry-in");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vadc(s->vec, f6, src, i.rd(), i.rs2(), i.rs1(), s->gpr[i.rs1()], rvv_simm5(i.raw),
		      carry_in, vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// ---- fixed-point scaling shift (reads vxrm) ---------------------------------------------------
HANDLER(vsshift)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	VSrc const src = rvv_src_of(i.funct3());
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (src == VSrc::VV)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	if (!i.vm() && (i.rs2() == 0 || (src == VSrc::VV && i.rs1() == 0))) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vsshift(s->vec, i.funct6() == VF6_VSSRA, src, i.rd(), i.rs2(), i.rs1(),
			 s->gpr[i.rs1()], rvv_uimm5(i.raw), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// ---- narrowing clip: 2*SEW source, rounds by vxrm, saturates into vxsat -----------------------
HANDLER(vnclip)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	VSrc const src = rvv_src_of(i.funct3());
	if (!narrow_registers_legal(vt, src, i.rd(), i.rs2(), i.rs1(), i.vm())) {
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vnclip(s->vec, i.funct6() == VF6_VNCLIP, src, i.rd(), i.rs2(), i.rs1(),
			s->gpr[i.rs1()], rvv_uimm5(i.raw), i.vm(), vlen, s->vec.vl, sew);
	s->vec.vstart = 0;
}

// ---- widening integer reduction: destination and scalar seed are 2*SEW ------------------------
HANDLER(vwred)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_REDUCTION_REGS(vt, /*widening=*/true);
	rvv_ref::vwred(s->vec, i.funct6() == VF6_VWREDSUM, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen,
		       s->vec.vl, sew);
	s->vec.vstart = 0;
}

// ---- vcpop.m / vfirst.m: read a mask, write a GPR ---------------------------------------------
HANDLER(vmaskpop)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	bool const is_first = i.rs1() == 0b10001;
	u32 const r = is_first ? (u32)rvv_ref::vfirst_m(s->vec, i.rs2(), i.vm(), s->vec.vl)
			       : rvv_ref::vcpop_m(s->vec, i.rs2(), i.vm(), s->vec.vl);
	if (i.rd())
		s->gpr[i.rd()] = r;
	s->vec.vstart = 0;
}

// ---- vmsbf / vmsof / vmsif / viota (VMUNARY0) --------------------------------------------------
HANDLER(vmunary)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	u32 const sub = i.rs1();
	i32 const lmul_log2 = vt.lmul_log2();
	if (sub == 0b10000) { // viota.m writes an element group at SEW
		RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
		RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
		// The source is a single mask register and the destination is a group; they must
		// not overlap, because the running count is read while the group is written.
		if (unlikely(i.rs2() >= i.rd() && i.rs2() < i.rd() + emul_group_regs(lmul_log2))) {
			InsnNotImplemented(i, "rvv: viota.m vd must not overlap the mask source");
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);
			return;
		}
		rvv_ref::viota(s->vec, i.rd(), i.rs2(), i.vm(), vlen, s->vec.vl, vt.sew() / 8);
	} else {
		// The set-before/only/including forms write a single mask register.
		if (unlikely(i.rd() == i.rs2() || (!i.vm() && i.rd() == 0))) {
			InsnNotImplemented(i, "rvv: mask prefix destination overlaps source or execution mask");
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);
			return;
		}
		rvv_ref::vmsetop(s->vec, sub, i.rd(), i.rs2(), i.vm(), s->vec.vl);
	}
	s->vec.vstart = 0;
}

// ---- vcompress.vm ------------------------------------------------------------------------------
HANDLER(vcompress)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	i32 const lmul_log2 = vt.lmul_log2();
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	// vd must not overlap vs2 or the selector: the write index runs behind the read index, so
	// an overlapping destination would consume elements it had already replaced.
	if (unlikely(group_overlaps(i.rd(), i.rs2(), lmul_log2) ||
		     (i.rs1() >= i.rd() && i.rs1() < i.rd() + emul_group_regs(lmul_log2)))) {
		InsnNotImplemented(i, "rvv: vcompress vd must not overlap vs2 or the selector");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vcompress(s->vec, i.rd(), i.rs2(), i.rs1(), vlen, s->vec.vl, vt.sew() / 8);
	s->vec.vstart = 0;
}

// ---- narrowing shifts: source is 2*SEW ----------------------------------------------------------
HANDLER(vnshift)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	VSrc const src = rvv_src_of(i.funct3());
	if (unlikely(!narrow_registers_legal(vt,src,i.rd(),i.rs2(),i.rs1(),i.vm()))) {
		InsnNotImplemented(i, "rvv: vnsrl/vnsra illegal 2*SEW source group");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vnshift(s->vec, i.funct6() == VF6_VNSRA, src, i.rd(), i.rs2(), i.rs1(),
			 s->gpr[i.rs1()], rvv_uimm5(i.raw), i.vm(), vlen, s->vec.vl, sew);
	s->vec.vstart = 0;
}

HANDLER(vfalu)
{
	// RESTARTABLE, not RUNNABLE: element-wise FP arithmetic is restartable and the reference
	// starts at vstart. The native route already handled vstart; this is the helper it falls
	// back to when RMM or the guard misses.
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_FP_RM();
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	i32 const lmul_log2 = vt.lmul_log2();
	bool const is_vf = i.funct3() == 0b101;
	// P15 candidate 7: this instruction's work may already have been done by its producer.
	if (unlikely(s->vec.fused_skip_valid) && gip == s->vec.fused_skip_pc &&
	    i.raw == s->vec.fused_skip_raw) {
		s->vec.fused_skip_valid = false;
		s->vec.vstart = 0;
		return;
	}
	// Handler-layer causal upper bound (2026-08-21 cycle, HANDLER_LAYER_OBSERVATION.md), Codex
	// point 3: DIAGNOSTIC ONLY, INCORRECT BY CONSTRUCTION IN GENERAL. Skips ONLY the
	// register-group/mask legality checks below -- vtype/vl decode above (RVV_REQUIRE_RUNNABLE_VTYPE,
	// sew, lmul_log2) and try_falu are unchanged. Valid ONLY on a corpus independently proven to
	// never trigger these checks: if `dbt::rv32::rvv_fast::g_fast.handler_legality_would_trap`
	// (kFastStats-gated, incremented from the ELSE branch below on a stats-enabled build) is ever
	// nonzero for a given run, this diagnostic's result for that run must be discarded -- it would
	// silently produce wrong behaviour (skip a real illegal-instruction trap) instead of a
	// performance difference. Never shipped, never a correctness or speedup claim by itself.
#ifdef RVDBT_DIAG_SKIP_HANDLER_LEGALITY
	if constexpr (rvv_fast::kFastStats) {
		bool const would_trap = (!i.vm() && i.rd() == 0) || !emul_in_range(lmul_log2) ||
					!reg_group_legal(i.rd(), lmul_log2) ||
					!reg_group_legal(i.rs2(), lmul_log2) ||
					(!is_vf && !reg_group_legal(i.rs1(), lmul_log2));
		if (unlikely(would_trap))
			rvv_fast::g_fast.handler_legality_would_trap++;
	}
#else
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (!is_vf)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
#endif
	// P15 candidate 7: OPFVV is 26.5 % of the corpus where OPIVV is 1.07 %, so this is where
	// the measured residency opportunity actually lives (raw/FUSE_CLASS_DIAGNOSIS.txt).
	if (dbt::config::rvv_fuse_pairs && dbt::config::rvv_fast && !is_vf) {
		if constexpr (rvv_fast::kFastStats)
			rvv_fast::g_fast.fuse_scan_attempted++;
		FusePlan const p = rvv_fusible_pair(vmem, gip, i.raw, /*OPFVV=*/1);
		if constexpr (rvv_fast::kFastStats)
			if (p.ok)
				rvv_fast::g_fast.fuse_scan_found++;
		if (p.ok && rvv_fast::try_falu_fused(s->vec, s->fpu, i.funct6(), p.f6_2, i.rd(),
						     i.rs2(), i.rs1(), p.op2_other, p.int_first,
						     vlen, s->vec.vl, sew, lmul_log2, p.pc2, vmem)) {
			s->vec.fused_skip_pc = p.pc2;
			s->vec.fused_skip_raw = *(u32 *)(vmem + p.pc2);
			s->vec.fused_skip_valid = true;
			s->vec.vstart = 0;
			return;
		}
	}
	if (!(dbt::config::rvv_fast &&
	      rvv_fast::try_falu(s->vec, s->fpu, i.funct6(), is_vf, i.rd(), i.rs2(), i.rs1(),
				 i.vm(), vlen, s->vec.vl, sew, lmul_log2, gip, vmem)))
		rvv_ref::vfalu(s->vec, s->fpu, i.funct6(), is_vf, i.rd(), i.rs2(), i.rs1(), i.vm(),
			       vlen, s->vec.vl, sew, s->vec.vstart);
	s->vec.vstart = 0;
}

HANDLER(vfma)
{
	// RESTARTABLE, not RUNNABLE: see HANDLER(vfalu).
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_FP_RM();
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	i32 const lmul_log2 = vt.lmul_log2();
	bool const is_vf = i.funct3() == 0b101;
	RVV_REQUIRE_MASK_NO_OVERLAP(i.rd(), i.vm(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rd(), lmul_log2);
	RVV_REQUIRE_LEGAL_GROUP(i.rs2(), lmul_log2);
	if (!is_vf)
		RVV_REQUIRE_LEGAL_GROUP(i.rs1(), lmul_log2);
	if (!(dbt::config::rvv_fast &&
	      rvv_fast::try_fma(s->vec, s->fpu, i.funct6(), is_vf, i.rd(), i.rs2(), i.rs1(),
				i.vm(), vlen, s->vec.vl, sew, lmul_log2, gip, vmem)))
		rvv_ref::vfma(s->vec, s->fpu, i.funct6(), is_vf, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen,
		      s->vec.vl, sew, s->vec.vstart);
	s->vec.vstart = 0;
}

HANDLER(vfcmp)
{
	// RESTARTABLE, not RUNNABLE: a compare is restartable and the reference starts at vstart.
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	i32 const lmul_log2 = vt.lmul_log2();
	bool const is_vf = i.funct3() == 0b101;
	// 5.2/5.3 for a mask destination, in the one shared predicate: a masked compare MAY write v0,
	// and vd may sit at a source group's FIRST register but nowhere else inside it. Source
	// alignment alone let the middle-of-group case through.
	if (unlikely(!mask_result_registers_legal(vt, i.rd(), i.rs2(), i.rs1(), is_vf))) {
		InsnNotImplemented(i, "rvv-fp: compare reserved mask-destination overlap (5.2)");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	if (!(dbt::config::rvv_fast &&
	      rvv_fast::try_vfcmp(s->vec, s->fpu, i.funct6(), is_vf, i.rd(), i.rs2(), i.rs1(),
				  i.vm(), vlen, s->vec.vl, sew, lmul_log2, gip, vmem)))
		rvv_ref::vfcmp(s->vec, s->fpu, i.funct6(), is_vf, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen,
			       s->vec.vl, sew, s->vec.vstart);
	s->vec.vstart = 0;
}

// Conversions. Widening doubles the DESTINATION width, narrowing doubles the SOURCE width, so
// the two sides have different EMUL and each must be checked against its own group.
HANDLER(vfcvt)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	u32 const sub = i.rs1(); // VFUNARY0 sub-encoding lives in the vs1 field
	// The EMULs the two sides use are derived inside convert_registers_legal from the width
	// relation below; only the element WIDTHS are needed here, for the FP-width checks and the
	// reference call.
	u32 ssew = sew, dsew = sew;
	if (vfcvt_is_widening(sub))
		dsew = sew * 2;
	else if (vfcvt_is_narrowing(sub))
		ssew = sew * 2;
	// The FP side of the conversion must be a legal FP width. For the integer<->float forms
	// only one side is FP, so check whichever that is.
	u32 const kind = sub & 0b111;
	bool const both_fp = kind == 0b100 || kind == 0b101;
	bool const dest_is_fp = (kind == 0b010 || kind == 0b011 || both_fp);
	RVV_REQUIRE_FP_SEW(dest_is_fp ? dsew : ssew);
	if (both_fp) RVV_REQUIRE_FP_SEW(ssew);
	// 5.2/5.3 in the one shared predicate, so a direct route and this fallback cannot disagree:
	// group alignment, the doubled width fitting ELEN, the masked form's v0 bar on BOTH the
	// destination and the data source, and the overlap rule each width relation allows.
	VConvWidth const conv_width = vfcvt_is_widening(sub)    ? VConvWidth::Widen
				      : vfcvt_is_narrowing(sub) ? VConvWidth::Narrow
								: VConvWidth::Same;
	if (unlikely(!convert_registers_legal(vt, conv_width, i.rd(), i.rs2(), i.vm()))) {
		InsnNotImplemented(i, "rvv-fp: conversion reserved register encoding (5.2/5.3)");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	// The .rtz forms carry their rounding mode in the opcode and never consult frm, so a
	// reserved frm does not make them illegal; every other form does consult it.
	// .rtz and .rod carry their rounding in the opcode and never consult frm, so a reserved
	// frm does not make them illegal.
	bool const rtz = sub == 0b00110 || sub == 0b00111 || sub == 0b01110 || sub == 0b01111 ||
			 sub == 0b10110 || sub == 0b10111 || sub == 0b10101;
	if (!rtz)
		RVV_REQUIRE_FP_RM();
	rvv_ref::vfcvt(s->vec, s->fpu, sub, i.rd(), i.rs2(), i.vm(), vlen, s->vec.vl, ssew, dsew);
	s->vec.vstart = 0;
}

HANDLER(vfunary1)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_FP_RM();
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	// 5.2/5.3 in the shared predicate: group alignment plus the masked form's v0 bar on BOTH the
	// destination and the source. The source half was missing -- v0 is read as the mask at EEW=1,
	// so it may not also be the SEW-wide data source.
	if (unlikely(!same_width_registers_legal(vt, i.rd(), i.rs2(), i.vm()))) {
		InsnNotImplemented(i, "rvv-fp: unary reserved register encoding (5.2/5.3)");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vfunary1(s->vec, s->fpu, i.rs1(), i.rd(), i.rs2(), i.vm(), vlen, s->vec.vl, sew);
	s->vec.vstart = 0;
}

HANDLER(vfred)
{
	RVV_REQUIRE_RUNNABLE_VTYPE(vt, vlen);
	RVV_REQUIRE_FP_RM();
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	RVV_REQUIRE_REDUCTION_REGS(vt, /*widening=*/false);
	rvv_ref::vfred(s->vec, s->fpu, i.funct6(), i.rd(), i.rs2(), i.rs1(), i.vm(), vlen,
		       s->vec.vl, sew);
	s->vec.vstart = 0;
}

HANDLER(vfmerge)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	// Merge reads v0 at EEW=1; its data source must not also read v0 at SEW.
	// The unmasked move encoding does not read vs2 at all.
	if (unlikely(i.vm() ? !reg_group_legal(i.rd(), vt.lmul_log2()) :
	             !same_width_registers_legal(vt, i.rd(), i.rs2(), false))) {
		InsnNotImplemented(i, "rvv: illegal vfmerge/vfmv register operands");
		RAISE_TRAP(TrapCode::ILLEGAL_INSN);
		return;
	}
	rvv_ref::vfmerge(s->vec, s->fpu, i.rd(), i.rs2(), i.rs1(), i.vm(), vlen, s->vec.vl, sew);
	s->vec.vstart = 0;
}

// vfmv.f.s: element 0 of vs2 into an F register (NaN-boxed for SEW=32).
HANDLER(vfmvfs)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	u64 const b = s->vec.elem_u(i.rs2(), 0, sew, vlen);
	s->fpu.f[i.rd()] = sew == 4 ? f32_box((u32)b) : b;
	s->vec.vstart = 0;
}

// vfmv.s.f: an F register into element 0 of vd. No-op when vl == 0.
HANDLER(vfmvsf)
{
	RVV_REQUIRE_RESTARTABLE_VTYPE(vt, vlen);
	u32 const sew = vt.sew() / 8;
	RVV_REQUIRE_FP_SEW(sew);
	if (s->vec.vstart < s->vec.vl) {
		u64 const b = sew == 4 ? (u64)f32_unbox(s->fpu.f[i.rs1()]) : s->fpu.f[i.rs1()];
		s->vec.elem_put(i.rd(), 0, sew, vlen, b);
	}
	s->vec.vstart = 0;
}

// ---- whole-register transfers -------------------------------------------------------------
// vtype-independent: these deliberately do NOT use RVV_REQUIRE_RUNNABLE_VTYPE. RVV 1.0 defines
// them to move whole registers irrespective of SEW/LMUL/vl, and to remain valid even when vill
// is set -- which is exactly why a compiler uses them for spills and LMUL regrouping. The only
// legality they carry is the NR-aligned register group, still enforced.
#define RVV_REQUIRE_WHOLE_GROUP(reg, nregs)                                                                  \
	do {                                                                                                 \
		if (unlikely(!whole_reg_group_legal(reg, nregs))) {                                          \
			InsnNotImplemented(i, "rvv: illegal whole-register group");                          \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                                  \
			return;                                                                              \
		}                                                                                            \
	} while (0)

HANDLER(vmvNr)
{
	u32 const vlen = dbt::config::vlen_bits;
	u32 const nregs = ((i.raw >> 15) & 0x1f) + 1; // vs1 field carries nr-1
	RVV_REQUIRE_WHOLE_GROUP(i.rd(), nregs);
	RVV_REQUIRE_WHOLE_GROUP(i.rs2(), nregs);
	rvv_ref::whole_reg_move(s->vec, i.rd(), i.rs2(), nregs, vlen);
	s->vec.vstart = 0;
}

// A14-RESTART: a nonzero vstart (reachable through `csrw vstart`, and the QCG frame's guard-miss
// arm sends every such execution here) starts the transfer at element vstart of the encoded EEW
// (8 for a store): elements [vstart, evl) are moved, the prefix is left alone in both the register
// group and memory, vstart >= evl moves nothing. vstart is cleared on completion either way.
HANDLER(vlNre)
{
	u32 const vlen = dbt::config::vlen_bits;
	u32 const nregs = ((i.raw >> 29) & 0x7) + 1;
	RVV_REQUIRE_WHOLE_GROUP(i.rd(), nregs);
	u32 const eew_bytes = 1u << (eew_log2_from_width(i.funct3()) - 3); // decoder admits 8/16/32/64
	u32 start_byte = 0;
	if (rvv_ref::whole_reg_start_byte(s->vec.vstart, eew_bytes, nregs, vlen, &start_byte))
		rvv_ref::whole_reg_load(s->vec, i.rd(), vmem, s->gpr[i.rs1()], nregs, vlen, start_byte);
	s->vec.vstart = 0;
}

HANDLER(vsNr)
{
	u32 const vlen = dbt::config::vlen_bits;
	u32 const nregs = ((i.raw >> 29) & 0x7) + 1;
	RVV_REQUIRE_WHOLE_GROUP(i.rd(), nregs); // rd field holds vs3 for stores
	u32 start_byte = 0; // the store's EEW is 8 (decoder pins width == 000)
	if (rvv_ref::whole_reg_start_byte(s->vec.vstart, 1u, nregs, vlen, &start_byte))
		rvv_ref::whole_reg_store(s->vec, i.rd(), vmem, s->gpr[i.rs1()], nregs, vlen, start_byte);
	s->vec.vstart = 0;
}

// ---------------------------------------------------------------------------------------------
// RV32F / RV32D scalar floating point.
//
// One handler covers the whole OP-FP major opcode, keyed by funct7 -- same discipline as the
// RVV families. IEEE arithmetic is done on the host FPU under the instruction's rounding mode,
// with accrued exceptions folded into fcsr.fflags; the RISC-V-specific parts (NaN boxing,
// canonical NaN, min/max NaN rules, saturating conversions, fclass) are explicit because the
// host does not implement them.
// ---------------------------------------------------------------------------------------------

// Resolve the instruction's rm field against fcsr.frm, trap if the effective mode is reserved,
// and bind `name` to the mode plus which engine must execute it. RMM has no host equivalent and
// is routed to the exact integer core in rv32_softfp.h rather than refused.
#define FP_MODE(name, rmfield)                                                                       \
	FpMode const name = fp_mode(s->fpu, (rmfield));                                              \
	do {                                                                                         \
		if (unlikely((name).path == FP_ILLEGAL)) {                                           \
			InsnNotImplemented(i, "fp: reserved rounding mode (rm=5,6 or frm=5,6,7)");    \
			RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                          \
			return;                                                                      \
		}                                                                                    \
	} while (0)

HANDLER(flw)
{
	u32 v = unaligned_load<u32>(vmem + (s->gpr[i.rs1()] + i.imm()));
	s->fpu.f[i.rd()] = f32_box(v); // NaN-box on load, per RV32D
}
HANDLER(fld) { s->fpu.f[i.rd()] = unaligned_load<u64>(vmem + (s->gpr[i.rs1()] + i.imm())); }
HANDLER(fsw)
{
	unaligned_store<u32>(vmem + (s->gpr[i.rs1()] + i.imm()), (u32)s->fpu.f[i.rs2()]);
}
HANDLER(fsd) { unaligned_store<u64>(vmem + (s->gpr[i.rs1()] + i.imm()), s->fpu.f[i.rs2()]); }

HANDLER(fpop)
{
#ifdef RVDBT_DIAG_SCALAR_FP_FREE
	// DIAGNOSTIC ONLY, INCORRECT BY CONSTRUCTION. Makes the scalar FP arithmetic handler a
	// no-op so the total headroom of the scalar-FP direction can be bounded before any method
	// is designed for it. N1 measured these stubs at 35.3% of pb_gemm at VLEN=1024. This build
	// computes wrong results and must never be shipped or used for a speedup claim; it exists
	// solely to answer "if scalar FP were free, would the VLEN1024 gap close?".
	return;
#endif
	u32 const raw = i.raw;
	u32 const fmt = fp_fmt(raw), op5 = fp_op5(raw), f3 = (raw >> 12) & 0x7;
	u32 const rs2f = (raw >> 20) & 0x1f;
	bool const dbl = fmt == 0b01;
	auto &fpu = s->fpu;

	// Operands. Single-precision reads go through the NaN-box check.
	u32 const a32 = f32_unbox(fpu.f[i.rs1()]), b32 = f32_unbox(fpu.f[i.rs2()]);
	u64 const a64 = fpu.f[i.rs1()], b64 = fpu.f[i.rs2()];

	switch (op5) {
	case FPOP_ADD:
	case FPOP_SUB:
	case FPOP_MUL:
	case FPOP_DIV: {
		FP_MODE(md, f3);
		if (md.path == FP_SOFT) {
			u32 fl = 0;
			auto const &F = dbl ? softfp::FMT64 : softfp::FMT32;
			u64 const x = dbl ? a64 : a32, y = dbl ? b64 : b32;
			u64 const z = op5 == FPOP_MUL ? softfp::op_mul(x, y, F, md.rm, fl)
						      : op5 == FPOP_DIV
							  ? softfp::op_div(x, y, F, md.rm, fl)
							  : softfp::op_add(x, y, op5 == FPOP_SUB, F,
									   md.rm, fl);
			fpu.f[i.rd()] = dbl ? z : f32_box((u32)z);
			fpu.raise(fl);
			return;
		}
		FRound r(fpu, md);
		if (dbl) {
			double const x = bits_to_f64(a64), y = bits_to_f64(b64);
			double z = op5 == FPOP_ADD ? x + y
						   : op5 == FPOP_SUB ? x - y
								     : op5 == FPOP_MUL ? x * y : x / y;
			fpu.f[i.rd()] = f64_canon(f64_to_bits(z));
		} else {
			float const x = bits_to_f32(a32), y = bits_to_f32(b32);
			float z = op5 == FPOP_ADD ? x + y
						  : op5 == FPOP_SUB ? x - y
								    : op5 == FPOP_MUL ? x * y : x / y;
			fpu.f[i.rd()] = f32_box(f32_canon(f32_to_bits(z)));
		}
		r.finish(fpu);
		return;
	}
	case FPOP_SQRT: {
		FP_MODE(md, f3);
		if (md.path == FP_SOFT) {
			u32 fl = 0;
			u64 const z = dbl ? softfp::op_sqrt(a64, softfp::FMT64, md.rm, fl)
					  : softfp::op_sqrt(a32, softfp::FMT32, md.rm, fl);
			fpu.f[i.rd()] = dbl ? z : f32_box((u32)z);
			fpu.raise(fl);
			return;
		}
		FRound r(fpu, md);
		if (dbl)
			fpu.f[i.rd()] = f64_canon(f64_to_bits(std::sqrt(bits_to_f64(a64))));
		else
			fpu.f[i.rd()] = f32_box(f32_canon(f32_to_bits(std::sqrt(bits_to_f32(a32)))));
		r.finish(fpu);
		return;
	}
	case FPOP_SGNJ: {
		// Sign injection is BIT manipulation, not arithmetic: it never raises a flag and
		// never canonicalises a NaN.
		if (dbl) {
			u64 const sa = a64 & ~(1ull << 63);
			u64 sign = f3 == 0b000 ? (b64 & (1ull << 63))
					       : f3 == 0b001 ? (~b64 & (1ull << 63))
							     : ((a64 ^ b64) & (1ull << 63));
			fpu.f[i.rd()] = sa | sign;
		} else {
			u32 const sa = a32 & 0x7fffffffu;
			u32 sign = f3 == 0b000 ? (b32 & 0x80000000u)
					       : f3 == 0b001 ? (~b32 & 0x80000000u)
							     : ((a32 ^ b32) & 0x80000000u);
			fpu.f[i.rd()] = f32_box(sa | sign);
		}
		return;
	}
	case FPOP_MINMAX: {
		bool const is_max = f3 == 0b001;
		if (dbl)
			fpu.f[i.rd()] = f64_minmax(fpu, a64, b64, is_max);
		else
			fpu.f[i.rd()] = f32_box(f32_minmax(fpu, a32, b32, is_max));
		return;
	}
	case FPOP_CMP: {
		// feq is a QUIET comparison (signalling NaN only); flt/fle are signalling
		// (any NaN raises NV). Result goes to a GPR.
		bool res = false;
		if (dbl) {
			double const x = bits_to_f64(a64), y = bits_to_f64(b64);
			bool const nan = std::isnan(x) || std::isnan(y);
			if (f3 == 0b010) { // feq
				if (f64_is_snan(a64) || f64_is_snan(b64))
					fpu.raise(FFLAG_NV);
				res = !nan && x == y;
			} else {
				if (nan)
					fpu.raise(FFLAG_NV);
				res = !nan && (f3 == 0b001 ? x < y : x <= y);
			}
		} else {
			float const x = bits_to_f32(a32), y = bits_to_f32(b32);
			bool const nan = std::isnan(x) || std::isnan(y);
			if (f3 == 0b010) {
				if (f32_is_snan(a32) || f32_is_snan(b32))
					fpu.raise(FFLAG_NV);
				res = !nan && x == y;
			} else {
				if (nan)
					fpu.raise(FFLAG_NV);
				res = !nan && (f3 == 0b001 ? x < y : x <= y);
			}
		}
		if (i.rd())
			s->gpr[i.rd()] = res ? 1 : 0;
		return;
	}
	case FPOP_CVT_F_F: {
		FP_MODE(md, f3);
		if (md.path == FP_SOFT) {
			u32 fl = 0;
			if (dbl) {
				fpu.f[i.rd()] = softfp::cvt_fmt(a32, softfp::FMT32, softfp::FMT64,
								md.rm, fl);
			} else {
				u64 const z = softfp::cvt_fmt(a64, softfp::FMT64, softfp::FMT32,
							      md.rm, fl);
				fpu.f[i.rd()] = f32_box((u32)z);
			}
			fpu.raise(fl);
			return;
		}
		FRound r(fpu, md);
		if (dbl) { // fcvt.d.s : widening, exact
			fpu.f[i.rd()] = f64_canon(f64_to_bits((double)bits_to_f32(a32)));
		} else { // fcvt.s.d : narrowing, rounds
			fpu.f[i.rd()] = f32_box(f32_canon(f32_to_bits((float)bits_to_f64(a64))));
		}
		r.finish(fpu);
		return;
	}
	case FPOP_CVT_I_F: { // float -> integer, saturating
		FP_MODE(md, f3);
		bool const is_signed = rs2f == 0;
		if (md.path == FP_SOFT) {
			u32 fl = 0;
			u32 const out = dbl ? softfp::cvt_to_int(a64, is_signed, softfp::FMT64,
								 md.rm, fl)
					    : softfp::cvt_to_int(a32, is_signed, softfp::FMT32,
								 md.rm, fl);
			fpu.raise(fl);
			if (i.rd())
				s->gpr[i.rd()] = out;
			return;
		}
		FRound r(fpu, md);
		double v;
		bool nan;
		if (dbl) {
			v = bits_to_f64(a64);
			nan = std::isnan(v);
		} else {
			float const fv = bits_to_f32(a32);
			v = (double)fv;
			nan = std::isnan(fv);
		}
		// float_to_int does the rounding itself: it needs the unrounded operand to decide
		// the inexact flag, and rounding here would throw that information away.
		u32 const out = float_to_int<i32, u32>(fpu, v, is_signed, nan);
		r.finish(fpu);
		if (i.rd())
			s->gpr[i.rd()] = out;
		return;
	}
	case FPOP_CVT_F_I: { // integer -> float
		FP_MODE(md, f3);
		bool const is_signed = rs2f == 0;
		u32 const x = s->gpr[i.rs1()];
		if (md.path == FP_SOFT) {
			u32 fl = 0;
			bool const neg = is_signed && (i32)x < 0;
			u64 const mag = neg ? (u64)(-(i64)(i32)x) : (u64)x;
			u64 const z = softfp::cvt_from_int(mag, neg,
							   dbl ? softfp::FMT64 : softfp::FMT32,
							   md.rm, fl);
			fpu.f[i.rd()] = dbl ? z : f32_box((u32)z);
			fpu.raise(fl);
			return;
		}
		FRound r(fpu, md);
		if (dbl)
			fpu.f[i.rd()] =
			    f64_to_bits(is_signed ? (double)(i32)x : (double)(u32)x);
		else
			fpu.f[i.rd()] =
			    f32_box(f32_to_bits(is_signed ? (float)(i32)x : (float)(u32)x));
		r.finish(fpu);
		return;
	}
	case FPOP_MV_X_F: {
		if (f3 == 0b000) { // fmv.x.w: raw bits, no boxing check, no flags
			if (i.rd())
				s->gpr[i.rd()] = (u32)fpu.f[i.rs1()];
		} else { // fclass
			u32 const c = dbl ? f64_classify(a64) : f32_classify(a32);
			if (i.rd())
				s->gpr[i.rd()] = c;
		}
		return;
	}
	default: // FPOP_MV_F_X -- fmv.w.x
		fpu.f[i.rd()] = f32_box(s->gpr[i.rs1()]);
		return;
	}
}

// Fused multiply-add. The product is NOT rounded before the add -- that is the whole point of
// the instruction -- so std::fma is used rather than a*b+c.
#define FMA_HANDLER(name, expr_d, expr_f, negp, negc)                                                 \
	HANDLER(name)                                                                                        \
	{                                                                                                    \
		auto &fpu = s->fpu;                                                                          \
		u32 const f3 = (i.raw >> 12) & 0x7;                                                          \
		u32 const rs3 = (i.raw >> 27) & 0x1f;                                                        \
		FP_MODE(md, f3);                                                                             \
		bool const md_dbl = fp_fmt(i.raw) == 0b01;                                                   \
		if (md.path == FP_SOFT) {                                                                    \
			u32 fl = 0;                                                                          \
			u64 const z =                                                                        \
			    md_dbl ? softfp::op_fma(fpu.f[i.rs1()], fpu.f[i.rs2()], fpu.f[rs3], (negp),      \
						    (negc), softfp::FMT64, md.rm, fl)                        \
				   : softfp::op_fma(f32_unbox(fpu.f[i.rs1()]),                               \
						    f32_unbox(fpu.f[i.rs2()]), f32_unbox(fpu.f[rs3]),        \
						    (negp), (negc), softfp::FMT32, md.rm, fl);               \
			fpu.f[i.rd()] = md_dbl ? z : f32_box((u32)z);                                        \
			fpu.raise(fl);                                                                       \
			return;                                                                              \
		}                                                                                            \
		FRound r(fpu, md);                                                                        \
		if (md_dbl) {                                                                                \
			double const a = bits_to_f64(fpu.f[i.rs1()]), b = bits_to_f64(fpu.f[i.rs2()]),       \
				     c = bits_to_f64(fpu.f[rs3]);                                            \
			fpu.f[i.rd()] = f64_canon(f64_to_bits(expr_d));                                      \
		} else {                                                                                     \
			float const a = bits_to_f32(f32_unbox(fpu.f[i.rs1()])),                              \
				    b = bits_to_f32(f32_unbox(fpu.f[i.rs2()])),                              \
				    c = bits_to_f32(f32_unbox(fpu.f[rs3]));                                  \
			fpu.f[i.rd()] = f32_box(f32_canon(f32_to_bits(expr_f)));                             \
		}                                                                                            \
		r.finish(fpu);                                                                               \
	}

// negate-product / negate-addend follow the RISC-V definitions:
//   fmadd = ab+c   fmsub = ab-c   fnmsub = -(ab)+c   fnmadd = -(ab)-c
FMA_HANDLER(fmadd, std::fma(a, b, c), std::fmaf(a, b, c), false, false)
FMA_HANDLER(fmsub, std::fma(a, b, -c), std::fmaf(a, b, -c), false, true)
FMA_HANDLER(fnmsub, std::fma(-a, b, c), std::fmaf(-a, b, c), true, false)
FMA_HANDLER(fnmadd, std::fma(-a, b, -c), std::fmaf(-a, b, -c), true, true)

HANDLER(ebreak)
{
	RAISE_TRAP(TrapCode::EBREAK);
	RaiseTrap();
}

// TODO: real atomics implementation, alignment checks
template <typename H>
static ALWAYS_INLINE void ApplyInsnA(CPUState *s, u8 *vmem, insn::A i)
{
	switch (i.rlaq()) {
	case 0b00:
		H().template operator()<std::memory_order_relaxed>(s, vmem, i);
		break;
	case 0b01:
		H().template operator()<std::memory_order_release>(s, vmem, i);
		break;
	case 0b10:
		H().template operator()<std::memory_order_acquire>(s, vmem, i);
		break;
	case 0b11:
		H().template operator()<std::memory_order_acq_rel>(s, vmem, i);
		break;
	default:
		unreachable("");
	}
}

HANDLER(lrw)
{
	// TODO: start transaction
	auto h = []<std::memory_order MO>(CPUState *s, u8 *vmem, insn::A i) {
		auto a = std::atomic_ref(*(u32 *)(vmem + s->gpr[i.rs1()]));
		u32 const v = a.load(MO);
		if (i.rd() != 0) // A10: x0 is hardwired zero; the A-class ops carry no HasRd flag, so
			s->gpr[i.rd()] = v; // nothing else would re-zero the slot after this write
	};
	ApplyInsnA<decltype(h)>(s, vmem, i);
}
HANDLER(scw)
{
	auto h = []<std::memory_order MO>(CPUState *s, u8 *vmem, insn::A i) {
		auto a = std::atomic_ref(*(u32 *)(vmem + s->gpr[i.rs1()]));
		a.store(s->gpr[i.rs2()], MO);
		if (i.rd() != 0) s->gpr[i.rd()] = 0; // A10: sc.w with rd == x0
	};
	ApplyInsnA<decltype(h)>(s, vmem, i);
}
HANDLER(amoswapw)
{
	auto h = []<std::memory_order MO>(CPUState *s, u8 *vmem, insn::A i) {
		auto a = std::atomic_ref(*(u32 *)(vmem + s->gpr[i.rs1()]));
		{ u32 const v = a.exchange(s->gpr[i.rs2()], MO); if (i.rd() != 0) s->gpr[i.rd()] = v; } // A10: rd == x0 discards the old value
	};
	ApplyInsnA<decltype(h)>(s, vmem, i);
}
HANDLER(amoaddw)
{
	auto h = []<std::memory_order MO>(CPUState *s, u8 *vmem, insn::A i) {
		auto a = std::atomic_ref(*(u32 *)(vmem + s->gpr[i.rs1()]));
		{ u32 const v = a.fetch_add(s->gpr[i.rs2()], MO); if (i.rd() != 0) s->gpr[i.rd()] = v; } // A10: rd == x0 discards the old value
	};
	ApplyInsnA<decltype(h)>(s, vmem, i);
}
HANDLER_Unimpl(amoxorw);
HANDLER_Unimpl(amoandw);
HANDLER_Unimpl(amoorw);
HANDLER_Unimpl(amominw);
HANDLER_Unimpl(amomaxw);
HANDLER_Unimpl(amominuw);
HANDLER(amomaxuw)
{
	auto h = []<std::memory_order MO>(CPUState *s, u8 *vmem, insn::A i) {
		auto a = std::atomic_ref(*(u32 *)(vmem + s->gpr[i.rs1()]));
		u32 cur = a.load(MO);
		u32 rhs = s->gpr[i.rs2()];
		while (!a.compare_exchange_weak(cur, std::max(cur, rhs), MO))
			;
	};
	ApplyInsnA<decltype(h)>(s, vmem, i);
}

HANDLER(mul)
{
	// Lower 32 bits of signed multiplication
	s->gpr[i.rd()] = (u32)((i64)s->gpr[i.rs1()] * (i64)s->gpr[i.rs2()]);

}
HANDLER(mulh)
{
	// Upper 32 bits of signed × signed
	// althought the s->gpr is u32, the value it store maybe negative, so we need to cast it to signed int32 first
	s->gpr[i.rd()] = (u32)(((i64)(i32)s->gpr[i.rs1()] * (i64)(i32)s->gpr[i.rs2()]) >> 32);
}
HANDLER(mulhsu)
{
	// Upper 32 bits of signed × unsigned
	s->gpr[i.rd()] = (u32)(((i64)(i32)s->gpr[i.rs1()] * s->gpr[i.rs2()]) >> 32);
}
HANDLER(mulhu)
{
	// Upper 32 bits of unsigned × unsigned
	s->gpr[i.rd()] = (u32)(((u64)s->gpr[i.rs1()] * (u64)s->gpr[i.rs2()]) >> 32);
}
HANDLER(div) 
{
	if (s->gpr[i.rs2()] == 0) {
		s->gpr[i.rd()] = 0xFFFFFFFF;  // Division by zero
	} else if ((i32)s->gpr[i.rs1()] == INT32_MIN && (i32)s->gpr[i.rs2()] == -1) {
		s->gpr[i.rd()] = INT32_MIN;   // Overflow case
	} else {
		s->gpr[i.rd()] = (i32)s->gpr[i.rs1()] / (i32)s->gpr[i.rs2()];
	}
}
HANDLER(divu)
{
	if (s->gpr[i.rs2()] == 0) {
		s->gpr[i.rd()] = 0xFFFFFFFF;
	} else {
		s->gpr[i.rd()] = s->gpr[i.rs1()] / s->gpr[i.rs2()];
	}
}
HANDLER(rem)
{
	if (s->gpr[i.rs2()] == 0) {
		s->gpr[i.rd()] = s->gpr[i.rs1()];  // Return dividend if divisor is zero
	} else if ((i32)s->gpr[i.rs1()] == INT32_MIN && (i32)s->gpr[i.rs2()] == -1) {
		s->gpr[i.rd()] = 0;   // Overflow case
	} else {
		s->gpr[i.rd()] = (i32)s->gpr[i.rs1()] % (i32)s->gpr[i.rs2()];
	}
}
HANDLER(remu)
{
	if (s->gpr[i.rs2()] == 0) {
		s->gpr[i.rd()] = s->gpr[i.rs1()];  // Return dividend if divisor is zero
	} else {
		s->gpr[i.rd()] = (u32)s->gpr[i.rs1()] % (u32)s->gpr[i.rs2()];
	}
}
// ---------------------------------------------------------------------------------------------
// RVV vector CSRs (vstart/vl/vtype/vlenb).
//
// Without this interception the generic `s->csr[]` array answers 0 for all four. `csrr a0,
// vlenb` is the standard way a strip-mined RVV kernel discovers the machine width, so answering
// 0 is a SILENT WRONG ANSWER -- exactly the fail-open class this substrate must not have. The
// architectural state lives in `s->vec`; vl/vtype/vlenb are read-only (writing them is an
// illegal instruction), vstart is read/write.
// ---------------------------------------------------------------------------------------------
// RV32F/D CSRs. Without these the guest's reads and writes of fflags/frm/fcsr hit rvdbt's
// generic csr[] array and NEVER reach FPUState -- so `fesetround`-style code and any program
// that inspects accrued exceptions would silently see zeros while the real state lived
// elsewhere. That is a silent-wrong-answer path, not a missing feature.
static constexpr u16 CSR_FFLAGS = 0x001;
static constexpr u16 CSR_FRM = 0x002;
static constexpr u16 CSR_FCSR = 0x003;

static constexpr u16 CSR_VSTART = 0x008;
// The fixed-point CSRs. vcsr is the packed view: {vxrm[2:1], vxsat[0]}. These are WRITABLE by the
// guest, unlike vl/vtype/vlenb, and vxrm is a real input to the averaging/scaling/clipping
// families -- leaving them on the generic CSR array makes every such instruction silently use
// rounding mode 0 no matter what the guest asked for.
static constexpr u16 CSR_VXSAT = 0x009;
static constexpr u16 CSR_VXRM = 0x00a;
static constexpr u16 CSR_VCSR = 0x00f;
static constexpr u16 CSR_VL = 0xc20;
static constexpr u16 CSR_VTYPE = 0xc21;
static constexpr u16 CSR_VLENB = 0xc22;

static ALWAYS_INLINE bool rvv_csr_is_vector(u16 a)
{
	return a == CSR_VSTART || a == CSR_VL || a == CSR_VTYPE || a == CSR_VLENB ||
	       a == CSR_VXSAT || a == CSR_VXRM || a == CSR_VCSR;
}
// vl, vtype and vlenb are read-only; vstart and the fixed-point CSRs are writable.
static ALWAYS_INLINE bool rvv_csr_writable(u16 a)
{
	return a == CSR_VSTART || a == CSR_VXSAT || a == CSR_VXRM || a == CSR_VCSR;
}
static ALWAYS_INLINE bool fp_csr_is_fp(u16 a)
{
	return a == CSR_FFLAGS || a == CSR_FRM || a == CSR_FCSR;
}
// fflags is fcsr[4:0], frm is fcsr[7:5], fcsr is the whole 8 bits. All three are views of the
// SAME architectural register, which is why they are handled together.
// An open fround run holds the guest's accumulated exception bits in MXCSR and the guest's
// rounding mode in MXCSR.RC, neither of which is visible in `fcsr` until the run is closed. Any
// read or write of fflags/frm/fcsr is therefore an OBSERVER of the bracketed state and must force
// the run closed first -- harvesting the flags into `fcsr` and restoring MXCSR -- or the guest
// sees stale flags. TB-exit closing is NOT sufficient: an FP op followed by `csrr a0, fflags`
// inside the same translated block never reaches a TB exit in between.
// One helper, no second copy of the flag mapping.
ALWAYS_INLINE void CloseFroundRunBeforeFcsrAccess(FPUState &fpu)
{
#ifdef RVDBT_FAULT_INJECT_NO_CSR_CLOSE
	// Deliberately skip the close, to demonstrate that the directed oracle in
	// src/fp_mode_oracle.c actually detects a missing close rather than passing vacuously.
	// Never defined in a shipped build; see docs/SEMANTIC_ORACLE.md for the recorded result.
	(void)fpu; return;
#endif
	if (unlikely(fpu.fround_run_open)) {
		fpu.sc_close_csr++;
		rvv_fast::fround_run_force_close(fpu);
	}
}

static ALWAYS_INLINE u32 fp_csr_read(CPUState *s, u16 a)
{
	CloseFroundRunBeforeFcsrAccess(s->fpu);
	switch (a) {
	case CSR_FFLAGS:
		return s->fpu.fflags();
	case CSR_FRM:
		return s->fpu.frm();
	default:
		return s->fpu.fcsr & 0xff;
	}
}
static ALWAYS_INLINE void fp_csr_write(CPUState *s, u16 a, u32 v)
{
	CloseFroundRunBeforeFcsrAccess(s->fpu);
	switch (a) {
	case CSR_FFLAGS:
		s->fpu.set_fflags(v & 0x1f);
		break;
	case CSR_FRM:
		// frm is WARL. A reserved value (5..7) is architecturally storable; what it makes
		// illegal is a LATER FP op that uses the dynamic rounding mode, which FRound
		// reports and the handlers turn into an illegal-instruction trap.
		s->fpu.set_frm(v & 0x7);
		break;
	default:
		s->fpu.fcsr = v & 0xff;
		break;
	}
}
static ALWAYS_INLINE u32 rvv_csr_read(CPUState *s, u16 a)
{
	switch (a) {
	case CSR_VSTART:
		return s->vec.vstart;
	case CSR_VL:
		return s->vec.vl;
	case CSR_VTYPE:
		return s->vec.vtype;
	case CSR_VXSAT:
		return s->vec.vxsat & 1;
	case CSR_VXRM:
		return s->vec.vxrm & 3;
	case CSR_VCSR:
		return ((s->vec.vxrm & 3) << 1) | (s->vec.vxsat & 1);
	default:
		return s->vec.vlenb;
	}
}
static ALWAYS_INLINE void rvv_csr_write(CPUState *s, u16 a, u32 v)
{
	switch (a) {
	case CSR_VSTART:
		// A14-RESTART. RVV 1.0 3.7: vstart has only enough writable bits to hold the largest
		// element index, i.e. log2(VLEN) bits for the maximum VLMAX (e8, m8); a wider write
		// wraps. QEMU 11.1.0 does the same (vstart_bits = log2(VLEN)), and the whole-register
		// oracle's `vstart == evl` row for nf 8 / EEW 8 (vstart == VLEN) is only reproducible
		// with this mask.
		s->vec.vstart = v & (dbt::config::vlen_bits - 1u);
		break;
	case CSR_VXSAT:
		s->vec.vxsat = v & 1;
		break;
	case CSR_VXRM:
		s->vec.vxrm = v & 3;
		break;
	default: // CSR_VCSR
		s->vec.vxsat = v & 1;
		s->vec.vxrm = (v >> 1) & 3;
		break;
	}
}

// Shared prologue for the six Zicsr handlers.
//
// Takes the OPERATION KIND rather than a precomputed value: csrrs/csrrc must OR/AND-NOT against
// the CSR's own current value, and an earlier version computed that from the vector accessor,
// which silently gave the wrong result once the FP CSRs joined the same path.
//
// `do_write` follows the architectural rule that csrrs/csrrc with a zero source do not write.
// An attempted write to a read-only vector CSR raises illegal-instruction BEFORE any state
// changes, so the access is side-effect free.
// A10-review. ONE ORDER FOR EVERY Zicsr FORM, stated once:
//   1. src  := the SOURCE OPERAND, snapshotted BEFORE anything is written (x[rs1] or uimm);
//   2. old  := the CSR's current value;
//   3. write the CSR (when the form writes) from (old, src);
//   4. write rd := old, only when rd != x0.
// Reading the source first is what makes rd == rs1 correct (`csrrs t1, fflags, t1` must OR the
// ORIGINAL t1, not the old CSR that was just written into t1); writing rd last and guarding x0 is
// what keeps x0's slot at zero (Zicsr ops carry no HasRd flag). The CSR side effect never depends
// on rd, and the read-only forms (rs1 == x0 / uimm == 0 for csrrs/csrrc) never write the CSR.
#define CSR_APPLY(kind, oldv, opnd) ((kind) == 'W' ? (opnd) : (kind) == 'S' ? ((oldv) | (opnd)) : ((oldv) & ~(opnd)))
#define RVV_CSR_INTERCEPT(csr_addr, kind, src, do_write, write_rd)                                           \
	do {                                                                                                 \
		if (unlikely(fp_csr_is_fp(csr_addr))) {                                                      \
			u32 const _old = fp_csr_read(s, csr_addr);                                           \
			if (do_write)                                                                        \
				fp_csr_write(s, csr_addr, CSR_APPLY(kind, _old, (src)));                     \
			if (write_rd)                                                                        \
				s->gpr[i.rd()] = _old;                                                       \
			return;                                                                              \
		}                                                                                            \
		if (unlikely(rvv_csr_is_vector(csr_addr))) {                                                 \
			bool const _w = (do_write);                                                          \
			if (unlikely(_w && !rvv_csr_writable(csr_addr))) {                                   \
				InsnNotImplemented(i, "rvv: write to read-only vector CSR");                 \
				RAISE_TRAP(TrapCode::ILLEGAL_INSN);                                          \
				return;                                                                      \
			}                                                                                    \
			u32 const _old = rvv_csr_read(s, csr_addr);                                          \
			if (_w)                                                                              \
				rvv_csr_write(s, csr_addr, CSR_APPLY(kind, _old, (src)));                    \
			if (write_rd)                                                                        \
				s->gpr[i.rd()] = _old;                                                       \
			return;                                                                              \
		}                                                                                            \
	} while (0)
// The plain (non-FP, non-vector) CSR array follows the same four steps.
#define CSR_PLAIN(kind, src, do_write)                                                                       \
	do {                                                                                                 \
		u32 const _old = s->csr[csr_addr];                                                           \
		if (do_write)                                                                                \
			s->csr[csr_addr] = CSR_APPLY(kind, _old, (src));                                     \
		if (i.rd() != 0)                                                                             \
			s->gpr[i.rd()] = _old;                                                               \
	} while (0)

HANDLER(csrrw)
{
	u16 const csr_addr = i.csr();
	u32 const src = s->gpr[i.rs1()]; // step 1: snapshot the source before any write
	RVV_CSR_INTERCEPT(csr_addr, 'W', src, true, i.rd() != 0);
	CSR_PLAIN('W', src, true);
}
HANDLER(csrrs)
{
	u16 const csr_addr = i.csr();
	u32 const src = s->gpr[i.rs1()];
	bool const w = i.rs1() != 0; // rs1 == x0: read-only, no write side effect
	RVV_CSR_INTERCEPT(csr_addr, 'S', src, w, i.rd() != 0);
	CSR_PLAIN('S', src, w);
}
HANDLER(csrrc)
{
	u16 const csr_addr = i.csr();
	u32 const src = s->gpr[i.rs1()];
	bool const w = i.rs1() != 0;
	RVV_CSR_INTERCEPT(csr_addr, 'C', src, w, i.rd() != 0);
	CSR_PLAIN('C', src, w);
}
HANDLER(csrrwi)
{
	u16 const csr_addr = i.csr();
	u32 const src = i.zimm(); // rs1 field is the immediate
	RVV_CSR_INTERCEPT(csr_addr, 'W', src, true, i.rd() != 0);
	CSR_PLAIN('W', src, true);
}
HANDLER(csrrsi)
{
	u16 const csr_addr = i.csr();
	u32 const src = i.zimm();
	bool const w = src != 0; // uimm == 0: read-only
	RVV_CSR_INTERCEPT(csr_addr, 'S', src, w, i.rd() != 0);
	CSR_PLAIN('S', src, w);
}
HANDLER(csrrci)
{
	u16 const csr_addr = i.csr();
	u32 const src = i.zimm();
	bool const w = src != 0;
	RVV_CSR_INTERCEPT(csr_addr, 'C', src, w, i.rd() != 0);
	CSR_PLAIN('C', src, w);
}

HANDLER(mret)
{
	// TODO: real mret implementation
}

void Interpreter::Execute(CPUState *state)
{
	u8 *vmem = mmu::base;
	u32 gip = state->ip;
	void *insn_ptr;

#ifdef DBT_DUMP_TRACE
entry:
	u32 icount = 0;
	state->ip = gip;
	state->DumpTrace("entry");
#define XDUMP(name)                                                                                          \
	do {                                                                                                 \
		if (++icount == TB_MAX_INSNS || !(gip & ~mmu::PAGE_MASK) ||                                  \
		    (insn::Insn_##name::flags & insn::Flags::Branch))                                        \
			goto entry;                                                                          \
	} while (0)
#else
#define XDUMP(name)
#endif

#ifdef DBT_DUMP_TRACE_VERBOSE
#define TRACE_INSN()                                                                                         \
	state->ip = gip;                                                                                     \
	state->DumpTrace("insn")
#else
#define TRACE_INSN()
#endif

	goto dispatch;

	static constexpr void *loc_gotos[] = {
#define OP(name, format_, flags_) [(u8)insn::Op::_##name] = &&Lab_##name,
	    RV32_OPCODE_LIST()
#undef OP
	};
#define OP(name, format_, flags_)                                                                            \
	Lab_##name:                                                                                          \
	{                                                                                                    \
		TRACE_INSN();                                                                                \
		H_##name(state, gip, vmem, *(u32 *)insn_ptr);                                                \
		XDUMP(name);                                                                                 \
		goto dispatch;                                                                               \
	}
	RV32_OPCODE_LIST()
#undef OP

dispatch:
	//
	{
		insn_ptr = vmem + gip;
		using decoder = insn::Decoder<insn::Op>;
		goto *loc_gotos[(u8)decoder::Decode(insn_ptr)];
	}
}

// Codex 4th review P1 (scenario d): `FroundRunGuard` (rv32_vector_fast.h) closes an inherited-
// but-abandoned rounding run on every refusal path INSIDE try_falu/try_fma/try_vfcmp, but it
// cannot help if the block ends -- instruction-count cap, page crossing, or a branch -- before the
// predicted-continuing instruction is ever dispatched at all. FPUState (and its fround_run_* pair)
// is persistent guest architectural state that survives a TB boundary correctly BY ITSELF when the
// very next dispatch really is the predicted instruction (the common case) -- but nothing may run
// on the host stack between one TB ending and the next one starting (JIT compilation of a hot
// block, the P1/A-line/web-repack/AOT-boot housekeeping `execute.cpp`'s main loop performs between
// blocks, a signal) without first harvesting/restoring, since none of that code is aware this
// bracket exists. Force-closing here makes the invariant hold at every TB exit unconditionally,
// not just the common case, at the cost of a redundant reopen if the predicted continuation really
// does run next -- the same safe-by-construction trade `FroundRunGuard` itself makes.
#ifdef RVDBT_CHECK_TBEXIT_MXCSR
extern "C" unsigned long long g_tbexit_mxcsr_violations;
#endif
ALWAYS_INLINE void TbExitCloseOpenFroundRun(FPUState &fpu)
{
#ifdef RVDBT_CHECK_TBEXIT_MXCSR
	// Directed check for the TB-exit boundary. The bracket is not guest-observable here -- any
	// guest read of fflags goes through the CSR close first -- so a guest-output oracle cannot
	// detect a missing TB-exit close. What it protects is HOST state: leaving MXCSR holding the
	// guest rounding mode across a block boundary means the JIT, AOT housekeeping and any host
	// FP between blocks run under the wrong mode. That invariant is checked here directly.
	{
		unsigned const rc = rvdbt_mxcsr_get() & 0x6000u;
		if (fpu.fround_run_open || rc != (dbt::config::g_mxcsr_resting & 0x6000u))
			g_tbexit_mxcsr_violations++;
	}
#endif
#ifdef RVDBT_FAULT_INJECT_NO_TBEXIT_CLOSE
	// Deliberately skip the TB-exit close, to demonstrate that the trap/branch/loop cases in
	// src/fp_mode_oracle.c actually detect its absence. Never defined in a shipped build.
	return;
#endif
	if (unlikely(fpu.fround_run_open)) {
		if constexpr (rvv_fast::kFastStats)
			rvv_fast::g_fast.fround_run_tb_exit_open++;
		fpu.sc_close_tbexit++;
		rvv_fast::fround_run_force_close(fpu);
	}
	assert(!fpu.fround_run_open);
}

// 2026-06-16 tier-0 lazy translation: interpret exactly ONE dynamic basic block then return. Boundary == JIT TB
// boundary (branch flag, page-aligned gip, or TB_MAX_INSNS). state->ip is left at the next block entry.
void Interpreter::ExecuteBlock(CPUState *state)
{
	u8 *vmem = mmu::base;
	u32 gip = state->ip;
	void *insn_ptr;
	u32 icount = 0;

	goto bdispatch;

	static constexpr void *bloc_gotos[] = {
#define OP(name, format_, flags_) [(u8)insn::Op::_##name] = &&BLab_##name,
	    RV32_OPCODE_LIST()
#undef OP
	};
#define OP(name, format_, flags_)                                                                            \
	BLab_##name:                                                                                          \
	{                                                                                                    \
		H_##name(state, gip, vmem, *(u32 *)insn_ptr);                                                \
		if (++icount == TB_MAX_INSNS || !(gip & ~mmu::PAGE_MASK) ||                                  \
		    (insn::Insn_##name::flags & insn::Flags::Branch)) {                                      \
			TbExitCloseOpenFroundRun(state->fpu);                                                \
			state->ip = gip;                                                                     \
			dbt::config::g_last_block_insns = icount;                                            \
			return;                                                                              \
		}                                                                                            \
		goto bdispatch;                                                                              \
	}
	RV32_OPCODE_LIST()
#undef OP

bdispatch:
	{
		insn_ptr = vmem + gip;
		using decoder = insn::Decoder<insn::Op>;
		goto *bloc_gotos[(u8)decoder::Decode(insn_ptr)];
	}
}

} // namespace dbt::rv32
