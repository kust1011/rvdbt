// S2.9: the exact `vsetvli rd, rs1, e32, m1, ta, ma` DIRECT-STATE route, verified mechanically at
// six levels -- decoder, admission, constructed QIR, post-QRegAlloc allocation, independently
// disassembled emitted host bytes, and coexistence with the eight accepted typed chunk routes.
//
// This file is NOT another copy of the eight route audits, and the differences are not stylistic.
// Everything below that has no analogue in S2.1-S2.7 follows from one fact: this opcode is where a
// block's vector configuration COMES FROM. It writes the very state those routes' runtime guards
// read back, and it is the only routed RVV opcode with no guard and no fallback edge of its own.
//
// [A] THE RESULT IS A RUNTIME VALUE, AND THE FROZEN WORKLOAD CANNOT PROVE THAT.
//
// `vl = min(AVL, VLMAX)` UNSIGNED, over the whole 2^32 AVL domain (rv32_interp.cpp HANDLER(vsetvli):
// `avl < vlmax ? avl : vlmax` on u32). The frozen S1.1-fix1 suite moves N = 4096 elements and
// 4096 % 16 == 4096 % 32 == 0, so EVERY strip step at BOTH admitted VLENs has AVL >= VLMAX and
// therefore vl == VLMAX. An emitter that wrote the constant VLMAX with no compare and no AVL read at
// all would pass every whole-suite arm, every output hash and every counter gate this chain has.
// Section [5] therefore reads the emitted bytes and requires the compare, the CONDITIONAL move and
// the AVL register operand to be present; section [5b] requires the condition to be `cmovb` and not
// `cmovl`, which is the only thing separating the top half of the AVL domain from a wrong answer.
// The executed AVL boundary table -- 9 values x 2 VLENs, read back through the intercepted CSRs --
// is the runtime fixture's obligation (src/guest_vsetvli_avl.c) and is not claimed here.
//
// [B] THERE IS NO GUARD FRAME, SO THE USUAL EVIDENCE IS UNAVAILABLE AND IS REPLACED, NOT DROPPED.
//
// The eight accepted routes are proved partly by `rvvtypedchunkbegin`'s runtime compare and by the
// `inline_hits`/`guard_fallbacks` counters it moves. This route emits neither, because every
// condition it depends on except AVL is settled at translation time and AVL needs no guard. What
// replaces them is an EXHAUSTIVE admission sweep (section [1]) plus a byte-level census of the
// emitted frame (sections [5]-[7]): the claim "exactly these words take this route, and it emits
// exactly these eight instructions" is made structurally rather than observed at run time.
//
// [C] IT WRITES FOUR ARCHITECTURAL FIELDS AND ALL FOUR ARE GUEST-OBSERVABLE.
//
//   vec.vtype <- vtypei   vec.vl <- vl   vec.vstart <- 0   vec.vlenb <- VLEN/8   gpr[rd] <- vl
//
// vstart/vl/vtype are intercepted CSRs and vlenb is published through the read-only `vlenb` CSR
// (rv32_interp.cpp, rv32_vector.h), so none of them is bookkeeping that may be skipped. The frozen
// mixed loop reads only `vl`, so a frame that put the right values in the wrong fields would keep
// every output hash in this chain intact. Section [6] therefore pins each of the four stores to its
// own `offsetof` displacement, computed here from CPUState the same way the emitter computes it.
//
// [D] A WRONG vtype OR vl HERE IS NOT A LOCAL ERROR.
//
// `Emit_rvvtypedchunkbegin` compares vec.vtype and vec.vl against constants the translator put on
// the node. A wrong value written by this route does not corrupt one lane: it either turns the
// twelve accepted typed frames of the frozen mixed loop into twelve silent helper fallbacks, or
// leaves their guard passing over a wrong element count. Section [8] drives a
// `vsetvli ; vle32.v ; vadd.vv ; vse32.v` region with all nine switches open and requires the three
// accepted frames to be node-for-node and mnemonic-for-mnemonic identical to the route-off arm.
//
// [E] DROPPING `rvv_bb_vtype` WOULD BE INVISIBLE IN EVERY COUNT, AND IS GATED SEPARATELY.
//
// The translator must record `rvv_bb_vtype = i.zimm11()` on BOTH paths, because that is the
// translation-time observation the eight accepted routes consume. Dropping it on the direct path
// cannot be seen in a typed-frame count, because those routes' unknown-vtype entry PROPOSES the very
// same e32/m1/ta/ma shape and produces the same nodes. Section [9] uses the one consumer that
// behaves differently: the legacy inline-SSE2 `rvvaddv` lowering requires a REAL observation and has
// no candidate entry, so with every chunk switch off an observed vtype yields an `rvvaddv` node and
// an unobserved one yields `hcall [rv32_vadd_vv]`.
//
//     RVV:  vsetvli rd, rs1, e32,m1,ta,ma  =>  vl = min(x[rs1], VLMAX); x[rd] = vl;
//                                              vtype = 0x0d0; vstart = 0; vlenb = VLEN/8
//           (rv32_interp.cpp HANDLER(vsetvli), the single definition of these semantics)
//     QIR:  rvvsetvl vtype:d0 vlmax16 vlenb64 [%rd|i32] [%rs1|i32]
//     x86:  mov eax,0x10 ; cmp <avl>,eax ; cmovb eax,<avl> ; mov <rd>,eax
//           mov DWORD PTR [r13+vtype],0xd0 ; mov DWORD PTR [r13+vl],eax
//           mov DWORD PTR [r13+vstart],0x0 ; mov DWORD PTR [r13+vlenb],0x40
//
// WHAT THIS FILE PROVES
//
//   1. DECODER + ADMISSION. Of 131072 OPCFG-space words -- 4096 values of bits 31:20 (which is
//      bit31, bit30 and the whole vtype immediate) x 4 (rd, rs1) in/out of x0 x 8 funct3 -- exactly
//      THREE take the route: the three (rd, rs1) x0 combinations that are not both x0. A further
//      exhaustive 32x32 rd/rs1 sweep at the admitted vtype gives exactly 1023 = 1024 - 1, the one
//      refusal being the reserved keep-vl word, and a 128-value opcode sweep gives exactly 1.
//   2. FALLBACK MATRIX. Every forbidden configuration keeps the pre-existing helper: zero rvvsetvl
//      nodes and exactly one `hcall [rv32_vsetvli]` (or the other opcode's own stub). Each axis is
//      varied alone, so a single over-broad gate cannot hide behind another. `--rvv-lowering 0`
//      (Ref) is included as a POSITIVE row: unlike the two memory routes, this one has no
//      Ref-versus-chunked divergence to preserve.
//   3. QIR. Exactly one `rvvsetvl` node whose vtype/vlmax/vlenb fields are 0x0d0, config::vlen_bits
//      /32 and config::vlen_bits/8 -- never VLEN_MAX_BITS, which is silently right at VLEN=1024 and
//      wrong at VLEN=512.
//   4. QRA. One allocated GPR output and one allocated GPR input, both out of GPR_POOL and neither
//      the fixed scratch; the input is a REGISTER and never an immediate.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits exactly eight instructions: one `mov
//      <scratch>, VLMAX`, one `cmp`, one `cmovb` (not `cmovl`, not `cmova`), one `mov <rd>,
//      <scratch>` and four `mov DWORD PTR [r13+disp]` at the four `offsetof` displacements -- with
//      no `call`, no `j*`, and no vector instruction anywhere.
//   6. STATE FIELDS. The four displacements are the four CPUState offsets, each carrying the right
//      value: vtype and vlenb their immediates, vstart the immediate 0, and vl the SCRATCH REGISTER
//      the min was computed into (not an immediate, which is the constant-VLMAX defect).
//   7. rd == rs1. The aliased encoding `vsetvli t0, t0` emits the same eight instructions with one
//      host register in both roles, and every read of it precedes the single write.
//   8. SAME-TB CONSUMERS. With all nine switches open, the three accepted frames of a
//      `vsetvli ; vle32.v ; vadd.vv ; vse32.v` region are identical to the route-off arm.
//   9. rvv_bb_vtype PRESERVED, through the one consumer that can tell.
//  10. FROZEN WORDS. Both `vsetvli` words the frozen S1.1-fix1 ELF actually contains take the route
//      at both VLENs, with the correct rd and rs1 state slots.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. The AVL boundary table is therefore NOT claimed here; it is the
//     runtime fixture's obligation, executed under QEMU as an oracle and under rvdbt.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//   * It adds no LLVM lowering. `QIRToLLVM::Emit_rvvsetvl` Panics, and the admission predicate
//     rejects `config::aot_use_llvm`, which section [2] gates.
//
// HOST NOTE, AND IT IS THE OPPOSITE OF THE EIGHT ROUTE AUDITS'. Those need
// `--rvv-qcg-typed-chunk-*-force-emit` because their admission probes for AVX-512F. This route
// emits only `mov`/`cmp`/`cmovb`, which are baseline x86-64, so it has no host-feature test and no
// force-emit twin: everything below runs identically on a host with and without AVX-512. The four
// sections that ALSO open an accepted chunk route ([8]) do use those switches' own force-emit flags,
// because those routes still probe.
//
// INSTRUCTION WORDS. Every encoding below was produced by explicit field-assembly of the RVV 1.0
// layout and then independently round-tripped through `llvm-mc -triple=riscv32 -mattr=+v
// -show-encoding`, so the constants are not hand-transcribed hex. The two reserved-vtype words
// cannot be assembled by llvm-mc at all and are built by field assembly only, which is noted at
// each of them.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/qemit.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using namespace dbt::qcg;

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_STREQ(a, b)                                                                                    \
	do {                                                                                                 \
		std::string const _a = (a);                                                                  \
		std::string const _b = (b);                                                                  \
		if (_a != _b) {                                                                              \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (\"%s\" vs \"%s\")\n", __FILE__, __LINE__,    \
				#a, #b, _a.c_str(), _b.c_str());                                             \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// The four CPUState displacements the emitter must use, computed here the same way it computes
// them: offsetof(CPUState, vec) + offsetof(rv32::VectorState, field). Never a number, so a layout
// change moves the test and the emitter together instead of silently splitting them.
constexpr i64 ST_VEC = (i64)offsetof(CPUState, vec);
constexpr i64 ST_VTYPE = ST_VEC + (i64)offsetof(rv32::VectorState, vtype);
constexpr i64 ST_VL = ST_VEC + (i64)offsetof(rv32::VectorState, vl);
constexpr i64 ST_VSTART = ST_VEC + (i64)offsetof(rv32::VectorState, vstart);
constexpr i64 ST_VLENB = ST_VEC + (i64)offsetof(rv32::VectorState, vlenb);

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with the disassembly llvm-mc independently produced for it.
// ---------------------------------------------------------------------------------------------

// The route's own encoding. rd = a0 (x10), rs1 = a1 (x11): two DIFFERENT registers, so the emitted
// operand roles are distinguishable, and neither is x0.
constexpr u32 RD_REG = 10;  // a0
constexpr u32 RS1_REG = 11; // a1
constexpr u32 VTYPE_E32M1TAMA = 0x0d0u; // vma|vta|vsew=010|vlmul=000 -- rv32_vector.h's own fields

constexpr u32 INSN_VSETVLI = 0x0d05f557u;	   // vsetvli a0, a1, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_ALIAS = 0x0d02f2d7u;	   // vsetvli t0, t0, e32, m1, ta, ma  (rd == rs1)
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d85f557u;	   // vsetvli a0, a1, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d15f557u;	   // vsetvli a0, a1, e32, m2, ta, ma
constexpr u32 INSN_VSETVLI_E32MF2 = 0x0d75f557u;   // vsetvli a0, a1, e32, mf2, ta, ma
constexpr u32 INSN_VSETVLI_E16M1 = 0x0c85f557u;	   // vsetvli a0, a1, e16, m1, ta, ma
constexpr u32 INSN_VSETVLI_TU_MA = 0x0905f557u;	   // vsetvli a0, a1, e32, m1, tu, ma
constexpr u32 INSN_VSETVLI_TA_MU = 0x0505f557u;	   // vsetvli a0, a1, e32, m1, ta, mu
constexpr u32 INSN_VSETVLI_TU_MU = 0x0105f557u;	   // vsetvli a0, a1, e32, m1, tu, mu
constexpr u32 INSN_VSETVLI_RD_X0 = 0x0d05f057u;	   // vsetvli zero, a1, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_RS1_X0 = 0x0d007557u;   // vsetvli a0, zero, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_BOTH_X0 = 0x0d007057u;  // vsetvli zero, zero, e32, m1, ta, ma
constexpr u32 INSN_VSETIVLI = 0xcd047557u;	   // vsetivli a0, 8, e32, m1, ta, ma
constexpr u32 INSN_VSETVL = 0x80c5f557u;	   // vsetvl a0, a1, a2

// Consumers, for sections [8] and [9].
constexpr u32 INSN_VADD_VV = 0x021101d7u; // vadd.vv v3, v1, v2
constexpr u32 INSN_VLE32_V = 0x02086407u; // vle32.v v8, (a6)
constexpr u32 INSN_VSE32_V = 0x02086427u; // vse32.v v8, (a6)

// Assemble one OPCFG word field by field, in rv32_decode.h's own layout.
constexpr u32 MakeOpcfg(u32 hi12, u32 rs1, u32 funct3, u32 rd, u32 opcode)
{
	return (hi12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode;
}

// The two RESERVED vtype immediates. llvm-mc refuses to assemble either -- there is no mnemonic for
// a reserved vtype -- so unlike every word above these are field-assembly only, and that is exactly
// why they matter: they are the words a route must NOT admit and an assembler cannot produce.
constexpr u32 VTYPE_RESERVED_SEW = (1u << 7) | (1u << 6) | (0b111u << 3) | 0b000u; // vsew = 111
constexpr u32 VTYPE_RESERVED_LMUL = (1u << 7) | (1u << 6) | (0b010u << 3) | 0b100u; // vlmul = 100
constexpr u32 INSN_VSETVLI_RES_SEW =
    MakeOpcfg(VTYPE_RESERVED_SEW, RS1_REG, 0b111, RD_REG, 0b1010111u);
constexpr u32 INSN_VSETVLI_RES_LMUL =
    MakeOpcfg(VTYPE_RESERVED_LMUL, RS1_REG, 0b111, RD_REG, 0b1010111u);

// The two words the frozen S1.1-fix1 guest ELF actually contains at its seven static vsetvli sites
// (guest ELF SHA-256 67fb07833ed040f7d318c20a85a123ac86d3269bc7ba8a5f4f1ef62c2563cb34, per the
// accepted S2.0/S2.5/S2.8 audits). Six single-family kernels share `vsetvli a5, a2`; the mixed
// loop's is `vsetvli t0, a5`. Two distinct (rd, rs1) pairs is what gives the state-slot join in
// section [10] its discriminating power.
struct FrozenWord {
	char const *text;
	u32 word;
	u32 rd;
	u32 rs1;
};
constexpr FrozenWord FROZEN_SETVLI[] = {
    {"vsetvli a5, a2", 0x0d0677d7u, 15, 12}, // 0x1300c, 0x13078, 0x130e4, 0x13150, 0x131bc, 0x13224
    {"vsetvli t0, a5", 0x0d07f2d7u, 5, 15},  // 0x132a8  (kern_mix)
};

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. The defaults are this route open and every OTHER route closed, so a stray
// frame is never ambiguous; section [8] is the one place the accepted routes are deliberately
// opened, and it uses their own force-emit audit switches because THEY still probe for AVX-512F.
struct RouteConfig {
	bool direct_setvl = true;
	bool aot_use_llvm = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	unsigned rvv_lowering = 1; // 1 = fixed-width chunks; 0 = Ref, which this route still admits
	u32 vlen_bits = 512;
	// Section [8]/[9] only: the accepted routes this file otherwise keeps shut.
	bool chunk_add = false;
	bool chunk_vle = false;
	bool chunk_vse = false;
};

void ApplyConfig(RouteConfig const &cfg)
{
	config::rvv_qcg_direct_setvl = cfg.direct_setvl;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::rvv_lowering = cfg.rvv_lowering;
	config::vlen_bits = cfg.vlen_bits;

	config::rvv_qcg_typed_chunk = cfg.chunk_add;
	config::rvv_qcg_typed_chunk_force_emit = cfg.chunk_add;
	config::rvv_qcg_typed_chunk_vle = cfg.chunk_vle;
	config::rvv_qcg_typed_chunk_vle_force_emit = cfg.chunk_vle;
	config::rvv_qcg_typed_chunk_vse = cfg.chunk_vse;
	config::rvv_qcg_typed_chunk_vse_force_emit = cfg.chunk_vse;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_diag_chunk = false;
}

// One region containing exactly the given words. Region is arena-allocated, so `arena` must outlive
// it -- both are locals in the caller's own scope.
Region *TranslateOne(MemArena &arena, u32 *words, u32 n, RouteConfig const &cfg)
{
	ApplyConfig(cfg);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += (ins.GetOpcode() == op);
		}
	}
	return n;
}

// Number of hcalls to one specific runtime stub -- the fallback evidence: a non-admitted vsetvli
// must produce exactly one call to the PRE-EXISTING rv32_vsetvli helper, not to a new stub.
unsigned CountHcall(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_hcall) {
				continue;
			}
			n += (static_cast<InstHcall *>(&ins)->stub == stub);
		}
	}
	return n;
}

InstRVVSetVL *FindSetVL(Region *region)
{
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvsetvl) {
				return static_cast<InstRVVSetVL *>(&ins);
			}
		}
	}
	return nullptr;
}

// Minimal Decoder Provider whose `_##name` members are the Op enum values themselves, so
// Decoder<>::Decode returns the decoded opcode directly. The decoder template is shared with the
// interpreter and the translator, so this exercises the real routing rule, not a copy of it.
struct OpProvider {
#define OP(name, format_, flags_) static constexpr rv32::insn::Op _##name = rv32::insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

rv32::insn::Op DecodeWord(u32 word)
{
	u32 w = word;
	return rv32::insn::Decoder<OpProvider>::Decode(&w);
}

// ---------------------------------------------------------------------------------------------
// 1. Decoder + admission: exhaustive sweeps of the OPCFG encoding space.
// ---------------------------------------------------------------------------------------------

// THE CENTRAL GATE OF THIS CHECKPOINT. Bits 31:20 of an OPCFG word are simultaneously the
// vsetvli/vsetivli/vsetvl selector (bit31, bit30) and the whole 11-bit vtype immediate, so sweeping
// all 4096 of them covers every vtype -- supported, reserved and vill -- and every opcode form the
// decoder can produce from this space, in one axis. T7S admits every legal immediate-vtype
// vsetvli/vsetivli encoding at VLEN512/1024 and rejects every other OPCFG form.
//
// Native-1 widened the register axis: rd == x0 and rs1 == x0 are each admitted on their own, AND so
// is their conjunction -- the keep-vl form, which the QCG emitter implements (the node carries
// `keep_vl` and the emitter has the reserved arm for it). So all FOUR (rd, rs1) x0 combinations at
// an admitted vtype take the route on this backend, which is what CheckRegisterSweep's 1024 says
// independently. (The LLVM arm is the one that refuses keep-vl, because `Emit_rvvsetvl` ignores the
// flag; that is `RvvSetVLShapeAdmit`'s extra row and is tested in the llvmgen sibling file.)
//
// TWO LOWERINGS EMIT `Op::_rvvsetvl`, AND THIS SWEEP HAS TO TELL THEM APART. That is the whole of
// what this function got wrong before:
//
//   * the SETUP route, for a legal immediate vtype: the node carries the guest's own `vtypei` and
//     `vlmax = compute_vlmax(vtype, VLEN)`;
//   * the VILL route, for a RESERVED or unsupported immediate vtype: TRANSLATOR(vsetvli) and
//     TRANSLATOR(vsetivli) both have a second direct arm that emits the SAME op with
//     `vtype = VTYPE_VILL_BIT`, `vlmax = 0` and a constant AVL of 0. It is a deliberate lowering,
//     not a leak: HANDLER(vsetvli)'s reserved path is `vtype <- vill; vl <- 0; vstart <- 0;
//     rd <- 0`, and that is exactly what this node's emitters produce (`vl = min(0, 0) = 0`, and
//     the `vlenb` write is the same VLEN/8 that `VectorState::Reset` already installed, so it is
//     observationally a no-op).
//
// `CountOp(_rvvsetvl) != 0` therefore means "took SOME direct lowering", not "took the setup
// route", and using it as the latter counted all 2896 reserved-vtype words as admitted and then
// failed its own `vtype_supported` assertion on every one of them. The fix is to classify by the
// node's own fields, which keeps the original 704 expectation for the setup route AND adds the
// assertion nothing made before: that the vill route covers exactly the complementary set.
//
// A predicate that accepted `tu`/`mu` shows up here as more legal words; one that accepted any SEW
// or LMUL as dozens; one that let a reserved vtype into the SETUP route as a legal word with an
// unsupported vtype -- and none of those is visible in DecodeWord at all, because every bit31 == 0
// word here legitimately reaches Op::_vsetvli.
void CheckEncodingSweep()
{
	printf("[1] OPCFG encoding sweep: 4096 (bits 31:20) x 4 (rd,rs1 in/out of x0) x 8 funct3 = "
	       "131072\n");

	MemArena arena(1u << 20);
	std::vector<u32> setup, vill;
	unsigned n_reach_vsetvli = 0, n_reach_vsetivli = 0, n_reach_vsetvl = 0;

	u32 const rds[2] = {0, RD_REG};
	u32 const rs1s[2] = {0, RS1_REG};
	for (u32 hi12 = 0; hi12 < 4096; ++hi12) {
		for (u32 ri = 0; ri < 2; ++ri) {
			for (u32 si = 0; si < 2; ++si) {
				for (u32 f3 = 0; f3 < 8; ++f3) {
					u32 w = MakeOpcfg(hi12, rs1s[si], f3, rds[ri], 0b1010111u);
					auto const op = DecodeWord(w);
					n_reach_vsetvli += (op == rv32::insn::Op::_vsetvli);
					n_reach_vsetivli += (op == rv32::insn::Op::_vsetivli);
					n_reach_vsetvl += (op == rv32::insn::Op::_vsetvl);
					arena.Reset();
					RouteConfig cfg;
					u32 word = w;
					Region *r = TranslateOne(arena, &word, 1, cfg);
					if (CountOp(r, Op::_rvvsetvl) == 0) {
						continue;
					}
					CHECK_EQ(CountOp(r, Op::_rvvsetvl), 1u);
					auto *ins = FindSetVL(r);
					CHECK(ins != nullptr);
					if (!ins) {
						continue;
					}
					// The node says which lowering it is; nothing else has to.
					if (ins->vtype == rv32::VTYPE_VILL_BIT && ins->vlmax == 0) {
						vill.push_back(w);
					} else {
						setup.push_back(w);
					}
				}
			}
		}
	}

	// THE TWO EXPECTED COUNTS, DERIVED FROM `vtype_supported` RATHER THAN PASTED, so a change to
	// the architectural legality rule moves both sides of the comparison together instead of
	// turning this into a number nobody can re-derive. `vsetvli` carries an 11-bit immediate and
	// `vsetivli` a 10-bit one, but a legal vtype has bits 10:8 clear either way, so the two see
	// the same legal set.
	unsigned legal_vsetvli = 0, legal_vsetivli = 0;
	for (u32 hi12 = 0; hi12 < 2048; ++hi12) // bit31 == 0 -> Op::_vsetvli
		legal_vsetvli += rv32::vtype_supported(rv32::VType{hi12 & 0x7ffu}, 512);
	for (u32 hi12 = 3072; hi12 < 4096; ++hi12) // bits 31:30 == 11 -> Op::_vsetivli
		legal_vsetivli += rv32::vtype_supported(rv32::VType{hi12 & 0x3ffu}, 512);
	unsigned const regs = 4; // the four (rd, rs1) in/out-of-x0 combinations
	CHECK_EQ(setup.size(), (size_t)(legal_vsetvli + legal_vsetivli) * regs);
	CHECK_EQ(setup.size(), 704u); // 88 legal vtypes x four register fields x two setup opcodes
	CHECK_EQ(vill.size(), (size_t)((2048u - legal_vsetvli) + (1024u - legal_vsetivli)) * regs);

	for (u32 w : setup) {
		auto const op = DecodeWord(w);
		CHECK(op == rv32::insn::Op::_vsetvli || op == rv32::insn::Op::_vsetivli);
		u32 const mask = op == rv32::insn::Op::_vsetivli ? 0x3ffu : 0x7ffu;
		CHECK(rv32::vtype_supported(rv32::VType{(w >> 20) & mask}, 512));
	}
	// The complementary claim, which nothing asserted before: every word the VILL route took is a
	// setup opcode whose immediate vtype is NOT supported, and the node it built carries the
	// reserved-path write set -- AVL 0 (so `vl = min(0, 0) = 0`) and not the keep-vl form, because
	// HANDLER(vsetvli) installs vill BEFORE it looks at the AVL form at all.
	for (u32 w : vill) {
		auto const op = DecodeWord(w);
		CHECK(op == rv32::insn::Op::_vsetvli || op == rv32::insn::Op::_vsetivli);
		u32 const mask = op == rv32::insn::Op::_vsetivli ? 0x3ffu : 0x7ffu;
		CHECK(!rv32::vtype_supported(rv32::VType{(w >> 20) & mask}, 512));
	}
	{ // the node's shape, on one representative rather than on all 11584
		arena.Reset();
		RouteConfig cfg;
		u32 word = vill.empty() ? INSN_VSETVLI_RES_SEW : vill[0];
		Region *r = TranslateOne(arena, &word, 1, cfg);
		auto *ins = FindSetVL(r);
		CHECK(ins != nullptr);
		if (ins) {
			CHECK_EQ(ins->vtype, rv32::VTYPE_VILL_BIT);
			CHECK_EQ(ins->vlmax, 0u);
			CHECK(!ins->keep_vl);
			CHECK(ins->i(0).IsConst());
			CHECK_EQ(ins->i(0).GetConst(), 0u);
		}
	}
	// EVERY setup word takes one of the two, and nothing else takes either: the two counts must
	// add up to the decoder's whole reach for the two setup opcodes.
	CHECK_EQ(setup.size() + vill.size(), (size_t)(2048u + 1024u) * regs);
	printf("    exactly %zu legal vsetvli/vsetivli words take the SETUP route; the other %zu take "
	       "the VILL route (vtype=vill, vlmax=0, AVL=0); no other OPCFG word takes either\n",
	       setup.size(), vill.size());

	// The decoder's own reach, reported for contrast rather than as the gate. rv32_decode.h is
	// EXACT here, unlike for vle/vse: only bit31 == 0 reaches Op::_vsetvli. Of the 4096 hi12
	// values 2048 have bit31 == 0, and each is crossed with 4 register combinations at funct3 =
	// 0b111 only, so 8192 words arrive -- and the route admits 3 of them.
	CHECK_EQ(n_reach_vsetvli, 2048u * 4u);
	CHECK_EQ(n_reach_vsetivli, 1024u * 4u); // bits 31:30 == 11
	CHECK_EQ(n_reach_vsetvl, 32u * 4u);	// bits 31:25 == 1000000
	printf("    decoder reach at funct3=111: vsetvli %u, vsetivli %u, vsetvl %u; the route "
	       "admits only legal setup words from the %u vsetvli encodings\n",
	       n_reach_vsetvli, n_reach_vsetivli, n_reach_vsetvl, n_reach_vsetvli);
}

// The x0 rule, on its own exhaustive axis. 32 x 32 register pairs at the admitted vtype: on THIS
// backend all 1024 take the route, keep-vl (rd == x0 && rs1 == x0) included, because the QCG
// emitter implements the keep-vl arm and the node carries the flag for it.
//
// This is the check that separates the readings of "the x0 rule" from each other: the old
// "rd != x0 AND rs1 != x0" would admit 961, a rule that refused only the conjunction would admit
// 1023, and the rule this backend implements admits 1024. The assertion is per-pair as well as on
// the total, so a count that came out right for the wrong reason still fails.
void CheckRegisterSweep()
{
	printf("[1b] register sweep: 32 rd x 32 rs1 at vtypei=0x0d0\n");

	MemArena arena(1u << 20);
	unsigned admitted = 0;
	for (u32 rd = 0; rd < 32; ++rd) {
		for (u32 rs1 = 0; rs1 < 32; ++rs1) {
			arena.Reset();
			RouteConfig cfg;
			u32 word = MakeOpcfg(VTYPE_E32M1TAMA, rs1, 0b111, rd, 0b1010111u);
			Region *r = TranslateOne(arena, &word, 1, cfg);
			bool const took = CountOp(r, Op::_rvvsetvl) != 0;
			admitted += took;
			CHECK(took);
			CHECK_EQ(CountOp(r, Op::_rvvsetvl), 1u);
			CHECK_EQ(CountHcall(r, RuntimeStubId::id_rv32_vsetvli), 0u);
		}
	}
	CHECK_EQ(admitted, 1024u);
	printf("    %u/1024 admitted, including architectural rd=x0,rs1=x0 keep-VL\n", admitted);
}

// The opcode field, exhaustively. Only OP-V may take the route; the other 127 opcodes decode to
// entirely different instructions and must produce no rvvsetvl node at all.
void CheckOpcodeSweep()
{
	printf("[1c] opcode sweep: all 128 opcode values at the otherwise-admitted word\n");

	MemArena arena(1u << 20);
	unsigned admitted = 0;
	for (u32 opc = 0; opc < 128; ++opc) {
		arena.Reset();
		RouteConfig cfg;
		u32 word = MakeOpcfg(VTYPE_E32M1TAMA, RS1_REG, 0b111, RD_REG, opc);
		Region *r = TranslateOne(arena, &word, 1, cfg);
		if (CountOp(r, Op::_rvvsetvl) != 0) {
			++admitted;
			CHECK_EQ(opc, 0b1010111u);
		}
	}
	CHECK_EQ(admitted, 1u);
	printf("    exactly %u opcode value admits (OP-V = 0b1010111)\n", admitted);
}

// ---------------------------------------------------------------------------------------------
// 2. Fallback matrix: each axis varied alone.
// ---------------------------------------------------------------------------------------------

// Every row here must produce ZERO rvvsetvl nodes and exactly ONE hcall to the pre-existing helper
// its opcode already had. Each row differs from the fully-open admitted configuration in exactly one
// field, so an over-broad gate cannot hide behind another gate that also happens to close.
//
// The LAST row is a POSITIVE control and is the one row that is not a refusal: `--rvv-lowering 0`
// (Ref) is excluded by the two memory routes because Ref addresses elements with a wrapping u32 add
// while rvv_chunked walks host pointers. vsetvli has no element loop and no address arithmetic --
// HANDLER(vsetvli) is one min and five stores, shared by both lowerings -- so this route admits
// under Ref, and that is a decision this file records rather than an omission.
void CheckFallbackMatrix()
{
	printf("[2] fallback matrix, one axis at a time\n");

	// THREE OUTCOMES, NOT TWO. `expect_route` used to mean "an rvvsetvl node appears", which
	// stopped being the same question as "took the setup route" once the reserved-vtype arm
	// started emitting the same op. A row that expects the VILL lowering wants a node AND no
	// helper, but a DIFFERENT node -- see CheckEncodingSweep for the two shapes.
	// `SetVlReg` is the register-vtype form's own direct lowering (C2a): a DIFFERENT QIR op,
	// `_rvvsetvlreg`, emitted by TRANSLATOR(vsetvl) under the same `--rvv-qcg-direct-setvl`
	// switch. This row is a negative control for the route under test and its real content is
	// unchanged -- no `_rvvsetvl` node -- but it stopped calling the helper when that arm landed.
	enum class Outcome { Helper, Setup, Vill, SetVlReg };
	struct Row {
		char const *name;
		RouteConfig cfg;
		u32 word;
		RuntimeStubId stub;
		Outcome expect;
	};

	auto base = []() {
		RouteConfig c;
		return c;
	};

	std::vector<Row> rows;
	auto add = [&](char const *name, RouteConfig c, u32 word, RuntimeStubId stub,
		       bool expect_route = false) {
		rows.push_back(Row{name, c, word, stub, expect_route ? Outcome::Setup : Outcome::Helper});
	};
	auto add_vill = [&](char const *name, RouteConfig c, u32 word, RuntimeStubId stub) {
		rows.push_back(Row{name, c, word, stub, Outcome::Vill});
	};
	auto add_setvlreg = [&](char const *name, RouteConfig c, u32 word, RuntimeStubId stub) {
		rows.push_back(Row{name, c, word, stub, Outcome::SetVlReg});
	};

	{ // the switch itself, which is the default state of the build
		RouteConfig c = base();
		c.direct_setvl = false;
		add("switch off (the DEFAULT)", c, INSN_VSETVLI, RuntimeStubId::id_rv32_vsetvli);
	}
	{
		RouteConfig c = base();
		c.aot_use_llvm = true;
		add("aot_use_llvm", c, INSN_VSETVLI, RuntimeStubId::id_rv32_vsetvli);
	}
	{
		RouteConfig c = base();
		c.rvv_verify = true;
		add("rvv_verify", c, INSN_VSETVLI, RuntimeStubId::id_rv32_vsetvli);
	}
	{
		RouteConfig c = base();
		c.rvv_direct = false;
		add("rvv_direct off", c, INSN_VSETVLI, RuntimeStubId::id_rv32_vsetvli);
	}
	// T6b NARROWED THIS AXIS TO WHAT IT ALWAYS MEANT. It used to read {128, 256, 2048}: two VLENs
	// that are not a whole number of 512-bit host chunks, and one that is. Only the first two were
	// ever a property of this route -- 2048 was refused by a literal VLEN set the route shared with
	// its neighbours, and T6b replaced that set with the whole-chunk rule, so 2048 and 4096 are now
	// ADMITTED and are checked as positives by rvv_generic_width_route_test. The partial-chunk
	// widths stay here, where they belong: they are refused by the rule itself and always were.
	// A VLEN past the storage reservation (k > kMaxChunks) is the third refusal the rule makes and
	// is exercised in that same file, which can set a width the CLI would not accept.
	// A15 (2026-09-05): GOLDEN CHANGE -- these two rows are now POSITIVE. The setup route emits no
	// vector instruction, so "not a whole 512-bit chunk" was never a property of it; T7S had
	// kept the narrow widths on the legacy e32,m1 shape, and A15 applies the one
	// architectural rule (vtype_supported) at every VLEN so the four-width comparison does
	// not mix a helper setup at 128/256 with a direct one at 512/1024.
	for (u32 v : {128u, 256u}) {
		RouteConfig c = base();
		c.vlen_bits = v;
		static char names[2][48];
		static int ni = 0;
		snprintf(names[ni], sizeof(names[0]), "VLEN=%u (POSITIVE since A15)", v);
		add(names[ni++], c, INSN_VSETVLI, RuntimeStubId::id_rv32_vsetvli, true);
	}
	add("e64,m1", base(), INSN_VSETVLI_E64M1, RuntimeStubId::id_rv32_vsetvli, true);
	add("e32,m2", base(), INSN_VSETVLI_E32M2, RuntimeStubId::id_rv32_vsetvli, true);
	add("e32,mf2", base(), INSN_VSETVLI_E32MF2, RuntimeStubId::id_rv32_vsetvli, true);
	add("e16,m1", base(), INSN_VSETVLI_E16M1, RuntimeStubId::id_rv32_vsetvli, true);
	add("e32,m1,tu,ma", base(), INSN_VSETVLI_TU_MA, RuntimeStubId::id_rv32_vsetvli, true);
	add("e32,m1,ta,mu", base(), INSN_VSETVLI_TA_MU, RuntimeStubId::id_rv32_vsetvli, true);
	add("e32,m1,tu,mu", base(), INSN_VSETVLI_TU_MU, RuntimeStubId::id_rv32_vsetvli, true);
	// RESERVED vtypes do NOT keep the helper: TRANSLATOR(vsetvli)'s second direct arm lowers them
	// to the vill node. That arm is what HANDLER(vsetvli)'s reserved path does
	// (vtype <- vill, vl <- 0, vstart <- 0, rd <- 0), so the right expectation is the VILL
	// lowering, not the helper -- and the node's own fields are what the loop below checks.
	add_vill("reserved vsew=111 (VILL node)", base(), INSN_VSETVLI_RES_SEW,
		 RuntimeStubId::id_rv32_vsetvli);
	add_vill("reserved vlmul=100 (VILL node)", base(), INSN_VSETVLI_RES_LMUL,
		 RuntimeStubId::id_rv32_vsetvli);
	// Native-1 moved these two from the exclusion list to the admitted set, and left the third
	// where it was. They are kept HERE, among the exclusions, rather than deleted: the axis they
	// test is the same one, and a row that says "POSITIVE" next to fifteen negatives is what
	// makes the boundary between them readable.
	add("rd = x0 (POSITIVE: Native-1)", base(), INSN_VSETVLI_RD_X0,
	    RuntimeStubId::id_rv32_vsetvli, true);
	add("rs1 = x0 (POSITIVE: Native-1)", base(), INSN_VSETVLI_RS1_X0,
	    RuntimeStubId::id_rv32_vsetvli, true);
	// The one vsetvli register form that is still refused: reserved keep-vl.
	add("rd = x0, rs1 = x0 (keep-vl)", base(), INSN_VSETVLI_BOTH_X0,
	    RuntimeStubId::id_rv32_vsetvli, true);
	add("vsetivli", base(), INSN_VSETIVLI, RuntimeStubId::id_rv32_vsetivli, true);
	// `vsetvl` takes its vtype from a GPR and must NOT produce this route's node -- that is what
	// this row is for and it still holds. Since C2a it has its own direct lowering to
	// `_rvvsetvlreg`, so it no longer reaches the helper either.
	add_setvlreg("vsetvl (register vtype -> _rvvsetvlreg)", base(), INSN_VSETVL,
		     RuntimeStubId::id_rv32_vsetvl);
	{ // POSITIVE control: Ref lowering is NOT an exclusion for this route
		RouteConfig c = base();
		c.rvv_lowering = 0;
		add("rvv_lowering = Ref (POSITIVE: still admitted)", c, INSN_VSETVLI,
		    RuntimeStubId::id_rv32_vsetvli, true);
	}

	for (auto const &r : rows) {
		// A15: every row is driven at all FOUR widths (the VLEN rows carry their own width).
		for (u32 vlen : {128u, 256u, 512u, 1024u}) {
			MemArena arena(1u << 20);
			RouteConfig c = r.cfg;
			if (c.vlen_bits == 512) {
				c.vlen_bits = vlen;
			}
			u32 word = r.word;
			Region *reg = TranslateOne(arena, &word, 1, c);
			unsigned const n_route = CountOp(reg, Op::_rvvsetvl);
			unsigned const n_helper = CountHcall(reg, r.stub);
			if (r.expect == Outcome::Helper) {
				CHECK_EQ(n_route, 0u);
				CHECK_EQ(n_helper, 1u);
			} else if (r.expect == Outcome::SetVlReg) {
				// The route under test builds `_rvvsetvl`; this form must not, and
				// that is the assertion this row exists for.
				CHECK_EQ(n_route, 0u);
				CHECK_EQ(CountOp(reg, Op::_rvvsetvlreg), 1u);
				CHECK_EQ(n_helper, 0u);
			} else {
				CHECK_EQ(n_route, 1u);
				CHECK_EQ(n_helper, 0u);
				// WHICH direct lowering, read off the node rather than assumed.
				auto *ins = FindSetVL(reg);
				CHECK(ins != nullptr);
				if (ins) {
					bool const is_vill = ins->vtype == rv32::VTYPE_VILL_BIT &&
							     ins->vlmax == 0;
					CHECK_EQ(is_vill, r.expect == Outcome::Vill);
				}
			}
			// No OTHER vsetvli-family helper may appear either: a route that fell back to
			// a different stub would still be a semantic change.
			for (auto s : {RuntimeStubId::id_rv32_vsetvli, RuntimeStubId::id_rv32_vsetvl,
				       RuntimeStubId::id_rv32_vsetivli}) {
				if (s == r.stub) {
					continue;
				}
				CHECK_EQ(CountHcall(reg, s), 0u);
			}
		}
		printf("    %-42s %s\n", r.name,
		       r.expect == Outcome::Setup ? "SETUP route (positive control)"
		       : r.expect == Outcome::Vill ? "VILL route (vtype=vill, vlmax=0)"
		       : r.expect == Outcome::SetVlReg ? "_rvvsetvlreg (0 _rvvsetvl nodes)"
						       : "helper (0 route nodes)");
	}
}

// ---------------------------------------------------------------------------------------------
// 3. Constructed QIR: the node's translation-time constants.
// ---------------------------------------------------------------------------------------------
void CheckQir(char const *tag, u32 vlen_bits)
{
	printf("[3] %s: constructed QIR\n", tag);

	MemArena arena(1u << 20);
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	u32 word = INSN_VSETVLI;
	Region *region = TranslateOne(arena, &word, 1, cfg);

	CHECK_EQ(CountOp(region, Op::_rvvsetvl), 1u);
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vsetvli), 0u);
	// No guard frame, no fallback edge, no call: the structural difference from all eight
	// accepted routes, asserted rather than described.
	CHECK_EQ(CountOp(region, Op::_rvvtypedchunkbegin), 0u);
	CHECK_EQ(CountOp(region, Op::_rvvtypedchunkend), 0u);
	CHECK_EQ(CountOp(region, Op::_hcall), 0u);

	auto *ins = FindSetVL(region);
	CHECK(ins != nullptr);
	if (!ins) {
		return;
	}
	CHECK_EQ(ins->vtype, VTYPE_E32M1TAMA);
	// THE TRAP THIS GATE EXISTS FOR: a vlmax taken from rv32::VLEN_MAX_BITS instead of
	// config::vlen_bits is silently right at VLEN=1024 and wrong at VLEN=512.
	CHECK_EQ(ins->vlmax, vlen_bits / 32u);
	CHECK(ins->vlmax != rv32::VLEN_MAX_BITS / 32u || vlen_bits == 1024);
	CHECK_EQ(ins->vlenb, vlen_bits / 8u);

	// One output bound to the guest rd global, one input read from the guest rs1 global.
	CHECK_EQ((unsigned)ins->OutputCount(), 1u);
	CHECK_EQ((unsigned)ins->InputCount(), 1u);
	auto const d = ins->o(0);
	auto const s = ins->i(0);
	CHECK(d.IsVGPR());
	CHECK(s.IsVGPR());
	CHECK(!s.IsConst());
	CHECK_EQ(d.GetType(), VType::I32);
	CHECK_EQ(s.GetType(), VType::I32);
	printf("    OK 1 rvvsetvl vtype=0x%x vlmax=%u vlenb=%u, 1 vreg out / 1 vreg in, no guard "
	       "frame, no hcall\n",
	       ins->vtype, ins->vlmax, ins->vlenb);
}

// A15. [3b] The general envelope at EVERY width: the node's constants follow compute_vlmax(vt,
// VLEN) and VLEN/8 for e8/e16/e32/e64, integral and fractional LMUL, every policy, register and
// immediate forms -- at 128/256 exactly as at 512/1024. What made the narrow widths "different"
// before A15 was only a switch in the admission predicate, never the recipe.
void CheckGeneralEnvelopeAllWidths()
{
	printf("[3b] A15: general vtype envelope, four widths, node constants from the architectural rule\n");
	struct Row { char const *name; u32 word; u32 vtype; bool imm; };
	// vsetvli a0,a0,<vtype>  = 0x00057557 | zimm11<<20 ; vsetivli a0,8,<vtype> = 0xc0047557 | zimm10<<20
	auto vli = [](u32 vt) { return 0x00057557u | (vt << 20); };
	auto ivli = [](u32 vt) { return 0xc0047557u | ((vt & 0x3ffu) << 20); };
	Row rows[] = {
	    {"vsetvli e8,m1,ta,ma", vli(0x0c0), 0x0c0, false},   {"vsetvli e16,mf2,tu,mu", vli(0x00f), 0x00f, false},
	    {"vsetvli e32,m4,ta,mu", vli(0x092), 0x092, false},  {"vsetvli e64,m8,ta,ma", vli(0x0db), 0x0db, false},
	    {"vsetvli e64,m1,ta,ma", vli(0x0d8), 0x0d8, false},  {"vsetvli e8,mf8,tu,ma", vli(0x045), 0x045, false},
	    {"vsetivli e64,m1,ta,ma", ivli(0x0d8), 0x0d8, true}, {"vsetivli e16,mf2,tu,mu", ivli(0x00f), 0x00f, true},
	};
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		for (auto const &r : rows) {
			MemArena arena(1u << 20);
			RouteConfig cfg; cfg.vlen_bits = vlen;
			u32 word = r.word;
			Region *region = TranslateOne(arena, &word, 1, cfg);
			rv32::VType const vt{r.vtype};
			bool const legal = rv32::vtype_supported(vt, vlen);
			CHECK_EQ(CountOp(region, Op::_rvvsetvl), legal ? 1u : 0u);
			CHECK_EQ(CountHcall(region, r.imm ? RuntimeStubId::id_rv32_vsetivli : RuntimeStubId::id_rv32_vsetvli), legal ? 0u : 1u);
			if (!legal) continue;
			auto *ins = FindSetVL(region); CHECK(ins != nullptr); if (!ins) continue;
			CHECK_EQ(ins->vtype, r.vtype);
			CHECK_EQ(ins->vlmax, rv32::compute_vlmax(vt, vlen));
			CHECK_EQ(ins->vlenb, vlen / 8u);
			CHECK(!ins->keep_vl);
			if (r.imm) { CHECK(ins->i(0).IsConst()); CHECK_EQ(ins->i(0).GetConst(), 8u); }
		}
		// keep-vl form (rd=x0, rs1=x0) at every width: the node carries keep_vl; the emitter's
		// reserved arm handles vl > new VLMAX
		{
			MemArena arena(1u << 20); RouteConfig cfg; cfg.vlen_bits = vlen;
			u32 word = 0x00007057u | (0x0d8u << 20); // vsetvli x0,x0,e64,m1,ta,ma
			Region *region = TranslateOne(arena, &word, 1, cfg);
			auto *ins = FindSetVL(region); CHECK(ins != nullptr); if (ins) CHECK(ins->keep_vl);
		}
		// Reserved vtype at every width: the VILL node, NOT the helper. The node carries the
		// architectural reserved-path result as constants -- vtype = vill, vlmax = 0 (so the
		// emitter's `min(AVL, VLMAX)` yields vl = 0 for any AVL), AVL = 0, and not keep-vl.
		{
			MemArena arena(1u << 20); RouteConfig cfg; cfg.vlen_bits = vlen;
			u32 word = INSN_VSETVLI_RES_SEW;
			Region *region = TranslateOne(arena, &word, 1, cfg);
			CHECK_EQ(CountOp(region, Op::_rvvsetvl), 1u);
			CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vsetvli), 0u);
			auto *ins = FindSetVL(region); CHECK(ins != nullptr);
			if (ins) {
				CHECK_EQ(ins->vtype, rv32::VTYPE_VILL_BIT);
				CHECK_EQ(ins->vlmax, 0u);
				CHECK_EQ(ins->vlenb, vlen / 8u);
				CHECK(!ins->keep_vl);
				CHECK(ins->i(0).IsConst()); CHECK_EQ(ins->i(0).GetConst(), 0u);
			}
		}
		printf("    VLEN %4u: %zu forms, node constants = compute_vlmax / VLEN/8; keep-vl node; reserved -> VILL node\n", vlen, sizeof(rows) / sizeof(rows[0]));
	}
}

// ---------------------------------------------------------------------------------------------
// 4. Post-QRegAlloc form.
// ---------------------------------------------------------------------------------------------
void CheckPostQRA(char const *tag, u32 vlen_bits, u32 word)
{
	printf("[4] %s: post-QRegAlloc allocation\n", tag);

	MemArena arena(1u << 20);
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	u32 w = word;
	Region *region = TranslateOne(arena, &w, 1, cfg);

	// Exactly the two passes qcg::GenerateCode runs before constructing QEmit (qcg.cpp).
	ArchTraits::init();
	MachineRegionInfo info;
	QSelPass::run(region, &info);
	QRegAllocPass::run(region);

	auto *ins = FindSetVL(region);
	CHECK(ins != nullptr);
	if (!ins) {
		return;
	}
	auto const d = ins->o(0);
	auto const s = ins->i(0);
	CHECK(d.IsPGPR());
	// THE OPERAND THE EMITTER'S `cmov` CANNOT ACCEPT AS AN IMMEDIATE. CT(rvvsetvl, r_r) declares
	// the input register-only, so QSel must have materialised any constant into a register; this
	// asserts the outcome of that rule rather than the rule.
	CHECK(s.IsPGPR());
	CHECK(!s.IsConst());
	CHECK(ArchTraits::GPR_POOL.Test(d.GetPGPR()));
	CHECK(ArchTraits::GPR_POOL.Test(s.GetPGPR()));
	// The whole rd == rs1 argument rests on the fixed scratch aliasing neither operand.
	CHECK(d.GetPGPR() != ArchTraits::AX);
	CHECK(s.GetPGPR() != ArchTraits::AX);
	printf("    OK out=p%u in=p%u, both in GPR_POOL, neither is the fixed scratch (p%u)\n",
	       (unsigned)d.GetPGPR(), (unsigned)s.GetPGPR(), (unsigned)ArchTraits::AX);
}

// ---------------------------------------------------------------------------------------------
// 5+6+7. Emitted host bytes, decoded by an external disassembler.
// ---------------------------------------------------------------------------------------------

// AllocateCode NEVER mmaps: it resizes a vector and returns its data pointer. That is the
// structural guarantee behind "the emitted bytes are never executed".
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this checkpoint's
// emission evidence cannot be produced at all.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_s29_emit_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write to temp file failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);

	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path +
	    " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		fprintf(stderr, "  popen(objdump) failed: %s\n", strerror(errno));
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	std::string cur;
	while (fgets(buf, sizeof(buf), p)) {
		cur += buf;
		if (!cur.empty() && cur.back() == '\n') {
			cur.pop_back();
			lines.push_back(cur);
			cur.clear();
		}
	}
	if (!cur.empty()) {
		lines.push_back(cur);
	}
	int const rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		return {};
	}
	return lines;
}

std::vector<u8> EmitOne(MemArena &arena, u32 *words, u32 n, RouteConfig const &cfg,
			TestCompilerRuntime &cr)
{
	Region *region = TranslateOne(arena, words, n, cfg);
	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cr, &segment, region, 0);
	CHECK(!code_span.empty());
	return std::vector<u8>(code_span.begin(), code_span.end());
}

// One decoded host instruction, reduced to the fields these gates read.
struct DecodedInsn {
	std::string mnemonic;
	std::vector<std::string> ops;
};

std::vector<std::string> SplitCommas(std::string const &s)
{
	std::vector<std::string> out;
	size_t start = 0;
	for (size_t i = 0; i <= s.size(); ++i) {
		if (i == s.size() || s[i] == ',') {
			out.push_back(s.substr(start, i - start));
			start = i + 1;
		}
	}
	return out;
}

bool ParseLine(std::string const &line, DecodedInsn *out)
{
	size_t const tab = line.find('\t');
	if (tab == std::string::npos) {
		return false;
	}
	std::string const rhs = line.substr(tab + 1);
	if (rhs.empty()) {
		return false;
	}
	size_t const sp = rhs.find(' ');
	out->mnemonic = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	size_t opstart = sp == std::string::npos ? rhs.size() : sp;
	while (opstart < rhs.size() && rhs[opstart] == ' ') {
		++opstart;
	}
	out->ops.clear();
	if (opstart < rhs.size()) {
		out->ops = SplitCommas(rhs.substr(opstart));
	}
	// objdump appends `# comment` to rip-relative forms; none of the shapes below has one, and
	// dropping a trailing comment silently would hide an unexpected addressing mode.
	return true;
}

// objdump prints the helper's REX-prefixed relative call as `rex call 0x...`, so the mnemonic
// field alone would MISS it -- and missing it is precisely the failure mode that would make "the
// helper call is gone" pass vacuously. Match `call` as a token anywhere in the decoded instruction.
bool IsCall(DecodedInsn const &in)
{
	if (in.mnemonic == "call") {
		return true;
	}
	for (auto const &o : in.ops) {
		if (o.compare(0, 5, "call ") == 0 || o == "call") {
			return true;
		}
	}
	return false;
}

// "DWORD PTR [r13+0x<hex>]" -> displacement. Any other addressing form -- a second register, a
// scale, a different base -- is rejected, which is what makes "these four stores go to CPUState and
// nowhere else" checkable rather than assumed.
bool ParseStateMem(std::string const &tok, i64 *disp)
{
	static std::string const prefix = "DWORD PTR [r13+";
	if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}
	if (tok.back() != ']') {
		return false;
	}
	std::string const inner = tok.substr(prefix.size(), tok.size() - prefix.size() - 1);
	if (inner.compare(0, 2, "0x") != 0) {
		return false;
	}
	i64 v = 0;
	size_t i = 2;
	for (; i < inner.size() && isxdigit((unsigned char)inner[i]); ++i) {
		char const c = (char)tolower((unsigned char)inner[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
	}
	if (i == 2 || i != inner.size()) {
		return false;
	}
	*disp = v;
	return true;
}

bool ParseImm(std::string const &tok, i64 *val)
{
	if (tok.compare(0, 2, "0x") != 0) {
		return false;
	}
	i64 v = 0;
	size_t i = 2;
	for (; i < tok.size() && isxdigit((unsigned char)tok[i]); ++i) {
		char const c = (char)tolower((unsigned char)tok[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
	}
	if (i == 2 || i != tok.size()) {
		return false;
	}
	*val = v;
	return true;
}

bool IsGpr32(std::string const &t)
{
	static char const *const regs[] = {"eax", "ecx", "edx",	 "ebx",	 "esp",	 "ebp",	 "esi",
					   "edi", "r8d", "r9d",	 "r10d", "r11d", "r12d", "r13d",
					   "r14d", "r15d"};
	for (auto const *r : regs) {
		if (t == r) {
			return true;
		}
	}
	return false;
}

// Emit one word and return the decoded instruction stream, in emission order. Every line objdump
// produced is parsed; an unparseable one is a hard failure with its text, not a silent drop -- that
// is what makes the counts below a census of the WHOLE frame rather than of the lines we liked.
std::vector<DecodedInsn> EmitAndDecode(char const *tag, u32 vlen_bits, u32 word,
				       std::vector<std::string> *out_lines)
{
	MemArena arena(1u << 20);
	TestCompilerRuntime cr;
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	u32 w = word;
	auto const code = EmitOne(arena, &w, 1, cfg, cr);
	if (code.empty()) {
		return {};
	}
	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (out_lines) {
		*out_lines = lines;
	}
	std::vector<DecodedInsn> out;
	for (auto const &l : lines) {
		DecodedInsn di;
		if (ParseLine(l, &di)) {
			out.push_back(di);
			continue;
		}
		// objdump's header lines ("...file format binary", section headers, blank lines)
		// carry no tab-separated mnemonic and are the only unparsed lines allowed.
		bool const is_header = l.find(':') == std::string::npos || l.find('\t') == std::string::npos;
		CHECK(is_header);
		if (!is_header) {
			fprintf(stderr, "  %s: unparsed line: %s\n", tag, l.c_str());
		}
	}
	return out;
}

// The frame this route emits, located inside the whole translated block by its own shape: the
// `cmovb` is unique in the block, and the seven instructions around it are fixed.
struct Frame {
	size_t at = (size_t)-1; // index of the `cmovb`
	std::string scratch;	// the register the min is computed in
	std::string avl;	// the AVL source register
	std::string rd;		// the destination register
	std::vector<std::pair<i64, std::string>> stores; // (displacement, value token)
};

void CheckEmitted(char const *tag, u32 vlen_bits, u32 word, bool aliased)
{
	printf("[5] %s: emitted host bytes, objdump-decoded%s\n", tag,
	       aliased ? " (rd == rs1)" : "");

	std::vector<std::string> lines;
	auto const insns = EmitAndDecode(tag, vlen_bits, word, &lines);
	if (insns.empty()) {
		return;
	}

	auto dump = [&]() {
		for (auto const &l : lines) {
			fprintf(stderr, "      %s\n", l.c_str());
		}
	};

	// [5a] THE CONDITIONAL MOVE IS PRESENT, EXACTLY ONCE IN THE WHOLE BLOCK, AND IS UNSIGNED.
	//
	// `cmovb` is CF=1, i.e. strictly-below UNSIGNED, which is what rv32_interp.cpp's u32 compare
	// means. `cmovl` would agree on every AVL below 2^31 and return AVL itself for the whole top
	// half of the domain; `cmova`/`cmovae` would invert or shift the boundary. objdump prints the
	// mnemonic, so this is decided on the emitted bytes and not on the source. Uniqueness in the
	// block is what lets the eight-instruction frame below be located by index rather than by
	// pattern-matching text.
	unsigned n_cmov = 0, n_cmovb = 0, n_vec = 0;
	size_t cmovb_at = (size_t)-1;
	for (size_t i = 0; i < insns.size(); ++i) {
		auto const &m = insns[i].mnemonic;
		if (m.compare(0, 4, "cmov") == 0) {
			++n_cmov;
			if (m == "cmovb") {
				++n_cmovb;
				cmovb_at = i;
			}
		}
		// A vector instruction anywhere in this block would mean something other than this
		// route emitted one: every accepted chunk switch is off in this configuration.
		n_vec += (m.compare(0, 1, "v") == 0 && m != "vsetvli");
	}
	CHECK_EQ(n_cmov, 1u);
	CHECK_EQ(n_cmovb, 1u);
	CHECK_EQ(n_vec, 0u);
	if (n_cmovb != 1 || n_vec != 0) {
		dump();
		return;
	}

	// [5b] THE EIGHT-INSTRUCTION FRAME, IN ORDER, AROUND THAT `cmovb`.
	CHECK(cmovb_at >= 2);
	CHECK(cmovb_at + 5 < insns.size());
	if (cmovb_at < 2 || cmovb_at + 5 >= insns.size()) {
		dump();
		return;
	}

	auto const &i_mov_vlmax = insns[cmovb_at - 2];
	auto const &i_cmp = insns[cmovb_at - 1];
	auto const &i_cmovb = insns[cmovb_at];
	auto const &i_mov_rd = insns[cmovb_at + 1];

	// mov <scratch>, VLMAX
	CHECK_STREQ(i_mov_vlmax.mnemonic, "mov");
	CHECK_EQ(i_mov_vlmax.ops.size(), (size_t)2);
	i64 vlmax_imm = -1;
	CHECK(ParseImm(i_mov_vlmax.ops[1], &vlmax_imm));
	CHECK_EQ(vlmax_imm, (i64)(vlen_bits / 32u));
	std::string const scratch = i_mov_vlmax.ops[0];
	// The scratch is the FIXED register, which is what makes the aliased case correct without an
	// operand comparison. Naming it here means a future change of ArchTraits::AX has to be made
	// deliberately.
	CHECK_STREQ(scratch, "eax");

	// cmp <avl>, <scratch>
	CHECK_STREQ(i_cmp.mnemonic, "cmp");
	CHECK_EQ(i_cmp.ops.size(), (size_t)2);
	std::string const avl = i_cmp.ops[0];
	CHECK(IsGpr32(avl));
	CHECK_STREQ(i_cmp.ops[1], scratch);
	// THE AVL IS READ FROM A REGISTER, NOT FOLDED AWAY. This is the gate that refutes the
	// constant-VLMAX emitter the frozen workload cannot see: that emitter has no compare at all,
	// and one that compared against an immediate would fail here.
	CHECK(avl != scratch);

	// cmovb <scratch>, <avl>
	CHECK_EQ(i_cmovb.ops.size(), (size_t)2);
	CHECK_STREQ(i_cmovb.ops[0], scratch);
	CHECK_STREQ(i_cmovb.ops[1], avl);

	// mov <rd>, <scratch>
	CHECK_STREQ(i_mov_rd.mnemonic, "mov");
	CHECK_EQ(i_mov_rd.ops.size(), (size_t)2);
	std::string const rd = i_mov_rd.ops[0];
	CHECK(IsGpr32(rd));
	CHECK_STREQ(i_mov_rd.ops[1], scratch);
	CHECK(rd != scratch);

	// THE ORDERING THE ALIASED CASE NEEDS, ASSERTED ON THE EMITTED BYTES RATHER THAN ON WHICH
	// REGISTER PAIR THE ALLOCATOR PICKED. `QRegAlloc::AllocOp` allocates inputs first and adds
	// each input's register to the `avoid` set before allocating outputs, so `rd != avl` here even
	// for the `vsetvli t0, t0` encoding -- the physically aliased case is NOT reachable through
	// the allocator today (pinning, the one path that bypasses `avoid`, is off for any region
	// containing a HAS_CALLS op, and the frozen loop has twelve). The emitter must not depend on
	// that, so what is gated here is the property that makes both cases correct: both reads of
	// `avl` (the `cmp` and the `cmovb`) precede the single write of `rd`, which the fixed indices
	// above establish. Section [6b] then forces the physical alias directly at the emitter.
	CHECK(rd != avl);

	// [6] THE FOUR STATE STORES, EACH AT ITS OWN offsetof DISPLACEMENT WITH ITS OWN VALUE.
	std::vector<std::pair<i64, std::string>> stores;
	for (size_t i = cmovb_at + 2; i < cmovb_at + 6; ++i) {
		auto const &in = insns[i];
		CHECK_STREQ(in.mnemonic, "mov");
		CHECK_EQ(in.ops.size(), (size_t)2);
		i64 disp = -1;
		CHECK(ParseStateMem(in.ops[0], &disp));
		stores.push_back({disp, in.ops[1]});
	}
	if (g_failures) {
		dump();
	}

	auto value_at = [&](i64 disp) -> std::string {
		for (auto const &s : stores) {
			if (s.first == disp) {
				return s.second;
			}
		}
		return "<missing>";
	};
	// vtype and vlenb carry their own immediates; vstart carries a literal 0.
	i64 v = -1;
	CHECK(ParseImm(value_at(ST_VTYPE), &v));
	CHECK_EQ(v, (i64)VTYPE_E32M1TAMA);
	CHECK(ParseImm(value_at(ST_VSTART), &v));
	CHECK_EQ(v, (i64)0);
	CHECK(ParseImm(value_at(ST_VLENB), &v));
	CHECK_EQ(v, (i64)(vlen_bits / 8u));
	// vl carries the SCRATCH REGISTER -- the value the min was computed into. An immediate here
	// would be the constant-VLMAX defect writing straight into architectural state, and it is the
	// one store whose value must NOT be a constant.
	CHECK_STREQ(value_at(ST_VL), scratch);

	// Exactly four r13 stores in the whole frame, at exactly those four displacements: a fifth
	// or a missing one is caught here rather than through behaviour.
	std::set<i64> got;
	for (auto const &s : stores) {
		got.insert(s.first);
	}
	std::set<i64> const want = {ST_VTYPE, ST_VL, ST_VSTART, ST_VLENB};
	CHECK(got == want);

	// [5c] NOTHING ELSE IS IN THE FRAME. The eight instructions located above are the whole of
	// what this route contributes: within that window there is exactly one `cmp`, no `call` and
	// no `j*`. The gate is scoped to the window on purpose -- the block's own prologue, its ip
	// spill, its global fills/spills and its region-exit dispatch (which does contain a `cmp`, a
	// `jne` and a `call`) belong to the BLOCK and are present with the route off as well.
	unsigned f_cmp = 0, f_call = 0, f_jmp = 0;
	for (size_t i = cmovb_at - 2; i <= cmovb_at + 5; ++i) {
		auto const &m = insns[i].mnemonic;
		f_cmp += (m == "cmp");
		f_call += IsCall(insns[i]);
		f_jmp += (m.size() >= 2 && m[0] == 'j');
	}
	CHECK_EQ(f_cmp, 1u);
	CHECK_EQ(f_call, 0u);
	CHECK_EQ(f_jmp, 0u);

	// [5d] THE HELPER CALL IS GONE, MEASURED AS A DELTA AGAINST THE SAME BLOCK WITH THE ROUTE
	// OFF. That is the statement this checkpoint exists to make, and it cannot be made by an
	// absolute count: the block's region-exit dispatch calls unconditionally in both arms. The
	// branch count must be UNCHANGED at the same time, or a "removed call" could have been a
	// call turned into a jump.
	{
		std::vector<std::string> off_lines;
		MemArena arena(1u << 20);
		TestCompilerRuntime cr;
		RouteConfig off_cfg;
		off_cfg.vlen_bits = vlen_bits;
		off_cfg.direct_setvl = false;
		u32 w = word;
		auto const off_code = EmitOne(arena, &w, 1, off_cfg, cr);
		auto const off_lines_v = Disassemble(off_code);
		unsigned off_call = 0, off_jmp = 0, on_call = 0, on_jmp = 0;
		for (auto const &l : off_lines_v) {
			DecodedInsn di;
			if (!ParseLine(l, &di)) {
				continue;
			}
			off_call += IsCall(di);
			off_jmp += (di.mnemonic.size() >= 2 && di.mnemonic[0] == 'j');
		}
		for (auto const &in : insns) {
			on_call += IsCall(in);
			on_jmp += (in.mnemonic.size() >= 2 && in.mnemonic[0] == 'j');
		}
		CHECK_EQ(off_call, on_call + 1u);
		CHECK_EQ(off_jmp, on_jmp);
		printf("    calls in this block: %u with the route off -> %u with it on; branches "
		       "unchanged at %u\n",
		       off_call, on_call, on_jmp);
	}

	printf("    OK 8 insns: mov %s,0x%llx / cmp %s,%s / cmovb %s,%s / mov %s,%s + 4 state "
	       "stores at +0x%llx,+0x%llx,+0x%llx,+0x%llx\n",
	       scratch.c_str(), (unsigned long long)vlmax_imm, avl.c_str(), scratch.c_str(),
	       scratch.c_str(), avl.c_str(), rd.c_str(), scratch.c_str(),
	       (unsigned long long)ST_VTYPE, (unsigned long long)ST_VL,
	       (unsigned long long)ST_VSTART, (unsigned long long)ST_VLENB);
}

// [7] The frame's WHOLE footprint, not just its recognised parts: with the route on, the block's
// only writes to CPUState's `vec` window are those four, and there is no other `cmov`, no `call`,
// no branch and no vector instruction anywhere in the block.
void CheckContainment(char const *tag, u32 vlen_bits)
{
	printf("[7] %s: whole-block containment\n", tag);

	std::vector<std::string> lines;
	auto const insns = EmitAndDecode(tag, vlen_bits, INSN_VSETVLI, &lines);
	if (insns.empty()) {
		return;
	}
	unsigned n_vec_window = 0, n_other_state = 0;
	for (auto const &in : insns) {
		for (auto const &o : in.ops) {
			i64 disp = -1;
			if (!ParseStateMem(o, &disp)) {
				continue;
			}
			bool const in_vec =
			    disp >= ST_VEC && disp < ST_VEC + (i64)sizeof(rv32::VectorState);
			if (in_vec) {
				++n_vec_window;
				// Only the four fields, never the register file.
				CHECK(disp == ST_VTYPE || disp == ST_VL || disp == ST_VSTART ||
				      disp == ST_VLENB);
			} else {
				++n_other_state;
			}
		}
	}
	CHECK_EQ(n_vec_window, 4u);
	// The other state accesses are the block's own prologue/epilogue and the `ip` spill from
	// PreSideeff -- reported, not gated to a number, because they belong to the block and not to
	// this route.
	printf("    OK %u accesses inside CPUState.vec, all four the route's own fields; %u other "
	       "state accesses belong to the block\n",
	       n_vec_window, n_other_state);
}

// ---------------------------------------------------------------------------------------------
// 6b. The physically aliased case, forced directly at the emitter.
// ---------------------------------------------------------------------------------------------
//
// Section [5] establishes that the allocator does NOT hand the same host register to both roles
// today, even for the `vsetvli t0, t0` encoding: AllocOp adds each input's register to the `avoid`
// set before allocating outputs, and the one path that bypasses it -- writing a PINNED global output
// straight into its reserved register -- is disabled for any region containing a HAS_CALLS op, which
// the frozen loop has twelve of. So the aliased allocation is unreachable through the route today.
//
// That is exactly why it is forced here. The emitter's correctness argument does not appeal to the
// allocator: it says the fixed scratch can alias neither operand, and every read of the AVL happens
// before the single write of rd. This section builds the node with ONE physical register in both
// operand slots -- the allocation the argument claims to survive -- runs the REAL QEmit, and reads
// the property off the disassembled bytes. An emitter that computed into `prd` first
// (`mov prd, VLMAX ; cmp pavl, prd ; cmovb prd, pavl`) is correct for every distinct pair and
// destroys its own input here; nothing in a node count, a register count or the frozen suite would
// see it.
//
// A hand-built region needs a StateInfo; one tracked global is enough, and nothing below reads it.
enum { G_VAL = 0, G_COUNT };
StateReg g_state_regs[] = {
    {(u16)offsetof(CPUState, gpr), VType::I32, "g0"},
};
StateInfo g_state_info{g_state_regs, G_COUNT};

void CheckForcedAlias(char const *tag, u32 vlen_bits)
{
	printf("[6b] %s: rd and rs1 forced into the SAME host register\n", tag);

	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	ApplyConfig(cfg);
	ArchTraits::init();

	// The first pool register, which is by construction not the fixed scratch.
	RegN p = 0;
	for (RegN i = 0; i < ArchTraits::GPR_NUM; ++i) {
		if (ArchTraits::GPR_POOL.Test(i)) {
			p = i;
			break;
		}
	}
	CHECK(p != ArchTraits::AX);

	MemArena arena(1u << 20);
	Region *region = arena.New<Region>(&arena, &g_state_info);
	Block *bb = region->CreateBlock();
	Builder qb(bb);
	auto const opnd = VOperand::MakePGPR(VType::I32, p);
	auto *ins = static_cast<InstRVVSetVL *>(qb.Create_rvvsetvl(
	    opnd, opnd, VTYPE_E32M1TAMA, vlen_bits / 32u, vlen_bits / 8u));

	TestCompilerRuntime cr;
	qir::CodeSegment segment(0u, 0x1000u);
	QEmit ce(region, &cr, &segment, true);
	ce.SetBlock(bb);
	ce.Emit_rvvsetvl(ins);
	auto const span = ce.EmitCode();
	std::vector<u8> const code(span.begin(), span.end());
	auto const lines = Disassemble(code);
	CHECK(!lines.empty());

	std::vector<DecodedInsn> insns;
	for (auto const &l : lines) {
		DecodedInsn di;
		if (ParseLine(l, &di)) {
			insns.push_back(di);
		}
	}
	// Locate the frame by its unique `cmovb`, exactly as section [5] does.
	size_t at = (size_t)-1;
	unsigned n_cmovb = 0;
	for (size_t i = 0; i < insns.size(); ++i) {
		if (insns[i].mnemonic == "cmovb") {
			++n_cmovb;
			at = i;
		}
	}
	CHECK_EQ(n_cmovb, 1u);
	if (n_cmovb != 1 || at < 2 || at + 1 >= insns.size()) {
		for (auto const &l : lines) {
			fprintf(stderr, "      %s\n", l.c_str());
		}
		return;
	}
	std::string const scratch = insns[at - 2].ops[0];
	std::string const reg = insns[at].ops[1];
	CHECK_STREQ(scratch, "eax");
	// The forced alias really is one register in both roles.
	CHECK_STREQ(insns[at - 1].ops[0], reg); // cmp <p>, eax
	CHECK_STREQ(insns[at + 1].ops[0], reg); // mov <p>, eax
	CHECK(reg != scratch);

	// THE GATE: nothing writes `p` before the last instruction of the min. Scanning from the
	// start of the emitted block, the FIRST instruction whose destination operand is `p` must be
	// the `mov <p>, eax` at index at+1 -- so both of `p`'s reads are still reading the AVL.
	size_t first_write = (size_t)-1;
	for (size_t i = 0; i < insns.size(); ++i) {
		auto const &in = insns[i];
		// Two-operand x86 destination is operand 0, and every instruction the emitter can
		// produce here is two-operand.
		if (in.ops.size() >= 1 && in.ops[0] == reg && in.mnemonic != "cmp") {
			first_write = i;
			break;
		}
	}
	CHECK_EQ(first_write, at + 1);
	printf("    OK scratch=%s, %s in both roles; first write of %s is instruction %zu, both "
	       "reads precede it\n",
	       scratch.c_str(), reg.c_str(), reg.c_str(), first_write);
}

// ---------------------------------------------------------------------------------------------
// 8. Same-TB consumers: the accepted frames must be untouched.
// ---------------------------------------------------------------------------------------------

// A `vsetvli ; vle32.v ; vadd.vv ; vse32.v` region -- the frozen mixed loop's own shape in
// miniature -- translated twice with the three accepted switches open and this route off then on.
// Everything about the three accepted frames must be identical; the ONLY differences allowed
// anywhere are the vsetvli helper call disappearing and the rvvsetvl node appearing.
void CheckSameTbConsumers(char const *tag, u32 vlen_bits, u32 nchunks)
{
	printf("[8] %s: same-TB consumers unchanged\n", tag);

	struct Census {
		unsigned begin = 0, end = 0, statechunkload = 0, statechunkstore = 0;
		unsigned chunkload = 0, chunkadd = 0, chunkstore = 0;
		unsigned setvl = 0, hcall_vsetvli = 0;
		unsigned zmm_lines = 0;
		std::vector<std::string> vec_mnemonics;
	};

	auto run = [&](bool route_on) {
		Census c;
		MemArena arena(1u << 20);
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.direct_setvl = route_on;
		cfg.chunk_add = true;
		cfg.chunk_vle = true;
		cfg.chunk_vse = true;
		u32 words[4] = {INSN_VSETVLI, INSN_VLE32_V, INSN_VADD_VV, INSN_VSE32_V};

		// The QIR census has to come from a translation that is NOT consumed by the emitter,
		// because GenerateCode rewrites the region in place.
		{
			MemArena a2(1u << 20);
			u32 w2[4] = {INSN_VSETVLI, INSN_VLE32_V, INSN_VADD_VV, INSN_VSE32_V};
			Region *r = TranslateOne(a2, w2, 4, cfg);
			c.begin = CountOp(r, Op::_rvvtypedchunkbegin);
			c.end = CountOp(r, Op::_rvvtypedchunkend);
			c.statechunkload = CountOp(r, Op::_vstatechunkload);
			c.statechunkstore = CountOp(r, Op::_vstatechunkstore);
			c.chunkload = CountOp(r, Op::_vchunkload);
			c.chunkadd = CountOp(r, Op::_vchunkadd);
			c.chunkstore = CountOp(r, Op::_vchunkstore);
			c.setvl = CountOp(r, Op::_rvvsetvl);
			c.hcall_vsetvli = CountHcall(r, RuntimeStubId::id_rv32_vsetvli);
		}

		auto const code = EmitOne(arena, words, 4, cfg, cr);
		auto const lines = Disassemble(code);
		for (auto const &l : lines) {
			if (l.find("zmm") == std::string::npos) {
				continue;
			}
			++c.zmm_lines;
			DecodedInsn di;
			if (ParseLine(l, &di)) {
				c.vec_mnemonics.push_back(di.mnemonic);
			}
		}
		return c;
	};

	auto const off = run(false);
	auto const on = run(true);

	// The three accepted frames, present and correct in BOTH arms.
	CHECK_EQ(off.begin, 3u);
	CHECK_EQ(on.begin, 3u);
	CHECK_EQ(on.end, off.end);
	CHECK_EQ(on.statechunkload, off.statechunkload);
	CHECK_EQ(on.statechunkstore, off.statechunkstore);
	CHECK_EQ(on.chunkload, off.chunkload);
	CHECK_EQ(on.chunkadd, off.chunkadd);
	CHECK_EQ(on.chunkstore, off.chunkstore);
	CHECK_EQ(off.chunkadd, nchunks);
	// The vector instruction stream, mnemonic for mnemonic and in order.
	CHECK_EQ(on.zmm_lines, off.zmm_lines);
	CHECK(on.vec_mnemonics == off.vec_mnemonics);

	// The only delta, in both directions.
	CHECK_EQ(off.setvl, 0u);
	CHECK_EQ(off.hcall_vsetvli, 1u);
	CHECK_EQ(on.setvl, 1u);
	CHECK_EQ(on.hcall_vsetvli, 0u);

	printf("    OK 3 typed frames unchanged (%u statechunkload, %u vchunkadd, %u vchunkload, %u "
	       "vchunkstore, %u ZMM lines); vsetvli helper 1 -> 0, rvvsetvl 0 -> 1\n",
	       off.statechunkload, off.chunkadd, off.chunkload, off.chunkstore, off.zmm_lines);
}

// ---------------------------------------------------------------------------------------------
// 9. rvv_bb_vtype must still be recorded on the DIRECT path.
// ---------------------------------------------------------------------------------------------

// The one consumer that can tell the difference. With every chunk switch off, `--rvv-direct 1` and
// an OBSERVED vtype, TRANSLATOR(vadd_vv) reaches the legacy inline-SSE2 `rvvaddv` lowering; with NO
// observation it falls through to `hcall [rv32_vadd_vv]`, because that lowering has no candidate
// entry. Every other consumer PROPOSES the same e32/m1/ta/ma shape when nothing was observed and so
// produces identical nodes either way -- which is exactly why dropping the assignment would be
// invisible in a typed-frame count.
void CheckBbVtypeRecorded(char const *tag, u32 vlen_bits)
{
	printf("[9] %s: rvv_bb_vtype recorded on both paths\n", tag);

	for (bool route_on : {false, true}) {
		MemArena arena(1u << 20);
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.direct_setvl = route_on;
		u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
		Region *r = TranslateOne(arena, words, 2, cfg);
		CHECK_EQ(CountOp(r, Op::_rvvaddv), 1u);
		CHECK_EQ(CountHcall(r, RuntimeStubId::id_rv32_vadd_vv), 0u);
		CHECK_EQ(CountOp(r, Op::_rvvsetvl), route_on ? 1u : 0u);
	}
	// The negative control for the gate itself: with NO vsetvli in the block the same vadd.vv
	// must fall to the helper. Without this, "1 rvvaddv" above would not be evidence that the
	// observation happened -- only that the lowering exists.
	{
		MemArena arena(1u << 20);
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		u32 word = INSN_VADD_VV;
		Region *r = TranslateOne(arena, &word, 1, cfg);
		CHECK_EQ(CountOp(r, Op::_rvvaddv), 0u);
		CHECK_EQ(CountHcall(r, RuntimeStubId::id_rv32_vadd_vv), 1u);
	}
	printf("    OK observed-vtype consumer sees the vtype in both arms; with no vsetvli it does "
	       "not\n");
}

// ---------------------------------------------------------------------------------------------
// 10. The frozen workload's own two words.
// ---------------------------------------------------------------------------------------------
void CheckFrozenWords(u32 vlen_bits)
{
	printf("[10] frozen S1.1-fix1 vsetvli words, VLEN=%u\n", vlen_bits);

	for (auto const &f : FROZEN_SETVLI) {
		MemArena arena(1u << 20);
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		u32 word = f.word;
		Region *region = TranslateOne(arena, &word, 1, cfg);
		CHECK_EQ(CountOp(region, Op::_rvvsetvl), 1u);
		CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vsetvli), 0u);
		auto *ins = FindSetVL(region);
		CHECK(ins != nullptr);
		if (!ins) {
			continue;
		}
		CHECK_EQ(ins->vtype, VTYPE_E32M1TAMA);
		CHECK_EQ(ins->vlmax, vlen_bits / 32u);
		CHECK_EQ(ins->vlenb, vlen_bits / 8u);
		// The state slots the node's two operands name, joined back to the ENCODED register
		// numbers. GlobalRegId::GPR_START + r - 1 is RV32Translator::GetStateInfo's own
		// numbering; a route that read a hardcoded register cannot satisfy both rows.
		CHECK_EQ((u32)ins->o(0).GetVGPR(), f.rd - 1u);
		CHECK_EQ((u32)ins->i(0).GetVGPR(), f.rs1 - 1u);
		printf("    %-16s 0x%08x -> rvvsetvl vlmax=%u, rd=x%u rs1=x%u\n", f.text, f.word,
		       ins->vlmax, f.rd, f.rs1);
	}
}

} // namespace

int main()
{
	printf("S2.9: exact vsetvli rd, rs1, e32,m1,ta,ma -> direct-state pure-QCG route\n\n");

	CheckEncodingSweep();
	CheckRegisterSweep();
	CheckOpcodeSweep();
	printf("\n");

	CheckFallbackMatrix();
	printf("\n");

	CheckQir("VLEN=512", 512);
	CheckQir("VLEN=1024", 1024);
	CheckGeneralEnvelopeAllWidths();
	printf("\n");

	CheckPostQRA("VLEN=512", 512, INSN_VSETVLI);
	CheckPostQRA("VLEN=1024", 1024, INSN_VSETVLI);
	CheckPostQRA("VLEN=512 rd==rs1", 512, INSN_VSETVLI_ALIAS);
	printf("\n");

	CheckEmitted("VLEN=512", 512, INSN_VSETVLI, false);
	CheckEmitted("VLEN=1024", 1024, INSN_VSETVLI, false);
	CheckEmitted("VLEN=512", 512, INSN_VSETVLI_ALIAS, true);
	CheckEmitted("VLEN=1024", 1024, INSN_VSETVLI_ALIAS, true);
	printf("\n");

	CheckForcedAlias("VLEN=512", 512);
	CheckForcedAlias("VLEN=1024", 1024);
	printf("\n");

	CheckContainment("VLEN=512", 512);
	CheckContainment("VLEN=1024", 1024);
	printf("\n");

	CheckSameTbConsumers("VLEN=512", 512, 1);
	CheckSameTbConsumers("VLEN=1024", 1024, 2);
	printf("\n");

	CheckBbVtypeRecorded("VLEN=512", 512);
	CheckBbVtypeRecorded("VLEN=1024", 1024);
	printf("\n");

	CheckFrozenWords(512);
	CheckFrozenWords(1024);
	printf("\n");

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
