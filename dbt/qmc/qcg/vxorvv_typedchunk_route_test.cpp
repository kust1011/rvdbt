// S2.2: the exact unmasked `vxor.vv` typed V512 chunk route, verified mechanically at four levels
// -- decoder, constructed QIR, post-QRegAlloc allocation, and independently disassembled emitted
// host bytes.
//
// This file is the vxor twin of qmc/qcg/vsubvv_typedchunk_route_test.cpp and deliberately keeps its
// structure, so the four routed chunk ops are checked to the same depth. What it does NOT keep is
// that file's central obligation, and what it adds instead is this route's own.
//
// WHAT THIS ROUTE DOES *NOT* NEED. S2.1's whole extra apparatus exists because subtraction does not
// commute, so an emitter that exchanged its two inputs would be structurally perfect and
// numerically negated. `vxor.vv` commutes: `a ^ b == b ^ a` in every lane, for every SEW, with no
// flags and no carries. So this file makes NO correctness claim from operand order, and does not
// contain S2.1's operand-role-exchange section -- that section would be untestable here, because
// both orders are the same function. Where S2.1 compares an ORDERED pair this file compares a SET,
// exactly as the accepted add/mul tests do, and the property it is actually asserting is
// per-chunk containment: each chunk's xor reads that chunk's own two loads and nothing else.
//
// WHAT THIS ROUTE DOES NEED, AND ITS ARITHMETIC SIBLINGS DO NOT: proof that the decoder captured
// exactly one encoding. `vxor.vv` leaves the generic `vialu` family, and its two nearest neighbours
// sit at ADJACENT funct6 values:
//
//     vand.vv  funct6 = 0b001001      Op::_vand_vv since S2.4 (a route of its OWN, switched off here)
//     vor.vv   funct6 = 0b001010      Op::_vor_vv since S2.3 (a route of its OWN, switched off here)
//     vxor.vv  funct6 = 0b001011  ->  Op::_vxor_vv        (this route)
//
// All three have identical operand shapes, so a predicate written with `<=`, with a mask, or with a
// mistyped constant would hand a guest AND or OR to an XOR emitter -- right chunk count, right
// windows, right def-use, right guard, right counters, and every lane wrong. Section [1] therefore
// does not check a hand-picked list: it sweeps the ENTIRE OP-V encoding space (8 funct3 groups x 64
// funct6 values x vm) and requires exactly one combination to reach `Op::_vxor_vv`. Section [7]
// closes the same hazard at the other end of the pipeline, on emitted bytes: the sibling encodings
// are pushed through the real code generator and must produce no ZMM instruction at all.
//
// S2.3 gave vor.vv its own op and its own switch, which does not weaken any of the above: the sweep
// now requires FIVE ops to be reached by exactly one encoding each (including vor_vv), so a
// predicate that stole the neighbour's encoding fails as `vxor_vv` hits 2 AND `vor_vv` hits 0. With
// this file's configuration the or route's switch is OFF, so section [7]'s vor.vv arm still expects
// no ZMM instruction at all -- it is testing that THIS route does not capture it, not that the
// encoding has no route anywhere.
//
//     RVV:  vxor.vv vd, vs2, vs1   =>   vd[i] = vs2[i] ^ vs1[i]
//           (rv32_vector_lower.h vialu_apply, VF6_VXOR)
//     QIR:  vchunkxor d, in0, in1  =>   d = in0 ^ in1        (qir.h InstVChunkXor)
//     x86:  vpxord    d, s0,  s1   =>   d = s0  ^ s1        (EVEX, AVX512F, unmasked)
//
// WHAT THIS FILE PROVES
//
//   1. DECODER. Exactly one encoding class in the whole OP-V space reaches the new op: funct3=OPIVV
//      / funct6=VF6_VXOR / vm=1. The sweep also re-checks that the four other splits (vadd.vv,
//      vsub.vv, vmul.vv and, since S2.3, vor.vv) are still reached by exactly one encoding each, so
//      no checkpoint can have widened or stolen one of them.
//   2. QIR. At VLEN=512 the admitted instruction becomes ONE 512-bit chunk (4 typed ops); at
//      VLEN=1024 TWO chunks (8 typed ops), in load-major order, at the exact low/high 64-byte
//      CPUState windows, with per-chunk def-use and no cross-chunk edge. The body op is
//      Op::_vchunkxor with sew_bytes=4 -- it is not the add, the subtract or the multiply wearing a
//      different name.
//   3. FALLBACK. Every forbidden shape keeps the pre-existing helper: zero typed nodes and exactly
//      one `hcall [rv32_vialu]`. Each forbidden condition is exercised on its own axis, so a single
//      over-broad admission cannot hide behind another still-closed gate.
//   4. QRA. Three distinct physical VPRs at VLEN=512, six at VLEN=1024, all out of VPR_POOL, with
//      per-chunk containment surviving allocation, and no allocator-inserted V512 mov inside the
//      frame.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits `vpxord` -- not vpaddd, not vpsubd, not
//      vpmulld, not the bitwise siblings vpandd/vpord, not a scalar sequence -- with the exact
//      allocated ZMM operands, the exact state displacements, and at VLEN=1024 two chunks whose
//      register sets are disjoint in the externally decoded bytes.
//   6. OVERLAP. vd==vs2, vd==vs1 and vd==vs1==vs2 each still emit both of a chunk's source loads
//      before that chunk's destination store. The frozen S1.1-fix1 workload contains BOTH an
//      overlapping form (kern_xor: v8 = v8 ^ v9) and a fully disjoint one (kern_mix:
//      v12 = v8 ^ v9), and both real words are exercised.
//   7. SIBLING NON-CAPTURE, on emitted bytes. See above.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. Runtime correctness is the xbd evidence's obligation, on a host
//     that actually has AVX-512.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//
// HOST NOTE. RvvQcgTypedXorChunkAdmit's host-feature row is a real __builtin_cpu_supports probe, so
// on a machine without AVX-512F the route would fail closed and there would be nothing to inspect.
// `config::rvv_qcg_typed_chunk_xor_force_emit` bypasses ONLY that probe -- not the architectural
// guard, not the admitted shape -- which is exactly what lets the emitted shape be audited here.
// This is the same device the accepted C2.3a vadd, P3.5a vmul and S2.1 vsub audits used.
//
// INSTRUCTION WORDS. Every encoding below was produced by an explicit field-assembly of the RVV 1.0
// OP-V layout and then independently round-tripped through `llvm-mc -triple=riscv32 -mattr=+v
// -show-encoding`, so the constants are not hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));

// Chunk 0 is a register's low 64-byte half, chunk 1 its high half -- the exact
// `r*VLEN_MAX_BYTES + chunk*64` formula RvvEmitTypedXorChunkGroup uses.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with the disassembly llvm-mc independently produced for it.
// ---------------------------------------------------------------------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma

constexpr u32 INSN_VXOR_VV = 0x2e1101d7u;	   // vxor.vv  v3, v1, v2
constexpr u32 INSN_VXOR_VV_SWAPPED = 0x2e2081d7u;  // vxor.vv  v3, v2, v1   (vs2/vs1 exchanged)
constexpr u32 INSN_VXOR_VV_D_EQ_S2 = 0x2e3101d7u;  // vxor.vv  v3, v3, v2   (vd == vs2)
constexpr u32 INSN_VXOR_VV_D_EQ_S1 = 0x2e1181d7u;  // vxor.vv  v3, v1, v3   (vd == vs1)
constexpr u32 INSN_VXOR_VV_ALL_SAME = 0x2e3181d7u; // vxor.vv  v3, v3, v3   (vd == vs1 == vs2)
constexpr u32 INSN_VXOR_VV_MASKED = 0x2c1101d7u;   // vxor.vv  v3, v1, v2, v0.t
constexpr u32 INSN_VXOR_VX = 0x2e1141d7u;	   // vxor.vx  v3, v1, sp
constexpr u32 INSN_VXOR_VI = 0x2e1131d7u;	   // vxor.vi  v3, v1, 2
constexpr u32 INSN_VAND_VV = 0x261101d7u;	   // vand.vv  v3, v1, v2   (funct6 001001)
constexpr u32 INSN_VOR_VV = 0x2a1101d7u;	   // vor.vv   v3, v1, v2   (funct6 001010)
constexpr u32 INSN_VMIN_VV = 0x161101d7u;	   // vmin.vv  v3, v1, v2
constexpr u32 INSN_VSUB_VV = 0x0a1101d7u;	   // vsub.vv  v3, v1, v2
constexpr u32 INSN_VADD_VV = 0x021101d7u;	   // vadd.vv  v3, v1, v2
constexpr u32 INSN_VMUL_VV = 0x961121d7u;	   // vmul.vv  v3, v1, v2   (OPMVV)
constexpr u32 INSN_VMXOR_MM = 0x6e1121d7u;	   // vmxor.mm v3, v1, v2   (mask logic, OPMVV)

// The two words the frozen S1.1-fix1 guest ELF actually contains (SHA-256
// 67fb07833ed040f7d318c20a85a123ac86d3269bc7ba8a5f4f1ef62c2563cb34, per the accepted S2.0 audit).
// Included so the route is tied to the real workload's encodings, not only to synthetic register
// choices. Unlike the sub's two words -- which are BOTH the vd==vs2 overlap -- these two differ:
// kern_xor overlaps (v8 = v8 ^ v9) and kern_mix does not (v12 = v8 ^ v9), so the frozen workload
// exercises both the aliasing and the fully disjoint destination form.
constexpr u32 INSN_VXOR_VV_S11_KERN = 0x2e848457u; // vxor.vv v8, v8, v9   (kern_xor, x7 unrolled)
constexpr u32 INSN_VXOR_VV_S11_MIX = 0x2e848657u;  // vxor.vv v12, v8, v9  (kern_mix)

constexpr u32 VS2_REG = 1; // v1
constexpr u32 VS1_REG = 2; // v2
constexpr u32 VD_REG = 3;  // v3

// ---------------------------------------------------------------------------------------------
// 1. Decoder admission: an exhaustive sweep of the OP-V encoding space.
// ---------------------------------------------------------------------------------------------

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

char const *OpName(rv32::insn::Op op)
{
	using Op32 = rv32::insn::Op;
	switch (op) {
	case Op32::_vxor_vv:
		return "vxor_vv";
	case Op32::_vor_vv:
		return "vor_vv";
	case Op32::_vsub_vv:
		return "vsub_vv";
	case Op32::_vadd_vv:
		return "vadd_vv";
	case Op32::_vmul_vv:
		return "vmul_vv";
	case Op32::_vialu:
		return "vialu";
	case Op32::_vmlogic:
		return "vmlogic";
	case Op32::_vimul:
		return "vimul";
	default:
		return "other";
	}
}

// Assemble one OP-V word with the register fields this file uses throughout (vd=v3, vs2=v1,
// vs1/rs1/imm=v2). The sweep varies ONLY funct3, funct6 and vm, so a hit is attributable to the
// encoding class and not to a register choice.
constexpr u32 MakeOpV(u32 funct6, u32 vm, u32 funct3)
{
	return (funct6 << 26) | (vm << 25) | (VS2_REG << 20) | (VS1_REG << 15) | (funct3 << 12) |
	       (VD_REG << 7) | 0b1010111u;
}

// THE CENTRAL DECODER GATE. Sweep every (funct3, funct6, vm) triple of the OP-V major opcode and
// count which reach each of the six split ops. Exactly one triple may reach each.
//
// This is stronger than the hand-written negative list S2.1 used, and it is stronger in the
// direction this route actually needs: a list can only rule out the encodings someone thought to
// write down, while the hazard here is that funct6 0b001001 (vand.vv) or 0b001010 (vor.vv) -- the
// two values immediately below vxor's -- get captured by an off-by-one predicate. A sweep cannot
// miss them, and it also proves this checkpoint did not perturb the accepted splits. Since S2.3 and
// S2.4 gave those two neighbours routes of their own, the sweep runs the other way too: it is now
// this file's check that NEITHER of them has taken THIS route's encoding.
void CheckDecoderSweep()
{
	using Op32 = rv32::insn::Op;
	printf("  decoder sweep: 8 funct3 x 64 funct6 x 2 vm = 1024 OP-V encodings\n");

	struct Split {
		char const *name;
		Op32 op;
		u32 want_funct3, want_funct6, want_vm;
		unsigned hits = 0;
		u32 hit_word = 0;
	};
	Split splits[] = {
	    {"vxor_vv", Op32::_vxor_vv, 0b000, 0b001011, 1, 0, 0}, // this file's route
	    {"vadd_vv", Op32::_vadd_vv, 0b000, 0b000000, 1, 0, 0}, // C2, must be untouched
	    {"vsub_vv", Op32::_vsub_vv, 0b000, 0b000010, 1, 0, 0}, // S2.1, must be untouched
	    {"vmul_vv", Op32::_vmul_vv, 0b010, 0b100101, 1, 0, 0}, // P3.5a, must be untouched
	    // S2.3's route, one funct6 value BELOW this file's. Swept here for the same reason this
	    // file's own op is swept from vorvv_typedchunk_route_test: the two encodings are
	    // adjacent, so each route must prove the other did not absorb its encoding.
	    {"vor_vv", Op32::_vor_vv, 0b000, 0b001010, 1, 0, 0}, // S2.3, must be untouched
	    // S2.4's route, two funct6 values below this file's, swept for the same reason: with all
	    // three adjacent bitwise encodings routed, each route's sweep is what proves none of the
	    // other two absorbed its encoding.
	    {"vand_vv", Op32::_vand_vv, 0b000, 0b001001, 1, 0, 0}, // S2.4, must be untouched
	};

	for (u32 funct3 = 0; funct3 < 8; ++funct3) {
		for (u32 funct6 = 0; funct6 < 64; ++funct6) {
			for (u32 vm = 0; vm < 2; ++vm) {
				u32 const word = MakeOpV(funct6, vm, funct3);
				Op32 const got = DecodeWord(word);
				for (auto &s : splits) {
					if (got == s.op) {
						++s.hits;
						s.hit_word = word;
						if (funct3 != s.want_funct3 ||
						    funct6 != s.want_funct6 || vm != s.want_vm) {
							fprintf(stderr,
								"  sweep: %s also reached by funct3=%u "
								"funct6=0b%06u vm=%u (0x%08x)\n",
								s.name, funct3, funct6, vm, word);
						}
					}
				}
			}
		}
	}
	for (auto const &s : splits) {
		CHECK_EQ(s.hits, 1u);
		CHECK_EQ(s.hit_word, MakeOpV(s.want_funct6, s.want_vm, s.want_funct3));
		printf("    %-8s reached by exactly %u encoding (0x%08x, funct3=%u funct6=0x%02x vm=%u)\n",
		       s.name, s.hits, s.hit_word, s.want_funct3, s.want_funct6, s.want_vm);
	}

	// And the specific neighbours, named, so a reader does not have to trust the counter alone.
	// These are the two encodings an off-by-one predicate would have swallowed. Both now have ops
	// of their own -- vor.vv since S2.3, vand.vv since S2.4 -- each with its own switch, off in
	// this file. Both are still "not captured by the xor route", which is what this section is for
	// -- and the sweep above separately proves each is reached by exactly one encoding.
	struct Neighbour {
		char const *name;
		u32 funct6;
		Op32 want;
	} const neighbours[] = {
	    {"vand.vv (funct6 001001)", 0b001001, Op32::_vand_vv},
	    {"vor.vv  (funct6 001010)", 0b001010, Op32::_vor_vv},
	};
	for (auto const &n : neighbours) {
		u32 const word = MakeOpV(n.funct6, 1, 0b000);
		Op32 const got = DecodeWord(word);
		CHECK(got == n.want);
		CHECK(got != Op32::_vxor_vv);
		printf("    %-24s 0x%08x -> %s (must be %s, and never vxor_vv)\n", n.name, word,
		       OpName(got), OpName(n.want));
	}
}

// The named-row table, kept alongside the sweep because it documents the axes in guest mnemonics
// and covers encodings OUTSIDE the OP-V major opcode's own funct3/funct6/vm grid at this file's
// register choice -- notably the real frozen-workload words.
void CheckDecoderRows()
{
	printf("  decoder rows: exact unmasked vxor.vv -> Op::_vxor_vv, everything else unchanged\n");
	using Op32 = rv32::insn::Op;

	struct Row {
		char const *name;
		u32 word;
		Op32 want;
	};
	Row const rows[] = {
	    {"vxor.vv v3,v1,v2", INSN_VXOR_VV, Op32::_vxor_vv},
	    {"vxor.vv v3,v2,v1 (swapped)", INSN_VXOR_VV_SWAPPED, Op32::_vxor_vv},
	    {"vxor.vv vd==vs2", INSN_VXOR_VV_D_EQ_S2, Op32::_vxor_vv},
	    {"vxor.vv vd==vs1", INSN_VXOR_VV_D_EQ_S1, Op32::_vxor_vv},
	    {"vxor.vv vd==vs1==vs2", INSN_VXOR_VV_ALL_SAME, Op32::_vxor_vv},
	    {"vxor.vv (S1.1 kern_xor word)", INSN_VXOR_VV_S11_KERN, Op32::_vxor_vv},
	    {"vxor.vv (S1.1 kern_mix word)", INSN_VXOR_VV_S11_MIX, Op32::_vxor_vv},
	    // vm axis: a masked vxor.vv keeps the family handler.
	    {"vxor.vv masked (vm=0)", INSN_VXOR_VV_MASKED, Op32::_vialu},
	    // funct3 axis: the .vx and .vi forms are different groups entirely.
	    {"vxor.vx", INSN_VXOR_VX, Op32::_vialu},
	    {"vxor.vi", INSN_VXOR_VI, Op32::_vialu},
	    // funct6 axis: THE ADJACENT SIBLINGS, and one more of the family. Both siblings'
	    // expectations are their own S2.3/S2.4 ops rather than the family handler -- the substance
	    // of the assertion is unchanged (the xor route must not capture either), so the rows are
	    // updated rather than dropped.
	    {"vand.vv", INSN_VAND_VV, Op32::_vand_vv},
	    {"vor.vv", INSN_VOR_VV, Op32::_vor_vv},
	    {"vmin.vv", INSN_VMIN_VV, Op32::_vialu},
	    // A DIFFERENT family whose mnemonic also says "xor": mask-register logic must not be
	    // captured by a funct6 test that ignored the funct3 group.
	    {"vmxor.mm", INSN_VMXOR_MM, Op32::_vmlogic},
	    // The three pre-existing splits this one is modelled on must be untouched.
	    {"vadd.vv", INSN_VADD_VV, Op32::_vadd_vv},
	    {"vsub.vv", INSN_VSUB_VV, Op32::_vsub_vv},
	    {"vmul.vv", INSN_VMUL_VV, Op32::_vmul_vv},
	};
	for (auto const &r : rows) {
		Op32 const got = DecodeWord(r.word);
		CHECK(got == r.want);
		if (got != r.want) {
			fprintf(stderr, "  decoder: %s (0x%08x) decoded to op %u (%s), expected %u (%s)\n",
				r.name, r.word, (unsigned)got, OpName(got), (unsigned)r.want,
				OpName(r.want));
		} else {
			printf("    ok  %-30s 0x%08x -> %s\n", r.name, r.word, OpName(r.want));
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. The defaults are the fully-open configuration; the fallback table below
// flips exactly one field at a time off it.
struct RouteConfig {
	bool typed_chunk_xor = true;
	bool force_emit = true; // see the file header HOST NOTE
	bool aot_use_llvm = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	u32 vlen_bits = 512;
	u32 vsetvli_word = INSN_VSETVLI_E32M1;
	u32 xor_word = INSN_VXOR_VV;
};

// One region containing exactly the translated vsetvli + vxor.vv pair. Region is arena-allocated,
// so `arena` must outlive it -- both are locals in the caller's own scope.
Region *TranslateOne(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	config::rvv_qcg_typed_chunk_xor = cfg.typed_chunk_xor;
	config::rvv_qcg_typed_chunk_xor_force_emit = cfg.force_emit;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::vlen_bits = cfg.vlen_bits;
	// The four sibling routes' switches stay off throughout: this file must observe the xor route
	// in isolation, and leaving them on would make a stray add/mul/sub/or frame indistinguishable
	// from an xor one. The `or` one is load-bearing rather than defensive, because this file
	// really does translate a vor.vv word (the fallback table and section [7]).
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_diag_chunk = false;

	CompilerJob::IpRangesSet ranges = {{0u, 8u}}; // two 4-byte instructions at ip 0 and 4
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

Region *TranslateCfg(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	words[0] = cfg.vsetvli_word;
	words[1] = cfg.xor_word;
	return TranslateOne(arena, words, cfg);
}

struct Group {
	unsigned n_begin = 0, n_end = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body; // strictly between begin and end, in construction (== emission) order
};

Group FindGroup(Region *region)
{
	Group g;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				++g.n_begin;
				g.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				++g.n_end;
				g.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				open = false;
				continue;
			}
			if (open) {
				g.body.push_back(&ins);
			}
		}
	}
	return g;
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

// Number of hcalls to one specific runtime stub -- the fallback evidence: a non-admitted vxor.vv
// must produce exactly one call to the PRE-EXISTING rv32_vialu helper, not to a new stub.
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

// ---------------------------------------------------------------------------------------------
// 2. Constructed QIR: exact admitted shape.
// ---------------------------------------------------------------------------------------------
void CheckRoute(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 xor_word,
		u32 vs2_reg, u32 vs1_reg, u32 vd_reg)
{
	printf("  %s: vlen=%u expect nchunks=%u vlmax=%u\n", tag, vlen_bits, nchunks, expect_vlmax);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.xor_word = xor_word;
	Region *region = TranslateCfg(arena, words, cfg);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		fprintf(stderr, "  %s: wrong number of typed-chunk frames\n", tag);
		return;
	}

	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	// The fallback is the PRE-EXISTING vialu helper on both frame nodes -- no new stub entered the
	// build with this route, and it is the SAME stub the vsub route falls back to because both
	// encodings come out of the same generic family.
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vialu);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vialu);
	// And there is no leftover helper call for this instruction: the frame replaced it.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vialu), 0u);

	CHECK_EQ(g.body.size(), (size_t)(4 * nchunks));
	if (g.body.size() != 4 * nchunks) {
		return;
	}

	// Load-major: all 2*nchunks source loads, then all nchunks xors, then all nchunks stores.
	// Construction order IS emission order (QSel and QRegAlloc walk each block in list order and
	// only insert around an instruction, never reorder one).
	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * c]->GetOpcode() == Op::_vstatechunkload;
		shape_ok = shape_ok && g.body[2 * c + 1]->GetOpcode() == Op::_vstatechunkload;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * nchunks + c]->GetOpcode() == Op::_vchunkxor;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[3 * nchunks + c]->GetOpcode() == Op::_vstatechunkstore;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: frame body is not load-major vchunkxor\n", tag);
		return;
	}
	// The xor is EXPLICIT in the IR, and it is not one of the three sibling ops wearing a different
	// name.
	CHECK_EQ(CountOp(region, Op::_vchunkxor), nchunks);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkmul), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunksub), 0u);

	std::vector<u32> vregs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(g.body[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(g.body[2 * c + 1]);
		auto *xr = static_cast<InstVChunkXor *>(g.body[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(g.body[3 * nchunks + c]);

		// Exact low/high state windows, disjoint by construction: chunk c of register r covers
		// [r*128 + 64c, r*128 + 64c + 64).
		CHECK_EQ(l_s2->offs, ChunkOffs(vs2_reg, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(vs1_reg, c));
		CHECK_EQ(store->offs, ChunkOffs(vd_reg, c));

		// The SEW the frame was admitted under is recorded on the node even though the emitter
		// does not select on it (qir.h). Gating it here is what keeps a future widening from
		// arriving as a silent reinterpretation of an existing node.
		CHECK_EQ((u32)xr->sew_bytes, 4u);

		// Typed V512 values throughout, in the vector register class.
		CHECK(l_s2->o(0).IsVVPR() && l_s2->o(0).GetType() == VType::V512);
		CHECK(l_s1->o(0).IsVVPR() && l_s1->o(0).GetType() == VType::V512);
		CHECK(xr->o(0).IsVVPR() && xr->o(0).GetType() == VType::V512);
		CHECK(store->i(0).IsVVPR() && store->i(0).GetType() == VType::V512);

		// PER-CHUNK CONTAINMENT, as a SET and deliberately so. xor commutes, so which of the two
		// loads is input 0 carries no meaning and asserting an order here would be asserting a
		// convention, not a property. What DOES matter -- and what this checks -- is that the two
		// inputs are exactly this chunk's own two loads, so no chunk can consume the other
		// chunk's data. (Contrast vsubvv_typedchunk_route_test, where the pair is ordered because
		// subtraction does not commute.)
		u32 const a = l_s2->o(0).GetVVPR(), b = l_s1->o(0).GetVVPR();
		u32 const i0 = xr->i(0).GetVVPR(), i1 = xr->i(1).GetVVPR();
		CHECK((i0 == a && i1 == b) || (i0 == b && i1 == a));
		CHECK_EQ(store->i(0).GetVVPR(), xr->o(0).GetVVPR());

		vregs.push_back(a);
		vregs.push_back(b);
		vregs.push_back(xr->o(0).GetVVPR());
	}

	// No cross-chunk dependency: 3 fresh virtual values per chunk, all distinct. At nchunks=2 that
	// is 6, which is exactly "chunk 1 reuses nothing chunk 0 defined".
	std::sort(vregs.begin(), vregs.end());
	size_t const before = vregs.size();
	vregs.erase(std::unique(vregs.begin(), vregs.end()), vregs.end());
	CHECK_EQ(vregs.size(), before);
	CHECK_EQ(vregs.size(), (size_t)(3 * nchunks));

	printf("  %s: OK %u chunk(s), %zu distinct V512 values, sew4, stub=rv32_vialu\n", tag, nchunks,
	       vregs.size());
}

// ---------------------------------------------------------------------------------------------
// 3. Fallback table: every forbidden shape keeps the helper.
// ---------------------------------------------------------------------------------------------
void CheckFallback(char const *why, RouteConfig const &cfg)
{
	MemArena arena(1u << 20);
	u32 words[2];
	Region *region = TranslateCfg(arena, words, cfg);

	unsigned const n_begin = CountOp(region, Op::_rvvtypedchunkbegin);
	unsigned const n_xor = CountOp(region, Op::_vchunkxor);
	unsigned const n_load = CountOp(region, Op::_vstatechunkload);
	unsigned const n_store = CountOp(region, Op::_vstatechunkstore);
	unsigned const n_helper = CountHcall(region, RuntimeStubId::id_rv32_vialu);

	CHECK_EQ(n_begin, 0u);
	CHECK_EQ(n_xor, 0u);
	CHECK_EQ(n_load, 0u);
	CHECK_EQ(n_store, 0u);
	// Exactly one call to the pre-existing helper -- the instruction still executes, through the
	// path this build already had.
	CHECK_EQ(n_helper, 1u);

	printf("    %-46s typed=0 helper_hcalls=%u  %s\n", why, n_helper,
	       (n_begin == 0 && n_xor == 0 && n_helper == 1) ? "ok" : "FAIL");
}

void CheckFallbackTable()
{
	printf("  fallback: every forbidden shape keeps hcall[rv32_vialu]\n");

	{ // the route's own switch, default off
		RouteConfig c;
		c.typed_chunk_xor = false;
		CheckFallback("--rvv-qcg-typed-chunk-xor off (the default)", c);
	}
	{ // LLVM/AOT backend has no lowering for vchunkxor
		RouteConfig c;
		c.aot_use_llvm = true;
		CheckFallback("aot_use_llvm (LLVM backend)", c);
	}
	{ // --rvv-verify cannot see emitted code
		RouteConfig c;
		c.rvv_verify = true;
		CheckFallback("rvv_verify", c);
	}
	{ // the direct-lowering master switch
		RouteConfig c;
		c.rvv_direct = false;
		CheckFallback("rvv_direct off", c);
	}
	{ // VLEN axis: not a whole number of 512-bit chunks
		for (u32 vlen : {128u, 256u}) {
			RouteConfig c;
			c.vlen_bits = vlen;
			char buf[64];
			snprintf(buf, sizeof(buf), "VLEN=%u (not 512/1024)", vlen);
			CheckFallback(buf, c);
		}
	}
	{ // SEW axis: only e32 is admitted by this checkpoint. Note this is NOT a host-capability
	  // limit -- an unmasked 512-bit vpxord is the same bits at every SEW -- it is an evidence
	  // limit, which is exactly why it has to be tested rather than assumed harmless.
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E64M1;
		CheckFallback("SEW=64 (e64,m1)", c);
	}
	{ // LMUL axis: a register group is more than one register
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E32M2;
		CheckFallback("LMUL=2 (e32,m2)", c);
	}
	{ // encoding axis: masked, .vx, .vi and the sibling family members never even reach this
	  // translator, but the whole-region result is what matters -- no typed node, one vialu call.
	  // vand.vv and vor.vv are the two that matter most: they are funct6-adjacent to vxor.vv. Both
	  // now reach translators of their OWN whose routes are switched off in this configuration, so
	  // they fall through to the same helper by a different mechanism than the masked/.vx/.vi rows.
		struct Row {
			char const *why;
			u32 word;
		} const rows[] = {
		    {"masked vxor.vv (vm=0)", INSN_VXOR_VV_MASKED},
		    {"vxor.vx", INSN_VXOR_VX},
		    {"vxor.vi", INSN_VXOR_VI},
		    {"vand.vv (its own route, switched off)", INSN_VAND_VV},
		    {"vor.vv  (its own route, switched off)", INSN_VOR_VV},
		    {"vmin.vv", INSN_VMIN_VV},
		    {"vsub.vv (its own route, switched off)", INSN_VSUB_VV},
		};
		for (auto const &r : rows) {
			RouteConfig c;
			c.xor_word = r.word;
			CheckFallback(r.why, c);
		}
	}
	{ // vmxor.mm reaches a DIFFERENT family (vmlogic), so its helper is not rv32_vialu at all.
	  // Checked separately rather than folded into the table above, because asserting
	  // "one rv32_vialu hcall" for it would be wrong -- the same trap S2.1 recorded for vssub.vv.
		MemArena arena(1u << 20);
		u32 words[2];
		RouteConfig c;
		c.xor_word = INSN_VMXOR_MM;
		Region *region = TranslateCfg(arena, words, c);
		unsigned const n_begin = CountOp(region, Op::_rvvtypedchunkbegin);
		unsigned const n_xor = CountOp(region, Op::_vchunkxor);
		unsigned const n_vialu = CountHcall(region, RuntimeStubId::id_rv32_vialu);
		unsigned const n_vmlogic = CountHcall(region, RuntimeStubId::id_rv32_vmlogic);
		CHECK_EQ(n_begin, 0u);
		CHECK_EQ(n_xor, 0u);
		CHECK_EQ(n_vialu, 0u);
		CHECK_EQ(n_vmlogic, 1u);
		printf("    %-46s typed=0 vialu_hcalls=%u vmlogic_hcalls=%u  %s\n", "vmxor.mm", n_vialu,
		       n_vmlogic,
		       (n_begin == 0 && n_xor == 0 && n_vialu == 0 && n_vmlogic == 1) ? "ok" : "FAIL");
	}
}

// ---------------------------------------------------------------------------------------------
// 4. Post-QRegAlloc allocation.
// ---------------------------------------------------------------------------------------------
void CheckRoutePostQRA(char const *tag, u32 vlen_bits, u32 nchunks)
{
	printf("  %s (post-QRA): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	Region *region = TranslateCfg(arena, words, cfg);

	// Exactly the two passes qcg::GenerateCode runs before constructing QEmit (qcg.cpp). QEmit and
	// QCodegen are deliberately never constructed here, so no host code exists on any host.
	ArchTraits::init();
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(region, &mri);
	qcg::QRegAllocPass::run(region);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}

	std::vector<Inst *> typed_ops;
	std::vector<Inst *> frame_movs;
	for (auto *ins : g.body) {
		(ins->GetOpcode() == Op::_mov ? frame_movs : typed_ops).push_back(ins);
	}
	// A scalar spill/fill of the preceding vsetvli's dirty a0 global may legally land inside the
	// frame; a V512 mov may not -- that would be a vector spill, fill or cross-class copy.
	for (auto *ins : frame_movs) {
		auto *u = static_cast<InstUnop *>(ins);
		bool const is_v512 = u->o(0).GetType() == VType::V512 || u->i(0).GetType() == VType::V512;
		CHECK(!is_v512);
	}
	CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
	if (typed_ops.size() != 4 * nchunks) {
		return;
	}

	std::vector<RegN> pregs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *xr = static_cast<InstVChunkXor *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);

		CHECK(xr->GetOpcode() == Op::_vchunkxor);
		CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));
		CHECK_EQ(store->offs, ChunkOffs(VD_REG, c));

		bool const allocated = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && xr->o(0).IsPVPR() &&
				       xr->i(0).IsPVPR() && xr->i(1).IsPVPR() && store->i(0).IsPVPR();
		CHECK(allocated);
		if (!allocated) {
			continue;
		}
		for (auto o : {l_s2->o(0), l_s1->o(0), xr->o(0)}) {
			CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
			CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
		}

		// Per-chunk containment again, as a SET, surviving allocation: a chunk whose xor resolved
		// to the OTHER chunk's physical register fails here.
		RegN const a = l_s2->o(0).GetPVPR(), b = l_s1->o(0).GetPVPR();
		RegN const i0 = xr->i(0).GetPVPR(), i1 = xr->i(1).GetPVPR();
		CHECK((i0 == a && i1 == b) || (i0 == b && i1 == a));
		CHECK_EQ(xr->o(0).GetPVPR(), store->i(0).GetPVPR());

		pregs.push_back(a);
		pregs.push_back(b);
		pregs.push_back(xr->o(0).GetPVPR());
	}

	std::sort(pregs.begin(), pregs.end());
	pregs.erase(std::unique(pregs.begin(), pregs.end()), pregs.end());
	CHECK_EQ(pregs.size(), (size_t)(3 * nchunks));

	printf("  %s: OK post-QRA distinct VPRs=%zu frame movs=%zu (zmm", tag, pregs.size(),
	       frame_movs.size());
	for (auto p : pregs) {
		printf(" %u", p);
	}
	printf(")\n");
}

// ---------------------------------------------------------------------------------------------
// 5. Real emission + independent disassembly.
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

struct DecodedVec {
	enum class Kind { LOAD, XOR, STORE } kind;
	std::string mnemonic;
	unsigned dst{}, src0{}, src1{};
	i64 disp{};
	bool has_disp{};
};

// "zmm<N>" -> N, rejecting any unconsumed suffix so a partially-recognised operand is reported as
// unparsed rather than misread.
bool ParseZmm(std::string const &tok, unsigned *out)
{
	if (tok.size() < 4 || tok.compare(0, 3, "zmm") != 0) {
		return false;
	}
	size_t i = 3;
	if (!isdigit((unsigned char)tok[i])) {
		return false;
	}
	unsigned v = 0;
	while (i < tok.size() && isdigit((unsigned char)tok[i])) {
		v = v * 10 + (unsigned)(tok[i] - '0');
		++i;
	}
	*out = v;
	return i == tok.size();
}

// "ZMMWORD PTR [r13+0x<hex>]" -> disp. Only the r13-relative form is accepted: vstatechunkload and
// vstatechunkstore address CPUState through the fixed state register, never a guest address.
bool ParseZmmWordR13(std::string const &tok, i64 *disp)
{
	static std::string const prefix = "ZMMWORD PTR [r13";
	if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}
	size_t i = prefix.size();
	bool const neg = tok[i] == '-';
	if (tok[i] != '+' && tok[i] != '-') {
		return false;
	}
	++i;
	if (tok.compare(i, 2, "0x") != 0) {
		return false;
	}
	i += 2;
	size_t const start = i;
	i64 v = 0;
	while (i < tok.size() && isxdigit((unsigned char)tok[i])) {
		char const c = (char)tolower((unsigned char)tok[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
		++i;
	}
	if (i == start || i >= tok.size() || tok[i] != ']' || i + 1 != tok.size()) {
		return false;
	}
	*disp = neg ? -v : v;
	return true;
}

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

// Parse one objdump Intel-syntax line. Only the two shapes this frame can emit are recognised: a
// two-operand vmovdqu64 against [r13+disp], and a three-register vpxord. Anything else returns
// false; the caller decides whether that is a harmless scalar line or an unaccounted ZMM line.
//
// vpaddd, vpsubd, vpmulld, vpandd and vpord are NOT recognised here on purpose, and for this route
// the bitwise two matter most: an AND or an OR emitted in place of the XOR is precisely the failure
// mode a shared decode family makes possible, and it would be invisible to every structural check.
// Such a line arrives as an unrecognised ZMM-bearing line and fails loudly with its text, rather
// than being silently accepted as "some vector op".
bool ParseLine(std::string const &line, DecodedVec *out)
{
	size_t const tab = line.find('\t');
	if (tab == std::string::npos) {
		return false;
	}
	std::string const rhs = line.substr(tab + 1);
	size_t const sp = rhs.find(' ');
	std::string const mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	std::string const operand_str = sp == std::string::npos ? std::string() : rhs.substr(sp + 1);
	auto const ops = SplitCommas(operand_str);

	if (mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned zr;
		i64 disp;
		if (ParseZmm(ops[0], &zr) && ParseZmmWordR13(ops[1], &disp)) {
			*out = DecodedVec{DecodedVec::Kind::LOAD, mnem, zr, 0, 0, disp, true};
			return true;
		}
		if (ParseZmmWordR13(ops[0], &disp) && ParseZmm(ops[1], &zr)) {
			*out = DecodedVec{DecodedVec::Kind::STORE, mnem, 0, zr, 0, disp, true};
			return true;
		}
		return false;
	}
	if (mnem == "vpxord" && ops.size() == 3) {
		unsigned d, s0, s1;
		if (ParseZmm(ops[0], &d) && ParseZmm(ops[1], &s0) && ParseZmm(ops[2], &s1)) {
			*out = DecodedVec{DecodedVec::Kind::XOR, mnem, d, s0, s1, 0, false};
			return true;
		}
	}
	return false;
}

bool MentionsZmm(std::string const &line)
{
	return line.find("zmm") != std::string::npos;
}

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this checkpoint's
// emission evidence cannot be produced at all.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_s22_emit_XXXXXX";
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
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
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

// Emit one admitted vxor.vv through the real pipeline and return the decoded ZMM census, or an
// empty vector on any structural failure. `vecs` is in emission order.
std::vector<DecodedVec> EmitAndDecode(char const *tag, u32 vlen_bits, u32 nchunks, u32 xor_word,
				      MemArena &arena, u32 (&words)[2], Region **out_region,
				      TestCompilerRuntime &cr)
{
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.xor_word = xor_word;
	Region *region = TranslateCfg(arena, words, cfg);
	*out_region = region;

	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cr, &segment, region, 0);
	CHECK(!code_span.empty());
	if (code_span.empty()) {
		return {};
	}
	std::vector<u8> const code(code_span.begin(), code_span.end());

	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		return {};
	}

	// Every decoded line is accounted for. A line naming a ZMM register that ParseLine does not
	// recognise is a hard failure with the offending text, not a silent drop -- that is what makes
	// the counts below a census rather than a filter.
	std::vector<DecodedVec> vecs;
	for (auto const &l : lines) {
		DecodedVec dv{};
		if (ParseLine(l, &dv)) {
			vecs.push_back(dv);
			continue;
		}
		bool const is_scalar = !MentionsZmm(l);
		CHECK(is_scalar);
		if (!is_scalar) {
			fprintf(stderr, "  %s: unrecognized ZMM-bearing line: %s\n", tag, l.c_str());
		}
	}
	CHECK_EQ(vecs.size(), (size_t)(4 * nchunks));
	if (vecs.size() != 4 * nchunks) {
		for (auto const &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return {};
	}
	return vecs;
}

void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 nchunks, u32 xor_word, u32 vs2_reg,
		       u32 vs1_reg, u32 vd_reg)
{
	printf("  %s (emitted): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2];
	TestCompilerRuntime cruntime;
	Region *region = nullptr;
	auto const vecs =
	    EmitAndDecode(tag, vlen_bits, nchunks, xor_word, arena, words, &region, cruntime);
	if (vecs.empty()) {
		return;
	}

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}
	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vialu);

	std::vector<Inst *> typed_ops;
	for (auto *ins : g.body) {
		if (ins->GetOpcode() != Op::_mov) {
			typed_ops.push_back(ins);
		}
	}
	CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
	if (typed_ops.size() != 4 * nchunks) {
		return;
	}

	for (size_t i = 0; i < vecs.size(); ++i) {
		auto const &v = vecs[i];
		switch (v.kind) {
		case DecodedVec::Kind::LOAD:
			printf("  %s: vec[%zu] LOAD  %s zmm%u <- [r13+0x%llx]\n", tag, i, v.mnemonic.c_str(),
			       v.dst, (unsigned long long)v.disp);
			break;
		case DecodedVec::Kind::XOR:
			printf("  %s: vec[%zu] XOR   %s zmm%u <- zmm%u, zmm%u\n", tag, i, v.mnemonic.c_str(),
			       v.dst, v.src0, v.src1);
			break;
		case DecodedVec::Kind::STORE:
			printf("  %s: vec[%zu] STORE %s [r13+0x%llx] <- zmm%u\n", tag, i,
			       v.mnemonic.c_str(), (unsigned long long)v.disp, v.src0);
			break;
		}
	}

	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * c].kind == DecodedVec::Kind::LOAD;
		shape_ok = shape_ok && vecs[2 * c + 1].kind == DecodedVec::Kind::LOAD;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * nchunks + c].kind == DecodedVec::Kind::XOR;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[3 * nchunks + c].kind == DecodedVec::Kind::STORE;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: decoded order is not load-major\n", tag);
		return;
	}

	std::vector<unsigned> chunk_regs[2];
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *xr = static_cast<InstVChunkXor *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);
		auto const &d_l_s2 = vecs[2 * c];
		auto const &d_l_s1 = vecs[2 * c + 1];
		auto const &d_xor = vecs[2 * nchunks + c];
		auto const &d_store = vecs[3 * nchunks + c];

		bool const ok = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && xr->o(0).IsPVPR() &&
				store->i(0).IsPVPR();
		CHECK(ok);
		if (!ok) {
			continue;
		}

		CHECK_EQ((u32)d_l_s2.dst, (u32)l_s2->o(0).GetPVPR());
		CHECK(d_l_s2.has_disp);
		CHECK_EQ(d_l_s2.disp, (i64)ChunkOffs(vs2_reg, c));
		CHECK_EQ((u32)d_l_s1.dst, (u32)l_s1->o(0).GetPVPR());
		CHECK(d_l_s1.has_disp);
		CHECK_EQ(d_l_s1.disp, (i64)ChunkOffs(vs1_reg, c));

		// THE OPERATION GATE. The emitted mnemonic is the EVEX packed bitwise XOR, at the exact
		// allocated registers. This is the check that stands in for S2.1's order gate: for a
		// commutative operation the hazard is not which source came first, it is whether the
		// host instruction is the right member of a family of near-identical bitwise ops.
		CHECK(d_xor.mnemonic == "vpxord");
		CHECK_EQ((u32)d_xor.dst, (u32)xr->o(0).GetPVPR());

		// Per-chunk containment on decoded bytes, as a SET (see the QIR check for why).
		bool const contained = (d_xor.src0 == d_l_s2.dst && d_xor.src1 == d_l_s1.dst) ||
				       (d_xor.src0 == d_l_s1.dst && d_xor.src1 == d_l_s2.dst);
		CHECK(contained);
		if (!contained) {
			fprintf(stderr,
				"  %s: chunk %u decoded `vpxord zmm%u,zmm%u,zmm%u`; this chunk's loads "
				"went to zmm%u (window 0x%llx) and zmm%u (window 0x%llx)\n",
				tag, c, d_xor.dst, d_xor.src0, d_xor.src1, d_l_s2.dst,
				(unsigned long long)d_l_s2.disp, d_l_s1.dst,
				(unsigned long long)d_l_s1.disp);
		}

		CHECK_EQ((u32)d_store.src0, (u32)d_xor.dst);
		CHECK(d_store.has_disp);
		CHECK_EQ(d_store.disp, (i64)ChunkOffs(vd_reg, c));

		if (c < 2) {
			chunk_regs[c] = {d_l_s2.dst, d_l_s1.dst, d_xor.dst};
		}
	}

	// No artificial cross-chunk dependency, re-derived from the externally decoded bytes: no
	// register named anywhere in chunk 0 is named anywhere in chunk 1.
	if (nchunks == 2) {
		bool disjoint = true;
		for (auto r0 : chunk_regs[0]) {
			for (auto r1 : chunk_regs[1]) {
				disjoint = disjoint && r0 != r1;
			}
		}
		CHECK(disjoint);
		printf("  %s: chunk0 zmm{%u,%u,%u} chunk1 zmm{%u,%u,%u} disjoint=%d\n", tag,
		       chunk_regs[0][0], chunk_regs[0][1], chunk_regs[0][2], chunk_regs[1][0],
		       chunk_regs[1][1], chunk_regs[1][2], (int)disjoint);
	}

	unsigned n_xor = 0, n_sibling = 0;
	for (auto const &v : vecs) {
		n_xor += (v.kind == DecodedVec::Kind::XOR);
		n_sibling += (v.mnemonic == "vpaddd" || v.mnemonic == "vpsubd" ||
			      v.mnemonic == "vpmulld" || v.mnemonic == "vpandd" || v.mnemonic == "vpord");
	}
	CHECK_EQ(n_xor, nchunks);
	CHECK_EQ(n_sibling, 0u);

	printf("  %s: OK objdump-decoded %zu/%u zmm instructions, %u vpxord, "
	       "0 vpaddd/vpsubd/vpmulld/vpandd/vpord, bytes never executed\n",
	       tag, vecs.size(), 4 * nchunks, n_xor);
}

// ---------------------------------------------------------------------------------------------
// 6. Legal operand overlap.
// ---------------------------------------------------------------------------------------------

// For each legal overlap, re-run the QIR shape check with that encoding's own source registers, and
// then assert the property the overlap actually depends on: within the frame, EVERY
// vstatechunkload precedes EVERY vstatechunkstore. That is what makes a destination that aliases a
// source read pre-instruction bytes.
void CheckOverlap(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 word, u32 vs2,
		  u32 vs1, u32 vd)
{
	CheckRoute(tag, vlen_bits, nchunks, expect_vlmax, word, vs2, vs1, vd);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.xor_word = word;
	Region *region = TranslateCfg(arena, words, cfg);

	Group g = FindGroup(region);
	if (!g.begin) {
		return;
	}
	int last_load = -1, first_store = -1;
	for (size_t i = 0; i < g.body.size(); ++i) {
		if (g.body[i]->GetOpcode() == Op::_vstatechunkload) {
			last_load = (int)i;
		}
		if (g.body[i]->GetOpcode() == Op::_vstatechunkstore && first_store < 0) {
			first_store = (int)i;
		}
	}
	CHECK(last_load >= 0 && first_store >= 0);
	CHECK(last_load < first_store);
	printf("  %s: OK all %d loads precede the first store (idx %d < %d)\n", tag,
	       (int)(2 * nchunks), last_load, first_store);
}

// ---------------------------------------------------------------------------------------------
// 7. Sibling non-capture, on emitted bytes.
// ---------------------------------------------------------------------------------------------
//
// The fallback table already proves the sibling encodings produce no typed QIR node. This closes
// the same hazard at the other end of the pipeline and on a different artifact: push each sibling
// word through the REAL code generator with the xor route fully open (switch on, force-emit on) and
// require the emitted block to contain NO ZMM instruction at all.
//
// Why both. The QIR check would still pass if a future change routed a sibling through some other
// vector emitter; this check would not. And unlike the QIR check, this one reads objdump's own
// decode of the bytes, so it cannot agree with the translator by construction. If the decoder ever
// captured vand.vv or vor.vv, the block would contain `vpxord` -- an XOR computed for a guest AND
// -- and that is the single most dangerous outcome this route can have. Since S2.3 and S2.4 both
// siblings have routes of their own (switched off here), so "no ZMM instruction" means "THIS route
// did not capture it" rather than "this encoding has no route"; the positive statement lives in
// those files' own coexistence sections.
void CheckSiblingNonCapture(u32 vlen_bits)
{
	printf("  sibling non-capture (emitted bytes): vlen=%u\n", vlen_bits);

	struct Arm {
		char const *name;
		u32 word;
	} const arms[] = {
	    {"vand.vv (funct6 001001)", INSN_VAND_VV},
	    {"vor.vv  (funct6 001010)", INSN_VOR_VV},
	    {"vxor.vv masked (vm=0)", INSN_VXOR_VV_MASKED},
	    {"vxor.vx", INSN_VXOR_VX},
	    {"vxor.vi", INSN_VXOR_VI},
	    {"vmxor.mm", INSN_VMXOR_MM},
	};

	for (auto const &a : arms) {
		MemArena arena(1u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.xor_word = a.word;
		Region *region = TranslateCfg(arena, words, cfg);

		qir::CodeSegment segment(0u, 0x1000u);
		auto const code_span = qcg::GenerateCode(&cr, &segment, region, 0);
		CHECK(!code_span.empty());
		if (code_span.empty()) {
			continue;
		}
		std::vector<u8> const code(code_span.begin(), code_span.end());
		auto const lines = Disassemble(code);
		CHECK(!lines.empty());

		unsigned n_zmm = 0;
		for (auto const &l : lines) {
			if (MentionsZmm(l)) {
				++n_zmm;
				fprintf(stderr, "  sibling %s emitted a ZMM line: %s\n", a.name, l.c_str());
			}
		}
		unsigned const n_typed = CountOp(region, Op::_vchunkxor);
		CHECK_EQ(n_zmm, 0u);
		CHECK_EQ(n_typed, 0u);
		printf("    %-28s emitted %zu lines, %u ZMM instructions, %u vchunkxor nodes  %s\n",
		       a.name, lines.size(), n_zmm, n_typed, (n_zmm == 0 && n_typed == 0) ? "ok" : "FAIL");
	}
}

} // namespace

int main()
{
	printf("S2.2 vxor.vv typed V512 chunk route\n");

	printf("[1] decoder\n");
	CheckDecoderSweep();
	CheckDecoderRows();

	printf("[2] constructed QIR\n");
	CheckRoute("vlen512", 512, 1, 16, INSN_VXOR_VV, VS2_REG, VS1_REG, VD_REG);
	CheckRoute("vlen1024", 1024, 2, 32, INSN_VXOR_VV, VS2_REG, VS1_REG, VD_REG);

	// The frozen S1.1-fix1 workload's own words, at both admitted widths. kern_xor overlaps
	// (v8 = v8 ^ v9); kern_mix does not (v12 = v8 ^ v9).
	CheckRoute("s11-kern_xor word vlen512", 512, 1, 16, INSN_VXOR_VV_S11_KERN, 8, 9, 8);
	CheckRoute("s11-kern_xor word vlen1024", 1024, 2, 32, INSN_VXOR_VV_S11_KERN, 8, 9, 8);
	CheckRoute("s11-kern_mix word vlen512", 512, 1, 16, INSN_VXOR_VV_S11_MIX, 8, 9, 12);
	CheckRoute("s11-kern_mix word vlen1024", 1024, 2, 32, INSN_VXOR_VV_S11_MIX, 8, 9, 12);

	printf("[3] fallback table\n");
	CheckFallbackTable();

	printf("[4] post-QRegAlloc\n");
	CheckRoutePostQRA("vlen512", 512, 1);
	CheckRoutePostQRA("vlen1024", 1024, 2);

	printf("[5] emitted host code\n");
	CheckRouteEmitted("vlen512", 512, 1, INSN_VXOR_VV, VS2_REG, VS1_REG, VD_REG);
	CheckRouteEmitted("vlen1024", 1024, 2, INSN_VXOR_VV, VS2_REG, VS1_REG, VD_REG);
	CheckRouteEmitted("s11-kern_xor vlen512", 512, 1, INSN_VXOR_VV_S11_KERN, 8, 9, 8);
	CheckRouteEmitted("s11-kern_xor vlen1024", 1024, 2, INSN_VXOR_VV_S11_KERN, 8, 9, 8);
	CheckRouteEmitted("s11-kern_mix vlen512", 512, 1, INSN_VXOR_VV_S11_MIX, 8, 9, 12);
	CheckRouteEmitted("s11-kern_mix vlen1024", 1024, 2, INSN_VXOR_VV_S11_MIX, 8, 9, 12);

	printf("[6] legal operand overlap\n");
	CheckOverlap("vd==vs2 vlen1024", 1024, 2, 32, INSN_VXOR_VV_D_EQ_S2, VD_REG, VS1_REG, VD_REG);
	CheckOverlap("vd==vs1 vlen1024", 1024, 2, 32, INSN_VXOR_VV_D_EQ_S1, VS2_REG, VD_REG, VD_REG);
	CheckOverlap("vd==vs1==vs2 vlen1024", 1024, 2, 32, INSN_VXOR_VV_ALL_SAME, VD_REG, VD_REG, VD_REG);
	// The overlap the frozen workload actually contains, at both widths, plus its disjoint form.
	CheckOverlap("s11 vd==vs2 vlen512", 512, 1, 16, INSN_VXOR_VV_S11_KERN, 8, 9, 8);
	CheckOverlap("s11 vd==vs2 vlen1024", 1024, 2, 32, INSN_VXOR_VV_S11_KERN, 8, 9, 8);
	CheckOverlap("s11 no-overlap vlen1024", 1024, 2, 32, INSN_VXOR_VV_S11_MIX, 8, 9, 12);

	printf("[7] sibling non-capture on emitted bytes\n");
	CheckSiblingNonCapture(512);
	CheckSiblingNonCapture(1024);

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK: all checks passed\n");
	return 0;
}
