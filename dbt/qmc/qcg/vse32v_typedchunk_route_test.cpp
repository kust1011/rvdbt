// S2.7: the exact unmasked unit-stride `vse32.v` typed V512 chunk route, verified mechanically at
// six levels -- decoder, constructed QIR, post-QRegAlloc allocation, independently disassembled
// emitted host bytes, coexistence with the seven accepted routes, and end-to-end load->ALU->store
// ordering.
//
// This file is the STORE twin of qmc/qcg/vle32v_typedchunk_route_test.cpp and keeps its structure so
// the eight routed frames are checked to the same depth. It is not a rename, and the reason is one
// sentence: THIS ROUTE WRITES GUEST MEMORY. Everything below that has no analogue in S2.1-S2.6
// follows from that and from nothing else.
//
// [A] THE DECODER DOES NOT NARROW THE SHAPE FOR THIS ROUTE, EITHER.
//
// rv32_decode.h tests nf/mew/mop/sumop for STORE-FP and then sends MASKED unit-stride stores and ALL
// FOUR supported EEWs to the SAME Op::_vse -- exactly as it does for loads, and `vm` is untested in
// both. So `vm` and the width field are the ROUTE's obligation. On this side the consequence of
// getting either wrong is worse than on the load side: a masked `vse32.v` must leave the guest
// memory of inactive elements UNTOUCHED, and `vse8.v` writes a quarter of the bytes for the same
// vl, so admitting either turns a partial write into a 64-byte block write over data the guest still
// owns. Section [1] is therefore an EXHAUSTIVE sweep of the whole STORE-FP field space --
// nf x mew x mop x vm x sumop x width, 32768 words -- pushed through the real translator, requiring
// that the set of words producing a typed frame is EXACTLY one.
//
// [B] THE DIRECTION GATE IS THE OTHER WAY ROUND, AND IT IS NOW THE SAFETY-CRITICAL ONE.
//
// The frame is `vstatechunkload` -> `vchunkstore`, and `vchunkstore` is used in its INDIRECT
// addressing form (qir.h explains why a QRegAlloc-allocated address operand cannot work inside a
// guard frame). Section [5] therefore demands that the guest address be the DESTINATION of the
// 64-byte move and the r13 window its SOURCE -- and section [5b] additionally requires that NO
// guest-addressed 64-byte LOAD appears anywhere in the frame. A frame built by copy-editing the
// accepted vle frame would have the right chunk count, the right registers, the right windows, the
// right guard and the right counters; it would read the guest's buffer into the vector register
// instead of writing it, and only an operand-ROLE check can see that.
//
// [C] CONTAINMENT: WHAT THE FRAME MAY WRITE IS BOUNDED, NOT JUST COUNTED.
//
// A load that wrote one chunk too many would corrupt an architectural vector register the frozen
// guest's own self-check observes. A STORE that writes one chunk too many overwrites 64 bytes of
// whatever the guest put after its buffer -- another buffer, the stack, or a code page, and rvdbt
// performs no translation invalidation on guest stores. Section [7] therefore gates the frame's
// ENTIRE vector footprint: exactly 2*nchunks ZMM instructions, of which exactly nchunks are guest
// writes, at displacements exactly {0} or {0, 0x40} off one base register, and no ZMM instruction of
// any other shape at all. That is the statement "this frame writes exactly nchunks*64 bytes at
// [base]" rather than "this frame contains nchunks stores".
//
// [D] vs3 IS THE `rd` FIELD, AND CONFUSING IT WITH vd IS A LIVE HAZARD.
//
// In the V format a store's SOURCE register is encoded where a load's DESTINATION is
// (rv32_interp.cpp HANDLER(vse) says so at its RVV_REQUIRE_LEGAL_GROUP). The route reads the source
// window from `i.rd()`. Section [2] pins the window to vs3's own 128-byte slot, and section [9]
// drives the frozen workload's own two distinct (vs3, base) pairs so the join is not satisfiable by
// a hardcoded register.
//
// [E] THE SECOND CHUNK'S ADDRESS IS THE SAME DECISION, WITH A WORSE FAILURE MODE (S2.5 section 4.3).
//
// `rvv_chunked::store_unit_stride` hands `copy_chunked` a `vmem + (u32)base` destination and then
// walks `dst + c*HOST_CHUNK_BYTES` on a HOST pointer, which does not wrap modulo 2^32. A direct
// route computing chunk 1's address as a QIR I32 add WOULD wrap, and for the 64 guest addresses in
// [2^32-128, 2^32-64) it would write 64 bytes to the BOTTOM of the guest address space. This route
// folds the displacement into the x86 memory operand instead. Section [6] asserts that positively:
// chunk 1 must reuse chunk 0's base register with a +0x40 displacement, and the frame must contain
// NO address arithmetic at all.
//
//     RVV:  vse32.v vs3, (rs1)  =>  mem[rs1, rs1+vl*4) <- vreg[vs3] bytes [0, vl*4)
//           (rv32_vector_lower.h rvv_chunked::store_unit_stride, EEW from the width field)
//     QIR:  vstatechunkload d, [state:vreg+vs3*128+disp] ; vchunkstore [state:rs1]+disp, d
//     x86:  vmovdqu64 zmm, ZMMWORD PTR [r13+state_off]
//           mov eax, DWORD PTR [r13+gpr_off] ; vmovdqu64 ZMMWORD PTR [rax+disp], zmm
//
// WHAT THIS FILE PROVES
//
//   1. DECODER + ADMISSION. Of 32768 STORE-FP encodings, exactly one produces a typed frame:
//      nf=0, mew=0, mop=00, vm=1, sumop=00000, width=110. Every other word keeps a helper. The six
//      accepted ALU splits are re-counted in the same run so this checkpoint cannot have disturbed
//      them.
//   2. QIR. At VLEN=512 the admitted instruction becomes ONE 512-bit chunk (2 typed ops); at
//      VLEN=1024 TWO chunks (4 typed ops), in load-major order, reading the exact low/high 64-byte
//      windows of vs3 and writing through the CPUState slot of the ENCODED rs1, with per-chunk
//      def-use and no cross-chunk edge. Nothing is written at displacement 64 when VLEN=512 -- the
//      chunk count comes from config::vlen_bits, never from VLEN_MAX.
//   3. FALLBACK. Every forbidden shape keeps the pre-existing helper: zero typed nodes and exactly
//      one `hcall [rv32_vse]` (or the other opcode's own stub). Each forbidden condition is
//      exercised on its own axis, so a single over-broad gate cannot hide behind another.
//   4. QRA. Distinct physical VPRs per chunk, all out of VPR_POOL, containment surviving
//      allocation, and no allocator-inserted V512 mov inside the frame.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits, per chunk, one 64-byte `vmovdqu64` whose
//      SOURCE is the r13-relative state window and one whose DESTINATION is a guest address -- in
//      that direction, with no guest-addressed load anywhere -- with the exact allocated ZMM
//      operands and, at VLEN=1024, two chunks whose register sets are disjoint in the externally
//      decoded bytes.
//   6. CHUNK-1 ADDRESS FORM. Same base register, +0x40 displacement, zero address arithmetic.
//   7. CONTAINMENT. The frame's whole vector footprint is 2*nchunks ZMM instructions and nothing
//      else, so the guest bytes it can touch are exactly [base, base + 64*nchunks).
//   8. NON-CAPTURE. `vle32.v`, masked `vse32.v`, `vse8/16/64.v`, `vsse32.v`, `vsuxei32.v`,
//      `vs2r.v`, `vsseg2e32.v`, `vsm.v` and `vse32.v` with base x0 are each pushed through the REAL
//      code generator with this route fully open, and each must produce no ZMM instruction at all.
//   9. COEXISTENCE AND ORDERING. With the vle, vand and vse switches all on in one process, a
//      `vle32.v ; vand.vv ; vse32.v` region emits its guest loads, then its `vpandd`, then its guest
//      stores, in that order -- the load->ALU->store QIR side-effect ordering, read off the emitted
//      stream. Independent-base and aliased-base variants are both driven, and the aliased one is
//      the frozen mixed loop's own `(a6)`-in, `(a6)`-out shape.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. Runtime correctness is the xbd evidence's obligation, on a host
//     that actually has AVX-512, and the guest-memory canaries live there because a static test
//     cannot observe a wild write.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//   * It says nothing about `vsetvli`, which remains the mixed loop's one residual helper.
//
// HOST NOTE. RvvQcgTypedVseChunkAdmit's host-feature row is a real __builtin_cpu_supports probe, so
// on a machine without AVX-512F the route would fail closed and there would be nothing to inspect.
// `config::rvv_qcg_typed_chunk_vse_force_emit` bypasses ONLY that probe -- not the architectural
// guard, not the admitted shape -- which is exactly what lets the emitted shape be audited here.
// This is the same device the seven accepted route audits used.
//
// INSTRUCTION WORDS. Every encoding below was produced by explicit field-assembly of the RVV 1.0
// layout and then independently round-tripped through `llvm-mc -triple=riscv32 -mattr=+v
// -show-encoding`, so the constants are not hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
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

// CHECK_EQ renders its operands as integers, so string comparisons get their own macro rather than
// a cast that would not compile.
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

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_GPR_BASE = (u32)offsetof(CPUState, gpr);

// Chunk 0 is a register's low 64-byte half, chunk 1 its high half -- the exact
// `r*VLEN_MAX_BYTES + chunk*64` formula RvvEmitTypedVseChunkGroup uses.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// The CPUState slot of guest register `r`, in the layout RV32Translator::GetStateInfo declares its
// globals with. This is what the emitted frame reads the destination address from.
constexpr u32 GprOffs(u32 r)
{
	return ST_GPR_BASE + 4u * r;
}

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with the disassembly llvm-mc independently produced for it.
// ---------------------------------------------------------------------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 INSN_VSETVLI_E16M1 = 0x0c857557u; // vsetvli a0, a0, e16, m1, ta, ma

// The route's own encoding, with vs3=v8 and base=a6(x16) -- the frozen mixed loop's own choice.
constexpr u32 VS3_REG = 8;    // v8
constexpr u32 BASE_REG = 16;  // x16 = a6

constexpr u32 INSN_VSE32_V = 0x02086427u;	 // vse32.v v8, (a6)
constexpr u32 INSN_VSE32_V_MASKED = 0x00086427u; // vse32.v v8, (a6), v0.t   (vm = 0)
constexpr u32 INSN_VSE8_V = 0x02080427u;	 // vse8.v   v8, (a6)
constexpr u32 INSN_VSE16_V = 0x02085427u;	 // vse16.v  v8, (a6)
constexpr u32 INSN_VSE64_V = 0x02087427u;	 // vse64.v  v8, (a6)
constexpr u32 INSN_VSE32_V_X0 = 0x02006427u;	 // vse32.v v8, (zero)      (rs1 = x0)
constexpr u32 INSN_VSSE32_V = 0x0ab86427u;	 // vsse32.v v8, (a6), a1    (mop = 10)
constexpr u32 INSN_VSUXEI32_V = 0x06b86427u;	 // vsuxei32.v v8, (a6), v11 (mop = 01)
constexpr u32 INSN_VS2R_V = 0x22880427u;	 // vs2r.v  v8, (a6)        (sumop = 01000, nf = 1)
constexpr u32 INSN_VSSEG2E32_V = 0x22086427u;	 // vsseg2e32.v v8, (a6)    (nf = 1)
constexpr u32 INSN_VSM_V = 0x02b80427u;		 // vsm.v   v8, (a6)        (sumop = 01011)
constexpr u32 INSN_VLE32_V = 0x02086407u;	 // vle32.v v8, (a6)        (LOAD-FP)
constexpr u32 INSN_VAND_VV = 0x261101d7u;	 // vand.vv v3, v1, v2

// The load->ALU->store pipeline words used by section [9].
constexpr u32 INSN_VLE32_V_A2_V8 = 0x02066407u; // vle32.v v8, (a2)
constexpr u32 INSN_VAND_VV_9_8_8 = 0x268404d7u; // vand.vv v9, v8, v8
constexpr u32 INSN_VSE32_V_A2_V9 = 0x020664a7u; // vse32.v v9, (a2)   -- ALIASED with the load's base
constexpr u32 INSN_VSE32_V_A3_V9 = 0x0206e4a7u; // vse32.v v9, (a3)   -- INDEPENDENT base

// The words the frozen S1.1-fix1 guest ELF actually contains at its eight static vse32.v sites
// (guest ELF SHA-256 67fb07833ed040f7d318c20a85a123ac86d3269bc7ba8a5f4f1ef62c2563cb34, per the
// accepted S2.0/S2.5 audits, re-read from its own disassembly here). Six single-family kernels share
// `v8, (a3)`; the mixed loop's two are distinct from those and from each other. Three distinct base
// registers and two distinct source registers is what gives the state-offset join teeth.
struct FrozenWord {
	char const *text;
	u32 word;
	u32 vs3;
	u32 base;
};
constexpr FrozenWord FROZEN_STORES[] = {
    {"vse32.v v8, (a3)", 0x0206e427u, 8, 13},  // 0x13038, 0x130a4, 0x13110, 0x1317c, 0x131e8, 0x13250
    {"vse32.v v8, (a6)", 0x02086427u, 8, 16},  // 0x132dc  (kern_mix)
    {"vse32.v v12, (a1)", 0x0205e627u, 12, 11}, // 0x132e4  (kern_mix)
};

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. The defaults are the fully-open configuration; the fallback table below
// flips exactly one field at a time off it.
//
// `typed_chunk_and` and `typed_chunk_vle` are FIELDS rather than hardcoded false because section [9]
// needs one configuration in which the accepted ALU route, the accepted load route and this store
// route are open at once. Both default to false so every other section observes this route alone.
struct RouteConfig {
	bool typed_chunk_vse = true;
	bool typed_chunk_vle = false; // section [9] turns this on
	bool typed_chunk_and = false; // section [9] turns this on
	bool force_emit = true;	      // see the file header HOST NOTE
	bool aot_use_llvm = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	unsigned rvv_lowering = 1; // 1 = fixed-width chunks; 0 = Ref, which this route refuses
	u32 vlen_bits = 512;
	u32 vsetvli_word = INSN_VSETVLI_E32M1;
	u32 store_word = INSN_VSE32_V;
};

void ApplyConfig(RouteConfig const &cfg)
{
	config::rvv_qcg_typed_chunk_vse = cfg.typed_chunk_vse;
	config::rvv_qcg_typed_chunk_vse_force_emit = cfg.force_emit;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::rvv_lowering = cfg.rvv_lowering;
	config::vlen_bits = cfg.vlen_bits;
	// The seven accepted routes' switches are normally off here: this file must observe the store
	// route in isolation, and an open load or ALU route would make a stray ZMM frame ambiguous.
	// Section [9] is the one place two of them are deliberately opened, and it uses the SAME
	// force-emit device so the audit bypass stays symmetric.
	config::rvv_qcg_typed_chunk_vle = cfg.typed_chunk_vle;
	config::rvv_qcg_typed_chunk_vle_force_emit = cfg.typed_chunk_vle;
	config::rvv_qcg_typed_chunk_and = cfg.typed_chunk_and;
	config::rvv_qcg_typed_chunk_and_force_emit = cfg.typed_chunk_and;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_diag_chunk = false;
}

// One region containing exactly the translated vsetvli + store pair. Region is arena-allocated, so
// `arena` must outlive it -- both are locals in the caller's own scope.
Region *TranslateOne(MemArena &arena, u32 *words, u32 n, RouteConfig const &cfg)
{
	ApplyConfig(cfg);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

Region *TranslateCfg(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	words[0] = cfg.vsetvli_word;
	words[1] = cfg.store_word;
	return TranslateOne(arena, words, 2, cfg);
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

// Number of hcalls to one specific runtime stub -- the fallback evidence: a non-admitted vse32.v
// must produce exactly one call to the PRE-EXISTING rv32_vse helper, not to a new stub.
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

// Every typed body op this route can produce, counted together. Used by the sweep, where the
// question is only "did a typed frame appear at all".
unsigned CountTypedNodes(Region *region)
{
	return CountOp(region, Op::_vstatechunkload) + CountOp(region, Op::_vchunkstore) +
	       CountOp(region, Op::_rvvtypedchunkbegin);
}

// ---------------------------------------------------------------------------------------------
// 1. Decoder + admission: an exhaustive sweep of the STORE-FP encoding space.
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

// Assemble one STORE-FP word with the register fields this file uses throughout (vs3=v8, rs1=a6).
// The sweep varies ONLY the six fields the route's predicate tests, so a hit is attributable to the
// encoding class and not to a register choice.
constexpr u32 MakeStoreFP(u32 nf, u32 mew, u32 mop, u32 vm, u32 sumop, u32 width)
{
	return (nf << 29) | (mew << 28) | (mop << 26) | (vm << 25) | (sumop << 20) |
	       (BASE_REG << 15) | (width << 12) | (VS3_REG << 7) | 0b0100111u;
}

// THE CENTRAL GATE OF THIS CHECKPOINT. Push all 8*2*4*2*32*8 = 32768 STORE-FP encodings through the
// REAL translator with the route fully open, and require that exactly ONE produces a typed frame.
//
// This is a sweep over the translator rather than over the decoder because the decoder is not where
// this route's shape is decided (see the file header). A predicate that forgot `vm` would show up
// here as two admitted words; one that accepted all four supported EEWs as eight; one that dropped
// the sumop test as more still. None of those is visible in `DecodeWord` at all, because every one
// of those words legitimately reaches Op::_vse.
void CheckEncodingSweep()
{
	printf("[1] STORE-FP encoding sweep: 8 nf x 2 mew x 4 mop x 2 vm x 32 sumop x 8 width = 32768\n");

	MemArena arena(1u << 20);
	u32 words[2];
	std::vector<u32> admitted;
	unsigned n_reach_vse = 0;

	for (u32 nf = 0; nf < 8; ++nf) {
		for (u32 mew = 0; mew < 2; ++mew) {
			for (u32 mop = 0; mop < 4; ++mop) {
				for (u32 vm = 0; vm < 2; ++vm) {
					for (u32 sumop = 0; sumop < 32; ++sumop) {
						for (u32 width = 0; width < 8; ++width) {
							u32 const w =
							    MakeStoreFP(nf, mew, mop, vm, sumop, width);
							n_reach_vse +=
							    (DecodeWord(w) == rv32::insn::Op::_vse);
							arena.Reset();
							RouteConfig cfg;
							cfg.store_word = w;
							Region *r = TranslateCfg(arena, words, cfg);
							if (CountTypedNodes(r) != 0) {
								admitted.push_back(w);
							}
						}
					}
				}
			}
		}
	}

	CHECK_EQ(admitted.size(), 1u);
	if (admitted.size() == 1) {
		CHECK_EQ(admitted[0], MakeStoreFP(0, 0, 0, 1, 0, 0b110));
		CHECK_EQ(admitted[0], INSN_VSE32_V);
		printf("    exactly 1 admitted word: 0x%08x "
		       "(nf=0 mew=0 mop=00 vm=1 sumop=00000 width=110)\n",
		       admitted[0]);
	} else {
		for (u32 w : admitted) {
			fprintf(stderr, "    unexpectedly admitted: 0x%08x\n", w);
		}
	}

	// The decoder's own reach, reported for contrast rather than as the gate: 4 supported widths
	// x 2 vm values = 8 words legitimately arrive at Op::_vse, and 7 of them must be refused by
	// the route's own predicate. That ratio is the whole reason this route has a predicate the
	// six ALU routes do not need, and it is the same ratio the load route faces.
	CHECK_EQ(n_reach_vse, 8u);
	printf("    %u of 32768 words reach Op::_vse; the route admits 1 of those 8\n", n_reach_vse);
}

// The six accepted ALU splits, re-counted in this process. If this checkpoint had disturbed the
// decoder -- it does not touch rv32_decode.h at all -- these would move, and a reader should not
// have to take "it does not touch it" on trust.
void CheckAcceptedSplitsUndisturbed()
{
	using Op32 = rv32::insn::Op;
	printf("[1b] the six accepted OPIVV/OPMVV splits, re-counted\n");

	struct Split {
		char const *name;
		Op32 op;
		u32 funct3, funct6;
		unsigned hits = 0;
	};
	Split splits[] = {
	    {"vadd_vv", Op32::_vadd_vv, 0b000, 0b000000, 0},
	    {"vsub_vv", Op32::_vsub_vv, 0b000, 0b000010, 0},
	    {"vxor_vv", Op32::_vxor_vv, 0b000, 0b001011, 0},
	    {"vor_vv", Op32::_vor_vv, 0b000, 0b001010, 0},
	    {"vand_vv", Op32::_vand_vv, 0b000, 0b001001, 0},
	    {"vmul_vv", Op32::_vmul_vv, 0b010, 0b100101, 0},
	};
	for (u32 funct3 = 0; funct3 < 8; ++funct3) {
		for (u32 funct6 = 0; funct6 < 64; ++funct6) {
			for (u32 vm = 0; vm < 2; ++vm) {
				u32 const word = (funct6 << 26) | (vm << 25) | (1u << 20) |
						 (2u << 15) | (funct3 << 12) | (3u << 7) | 0b1010111u;
				Op32 const got = DecodeWord(word);
				for (auto &s : splits) {
					if (got != s.op) {
						continue;
					}
					++s.hits;
					CHECK_EQ(funct3, s.funct3);
					CHECK_EQ(funct6, s.funct6);
					CHECK_EQ(vm, 1u);
				}
			}
		}
	}
	for (auto const &s : splits) {
		CHECK_EQ(s.hits, 1u);
	}
	printf("    all six still reached by exactly one OP-V encoding each\n");
}

// ---------------------------------------------------------------------------------------------
// 2. Constructed QIR: exact admitted shape.
// ---------------------------------------------------------------------------------------------
void CheckRoute(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 store_word,
		u32 vs3_reg, u32 base_reg)
{
	printf("[2] %s: VLEN=%u -> %u chunk(s)\n", tag, vlen_bits, nchunks);

	MemArena arena(4u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.store_word = store_word;
	Region *region = TranslateCfg(arena, words, cfg);

	auto g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		return;
	}

	// The guard the emitter will generate: the exact vtype translation assumed, and vl == VLMAX
	// for that vtype at this VLEN. `vstart == 0` is compared against a literal in the emitter.
	CHECK_EQ(g.begin->vtype, rv32::VTYPE_E32_M1_TA_MA);
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	CHECK_EQ(g.begin->raw, store_word);
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vse);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vse);
	// Two typed ops per chunk -- a state read and a guest write. The `end` emitter Panics if the
	// body it saw is not this shape, so a wrong declaration here is a translation abort, not a
	// silent miscount. That accounting is NEW for vchunkstore in this checkpoint: before S2.7 the
	// op did not count itself into the group at all.
	CHECK_EQ((unsigned)g.begin->n_typed, 2u * nchunks);
	CHECK_EQ(g.body.size(), (size_t)(2 * nchunks));
	if (g.body.size() != 2 * nchunks) {
		return;
	}

	// LOAD-MAJOR: every chunk's CPUState read, then every chunk's guest-memory write. The whole
	// source register is captured into ZMMs before the first guest byte is written.
	std::vector<RegN> src_vals;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *ins = g.body[c];
		CHECK(ins->GetOpcode() == Op::_vstatechunkload);
		if (ins->GetOpcode() != Op::_vstatechunkload) {
			return;
		}
		auto *ld = static_cast<InstVStateChunkLoad *>(ins);
		// THE SOURCE WINDOW. vs3's own 128-byte slot, chunk c's own 64-byte half. `vs3` is the
		// V format's `rd` field for a store; a route that read the vd of a load, or a
		// neighbouring register, differs by 128 here.
		CHECK_EQ((u32)ld->offs, ChunkOffs(vs3_reg, c));
		CHECK(ld->o(0).GetType() == VType::V512);
		src_vals.push_back(ld->o(0).GetVVPR());
	}
	for (u32 c = 0; c < nchunks; ++c) {
		auto *ins = g.body[nchunks + c];
		CHECK(ins->GetOpcode() == Op::_vchunkstore);
		if (ins->GetOpcode() != Op::_vchunkstore) {
			return;
		}
		auto *st = static_cast<InstVChunkStore *>(ins);
		// THE DESTINATION ADDRESS. Indirect form, reading the CPUState slot of the ENCODED
		// base register. A route that hardcoded a register, or that read vs3's slot, fails.
		CHECK_EQ((u32)st->base_state_offs, GprOffs(base_reg));
		CHECK(st->base_state_offs != InstVChunkStore::NO_STATE_BASE);
		// THE DISPLACEMENT (S2.5 section 4.3). Chunk c is at +64c, folded into the memory
		// operand rather than computed. Section [6] re-derives this from emitted bytes.
		CHECK_EQ((u32)st->disp, c * 64u);
		// The unused address operand slot of the indirect form.
		CHECK(st->i(0).IsConst());
		CHECK_EQ(st->i(0).GetConst(), 0u);
		// Per-chunk def-use: chunk c's store consumes chunk c's state read and nothing else.
		CHECK(st->i(1).IsVVPR());
		CHECK_EQ(st->i(1).GetVVPR(), src_vals[c]);
	}
	// The two chunks are independent values. At VLEN=1024 a shared value would mean the high
	// chunk wrote the low one's data to guest memory.
	if (nchunks == 2) {
		CHECK(src_vals[0] != src_vals[1]);
	}

	// NOTHING AT +64 WHEN VLEN=512 -- the trap S2.5 section 3 names, and it is sharper on this
	// side: a chunk count taken from VLEN_MAX_BITS is invisible at VLEN=1024 and at VLEN=512
	// writes 64 bytes of a NEIGHBOURING GUEST BUFFER, taken from the neighbouring register's slot.
	if (nchunks == 1) {
		for (auto *ins : g.body) {
			if (ins->GetOpcode() == Op::_vstatechunkload) {
				CHECK(static_cast<InstVStateChunkLoad *>(ins)->offs !=
				      ChunkOffs(vs3_reg, 1));
			}
			if (ins->GetOpcode() == Op::_vchunkstore) {
				CHECK_EQ((u32)static_cast<InstVChunkStore *>(ins)->disp, 0u);
			}
		}
	}

	// The frame is the whole lowering: no helper for this instruction, and none of the seven
	// accepted routes' body ops anywhere.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vse), 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), nchunks);
	CHECK_EQ(CountOp(region, Op::_vchunkstore), nchunks);
	CHECK_EQ(CountOp(region, Op::_vchunkload), 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunksub), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkmul), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkxor), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkor), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkand), 0u);
	// The vsetvli ahead of it is untouched -- this checkpoint implements ONE opcode.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vsetvli), 1u);
	printf("    OK vlmax=%u, %u vstatechunkload(vs3 window) -> %u vchunkstore(+disp %s), "
	       "base slot 0x%x\n",
	       expect_vlmax, nchunks, nchunks, nchunks == 2 ? "0,64" : "0", GprOffs(base_reg));
}

// ---------------------------------------------------------------------------------------------
// 3. Fallback matrix: one axis at a time.
// ---------------------------------------------------------------------------------------------
void CheckFallback(char const *why, RouteConfig const &cfg)
{
	MemArena arena(4u << 20);
	u32 words[2];
	Region *region = TranslateCfg(arena, words, cfg);
	unsigned const typed = CountTypedNodes(region);
	unsigned const hcalls = CountHcall(region, RuntimeStubId::id_rv32_vse);
	CHECK_EQ(typed, 0u);
	CHECK_EQ(hcalls, 1u);
	printf("    %-46s typed=%u hcall[rv32_vse]=%u\n", why, typed, hcalls);
}

// A word that belongs to a DIFFERENT decode family. It must reach that family's own pre-existing
// stub -- not this route, and not rv32_vse either.
void CheckFallbackOtherFamily(char const *why, u32 word, RuntimeStubId want_stub)
{
	MemArena arena(4u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.store_word = word;
	Region *region = TranslateCfg(arena, words, cfg);
	unsigned const typed = CountTypedNodes(region);
	unsigned const hcalls = CountHcall(region, want_stub);
	CHECK_EQ(typed, 0u);
	CHECK_EQ(hcalls, 1u);
	printf("    %-46s typed=%u hcall[own stub]=%u\n", why, typed, hcalls);
}

void CheckFallbackTable()
{
	printf("[3] fallback matrix -- every row must keep the pre-existing helper\n");

	{
		RouteConfig c;
		c.typed_chunk_vse = false;
		CheckFallback("switch off (the DEFAULT)", c);
	}
	{
		RouteConfig c;
		c.aot_use_llvm = true;
		CheckFallback("aot_use_llvm (LLVM has no vchunkstore lowering)", c);
	}
	{
		RouteConfig c;
		c.rvv_verify = true;
		CheckFallback("rvv_verify (emitted code cannot cross-check)", c);
	}
	{
		RouteConfig c;
		c.rvv_lowering = 0;
		CheckFallback("rvv_lowering=Ref (element-wise reference arm)", c);
	}
	{
		RouteConfig c;
		c.rvv_direct = false;
		CheckFallback("rvv_direct off", c);
	}
	{
		RouteConfig c;
		c.vlen_bits = 128;
		CheckFallback("VLEN=128 (not a whole 512-bit chunk)", c);
	}
	{
		RouteConfig c;
		c.vlen_bits = 256;
		CheckFallback("VLEN=256 (not a whole 512-bit chunk)", c);
	}
	{
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E64M1;
		CheckFallback("e64,m1 (SEW != 32, so EMUL != 1)", c);
	}
	{
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E32M2;
		CheckFallback("e32,m2 (LMUL != 1)", c);
	}
	{
		// THE ROW WITH NO ANALOGUE AMONG THE ALU ROUTES. EEW=32 from the encoding against
		// SEW=16 from vtype gives EMUL = (32/16)*1 = 2: the source is a TWO-register group
		// and one 64-byte chunk per register is not the whole of it. An admission test that
		// used LMUL where EMUL was meant would pass this row -- and would then write half the
		// bytes the architecture requires.
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E16M1;
		CheckFallback("e16,m1 (EMUL=2 != LMUL=1)", c);
	}
	{
		RouteConfig c;
		c.store_word = INSN_VSE32_V_MASKED;
		CheckFallback("MASKED vse32.v (vm=0; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.store_word = INSN_VSE8_V;
		CheckFallback("vse8.v  (EEW=8; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.store_word = INSN_VSE16_V;
		CheckFallback("vse16.v (EEW=16; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.store_word = INSN_VSE64_V;
		CheckFallback("vse64.v (EEW=64; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.store_word = INSN_VSE32_V_X0;
		CheckFallback("base register x0 (not a tracked global)", c);
	}

	// Different decode families. These cannot reach the route at all, and the rows exist to say
	// so from the translator rather than from a reading of the decoder.
	CheckFallbackOtherFamily("vsse32.v   (strided, mop=10)", INSN_VSSE32_V,
				 RuntimeStubId::id_rv32_vsse);
	CheckFallbackOtherFamily("vsuxei32.v (indexed, mop=01)", INSN_VSUXEI32_V,
				 RuntimeStubId::id_rv32_vsxei);
	CheckFallbackOtherFamily("vs2r.v     (whole-register, sumop=01000)", INSN_VS2R_V,
				 RuntimeStubId::id_rv32_vsNr);
	CheckFallbackOtherFamily("vsseg2e32.v (segment, nf=1)", INSN_VSSEG2E32_V,
				 RuntimeStubId::id_rv32_vsseg);
	CheckFallbackOtherFamily("vsm.v      (mask store, sumop=01011)", INSN_VSM_V,
				 RuntimeStubId::id_rv32_vsm);
	// THE OPCODE THIS SWITCH IS NOT. The accepted S2.6 load route is on its OWN switch, which is
	// off in this configuration, so vle32.v must still be its unchanged helper here.
	CheckFallbackOtherFamily("vle32.v    (the LOAD -- S2.6's own switch, off here)", INSN_VLE32_V,
				 RuntimeStubId::id_rv32_vle);
}

// ---------------------------------------------------------------------------------------------
// 4. Post-QRegAlloc allocation.
// ---------------------------------------------------------------------------------------------
void CheckRoutePostQRA(char const *tag, u32 vlen_bits, u32 nchunks)
{
	printf("[4] %s: post-QRegAlloc allocation\n", tag);

	MemArena arena(4u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	Region *region = TranslateCfg(arena, words, cfg);

	// Exactly the two passes qcg::GenerateCode runs before constructing QEmit (qcg.cpp).
	ArchTraits::init();
	MachineRegionInfo info;
	QSelPass::run(region, &info);
	QRegAllocPass::run(region);

	auto g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}
	// No allocator-inserted mov survived inside the frame. Emit_mov Panics on one, so reaching
	// this check at all already means none was emitted -- but asserting it here names the
	// property instead of leaving it implicit in a crash that did not happen.
	CHECK_EQ(g.body.size(), (size_t)(2 * nchunks));
	std::set<RegN> zmms;
	for (auto *ins : g.body) {
		CHECK(ins->GetOpcode() != Op::_mov);
		if (ins->GetOpcode() == Op::_vstatechunkload) {
			auto d = ins->o(0);
			CHECK(d.IsPVPR());
			CHECK(ArchTraits::VPR_POOL.Test(d.GetPVPR()));
			zmms.insert(d.GetPVPR());
		}
		if (ins->GetOpcode() == Op::_vchunkstore) {
			// The DATA operand. The address operand of the indirect form is the
			// placeholder constant and must have stayed one -- if QRegAlloc had put it in
			// a register, the emitter's fixed-scratch argument would be describing
			// something that no longer happens.
			auto a = ins->i(0);
			CHECK(a.IsConst());
			auto s = ins->i(1);
			CHECK(s.IsPVPR());
			CHECK(ArchTraits::VPR_POOL.Test(s.GetPVPR()));
			zmms.insert(s.GetPVPR());
		}
	}
	// One physical ZMM per chunk, distinct across chunks: the "two chunks, different ZMM
	// registers" requirement, read off the allocation rather than assumed.
	CHECK_EQ(zmms.size(), (size_t)nchunks);
	printf("    OK %zu distinct pool ZMM(s), no allocator mov inside the frame\n", zmms.size());
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

// The four host instruction shapes this file recognises, and nothing else.
//
// BASE is the scalar `mov <r32>, DWORD PTR [r13+off]` that materialises the guest base address.
// STATE_LOAD's memory operand names r13 and is the SOURCE; GUEST_STORE's names a guest register and
// is the DESTINATION. GUEST_LOAD -- a guest address as the SOURCE of a ZMM move -- is the accepted
// vle route's shape and is recognised ONLY so that section [9] can count it and sections [5]-[7] can
// reject it by name rather than as an unparsed line. Keeping all four as distinct kinds is what
// makes a direction slip a parse-level failure instead of an operand-comparison failure.
struct DecodedVec {
	enum class Kind { BASE, STATE_LOAD, GUEST_STORE, GUEST_LOAD, STATE_STORE } kind;
	std::string mnemonic;
	unsigned zmm{};	  // for the three vector kinds
	std::string breg; // base GPR text, for BASE (destination) and GUEST_STORE/GUEST_LOAD (address)
	i64 disp{};	  // r13 displacement for BASE/STATE_*, guest displacement for GUEST_*
};

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

// "<SIZE> PTR [<reg>]" or "<SIZE> PTR [<reg>+0x<hex>]" / "[<reg>-0x<hex>]".
// Returns the register text and the displacement (0 when absent). Any other addressing form --
// a second register, a scale, a segment override -- is rejected, which is what makes "no address
// arithmetic" checkable: an emitter that had computed the address would need a form this refuses.
bool ParseMemOperand(std::string const &tok, char const *size_kw, std::string *reg, i64 *disp)
{
	std::string const prefix = std::string(size_kw) + " PTR [";
	if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}
	if (tok.back() != ']') {
		return false;
	}
	std::string inner = tok.substr(prefix.size(), tok.size() - prefix.size() - 1);
	size_t const sign = inner.find_first_of("+-");
	if (sign == std::string::npos) {
		if (inner.empty() || inner.find_first_of("*+- ") != std::string::npos) {
			return false;
		}
		*reg = inner;
		*disp = 0;
		return true;
	}
	std::string const r = inner.substr(0, sign);
	if (r.empty() || r.find_first_of("*+- ") != std::string::npos) {
		return false;
	}
	bool const neg = inner[sign] == '-';
	std::string const rest = inner.substr(sign + 1);
	if (rest.compare(0, 2, "0x") != 0) {
		return false;
	}
	i64 v = 0;
	size_t i = 2;
	for (; i < rest.size() && isxdigit((unsigned char)rest[i]); ++i) {
		char const c = (char)tolower((unsigned char)rest[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
	}
	if (i == 2 || i != rest.size()) {
		return false;
	}
	*reg = r;
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

bool MentionsZmm(std::string const &line)
{
	return line.find("zmm") != std::string::npos;
}

// The base materialisation writes a 32-bit register (the mov zero-extends, which is what turns the
// u32 guest address into a host address); the memory operand that dereferences it names the 64-bit
// alias of the same architectural register. Normalise so the two can be compared.
std::string Norm64(std::string const &r)
{
	static char const *const pairs[][2] = {
	    {"eax", "rax"}, {"ecx", "rcx"}, {"edx", "rdx"}, {"ebx", "rbx"},
	    {"esp", "rsp"}, {"ebp", "rbp"}, {"esi", "rsi"}, {"edi", "rdi"},
	    {"r8d", "r8"},  {"r9d", "r9"},  {"r10d", "r10"}, {"r11d", "r11"},
	    {"r12d", "r12"}, {"r13d", "r13"}, {"r14d", "r14"}, {"r15d", "r15"},
	};
	for (auto const &p : pairs) {
		if (r == p[0]) {
			return p[1];
		}
	}
	return r;
}

// Parse one objdump Intel-syntax line into one of the shapes above, or return false.
//
// All four `vmovdqu64` roles are recognised, INCLUDING the two this route must never emit
// (GUEST_LOAD, STATE_STORE), so that a direction slip is reported as a WRONG ROLE with its
// displacement and register rather than as an unparsed line. Section [5] then rejects those two by
// name. Section [9] is the one place a GUEST_LOAD is legitimate -- it belongs to the accepted vle
// route running alongside.
bool ParseLine(std::string const &line, DecodedVec *out)
{
	size_t const tab = line.find('\t');
	if (tab == std::string::npos) {
		return false;
	}
	std::string const rhs = line.substr(tab + 1);
	size_t const sp = rhs.find(' ');
	std::string const mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	size_t opstart = sp == std::string::npos ? rhs.size() : sp;
	while (opstart < rhs.size() && rhs[opstart] == ' ') {
		++opstart;
	}
	auto const ops = SplitCommas(rhs.substr(opstart));

	if (mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned zr;
		std::string reg;
		i64 disp;
		// STATE LOAD: zmm <- [r13+off]. This route's SOURCE half.
		if (ParseZmm(ops[0], &zr) && ParseMemOperand(ops[1], "ZMMWORD", &reg, &disp) &&
		    reg == "r13") {
			*out = DecodedVec{DecodedVec::Kind::STATE_LOAD, mnem, zr, reg, disp};
			return true;
		}
		// GUEST LOAD: zmm <- [guest]. The accepted vle route's shape; forbidden inside a vse
		// frame.
		if (ParseZmm(ops[0], &zr) && ParseMemOperand(ops[1], "ZMMWORD", &reg, &disp)) {
			*out = DecodedVec{DecodedVec::Kind::GUEST_LOAD, mnem, zr, reg, disp};
			return true;
		}
		// GUEST STORE: [guest] <- zmm. This route's DESTINATION half.
		if (ParseMemOperand(ops[0], "ZMMWORD", &reg, &disp) && reg != "r13" &&
		    ParseZmm(ops[1], &zr)) {
			*out = DecodedVec{DecodedVec::Kind::GUEST_STORE, mnem, zr, reg, disp};
			return true;
		}
		// STATE STORE: [r13+off] <- zmm. The accepted ALU/vle routes' shape; forbidden here.
		if (ParseMemOperand(ops[0], "ZMMWORD", &reg, &disp) && reg == "r13" &&
		    ParseZmm(ops[1], &zr)) {
			*out = DecodedVec{DecodedVec::Kind::STATE_STORE, mnem, zr, reg, disp};
			return true;
		}
		return false;
	}
	// The base materialisation. Recognised only in the r13-relative direction: a 32-bit read of
	// a CPUState slot into a scalar register.
	if (mnem == "mov" && ops.size() == 2 && !MentionsZmm(line)) {
		std::string reg;
		i64 disp;
		if (ParseMemOperand(ops[1], "DWORD", &reg, &disp) && reg == "r13") {
			*out = DecodedVec{DecodedVec::Kind::BASE, mnem, 0, ops[0], disp};
			return true;
		}
	}
	return false;
}

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this checkpoint's
// emission evidence cannot be produced at all.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_s27_emit_XXXXXX";
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

// Emit one admitted vse32.v through the real pipeline and return the decoded census, in emission
// order. Every line naming a ZMM register that ParseLine does not recognise is a hard failure with
// the offending text, not a silent drop -- that is what makes the counts below a census.
std::vector<DecodedVec> EmitAndDecode(char const *tag, u32 vlen_bits, u32 store_word,
				      std::vector<std::string> *out_lines)
{
	MemArena arena(4u << 20);
	u32 words[2];
	TestCompilerRuntime cr;
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.store_word = store_word;
	words[0] = cfg.vsetvli_word;
	words[1] = cfg.store_word;
	auto const code = EmitOne(arena, words, 2, cfg, cr);
	if (code.empty()) {
		return {};
	}
	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		return {};
	}
	if (out_lines) {
		*out_lines = lines;
	}

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
			for (auto const &q : lines) {
				fprintf(stderr, "    %s\n", q.c_str());
			}
		}
	}
	return vecs;
}

void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 nchunks, u32 store_word, u32 vs3_reg,
		       u32 base_reg)
{
	printf("[5] %s: emitted host bytes, objdump-decoded\n", tag);

	std::vector<std::string> lines;
	auto const vecs = EmitAndDecode(tag, vlen_bits, store_word, &lines);
	if (vecs.empty()) {
		return;
	}

	// The census: per chunk one state read and one guest write, plus one base materialisation per
	// guest write.
	std::vector<DecodedVec> bases, sloads, gstores, gloads, sstores;
	for (auto const &v : vecs) {
		switch (v.kind) {
		case DecodedVec::Kind::BASE:
			// Only the frame's own base read; the guest ip store and any spill are
			// r13-relative movs too but go the other way (memory destination), which
			// ParseLine does not recognise as BASE.
			if (v.disp == (i64)GprOffs(base_reg)) {
				bases.push_back(v);
			}
			break;
		case DecodedVec::Kind::STATE_LOAD:
			sloads.push_back(v);
			break;
		case DecodedVec::Kind::GUEST_STORE:
			gstores.push_back(v);
			break;
		case DecodedVec::Kind::GUEST_LOAD:
			gloads.push_back(v);
			break;
		case DecodedVec::Kind::STATE_STORE:
			sstores.push_back(v);
			break;
		}
	}

	// THE DIRECTION GATE, stated as two positive counts and two zeroes. A frame built by
	// copy-editing the accepted vle frame would have exactly the reverse census: nchunks
	// GUEST_LOADs and nchunks STATE_STOREs, with the right chunk count, the right registers, the
	// right windows, the right guard and the right counters. Only the roles separate them.
	CHECK_EQ(sloads.size(), (size_t)nchunks);
	CHECK_EQ(gstores.size(), (size_t)nchunks);
	CHECK_EQ(gloads.size(), (size_t)0);
	CHECK_EQ(sstores.size(), (size_t)0);
	// ONE base read PER CHUNK, and this is a recorded property rather than an optimum. Each
	// vchunkstore emits its own `mov <scratch>, [r13+gpr_off]`, so the op is self-contained and no
	// emitter state is carried between the two chunks -- the same "the emitter picks nothing and
	// remembers nothing" discipline the seven accepted frames keep. The reload is redundant
	// (nothing between the two writes that CPUState slot) and it is a known, deliberate cost. What
	// matters for correctness is asserted below: every base read names the SAME slot and the SAME
	// fixed scratch register, so both chunks address the same base.
	// A13-FIX: PLUS ONE. The frame's guard now reads the base once more (`mov eax,[r13+gpr]` then
	// `cmp eax, 2^32 - VLEN/8; ja fallback`) so that no chunk window can leave the 4 GiB guest
	// space; the pre-A13-FIX count of exactly nchunks is not preserved because that frame carried
	// the over-access. The per-chunk reads below are unchanged.
	CHECK_EQ(bases.size(), (size_t)nchunks + 1u);
	if (sloads.size() != nchunks || gstores.size() != nchunks || bases.size() != nchunks + 1u ||
	    !gloads.empty() || !sstores.empty()) {
		for (auto const &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return;
	}

	// THE SCRATCH REGISTER IS THE WHOLE SAFETY ARGUMENT, so it is pinned by name. ArchTraits::AX
	// is in GPR_FIXED, which QRegAlloc::AllocPReg can never return, which is why writing it inside
	// the guarded window cannot destroy an allocated value and why no address operand -- and
	// therefore no allocator fill -- is needed at all (qir.h InstVChunkStore). A change that moved
	// this to a pool register would silently reintroduce exactly the hazard the indirect form
	// removes, and would be invisible to every structural count in this file.
	std::string const base_gpr = Norm64(bases[0].breg);
	CHECK_STREQ(base_gpr, "rax");
	for (auto const &b : bases) {
		CHECK_STREQ(Norm64(b.breg), base_gpr);
		CHECK_EQ(b.disp, (i64)GprOffs(base_reg));
	}

	std::set<unsigned> src_zmms, dst_zmms;
	for (u32 c = 0; c < nchunks; ++c) {
		// DIRECTION, per chunk. The r13 window is the SOURCE of a state read and the guest
		// address is the DESTINATION of a guest write.
		CHECK(sloads[c].kind == DecodedVec::Kind::STATE_LOAD);
		CHECK(gstores[c].kind == DecodedVec::Kind::GUEST_STORE);
		// The source window is vs3's own slot, this chunk's own half. A vs3+1 slip is a
		// 128-byte difference here; reading a load's vd field instead of the store's vs3 shows
		// up the same way whenever the two differ.
		CHECK_EQ(sloads[c].disp, (i64)ChunkOffs(vs3_reg, c));
		// The guest address is the base register the frame just materialised, plus this
		// chunk's displacement -- and NOTHING else. Section [6]'s core assertion.
		CHECK_STREQ(Norm64(gstores[c].breg), base_gpr);
		CHECK_EQ(gstores[c].disp, (i64)(c * 64u));
		// The value written is the value this chunk read out of CPUState.
		CHECK_EQ(gstores[c].zmm, sloads[c].zmm);
		src_zmms.insert(sloads[c].zmm);
		dst_zmms.insert(gstores[c].zmm);
	}
	// Two chunks, two different ZMM registers, in the externally decoded bytes.
	CHECK_EQ(src_zmms.size(), (size_t)nchunks);
	CHECK_EQ(dst_zmms.size(), (size_t)nchunks);

	printf("    OK %zu base read(s) [r13+0x%x]->%s, %zu state read(s) [r13+0x%x..], "
	       "%zu guest store(s) [%s%s], %zu distinct zmm, 0 guest loads, 0 state stores\n",
	       bases.size(), GprOffs(base_reg), base_gpr.c_str(), sloads.size(),
	       ChunkOffs(vs3_reg, 0), gstores.size(), base_gpr.c_str(),
	       nchunks == 2 ? "(+0,+0x40)" : "(+0)", src_zmms.size());
}

// THE S2.5 SECTION 4.3 GATE, stated on its own because it is a decision this checkpoint owed, and
// because on the store side getting it wrong is a WILD WRITE rather than a wrong read.
//
// The helper arm this route replaces addresses chunk c as `dst + c*HOST_CHUNK_BYTES` on a HOST
// pointer, so it does not wrap modulo 2^32. This route must do the same, so it must NOT compute the
// second address in 32-bit guest arithmetic. Two properties together say that, and neither says it
// alone:
//
//   * chunk 1's memory operand names chunk 0's base register with a +0x40 DISPLACEMENT
//     (asserted in CheckRouteEmitted above);
//   * the emitted region contains no scalar arithmetic on that register at all -- no add, no lea,
//     no inc, no sub, in either its 32- or 64-bit spelling.
//
// The second is what this function adds. A route that had computed `base + 64` as a QIR I32 add
// would show an `add` or `lea` here even though every structural count above would still pass, and
// the only observable difference would be 64 guest addresses at the very top of the address space --
// where this route would write 64 bytes to address 0 instead.
void CheckNoAddressArithmetic(char const *tag, u32 vlen_bits)
{
	printf("[6] %s: chunk-1 address form -- no address arithmetic\n", tag);

	std::vector<std::string> lines;
	auto const vecs = EmitAndDecode(tag, vlen_bits, INSN_VSE32_V, &lines);
	if (vecs.empty() || lines.empty()) {
		return;
	}

	// Find the base register the frame materialised, then require that no instruction anywhere in
	// the emitted region writes it with arithmetic. Both spellings are searched because a 32-bit
	// `add eax,0x40` and a 64-bit `add rax,0x40` are equally disqualifying.
	std::string base32, base64;
	for (auto const &v : vecs) {
		if (v.kind == DecodedVec::Kind::BASE && v.disp == (i64)GprOffs(BASE_REG)) {
			base32 = v.breg;
			base64 = Norm64(v.breg);
		}
	}
	CHECK(!base64.empty());
	if (base64.empty()) {
		return;
	}

	// BOUND THE SCAN AT THE LAST GUEST STORE, and the reason is not cosmetic. The code buffer is
	// zero-padded to its allocation size, and objdump decodes a run of `00 00` as
	// `add BYTE PTR [rax],al` -- padding that names the scratch register and would be counted as
	// address arithmetic by a scan over the whole listing. Everything that could feed a chunk
	// address necessarily precedes the frame's last store, so this window excludes the padding
	// without excluding any position the mutation this section refutes could occupy.
	size_t last_store = 0;
	bool have_store = false;
	for (size_t i = 0; i < lines.size(); ++i) {
		DecodedVec dv{};
		if (ParseLine(lines[i], &dv) && dv.kind == DecodedVec::Kind::GUEST_STORE) {
			last_store = i;
			have_store = true;
		}
	}
	CHECK(have_store);
	if (!have_store) {
		return;
	}

	unsigned n_arith = 0;
	for (size_t i = 0; i <= last_store; ++i) {
		std::string const &l = lines[i];
		size_t const tab = l.find('\t');
		if (tab == std::string::npos) {
			continue;
		}
		std::string const rhs = l.substr(tab + 1);
		size_t const sp = rhs.find(' ');
		std::string const mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
		if (mnem != "add" && mnem != "lea" && mnem != "inc" && mnem != "sub") {
			continue;
		}
		// Only arithmetic naming the frame's base register matters; the region's own
		// loop/ip bookkeeping is not this route's business.
		if (rhs.find(base32) == std::string::npos && rhs.find(base64) == std::string::npos) {
			continue;
		}
		++n_arith;
		fprintf(stderr, "    %s: address arithmetic on %s/%s: %s\n", tag, base32.c_str(),
			base64.c_str(), l.c_str());
	}
	CHECK_EQ(n_arith, 0u);
	printf("    OK %s/%s carries the base and is never modified; chunk 1 is a +0x40 "
	       "host displacement\n",
	       base32.c_str(), base64.c_str());
}

// ---------------------------------------------------------------------------------------------
// 7. Containment: the frame's ENTIRE vector footprint, bounded rather than counted.
// ---------------------------------------------------------------------------------------------
//
// This section exists because the store's failure mode is not the load's. A load that emitted one
// extra 64-byte move would corrupt an architectural vector register the frozen guest observes; a
// store that emitted one would overwrite 64 bytes of guest memory the guest still owns, with no
// translation invalidation. So it is not enough to count the moves this route is supposed to make:
// what must be bounded is everything vector the frame emits AT ALL.
//
// The gate: the emitted region contains exactly 2*nchunks lines naming any vector register of any
// width, all of them `vmovdqu64`, split exactly nchunks/nchunks between the state read and the guest
// write, at guest displacements exactly {0} or {0, 0x40}. Together with section [5]'s base-register
// identity that is the statement "the guest bytes this frame can touch are exactly
// [base, base + 64*nchunks)".
void CheckContainment(char const *tag, u32 vlen_bits, u32 nchunks)
{
	printf("[7] %s: containment -- the frame's whole vector footprint\n", tag);

	std::vector<std::string> lines;
	auto const vecs = EmitAndDecode(tag, vlen_bits, INSN_VSE32_V, &lines);
	if (vecs.empty() || lines.empty()) {
		return;
	}

	// Every vector-register-bearing line in the whole emitted region, by any spelling. ymm/xmm are
	// counted too: an emitter that had used a 32-byte or 16-byte operand would move the wrong
	// number of bytes, and the ZMM-only census of section [5] would not see it.
	unsigned n_vec_lines = 0, n_non_vmovdqu64 = 0;
	for (auto const &l : lines) {
		if (l.find("zmm") == std::string::npos && l.find("ymm") == std::string::npos &&
		    l.find("xmm") == std::string::npos) {
			continue;
		}
		++n_vec_lines;
		if (l.find("vmovdqu64") == std::string::npos) {
			++n_non_vmovdqu64;
			fprintf(stderr, "    %s: unexpected vector instruction: %s\n", tag, l.c_str());
		}
	}
	CHECK_EQ(n_vec_lines, 2u * nchunks);
	CHECK_EQ(n_non_vmovdqu64, 0u);

	std::set<i64> written;
	unsigned n_state_load = 0, n_guest_store = 0, n_other_role = 0;
	for (auto const &v : vecs) {
		switch (v.kind) {
		case DecodedVec::Kind::STATE_LOAD:
			++n_state_load;
			break;
		case DecodedVec::Kind::GUEST_STORE:
			++n_guest_store;
			written.insert(v.disp);
			break;
		case DecodedVec::Kind::GUEST_LOAD:
		case DecodedVec::Kind::STATE_STORE:
			++n_other_role;
			break;
		case DecodedVec::Kind::BASE:
			break;
		}
	}
	CHECK_EQ(n_state_load, nchunks);
	CHECK_EQ(n_guest_store, nchunks);
	CHECK_EQ(n_other_role, 0u);
	std::set<i64> want;
	for (u32 c = 0; c < nchunks; ++c) {
		want.insert((i64)(c * 64u));
	}
	CHECK(written == want);
	printf("    OK %u vector line(s) total, all vmovdqu64; guest bytes touched = "
	       "[base+0, base+%u)\n",
	       n_vec_lines, 64u * nchunks);
}

// ---------------------------------------------------------------------------------------------
// 8. Non-capture, on emitted bytes.
// ---------------------------------------------------------------------------------------------
//
// Each word here is pushed through the REAL code generator with this route fully open, and must
// produce NO ZMM instruction at all. That is a stronger statement than the QIR fallback table: a
// route could construct the right nodes and still have an emitter that fired on the wrong opcode.
void CheckNonCapture(u32 vlen_bits)
{
	printf("[8] non-capture on emitted bytes, VLEN=%u\n", vlen_bits);

	struct Row {
		char const *name;
		u32 word;
	};
	Row const rows[] = {
	    {"vle32.v (the LOAD -- S2.6's own switch, off)", INSN_VLE32_V},
	    {"masked vse32.v", INSN_VSE32_V_MASKED},
	    {"vse8.v", INSN_VSE8_V},
	    {"vse16.v", INSN_VSE16_V},
	    {"vse64.v", INSN_VSE64_V},
	    {"vsse32.v", INSN_VSSE32_V},
	    {"vsuxei32.v", INSN_VSUXEI32_V},
	    {"vs2r.v", INSN_VS2R_V},
	    {"vsseg2e32.v", INSN_VSSEG2E32_V},
	    {"vsm.v", INSN_VSM_V},
	    {"vse32.v with base x0", INSN_VSE32_V_X0},
	};

	for (auto const &r : rows) {
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.store_word = r.word;
		words[0] = cfg.vsetvli_word;
		words[1] = cfg.store_word;
		auto const code = EmitOne(arena, words, 2, cfg, cr);
		if (code.empty()) {
			continue;
		}
		auto const lines = Disassemble(code);
		CHECK(!lines.empty());
		unsigned n_zmm = 0;
		for (auto const &l : lines) {
			if (MentionsZmm(l)) {
				++n_zmm;
				fprintf(stderr, "    %s: unexpected ZMM line: %s\n", r.name,
					l.c_str());
			}
		}
		CHECK_EQ(n_zmm, 0u);
		printf("    %-44s 0 zmm instructions\n", r.name);
	}
}

// ---------------------------------------------------------------------------------------------
// 9. Coexistence with the accepted routes, and the load -> ALU -> store ordering.
// ---------------------------------------------------------------------------------------------
//
// The store route, the accepted S2.6 load route and the accepted S2.4 vand route open together in
// one process. This is the only section that states the earlier routes' non-regression POSITIVELY:
// silence would also be produced by a route that had stopped working.
//
// It is also where the ORDERING obligation is discharged. The frozen mixed loop reads a buffer and
// writes the SAME buffer in one strip step, so the emitted guest loads must precede the emitted
// `vpandd`, which must precede the emitted guest stores. Both `vchunkload` and `vchunkstore` are
// declared SIDEEFF (qir_ops.h), and the check below reads the resulting order off the emitted
// stream rather than trusting the flag.
void CheckPipelineOrdering(char const *tag, u32 vlen_bits, u32 nchunks, u32 store_word,
			   u32 store_base_reg, char const *shape)
{
	printf("[9] %s: vle32.v -> vand.vv -> %s (%s), VLEN=%u\n", tag, "vse32.v", shape, vlen_bits);

	MemArena arena(8u << 20);
	u32 words[4] = {INSN_VSETVLI_E32M1, INSN_VLE32_V_A2_V8, INSN_VAND_VV_9_8_8, store_word};
	TestCompilerRuntime cr;
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.typed_chunk_vle = true;
	cfg.typed_chunk_and = true;
	Region *region = TranslateOne(arena, words, 4, cfg);
	// All three routes fired, each producing its own body ops and no helper for its own opcode.
	CHECK_EQ(CountOp(region, Op::_vchunkload), nchunks);  // the load frame's guest read
	CHECK_EQ(CountOp(region, Op::_vchunkand), nchunks);   // the ALU
	CHECK_EQ(CountOp(region, Op::_vchunkstore), nchunks); // the store frame's guest write
	// The two CPUState ops are SHARED between the three frames, so their totals are stated as
	// arithmetic over the frames rather than as this route's own count -- a frame that stopped
	// emitting its half is then visible as a wrong total.
	//   vstatechunkstore: the load frame writes vd (1/chunk), the ALU frame writes its vd
	//                     (1/chunk); the store frame writes no CPUState at all  -> 2/chunk.
	//   vstatechunkload : the ALU frame reads vs2 and vs1 (2/chunk), the store frame reads vs3
	//                     (1/chunk); the load frame reads no CPUState at all    -> 3/chunk.
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), 2u * nchunks);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), 3u * nchunks);
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vle), 0u);
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vse), 0u);
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vialu), 0u);

	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
	std::vector<u8> const code(span.begin(), span.end());
	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		return;
	}

	// Positions in the emitted stream, in order.
	std::vector<size_t> gload_at, and_at, gstore_at;
	std::vector<DecodedVec> gstores;
	std::vector<DecodedVec> bases;
	for (size_t i = 0; i < lines.size(); ++i) {
		if (lines[i].find("vpandd") != std::string::npos) {
			and_at.push_back(i);
			continue;
		}
		DecodedVec dv{};
		if (!ParseLine(lines[i], &dv)) {
			continue;
		}
		if (dv.kind == DecodedVec::Kind::GUEST_LOAD) {
			gload_at.push_back(i);
		} else if (dv.kind == DecodedVec::Kind::GUEST_STORE) {
			gstore_at.push_back(i);
			gstores.push_back(dv);
		} else if (dv.kind == DecodedVec::Kind::BASE) {
			bases.push_back(dv);
		}
	}
	CHECK_EQ(gload_at.size(), (size_t)nchunks);
	CHECK_EQ(and_at.size(), (size_t)nchunks);
	CHECK_EQ(gstore_at.size(), (size_t)nchunks);
	if (gload_at.size() != nchunks || and_at.size() != nchunks || gstore_at.size() != nchunks) {
		for (auto const &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return;
	}
	// THE ORDERING GATE. Every guest READ precedes every vpandd, which precedes every guest WRITE.
	// A pass that sank the load past the store, or hoisted the store above the ALU, would break
	// the in-block memory dependence the frozen mixed loop actually has.
	CHECK(gload_at.back() < and_at.front());
	CHECK(and_at.back() < gstore_at.front());

	// THE DESTINATION BASE. The store's own base read must name the slot of the register the
	// STORE encodes, which in the independent-base row is not the load's.
	bool found_store_base = false;
	for (auto const &b : bases) {
		if (b.disp == (i64)GprOffs(store_base_reg)) {
			found_store_base = true;
		}
	}
	CHECK(found_store_base);
	for (auto const &s : gstores) {
		CHECK_STREQ(Norm64(s.breg), "rax");
	}
	printf("    OK %zu guest read(s) < %zu vpandd < %zu guest write(s); store base slot 0x%x "
	       "present\n",
	       gload_at.size(), and_at.size(), gstore_at.size(), GprOffs(store_base_reg));
}

void CheckCoexistence(u32 vlen_bits, u32 nchunks)
{
	printf("[9b] coexistence with the accepted S2.4 vand.vv and S2.6 vle32.v routes, VLEN=%u\n",
	       vlen_bits);

	// The store, with the and and load routes also open.
	{
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.typed_chunk_and = true;
		cfg.typed_chunk_vle = true;
		cfg.store_word = INSN_VSE32_V;
		Region *region = TranslateCfg(arena, words, cfg);
		CHECK_EQ(CountOp(region, Op::_vstatechunkload), nchunks);
		CHECK_EQ(CountOp(region, Op::_vchunkstore), nchunks);
		CHECK_EQ(CountOp(region, Op::_vchunkand), 0u);
		CHECK_EQ(CountOp(region, Op::_vchunkload), 0u);

		qir::CodeSegment segment(0u, 0x1000u);
		auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
		std::vector<u8> const code(span.begin(), span.end());
		auto const lines = Disassemble(code);
		unsigned n_movdqu = 0, n_pandd = 0, n_gload = 0;
		for (auto const &l : lines) {
			n_movdqu += (l.find("vmovdqu64") != std::string::npos);
			n_pandd += (l.find("vpandd") != std::string::npos);
			DecodedVec dv{};
			if (ParseLine(l, &dv) && dv.kind == DecodedVec::Kind::GUEST_LOAD) {
				++n_gload;
			}
		}
		CHECK_EQ(n_movdqu, 2u * nchunks);
		CHECK_EQ(n_pandd, 0u);
		CHECK_EQ(n_gload, 0u);
		printf("    vse32.v with three switches on: %u vmovdqu64, %u vpandd, %u guest loads\n",
		       n_movdqu, n_pandd, n_gload);
	}
	// The and, with the store route also open. Its own mnemonic must be exactly what S2.4
	// accepted, and no guest-memory access may appear.
	{
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.typed_chunk_and = true;
		cfg.typed_chunk_vle = true;
		cfg.store_word = INSN_VAND_VV;
		Region *region = TranslateCfg(arena, words, cfg);
		CHECK_EQ(CountOp(region, Op::_vchunkand), nchunks);
		CHECK_EQ(CountOp(region, Op::_vchunkstore), 0u);
		CHECK_EQ(CountOp(region, Op::_vchunkload), 0u);

		qir::CodeSegment segment(0u, 0x1000u);
		auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
		std::vector<u8> const code(span.begin(), span.end());
		auto const lines = Disassemble(code);
		unsigned n_pandd = 0, n_guest = 0;
		for (auto const &l : lines) {
			n_pandd += (l.find("vpandd") != std::string::npos);
			DecodedVec dv{};
			if (ParseLine(l, &dv) && (dv.kind == DecodedVec::Kind::GUEST_STORE ||
						  dv.kind == DecodedVec::Kind::GUEST_LOAD)) {
				++n_guest;
			}
		}
		CHECK_EQ(n_pandd, nchunks);
		// The and frame touches CPUState only. A store route that had captured an ALU PC would
		// show a guest-addressed vmovdqu64 here -- and it would be a WRITE.
		CHECK_EQ(n_guest, 0u);
		printf("    vand.vv with three switches on: %u vpandd, %u guest-memory accesses\n",
		       n_pandd, n_guest);
	}
	// The load, with the store route also open. Its accepted shape must be unchanged: nchunks
	// guest READS and nchunks CPUState writes, and no guest write at all.
	{
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.typed_chunk_and = true;
		cfg.typed_chunk_vle = true;
		cfg.store_word = INSN_VLE32_V;
		Region *region = TranslateCfg(arena, words, cfg);
		CHECK_EQ(CountOp(region, Op::_vchunkload), nchunks);
		CHECK_EQ(CountOp(region, Op::_vstatechunkstore), nchunks);
		CHECK_EQ(CountOp(region, Op::_vchunkstore), 0u);

		qir::CodeSegment segment(0u, 0x1000u);
		auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
		std::vector<u8> const code(span.begin(), span.end());
		auto const lines = Disassemble(code);
		unsigned n_gload = 0, n_gstore = 0;
		for (auto const &l : lines) {
			DecodedVec dv{};
			if (!ParseLine(l, &dv)) {
				continue;
			}
			n_gload += (dv.kind == DecodedVec::Kind::GUEST_LOAD);
			n_gstore += (dv.kind == DecodedVec::Kind::GUEST_STORE);
		}
		CHECK_EQ(n_gload, nchunks);
		CHECK_EQ(n_gstore, 0u);
		printf("    vle32.v with three switches on: %u guest loads, %u guest stores\n", n_gload,
		       n_gstore);
	}
}

// ---------------------------------------------------------------------------------------------
// 10. The frozen workload's own vse32.v words.
// ---------------------------------------------------------------------------------------------
void CheckFrozenWords(u32 vlen_bits, u32 nchunks)
{
	printf("[10] the frozen S1.1-fix1 suite's three distinct vse32.v words, VLEN=%u\n", vlen_bits);
	for (auto const &f : FROZEN_STORES) {
		// Each word has its own (vs3, base) pair, so this is the check that the two state
		// offsets the frame computes really come from the encoding.
		MemArena arena(4u << 20);
		u32 words[2];
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.store_word = f.word;
		Region *region = TranslateCfg(arena, words, cfg);
		auto g = FindGroup(region);
		CHECK_EQ(g.n_begin, 1u);
		CHECK_EQ(g.body.size(), (size_t)(2 * nchunks));
		if (g.body.size() != 2 * nchunks) {
			continue;
		}
		for (u32 c = 0; c < nchunks; ++c) {
			auto *ld = static_cast<InstVStateChunkLoad *>(g.body[c]);
			CHECK_EQ((u32)ld->offs, ChunkOffs(f.vs3, c));
			auto *st = static_cast<InstVChunkStore *>(g.body[nchunks + c]);
			CHECK_EQ((u32)st->base_state_offs, GprOffs(f.base));
			CHECK_EQ((u32)st->disp, c * 64u);
		}
		printf("    %-20s vs3=v%-2u base=x%-2u -> %u chunk(s) OK\n", f.text, f.vs3, f.base,
		       nchunks);
	}
}

// ---------------------------------------------------------------------------------------------
// 11. S2.7-fix1 (Codex-found): the EMITTER's own sizeof(CPUState) bound on the indirect base.
// ---------------------------------------------------------------------------------------------
//
// THE DEFECT THIS SECTION EXISTS FOR. qir.h documents a two-stage validation for the indirect
// addressing form of both `vchunkload` and `vchunkstore`: QIR checks that the CPUState offset is
// REPRESENTABLE in the u16 encoding, and QEmit checks -- against `sizeof(CPUState)`, which QIR
// cannot see -- that the 4-byte address read it names actually lies inside CPUState. That is
// exactly the division of labour the two `InstVStateChunk*` emitters implement. The second stage
// was documented but NOT implemented for either indirect form: both emitters read
// `[R_STATE + base_state_offs]` unconditionally. Every offset the routes can produce is a guest GPR
// slot and is therefore in range, so no routed frame was ever wrong -- but the bound the comment
// promised did not exist, and on the store side an out-of-range base would take a guest ADDRESS
// from unrelated host memory past the end of CPUState and then make it the destination of a 64-byte
// guest-memory write.
//
// WHAT IS ASSERTED, AND WHY IT NEEDS A FORKED CHILD. `Panic` is noreturn (it aborts), so an
// out-of-range construction cannot be observed by a return value. Each case below builds a minimal
// region containing ONE indirect chunk op, runs the REAL qcg::GenerateCode pipeline in a forked
// child, and requires the child to die on SIGABRT. The same device qra_vpr_test's T3 uses.
//
// THE OFFSET IS DERIVED, NOT PICKED. `sizeof(CPUState)` is the smallest offset whose 4-byte read is
// out of bounds, and it is asserted here to be BOTH below the u16 representability limit AND
// different from NO_STATE_BASE -- so the QIR constructor accepts it and the emitter is provably the
// only thing that can reject it. That is what makes this a test of the emitter bound rather than of
// the QIR bound that already existed.
//
// EVERY DEATH CASE HAS AN IN-RANGE POSITIVE CONTROL that must exit 0 through the same code path, so
// a child dying for an unrelated reason cannot be mistaken for the bound firing.

// A hand-built region needs a StateInfo; one tracked global is enough, and the offset does not
// matter because nothing below reads it. Deliberately NOT rv32's, so nothing here depends on the
// guest's own layout -- only on sizeof(CPUState), which is what the emitter bounds against.
enum { G_VAL = 0, G_COUNT };
StateReg g_state_regs[] = {
    {(u16)ST_GPR_BASE, VType::I32, "g0"},
};
StateInfo g_state_info{g_state_regs, G_COUNT};

struct HandBuiltRegion {
	explicit HandBuiltRegion(size_t arena_sz = 1u << 20) : arena(arena_sz)
	{
		region = arena.New<Region>(&arena, &g_state_info);
		bb = region->CreateBlock();
		qb = Builder(bb);
	}
	VOperand NewV()
	{
		return VOperand::MakeVVPR(VType::V512, qb.CreateVGPR(VType::V512));
	}
	MemArena arena;
	Region *region{};
	Block *bb{};
	Builder qb{nullptr};
};

// Run one hand-built region through the real code generator in a child process. Returns:
//   0  the child exited 0 (no Panic)
//   1  the child died on SIGABRT (Panic)
//   2  anything else
int EmitInChild(void (*build)(HandBuiltRegion &, u32), u32 base_offs)
{
	fflush(stdout);
	fflush(stderr);
	pid_t const pid = fork();
	if (pid == 0) {
		HandBuiltRegion t;
		build(t, base_offs);
		TestCompilerRuntime cr;
		(void)qcg::GenerateCode(&cr, nullptr, t.region, 0);
		_exit(0); // reached only if the emitter accepted the offset
	}
	if (pid < 0) {
		return 2;
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid) {
		return 2;
	}
	if (WIFSIGNALED(status)) {
		return WTERMSIG(status) == SIGABRT ? 1 : 2;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return 0;
	}
	return 2;
}

void BuildIndirectLoad(HandBuiltRegion &t, u32 base_offs)
{
	auto v = t.NewV();
	t.qb.Create_vchunkload(v, base_offs, 0u);
	// A consumer, so the value is not dead and the load survives to the emitter.
	t.qb.Create_vstatechunkstore(ChunkOffs(0, 0), v);
}

void BuildIndirectStore(HandBuiltRegion &t, u32 base_offs)
{
	auto v = t.NewV();
	t.qb.Create_vstatechunkload(v, ChunkOffs(0, 0));
	t.qb.Create_vchunkstore(base_offs, 0u, v);
}

void CheckIndirectBaseBound()
{
	printf("[11] the emitter's sizeof(CPUState) bound on the indirect base offset\n");

	u32 const oob = (u32)sizeof(CPUState);
	u32 const in_range = GprOffs(BASE_REG); // a real guest GPR slot: what the routes produce
	printf("    sizeof(CPUState)=%u  out-of-range offset=%u  in-range control=%u\n",
	       (unsigned)sizeof(CPUState), oob, in_range);

	// The offset must be one the QIR constructors ACCEPT, or this would be a test of the u16
	// bound that already existed rather than of the emitter bound this fix adds.
	CHECK(oob <= InstVChunkLoad::STATE_OFFS_LIMIT - sizeof(u32));
	CHECK(oob != InstVChunkLoad::NO_STATE_BASE);
	CHECK(oob <= InstVChunkStore::STATE_OFFS_LIMIT - sizeof(u32));
	CHECK(oob != InstVChunkStore::NO_STATE_BASE);
	CHECK((size_t)in_range + sizeof(u32) <= sizeof(CPUState));

	ArchTraits::init();

	struct Row {
		char const *name;
		void (*build)(HandBuiltRegion &, u32);
	};
	Row const rows[] = {
	    {"vchunkload  (S2.6 indirect form)", BuildIndirectLoad},
	    {"vchunkstore (S2.7 indirect form)", BuildIndirectStore},
	};
	for (auto const &r : rows) {
		int const oob_rc = EmitInChild(r.build, oob);
		int const ok_rc = EmitInChild(r.build, in_range);
		CHECK_EQ(oob_rc, 1); // must Panic
		CHECK_EQ(ok_rc, 0);  // must emit cleanly
		printf("    %-34s out-of-range=%s  in-range control=%s\n", r.name,
		       oob_rc == 1 ? "PANIC (rejected)" : "NOT REJECTED",
		       ok_rc == 0 ? "emitted" : "unexpectedly failed");
	}
}

} // namespace

int main()
{
	printf("S2.7: exact unmasked unit-stride vse32.v -> typed V512 chunk route\n\n");

	CheckEncodingSweep();
	CheckAcceptedSplitsUndisturbed();
	printf("\n");

	CheckRoute("VLEN=512", 512, 1, 16, INSN_VSE32_V, VS3_REG, BASE_REG);
	CheckRoute("VLEN=1024", 1024, 2, 32, INSN_VSE32_V, VS3_REG, BASE_REG);
	printf("\n");

	CheckFallbackTable();
	printf("\n");

	CheckRoutePostQRA("VLEN=512", 512, 1);
	CheckRoutePostQRA("VLEN=1024", 1024, 2);
	printf("\n");

	CheckRouteEmitted("VLEN=512", 512, 1, INSN_VSE32_V, VS3_REG, BASE_REG);
	CheckRouteEmitted("VLEN=1024", 1024, 2, INSN_VSE32_V, VS3_REG, BASE_REG);
	printf("\n");

	CheckNoAddressArithmetic("VLEN=512", 512);
	CheckNoAddressArithmetic("VLEN=1024", 1024);
	printf("\n");

	CheckContainment("VLEN=512", 512, 1);
	CheckContainment("VLEN=1024", 1024, 2);
	printf("\n");

	CheckNonCapture(512);
	CheckNonCapture(1024);
	printf("\n");

	CheckPipelineOrdering("VLEN=512", 512, 1, INSN_VSE32_V_A3_V9, 13, "independent bases a2->a3");
	CheckPipelineOrdering("VLEN=1024", 1024, 2, INSN_VSE32_V_A3_V9, 13,
			      "independent bases a2->a3");
	CheckPipelineOrdering("VLEN=512", 512, 1, INSN_VSE32_V_A2_V9, 12, "ALIASED base a2->a2");
	CheckPipelineOrdering("VLEN=1024", 1024, 2, INSN_VSE32_V_A2_V9, 12, "ALIASED base a2->a2");
	printf("\n");

	CheckCoexistence(512, 1);
	CheckCoexistence(1024, 2);
	printf("\n");

	CheckFrozenWords(512, 1);
	CheckFrozenWords(1024, 2);
	printf("\n");

	CheckIndirectBaseBound();
	printf("\n");

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
