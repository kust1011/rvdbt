// S2.6: the exact unmasked unit-stride `vle32.v` typed V512 chunk route, verified mechanically at
// five levels -- decoder, constructed QIR, post-QRegAlloc allocation, independently disassembled
// emitted host bytes, and coexistence with the six accepted ALU routes.
//
// This file is the memory-opcode twin of qmc/qcg/vandvv_typedchunk_route_test.cpp and keeps its
// structure so the seven routed frames are checked to the same depth. Three things make it NOT a
// rename, and each one is a section that has no analogue in S2.1-S2.4.
//
// [A] THE DECODER DOES NOT NARROW THE SHAPE FOR THIS ROUTE.
//
// Every accepted ALU route got `vm == 1` and its exact operation for free, because rv32_decode.h
// splits the unmasked encoding into its own Op:
//
//     vand.vv  funct3=OPIVV funct6=001001 vm=1  ->  Op::_vand_vv     (nothing else can arrive)
//
// `vle` has no such split. The decoder tests nf/mew/mop/lumop and then sends MASKED unit-stride
// loads and ALL FOUR supported EEWs to the SAME Op::_vle -- its own comment says so ("vm may be 0
// or 1 -- masked loads leave inactive elements undisturbed"). So `vm` and the width field are the
// ROUTE's obligation, and they are the only thing standing between a masked load (whose inactive
// elements must stay undisturbed) or a `vle8.v` (which moves a quarter of the bytes for the same
// vl) and a 64-byte block move. Section [1] is therefore an EXHAUSTIVE sweep of the whole LOAD-FP
// field space -- nf x mew x mop x vm x lumop x width, 32768 words -- pushed through the real
// translator, requiring that the set of words producing a typed frame is EXACTLY one.
//
// [B] THE READ SIDE IS GUEST MEMORY, AND ITS ADDRESS IS NOT AN ALLOCATED OPERAND.
//
// The frame is `vchunkload` -> `vstatechunkstore`, and `vchunkload` is used in its INDIRECT
// addressing form: the base is read out of CPUState through the emitter's fixed scratch register
// (qir.h explains why a QRegAlloc-allocated address operand cannot work inside a guard frame).
// Section [5] therefore gates something no earlier route had to: WHICH operand is the guest-memory
// reference. A frame that stored CPUState into guest memory instead of loading would have the right
// chunk count, the right registers, the right windows, the right guard and the right counters --
// only an operand-role check can see it.
//
// [C] THE SECOND CHUNK'S ADDRESS IS A DECISION, NOT AN ACCIDENT (S2.5 section 4.3).
//
// At VLEN=1024 the helper arm this route replaces, `rvv_chunked::load_unit_stride`, issues one
// `copy_chunked(dst, vmem + (u32)base, 128)` whose successive 64-byte chunks are addressed as
// `src + c*HOST_CHUNK_BYTES` in HOST pointer arithmetic -- they do not wrap modulo 2^32. A direct
// route that computed chunk 1's address as a QIR I32 add WOULD wrap, and the two would disagree for
// the 64 guest addresses in [2^32-128, 2^32-64). This route folds the displacement into the x86
// memory operand instead, so it does not wrap either and the divergence does not exist. Section [6]
// asserts that positively: chunk 1 must reuse chunk 0's base register with a +0x40 displacement,
// and the frame must contain NO address arithmetic at all.
//
//     RVV:  vle32.v vd, (rs1)   =>   vreg[vd] bytes [0, vl*4) <- mem[rs1, rs1+vl*4)
//           (rv32_vector_lower.h rvv_chunked::load_unit_stride, EEW from the width field)
//     QIR:  vchunkload d, [state:rs1]+disp ; vstatechunkstore [state:vreg+vd*128+disp], d
//     x86:  mov eax, DWORD PTR [r13+gpr_off] ; vmovdqu64 zmm, ZMMWORD PTR [rax+disp]
//           vmovdqu64 ZMMWORD PTR [r13+state_off], zmm
//
// WHAT THIS FILE PROVES
//
//   1. DECODER + ADMISSION. Of 32768 LOAD-FP encodings, exactly one produces a typed frame:
//      nf=0, mew=0, mop=00, vm=1, lumop=00000, width=110. Every other word keeps a helper. The six
//      accepted ALU splits are re-counted in the same run so this checkpoint cannot have disturbed
//      them.
//   2. QIR. At VLEN=512 the admitted instruction becomes ONE 512-bit chunk (2 typed ops); at
//      VLEN=1024 TWO chunks (4 typed ops), in load-major order, reading the guest base from the
//      CPUState slot of the ENCODED rs1 and writing the exact low/high 64-byte windows of vd, with
//      per-chunk def-use and no cross-chunk edge. Nothing is emitted at displacement 64 when
//      VLEN=512 -- the chunk count comes from config::vlen_bits, never from VLEN_MAX.
//   3. FALLBACK. Every forbidden shape keeps the pre-existing helper: zero typed nodes and exactly
//      one `hcall [rv32_vle]` (or the other opcode's own stub). Each forbidden condition is
//      exercised on its own axis, so a single over-broad gate cannot hide behind another.
//   4. QRA. Distinct physical VPRs per chunk, all out of VPR_POOL, containment surviving
//      allocation, and no allocator-inserted V512 mov inside the frame.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits, per chunk, one 64-byte `vmovdqu64` whose
//      SOURCE is a guest address and one whose DESTINATION is the r13-relative state window -- in
//      that direction -- with the exact allocated ZMM operands and, at VLEN=1024, two chunks whose
//      register sets are disjoint in the externally decoded bytes.
//   6. CHUNK-1 ADDRESS FORM. Same base register, +0x40 displacement, zero address arithmetic.
//   7. NON-CAPTURE. `vse32.v`, masked `vle32.v`, `vle8/16/64.v`, `vlse32.v`, `vleff`, `vl2re32.v`,
//      `vlseg2e32.v` and `vlm.v` are each pushed through the REAL code generator with this route
//      fully open, and each must produce no ZMM instruction at all.
//   8. COEXISTENCE. With all seven switches on in one process, `vle32.v` emits its load pair and
//      `vand.vv` still emits exactly `vpandd` -- the memory route does not perturb an accepted ALU
//      route, and the ALU route does not steal the load.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. Runtime correctness is the xbd evidence's obligation, on a host
//     that actually has AVX-512.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//   * It says nothing about `vse32.v` beyond "it still calls its helper". The store is a separate
//     checkpoint and this file must not be read as evidence for it.
//
// HOST NOTE. RvvQcgTypedVleChunkAdmit's host-feature row is a real __builtin_cpu_supports probe, so
// on a machine without AVX-512F the route would fail closed and there would be nothing to inspect.
// `config::rvv_qcg_typed_chunk_vle_force_emit` bypasses ONLY that probe -- not the architectural
// guard, not the admitted shape -- which is exactly what lets the emitted shape be audited here.
// This is the same device the six accepted route audits used.
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
// `r*VLEN_MAX_BYTES + chunk*64` formula RvvEmitTypedVleChunkGroup uses.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// The CPUState slot of guest register `r`, in the layout RV32Translator::GetStateInfo declares its
// globals with. This is what the emitted frame reads the base address from.
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

// The route's own encoding, with vd=v8 and base=a6(x16) -- the frozen suite's own register choice.
constexpr u32 VD_REG = 8;   // v8
constexpr u32 BASE_REG = 16; // x16 = a6

constexpr u32 INSN_VLE32_V = 0x02086407u;	  // vle32.v v8, (a6)
constexpr u32 INSN_VLE32_V_MASKED = 0x00086407u;  // vle32.v v8, (a6), v0.t   (vm = 0)
constexpr u32 INSN_VLE8_V = 0x02080407u;	  // vle8.v   v8, (a6)
constexpr u32 INSN_VLE16_V = 0x02085407u;	  // vle16.v  v8, (a6)
constexpr u32 INSN_VLE64_V = 0x02087407u;	  // vle64.v  v8, (a6)
constexpr u32 INSN_VLE32_V_X0 = 0x02006407u;	  // vle32.v v8, (zero)       (rs1 = x0)
constexpr u32 INSN_VLSE32_V = 0x0a586407u;	  // vlse32.v v8, (a6), a1     (mop = 10)
constexpr u32 INSN_VLE32FF_V = 0x03086407u;	  // vle32ff.v v8, (a6)       (lumop = 10000)
constexpr u32 INSN_VL2RE32_V = 0x22886407u;	  // vl2re32.v v8, (a6)       (lumop = 01000, nf = 1)
constexpr u32 INSN_VLSEG2E32_V = 0x22086407u;	  // vlseg2e32.v v8, (a6)     (nf = 1)
constexpr u32 INSN_VLM_V = 0x02b80407u;		  // vlm.v   v8, (a6)         (lumop = 01011)
constexpr u32 INSN_VSE32_V = 0x02086427u;	  // vse32.v v8, (a6)         (STORE-FP)
constexpr u32 INSN_VAND_VV = 0x261101d7u;	  // vand.vv v3, v1, v2

// The four words the frozen S1.1-fix1 guest ELF's mixed kernel actually contains (guest ELF
// SHA-256 67fb07833ed040f7d318c20a85a123ac86d3269bc7ba8a5f4f1ef62c2563cb34, per the accepted S2.0
// and S2.5 audits). Included so the route is tied to the real workload's encodings, not only to
// synthetic register choices. All four are distinct (vd, base) pairs, which is what makes them a
// useful check on the two state offsets the frame computes.
struct FrozenWord {
	char const *text;
	u32 word;
	u32 vd;
	u32 base;
};
constexpr FrozenWord FROZEN_MIX_LOADS[] = {
    {"vle32.v v8, (a6)", 0x02086407u, 8, 16},  // 0x132ac
    {"vle32.v v9, (a2)", 0x02066487u, 9, 12},  // 0x132b0
    {"vle32.v v10, (a3)", 0x0206e507u, 10, 13}, // 0x132b8
    {"vle32.v v11, (a4)", 0x02076587u, 11, 14}, // 0x132c0
};

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. The defaults are the fully-open configuration; the fallback table below
// flips exactly one field at a time off it.
//
// `typed_chunk_and` is a FIELD rather than hardcoded false, unlike the other five ALU switches,
// because section [8] needs one configuration in which an accepted ALU route and this memory route
// are open at once. It defaults to false so every other section observes this route in isolation.
struct RouteConfig {
	bool typed_chunk_vle = true;
	bool typed_chunk_and = false; // section [8] turns this on; everything else keeps it off
	bool force_emit = true;	      // see the file header HOST NOTE
	bool aot_use_llvm = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	unsigned rvv_lowering = 1; // 1 = fixed-width chunks; 0 = Ref, which this route refuses
	u32 vlen_bits = 512;
	u32 vsetvli_word = INSN_VSETVLI_E32M1;
	u32 load_word = INSN_VLE32_V;
};

void ApplyConfig(RouteConfig const &cfg)
{
	config::rvv_qcg_typed_chunk_vle = cfg.typed_chunk_vle;
	config::rvv_qcg_typed_chunk_vle_force_emit = cfg.force_emit;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::rvv_lowering = cfg.rvv_lowering;
	config::vlen_bits = cfg.vlen_bits;
	// The six accepted ALU routes' switches are normally off here: this file must observe the
	// load route in isolation, and an open ALU route would make a stray ZMM frame ambiguous.
	// Section [8] is the one place one of them is deliberately opened, and it uses the SAME
	// force-emit device so the audit bypass stays symmetric.
	config::rvv_qcg_typed_chunk_and = cfg.typed_chunk_and;
	config::rvv_qcg_typed_chunk_and_force_emit = cfg.typed_chunk_and;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_diag_chunk = false;
}

// One region containing exactly the translated vsetvli + load pair. Region is arena-allocated, so
// `arena` must outlive it -- both are locals in the caller's own scope.
Region *TranslateOne(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	ApplyConfig(cfg);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}}; // two 4-byte instructions at ip 0 and 4
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

Region *TranslateCfg(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	words[0] = cfg.vsetvli_word;
	words[1] = cfg.load_word;
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

// Number of hcalls to one specific runtime stub -- the fallback evidence: a non-admitted vle32.v
// must produce exactly one call to the PRE-EXISTING rv32_vle helper, not to a new stub.
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
	return CountOp(region, Op::_vchunkload) + CountOp(region, Op::_vstatechunkstore) +
	       CountOp(region, Op::_rvvtypedchunkbegin);
}

// ---------------------------------------------------------------------------------------------
// 1. Decoder + admission: an exhaustive sweep of the LOAD-FP encoding space.
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

// Assemble one LOAD-FP word with the register fields this file uses throughout (vd=v8, rs1=a6).
// The sweep varies ONLY the six fields the route's predicate tests, so a hit is attributable to the
// encoding class and not to a register choice.
constexpr u32 MakeLoadFP(u32 nf, u32 mew, u32 mop, u32 vm, u32 lumop, u32 width)
{
	return (nf << 29) | (mew << 28) | (mop << 26) | (vm << 25) | (lumop << 20) |
	       (BASE_REG << 15) | (width << 12) | (VD_REG << 7) | 0b0000111u;
}

// THE CENTRAL GATE OF THIS CHECKPOINT. Push all 8*2*4*2*32*8 = 32768 LOAD-FP encodings through the
// REAL translator with the route fully open, and require that exactly ONE produces a typed frame.
//
// This is a sweep over the translator rather than over the decoder because the decoder is not where
// this route's shape is decided (see the file header). A predicate that forgot `vm` would show up
// here as two admitted words; one that accepted all four supported EEWs as eight; one that dropped
// the lumop test as more still. None of those is visible in `DecodeWord` at all, because every one
// of those words legitimately reaches Op::_vle.
void CheckEncodingSweep()
{
	printf("[1] LOAD-FP encoding sweep: 8 nf x 2 mew x 4 mop x 2 vm x 32 lumop x 8 width = 32768\n");

	MemArena arena(1u << 20);
	u32 words[2];
	std::vector<u32> admitted;
	unsigned n_reach_vle = 0;

	for (u32 nf = 0; nf < 8; ++nf) {
		for (u32 mew = 0; mew < 2; ++mew) {
			for (u32 mop = 0; mop < 4; ++mop) {
				for (u32 vm = 0; vm < 2; ++vm) {
					for (u32 lumop = 0; lumop < 32; ++lumop) {
						for (u32 width = 0; width < 8; ++width) {
							u32 const w =
							    MakeLoadFP(nf, mew, mop, vm, lumop, width);
							n_reach_vle +=
							    (DecodeWord(w) == rv32::insn::Op::_vle);
							arena.Reset();
							RouteConfig cfg;
							cfg.load_word = w;
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
		CHECK_EQ(admitted[0], MakeLoadFP(0, 0, 0, 1, 0, 0b110));
		CHECK_EQ(admitted[0], INSN_VLE32_V);
		printf("    exactly 1 admitted word: 0x%08x "
		       "(nf=0 mew=0 mop=00 vm=1 lumop=00000 width=110)\n",
		       admitted[0]);
	} else {
		for (u32 w : admitted) {
			fprintf(stderr, "    unexpectedly admitted: 0x%08x\n", w);
		}
	}

	// The decoder's own reach, reported for contrast rather than as the gate: 4 supported widths
	// x 2 vm values = 8 words legitimately arrive at Op::_vle, and 7 of them must be refused by
	// the route's own predicate. That ratio is the whole reason this route has a predicate the
	// six ALU routes do not need.
	CHECK_EQ(n_reach_vle, 8u);
	printf("    %u of 32768 words reach Op::_vle; the route admits 1 of those 8\n", n_reach_vle);
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
void CheckRoute(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 load_word,
		u32 vd_reg, u32 base_reg)
{
	printf("[2] %s: VLEN=%u -> %u chunk(s)\n", tag, vlen_bits, nchunks);

	MemArena arena(4u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.load_word = load_word;
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
	CHECK_EQ(g.begin->raw, load_word);
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vle);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vle);
	// Two typed ops per chunk -- a load and a store. The `end` emitter Panics if the body it saw
	// is not this shape, so a wrong declaration here is a translation abort, not a silent miscount.
	CHECK_EQ((unsigned)g.begin->n_typed, 2u * nchunks);
	CHECK_EQ(g.body.size(), (size_t)(2 * nchunks));
	if (g.body.size() != 2 * nchunks) {
		return;
	}

	// LOAD-MAJOR: every chunk's guest-memory load, then every chunk's state store.
	std::vector<RegN> load_dsts;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *ins = g.body[c];
		CHECK(ins->GetOpcode() == Op::_vchunkload);
		if (ins->GetOpcode() != Op::_vchunkload) {
			return;
		}
		auto *ld = static_cast<InstVChunkLoad *>(ins);
		// THE ADDRESS. Indirect form, reading the CPUState slot of the ENCODED base register.
		// A route that hardcoded a register, or that read the vd slot, fails here.
		CHECK_EQ((u32)ld->base_state_offs, GprOffs(base_reg));
		CHECK(ld->base_state_offs != InstVChunkLoad::NO_STATE_BASE);
		// THE DISPLACEMENT (S2.5 section 4.3). Chunk c is at +64c, folded into the memory
		// operand rather than computed. Section [6] re-derives this from emitted bytes.
		CHECK_EQ((u32)ld->disp, c * 64u);
		// The unused operand slot of the indirect form.
		CHECK(ld->i(0).IsConst());
		CHECK_EQ(ld->i(0).GetConst(), 0u);
		CHECK(ld->o(0).GetType() == VType::V512);
		load_dsts.push_back(ld->o(0).GetVVPR());
	}
	for (u32 c = 0; c < nchunks; ++c) {
		auto *ins = g.body[nchunks + c];
		CHECK(ins->GetOpcode() == Op::_vstatechunkstore);
		if (ins->GetOpcode() != Op::_vstatechunkstore) {
			return;
		}
		auto *st = static_cast<InstVStateChunkStore *>(ins);
		// THE WINDOW. vd's own 128-byte slot, chunk c's own 64-byte half. An off-by-one
		// destination register differs by 128 here.
		CHECK_EQ((u32)st->offs, ChunkOffs(vd_reg, c));
		// Per-chunk def-use: chunk c's store consumes chunk c's load and nothing else.
		CHECK(st->i(0).IsVVPR());
		CHECK_EQ(st->i(0).GetVVPR(), load_dsts[c]);
	}
	// The two chunks are independent values. At VLEN=1024 a shared value would mean the high
	// chunk overwrote the low one's data.
	if (nchunks == 2) {
		CHECK(load_dsts[0] != load_dsts[1]);
	}

	// NOTHING AT +64 WHEN VLEN=512 -- the trap S2.5 section 3 names. A chunk count taken from
	// VLEN_MAX_BITS instead of config::vlen_bits is invisible at VLEN=1024 and corrupts the
	// NEIGHBOURING register's slot at VLEN=512.
	if (nchunks == 1) {
		for (auto *ins : g.body) {
			if (ins->GetOpcode() == Op::_vstatechunkstore) {
				CHECK(static_cast<InstVStateChunkStore *>(ins)->offs !=
				      ChunkOffs(vd_reg, 1));
			}
			if (ins->GetOpcode() == Op::_vchunkload) {
				CHECK_EQ((u32)static_cast<InstVChunkLoad *>(ins)->disp, 0u);
			}
		}
	}

	// The frame is the whole lowering: no helper for this instruction, and none of the six ALU
	// routes' body ops anywhere.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vle), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkload), nchunks);
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), nchunks);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkstore), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunksub), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkmul), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkxor), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkor), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkand), 0u);
	// The vsetvli ahead of it is untouched -- this checkpoint implements ONE opcode.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vsetvli), 1u);
	printf("    OK vlmax=%u, %u vchunkload(+disp %s) -> %u vstatechunkstore, base slot 0x%x\n",
	       expect_vlmax, nchunks, nchunks == 2 ? "0,64" : "0", nchunks, GprOffs(base_reg));
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
	unsigned const hcalls = CountHcall(region, RuntimeStubId::id_rv32_vle);
	CHECK_EQ(typed, 0u);
	CHECK_EQ(hcalls, 1u);
	printf("    %-46s typed=%u hcall[rv32_vle]=%u\n", why, typed, hcalls);
}

// A word that belongs to a DIFFERENT decode family. It must reach that family's own pre-existing
// stub -- not this route, and not rv32_vle either.
void CheckFallbackOtherFamily(char const *why, u32 word, RuntimeStubId want_stub)
{
	MemArena arena(4u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.load_word = word;
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
		c.typed_chunk_vle = false;
		CheckFallback("switch off (the DEFAULT)", c);
	}
	{
		RouteConfig c;
		c.aot_use_llvm = true;
		CheckFallback("aot_use_llvm (LLVM has no vchunkload lowering)", c);
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
		// SEW=16 from vtype gives EMUL = (32/16)*1 = 2: the destination is a TWO-register
		// group and one 64-byte chunk per register is not the whole of it. An admission test
		// that used LMUL where EMUL was meant would pass this row.
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E16M1;
		CheckFallback("e16,m1 (EMUL=2 != LMUL=1)", c);
	}
	{
		RouteConfig c;
		c.load_word = INSN_VLE32_V_MASKED;
		CheckFallback("MASKED vle32.v (vm=0; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.load_word = INSN_VLE8_V;
		CheckFallback("vle8.v  (EEW=8; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.load_word = INSN_VLE16_V;
		CheckFallback("vle16.v (EEW=16; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.load_word = INSN_VLE64_V;
		CheckFallback("vle64.v (EEW=64; decoder does not filter it)", c);
	}
	{
		RouteConfig c;
		c.load_word = INSN_VLE32_V_X0;
		CheckFallback("base register x0 (not a tracked global)", c);
	}

	// Different decode families. These cannot reach the route at all, and the rows exist to say
	// so from the translator rather than from a reading of the decoder.
	CheckFallbackOtherFamily("vlse32.v   (strided, mop=10)", INSN_VLSE32_V,
				 RuntimeStubId::id_rv32_vlse);
	CheckFallbackOtherFamily("vle32ff.v  (fault-only-first, lumop=10000)", INSN_VLE32FF_V,
				 RuntimeStubId::id_rv32_vleff);
	CheckFallbackOtherFamily("vl2re32.v  (whole-register, lumop=01000)", INSN_VL2RE32_V,
				 RuntimeStubId::id_rv32_vlNre);
	CheckFallbackOtherFamily("vlseg2e32.v (segment, nf=1)", INSN_VLSEG2E32_V,
				 RuntimeStubId::id_rv32_vlseg);
	CheckFallbackOtherFamily("vlm.v      (mask load, lumop=01011)", INSN_VLM_V,
				 RuntimeStubId::id_rv32_vlm);
	// THE OPCODE THIS CHECKPOINT IS NOT. S2.6 is one opcode; the store must be untouched.
	CheckFallbackOtherFamily("vse32.v    (the STORE -- a later checkpoint)", INSN_VSE32_V,
				 RuntimeStubId::id_rv32_vse);
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
		if (ins->GetOpcode() == Op::_vchunkload) {
			auto d = ins->o(0);
			CHECK(d.IsPVPR());
			CHECK(ArchTraits::VPR_POOL.Test(d.GetPVPR()));
			zmms.insert(d.GetPVPR());
		}
		if (ins->GetOpcode() == Op::_vstatechunkstore) {
			auto s = ins->i(0);
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
// 5+6. Emitted host bytes, decoded by an external disassembler.
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

// The three host instruction shapes this frame can emit, and nothing else.
//
// BASE is the scalar `mov <r32>, DWORD PTR [r13+off]` that materialises the guest base address.
// GUEST_LOAD's memory operand names a GUEST address; STATE_STORE's names r13. Keeping them as
// distinct kinds -- rather than one "vmovdqu64" kind with a flag -- is what makes a direction slip
// a parse-level failure instead of an operand-comparison failure.
struct DecodedVec {
	enum class Kind { BASE, GUEST_LOAD, STATE_STORE } kind;
	std::string mnemonic;
	unsigned zmm{};	    // for GUEST_LOAD / STATE_STORE
	std::string breg;   // base GPR text, for BASE (destination) and GUEST_LOAD (address)
	i64 disp{};	    // r13 displacement for BASE/STATE_STORE, guest displacement for GUEST_LOAD
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

// Parse one objdump Intel-syntax line into one of the three shapes above, or return false.
//
// A `vmovdqu64` whose GUEST address is the DESTINATION is deliberately NOT recognised. That is the
// direction mutation from S2.5 section 6: swapping the frame's two moves keeps the chunk count, the
// register sets, the windows, the guard and the counters all correct, and only reading which
// operand is the memory reference can see it. Such a line arrives here as an unrecognised
// ZMM-bearing line and fails loudly with its text.
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
		// GUEST LOAD: zmm <- [guest]. The 64-byte operand size is objdump's own ZMMWORD.
		if (ParseZmm(ops[0], &zr) && ParseMemOperand(ops[1], "ZMMWORD", &reg, &disp) &&
		    reg != "r13") {
			*out = DecodedVec{DecodedVec::Kind::GUEST_LOAD, mnem, zr, reg, disp};
			return true;
		}
		// STATE STORE: [r13+off] <- zmm.
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
	char path[] = "/tmp/rvdbt_s26_emit_XXXXXX";
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

std::vector<u8> EmitOne(MemArena &arena, u32 (&words)[2], RouteConfig const &cfg,
			TestCompilerRuntime &cr)
{
	Region *region = TranslateCfg(arena, words, cfg);
	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cr, &segment, region, 0);
	CHECK(!code_span.empty());
	return std::vector<u8>(code_span.begin(), code_span.end());
}

// Emit one admitted vle32.v through the real pipeline and return the decoded census, in emission
// order. Every line naming a ZMM register that ParseLine does not recognise is a hard failure with
// the offending text, not a silent drop -- that is what makes the counts below a census.
std::vector<DecodedVec> EmitAndDecode(char const *tag, u32 vlen_bits, u32 load_word,
				      std::vector<std::string> *out_lines)
{
	MemArena arena(4u << 20);
	u32 words[2];
	TestCompilerRuntime cr;
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.load_word = load_word;
	auto const code = EmitOne(arena, words, cfg, cr);
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

void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 nchunks, u32 load_word, u32 vd_reg,
		       u32 base_reg)
{
	printf("[5] %s: emitted host bytes, objdump-decoded\n", tag);

	std::vector<std::string> lines;
	auto const vecs = EmitAndDecode(tag, vlen_bits, load_word, &lines);
	if (vecs.empty()) {
		return;
	}

	// The census: one base materialisation, then per chunk one guest load and one state store.
	// The base read is counted separately because more than one would mean the frame recomputed
	// an address it already had -- which is the shape a wrapping I32 add would have produced.
	std::vector<DecodedVec> bases, loads, stores;
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
		case DecodedVec::Kind::GUEST_LOAD:
			loads.push_back(v);
			break;
		case DecodedVec::Kind::STATE_STORE:
			stores.push_back(v);
			break;
		}
	}

	CHECK_EQ(loads.size(), (size_t)nchunks);
	CHECK_EQ(stores.size(), (size_t)nchunks);
	// ONE base read PER CHUNK, and this is a recorded property rather than an optimum. Each
	// vchunkload emits its own `mov <scratch>, [r13+gpr_off]`, so the op is self-contained and no
	// emitter state is carried between the two chunks -- the same "the emitter picks nothing and
	// remembers nothing" discipline the six ALU frames keep. The reload is redundant (nothing
	// between the two loads writes that CPUState slot; the stores come after both, load-major) and
	// it is a known, deliberate cost, not an accident. What matters for correctness is asserted
	// below: every base read names the SAME slot and the SAME fixed scratch register, so both
	// chunks address the same base.
	// A13-FIX: PLUS ONE. The frame's guard now reads the base once more (`mov eax,[r13+gpr]` then
	// `cmp eax, 2^32 - VLEN/8; ja fallback`) so that no chunk window can leave the 4 GiB guest
	// space; the pre-A13-FIX count of exactly nchunks is not preserved because that frame carried
	// the over-access. The per-chunk reads below are unchanged.
	CHECK_EQ(bases.size(), (size_t)nchunks + 1u);
	if (loads.size() != nchunks || stores.size() != nchunks || bases.size() != nchunks + 1u) {
		for (auto const &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return;
	}

	// THE SCRATCH REGISTER IS THE WHOLE SAFETY ARGUMENT, so it is pinned by name. ArchTraits::AX
	// is in GPR_FIXED, which QRegAlloc::AllocPReg can never return, which is why writing it inside
	// the guarded window cannot destroy an allocated value and why no operand -- and therefore no
	// allocator fill -- is needed at all (qir.h InstVChunkLoad). A change that moved this to a
	// pool register would silently reintroduce exactly the hazard the indirect form removes, and
	// would be invisible to every structural count in this file.
	std::string const base_gpr = Norm64(bases[0].breg);
	CHECK_STREQ(base_gpr, "rax");
	for (auto const &b : bases) {
		CHECK_STREQ(Norm64(b.breg), base_gpr);
		CHECK_EQ(b.disp, (i64)GprOffs(base_reg));
	}

	std::set<unsigned> load_zmms, store_zmms;
	for (u32 c = 0; c < nchunks; ++c) {
		// DIRECTION. The guest address is the SOURCE of a load and the r13 window is the
		// DESTINATION of a store. A frame built by copy-editing a future vse frame would
		// reverse both and never reach here (ParseLine refuses that shape).
		CHECK(loads[c].kind == DecodedVec::Kind::GUEST_LOAD);
		CHECK(stores[c].kind == DecodedVec::Kind::STATE_STORE);
		// The guest address is the base register the frame just materialised, plus this
		// chunk's displacement -- and NOTHING else. Section [6]'s core assertion.
		CHECK_STREQ(Norm64(loads[c].breg), base_gpr);
		CHECK_EQ(loads[c].disp, (i64)(c * 64u));
		// The destination window is vd's own slot, this chunk's own half. A vd+1 slip is
		// a 128-byte difference here.
		CHECK_EQ(stores[c].disp, (i64)ChunkOffs(vd_reg, c));
		// The value stored is the value this chunk loaded.
		CHECK_EQ(stores[c].zmm, loads[c].zmm);
		load_zmms.insert(loads[c].zmm);
		store_zmms.insert(stores[c].zmm);
	}
	// Two chunks, two different ZMM registers, in the externally decoded bytes.
	CHECK_EQ(load_zmms.size(), (size_t)nchunks);
	CHECK_EQ(store_zmms.size(), (size_t)nchunks);

	printf("    OK %zu base read(s) [r13+0x%x]->%s, %zu guest load(s) [%s%s], %zu state store(s), "
	       "%zu distinct zmm\n",
	       bases.size(), GprOffs(base_reg), base_gpr.c_str(), loads.size(), base_gpr.c_str(),
	       nchunks == 2 ? "(+0,+0x40)" : "(+0)", stores.size(), load_zmms.size());
}

// THE S2.5 SECTION 4.3 GATE, stated on its own because it is a decision this checkpoint owed.
//
// The helper arm this route replaces addresses chunk c as `src + c*HOST_CHUNK_BYTES` on a HOST
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
// would show an `add` or `lea` here even though every structural count above would still pass: the
// chunk count, the ZMM sets, the windows, the guard and the counters would all be right, and the
// only observable difference would be 64 guest addresses at the very top of the address space.
void CheckNoAddressArithmetic(char const *tag, u32 vlen_bits)
{
	printf("[6] %s: chunk-1 address form -- no address arithmetic\n", tag);

	std::vector<std::string> lines;
	auto const vecs = EmitAndDecode(tag, vlen_bits, INSN_VLE32_V, &lines);
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

	// BOUND THE SCAN AT THE LAST STATE STORE, and the reason is not cosmetic. The code buffer is
	// zero-padded to its allocation size, and objdump decodes a run of `00 00` as
	// `add BYTE PTR [rax],al` -- padding that names the scratch register and would be counted as
	// address arithmetic by a scan over the whole listing. Everything that could feed a chunk
	// address necessarily precedes the frame's last store, so this window excludes the padding
	// without excluding any position the mutation this section refutes could occupy.
	size_t last_store = 0;
	bool have_store = false;
	for (size_t i = 0; i < lines.size(); ++i) {
		DecodedVec dv{};
		if (ParseLine(lines[i], &dv) && dv.kind == DecodedVec::Kind::STATE_STORE) {
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
// 7. Non-capture, on emitted bytes.
// ---------------------------------------------------------------------------------------------
//
// Each word here is pushed through the REAL code generator with this route fully open, and must
// produce NO ZMM instruction at all. That is a stronger statement than the QIR fallback table: a
// route could construct the right nodes and still have an emitter that fired on the wrong opcode.
void CheckNonCapture(u32 vlen_bits)
{
	printf("[7] non-capture on emitted bytes, VLEN=%u\n", vlen_bits);

	struct Row {
		char const *name;
		u32 word;
	};
	Row const rows[] = {
	    {"vse32.v (the store -- a later checkpoint)", INSN_VSE32_V},
	    {"masked vle32.v", INSN_VLE32_V_MASKED},
	    {"vle8.v", INSN_VLE8_V},
	    {"vle16.v", INSN_VLE16_V},
	    {"vle64.v", INSN_VLE64_V},
	    {"vlse32.v", INSN_VLSE32_V},
	    {"vle32ff.v", INSN_VLE32FF_V},
	    {"vl2re32.v", INSN_VL2RE32_V},
	    {"vlseg2e32.v", INSN_VLSEG2E32_V},
	    {"vlm.v", INSN_VLM_V},
	    {"vle32.v with base x0", INSN_VLE32_V_X0},
	};

	for (auto const &r : rows) {
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.load_word = r.word;
		auto const code = EmitOne(arena, words, cfg, cr);
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
		printf("    %-42s 0 zmm instructions\n", r.name);
	}
}

// ---------------------------------------------------------------------------------------------
// 8. Coexistence with an accepted ALU route.
// ---------------------------------------------------------------------------------------------
//
// The load route and the vand route open together in one process. Neither may take the other's
// encoding, and the ALU route's emitted mnemonic must be unchanged. This is the only section that
// states the ALU non-regression POSITIVELY: silence would also be produced by a route that had
// stopped working.
void CheckCoexistence(u32 vlen_bits, u32 nchunks)
{
	printf("[8] coexistence with the accepted S2.4 vand.vv route, VLEN=%u\n", vlen_bits);

	// The load, with the and route also open.
	{
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.typed_chunk_and = true;
		cfg.load_word = INSN_VLE32_V;
		Region *region = TranslateCfg(arena, words, cfg);
		CHECK_EQ(CountOp(region, Op::_vchunkload), nchunks);
		CHECK_EQ(CountOp(region, Op::_vstatechunkstore), nchunks);
		CHECK_EQ(CountOp(region, Op::_vchunkand), 0u);

		qir::CodeSegment segment(0u, 0x1000u);
		auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
		std::vector<u8> const code(span.begin(), span.end());
		auto const lines = Disassemble(code);
		unsigned n_movdqu = 0, n_pandd = 0;
		for (auto const &l : lines) {
			n_movdqu += (l.find("vmovdqu64") != std::string::npos);
			n_pandd += (l.find("vpandd") != std::string::npos);
		}
		CHECK_EQ(n_movdqu, 2u * nchunks);
		CHECK_EQ(n_pandd, 0u);
		printf("    vle32.v with both switches on: %u vmovdqu64, %u vpandd\n", n_movdqu,
		       n_pandd);
	}
	// The and, with the load route also open. Its own mnemonic must be exactly what S2.4
	// accepted, and no load frame may appear.
	{
		MemArena arena(4u << 20);
		u32 words[2];
		TestCompilerRuntime cr;
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.typed_chunk_and = true;
		cfg.load_word = INSN_VAND_VV;
		Region *region = TranslateCfg(arena, words, cfg);
		CHECK_EQ(CountOp(region, Op::_vchunkand), nchunks);
		CHECK_EQ(CountOp(region, Op::_vchunkload), 0u);

		qir::CodeSegment segment(0u, 0x1000u);
		auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
		std::vector<u8> const code(span.begin(), span.end());
		auto const lines = Disassemble(code);
		unsigned n_pandd = 0, n_guest_load = 0;
		for (auto const &l : lines) {
			n_pandd += (l.find("vpandd") != std::string::npos);
			DecodedVec dv{};
			if (ParseLine(l, &dv) && dv.kind == DecodedVec::Kind::GUEST_LOAD) {
				++n_guest_load;
			}
		}
		CHECK_EQ(n_pandd, nchunks);
		// The and frame reads CPUState, never guest memory. A load route that had captured
		// an ALU PC would show a guest-addressed vmovdqu64 here.
		CHECK_EQ(n_guest_load, 0u);
		printf("    vand.vv with both switches on: %u vpandd, %u guest-addressed loads\n",
		       n_pandd, n_guest_load);
	}
}

// ---------------------------------------------------------------------------------------------
// 9. The frozen workload's own four mixed-kernel words.
// ---------------------------------------------------------------------------------------------
void CheckFrozenWords(u32 vlen_bits, u32 nchunks)
{
	printf("[9] the frozen S1.1-fix1 mixed kernel's four vle32.v words, VLEN=%u\n", vlen_bits);
	for (auto const &f : FROZEN_MIX_LOADS) {
		// Each word has its own (vd, base) pair, so this is the check that the two state
		// offsets the frame computes really come from the encoding.
		MemArena arena(4u << 20);
		u32 words[2];
		RouteConfig cfg;
		cfg.vlen_bits = vlen_bits;
		cfg.load_word = f.word;
		Region *region = TranslateCfg(arena, words, cfg);
		auto g = FindGroup(region);
		CHECK_EQ(g.n_begin, 1u);
		CHECK_EQ(g.body.size(), (size_t)(2 * nchunks));
		if (g.body.size() != 2 * nchunks) {
			continue;
		}
		for (u32 c = 0; c < nchunks; ++c) {
			auto *ld = static_cast<InstVChunkLoad *>(g.body[c]);
			CHECK_EQ((u32)ld->base_state_offs, GprOffs(f.base));
			CHECK_EQ((u32)ld->disp, c * 64u);
			auto *st = static_cast<InstVStateChunkStore *>(g.body[nchunks + c]);
			CHECK_EQ((u32)st->offs, ChunkOffs(f.vd, c));
		}
		printf("    %-20s vd=v%-2u base=x%-2u -> %u chunk(s) OK\n", f.text, f.vd, f.base,
		       nchunks);
	}
}

} // namespace

int main()
{
	printf("S2.6: exact unmasked unit-stride vle32.v -> typed V512 chunk route\n\n");

	CheckEncodingSweep();
	CheckAcceptedSplitsUndisturbed();
	printf("\n");

	CheckRoute("VLEN=512", 512, 1, 16, INSN_VLE32_V, VD_REG, BASE_REG);
	CheckRoute("VLEN=1024", 1024, 2, 32, INSN_VLE32_V, VD_REG, BASE_REG);
	printf("\n");

	CheckFallbackTable();
	printf("\n");

	CheckRoutePostQRA("VLEN=512", 512, 1);
	CheckRoutePostQRA("VLEN=1024", 1024, 2);
	printf("\n");

	CheckRouteEmitted("VLEN=512", 512, 1, INSN_VLE32_V, VD_REG, BASE_REG);
	CheckRouteEmitted("VLEN=1024", 1024, 2, INSN_VLE32_V, VD_REG, BASE_REG);
	printf("\n");

	CheckNoAddressArithmetic("VLEN=512", 512);
	CheckNoAddressArithmetic("VLEN=1024", 1024);
	printf("\n");

	CheckNonCapture(512);
	CheckNonCapture(1024);
	printf("\n");

	CheckCoexistence(512, 1);
	CheckCoexistence(1024, 2);
	printf("\n");

	CheckFrozenWords(512, 1);
	CheckFrozenWords(1024, 2);
	printf("\n");

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
