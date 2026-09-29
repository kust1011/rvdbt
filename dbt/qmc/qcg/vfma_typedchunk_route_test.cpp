// P7I-B: the OPFVF FUSED multiply-add typed V512 chunk route -- `vfmadd.vf` and `vfnmsub.vf` at an
// OBSERVED e32/e64, ta, ma, unmasked vtype -- checked at every level where it can be wrong.
//
// WHY THIS FILE EXISTS
//
// P7H closed the three floating-ALU opcodes miniWeather uses and measured what was left: the two
// OPFVF FMA words below are 182,400 helper calls at VLEN 512 and 91,200 at VLEN 1024, i.e. 94.85%
// and 93.53% of all remaining RVV helper traffic. They never reached RvvQcgTypedFaluAdmit at all --
// rv32_decode.h:215-221 sends every FMA funct6 to TRANSLATOR(vfma), because vfalu_supported()
// (rv32_vector_lower.h:962-974) excludes them -- so this is the first direct lowering the vfma
// decode family has had on the pure-QCG path, not a widening of an existing one.
//
// THE THREE WAYS THIS ROUTE CAN BE SILENTLY WRONG, AND WHERE EACH IS CAUGHT
//
//   1. THE OPCODE NAMING TRAP. RVV's `vfnmsub` computes fma(-vd_old, b, vs2) -- only the PRODUCT
//      is negated (rv32_vector_lower.h:1637). x86's identically-spelled vfnmsub213pd computes
//      -(src1*dst) - src2, which negates the ADDEND TOO. The correct mapping is x86's
//      vfnmADD213pd. Choosing by name gives a frame with the right node count, the right chunk
//      count, the right windows and the right guard, and the wrong sign on the addend.
//      Caught by: [7] (the disassembled mnemonic) and [8] (the value differential).
//   2. OPERAND ORDER. vd is BOTH the destination and the multiplicand -- unique to the
//      madd/msub half of the family (rv32_vector_lower.h:1626-1627). Swapping the vd and vs2
//      loads is invisible to any count-based check.
//      Caught by: [2] (which window each load reads) and [8].
//   3. DECOMPOSITION. vfmul + vfadd rounds TWICE and is a different function from std::fma.
//      Caught by: [7] (no vmulpd/vaddpd pair is emitted) and [8], whose corpus contains a triple
//      chosen so that fma(d,b,a) != (d*b)+a -- and [8] ASSERTS that it does, so the corpus cannot
//      quietly stop being able to tell them apart.
//
// WHAT EACH SECTION PROVES
//
//   [1] shape rule: chunks = emul_group_regs(LMUL) * (VLEN/512), n_typed = 4k+3, zero helpers.
//   [2] the two REAL miniWeather words: every load/store window, both VLENs, both LMULs.
//   [3] funct6 fidelity: the two words do not collapse onto one lowering.
//   [4] load-major, including the legal `vd == vs2` overlap.
//   [5] window geometry and the LMUL=2 tiling.
//   [6] fail-closed matrix, including the unobserved-vtype refusal that is stricter than falu's.
//   [7] REAL emitted host bytes, disassembled by objdump: the exact FMA mnemonic, its operand
//       roles, the absence of vfnmsub213pd and of any mul/add pair, no xmm/ymm, and the FP
//       bracket (stmxcsr/ldmxcsr) enclosing the arithmetic.
//   [8] VALUE DIFFERENTIAL against the real rv32::vfma helper, driven by INTERPRETING THE
//       DISASSEMBLY -- not by re-reading this repository's emitter. See the header of
//       Section8_ValueDifferential for exactly what that does and does not establish.
//
// WHAT IT DELIBERATELY NEVER DOES. It never executes the emitted bytes. TestCompilerRuntime
// resizes a std::vector<u8>; there is no mmap in this process, let alone a PROT_EXEC one. The
// development host is an Ivy Bridge i7-3770 with neither AVX-512F, FMA3 nor... (it does have BMI2's
// absence in common with them: /proc/cpuinfo shows no avx512f and no fma), so
// `rvv_qcg_typed_chunk_fma_force_emit` is what lets the shape be inspected here at all. It bypasses
// ONLY the CPUID probes. Nothing here times anything or makes any performance claim.
//
// UNDER -DRVV_FP_FORCE_SOFT this file compiles to a DIFFERENT main(): see Section_N2_ForceSoft.
//
// INSTRUCTION WORDS. Every word below was round-tripped through
// `llvm-mc-20 --disassemble -triple=riscv32 -mattr=+v`; the disassembly is quoted beside each one.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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
constexpr u32 ST_F_BASE = (u32)(offsetof(CPUState, fpu) + offsetof(rv32::FPUState, f));

// Chunk c of a group based at `reg`, recomputed here from VLEN rather than read back from the
// frame under test.
u32 ChunkOffs(u32 reg, u32 chunk, u32 vlen_bits)
{
	u32 const per_reg = vlen_bits / 512u;
	return ST_VREG_BASE + (reg + chunk / per_reg) * rv32::VLEN_MAX_BYTES + (chunk % per_reg) * 64u;
}

// The chunk count the rule must produce, derived independently of the predicate.
u32 ExpectChunks(u32 lmul_regs, u32 vlen_bits) { return lmul_regs * (vlen_bits / 512u); }

// ---------------------------------------------------------------------------------------------
// Instruction words.
// ---------------------------------------------------------------------------------------------
constexpr u32 VSETVLI_E32M1 = 0x0d057557u;    // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 VSETVLI_E32M2 = 0x0d157557u;    // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;    // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;    // vsetvli a0, a0, e64, m2, ta, ma
constexpr u32 VSETVLI_E64M4 = 0x0da57557u;    // vsetvli a0, a0, e64, m4, ta, ma
constexpr u32 VSETVLI_E64M8 = 0x0db57557u;    // vsetvli a0, a0, e64, m8, ta, ma
constexpr u32 VSETVLI_E64MF2 = 0x0df57557u;   // vsetvli a0, a0, e64, mf2, ta, ma
constexpr u32 VSETVLI_E16M1 = 0x0c857557u;    // vsetvli a0, a0, e16, m1, ta, ma
constexpr u32 VSETVLI_E8M1 = 0x0c057557u;     // vsetvli a0, a0, e8,  m1, ta, ma
constexpr u32 VSETVLI_E64M1_TU = 0x09857557u; // vsetvli a0, a0, e64, m1, tu, ma

// THE TWO WORDS P7D/P7H MEASURED IN miniWeather. Not synthetic: these are the raw values
// --rvv-pc-census recorded, and what llvm-objdump reads out of the guest ELF.
constexpr u32 MW_VFMADD_VF = 0xa28454d7u;  // vfmadd.vf  v9, fs0, v8   f6=40 vd=9 rs1=f8  vs2=8
constexpr u32 MW_VFNMSUB_VF = 0xae86d4d7u; // vfnmsub.vf v9, fa3, v8   f6=43 vd=9 rs1=f13 vs2=8

// Every OTHER word in this file is BUILT from the encoding rather than hand-written in hex, and
// the builder is pinned against the two real words above by a static_assert. A hand-typed hex
// constant with the wrong vs2 field would otherwise silently change what a test is testing --
// which is exactly what happened while writing this file.
constexpr u32 MakeOpFV(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (rs1 << 15) | (funct3 << 12) | (vd << 7) |
	       0x57u;
}
constexpr u32 MakeOpfvf(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 vd)
{
	return MakeOpFV(f6, vm, vs2, rs1, vd, 0b101u);
}
static_assert(MakeOpfvf(40, 1, 8, 8, 9) == MW_VFMADD_VF, "OPFVF encoder disagrees with the real "
						         "miniWeather vfmadd.vf word");
static_assert(MakeOpfvf(43, 1, 8, 13, 9) == MW_VFNMSUB_VF, "OPFVF encoder disagrees with the real "
							   "miniWeather vfnmsub.vf word");

// Even-numbered, DISJOINT vd and vs2, so the same words are legal at LMUL=2 too.
constexpr u32 VFMADD_VF_EVEN = MakeOpfvf(40, 1, /*vs2=*/10, /*rs1=*/9, /*vd=*/8);
constexpr u32 VFNMSUB_VF_EVEN = MakeOpfvf(43, 1, /*vs2=*/10, /*rs1=*/13, /*vd=*/8);

// The legal-overlap words: vd and vs2 are the SAME register group.
constexpr u32 VFMADD_VF_ALIAS = MakeOpfvf(40, 1, /*vs2=*/9, /*rs1=*/9, /*vd=*/9);
constexpr u32 VFNMSUB_VF_ALIAS_EVEN = MakeOpfvf(43, 1, /*vs2=*/8, /*rs1=*/13, /*vd=*/8);

// Masked form of the admitted word: identical except vm = 0.
constexpr u32 VFMADD_VF_MASKED = MakeOpfvf(40, 0, 8, 8, 9);

// OPFVV counterpart. vs1 = v9 is ODD, so this word is legal at m1 and illegal at m2 -- which is
// what makes the .vv arm's vs1 alignment rule (new: vs1 is a vector GROUP in this form) testable
// in both directions from one word.
constexpr u32 VFMADD_VV = MakeOpFV(40, 1, /*vs2=*/10, /*vs1=*/9, /*vd=*/8, 0b001u);

// .vv with every group aligned for m8, and its .vf twin: vd = v8 and vs2 = v16 are multiples of 8.
constexpr u32 VFMADD_VV_M8 = MakeOpFV(40, 1, /*vs2=*/16, /*vs1=*/24, /*vd=*/8, 0b001u);
constexpr u32 VFMADD_VF_M8 = MakeOpfvf(40, 1, /*vs2=*/16, /*rs1=*/9, /*vd=*/8);

// THE OTHER SIX FMA funct6 VALUES, OPFVF, with the same fields as MW_VFMADD_VF, so nothing but
// funct6 distinguishes them from an admitted word.
constexpr u32 FmaWordWithFunct6(u32 f6) { return MakeOpfvf(f6, 1, 8, 8, 9); }

// ---------------------------------------------------------------------------------------------
// Translation harness. Every knob the route reads is set on EVERY translation.
// ---------------------------------------------------------------------------------------------
struct Env {
	u32 vlen_bits = 512;
	bool fma = true;
	bool force_emit = true;
	bool rvv_direct = true;
	bool rvv_verify = false;
	bool aot_use_llvm = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_typed_chunk_fma = e.fma;
	config::rvv_qcg_typed_chunk_fma_force_emit = e.force_emit;
	config::rvv_direct = e.rvv_direct;
	config::rvv_verify = e.rvv_verify;
	config::aot_use_llvm = e.aot_use_llvm;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	// Everything else that could build a frame or take the word first must be off, so a census
	// below can say which route produced what. The falu route in particular is left OFF: it
	// cannot see an FMA funct6 (rv32_decode.h routes those elsewhere), and keeping it off makes
	// that a checked property of the run rather than a claim.
	config::rvv_qcg_typed_chunk_falu = false;
	config::rvv_qcg_typed_chunk_falu_force_emit = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_vle = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_vector_run = false;
	config::rvv_lowering = 1;
}

Region *TranslateWords(MemArena &arena, u32 const *words, unsigned n, Env const &e)
{
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};

std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				break;
			case Op::_rvvtypedchunkend:
				if (open) {
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					out.push_back(cur);
					open = false;
				}
				break;
			default:
				if (open)
					cur.body.push_back(&ins);
				break;
			}
		}
	}
	return out;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			n += ins.GetOpcode() == op;
	return n;
}

unsigned CountStub(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_hcall)
				n += static_cast<InstHcall *>(&ins)->stub == stub;
	return n;
}

Region *TranslatePair(MemArena &arena, u32 (&words)[2], u32 setvli, u32 word, Env const &e)
{
	words[0] = setvli;
	words[1] = word;
	return TranslateWords(arena, words, 2, e);
}

bool Admitted(u32 setvli, u32 word, Env const &e)
{
	MemArena arena(1u << 20);
	u32 words[2];
	auto *region = TranslatePair(arena, words, setvli, word, e);
	return !FindFrames(region).empty();
}

// "Refused" means BOTH: no frame was built AND the pre-existing helper is still there. Checking
// only the first would pass on an implementation that dropped the instruction entirely.
bool RefusedToHelper(u32 setvli, u32 word, Env const &e)
{
	MemArena arena(1u << 20);
	u32 words[2];
	auto *region = TranslatePair(arena, words, setvli, word, e);
	return FindFrames(region).empty() && CountStub(region, RuntimeStubId::id_rv32_vfma) == 1u &&
	       CountOp(region, Op::_vchunkfma) == 0u;
}

#ifndef RVV_FP_FORCE_SOFT

// ---------------------------------------------------------------------------------------------
// [1] THE SHAPE RULE.
// ---------------------------------------------------------------------------------------------
struct ShapeCase {
	char const *name;
	u32 setvli;
	u32 lmul_regs;
	u32 sew_bits;
};

constexpr ShapeCase SHAPES[] = {
    {"e64,m1", VSETVLI_E64M1, 1, 64},
    {"e64,m2", VSETVLI_E64M2, 2, 64},
    {"e32,m1", VSETVLI_E32M1, 1, 32},
    {"e32,m2", VSETVLI_E32M2, 2, 32},
};

void Section1_ShapeRule()
{
	fprintf(stderr, "[1] chunk count = emul_group_regs(LMUL) * (VLEN/512), n_typed = 4k+3\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &s : SHAPES) {
			for (u32 word : {VFMADD_VF_EVEN, VFNMSUB_VF_EVEN}) {
				MemArena arena(1u << 20);
				u32 words[2];
				Env e{vlen};
				auto *region = TranslatePair(arena, words, s.setvli, word, e);
				auto frames = FindFrames(region);
				CHECK_EQ(frames.size(), (size_t)1);
				if (frames.empty())
					continue;
				u32 const k = ExpectChunks(s.lmul_regs, vlen);
				// Two loads (vs2 and the OLD vd), one fused op and one store per chunk,
				// plus the scalar broadcast and the fp begin/end pair.
				CHECK_EQ((unsigned)frames[0].begin->n_typed, 4u * k + 3u);
				CHECK_EQ(CountOp(region, Op::_vchunkfma), k);
				CHECK_EQ(CountOp(region, Op::_vstatechunkload), 2u * k);
				CHECK_EQ(CountOp(region, Op::_vstatechunkstore), k);
				CHECK_EQ(CountOp(region, Op::_vchunkfbroadcast), 1u);
				CHECK_EQ(CountOp(region, Op::_vchunkfalu), 0u);
				CHECK_EQ(CountStub(region, RuntimeStubId::id_rv32_vfma), 0u);
				CHECK_EQ(frames[0].begin->vlmax, (vlen / s.sew_bits) * s.lmul_regs);
			}
			fprintf(stderr, "    VLEN %-4u %-7s -> %u chunk(s)\n", vlen, s.name,
				ExpectChunks(s.lmul_regs, vlen));
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [2] THE TWO REAL miniWeather WORDS, AND WHICH WINDOW EVERY OPERAND READS.
// ---------------------------------------------------------------------------------------------
struct MwCase {
	char const *name;
	u32 word;
	u8 f6;
	u32 vd, vs2, rs1;
};

constexpr MwCase MW[] = {
    {"vfmadd.vf v9,fs0,v8", MW_VFMADD_VF, 40, 9, 8, 8},
    {"vfnmsub.vf v9,fa3,v8", MW_VFNMSUB_VF, 43, 9, 8, 13},
};

// The frame's loads in program order: chunks of vs2 first, then chunks of the OLD vd. Returns the
// offsets in emission order so the caller can pin both the identity AND the order.
std::vector<u32> LoadOffsets(Frame const &f)
{
	std::vector<u32> out;
	for (auto *ins : f.body)
		if (ins->GetOpcode() == Op::_vstatechunkload)
			out.push_back(static_cast<InstVStateChunkLoad *>(ins)->offs);
	return out;
}

std::vector<u32> StoreOffsets(Frame const &f)
{
	std::vector<u32> out;
	for (auto *ins : f.body)
		if (ins->GetOpcode() == Op::_vstatechunkstore)
			out.push_back(static_cast<InstVStateChunkStore *>(ins)->offs);
	return out;
}

void Section2_MiniWeatherWords()
{
	fprintf(stderr, "[2] the two P7D/P7H-measured miniWeather words, operand by operand\n");
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = ExpectChunks(1, vlen);
		for (auto const &c : MW) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, VSETVLI_E64M1, c.word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty()) {
				fprintf(stderr, "    VLEN %-4u %-22s -> REFUSED\n", vlen, c.name);
				continue;
			}
			auto const &f = frames[0];
			CHECK_EQ(CountOp(region, Op::_vchunkfma), k);
			CHECK_EQ(CountStub(region, RuntimeStubId::id_rv32_vfma), 0u);
			CHECK_EQ((unsigned)f.begin->n_typed, 4u * k + 3u);
			CHECK_EQ(f.begin->vtype, VSETVLI_E64M1 >> 20);
			CHECK_EQ(f.begin->vlmax, vlen / 64u);
			CHECK(f.begin->stub == RuntimeStubId::id_rv32_vfma);
			CHECK(f.end->stub == RuntimeStubId::id_rv32_vfma);
			// The guard is the EXISTING kind, not a new one: vtype equal, vl <= VLMAX,
			// vstart == 0 and frm == RNE. The RNE half is what excludes the helper's
			// FRM_RMM exact-core path, which is a different function.
			// QCG programs MXCSR from the live guest frm and falls back for RMM,
			// so this is the host-representable-rounding guard.
			CHECK(f.begin->guard_kind ==
			      InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost);

			// LOADS: k chunks of vs2, then k chunks of the OLD vd. This is the operand
			// order check -- an implementation that fed vd where vs2 belongs computes
			// fma(vs2_old, b, vd) and every count in this file still matches.
			auto loads = LoadOffsets(f);
			CHECK_EQ(loads.size(), (size_t)(2 * k));
			if (loads.size() == 2 * k) {
				for (u32 i = 0; i < k; ++i)
					CHECK_EQ(loads[i], ChunkOffs(c.vs2, i, vlen));
				for (u32 i = 0; i < k; ++i)
					CHECK_EQ(loads[k + i], ChunkOffs(c.vd, i, vlen));
			}
			// STORES: vd's own chunks, in order.
			auto stores = StoreOffsets(f);
			CHECK_EQ(stores.size(), (size_t)k);
			for (u32 i = 0; i < stores.size(); ++i)
				CHECK_EQ(stores[i], ChunkOffs(c.vd, i, vlen));
			// THE SCALAR: f[rs1], through the same broadcast node the falu .vf frame uses,
			// at SEW 8 (so raw, unboxed -- rv32_vector_lower.h:1467).
			unsigned nbcast = 0;
			for (auto *ins : f.body) {
				if (ins->GetOpcode() != Op::_vchunkfbroadcast)
					continue;
				auto *b = static_cast<InstVChunkFBroadcast *>(ins);
				CHECK_EQ((u32)b->offs, ST_F_BASE + c.rs1 * (u32)sizeof(u64));
				CHECK_EQ((unsigned)b->sew_bytes, 8u);
				++nbcast;
			}
			CHECK_EQ(nbcast, 1u);

			// THE FUSED NODE'S OWN OPERAND SLOTS, traced back to the load that defined
			// them. i(0) must be the vd load, i(2) the vs2 load, i(1) the broadcast.
			unsigned nfma = 0;
			for (auto *ins : f.body) {
				if (ins->GetOpcode() != Op::_vchunkfma)
					continue;
				auto *m = static_cast<InstVChunkFMA *>(ins);
				CHECK_EQ((unsigned)m->funct6, (unsigned)c.f6);
				CHECK_EQ((unsigned)m->sew_bytes, 8u);
				CHECK_EQ((unsigned)m->chunk, nfma);
				++nfma;
			}
			CHECK_EQ(nfma, k);
			fprintf(stderr, "    VLEN %-4u %-22s -> DIRECT, %u chunk(s), f6=%u, 0 helpers\n",
				vlen, c.name, k, c.f6);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [3] funct6 FIDELITY: the two admitted words must not collapse onto one lowering.
// ---------------------------------------------------------------------------------------------
void Section3_Funct6Fidelity()
{
	fprintf(stderr, "[3] vfmadd and vfnmsub stay distinguishable through the whole frame\n");
	for (u32 vlen : {512u, 1024u}) {
		u8 seen[2] = {0xff, 0xff};
		unsigned i = 0;
		for (u32 word : {MW_VFMADD_VF, MW_VFNMSUB_VF}) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, VSETVLI_E64M1, word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty())
				continue;
			for (auto *ins : frames[0].body)
				if (ins->GetOpcode() == Op::_vchunkfma)
					seen[i] = static_cast<InstVChunkFMA *>(ins)->funct6;
			// The raw word is carried on the frame too, so a lost funct6 cannot be
			// reconstructed from a coincidence.
			CHECK_EQ(frames[0].begin->raw, word);
			++i;
		}
		CHECK_EQ((unsigned)seen[0], 40u);
		CHECK_EQ((unsigned)seen[1], 43u);
		CHECK(seen[0] != seen[1]);
	}
	fprintf(stderr, "    funct6 40 and 43 reach the node distinctly at both VLENs\n");
}

// ---------------------------------------------------------------------------------------------
// [4] LOAD-MAJOR, AND THE LEGAL vd == vs2 OVERLAP.
// ---------------------------------------------------------------------------------------------
void Section4_LoadMajor()
{
	fprintf(stderr, "[4] every load precedes every store, including when vd == vs2\n");
	struct Row { char const *name; u32 word; u32 setvli; u32 lmul_regs; };
	Row const rows[] = {
	    {"vfmadd.vf v9,fs0,v8 (disjoint)", MW_VFMADD_VF, VSETVLI_E64M1, 1},
	    {"vfmadd.vf v9,fs1,v9 (vd==vs2)", VFMADD_VF_ALIAS, VSETVLI_E64M1, 1},
	    {"vfnmsub.vf v8,fa3,v8 (vd==vs2)", VFNMSUB_VF_ALIAS_EVEN, VSETVLI_E64M2, 2},
	};
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &r : rows) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, r.setvli, r.word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty())
				continue;
			u32 const k = ExpectChunks(r.lmul_regs, vlen);
			int last_load = -1, first_store = -1;
			int idx = 0;
			for (auto *ins : frames[0].body) {
				if (ins->GetOpcode() == Op::_vstatechunkload)
					last_load = idx;
				if (ins->GetOpcode() == Op::_vstatechunkstore && first_store < 0)
					first_store = idx;
				++idx;
			}
			CHECK(last_load >= 0 && first_store >= 0);
			// THE INVARIANT. If a store could precede a load, the vd == vs2 rows above
			// would read values this instruction had already overwritten -- and only
			// those rows, which is why an aliased word is in the table.
			CHECK(last_load < first_store);
			// The aliased case really does load the same window twice rather than
			// silently reusing one value: 2k loads, not k.
			CHECK_EQ(LoadOffsets(frames[0]).size(), (size_t)(2 * k));
		}
	}
	// And the aliased word's two load groups are the SAME offsets, in the documented order.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{512u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M1, VFMADD_VF_ALIAS, e);
		auto frames = FindFrames(region);
		if (!frames.empty()) {
			auto loads = LoadOffsets(frames[0]);
			CHECK_EQ(loads.size(), (size_t)2);
			if (loads.size() == 2) {
				CHECK_EQ(loads[0], ChunkOffs(9, 0, 512));
				CHECK_EQ(loads[1], ChunkOffs(9, 0, 512));
			}
		}
	}
	fprintf(stderr, "    load-major holds at both VLENs, both LMULs, aliased and disjoint\n");
}

// ---------------------------------------------------------------------------------------------
// [5] WINDOW GEOMETRY: the two different 2-chunk tilings are not the same thing.
// ---------------------------------------------------------------------------------------------
void Section5_WindowGeometry()
{
	fprintf(stderr, "[5] 2 chunks means two different tilings\n");
	// (a) e64,m1 at VLEN 1024: ONE register, two 64-byte windows of its own slot.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{1024u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M1, MW_VFMADD_VF, e);
		auto frames = FindFrames(region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (!frames.empty()) {
			auto st = StoreOffsets(frames[0]);
			CHECK_EQ(st.size(), (size_t)2);
			if (st.size() == 2) {
				CHECK_EQ(st[1] - st[0], 64u);
				CHECK_EQ(st[0], ST_VREG_BASE + 9u * rv32::VLEN_MAX_BYTES);
			}
		}
	}
	// (b) e64,m2 at VLEN 512: TWO registers, one window each, VLEN_MAX_BYTES apart.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{512u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M2, VFMADD_VF_EVEN, e);
		auto frames = FindFrames(region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (!frames.empty()) {
			auto st = StoreOffsets(frames[0]);
			CHECK_EQ(st.size(), (size_t)2);
			if (st.size() == 2) {
				CHECK_EQ(st[1] - st[0], (u32)rv32::VLEN_MAX_BYTES);
				CHECK_EQ(st[0], ST_VREG_BASE + 8u * rv32::VLEN_MAX_BYTES);
			}
		}
	}
	fprintf(stderr, "    e64,m1@1024 = one register +0/+64 ; e64,m2@512 = v8 and v9\n");
}

// ---------------------------------------------------------------------------------------------
// [6] FAIL-CLOSED.
// ---------------------------------------------------------------------------------------------
void Section6_FailClosed()
{
	fprintf(stderr, "[6] fail-closed matrix\n");

	// 6.1 THE UNOBSERVED-VTYPE REFUSAL. This is the rule that is deliberately STRICTER than the
	// falu route's, so it gets its own case rather than a row in a table: with no vsetvli in the
	// block the falu route proposes a candidate shape and lets the guard prove it; this route
	// refuses, because a fused frame also loads the OLD vd and there is no observation to say
	// what element width that is.
	for (u32 vlen : {512u, 1024u}) {
		for (u32 word : {MW_VFMADD_VF, MW_VFNMSUB_VF, VFMADD_VF_EVEN}) {
			MemArena arena(1u << 20);
			u32 w = word;
			Env e{vlen};
			auto *region = TranslateWords(arena, &w, 1, e);
			CHECK_EQ(FindFrames(region).size(), (size_t)0);
			CHECK_EQ(CountOp(region, Op::_vchunkfma), 0u);
			CHECK_EQ(CountStub(region, RuntimeStubId::id_rv32_vfma), 1u);
		}
	}
	fprintf(stderr, "    6.1 no observed vsetvli -> helper (stricter than the falu route)\n");

	// 6.2 vtype rows.
	struct Row { char const *name; u32 setvli; };
	Row const bad_vtypes[] = {
	    {"e64,mf2", VSETVLI_E64MF2},
	    {"e16,m1", VSETVLI_E16M1}, {"e8,m1", VSETVLI_E8M1},
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &r : bad_vtypes)
			for (u32 word : {VFMADD_VF_EVEN, VFNMSUB_VF_EVEN})
				CHECK(RefusedToHelper(r.setvli, word, Env{vlen}));
	fprintf(stderr, "    6.2 mf2 / e16 / e8 refused at both VLENs\n");

	// 6.2b THE INTEGER LMUL LADDER IS NOW ADMITTED, m1 through m8, and the fractional one is not.
	// m4/m8 need every group aligned to the LMUL, so the ladder is walked with words whose vd and
	// vs2 are multiples of 8; the chunk count must be lmul_regs * (VLEN/512) at each rung, which is
	// the same independent formula the m1/m2 rows above use.
	{
		struct L { char const *name; u32 setvli; u32 regs; };
		L const ladder[] = {{"m1", VSETVLI_E64M1, 1}, {"m2", VSETVLI_E64M2, 2},
				    {"m4", VSETVLI_E64M4, 4}, {"m8", VSETVLI_E64M8, 8}};
		for (u32 vlen : {512u, 1024u})
			for (auto const &l : ladder)
				for (u32 word : {VFMADD_VF_M8, VFMADD_VV_M8}) {
					CHECK(Admitted(l.setvli, word, Env{vlen}));
					MemArena arena(1u << 21);
					u32 words[2] = {l.setvli, word};
					Env e{vlen};
					auto *region = TranslateWords(arena, words, 2, e);
					auto frames = FindFrames(region);
					CHECK_EQ(frames.size(), (size_t)1);
					u32 const k = ExpectChunks(l.regs, vlen);
					CHECK_EQ(CountOp(region, Op::_vchunkfma), k);
					CHECK_EQ(CountStub(region, RuntimeStubId::id_rv32_vfma), 0u);
					// .vf keeps the broadcast and 4 nodes per chunk; .vv trades the
					// broadcast for a vs1 load per chunk, so it is 5 per chunk.
					bool const vf = ((word >> 12) & 7u) == 0b101u;
					CHECK_EQ((unsigned)frames[0].begin->n_typed,
						 vf ? 4u * k + 3u : 5u * k + 2u);
					CHECK_EQ(CountOp(region, Op::_vchunkfbroadcast), vf ? 1u : 0u);
				}
		// ... and mf2 is still out, so "integer LMUL" is a real boundary and not a no-op.
		for (u32 vlen : {512u, 1024u})
			CHECK(RefusedToHelper(VSETVLI_E64MF2, VFMADD_VF_M8, Env{vlen}));
	}
	fprintf(stderr, "    6.2b m1/m2/m4/m8 admitted for .vf and .vv with the right chunk and node "
			"counts; mf2 still refused\n");

	// 6.3 Masked forms are direct when vd does not overlap v0. Register-group alignment remains
	// an independent legality condition, so this particular odd-vd word is refused at m2.
	for (u32 vlen : {512u, 1024u}) {
		CHECK(Admitted(VSETVLI_E64M1, VFMADD_VF_MASKED, Env{vlen}));
		CHECK(RefusedToHelper(VSETVLI_E64M2, VFMADD_VF_MASKED, Env{vlen}));
		// OPFVV is ADMITTED now (the .vv arm loads a vs1 chunk instead of broadcasting f[rs1]),
		// but vs1 is a vector GROUP in that form and gets the LMUL alignment rule: this word's
		// vs1 = v9 is odd, so the same word is admitted at m1 and refused at m2. Both
		// directions, so the new rule is not vacuous either.
		CHECK(Admitted(VSETVLI_E64M1, VFMADD_VV, Env{vlen}));
		CHECK(RefusedToHelper(VSETVLI_E64M2, VFMADD_VV, Env{vlen}));
		// vd = v9 is odd, so it cannot base a two-register group -- admitted at m1, refused
		// at m2. Both directions, so the rule is not vacuous.
		CHECK(RefusedToHelper(VSETVLI_E64M2, MW_VFMADD_VF, Env{vlen}));
		CHECK(Admitted(VSETVLI_E64M1, MW_VFMADD_VF, Env{vlen}));
	}
	fprintf(stderr, "    6.3 masked m1 admitted; odd group at m2 refused; OPFVV admitted at m1 and refused "
			"at m2 for its odd vs1\n");

	// 6.4 ALL EIGHT FMA funct6 VALUES, in both operand forms. Each word differs from another
	// ONLY in funct6, so an under- or over-broad funct6 row has nowhere to hide, and the node
	// must carry the funct6 through unchanged (the emitter picks the 213/231 form and the sign
	// pair from it, so a dropped funct6 would silently compute a different sign).
	{
		struct F6 { char const *name; u32 f6; };
		F6 const all_eight[] = {
		    {"vfmadd", rv32::VF6_VFMADD},   {"vfnmadd", rv32::VF6_VFNMADD},
		    {"vfmsub", rv32::VF6_VFMSUB},   {"vfnmsub", rv32::VF6_VFNMSUB},
		    {"vfmacc", rv32::VF6_VFMACC},   {"vfnmacc", rv32::VF6_VFNMACC},
		    {"vfmsac", rv32::VF6_VFMSAC},   {"vfnmsac", rv32::VF6_VFNMSAC},
		};
		for (u32 vlen : {512u, 1024u})
			for (auto const &o : all_eight) {
				u32 const vfw = FmaWordWithFunct6(o.f6);
				u32 const vvw = MakeOpFV(o.f6, 1, /*vs2=*/8, /*vs1=*/8, /*vd=*/9, 0b001u);
				CHECK(Admitted(VSETVLI_E64M1, vfw, Env{vlen}));
				CHECK(Admitted(VSETVLI_E64M1, vvw, Env{vlen}));
				for (u32 word : {vfw, vvw}) {
					MemArena arena(1u << 20);
					u32 words[2] = {VSETVLI_E64M1, word};
					Env e{vlen};
					auto *region = TranslateWords(arena, words, 2, e);
					u32 const k = ExpectChunks(1, vlen);
					CHECK_EQ(CountOp(region, Op::_vchunkfma), k);
					CHECK_EQ(CountStub(region, RuntimeStubId::id_rv32_vfma), 0u);
					// the funct6 the node carries is the guest's, unmodified: the
					// emitter picks the 213/231 form and the sign pair from it.
					auto fr = FindFrames(region);
					CHECK_EQ(fr.size(), (size_t)1);
					unsigned nf6 = 0;
					for (auto *ins : fr[0].body) {
						if (ins->GetOpcode() != Op::_vchunkfma)
							continue;
						auto *m = static_cast<InstVChunkFMA *>(ins);
						CHECK_EQ((unsigned)m->funct6, (unsigned)o.f6);
						CHECK_EQ((unsigned)m->sew_bytes, 8u);
						++nf6;
					}
					CHECK_EQ(nf6, k);
				}
			}
		// ... and the two miniWeather words really are these same builders at funct6 40/43.
		CHECK_EQ(FmaWordWithFunct6(rv32::VF6_VFMADD), MW_VFMADD_VF);
		// "All eight" is a contiguous RANGE and not "everything in OPFVV/OPFVF". Checked at
		// compile time on the predicate itself rather than by translating a neighbour word:
		// a non-FMA funct6 lowers to a DIFFERENT helper, so RefusedToHelper -- which requires
		// the vfma stub specifically -- cannot express that case.
		static_assert(rv32::vfma_supported(rv32::VF6_VFMADD) &&
			      rv32::vfma_supported(rv32::VF6_VFNMSAC) &&
			      !rv32::vfma_supported(rv32::VF6_VFMADD - 1u) &&
			      !rv32::vfma_supported(rv32::VF6_VFNMSAC + 1u),
			      "the FMA funct6 range is exactly 0b101000..0b101111");
	}
	fprintf(stderr, "    6.4 all eight FMA funct6 values admitted in .vf and .vv, funct6 carried "
			"onto the node; the neighbours of the range refused\n");

	// 6.5 VLENs outside the route's range, and the route's own gates.
	for (u32 vlen : {128u, 256u})
		CHECK(RefusedToHelper(VSETVLI_E64M1, MW_VFMADD_VF, Env{vlen}));
	for (u32 vlen : {512u, 1024u}) {
		Env off{vlen}; off.fma = false;
		CHECK(RefusedToHelper(VSETVLI_E64M1, MW_VFMADD_VF, off));
		Env ver{vlen}; ver.rvv_verify = true;
		CHECK(RefusedToHelper(VSETVLI_E64M1, MW_VFMADD_VF, ver));
		Env llvm{vlen}; llvm.aot_use_llvm = true;
		CHECK(RefusedToHelper(VSETVLI_E64M1, MW_VFMADD_VF, llvm));
		Env nod{vlen}; nod.rvv_direct = false;
		CHECK(RefusedToHelper(VSETVLI_E64M1, MW_VFMADD_VF, nod));
	}
	fprintf(stderr, "    6.5 VLEN 128/256 / switch off / --rvv-verify / LLVM / --rvv-direct 0\n");

	// 6.6 N1b: THE HOST PROBE IS NOT VACUOUS. On this development host (no avx512f, no fma, no
	// bmi2 in /proc/cpuinfo) the route must refuse whenever force_emit is off -- which is also
	// the proof that every admitted frame above exists only because force_emit bypassed CPUID,
	// and that no measurement arm on this machine could ever reach this code.
	{
		bool const x86 =
#if defined(__x86_64__) || defined(__i386__)
		    true;
#else
		    false;
#endif
		__builtin_cpu_init();
		bool const have = x86 && __builtin_cpu_supports("avx512f") &&
				  __builtin_cpu_supports("fma") && __builtin_cpu_supports("bmi2");
		for (u32 vlen : {512u, 1024u}) {
			Env noforce{vlen};
			noforce.force_emit = false;
			CHECK_EQ(Admitted(VSETVLI_E64M1, MW_VFMADD_VF, noforce), have);
		}
		fprintf(stderr,
			"    6.6 host avx512f+fma+bmi2 = %s -> admission without force-emit = %s\n",
			have ? "present" : "ABSENT", have ? "yes" : "no");
	}
}

// ---------------------------------------------------------------------------------------------
// [7]/[8] REAL HOST BYTES.
// ---------------------------------------------------------------------------------------------

// A CompilerRuntime whose AllocateCode NEVER mmaps anything, executable or not. There is no mmap
// call anywhere in this object's lifetime, so no path in this file could branch into the bytes.
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

std::vector<u8> EmitBytes(MemArena &arena, u32 setvli, u32 word, Env const &e)
{
	u32 words[2];
	Region *region = TranslatePair(arena, words, setvli, word, e);
	if (FindFrames(region).empty())
		return {};
	TestCompilerRuntime cruntime;
	qir::CodeSegment segment(0u, 0x1000u);
	auto span = qcg::GenerateCode(&cruntime, &segment, region, 0);
	return std::vector<u8>(span.begin(), span.end());
}

std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_p7ib_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel "
				      "--no-show-raw-insn ") +
			  path + " 2>&1";
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
	if (!cur.empty())
		lines.push_back(cur);
	int rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		return {};
	}
	return lines;
}

// ---- a minimal decoder for objdump's Intel syntax -------------------------------------------
// Only the operand kinds this frame can produce are recognised; anything else is reported, never
// guessed at.
struct Operand {
	enum class Kind { NONE, ZMM, KREG, GPR, MEM, IMM } kind = Kind::NONE;
	unsigned reg = 0;      // ZMM/KREG number
	std::string gpr;       // GPR name as written
	unsigned kmask = 0;    // 0 = none, else the {kN} writemask on this operand
	i64 disp = 0;          // MEM
	unsigned memsize = 0;  // MEM: bytes
	u64 imm = 0;           // IMM
};

struct Insn {
	u64 addr = 0;
	std::string mnem;
	std::vector<Operand> ops;
	std::string text;
};

bool ParseOperand(std::string t, Operand *out)
{
	// strip a trailing {kN} writemask
	size_t br = t.find('{');
	if (br != std::string::npos) {
		size_t end = t.find('}', br);
		if (end == std::string::npos)
			return false;
		std::string m = t.substr(br + 1, end - br - 1);
		if (m.size() == 2 && m[0] == 'k' && isdigit((unsigned char)m[1]))
			out->kmask = (unsigned)(m[1] - '0');
		else
			return false;
		t = t.substr(0, br) + t.substr(end + 1);
	}
	while (!t.empty() && t.front() == ' ')
		t.erase(t.begin());
	while (!t.empty() && t.back() == ' ')
		t.pop_back();
	if (t.empty())
		return false;
	if (t.compare(0, 3, "zmm") == 0 && t.find_first_not_of("0123456789", 3) == std::string::npos) {
		out->kind = Operand::Kind::ZMM;
		out->reg = (unsigned)strtoul(t.c_str() + 3, nullptr, 10);
		return true;
	}
	if (t.size() == 2 && t[0] == 'k' && isdigit((unsigned char)t[1])) {
		out->kind = Operand::Kind::KREG;
		out->reg = (unsigned)(t[1] - '0');
		return true;
	}
	// "<SIZE> PTR [r13+0x..]" / "[r13-0x..]"
	size_t lb = t.find('[');
	if (lb != std::string::npos) {
		std::string sz = t.substr(0, lb);
		unsigned bytes = 0;
		if (sz.find("ZMMWORD") != std::string::npos)
			bytes = 64;
		else if (sz.find("QWORD") != std::string::npos)
			bytes = 8;
		else if (sz.find("DWORD") != std::string::npos)
			bytes = 4;
		else if (sz.find("BYTE") != std::string::npos)
			bytes = 1;
		else
			return false;
		std::string inner = t.substr(lb + 1);
		if (inner.empty() || inner.back() != ']')
			return false;
		inner.pop_back();
		if (inner.compare(0, 3, "r13") != 0)
			return false;
		i64 d = 0;
		if (inner.size() > 3) {
			char sign = inner[3];
			if (sign != '+' && sign != '-')
				return false;
			d = (i64)strtoull(inner.c_str() + 4, nullptr, 0);
			if (sign == '-')
				d = -d;
		}
		out->kind = Operand::Kind::MEM;
		out->disp = d;
		out->memsize = bytes;
		return true;
	}
	if (t.compare(0, 2, "0x") == 0) {
		out->kind = Operand::Kind::IMM;
		out->imm = strtoull(t.c_str(), nullptr, 16);
		return true;
	}
	if (isalpha((unsigned char)t[0])) {
		out->kind = Operand::Kind::GPR;
		out->gpr = t;
		return true;
	}
	return false;
}

bool ParseInsn(std::string const &line, Insn *out)
{
	size_t tab = line.find('\t');
	if (tab == std::string::npos)
		return false;
	std::string lhs = line.substr(0, tab), rhs = line.substr(tab + 1);
	size_t colon = lhs.find(':');
	if (colon == std::string::npos)
		return false;
	out->addr = strtoull(lhs.c_str(), nullptr, 16);
	out->text = rhs;
	size_t sp = rhs.find(' ');
	out->mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	if (sp == std::string::npos)
		return true;
	std::string rest = rhs.substr(sp + 1);
	while (!rest.empty() && rest.front() == ' ')
		rest.erase(rest.begin());
	if (rest.empty())
		return true;
	// Split on commas. No operand this frame emits contains a comma.
	size_t start = 0;
	for (size_t i = 0; i <= rest.size(); ++i) {
		if (i != rest.size() && rest[i] != ',')
			continue;
		Operand o;
		if (!ParseOperand(rest.substr(start, i - start), &o))
			o.kind = Operand::Kind::NONE;
		out->ops.push_back(o);
		start = i + 1;
	}
	return true;
}

std::vector<Insn> DecodeAll(std::vector<u8> const &code, bool *ok)
{
	*ok = false;
	auto lines = Disassemble(code);
	if (lines.empty())
		return {};
	std::vector<Insn> out;
	for (auto const &l : lines) {
		Insn i;
		if (ParseInsn(l, &i))
			out.push_back(i);
	}
	*ok = !out.empty();
	return out;
}

bool MentionsZmm(std::string const &s) { return s.find("zmm") != std::string::npos; }

// The frame's instruction window starts immediately after the FP bracket's last setup ldmxcsr
// preceding the first vector-state load, and ends at the last vector-state store. This includes
// shared-mask setup and scalar broadcast even when code scheduling places them before the first
// load. The guard and helper fallback remain outside; the fflags epilogue starts after `hi`.
bool FrameWindow(std::vector<Insn> const &v, size_t *lo, size_t *hi)
{
	long first = -1, last = -1;
	for (size_t i = 0; i < v.size(); ++i) {
		auto const &n = v[i];
		if (n.mnem.compare(0, 7, "vmovdqu") != 0 || n.ops.size() != 2)
			continue;
		bool const load = n.ops[0].kind == Operand::Kind::ZMM &&
				  n.ops[1].kind == Operand::Kind::MEM && n.ops[1].memsize == 64;
		bool const store = n.ops[0].kind == Operand::Kind::MEM && n.ops[0].memsize == 64 &&
				   n.ops[1].kind == Operand::Kind::ZMM;
		if (load && first < 0)
			first = (long)i;
		if (store)
			last = (long)i;
	}
	if (first < 0 || last < 0 || last < first)
		return false;
	long setup = -1;
	for (long i = 0; i < first; ++i)
		if (v[(size_t)i].mnem == "ldmxcsr")
			setup = i;
	*lo = setup >= 0 ? (size_t)setup + 1u : (size_t)first;
	*hi = (size_t)last;
	return true;
}

struct FmaSite {
	std::string mnem;
	unsigned dst, src1, src2, kmask;
};

void Section7_EmittedBytes()
{
	fprintf(stderr, "[7] real emitted host bytes, disassembled by objdump\n");
	struct Row { char const *name; u32 setvli; u32 word; u32 vlen; char const *expect; u32 k; };
	Row const rows[] = {
	    {"e64,m1@512  vfmadd.vf", VSETVLI_E64M1, MW_VFMADD_VF, 512, "vfmadd213pd", 1},
	    {"e64,m1@512  vfnmsub.vf", VSETVLI_E64M1, MW_VFNMSUB_VF, 512, "vfnmadd213pd", 1},
	    {"e64,m1@1024 vfmadd.vf", VSETVLI_E64M1, MW_VFMADD_VF, 1024, "vfmadd213pd", 2},
	    {"e64,m1@1024 vfnmsub.vf", VSETVLI_E64M1, MW_VFNMSUB_VF, 1024, "vfnmadd213pd", 2},
	    {"e32,m1@512  vfmadd.vf", VSETVLI_E32M1, VFMADD_VF_EVEN, 512, "vfmadd213ps", 1},
	    {"e32,m1@512  vfnmsub.vf", VSETVLI_E32M1, VFNMSUB_VF_EVEN, 512, "vfnmadd213ps", 1},
	    {"e64,m2@512  vfmadd.vf", VSETVLI_E64M2, VFMADD_VF_EVEN, 512, "vfmadd213pd", 2},
	};
	for (auto const &r : rows) {
		MemArena arena(1u << 20);
		Env e{r.vlen};
		auto code = EmitBytes(arena, r.setvli, r.word, e);
		CHECK(!code.empty());
		if (code.empty())
			continue;
		bool ok = false;
		auto insns = DecodeAll(code, &ok);
		CHECK(ok);
		if (!ok)
			continue;
		size_t lo = 0, hi = 0;
		CHECK(FrameWindow(insns, &lo, &hi));
		if (!FrameWindow(insns, &lo, &hi))
			continue;

		std::vector<FmaSite> sites;
		unsigned n_cmp = 0, n_canon_mov = 0, n_bcast_state = 0, n_bcast_gpr = 0,
			 n_zmm_outside = 0;
		unsigned n_forbidden = 0, n_narrow = 0;
		for (size_t i = 0; i < insns.size(); ++i) {
			auto const &n = insns[i];
			bool const inside = i >= lo && i <= hi;
			if (!inside && MentionsZmm(n.text))
				++n_zmm_outside;
			if (!inside)
				continue;
			// The naming trap and the decomposition, both as hard negatives.
			if (n.mnem.find("vfnmsub") == 0 || n.mnem.find("vfmsub") == 0 ||
			    n.mnem == "vmulpd" || n.mnem == "vmulps" || n.mnem == "vaddpd" ||
			    n.mnem == "vaddps" || n.mnem == "vsubpd" || n.mnem == "vsubps")
				++n_forbidden;
			if (n.text.find("xmm") != std::string::npos ||
			    n.text.find("ymm") != std::string::npos)
				++n_narrow;
			if (n.mnem.compare(0, 2, "vf") == 0 &&
			    (n.mnem.find("madd213") != std::string::npos ||
			     n.mnem.find("msub213") != std::string::npos)) {
				CHECK_EQ(n.ops.size(), (size_t)3);
				if (n.ops.size() == 3 && n.ops[0].kind == Operand::Kind::ZMM &&
				    n.ops[1].kind == Operand::Kind::ZMM &&
				    n.ops[2].kind == Operand::Kind::ZMM)
					sites.push_back({n.mnem, n.ops[0].reg, n.ops[1].reg,
							 n.ops[2].reg, n.ops[0].kmask});
			}
			// objdump renders the imm8=3 (UNORD_Q) compare through its alias mnemonic,
			// vcmpunordp{s,d}. Both spellings are accepted; anything else is not a
			// NaN-canonicalisation compare and is not counted as one.
			if (n.mnem == "vcmppd" || n.mnem == "vcmpps" || n.mnem == "vcmpunordpd" ||
			    n.mnem == "vcmpunordps")
				++n_cmp;
			if (n.mnem == "vmovapd" || n.mnem == "vmovaps")
				++n_canon_mov;
			if (n.mnem == "vpbroadcastq" || n.mnem == "vpbroadcastd") {
				if (n.ops.size() == 2 && n.ops[1].kind == Operand::Kind::MEM)
					++n_bcast_state;
				else if (n.ops.size() == 2 && n.ops[1].kind == Operand::Kind::GPR)
					++n_bcast_gpr;
			}
		}
		// THE MNEMONIC. One per chunk, all the same, and exactly the one the RVV funct6 maps
		// to -- vfnmADD for RVV's vfnmsub.
		CHECK_EQ(sites.size(), (size_t)r.k);
		for (auto const &s : sites) {
			CHECK(s.mnem == r.expect);
			// Every FMA is lane-masked by k1. An unmasked one would write the whole
			// 512-bit chunk regardless of vl.
			CHECK_EQ(s.kmask, 1u);
			// The 213 form's destination is also its multiplicand, so dst must differ
			// from neither source by accident: dst is the copy of the old vd.
			CHECK(s.src1 != s.dst || s.src2 != s.dst);
		}
		// NO vfnmsub213*, no vmul+vadd decomposition, no 128/256-bit operation, and no ZMM
		// instruction outside the frame window (which is what makes the window a real
		// boundary rather than a convenient one).
		CHECK_EQ(n_forbidden, 0u);
		CHECK_EQ(n_narrow, 0u);
		CHECK_EQ(n_zmm_outside, 0u);
		// One NaN-canonicalisation compare and one masked move per chunk.
		CHECK_EQ(n_cmp, r.k);
		CHECK_EQ(n_canon_mov, r.k);
		// The broadcasts, counted by SOURCE, because the two SEWs read the scalar
		// differently and the difference is architectural rather than cosmetic:
		//   SEW=64  the scalar is NOT unboxed (rv32_vector_lower.h:1467), so it is one
		//           vpbroadcastq straight out of CPUState -- 1 memory-sourced broadcast,
		//           plus one register-sourced canonical-NaN splat per chunk.
		//   SEW=32  f32_unbox has to inspect the upper half first, so the splat is
		//           register-sourced -- 0 memory-sourced, 1 + k register-sourced.
		bool const sew32 = strstr(r.expect, "ps") != nullptr;
		CHECK_EQ(n_bcast_state, sew32 ? 0u : 1u);
		CHECK_EQ(n_bcast_gpr, sew32 ? r.k + 1u : r.k);

		// THE FP BRACKET ENCLOSES THE ARITHMETIC. Emit_rvvqcgfpbegin's ldmxcsr must precede
		// the window and Emit_rvvqcgfpend's stmxcsr must follow it -- that bracket is what
		// forces RNE, clears FTZ/DAZ and accrues MXCSR's exception bits into the guest fcsr.
		long last_ld_before = -1, first_st_after = -1;
		for (size_t i = 0; i < insns.size(); ++i) {
			if (insns[i].mnem == "ldmxcsr" && i < lo)
				last_ld_before = (long)i;
			if (insns[i].mnem == "stmxcsr" && i > hi && first_st_after < 0)
				first_st_after = (long)i;
		}
		CHECK(last_ld_before >= 0);
		CHECK(first_st_after >= 0);

		fprintf(stderr, "    %-24s -> %u x %-13s k1-masked, bracket ok\n", r.name, r.k,
			r.expect);
		// P7I_DUMP=1 prints the frame window verbatim, so the raw bundle carries the actual
		// disassembled bytes as primary evidence rather than only the assertions about them.
		if (getenv("P7I_DUMP")) {
			printf("\n---- %s : emitted frame window (objdump, Intel syntax) ----\n",
			       r.name);
			for (size_t i = lo; i <= hi; ++i)
				printf("  %s\n", insns[i].text.c_str());
			fflush(stdout);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [7b] THE fflags ACCRUAL PATH, at the disassembly level.
//
// The route inherits its exception reporting from the SHARED Emit_rvvqcgfpend, which is what makes
// this checkable at all: no oracle in this project executes a guest that reads fcsr after an FMA
// (miniWeather does not), so a VALUE differential for fflags does not exist. What CAN be checked
// mechanically is that the emitted epilogue performs the SAME host->guest exception mapping the
// helper's FRound::finish performs, and that the FMA really is inside the bracket ([7] above).
//
// The two mappings are stated independently here:
//   host MXCSR (Intel SDM):  IE=bit0  ZE=bit2  OE=bit3  UE=bit4  PE=bit5
//   guest fflags (RISC-V):   NV=0x10  DZ=0x08  OF=0x04  UF=0x02  NX=0x01
// FRound::finish (rv32_fpu.h:321-338) pairs invalid->NV, divbyzero->DZ, overflow->OF,
// underflow->UF, inexact->NX. The emitted code must pair the same five, and no others.
//
// WHAT THIS DOES NOT ESTABLISH, stated here rather than in a report: that the silicon raises the
// same MXCSR bits for vfmadd213pd that glibc's fma() raises through the C fenv bracket. Nothing
// available on this host can show that, and it is carried as an open item.
void Section7b_FflagsAccrual()
{
	fprintf(stderr, "[7b] the emitted fflags accrual matches FRound::finish's mapping\n");
	constexpr u32 FCSR_OFF = (u32)(offsetof(CPUState, fpu) + offsetof(rv32::FPUState, fcsr));
	struct Pair { u64 host_bit; u64 guest_bit; char const *name; };
	Pair const want[] = {
	    {1u << 0, 0x10, "IE->NV"}, {1u << 2, 0x08, "ZE->DZ"}, {1u << 3, 0x04, "OE->OF"},
	    {1u << 4, 0x02, "UE->UF"}, {1u << 5, 0x01, "PE->NX"},
	};
	MemArena arena(1u << 20);
	Env e{512u};
	auto code = EmitBytes(arena, VSETVLI_E64M1, MW_VFMADD_VF, e);
	CHECK(!code.empty());
	if (code.empty())
		return;
	bool ok = false;
	auto insns = DecodeAll(code, &ok);
	CHECK(ok);
	size_t lo = 0, hi = 0;
	if (!ok || !FrameWindow(insns, &lo, &hi)) {
		CHECK(false);
		return;
	}
	// Walk forward from the end of the frame, collecting every (test eax,<host>) immediately
	// followed by a jz over an `or DWORD PTR [r13+fcsr],<guest>`.
	std::vector<std::pair<u64, u64>> got;
	bool saw_st = false, saw_ld_after = false;
	for (size_t i = hi + 1; i < insns.size(); ++i) {
		auto const &n = insns[i];
		if (n.mnem == "stmxcsr")
			saw_st = true;
		if (!saw_st)
			continue;
		if (n.mnem == "ldmxcsr")
			saw_ld_after = true;
		if (n.mnem != "test" || n.ops.size() != 2 ||
		    n.ops[1].kind != Operand::Kind::IMM)
			continue;
		u64 const host = n.ops[1].imm;
		// the OR is two instructions later (test, jz, or)
		for (size_t j = i + 1; j < insns.size() && j <= i + 2; ++j) {
			auto const &o = insns[j];
			if (o.mnem != "or" || o.ops.size() != 2 ||
			    o.ops[0].kind != Operand::Kind::MEM ||
			    o.ops[1].kind != Operand::Kind::IMM)
				continue;
			CHECK_EQ((u32)o.ops[0].disp, FCSR_OFF);
			got.push_back({host, o.ops[1].imm});
			break;
		}
	}
	CHECK(saw_st);
	CHECK(saw_ld_after);
	CHECK_EQ(got.size(), (size_t)5);
	if (got.size() == 5) {
		for (unsigned i = 0; i < 5; ++i) {
			CHECK_EQ(got[i].first, want[i].host_bit);
			CHECK_EQ(got[i].second, want[i].guest_bit);
		}
		fprintf(stderr, "    IE->NV ZE->DZ OE->OF UE->UF PE->NX, all into [r13+0x%x]\n",
			FCSR_OFF);
	}
	// FFLAG_* are the guest bits this mapping claims; pin them against the header rather than
	// against the five literals above, so a change to either side is a failure and not a drift.
	CHECK_EQ((u64)rv32::FFLAG_NV, want[0].guest_bit);
	CHECK_EQ((u64)rv32::FFLAG_DZ, want[1].guest_bit);
	CHECK_EQ((u64)rv32::FFLAG_OF, want[2].guest_bit);
	CHECK_EQ((u64)rv32::FFLAG_UF, want[3].guest_bit);
	CHECK_EQ((u64)rv32::FFLAG_NX, want[4].guest_bit);
}

// ---------------------------------------------------------------------------------------------
// [8] VALUE DIFFERENTIAL: emitted code vs the rv32::vfma helper.
//
// WHAT THIS DOES. It disassembles the REAL emitted bytes and INTERPRETS them over a real CPUState
// image, then runs the REAL helper (dbt::rv32::vfma) on an independent copy of the same inputs and
// compares the destination register byte for byte.
//
// WHY IT IS INTERPRETED FROM THE DISASSEMBLY rather than modelled from this repository's emitter:
// a model written from qemit.cpp would agree with qemit.cpp by construction and would pass with
// the opcode, the operand order or the canonicalisation tail broken. Here the only inputs are
// (a) objdump's decoding of the bytes and (b) the Intel SDM definition of each mnemonic, both
// external to this change. The mutation table in P7I_B_FMA_IMPLEMENTATION.md records which
// mutations this catches and which it does not.
//
// WHAT IT DOES NOT ESTABLISH. It does not execute the bytes -- this host has no AVX-512F and no
// FMA3 -- so it cannot prove that silicon implements vfmadd213pd as the SDM says, and it does not
// model MXCSR, so the fflags accrual in Emit_rvvqcgfpend is NOT covered here. Both are recorded as
// open items rather than papered over.
// ---------------------------------------------------------------------------------------------

// SDM semantics, indexed by mnemonic. `dst` is read as the second multiplicand (the "213" form).
// std::fma is used because it is the once-rounded fused product-sum these opcodes are defined to
// compute; it is correctly rounded in glibc whether or not the host has an FMA unit.
bool FmaSem(std::string const &m, double dst, double s1, double s2, double *out)
{
	if (m == "vfmadd213pd" || m == "vfmadd213ps") { *out = std::fma(s1, dst, s2); return true; }
	if (m == "vfnmadd213pd" || m == "vfnmadd213ps") { *out = std::fma(-s1, dst, s2); return true; }
	if (m == "vfmsub213pd" || m == "vfmsub213ps") { *out = std::fma(s1, dst, -s2); return true; }
	if (m == "vfnmsub213pd" || m == "vfnmsub213ps") { *out = std::fma(-s1, dst, -s2); return true; }
	return false;
}

struct Machine {
	std::array<std::array<u8, 64>, 32> zmm{};
	u32 k[8]{};
	std::map<std::string, u64> gpr;
	u8 *mem = nullptr;
	size_t memsz = 0;
	// last unsigned cmp, for the ja/je the lane-mask prologue uses
	u64 cmp_l = 0, cmp_r = 0;
	bool bad = false;
	std::string why;
};

double LaneGet(std::array<u8, 64> const &z, unsigned lane, unsigned sew)
{
	if (sew == 8) {
		u64 b;
		memcpy(&b, z.data() + lane * 8, 8);
		return rv32::bits_to_f64(b);
	}
	u32 b;
	memcpy(&b, z.data() + lane * 4, 4);
	return (double)rv32::bits_to_f32(b);
}

void LaneSet(std::array<u8, 64> &z, unsigned lane, unsigned sew, double v)
{
	if (sew == 8) {
		u64 b = rv32::f64_to_bits(v);
		memcpy(z.data() + lane * 8, &b, 8);
		return;
	}
	u32 b = rv32::f32_to_bits((float)v);
	memcpy(z.data() + lane * 4, &b, 4);
}

// Interpret [lo,hi] of the decoded stream. `sew` is only used to size FP lanes; every instruction's
// element width comes from its own mnemonic suffix, so a ps/pd mismatch is a hard error, not a
// silent reinterpretation.
void Interpret(Machine &M, std::vector<Insn> const &v, size_t lo, size_t hi)
{
	std::map<u64, size_t> by_addr;
	for (size_t i = 0; i < v.size(); ++i)
		by_addr[v[i].addr] = i;
	auto fail = [&](std::string const &s) {
		M.bad = true;
		if (M.why.empty())
			M.why = s;
	};
	size_t pc = lo;
	unsigned steps = 0;
	while (pc <= hi && !M.bad) {
		if (++steps > 4096) {
			fail("step limit");
			return;
		}
		auto const &n = v[pc];
		auto const &o = n.ops;
		std::string const &m = n.mnem;
		size_t next = pc + 1;
		auto memchk = [&](i64 d, size_t sz) {
			if (d < 0 || (size_t)d + sz > M.memsz) {
				fail("memory access outside CPUState: " + n.text);
				return false;
			}
			return true;
		};
		// Element width comes from the mnemonic's own packed-single/packed-double suffix, so
		// a ps/pd mix-up cannot be silently reinterpreted. This holds for the vcmpunordp{s,d}
		// alias too, which keeps the same final character.
		auto lanes_of = [&](std::string const &mn) -> unsigned {
			return mn.back() == 's' ? 16u : 8u;
		};
		auto sew_of = [&](std::string const &mn) -> unsigned {
			return mn.back() == 's' ? 4u : 8u;
		};
		bool const movdqu = m.compare(0, 7, "vmovdqu") == 0;
		unsigned const mov_lane = m == "vmovdqu32" ? 4u : 8u;
		if (movdqu && o.size() == 2 && o[0].kind == Operand::Kind::ZMM &&
		    o[1].kind == Operand::Kind::MEM && o[1].memsize == 64) {
			if (!memchk(o[1].disp, 64))
				return;
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			for (unsigned l = 0; l < 64u / mov_lane; ++l)
				if (mask & (1u << l))
					memcpy(M.zmm[o[0].reg].data() + l * mov_lane,
					       M.mem + o[1].disp + l * mov_lane, mov_lane);
		} else if (movdqu && o.size() == 2 && o[0].kind == Operand::Kind::MEM &&
			   o[0].memsize == 64 && o[1].kind == Operand::Kind::ZMM) {
			if (!memchk(o[0].disp, 64))
				return;
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			for (unsigned l = 0; l < 64u / mov_lane; ++l)
				if (mask & (1u << l))
					memcpy(M.mem + o[0].disp + l * mov_lane,
					       M.zmm[o[1].reg].data() + l * mov_lane, mov_lane);
		} else if (movdqu && o.size() == 2 && o[0].kind == Operand::Kind::ZMM &&
			   o[1].kind == Operand::Kind::ZMM) {
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			for (unsigned l = 0; l < 64u / mov_lane; ++l)
				if (mask & (1u << l))
					memcpy(M.zmm[o[0].reg].data() + l * mov_lane,
					       M.zmm[o[1].reg].data() + l * mov_lane, mov_lane);
		} else if ((m == "vmovapd" || m == "vmovaps") && o.size() == 2 &&
			   o[0].kind == Operand::Kind::ZMM && o[1].kind == Operand::Kind::ZMM) {
			unsigned const nl = lanes_of(m), sw = sew_of(m);
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			for (unsigned l = 0; l < nl; ++l)
				if (mask & (1u << l))
					memcpy(M.zmm[o[0].reg].data() + l * sw,
					       M.zmm[o[1].reg].data() + l * sw, sw);
		} else if (double dummy; FmaSem(m, 0, 0, 0, &dummy) && o.size() == 3 &&
					 o[0].kind == Operand::Kind::ZMM &&
					 o[1].kind == Operand::Kind::ZMM &&
					 o[2].kind == Operand::Kind::ZMM) {
			unsigned const nl = lanes_of(m), sw = sew_of(m);
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			auto dst = M.zmm[o[0].reg];
			for (unsigned l = 0; l < nl; ++l) {
				if (!(mask & (1u << l)))
					continue;
				double res = 0;
				if (sw == 4) {
					float const fd = (float)LaneGet(M.zmm[o[0].reg], l, 4);
					float const f1 = (float)LaneGet(M.zmm[o[1].reg], l, 4);
					float const f2 = (float)LaneGet(M.zmm[o[2].reg], l, 4);
					// binary32 fused: fmaf, not double-then-narrow.
					float r32;
					if (m == "vfmadd213ps")
						r32 = std::fmaf(f1, fd, f2);
					else if (m == "vfnmadd213ps")
						r32 = std::fmaf(-f1, fd, f2);
					else if (m == "vfmsub213ps")
						r32 = std::fmaf(f1, fd, -f2);
					else
						r32 = std::fmaf(-f1, fd, -f2);
					res = (double)r32;
				} else {
					FmaSem(m, LaneGet(M.zmm[o[0].reg], l, 8),
					       LaneGet(M.zmm[o[1].reg], l, 8),
					       LaneGet(M.zmm[o[2].reg], l, 8), &res);
				}
				LaneSet(dst, l, sw, res);
			}
			M.zmm[o[0].reg] = dst;
		} else if ((m == "vmulpd" || m == "vmulps" || m == "vaddpd" || m == "vaddps" ||
			    m == "vsubpd" || m == "vsubps" || m == "vdivpd" || m == "vdivps") &&
			   o.size() == 3 && o[0].kind == Operand::Kind::ZMM &&
			   o[1].kind == Operand::Kind::ZMM && o[2].kind == Operand::Kind::ZMM) {
			// Present ONLY so a decomposed mul+add mutant is executed faithfully (and
			// therefore shows up as a VALUE difference) instead of being rejected as an
			// unknown opcode, which would fail for the wrong reason.
			unsigned const nl = lanes_of(m), sw = sew_of(m);
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			auto dst = M.zmm[o[0].reg];
			for (unsigned l = 0; l < nl; ++l) {
				if (!(mask & (1u << l)))
					continue;
				if (sw == 4) {
					float x = (float)LaneGet(M.zmm[o[1].reg], l, 4);
					float y = (float)LaneGet(M.zmm[o[2].reg], l, 4);
					float r = m[2] == 'u' && m[3] == 'l' ? x * y
						  : m[1] == 'a'		     ? x + y
						  : m[1] == 's'		     ? x - y
									     : x / y;
					LaneSet(dst, l, 4, (double)r);
				} else {
					double x = LaneGet(M.zmm[o[1].reg], l, 8);
					double y = LaneGet(M.zmm[o[2].reg], l, 8);
					double r = m[2] == 'u' && m[3] == 'l' ? x * y
						   : m[1] == 'a'	      ? x + y
						   : m[1] == 's'	      ? x - y
									      : x / y;
					LaneSet(dst, l, 8, r);
				}
			}
			M.zmm[o[0].reg] = dst;
		} else if ((m == "vcmppd" || m == "vcmpps" || m == "vcmpunordpd" ||
			    m == "vcmpunordps") &&
			   (o.size() == 3 || o.size() == 4) && o[0].kind == Operand::Kind::KREG) {
			// objdump prints imm8=3 through the vcmpunordp{s,d} alias, in which case the
			// immediate is folded into the mnemonic. Any explicit immediate that is not 3
			// is a predicate this frame never emits and is refused rather than assumed.
			if (o.size() == 4 &&
			    (o[3].kind != Operand::Kind::IMM || o[3].imm != 3)) {
				fail("unexpected vcmp predicate: " + n.text);
				return;
			}
			if (o.size() == 3 && m.find("unord") == std::string::npos) {
				fail("three-operand vcmp without an unord alias: " + n.text);
				return;
			}
			unsigned const nl = lanes_of(m), sw = sew_of(m);
			u32 const mask = o[0].kmask ? M.k[o[0].kmask] : 0xffffffffu;
			u32 r = 0;
			for (unsigned l = 0; l < nl; ++l) {
				if (!(mask & (1u << l)))
					continue;
				double x = LaneGet(M.zmm[o[1].reg], l, sw);
				double y = LaneGet(M.zmm[o[2].reg], l, sw);
				if (std::isnan(x) || std::isnan(y)) // UNORD_Q
					r |= 1u << l;
			}
			M.k[o[0].reg] = r;
		} else if ((m == "vpbroadcastq" || m == "vpbroadcastd") && o.size() == 2 &&
			   o[0].kind == Operand::Kind::ZMM) {
			unsigned const w = m.back() == 'q' ? 8u : 4u;
			u64 val = 0;
			if (o[1].kind == Operand::Kind::MEM) {
				if (o[1].memsize != w || !memchk(o[1].disp, w))
					return;
				memcpy(&val, M.mem + o[1].disp, w);
			} else if (o[1].kind == Operand::Kind::GPR) {
				val = M.gpr[o[1].gpr];
			} else {
				fail("unhandled vpbroadcast source: " + n.text);
				return;
			}
			for (unsigned l = 0; l < 64 / w; ++l)
				memcpy(M.zmm[o[0].reg].data() + l * w, &val, w);
		} else if (m == "kmovw" && o.size() == 2 && o[0].kind == Operand::Kind::KREG &&
			   o[1].kind == Operand::Kind::GPR) {
			M.k[o[0].reg] = (u32)(M.gpr[o[1].gpr] & 0xffffu);
		} else if (m == "mov" && o.size() == 2 && o[0].kind == Operand::Kind::MEM &&
			   o[1].kind == Operand::Kind::IMM) {
			if (!memchk(o[0].disp, o[0].memsize))
				return;
			u64 const val = o[1].imm;
			memcpy(M.mem + o[0].disp, &val, o[0].memsize);
		} else if ((m == "mov" || m == "movabs") && o.size() == 2 &&
			   o[0].kind == Operand::Kind::GPR) {
			if (o[1].kind == Operand::Kind::IMM) {
				M.gpr[o[0].gpr] = o[1].imm;
			} else if (o[1].kind == Operand::Kind::MEM) {
				if (!memchk(o[1].disp, o[1].memsize))
					return;
				u64 val = 0;
				memcpy(&val, M.mem + o[1].disp, o[1].memsize);
				M.gpr[o[0].gpr] = val;
			} else if (o[1].kind == Operand::Kind::GPR) {
				M.gpr[o[0].gpr] = M.gpr[o[1].gpr];
			} else {
				fail("unhandled mov: " + n.text);
				return;
			}
		} else if (m == "cmp" && o.size() == 2 && o[0].kind == Operand::Kind::GPR) {
			M.cmp_l = M.gpr[o[0].gpr];
			M.cmp_r = o[1].kind == Operand::Kind::IMM ? o[1].imm : M.gpr[o[1].gpr];
		} else if ((m == "ja" || m == "jbe") && o.size() == 1 &&
			   o[0].kind == Operand::Kind::IMM) {
			bool const take = m == "ja" ? M.cmp_l > M.cmp_r : M.cmp_l <= M.cmp_r;
			if (take) {
				auto it = by_addr.find(o[0].imm);
				if (it == by_addr.end()) {
					fail(m + " target outside decoded stream");
					return;
				}
				next = it->second;
			}
		} else if (m == "je" && o.size() == 1 && o[0].kind == Operand::Kind::IMM) {
			if (M.cmp_l == M.cmp_r) {
				auto it = by_addr.find(o[0].imm);
				if (it == by_addr.end()) {
					fail("je target outside decoded stream");
					return;
				}
				next = it->second;
			}
		} else if (m == "jmp" && o.size() == 1 && o[0].kind == Operand::Kind::IMM) {
			auto it = by_addr.find(o[0].imm);
			if (it == by_addr.end()) {
				fail("jmp target outside decoded stream");
				return;
			}
			next = it->second;
		} else if (m == "cmova" && o.size() == 2 && o[0].kind == Operand::Kind::GPR &&
			   o[1].kind == Operand::Kind::GPR) {
			if (M.cmp_l > M.cmp_r)
				M.gpr[o[0].gpr] = M.gpr[o[1].gpr];
		} else if (m == "xor" && o.size() == 2 && o[0].kind == Operand::Kind::GPR &&
			   o[1].kind == Operand::Kind::GPR && o[0].gpr == o[1].gpr) {
			M.gpr[o[0].gpr] = 0;
		} else if (m == "sub" && o.size() == 2 && o[0].kind == Operand::Kind::GPR &&
			   o[1].kind == Operand::Kind::IMM) {
			M.gpr[o[0].gpr] = (u32)(M.gpr[o[0].gpr] - o[1].imm);
		} else if (m == "bzhi" && o.size() == 3 && o[0].kind == Operand::Kind::GPR &&
			   o[1].kind == Operand::Kind::GPR && o[2].kind == Operand::Kind::GPR) {
			u32 const src = (u32)M.gpr[o[1].gpr];
			u32 const idx = (u32)(M.gpr[o[2].gpr] & 0xffu);
			M.gpr[o[0].gpr] = idx >= 32 ? src : (src & ((1u << idx) - 1u));
		} else {
			fail("unhandled instruction in frame window: " + n.text);
			return;
		}
		pc = next;
	}
}

// One differential case: the same inputs on both sides.
struct Lane {
	char const *name;
	u64 a_bits; // vs2 element
	u64 d_bits; // OLD vd element
};

void RunDifferential(char const *tag, u32 vlen, u32 setvli, u32 word, u32 vd, u32 vs2, u32 rs1,
		     u8 f6, unsigned sew, u64 scalar_bits, u32 vl, std::vector<Lane> const &lanes,
		     u32 group_regs = 1)
{
	MemArena arena(1u << 20);
	Env e{vlen};
	auto code = EmitBytes(arena, setvli, word, e);
	CHECK(!code.empty());
	if (code.empty())
		return;
	bool ok = false;
	auto insns = DecodeAll(code, &ok);
	CHECK(ok);
	if (!ok)
		return;
	size_t lo = 0, hi = 0;
	if (!FrameWindow(insns, &lo, &hi)) {
		CHECK(false);
		return;
	}

	// CPUState has no default constructor; the uthread pointer is never read by anything in
	// this file (nothing here dispatches, faults or calls a helper stub through the state).
	auto state = std::make_unique<CPUState>(nullptr);
	state->vec = rv32::VectorState{};
	state->fpu = rv32::FPUState{};
	state->vec.Reset(vlen);
	state->vec.vtype = setvli >> 20;
	state->vec.vl = vl;
	state->vec.vstart = 0;
	state->fpu.f[rs1] = scalar_bits;
	// The GROUP's element count: LMUL registers of VLEN/SEW elements each. elem_put/elem_u
	// index across the group (elem_ptr advances to base_reg + index/per_reg), so an LMUL=2 case
	// really does place its upper half in the second register.
	unsigned const elems = (vlen / (sew * 8u)) * group_regs;
	for (unsigned i = 0; i < lanes.size() && i < elems; ++i) {
		state->vec.elem_put(vs2, i, sew, vlen, lanes[i].a_bits);
		state->vec.elem_put(vd, i, sew, vlen, lanes[i].d_bits);
	}

	// --- reference: the real helper, on an independent copy ---
	auto ref = std::make_unique<CPUState>(nullptr);
	ref->vec = state->vec;
	ref->fpu = state->fpu;
	ref->fpu.set_frm(0); // RNE -- exactly what the emitted guard requires
	rv32::rvv_ref::vfma(ref->vec, ref->fpu, f6, /*is_vf=*/true, vd, vs2, rs1, /*vm=*/true, vlen, vl, sew);

	// --- candidate: interpret the emitted bytes over the CPUState image ---
	Machine M;
	M.mem = reinterpret_cast<u8 *>(state.get());
	M.memsz = sizeof(CPUState);
	Interpret(M, insns, lo, hi);
	if (M.bad) {
		fprintf(stderr, "  FAIL %s: interpreter refused: %s\n", tag, M.why.c_str());
		++g_failures;
		return;
	}

	unsigned mismatches = 0;
	for (unsigned i = 0; i < vl && i < elems; ++i) {
		u64 const got = state->vec.elem_u(vd, i, sew, vlen);
		u64 const want = ref->vec.elem_u(vd, i, sew, vlen);
		if (got != want) {
			++mismatches;
			char const *nm = i < lanes.size() ? lanes[i].name : "?";
			fprintf(stderr,
				"  FAIL %s lane %u (%s): emitted 0x%016llx != helper 0x%016llx\n",
				tag, i, nm, (unsigned long long)got, (unsigned long long)want);
		}
	}
	// Lanes at or above vl are NOT compared: the helper leaves them untouched while the frame
	// writes the whole 64-byte chunk, and the admitted vtype is tail-AGNOSTIC (vta), which
	// permits exactly that. Comparing them would assert a policy RVV does not require.
	if (mismatches)
		g_failures += (int)mismatches;
	else
		fprintf(stderr, "    %-34s : %u/%u lanes byte-identical to the helper\n", tag,
			std::min(vl, elems), std::min(vl, elems));
}

void Section8_ValueDifferential()
{
	fprintf(stderr, "[8] value differential: interpreted emitted bytes vs rv32::vfma helper\n");

	// f64 bit patterns, written as bits so nothing depends on decimal parsing.
	auto B = [](double d) { return rv32::f64_to_bits(d); };
	u64 const SUBNORMAL = 0x0000000000000003ull; // 3 * 2^-1074
	u64 const QNAN_PAYLOAD = 0x7ff8000000000123ull;
	u64 const SNAN_BITS = 0x7ff0000000000001ull; // signalling: quiet bit clear, payload nonzero
	u64 const INF = 0x7ff0000000000000ull;
	u64 const HUGE_V = B(1e308);

	// THE SCALAR MULTIPLIER, chosen so the corpus can separate a fused product-sum from a
	// rounded multiply followed by a rounded add. 0.1 is not representable, so 0.1*10 is
	// 1.0000000000000000555... exactly; rounding that to binary64 gives exactly 1.0, and the
	// discarded 2^-54 is what a fused operation keeps and a split one loses.
	u64 const SCALAR = B(10.0);

	// THE DOUBLE-ROUNDING WITNESSES, one per admitted funct6, and the assertions that they still
	// work. If either ever stops distinguishing fma from mul+add, the corpus has silently lost
	// its power to catch a decomposed lowering and this test says so instead of passing.
	{
		double const d = 0.1, b = 10.0;
		double const madd_fused = std::fma(d, b, -1.0), madd_split = d * b + -1.0;
		double const nmsub_fused = std::fma(-d, b, 1.0), nmsub_split = -(d * b) + 1.0;
		CHECK(rv32::f64_to_bits(madd_fused) != rv32::f64_to_bits(madd_split));
		CHECK(rv32::f64_to_bits(nmsub_fused) != rv32::f64_to_bits(nmsub_split));
		fprintf(stderr,
			"    double-rounding witness: vfmadd fma=%a split=%a ; vfnmsub fma=%a split=%a\n",
			madd_fused, madd_split, nmsub_fused, nmsub_split);
	}
	// THE NaN-CANONICALISATION WITNESS: the raw fused result of the sNaN lane must NOT already be
	// the canonical quiet NaN, or removing the canonicalisation tail would be undetectable.
	{
		double const r = std::fma(rv32::bits_to_f64(SNAN_BITS), 2.0, 1.0);
		CHECK(rv32::f64_to_bits(r) != 0x7ff8000000000000ull);
		fprintf(stderr, "    NaN-canon witness: raw fma of a sNaN = 0x%016llx (must differ "
				"from 0x7ff8000000000000)\n",
			(unsigned long long)rv32::f64_to_bits(r));
	}

	// Lane 1 is the vfmadd double-rounding witness and lane 2 the vfnmsub one, so BOTH admitted
	// opcodes are exercised on a value where fused and split disagree, whichever word is run.
	std::vector<Lane> const f64_lanes = {
	    {"ordinary", B(3.5), B(-1.25)},
	    {"double-rounding (madd)", B(-1.0), B(0.1)},
	    {"double-rounding (nmsub)", B(1.0), B(0.1)},
	    {"subnormal operand", SUBNORMAL, B(0.5)},
	    {"subnormal result", B(0.0), SUBNORMAL},
	    {"qNaN payload in vs2", QNAN_PAYLOAD, B(1.0)},
	    {"sNaN in vd", B(1.0), SNAN_BITS},
	    {"inf * 0 -> invalid", B(0.0), INF},
	};
	// A second corpus whose lanes overflow and underflow, run separately so the eight-lane
	// chunk does not have to carry every case at once.
	std::vector<Lane> const f64_extremes = {
	    {"overflow", HUGE_V, HUGE_V},
	    {"-overflow", B(-1e308), HUGE_V},
	    {"underflow to subnormal", B(0.0), B(1e-310)},
	    {"inf - inf", B(-1.0), INF},
	    {"zero * inf", B(1.0), B(0.0)},
	    {"tiny * tiny", SUBNORMAL, SUBNORMAL},
	    {"neg zero", B(-0.0), B(-0.0)},
	    {"max normal", B(1.7976931348623157e308), B(1.0)},
	};

	// VLEN 512, e64, m1: one chunk, no branch in the lane-mask prologue.
	RunDifferential("e64,m1@512 vfmadd.vf  full VL", 512, VSETVLI_E64M1, MW_VFMADD_VF, 9, 8, 8,
			40, 8, SCALAR, 8, f64_lanes);
	RunDifferential("e64,m1@512 vfnmsub.vf full VL", 512, VSETVLI_E64M1, MW_VFNMSUB_VF, 9, 8, 13,
			43, 8, SCALAR, 8, f64_lanes);
	// PARTIAL VL: the lane mask is real, and only lanes below vl are compared.
	RunDifferential("e64,m1@512 vfmadd.vf  vl=5", 512, VSETVLI_E64M1, MW_VFMADD_VF, 9, 8, 8, 40,
			8, SCALAR, 5, f64_lanes);
	RunDifferential("e64,m1@512 vfnmsub.vf vl=3", 512, VSETVLI_E64M1, MW_VFNMSUB_VF, 9, 8, 13,
			43, 8, SCALAR, 3, f64_lanes);
	// The overflow/underflow corpus, on both opcodes.
	RunDifferential("e64,m1@512 vfmadd.vf  extremes", 512, VSETVLI_E64M1, MW_VFMADD_VF, 9, 8, 8,
			40, 8, SCALAR, 8, f64_extremes);
	RunDifferential("e64,m1@512 vfnmsub.vf extremes", 512, VSETVLI_E64M1, MW_VFNMSUB_VF, 9, 8,
			13, 43, 8, SCALAR, 8, f64_extremes);
	// VLEN 1024, e64, m1: TWO chunks, so chunk 1's mask prologue really branches.
	{
		std::vector<Lane> wide = f64_lanes;
		for (unsigned i = 0; i < 8; ++i)
			wide.push_back(f64_lanes[i]);
		RunDifferential("e64,m1@1024 vfmadd.vf  full VL", 1024, VSETVLI_E64M1, MW_VFMADD_VF,
				9, 8, 8, 40, 8, SCALAR, 16, wide);
		RunDifferential("e64,m1@1024 vfnmsub.vf vl=11", 1024, VSETVLI_E64M1, MW_VFNMSUB_VF, 9,
				8, 13, 43, 8, SCALAR, 11, wide);
	}
	// SEW=32, with a properly NaN-boxed scalar and, separately, an UNBOXED one -- the second is
	// the case where the guest wrote a 64-bit value into f[rs1] and the architecture requires the
	// scalar to read as the canonical binary32 NaN.
	{
		auto B32 = [](float f) { return (u64)0xffffffff00000000ull | rv32::f32_to_bits(f); };
		std::vector<Lane> f32_lanes;
		u64 const raw[] = {rv32::f32_to_bits(3.5f),  rv32::f32_to_bits(-1.25f),
				   0x00000003u,		     0x7fc00123u,
				   0x7f800001u,		     0x7f800000u,
				   rv32::f32_to_bits(1e38f), 0u};
		char const *nm[] = {"ordinary", "negative", "subnormal", "qNaN payload",
				    "sNaN",	"inf",	    "overflow",	 "zero"};
		for (unsigned i = 0; i < 16; ++i)
			f32_lanes.push_back({nm[i % 8], raw[i % 8], raw[(i + 3) % 8]});
		RunDifferential("e32,m1@512 vfmadd.vf boxed", 512, VSETVLI_E32M1, VFMADD_VF_EVEN, 8, 10,
				9, 40, 4, B32(1.5f), 16, f32_lanes);
		RunDifferential("e32,m1@512 vfmadd.vf UNBOXED", 512, VSETVLI_E32M1, VFMADD_VF_EVEN, 8,
				10, 9, 40, 4, 0x0000000000000001ull, 16, f32_lanes);
		RunDifferential("e32,m1@512 vfnmsub.vf boxed", 512, VSETVLI_E32M1, VFNMSUB_VF_EVEN, 8,
				10, 13, 43, 4, B32(1.5f), 16, f32_lanes);
	}
	// LMUL=2 at VLEN 512: two registers, one chunk each.
	{
		std::vector<Lane> wide = f64_lanes;
		for (unsigned i = 0; i < 8; ++i)
			wide.push_back(f64_lanes[i]);
		RunDifferential("e64,m2@512 vfmadd.vf full VL", 512, VSETVLI_E64M2, VFMADD_VF_EVEN, 8,
				10, 9, 40, 8, SCALAR, 16, wide, /*group_regs=*/2);
		RunDifferential("e64,m2@512 vfnmsub.vf vl=13", 512, VSETVLI_E64M2, VFNMSUB_VF_EVEN, 8,
				10, 13, 43, 8, SCALAR, 13, wide, /*group_regs=*/2);
	}
}

// ---------------------------------------------------------------------------------------------
// [9] THE LANE-MASK PROLOGUE IS THE SAME ONE THE SHIPPED falu ROUTE USES.
// Compared at the DISASSEMBLY level, not by reading qemit.cpp: the instruction sequence between a
// frame's first 64-byte load and its arithmetic must be identical for the two routes at the same
// SEW and chunk index. That is what lets [8]'s partial-VL cases stand on P7E/P7H's dynamic
// validation of that prologue rather than re-deriving it.
// ---------------------------------------------------------------------------------------------
std::vector<std::string> MaskPrologueMnemonics(std::vector<Insn> const &v, size_t lo, size_t hi)
{
	std::vector<std::string> out;
	bool started = false;
	for (size_t i = lo; i <= hi; ++i) {
		auto const &m = v[i].mnem;
		if (m == "mov" && v[i].ops.size() == 2 && v[i].ops[0].kind == Operand::Kind::GPR &&
		    v[i].ops[1].kind == Operand::Kind::MEM && v[i].ops[1].memsize == 4)
			started = true;
		if (!started)
			continue;
		out.push_back(m);
		if (m == "kmovw")
			break;
	}
	return out;
}

void Section9_MaskPrologueIdentity()
{
	fprintf(stderr, "[9] the lane-mask prologue is instruction-identical to the falu route's\n");
	auto prologue_of = [&](bool fma_route, u32 vlen, u32 setvli, u32 word) {
		MemArena arena(1u << 20);
		Env e{vlen};
		ApplyEnv(e);
		if (!fma_route) {
			config::rvv_qcg_typed_chunk_fma = false;
			config::rvv_qcg_typed_chunk_falu = true;
			config::rvv_qcg_typed_chunk_falu_force_emit = true;
		}
		u32 words[2] = {setvli, word};
		CompilerJob::IpRangesSet ranges = {{0u, 8u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		if (FindFrames(region).empty())
			return std::vector<std::string>{};
		TestCompilerRuntime cr;
		qir::CodeSegment segment(0u, 0x1000u);
		auto span = qcg::GenerateCode(&cr, &segment, region, 0);
		std::vector<u8> code(span.begin(), span.end());
		bool ok = false;
		auto insns = DecodeAll(code, &ok);
		size_t lo = 0, hi = 0;
		if (!ok || !FrameWindow(insns, &lo, &hi))
			return std::vector<std::string>{};
		return MaskPrologueMnemonics(insns, lo, hi);
	};
	// vfmul.vf @ e64,m1 is a shipped falu form with the same SEW and chunk index.
	constexpr u32 MW_VFMUL_VF = 0x92c7d6d7u; // vfmul.vf v13, v12, fa5
	auto fma_p = prologue_of(true, 512, VSETVLI_E64M1, MW_VFMADD_VF);
	auto falu_p = prologue_of(false, 512, VSETVLI_E64M1, MW_VFMUL_VF);
	CHECK(!fma_p.empty());
	CHECK(!falu_p.empty());
	CHECK(fma_p == falu_p);
	std::string joined;
	for (auto const &s : fma_p)
		joined += s + " ";
	fprintf(stderr, "    %s\n", joined.c_str());
}

#endif // !RVV_FP_FORCE_SOFT

// ---------------------------------------------------------------------------------------------
// N2: under -DRVV_FP_FORCE_SOFT the route must not exist AT ALL.
//
// In that build fp_mode() returns FP_SOFT unconditionally (rv32_fpu.h:176-179), so the helper
// computes every element in rv32_softfp.h's exact integer core, which is the reference that build
// exists to establish. An emitted host-FP frame is a different function and NO runtime guard can
// express the difference -- frm is still RNE, the vtype still matches. So the refusal has to be at
// compile time, and force-emit must not bypass it either.
//
// This binary links a copy of guest/rv32_qir.cpp rebuilt with the macro, so the predicate under
// test really is the force-soft one.
// ---------------------------------------------------------------------------------------------
// The POSITIVE case matrix, shared by the force-soft refusal test and its control so the two
// cannot drift apart. Only combinations that are admissible under the ordinary rules are listed:
// every setvli/word pair here has an even-or-m1-legal register group.
struct PosCase { u32 vlen, setvli, word; };
std::vector<PosCase> PositiveCases()
{
	std::vector<PosCase> out;
	u32 const m1[] = {VSETVLI_E64M1, VSETVLI_E32M1};
	u32 const m2[] = {VSETVLI_E64M2, VSETVLI_E32M2};
	for (u32 vlen : {512u, 1024u}) {
		for (u32 sv : m1)
			for (u32 w : {MW_VFMADD_VF, MW_VFNMSUB_VF, VFMADD_VF_EVEN, VFNMSUB_VF_EVEN})
				out.push_back({vlen, sv, w});
		for (u32 sv : m2)
			for (u32 w : {VFMADD_VF_EVEN, VFNMSUB_VF_EVEN})
				out.push_back({vlen, sv, w});
	}
	return out;
}

void Section_N2_ForceSoft()
{
	fprintf(stderr, "[N2] -DRVV_FP_FORCE_SOFT: the route must be compiled out\n");
	unsigned cases = 0;
	for (auto const &c : PositiveCases())
		for (bool force : {false, true}) {
			Env e{c.vlen};
			// force-emit bypasses the CPUID probes and must NOT bypass this.
			e.force_emit = force;
			CHECK(RefusedToHelper(c.setvli, c.word, e));
			++cases;
		}
	fprintf(stderr, "    %u case(s), all 0 frames + 1 rv32_vfma hcall\n", cases);
}

#ifndef RVV_FP_FORCE_SOFT
// N2's CONTROL, and the reason N2 is not vacuous. The force-soft binary refuses all of
// PositiveCases(); this asserts that the SAME cases are admitted by the ordinary build, so the
// refusal there is caused by the macro and not by a case list that could never have admitted.
// It is also the check that the force-soft executable really did recompile rv32_qir.cpp with the
// macro rather than link the archive copy: if it had linked the archive copy, its results would
// match this one.
void Section_N2_Control()
{
	fprintf(stderr, "[N2c] control: the same cases admit in the ordinary build\n");
	unsigned n = 0;
	for (auto const &c : PositiveCases()) {
		Env e{c.vlen};
		e.force_emit = true;
		CHECK(Admitted(c.setvli, c.word, e));
		++n;
	}
	fprintf(stderr, "    %u/%u admitted\n", n, (unsigned)PositiveCases().size());
}
#endif

} // namespace

int main()
{
#ifdef RVV_FP_FORCE_SOFT
	fprintf(stderr, "P7I-B vfma typed-chunk route test (RVV_FP_FORCE_SOFT build)\n");
	Section_N2_ForceSoft();
#else
	fprintf(stderr, "P7I-B vfma typed-chunk route test\n");
	Section1_ShapeRule();
	Section2_MiniWeatherWords();
	Section3_Funct6Fidelity();
	Section4_LoadMajor();
	Section5_WindowGeometry();
	Section6_FailClosed();
	Section7_EmittedBytes();
	Section7b_FflagsAccrual();
	Section8_ValueDifferential();
	Section9_MaskPrologueIdentity();
	Section_N2_Control();
#endif
	if (g_failures) {
		fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	fprintf(stderr, "OK\n");
	return 0;
}
