// P7K-B: the three e64 floating-ALU forms that were miniWeather's ENTIRE remaining FP helper
// traffic -- `vfdiv.vv`, `vfadd.vf` and `vfsub.vf` -- and the softfloat-build refusal that had to
// come with them.
//
// WHAT P7J-B MEASURED, AND WHY THESE THREE
//
// After the FMA route closed, miniWeather's residual helper traffic was 9,910 calls at VLEN 512
// and 6,310 at VLEN 1024. Of those, 7,200 / 3,600 were floating-point arithmetic, and every one of
// them came from SIX PCs inside a single loop in `output()` (0x12a94-0x12af4). The six raw words
// are reproduced below verbatim; nothing here is synthetic.
//
// THE CLAIM THIS FILE CHECKS, AND THE ONE IT DOES NOT
//
// P7K-A's audit concluded that each of the three is a CROSS-PRODUCT of two halves this route
// already ships: the emitter case (0b000000 / 0b000010 / 0b100000) is already validated at another
// SEW or another funct3, and the e64 `.vf` broadcast and e64 `.vv` two-load operand shapes are
// already validated by forms P7H closed on hardware. So no QIR node, no emitter case, no GuardKind
// and no FP-bracket change was needed. This file checks that the admission really is the only
// thing that moved, and that it moved in exactly one direction.
//
// It does NOT execute a single emitted byte. The development host has no AVX-512F and no BMI2, so
// `rvv_qcg_typed_chunk_falu_force_emit` is what lets the shape be inspected at all; it bypasses
// ONLY the CPUID probe, and TestCompilerRuntime resizes a std::vector<u8> -- there is no mmap in
// this process, let alone a PROT_EXEC one. Nothing here is timed and no workload is run.
//
// THE TWO THINGS THAT COULD GO WRONG, AND WHERE EACH IS CAUGHT
//
//   1. OPERAND ORDER. `vfsub` and `vfdiv` do not commute. The helper computes `vs2 OP (vs1|scalar)`
//      (rv32_vector_lower.h:1536-1544) and the emitter must emit `vsubpd/vdivpd out, a=vs2, b=vs1`.
//      The same emitter has a deliberately REVERSED case for `vfrdiv.vf` (qemit.cpp:2537), which is
//      what makes the order a maintained contract rather than an accident -- and what makes a swap
//      plausible. Caught by [2] at the QIR level and by [4] on the disassembled bytes, where the
//      zmm feeding each operand is traced back to the CPUState window it was loaded from.
//   2. THE `!dynamic_vtype` GATE. `observed_at_sew` also serves the UNOBSERVED-vtype path, where
//      the frame proposes a hard-coded e64,m2 candidate. The six measured PCs are e64,m1, so an
//      unobserved-path admission would emit a guard that misses on every execution: 7,200 new
//      guard_fallbacks and zero closure -- P7H section 4's vle32.v failure, 150x larger. Caught by
//      [5.1], which requires the unobserved path to reach the helper for exactly these words while
//      the pre-existing unobserved behaviour is unchanged.
//
// UNDER -DRVV_FP_FORCE_SOFT this file compiles to a DIFFERENT main(): see Section_SoftGate.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                  \
	do {                                                                                         \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                        \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_F_BASE = (u32)(offsetof(CPUState, fpu) + offsetof(rv32::FPUState, f));

u32 ChunkOffs(u32 reg, u32 chunk, u32 vlen_bits)
{
	u32 const per_reg = vlen_bits / 512u;
	return ST_VREG_BASE + (reg + chunk / per_reg) * rv32::VLEN_MAX_BYTES + (chunk % per_reg) * 64u;
}

// ---------------------------------------------------------------------------------------------
// Instruction words.
// ---------------------------------------------------------------------------------------------
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;    // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;    // vsetvli a0, a0, e64, m2, ta, ma
constexpr u32 VSETVLI_E32M1 = 0x0d057557u;    // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 VSETVLI_E32M2 = 0x0d157557u;    // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 VSETVLI_E64M4 = 0x0da57557u;    // vsetvli a0, a0, e64, m4, ta, ma
constexpr u32 VSETVLI_E64MF2 = 0x0df57557u;   // vsetvli a0, a0, e64, mf2, ta, ma
constexpr u32 VSETVLI_E16M1 = 0x0c857557u;    // vsetvli a0, a0, e16, m1, ta, ma
constexpr u32 VSETVLI_E8M1 = 0x0c057557u;     // vsetvli a0, a0, e8,  m1, ta, ma
constexpr u32 VSETVLI_E64M1_TU = 0x09857557u; // vsetvli a0, a0, e64, m1, tu, ma

// THE SIX WORDS P7J-B MEASURED IN miniWeather's output() loop. These are the raw values
// --rvv-pc-census recorded, at the PCs named beside them.
constexpr u32 MW_VFADD_VF_A = 0x0287d457u;  // 0x12ab8  vfadd.vf  v8,  v8,  fa5
constexpr u32 MW_VFADD_VF_B = 0x029754d7u;  // 0x12ae0  vfadd.vf  v9,  v9,  fa4
constexpr u32 MW_VFSUB_VF = 0x0a86d457u;    // 0x12ae8  vfsub.vf  v8,  v8,  fa3
constexpr u32 MW_VFDIV_VV_A = 0x829414d7u;  // 0x12abc  vfdiv.vv  v9,  v9,  v8
constexpr u32 MW_VFDIV_VV_B = 0x82a41557u;  // 0x12ad0  vfdiv.vv  v10, v10, v8
constexpr u32 MW_VFDIV_VV_ALIAS = 0x82941457u; // 0x12ae4 vfdiv.vv v8, v9, v8  -- vd == vs1

// The encoder, pinned against the six measured words so every synthetic word below is derived
// rather than hand-typed. A mistyped hex constant silently changes what a test is testing.
constexpr u32 MakeOpFV(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (rs1 << 15) | (funct3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpFV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpFV(f6, 1, vs2, rs1, vd, 0b101u); }
static_assert(Vf(0, 8, 15, 8) == MW_VFADD_VF_A, "encoder disagrees with the measured vfadd.vf");
static_assert(Vf(0, 9, 14, 9) == MW_VFADD_VF_B, "encoder disagrees with the measured vfadd.vf");
static_assert(Vf(2, 8, 13, 8) == MW_VFSUB_VF, "encoder disagrees with the measured vfsub.vf");
static_assert(Vv(32, 9, 8, 9) == MW_VFDIV_VV_A, "encoder disagrees with the measured vfdiv.vv");
static_assert(Vv(32, 10, 8, 10) == MW_VFDIV_VV_B, "encoder disagrees with the measured vfdiv.vv");
static_assert(Vv(32, 9, 8, 8) == MW_VFDIV_VV_ALIAS, "encoder disagrees with the measured vfdiv.vv");

// Even-numbered, disjoint operands so the same forms are legal at LMUL=2 as well.
constexpr u32 VFDIV_VV_EVEN = Vv(32, /*vs2=*/10, /*vs1=*/12, /*vd=*/8);
constexpr u32 VFADD_VF_EVEN = Vf(0, /*vs2=*/10, /*rs1=*/9, /*vd=*/8);
constexpr u32 VFSUB_VF_EVEN = Vf(2, /*vs2=*/10, /*rs1=*/13, /*vd=*/8);
// Masked variants: identical except vm = 0.
constexpr u32 VFDIV_VV_MASKED = MakeOpFV(32, 0, 10, 12, 8, 0b001u);
constexpr u32 VFSUB_VF_MASKED = MakeOpFV(2, 0, 10, 13, 8, 0b101u);
// Forms P7K-B did NOT add, which must stay on the helper.
constexpr u32 VFRDIV_VF_E64 = Vf(33, 10, 13, 8); // vfrdiv.vf: reversed, admitted at SEW 32 only
constexpr u32 VFRSUB_VF_E64 = Vf(39, 10, 13, 8); // vfrsub.vf: never admitted by this route
// Forms this route admitted BEFORE P7K-B, used to prove nothing regressed.
constexpr u32 PRE_VFADD_VV = Vv(0, 10, 12, 8);
constexpr u32 PRE_VFSUB_VV = Vv(2, 10, 12, 8);
constexpr u32 PRE_VFMUL_VF = Vf(36, 10, 15, 8);
constexpr u32 PRE_VFDIV_VF = Vf(32, 10, 15, 8);
constexpr u32 PRE_VFRDIV_VF_E32 = Vf(33, 10, 15, 8);

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------
struct Env {
	u32 vlen_bits = 512;
	bool falu = true;
	bool force_emit = true;
	bool rvv_direct = true;
	bool rvv_verify = false;
	bool aot_use_llvm = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_typed_chunk_falu = e.falu;
	config::rvv_qcg_typed_chunk_falu_force_emit = e.force_emit;
	config::rvv_direct = e.rvv_direct;
	config::rvv_verify = e.rvv_verify;
	config::aot_use_llvm = e.aot_use_llvm;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	// The FMA route is a different predicate and a different stub; keeping it off makes "which
	// route produced this frame" a property of the run rather than a claim.
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_typed_chunk_fma_force_emit = false;
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
	for (auto &bb : region->GetBlocks())
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

unsigned CountFaluHelper(Region *region)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_hcall)
				n += static_cast<InstHcall *>(&ins)->stub == RuntimeStubId::id_rv32_vfalu;
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
	return !FindFrames(TranslatePair(arena, words, setvli, word, e)).empty();
}

// "Refused" means BOTH no frame AND the pre-existing helper is still there: checking only the
// first would pass on an implementation that dropped the instruction entirely.
bool RefusedToHelper(u32 setvli, u32 word, Env const &e)
{
	MemArena arena(1u << 20);
	u32 words[2];
	auto *region = TranslatePair(arena, words, setvli, word, e);
	return FindFrames(region).empty() && CountFaluHelper(region) == 1u &&
	       CountOp(region, Op::_vchunkfalu) == 0u;
}

bool RefusedUnobserved(u32 word, Env const &e)
{
	MemArena arena(1u << 20);
	u32 w = word;
	auto *region = TranslateWords(arena, &w, 1, e);
	return FindFrames(region).empty() && CountFaluHelper(region) == 1u &&
	       CountOp(region, Op::_vchunkfalu) == 0u;
}

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

// The six measured words, with the fields the frame must reproduce.
struct MwCase {
	char const *name;
	char const *pc;
	u32 word;
	bool vf;
	u8 f6;
	u32 vd, vs2, src1; // src1 = vs1 for .vv, rs1 (an F register) for .vf
};
constexpr MwCase MW[] = {
    {"vfadd.vf v8,v8,fa5", "0x12ab8", MW_VFADD_VF_A, true, 0, 8, 8, 15},
    {"vfadd.vf v9,v9,fa4", "0x12ae0", MW_VFADD_VF_B, true, 0, 9, 9, 14},
    {"vfsub.vf v8,v8,fa3", "0x12ae8", MW_VFSUB_VF, true, 2, 8, 8, 13},
    {"vfdiv.vv v9,v9,v8", "0x12abc", MW_VFDIV_VV_A, false, 32, 9, 9, 8},
    {"vfdiv.vv v10,v10,v8", "0x12ad0", MW_VFDIV_VV_B, false, 32, 10, 10, 8},
    {"vfdiv.vv v8,v9,v8", "0x12ae4", MW_VFDIV_VV_ALIAS, false, 32, 8, 9, 8},
};

#ifndef RVV_FP_FORCE_SOFT

// ---------------------------------------------------------------------------------------------
// [1] THE SIX MEASURED WORDS ADMIT AT e64,m1, AND THE FRAME HAS THE RIGHT SHAPE.
// ---------------------------------------------------------------------------------------------
void Section1_Shape()
{
	fprintf(stderr, "[1] the six miniWeather output()-loop words at e64,m1\n");
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = vlen / 512u; // LMUL=1: one chunk per 512 bits of ONE register
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
			CHECK_EQ(CountOp(region, Op::_vchunkfalu), k);
			CHECK_EQ(CountFaluHelper(region), 0u);
			// .vf: one source load, one lane op, one store per chunk, plus the broadcast
			// and the fp begin/end pair. .vv: two loads instead of the broadcast.
			CHECK_EQ((unsigned)f.begin->n_typed, c.vf ? 3u * k + 3u : 4u * k + 2u);
			CHECK_EQ(CountOp(region, Op::_vstatechunkload), c.vf ? k : 2u * k);
			CHECK_EQ(CountOp(region, Op::_vchunkfbroadcast), c.vf ? 1u : 0u);
			CHECK_EQ(CountOp(region, Op::_vstatechunkstore), k);
			// The guard is the vtype the block observed and the EXISTING guard kind.
			CHECK_EQ(f.begin->vtype, VSETVLI_E64M1 >> 20);
			CHECK_EQ(f.begin->vlmax, vlen / 64u);
			CHECK_EQ(f.begin->raw, c.word);
			// QCG programs MXCSR from the live guest frm and falls back for the
			// unsupported RMM case, so the frame accepts host-representable modes.
			CHECK(f.begin->guard_kind ==
			      InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost);
			CHECK(f.begin->stub == RuntimeStubId::id_rv32_vfalu);
			CHECK(f.end->stub == RuntimeStubId::id_rv32_vfalu);
			fprintf(stderr, "    VLEN %-4u %-8s %-22s -> DIRECT, %u chunk(s), f6=%u\n",
				vlen, c.pc, c.name, k, (unsigned)c.f6);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [2] OPERAND ORDER AND FUNCT6 FIDELITY, AT THE QIR LEVEL.
// vfsub and vfdiv do not commute, so which window feeds which operand is the whole correctness
// question. Every count in section [1] is identical under a swap.
// ---------------------------------------------------------------------------------------------
void Section2_OperandOrder()
{
	fprintf(stderr, "[2] operand order: vs2 is the left operand, vs1/scalar the right\n");
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = vlen / 512u;
		for (auto const &c : MW) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, VSETVLI_E64M1, c.word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty())
				continue;
			auto const &f = frames[0];
			auto loads = LoadOffsets(f);
			auto stores = StoreOffsets(f);
			// LOADS: k chunks of vs2 first; for .vv, then k chunks of vs1.
			CHECK_EQ(loads.size(), (size_t)(c.vf ? k : 2 * k));
			for (u32 i = 0; i < k && i < loads.size(); ++i)
				CHECK_EQ(loads[i], ChunkOffs(c.vs2, i, vlen));
			if (!c.vf)
				for (u32 i = 0; i < k && k + i < loads.size(); ++i)
					CHECK_EQ(loads[k + i], ChunkOffs(c.src1, i, vlen));
			// STORES: vd's own chunks, in order.
			CHECK_EQ(stores.size(), (size_t)k);
			for (u32 i = 0; i < stores.size(); ++i)
				CHECK_EQ(stores[i], ChunkOffs(c.vd, i, vlen));
			// THE SCALAR of a .vf form: f[rs1], read raw at SEW 8. At FLEN=64 and SEW=64
			// the scalar and the F register are the same width, so there is no narrower
			// value to unbox -- the broadcast reads the register verbatim, exactly as
			// rv32_vector_lower.h:1537's `fs.f[vs1]` does.
			unsigned nb = 0;
			for (auto *ins : f.body) {
				if (ins->GetOpcode() != Op::_vchunkfbroadcast)
					continue;
				auto *b = static_cast<InstVChunkFBroadcast *>(ins);
				CHECK_EQ((u32)b->offs, ST_F_BASE + c.src1 * (u32)sizeof(u64));
				CHECK_EQ((unsigned)b->sew_bytes, 8u);
				++nb;
			}
			CHECK_EQ(nb, c.vf ? 1u : 0u);
			// funct6 reaches the node intact, and the chunk index is sequential.
			unsigned n = 0;
			for (auto *ins : f.body) {
				if (ins->GetOpcode() != Op::_vchunkfalu)
					continue;
				auto *m = static_cast<InstVChunkFALU *>(ins);
				CHECK_EQ((unsigned)m->funct6, (unsigned)c.f6);
				CHECK_EQ((unsigned)m->sew_bytes, 8u);
				CHECK_EQ((unsigned)m->chunk, n);
				++n;
			}
			CHECK_EQ(n, k);
		}
	}
	// The three funct6 values must stay distinguishable through the frame: if they collapsed,
	// a divide would be emitted as an add and every count above would still match.
	{
		u8 seen[3] = {0xff, 0xff, 0xff};
		unsigned i = 0;
		for (u32 w : {MW_VFADD_VF_A, MW_VFSUB_VF, MW_VFDIV_VV_A}) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{512u};
			auto *region = TranslatePair(arena, words, VSETVLI_E64M1, w, e);
			auto frames = FindFrames(region);
			if (!frames.empty())
				for (auto *ins : frames[0].body)
					if (ins->GetOpcode() == Op::_vchunkfalu)
						seen[i] = static_cast<InstVChunkFALU *>(ins)->funct6;
			++i;
		}
		CHECK_EQ((unsigned)seen[0], 0u);
		CHECK_EQ((unsigned)seen[1], 2u);
		CHECK_EQ((unsigned)seen[2], 32u);
	}
	fprintf(stderr, "    windows, scalar offset and funct6 (0/2/32) all pinned\n");
}

// ---------------------------------------------------------------------------------------------
// [3] LOAD-MAJOR, INCLUDING THE REAL vd == vs1 WORD.
// `vfdiv.vv v8, v9, v8` (0x82941457, PC 0x12ae4) writes the register it also divides BY. If any
// store could precede any load, that one word -- and only that one -- would read a value it had
// already overwritten.
// ---------------------------------------------------------------------------------------------
void Section3_LoadMajor()
{
	fprintf(stderr, "[3] every load precedes every store, including vd == vs1\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : MW) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, VSETVLI_E64M1, c.word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty())
				continue;
			int last_load = -1, first_store = -1, idx = 0;
			for (auto *ins : frames[0].body) {
				if (ins->GetOpcode() == Op::_vstatechunkload)
					last_load = idx;
				if (ins->GetOpcode() == Op::_vstatechunkstore && first_store < 0)
					first_store = idx;
				++idx;
			}
			CHECK(last_load >= 0 && first_store >= 0);
			CHECK(last_load < first_store);
		}
	}
	// The aliased word really loads both windows before writing either.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{512u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M1, MW_VFDIV_VV_ALIAS, e);
		auto frames = FindFrames(region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (!frames.empty()) {
			auto loads = LoadOffsets(frames[0]);
			auto stores = StoreOffsets(frames[0]);
			CHECK_EQ(loads.size(), (size_t)2);
			CHECK_EQ(stores.size(), (size_t)1);
			if (loads.size() == 2 && stores.size() == 1) {
				CHECK_EQ(loads[0], ChunkOffs(9, 0, 512)); // vs2 = v9
				CHECK_EQ(loads[1], ChunkOffs(8, 0, 512)); // vs1 = v8
				CHECK_EQ(stores[0], ChunkOffs(8, 0, 512)); // vd  = v8, aliases vs1
			}
		}
	}
	fprintf(stderr, "    0x82941457 (vd==vs1) loads v9 and v8 before storing v8\n");
}

// ---------------------------------------------------------------------------------------------
// [4] REAL EMITTED HOST BYTES.
// ---------------------------------------------------------------------------------------------
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

std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_p7kb_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel "
				      "--no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	while (fgets(buf, sizeof(buf), p)) {
		std::string s(buf);
		while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
			s.pop_back();
		lines.push_back(s);
	}
	int rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (%d)\n", rc);
		return {};
	}
	return lines;
}

// "  <addr>:\t<mnem> <ops>" -> (mnem, [operand strings]).
bool Split(std::string const &line, std::string *mnem, std::vector<std::string> *ops)
{
	size_t tab = line.find('\t');
	if (tab == std::string::npos)
		return false;
	std::string rhs = line.substr(tab + 1);
	size_t sp = rhs.find(' ');
	*mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	ops->clear();
	if (sp == std::string::npos)
		return true;
	std::string rest = rhs.substr(sp + 1);
	size_t start = 0;
	for (size_t i = 0; i <= rest.size(); ++i)
		if (i == rest.size() || rest[i] == ',') {
			std::string t = rest.substr(start, i - start);
			while (!t.empty() && t.front() == ' ')
				t.erase(t.begin());
			ops->push_back(t);
			start = i + 1;
		}
	return true;
}

// "zmm5" or "zmm5{k1}" -> (5, kmask). Rejects anything else.
bool ParseZmm(std::string t, unsigned *reg, unsigned *kmask)
{
	*kmask = 0;
	size_t br = t.find('{');
	if (br != std::string::npos) {
		size_t e = t.find('}', br);
		if (e == std::string::npos)
			return false;
		std::string m = t.substr(br + 1, e - br - 1);
		if (m.size() != 2 || m[0] != 'k' || !isdigit((unsigned char)m[1]))
			return false;
		*kmask = (unsigned)(m[1] - '0');
		t = t.substr(0, br) + t.substr(e + 1);
	}
	if (t.compare(0, 3, "zmm") != 0 || t.find_first_not_of("0123456789", 3) != std::string::npos)
		return false;
	*reg = (unsigned)strtoul(t.c_str() + 3, nullptr, 10);
	return true;
}

// "ZMMWORD PTR [r13+0x...]" / "QWORD PTR [r13+0x...]" -> displacement.
bool ParseR13(std::string const &t, i64 *disp, unsigned *bytes)
{
	size_t lb = t.find('[');
	if (lb == std::string::npos)
		return false;
	std::string sz = t.substr(0, lb);
	if (sz.find("ZMMWORD") != std::string::npos)
		*bytes = 64;
	else if (sz.find("QWORD") != std::string::npos)
		*bytes = 8;
	else if (sz.find("DWORD") != std::string::npos)
		*bytes = 4;
	else
		return false;
	std::string in = t.substr(lb + 1);
	if (in.empty() || in.back() != ']')
		return false;
	in.pop_back();
	if (in.compare(0, 3, "r13") != 0)
		return false;
	if (in.size() == 3) {
		*disp = 0;
		return true;
	}
	char sign = in[3];
	if (sign != '+' && sign != '-')
		return false;
	i64 v = (i64)strtoull(in.c_str() + 4, nullptr, 0);
	*disp = sign == '-' ? -v : v;
	return true;
}

std::vector<u8> EmitBytes(MemArena &arena, u32 setvli, u32 word, Env const &e)
{
	u32 words[2];
	Region *region = TranslatePair(arena, words, setvli, word, e);
	if (FindFrames(region).empty())
		return {};
	TestCompilerRuntime cr;
	qir::CodeSegment segment(0u, 0x1000u);
	auto span = qcg::GenerateCode(&cr, &segment, region, 0);
	return std::vector<u8>(span.begin(), span.end());
}

void Section4_EmittedBytes()
{
	fprintf(stderr, "[4] real emitted host bytes, disassembled by objdump\n");
	struct Row { char const *name; u32 word; char const *mnem; bool vf; u32 vs2, src1, vd; };
	Row const rows[] = {
	    {"vfadd.vf v8,v8,fa5", MW_VFADD_VF_A, "vaddpd", true, 8, 15, 8},
	    {"vfadd.vf v9,v9,fa4", MW_VFADD_VF_B, "vaddpd", true, 9, 14, 9},
	    {"vfsub.vf v8,v8,fa3", MW_VFSUB_VF, "vsubpd", true, 8, 13, 8},
	    {"vfdiv.vv v9,v9,v8", MW_VFDIV_VV_A, "vdivpd", false, 9, 8, 9},
	    {"vfdiv.vv v10,v10,v8", MW_VFDIV_VV_B, "vdivpd", false, 10, 8, 10},
	    {"vfdiv.vv v8,v9,v8", MW_VFDIV_VV_ALIAS, "vdivpd", false, 9, 8, 8},
	};
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = vlen / 512u;
		for (auto const &r : rows) {
			MemArena arena(1u << 20);
			Env e{vlen};
			auto code = EmitBytes(arena, VSETVLI_E64M1, r.word, e);
			CHECK(!code.empty());
			if (code.empty())
				continue;
			auto lines = Disassemble(code);
			CHECK(!lines.empty());
			if (lines.empty())
				continue;
			// Track what each zmm holds: a CPUState window (by displacement) or the
			// broadcast of the scalar. That is what turns "an operand is zmm4" into
			// "an operand is vs2", without consulting this repository's emitter.
			std::map<unsigned, i64> zmm_src; // zmm -> [r13+disp] it was loaded from
			unsigned n_alu = 0, n_bad_mnem = 0, n_narrow = 0, n_ps = 0, n_cmp = 0;
			unsigned n_order_ok = 0, n_masked = 0;
			std::string mnem;
			std::vector<std::string> ops;
			for (auto const &l : lines) {
				if (!Split(l, &mnem, &ops))
					continue;
				if (l.find("xmm") != std::string::npos ||
				    l.find("ymm") != std::string::npos)
					++n_narrow;
				unsigned zd, zs1, zs2, km;
				i64 disp;
				unsigned bytes;
				if ((mnem == "vmovdqu64" || mnem == "vpbroadcastq") && ops.size() == 2 &&
				    ParseZmm(ops[0], &zd, &km) && ParseR13(ops[1], &disp, &bytes))
					zmm_src[zd] = disp;
				else if (mnem == "vmovdqu64" && ops.size() == 2 &&
					 ParseZmm(ops[0], &zd, &km) && ParseZmm(ops[1], &zs1, &km)) {
					auto it = zmm_src.find(zs1);
					if (it != zmm_src.end())
						zmm_src[zd] = it->second; // out <- copy of vs2
				}
				if (mnem == "vaddps" || mnem == "vsubps" || mnem == "vdivps" ||
				    mnem == "vmulps")
					++n_ps;
				if (mnem == "vcmppd" || mnem == "vcmpunordpd")
					++n_cmp;
				if (mnem != r.mnem)
					continue;
				++n_alu;
				CHECK_EQ(ops.size(), (size_t)3);
				if (ops.size() != 3)
					continue;
				if (!ParseZmm(ops[0], &zd, &km) || !ParseZmm(ops[1], &zs1, &km) ||
				    !ParseZmm(ops[2], &zs2, &km))
					continue;
				unsigned kdst = 0;
				ParseZmm(ops[0], &zd, &kdst);
				if (kdst == 1)
					++n_masked;
				// THE ORDER CHECK. src1 must be the register holding vs2's window,
				// src2 the one holding vs1's window (or the scalar broadcast).
				auto s1 = zmm_src.find(zs1), s2 = zmm_src.find(zs2);
				bool ok = s1 != zmm_src.end() && s2 != zmm_src.end();
				if (ok) {
					i64 want1 = (i64)ChunkOffs(r.vs2, n_alu - 1, vlen);
					i64 want2 = r.vf
						? (i64)(ST_F_BASE + r.src1 * sizeof(u64))
						: (i64)ChunkOffs(r.src1, n_alu - 1, vlen);
					ok = s1->second == want1 && s2->second == want2;
					if (!ok)
						fprintf(stderr,
							"  FAIL %s VLEN %u: %s src1=[r13+0x%llx] "
							"src2=[r13+0x%llx], wanted 0x%llx / 0x%llx\n",
							r.name, vlen, r.mnem,
							(unsigned long long)s1->second,
							(unsigned long long)s2->second,
							(unsigned long long)want1,
							(unsigned long long)want2);
				}
				n_order_ok += ok ? 1 : 0;
			}
			// The forbidden mnemonics: any OTHER packed FP ALU op would mean the funct6
			// switch picked the wrong case.
			for (char const *bad : {"vaddpd", "vsubpd", "vdivpd", "vmulpd"}) {
				if (std::string(bad) == r.mnem)
					continue;
				unsigned c = 0;
				for (auto const &l : lines)
					if (Split(l, &mnem, &ops) && mnem == bad)
						++c;
				n_bad_mnem += c;
			}
			CHECK_EQ(n_alu, k);
			CHECK_EQ(n_order_ok, k);
			CHECK_EQ(n_masked, k);
			CHECK_EQ(n_bad_mnem, 0u);
			CHECK_EQ(n_ps, 0u);      // e64 must not emit a packed-single form
			CHECK_EQ(n_narrow, 0u);  // every lane op is 512-bit
			CHECK_EQ(n_cmp, k);      // one NaN-canonicalisation compare per chunk
			if (getenv("P7KB_DUMP")) {
				printf("\n---- %s @ VLEN %u ----\n", r.name, vlen);
				for (auto const &l : lines)
					if (l.find("zmm") != std::string::npos ||
					    l.find("bzhi") != std::string::npos)
						printf("  %s\n", l.substr(l.find('\t') + 1).c_str());
			}
			fprintf(stderr, "    VLEN %-4u %-22s -> %u x %-7s k1-masked, operands in order\n",
				vlen, r.name, k, r.mnem);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [5] FAIL-CLOSED.
// ---------------------------------------------------------------------------------------------
void Section5_FailClosed()
{
	fprintf(stderr, "[5] fail-closed matrix\n");

	// 5.1 THE `!dynamic_vtype` GATE -- the reason this section exists at all.
	// With no vsetvli in the block the route may propose a hard-coded candidate. For these three
	// forms it must NOT: the proposal there is e64,m2 while every measured PC is e64,m1, so an
	// unobserved-path admission would emit a guard that misses on every execution.
	// The split matters and getting it wrong is easy: `vfdiv.vv` and `vfsub.vf` had NO row at
	// all before P7K-B, so the unobserved path must still refuse them. `vfadd.vf` DID have one
	// (`vf && VF6_VFADD && sew == 32`), so the unobserved path already admitted it with an
	// e32,m2 candidate -- and must go on doing exactly that, unchanged. Asserting "all six
	// refused" would be asserting a regression, and did fail here before this was written down.
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : MW) {
			bool const had_a_row_before = c.f6 == 0 && c.vf; // vf VFADD, at SEW 32
			if (!had_a_row_before)
				CHECK(RefusedUnobserved(c.word, Env{vlen}));
		}
		for (u32 w : {VFDIV_VV_EVEN, VFSUB_VF_EVEN})
			CHECK(RefusedUnobserved(w, Env{vlen}));
	}
	// The pre-existing unobserved behaviour, pinned in FULL rather than just "still admitted":
	// the candidate must still be e32 (0xd1), still LMUL=2 (2 chunks per 512 bits), and the .vf
	// broadcast must still be the 4-byte one. If a P7K-B row had leaked into this path, the
	// candidate would have become e64,m2 (0xd9) with an 8-byte broadcast.
	for (u32 vlen : {512u, 1024u})
		for (u32 w : {VFADD_VF_EVEN, PRE_VFDIV_VF, PRE_VFRDIV_VF_E32}) {
			MemArena arena(1u << 20);
			u32 word = w;
			Env e{vlen};
			auto *region = TranslateWords(arena, &word, 1, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty())
				continue;
			CHECK_EQ(CountOp(region, Op::_vchunkfalu), 2u * (vlen / 512u));
			u32 const want = (w == PRE_VFDIV_VF) ? 0xd9u : 0xd1u;
			CHECK_EQ(frames[0].begin->vtype, want);
			for (auto *ins : frames[0].body)
				if (ins->GetOpcode() == Op::_vchunkfbroadcast)
					CHECK_EQ((unsigned)static_cast<InstVChunkFBroadcast *>(ins)
							 ->sew_bytes,
						 want == 0xd9u ? 8u : 4u);
		}
	fprintf(stderr, "    5.1 unobserved vtype -> helper for vfdiv.vv and vfsub.vf; the "
			"pre-existing unobserved candidates are byte-for-byte unchanged\n");

	// 5.2 SEW. The current arithmetic-family rule is shared by e32 and e64.
	for (u32 vlen : {512u, 1024u})
		for (u32 sv : {VSETVLI_E32M1, VSETVLI_E32M2}) {
			CHECK(Admitted(sv, VFDIV_VV_EVEN, Env{vlen}));
			CHECK(Admitted(sv, VFSUB_VF_EVEN, Env{vlen})); // A22: add/sub family rule admits vfsub.vf @ e32 (vfaddsub_family_route_test pins it)
			// vfadd.vf at e32 was ALREADY admitted by T7R's own row; it still is.
			CHECK(Admitted(sv, VFADD_VF_EVEN, Env{vlen}));
		}
	for (u32 vlen : {512u, 1024u})
		for (u32 sv : {VSETVLI_E16M1, VSETVLI_E8M1})
			for (u32 w : {VFDIV_VV_EVEN, VFADD_VF_EVEN, VFSUB_VF_EVEN})
				CHECK(RefusedToHelper(sv, w, Env{vlen}));
	fprintf(stderr, "    5.2 e32/e64 arithmetic admitted; e16/e8 refused\n");

	// 5.3 Tail-undisturbed and masked forms are handled by the common active-lane predicate.
	// Fractional LMUL is outside this FP route; LMUL=4 additionally requires aligned groups.
	for (u32 vlen : {512u, 1024u}) {
		for (u32 w : {VFDIV_VV_EVEN, VFADD_VF_EVEN, VFSUB_VF_EVEN}) {
			CHECK(Admitted(VSETVLI_E64M1_TU, w, Env{vlen}));
			CHECK(RefusedToHelper(VSETVLI_E64MF2, w, Env{vlen}));
		}
		CHECK(Admitted(VSETVLI_E64M1, VFDIV_VV_MASKED, Env{vlen}));
		CHECK(Admitted(VSETVLI_E64M1, VFSUB_VF_MASKED, Env{vlen}));
	}
	fprintf(stderr, "    5.3 tu / masked admitted; fractional LMUL refused\n");

	// 5.4 LMUL=2 is admitted for the new forms too (the rows say sew, not LMUL), but an odd
	// register group must still be refused there -- and admitted at m1.
	for (u32 vlen : {512u, 1024u}) {
		for (u32 w : {VFDIV_VV_EVEN, VFADD_VF_EVEN, VFSUB_VF_EVEN})
			CHECK(Admitted(VSETVLI_E64M2, w, Env{vlen}));
		// v9 is odd: illegal as the base of a two-register group.
		CHECK(RefusedToHelper(VSETVLI_E64M2, MW_VFDIV_VV_A, Env{vlen}));
		CHECK(Admitted(VSETVLI_E64M1, MW_VFDIV_VV_A, Env{vlen}));
	}
	fprintf(stderr, "    5.4 m2 admitted for even groups, refused for odd, admitted at m1\n");

	// 5.5 Reversed scalar forms use the same arithmetic-family frame; the emitter exchanges
	// operand order rather than treating them as a workload-specific exception.
	for (u32 vlen : {512u, 1024u})
		for (u32 w : {VFRDIV_VF_E64, VFRSUB_VF_E64}) {
			CHECK(Admitted(VSETVLI_E64M1, w, Env{vlen}));
			CHECK(Admitted(VSETVLI_E64M2, w, Env{vlen}));
		}
	fprintf(stderr, "    5.5 vfrdiv.vf / vfrsub.vf share the direct arithmetic route\n");

	// 5.6 VLEN outside the route's range, and the route's own gates.
	for (u32 vlen : {128u, 256u})
		for (u32 w : {VFDIV_VV_EVEN, VFADD_VF_EVEN, VFSUB_VF_EVEN})
			CHECK(RefusedToHelper(VSETVLI_E64M1, w, Env{vlen}));
	for (u32 vlen : {512u, 1024u}) {
		Env off{vlen}; off.falu = false;
		Env ver{vlen}; ver.rvv_verify = true;
		Env llvm{vlen}; llvm.aot_use_llvm = true;
		Env nod{vlen}; nod.rvv_direct = false;
		for (u32 w : {VFDIV_VV_EVEN, VFADD_VF_EVEN, VFSUB_VF_EVEN}) {
			CHECK(RefusedToHelper(VSETVLI_E64M1, w, off));
			CHECK(RefusedToHelper(VSETVLI_E64M1, w, ver));
			CHECK(RefusedToHelper(VSETVLI_E64M1, w, llvm));
			CHECK(RefusedToHelper(VSETVLI_E64M1, w, nod));
		}
	}
	fprintf(stderr, "    5.6 VLEN 128/256 / switch off / --rvv-verify / LLVM / --rvv-direct 0\n");

	// 5.7 the host probe is not vacuous: on this machine (no avx512f, no bmi2) the route must
	// refuse whenever force_emit is off, which is also why every admitted frame above exists
	// only because force_emit bypassed CPUID.
	{
		bool const x86 =
#if defined(__x86_64__) || defined(__i386__)
		    true;
#else
		    false;
#endif
		__builtin_cpu_init();
		bool const have = x86 && __builtin_cpu_supports("avx512f") &&
				  __builtin_cpu_supports("bmi2");
		for (u32 vlen : {512u, 1024u}) {
			Env nf{vlen};
			nf.force_emit = false;
			CHECK_EQ(Admitted(VSETVLI_E64M1, MW_VFDIV_VV_A, nf), have);
		}
		fprintf(stderr, "    5.7 host avx512f+bmi2 = %s -> admission without force-emit = %s\n",
			have ? "present" : "ABSENT", have ? "yes" : "no");
	}
}

// ---------------------------------------------------------------------------------------------
// [6] NOTHING THAT WAS ADMITTED BEFORE REGRESSED. There are SEVEN such rows, not six: vfadd.vv
// at e32 and at e64 are two separate admitted forms sharing one instruction word.
// ---------------------------------------------------------------------------------------------
void Section6_NoRegression()
{
	fprintf(stderr, "[6] the seven pre-P7K-B forms still admit, unchanged\n");
	struct Row { char const *name; u32 setvli; u32 word; bool vf; };
	Row const rows[] = {
	    {"vfadd.vv@e32", VSETVLI_E32M1, PRE_VFADD_VV, false},
	    {"vfadd.vv@e64", VSETVLI_E64M1, PRE_VFADD_VV, false},
	    {"vfsub.vv@e64", VSETVLI_E64M1, PRE_VFSUB_VV, false},
	    {"vfadd.vf@e32", VSETVLI_E32M1, VFADD_VF_EVEN, true},
	    {"vfmul.vf@e64", VSETVLI_E64M1, PRE_VFMUL_VF, true},
	    {"vfdiv.vf@e64", VSETVLI_E64M1, PRE_VFDIV_VF, true},
	    {"vfrdiv.vf@e32", VSETVLI_E32M1, PRE_VFRDIV_VF_E32, true},
	};
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = vlen / 512u;
		for (auto const &r : rows) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, r.setvli, r.word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty()) {
				fprintf(stderr, "    %s REGRESSED to helper\n", r.name);
				continue;
			}
			CHECK_EQ(CountOp(region, Op::_vchunkfalu), k);
			CHECK_EQ(CountFaluHelper(region), 0u);
			CHECK_EQ((unsigned)frames[0].begin->n_typed, r.vf ? 3u * k + 3u : 4u * k + 2u);
		}
	}
	fprintf(stderr, "    7/7 pre-existing rows still direct at both VLENs\n");
}

#endif // !RVV_FP_FORCE_SOFT

// ---------------------------------------------------------------------------------------------
// THE SOFTFLOAT GATE: under -DRVV_FP_FORCE_SOFT the ENTIRE floating-ALU direct route must be
// unreachable, for the reason RvvQcgTypedFmaAdmit already refuses there. fp_mode() returns
// FP_SOFT unconditionally in that build, so the helper computes every element in the exact
// integer core -- the reference that build exists to establish -- and an emitted host-FP frame is
// a different function. No runtime guard can express that: frm is still RNE and the vtype still
// matches. force-emit must not bypass it either.
//
// This binary links a copy of guest/rv32_qir.cpp rebuilt with the macro, so the predicate under
// test really is the force-soft one.
// ---------------------------------------------------------------------------------------------
struct SoftCase { u32 setvli; u32 word; };
std::vector<SoftCase> AllPositiveCases()
{
	std::vector<SoftCase> out;
	for (auto const &c : MW)
		out.push_back({VSETVLI_E64M1, c.word});
	for (u32 w : {VFDIV_VV_EVEN, VFADD_VF_EVEN, VFSUB_VF_EVEN}) {
		out.push_back({VSETVLI_E64M1, w});
		out.push_back({VSETVLI_E64M2, w});
	}
	// and every form the route admitted BEFORE P7K-B: the gate is for the whole route.
	out.push_back({VSETVLI_E32M1, PRE_VFADD_VV});
	out.push_back({VSETVLI_E64M1, PRE_VFADD_VV});
	out.push_back({VSETVLI_E64M1, PRE_VFSUB_VV});
	out.push_back({VSETVLI_E32M1, VFADD_VF_EVEN});
	out.push_back({VSETVLI_E64M1, PRE_VFMUL_VF});
	out.push_back({VSETVLI_E64M1, PRE_VFDIV_VF});
	out.push_back({VSETVLI_E32M1, PRE_VFRDIV_VF_E32});
	return out;
}

void Section_SoftGate()
{
	fprintf(stderr, "[S] -DRVV_FP_FORCE_SOFT: the WHOLE falu route must be compiled out\n");
	unsigned n = 0;
	for (u32 vlen : {512u, 1024u})
		for (auto const &c : AllPositiveCases())
			for (bool force : {false, true}) {
				Env e{vlen};
				e.force_emit = force; // force-emit must NOT bypass this
				CHECK(RefusedToHelper(c.setvli, c.word, e));
				++n;
			}
	fprintf(stderr, "    %u case(s), all 0 frames + 1 rv32_vfalu hcall\n", n);
}

#ifndef RVV_FP_FORCE_SOFT
// The control for the gate above: the SAME cases must be admitted by the ordinary build, so the
// force-soft refusal is caused by the macro and not by a case list that could never have admitted.
// It is also what proves the force-soft executable really recompiled rv32_qir.cpp with the macro
// instead of linking the archive copy.
void Section_SoftGateControl()
{
	fprintf(stderr, "[Sc] control: the same cases admit in the ordinary build\n");
	unsigned n = 0, tot = 0;
	for (u32 vlen : {512u, 1024u})
		for (auto const &c : AllPositiveCases()) {
			++tot;
			Env e{vlen};
			if (Admitted(c.setvli, c.word, e))
				++n;
			else
				CHECK(false);
		}
	fprintf(stderr, "    %u/%u admitted\n", n, tot);
}
#endif

} // namespace

int main()
{
#ifdef RVV_FP_FORCE_SOFT
	fprintf(stderr, "P7K-B residual e64 falu route test (RVV_FP_FORCE_SOFT build)\n");
	Section_SoftGate();
#else
	fprintf(stderr, "P7K-B residual e64 falu route test\n");
	Section1_Shape();
	Section2_OperandOrder();
	Section3_LoadMajor();
	Section4_EmittedBytes();
	Section5_FailClosed();
	Section6_NoRegression();
	Section_SoftGateControl();
#endif
	if (g_failures) {
		fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	fprintf(stderr, "OK\n");
	return 0;
}
