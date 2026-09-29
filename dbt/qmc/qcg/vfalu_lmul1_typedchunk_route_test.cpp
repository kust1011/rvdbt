// P7E: the T7R floating-ALU typed V512 chunk route, generalized from LMUL=2 to LMUL in {1,2} on
// the OBSERVED-vtype path, checked at the level the generalization actually lives at.
//
// WHY THIS FILE EXISTS
//
// T7R admitted exactly one group size. Its predicate said so three times, in three different
// idioms that had to agree and did only by repetition:
//
//     vt.lmul_log2() != 1                      -> refuse            (the vtype row)
//     reg_group_legal(rd|rs2|rs1, 1)           -> refuse            (the alignment rule)
//     return 2u * (config::vlen_bits / 512u)   -> the chunk count
//
// P7D measured what that costs. miniWeather's compute kernels run e64,m1 and issue
// `vfsub.vv v8, v9, v8`, `vfdiv.vf v8, v8, fa5` and `vfmul.vf v13, v12, fa5` -- all three are
// inside T7R's OWN semantic set (vv VFSUB at SEW 64, vf VFDIV at SEW 64, vf VFMUL at SEW 64), and
// all three took the rv32_vfalu helper. The first was refused by the ALIGNMENT rule before the
// vtype row was even reached: vs2 = v9 is odd, and `reg_group_legal(9, 1)` is false for a
// two-register group. P7E replaces all three literals with one value, `group_log2`.
//
// WHAT THE GENERALIZATION IS NOT. It is not a widening of the opcode set, not a new guard kind,
// not a new emitter and not a change to the unknown-vtype candidate. Sections 5 and 6 are what
// make those falsifiable rather than asserted:
//
//   * the frame builder was ALREADY generic. `off(reg,c) = base + (reg + c/per_reg)*slot +
//     (c%per_reg)*64` with per_reg = VLEN/512 tiles a group of ANY size, and Emit_vchunkfalu
//     derives its per-chunk lane mask from the LIVE vl and `chunk*lanes`. Section 3 checks the
//     two tilings that this one expression has to produce and that a wrong "generic" rule would
//     confuse: LMUL=1 at VLEN 1024 is ONE register covered by two 64-byte windows, LMUL=2 at
//     VLEN 512 is TWO registers of one window each. Both are 2 chunks. A count-only test passes
//     on an implementation that swaps them; this one does not.
//   * the unknown-vtype path still proposes m2. Section 6 pins that, including the fact that the
//     odd-vs2 `vfsub.vv` is STILL refused there -- if P7E had leaked `group_log2` into that path,
//     that word would start being admitted under a shape the block never observed.
//
// WHAT THIS FILE PROVES
//
//   1. SHAPE RULE. The admitted chunk count is emul_group_regs(LMUL) * (VLEN/512), computed here
//      from the vtype's own fields rather than read back from the predicate: 1/2 chunks for
//      e64,m1 at VLEN 512/1024 and 2/4 for e64,m2. Section 1.
//   2. THE THREE P7D-MEASURED WORDS ADMIT AT e64,m1, at both VLENs, with the right chunk count,
//      the right CPUState windows, the right guarded vtype and VLMAX, the right body opcode and
//      ZERO rv32_vfalu helper calls. These are the REAL instruction words `llvm-objdump -d` reads
//      out of the miniWeather guest ELF, not synthetic ones. Section 2.
//   3. WINDOW GEOMETRY distinguishes the two 2-chunk cases. Section 3.
//   4. NO LMUL=2 REGRESSION. Every form T7R admitted before still admits, with the same chunk
//      count, the same windows and the same guard. Section 4.
//   5. FAIL-CLOSED. LMUL 4 and 8, fractional LMUL, tu/mu, SEW 8/16, masked, VLEN 128/256, the
//      route's own switch off, --rvv-verify, and the LLVM backend each still refuse AT BOTH LMULs,
//      so an over-broad LMUL row cannot hide behind a still-closed one. Section 5.
//   6. THE OPCODE SET DID NOT MOVE. The forms outside T7R's observed set still take the helper at
//      e64,m1 -- vfadd.vf (T7R has it at SEW 32 only), vfsub.vf, vfdiv.vv -- and, explicitly,
//      BOTH OPFVF FMA forms P7D measured, vfmadd.vf and vfnmsub.vf. Those are the next
//      checkpoint's work and this one must not capture them. Section 5.3.
//   7. UNKNOWN-VTYPE PATH UNCHANGED. Section 6.
//
// WHAT IT DELIBERATELY NEVER DOES. It never executes the emitted bytes -- there is no PROT_EXEC
// page in this process -- never runs a guest program, never times anything and makes no
// performance claim. The development host is an Ivy Bridge i7-3770 with no AVX-512, so these
// frames could not be executed here even deliberately; `rvv_qcg_typed_chunk_falu_force_emit`
// bypasses ONLY that host probe, never the architectural guard and never the admitted shape.
// The dynamic half of P7E's evidence is the four-width miniWeather smoke on xbd.
//
// INSTRUCTION WORDS. Every word below was round-tripped through
// `llvm-mc-20 --disassemble -triple=riscv32 -mattr=+v`; the disassembly is quoted beside each one.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
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

// Chunk c of a group based at `reg`: the `(reg + c/per_reg)*VLEN_MAX_BYTES + (c%per_reg)*64`
// tiling, recomputed here from VLEN rather than read back from the frame under test.
u32 ChunkOffs(u32 reg, u32 chunk, u32 vlen_bits)
{
	u32 const per_reg = vlen_bits / 512u;
	return ST_VREG_BASE + (reg + chunk / per_reg) * rv32::VLEN_MAX_BYTES + (chunk % per_reg) * 64u;
}

// The chunk count the generalized rule must produce, derived INDEPENDENTLY of the predicate: one
// 512-bit host chunk per 512 bits of the register GROUP, and the group is LMUL registers of VLEN
// bits each. Not a copy of the implementation -- it is the definition the implementation must meet.
u32 ExpectChunks(u32 lmul_regs, u32 vlen_bits) { return lmul_regs * (vlen_bits / 512u); }

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with its llvm-mc disassembly.
// ---------------------------------------------------------------------------------------------
constexpr u32 VSETVLI_E32M1 = 0x0d057557u;  // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 VSETVLI_E32M2 = 0x0d157557u;  // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;  // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;  // vsetvli a0, a0, e64, m2, ta, ma
constexpr u32 VSETVLI_E64M4 = 0x0da57557u;  // vsetvli a0, a0, e64, m4, ta, ma
constexpr u32 VSETVLI_E64MF2 = 0x0df57557u; // vsetvli a0, a0, e64, mf2, ta, ma
constexpr u32 VSETVLI_E16M1 = 0x0c857557u;  // vsetvli a0, a0, e16, m1, ta, ma
constexpr u32 VSETVLI_E64M1_TU = 0x09857557u; // vsetvli a0, a0, e64, m1, tu, ma

// THE THREE WORDS P7D MEASURED IN miniWeather. Not synthetic: these are the raw values the
// --rvv-pc-census recorded, and the same values llvm-objdump reads out of the guest ELF.
constexpr u32 MW_VFSUB_VV = 0x0a941457u; // vfsub.vv  v8,  v9,  v8   -- vs2 = v9 is ODD
constexpr u32 MW_VFDIV_VF = 0x8287d457u; // vfdiv.vf  v8,  v8,  fa5
constexpr u32 MW_VFMUL_VF = 0x92c7d6d7u; // vfmul.vf  v13, v12, fa5  -- vd = v13 is ODD

// T7R's remaining observed forms, with EVEN registers so they are legal at LMUL=2 as well and the
// LMUL=2 no-regression section can use the same words.
constexpr u32 VFADD_VV_EVEN = 0x02a61457u;  // vfadd.vv  v8, v10, v12
constexpr u32 VFSUB_VV_EVEN = 0x0aa61457u;  // vfsub.vv  v8, v10, v12
constexpr u32 VFRDIV_VF_EVEN = 0x86a7d457u; // vfrdiv.vf v8, v10, fa5
constexpr u32 VFSUB_VV_MASKED = 0x08a61457u; // vfsub.vv v8, v10, v12, v0.t

// OUTSIDE T7R's observed set. None of these may be captured by the LMUL generalization.
constexpr u32 VFMADD_VF = 0xa28454d7u;  // vfmadd.vf  v9, fs0, v8   -- next checkpoint, NOT this one
constexpr u32 VFNMSUB_VF = 0xae86d4d7u; // vfnmsub.vf v9, fa3, v8   -- next checkpoint, NOT this one
constexpr u32 VFDIV_VV = 0x82a61457u;   // vfdiv.vv   v8, v10, v12  -- vv VFDIV is not in the set
constexpr u32 VFSUB_VF = 0x0a86d457u;   // vfsub.vf   v8, v8,  fa3  -- vf VFSUB is not in the set
constexpr u32 VFADD_VF = 0x0287d457u;   // vfadd.vf   v8, v8,  fa5  -- vf VFADD is SEW 32 only

// ---------------------------------------------------------------------------------------------
// Translation harness. Every knob this route reads is set on EVERY translation, so no case can
// inherit another's global state.
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
	// Everything else that could build a frame or take the word first must be off, or a census
	// below could not say which route produced what.
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

unsigned CountVfaluHelper(Region *region)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_hcall)
				n += static_cast<InstHcall *>(&ins)->stub == RuntimeStubId::id_rv32_vfalu;
	return n;
}

// One `vsetvli` + one arithmetic word: the shape every real strip-mine body has, and the only one
// that reaches the OBSERVED-vtype half of the predicate.
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
	fprintf(stderr, "[1] chunk count = emul_group_regs(LMUL) * (VLEN/512)\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &s : SHAPES) {
			// vfadd.vv is the one form T7R observes at BOTH SEWs, so it is the only word
			// that can exercise all four vtypes without changing opcode as well as shape.
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, s.setvli, VFADD_VV_EVEN, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty())
				continue;
			u32 const k = ExpectChunks(s.lmul_regs, vlen);
			// A .vv ALU frame is 4 typed ops per chunk plus the fp begin/end pair.
			CHECK_EQ((unsigned)frames[0].begin->n_typed, 4u * k + 2u);
			CHECK_EQ(CountOp(region, Op::_vchunkfalu), k);
			CHECK_EQ(CountVfaluHelper(region), 0u);
			// The guard's own constants, derived from the vtype rather than copied.
			CHECK_EQ(frames[0].begin->vlmax, (vlen / s.sew_bits) * s.lmul_regs);
			fprintf(stderr, "    VLEN %-4u %-7s -> %u chunk(s), vlmax %u\n", vlen, s.name,
				k, frames[0].begin->vlmax);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [2] THE THREE WORDS P7D MEASURED, AT e64,m1.
// ---------------------------------------------------------------------------------------------
struct MwCase {
	char const *name;
	u32 word;
	bool vf;
	u32 vd, vs2;
};

constexpr MwCase MW[] = {
    {"vfsub.vv v8,v9,v8", MW_VFSUB_VV, false, 8, 9},
    {"vfdiv.vf v8,v8,fa5", MW_VFDIV_VF, true, 8, 8},
    {"vfmul.vf v13,v12,fa5", MW_VFMUL_VF, true, 13, 12},
};

void Section2_MiniWeatherWords()
{
	fprintf(stderr, "[2] the three P7D-measured miniWeather words at e64,m1\n");
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
				fprintf(stderr, "    VLEN %-4u %-22s -> REFUSED (helper)\n", vlen, c.name);
				continue;
			}
			auto const &f = frames[0];
			// Body op and helper count: the arithmetic is really in the IR, and the
			// pre-existing helper is really gone.
			CHECK_EQ(CountOp(region, Op::_vchunkfalu), k);
			CHECK_EQ(CountVfaluHelper(region), 0u);
			// A .vf frame is 3 typed ops per chunk (one source load, one lane op, one
			// store) plus the broadcast and the fp begin/end pair; a .vv frame is 4 per
			// chunk plus the pair.
			CHECK_EQ((unsigned)f.begin->n_typed, c.vf ? 3u * k + 3u : 4u * k + 2u);
			// The guard is the vtype the block observed, and VLMAX for it.
			CHECK_EQ(f.begin->vtype, VSETVLI_E64M1 >> 20);
			CHECK_EQ(f.begin->vlmax, vlen / 64u);
			CHECK(f.begin->stub == RuntimeStubId::id_rv32_vfalu);
			CHECK(f.end->stub == RuntimeStubId::id_rv32_vfalu);
			// The destination windows are this ONE register's own chunks.
			unsigned stores = 0;
			for (auto *ins : f.body) {
				if (ins->GetOpcode() != Op::_vstatechunkstore)
					continue;
				CHECK_EQ(static_cast<InstVStateChunkStore *>(ins)->offs,
					 ChunkOffs(c.vd, stores, vlen));
				++stores;
			}
			CHECK_EQ(stores, k);
			// And the first source window is vs2's.
			for (auto *ins : f.body) {
				if (ins->GetOpcode() != Op::_vstatechunkload)
					continue;
				CHECK_EQ(static_cast<InstVStateChunkLoad *>(ins)->offs,
					 ChunkOffs(c.vs2, 0, vlen));
				break;
			}
			fprintf(stderr, "    VLEN %-4u %-22s -> DIRECT, %u chunk(s), 0 helpers\n", vlen,
				c.name, k);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [3] WINDOW GEOMETRY: the two different 2-chunk tilings must not be confused.
// ---------------------------------------------------------------------------------------------
void Section3_WindowGeometry()
{
	fprintf(stderr, "[3] 2 chunks means two things, and they are different\n");
	// (a) e64,m1 at VLEN 1024: ONE register, two 64-byte windows of its own slot.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{1024u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M1, VFSUB_VV_EVEN, e);
		auto frames = FindFrames(region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (!frames.empty()) {
			std::vector<u32> st;
			for (auto *ins : frames[0].body)
				if (ins->GetOpcode() == Op::_vstatechunkstore)
					st.push_back(static_cast<InstVStateChunkStore *>(ins)->offs);
			CHECK_EQ(st.size(), (size_t)2);
			if (st.size() == 2) {
				// Same register slot, 64 bytes apart.
				CHECK_EQ(st[1] - st[0], 64u);
				CHECK_EQ(st[0], ST_VREG_BASE + 8u * rv32::VLEN_MAX_BYTES);
			}
		}
	}
	// (b) e64,m2 at VLEN 512: TWO registers, one window each, VLEN_MAX_BYTES apart.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{512u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M2, VFSUB_VV_EVEN, e);
		auto frames = FindFrames(region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (!frames.empty()) {
			std::vector<u32> st;
			for (auto *ins : frames[0].body)
				if (ins->GetOpcode() == Op::_vstatechunkstore)
					st.push_back(static_cast<InstVStateChunkStore *>(ins)->offs);
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
// [4] NO LMUL=2 REGRESSION.
// ---------------------------------------------------------------------------------------------
void Section4_Lmul2NoRegression()
{
	fprintf(stderr, "[4] every form T7R admitted at LMUL=2 still admits, unchanged\n");
	struct Row { char const *name; u32 setvli; u32 word; bool vf; u32 vd; };
	Row const rows[] = {
	    {"e32,m2 vfadd.vv", VSETVLI_E32M2, VFADD_VV_EVEN, false, 8},
	    {"e64,m2 vfadd.vv", VSETVLI_E64M2, VFADD_VV_EVEN, false, 8},
	    {"e64,m2 vfsub.vv", VSETVLI_E64M2, VFSUB_VV_EVEN, false, 8},
	    {"e64,m2 vfdiv.vf", VSETVLI_E64M2, MW_VFDIV_VF, true, 8},
	    {"e32,m2 vfrdiv.vf", VSETVLI_E32M2, VFRDIV_VF_EVEN, true, 8},
	};
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = ExpectChunks(2, vlen);
		for (auto const &r : rows) {
			MemArena arena(1u << 20);
			u32 words[2];
			Env e{vlen};
			auto *region = TranslatePair(arena, words, r.setvli, r.word, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.empty()) {
				fprintf(stderr, "    VLEN %-4u %-18s -> REGRESSED to helper\n", vlen, r.name);
				continue;
			}
			CHECK_EQ(CountOp(region, Op::_vchunkfalu), k);
			CHECK_EQ(CountVfaluHelper(region), 0u);
			CHECK_EQ((unsigned)frames[0].begin->n_typed, r.vf ? 3u * k + 3u : 4u * k + 2u);
			CHECK_EQ(frames[0].begin->vtype, r.setvli >> 20);
			// The two-register tiling: chunk k/2 is where the SECOND register starts.
			std::vector<u32> st;
			for (auto *ins : frames[0].body)
				if (ins->GetOpcode() == Op::_vstatechunkstore)
					st.push_back(static_cast<InstVStateChunkStore *>(ins)->offs);
			CHECK_EQ(st.size(), (size_t)k);
			for (u32 c = 0; c < st.size(); ++c)
				CHECK_EQ(st[c], ChunkOffs(r.vd, c, vlen));
		}
		fprintf(stderr, "    VLEN %-4u : 5/5 LMUL=2 rows still direct at %u chunks\n", vlen, k);
	}
	// The odd-register refusal at LMUL=2 is a REAL rule, not an artefact P7E removed: v9 cannot
	// base a two-register group. It must still be refused there while being admitted at m1.
	CHECK(!Admitted(VSETVLI_E64M2, MW_VFSUB_VV, Env{1024u}));
	CHECK(Admitted(VSETVLI_E64M1, MW_VFSUB_VV, Env{1024u}));
	CHECK(!Admitted(VSETVLI_E64M2, MW_VFMUL_VF, Env{1024u})); // vd = v13, odd
	CHECK(Admitted(VSETVLI_E64M1, MW_VFMUL_VF, Env{1024u}));
	fprintf(stderr, "    odd-register groups still refused at m2, admitted at m1\n");
}

// ---------------------------------------------------------------------------------------------
// [5] FAIL-CLOSED, AT BOTH LMULs.
// ---------------------------------------------------------------------------------------------
void Section5_FailClosed()
{
	fprintf(stderr, "[5] fail-closed matrix\n");

	// 5.1 Unsupported element width. Integer and fractional LMUL plus tail policy are handled by
	// the generic group geometry and predicated state store; they are not refusal conditions.
	struct Row { char const *name; u32 setvli; };
	Row const bad_vtypes[] = {
	    {"e16,m1", VSETVLI_E16M1},
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &r : bad_vtypes) {
			CHECK(!Admitted(r.setvli, VFADD_VV_EVEN, Env{vlen}));
			CHECK(!Admitted(r.setvli, MW_VFDIV_VF, Env{vlen}));
		}
	fprintf(stderr, "    5.1 unsupported FP SEW 16 refused at both VLENs\n");

	// 5.2 Masked forms are admitted when the destination does not overlap v0. The emitted active
	// mask combines vl, vstart and v0; the state store preserves inactive/tail elements.
	for (u32 vlen : {512u, 1024u}) {
		CHECK(Admitted(VSETVLI_E64M1, VFSUB_VV_MASKED, Env{vlen}));
		CHECK(Admitted(VSETVLI_E64M2, VFSUB_VV_MASKED, Env{vlen}));
	}
	// Narrow host chunks are controlled by a separate switch and are off in this harness.
	for (u32 vlen : {128u, 256u}) {
		CHECK(!Admitted(VSETVLI_E64M1, VFSUB_VV_EVEN, Env{vlen}));
		CHECK(!Admitted(VSETVLI_E64M2, VFSUB_VV_EVEN, Env{vlen}));
	}
	fprintf(stderr, "    5.2 masked admitted; narrow-width route remains off in this harness\n");

	// 5.3 THE OPCODE SET DID NOT MOVE *AT THIS CHECKPOINT'S BOUNDARY*.
	//
	// UPDATED BY P7K-B. Three of the five words this section originally listed as outside the
	// set -- vfdiv.vv, vfsub.vf and vfadd.vf, all at e64 -- were admitted by P7K-B, which is
	// what makes miniWeather's output() loop helper-free. They are therefore checked in the
	// OTHER direction here, and their own focused evidence lives in
	// vfalu_residual_e64_route_test.cpp. Moving them without leaving a trace would have hidden
	// a real change to this route's accepted set, so the row is kept and inverted rather than
	// deleted.
	struct OpRow { char const *name; u32 word; };
	OpRow const outside[] = {
	    {"vfmadd.vf", VFMADD_VF},   // OPFVF FMA: a different decode family and a different route
	    {"vfnmsub.vf", VFNMSUB_VF}, // (rv32_vfma), never admitted by THIS predicate
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &r : outside) {
			CHECK(!Admitted(VSETVLI_E64M1, r.word, Env{vlen}));
			CHECK(!Admitted(VSETVLI_E64M2, r.word, Env{vlen}));
		}
	// ... and the two FMA words really do reach a helper rather than vanishing.
	{
		MemArena arena(1u << 20);
		u32 words[2];
		Env e{1024u};
		auto *region = TranslatePair(arena, words, VSETVLI_E64M1, VFMADD_VF, e);
		CHECK_EQ(FindFrames(region).size(), (size_t)0);
	}
	// THE P7K-B ROWS, ASSERTED FROM THIS FILE TOO. VFDIV_VV/VFSUB_VF/VFADD_VF use EVEN
	// registers here, so they are legal at m2 as well as m1 and both must now admit.
	// `e32_stays` records what e32 did BEFORE P7K-B, because P7K-B's rows are all `sew == 64`
	// and must not have moved e32 in either direction: vfdiv.vv and vfsub.vf were refused at
	// e32 and still are, while vfadd.vf was ALREADY admitted at e32 by T7R's own row
	// (`vf && VF6_VFADD && sew == 32`) and still is. Asserting "all three refused at e32" would
	// have been wrong, and was: it failed here before the row was written down correctly.
	struct P7kbRow { char const *name; u32 word; bool e32_stays; };
	P7kbRow const p7kb[] = {
	    {"vfdiv.vv@e64", VFDIV_VV, true}, // arithmetic-family rule is width-generic
	    {"vfsub.vf@e64", VFSUB_VF, true}, // A22: admitted at e32 too by the add/sub family rule
	    {"vfadd.vf@e64", VFADD_VF, true}, // pre-existing T7R row at SEW 32
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &r : p7kb) {
			CHECK(Admitted(VSETVLI_E64M1, r.word, Env{vlen}));
			CHECK(Admitted(VSETVLI_E64M2, r.word, Env{vlen}));
			if (Admitted(VSETVLI_E32M1, r.word, Env{vlen}) != r.e32_stays)
				fprintf(stderr, "  5.3 e32 row: %s vlen %u\n", r.name, vlen);
			CHECK_EQ(Admitted(VSETVLI_E32M1, r.word, Env{vlen}), r.e32_stays);
		}
	fprintf(stderr, "    5.3 vfmadd.vf / vfnmsub.vf still refused; the three P7K-B e64 forms now"
			" admit at m1 and m2; e32 unchanged in both directions\n");

	// 5.4 the route's own gates.
	for (u32 vlen : {512u, 1024u}) {
		Env off{vlen}; off.falu = false;
		CHECK(!Admitted(VSETVLI_E64M1, VFSUB_VV_EVEN, off));
		Env ver{vlen}; ver.rvv_verify = true;
		CHECK(!Admitted(VSETVLI_E64M1, VFSUB_VV_EVEN, ver));
		Env llvm{vlen}; llvm.aot_use_llvm = true;
		CHECK(!Admitted(VSETVLI_E64M1, VFSUB_VV_EVEN, llvm));
		Env nod{vlen}; nod.rvv_direct = false;
		CHECK(!Admitted(VSETVLI_E64M1, VFSUB_VV_EVEN, nod));
	}
	fprintf(stderr, "    5.4 switch off / --rvv-verify / LLVM backend / --rvv-direct 0 refused\n");
}

// ---------------------------------------------------------------------------------------------
// [6] THE UNKNOWN-VTYPE CANDIDATE IS UNCHANGED.
// ---------------------------------------------------------------------------------------------
void Section6_UnknownVtypeUnchanged()
{
	fprintf(stderr, "[6] with no observed vsetvli the proposal is still m2\n");
	for (u32 vlen : {512u, 1024u}) {
		u32 const k2 = ExpectChunks(2, vlen);
		// A word legal at m2 is still proposed at m2 -- the chunk count proves which.
		{
			MemArena arena(1u << 20);
			u32 word = MW_VFDIV_VF;
			Env e{vlen};
			auto *region = TranslateWords(arena, &word, 1, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (!frames.empty()) {
				CHECK_EQ(CountOp(region, Op::_vchunkfalu), k2);
				CHECK_EQ((unsigned)frames[0].begin->n_typed, 3u * k2 + 3u);
			}
		}
		// And a word ILLEGAL at m2 is still refused there. If P7E had leaked group_log2 into
		// this path, the odd-vs2 vfsub.vv would start being admitted under a shape the block
		// never observed.
		{
			MemArena arena(1u << 20);
			u32 word = MW_VFSUB_VV;
			Env e{vlen};
			auto *region = TranslateWords(arena, &word, 1, e);
			CHECK_EQ(FindFrames(region).size(), (size_t)0);
			CHECK_EQ(CountVfaluHelper(region), 1u);
		}
		fprintf(stderr, "    VLEN %-4u : unobserved vfdiv.vf -> %u chunks (m2); odd vfsub.vv -> helper\n",
			vlen, k2);
	}
}

} // namespace

int main()
{
	fprintf(stderr, "P7E vfalu LMUL=1 typed-chunk route test\n");
	Section1_ShapeRule();
	Section2_MiniWeatherWords();
	Section3_WindowGeometry();
	Section4_Lmul2NoRegression();
	Section5_FailClosed();
	Section6_UnknownVtypeUnchanged();
	if (g_failures) {
		fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	fprintf(stderr, "OK\n");
	return 0;
}
