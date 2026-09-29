// P7G: the live-RVV-configuration entry hint, checked at the level it lives at -- the translator.
//
// WHAT THE HINT IS, AND WHAT IT REPLACES
//
// A typed RVV frame is specialized for one vtype and proves it with an emitted guard. When a block
// contains no `vsetvli`, the translator has no observation to specialize on, and the pre-existing
// rule (C3.1f) proposes ONE HARDCODED candidate shape and lets the guard prove it. That is correct
// -- a wrong candidate costs a guard miss, never a wrong answer -- but it is a guess, and P7D/P7E
// measured what the guess costs on a real application: miniWeather runs e64,m1 and the falu route's
// candidate is m2, so 11 of every 12 executions missed.
//
// P7G changes ONLY THE SOURCE OF THE CANDIDATE. Execute()'s JIT arm runs with the guest paused at
// the ip about to be compiled, so `state->vec.vtype` is the configuration every instruction BEFORE
// this block left behind -- including a `vsetvli` in a loop preheader that belongs to a DIFFERENT
// translation block. That raw word travels on CompilerJob as an optional hint and seeds
// `rvv_bb_vtype` once, at the region-entry ip range.
//
// EVERYTHING DOWNSTREAM IS UNTOUCHED, and this file's job is to make that falsifiable rather than
// asserted: same admission predicates, same emitted guard, same ordered fallback, same helpers,
// same TBlock/cache/link/invalidation rules (the hint is never stored anywhere).
//
// WHAT THIS FILE PROVES
//
//   [1] NO HINT => IDENTICAL QIR. The 4-argument CompilerJob (every AOT driver and every other
//       focused test), an explicitly invalid hint, and every hint `vtype_supported` rejects --
//       vill, a reserved bit, the all-ones sentinel, fractional LMUL -- all produce byte-identical
//       opcode sequences. This is the AOT/no-regression invariant AND the requirement
//       "vill/reserved/unsupported == no hint", checked as one identity instead of two claims.
//   [1b] A LEGAL VTYPE alone does not establish operand legality. For e64,m4, aligned operands
//       form a guarded frame; an operand misaligned for LMUL=4 still takes the helper.
//   [2] AN e64,m1 HINT SPECIALIZES A BLOCK THAT HAS NO vsetvli. Two independent signals, so the
//       check cannot pass on a route that merely changed its chunk count: `vfdiv.vf` (legal at
//       both LMULs) must become a 1-chunk frame guarded on 0xd8 instead of a 2-chunk frame guarded
//       on 0xd9; and `vfsub.vv v8,v9,v8` -- REFUSED at m2 because vs2=v9 cannot base a
//       two-register group -- must go from helper to frame.
//   [3] AN IN-BLOCK vsetvli/vsetivli OVERRIDES THE HINT. Observation always wins. Checked for
//       both the immediate-AVL and the immediate-AVL-and-immediate-vtype encodings, and in the
//       direction that matters: an e64,m2 observation must beat an e64,m1 hint.
//   [4] A REGISTER-FORM `vsetvl` DISCARDS THE HINT. After it the configuration is not known at
//       translation time at all, so a following falu must fall back to the unknown-vtype
//       candidate. This is the one path where reusing the entry snapshot would be WRONG rather
//       than merely unprofitable, and section 4 is the only check that can catch it.
//   [5] THE HINT IS NOT STORED, and it does not leak past the region entry. Translating the same
//       ip twice with different hints yields different code (no memoization), and in a
//       multi-ip-range region -- the AOT region shape -- only the entry range is seeded.
//
// WHAT IT DELIBERATELY NEVER DOES. It never emits or executes host bytes, never runs a guest
// program, never times anything and makes no performance claim. It inspects constructed QIR only,
// so it runs on this development host (Ivy Bridge i7-3770, no AVX-512);
// `rvv_qcg_typed_chunk_falu_force_emit` bypasses ONLY the host feature probe, never the
// architectural guard and never the admitted shape.
//
// INSTRUCTION WORDS. Every word below was round-tripped through
// `llvm-mc-20 --disassemble -triple=riscv32 -mattr=+v`; the disassembly is quoted beside each one.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <string>
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

#define CHECK_STREQ(a, b)                                                                                    \
	do {                                                                                                 \
		auto const &_a = (a);                                                                        \
		auto const &_b = (b);                                                                        \
		if (_a != _b) {                                                                              \
			fprintf(stderr, "  FAIL %s:%d: %s != %s\n    lhs: %s\n    rhs: %s\n", __FILE__,       \
				__LINE__, #a, #b, _a.c_str(), _b.c_str());                                   \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Instruction words.
// ---------------------------------------------------------------------------------------------
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;   // vsetvli  a0, a0, e64, m1, ta, ma
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;   // vsetvli  a0, a0, e64, m2, ta, ma
constexpr u32 VSETIVLI_E64M2 = 0xcd947557u;  // vsetivli a0, 8,  e64, m2, ta, ma
constexpr u32 VSETVL_REG = 0x80b57557u;      // vsetvl   a0, a0, a1      <- vtype from a GPR
// The two P7D-measured miniWeather words this route admits.
constexpr u32 VFDIV_VF = 0x8287d457u;        // vfdiv.vf v8, v8, fa5     <- legal at m1 AND m2
constexpr u32 VFSUB_VV_ODD = 0x0a941457u;    // vfsub.vv v8, v9, v8      <- vs2=v9: m1 only
constexpr u32 NOP = 0x00000013u;             // addi zero, zero, 0

// The vtype immediates, as the guest encodes them (bits [30:20] of a vsetvli).
constexpr u32 VT_E64M1 = 0xd8u;
constexpr u32 VT_E64M2 = 0xd9u;
constexpr u32 VT_E64M4 = 0xdau;
constexpr u32 VT_E64MF2 = 0xdfu; // fractional LMUL
constexpr u32 VT_VILL = 0x80000000u | VT_E64M1; // vill bit set
constexpr u32 VT_RESERVED = 0x00000100u | VT_E64M1; // a reserved bit [30:8] set

// ---------------------------------------------------------------------------------------------
// Harness. Every knob this route reads is set on EVERY translation, so no case inherits another's
// global state -- the failure that would otherwise make a fail-closed row pass.
// ---------------------------------------------------------------------------------------------
struct Env {
	u32 vlen_bits = 512;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
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
	config::rvv_lane_census = false;
	config::rvv_lowering = 1;
}

// The 5-argument form: a job that carries a hint.
Region *TranslateHinted(MemArena &arena, u32 const *words, unsigned n, Env const &e, RvvEntryHint hint)
{
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges), hint);
	return CompilerGenRegionIR(&arena, job);
}

// The 4-argument form: EXACTLY the call every AOT driver and every other focused test makes. It is
// used on purpose rather than passing `RvvEntryHint{}`, because the property under test in [1] is
// that the DEFAULTED parameter path is unchanged, not that an explicit default behaves like itself.
Region *TranslateNoHintArg(MemArena &arena, u32 const *words, unsigned n, Env const &e)
{
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
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

// A total, order-preserving fingerprint of the constructed IR. Opcode identity alone would let a
// change in the guarded vtype or the chunk count pass, so every typed frame's guard constants and
// every chunk window are folded in too.
std::string Fingerprint(Region *region)
{
	std::string s;
	char buf[128];
	for (auto &bb : region->GetBlocks()) {
		snprintf(buf, sizeof(buf), "bb(%08x){", bb.entry_ip);
		s += buf;
		for (auto &ins : bb.ilist) {
			snprintf(buf, sizeof(buf), "%u", (unsigned)ins.GetOpcode());
			s += buf;
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: {
				auto *b = static_cast<InstRVVTypedChunkBegin *>(&ins);
				snprintf(buf, sizeof(buf), "[vt=%x,vlmax=%u,n=%u,gk=%u]", b->vtype, b->vlmax,
					 (unsigned)b->n_typed, (unsigned)b->guard_kind);
				s += buf;
				break;
			}
			case Op::_vstatechunkload:
				snprintf(buf, sizeof(buf), "[l=%u]",
					 static_cast<InstVStateChunkLoad *>(&ins)->offs);
				s += buf;
				break;
			case Op::_vstatechunkstore:
				snprintf(buf, sizeof(buf), "[s=%u]",
					 static_cast<InstVStateChunkStore *>(&ins)->offs);
				s += buf;
				break;
			case Op::_hcall:
				snprintf(buf, sizeof(buf), "[h=%u]",
					 (unsigned)static_cast<InstHcall *>(&ins)->stub);
				s += buf;
				break;
			default:
				break;
			}
			s += ",";
		}
		s += "}";
	}
	return s;
}

// What a frame is specialized for, in one line, so a failure says WHICH shape was produced.
struct Shape {
	bool framed = false;
	u32 vtype = 0;
	u32 vlmax = 0;
	unsigned chunks = 0;
	unsigned helpers = 0;
};

Shape ShapeOf(Region *region)
{
	Shape sh;
	auto frames = FindFrames(region);
	sh.helpers = CountVfaluHelper(region);
	sh.chunks = CountOp(region, Op::_vchunkfalu);
	if (!frames.empty()) {
		sh.framed = true;
		sh.vtype = frames[0].begin->vtype;
		sh.vlmax = frames[0].begin->vlmax;
	}
	return sh;
}

void PrintShape(char const *label, Shape const &s)
{
	if (s.framed)
		fprintf(stderr, "    %-46s frame vtype=0x%02x vlmax=%-3u chunks=%u helpers=%u\n", label,
			s.vtype, s.vlmax, s.chunks, s.helpers);
	else
		fprintf(stderr, "    %-46s NO FRAME (helpers=%u)\n", label, s.helpers);
}

// ---------------------------------------------------------------------------------------------
// [1] NO HINT => IDENTICAL QIR, and unsupported hint == no hint.
// ---------------------------------------------------------------------------------------------
void Section1_NoHintUnchanged()
{
	fprintf(stderr, "[1] no hint / invalid hint / unsupported hint all produce IDENTICAL QIR\n");
	// Several block shapes, so the identity is not established on one accidental case: a bare
	// falu, a falu behind an observed vsetvli, and a falu behind a register-form vsetvl.
	struct Case { char const *name; u32 words[4]; unsigned n; };
	Case const cases[] = {
	    {"bare vfdiv.vf", {VFDIV_VF, 0, 0, 0}, 1},
	    {"bare vfsub.vv(odd vs2)", {VFSUB_VV_ODD, 0, 0, 0}, 1},
	    {"vsetvli e64,m1 + vfdiv.vf", {VSETVLI_E64M1, VFDIV_VF, 0, 0}, 2},
	    {"vsetvl(reg) + vfdiv.vf", {VSETVL_REG, VFDIV_VF, 0, 0}, 2},
	    {"nop + vfdiv.vf", {NOP, VFDIV_VF, 0, 0}, 2},
	};
	// Hints that MUST behave exactly like no hint at all, because each one fails
	// `vtype_supported` (or the validity bit) and is therefore never seeded.
	//   * valid=false  -- the AOT/test path.
	//   * vill         -- VTYPE_RESERVED_MASK is 0xffffff00, i.e. it COVERS bit 31, so
	//                     `reserved_clear()` already rejects a set vill bit.
	//   * reserved     -- any bit in [30:8].
	//   * ~0u          -- vsew_field() == 7 > 3, so `sew_valid()` rejects it. This is also the
	//                     sentinel `rvv_bb_vtype` uses for "unknown", so a hint carrying it must
	//                     not be mistaken for a real observation.
	//   * e64,mf2      -- SEW <= LMUL*ELEN fails (6 > -1+6), the spec's fractional-LMUL rule.
	// e64,m4 is deliberately NOT in this list: it is a LEGAL vtype, so it IS seeded, and what it
	// does then is section 1b's subject.
	struct Bad { char const *name; RvvEntryHint hint; };
	Bad const bad[] = {
	    {"invalid(valid=false)", RvvEntryHint{VT_E64M1, false}},
	    {"vill", RvvEntryHint{VT_VILL, true}},
	    {"reserved bit set", RvvEntryHint{VT_RESERVED, true}},
	    {"e64,mf2 (fractional LMUL)", RvvEntryHint{VT_E64MF2, true}},
	    {"all-ones (the unknown sentinel)", RvvEntryHint{~0u, true}},
	};
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : cases) {
			MemArena a0(1u << 20);
			std::string const base = Fingerprint(TranslateNoHintArg(a0, c.words, c.n, Env{vlen}));
			for (auto const &b : bad) {
				MemArena a(1u << 20);
				std::string const got =
				    Fingerprint(TranslateHinted(a, c.words, c.n, Env{vlen}, b.hint));
				if (got != base)
					fprintf(stderr, "    VLEN %u  case '%s'  hint '%s'\n", vlen, c.name,
						b.name);
				CHECK_STREQ(got, base);
			}
		}
		fprintf(stderr, "    VLEN %-4u : %u block shapes x %u must-be-inert hints, all identical\n",
			vlen, (unsigned)(sizeof(cases) / sizeof(cases[0])),
			(unsigned)(sizeof(bad) / sizeof(bad[0])));
	}
}

// ---------------------------------------------------------------------------------------------
// [1b] A LEGAL HINT USES THE CURRENT ROUTE'S OPERAND-GROUP ADMISSION.
//
// This is the one case where a present hint does NOT reproduce the previous code, and it is
// `vtype_supported` accepts e64,m4, so the hinted route uses that observed shape. `vfdiv.vf`
// has aligned groups and admits a typed frame; `vfsub.vv` names v9 as a source, which cannot
// base an LMUL=4 group, and still takes the helper.
//
// Without the hint the block uses the hardcoded m2 candidate. The observed m4 shape can instead
// produce a matching guard for an admitted instruction or skip a guaranteed miss when illegal
// register grouping forces a helper.
//
// This section is also the honest record of a P7F under-specification: that design said an ABSENT
// hint reproduces today's behaviour (it does, see [1]); it did not say what a legal-but-unadmitted
// hint should do. This is the answer, and it was found by this test rather than assumed.
// ---------------------------------------------------------------------------------------------
void Section1b_LegalButUnadmittedHintTakesHelper()
{
	fprintf(stderr, "[1b] e64,m4 hint: aligned operand framed, illegal group helper\n");
	for (u32 vlen : {512u, 1024u}) {
		for (u32 w : {VFDIV_VF, VFSUB_VV_ODD}) {
			MemArena a0(1u << 20), a1(1u << 20);
			Shape const no = ShapeOf(TranslateNoHintArg(a0, &w, 1, Env{vlen}));
			Shape const m4 =
			    ShapeOf(TranslateHinted(a1, &w, 1, Env{vlen}, RvvEntryHint{VT_E64M4, true}));
			char label[96];
			snprintf(label, sizeof(label), "VLEN %u  raw=%08x  hint e64,m4", vlen, w);
			PrintShape(label, m4);
			if (w == VFDIV_VF) {
				CHECK(m4.framed);
				CHECK_EQ(m4.vtype, VT_E64M4);
				CHECK_EQ(m4.vlmax, vlen / 16u);
				CHECK_EQ(m4.chunks, vlen / 128u);
				CHECK_EQ(m4.helpers, 0u);
			} else {
				CHECK(!m4.framed);
				CHECK_EQ(m4.chunks, 0u);
				CHECK_EQ(m4.helpers, 1u);
			}
			// And it must genuinely DIFFER from the no-hint arm for vfdiv.vf, which is the
			// word the no-hint path does frame. If these were equal the section would be
			// vacuous.
			if (w == VFDIV_VF) {
				CHECK(no.framed);
				CHECK_EQ(no.vtype, VT_E64M2);
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [2] AN e64,m1 HINT SPECIALIZES A BLOCK WITH NO vsetvli.
// ---------------------------------------------------------------------------------------------
void Section2_HintSpecializes()
{
	fprintf(stderr, "[2] e64,m1 hint on a falu block that contains no vsetvli\n");
	for (u32 vlen : {512u, 1024u}) {
		u32 const k_m1 = vlen / 512u;      // emul_group_regs(1) * VLEN/512
		u32 const k_m2 = 2u * (vlen / 512u);
		// (a) vfdiv.vf is legal at BOTH LMULs, so the chunk count and the guarded vtype -- not
		//     admitted-vs-refused -- are what distinguish the two candidates.
		{
			u32 w = VFDIV_VF;
			MemArena a0(1u << 20), a1(1u << 20);
			Shape const no = ShapeOf(TranslateNoHintArg(a0, &w, 1, Env{vlen}));
			Shape const hi = ShapeOf(
			    TranslateHinted(a1, &w, 1, Env{vlen}, RvvEntryHint{VT_E64M1, true}));
			fprintf(stderr, "  VLEN %u  vfdiv.vf\n", vlen);
			PrintShape("no hint (C3.1f candidate: m2)", no);
			PrintShape("hint e64,m1", hi);
			// Baseline: the pre-existing hardcoded candidate is m2.
			CHECK(no.framed);
			CHECK_EQ(no.vtype, VT_E64M2);
			CHECK_EQ(no.chunks, k_m2);
			// With the hint: m1, and the guard constant follows the vtype rather than a
			// separate table -- VLMAX(e64,m1) = VLEN/64.
			CHECK(hi.framed);
			CHECK_EQ(hi.vtype, VT_E64M1);
			CHECK_EQ(hi.chunks, k_m1);
			CHECK_EQ(hi.vlmax, vlen / 64u);
			CHECK_EQ(hi.helpers, 0u);
		}
		// (b) vfsub.vv v8,v9,v8 is REFUSED at m2 (vs2=v9 cannot base a two-register group) and
		//     admitted at m1. So this word turns the same question into a binary signal that a
		//     chunk-count bug cannot fake.
		{
			u32 w = VFSUB_VV_ODD;
			MemArena a0(1u << 20), a1(1u << 20);
			Shape const no = ShapeOf(TranslateNoHintArg(a0, &w, 1, Env{vlen}));
			Shape const hi = ShapeOf(
			    TranslateHinted(a1, &w, 1, Env{vlen}, RvvEntryHint{VT_E64M1, true}));
			fprintf(stderr, "  VLEN %u  vfsub.vv v8,v9,v8 (odd vs2)\n", vlen);
			PrintShape("no hint", no);
			PrintShape("hint e64,m1", hi);
			CHECK(!no.framed);
			CHECK_EQ(no.helpers, 1u);
			CHECK(hi.framed);
			CHECK_EQ(hi.vtype, VT_E64M1);
			CHECK_EQ(hi.chunks, k_m1);
			CHECK_EQ(hi.helpers, 0u);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [3] AN IN-BLOCK vsetvli / vsetivli OVERRIDES THE HINT.
// ---------------------------------------------------------------------------------------------
void Section3_ObservationWins()
{
	fprintf(stderr, "[3] an observed vsetvli/vsetivli beats the hint\n");
	struct Row { char const *name; u32 setter; };
	Row const rows[] = {
	    {"vsetvli e64,m2", VSETVLI_E64M2},
	    {"vsetivli e64,m2", VSETIVLI_E64M2},
	};
	for (u32 vlen : {512u, 1024u}) {
		u32 const k_m2 = 2u * (vlen / 512u);
		for (auto const &r : rows) {
			u32 words[2] = {r.setter, VFDIV_VF};
			MemArena a(1u << 20);
			// The hint says m1; the block says m2. m2 must win.
			Shape const s = ShapeOf(
			    TranslateHinted(a, words, 2, Env{vlen}, RvvEntryHint{VT_E64M1, true}));
			char label[96];
			snprintf(label, sizeof(label), "VLEN %u  %s + vfdiv.vf, hint=m1", vlen, r.name);
			PrintShape(label, s);
			CHECK(s.framed);
			CHECK_EQ(s.vtype, VT_E64M2);
			CHECK_EQ(s.chunks, k_m2);
			CHECK_EQ(s.vlmax, 2u * (vlen / 64u));
		}
		// And the symmetric direction, so this is not passing because m2 is simply always
		// produced: an observed e64,m1 with an e64,m2 hint must give m1.
		{
			u32 words[2] = {VSETVLI_E64M1, VFDIV_VF};
			MemArena a(1u << 20);
			Shape const s = ShapeOf(
			    TranslateHinted(a, words, 2, Env{vlen}, RvvEntryHint{VT_E64M2, true}));
			CHECK(s.framed);
			CHECK_EQ(s.vtype, VT_E64M1);
			CHECK_EQ(s.chunks, vlen / 512u);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [4] A REGISTER-FORM vsetvl DISCARDS THE HINT.
// ---------------------------------------------------------------------------------------------
void Section4_VsetvlClearsHint()
{
	fprintf(stderr, "[4] after a register-form vsetvl the hint must NOT be reused\n");
	for (u32 vlen : {512u, 1024u}) {
		u32 const k_m2 = 2u * (vlen / 512u);
		// `vsetvl a0, a0, a1` takes its vtype from a GPR, so after it the configuration is
		// unknown at translation time. Continuing to describe the block with the ENTRY
		// snapshot would emit a guard for a width the guest may no longer be in -- the one
		// place where reusing the hint is WRONG rather than merely unprofitable.
		u32 words[2] = {VSETVL_REG, VFDIV_VF};
		MemArena a(1u << 20);
		Shape const s =
		    ShapeOf(TranslateHinted(a, words, 2, Env{vlen}, RvvEntryHint{VT_E64M1, true}));
		char label[96];
		snprintf(label, sizeof(label), "VLEN %u  vsetvl(reg) + vfdiv.vf, hint=m1", vlen);
		PrintShape(label, s);
		// It must be the unknown-vtype candidate (m2), NOT the hint's m1.
		CHECK(s.framed);
		CHECK_EQ(s.vtype, VT_E64M2);
		CHECK_EQ(s.chunks, k_m2);
		// The same word with the hint but WITHOUT the vsetvl gives m1 -- so the check above
		// is about the vsetvl and not about the hint failing to arrive at all.
		{
			u32 w = VFDIV_VF;
			MemArena b(1u << 20);
			Shape const ok =
			    ShapeOf(TranslateHinted(b, &w, 1, Env{vlen}, RvvEntryHint{VT_E64M1, true}));
			CHECK(ok.framed);
			CHECK_EQ(ok.vtype, VT_E64M1);
		}
		// And the falu BEFORE a vsetvl still gets the hint: the discard is positional, not a
		// whole-block veto.
		{
			u32 w3[3] = {VFDIV_VF, VSETVL_REG, VFDIV_VF};
			MemArena c(1u << 20);
			auto *region = TranslateHinted(c, w3, 3, Env{vlen}, RvvEntryHint{VT_E64M1, true});
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)2);
			if (frames.size() == 2) {
				CHECK_EQ(frames[0].begin->vtype, VT_E64M1); // before the vsetvl
				CHECK_EQ(frames[1].begin->vtype, VT_E64M2); // after it: candidate
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [5] THE HINT IS NOT STORED, AND IT DOES NOT LEAK PAST THE REGION ENTRY.
// ---------------------------------------------------------------------------------------------
void Section5_NotStoredNotLeaked()
{
	fprintf(stderr, "[5] the hint is consumed, not remembered\n");
	// (a) No memoization: the SAME ip translated twice with different hints must give different
	//     code. If anything cached the first translation or the first hint, these would match.
	{
		u32 w = VFDIV_VF;
		MemArena a1(1u << 20), a2(1u << 20), a3(1u << 20);
		std::string const m1 =
		    Fingerprint(TranslateHinted(a1, &w, 1, Env{512}, RvvEntryHint{VT_E64M1, true}));
		std::string const m2 =
		    Fingerprint(TranslateHinted(a2, &w, 1, Env{512}, RvvEntryHint{VT_E64M2, true}));
		std::string const again =
		    Fingerprint(TranslateHinted(a3, &w, 1, Env{512}, RvvEntryHint{VT_E64M1, true}));
		CHECK(m1 != m2);      // the hint really selected the shape
		CHECK_STREQ(again, m1); // and it is reproducible, so the difference is the hint
	}
	// (b) Region entry only. A two-ip-range region is the AOT region shape; the hint describes
	//     the state at the ip the JIT loop was paused at, which is range 0's entry, so range 1
	//     must be translated as if there were no hint.
	{
		ApplyEnv(Env{512});
		u32 words[4] = {VFDIV_VF, NOP, VFDIV_VF, NOP};
		MemArena a(1u << 20);
		CompilerJob::IpRangesSet ranges = {{0u, 8u}, {8u, 16u}};
		CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges),
				RvvEntryHint{VT_E64M1, true});
		auto *region = CompilerGenRegionIR(&a, job);
		auto frames = FindFrames(region);
		CHECK_EQ(frames.size(), (size_t)2);
		if (frames.size() == 2) {
			fprintf(stderr, "    two-range region: entry frame vtype=0x%02x, second=0x%02x\n",
				frames[0].begin->vtype, frames[1].begin->vtype);
			CHECK_EQ(frames[0].begin->vtype, VT_E64M1); // seeded
			CHECK_EQ(frames[1].begin->vtype, VT_E64M2); // NOT seeded: candidate
		}
	}
}

} // namespace

int main()
{
	fprintf(stderr, "P7G live-vtype entry hint test\n");
	Section1_NoHintUnchanged();
	Section1b_LegalButUnadmittedHintTakesHelper();
	Section2_HintSpecializes();
	Section3_ObservationWins();
	Section4_VsetvlClearsHint();
	Section5_NotStoredNotLeaked();
	if (g_failures) {
		fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	fprintf(stderr, "OK\n");
	return 0;
}
