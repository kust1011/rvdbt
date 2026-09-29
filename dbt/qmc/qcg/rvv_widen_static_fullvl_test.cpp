// W21: THE STATIC FULL-VL PROOF THAT LETS THE WIDENING ROUTE EMIT NO ACTIVE-VL LADDER AT ALL.
//
// S1-3W (`--rvv-qcg-active-vl-widen-bound`) precedes each host chunk c >= 1 of a widening integer
// frame with one `vchunkactive` bound. W20 measured what that ladder costs when it never fires:
// exactly 2 retired instructions per fall-through bound and 3.358 cycles (97.07 % CI [1.39, 4.16])
// on the accepted CABAC ROI. W21 adds ONE conjunct to the route's `bounded` decision -- the
// block-scoped VL knowledge `rvv_bb_vl` proves `vl == VLMAX` for this frame's own vtype -- and this
// file is where that conjunct's rules are pinned.
//
// WHAT THE PROOF IS AND IS NOT RESPONSIBLE FOR, because it decides what a failure here means.
// Omitting a bound is never a VALUE-level error: the chunk a bound would have skipped is already an
// architectural no-op at that vl (empty body mask, masked store writes no byte), which is exactly
// why the OFF arm -- a widening frame with no ladder at all -- is correct at every vl and every
// vstart, and is the arm every accepted round measured against. So a WRONG "provably full" answer
// cannot produce a wrong result; it silently forfeits the S1-3W benefit on a frame that really does
// run at a partial vl. Every check below is therefore aimed at that specific failure, in both
// directions: a ladder that should have gone and did not, and a ladder that should have stayed and
// went.
//
// WHAT THIS FILE CAN AND CANNOT OBSERVE. Same envelope as the S1-3W suite: the frames are AVX-512
// bodies, this suite is built and run on a host without AVX-512, `--rvv-qcg-typed-chunk-force-emit`
// bypasses exactly the host-feature admission row, nothing here is ever executed, and no assertion
// below is a value-level one. What is discharged here is everything the QIR and the emitted bytes
// can settle about WHICH shape the route chose.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [F1] SAME-TB FULL VL. `vsetvli rd!=x0, x0, vtypei` is the architecture's "request VLMAX" form,
//        so the block's vl is VLMAX exactly. Over e8/e16/e32 x m1/m2/m4 x VLEN 512/1024 the ON frame
//        must then carry ZERO bounds, `n_typed == chunks`, `finish` on exactly the last chunk,
//        `frame_clears_vstart == false` -- and its emitted bytes must be BYTE-IDENTICAL to the OFF
//        arm's. Byte equality is the strong form of the requirement: the proof must produce the arm
//        that already exists, not a third shape. Failure = the proof did not fire, or it fired and
//        changed something else as well.
//
//   [F2] KEEP-VL RETYPING -- the shape the accepted FFmpeg `ff_h264_init_cabac_states` loop body is
//        written in, and the one W18's own AVL tracker got wrong. `vsetvli t0, x0, e8, m2` followed
//        by `vsetvli x0, x0, e32, m8` and `vsetvli x0, x0, e16, m4` keeps vl across two retypes that
//        leave VLMAX unchanged, so the widening op still runs at full VL. Zero bounds, byte-identical
//        to OFF. Failure = the W18 provenance bug (knowledge dropped at the retype), which would cost
//        the whole candidate population.
//
//   [F3]/[F4] THE KEEP-VL RESERVED BOUNDARY IS ON VLMAX. RVV 1.0 section 6.2: the `vsetvli x0, x0`
//        form "can only be used when VLMAX and hence vl is not actually changed by the new SEW/LMUL
//        ratio. Use of the instruction with a new SEW/LMUL ratio that would result in a change of
//        VLMAX is reserved." Three cases, and the middle one is the whole point: F3, the ratio
//        changes and the old vl no longer fits (reserved on any reading, ladder retained); F4a, the
//        ratio is PRESERVED at a different value from F2's (carried, ladder removed, bytes equal to
//        OFF); and F4b, the ratio changes while the old vl STILL FITS -- reserved by the SPEC, and
//        accepted by this tree's own HANDLER(vsetvli), whose test is the weaker "would the retained
//        vl have to change". F4b asserts both halves of that disagreement (VLMAX really changes, the
//        old vl really fits) and requires the ladder to survive. Failure of F4b = a tracker built on
//        the interpreter's condition rather than the architecture's, which is exactly the defect the
//        W21 audit found in the first implementation. Fixing the interpreter is a separate,
//        pre-existing question and is not in this checkpoint.
//
//   [F5] DYNAMIC AVL. `vsetvli rd, rs1!=x0` takes its AVL from a runtime GPR. Unknown, ladder
//        retained, and the frame must be byte-identical to the pre-W21 ON arm. Failure = the proof
//        treats "the AVL register exists" as "the AVL is VLMAX".
//
//   [F6] CONSTANT-SHORT AVL, AND THE `min` THAT MAKES IT FULL ANYWAY. `vsetivli`'s AVL is its 5-bit
//        immediate ALWAYS (no x0 rule, no keep-VL form), so vl = min(uimm5, VLMAX) is known exactly:
//        `vsetivli t0, 4` is a SHORT vl and keeps its ladder, while `vsetivli t0, 31` at a shape whose
//        VLMAX is 16 is FULL and loses it. Failure = dropping the `min` in either direction.
//
//   [F7] THE TB BOUNDARY, IN ONE PROGRAM. The same five words translated as ONE ip range and as TWO,
//        cut exactly where rvdbt cuts the accepted CABAC loop -- between the `vsetvli rd, x0` and the
//        keep-VL retype that heads the loop body. One range: both frames proved, zero bounds. Two
//        ranges: the first frame proved, the SECOND keeps its full ladder, because a block is
//        reachable from the translation cache by every guest transfer to its entry ip and a fact about
//        one predecessor is not a fact about the block. Failure = knowledge that crossed a boundary it
//        cannot cross, or that was seeded from the preceding instruction word or from an entry hint.
//
//   [F8] ILLEGAL / RESERVED VTYPE FAILS CLOSED. A vtype that is reserved, or unsupported at this VLEN
//        (`e64, mf8`), installs vill and zeroes vl; the knowledge must become unknown and must not be
//        recoverable by a later keep-VL retype. Failure = a proof built on a vtype the guest never
//        actually ran in.
//
//   [F9] MASKING IS IRRELEVANT TO THE PROOF, AND THAT IS DELIBERATE. The vm = 0 form of a
//        proved-full-VL frame also loses its ladder, and its bytes equal the vm = 0 OFF arm's. The
//        ladder's test is on vl and never on the mask; `vl == VLMAX` empties the TAIL set at any
//        vstart, so no bound could fire regardless of v0. Failure = a proof that started reading the
//        mask, which is the S1-3W design's one forbidden move.
//
//  [F10] LEGAL OVERLAP. The `.wv` wide-`vs2` form and the top-aligned narrow source both keep their
//        exact per-chunk work multiset and chunk ORDER when the ladder is removed, and the removal is
//        byte-identical to OFF. A widening destination group is twice its source group, so this is
//        the watchdog for "delete the ladder, reorder nothing".
//
//  [F11] THE TWO INVALIDATORS. `vsetvl` (vtype from a GPR, so VLMAX is unknown and therefore so is
//        min(AVL, VLMAX)) and `vleff` (the only non-OPCFG architectural writer of vl in RVV 1.0) each
//        turn a proved block into an unknown one. Each is checked as an A/B against the identical
//        program without that one instruction, so the check cannot pass because the program stopped
//        routing. Failure = a vl written at run time that the translator kept claiming to know.
//
//  [F12] THE MUTATION TABLE. Seven ways to make the proof unsound, each with a witness program from
//        the checks above, the sound bound count, and the count the mutant would produce. The test
//        asserts BOTH that the production route gives the sound count AND that the mutant count
//        differs from it -- so a mutation row that could not distinguish anything fails as loudly as
//        a wrong answer. That assertion is what forced one row OUT of the table: under the corrected
//        keep-VL rule VLMAX is invariant while a vl value is live, so "fullness measured against the
//        CREATING vtype" is no longer a distinguishable mutation and was removed rather than kept.
//
//  [F13] THE METHOD WAS NOT BROADENED. In a block whose vl is PROVED full, the equal-width integer
//        route (S1-3A, `--rvv-qcg-active-vl-int-bound`) keeps its complete ladder, and its bytes are
//        identical with the widening switch off and on. W21 is scoped to the widening family in this
//        checkpoint; this is where that stays true.
//
//  [F14] DEFAULT-OFF IS STILL INERT. With `--rvv-qcg-active-vl-widen-bound` clear, every program in
//        this file emits zero bounds and the same bytes it emitted before W21 existed -- which is the
//        same statement as "the OFF arm of every byte-equality check above is a fixed point".

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <tuple>
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
		long long _a = (long long)(a);                                                       \
		long long _b = (long long)(b);                                                       \
		if (_a != _b) {                                                                      \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, _a, _b);                                           \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Guest encodings, built from the field layout (rv32_decode.h) rather than copied as magic words.

constexpr u32 SEW8 = 0u, SEW16 = 1u, SEW32 = 2u, SEW64 = 3u;
// vlmul field encodings: 000=m1 001=m2 010=m4 011=m8, 101=mf8 110=mf4 111=mf2.
constexpr u32 M1 = 0u, M2 = 1u, M4 = 2u, M8 = 3u, MF8 = 5u;
// vtypei = vma | vta | vsew | vlmul. 0xc0 sets vma and vta, exactly as every accepted suite does.
constexpr u32 VType10(u32 vsew, u32 vlmul) { return 0xc0u | (vsew << 3) | vlmul; }
// A vtypei whose vsew field is a RESERVED encoding (0b101): vtype_supported must refuse it.
constexpr u32 VTypeReserved() { return 0xc0u | (5u << 3) | M1; }

// vsetvli rd, rs1, vtypei -- bit 31 clear. rs1 == x0 && rd != x0 requests VLMAX; rs1 == x0 &&
// rd == x0 is the keep-VL retype; rs1 != x0 takes the AVL from x[rs1].
constexpr u32 Vsetvli(u32 rd, u32 rs1, u32 vtypei)
{
	return (vtypei << 20) | (rs1 << 15) | (7u << 12) | (rd << 7) | 0x57u;
}
// vsetivli rd, uimm5, vtypei -- bits 31:30 = 11, vtypei is 10 bits.
constexpr u32 Vsetivli(u32 rd, u32 uimm5, u32 vtypei)
{
	return (0b11u << 30) | (vtypei << 20) | (uimm5 << 15) | (7u << 12) | (rd << 7) | 0x57u;
}
// vsetvl rd, rs1, rs2 -- funct7 = 1000000, vtype from x[rs2].
constexpr u32 Vsetvl(u32 rd, u32 rs1, u32 rs2)
{
	return (0b1000000u << 25) | (rs2 << 20) | (rs1 << 15) | (7u << 12) | (rd << 7) | 0x57u;
}
// vle8ff.v vd, (rs1) -- unit-stride fault-only-first: nf=0, mew=0, mop=00, lumop=10000, width=000.
constexpr u32 Vle8ff(u32 vd, u32 rs1)
{
	return (1u << 25) | (0b10000u << 20) | (rs1 << 15) | (0u << 12) | (vd << 7) | 0x07u;
}
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OPMVV = 2u, OPMVX = 6u, OPIVV = 0u;
constexpr u32 F6_VWADD = 0b110001u, F6_VWADD_W = 0b110101u, F6_VWMUL = 0b111011u,
	      F6_VWMACC = 0b111101u, F6_VWADDU = 0b110000u, F6_VADD = 0u;

constexpr int LmulLog2(u32 vlmul) { return (vlmul & 0b100u) ? (int)vlmul - 8 : (int)vlmul; }

// The route's own chunk geometry, re-derived here from VLEN and LMUL rather than read back from the
// node the translator built: gb = (VLEN/8) << (lmul_log2 + 1), chunk width min(VLEN/8, 64).
unsigned Chunks(u32 vlen, u32 vlmul)
{
	u32 const rb = vlen / 8, bytes = rb < 64u ? rb : 64u;
	int const wl = LmulLog2(vlmul) + 1;
	u32 const gb = wl >= 0 ? (rb << wl) : (rb >> (-wl));
	return (gb + bytes - 1) / bytes;
}
// VLMAX = (VLEN / SEW) * 2^lmul_log2, the identity every expectation in this file is derived from.
u32 Vlmax(u32 vlen, u32 vsew, u32 vlmul)
{
	u32 const sew = 8u << vsew;
	int const lm = LmulLog2(vlmul);
	u32 const base = vlen / sew;
	return lm >= 0 ? (base << lm) : (base >> (-lm));
}

// ---------------------------------------------------------------------------------------------
// One process-wide code buffer, refilled with 0xcc on every allocation, for the same two reasons the
// S1-3W suite states: an emitted region can embed the address of its own buffer, so two translations
// into two heap allocations would differ in bytes that have nothing to do with the switch; and
// asmjit's section-alignment slack would otherwise be stale bytes from a previous emission.
alignas(4096) u8 g_code_buf[1u << 21];
constexpr u8 kPadByte = 0xcc;

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("widen static full-vl test: emitted region exceeds the code buffer");
		memset(g_code_buf, kPadByte, sizeof(g_code_buf));
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 512;
	bool widen_bound = false;
	bool int_bound = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_active_vl_widen_bound = e.widen_bound;
	config::rvv_qcg_active_vl_int_bound = e.int_bound;
	config::rvv_qcg_typed_chunk_falu = false;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_partial_vl = false;
	// The direct-state `vsetvli` lowering is deliberately OFF: W21's tracking is recorded by the
	// TRANSLATOR before any admission decision, so it must not depend on which lowering the
	// config instruction itself takes. [F1] is re-run with it ON to prove exactly that.
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
}

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

// One ip range covering the whole program, which is what the JIT always builds ("the ip range size
// is always 1 for JIT", qmc/compile.cpp).
void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

// The SAME program cut into two ip ranges at word `cut`, which is what [F7] needs: the second range
// is a block whose entry the guest can also reach by a branch, and its translation must not inherit
// anything from the first.
void TranslateSplit(Built &b, std::vector<u32> const &words, u32 cut, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, cut * 4u}, {cut * 4u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	size_t const full = b.code.size();
	while (!b.code.empty() && b.code.back() == kPadByte)
		b.code.pop_back();
	CHECK(full - b.code.size() < 8u);
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

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

// Frames that contain at least one widening chunk node, in emission order.
std::vector<Frame> WidenFrames(Region *region)
{
	std::vector<Frame> out;
	for (auto &f : FindFrames(region))
		if (CountOp(f, Op::_vchunkwiden))
			out.push_back(f);
	return out;
}

unsigned WidenBounds(Region *region)
{
	unsigned n = 0;
	for (auto &f : WidenFrames(region))
		n += CountOp(f, Op::_vchunkactive);
	return n;
}

std::vector<int> OpcodeStream(Region *r)
{
	std::vector<int> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			out.push_back((int)ins.GetOpcode());
	return out;
}

// Everything a widening chunk node says about WHICH bytes it touches and under WHICH predicate,
// in emission order. `finish` is EXCLUDED on purpose: moving that one write is the S1-3W
// transformation, and [F10] must be able to compare a bounded frame against an unbounded one.
using Work = std::tuple<int, u32, u32, u32, int, int, u32, int, int, int, int, int, int>;

std::vector<Work> ChunkWork(Frame const &f)
{
	std::vector<Work> out;
	for (auto *i : f.body) {
		if (i->GetOpcode() != Op::_vchunkwiden)
			continue;
		auto *n = static_cast<InstVChunkWiden *>(i);
		out.push_back({(int)n->op, n->rd, n->rs2, n->rs1, (int)n->sew, (int)n->bytes, n->base,
			       (int)n->scalar, (int)n->zero, (int)n->wide2, (int)n->sign2,
			       (int)n->sign1, (int)n->masked});
	}
	return out;
}

std::vector<u32> BoundLadder(Frame const &f)
{
	std::vector<u32> out;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkactive)
			out.push_back(static_cast<InstVChunkActive *>(i)->element_base);
	return out;
}

// ---------------------------------------------------------------------------------------------
// The two shapes every check below is stated in terms of.
//
//   UNBOUNDED  the arm the OFF switch has always produced: `chunks` chunk nodes, no bound,
//              `finish` on exactly the last one, `frame_clears_vstart` clear, n_typed == chunks.
//   BOUNDED    the S1-3W ON arm: `chunks - 1` bounds at the destination-lane ladder, each
//              IMMEDIATELY before its own chunk, no `finish` anywhere, `frame_clears_vstart` set,
//              n_typed == 2*chunks - 1.
//
// A W21 "provably full" answer must produce the FIRST of these -- not a third shape -- which is why
// both are written out in full and why every [F1]/[F2] case also compares emitted BYTES.

void ExpectUnbounded(Frame const &f, unsigned chunks, char const *what)
{
	if (CountOp(f, Op::_vchunkactive) != 0u)
		fprintf(stderr, "  (%s: expected no ladder)\n", what);
	CHECK_EQ(CountOp(f, Op::_vchunkactive), 0u);
	CHECK_EQ(CountOp(f, Op::_vchunkwiden), chunks);
	CHECK_EQ(f.begin->n_typed, chunks);
	CHECK(!f.end->frame_clears_vstart);
	unsigned finished = 0, idx = 0, last_finish = 0;
	for (auto *i : f.body) {
		if (i->GetOpcode() != Op::_vchunkwiden)
			continue;
		if (static_cast<InstVChunkWiden *>(i)->finish) {
			++finished;
			last_finish = idx;
		}
		++idx;
	}
	CHECK_EQ(finished, 1u);
	CHECK_EQ(last_finish, chunks - 1u);
}

void ExpectBounded(Frame const &f, unsigned chunks, u32 lanes_per_chunk, char const *what)
{
	if (CountOp(f, Op::_vchunkactive) != chunks - 1u)
		fprintf(stderr, "  (%s: expected the full ladder)\n", what);
	CHECK_EQ(CountOp(f, Op::_vchunkactive), chunks - 1u);
	CHECK_EQ(CountOp(f, Op::_vchunkwiden), chunks);
	CHECK_EQ(f.begin->n_typed, 2u * chunks - 1u);
	CHECK(f.end->frame_clears_vstart);
	// The ladder is the destination-lane one: bound c carries chunk index c and element_base
	// c * lanes. Re-derived from VLEN/SEW here, never read back from the node.
	auto const ladder = BoundLadder(f);
	CHECK_EQ(ladder.size(), chunks - 1u);
	for (unsigned c = 1; c < chunks && c - 1 < ladder.size(); ++c)
		CHECK_EQ(ladder[c - 1], c * lanes_per_chunk);
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkwiden)
			CHECK(!static_cast<InstVChunkWiden *>(i)->finish);
}

// The destination-lane count of one host chunk: chunk_bytes / (2 * SEW/8).
u32 LanesPerChunk(u32 vlen, u32 vsew)
{
	u32 const rb = vlen / 8, bytes = rb < 64u ? rb : 64u;
	return bytes / (2u * (1u << vsew));
}

// ---------------------------------------------------------------------------------------------
// The widening instruction every check uses, and its register triple.
//
// vd = v16, vs2 = v8, vs1 = v12 is legal at m1/m2/m4 for the .vv forms (the destination group is
// 2*LMUL and lies above both sources with no overlap at any of the three), and vs1 = v24 keeps the
// .wv form legal, whose vs2 is itself a 2*LMUL group.
constexpr u32 VD = 16u, VS2 = 8u, VS1 = 12u, VS1_WIDE = 24u;

u32 WAdd(u32 vm = 1) { return MakeOpV(F6_VWADD, vm, VS2, VS1, VD, OPMVV); }
u32 WAddW(u32 vm = 1) { return MakeOpV(F6_VWADD_W, vm, VS2, VS1_WIDE, VD, OPMVV); }

// ---------------------------------------------------------------------------------------------
// [F1] same-TB full VL: `vsetvli rd != x0, x0, vtypei`.

struct Shape {
	u32 vsew, vlmul;
	char const *name;
};
constexpr Shape kShapes[] = {
    {SEW8, M1, "e8,m1"},   {SEW8, M2, "e8,m2"},   {SEW8, M4, "e8,m4"},
    {SEW16, M1, "e16,m1"}, {SEW16, M2, "e16,m2"}, {SEW16, M4, "e16,m4"},
    {SEW32, M1, "e32,m1"}, {SEW32, M2, "e32,m2"}, {SEW32, M4, "e32,m4"},
};

void TestSameTbFullVl()
{
	printf("[F1] same-TB full VL (vsetvli rd, x0)\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned proved = 0;
		for (auto const &s : kShapes) {
			std::vector<u32> const words = {Vsetvli(5, 0, VType10(s.vsew, s.vlmul)), WAdd()};
			Built off, on;
			Translate(off, words, Env{vlen, /*widen_bound=*/false});
			Translate(on, words, Env{vlen, /*widen_bound=*/true});
			auto fo = WidenFrames(off.region), fn = WidenFrames(on.region);
			CHECK_EQ(fo.size(), 1u);
			CHECK_EQ(fn.size(), 1u);
			if (fo.size() != 1 || fn.size() != 1)
				continue;
			unsigned const chunks = Chunks(vlen, s.vlmul);
			ExpectUnbounded(fo[0], chunks, s.name);
			ExpectUnbounded(fn[0], chunks, s.name);
			Emit(off);
			Emit(on);
			CHECK(!off.code.empty());
			CHECK(off.code == on.code);
			CHECK(OpcodeStream(off.region) == OpcodeStream(on.region));
			++proved;
		}
		CHECK_EQ(proved, sizeof(kShapes) / sizeof(kShapes[0]));
		printf("  ok   VLEN %-4u %u/%zu shapes proved full; ON is byte-identical to OFF\n", vlen,
		       proved, sizeof(kShapes) / sizeof(kShapes[0]));
	}
	// The tracking is recorded by TRANSLATOR(vsetvli) BEFORE any admission decision, so it must
	// not depend on whether the config instruction takes the direct-state lowering or the helper.
	for (u32 vlen : {512u, 1024u}) {
		std::vector<u32> const words = {Vsetvli(5, 0, VType10(SEW16, M2)), WAdd()};
		Built helper_arm, direct_arm;
		Translate(helper_arm, words, Env{vlen, true});
		ApplyEnv(Env{vlen, true});
		config::rvv_qcg_direct_setvl = true;
		direct_arm.words = words;
		{
			CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
			CompilerJob job(nullptr, (uptr)direct_arm.words.data(),
					CodeSegment(0u, 0x1000u), std::move(ranges));
			direct_arm.region = CompilerGenRegionIR(&direct_arm.arena, job);
		}
		CHECK_EQ(WidenBounds(helper_arm.region), 0u);
		CHECK_EQ(WidenBounds(direct_arm.region), 0u);
	}
	printf("  ok   the proof is independent of the vsetvli lowering (helper and direct-state\n"
	       "       both give zero bounds)\n");
}

// ---------------------------------------------------------------------------------------------
// [F2] keep-VL retyping -- the accepted ff_h264_init_cabac_states loop-body shape.

void TestKeepVlRetype()
{
	printf("[F2] keep-VL retyping across VLMAX-preserving vtypes\n");
	// The guest's own chain, byte for byte in field terms. Every retype in it keeps the SEW/LMUL
	// RATIO at 4 (8/2, 32/8, 16/4), so VLMAX is unchanged and the form is the one RVV 1.0
	// section 6.2 permits -- which is what makes the value carryable at all:
	//   vsetvli t5, zero, e8,  m2   -> vl = VLMAX(e8,m2)  = VLEN/4
	//   vsetvli zero, zero, e32, m8 -> VLMAX(e32,m8) = VLEN/4, UNCHANGED, retained
	//   vsetvli zero, zero, e16, m4 -> VLMAX(e16,m4) = VLEN/4, UNCHANGED, retained
	//   vwadd.wv                    -> runs at vl == VLMAX(e16,m4)
	std::vector<u32> const words = {
	    Vsetvli(30, 0, VType10(SEW8, M2)), Vsetvli(0, 0, VType10(SEW32, M8)),
	    Vsetvli(0, 0, VType10(SEW16, M4)), WAddW()};
	for (u32 vlen : {512u, 1024u}) {
		// The three VLMAXes really are equal; if this ever stops holding the check below is
		// testing something else.
		CHECK_EQ(Vlmax(vlen, SEW8, M2), Vlmax(vlen, SEW32, M8));
		CHECK_EQ(Vlmax(vlen, SEW8, M2), Vlmax(vlen, SEW16, M4));
		Built off, on;
		Translate(off, words, Env{vlen, false});
		Translate(on, words, Env{vlen, true});
		auto fo = WidenFrames(off.region), fn = WidenFrames(on.region);
		CHECK_EQ(fo.size(), 1u);
		CHECK_EQ(fn.size(), 1u);
		if (fo.size() != 1 || fn.size() != 1)
			continue;
		unsigned const chunks = Chunks(vlen, M4);
		// The accepted CABAC geometry: 8 chunks (7 bounds) at VLEN 512, 16 (15) at 1024.
		CHECK_EQ(chunks, vlen == 512u ? 8u : 16u);
		ExpectUnbounded(fn[0], chunks, "e16,m4 after two keep-VL retypes");
		Emit(off);
		Emit(on);
		CHECK(!off.code.empty());
		CHECK(off.code == on.code);
		printf("  ok   VLEN %-4u vl carried through 2 retypes; %u would-be bounds removed;\n"
		       "       ON byte-identical to OFF\n",
		       vlen, chunks - 1u);
	}
}

// ---------------------------------------------------------------------------------------------
// [F3]/[F4] THE KEEP-VL RESERVED BOUNDARY, AND IT IS ON VLMAX, NOT ON "DOES THE OLD vl STILL FIT".
//
// RVV 1.0 section 6.2: "When rs1=x0 and rd=x0 ... This form can only be used when VLMAX and hence vl
// is not actually changed by the new SEW/LMUL ratio. USE OF THE INSTRUCTION WITH A NEW SEW/LMUL
// RATIO THAT WOULD RESULT IN A CHANGE OF VLMAX IS RESERVED. Use of the instruction is also reserved
// if vill is set."
//
// So there are exactly two cases to separate, and the ONE that matters is the second:
//
//   F3  the ratio changes and the old vl no longer fits   -- reserved on any reading
//   F4b the ratio changes and the old vl STILL FITS       -- reserved by the SPEC, and accepted by
//       this tree's own HANDLER(vsetvli), whose test is the weaker `vl != min(vl, VLMAX_new)`
//
// F4b is the case a first draft of W21 got wrong: it carried the value through, on the strength of
// the interpreter's condition rather than the architecture's. The tracker now follows the spec,
// which is the CONSERVATIVE direction -- an encoding the interpreter would accept and the spec
// reserves makes the tracker drop its knowledge and keep the ladder, so the tracker can lose an
// optimisation on such a guest but can never claim fullness for one. Fixing the interpreter's own
// condition is a separate, pre-existing semantics question and is NOT in this checkpoint.
//
// F4a is the matching POSITIVE: a ratio-PRESERVING retype at a different ratio from F2's, which must
// still carry the value and still produce the unbounded frame.

void TestKeepVlBoundaries()
{
	printf("[F3] reserved keep-VL retype: the ratio changes AND the old vl no longer fits\n");
	//   vsetvli t0, zero, e8, m2  -> vl = VLMAX(e8,m2)  = VLEN/4, ratio 4
	//   vsetvli zero, zero, e16,m2 -> ratio 8, VLMAX = VLEN/8 < vl  => RESERVED
	std::vector<u32> const words = {Vsetvli(5, 0, VType10(SEW8, M2)),
					Vsetvli(0, 0, VType10(SEW16, M2)), WAdd()};
	for (u32 vlen : {512u, 1024u}) {
		CHECK(Vlmax(vlen, SEW16, M2) < Vlmax(vlen, SEW8, M2));
		Built on;
		Translate(on, words, Env{vlen, true});
		auto f = WidenFrames(on.region);
		CHECK_EQ(f.size(), 1u);
		if (f.size() != 1)
			continue;
		unsigned const chunks = Chunks(vlen, M2);
		ExpectBounded(f[0], chunks, LanesPerChunk(vlen, SEW16), "reserved retype (vl would change)");
		printf("  ok   VLEN %-4u ladder retained (%u bounds)\n", vlen, chunks - 1u);
	}

	printf("[F4a] POSITIVE: a ratio-PRESERVING retype carries the value (ratio 16, not F2's 4)\n");
	//   vsetvli t0, zero, e16, m1 -> vl = VLMAX(e16,m1) = VLEN/16, ratio 16
	//   vsetvli zero, zero, e32,m2 -> ratio 16 UNCHANGED, VLMAX = VLEN/16: carried, still full
	//   vwadd.vv at e32,m2         -> vl == VLMAX: no ladder
	std::vector<u32> const same_ratio = {Vsetvli(5, 0, VType10(SEW16, M1)),
					     Vsetvli(0, 0, VType10(SEW32, M2)), WAdd()};
	for (u32 vlen : {512u, 1024u}) {
		CHECK_EQ(Vlmax(vlen, SEW16, M1), Vlmax(vlen, SEW32, M2));
		Built off, on;
		Translate(off, same_ratio, Env{vlen, false});
		Translate(on, same_ratio, Env{vlen, true});
		auto fo = WidenFrames(off.region), fn = WidenFrames(on.region);
		CHECK_EQ(fo.size(), 1u);
		CHECK_EQ(fn.size(), 1u);
		if (fo.size() != 1 || fn.size() != 1)
			continue;
		unsigned const chunks = Chunks(vlen, M2);
		ExpectUnbounded(fn[0], chunks, "ratio-preserving retype at ratio 16");
		Emit(off);
		Emit(on);
		CHECK(!off.code.empty());
		CHECK(off.code == on.code);
		printf("  ok   VLEN %-4u VLMAX %u unchanged across e16,m1 -> e32,m2: %u bounds removed,\n"
		       "       ON byte-identical to OFF\n",
		       vlen, Vlmax(vlen, SEW16, M1), chunks - 1u);
	}

	printf("[F4b] NEGATIVE: the ratio changes but the old vl still fits -- RESERVED by the spec,\n"
	       "      accepted by this tree's own interpreter; the tracker follows the spec\n");
	//   vsetvli t0, zero, e16, m2 -> vl = VLMAX(e16,m2) = VLEN/8, ratio 8
	//   vsetvli zero, zero, e8, m2 -> ratio 4, VLMAX = VLEN/4: CHANGED => RESERVED,
	//                                 even though VLEN/8 <= VLEN/4 so the value would survive.
	std::vector<u32> const wider = {Vsetvli(5, 0, VType10(SEW16, M2)),
					Vsetvli(0, 0, VType10(SEW8, M2)), WAdd()};
	for (u32 vlen : {512u, 1024u}) {
		u32 const old_vl = Vlmax(vlen, SEW16, M2), new_vlmax = Vlmax(vlen, SEW8, M2);
		// The two halves of "this is the case the two readings disagree about", asserted rather
		// than described: VLMAX really does change, and the old vl really does still fit -- so
		// HANDLER(vsetvli)'s `vl != min(vl, VLMAX_new)` test would NOT fire here.
		CHECK(new_vlmax != old_vl);
		CHECK(old_vl <= new_vlmax);
		Built on;
		Translate(on, wider, Env{vlen, true});
		auto f = WidenFrames(on.region);
		CHECK_EQ(f.size(), 1u);
		if (f.size() != 1)
			continue;
		unsigned const chunks = Chunks(vlen, M2);
		// Knowledge dropped => UNKNOWN => the full ladder, NOT "vl is half of VLMAX".
		ExpectBounded(f[0], chunks, LanesPerChunk(vlen, SEW8), "reserved retype (VLMAX changed)");
		printf("  ok   VLEN %-4u old vl %u fits the new VLMAX %u, but the ratio changed:\n"
		       "       knowledge dropped, ladder retained (%u bounds)\n",
		       vlen, old_vl, new_vlmax, chunks - 1u);
	}
}

// ---------------------------------------------------------------------------------------------
// [F5] dynamic AVL and [F6] constant AVL.

void TestAvlForms()
{
	printf("[F5] dynamic AVL (vsetvli rd, rs1 != x0)\n");
	for (u32 vlen : {512u, 1024u}) {
		std::vector<u32> const words = {Vsetvli(5, 10, VType10(SEW16, M2)), WAdd()};
		Built on;
		Translate(on, words, Env{vlen, true});
		auto f = WidenFrames(on.region);
		CHECK_EQ(f.size(), 1u);
		if (f.size() != 1)
			continue;
		unsigned const chunks = Chunks(vlen, M2);
		ExpectBounded(f[0], chunks, LanesPerChunk(vlen, SEW16), "dynamic AVL");
		printf("  ok   VLEN %-4u ladder retained (%u bounds)\n", vlen, chunks - 1u);
	}

	printf("[F6] vsetivli: constant-short AVL keeps the ladder, min(uimm5, VLMAX) can still be full\n");
	for (u32 vlen : {512u, 1024u}) {
		// uimm5 = 4, VLMAX(e16,m2) >= 64: a SHORT constant vl. Knowledge, not fullness.
		std::vector<u32> const short_avl = {Vsetivli(5, 4, VType10(SEW16, M2)), WAdd()};
		Built sb;
		Translate(sb, short_avl, Env{vlen, true});
		auto fs = WidenFrames(sb.region);
		CHECK_EQ(fs.size(), 1u);
		unsigned const chunks_m2 = Chunks(vlen, M2);
		CHECK(4u < Vlmax(vlen, SEW16, M2));
		if (fs.size() == 1)
			ExpectBounded(fs[0], chunks_m2, LanesPerChunk(vlen, SEW16), "vsetivli 4");
		// uimm5 = 31 at a shape whose VLMAX is <= 31: min() clamps to VLMAX, so it IS full.
		// VLMAX(e32,m1) = 16 at VLEN 512 and 32 at VLEN 1024, so the 512 arm is full and the
		// 1024 arm is short -- one immediate, two answers, which is the whole point of `min`.
		std::vector<u32> const clamped = {Vsetivli(5, 31, VType10(SEW32, M1)), WAdd()};
		Built cb;
		Translate(cb, clamped, Env{vlen, true});
		auto fc = WidenFrames(cb.region);
		CHECK_EQ(fc.size(), 1u);
		unsigned const chunks_m1 = Chunks(vlen, M1);
		bool const full = 31u >= Vlmax(vlen, SEW32, M1);
		CHECK_EQ(full, vlen == 512u);
		if (fc.size() == 1) {
			if (full)
				ExpectUnbounded(fc[0], chunks_m1, "vsetivli 31 clamped to VLMAX");
			else
				ExpectBounded(fc[0], chunks_m1, LanesPerChunk(vlen, SEW32),
					      "vsetivli 31 below VLMAX");
		}
		printf("  ok   VLEN %-4u uimm5=4 -> %u bounds; uimm5=31 vs VLMAX %u -> %u bounds\n", vlen,
		       chunks_m2 - 1u, Vlmax(vlen, SEW32, M1), full ? 0u : chunks_m1 - 1u);
	}
}

// ---------------------------------------------------------------------------------------------
// [F7] the TB boundary, cut where rvdbt cuts the accepted CABAC loop.

void TestTbBoundary()
{
	printf("[F7] the TB boundary: the same words, one range and two\n");
	// vsetvli t5, zero, e8, m2 | vwadd.vv | vsetvli zero, zero, e16, m4 | vwadd.wv
	// Cut after word 2, i.e. exactly between the VLMAX-requesting vsetvli's block and the
	// keep-VL retype that heads the loop body -- the accepted CABAC cut.
	std::vector<u32> const words = {Vsetvli(30, 0, VType10(SEW8, M2)), WAdd(),
					Vsetvli(0, 0, VType10(SEW16, M4)), WAddW()};
	for (u32 vlen : {512u, 1024u}) {
		unsigned const c_m2 = Chunks(vlen, M2), c_m4 = Chunks(vlen, M4);
		Built one;
		Translate(one, words, Env{vlen, true});
		auto f1 = WidenFrames(one.region);
		CHECK_EQ(f1.size(), 2u);
		if (f1.size() == 2) {
			ExpectUnbounded(f1[0], c_m2, "one range, frame 0");
			ExpectUnbounded(f1[1], c_m4, "one range, frame 1");
		}
		Built two;
		TranslateSplit(two, words, /*cut=*/2u, Env{vlen, true});
		auto f2 = WidenFrames(two.region);
		CHECK_EQ(f2.size(), 2u);
		if (f2.size() == 2) {
			ExpectUnbounded(f2[0], c_m2, "two ranges, range 0");
			// The second range's entry is reachable by a branch, so nothing from the
			// first range -- and nothing from the word immediately before it -- may be
			// assumed. Its keep-VL retype has no incoming value to keep.
			ExpectBounded(f2[1], c_m4, LanesPerChunk(vlen, SEW16), "two ranges, range 1");
		}
		printf("  ok   VLEN %-4u one range: 0 + 0 bounds; two ranges: 0 + %u bounds\n", vlen,
		       c_m4 - 1u);
	}
}

// ---------------------------------------------------------------------------------------------
// [F8] illegal / reserved vtype fails closed.

void TestIllegalVtype()
{
	printf("[F8] illegal and reserved vtypes fail closed\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const chunks = Chunks(vlen, M2);
		// (a) a reserved vsew encoding, then a keep-VL retype to a legal vtype: the retype has
		// no value to keep, so the frame keeps its ladder.
		std::vector<u32> const reserved = {Vsetvli(5, 0, VTypeReserved()),
						   Vsetvli(0, 0, VType10(SEW16, M2)), WAdd()};
		// (b) e64, mf8 is unsupported (SEW > LMUL*ELEN), same consequence.
		std::vector<u32> const unsup = {Vsetvli(5, 0, VType10(SEW64, MF8)),
						Vsetvli(0, 0, VType10(SEW16, M2)), WAdd()};
		for (auto const *p : {&reserved, &unsup}) {
			Built on;
			Translate(on, *p, Env{vlen, true});
			auto f = WidenFrames(on.region);
			CHECK_EQ(f.size(), 1u);
			if (f.size() == 1)
				ExpectBounded(f[0], chunks, LanesPerChunk(vlen, SEW16),
					      "after an illegal vtype");
		}
		printf("  ok   VLEN %-4u reserved and unsupported vtypes both leave %u bounds\n", vlen,
		       chunks - 1u);
	}
}

// ---------------------------------------------------------------------------------------------
// [F9] masking and [F10] legal overlap.

void TestMaskAndOverlap()
{
	printf("[F9] the proof is blind to v0\n");
	for (u32 vlen : {512u, 1024u}) {
		std::vector<u32> const masked = {Vsetvli(5, 0, VType10(SEW16, M2)), WAdd(/*vm=*/0)};
		Built off, on;
		Translate(off, masked, Env{vlen, false});
		Translate(on, masked, Env{vlen, true});
		auto fo = WidenFrames(off.region), fn = WidenFrames(on.region);
		CHECK_EQ(fo.size(), 1u);
		CHECK_EQ(fn.size(), 1u);
		unsigned const chunks = Chunks(vlen, M2);
		if (fn.size() == 1) {
			ExpectUnbounded(fn[0], chunks, "masked, proved full");
			// ...and it really is the masked form.
			for (auto *i : fn[0].body)
				if (i->GetOpcode() == Op::_vchunkwiden)
					CHECK(static_cast<InstVChunkWiden *>(i)->masked);
		}
		Emit(off);
		Emit(on);
		CHECK(!off.code.empty());
		CHECK(off.code == on.code);
		printf("  ok   VLEN %-4u vm = 0 with proved full VL: 0 bounds, bytes equal OFF\n", vlen);
	}

	printf("[F10] legal overlap: same work multiset, same chunk order\n");
	for (u32 vlen : {512u, 1024u}) {
		// The `.wv` wide-vs2 form, and the top-aligned narrow source the route admits
		// (vs2 + ng == vd + dg at e16,m2: 20 + 2 == 16 + 6? no -- the top-aligned case is
		// vs2 = vd + dg - ng, computed here rather than written as a literal).
		u32 const dg = 1u << (LmulLog2(M2) + 1), ng = 1u << LmulLog2(M2);
		u32 const top_aligned_vs2 = VD + dg - ng;
		std::vector<std::vector<u32>> const cases = {
		    {Vsetvli(5, 0, VType10(SEW16, M2)), WAddW()},
		    {Vsetvli(5, 0, VType10(SEW16, M2)),
		     MakeOpV(F6_VWADD, 1, top_aligned_vs2, VS1, VD, OPMVV)},
		    {Vsetvli(5, 0, VType10(SEW16, M2)), MakeOpV(F6_VWMACC, 1, VS2, VS1, VD, OPMVV)},
		    {Vsetvli(5, 0, VType10(SEW16, M2)), MakeOpV(F6_VWMUL, 1, VS2, VS1, VD, OPMVV)},
		    {Vsetvli(5, 0, VType10(SEW16, M2)), MakeOpV(F6_VWADDU, 1, VS2, 7, VD, OPMVX)},
		};
		unsigned seen = 0;
		for (auto const &words : cases) {
			Built off, on;
			Translate(off, words, Env{vlen, false});
			Translate(on, words, Env{vlen, true});
			auto fo = WidenFrames(off.region), fn = WidenFrames(on.region);
			if (fo.size() != 1 || fn.size() != 1)
				continue;
			++seen;
			ExpectUnbounded(fn[0], Chunks(vlen, M2), "overlap case");
			CHECK(ChunkWork(fo[0]) == ChunkWork(fn[0]));
			Emit(off);
			Emit(on);
			CHECK(!off.code.empty());
			CHECK(off.code == on.code);
		}
		CHECK_EQ(seen, cases.size());
		printf("  ok   VLEN %-4u %u overlap/form cases: work and bytes unchanged\n", vlen, seen);
	}
}

// ---------------------------------------------------------------------------------------------
// [F11] the two invalidators, each as an A/B against the identical program without it.

void TestInvalidators()
{
	printf("[F11] vsetvl and vleff invalidate the knowledge\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const chunks = Chunks(vlen, M2);
		u32 const lanes = LanesPerChunk(vlen, SEW16);
		// The control: proved full, ladder gone.
		std::vector<u32> const base = {Vsetvli(5, 0, VType10(SEW16, M2)), WAdd()};
		Built ctl;
		Translate(ctl, base, Env{vlen, true});
		CHECK_EQ(WidenBounds(ctl.region), 0u);
		// (a) vsetvl: the vtype comes from a GPR, so VLMAX -- and therefore min(AVL, VLMAX) --
		// is unknown. The following keep-VL retype re-establishes a vtype but no vl.
		std::vector<u32> const with_vsetvl = {Vsetvli(5, 0, VType10(SEW16, M2)), Vsetvl(0, 10, 11),
						      Vsetvli(0, 0, VType10(SEW16, M2)), WAdd()};
		Built a;
		Translate(a, with_vsetvl, Env{vlen, true});
		auto fa = WidenFrames(a.region);
		CHECK_EQ(fa.size(), 1u);
		if (fa.size() == 1)
			ExpectBounded(fa[0], chunks, lanes, "after vsetvl");
		// (b) vleff trims vl to what it managed to load.
		std::vector<u32> const with_vleff = {Vsetvli(5, 0, VType10(SEW16, M2)), Vle8ff(1, 10),
						     WAdd()};
		Built b;
		Translate(b, with_vleff, Env{vlen, true});
		auto fb = WidenFrames(b.region);
		CHECK_EQ(fb.size(), 1u);
		if (fb.size() == 1)
			ExpectBounded(fb[0], chunks, lanes, "after vleff");
		// ...and the same program with a NON-vl-writing vector instruction in the same slot
		// keeps the proof, so (b) is about vleff and not about "an instruction appeared".
		std::vector<u32> const with_vadd = {Vsetvli(5, 0, VType10(SEW16, M2)),
						    MakeOpV(F6_VADD, 1, 2, 3, 4, OPIVV), WAdd()};
		Built c;
		Translate(c, with_vadd, Env{vlen, true});
		CHECK_EQ(WidenBounds(c.region), 0u);
		printf("  ok   VLEN %-4u vsetvl and vleff each restore %u bounds; a vadd.vv does not\n",
		       vlen, chunks - 1u);
	}
}

// ---------------------------------------------------------------------------------------------
// [F12] the mutation table.
//
// Each row is one way to make the proof unsound, a witness program built above, the SOUND bound
// count, and the count the mutant would produce. Both halves are asserted: the production route must
// give the sound count, and the mutant count must DIFFER from it -- a row that cannot distinguish
// anything is a failure, not a pass.

void TestMutations()
{
	printf("[F12] mutations that an unsound proof would fail\n");
	struct Row {
		char const *mutation;
		std::vector<u32> words;
		unsigned sound, mutant;
		char const *why;
	};
	for (u32 vlen : {512u, 1024u}) {
		unsigned const c_m1 = Chunks(vlen, M1), c_m2 = Chunks(vlen, M2), c_m4 = Chunks(vlen, M4);
		std::vector<Row> const rows = {
		    {"rs1 != x0 counted as a VLMAX request",
		     {Vsetvli(5, 10, VType10(SEW16, M2)), WAdd()},
		     c_m2 - 1u,
		     0u,
		     "the AVL is a runtime GPR"},
		    {"keep-VL retype always retains (no reserved test at all)",
		     {Vsetvli(5, 0, VType10(SEW8, M2)), Vsetvli(0, 0, VType10(SEW16, M2)), WAdd()},
		     c_m2 - 1u,
		     0u,
		     "the ratio changes and the old vl no longer fits"},
		    {"keep-VL retype uses HANDLER(vsetvli)'s weaker test ('would the retained vl have to "
		     "change') instead of the spec's ('does the SEW/LMUL ratio change VLMAX')",
		     {Vsetvli(5, 0, VType10(SEW16, M2)), Vsetvli(0, 0, VType10(SEW8, M2)), WAdd()},
		     c_m2 - 1u,
		     0u,
		     "RVV 1.0 6.2 reserves a VLMAX-changing retype even when the old vl fits; this is "
		     "the mutation the W21 audit caught in the first implementation"},
		    {"keep-VL retype always drops (the W18 provenance bug)",
		     {Vsetvli(30, 0, VType10(SEW8, M2)), Vsetvli(0, 0, VType10(SEW32, M8)),
		      Vsetvli(0, 0, VType10(SEW16, M4)), WAddW()},
		     0u,
		     c_m4 - 1u,
		     "a VLMAX-preserving retype keeps vl"},
		    {"vsetivli treated as a VLMAX request",
		     {Vsetivli(5, 4, VType10(SEW16, M2)), WAdd()},
		     c_m2 - 1u,
		     0u,
		     "the AVL is the immediate, and 4 < VLMAX"},
		    // NOT a row any more: "fullness measured against the vtype that CREATED the
		    // knowledge". Under the corrected keep-VL rule VLMAX is INVARIANT for as long as one
		    // vl value is live, so the creating and the consuming VLMAX are provably equal and
		    // no program can distinguish the two. A row that cannot distinguish anything is
		    // removed rather than kept as decoration -- the table's own `sound != mutant`
		    // assertion would fail on it, which is how its removal was forced.
		    {"a ratio-PRESERVING retype is treated as reserved (the W18 direction, narrowed)",
		     {Vsetvli(5, 0, VType10(SEW16, M1)), Vsetvli(0, 0, VType10(SEW32, M2)), WAdd()},
		     0u,
		     c_m2 - 1u,
		     "VLMAX is unchanged across e16,m1 -> e32,m2, so the value must be carried"},
		    {"vsetivli's min(uimm5, VLMAX) dropped",
		     {Vsetivli(5, 31, VType10(SEW32, M1)), WAdd()},
		     vlen == 512u ? 0u : c_m1 - 1u,
		     vlen == 512u ? c_m1 - 1u : 0u,
		     "31 clamps to VLMAX at 512 and does not at 1024"},
		};
		for (auto const &r : rows) {
			Built on;
			Translate(on, r.words, Env{vlen, true});
			unsigned const got = WidenBounds(on.region);
			CHECK_EQ(WidenFrames(on.region).size(), 1u);
			CHECK_EQ(got, r.sound);
			// The row must be able to tell the two apart, or it proves nothing.
			CHECK(r.sound != r.mutant);
			if (got != r.sound || r.sound == r.mutant)
				fprintf(stderr, "  (mutation row: %s -- %s)\n", r.mutation, r.why);
		}
		printf("  ok   VLEN %-4u %zu mutation rows: production sound, each mutant distinguishable\n",
		       vlen, rows.size());
	}
	// The cross-range mutation ("knowledge crosses an ip range", which is also the "seed the block
	// from the preceding word or from the entry hint" mutation) needs the split translation and so
	// is stated separately.
	for (u32 vlen : {512u, 1024u}) {
		std::vector<u32> const words = {Vsetvli(30, 0, VType10(SEW8, M2)), WAdd(),
						Vsetvli(0, 0, VType10(SEW16, M4)), WAddW()};
		Built two;
		TranslateSplit(two, words, 2u, Env{vlen, true});
		auto f = WidenFrames(two.region);
		CHECK_EQ(f.size(), 2u);
		unsigned const sound = Chunks(vlen, M4) - 1u, mutant = 0u;
		CHECK(sound != mutant);
		if (f.size() == 2)
			CHECK_EQ(CountOp(f[1], Op::_vchunkactive), sound);
	}
	printf("  ok   cross-range mutation (knowledge seeded from a predecessor) distinguished at\n"
	       "       both widths\n");
}

// ---------------------------------------------------------------------------------------------
// [F13] the method was not broadened, and [F14] default-off is still inert.

void TestNotBroadenedAndInert()
{
	printf("[F13] the equal-width route is untouched in a proved-full-VL block\n");
	for (u32 vlen : {512u, 1024u}) {
		// A block whose vl is PROVED full, containing an equal-width integer frame.
		std::vector<u32> const words = {Vsetvli(5, 0, VType10(SEW32, M2)),
						MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV)};
		Built a, b;
		Translate(a, words, Env{vlen, /*widen_bound=*/false, /*int_bound=*/true});
		Translate(b, words, Env{vlen, /*widen_bound=*/true, /*int_bound=*/true});
		auto fa = FindFrames(a.region), fb = FindFrames(b.region);
		CHECK_EQ(fa.size(), 1u);
		CHECK_EQ(fb.size(), 1u);
		unsigned const eq_chunks = [&] {
			u32 const rb = vlen / 8, bytes = rb < 64u ? rb : 64u;
			return (unsigned)((rb << LmulLog2(M2)) / bytes);
		}();
		// S1-3A's ladder is `chunks - 1` bounds and W21 must not have removed it.
		if (fa.size() == 1)
			CHECK_EQ(CountOp(fa[0], Op::_vchunkactive), eq_chunks - 1u);
		if (fb.size() == 1)
			CHECK_EQ(CountOp(fb[0], Op::_vchunkactive), eq_chunks - 1u);
		Emit(a);
		Emit(b);
		CHECK(!a.code.empty());
		CHECK(a.code == b.code);
		printf("  ok   VLEN %-4u equal-width keeps its %u bounds; the widening switch moves no\n"
		       "       byte of it\n",
		       vlen, eq_chunks - 1u);
	}

	printf("[F14] default-off is inert\n");
	std::vector<std::vector<u32>> const programs = {
	    {Vsetvli(5, 0, VType10(SEW16, M2)), WAdd()},
	    {Vsetvli(5, 10, VType10(SEW16, M2)), WAdd()},
	    {Vsetivli(5, 4, VType10(SEW16, M2)), WAdd()},
	    {Vsetvli(30, 0, VType10(SEW8, M2)), Vsetvli(0, 0, VType10(SEW32, M8)),
	     Vsetvli(0, 0, VType10(SEW16, M4)), WAddW()},
	    {Vsetvli(5, 0, VType10(SEW16, M2)), Vle8ff(1, 10), WAdd()},
	};
	for (u32 vlen : {512u, 1024u}) {
		unsigned n = 0;
		for (auto const &p : programs) {
			Built off;
			Translate(off, p, Env{vlen, false});
			CHECK_EQ(WidenBounds(off.region), 0u);
			for (auto &f : WidenFrames(off.region)) {
				CHECK(!f.end->frame_clears_vstart);
				++n;
			}
		}
		CHECK_EQ(n, programs.size());
		printf("  ok   VLEN %-4u %u OFF frames: no bound, no vstart claim\n", vlen, n);
	}
}

} // namespace

int main()
{
	TestSameTbFullVl();
	TestKeepVlRetype();
	TestKeepVlBoundaries();
	TestAvlForms();
	TestTbBoundary();
	TestIllegalVtype();
	TestMaskAndOverlap();
	TestInvalidators();
	TestMutations();
	TestNotBroadenedAndInert();

	if (g_failures) {
		printf("FAIL rvv_widen_static_fullvl_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_widen_static_fullvl_test\n");
	return 0;
}
