// C4e: THE GROUPED COMPONENT-MAJOR MULTI-MEMBER RUN BODY AND ITS OPTIONAL ACTIVE-SUFFIX BOUND.
//
// Design: C4D_MULTI_MEMBER_ACTIVE_COMPONENT_DESIGN_20260913.md (design 1). The three arms this
// implementation is meant to make definable are
//
//   A  --rvv-vector-run=0                             per-instruction frames, materialize at every
//                                                     guest instruction boundary
//   B  --rvv-run-grouped-component-major=1            one guarded frame, component-major body,
//      --rvv-qcg-active-vl-run-bound=0                NO bound node anywhere
//   C  --rvv-run-grouped-component-major=1            the SAME body, plus one active-VL bound in
//      --rvv-qcg-active-vl-run-bound=1                front of each boundable component slice
//
// and the property that makes B -> C a single factor is checked here directly rather than argued:
// strip the `vchunkactive` nodes out of arm C's frame body and what is left must equal arm B's
// frame body node for node.
//
// THE SECTIONS, AND WHAT EACH WOULD CATCH:
//
//   [1] B AND C DIFFER BY THE BOUND NODES AND BY NOTHING ELSE. Same words, same VLEN, same run.
//       Arm C's body minus its bounds is arm B's body, opcode for opcode and operand for operand
//       where the node carries one; the bounds are `k` in number, carry ascending chunk indices and
//       element bases `c * lanes`, and each sits immediately before its own component's mask node.
//       A body that reordered, added or dropped any other node would fail here.
//   [2] THE BODY REALLY IS COMPONENT-MAJOR. Component c's stores all precede component c+1's mask
//       node and loads, and every member's lane op for component c lies between them. This is the
//       property the bound's correctness rests on: it is what makes the inactive components a
//       contiguous TAIL of the body for every member at once.
//   [3] MULTI-MEMBER + MEMBER-MAJOR IS STILL REFUSED. With the grouped switch off the same run is
//       still closed as `MultiMember`: no bound node, no component-major claim on the begin node,
//       and a zero census geometry on the end node. And with the grouped switch off but the BOUND
//       switch on -- a combination elfrun refuses at parse time and this suite sets directly -- the
//       frame is still unbounded, because the planner's `suffix_is_body_tail` conjunct is false.
//   [4] A COMPONENT-MAJOR CLAIM THAT THE BODY DOES NOT SUPPORT IS A PANIC, not wrong code. Three
//       mutations in child processes: the claim on a member-major run body, the claim on a
//       single-member frame, and a unit count that disagrees with the emitted slices. Two
//       unmutated controls run first, so a finalizer that refused everything would not pass.
//   [5] THE SWITCH-OFF ARM IS THE OLD ARM. With both switches off the emitted host bytes for a run
//       are identical to the bytes emitted with the feature compiled in but every switch clear --
//       checked here by emitting the same words under an Env that differs only in the two new
//       switches and requiring byte equality against the arm that never sets them. (The suite-wide
//       half of this claim is the rest of the test binaries, run unchanged.)
//   [6] THE ADMITTED CLASS IS THE GUARD'S, NOT AN OPCODE LIST. An integer run -- whose guard proves
//       `vl == VLMAX` and therefore has no inactive suffix to leave -- is NOT grouped even with
//       both switches on, and its frame is byte-identical to the switch-off arm.
//   [7] THE PLANNER'S OWN PREDICATE. `suffix_is_body_tail` is the single conjunct that changed:
//       true for a single-member frame, true for a multi-member component-major frame, false for a
//       multi-member member-major frame, with every other input held fixed.
//
// C4h ADDS THE EVALUATION-ONLY PLACEBO ARM AND ITS FOUR SECTIONS.
//
//   P  --rvv-run-grouped-component-major=1            the SAME body and the SAME bound nodes as C,
//      --rvv-qcg-active-vl-run-bound=1                but every bound compares `vec.vl` against 0
//      --rvv-qcg-active-vl-bound-placebo=1            instead of its unit's own element base
//
// P exists because B -> C is NOT a single factor for a TIMING comparison even though it is one for
// the QIR body: arm C's hot block is longer and carries two more branches, and C4g measured a
// difference between the arms at the two `vl` values where the bound provably cannot fire. P
// carries C's code shape exactly and skips nothing, so C4g's `C/B` factors as `(C/P) * (P/B)`.
//
//   [8] P's QIR BODY IS C's, FIELD FOR FIELD, EXCEPT THE BOUND IMMEDIATE. Same node sequence, same
//       node count, same `chunk` indices, same `n_typed`, same census geometry, and every body
//       node's own element base and mask width unmoved -- the last is what would catch a placebo
//       pushed into the planner's `element_base()`, which the guarded unit's lane mask also reads.
//       Every `InstVChunkActive::element_base` is 0, not just some of them.
//   [9] P's EMITTED BYTES ARE C's, EXCEPT ONE IMMEDIATE BYTE PER NON-ZERO BOUND. Same length, and
//       the number of differing bytes equals the number of bounds whose real immediate is non-zero;
//       patching those bytes back to the real immediates reproduces arm C's buffer exactly. Also
//       the switch-off half: with the placebo clear the bytes are the arm-C bytes bit for bit.
//   [10] THE EQUIVALENCE CHECK IS LIVE, NOT VACUOUS. An immediate of 128 or more forces asmjit's
//       11-byte `81 /7 id` encoding instead of the 8-byte `83 /7 ib` one, so a frame whose bounds
//       crossed that boundary would NOT be length-equivalent. Section [10] mutates one bound's
//       immediate to 128 and requires the emitted length to CHANGE. A section that could only pass
//       would say nothing about the family that [11] then proves stays below the boundary.
//   [11] WHY THIS FAMILY NEVER CROSSES IT. `element_base(c) = c * lanes`, EMUL is pinned to 1 so
//       `c < rvvrun::kMaxChunks == VLEN_MAX_BITS / 512 == 8`, and an FP host chunk is at most 64
//       bytes over a 4-byte SEW so `lanes <= 16`: the largest immediate an admitted grouped run
//       frame can carry is 7 * 16 == 112 < 128. Asserted over every legal (VLEN, SEW) rather than
//       argued, so a future relaxation of the LMUL conjunct fails here instead of silently making
//       the placebo non-equivalent.
//
// SCOPE. No workload, no timing, no ISA change, no default changed. Nothing here executes emitted
// code; the correctness of a SKIPPED component against a reference is a differential-oracle
// question and is deliberately not claimed by this file. The placebo is an EVALUATION CONTROL and
// this file makes no performance claim about it whatsoever.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_active_chunk_plan.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_frame_semantics.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvfinal = dbt::rv32::rvvfinal;
namespace rvvplan = dbt::rv32::rvvplan;
namespace rvvrun = dbt::rv32::rvvrun;

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
// [0] Compile-time pins. If either of these moves, the counts below stop meaning what they say.
// ---------------------------------------------------------------------------------------------
static_assert(qir::RVV_FP_SHARED_MASK_MAX_CHUNKS >= 2,
	      "the grouped body needs one resident mask per component");

// ---------------------------------------------------------------------------------------------
// Guest encodings, field by field, pinned against the words the accepted FP-run suites already use.
// ---------------------------------------------------------------------------------------------
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) |
	       0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Iv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b000u); }

constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u, F6_VFMUL = 0b100100u;
constexpr u32 F6_VFDIV = 0b100000u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u;

static_assert(Vv(F6_VFDIV, 9, 8, 9) == 0x829414d7u, "vfdiv.vv v9,v9,v8");
static_assert(Iv(F6_VADD, 1, 2, 3) == 0x021101d7u, "vadd.vv v3,v1,v2");

// vsetvli a0,a0,e32,m1,ta,ma. `ta` matters: the run's FP admission refuses a tail-undisturbed
// member, because the run body writes whole chunks back (rv32_qir.cpp, the `vta()` test).
constexpr u32 VSETVLI_E32M1 = 0x0d057557u;

// A four-member all-FP run with real cross-member dataflow: every member reads a register an
// earlier member wrote, so the frame is not a set of independent instructions that happen to be
// adjacent. Nothing here is a workload constant; the register numbers are arbitrary and nothing in
// the substrate reads them.
std::vector<u32> FpRunWords()
{
	return {VSETVLI_E32M1,
		Vv(F6_VFADD, /*vs2=*/9, /*vs1=*/10, /*vd=*/8),
		Vv(F6_VFMUL, /*vs2=*/8, /*vs1=*/10, /*vd=*/11),
		Vv(F6_VFSUB, /*vs2=*/11, /*vs1=*/8, /*vd=*/12),
		Vv(F6_VFDIV, /*vs2=*/12, /*vs1=*/11, /*vd=*/13)};
}

// The integer control: same shape, but its run guard proves `vl == VLMAX`, so there is no inactive
// suffix for a bound to leave and the grouped body must refuse it.
std::vector<u32> IntRunWords()
{
	return {VSETVLI_E32M1,
		Iv(F6_VADD, /*vs2=*/9, /*vs1=*/10, /*vd=*/8),
		Iv(F6_VSUB, /*vs2=*/8, /*vs1=*/10, /*vd=*/11),
		Iv(F6_VADD, /*vs2=*/11, /*vs1=*/8, /*vd=*/12)};
}

// ---------------------------------------------------------------------------------------------
// Harness. One fixed code buffer, for the reason the accepted component-separable suite records:
// QEmit embeds absolute addresses, so two arms allocated at two addresses differ in immediates for
// a reason unrelated to the arm under test.
// ---------------------------------------------------------------------------------------------
alignas(64) u8 g_code_buf[1u << 21];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("test code buffer too small");
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 1024; // k = VLEN/8 / 64 = 2 components per register at LMUL 1
	bool grouped = false;
	bool run_bound = false;
	bool placebo = false; // C4h: weaken every bound's immediate to 0
	bool int_routes = true;
};

// Every switch this file's result can depend on is set on EVERY call, so no section inherits a
// value another one left in the process globals.
void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_component_demand_placement = false;
	config::rvv_run_scalar_passthrough = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_run_split_value_weighted = false;
	config::rvv_run_frame_census = false;
	// The two switches under test, and C4h's evaluation-only control.
	config::rvv_run_grouped_component_major = e.grouped;
	config::rvv_qcg_active_vl_run_bound = e.run_bound;
	config::rvv_qcg_active_vl_bound_placebo = e.placebo;
	// The other three members of the active-vl policy family stay OFF: this suite's subject is
	// the run bound, and a single-instruction frame that also carried one would make the frame
	// counts below ambiguous.
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_active_vl_widen_bound = false;
	config::rvv_qcg_active_vl_narrow_bound = true;
	config::rvv_qcg_active_chunk_census = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_typed_chunk = e.int_routes;
	config::rvv_qcg_typed_chunk_sub = e.int_routes;
	config::rvv_qcg_typed_chunk_mul = e.int_routes;
	config::rvv_qcg_typed_chunk_xor = e.int_routes;
	config::rvv_qcg_typed_chunk_or = e.int_routes;
	config::rvv_qcg_typed_chunk_and = e.int_routes;
	config::rvv_qcg_typed_chunk_force_emit = e.int_routes;
	config::rvv_qcg_typed_chunk_sub_force_emit = e.int_routes;
	config::rvv_qcg_typed_chunk_mul_force_emit = e.int_routes;
	config::rvv_qcg_typed_chunk_xor_force_emit = e.int_routes;
	config::rvv_qcg_typed_chunk_or_force_emit = e.int_routes;
	config::rvv_qcg_typed_chunk_and_force_emit = e.int_routes;
	// The shared per-chunk masks ARE the grouped body's per-unit mask nodes.
	config::rvv_qcg_fp_shared_mask = true;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	while (!b.code.empty() && b.code.back() == 0)
		b.code.pop_back();
}

std::vector<u8> EmitBytes(std::vector<u32> const &words, Env const &e)
{
	Built b;
	Translate(b, words, e);
	Emit(b);
	return b.code;
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	Block *bb = nullptr;
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
				cur.bb = &bb;
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

Frame const *Widest(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (!best || f.begin->n_members > best->begin->n_members)
			best = &f;
	return best;
}

// The chunk index a state load/store names, recovered from the SAME arithmetic
// rv32::group_chunk_state_offset performs. At LMUL 1 a register's k chunks are k consecutive
// `stride`-byte windows inside its VLEN_MAX_BYTES slot.
u32 StateChunkIndex(u32 offs, u32 stride)
{
	u32 const vreg_base =
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	return ((offs - vreg_base) % dbt::rv32::VLEN_MAX_BYTES) / stride;
}

// A node's identity for the "same body" comparison: the opcode plus whatever chunk/base/offset
// field the node type carries. Two bodies that agree on this sequence agree on every decision the
// grouped arm could have taken differently.
std::string NodeKey(Inst *i)
{
	char buf[128];
	switch (i->GetOpcode()) {
	case Op::_vchunkmaskset: {
		auto *n = static_cast<InstVChunkMaskSet *>(i);
		snprintf(buf, sizeof(buf), "maskset c=%u lanes=%u", n->chunk, n->lanes);
		break;
	}
	case Op::_vchunkfalu: {
		auto *n = static_cast<InstVChunkFALU *>(i);
		snprintf(buf, sizeof(buf), "falu c=%u f6=%u k=%u", n->chunk, n->funct6, n->kmask);
		break;
	}
	case Op::_vchunkfma: {
		auto *n = static_cast<InstVChunkFMA *>(i);
		snprintf(buf, sizeof(buf), "fma c=%u f6=%u k=%u", n->chunk, n->funct6, n->kmask);
		break;
	}
	case Op::_vstatechunkload: {
		auto *n = static_cast<InstVStateChunkLoad *>(i);
		snprintf(buf, sizeof(buf), "load offs=%u", (unsigned)n->offs);
		break;
	}
	case Op::_vstatechunkstore: {
		auto *n = static_cast<InstVStateChunkStore *>(i);
		snprintf(buf, sizeof(buf), "store offs=%u", (unsigned)n->offs);
		break;
	}
	case Op::_vchunkactive: {
		auto *n = static_cast<InstVChunkActive *>(i);
		snprintf(buf, sizeof(buf), "BOUND c=%u base=%u", n->chunk, n->element_base);
		break;
	}
	default:
		snprintf(buf, sizeof(buf), "op=%d", (int)i->GetOpcode());
		break;
	}
	return std::string(buf);
}

std::vector<std::string> BodyKeys(Frame const &f, bool drop_bounds)
{
	std::vector<std::string> out;
	for (auto *i : f.body) {
		if (drop_bounds && i->GetOpcode() == Op::_vchunkactive)
			continue;
		out.push_back(NodeKey(i));
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

// A Panic aborts, so every fail-closed contract runs in a child whose stderr is matched against the
// specific message: "the child died" would also be produced by an unrelated crash.
void ExpectPanic(char const *what, char const *expect, std::function<void()> const &body)
{
	char path[] = "/tmp/c4e_panic_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		Panic("c4e test: mkstemp");
	fflush(stdout);
	fflush(stderr);
	pid_t const pid = fork();
	if (pid == 0) {
		dup2(fd, 2);
		close(fd);
		body();
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	std::string out;
	{
		lseek(fd, 0, SEEK_SET);
		char buf[4096];
		ssize_t n;
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			out.append(buf, (size_t)n);
	}
	close(fd);
	unlink(path);
	bool const clean = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	bool const matched = out.find(expect) != std::string::npos;
	if (clean || !matched) {
		fprintf(stderr, "  FAIL %s: expected Panic \"%s\" (clean_exit=%d matched=%d)\n", what,
			expect, (int)clean, (int)matched);
		++g_failures;
	} else {
		printf("    %-52s refused\n", what);
	}
}

void ExpectClean(char const *what, std::function<void()> const &body)
{
	fflush(stdout);
	fflush(stderr);
	pid_t const pid = fork();
	if (pid == 0) {
		body();
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
		fprintf(stderr, "  FAIL %s: the UNMUTATED control did not finish cleanly\n", what);
		++g_failures;
	} else {
		printf("    %-52s clean\n", what);
	}
}

// ---------------------------------------------------------------------------------------------
// [1] Arm B and arm C differ by the bound nodes and by nothing else.
// ---------------------------------------------------------------------------------------------
void Section1()
{
	printf("[1] arm B vs arm C: the bodies differ by the bound nodes only\n");
	auto const words = FpRunWords();
	Built bb, bc;
	Translate(bb, words, Env{.grouped = true, .run_bound = false});
	Translate(bc, words, Env{.grouped = true, .run_bound = true});
	auto const fb = FindFrames(bb.region), fc = FindFrames(bc.region);
	auto const *rb = Widest(fb), *rc = Widest(fc);
	CHECK(rb != nullptr && rc != nullptr);
	if (!rb || !rc)
		return;
	// The run really formed, and really is the grouped body on both arms.
	CHECK(rb->begin->n_members >= 2);
	CHECK_EQ(rb->begin->n_members, rc->begin->n_members);
	CHECK(rb->begin->body_component_major);
	CHECK(rc->begin->body_component_major);

	u32 const k = rb->end->census_units;
	CHECK(k >= 2); // the transformation is the identity below two components
	CHECK_EQ(rc->end->census_units, k);
	// The control arm executes every unit; the bounded arm executes only its unbounded prefix.
	CHECK_EQ(rb->end->census_prefix_units, k);
	CHECK_EQ(rc->end->census_prefix_units, 0u);

	// No bound on arm B; exactly one per component on arm C.
	CHECK_EQ(CountOp(*rb, Op::_vchunkactive), 0u);
	CHECK_EQ(CountOp(*rc, Op::_vchunkactive), k);

	// THE SINGLE-FACTOR ASSERTION.
	auto const kb = BodyKeys(*rb, /*drop_bounds=*/false);
	auto const kc = BodyKeys(*rc, /*drop_bounds=*/true);
	CHECK_EQ(kb.size(), kc.size());
	size_t const n = kb.size() < kc.size() ? kb.size() : kc.size();
	size_t diffs = 0;
	for (size_t i = 0; i < n; ++i)
		if (kb[i] != kc[i]) {
			if (diffs < 4)
				fprintf(stderr, "  FAIL body differs at %zu: B=%s C=%s\n", i,
					kb[i].c_str(), kc[i].c_str());
			++diffs;
		}
	CHECK_EQ(diffs, 0u);

	// Each bound guards its OWN component and sits immediately before that component's mask node.
	u32 const stride = 64u; // the FP route's host chunk width; the mask node's lanes pin the rest
	(void)stride;
	u32 seen = 0;
	for (size_t i = 0; i < rc->body.size(); ++i) {
		if (rc->body[i]->GetOpcode() != Op::_vchunkactive)
			continue;
		auto *bd = static_cast<InstVChunkActive *>(rc->body[i]);
		CHECK_EQ(bd->chunk, seen);
		CHECK(i + 1 < rc->body.size());
		if (i + 1 >= rc->body.size())
			break;
		CHECK_EQ((int)rc->body[i + 1]->GetOpcode(), (int)Op::_vchunkmaskset);
		if (rc->body[i + 1]->GetOpcode() == Op::_vchunkmaskset) {
			auto *ms = static_cast<InstVChunkMaskSet *>(rc->body[i + 1]);
			CHECK_EQ(ms->chunk, seen);
			// The bound's immediate is the unit's first ELEMENT index, which is the same
			// number the unit's own mask node uses as its stride.
			CHECK_EQ(bd->element_base, seen * ms->lanes);
		}
		++seen;
	}
	CHECK_EQ(seen, k);

	// Both arms emit; a declared/seen typed-op mismatch would Panic in Emit_rvvtypedchunkend.
	Emit(bb);
	Emit(bc);
	CHECK(!bb.code.empty() && !bc.code.empty());
	printf("    members=%u components=%u  B body=%zu nodes  C body=%zu nodes (+%u bounds)\n",
	       rb->begin->n_members, k, kb.size(), rc->body.size(), k);
}

// ---------------------------------------------------------------------------------------------
// [2] The body really is component-major.
// ---------------------------------------------------------------------------------------------
void Section2()
{
	printf("[2] component-major order: slice c is closed before slice c+1 opens\n");
	Built b;
	Translate(b, FpRunWords(), Env{.grouped = true, .run_bound = true});
	auto const fs = FindFrames(b.region);
	auto const *r = Widest(fs);
	CHECK(r != nullptr);
	if (!r)
		return;
	u32 const k = r->end->census_units;
	// The stride the frame's own mask node states, so nothing here assumes a host chunk width.
	u32 lanes = 0;
	for (auto *i : r->body)
		if (i->GetOpcode() == Op::_vchunkmaskset) {
			lanes = static_cast<InstVChunkMaskSet *>(i)->lanes;
			break;
		}
	CHECK(lanes != 0);
	u32 const stride = lanes * 4u; // e32: SEW = 4 bytes
	int slice = -1;
	unsigned lane_ops = 0, loads = 0, stores = 0;
	bool ok = true;
	for (auto *i : r->body) {
		switch (i->GetOpcode()) {
		case Op::_vchunkactive:
			// A bound opens its slice, before that slice's mask node.
			if ((int)static_cast<InstVChunkActive *>(i)->chunk != slice + 1)
				ok = false;
			break;
		case Op::_vchunkmaskset:
			if ((int)static_cast<InstVChunkMaskSet *>(i)->chunk != slice + 1)
				ok = false;
			slice = (int)static_cast<InstVChunkMaskSet *>(i)->chunk;
			break;
		case Op::_vchunkfalu:
			++lane_ops;
			if ((int)static_cast<InstVChunkFALU *>(i)->chunk != slice)
				ok = false;
			break;
		case Op::_vchunkfma:
			++lane_ops;
			if ((int)static_cast<InstVChunkFMA *>(i)->chunk != slice)
				ok = false;
			break;
		case Op::_vstatechunkload:
			++loads;
			if ((int)StateChunkIndex(static_cast<InstVStateChunkLoad *>(i)->offs, stride) !=
			    slice)
				ok = false;
			break;
		case Op::_vstatechunkstore:
			++stores;
			if ((int)StateChunkIndex(static_cast<InstVStateChunkStore *>(i)->offs,
						 stride) != slice)
				ok = false;
			break;
		default:
			break;
		}
	}
	CHECK(ok);
	CHECK_EQ(slice + 1, (int)k);
	// Every member's lane op appears once per component.
	CHECK_EQ(lane_ops, r->begin->n_members * k);
	CHECK(loads >= k && stores >= k);
	printf("    components=%u lane ops=%u loads=%u stores=%u (all in their own slice)\n", k,
	       lane_ops, loads, stores);
}

// ---------------------------------------------------------------------------------------------
// [3] Multi-member + member-major is still refused.
// ---------------------------------------------------------------------------------------------
void Section3()
{
	printf("[3] a member-major multi-member run is still refused a bound\n");
	// (a) both switches off: the accepted arm, unchanged.
	Built off;
	Translate(off, FpRunWords(), Env{.grouped = false, .run_bound = false});
	auto const fo = FindFrames(off.region);
	auto const *ro = Widest(fo);
	CHECK(ro != nullptr);
	if (ro) {
		CHECK(ro->begin->n_members >= 2);
		CHECK(!ro->begin->body_component_major);
		CHECK_EQ(CountOp(*ro, Op::_vchunkactive), 0u);
		// The ineligible close leaves the census geometry at zero, which is what says the
		// frame did not go through the planner arm.
		CHECK_EQ(ro->end->census_units, 0u);
		CHECK_EQ(ro->end->census_prefix_units, 0u);
	}

	// (b) the bound switch on with the body switch OFF -- refused by elfrun at parse time, set
	//     directly here. The planner's `suffix_is_body_tail` conjunct is what refuses it, so the
	//     frame must still be unbounded rather than Panic.
	Built bad;
	Translate(bad, FpRunWords(), Env{.grouped = false, .run_bound = true});
	auto const fb = FindFrames(bad.region);
	auto const *rb = Widest(fb);
	CHECK(rb != nullptr);
	if (rb) {
		CHECK(!rb->begin->body_component_major);
		CHECK_EQ(CountOp(*rb, Op::_vchunkactive), 0u);
		CHECK_EQ(rb->end->census_units, 0u);
	}
	printf("    member-major run: no bound, no component-major claim, zero census geometry\n");
}

// ---------------------------------------------------------------------------------------------
// [4] A component-major claim the body does not support is a Panic.
// ---------------------------------------------------------------------------------------------
void Section4()
{
	// The mutation harness, and the reason it re-runs the finalizer rather than rebuilding: the
	// finalizer scans from `begin` to the Builder's own position, so a Builder placed AT the
	// frame's existing end node sees exactly the body the producer built and nothing else. This
	// is the accepted pattern from rvv_frame_finalizer_test.cpp, not a new one.
	auto refinalize = [](std::vector<u32> const &words, Env const &e, bool claim, u32 units) {
		ApplyEnv(e);
		MemArena arena{1u << 22};
		std::vector<u32> w = words;
		CompilerJob::IpRangesSet ranges = {{0u, (u32)w.size() * 4u}};
		CompilerJob job(nullptr, (uptr)w.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
		Region *region = CompilerGenRegionIR(&arena, job);
		auto const fs = FindFrames(region);
		Frame const *r = nullptr;
		for (auto const &f : fs)
			if (!r || f.begin->n_members > r->begin->n_members)
				r = &f;
		if (!r)
			Panic("c4e test: no frame to re-finalize");
		if (claim)
			r->begin->body_component_major = true;
		rvvfinal::FrameGeometry g{};
		g.policy_enabled = false;
		g.units = units;
		g.unit_dest_bytes = 64;
		g.dest_element_bytes = 4;
		g.per_unit_mask = true;
		g.vstart_owner = rvvfinal::VStartOwner::FrameEpilogue;
		Builder qb(r->bb, IListIterator<Inst>(r->end));
		rvvfinal::CloseFrame(qb, r->begin,
				     {.reason = rvvfinal::Ineligibility::None,
				      .geom = g,
				      .raw = w[1],
				      .stub = RuntimeStubId::id_rv32_vfalu,
				      .members = r->end->members,
				      .n_members = r->end->n_members});
	};

	printf("[4] a claim the emitted body does not support is refused\n");
	// Two unmutated controls first: a suite whose mutations all "pass" because everything Panics
	// would otherwise look healthy.
	ExpectClean("C1 grouped run, bound off", [] {
		Built b;
		Translate(b, FpRunWords(), Env{.grouped = true, .run_bound = false});
		Emit(b);
	});
	ExpectClean("C2 grouped run, bound on", [] {
		Built b;
		Translate(b, FpRunWords(), Env{.grouped = true, .run_bound = true});
		Emit(b);
	});
	// C3: re-finalizing an UNMUTATED grouped body with the right unit count is clean, so the two
	// mutations below fail for their own reason and not because re-finalization itself fails.
	ExpectClean("C3 re-finalize a grouped body, units correct", [&refinalize] {
		refinalize(FpRunWords(), Env{.grouped = true, .run_bound = false}, /*claim=*/false,
			   /*units=*/2);
	});

	// M1. THE CLAIM ON A MEMBER-MAJOR RUN BODY -- the mistake the node bit invites. Refused by
	// the ordinal ascent check, which is pre-existing: in member-major order the unit ordinals
	// run 0,1,0,1,... so the second member's first unit is not ascending. Recorded as such: the
	// new check adds the two shapes the ordinal check cannot see (a unit with no anchor, a unit
	// with no ordinal), and M2 below is the one only the new check refuses.
	ExpectPanic("M1 component-major claimed on a member-major body",
		    "work units are not emitted in ascending ordinal order", [&refinalize] {
			    refinalize(FpRunWords(), Env{.grouped = false, .run_bound = false},
				       /*claim=*/true, /*units=*/8);
		    });

	// M2. THE CLAIM ON A SINGLE-MEMBER FRAME. The bit says "several members share a slice"; on a
	// one-member frame it has no content, and a frame carrying it would have bypassed the
	// `n_members == 1` half of the predicate for no reason. Only the new check refuses this.
	ExpectPanic("M2 component-major claimed on a single-member frame",
		    "a single-member frame claims a component-major body", [&refinalize] {
			    refinalize({VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)},
				       Env{.grouped = false, .run_bound = false}, /*claim=*/true,
				       /*units=*/2);
		    });

	// M3. A UNIT COUNT THAT DISAGREES WITH THE SLICES THE BODY CONTAINS.
	ExpectPanic("M3 geometry claims one component too many",
		    "the emitted work-unit count disagrees with the geometry", [&refinalize] {
			    refinalize(FpRunWords(), Env{.grouped = true, .run_bound = false},
				       /*claim=*/false, /*units=*/3);
		    });
}

// ---------------------------------------------------------------------------------------------
// [5] The switch-off arm, and [6] the class the guard admits.
// ---------------------------------------------------------------------------------------------
void Section56()
{
	printf("[5] switch-off is byte-identical to the arm that never sets the switches\n");
	auto const base = EmitBytes(FpRunWords(), Env{.grouped = false, .run_bound = false});
	auto const again = EmitBytes(FpRunWords(), Env{.grouped = false, .run_bound = true});
	CHECK(!base.empty());
	CHECK_EQ(base.size(), again.size());
	CHECK(base == again);
	printf("    %zu bytes, identical with the bound switch set but the body switch clear\n",
	       base.size());

	printf("[6] an integer run is NOT grouped: its guard proves vl == VLMAX\n");
	Built io, ig;
	Translate(io, IntRunWords(), Env{.grouped = false, .run_bound = false});
	Translate(ig, IntRunWords(), Env{.grouped = true, .run_bound = true});
	auto const fo = FindFrames(io.region), fg = FindFrames(ig.region);
	auto const *ro = Widest(fo), *rg = Widest(fg);
	CHECK(ro != nullptr && rg != nullptr);
	if (ro && rg) {
		CHECK(ro->begin->n_members >= 2);
		CHECK_EQ(ro->begin->n_members, rg->begin->n_members);
		CHECK(!rg->begin->body_component_major);
		CHECK_EQ(CountOp(*rg, Op::_vchunkactive), 0u);
		CHECK(BodyKeys(*ro, false) == BodyKeys(*rg, false));
	}
	auto const ib = EmitBytes(IntRunWords(), Env{.grouped = false, .run_bound = false});
	auto const ib2 = EmitBytes(IntRunWords(), Env{.grouped = true, .run_bound = true});
	CHECK(!ib.empty());
	CHECK(ib == ib2);
	printf("    integer run: %zu bytes, identical with both switches on\n", ib.size());
}

// ---------------------------------------------------------------------------------------------
// [7] The planner conjunct that changed.
// ---------------------------------------------------------------------------------------------
void Section7()
{
	printf("[7] suffix_is_body_tail: the one conjunct, in isolation\n");
	using GuardKind = InstRVVTypedChunkBegin::GuardKind;
	auto make = [](bool tail) {
		rvvplan::ActiveChunkInput in;
		in.family_enabled = true;
		in.units = 4;
		in.unit_dest_bytes = 64;
		in.dest_element_bytes = 4;
		in.guard_kind = GuardKind::VTypePartialVlVstartFrmRNE;
		in.static_full_vl_proved = false;
		in.suffix_is_body_tail = tail;
		in.per_chunk_active_mask = true;
		in.vstart_owner = rvvplan::VStartOwner::FrameEpilogue;
		return rvvplan::ActiveChunkPlan::Make(in);
	};
	CHECK(make(true).bounded());
	CHECK(!make(false).bounded());
	// And the guard half is unchanged: a kind that already proves full VL is refused whatever
	// the body order is.
	rvvplan::ActiveChunkInput full;
	full.family_enabled = true;
	full.units = 4;
	full.unit_dest_bytes = 64;
	full.dest_element_bytes = 4;
	full.guard_kind = GuardKind::VTypeVlVstart;
	full.suffix_is_body_tail = true;
	full.per_chunk_active_mask = true;
	full.vstart_owner = rvvplan::VStartOwner::FrameEpilogue;
	CHECK(!rvvplan::ActiveChunkPlan::Make(full).bounded());
	printf("    bounded iff the body's inactive units are its tail AND the guard leaves a tail\n");
}

// ---------------------------------------------------------------------------------------------
// C4h helpers: locating the emitted bound sequences, by ENCODING rather than by immediate value.
//
// The placebo makes every bound's immediate 0, so two bounds in the same frame become
// indistinguishable by their operand. Anything that recognised a bound by "the immediate equals
// c * lanes" would therefore find one sequence on arm C and a different set on arm P and call the
// arms different for the wrong reason. This scanner matches the ENCODING QEmit::Emit_vchunkactive
// produces and nothing else:
//
//     [REX] 83 /7 mod=10 disp32 ib      cmp dword ptr [R_STATE + vec.vl], imm8
//     0f 86 rel32                       jbe <frame body-done label>
//
// `mod == 10` (a disp32 memory operand) is what excludes the register-form `cmp eax, base`
// comparisons EmitRvvFpLaneMask and EmitRvvBodyMask emit, and `0f 86` excludes the frame guard's
// own `cmp [vec.vl], vlmax` + `ja` (0f 87).
struct BoundSeq {
	size_t imm_pos = 0;   // byte offset of the imm8 -- the only byte the placebo may change
	int imm = 0;          // the element index the bound compares vec.vl against
	int32_t rel32 = 0;    // the jbe displacement: the branch target distance
};

std::vector<BoundSeq> FindBoundSeqs(std::vector<u8> const &code)
{
	std::vector<BoundSeq> out;
	for (size_t i = 1; i + 8 < code.size(); ++i) {
		if (code[i] != 0x83u)
			continue;
		u8 const modrm = code[i + 1];
		if ((modrm & 0xC0u) != 0x80u || ((modrm >> 3) & 7u) != 7u)
			continue; // not `cmp r/m32, imm8` with a disp32 memory operand
		size_t const imm_pos = i + 2 + 4;
		if (imm_pos + 6 >= code.size())
			continue;
		if (code[imm_pos + 1] != 0x0fu || code[imm_pos + 2] != 0x86u)
			continue; // not followed by `jbe rel32`
		int32_t rel = 0;
		memcpy(&rel, &code[imm_pos + 3], 4);
		out.push_back(BoundSeq{imm_pos, (int)(int8_t)code[imm_pos], rel});
	}
	return out;
}

std::vector<InstVChunkActive *> Bounds(Frame const &f)
{
	std::vector<InstVChunkActive *> out;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkactive)
			out.push_back(static_cast<InstVChunkActive *>(i));
	return out;
}

// Every body node's OWN element index and mask width -- the quantities the placebo must not move.
// `ActiveChunkPlan::element_base()` feeds both the bound's immediate and the guarded unit's lane
// mask, so a placebo applied there instead of in the finalizer's insertion loop would shift the
// active lanes. That is wrong values, not a control, and this is what catches it.
std::vector<std::string> UnitGeometryKeys(Frame const &f)
{
	std::vector<std::string> out;
	char buf[96];
	for (auto *i : f.body) {
		switch (i->GetOpcode()) {
		case Op::_vchunkmaskset: {
			auto *n = static_cast<InstVChunkMaskSet *>(i);
			snprintf(buf, sizeof(buf), "maskset c=%u lanes=%u", n->chunk, n->lanes);
			out.push_back(buf);
			break;
		}
		case Op::_vstatechunkload: {
			auto *n = static_cast<InstVStateChunkLoad *>(i);
			snprintf(buf, sizeof(buf), "load offs=%u", (unsigned)n->offs);
			out.push_back(buf);
			break;
		}
		case Op::_vstatechunkstore: {
			auto *n = static_cast<InstVStateChunkStore *>(i);
			snprintf(buf, sizeof(buf), "store offs=%u sew=%u", (unsigned)n->offs,
				 (unsigned)n->active_sew);
			out.push_back(buf);
			break;
		}
		default:
			break;
		}
	}
	return out;
}

// ---------------------------------------------------------------------------------------------
// [8] The placebo arm's QIR body is arm C's, field for field, except the bound immediate.
// ---------------------------------------------------------------------------------------------
void Section8()
{
	printf("[8] arm P vs arm C: the QIR bodies differ in the bound IMMEDIATE only\n");
	auto const words = FpRunWords();
	Built bc, bp;
	Translate(bc, words, Env{.grouped = true, .run_bound = true});
	Translate(bp, words, Env{.grouped = true, .run_bound = true, .placebo = true});
	auto const fc = FindFrames(bc.region), fp = FindFrames(bp.region);
	auto const *rc = Widest(fc), *rp = Widest(fp);
	CHECK(rc != nullptr && rp != nullptr);
	if (!rc || !rp)
		return;

	// Same frame: same members, same component-major claim, same declared and census shape.
	CHECK_EQ(rc->begin->n_members, rp->begin->n_members);
	CHECK(rp->begin->body_component_major);
	CHECK_EQ(rc->begin->n_typed, rp->begin->n_typed);
	CHECK_EQ(rc->end->census_units, rp->end->census_units);
	CHECK_EQ(rc->end->census_prefix_units, rp->end->census_prefix_units);
	CHECK_EQ(rc->body.size(), rp->body.size());

	u32 const k = rc->end->census_units;
	auto const bounds_c = Bounds(*rc), bounds_p = Bounds(*rp);
	CHECK_EQ(bounds_c.size(), k);
	CHECK_EQ(bounds_p.size(), k);

	// THE SINGLE-FACTOR ASSERTION, twice over.
	// (a) With the bounds dropped the two bodies are identical -- so nothing OUTSIDE the bound
	//     nodes moved.
	CHECK(BodyKeys(*rc, /*drop_bounds=*/true) == BodyKeys(*rp, /*drop_bounds=*/true));
	// (b) The body nodes' own element bases and mask widths are identical -- so the planner's
	//     `element_base()` was not weakened, only the finalizer's copy of it.
	CHECK(UnitGeometryKeys(*rc) == UnitGeometryKeys(*rp));

	// Every bound: same position in the body, same chunk index, arm C's own element base, and
	// arm P's zero. "Every", not "some": a placebo that missed unit 0 would pass a spot check.
	unsigned nonzero_real = 0;
	for (size_t c = 0; c < bounds_c.size() && c < bounds_p.size(); ++c) {
		CHECK_EQ(bounds_c[c]->chunk, bounds_p[c]->chunk);
		CHECK_EQ(bounds_p[c]->element_base, 0u);
		nonzero_real += bounds_c[c]->element_base != 0;
	}
	// And arm C really did carry ascending non-zero bases, or the comparison above is vacuous.
	CHECK_EQ(nonzero_real, k - 1);
	for (size_t c = 1; c < bounds_c.size(); ++c)
		CHECK(bounds_c[c]->element_base > bounds_c[c - 1]->element_base);
	printf("    components=%u  C bases=", k);
	for (auto *b : bounds_c)
		printf("%u ", b->element_base);
	printf(" P bases=all zero  body=%zu nodes both arms\n", rc->body.size());
}

// ---------------------------------------------------------------------------------------------
// [9] The placebo arm's emitted bytes are arm C's, except one immediate byte per non-zero bound.
// ---------------------------------------------------------------------------------------------
void Section9()
{
	printf("[9] arm P vs arm C: same length, and only the bound immediates differ\n");
	auto const words = FpRunWords();
	auto const cc = EmitBytes(words, Env{.grouped = true, .run_bound = true});
	auto const pp = EmitBytes(words, Env{.grouped = true, .run_bound = true, .placebo = true});
	CHECK(!cc.empty());
	CHECK_EQ(cc.size(), pp.size());
	if (cc.size() != pp.size())
		return;

	// The bound sequences, located by encoding. Same count, same positions, same branch target
	// distances; only the immediates differ, and on arm P they are all zero.
	auto const sc = FindBoundSeqs(cc), sp = FindBoundSeqs(pp);
	CHECK(!sc.empty());
	CHECK_EQ(sc.size(), sp.size());
	unsigned expect_diffs = 0;
	for (size_t i = 0; i < sc.size() && i < sp.size(); ++i) {
		CHECK_EQ(sc[i].imm_pos, sp[i].imm_pos); // same byte offset -> nothing shifted
		CHECK_EQ(sc[i].rel32, sp[i].rel32);     // same branch target distance
		CHECK_EQ(sp[i].imm, 0);
		expect_diffs += sc[i].imm != 0;
	}

	// The byte-level difference, independently of the scanner: the differing positions are
	// exactly the non-zero bounds' immediate bytes, and patching them back reproduces arm C.
	std::vector<size_t> diffs;
	for (size_t i = 0; i < cc.size(); ++i)
		if (cc[i] != pp[i])
			diffs.push_back(i);
	CHECK_EQ(diffs.size(), expect_diffs);
	std::vector<u8> patched = pp;
	for (auto const &s : sc)
		patched[s.imm_pos] = (u8)s.imm;
	CHECK(patched == cc);
	for (size_t d : diffs) {
		bool named = false;
		for (auto const &s : sc)
			named |= s.imm_pos == d;
		CHECK(named); // every differing byte is a bound's imm8, not something else
	}

	// Switch-off: with the placebo clear the bytes ARE arm C's, bit for bit. (The pre-C4h arms
	// are covered by section [5]; this is the new switch's own inertness.)
	auto const cc_again = EmitBytes(words, Env{.grouped = true, .run_bound = true});
	CHECK(cc_again == cc);
	auto const b_off = EmitBytes(words, Env{.grouped = true, .run_bound = false});
	auto const b_placebo = EmitBytes(words, Env{.grouped = true, .run_bound = false,
						    .placebo = true});
	CHECK(b_off == b_placebo); // no bound node to weaken -> no effect at all
	printf("    %zu bytes both arms, %zu differing byte(s), all of them a bound imm8; "
	       "jbe rel32 unchanged\n",
	       cc.size(), diffs.size());
	// The sequences themselves, so the claim is readable and not merely asserted. Each is the
	// 8-byte `cmp dword ptr [R_STATE+disp32], imm8` followed by the 6-byte `jbe rel32`.
	for (size_t i = 0; i < sc.size(); ++i) {
		size_t const start = sc[i].imm_pos - 7; // REX .. imm8 is 8 bytes
		printf("      bound %zu @%+5zu  C:", i, start);
		for (size_t j = start; j < start + 14 && j < cc.size(); ++j)
			printf(" %02x", cc[j]);
		printf("\n                     P:");
		for (size_t j = start; j < start + 14 && j < pp.size(); ++j)
			printf(" %02x", pp[j]);
		printf("\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [10] The length-equivalence check is LIVE: an immediate >= 128 changes the encoding length.
// ---------------------------------------------------------------------------------------------
void Section10()
{
	printf("[10] negative control: an immediate >= 128 does NOT keep the length\n");
	auto const words = FpRunWords();
	Built ref, mut;
	Translate(ref, words, Env{.grouped = true, .run_bound = true});
	Translate(mut, words, Env{.grouped = true, .run_bound = true});
	// Mutate the highest bound's immediate past the signed-byte boundary. The value is not a
	// frame this family can build -- [11] proves that -- which is the point: it shows what the
	// equivalence in [9] is resting on, and that it is not resting on nothing.
	auto const fm = FindFrames(mut.region);
	auto const *rm = Widest(fm);
	CHECK(rm != nullptr);
	if (!rm)
		return;
	auto const bs = Bounds(*rm);
	CHECK(!bs.empty());
	if (bs.empty())
		return;
	u32 const real_base = bs.back()->element_base;
	bs.back()->element_base = 128u;
	Emit(ref);
	Emit(mut);
	CHECK(!ref.code.empty());
	// 8-byte `83 /7 ib` -> 11-byte `81 /7 id`: the block grows, so the arms are NOT comparable.
	CHECK(mut.code.size() != ref.code.size());
	CHECK_EQ(mut.code.size() - ref.code.size(), 3u);
	printf("    highest bound base %u -> 128: %zu bytes becomes %zu (+%zu) -- the gate can fail\n",
	       real_base, ref.code.size(), mut.code.size(), mut.code.size() - ref.code.size());
}

// ---------------------------------------------------------------------------------------------
// [11] Why this family never crosses that boundary. Measured over every legal VLEN, not argued.
// ---------------------------------------------------------------------------------------------
void Section11()
{
	printf("[11] every admitted grouped-run bound immediate is below the imm8 boundary\n");
	// The theorem, taken from the constants themselves rather than restated. TWO caps apply and
	// the claim holds under EITHER, so it does not depend on which one is currently binding:
	//
	//   * EMUL is pinned to 1, so a register spans at most `rvvrun::kMaxChunks` components;
	//   * a grouped body needs one RESIDENT per-component mask, so a component index must also
	//     be below `qir::RVV_FP_SHARED_MASK_MAX_CHUNKS` -- currently the binding one.
	//
	// A component holds at most 16 lanes: an FP host chunk is at most 64 bytes and FP SEW is 4 or
	// 8 bytes.
	static_assert(rvvrun::kMaxChunks == dbt::rv32::VLEN_MAX_BITS / 512,
		      "the component cap is VLEN_MAX / host chunk width");
	constexpr u32 kMaxLanes = 64u / 4u;
	constexpr u32 kCap = rvvrun::kMaxChunks < qir::RVV_FP_SHARED_MASK_MAX_CHUNKS
				 ? (u32)rvvrun::kMaxChunks
				 : (u32)qir::RVV_FP_SHARED_MASK_MAX_CHUNKS;
	static_assert((rvvrun::kMaxChunks - 1u) * kMaxLanes < 128u,
		      "an admitted grouped-run bound immediate must fit in a signed byte");
	static_assert((kCap - 1u) * kMaxLanes < 128u, "and under the binding cap too");

	// And the same claim as an observation on real frames: build the run at every legal VLEN and
	// read the largest immediate the finalizer actually produced.
	u32 max_base = 0, frames = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u}) {
		CHECK(dbt::rv32::vlen_supported(vlen));
		Built b;
		Translate(b, FpRunWords(),
			  Env{.vlen_bits = vlen, .grouped = true, .run_bound = true});
		auto const fs = FindFrames(b.region);
		auto const *r = Widest(fs);
		if (!r) {
			printf("      VLEN %4u: no run frame\n", vlen);
			continue;
		}
		auto const bs = Bounds(*r);
		if (bs.empty()) {
			// Either k == 1 (the grouped body is the identity, VLEN <= 512) or the
			// component count exceeds the resident-mask cap (VLEN 4096). Both are
			// refusals, and a refused frame carries no immediate to be equivalent about.
			printf("      VLEN %4u: run formed, no bound (k=%u)\n", vlen,
			       r->end->census_units);
			continue;
		}
		++frames;
		for (auto *bd : bs) {
			CHECK(bd->element_base < 128u);
			if (bd->element_base > max_base)
				max_base = bd->element_base;
		}
		// The emitted form agrees: every bound is the 8-byte `83 /7 ib` encoding, and the
		// immediate QEmit put there is the one the finalizer computed.
		Emit(b);
		auto const seqs = FindBoundSeqs(b.code);
		CHECK_EQ(seqs.size(), bs.size());
		for (size_t i = 0; i < seqs.size() && i < bs.size(); ++i)
			CHECK_EQ(seqs[i].imm, (int)bs[i]->element_base);
		printf("      VLEN %4u: k=%zu bounds, largest immediate %u\n", vlen, bs.size(),
		       bs.back()->element_base);
	}
	CHECK(frames >= 1); // a loop that found no bounded frame would prove nothing
	CHECK(max_base < 128u);
	CHECK(max_base <= (kCap - 1u) * kMaxLanes);
	printf("    %u VLEN(s) bounded; largest immediate observed %u, cap %u, boundary 128\n",
	       frames, max_base, (kCap - 1u) * kMaxLanes);
}

} // namespace

int main()
{
	printf("=== C4e: grouped component-major run body + optional active-suffix bound ===\n");
	Section1();
	Section2();
	Section3();
	Section4();
	Section56();
	Section7();
	printf("=== C4h: the evaluation-only placebo arm ===\n");
	Section8();
	Section9();
	Section10();
	Section11();
	if (g_failures) {
		printf("FAILED (%d)\n", g_failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
