// P1b: the COMMON FRAME FINALIZER's own invariants (dbt/guest/rv32_frame_semantics.h).
//
// P1a's transitional duplicate is gone: the finalizer is now the only semantic classifier and the
// only inserter of active-suffix bounds, so what is left to test here is the finalizer's own
// post-conditions -- the refusals it must make when what a producer built disagrees with what its
// own nodes say. The behaviour-preserving half of the claim lives in `rvv_p1b_freeze_test` and its
// two controlled measurements, not here.
//
//   [A] THE TEN PRODUCERS FINALIZE CLEANLY, at VLEN 512 and 1024 with the policies clear and set,
//       and really do carry bounds when the policies are set. A Panic aborts, so "this suite reached
//       its summary" IS the acceptance assertion; the frame and bound counts keep it from being
//       vacuous.
//
//   [B] A MALFORMED FRAME IS REFUSED, six ways, each with its own message. Every case hands the
//       finalizer a REAL translated body with one deliberately wrong input, so the body under test
//       is the one the translator really builds. Each runs in a child process and its stderr must
//       contain the specific message -- "the child died" would also be produced by an unrelated
//       crash or a different Panic. Two UNMUTATED controls run first: without them a finalizer that
//       refused everything would pass.
//
// OUT OF SCOPE: no other route, no eleventh family, no policy default is changed, nothing is timed.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_frame_semantics.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvfinal = dbt::rv32::rvvfinal;

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
// Guest encodings, taken field by field from rv32_decode.h's own conditions, never as magic words.
// The forms below are the ones the four accepted route suites already use.

constexpr u32 Vsetvli(u32 vsew, u32 vlmul)
{
	return ((0xc0u | (vsew << 3) | vlmul) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OPIVV = 0u, OPFVV = 1u, OPMVV = 2u, OPFVF = 5u;
constexpr u32 SEW8 = 0u, SEW16 = 1u, SEW32 = 2u, SEW64 = 3u;
constexpr u32 M1 = 0u, M2 = 1u;

constexpr u32 F6_VADD = 0b000000u;
constexpr u32 F6_VWADD = 0b110001u;
constexpr u32 F6_VNSRL = 0b101100u, F6_VNCLIP = 0b101111u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFMADD = 0b101000u;
constexpr u32 F6_VXUNARY0 = 0b010010u, F6_VMUNARY0 = 0b010100u;
constexpr u32 F6_VFUNARY0 = 0b010010u, F6_VFUNARY1 = 0b010011u, F6_VFMERGE = 0b010111u;
constexpr u32 EXT_ZVF2 = 6u;

// ---------------------------------------------------------------------------------------------
// ONE PROCESS-WIDE CODE BUFFER at a fixed address: [A2] compares two emitted streams for literal
// equality and an emitted region can embed the address of its own buffer. Nothing is executed.
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("semantic verifier test: emitted region exceeds the fixed code buffer");
		// Zeroed before every emission: the returned region is rounded up past the last
		// instruction, and in a shared buffer that padding is the previous translation's
		// bytes. The accepted family-closure suite records the same requirement.
		memset(g_code_buf, 0, sz);
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 512;
	bool policies_on = false;
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
	// All three policy switches move together here: this suite is about the verifier, and the
	// per-policy assignment is the accepted family-closure suite's subject, not this one's.
	config::rvv_qcg_active_vl_int_bound = e.policies_on;
	config::rvv_qcg_active_vl_bound = e.policies_on;
	config::rvv_qcg_active_vl_widen_bound = e.policies_on;
	config::rvv_qcg_active_vl_narrow_bound = true; // W28's ablation control at its default
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_fp_shared_mask = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_partial_vl = false;
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
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
	std::vector<int> opcodes;
};

void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			b.opcodes.push_back((int)ins.GetOpcode());
}

// Trailing zeros are trimmed for the reason the accepted family-closure suite records: the region
// is rounded up past the last instruction, so its final bytes are padding, not code.
void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	while (!b.code.empty() && b.code.back() == 0)
		b.code.pop_back();
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

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

// A Panic aborts, so every fail-closed contract runs in a child whose stderr is matched against the
// message that contract is supposed to produce. An abnormal exit alone would also be produced by an
// unrelated crash or by a DIFFERENT Panic. (The idiom is the accepted rvv_active_vl_bound_test's.)
void ExpectPanic(char const *what, char const *expect, std::function<void()> const &body)
{
	char path[] = "/tmp/p1a_verify_panic_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		Panic("semantic verifier test: mkstemp");
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
		printf("  ok   %-34s -> \"%s\"\n", what, expect);
	}
}

void ExpectNoPanic(char const *what, std::function<void()> const &body)
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
		fprintf(stderr, "  FAIL %s: expected a clean exit, child aborted\n", what);
		++g_failures;
	} else {
		printf("  ok   %-34s -> clean\n", what);
	}
}

// ---------------------------------------------------------------------------------------------
// [A] the ten producers.

struct Shape {
	char const *name;
	u32 vsew, vlmul;
	u32 op;
	bool multi_unit_at_512; // does this shape have >= 2 work units at VLEN 512?
};

Shape const kShapes[] = {
    // equal-width integer lane (the vchunkpartialalu block, which also serves the compare arm)
    {"vadd.vv     e32,m2", SEW32, M2, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV), true},
    // widening
    {"vwadd.vv    e16,m1", SEW16, M1, MakeOpV(F6_VWADD, 1, 10, 12, 8, OPMVV), true},
    // narrowing, both nodes: vnsrl uses InstVChunkNarrowShift, vnclip the partialalu clip arm
    {"vnsrl.wv    e16,m2", SEW16, M2, MakeOpV(F6_VNSRL, 1, 12, 10, 8, OPIVV), true},
    {"vnclip.wv   e16,m2", SEW16, M2, MakeOpV(F6_VNCLIP, 1, 12, 10, 8, OPIVV), true},
    // FP equal-width lane and FP fused multiply-add
    {"vfadd.vv    e32,m2", SEW32, M2, MakeOpV(F6_VFADD, 1, 10, 12, 8, OPFVV), true},
    {"vfmadd.vf   e32,m2", SEW32, M2, MakeOpV(F6_VFMADD, 1, 10, 3, 8, OPFVF), true},
    // the five W29 element-wise families
    {"vzext.vf2   e32,m2", SEW32, M2, MakeOpV(F6_VXUNARY0, 1, 12, EXT_ZVF2, 8, OPMVV), true},
    {"vfmerge.vfm e32,m2", SEW32, M2, MakeOpV(F6_VFMERGE, 0, 10, 3, 8, OPFVF), true},
    {"vfclass.v   e32,m2", SEW32, M2, MakeOpV(F6_VFUNARY1, 1, 10, 16, 8, OPFVV), true},
    {"vid.v       e32,m2", SEW32, M2, MakeOpV(F6_VMUNARY0, 1, 0, 17, 8, OPMVV), true},
    {"vfcvt.x.f.v e32,m2", SEW32, M2, MakeOpV(F6_VFUNARY0, 1, 10, 1, 8, OPFVV), true},
};

void TestAccept()
{
	printf("[A] ten producers x VLEN {512,1024} x policies {off,on}: the finalizer closes every\n"
	       "    frame and really inserts the bounds when the policies are set\n");
	unsigned frames_total = 0, bounds_total = 0;
	for (auto const &s : kShapes) {
		for (u32 vlen : {512u, 1024u}) {
			for (bool on : {false, true}) {
				std::vector<u32> const words = {Vsetvli(s.vsew, s.vlmul), s.op};
				Built b;
				Translate(b, words, Env{vlen, on});
				Emit(b);
				CHECK(!b.code.empty());
				auto const frames = FindFrames(b.region);
				CHECK_EQ(frames.size(), 1u);
				if (frames.empty())
					continue;
				frames_total += (unsigned)frames.size();
				unsigned const bounds = CountOp(frames[0], Op::_vchunkactive);
				bounds_total += bounds;
				// The finalizer is the only inserter, so this is also the check that it
				// ran at all on this shape.
				if (on && s.multi_unit_at_512)
					CHECK(bounds > 0);
				if (!on)
					CHECK_EQ(bounds, 0u);
			}
		}
	}
	printf("  ok   %u frames finalized, %u bounds inserted by the finalizer over %zu cells\n",
	       frames_total, bounds_total, sizeof(kShapes) / sizeof(kShapes[0]) * 2 * 2);
}

// ---------------------------------------------------------------------------------------------
// [B] malformed inputs to the finalizer.
//
// The equal-width e32/m2 frame at VLEN 512, re-derived here from the RVV geometry rather than read
// back from any planner: reg = 64 B, group = 128 B, host unit = min(64, 64) = 64 B, so 2 units of
// 64/4 = 16 elements each, and the last body node owns `vec.vstart = 0`.
constexpr u32 kUnits = 2, kUnitDestBytes = 64, kDestElemBytes = 4;

rvvfinal::FrameGeometry MakeGeom(bool enabled, u32 units, u32 unit_dest_bytes, u32 dest_elem_bytes,
				 rvvfinal::VStartOwner owner)
{
	return rvvfinal::FrameGeometry{
	    .policy_enabled = enabled,
	    .units = units,
	    .unit_dest_bytes = unit_dest_bytes,
	    .dest_element_bytes = dest_elem_bytes,
	    .static_full_vl_proved = false,
	    .per_unit_mask = true,
	    .vstart_owner = owner,
	};
}

// Translate the control shape with the policies CLEAR -- so its body carries no bound and its last
// node still owns the vstart write, i.e. exactly the state a producer hands the finalizer -- then
// hand that body back to the finalizer with `geom`, optionally after inserting `extra`.
void Refinalize(rvvfinal::FrameGeometry const &geom, bool policies_on,
		std::function<void(Builder &)> const &insert_extra)
{
	Built b;
	std::vector<u32> const words = {Vsetvli(SEW32, M2), MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV)};
	Translate(b, words, Env{512u, policies_on});
	auto const frames = FindFrames(b.region);
	if (frames.size() != 1)
		Panic("finalizer test: the control shape did not build exactly one frame");
	Builder qb(frames[0].bb, IListIterator<Inst>(frames[0].end));
	if (insert_extra)
		insert_extra(qb);
	rvvfinal::FinalizeFrame(qb, frames[0].begin, geom, words[1], RuntimeStubId::id_rv32_vialu);
}

void TestMalformed()
{
	printf("[B] six malformed inputs, each on a real translated body, each with its own message\n");
	auto const good = MakeGeom(true, kUnits, kUnitDestBytes, kDestElemBytes,
				   rvvfinal::VStartOwner::LastChunkNode);
	auto const good_off = MakeGeom(false, kUnits, kUnitDestBytes, kDestElemBytes,
				       rvvfinal::VStartOwner::LastChunkNode);

	// The controls FIRST: without them a finalizer that refused everything would pass [B].
	ExpectNoPanic("control: correct geometry, off", [&] { Refinalize(good_off, false, nullptr); });
	ExpectNoPanic("control: correct geometry, on", [&] { Refinalize(good, false, nullptr); });

	ExpectPanic("B1 geometry claims one unit too many",
		    "the emitted work-unit count disagrees with the geometry", [&] {
			    Refinalize(MakeGeom(true, kUnits + 1, kUnitDestBytes, kDestElemBytes,
						rvvfinal::VStartOwner::LastChunkNode),
				       false, nullptr);
		    });

	ExpectPanic("B2 geometry's element stride doubled",
		    "a unit's element base disagrees with the geometry", [&] {
			    Refinalize(MakeGeom(true, kUnits, kUnitDestBytes, kDestElemBytes / 2,
						rvvfinal::VStartOwner::LastChunkNode),
				       false, nullptr);
		    });

	ExpectPanic("B3 geometry claims the FP vstart owner",
		    "a FrameEpilogue frame carries a body-node vstart write", [&] {
			    Refinalize(MakeGeom(true, kUnits, kUnitDestBytes, kDestElemBytes,
						rvvfinal::VStartOwner::FrameEpilogue),
				       false, nullptr);
		    });

	// Mask logic is now eligible, but adding a work unit must still match the geometry.
	ExpectPanic("B4 an undeclared mask work unit in the body",
		    "the emitted work-unit count disagrees with the geometry", [&] {
			    Refinalize(good, false, [](Builder &qb) {
				    qb.Create_vmasklogic(0, 4096, 4104, 4112, 0, false);
			    });
		    });

	ExpectPanic("B5 a partial arm in a planner frame",
		    "the frame's nodes and guard do not support the declared reason", [&] {
			    Refinalize(good, false,
				       [](Builder &qb) { qb.Create_rvvtypedchunkpartial(); });
		    });

	ExpectPanic("B6 the body already carries a bound", "the body already carries a bound",
		    [&] { Refinalize(good, /*policies_on=*/true, nullptr); });
}

// ---------------------------------------------------------------------------------------------
// [D] P1c: no frame may bypass classification, and an unknown shape must fail closed.

void CloseWith(rvvfinal::FrameClose c, std::function<void(Builder &)> const &insert_extra)
{
	Built b;
	std::vector<u32> const words = {Vsetvli(SEW32, M2), MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV)};
	Translate(b, words, Env{512u, false});
	auto const frames = FindFrames(b.region);
	if (frames.size() != 1)
		Panic("finalizer test: the control shape did not build exactly one frame");
	Builder qb(frames[0].bb, IListIterator<Inst>(frames[0].end));
	if (insert_extra)
		insert_extra(qb);
	c.raw = words[1];
	c.stub = RuntimeStubId::id_rv32_vialu;
	rvvfinal::CloseFrame(qb, frames[0].begin, c);
}

void TestClassificationIsMandatory()
{
	printf("[D] P1c: every frame is classified, and an unknown shape fails closed\n");

	// The control: an ineligible frame closes cleanly when its declared reason is the one its
	// own nodes support. Without this, a close that refused everything would pass [D].
	ExpectNoPanic("control: partial-arm protocol, declared so", [&] {
		CloseWith({.reason = rvvfinal::Ineligibility::MemoryOrProtocol},
			  [](Builder &qb) { qb.Create_rvvtypedchunkpartial(); });
	});

	ExpectPanic("D1 no classification at all",
		    "a frame reached the common close without a classification",
		    [&] { CloseWith({.reason = rvvfinal::Ineligibility::Unclassified}, nullptr); });

	ExpectPanic("D2 a reason the nodes do not support",
		    "the frame's nodes and guard do not support the declared reason",
		    [&] { CloseWith({.reason = rvvfinal::Ineligibility::ScalarResult}, nullptr); });

	// The load-bearing P1c case: a node type the derivation table does not know must NOT be
	// treated as eligible. It is refused whether the frame claims to be a planner frame...
	ExpectPanic("D3 unknown node, declared eligible",
		    "unclassified node inside a finalized frame", [&] {
			    CloseWith({.reason = rvvfinal::Ineligibility::None,
				       .geom = MakeGeom(false, kUnits, kUnitDestBytes, kDestElemBytes,
							rvvfinal::VStartOwner::LastChunkNode)},
				      [](Builder &qb) { qb.Create_rvvrunscalar(0x00000013u); });
		    });
	// ... or claims an ineligibility its nodes do not establish.
	ExpectPanic("D4 unknown node, declared ineligible",
		    "the frame's nodes and guard do not support the declared reason", [&] {
			    CloseWith({.reason = rvvfinal::Ineligibility::MemoryOrProtocol},
				      [](Builder &qb) { qb.Create_rvvrunscalar(0x00000013u); });
		    });
}

} // namespace

int main()
{
	printf("P1b/P1c common frame close\n");
	TestAccept();
	TestMalformed();
	TestClassificationIsMandatory();
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASSED\n");
	return 0;
}
