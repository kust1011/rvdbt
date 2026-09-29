// C2l (2026-09-14): the materialize run body must be TOTAL over the member shapes the run
// classifier can admit, and its typed-op declaration must be the same switch its emission is.
//
// WHAT FAILED BEFORE THIS TEST EXISTED. C2j ran the frozen eight-cell materialize/SSA gate and all
// four materialize cells aborted on the same shift-dispatch Panic. The abort was a symptom of two
// independent defects: the materialize arm sent every non-FP member into a TWO-INPUT INTEGER ALU
// dispatch that has six cases, and it declared a single four-term formula that is wrong for seven
// of the fifteen member shapes. Both are now answered by one function, RvvMaterializeRunMember,
// and this file is the falsification harness for it.
//
// EVERY CHECK BELOW HAS A STATED FAILURE PATH, because an assertion that cannot fail is not
// evidence:
//
//   [0] COMPILE-TIME COVERAGE. `ExpectedOps` switches over `RunOp` with no `default:`, so adding a
//       route row without deciding this test's expected count does not COMPILE. It also pins
//       `kTypedAluRouteTableVersion`, so widening the table without revisiting the dispatcher does
//       not compile either. Failure path: add an enum value; the build breaks.
//   [1] COUNT == EMITTED, per shape, at VLEN 512 and 1024. The frame's declared `n_typed` is
//       compared against the number of nodes actually constructed between `begin` and `end`, and
//       BOTH are compared against the independently written table in [0]. Failure path: make any
//       dispatcher arm return a number that differs from the nodes it builds -- e.g. drop the
//       `+ 1` from the `.vx` broadcast, or restore the old `4 * m * k` formula -- and the
//       declared/emitted equality fails for that shape. This is the assertion that would have
//       caught the accounting half of the C2j defect at unit-test time.
//   [2] THE BODY SELECTOR MUST NOT SELECT THE POPULATION. The same guest words are translated with
//       `--rvv-run-body=ssa` and `=materialize` and the resulting run DESCRIPTORS are compared
//       field by field. Failure path: restore any `config::rvv_run_body_materialize` disjunct in
//       RvvRunMemberChunks and the member counts diverge -- which is exactly the state C2j found,
//       and the reason its G5 gate could not be evaluated.
//   [3] THE SHAPES THE OLD ARM COULD NOT LOWER AT ALL: the four move forms, the whole-register
//       transfer pair and the `.vx` multiply/accumulate pair, each with its exact node census.
//       Failure path: route a move through the integer ALU body again and the census (which
//       demands ZERO lane operations for a move) fails instead of Panicking at translation time.
//   [4] (C2m) THE DECLARATION PASS DIRECTLY, over every member shape x k in {1, 2, 4, 8}. Sections
//       [1]-[3] reach the dispatcher through a real translation, which pins it only at the k values
//       a supported VLEN produces (1 and 2 here) and only through descriptors FormRun happens to
//       build. This section calls RvvMaterializeRunMemberOps on a hand-built RunMember for each
//       shape, so every arm's count is checked against [0]'s table at every chunk count the frame
//       array admits. Failure path: change any arm's returned expression -- the `3k + 1` of a
//       broadcast source, the `2k` of a move or a whole-register transfer -- and the shape whose
//       expression changed fails at some k even if k == 1 still happens to agree.
//   [5] (C2m) THE FAIL-CLOSED BACKSTOPS, each in a forked child whose stderr must contain that
//       backstop's own message. These fire on descriptor field combinations FormRun does not
//       produce -- a `.vx` member whose rs1 is not a GPR, a member carrying two source-1 kinds, a
//       whole-register member whose direction and `defines_vd` disagree, `RunOp::None` -- so no
//       guest word reaches them and sections [1]-[4] cannot. Failure path: delete any one of those
//       checks and the dispatcher exits cleanly (or Panics with a different message) where this
//       section demands that exact abort. An abnormal exit alone is NOT accepted: an unrelated
//       crash would produce one too, so the message is matched.
//
//       WHAT THIS SECTION DOES NOT CLAIM. These are backstops, not a refusal policy. The fail-closed
//       rule this implementation actually relies on is compile-time ([0]) precisely because a
//       run-time refusal conditioned on the body selector would make the two arms form different
//       runs -- the defect [2] exists to catch.
//
// Nothing here names a workload, a guest PC, a threshold or an iteration count. Every input is an
// encoding and every expected number is derived from the member's shape.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_qir.h" // C2m: RvvMaterializeRunMemberOps, the declaration-pass hook
#include "dbt/guest/rv32_vector_lower.h" // the VF6_* funct6 constants
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
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
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// [0] The expected typed-op count per member SHAPE, written out independently of the dispatcher.
// ---------------------------------------------------------------------------------------------

// C2l pins the route table version here as well as beside the dispatcher, so that a widening which
// somehow skipped the production assert still cannot reach a green test run.
static_assert(rvvrun::kTypedAluRouteTableVersion == 4,
	      "route table widened: give the new row a materialize body and add its shape here");

// The fifteen shapes, counting each source-1 kind of a row as its own shape -- which is the level
// at which the typed-op count actually differs.
enum class Shape {
	Scalar,
	IntVV,	  // two vector sources
	ShiftVI,  // one vector source + a translation-time shift amount
	FAluVV,
	FAluVF,
	FmaVV,
	FmaVF,
	MulVX,
	MaccVX,
	MovV,
	MovX,
	MovI,
	MovF,
	LoadWhole,
	StoreWhole,
};

// THE TABLE. Derived from the member's shape and from nothing else; `k` is the run's host chunk
// count. It is deliberately NOT the dispatcher's expression rearranged -- it is the load/op/store
// census of each body, written from the body's own structure, so that the two agreeing is
// evidence rather than a tautology.
constexpr u32 ExpectedOps(Shape s, u32 k)
{
	switch (s) {
	case Shape::Scalar:
		return 1; // no vector chunk at all
	case Shape::IntVV:
		return 4 * k; // 2k loads + k lane ops + k stores
	case Shape::ShiftVI:
		return 3 * k; // k loads + k lane ops + k stores; the shift amount is an immediate
	case Shape::FAluVV:
		return 4 * k;
	case Shape::FAluVF:
		return 3 * k + 1; // one broadcast replaces the k vs1 loads
	case Shape::FmaVV:
		return 5 * k; // ... + k loads of the OLD vd
	case Shape::FmaVF:
		return 4 * k + 1;
	case Shape::MulVX:
		return 3 * k + 1; // 1 GPR broadcast + k vs2 loads + k multiplies + k stores
	case Shape::MaccVX:
		return 5 * k + 1; // ... + k old-vd loads + k adds
	case Shape::MovV:
		return 2 * k; // k loads + k stores, and NO lane operation
	case Shape::MovX:
	case Shape::MovI:
	case Shape::MovF:
		return k + 1; // 1 broadcast + k stores
	case Shape::LoadWhole:
	case Shape::StoreWhole:
		return 2 * k; // k source reads + k destination writes
	}
	return 0; // unreachable: the switch above is total over Shape
}

// THE ENUM-COVERAGE PIN. This function is never called; it exists so that adding a `RunOp` value
// without giving it a shape here is a build failure, exactly as adding one without giving it a body
// is a build failure inside RvvMaterializeRunMember. A run-time check could not do this: the new
// row's guest encoding would simply never appear in this file's words.
//
// C2m: dbt/CMakeLists.txt compiles THIS FILE and guest/rv32_qir.cpp with -Werror=switch. Without
// that the project's plain `-Wall` made both pins warnings, which is not a build failure and is not
// what either comment claimed.
[[maybe_unused]] constexpr bool EveryRunOpHasAShapeInThisTest(rvvrun::RunOp op)
{
	using rvvrun::RunOp;
	switch (op) {
	case RunOp::None: // never produced by FormRun; it is the descriptor's initial value
	case RunOp::Scalar:
	case RunOp::Add:
	case RunOp::Sub:
	case RunOp::Mul:
	case RunOp::Xor:
	case RunOp::Or:
	case RunOp::And:
	case RunOp::FAlu:
	case RunOp::FMA:
	case RunOp::Sll:
	case RunOp::Srl:
	case RunOp::Mov:
	case RunOp::MulX:
	case RunOp::MAccX:
	case RunOp::LoadWhole:
	case RunOp::StoreWhole:
		return true;
	}
	return false;
}

// ---------------------------------------------------------------------------------------------
// Encodings, field by field, in RVV 1.0's own layout.
// ---------------------------------------------------------------------------------------------
constexpr u32 F3_OPIVV = 0b000u, F3_OPFVV = 0b001u, F3_OPIVI = 0b011u, F3_OPMVV = 0b010u;
constexpr u32 F3_OPIVX = 0b100u, F3_OPFVF = 0b101u, F3_OPMVX = 0b110u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u, F6_VAND = 0b001001u;
constexpr u32 F6_VOR = 0b001010u, F6_VXOR = 0b001011u, F6_VMULVV = 0b100101u;
constexpr u32 F6_VSLL = 0b100101u, F6_VSRL = 0b101000u, F6_VMERGE = 0b010111u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFMUL = 0b100100u, F6_VFMADD = 0b101000u;

constexpr u32 OpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 f3, u32 vd)
{
	return 0b1010111u | (vd << 7) | (f3 << 12) | (src1 << 15) | (vs2 << 20) | (vm << 25) |
	       (f6 << 26);
}
constexpr u32 Iv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return OpV(f6, 1, vs2, vs1, F3_OPIVV, vd); }
constexpr u32 Mv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return OpV(f6, 1, vs2, vs1, F3_OPMVV, vd); }
constexpr u32 Vsll(u32 vd, u32 vs2, u32 uimm) { return OpV(F6_VSLL, 1, vs2, uimm, F3_OPIVI, vd); }
constexpr u32 Vsrl(u32 vd, u32 vs2, u32 uimm) { return OpV(F6_VSRL, 1, vs2, uimm, F3_OPIVI, vd); }
constexpr u32 Fvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return OpV(f6, 1, vs2, vs1, F3_OPFVV, vd); }
constexpr u32 Fvf(u32 f6, u32 vd, u32 vs2, u32 rs1) { return OpV(f6, 1, vs2, rs1, F3_OPFVF, vd); }
constexpr u32 Vmx(u32 f6, u32 vd, u32 vs2, u32 rs1) { return OpV(f6, 1, vs2, rs1, F3_OPMVX, vd); }
constexpr u32 VmvVV(u32 vd, u32 vs1) { return OpV(F6_VMERGE, 1, 0, vs1, F3_OPIVV, vd); }
constexpr u32 VmvVX(u32 vd, u32 rs1) { return OpV(F6_VMERGE, 1, 0, rs1, F3_OPIVX, vd); }
constexpr u32 VmvVI(u32 vd, u32 imm) { return OpV(F6_VMERGE, 1, 0, imm & 0x1fu, F3_OPIVI, vd); }
constexpr u32 VfmvVF(u32 vd, u32 fs1) { return OpV(F6_VMERGE, 1, 0, fs1, F3_OPFVF, vd); }
constexpr u32 VlNre32(u32 nf, u32 rs1, u32 vd)
{
	return 0b0000111u | (vd << 7) | (0b110u << 12) | (rs1 << 15) | (0b01000u << 20) |
	       (1u << 25) | ((nf - 1) << 29);
}
constexpr u32 VsNr(u32 nf, u32 rs1, u32 vs3)
{
	return 0b0100111u | (vs3 << 7) | (rs1 << 15) | (0b01000u << 20) | (1u << 25) |
	       ((nf - 1) << 29);
}
// vsetvli rd, x0, e32, m1, ta, ma -- establishes the block's observed vtype.
constexpr u32 VSetVli(u32 rd) { return 0b1010111u | (rd << 7) | (0b111u << 12) | (0xd0u << 20); }

// THE ENCODER IS PINNED, so a mistyped field order fails to compile rather than silently changing
// which instruction each case is about. Every word below is cross-checked against the same word in
// an already-accepted test file.
static_assert(VSetVli(6) == 0x0d007357u, "vsetvli t1,zero,e32,m1,ta,ma");
static_assert(VlNre32(1, 14, 8) == 0x02876407u, "vl1re32.v v8,(a4)");
static_assert(VsNr(1, 14, 8) == 0x02870427u, "vs1r.v v8,(a4)");
static_assert(Vmx(dbt::rv32::VF6_VMUL, 8, 8, 11) == 0x9685e457u, "vmul.vx v8,v8,a1");
static_assert(Vmx(dbt::rv32::VF6_VMACC, 9, 8, 23) == 0xb68be4d7u, "vmacc.vx v9,s7,v8");
static_assert(VmvVV(9, 8) == 0x5e0404d7u, "vmv.v.v v9,v8");
static_assert(VmvVI(8, 5) == 0x5e02b457u, "vmv.v.i v8,5");
static_assert(Iv(F6_VADD, 3, 1, 2) == 0x021101d7u, "vadd.vv v3,v1,v2");

// ---------------------------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------------------------
struct Env {
	u32 vlen = 512;
	bool materialize = false;
	bool scalar_passthrough = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = e.materialize;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_component_demand_placement = false;
	config::rvv_run_grouped_component_major = false;
	config::rvv_run_scalar_passthrough = e.scalar_passthrough;
	// Every element-wise route this file needs, with its audit-only force-emit so the shapes are
	// inspectable on a host without AVX-512. Nothing here is a workload constant.
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_typed_chunk_vmv = true;
	config::rvv_qcg_typed_chunk_vmv_force_emit = true;
	config::rvv_qcg_whole_reg = true;
	config::rvv_qcg_whole_reg_force_emit = true;
	config::rvv_qcg_vx_mulacc = true;
	config::rvv_qcg_vx_mulacc_force_emit = true;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_active_vl_run_bound = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
};

void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};

std::vector<Frame> FindFrames(Region *r)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
			} else if (ins.GetOpcode() == Op::_rvvtypedchunkend) {
				if (open) {
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					out.push_back(cur);
					open = false;
				}
			} else if (open) {
				cur.body.push_back(&ins);
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

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

// ---------------------------------------------------------------------------------------------
// [1] Per-shape: the declaration, the emission and the independent table must all agree.
// ---------------------------------------------------------------------------------------------
struct Case {
	char const *name;
	std::vector<u32> words;	 // WITHOUT the leading vsetvli, which is added here
	std::vector<Shape> shapes; // the run's members, in guest order
};

void CheckCase(Case const &c, u32 vlen)
{
	u32 const k = vlen / 512u; // every route in this file uses the 64-byte host chunk
	std::vector<u32> words = {VSetVli(6)};
	words.insert(words.end(), c.words.begin(), c.words.end());

	Built b;
	Translate(b, words, Env{vlen, /*materialize=*/true});
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f || f->begin->n_members != c.shapes.size()) {
		fprintf(stderr, "  FAIL %s vlen=%u: expected a %zu-member run, got %d\n", c.name,
			vlen, c.shapes.size(), f ? (int)f->begin->n_members : -1);
		++g_failures;
		return;
	}
	u32 expect = 0;
	for (Shape s : c.shapes)
		expect += ExpectedOps(s, k);
	// The FP bracket is a property of the FRAME, not of any member, and both body modes emit it,
	// so it is added here rather than to any shape's row.
	expect += CountOp(*f, Op::_rvvqcgfpbegin) + CountOp(*f, Op::_rvvqcgfpend);
	// ... and so are the FP frame's shared active masks.
	expect += CountOp(*f, Op::_vchunkmaskset);

	// (a) THE DECLARATION MATCHES THE INDEPENDENT TABLE. Fails if any dispatcher arm returns a
	//     different number from the one this file's census of that body says it should.
	if ((u32)f->begin->n_typed != expect)
		fprintf(stderr, "  [%s vlen=%u] declared %u, table says %u\n", c.name, vlen,
			(unsigned)f->begin->n_typed, expect);
	CHECK_EQ((u32)f->begin->n_typed, expect);
	// (b) THE EMISSION MATCHES THE DECLARATION. This is the anti-drift assertion: it counts the
	//     nodes actually constructed, so a body that builds more or fewer than it declared fails
	//     HERE instead of at Emit_rvvtypedchunkend, which no unit test reaches.
	if ((u32)f->body.size() != (u32)f->begin->n_typed)
		fprintf(stderr, "  [%s vlen=%u] declared %u, emitted %zu\n", c.name, vlen,
			(unsigned)f->begin->n_typed, f->body.size());
	CHECK_EQ((u32)f->body.size(), (u32)f->begin->n_typed);
}

// The case list. Each run is at least two members, because a one-member "run" is not lowered as a
// run; the second member is always a plain integer add whose own contribution the table covers.
std::vector<Case> AllCases()
{
	using S = Shape;
	std::vector<Case> cs;
	// The six two-input integer rows, one run.
	cs.push_back({"int .vv x6",
		      {Iv(F6_VADD, 9, 8, 8), Iv(F6_VSUB, 10, 9, 8), Mv(F6_VMULVV, 11, 10, 9),
		       Iv(F6_VXOR, 12, 11, 10), Iv(F6_VOR, 13, 12, 11), Iv(F6_VAND, 14, 13, 12)},
		      {S::IntVV, S::IntVV, S::IntVV, S::IntVV, S::IntVV, S::IntVV}});
	// The two shift-immediate rows -- the shape whose missing call C2j aborted on.
	cs.push_back({"shift .vi x2 + add",
		      {Vsll(9, 8, 3), Vsrl(10, 9, 7), Iv(F6_VADD, 11, 10, 9)},
		      {S::ShiftVI, S::ShiftVI, S::IntVV}});
	// The four FP shapes. `.vf` sources an F register; the fused forms read vd.
	cs.push_back({"vfalu .vv/.vf",
		      {Fvv(F6_VFADD, 9, 8, 8), Fvf(F6_VFMUL, 10, 9, 15)},
		      {S::FAluVV, S::FAluVF}});
	cs.push_back({"vfma .vv/.vf",
		      {Fvv(F6_VFMADD, 9, 8, 8), Fvf(F6_VFMADD, 10, 9, 15)},
		      {S::FmaVV, S::FmaVF}});
	// The OPMVX pair: the shape whose `rs1` is a GPR NUMBER, which the old arm would have read
	// as vector register #rs1 had the shift not aborted first.
	cs.push_back({"vmul.vx + vmacc.vx",
		      {Vmx(dbt::rv32::VF6_VMUL, 9, 8, 11), Vmx(dbt::rv32::VF6_VMACC, 10, 9, 11)},
		      {S::MulVX, S::MaccVX}});
	// The four move forms plus an arithmetic member.
	cs.push_back({"mov v/x/i/f + add",
		      {VmvVI(8, 5), VmvVX(9, 11), VfmvVF(10, 12), VmvVV(11, 9),
		       Iv(F6_VADD, 12, 8, 11)},
		      {S::MovI, S::MovX, S::MovF, S::MovV, S::IntVV}});
	// The whole-register transfer pair around a `.vx` multiply: the run shape G1 exists for.
	cs.push_back({"vl1re32 + vmul.vx + vs1r",
		      {VlNre32(1, 14, 8), Vmx(dbt::rv32::VF6_VMUL, 8, 8, 11), VsNr(1, 14, 8)},
		      {S::LoadWhole, S::MulVX, S::StoreWhole}});
	return cs;
}

void CheckAllShapes()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &c : AllCases())
			CheckCase(c, vlen);
}

// The scalar passthrough member, which needs its own switch and therefore its own case.
void CheckScalarMember(u32 vlen)
{
	u32 const k = vlen / 512u;
	Built b;
	// `addi a1,a1,1` between two vector members: a non-trapping scalar integer update carried
	// through the run.
	std::vector<u32> const words = {VSetVli(6), Iv(F6_VADD, 9, 8, 8), 0x00158593u,
					Iv(F6_VADD, 10, 9, 8)};
	Translate(b, words, Env{vlen, /*materialize=*/true, /*scalar_passthrough=*/true});
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f || f->begin->n_members != 3) {
		fprintf(stderr, "  FAIL scalar member vlen=%u: expected a 3-member run, got %d\n",
			vlen, f ? (int)f->begin->n_members : -1);
		++g_failures;
		return;
	}
	u32 const expect = ExpectedOps(Shape::IntVV, k) + ExpectedOps(Shape::Scalar, k) +
			   ExpectedOps(Shape::IntVV, k);
	CHECK_EQ((u32)f->begin->n_typed, expect);
	CHECK_EQ((u32)f->body.size(), (u32)f->begin->n_typed);
	CHECK_EQ(CountOp(*f, Op::_rvvrunscalar), 1u);
}

// ---------------------------------------------------------------------------------------------
// [2] The body selector must not change the run that is formed.
// ---------------------------------------------------------------------------------------------
void CheckRunShapeInvariant(Case const &c, u32 vlen)
{
	std::vector<u32> words = {VSetVli(6)};
	words.insert(words.end(), c.words.begin(), c.words.end());
	Built b[2];
	for (int m = 0; m < 2; ++m)
		Translate(b[m], words, Env{vlen, /*materialize=*/m == 1});
	auto const f0 = FindFrames(b[0].region), f1 = FindFrames(b[1].region);
	auto const *ssa = Widest(f0);
	auto const *mat = Widest(f1);
	if (!ssa || !mat) {
		fprintf(stderr, "  FAIL runshape %s vlen=%u: a frame is missing (%s)\n", c.name,
			vlen, ssa ? "materialize" : "ssa");
		++g_failures;
		return;
	}
	// The DESCRIPTOR's observable projection onto the frame node. If admission ever reads the
	// body selector again -- the defect the C2j G5 gate could not evaluate -- the member counts
	// are the first thing to diverge.
	CHECK_EQ((unsigned)ssa->begin->n_members, (unsigned)mat->begin->n_members);
	CHECK_EQ((unsigned)ssa->begin->n_members, (unsigned)c.shapes.size());
	CHECK_EQ((unsigned)ssa->begin->guard_kind, (unsigned)mat->begin->guard_kind);
	CHECK_EQ(ssa->begin->vtype, mat->begin->vtype);
	CHECK_EQ(ssa->begin->vlmax, mat->begin->vlmax);
	CHECK_EQ(ssa->begin->base_state_mask, mat->begin->base_state_mask);
	CHECK_EQ(ssa->begin->base_limit, mat->begin->base_limit);
	// ... and the member list itself, guest PC by guest PC. A body that reordered members would
	// break the whole-register pair's memory ordering, so this is a correctness assertion and
	// not only a bookkeeping one.
	if (ssa->begin->n_members != mat->begin->n_members)
		return;
	for (u8 i = 0; i < ssa->begin->n_members; ++i) {
		CHECK_EQ(ssa->end->members[i].pc, mat->end->members[i].pc);
		CHECK_EQ(ssa->end->members[i].raw, mat->end->members[i].raw);
		CHECK_EQ((unsigned)ssa->end->members[i].stub,
			 (unsigned)mat->end->members[i].stub);
	}
	// The two bodies must NOT be the same size: materialize hands intermediate values through
	// CPUState and re-broadcasts scalar sources per member. If this ever held, the two
	// arms would be the same body and the ablation would have no factor at all.
	CHECK(ssa->begin->n_typed != mat->begin->n_typed);
}

void CheckAllRunShapesInvariant()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &c : AllCases())
			CheckRunShapeInvariant(c, vlen);
}

// ---------------------------------------------------------------------------------------------
// [3] The shapes the old materialize arm could not lower at all, with their exact node census.
// ---------------------------------------------------------------------------------------------
void CheckMoveMaterialize(u32 vlen)
{
	unsigned const k = vlen / 512u;
	Built b;
	Translate(b,
		  {VSetVli(6), VmvVI(8, 5), VmvVX(9, 11), VfmvVF(10, 12), VmvVV(11, 9),
		   Iv(F6_VADD, 12, 8, 11)},
		  Env{vlen, /*materialize=*/true});
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL move materialize vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 5u);
	// ONE broadcast per BROADCAST MEMBER -- not per frame, which is the SSA body's rule and the
	// measurable difference between the two arms.
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 2u);  // vmv.v.i and vmv.v.x
	CHECK_EQ(CountOp(*f, Op::_vchunkfbroadcast), 1u); // vfmv.v.f
	// A MOVE HAS NO LANE ARITHMETIC. Only the add does, and it does it once per chunk. This is
	// the assertion that fails if a move is ever routed back through the integer ALU body.
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), k);
	// vmv.v.v reads its k source chunks; the add reads its two sources' k chunks each.
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), 3u * k);
	// every member writes its vd once per chunk, because that is what materializing means
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), 5u * k);
	CHECK_EQ((u32)f->begin->n_typed, 3u * (k + 1u) + 2u * k + 4u * k);
}

void CheckWholeRegMaterialize(u32 vlen)
{
	unsigned const k = vlen / 512u;
	Built b;
	Translate(b,
		  {VSetVli(6), VlNre32(1, 14, 8), Vmx(dbt::rv32::VF6_VMUL, 8, 8, 11),
		   VsNr(1, 14, 8)},
		  Env{vlen, /*materialize=*/true});
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL whole-reg materialize vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 3u);
	// The memory frames' base-range guard, unchanged by the body selector.
	CHECK_EQ((unsigned)f->begin->guard_kind,
		 (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit);
	// THE ROUND TRIP IS THE POINT. Materializing means the load writes CPUState and the multiply
	// reads it back, so there is one guest-memory access per chunk per memory member and the
	// CPUState traffic is what the SSA arm removes.
	CHECK_EQ(CountOp(*f, Op::_vchunkload), k);  // the whole-register load's memory reads
	CHECK_EQ(CountOp(*f, Op::_vchunkstore), k); // the whole-register store's memory writes
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 1u); // the .vx member's scalar
	CHECK_EQ(CountOp(*f, Op::_vchunkmul), k);
	// loads of CPUState: the multiply's vs2 (k) and the store's source (k). The whole-register
	// LOAD reads memory, not state.
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), 2u * k);
	// stores to CPUState: the load's destination (k) and the multiply's vd (k).
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), 2u * k);
	CHECK_EQ((u32)f->begin->n_typed, 2u * k + (3u * k + 1u) + 2u * k);
}

void CheckVxMaterialize(u32 vlen)
{
	unsigned const k = vlen / 512u;
	Built b;
	Translate(b,
		  {VSetVli(6), Vmx(dbt::rv32::VF6_VMUL, 9, 8, 11),
		   Vmx(dbt::rv32::VF6_VMACC, 10, 9, 11)},
		  Env{vlen, /*materialize=*/true});
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL vx materialize vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 2u);
	// ONE broadcast PER MEMBER even though both read the same GPR: that re-broadcast is part of
	// what the ablation measures, and stating it here keeps it from being described later as
	// "purely k CPUState reloads".
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 2u);
	CHECK_EQ(CountOp(*f, Op::_vchunkmul), 2u * k);
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), k); // the accumulate's add only
	// vmul reads vs2 (k); vmacc reads vs2 (k) AND its old vd (k).
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), 3u * k);
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), 2u * k);
	CHECK_EQ((u32)f->begin->n_typed, (3u * k + 1u) + (5u * k + 1u));
}

void CheckVxBodyCensus(u32 vlen)
{
	unsigned const k = vlen / 512u;
	std::vector<u32> const words = {VSetVli(6), Vmx(dbt::rv32::VF6_VMUL, 9, 8, 11),
					 Vmx(dbt::rv32::VF6_VMACC, 10, 9, 11)};
	Built b[2];
	for (int m = 0; m < 2; ++m)
		Translate(b[m], words, Env{vlen, /*materialize=*/m == 1});
	auto const sf = FindFrames(b[0].region), mf = FindFrames(b[1].region);
	auto const *ssa = Widest(sf);
	auto const *mat = Widest(mf);
	if (!ssa || !mat) {
		fprintf(stderr, "  FAIL vx body census vlen=%u: missing frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)ssa->begin->n_members, (unsigned)mat->begin->n_members);
	unsigned const ml = CountOp(*mat, Op::_vstatechunkload);
	unsigned const sl = CountOp(*ssa, Op::_vstatechunkload);
	unsigned const ms = CountOp(*mat, Op::_vstatechunkstore);
	unsigned const ss = CountOp(*ssa, Op::_vstatechunkstore);
	unsigned const mb = CountOp(*mat, Op::_vchunkbroadcast);
	unsigned const sb = CountOp(*ssa, Op::_vchunkbroadcast);
	CHECK_EQ(ml, 3u * k);
	CHECK(sl < ml);
	CHECK(ss <= ms);
	CHECK_EQ(mb, 2u);
	CHECK_EQ(sb, 1u);
	CHECK_EQ(CountOp(*mat, Op::_vchunkmul), CountOp(*ssa, Op::_vchunkmul));
	CHECK_EQ(CountOp(*mat, Op::_vchunkadd), CountOp(*ssa, Op::_vchunkadd));
	printf("  vx census vlen=%u M/S0 CPUState loads=%u/%u stores=%u/%u broadcasts=%u/%u\n",
	       vlen, ml, sl, ms, ss, mb, sb);
}

void CheckWholeRegBodyCensus(u32 vlen)
{
	unsigned const k = vlen / 512u;
	std::vector<u32> const words = {VSetVli(6), VlNre32(1, 14, 8),
					 Vmx(dbt::rv32::VF6_VMUL, 8, 8, 11), VsNr(1, 14, 8)};
	Built b[2];
	for (int m = 0; m < 2; ++m)
		Translate(b[m], words, Env{vlen, /*materialize=*/m == 1});
	auto const sf = FindFrames(b[0].region), mf = FindFrames(b[1].region);
	auto const *ssa = Widest(sf);
	auto const *mat = Widest(mf);
	if (!ssa || !mat) {
		fprintf(stderr, "  FAIL whole-reg body census vlen=%u: missing frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)ssa->begin->n_members, (unsigned)mat->begin->n_members);
	unsigned const ml = CountOp(*mat, Op::_vstatechunkload);
	unsigned const sl = CountOp(*ssa, Op::_vstatechunkload);
	unsigned const ms = CountOp(*mat, Op::_vstatechunkstore);
	unsigned const ss = CountOp(*ssa, Op::_vstatechunkstore);
	CHECK_EQ(ml, 2u * k);
	CHECK_EQ(sl, 0u);
	CHECK_EQ(ms, 2u * k);
	CHECK_EQ(ss, k);
	CHECK_EQ(CountOp(*mat, Op::_vchunkload), CountOp(*ssa, Op::_vchunkload));
	CHECK_EQ(CountOp(*mat, Op::_vchunkstore), CountOp(*ssa, Op::_vchunkstore));
	CHECK_EQ(CountOp(*mat, Op::_vchunkmul), CountOp(*ssa, Op::_vchunkmul));
	printf("  whole-reg census vlen=%u M/S0 CPUState loads=%u/%u stores=%u/%u\n",
	       vlen, ml, sl, ms, ss);
}

// ---------------------------------------------------------------------------------------------
// [4] C2m: the declaration pass directly, per shape, at every chunk count the frame array admits.
// ---------------------------------------------------------------------------------------------

// A member carrying exactly the shape fields the dispatcher reads for `s`, and nothing else. The
// register numbers are arbitrary and deliberately distinct: the DECLARATION pass must not depend on
// them, so a dispatcher arm that started counting from `rd == rs2` would still be asked for the
// same number here.
rvvrun::RunMember MemberFor(Shape s, u8 k)
{
	using rvvrun::RunOp;
	rvvrun::RunMember m{};
	m.pc = 0x1000u;
	m.rd = 9;
	m.rs1 = 8;
	m.rs2 = 7;
	m.sew_bytes = 4;
	m.nchunks = k;
	m.chunk_bytes = 64;
	switch (s) {
	case Shape::Scalar:
		m.op = RunOp::Scalar;
		m.raw = 0x00158593u; // addi a1,a1,1
		break;
	case Shape::IntVV:
		m.op = RunOp::Add;
		break;
	case Shape::ShiftVI:
		m.op = RunOp::Sll;
		m.rs1 = 3; // the shift AMOUNT, not a register number
		m.src1_is_imm5 = true;
		break;
	case Shape::FAluVV:
		m.op = RunOp::FAlu;
		m.fp_host_arith = true;
		break;
	case Shape::FAluVF:
		m.op = RunOp::FAlu;
		m.fp_host_arith = true;
		m.src1_is_fscalar = true;
		break;
	case Shape::FmaVV:
		m.op = RunOp::FMA;
		m.fp_host_arith = true;
		m.reads_vd = true;
		break;
	case Shape::FmaVF:
		m.op = RunOp::FMA;
		m.fp_host_arith = true;
		m.src1_is_fscalar = true;
		m.reads_vd = true;
		break;
	case Shape::MulVX:
		m.op = RunOp::MulX;
		m.src1_is_xscalar = true;
		break;
	case Shape::MaccVX:
		m.op = RunOp::MAccX;
		m.src1_is_xscalar = true;
		m.reads_vd = true;
		break;
	case Shape::MovV:
		m.op = RunOp::Mov;
		m.src2_is_vector = false;
		break;
	case Shape::MovX:
		m.op = RunOp::Mov;
		m.src1_is_xscalar = true;
		m.src2_is_vector = false;
		break;
	case Shape::MovI:
		m.op = RunOp::Mov;
		m.src1_is_simm5 = true;
		m.src2_is_vector = false;
		break;
	case Shape::MovF:
		m.op = RunOp::Mov;
		m.src1_is_fscalar = true;
		m.src2_is_vector = false;
		break;
	case Shape::LoadWhole:
		m.op = RunOp::LoadWhole;
		m.src1_is_xbase = true;
		m.src2_is_vector = false;
		m.defines_vd = true;
		break;
	case Shape::StoreWhole:
		m.op = RunOp::StoreWhole;
		m.src1_is_xbase = true;
		m.src2_is_vector = false;
		m.defines_vd = false;
		break;
	}
	return m;
}

char const *ShapeName(Shape s)
{
	switch (s) {
	case Shape::Scalar: return "Scalar";
	case Shape::IntVV: return "IntVV";
	case Shape::ShiftVI: return "ShiftVI";
	case Shape::FAluVV: return "FAluVV";
	case Shape::FAluVF: return "FAluVF";
	case Shape::FmaVV: return "FmaVV";
	case Shape::FmaVF: return "FmaVF";
	case Shape::MulVX: return "MulVX";
	case Shape::MaccVX: return "MaccVX";
	case Shape::MovV: return "MovV";
	case Shape::MovX: return "MovX";
	case Shape::MovI: return "MovI";
	case Shape::MovF: return "MovF";
	case Shape::LoadWhole: return "LoadWhole";
	case Shape::StoreWhole: return "StoreWhole";
	}
	return "?";
}

void CheckDeclarationPassPerShape()
{
	using T = qir::rv32::RV32Translator;
	Shape const all[] = {Shape::Scalar,	Shape::IntVV,  Shape::ShiftVI, Shape::FAluVV,
			     Shape::FAluVF,	Shape::FmaVV,  Shape::FmaVF,   Shape::MulVX,
			     Shape::MaccVX,	Shape::MovV,   Shape::MovX,    Shape::MovI,
			     Shape::MovF,	Shape::LoadWhole, Shape::StoreWhole};
	// Every k the frame's per-chunk arrays admit (rvvrun::kMaxChunks == 8), not only the two a
	// supported VLEN produces in sections [1]-[3].
	for (u8 k : {(u8)1, (u8)2, (u8)4, (u8)8}) {
		for (Shape s : all) {
			auto const m = MemberFor(s, k);
			u32 const got = T::RvvMaterializeRunMemberOps(m, k, 64);
			u32 const want = ExpectedOps(s, k);
			if (got != want)
				fprintf(stderr, "  FAIL decl %s k=%u: dispatcher %u, table %u\n",
					ShapeName(s), (unsigned)k, got, want);
			CHECK_EQ(got, want);
		}
	}
	printf("  ok   declaration pass: 15 shapes x k in {1,2,4,8} agree with the table\n");
}

// ---------------------------------------------------------------------------------------------
// [5] C2m: the fail-closed backstops, each matched on its own Panic message.
// ---------------------------------------------------------------------------------------------

// A Panic aborts, so each backstop runs in a child whose stderr the parent matches. An abnormal
// exit alone would also be produced by an unrelated crash or by a DIFFERENT Panic, so the message
// is required. Same shape as rvv_active_vl_bound_test.cpp's ExpectPanic, for the same reason.
void ExpectPanic(char const *what, char const *expect, rvvrun::RunMember const &m, u8 k)
{
	char path[] = "/tmp/rvv_mat_panic_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  FAIL %s: mkstemp\n", what);
		++g_failures;
		return;
	}
	fflush(stdout);
	fflush(stderr);
	pid_t const pid = fork();
	if (pid == 0) {
		dup2(fd, 2);
		close(fd);
		// The result is deliberately consumed: the contract is that this call does not RETURN.
		u32 const n = qir::rv32::RV32Translator::RvvMaterializeRunMemberOps(m, k, 64);
		fprintf(stderr, "returned %u instead of panicking\n", n);
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
		printf("  ok   %s -> \"%s\"\n", what, expect);
	}
}

void CheckFailClosedBackstops()
{
	u8 const k = 2;
	{
		// An integer member that claims the frame's FP bracket. The bracket is a property of the
		// FRAME, opened by the caller, so a member on which the two disagree means the body about
		// to run is not the one the frame was built for.
		auto m = MemberFor(Shape::IntVV, k);
		m.fp_host_arith = true;
		ExpectPanic("integer member claims the FP bracket",
			    "member's FP bracket flag disagrees with its route", m, k);
	}
	{
		// ... and the mirror: an FP member that does not.
		auto m = MemberFor(Shape::FAluVV, k);
		m.fp_host_arith = false;
		ExpectPanic("FP member without the FP bracket flag",
			    "member's FP bracket flag disagrees with its route", m, k);
	}
	{
		// Two source-1 kinds at once. The four are different funct3 groups and cannot both be
		// true, which is CHECKED rather than assumed -- deriving `src1_kind` from a priority
		// chain over flags that silently overlapped would pick one and lower the other's operand.
		auto m = MemberFor(Shape::MovX, k);
		m.src1_is_simm5 = true;
		ExpectPanic("move member with two source-1 kinds",
			    "member has more than one source-1 kind", m, k);
	}
	{
		// A shift whose rs1 is not an immediate. `rs1` carries the shift AMOUNT for these rows,
		// so without the flag the body would shift by a register NUMBER.
		auto m = MemberFor(Shape::ShiftVI, k);
		m.src1_is_imm5 = false;
		ExpectPanic("shift member whose rs1 is not an immediate",
			    "a shift member's rs1 is not an immediate", m, k);
	}
	{
		// THE SECOND DEFECT C2j's abort was hiding, as an assertion. A `.vx` member's rs1 is a
		// GPR number; the old arm passed the default source-1 kind (Vector), which would have
		// read VECTOR REGISTER #rs1 -- structurally perfect, wrong-valued code.
		auto m = MemberFor(Shape::MulVX, k);
		m.src1_is_xscalar = false;
		ExpectPanic("`.vx` member whose rs1 is not a GPR scalar",
			    "a .vx member's rs1 is not a GPR scalar", m, k);
	}
	{
		// vmacc.vx reads its old vd and vmul.vx does not; the run's dataflow is keyed on that,
		// so a member on which the op and the flag disagree is a descriptor the body cannot
		// lower consistently with the live-in set the scan computed.
		auto m = MemberFor(Shape::MaccVX, k);
		m.reads_vd = false;
		ExpectPanic("`.vx` accumulate without reads_vd", ".vx accumulate and reads_vd disagree",
			    m, k);
	}
	{
		auto m = MemberFor(Shape::LoadWhole, k);
		m.src1_is_xbase = false;
		ExpectPanic("whole-register member whose rs1 is not a base address",
			    "a whole-register member's rs1 is not a base address", m, k);
	}
	{
		// LoadWhole DEFINES vd and StoreWhole defines no vector register. The body picks the
		// vector register out of a DIFFERENT field in each direction, so this disagreement would
		// transfer the wrong register rather than fail.
		auto m = MemberFor(Shape::StoreWhole, k);
		m.defines_vd = true;
		ExpectPanic("whole-register store claiming defines_vd",
			    "defines_vd disagrees with", m, k);
	}
	{
		// The closed-world switch's own backstop. FormRun never produces `None` -- it is the
		// descriptor's initial value -- so this is the path a route row added without a body
		// would take if the compile-time pin were ever bypassed.
		rvvrun::RunMember m{};
		m.nchunks = k;
		m.chunk_bytes = 64;
		m.sew_bytes = 4;
		ExpectPanic("RunOp::None has no body", "run member op has no body", m, k);
	}
}

} // namespace

int main()
{
	CheckAllShapes();
	CheckScalarMember(512);
	CheckScalarMember(1024);
	CheckAllRunShapesInvariant();
	for (u32 vlen : {512u, 1024u}) {
		CheckMoveMaterialize(vlen);
		CheckWholeRegMaterialize(vlen);
		CheckVxMaterialize(vlen);
		CheckVxBodyCensus(vlen);
		CheckWholeRegBodyCensus(vlen);
	}
	CheckDeclarationPassPerShape();
	CheckFailClosedBackstops();
	if (g_failures) {
		fprintf(stderr, "FAIL rvv_materialize_run_body (%d failures)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_materialize_run_body\n");
	return 0;
}
