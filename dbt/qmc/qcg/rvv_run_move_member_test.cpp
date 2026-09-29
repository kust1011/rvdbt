// G3 (2026-09-06): the unmasked move/broadcast forms as component-SSA run members.
//
// RVV 1.0 encodes vmv.v.v / vmv.v.x / vmv.v.i / vfmv.v.f as funct6 010111 with vm = 1 and the vs2
// field fixed to zero; the funct3 group alone says what source 1 is. The run must therefore:
//
//   [1] admit all four in one frame with the arithmetic members, VLEN 512 and 1024;
//   [2] emit NO per-chunk operation for a move -- the member republishes its source component --
//       with exactly one broadcast per distinct x/f source and one per immediate member, and
//       exactly one CPUState store per written vd at the run exit;
//   [3] preserve operand-overlap semantics: a move's result is the source's value AT THAT POINT,
//       so a later write to the source does not change what the move published;
//   [4] fail closed on the merge forms (vm = 0), on a reserved non-zero vs2, and keep the full-vl
//       guard (vl == VLMAX, vstart == 0) so partial/undisturbed executions take the ordered
//       fallback unchanged.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include <cstdio>
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
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

constexpr u32 F6_MERGE = 0b010111u, F6_ADD = 0b000000u;
constexpr u32 OpV(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 f3, u32 vd)
{
	return 0b1010111u | (vd << 7) | (f3 << 12) | (rs1 << 15) | (vs2 << 20) | (vm << 25) | (f6 << 26);
}
constexpr u32 VmvVV(u32 vd, u32 vs1) { return OpV(F6_MERGE, 1, 0, vs1, 0b000, vd); }
constexpr u32 VmvVX(u32 vd, u32 rs1) { return OpV(F6_MERGE, 1, 0, rs1, 0b100, vd); }
constexpr u32 VmvVI(u32 vd, u32 imm) { return OpV(F6_MERGE, 1, 0, imm & 0x1fu, 0b011, vd); }
constexpr u32 VfmvVF(u32 vd, u32 fs1) { return OpV(F6_MERGE, 1, 0, fs1, 0b101, vd); }
constexpr u32 VmergeVVM(u32 vd, u32 vs2, u32 vs1) { return OpV(F6_MERGE, 0, vs2, vs1, 0b000, vd); }
constexpr u32 VaddVV(u32 vd, u32 vs2, u32 vs1) { return OpV(F6_ADD, 1, vs2, vs1, 0b000, vd); }
constexpr u32 VSetVli(u32 rd) { return 0b1010111u | (rd << 7) | (0b111u << 12) | (0xd0u << 20); }
static_assert(VmvVV(9, 8) == 0x5e0404d7u, "vmv.v.v v9,v8");
static_assert(VmvVI(8, 5) == 0x5e02b457u, "vmv.v.i v8,5");

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};
void ApplyEnv(u32 vlen)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_vmv = true;
	config::rvv_qcg_typed_chunk_vmv_force_emit = true;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}
struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
};
void Translate(Built &b, std::vector<u32> const &words, u32 vlen)
{
	ApplyEnv(vlen);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}
struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
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
					out.push_back(cur);
					open = false;
				}
			} else if (open) {
				cur.body.push_back(&ins);
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
Frame const *Widest(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (!best || f.begin->n_members > best->begin->n_members)
			best = &f;
	return best;
}

// [1]+[2] one frame with all four move forms plus an arithmetic member.
void CheckMoveRun(u32 vlen, unsigned k)
{
	Built b;
	Translate(b,
		  {VSetVli(6), VmvVI(8, 5), VmvVX(9, 11), VfmvVF(10, 12), VmvVV(11, 9),
		   VaddVV(12, 8, 11)},
		  vlen);
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL move run vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 5u);
	// the full-vl guard, so a partial or restarted execution takes the ordered fallback
	CHECK(f->begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
	CHECK_EQ(f->begin->vlmax, vlen / 32u);
	// one broadcast per distinct scalar source: one immediate, one GPR, one F register
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 2u);  // vmv.v.i and vmv.v.x
	CHECK_EQ(CountOp(*f, Op::_vchunkfbroadcast), 1u); // vfmv.v.f
	// the moves cost no lane operation; only the add does
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), k);
	// nothing is read from CPUState: every source is produced inside the run
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), 0u);
	// v8, v9, v10, v11 and v12 are each written exactly once per chunk, at the exit
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), 5u * k);
}

// [3] overlap: a move publishes the source value at that point; a later write to the source must
// not change it. `vmv.v.v v9,v8; vadd.vv v8,v8,v8; vadd.vv v10,v9,v9` -- the second add must read
// the value v8 had on entry (the live-in), not the first add's result.
void CheckMoveOverlap(u32 vlen, unsigned k)
{
	Built b;
	Translate(b, {VSetVli(6), VmvVV(9, 8), VaddVV(8, 8, 8), VaddVV(10, 9, 9)}, vlen);
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL overlap vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 3u);
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), k);   // v8 is the one live-in
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), 2u * k);
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), 3u * k); // v8, v9, v10
	// the adds must not share an input value: the first consumes the live-in, the second
	// consumes what the move published, which is that same live-in -- so the SECOND add's
	// operands are the live-in value, never the first add's result.
	std::vector<Inst *> adds, loads;
	for (auto *i : f->body) {
		if (i->GetOpcode() == Op::_vchunkadd)
			adds.push_back(i);
		if (i->GetOpcode() == Op::_vstatechunkload)
			loads.push_back(i);
	}
	CHECK_EQ(adds.size(), 2u * k);
	// Both adds read the SAME component value -- the live-in v8 -- because the move published
	// exactly that value and the first add's result is a new value that only vd names.
	for (unsigned c = 0; c < k; ++c) {
		auto *first = static_cast<InstVChunkAdd *>(adds[c]);
		auto *second = static_cast<InstVChunkAdd *>(adds[k + c]);
		CHECK(first->i(0).IsVVPR() && second->i(0).IsVVPR());
		CHECK_EQ(second->i(0).GetVVPR(), first->i(0).GetVVPR());
		CHECK_EQ(second->i(1).GetVVPR(), first->i(1).GetVVPR());
		// and the second add does NOT consume the first add's result
		CHECK(second->i(0).GetVVPR() != first->o(0).GetVVPR());
	}
}

// [4] fail-closed: the merge forms and a reserved non-zero vs2 are not members.
void CheckFailClosed(u32 vlen)
{
	{ // masked vmerge.vvm keeps its own path
		Built b;
		Translate(b, {VSetVli(6), VmvVI(8, 5), VmergeVVM(9, 8, 8), VaddVV(10, 8, 8)}, vlen);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(!f || f->begin->n_members < 3);
	}
	{ // vm = 1 with a non-zero vs2 is reserved: not a member
		Built b;
		Translate(b, {VSetVli(6), OpV(F6_MERGE, 1, 3, 8, 0b000, 9), VaddVV(10, 9, 9)}, vlen);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(!f || f->begin->n_members < 2);
	}
	{ // the FP merge form (vm = 0) is not a member either
		Built b;
		Translate(b, {VSetVli(6), OpV(F6_MERGE, 0, 8, 12, 0b101, 9), VaddVV(10, 9, 9)}, vlen);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(!f || f->begin->n_members < 2);
	}
}
// [5] G9 CHANGED THIS CONTRACT DELIBERATELY, and the assertion is inverted rather than deleted.
//
// G3 shipped with the split body refusing move members, so this section asserted that the
// five-member run did NOT form while --rvv-run-live-range-split was on. G9 gave that body its own
// move arm -- same republish semantics, same zero-copy vmv.v.v rename, residency accounted by
// value identity -- so the correct contract is now the opposite one: the run DOES form, with all
// five members, and the move members still emit no per-chunk lane operation.
//
// The two bodies that still refuse a move keep their fail-closed assertion below, so this section
// remains a test of a boundary rather than a rubber stamp.
void CheckSplitAdmitsMoves(u32 vlen)
{
	Built b;
	ApplyEnv(vlen);
	config::rvv_run_live_range_split = true;
	b.words = {VSetVli(6), VmvVI(8, 5), VmvVX(9, 11), VfmvVF(10, 12), VmvVV(11, 9),
		   VaddVV(12, 8, 11)};
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	config::rvv_run_live_range_split = false;
	auto const frames = FindFrames(b.region);
	auto const *w = Widest(frames);
	if (!w) {
		fprintf(stderr, "  FAIL split move run vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)w->begin->n_members, 5u); // the five-member move run DOES form now
	// the same broadcast counts the fixed-placement body produces: one per distinct scalar
	// source, and none per chunk
	CHECK_EQ(CountOp(*w, Op::_vchunkbroadcast), 2u);
	CHECK_EQ(CountOp(*w, Op::_vchunkfbroadcast), 1u);
	// and still exactly one lane operation per chunk for the single arithmetic member
	CHECK_EQ(CountOp(*w, Op::_vchunkadd), (unsigned)(vlen / 512u));
}
// [5b] NEITHER THE MATERIALIZE BODY NOR THE ISSUE ORDER MAY REFUSE A MOVE MEMBER.
//
// P6C-R (2026-09-10) removed the ORDER half. The chunk-major arm of RvvEmitVectorRunGroup had been
// a second, smaller copy of the member loop with no arm for a move, so RvvRunMemberChunks refused
// the row rather than emit wrong code -- which made a BODY selector visible to ADMISSION and
// destroyed the single-factor order comparison (SIBLING_ORDER_ABLATION_AUDIT_20260910.md).
//
// C2l (2026-09-14) REMOVES THE MATERIALIZE HALF, and this assertion is INVERTED rather than
// deleted for the same reason G9's was when the split body gained its move arm. The refusal was
// the same shape of defect as the order one, one round later: the materialize arm had no body for
// a move, so admission refused the row. It now has one -- RvvEmitTypedVmvChunkBody, the
// single-instruction frame's own body, extended with the OPFVF broadcast -- so the correct
// contract is that the five-member run DOES form under materialize, and that is what is asserted.
//
// This is the mutation-visible gate for the removal: restoring the `rvv_run_body_materialize`
// disjunct in RvvRunMemberChunks' Mov arm makes this check fail. The node CENSUS of the
// materialized move bodies is pinned separately, in rvv_materialize_run_body_test.cpp.
void CheckMaterializeAdmitsMoves(u32 vlen)
{
	unsigned const k = vlen / 512u;
	Built b;
	ApplyEnv(vlen);
	config::rvv_run_body_materialize = true;
	b.words = {VSetVli(6), VmvVI(8, 5), VmvVX(9, 11), VfmvVF(10, 12), VmvVV(11, 9),
		   VaddVV(12, 8, 11)};
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	config::rvv_run_body_materialize = false;
	auto const frames = FindFrames(b.region);
	auto const *w = Widest(frames);
	if (!w) {
		fprintf(stderr, "  FAIL materialize move run vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)w->begin->n_members, 5u); // the five-member move run DOES form now
	// The materialize body's own shape, which is what makes it a DIFFERENT body rather than a
	// renamed one: a broadcast per broadcast MEMBER (not per frame), every vd written once per
	// chunk, and still no lane operation for a move.
	CHECK_EQ(CountOp(*w, Op::_vchunkbroadcast), 2u);
	CHECK_EQ(CountOp(*w, Op::_vchunkfbroadcast), 1u);
	CHECK_EQ(CountOp(*w, Op::_vchunkadd), k);
	CHECK_EQ(CountOp(*w, Op::_vstatechunkstore), 5u * k);
}

// The issue order forms the SAME run and declares the same frame, which is the property
// `--rvv-run-order` claims and the pre-repair tree did not have.
void CheckOrderDoesNotRefuseMove(u32 vlen)
{
	std::vector<u32> const words = {VSetVli(6),   VmvVI(8, 5),	VmvVX(9, 11),
					VfmvVF(10, 12), VmvVV(11, 9), VaddVV(12, 8, 11)};
	Built b[2];
	for (int m = 0; m < 2; ++m) {
		ApplyEnv(vlen);
		config::rvv_run_order_chunk_major = (m == 1);
		b[m].words = words;
		CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
		CompilerJob job(nullptr, (uptr)b[m].words.data(), CodeSegment(0u, 0x1000u),
				std::move(ranges));
		b[m].region = CompilerGenRegionIR(&b[m].arena, job);
		config::rvv_run_order_chunk_major = false;
	}
	auto const f0 = FindFrames(b[0].region), f1 = FindFrames(b[1].region);
	auto const *w0 = Widest(f0);
	auto const *w1 = Widest(f1);
	CHECK(w0 != nullptr);
	CHECK(w1 != nullptr);
	if (!w0 || !w1)
		return;
	CHECK_EQ((unsigned)w0->begin->n_members, 5u); // the five-member move run DOES form
	CHECK_EQ((unsigned)w1->begin->n_members, (unsigned)w0->begin->n_members);
	CHECK_EQ((unsigned)w1->begin->n_typed, (unsigned)w0->begin->n_typed);
	CHECK_EQ((unsigned)w1->begin->vtype, (unsigned)w0->begin->vtype);
	CHECK_EQ(w1->body.size(), w0->body.size());
	// The move member emits no lane op in either order, and the arithmetic member emits exactly
	// one per chunk in both -- the property this file exists to pin, now checked on both arms.
	CHECK_EQ(CountOp(*w1, Op::_vchunkadd), CountOp(*w0, Op::_vchunkadd));
	CHECK_EQ(CountOp(*w1, Op::_vchunkadd), (unsigned)(vlen / 512u));
	CHECK_EQ(CountOp(*w1, Op::_vstatechunkload), CountOp(*w0, Op::_vstatechunkload));
	CHECK_EQ(CountOp(*w1, Op::_vstatechunkstore), CountOp(*w0, Op::_vstatechunkstore));
	CHECK_EQ(CountOp(*w1, Op::_vchunkbroadcast), CountOp(*w0, Op::_vchunkbroadcast));
}
} // namespace

int main()
{
	CheckMoveRun(512, 1);
	CheckMoveRun(1024, 2);
	CheckMoveOverlap(512, 1);
	CheckMoveOverlap(1024, 2);
	CheckFailClosed(512);
	CheckFailClosed(1024);
	CheckSplitAdmitsMoves(512);
	CheckSplitAdmitsMoves(1024);
	CheckMaterializeAdmitsMoves(512);
	CheckMaterializeAdmitsMoves(1024);
	CheckOrderDoesNotRefuseMove(512);
	CheckOrderDoesNotRefuseMove(1024);
	printf("%s rvv_run_move_member (%d failures)\n", g_failures ? "FAIL" : "PASS", g_failures);
	return g_failures != 0;
}
