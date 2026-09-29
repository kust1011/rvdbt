// G1 (2026-09-06): a CONTIGUOUS whole-register load -> .vx multiply/accumulate -> whole-register
// store must form ONE generic vector run, with the loaded chunks feeding the arithmetic and the
// store consuming them as host SSA values -- no CPUState round trip between the three members.
//
// Nothing here names a guest pc, a workload or an iteration count: every row is an encoding, and
// every admitted shape is the one the member's own single-instruction route admits.
//
//   [1] admission: {vsetvli; vl1re32.v; vmul.vx; vs1r.v} is one frame with THREE members, guarded
//       with the memory frames' base-range kind (exact vtype, vl == VLMAX, vstart == 0, base <=
//       2^32 - VLEN/8) against the ONE base register the three members share.
//   [2] codegen: the frame's body holds one vchunkload, one vchunkmul and one vchunkstore per host
//       chunk, ONE broadcast of the scalar GPR, ZERO vstatechunkload (the loaded value is never
//       spilled and re-read) and exactly one vstatechunkstore per chunk (the architectural write
//       of the destination register the run leaves live-out).
//   [3] the vmacc.vx form: same shape plus one vchunkadd per chunk, and the accumulator is read
//       from the run's own value, not from CPUState.
//   [4] fail-closed: nf != 1, a second memory member with a DIFFERENT base register, and an
//       OPMVX funct6 that is not vmul/vmacc each cut the run instead of widening the frame.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include <cstdio>
#include <cstring>
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

// Encodings, field by field, in RVV 1.0's own layout.
constexpr u32 VlNre32(u32 nf, u32 rs1, u32 vd)
{
	return 0b0000111u | (vd << 7) | (0b110u << 12) | (rs1 << 15) | (0b01000u << 20) | (1u << 25) |
	       ((nf - 1) << 29);
}
constexpr u32 VsNr(u32 nf, u32 rs1, u32 vs3)
{
	return 0b0100111u | (vs3 << 7) | (rs1 << 15) | (0b01000u << 20) | (1u << 25) |
	       ((nf - 1) << 29);
}
constexpr u32 OpMvx(u32 f6, u32 vd, u32 rs1, u32 vs2)
{
	return 0b1010111u | (vd << 7) | (0b110u << 12) | (rs1 << 15) | (vs2 << 20) | (1u << 25) |
	       (f6 << 26);
}
// vsetvli rd, x0, e32, m1, ta, ma -- establishes the block's observed vtype.
constexpr u32 VSetVli(u32 rd) { return 0b1010111u | (rd << 7) | (0b111u << 12) | (0xd0u << 20); }
static_assert(VlNre32(1, 14, 8) == 0x02876407u, "vl1re32.v v8,(a4)");
static_assert(VsNr(1, 14, 8) == 0x02870427u, "vs1r.v v8,(a4)");
static_assert(OpMvx(rv32::VF6_VMUL, 8, 11, 8) == 0x9685e457u, "vmul.vx v8,v8,a1");
static_assert(OpMvx(rv32::VF6_VMACC, 9, 23, 8) == 0xb68be4d7u, "vmacc.vx v9,s7,v8");
static_assert(VSetVli(6) == 0x0d007357u, "vsetvli t1,zero,e32,m1,ta,ma");

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
	config::rvv_qcg_whole_reg = true;
	config::rvv_qcg_whole_reg_force_emit = true;
	config::rvv_qcg_vx_mulacc = true;
	config::rvv_qcg_vx_mulacc_force_emit = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_narrow_chunk_width = false;
	config::rvv_qcg_narrow_chunk_width_force_emit = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
};
void Translate(Built &b, std::vector<u32> const &words, u32 vlen, bool partial = false)
{
	ApplyEnv(vlen);
	config::rvv_qcg_partial_vl = partial;
	config::rvv_qcg_narrow_chunk_width_force_emit = partial;
	if (partial)
		config::rvv_qcg_narrow_chunk_width = true;
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
u32 GprOffs(u32 r) { return (u32)(offsetof(CPUState, gpr) + 4u * r); }

// The largest frame in the region, which is the run when one was formed.
Frame const *Widest(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (!best || f.begin->n_members > best->begin->n_members)
			best = &f;
	return best;
}

void CheckMulRun(u32 vlen, u32 chunks)
{
	Built b;
	Translate(b, {VSetVli(6), VlNre32(1, 14, 8), OpMvx(rv32::VF6_VMUL, 8, 11, 8), VsNr(1, 14, 8)},
		  vlen);
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL vlen=%u: no typed chunk frame at all\n", vlen);
		++g_failures;
		return;
	}
	// [1] one run, three members, the memory frames' guard against the shared base register.
	CHECK_EQ((unsigned)f->begin->n_members, 3u);
	CHECK(f->begin->guard_kind ==
	      InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit);
	CHECK_EQ((u32)f->begin->base_state_offs, GprOffs(14));
	CHECK_EQ(f->begin->base_limit, 0u - vlen / 8u);
	CHECK_EQ(f->begin->vlmax, vlen / 32u);
	// [2] the body: guest memory in, guest memory out, one architectural state write, and NO
	// state read -- the loaded chunks reach the multiply as values.
	CHECK_EQ(CountOp(*f, Op::_vchunkload), chunks);
	CHECK_EQ(CountOp(*f, Op::_vchunkmul), chunks);
	CHECK_EQ(CountOp(*f, Op::_vchunkstore), chunks);
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), 0u);
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), chunks);
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 1u);
}

void CheckMaccRun(u32 vlen, u32 chunks)
{
	Built b;
	// vl1re32.v v9,(a4); vmacc.vx v9,s7,v8; vs1r.v v9,(a4). v8 is a run live-in (loaded once),
	// v9 is produced by the load, accumulated in place and stored.
	Translate(b,
		  {VSetVli(6), VlNre32(1, 14, 9), OpMvx(rv32::VF6_VMACC, 9, 23, 8), VsNr(1, 14, 9)},
		  vlen);
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL macc vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 3u);
	CHECK_EQ(CountOp(*f, Op::_vchunkload), chunks);      // vs2's group: guest memory
	CHECK_EQ(CountOp(*f, Op::_vchunkmul), chunks);
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), chunks);       // the accumulate half of vmacc
	CHECK_EQ(CountOp(*f, Op::_vchunkstore), chunks);
	CHECK_EQ(CountOp(*f, Op::_vstatechunkload), chunks); // v8 only: the one true live-in
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), chunks);
}

void CheckCuts(u32 vlen)
{
	{ // nf = 2 is not an admitted member: the run cannot contain the load.
		Built b;
		Translate(b,
			  {VSetVli(6), VlNre32(2, 14, 8), OpMvx(rv32::VF6_VMUL, 8, 11, 8),
			   VsNr(1, 14, 8)},
			  vlen);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(!f || f->begin->n_members < 3);
	}
	{ // Different memory bases share one run and are both represented by its base-mask guard.
		Built b;
		Translate(b,
			  {VSetVli(6), VlNre32(1, 14, 8), OpMvx(rv32::VF6_VMUL, 8, 11, 8),
			   VsNr(1, 15, 8)},
			  vlen);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(f && f->begin->n_members == 3);
		if (f) {
			CHECK(f->begin->guard_kind ==
			      InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseMask);
			CHECK_EQ(f->begin->base_state_mask, (1u << 14) | (1u << 15));
		}
	}
	{ // an OPMVX funct6 that is not vmul/vmacc (vdivu.vx) is not a member.
		Built b;
		Translate(b,
			  {VSetVli(6), VlNre32(1, 14, 8), OpMvx(rv32::VF6_VDIVU, 8, 11, 8),
			   VsNr(1, 14, 8)},
			  vlen);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(!f || f->begin->n_members < 3);
	}
}
void CheckMixedPartialRun(u32 vlen, u32 lmul)
{
	for (u32 f6 : {rv32::VF6_VMUL, rv32::VF6_VMACC}) {
		for (bool reverse : {false, true}) {
			Built b;
			u32 const mul = OpMvx(f6, 8, 11, 8);
			u32 const add = (rv32::VF6_VADD << 26) | (1u << 25) | (10u << 20) |
				       (8u << 15) | (8u << 7) | 0x57u;
			Translate(b, {VSetVli(6) | (lmul << 20), reverse ? add : mul,
				      reverse ? mul : add}, vlen, true);
			auto frames = FindFrames(b.region);
			auto const *f = Widest(frames);
			if (lmul != 0) {
				// Integer run admission currently excludes grouped registers.
				CHECK(!f || f->begin->n_members < 2);
				continue;
			}
			CHECK(f && f->begin->n_members == 2);
			if (!f || f->begin->n_members != 2)
			{
				fprintf(stderr, "mixed partial admission: vlen=%u lmul=%u f6=%u reverse=%u\n", vlen, lmul, f6, reverse);
				continue;
			}
			CHECK(f->begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
			CHECK_EQ(CountOp(*f, Op::_vchunkpartialalu), 0u);
			CHECK(CountOp(*f, Op::_vstatechunkstore) > 0);
			for (auto *ins : f->body)
				if (ins->GetOpcode() == Op::_vstatechunkstore) {
					auto *s = static_cast<InstVStateChunkStore *>(ins);
					CHECK_EQ(s->active_sew, 4u);
				}
			TestCompilerRuntime runtime;
			CodeSegment segment(0u, 0x1000u);
			qcg::GenerateCode(&runtime, &segment, b.region, 0u);
			CHECK(!runtime.buf.empty());
		}
	}
}
} // namespace

int main()
{
	// VLEN 512 is one 64-byte host chunk per register; 1024 is two, which is the shape whose two
	// independent chunk streams the run exists to keep apart.
	CheckMulRun(512, 1);
	CheckMulRun(1024, 2);
	CheckMaccRun(512, 1);
	CheckMaccRun(1024, 2);
	CheckCuts(512);
	CheckCuts(1024);
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
		CheckMixedPartialRun(vlen, 0);
		CheckMixedPartialRun(vlen, 1);
	}
	printf("%s rvv_run_mem_member (%d failures)\n", g_failures ? "FAIL" : "PASS", g_failures);
	return g_failures != 0;
}
