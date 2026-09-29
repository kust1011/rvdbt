// S1-2D: `--rvv-qcg-active-vl-bound` extended from the single-instruction typed vfalu frame to the
// single-instruction typed FMA frame. Vector runs stay excluded, and this file is where that stays
// true.
//
// WHY THE FMA FRAME NEEDS ITS OWN SHAPE TEST RATHER THAN INHERITING STAGE 2A's. One thing differs
// between the two routes, and it is the one thing chunk-major touches: the FMA frame READS the old
// vd. In batch mode every load of the frame preceded every store of the frame, and that global
// load-major order is what the route's own comment calls a hard invariant, because `vd == vs2` is a
// legal and actually-occurring overlap. Chunk-major keeps load-major WITHIN a chunk and gives it up
// BETWEEN chunks. So the checks below are not "the falu checks again": [2b] pins the within-chunk
// order that must survive, and [3b] pins the property that makes an early exit safe at all.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [1] OFF is inert. With the switch clear there is no vchunkactive anywhere, every vchunkmaskset
//       is still ahead of the first load, and n_typed is the OLD formula recomputed here from
//       nchunks and the operand form -- not read back from the node it is supposed to check.
//       Failure = the switch is not really default-off, or the mask move leaked into batch mode.
//
//   [2] ON is one bound per chunk, chunk-major. Exactly nchunks vchunkactive, in increasing chunk
//       order, each immediately followed by its OWN chunk's vchunkmaskset, each region closed by
//       exactly one store; n_typed grew by exactly nchunks and nothing else about the frame
//       (guard kind, vtype, vlmax) moved. Failure = a bound in the wrong place, or a mask left at
//       the top of the frame where its own chunk's branch would skip it and the lane op would then
//       consume a k register this frame never set.
//
//   [2b] FMA-SPECIFIC: within each chunk's region, every vstatechunkload precedes the vchunkfma,
//       which precedes the single vstatechunkstore, and the region holds exactly the loads that
//       chunk needs (vs2 + old vd, plus vs1 in the .vv form). Failure = a store hoisted above a
//       load of the same chunk, which corrupts exactly the `vd == vs2` case and nothing else.
//
//   [3] The chunk WORK is the same multiset ON and OFF -- (opcode, offset, chunk, sew, kmask,
//       masked) over every load, lane op, store and maskset. Failure = the chunk-major rewrite
//       changed which bytes a chunk reads or writes, or under which mask.
//
//   [3b] PER-CHUNK DATAFLOW IS CLOSED. Every SSA value defined inside chunk c's region is used only
//       inside chunk c's region, and the only value that crosses a region boundary is the .vf
//       scalar broadcast, which is defined BEFORE the first bound. This is the property that makes
//       the early exit safe: a skipped chunk leaves its own values undefined and nothing else reads
//       them. Failure = the one way this checkpoint could silently miscompile -- a later chunk
//       reading a register an earlier, skipped chunk was supposed to define.
//
//   [4] Every vchunkfma names its own chunk's shared mask, k(1+chunk), in BOTH modes. Failure =
//       the deferred-node path forgot to establish residency, which QEmit::FpMaskRegs Panics on.
//
//   [5] vfalu is unchanged by this checkpoint: with the switch ON a vfalu frame still carries
//       exactly nchunks bounds in chunk-major order (Stage 2A's behaviour), and with it OFF it
//       carries none. Failure = the FMA wiring disturbed the route it was modelled on.
//
//   [6] A multi-member FP run is still unbounded, and its QIR is opcode-for-opcode identical ON and
//       OFF. Failure = the flag reached the run materializer, where one member's early exit would
//       leave the following members' shared masks undefined.
//
//   [7] The refusals are structural: an FMA frame with no shared masks, and one with more chunks
//       than k1..k6 can hold, both stay unbounded with the switch ON.
//
//   [8] The emitted host bytes carry exactly nchunks `cmp [vec.vl], imm` at immediates
//       0, lanes, 2*lanes, ... -- read back out of the buffer, not assumed.
//
// Nothing here executes host bytes. This is a SHAPE checkpoint: the value-level claim that skipping
// a `vl <= base` chunk is architecturally a no-op needs the oracle matrix on hardware, exactly as
// Stage 2B ran it for vfalu, and is NOT made here.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
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

constexpr u32 VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpV(f6, 1, vs2, rs1, vd, 0b101u); }
// vm == 0 is the MASKED form. It is included because the bound's test is `vl` alone and must stay
// independent of v0; a masked shape is the case that would break if someone "optimised" the test
// into a mask test.
constexpr u32 VvM(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 0, vs2, vs1, vd, 0b001u); }

// The fused family is funct6 0b101000..0b101111. Both operand-role groups are represented: vd as a
// multiplicand (vfmadd/vfnmsub/vfmsub) and vd as the addend (vfmacc/vfnmacc/vfnmsac).
constexpr u32 F6_VFMADD = 0b101000u, F6_VFNMADD = 0b101001u, F6_VFMSUB = 0b101010u,
	      F6_VFNMSUB = 0b101011u, F6_VFMACC = 0b101100u, F6_VFNMACC = 0b101101u,
	      F6_VFNMSAC = 0b101111u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFMUL = 0b100100u, F6_VFSUB = 0b000010u;

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

struct Env {
	u32 vlen_bits = 512;
	bool shared = true;
	bool bound = false;
	bool vector_run = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_fp_shared_mask = e.shared;
	config::rvv_qcg_active_vl_bound = e.bound;
	config::rvv_vector_run = e.vector_run;
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_qcg_typed_chunk = false;
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

using Work = std::tuple<int, u32, int, int, int, int>; // op, offs/funct6, chunk, sew, kmask, masked

std::vector<Work> ChunkWork(Frame const &f)
{
	std::vector<Work> out;
	for (auto *i : f.body) {
		switch (i->GetOpcode()) {
		case Op::_vstatechunkload: {
			auto *n = static_cast<InstVStateChunkLoad *>(i);
			out.push_back({(int)Op::_vstatechunkload, n->offs, -1, -1, -1, -1});
			break;
		}
		case Op::_vstatechunkstore: {
			auto *n = static_cast<InstVStateChunkStore *>(i);
			out.push_back({(int)Op::_vstatechunkstore, n->offs, (int)n->chunk,
				       (int)n->active_sew, -1, (int)n->masked});
			break;
		}
		case Op::_vchunkfma: {
			auto *n = static_cast<InstVChunkFMA *>(i);
			out.push_back({(int)Op::_vchunkfma, n->funct6, (int)n->chunk,
				       (int)n->sew_bytes, (int)n->kmask, (int)n->masked});
			break;
		}
		case Op::_vchunkfalu: {
			auto *n = static_cast<InstVChunkFALU *>(i);
			out.push_back({(int)Op::_vchunkfalu, n->funct6, (int)n->chunk,
				       (int)n->sew_bytes, (int)n->kmask, (int)n->masked});
			break;
		}
		case Op::_vchunkmaskset: {
			auto *n = static_cast<InstVChunkMaskSet *>(i);
			out.push_back({(int)Op::_vchunkmaskset, 0, (int)n->chunk, (int)n->lanes, -1, -1});
			break;
		}
		case Op::_vchunkfbroadcast: {
			auto *n = static_cast<InstVChunkFBroadcast *>(i);
			out.push_back({(int)Op::_vchunkfbroadcast, n->offs, -1, (int)n->sew_bytes, -1, -1});
			break;
		}
		default:
			break;
		}
	}
	std::sort(out.begin(), out.end());
	return out;
}

std::vector<int> OpcodeStream(Region *r)
{
	std::vector<int> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			out.push_back((int)ins.GetOpcode());
	return out;
}

struct Shape {
	char const *name;
	u32 setvli;
	u32 word;
	bool vf;
};

Shape const kFmaShapes[] = {
    {"vfmadd.vf  e64m2", VSETVLI_E64M2, Vf(F6_VFMADD, 10, 15, 8), true},
    {"vfnmsub.vf e32m1", VSETVLI_E32M1, Vf(F6_VFNMSUB, 9, 15, 8), true},
    {"vfmacc.vv  e32m1", VSETVLI_E32M1, Vv(F6_VFMACC, 9, 10, 8), false},
    {"vfnmacc.vv e64m1", VSETVLI_E64M1, Vv(F6_VFNMACC, 9, 10, 8), false},
    {"vfnmsac.vv e64m2", VSETVLI_E64M2, Vv(F6_VFNMSAC, 10, 12, 8), false},
    {"vfmsub.vf  e64m2", VSETVLI_E64M2, Vf(F6_VFMSUB, 10, 15, 8), true},
    {"vfnmadd.vv e64m2", VSETVLI_E64M2, Vv(F6_VFNMADD, 10, 12, 8), false},
    {"vfmacc.vv  e64m2 masked", VSETVLI_E64M2, VvM(F6_VFMACC, 10, 12, 8), false},
    // vd IS vs2: the aliased case the route's load-major comment is about, and the case
    // chunk-major has to keep correct by byte-disjointness rather than by global load ordering.
    {"vfmacc.vv  e64m2 vd==vs2", VSETVLI_E64M2, Vv(F6_VFMACC, 8, 12, 8), false},
};

// The chunk regions of a bounded frame: [start of vchunkactive(c), just before vchunkactive(c+1)).
std::vector<std::pair<size_t, size_t>> Regions(Frame const &f)
{
	std::vector<std::pair<size_t, size_t>> out;
	for (size_t i = 0; i < f.body.size(); ++i)
		if (f.body[i]->GetOpcode() == Op::_vchunkactive) {
			if (!out.empty())
				out.back().second = i;
			out.push_back({i, f.body.size()});
		}
	return out;
}

void TestOffAndOn()
{
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &s : kFmaShapes) {
			Built off, on;
			Translate(off, {s.setvli, s.word}, Env{vlen, true, false});
			Translate(on, {s.setvli, s.word}, Env{vlen, true, true});
			auto fo = FindFrames(off.region), fn = FindFrames(on.region);
			CHECK_EQ(fo.size(), 1u);
			CHECK_EQ(fn.size(), 1u);
			if (fo.size() != 1 || fn.size() != 1)
				continue;
			auto const &a = fo[0];
			auto const &b = fn[0];
			unsigned const nchunks = CountOp(a, Op::_vchunkmaskset);
			CHECK(nchunks > 0);
			CHECK_EQ(CountOp(a, Op::_vchunkfma), nchunks);

			// [1] OFF: no bound, masksets all ahead of the first load, and n_typed is the
			// OLD formula recomputed here rather than taken from the node.
			CHECK_EQ(CountOp(a, Op::_vchunkactive), 0u);
			size_t first_load = a.body.size();
			for (size_t i = 0; i < a.body.size(); ++i)
				if (a.body[i]->GetOpcode() == Op::_vstatechunkload) {
					first_load = i;
					break;
				}
			for (size_t i = first_load; i < a.body.size(); ++i)
				CHECK(a.body[i]->GetOpcode() != Op::_vchunkmaskset);
			unsigned const want_off_typed =
			    (s.vf ? 4u * nchunks + 3u : 5u * nchunks + 2u) + nchunks;
			CHECK_EQ((unsigned)a.begin->n_typed, want_off_typed);

			// [2] ON: one bound per chunk, chunk-major, +nchunks typed ops, frame identity
			// otherwise untouched.
			CHECK_EQ(CountOp(b, Op::_vchunkactive), nchunks);
			CHECK_EQ(CountOp(b, Op::_vchunkmaskset), nchunks);
			CHECK_EQ((unsigned)b.begin->n_typed, want_off_typed + nchunks);
			CHECK(a.begin->guard_kind == b.begin->guard_kind);
			CHECK_EQ(a.begin->vlmax, b.begin->vlmax);
			CHECK_EQ(a.begin->vtype, b.begin->vtype);
			CHECK_EQ((unsigned)a.begin->n_members, (unsigned)b.begin->n_members);
			CHECK_EQ((unsigned)b.begin->n_members, 1u);

			auto const regions = Regions(b);
			CHECK_EQ(regions.size(), nchunks);
			int expect_chunk = 0;
			for (auto const &[lo, hi] : regions) {
				auto *act = static_cast<InstVChunkActive *>(b.body[lo]);
				CHECK_EQ((int)act->chunk, expect_chunk);
				++expect_chunk;
				// the bound's own chunk's mask is the very next node
				CHECK(lo + 1 < hi);
				if (lo + 1 >= hi)
					continue;
				CHECK(b.body[lo + 1]->GetOpcode() == Op::_vchunkmaskset);
				if (b.body[lo + 1]->GetOpcode() == Op::_vchunkmaskset)
					CHECK_EQ((int)static_cast<InstVChunkMaskSet *>(b.body[lo + 1])
						     ->chunk,
						 (int)act->chunk);

				// [2b] FMA-SPECIFIC: loads, then the fused op, then one store, all of
				// this chunk. This is the invariant chunk-major has to preserve for the
				// vd == vs2 overlap; between chunks it is byte-disjointness instead.
				long op_at = -1, store_at = -1;
				unsigned loads = 0, stores = 0;
				for (size_t i = lo; i < hi; ++i) {
					switch (b.body[i]->GetOpcode()) {
					case Op::_vstatechunkload:
						++loads;
						CHECK(op_at < 0);   // no load after the fused op
						CHECK(store_at < 0); // and none after the store
						break;
					case Op::_vchunkfma: {
						auto *n = static_cast<InstVChunkFMA *>(b.body[i]);
						CHECK_EQ((int)n->chunk, (int)act->chunk);
						op_at = (long)i;
						break;
					}
					case Op::_vstatechunkstore: {
						auto *n = static_cast<InstVStateChunkStore *>(b.body[i]);
						CHECK_EQ((int)n->chunk, (int)act->chunk);
						CHECK(op_at >= 0); // the op is before its store
						store_at = (long)i;
						++stores;
						break;
					}
					default:
						break;
					}
				}
				// .vf: vs2 + old vd. .vv: vs2 + vs1 + old vd.
				CHECK_EQ(loads, s.vf ? 2u : 3u);
				CHECK_EQ(stores, 1u);
				CHECK(op_at >= 0 && store_at > op_at);
			}

			// [3] the chunk work is the same multiset in both modes.
			CHECK(ChunkWork(a) == ChunkWork(b));

			// [3b] per-chunk dataflow closure. A value defined inside a region must not be
			// read outside it; the only cross-region value is the .vf broadcast, defined
			// before the first bound.
			for (size_t r = 0; r < regions.size(); ++r) {
				std::set<u32> defined;
				for (size_t i = regions[r].first; i < regions[r].second; ++i) {
					auto outs = b.body[i]->outputs();
					for (u8 x = 0; x < outs.size(); ++x)
						if (outs[x].IsVirtualReg())
							defined.insert((u32)outs[x].GetVirtualReg());
				}
				CHECK(!defined.empty());
				for (size_t i = 0; i < b.body.size(); ++i) {
					if (i >= regions[r].first && i < regions[r].second)
						continue;
					auto ins = b.body[i]->inputs();
					for (u8 x = 0; x < ins.size(); ++x)
						if (ins[x].IsVirtualReg())
							CHECK(!defined.count(
							    (u32)ins[x].GetVirtualReg()));
				}
			}
			// and the broadcast, when there is one, is before the first bound. Guarded on
			// `regions` being non-empty so that a build with the bound unwired reports the
			// missing bounds above rather than dying here on an empty container.
			if (!regions.empty())
				for (size_t i = 0; i < b.body.size(); ++i)
					if (b.body[i]->GetOpcode() == Op::_vchunkfbroadcast)
						CHECK(i < regions.front().first);

			// [4] every fused op names its own chunk's shared mask, in both modes.
			for (auto const *f : {&a, &b})
				for (auto *i : f->body)
					if (i->GetOpcode() == Op::_vchunkfma) {
						auto *n = static_cast<InstVChunkFMA *>(i);
						CHECK_EQ((int)n->kmask, 1 + (int)n->chunk);
					}
			printf("  ok   VLEN %-4u %-24s chunks=%u n_typed %u -> %u\n", vlen, s.name,
			       nchunks, (unsigned)a.begin->n_typed, (unsigned)b.begin->n_typed);
		}
	}
}

void TestFaluUnchangedAndRunUntouched()
{
	// [5] vfalu: Stage 2A's behaviour must survive this checkpoint unchanged.
	struct FaluShape {
		char const *name;
		u32 setvli;
		u32 word;
	};
	FaluShape const falu[] = {
	    {"vfadd.vv e32m1", VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)},
	    {"vfmul.vv e64m2", VSETVLI_E64M2, Vv(F6_VFMUL, 10, 12, 8)},
	};
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : falu) {
			Built off, on;
			Translate(off, {s.setvli, s.word}, Env{vlen, true, false});
			Translate(on, {s.setvli, s.word}, Env{vlen, true, true});
			auto fo = FindFrames(off.region), fn = FindFrames(on.region);
			CHECK_EQ(fo.size(), 1u);
			CHECK_EQ(fn.size(), 1u);
			if (fo.empty() || fn.empty())
				continue;
			unsigned const nchunks = CountOp(fo[0], Op::_vchunkmaskset);
			CHECK_EQ(CountOp(fo[0], Op::_vchunkactive), 0u);
			CHECK_EQ(CountOp(fn[0], Op::_vchunkactive), nchunks);
			CHECK_EQ((unsigned)fn[0].begin->n_typed,
				 (unsigned)fo[0].begin->n_typed + nchunks);
			CHECK(ChunkWork(fo[0]) == ChunkWork(fn[0]));
			int expect = 0;
			for (auto *i : fn[0].body)
				if (i->GetOpcode() == Op::_vchunkactive)
					CHECK_EQ((int)static_cast<InstVChunkActive *>(i)->chunk,
						 expect++);
			printf("  ok   VLEN %-4u %-15s vfalu still bounded (%u chunks)\n", vlen,
			       s.name, nchunks);
		}

	// [6] A multi-member FP run stays unbounded and byte-for-byte the same shape.
	std::vector<u32> const run = {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8), Vv(F6_VFMUL, 8, 11, 8),
				      Vv(F6_VFSUB, 8, 12, 8)};
	for (u32 vlen : {512u, 1024u}) {
		Built off, on;
		Translate(off, run, Env{vlen, true, false, /*vector_run=*/true});
		Translate(on, run, Env{vlen, true, true, /*vector_run=*/true});
		auto fn = FindFrames(on.region);
		unsigned bounds = 0, multi = 0;
		for (auto const &f : fn) {
			bounds += CountOp(f, Op::_vchunkactive);
			multi += f.begin->n_members > 1;
		}
		CHECK_EQ(bounds, 0u);
		CHECK(OpcodeStream(off.region) == OpcodeStream(on.region));
		printf("  ok   VLEN %-4u FP run unchanged (%zu frame(s), %u multi-member, 0 bounds)\n",
		       vlen, fn.size(), multi);
	}

	// [6b] A run whose members are FMA, materialized through the SAME shared body this
	// checkpoint changed. The bound must not appear there either.
	std::vector<u32> const fma_run = {VSETVLI_E32M1, Vv(F6_VFMACC, 9, 10, 8),
					  Vv(F6_VFMACC, 11, 12, 8), Vv(F6_VFMACC, 13, 14, 8)};
	for (u32 vlen : {512u, 1024u}) {
		Built off, on;
		Translate(off, fma_run, Env{vlen, true, false, /*vector_run=*/true});
		Translate(on, fma_run, Env{vlen, true, true, /*vector_run=*/true});
		auto fn = FindFrames(on.region);
		unsigned bounds = 0, multi = 0;
		for (auto const &f : fn) {
			bounds += CountOp(f, Op::_vchunkactive);
			multi += f.begin->n_members > 1;
		}
		if (multi == 0) {
			// The run former did not build a multi-member frame for these words; say so
			// rather than reporting a vacuous pass.
			printf("  ..   VLEN %-4u FMA run produced no multi-member frame (%zu frame(s))\n",
			       vlen, fn.size());
			CHECK(OpcodeStream(off.region) == OpcodeStream(on.region) || bounds > 0);
			continue;
		}
		CHECK_EQ(bounds, 0u);
		CHECK(OpcodeStream(off.region) == OpcodeStream(on.region));
		printf("  ok   VLEN %-4u FMA run unchanged (%zu frame(s), %u multi-member, 0 bounds)\n",
		       vlen, fn.size(), multi);
	}
}

void TestRefusals()
{
	// [7a] no shared masks -> no bound (the bounded body is what creates them).
	{
		Built b;
		Translate(b, {VSETVLI_E64M2, Vf(F6_VFMADD, 10, 15, 8)}, Env{512, false, true});
		auto f = FindFrames(b.region);
		CHECK_EQ(f.size(), 1u);
		if (!f.empty()) {
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ(CountOp(f[0], Op::_vchunkmaskset), 0u);
		}
		printf("  ok   FMA, shared masks off -> unbounded\n");
	}
	// [7b] more chunks than k1..k6 can hold: the shared masks are refused and the bound follows.
	{
		Built b;
		Translate(b, {VSETVLI_E64M2, Vf(F6_VFMADD, 10, 15, 8)}, Env{4096, true, true});
		auto f = FindFrames(b.region);
		if (!f.empty() && CountOp(f[0], Op::_vchunkmaskset) == 0) {
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			printf("  ok   FMA, %u chunks > shared-mask cap -> unbounded\n",
			       CountOp(f[0], Op::_vstatechunkstore));
		} else {
			printf("  ..   VLEN 4096 did not produce an over-cap FMA frame (skipped)\n");
		}
	}
}

void TestEmittedImmediates()
{
	// [8] read the bounds' immediates back out of the emitted host bytes of an FMA frame.
	Built b;
	Translate(b, {VSETVLI_E64M2, Vf(F6_VFMADD, 10, 15, 8)}, Env{1024, true, true});
	auto f = FindFrames(b.region);
	CHECK_EQ(f.size(), 1u);
	if (f.empty())
		return;
	unsigned const nchunks = CountOp(f[0], Op::_vchunkactive);
	CHECK_EQ(CountOp(f[0], Op::_vchunkfma), nchunks);
	// S1-3 renamed InstVChunkActive's second field from `lanes` to `element_base`, the immediate
	// itself. `lanes` is therefore taken from the frame's OWN vchunkmaskset nodes -- an independent
	// node whose field did not change -- and the rename is then checked rather than assumed: every
	// bound's element_base must equal chunk * lanes, i.e. exactly the product the old constructor
	// formed. The emitted-byte scan below is unchanged, so it is still the pre-rename assertion and
	// still fails if the FP immediate moved by one byte.
	u8 lanes = 0;
	for (auto *i : f[0].body)
		if (i->GetOpcode() == Op::_vchunkmaskset)
			lanes = static_cast<InstVChunkMaskSet *>(i)->lanes;
	CHECK(nchunks > 1);
	CHECK(lanes > 0);
	for (auto *i : f[0].body)
		if (i->GetOpcode() == Op::_vchunkactive) {
			auto *n = static_cast<InstVChunkActive *>(i);
			CHECK_EQ(n->element_base, (u32)n->chunk * (u32)lanes);
		}
	Emit(b);
	CHECK(!b.code.empty());

	auto const state = asmjit::x86::gpq(qcg::ArchTraits::STATE);
	auto const vl_off =
	    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vl);
	for (unsigned c = 0; c < nchunks; ++c) {
		asmjit::CodeHolder holder;
		holder.init(asmjit::Environment::host());
		asmjit::x86::Assembler a(&holder);
		a.cmp(asmjit::x86::dword_ptr(state, vl_off), (int32_t)(c * lanes));
		holder.flatten();
		holder.resolveUnresolvedLinks();
		std::vector<u8> want(holder.codeSize());
		holder.copyFlattenedData(want.data(), want.size());
		unsigned found = 0;
		for (size_t i = 0; i + want.size() <= b.code.size(); ++i)
			found += memcmp(b.code.data() + i, want.data(), want.size()) == 0;
		CHECK_EQ(found, 1u);
	}
	printf("  ok   FMA frame emitted %u bounds, immediates 0,%u,...,%u (lanes=%u)\n", nchunks,
	       lanes, (nchunks - 1) * lanes, lanes);
}
} // namespace

int main()
{
	printf("[1][2][2b][3][3b][4] FMA: OFF inert; ON chunk-major, bounded, dataflow closed\n");
	TestOffAndOn();
	printf("[5][6] vfalu unchanged; vector runs untouched\n");
	TestFaluUnchangedAndRunUntouched();
	printf("[7] structural refusals\n");
	TestRefusals();
	printf("[8] emitted immediates\n");
	TestEmittedImmediates();
	if (g_failures) {
		printf("FAIL rvv_active_vl_bound_stage2d_fma_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_bound_stage2d_fma_test\n");
	return 0;
}
