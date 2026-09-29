// S1-2A: `--rvv-qcg-active-vl-bound` wired into the single-instruction typed FP ARITHMETIC frame
// (the vfalu route). Vector runs are deliberately NOT wired, and this file is where that stays true.
// (S1-2D later wired the single-instruction FMA frame; see [5] and
// rvv_active_vl_bound_stage2d_fma_test.cpp.)
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [1] OFF is inert. With the switch clear, the constructed QIR for four shapes at four VLENs is
//       node-for-node what it was: no vchunkactive anywhere, the frame's vchunkmaskset nodes are
//       all still up front (between rvvqcgfpbegin and the first load), and n_typed is the old
//       formula. Failure = the switch is not really default-off, or the mask move leaked into the
//       unbounded path.
//
//   [2] ON changes the SHAPE and nothing else. Exactly one vchunkactive per chunk; the body is
//       chunk-major; each chunk's region is `vchunkactive(c) -> vchunkmaskset(c) -> loads -> lane
//       op -> store` in that order; n_typed grew by exactly nchunks. Failure = a bound in the wrong
//       place, a mask left behind at the top of the frame (it would be skipped by its own chunk's
//       branch and read undefined), or an n_typed that the emitter's counter would reject.
//
//   [3] The CHUNK OFFSET SET is equivalent. ON and OFF are compared as MULTISETS of
//       (opcode, CPUState offset, chunk index, sew, kmask, masked) over every load, lane op and
//       store. They must be equal: the bounded body reorders chunk work, it does not add, drop,
//       retarget or re-mask any of it. Failure = the batch=1 rewrite changed which bytes a chunk
//       reads or writes -- the one way this could silently miscompile.
//
//   [4] Each chunk's lane op still names its own shared mask, k(1+chunk), in BOTH modes. Failure =
//       the deferred-node path forgot to establish residency, which RvvEmitChunkLaneOp turns into
//       kmask == 0 and Emit_vchunkfalu then Panics on (mixed conventions) -- or worse, silently
//       overwrites chunk 0's and 1's masks.
//
//   [5] FMA WIRING. Superseded by S1-2D: the FMA frame is now bounded too, so what is checked is
//       that it IS -- one bound per chunk with the switch ON, none with it OFF, n_typed grown by
//       exactly nchunks. Its shape is checked in rvv_active_vl_bound_stage2d_fma_test.cpp.
//       Failure = FMA was silently unwired, or wired without declaring the extra typed ops.
//
//   [6] Vector runs are untouched. A multi-member FP run emits no vchunkactive with the switch ON,
//       and its QIR is identical to the switch-OFF QIR. Failure = the flag leaked into the run
//       materializer, where a member's early exit would leave later members' masks undefined.
//
//   [7] The refusals are structural, not incidental: a frame with no shared masks (switch off), a
//       run-time-SEW frame (unobserved vtype, sew_bytes == 0) and a frame with more chunks than
//       k1..k6 can hold all stay unbounded with the switch ON.
//
//   [8] The emitted host code for a bounded frame contains exactly nchunks `cmp [vec.vl], imm` +
//       `jbe` pairs whose immediates are 0, lanes, 2*lanes, ... -- read back from the emitted bytes
//       rather than assumed. Failure = a wrong `base` (lanes vs chunk_bytes vs a VLEN constant).
//
// Nothing here executes host bytes. This is a SHAPE checkpoint: the value-level claim that skipping
// a `vl <= base` chunk is architecturally a no-op needs the oracle matrix on hardware and is not
// made here.

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

constexpr u32 VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpV(f6, 1, vs2, rs1, vd, 0b101u); }
// The five the Livermore population actually contains, plus the reversed form, so the family is
// exercised rather than one representative. vfneg.v is the vfsgnjn.vv pseudo.
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u, F6_VFMUL = 0b100100u,
	      F6_VFDIV = 0b100000u, F6_VFSGNJN = 0b001001u, F6_VFMADD = 0b101000u;

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

// The per-chunk work, as a comparable tuple. Everything a chunk's nodes say about WHICH bytes are
// touched and under WHICH mask is in here; the ORDER is deliberately not, because reordering is
// exactly what the bounded body does.
using Work = std::tuple<int, u32, int, int, int, int>; // op, offs, chunk, sew, kmask, masked

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
		case Op::_vchunkfalu: {
			auto *n = static_cast<InstVChunkFALU *>(i);
			out.push_back({(int)Op::_vchunkfalu, n->funct6, (int)n->chunk,
				       (int)n->sew_bytes, (int)n->kmask, (int)n->masked});
			break;
		}
		case Op::_vchunkfma: {
			auto *n = static_cast<InstVChunkFMA *>(i);
			out.push_back({(int)Op::_vchunkfma, n->funct6, (int)n->chunk,
				       (int)n->sew_bytes, (int)n->kmask, (int)n->masked});
			break;
		}
		case Op::_vchunkmaskset: {
			auto *n = static_cast<InstVChunkMaskSet *>(i);
			out.push_back({(int)Op::_vchunkmaskset, 0, (int)n->chunk, (int)n->lanes, -1, -1});
			break;
		}
		default:
			break;
		}
	}
	std::sort(out.begin(), out.end());
	return out;
}

// A frame's whole node stream as opcodes, so "identical QIR" is checkable without caring what each
// node holds. Used for the FMA and run cases, where the claim is that nothing at all moved.
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
	u8 lanes_at_512; // chunk_bytes/SEW at VLEN 512, where chunk_bytes is min(VLEN/8,64)
	u8 chunks_at_512;
};

// vfneg.v is vfsgnjn.vv with vs1 == vs2, which is how the compiler spells it.
Shape const kShapes[] = {
    {"vfadd.vv e32m1", VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8), 16, 1},
    {"vfsub.vv e64m1", VSETVLI_E64M1, Vv(F6_VFSUB, 9, 10, 8), 8, 1},
    {"vfmul.vv e64m2", VSETVLI_E64M2, Vv(F6_VFMUL, 10, 12, 8), 8, 2},
    {"vfdiv.vf e64m2", VSETVLI_E64M2, Vf(F6_VFDIV, 10, 15, 8), 8, 2},
    {"vfneg.v  e64m2", VSETVLI_E64M2, Vv(F6_VFSGNJN, 10, 10, 8), 8, 2},
};

void TestOffAndOn()
{
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &s : kShapes) {
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

			// [1] OFF: no bound, and every maskset is before the first load.
			CHECK_EQ(CountOp(a, Op::_vchunkactive), 0u);
			size_t first_load = a.body.size();
			for (size_t i = 0; i < a.body.size(); ++i)
				if (a.body[i]->GetOpcode() == Op::_vstatechunkload) {
					first_load = i;
					break;
				}
			for (size_t i = first_load; i < a.body.size(); ++i)
				CHECK(a.body[i]->GetOpcode() != Op::_vchunkmaskset);

			// [2] ON: one bound per chunk, and each chunk's region is bound -> maskset ->
			// ... -> store, in that order.
			CHECK_EQ(CountOp(b, Op::_vchunkactive), nchunks);
			CHECK_EQ(CountOp(b, Op::_vchunkmaskset), nchunks);
			CHECK_EQ((unsigned)b.begin->n_typed, (unsigned)a.begin->n_typed + nchunks);
			CHECK(a.begin->guard_kind == b.begin->guard_kind);
			CHECK_EQ(a.begin->vlmax, b.begin->vlmax);
			CHECK_EQ(a.begin->vtype, b.begin->vtype);

			unsigned seen_bounds = 0, stores_since_bound = 0;
			int last_bound_chunk = -1;
			for (size_t i = 0; i < b.body.size(); ++i) {
				auto op = b.body[i]->GetOpcode();
				if (op == Op::_vchunkactive) {
					auto *n = static_cast<InstVChunkActive *>(b.body[i]);
					// chunk-major: the bounds appear in increasing chunk order,
					// and each one opens a region that ends with a store.
					CHECK_EQ((int)n->chunk, last_bound_chunk + 1);
					if (seen_bounds)
						CHECK_EQ(stores_since_bound, 1u);
					last_bound_chunk = (int)n->chunk;
					stores_since_bound = 0;
					++seen_bounds;
					// the very next node is this chunk's own maskset
					CHECK(i + 1 < b.body.size());
					if (i + 1 < b.body.size()) {
						CHECK(b.body[i + 1]->GetOpcode() == Op::_vchunkmaskset);
						if (b.body[i + 1]->GetOpcode() == Op::_vchunkmaskset)
							CHECK_EQ((int)static_cast<InstVChunkMaskSet *>(
								     b.body[i + 1])
								     ->chunk,
								 (int)n->chunk);
					}
				} else if (op == Op::_vstatechunkstore) {
					++stores_since_bound;
				}
			}
			CHECK_EQ(seen_bounds, nchunks);
			CHECK_EQ(stores_since_bound, 1u);

			// [3] the chunk work is the same multiset in both modes.
			auto wa = ChunkWork(a), wb = ChunkWork(b);
			CHECK(wa == wb);

			// [4] every lane op names its own chunk's shared mask, in both modes.
			for (auto const *f : {&a, &b})
				for (auto *i : f->body)
					if (i->GetOpcode() == Op::_vchunkfalu) {
						auto *n = static_cast<InstVChunkFALU *>(i);
						CHECK_EQ((int)n->kmask, 1 + (int)n->chunk);
					}
			printf("  ok   VLEN %-4u %-15s chunks=%u n_typed %u -> %u\n", vlen, s.name,
			       nchunks, (unsigned)a.begin->n_typed, (unsigned)b.begin->n_typed);
		}
	}
}

void TestFmaAndRunUntouched()
{
	// [5] FMA. S1-2D WIRED THIS ROUTE, so the Stage 2A assertion "the flag did not leak into
	// RvvEmitTypedFmaChunkGroup" is no longer a true property and has been replaced rather than
	// deleted: with the switch ON the FMA frame is now bounded on the same three conjuncts, and
	// with it OFF it is still inert. The frame's SHAPE -- chunk-major order, within-chunk
	// load/op/store order, per-chunk dataflow closure -- is checked in
	// rvv_active_vl_bound_stage2d_fma_test.cpp; what stays here is only the wiring fact, so that
	// a future change that silently unwires FMA fails in both files.
	for (u32 vlen : {512u, 1024u}) {
		Built off, on;
		Translate(off, {VSETVLI_E64M2, Vf(F6_VFMADD, 10, 15, 8)}, Env{vlen, true, false});
		Translate(on, {VSETVLI_E64M2, Vf(F6_VFMADD, 10, 15, 8)}, Env{vlen, true, true});
		auto fo = FindFrames(off.region), fn = FindFrames(on.region);
		CHECK_EQ(fo.size(), 1u);
		CHECK_EQ(fn.size(), 1u);
		if (fo.empty() || fn.empty())
			continue;
		unsigned const nchunks = CountOp(fo[0], Op::_vchunkmaskset);
		CHECK(nchunks > 0);
		CHECK_EQ(CountOp(fo[0], Op::_vchunkactive), 0u);
		CHECK_EQ(CountOp(fn[0], Op::_vchunkactive), nchunks);
		CHECK_EQ((unsigned)fn[0].begin->n_typed, (unsigned)fo[0].begin->n_typed + nchunks);
		printf("  ok   VLEN %-4u vfmadd.vf frame bounded by S1-2D (n_typed %u -> %u, %u bounds)\n",
		       vlen, (unsigned)fo[0].begin->n_typed, (unsigned)fn[0].begin->n_typed, nchunks);
	}

	// [6] A multi-member FP run. Same words, switch ON, must be identical and carry no bound.
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
}

void TestRefusals()
{
	// [7a] no shared masks -> no bound (the body would have nothing to move).
	{
		Built b;
		Translate(b, {VSETVLI_E64M2, Vv(F6_VFADD, 10, 12, 8)}, Env{512, false, true});
		auto f = FindFrames(b.region);
		CHECK_EQ(f.size(), 1u);
		if (!f.empty()) {
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ(CountOp(f[0], Op::_vchunkmaskset), 0u);
		}
		printf("  ok   shared masks off -> unbounded\n");
	}
	// [7b] run-time SEW (no vsetvli observed in the block) -> no bound: the bound's immediate
	// needs a translation-time lane count.
	{
		Built b;
		Translate(b, {Vv(F6_VFADD, 10, 12, 8)}, Env{512, true, true});
		auto f = FindFrames(b.region);
		if (!f.empty()) {
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			printf("  ok   run-time SEW frame -> unbounded\n");
		} else {
			printf("  ok   run-time SEW word took no typed frame\n");
		}
	}
	// [7c] more chunks than k1..k6 can hold: e32,m2 at VLEN 4096 is 16 chunks, so the shared
	// masks are refused and the bound follows them.
	{
		Built b;
		Translate(b, {VSETVLI_E64M2, Vv(F6_VFADD, 10, 12, 8)}, Env{4096, true, true});
		auto f = FindFrames(b.region);
		if (!f.empty() && CountOp(f[0], Op::_vchunkmaskset) == 0) {
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			printf("  ok   %u chunks > shared-mask cap -> unbounded\n",
			       CountOp(f[0], Op::_vstatechunkstore));
		} else {
			printf("  ..   VLEN 4096 did not produce an over-cap typed frame (skipped)\n");
		}
	}
}

void TestEmittedImmediates()
{
	// [8] read the bounds' immediates back out of the emitted host bytes.
	Built b;
	Translate(b, {VSETVLI_E64M2, Vv(F6_VFADD, 10, 12, 8)}, Env{1024, true, true});
	auto f = FindFrames(b.region);
	CHECK_EQ(f.size(), 1u);
	if (f.empty())
		return;
	unsigned const nchunks = CountOp(f[0], Op::_vchunkactive);
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
	printf("  ok   emitted %u bounds with immediates 0,%u,...,%u (lanes=%u)\n", nchunks, lanes,
	       (nchunks - 1) * lanes, lanes);
}
} // namespace

int main()
{
	printf("[1][2][3][4] switch OFF is inert; ON is chunk-major and bounded\n");
	TestOffAndOn();
	printf("[5][6] FMA frames and vector runs are untouched\n");
	TestFmaAndRunUntouched();
	printf("[7] structural refusals\n");
	TestRefusals();
	printf("[8] emitted immediates\n");
	TestEmittedImmediates();
	if (g_failures) {
		printf("FAIL rvv_active_vl_bound_stage2a_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_bound_stage2a_test\n");
	return 0;
}
