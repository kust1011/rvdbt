// C2.1b1: minimal translator-route test for the typed QCG `vadd.vv` chunk group.
//
// SCOPE. Every test in this file's sibling suite (qra_vpr_test.cpp, vchunk_dataflow_test.cpp,
// vstatechunkload_test.cpp) builds QIR BY HAND, through a local Builder against a toy StateInfo --
// never through RV32Translator::Translate. None of them can therefore observe an admission
// DECISION: whether a real encoded guest instruction, at a given config::vlen_bits, actually takes
// the typed-chunk path, as one frame, with the right op count/order/offsets, or falls back. That is
// exactly this file's one job, via the smallest real seam that reaches the translator without
// generating or executing any code: `qir::CompilerGenRegionIR` (dbt/qmc/compile.cpp), which builds
// a Region from the real `IRTranslator::state_info` and calls the real
// `RV32Translator::Translate` -- and does nothing else (no QSel, no QRegAlloc, no QEmit, no guest
// memory, no CompilerRuntime callback).
//
// The routed instruction pair is the exact bytes `run_eligible()` in
// experiments/2026-08-24-0935-rvv-typed-chunk-vaddvv-route/src/guest_vaddvv_typed.c executes, and
// that experiment's accepted C0.1/C0.2 evidence already ran through this same decoder and the real
// runtime guard successfully (see that directory's README.md, sections 2 and 6). Reusing them means this
// test's instruction bytes are not a new, independently-unverified claim; re-confirmed live while
// writing this test via `llvm-objdump-20 -d -M no-aliases` on the locally-built
// `guest_vaddvv_typed.elf` -- gitignored by design, a generated artifact rather than checked in
// (see docs/C0_3A_SCOPE_AUDIT.md section 4.1 in that same experiment directory), present on disk from the
// C0.1-C1 evidence runs and reproducible on demand from guest_vaddvv_typed.c:
//
//   11b58: 09057557   vsetvli a0, a0, e32, m1, tu, ma
//   11b70: 021101d7   vadd.vv v3, v1, v2      (vd=3, vs2=1, vs1=2, vm=1 unmasked)
//
// This test checks two things, both read directly off the constructed Region's instruction list
// (no code generation or execution anywhere in this file):
//
//   * VLEN=512 regression control -- exactly one begin/end frame, n_typed=4, the pre-existing
//     load,load,add,store order at the pre-existing offsets. A failure here is a harness bug, not
//     a VLEN=1024 admission failure, which is why it is checked first.
//   * VLEN=1024 -- exactly one begin/end frame (not zero, not two), n_typed=8, vlmax=32, the
//     load-major eight-op order (four loads, then two adds, then two stores) at the exact +0/+64
//     per-chunk offsets, each add consuming exactly its own chunk's two loads by def-use, and the
//     SAME `id_rv32_vadd_vv` fallback stub as the VLEN=512 case.
//
// What this file does NOT check: emitted x86 bytes (already covered, at one offset at a time, by
// vstatechunkload_test.cpp/vchunk_dataflow_test.cpp's op-level extensions), arithmetic correctness
// on real data, or anything about host-CPU instruction scheduling/overlap -- none of that is
// observable at this layer, and none of it is claimed here.
//
// HOST NOTE. RvvQcgTypedChunkAdmit's host-feature row is a real `__builtin_cpu_supports` probe, not
// a build-time #ifdef. This workstation has AVX but not AVX-512F (confirmed live via /proc/cpuinfo
// while writing this test), so without `--rvv-qcg-typed-chunk-force-emit` the admission test would
// return 0 everywhere and this file would prove nothing. Force-emit is used below for exactly that
// reason and bypasses only that one row (every other admission row -- feature flag, aot_use_llvm,
// rvv_verify, VLEN, SEW -- is unchanged and still enforced). This is safe on any host, including
// this one: CheckRoute's pre-QRA inspection never reaches QSel/QRegAlloc/QEmit at all, and
// CheckRoutePostQRA (C2.2a, below) deliberately RUNS QSel and QRegAlloc but never constructs
// QEmit/QCodegen -- so on both paths no AVX-512 instruction is ever assembled or executed by this
// file.
//
// C2.2a ADDENDUM. CheckRoute above stops before QSel/QRegAlloc -- it proves the shape the
// translator constructs, but says nothing about whether that shape survives real register
// allocation, which is the layer that actually assigns physical ZMMs and is the only place a
// spill/copy `mov` could get threaded into the frame. CheckRoutePostQRA below closes exactly that
// gap. Because QSel/QRegAlloc rewrite operands in place, the same Region cannot be checked both
// before and after allocation, so each call translates its own FRESH region (same real-translator
// route as CheckRoute) and then runs `ArchTraits::init()`, `QSelPass::run()` and
// `QRegAllocPass::run()` -- the identical two passes `qcg::GenerateCode` runs
// (dbt/qmc/qcg/qcg.cpp:30-40) immediately before constructing `QEmit`. `QEmit`/`QCodegen` are
// deliberately never constructed here, so, exactly as above, no host code is generated or executed
// by this file, on any host. It then re-inspects the same begin/end frame for: every register
// operand rewritten to a physical VPR inside `ArchTraits::VPR_POOL` and outside `VPR_FIXED`; three
// (VLEN=512) or six (VLEN=1024) mutually distinct physical registers; each add/store's def-use
// still resolving to its own chunk and never the other chunk's (the low/high alias this rules out);
// and no allocator-inserted `mov` touching a V512 operand anywhere inside the frame. A scalar
// spill/fill `mov` of the preceding `vsetvli`'s dirty `a0` global is legal here and is not this
// claim -- `QRegAlloc::CallOp` runs on `rvvtypedchunkbegin` (dbt/qmc/qcg/qra.cpp) -- so only V512
// movs are checked, the same distinction qra_vpr_test.cpp's `CollectMovs(..., vector_only)` draws.
//
// C2.3a ADDENDUM.  CheckRoute and CheckRoutePostQRA above both stop before QEmit/QCodegen ever run,
// so neither has produced one byte of host code -- CheckRoute inspects the translator's own QIR,
// CheckRoutePostQRA inspects the same QIR again after QSelPass/QRegAllocPass have rewritten its
// operands in place. CheckRouteEmitted below closes that gap: it calls the REAL, unmodified
// qcg::GenerateCode (dbt/qmc/qcg/qcg.cpp:28-53) -- the exact function every real translation unit
// calls, running QSelPass, QRegAllocPass, QEmit and QCodegen in that order -- on a fresh region from
// the same real-translator route, and inspects the RETURNED HOST BYTES with an external, real x86-64
// disassembler (GNU objdump, -b binary -m i386:x86-64; confirmed live against known-good AVX-512
// bytes while writing this test, including that it resolves EVEX compressed 8-bit displacements to
// the same absolute byte offsets an independent hand assembly of the same instructions produces).
// Nothing in this file ever branches into the returned bytes: TestCompilerRuntime::AllocateCode
// below always resizes a std::vector<u8> and returns its data pointer -- there is no mmap call
// anywhere in this function, let alone a PROT_EXEC one, so there is no code path by which this test
// could execute the AVX-512 body this workstation's Ivy Bridge silicon cannot retire.
//
// Ground truth for what the bytes SHOULD contain comes from the exact same mechanism
// CheckRoutePostQRA already uses: the compiled region's own post-pipeline operands.
// qcg::GenerateCode rewrites them in place through the identical QSelPass::run/QRegAllocPass::run
// calls CheckRoutePostQRA makes by hand (qcg.cpp:35,39), so FindGroup on the SAME region after
// GenerateCode returns sees exactly what QEmit read to build the bytes above. Decoding is
// independent of that ground truth: objdump has never seen this region, this test file, or asmjit's
// encoder tables. The two are then cross-checked instruction for instruction, in program order --
// preserved end to end because no pass between QIR construction and QCodegen::Run reorders an
// existing instruction, it only ever inserts around one (see the CheckRoutePostQRA comment on frame
// movs) -- which is what makes this a claim about the ACTUAL emitted bytes, not about the IR that
// was supposed to produce them.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/qmc/qir_printer.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using namespace dbt::qcg;

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

#define CHECK_EQ(a, b)                                                                                      \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,   \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));

// Chunk 0 is a register's low 64-byte half, chunk 1 its high half -- the exact `r*VLEN_MAX_BYTES +
// chunk*64` formula rv32_qir.cpp's TRANSLATOR(vadd_vv) uses for both the VLEN=512 (chunk=0 only)
// and VLEN=1024 (chunk 0 and 1) shapes.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// The routed instruction pair -- see the file header for provenance and the exact hex.
constexpr u32 INSN_VSETVLI = 0x09057557u; // vsetvli a0, a0, e32, m1, tu, ma
constexpr u32 INSN_VADD_VV = 0x021101d7u; // vadd.vv v3, v1, v2
constexpr u32 VS2_REG = 1;		   // v1
constexpr u32 VS1_REG = 2;		   // v2
constexpr u32 VD_REG = 3;		   // v3

// One region containing exactly the translated vsetvli + vadd.vv pair, for one VLEN. Region is
// arena-allocated, so `arena` must outlive it -- both are locals in the caller's own scope.
Region *TranslateOne(MemArena &arena, u32 words[2], u32 vlen_bits)
{
	config::rvv_qcg_typed_chunk = true;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk_force_emit = true; // see file header HOST NOTE
	config::vlen_bits = vlen_bits;

	CompilerJob::IpRangesSet ranges = {{0u, 8u}}; // two 4-byte instructions at ip 0 and 4
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

struct Group {
	unsigned n_begin = 0, n_end = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body; // strictly between begin and end, in construction (== emission) order
};

Group FindGroup(Region *region)
{
	Group g;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				++g.n_begin;
				g.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				++g.n_end;
				g.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				open = false;
				continue;
			}
			if (open) {
				g.body.push_back(&ins);
			}
		}
	}
	return g;
}

// Shared shape check for VLEN=512 (nchunks=1, the pre-existing shape) and VLEN=1024 (nchunks=2,
// the C2.1b generalization): admission observed through the real translator, one frame,
// n_typed=4*nchunks, load-major body, exact per-chunk offsets, and def-use from each add back to
// its own chunk's two loads.
void CheckRoute(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax)
{
	printf("  %s: vlen=%u expect nchunks=%u expect vlmax=%u\n", tag, vlen_bits, nchunks, expect_vlmax);

	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Region *region = TranslateOne(arena, words, vlen_bits);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		fprintf(stderr, "  %s: wrong number of typed-chunk frames, cannot check further\n", tag);
		return;
	}

	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vadd_vv);
	{
		// Direct evidence the admitted shape really is SEW=32/LMUL=1, not a stale guard.
		rv32::VType const vt{g.begin->vtype};
		CHECK_EQ(vt.sew(), 32u);
		CHECK_EQ((int)vt.lmul_log2(), 0);
	}

	CHECK_EQ(g.body.size(), (size_t)(4 * nchunks));
	if (g.body.size() != 4 * nchunks) {
		return;
	}

	// Load-major: every chunk's two source loads first (vs2 then vs1, matching construction
	// order), then every chunk's add, then every chunk's store. At nchunks=1 this collapses to
	// exactly the pre-existing load,load,add,store sequence.
	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * c]->GetOpcode() == Op::_vstatechunkload;
		shape_ok = shape_ok && g.body[2 * c + 1]->GetOpcode() == Op::_vstatechunkload;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * nchunks + c]->GetOpcode() == Op::_vchunkadd;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[3 * nchunks + c]->GetOpcode() == Op::_vstatechunkstore;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		return;
	}

	std::vector<RegN> distinct_defs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(g.body[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(g.body[2 * c + 1]);
		auto *add = static_cast<InstVChunkAdd *>(g.body[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(g.body[3 * nchunks + c]);

		CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));
		CHECK_EQ(store->offs, ChunkOffs(VD_REG, c));

		CHECK(l_s2->o(0).IsVVPR());
		CHECK(l_s1->o(0).IsVVPR());
		CHECK(add->o(0).IsVVPR());
		CHECK(add->i(0).IsVVPR());
		CHECK(add->i(1).IsVVPR());
		CHECK(store->i(0).IsVVPR());
		if (!(l_s2->o(0).IsVVPR() && l_s1->o(0).IsVVPR() && add->i(0).IsVVPR() && add->i(1).IsVVPR() &&
		      add->o(0).IsVVPR() && store->i(0).IsVVPR())) {
			continue;
		}

		RegN const want_a = l_s2->o(0).GetVVPR();
		RegN const want_b = l_s1->o(0).GetVVPR();
		RegN const got_a = add->i(0).GetVVPR();
		RegN const got_b = add->i(1).GetVVPR();
		// def-use, not textual adjacency: the add must consume exactly this chunk's own two
		// loads, order-independent (addition is commutative and the design does not promise
		// which QIR input slot each source lands in) -- the same technique
		// vchunk_dataflow_test.cpp's CaptureIntent/SimulateV512 use for the identical op.
		CHECK((got_a == want_a && got_b == want_b) || (got_a == want_b && got_b == want_a));
		CHECK_EQ(add->o(0).GetVVPR(), store->i(0).GetVVPR());

		distinct_defs.push_back(want_a);
		distinct_defs.push_back(want_b);
		distinct_defs.push_back(add->o(0).GetVVPR());
	}

	// Six fresh virtual V512 identities at nchunks=2 (two loads + one add per chunk), three at
	// nchunks=1 -- a naming fact about distinct region-wide virtual indices, not a claim that
	// they are ever simultaneously register-resident (this test performs no register
	// allocation at all).
	std::sort(distinct_defs.begin(), distinct_defs.end());
	distinct_defs.erase(std::unique(distinct_defs.begin(), distinct_defs.end()), distinct_defs.end());
	CHECK_EQ(distinct_defs.size(), (size_t)(3 * nchunks));

	printf("  %s: OK n_typed=%u vlmax=%u body=%zu distinct V512 values=%zu\n", tag, g.begin->n_typed,
	       g.begin->vlmax, g.body.size(), distinct_defs.size());
}

// C2.2a: post-QRA check -- see the C2.2a ADDENDUM in the file header for what this closes and why a
// fresh region is required. Same real-translator route as CheckRoute; the only addition is running
// the real QSel/QRegAlloc pipeline (never QEmit/QCodegen) before inspecting the frame.
void CheckRoutePostQRA(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax)
{
	printf("  %s (post-QRA): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Region *region = TranslateOne(arena, words, vlen_bits);

	// The exact two passes qcg::GenerateCode runs before constructing QEmit
	// (dbt/qmc/qcg/qcg.cpp:30-40). QEmit/QCodegen are deliberately never constructed below, so no
	// host code is generated or executed, on any host.
	ArchTraits::init();
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(region, &mri);
	qcg::QRegAllocPass::run(region);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		fprintf(stderr, "  %s: wrong number of typed-chunk frames after QRA, cannot check further\n",
			tag);
		return;
	}

	// n_typed/vlmax/stub are plain scalar fields on the begin/end nodes, not operands -- QSel and
	// QRegAlloc rewrite operands, not fields, but that is re-checked here rather than assumed.
	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vadd_vv);

	// Split the frame body into the typed ops (load/add/store) and any `mov` the allocator threaded
	// through it. A scalar spill/fill of the preceding vsetvli's dirty `a0` global can legally land
	// here (QRegAlloc::CallOp runs on rvvtypedchunkbegin, dbt/qmc/qcg/qra.cpp) and is not part of
	// this claim, so movs are checked separately below instead of folded into one body-length
	// assertion that a harmless scalar mov could trip for the wrong reason.
	std::vector<Inst *> typed_ops;
	std::vector<Inst *> frame_movs;
	for (auto *ins : g.body) {
		if (ins->GetOpcode() == Op::_mov) {
			frame_movs.push_back(ins);
		} else {
			typed_ops.push_back(ins);
		}
	}

	// Proves no allocator-inserted V512 mov appears inside the frame -- a spill, fill or
	// cross-class copy of a vector value is always emitted as Op::_mov with a V512 operand
	// (QRegAlloc::EmitSpill/EmitFill/AllocOpInputV), the same signature qra_vpr_test.cpp's
	// CollectMovs(..., vector_only=true) uses to find them on the hand-built mechanism case.
	for (auto *ins : frame_movs) {
		auto *u = static_cast<InstUnop *>(ins);
		bool const is_v512 = u->o(0).GetType() == VType::V512 || u->i(0).GetType() == VType::V512;
		CHECK(!is_v512);
		if (is_v512) {
			fprintf(stderr, "  %s: allocator inserted a V512 mov inside the typed frame (id=%u)\n",
				tag, ins->GetId());
		}
	}

	CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
	if (typed_ops.size() != 4 * nchunks) {
		return;
	}

	// Load-major order is unchanged: QSel::Run and QRegAlloc::Run both walk each block strictly in
	// list order and only ever insert around an instruction, never reorder one (CheckRoute's
	// comment above; C2.1a audit section 5).
	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && typed_ops[2 * c]->GetOpcode() == Op::_vstatechunkload;
		shape_ok = shape_ok && typed_ops[2 * c + 1]->GetOpcode() == Op::_vstatechunkload;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && typed_ops[2 * nchunks + c]->GetOpcode() == Op::_vchunkadd;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && typed_ops[3 * nchunks + c]->GetOpcode() == Op::_vstatechunkstore;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		return;
	}

	std::vector<RegN> distinct_pregs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *add = static_cast<InstVChunkAdd *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);

		// Exact low/high state offsets remain unchanged: `offs` is a translation-time u16 constant,
		// not an operand, so QSel/QRegAlloc structurally cannot touch it -- re-checked anyway.
		CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));
		CHECK_EQ(store->offs, ChunkOffs(VD_REG, c));

		// After QRegAllocPass every register operand is rewritten from a virtual VVPR to a physical
		// PVPR (qra.cpp AllocOpOutputV/AllocOpInputV).
		CHECK(l_s2->o(0).IsPVPR());
		CHECK(l_s1->o(0).IsPVPR());
		CHECK(add->o(0).IsPVPR());
		CHECK(add->i(0).IsPVPR());
		CHECK(add->i(1).IsPVPR());
		CHECK(store->i(0).IsPVPR());
		if (!(l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && add->i(0).IsPVPR() && add->i(1).IsPVPR() &&
		      add->o(0).IsPVPR() && store->i(0).IsPVPR())) {
			continue;
		}

		for (auto o : {l_s2->o(0), l_s1->o(0), add->o(0)}) {
			CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
			CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
		}

		RegN const want_a = l_s2->o(0).GetPVPR();
		RegN const want_b = l_s1->o(0).GetPVPR();
		RegN const got_a = add->i(0).GetPVPR();
		RegN const got_b = add->i(1).GetPVPR();
		// def-use survives allocation, per chunk: the add must still consume exactly THIS chunk's
		// own two loads (order-independent, same reasoning as CheckRoute). This is the low/high
		// alias check -- chunk c's add resolving to chunk c' != c's physical register would pass a
		// bare "3*nchunks distinct regs total" count if the two chunks' sets happened to overlap
		// elsewhere in a compensating way, but cannot pass this per-chunk identity check.
		CHECK((got_a == want_a && got_b == want_b) || (got_a == want_b && got_b == want_a));
		CHECK_EQ(add->o(0).GetPVPR(), store->i(0).GetPVPR());

		distinct_pregs.push_back(want_a);
		distinct_pregs.push_back(want_b);
		distinct_pregs.push_back(add->o(0).GetPVPR());
	}

	// Three distinct allocated VPRs at VLEN=512, six at VLEN=1024 -- now a claim about physical ZMM
	// numbers QRegAllocPass actually handed out, one allocation stage later than CheckRoute's
	// equivalent distinct-virtual-index check.
	std::sort(distinct_pregs.begin(), distinct_pregs.end());
	distinct_pregs.erase(std::unique(distinct_pregs.begin(), distinct_pregs.end()), distinct_pregs.end());
	CHECK_EQ(distinct_pregs.size(), (size_t)(3 * nchunks));

	printf("  %s: OK post-QRA distinct VPRs=%zu frame movs=%zu (zmm", tag, distinct_pregs.size(),
	       frame_movs.size());
	for (auto p : distinct_pregs) {
		printf(" %u", p);
	}
	printf(")\n");
}

// ---------------------------------------------------------------------------------------------
// C2.3a: real host-code emission and independent disassembly (see the file header ADDENDUM).
// ---------------------------------------------------------------------------------------------

// A CompilerRuntime whose AllocateCode NEVER mmaps anything, executable or not: it always resizes a
// std::vector<u8> and hands back its data pointer. This is the structural guarantee behind "never
// executed" -- there is no mmap call anywhere in this object's lifetime, let alone a PROT_EXEC one,
// so no code path in this file could branch into the returned bytes even by mistake. Contrast with
// the executable=true mode of vchunk_dataflow_test.cpp's TestCompilerRuntime, which this file
// deliberately does not reproduce.
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}

	std::vector<u8> buf;
};

// One zmm-touching instruction decoded from objdump's Intel-syntax, no-raw-bytes output, independent
// of how it was built. `disp` is the resolved [r13+disp] displacement for LOAD/STORE; ADD has none.
struct DecodedVec {
	enum class Kind { LOAD, ADD, STORE } kind;
	std::string mnemonic;
	unsigned dst{}, src0{}, src1{};
	i64 disp{};
	bool has_disp{};
};

// "zmm<N>" -> N. Rejects anything with a non-digit suffix rather than parsing a prefix and ignoring
// the rest, so an operand this does not fully recognise is reported as unparsed rather than misread.
bool ParseZmm(std::string const &tok, unsigned *out)
{
	if (tok.size() < 4 || tok.compare(0, 3, "zmm") != 0) {
		return false;
	}
	size_t i = 3;
	if (!isdigit((unsigned char)tok[i])) {
		return false;
	}
	unsigned v = 0;
	while (i < tok.size() && isdigit((unsigned char)tok[i])) {
		v = v * 10 + (unsigned)(tok[i] - '0');
		++i;
	}
	*out = v;
	return i == tok.size();
}

// "ZMMWORD PTR [r13+0x<hex>]" or "...-0x<hex>]" -> disp. Only the r13-relative form is accepted:
// nothing in the typed chunk group ever emits any other base or an absolute [disp32] operand -- that
// is vchunkload/store's shape (a guest address), not vstatechunkload/store's (dbt/qmc/qir.h).
bool ParseZmmWordR13(std::string const &tok, i64 *disp)
{
	static std::string const prefix = "ZMMWORD PTR [r13";
	if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}
	size_t i = prefix.size();
	bool neg = tok[i] == '-';
	if (tok[i] != '+' && tok[i] != '-') {
		return false;
	}
	++i;
	if (tok.compare(i, 2, "0x") != 0) {
		return false;
	}
	i += 2;
	size_t start = i;
	i64 v = 0;
	while (i < tok.size() && isxdigit((unsigned char)tok[i])) {
		char c = (char)tolower((unsigned char)tok[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
		++i;
	}
	if (i == start || i >= tok.size() || tok[i] != ']' || i + 1 != tok.size()) {
		return false;
	}
	*disp = neg ? -v : v;
	return true;
}

std::vector<std::string> SplitCommas(std::string const &s)
{
	std::vector<std::string> out;
	size_t start = 0;
	for (size_t i = 0; i <= s.size(); ++i) {
		if (i == s.size() || s[i] == ',') {
			out.push_back(s.substr(start, i - start));
			start = i + 1;
		}
	}
	return out;
}

// Parse one `objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn` line. Only the two
// shapes the typed chunk group can ever emit are recognised -- a two-operand vmovdqu64 (register,
// [r13+disp]) and a three-register vpadd{b,w,d,q} -- everything else (the scalar guard/fallback/
// prologue code around the frame) returns false and is simply not a vector instruction, not a parse
// error.
bool ParseLine(std::string const &line, DecodedVec *out)
{
	size_t tab = line.find('\t');
	if (tab == std::string::npos) {
		return false;
	}
	std::string rhs = line.substr(tab + 1);
	size_t sp = rhs.find(' ');
	std::string mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	std::string operand_str = sp == std::string::npos ? std::string() : rhs.substr(sp + 1);
	auto ops = SplitCommas(operand_str);

	if (mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned zr;
		i64 disp;
		if (ParseZmm(ops[0], &zr) && ParseZmmWordR13(ops[1], &disp)) {
			*out = DecodedVec{DecodedVec::Kind::LOAD, mnem, zr, 0, 0, disp, true};
			return true;
		}
		if (ParseZmmWordR13(ops[0], &disp) && ParseZmm(ops[1], &zr)) {
			*out = DecodedVec{DecodedVec::Kind::STORE, mnem, 0, zr, 0, disp, true};
			return true;
		}
		return false;
	}
	if ((mnem == "vpaddb" || mnem == "vpaddw" || mnem == "vpaddd" || mnem == "vpaddq") && ops.size() == 3) {
		unsigned d, s0, s1;
		if (ParseZmm(ops[0], &d) && ParseZmm(ops[1], &s0) && ParseZmm(ops[2], &s1)) {
			*out = DecodedVec{DecodedVec::Kind::ADD, mnem, d, s0, s1, 0, false};
			return true;
		}
	}
	return false;
}

// Write `code` to a private temp file, disassemble it as a raw flat x86-64 binary with GNU objdump,
// and return the decoded lines verbatim, one per element, in file order (== program order: objdump
// disassembles linearly from offset 0, and every byte here is real code with no embedded data).
// Fails loudly (empty result plus a printed diagnostic) rather than skipping, unlike the AVX-512
// CPUID checks elsewhere in this suite -- a missing or failing disassembler means C2.3a's evidence
// cannot be produced at all, which is a hard failure here, not an expected environment gap.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_c23a_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write to temp file failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);

	std::string cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		fprintf(stderr, "  popen(objdump) failed: %s\n", strerror(errno));
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	std::string cur;
	while (fgets(buf, sizeof(buf), p)) {
		cur += buf;
		if (!cur.empty() && cur.back() == '\n') {
			cur.pop_back();
			lines.push_back(cur);
			cur.clear();
		}
	}
	if (!cur.empty()) {
		lines.push_back(cur);
	}
	int rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		for (auto &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return {};
	}
	return lines;
}

// True if `line` mentions a ZMM register operand anywhere. The lowercase "zmm" substring appears
// only inside objdump's Intel-syntax register names ("zmm0".."zmm31"); the memory-size keyword is
// spelled "ZMMWORD" (uppercase Z-M-M), so this cannot false-positive on a plain memory-size operand.
// Deliberately independent of, and looser than, ParseLine's own shape-specific parsing -- that
// asymmetry is what lets the two be combined to catch a ZMM-bearing line neither recognises.
bool MentionsZmm(std::string const &line)
{
	return line.find("zmm") != std::string::npos;
}

// One compact, single-line record per decoded vector instruction: mnemonic, every ZMM operand, and
// the resolved [r13+disp] state displacement for LOAD/STORE -- so each of the 4 (VLEN=512) or 8
// (VLEN=1024) typed-frame instructions is independently readable from stdout, not merely counted.
void PrintDecodedVec(char const *tag, size_t idx, DecodedVec const &v)
{
	switch (v.kind) {
	case DecodedVec::Kind::LOAD:
		printf("  %s: vec[%zu] LOAD  %s zmm%u <- [r13+0x%llx]\n", tag, idx, v.mnemonic.c_str(), v.dst,
		       (unsigned long long)v.disp);
		break;
	case DecodedVec::Kind::ADD:
		printf("  %s: vec[%zu] ADD   %s zmm%u <- zmm%u, zmm%u\n", tag, idx, v.mnemonic.c_str(), v.dst,
		       v.src0, v.src1);
		break;
	case DecodedVec::Kind::STORE:
		printf("  %s: vec[%zu] STORE %s [r13+0x%llx] <- zmm%u\n", tag, idx, v.mnemonic.c_str(),
		       (unsigned long long)v.disp, v.src0);
		break;
	}
}

// Routes the real translator's region through the REAL emission pipeline (qcg::GenerateCode: QSel ->
// QRegAlloc -> QEmit -> QCodegen), independently disassembles the returned bytes with objdump, and
// cross-checks the decoded instructions -- in program order -- against the same region's
// post-pipeline operands. See the file header C2.3a ADDENDUM for what this proves and what it
// deliberately never does (execute the bytes).
void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax)
{
	printf("  %s (emitted): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Region *region = TranslateOne(arena, words, vlen_bits);

	TestCompilerRuntime cruntime;
	// Unlike the hand-built regions in vchunk_dataflow_test.cpp/vstatechunkload_test.cpp (which pass
	// segment=nullptr because they never reach a terminator), a REAL CompilerGenRegionIR translation
	// always ends in a block-exit instruction (here, Emit_gbr to the fallthrough ip) that
	// dereferences `segment` (qemit.cpp's Emit_gbr: `segment->InSegment(...)`) -- so this needs the
	// same CodeSegment shape TranslateOne gave the translator's own CompilerJob.
	qir::CodeSegment segment(0u, 0x1000u);
	auto code_span = qcg::GenerateCode(&cruntime, &segment, region, 0);
	CHECK(!code_span.empty());
	if (code_span.empty()) {
		return;
	}
	std::vector<u8> code(code_span.begin(), code_span.end());

	// Ground truth: the SAME region, after qcg::GenerateCode has already run QSelPass and
	// QRegAllocPass internally (qcg.cpp:35,39) -- operands are rewritten in place, so this reads
	// exactly what QEmit read to build the bytes above.
	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		fprintf(stderr, "  %s: wrong number of typed-chunk frames, cannot check emitted bytes\n", tag);
		return;
	}
	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vadd_vv);

	// Same split CheckRoutePostQRA already makes: a legal scalar spill/fill mov of the preceding
	// vsetvli's dirty a0 global may land inside the frame, so the typed ops are isolated from any
	// such mov before indexing into them positionally. A V512 mov may not (qra_vpr_test.cpp's
	// vector_only distinction) -- checked here too rather than assumed, even though QEmit's own
	// Emit_mov would Panic the whole process before returning any code if one existed.
	std::vector<Inst *> typed_ops;
	std::vector<Inst *> frame_movs;
	for (auto *ins : g.body) {
		if (ins->GetOpcode() == Op::_mov) {
			frame_movs.push_back(ins);
		} else {
			typed_ops.push_back(ins);
		}
	}
	for (auto *ins : frame_movs) {
		auto *u = static_cast<InstUnop *>(ins);
		bool const is_v512 = u->o(0).GetType() == VType::V512 || u->i(0).GetType() == VType::V512;
		CHECK(!is_v512);
	}
	CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
	if (typed_ops.size() != 4 * nchunks) {
		fprintf(stderr, "  %s: unexpected typed op count %zu, cannot check emitted bytes\n", tag,
			typed_ops.size());
		return;
	}

	auto lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		fprintf(stderr, "  %s: objdump produced no usable output, cannot verify emitted bytes\n", tag);
		return;
	}

	// Every line objdump decoded is accounted for: recognized typed-frame vector instructions are
	// kept, ordinary scalar lines (no ZMM operand at all -- the guard/fallback/prologue code around
	// the frame) are silently skipped, and anything in between -- a line that NAMES a ZMM register
	// but does not match either shape ParseLine recognises -- is the evidence hole this checkpoint
	// closes: previously it was silently dropped, so an unexpected form (a masked/broadcast EVEX
	// variant, a register-register copy, a non-r13-based spill/fill, ...) could pass through
	// unnoticed and simply not be counted. That must fail loudly instead, with the exact line.
	std::vector<DecodedVec> vecs;
	for (auto &l : lines) {
		DecodedVec dv{};
		if (ParseLine(l, &dv)) {
			vecs.push_back(dv);
			continue;
		}
		bool const is_scalar = !MentionsZmm(l);
		CHECK(is_scalar);
		if (!is_scalar) {
			fprintf(stderr, "  %s: unrecognized ZMM-bearing disassembly line: %s\n", tag, l.c_str());
		}
	}

	// Traceable per-instruction evidence: every recognized vector instruction, in program order,
	// with its mnemonic, ZMM operands and (for LOAD/STORE) resolved state displacement -- so the
	// exact 4 (VLEN=512) or 8 (VLEN=1024) instructions can be read individually off stdout rather
	// than inferred from the aggregate counts checked below.
	for (size_t i = 0; i < vecs.size(); ++i) {
		PrintDecodedVec(tag, i, vecs[i]);
	}

	CHECK_EQ(vecs.size(), (size_t)(4 * nchunks));
	if (vecs.size() != 4 * nchunks) {
		fprintf(stderr,
			"  %s: expected %u zmm-touching instructions, objdump decoded %zu; full "
			"disassembly:\n",
			tag, 4 * nchunks, vecs.size());
		for (auto &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return;
	}

	// Program order is preserved end to end (file header), so decoded[i] must be the same opcode
	// CLASS as typed_ops[i], in the same load-major position CheckRoute/CheckRoutePostQRA already
	// established for the IR.
	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * c].kind == DecodedVec::Kind::LOAD;
		shape_ok = shape_ok && vecs[2 * c + 1].kind == DecodedVec::Kind::LOAD;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * nchunks + c].kind == DecodedVec::Kind::ADD;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[3 * nchunks + c].kind == DecodedVec::Kind::STORE;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: decoded instruction order is not load-major\n", tag);
		return;
	}

	std::vector<unsigned> chunk_regs[2]; // registers this chunk's decoded bytes name (c < 2 only)
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *add = static_cast<InstVChunkAdd *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);
		auto &d_l_s2 = vecs[2 * c];
		auto &d_l_s1 = vecs[2 * c + 1];
		auto &d_add = vecs[2 * nchunks + c];
		auto &d_store = vecs[3 * nchunks + c];

		bool operands_ok = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && add->o(0).IsPVPR() &&
				   add->i(0).IsPVPR() && add->i(1).IsPVPR() && store->i(0).IsPVPR();
		CHECK(operands_ok);
		if (!operands_ok) {
			continue;
		}

		// Loads: decoded destination zmm and displacement must be the exact physical register
		// QRegAlloc chose and the exact low/high vector-state offset the translator assigned this
		// chunk -- not merely some zmm at some offset.
		CHECK_EQ((u32)d_l_s2.dst, (u32)l_s2->o(0).GetPVPR());
		CHECK(d_l_s2.has_disp);
		CHECK_EQ(d_l_s2.disp, (i64)l_s2->offs);
		CHECK_EQ(d_l_s2.disp, (i64)ChunkOffs(VS2_REG, c));

		CHECK_EQ((u32)d_l_s1.dst, (u32)l_s1->o(0).GetPVPR());
		CHECK(d_l_s1.has_disp);
		CHECK_EQ(d_l_s1.disp, (i64)l_s1->offs);
		CHECK_EQ(d_l_s1.disp, (i64)ChunkOffs(VS1_REG, c));

		// Add: SEW=32 selects vpaddd (Emit_vchunkadd's sew_bytes switch, qemit.cpp), and its
		// decoded sources must be exactly THIS chunk's own two loads' destinations, order-
		// independent for the same reason CheckRoute's def-use check is (addition is commutative
		// and nothing here promises which QIR input slot lands in which decoded operand
		// position) -- and never the other chunk's, which is the low/high alias this rules out.
		CHECK(d_add.mnemonic == "vpaddd");
		CHECK_EQ((u32)d_add.dst, (u32)add->o(0).GetPVPR());
		bool add_matches_own_loads = (d_add.src0 == d_l_s2.dst && d_add.src1 == d_l_s1.dst) ||
					      (d_add.src0 == d_l_s1.dst && d_add.src1 == d_l_s2.dst);
		CHECK(add_matches_own_loads);
		if (!add_matches_own_loads) {
			fprintf(stderr,
				"  %s: chunk %u decoded add reads zmm%u,zmm%u; this chunk's own loads are "
				"zmm%u/zmm%u\n",
				tag, c, d_add.src0, d_add.src1, d_l_s2.dst, d_l_s1.dst);
		}

		// Store: decoded source register must be THIS chunk's own add's destination, and the
		// displacement must be this chunk's own vd offset.
		CHECK_EQ((u32)d_store.src0, (u32)add->o(0).GetPVPR());
		CHECK_EQ((u32)d_store.src0, (u32)d_add.dst);
		CHECK(d_store.has_disp);
		CHECK_EQ(d_store.disp, (i64)store->offs);
		CHECK_EQ(d_store.disp, (i64)ChunkOffs(VD_REG, c));

		if (c < 2) {
			chunk_regs[c] = {d_l_s2.dst, d_l_s1.dst, d_add.dst};
		}
	}

	// No artificial cross-chunk dependency: at VLEN=1024 the two chunks' decoded registers must be
	// completely disjoint SETS, read straight off objdump's output -- not merely "the totals
	// differ", but that no register named anywhere in chunk 0's decoded bytes is named anywhere in
	// chunk 1's. This is independent of the post-QRA distinctness C2.2a already established from
	// QIR alone: here it is re-derived from the actual emitted, externally-decoded bytes.
	if (nchunks == 2) {
		bool disjoint = true;
		for (auto r0 : chunk_regs[0]) {
			for (auto r1 : chunk_regs[1]) {
				disjoint = disjoint && r0 != r1;
			}
		}
		CHECK(disjoint);
		if (!disjoint) {
			fprintf(stderr, "  %s: chunk 0 and chunk 1 share a physical ZMM in the decoded bytes\n",
				tag);
		}
		printf("  %s: chunk0 zmm{%u,%u,%u} chunk1 zmm{%u,%u,%u} disjoint=%d\n", tag, chunk_regs[0][0],
		       chunk_regs[0][1], chunk_regs[0][2], chunk_regs[1][0], chunk_regs[1][1],
		       chunk_regs[1][2], (int)disjoint);
	}

	unsigned n_add_chains = 0;
	for (auto &v : vecs) {
		n_add_chains += (v.kind == DecodedVec::Kind::ADD);
	}
	CHECK_EQ(n_add_chains, nchunks);

	printf("  %s: OK objdump-decoded %zu/%u zmm instructions, %u vpaddd chain(s), bytes never "
	       "executed\n",
	       tag, vecs.size(), 4 * nchunks, n_add_chains);
}

} // namespace

namespace
{

// ---------------------------------------------------------------------------------------------
// C3.1f: unknown-vtype typed admission.
//
// rvv_bb_vtype is translation-block scoped -- reset at every TB entry, set only by a vsetvli in
// that same TB. A guest that hoists its vsetvli into another function leaves it ~0u, and before
// C3.1f every typed/diag/SSE2 path was skipped, so the routed instruction fell to the helper. The
// emitted guard never trusted that observation anyway: Emit_rvvtypedchunkbegin COMPARES the live
// vtype/vl/vstart against constants on the node. So with nothing observed the one admitted shape
// (e32,m1,ta,ma, built from RVV field constants) is offered as a candidate and the same guard
// proves it at run time.
//
// These regions contain a vadd.vv and NOTHING else, which is what makes rvv_bb_vtype unknown. The
// region starts at ip 0, so rv32_qir.cpp's `ip >= 4` pre-block recovery cannot read a preceding
// word either -- and that recovery is additionally gated on RvvSSAEnabled(), left false here.
// ---------------------------------------------------------------------------------------------

// vsetvli encodings, built from the vtype fields rather than pasted: bit31=0, zimm11 in [30:20],
// rs1 in [19:15], funct3=0b111, rd in [11:7], opcode 0x57. rd/rs1 match INSN_VSETVLI's x10/x10, and
// vsetvli(0x090) reproduces INSN_VSETVLI exactly, which is how these were checked.
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
// e64,m1,ta,ma. The TYPED arm does not admit it (`RvvQcgTypedChunkAdmit` requires sew_bytes==4);
// the DIAGNOSTIC arm does (sew_bytes 1/2/4/8 are all one packed add). Both facts are asserted
// below, by two different cases.
constexpr u32 VTYPE_E64_M1_TA_MA = Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
// The vsetvli that sets it, built from the same fields so the encoding and the expected vtype
// cannot drift apart.
constexpr u32 INSN_VSETVLI_E64 = EncodeVsetvli(VTYPE_E64_M1_TA_MA);

// One region containing exactly one instruction at ip 0, with both chunk arms' switches under the
// caller's control. C3.2a-fix1 made the unknown-vtype candidate available to the diagnostic arm as
// well as the typed one, so the arm selection -- not just "typed on/off" -- is now what these cases
// vary. `rvv_direct` is the shared prerequisite of both arms (contract section 4.1) and is a
// parameter too, because arm H is exactly its off-state.
Region *TranslateSoloArm(MemArena &arena, u32 words[1], u32 vlen_bits, bool direct_enabled,
			 bool diag_enabled, bool typed_enabled)
{
	config::rvv_qcg_typed_chunk = typed_enabled;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = direct_enabled;
	config::rvv_qcg_diag_chunk = diag_enabled;
	config::rvv_vector_ssa = false; // the ip-4 recovery path stays off
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_diag_chunk_force_emit = true; // same host-feature bypass, same reason
	config::vlen_bits = vlen_bits;

	CompilerJob::IpRangesSet ranges = {{0u, 4u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

// The pre-existing two-argument form, preserved so the C3.1f cases below read exactly as they did
// when they were accepted: arm I on, diagnostic arm off.
Region *TranslateSolo(MemArena &arena, u32 words[1], u32 vlen_bits, bool typed_enabled)
{
	return TranslateSoloArm(arena, words, vlen_bits, /*direct_enabled=*/true,
				/*diag_enabled=*/false, typed_enabled);
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == op)
				++n;
	return n;
}

// ADMITTED: no vsetvli anywhere in the block, yet the typed frame is built, and its guard carries
// the candidate vtype and the VLMAX derived from it -- not from any observation.
static void CheckUnknownVtypeAdmitted(char const *label, u32 vlen_bits, u32 want_chunks,
				      u32 want_vlmax)
{
	printf("%s: unknown-vtype typed admission\n", label);
	MemArena arena(1u << 20);
	u32 words[1] = {INSN_VADD_VV};
	Region *region = TranslateSolo(arena, words, vlen_bits, /*typed_enabled=*/true);
	Group g = FindGroup(region);

	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end)
		return;
	// The candidate is the field-built constant, not whatever a previous block happened to set.
	CHECK_EQ(g.begin->vtype, rv32::VTYPE_E32_M1_TA_MA);
	CHECK_EQ(g.begin->vlmax, want_vlmax);
	CHECK_EQ(g.begin->n_typed, (u8)(4u * want_chunks));
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vadd_vv);
	// Same body shape the observed-vtype route produces: 2*chunks loads, chunks adds, chunks stores.
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), 2u * want_chunks);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), want_chunks);
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), want_chunks);
	// Offered to the typed route only: no diagnostic frame and no SSE2 direct lowering appeared.
	CHECK_EQ(CountOp(region, Op::_rvvdiagchunkbegin), 0u);
	CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	printf("  vtype=0x%08x vlmax=%u n_typed=%u loads=%u adds=%u stores=%u\n", g.begin->vtype,
	       g.begin->vlmax, g.begin->n_typed, CountOp(region, Op::_vstatechunkload),
	       CountOp(region, Op::_vchunkadd), CountOp(region, Op::_vstatechunkstore));
}

// REJECTED: with --rvv-qcg-typed-chunk off, an unknown vtype must produce no typed frame at all.
// There is no separate switch for the dynamic candidate, so this is the whole off-state.
static void CheckUnknownVtypeDefaultOff(char const *label, u32 vlen_bits)
{
	printf("%s: unknown-vtype, typed chunk DISABLED\n", label);
	MemArena arena(1u << 20);
	u32 words[1] = {INSN_VADD_VV};
	Region *region = TranslateSolo(arena, words, vlen_bits, /*typed_enabled=*/false);
	Group g = FindGroup(region);

	CHECK_EQ(g.n_begin, 0u);
	CHECK_EQ(g.n_end, 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), 0u);
	// It must reach the helper directly, not the diagnostic or SSE2 arm.
	CHECK_EQ(CountOp(region, Op::_rvvdiagchunkbegin), 0u);
	CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	printf("  no typed frame, no diag frame, no rvvaddv\n");
}

// An observed e64 vtype must not be replaced with the old e32 candidate. It now
// uses the general integer path, which admits the observed width and partial VL.
static void CheckObservedVtypePrecedence(char const *label, u32 vlen_bits)
{
	printf("%s: observed non-admitted vtype takes precedence\n", label);
	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI_E64, INSN_VADD_VV};

	config::rvv_qcg_typed_chunk = true;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::vlen_bits = vlen_bits;
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	CHECK(g.begin && g.begin->vtype == ((INSN_VSETVLI_E64 >> 20) & 0x7ffu));
	CHECK(g.begin && g.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeInteger);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkpartialalu), vlen_bits / 512u);
	printf("  vsetvli e64,m1 (0x%08x) observed -> general integer frame\n",
	       INSN_VSETVLI_E64);
}

// ---------------------------------------------------------------------------------------------
// C3.2a-fix1: the unknown-vtype candidate reaches the DIAGNOSTIC arm too.
//
// Why this exists. Contract section 4.1's arm D is the primary method control for arm I: same
// admission, same guard frame, same 512-bit width, same chunk count, differing in ONE design axis
// -- typed allocated V512 value versus emitter-hardcoded register fed from CPUState. Before this
// fix the unknown-vtype candidate was offered to I only, so on a kernel that hoists its vsetvli out
// of the timed block (which K1 does deliberately) arm D admitted nothing, ran the helper, and was
// silently a second copy of arm H. The comparison would then have measured an admission asymmetry
// rather than the axis it claims. These cases pin the symmetry, and pin that it did not become a
// widening: same candidate vtype, same VLMAX, same stub, same chunk count per width.
// ---------------------------------------------------------------------------------------------

struct DiagGroup {
	unsigned n_begin = 0, n_add = 0, n_end = 0;
	InstRVVDiagChunkBegin *begin = nullptr;
	std::vector<InstRVVDiagChunkAdd *> adds;
};

DiagGroup FindDiagGroup(Region *region)
{
	DiagGroup g;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvdiagchunkbegin:
				++g.n_begin;
				g.begin = static_cast<InstRVVDiagChunkBegin *>(&ins);
				break;
			case Op::_rvvdiagchunkadd:
				++g.n_add;
				g.adds.push_back(static_cast<InstRVVDiagChunkAdd *>(&ins));
				break;
			case Op::_rvvdiagchunkend:
				++g.n_end;
				break;
			default:
				break;
			}
		}
	}
	return g;
}

// ADMITTED: no vsetvli anywhere in the block, arm D selected (direct on, diag on, typed OFF), and
// the diagnostic frame is built from the same field-derived candidate the typed arm gets -- one
// `rvvdiagchunkadd` per 512-bit host chunk, so one at VLEN=512 and two at VLEN=1024.
static void CheckUnknownVtypeDiagAdmitted(char const *label, u32 vlen_bits, u32 want_chunks,
					  u32 want_vlmax)
{
	printf("%s: unknown-vtype DIAGNOSTIC (arm D) admission\n", label);
	MemArena arena(1u << 20);
	u32 words[1] = {INSN_VADD_VV};
	Region *region = TranslateSoloArm(arena, words, vlen_bits, /*direct=*/true, /*diag=*/true,
					  /*typed=*/false);

	DiagGroup d = FindDiagGroup(region);
	CHECK_EQ(d.n_begin, 1u);
	CHECK_EQ(d.n_end, 1u);
	CHECK_EQ(d.n_add, want_chunks);
	if (!d.begin || d.n_add != want_chunks)
		return;

	// The candidate is the field-built constant, not an observation and not a widened shape.
	CHECK_EQ(d.begin->vtype, rv32::VTYPE_E32_M1_TA_MA);
	CHECK_EQ(d.begin->vlmax, want_vlmax);
	CHECK(d.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
	{
		rv32::VType const vt{d.begin->vtype};
		CHECK_EQ(vt.sew(), 32u);
		CHECK_EQ((int)vt.lmul_log2(), 0);
	}
	// Chunk indices are 0..n-1 in order, and every add names this instruction's own registers at
	// the candidate's SEW -- the emitter derives both the ZMM and the byte offset from `index`.
	for (unsigned c = 0; c < want_chunks; ++c) {
		CHECK_EQ((unsigned)d.adds[c]->index, c);
		CHECK_EQ((unsigned)d.adds[c]->vd, VD_REG);
		CHECK_EQ((unsigned)d.adds[c]->vs2, VS2_REG);
		CHECK_EQ((unsigned)d.adds[c]->vs1, VS1_REG);
		CHECK_EQ((unsigned)d.adds[c]->sew_bytes, 4u);
	}
	// Arm D is not arm I and not the SSE2 arm: no typed frame and no rvvaddv may appear.
	CHECK_EQ(CountOp(region, Op::_rvvtypedchunkbegin), 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), 0u);
	CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	printf("  vtype=0x%08x vlmax=%u diag adds=%u (one per 512-bit host chunk), no typed frame, "
	       "no rvvaddv\n",
	       d.begin->vtype, d.begin->vlmax, d.n_add);
}

// PRECEDENCE: with BOTH switches on and no observed vtype, the typed arm must still win, so that
// enabling the control can never displace the method being measured.
static void CheckUnknownVtypeBothArmsTypedWins(char const *label, u32 vlen_bits, u32 want_chunks)
{
	printf("%s: unknown-vtype with BOTH chunk arms enabled -> typed wins\n", label);
	MemArena arena(1u << 20);
	u32 words[1] = {INSN_VADD_VV};
	Region *region = TranslateSoloArm(arena, words, vlen_bits, /*direct=*/true, /*diag=*/true,
					  /*typed=*/true);

	Group g = FindGroup(region);
	DiagGroup d = FindDiagGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	CHECK_EQ(d.n_begin, 0u);
	CHECK_EQ(d.n_add, 0u);
	CHECK_EQ(d.n_end, 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), want_chunks);
	CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	printf("  typed frame present (%u typed adds), diagnostic frame absent\n", want_chunks);
}

// ARM H / all switches off: `--rvv-direct 0` is arm H's whole definition, and with it neither chunk
// arm may be reached, whatever the other two switches say. Checked in both of the ways a harness
// could get it wrong: direct off with both chunk switches on, and direct on with both off.
static void CheckUnknownVtypeHelperArm(char const *label, u32 vlen_bits)
{
	printf("%s: unknown-vtype, helper arm H and all-off\n", label);
	{
		MemArena arena(1u << 20);
		u32 words[1] = {INSN_VADD_VV};
		Region *region = TranslateSoloArm(arena, words, vlen_bits, /*direct=*/false,
						  /*diag=*/true, /*typed=*/true);
		Group g = FindGroup(region);
		DiagGroup d = FindDiagGroup(region);
		CHECK_EQ(g.n_begin, 0u);
		CHECK_EQ(d.n_begin, 0u);
		CHECK_EQ(d.n_add, 0u);
		CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
		CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	}
	{
		MemArena arena(1u << 20);
		u32 words[1] = {INSN_VADD_VV};
		Region *region = TranslateSoloArm(arena, words, vlen_bits, /*direct=*/true,
						  /*diag=*/false, /*typed=*/false);
		Group g = FindGroup(region);
		DiagGroup d = FindDiagGroup(region);
		CHECK_EQ(g.n_begin, 0u);
		CHECK_EQ(d.n_begin, 0u);
		CHECK_EQ(d.n_add, 0u);
		CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
		// The unknown-vtype block goes straight to the helper rather than falling into the
		// SSE2 arm with an assumed vtype -- that restriction is unchanged by C3.2a-fix1.
		CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	}
	printf("  no typed frame, no diagnostic frame, no rvvaddv in either off-state\n");
}

// OBSERVED vtype still wins for the diagnostic arm.
//
// What "wins" MEANS here is different from the arm I case above, and the difference is the whole
// point. Arm I does not admit e64 at all (`RvvQcgTypedChunkAdmit` requires sew_bytes==4), so its
// observed-e64 case correctly expects no typed frame and the SSE2 `rvvaddv` route. Arm D's
// admission test accepts sew_bytes 1, 2, 4 and 8, so the pre-existing behaviour at an observed
// e64,m1 is a DIAGNOSTIC FRAME -- not `rvvaddv`. The property C3.2a-fix1 must not break is
// therefore not "no frame appears" but "the frame that appears carries the OBSERVED vtype": the
// e32,m1,ta,ma candidate this fix added may be proposed only when nothing was observed.
//
// This case previously accepted either outcome through an if/else, which would have passed just as
// happily if the fix had started substituting the candidate over an observation, or if the
// diagnostic arm had silently stopped admitting e64. It is now exact in both directions: one
// begin/end, the width's own chunk-add count, the observed vtype and its VLMAX, SEW=64 on every
// add, and no typed frame or rvvaddv anywhere.
static void CheckObservedVtypePrecedenceDiag(char const *label, u32 vlen_bits, u32 want_chunks,
					     u32 want_vlmax)
{
	printf("%s: observed non-admitted vtype takes precedence (arm D)\n", label);
	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI_E64, INSN_VADD_VV};

	config::rvv_qcg_typed_chunk = false;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_diag_chunk = true;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_diag_chunk_force_emit = true;
	config::vlen_bits = vlen_bits;
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);

	DiagGroup d = FindDiagGroup(region);
	Group g = FindGroup(region);

	// Exactly one diagnostic frame, and the width's own chunk count -- RvvQcgDiagChunkAdmit
	// returns vlen_bits/512 regardless of SEW, so this is 1 at VLEN=512 and 2 at VLEN=1024 for
	// e64 exactly as it is for e32.
	CHECK_EQ(d.n_begin, 1u);
	CHECK_EQ(d.n_end, 1u);
	CHECK_EQ(d.n_add, want_chunks);
	// Neither the typed arm nor the SSE2 arm may appear: the diagnostic arm returns before both.
	CHECK_EQ(g.n_begin, 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_rvvaddv), 0u);
	if (!d.begin || d.n_add != want_chunks)
		return;

	// The frame carries what the vsetvli SET, not what C3.2a-fix1 can propose. Both are checked:
	// equality with the observed encoding, and inequality with the candidate.
	CHECK_EQ(d.begin->vtype, VTYPE_E64_M1_TA_MA);
	CHECK(d.begin->vtype != rv32::VTYPE_E32_M1_TA_MA);
	// VLMAX is the observed vtype's own, VLEN/SEW at LMUL=1 -- 8 at VLEN=512, 16 at VLEN=1024,
	// and never the e32 candidate's 16/32. Derived here rather than trusted from the argument.
	CHECK_EQ(want_vlmax, vlen_bits / 64u);
	CHECK_EQ(d.begin->vlmax, want_vlmax);
	CHECK(d.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
	{
		rv32::VType const vt{d.begin->vtype};
		CHECK_EQ(vt.sew(), 64u);
		CHECK_EQ((int)vt.lmul_log2(), 0);
	}
	// Every chunk add is at the observed SEW, in index order, on this instruction's own registers.
	for (unsigned c = 0; c < want_chunks; ++c) {
		CHECK_EQ((unsigned)d.adds[c]->index, c);
		CHECK_EQ((unsigned)d.adds[c]->vd, VD_REG);
		CHECK_EQ((unsigned)d.adds[c]->vs2, VS2_REG);
		CHECK_EQ((unsigned)d.adds[c]->vs1, VS1_REG);
		CHECK_EQ((unsigned)d.adds[c]->sew_bytes, 8u);
	}
	printf("  observed e64 frame kept: vtype=0x%08x vlmax=%u diag adds=%u sew_bytes=8, candidate "
	       "not substituted, no typed frame, no rvvaddv\n",
	       d.begin->vtype, d.begin->vlmax, d.n_add);
}

// ---------------------------------------------------------------------------------------------
// C3.1f-fix11: SEVERAL typed groups inside ONE block.
//
// Every case above routes exactly one guest `vadd.vv`, so the region holds one typed frame and the
// question of what happens to a group's V512 values once its own store has run never arises. The
// K1 measurement kernel puts eight `vadd.vv` back to back in one translation block, and that shape
// hit `Panic: QRegAlloc: spill frame exhausted` on xbd before any guest instruction executed:
// `rvvtypedchunkbegin` is HAS_CALLS, so each group's begin spilled the PREVIOUS group's three (or
// six) values -- values nothing can read again -- and `AllocFrameSlot` is a bump pointer, so each
// of those spills permanently owned 64 of the fixed 1024-byte frame. The 17th such slot exceeds
// the frame: group 7 at VLEN=512, group 3 at VLEN=1024.
//
// These two cases are that exact shape, and they assert the property that makes the panic
// impossible rather than merely absent: across all eight groups NOT ONE V512 value is written to
// or read from the spill frame, so `frame_cur` never leaves zero however long the block gets.
// They also re-assert, at eight groups, everything the single-group cases assert about one: per
// chunk def-use, and -- at VLEN=1024 -- two chunks in disjoint physical ZMM sets.
//
// If the allocator regresses, QRegAllocPass calls Panic() and this executable aborts with that
// message rather than reporting a failed CHECK; these cases are therefore last in main(). Nothing
// here builds QEmit/QCodegen, so no AVX-512 byte is assembled or executed, on any host.
// ---------------------------------------------------------------------------------------------

constexpr unsigned K_GROUPS = 8; // K1's timed body: eight straight-line vadd.vv

// vadd.vv vd, vs2, vs1 (OPIVV, unmasked): funct6=0b000000, vm=1, vs2[24:20], vs1[19:15],
// funct3=0b000, vd[11:7], opcode=0b1010111. Built from the fields rather than pasted; the
// CHECK in CheckManyGroups proves it reproduces INSN_VADD_VV for (vd=3, vs2=1, vs1=2).
constexpr u32 EncodeVaddVV(u32 vd, u32 vs2, u32 vs1)
{
	return (1u << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}

// One region containing exactly `n` instructions at ip 0, 4, ... 4*(n-1). Same config as
// TranslateSolo: no vsetvli anywhere, so admission goes through the C3.1f unknown-vtype candidate,
// which is precisely how K1 reaches the typed route.
Region *TranslateStraightLine(MemArena &arena, u32 *words, unsigned n, u32 vlen_bits)
{
	config::rvv_qcg_typed_chunk = true;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::vlen_bits = vlen_bits;

	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

// FindGroup's multi-frame twin: every begin/end frame in the region, in order, each remembering
// which block it lives in (the retirement being tested is block-local, so "all eight in one block"
// is part of the claim, not an assumption).
struct GroupN : Group {
	Block *blk = nullptr;
};

std::vector<GroupN> FindGroups(Region *region)
{
	std::vector<GroupN> out;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				out.emplace_back();
				out.back().blk = &bb;
				out.back().n_begin = 1;
				out.back().begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				if (!out.empty()) {
					out.back().n_end = 1;
					out.back().end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				}
				open = false;
				continue;
			}
			if (open && !out.empty()) {
				out.back().body.push_back(&ins);
			}
		}
	}
	return out;
}

// Every `mov` in the region that touches a V512 operand, i.e. exactly the allocator's vector
// spills, fills and copies (QRegAlloc::EmitSpill/EmitFill/AllocOpInputV) -- the same signature
// qra_vpr_test.cpp's CollectMovs(..., vector_only=true) uses.
unsigned CountV512Movs(Region *region, unsigned *n_frame_slot_movs)
{
	unsigned n = 0;
	*n_frame_slot_movs = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_mov) {
				continue;
			}
			auto *u = static_cast<InstUnop *>(&ins);
			if (!(u->o(0).GetType() == VType::V512 || u->i(0).GetType() == VType::V512)) {
				continue;
			}
			++n;
			// A LOCAL slot operand is a spill-frame access; a GLOBAL slot operand would be
			// CPUState, which is not what AllocFrameSlot hands out.
			if (u->o(0).IsLSlot() || u->i(0).IsLSlot()) {
				++*n_frame_slot_movs;
			}
		}
	}
	return n;
}

void CheckManyGroups(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax)
{
	printf("%s: %u typed groups in one block\n", tag, K_GROUPS);
	CHECK_EQ(EncodeVaddVV(VD_REG, VS2_REG, VS1_REG), INSN_VADD_VV);

	MemArena arena(1u << 20);
	u32 words[K_GROUPS];
	for (unsigned i = 0; i < K_GROUPS; ++i) {
		// Eight distinct destination registers, as K1's eight accumulators have; sources shared,
		// which is also K1's shape (one addend register reused by every accumulator).
		words[i] = EncodeVaddVV(/*vd=*/8u + i, VS2_REG, VS1_REG);
	}
	Region *region = TranslateStraightLine(arena, words, K_GROUPS, vlen_bits);

	// The pre-allocation shape: eight frames, all in the same block.
	{
		auto groups = FindGroups(region);
		CHECK_EQ(groups.size(), (size_t)K_GROUPS);
		if (groups.size() != K_GROUPS) {
			return;
		}
		for (auto &g : groups) {
			CHECK_EQ(g.n_begin, 1u);
			CHECK_EQ(g.n_end, 1u);
			CHECK(g.blk == groups[0].blk);
			CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
			CHECK_EQ(g.begin->vlmax, expect_vlmax);
			CHECK(g.begin->stub == RuntimeStubId::id_rv32_vadd_vv);
		}
	}

	// The two passes qcg::GenerateCode runs before QEmit. This is where the frame-exhaustion Panic
	// used to happen -- reaching the next line at all is part of the result.
	ArchTraits::init();
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(region, &mri);
	qcg::QRegAllocPass::run(region);

	// THE claim: not one V512 byte ever reached the spill frame, at any group. Frame demand grew
	// linearly with group count before block-local retirement; now it is zero and stays zero.
	unsigned n_frame_movs = 0;
	unsigned const n_v512_movs = CountV512Movs(region, &n_frame_movs);
	CHECK_EQ(n_frame_movs, 0u);
	CHECK_EQ(n_v512_movs, 0u);

	auto groups = FindGroups(region);
	CHECK_EQ(groups.size(), (size_t)K_GROUPS);
	if (groups.size() != K_GROUPS) {
		return;
	}

	std::vector<RegN> group0_regs;
	for (size_t gi = 0; gi < groups.size(); ++gi) {
		auto &g = groups[gi];
		std::vector<Inst *> typed_ops;
		for (auto *ins : g.body) {
			if (ins->GetOpcode() != Op::_mov) {
				typed_ops.push_back(ins);
			}
		}
		CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
		if (typed_ops.size() != 4 * nchunks) {
			return;
		}

		std::vector<RegN> regs;
		std::vector<std::vector<RegN>> chunk_regs(nchunks);
		for (u32 c = 0; c < nchunks; ++c) {
			auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
			auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
			auto *add = static_cast<InstVChunkAdd *>(typed_ops[2 * nchunks + c]);
			auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);
			CHECK(l_s2->GetOpcode() == Op::_vstatechunkload);
			CHECK(l_s1->GetOpcode() == Op::_vstatechunkload);
			CHECK(add->GetOpcode() == Op::_vchunkadd);
			CHECK(store->GetOpcode() == Op::_vstatechunkstore);

			CHECK(l_s2->o(0).IsPVPR());
			CHECK(l_s1->o(0).IsPVPR());
			CHECK(add->o(0).IsPVPR());
			CHECK(add->i(0).IsPVPR());
			CHECK(add->i(1).IsPVPR());
			CHECK(store->i(0).IsPVPR());
			if (!(l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && add->o(0).IsPVPR() &&
			      add->i(0).IsPVPR() && add->i(1).IsPVPR() && store->i(0).IsPVPR())) {
				return;
			}

			// The per-group destination really is this group's own guest register: group `gi`
			// writes v(8+gi), so a group reusing another group's store offset -- the failure a
			// register-recycling bug could plausibly produce -- is caught here.
			CHECK_EQ(store->offs, ChunkOffs(8u + (u32)gi, c));
			CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
			CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));

			RegN const want_a = l_s2->o(0).GetPVPR();
			RegN const want_b = l_s1->o(0).GetPVPR();
			RegN const got_a = add->i(0).GetPVPR();
			RegN const got_b = add->i(1).GetPVPR();
			CHECK((got_a == want_a && got_b == want_b) || (got_a == want_b && got_b == want_a));
			CHECK_EQ(add->o(0).GetPVPR(), store->i(0).GetPVPR());
			for (auto o : {l_s2->o(0), l_s1->o(0), add->o(0)}) {
				CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
				CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
			}

			chunk_regs[c] = {want_a, want_b, add->o(0).GetPVPR()};
			regs.insert(regs.end(), chunk_regs[c].begin(), chunk_regs[c].end());
		}

		// Unchanged at eight groups: within one guest instruction the low and high chunks stay in
		// completely disjoint physical ZMM sets (C2.2a/C2.3a).
		std::vector<RegN> uniq = regs;
		std::sort(uniq.begin(), uniq.end());
		uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
		CHECK_EQ(uniq.size(), (size_t)(3 * nchunks));

		// And every group gets the SAME registers as the first: the pool is recycled, not
		// consumed, which is the observable difference between retiring dead values and leaking
		// them.
		if (gi == 0) {
			group0_regs = uniq;
		} else {
			CHECK(uniq == group0_regs);
		}
	}

	// The same eight-group shape through the REAL, unmodified qcg::GenerateCode -- the exact
	// function elfrun's translator calls, QSel -> QRegAlloc -> QEmit -> QCodegen -- on its own
	// fresh region, since the one above has already been rewritten in place. This is where the
	// panic actually happened on xbd, so the pipeline being able to complete it (and still touch
	// the spill frame with no V512) is the closing half of the result. TestCompilerRuntime never
	// mmaps anything, so the emitted AVX-512 bytes cannot be executed by this test, on any host.
	unsigned emitted_frame_movs = 0, emitted_v512_movs = 0;
	size_t emitted_bytes = 0;
	{
		MemArena arena2(1u << 20);
		Region *region2 = TranslateStraightLine(arena2, words, K_GROUPS, vlen_bits);
		TestCompilerRuntime cruntime;
		qir::CodeSegment segment(0u, 0x1000u);
		auto code_span = qcg::GenerateCode(&cruntime, &segment, region2, 0);
		CHECK(!code_span.empty());
		emitted_bytes = code_span.size();
		CHECK_EQ(FindGroups(region2).size(), (size_t)K_GROUPS);
		emitted_v512_movs = CountV512Movs(region2, &emitted_frame_movs);
		CHECK_EQ(emitted_frame_movs, 0u);
		CHECK_EQ(emitted_v512_movs, 0u);
	}

	printf("  %s: OK %u groups, V512 spill-frame movs=%u, V512 movs total=%u, per-group zmm{", tag,
	       K_GROUPS, n_frame_movs, n_v512_movs);
	for (size_t i = 0; i < group0_regs.size(); ++i) {
		printf("%s%u", i ? "," : "", group0_regs[i]);
	}
	printf("}; GenerateCode: %zu bytes, V512 frame movs=%u\n", emitted_bytes, emitted_frame_movs);
}

// ---------------------------------------------------------------------------------------------
// M2C: the WIDTH-CORRECT vertical slice.
//
// Everything above this point tests the 512-bit-chunk shape, which is exact only when a guest
// vector register is at least as wide as one AVX-512 register. M2C makes the width a property of
// the QIR VALUE (qir::VType::V128/V256/V512), so one guest vadd.vv becomes exactly one host packed
// add of the guest register's own width -- or, at VLEN 1024 where the register is genuinely wider
// than the host's, two register-disjoint 512-bit ones.
//
// The checks below are deliberately not "the mnemonic is vpaddd". A wrong-width lowering emits the
// same mnemonic; what distinguishes it is the OPERAND width, the memory-operand width, the
// displacement stride, and how many destination bytes the frame writes in total. Each of those is
// asserted separately, and section MC5 shows what each one catches.
// ---------------------------------------------------------------------------------------------

struct WidthCase {
	u32 vlen;	   // runtime VLEN in bits
	u32 chunk_bytes;   // width of one host chunk
	u32 nchunks;	   // chunks per guest vector register
	char const *reg;   // the host register form objdump prints
	char const *ptr;   // the memory-operand keyword objdump prints
	u32 vlmax;	   // e32,m1
};

// bytes * nchunks == vlen/8 for every row: the frame covers the architectural register exactly.
WidthCase const M2C_CASES[] = {
    {128u, 16u, 1u, "xmm", "XMMWORD", 4u},
    {256u, 32u, 1u, "ymm", "YMMWORD", 8u},
    {512u, 64u, 1u, "zmm", "ZMMWORD", 16u},
    {1024u, 64u, 2u, "zmm", "ZMMWORD", 32u},
};

u32 M2CChunkOffs(u32 reg, u32 chunk, u32 chunk_bytes)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * chunk_bytes;
}

VType M2CExpectType(u32 chunk_bytes)
{
	return chunk_bytes == 16 ? VType::V128 : chunk_bytes == 32 ? VType::V256 : VType::V512;
}

// A width-aware decoder, separate from the zmm-only one above on purpose: that one must keep
// asserting the accepted 512-bit goldens exactly as it always has.
struct WideVec {
	enum class Kind { LOAD, ADD, STORE } kind;
	std::string mnemonic;
	unsigned reg_bits{};  // 128/256/512, from the REGISTER operand
	unsigned mem_bits{};  // 128/256/512, from the MEMORY operand keyword (0 for ADD)
	unsigned dst{}, src0{}, src1{};
	i64 disp{};
};

bool ParseVecReg(std::string const &tok, unsigned *num, unsigned *bits)
{
	unsigned b = 0;
	if (tok.compare(0, 3, "xmm") == 0)
		b = 128;
	else if (tok.compare(0, 3, "ymm") == 0)
		b = 256;
	else if (tok.compare(0, 3, "zmm") == 0)
		b = 512;
	else
		return false;
	size_t i = 3;
	if (i >= tok.size() || !isdigit((unsigned char)tok[i]))
		return false;
	unsigned v = 0;
	while (i < tok.size() && isdigit((unsigned char)tok[i])) {
		v = v * 10 + (unsigned)(tok[i] - '0');
		++i;
	}
	if (i != tok.size())
		return false;
	*num = v;
	*bits = b;
	return true;
}

// "<X>WORD PTR [r13+0x..]". The keyword IS the access width, and checking it is the whole point:
// a 64-byte access dressed up as a 128-bit one prints ZMMWORD next to an xmm register.
bool ParseVecMemR13(std::string const &tok, i64 *disp, unsigned *bits)
{
	struct {
		char const *kw;
		unsigned bits;
	} const kinds[] = {{"XMMWORD PTR [r13", 128}, {"YMMWORD PTR [r13", 256}, {"ZMMWORD PTR [r13", 512}};
	for (auto const &k : kinds) {
		std::string const prefix = k.kw;
		if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0)
			continue;
		size_t i = prefix.size();
		bool neg = tok[i] == '-';
		if (tok[i] != '+' && tok[i] != '-')
			return false;
		++i;
		if (tok.compare(i, 2, "0x") != 0)
			return false;
		i += 2;
		size_t start = i;
		i64 v = 0;
		while (i < tok.size() && isxdigit((unsigned char)tok[i])) {
			char c = (char)tolower((unsigned char)tok[i]);
			v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
			++i;
		}
		if (i == start || i >= tok.size() || tok[i] != ']' || i + 1 != tok.size())
			return false;
		*disp = neg ? -v : v;
		*bits = k.bits;
		return true;
	}
	return false;
}

// objdump WITH the raw byte column: "  <addr>:\t<hex bytes>\t<text>". The first opcode byte is
// what says EVEX (0x62) rather than VEX (0xc4/0xc5), and that distinction is not cosmetic -- only
// EVEX can name zmm16-31, so a VEX-encoded narrow form would silently halve the register file the
// allocator may use.
struct RawLine {
	unsigned first_byte{};
	std::string text;
};

std::vector<RawLine> DisassembleRaw(std::vector<u8> const &code)
{
	std::vector<RawLine> out;
	char path[] = "/tmp/rvdbt_m2c_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return out;
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			close(fd);
			unlink(path);
			return out;
		}
		written += (size_t)n;
	}
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		unlink(path);
		return out;
	}
	char buf[1024];
	while (fgets(buf, sizeof(buf), p)) {
		std::string line(buf);
		if (!line.empty() && line.back() == '\n')
			line.pop_back();
		size_t t1 = line.find('\t');
		if (t1 == std::string::npos)
			continue;
		size_t t2 = line.find('\t', t1 + 1);
		if (t2 == std::string::npos)
			continue;
		std::string bytes = line.substr(t1 + 1, t2 - t1 - 1);
		size_t b = bytes.find_first_not_of(' ');
		if (b == std::string::npos || !isxdigit((unsigned char)bytes[b]))
			continue;
		RawLine r;
		r.first_byte = (unsigned)strtoul(bytes.substr(b, 2).c_str(), nullptr, 16);
		r.text = line.substr(t2 + 1);
		out.push_back(r);
	}
	pclose(p);
	unlink(path);
	return out;
}

bool ParseWideLine(std::string const &text_in, WideVec *out)
{
	// binutils >= 2.40 prints a `{evex}` pseudo-prefix on an EVEX encoding that also has a VEX
	// form (so on xmm/ymm but never on zmm); 2.38 does not. Strip any such brace token so the
	// assertions do not depend on the disassembler's version.
	std::string rhs = text_in;
	while (!rhs.empty() && rhs[0] == '{') {
		size_t close_at = rhs.find('}');
		if (close_at == std::string::npos)
			return false;
		size_t next = rhs.find_first_not_of(' ', close_at + 1);
		if (next == std::string::npos)
			return false;
		rhs = rhs.substr(next);
	}
	size_t sp = rhs.find(' ');
	std::string mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	auto ops = SplitCommas(sp == std::string::npos ? std::string() : rhs.substr(sp + 1));

	if (mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned r, rb, mb;
		i64 disp;
		if (ParseVecReg(ops[0], &r, &rb) && ParseVecMemR13(ops[1], &disp, &mb)) {
			*out = WideVec{WideVec::Kind::LOAD, mnem, rb, mb, r, 0, 0, disp};
			return true;
		}
		if (ParseVecMemR13(ops[0], &disp, &mb) && ParseVecReg(ops[1], &r, &rb)) {
			*out = WideVec{WideVec::Kind::STORE, mnem, rb, mb, 0, r, 0, disp};
			return true;
		}
		return false;
	}
	if ((mnem == "vpaddb" || mnem == "vpaddw" || mnem == "vpaddd" || mnem == "vpaddq") &&
	    ops.size() == 3) {
		unsigned d, s0, s1, db, s0b, s1b;
		if (ParseVecReg(ops[0], &d, &db) && ParseVecReg(ops[1], &s0, &s0b) &&
		    ParseVecReg(ops[2], &s1, &s1b) && db == s0b && db == s1b) {
			*out = WideVec{WideVec::Kind::ADD, mnem, db, 0, d, s0, s1, 0};
			return true;
		}
	}
	return false;
}

// MC1/MC2: QIR-level width coherence, at all four widths.
void M2C_CheckQIRWidth(WidthCase const &c)
{
	printf("  M2C QIR vlen=%u: expect %u x %u-byte chunk\n", c.vlen, c.nchunks, c.chunk_bytes);
	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Region *region = TranslateOne(arena, words, c.vlen);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end)
		return;
	CHECK_EQ(g.begin->n_typed, (u8)(4 * c.nchunks));
	CHECK_EQ(g.begin->vlmax, c.vlmax);

	VType const want = M2CExpectType(c.chunk_bytes);
	unsigned n_load = 0, n_add = 0, n_store = 0;
	// The exact windows the frame is allowed to touch, and nothing else: chunk c of a register
	// starts at c * chunk_bytes. A stride bug moves a displacement out of this set.
	std::vector<u32> want_loads, want_stores;
	for (u32 k = 0; k < c.nchunks; ++k) {
		want_loads.push_back(M2CChunkOffs(VS2_REG, k, c.chunk_bytes));
		want_loads.push_back(M2CChunkOffs(VS1_REG, k, c.chunk_bytes));
		want_stores.push_back(M2CChunkOffs(VD_REG, k, c.chunk_bytes));
	}
	std::vector<u32> got_loads, got_stores;
	for (auto *ins : g.body) {
		switch (ins->GetOpcode()) {
		case Op::_vstatechunkload: {
			auto *l = static_cast<InstVStateChunkLoad *>(ins);
			++n_load;
			CHECK(l->o(0).GetType() == want);
			CHECK_EQ(l->Bytes(), c.chunk_bytes);
			got_loads.push_back(l->offs);
			break;
		}
		case Op::_vstatechunkstore: {
			auto *st = static_cast<InstVStateChunkStore *>(ins);
			++n_store;
			CHECK(st->i(0).GetType() == want);
			CHECK_EQ(st->Bytes(), c.chunk_bytes);
			got_stores.push_back(st->offs);
			break;
		}
		case Op::_vchunkadd: {
			auto *a = static_cast<InstVChunkAdd *>(ins);
			++n_add;
			CHECK(a->o(0).GetType() == want);
			CHECK(a->i(0).GetType() == want);
			CHECK(a->i(1).GetType() == want);
			CHECK_EQ(a->sew_bytes, (u8)4);
			break;
		}
		default:
			break;
		}
	}
	CHECK_EQ(n_add, c.nchunks);
	CHECK_EQ(n_load, 2u * c.nchunks);
	CHECK_EQ(n_store, c.nchunks);
	std::sort(got_loads.begin(), got_loads.end());
	std::sort(want_loads.begin(), want_loads.end());
	std::sort(got_stores.begin(), got_stores.end());
	std::sort(want_stores.begin(), want_stores.end());
	CHECK(got_loads == want_loads);
	CHECK(got_stores == want_stores);

	// The frame writes the architectural register EXACTLY once and no byte more: nchunks stores
	// of chunk_bytes each, contiguous from the register's base.
	CHECK_EQ(c.chunk_bytes * c.nchunks, c.vlen / 8u);
	// Reported as observed values, not as a fixed "ok": a line that says "ok" whatever happened
	// is not evidence, and every mutant in the M2C record below prints through here.
	printf("    QIR: %u load / %u add / %u store, all %s, %zu/%zu load and %zu/%zu store windows "
	       "as expected\n",
	       n_load, n_add, n_store, qir::vtype_names[to_underlying(want)],
	       got_loads == want_loads ? want_loads.size() : 0u, want_loads.size(),
	       got_stores == want_stores ? want_stores.size() : 0u, want_stores.size());
}

// MC1/MC3: emitted bytes -- operand width, memory-operand width, displacements, and (VLEN 1024)
// register-disjoint chains.
void M2C_CheckEmittedWidth(WidthCase const &c)
{
	printf("  M2C emitted vlen=%u: expect %u x %s %s add\n", c.vlen, c.nchunks, c.reg,
	       c.chunk_bytes == 64 ? "512-bit" : c.chunk_bytes == 32 ? "256-bit" : "128-bit");

	MemArena arena(1u << 20);
	u32 words[2] = {INSN_VSETVLI, INSN_VADD_VV};
	Region *region = TranslateOne(arena, words, c.vlen);
	TestCompilerRuntime cruntime;
	qir::CodeSegment segment(0u, 0x1000u);
	auto code_span = qcg::GenerateCode(&cruntime, &segment, region, 0);
	CHECK(!code_span.empty());
	if (code_span.empty())
		return;
	std::vector<u8> code(code_span.begin(), code_span.end());
	auto lines = DisassembleRaw(code);
	CHECK(!lines.empty());
	if (lines.empty())
		return;

	unsigned const want_bits = c.chunk_bytes * 8u;
	std::vector<WideVec> vecs;
	unsigned n_not_evex = 0;
	for (auto const &l : lines) {
		WideVec v;
		if (!ParseWideLine(l.text, &v))
			continue;
		// EVEX (0x62) at every width, including the two that have a legal VEX form. Without it
		// the encoding -- and therefore which registers the allocator may use -- would depend on
		// which register it happened to pick.
		if (l.first_byte != 0x62) {
			++n_not_evex;
			fprintf(stderr, "    not EVEX (first byte 0x%02x): %s\n", l.first_byte,
				l.text.c_str());
		}
		vecs.push_back(v);
	}
	CHECK_EQ(n_not_evex, 0u);

	unsigned n_load = 0, n_add = 0, n_store = 0, n_wrong_width = 0;
	std::vector<i64> load_disp, store_disp;
	std::vector<std::vector<unsigned>> chunk_regs(c.nchunks);
	for (auto const &v : vecs) {
		// THE INACTIVE-BYTE CHECK. Every vector access in this frame must be exactly the
		// architectural width. A wider one would read -- or, for the store, WRITE -- guest
		// vector bytes the instruction does not define.
		if (v.reg_bits != want_bits || (v.kind != WideVec::Kind::ADD && v.mem_bits != want_bits)) {
			++n_wrong_width;
			fprintf(stderr, "    wrong width: %s reg=%u mem=%u, want %u\n",
				v.mnemonic.c_str(), v.reg_bits, v.mem_bits, want_bits);
			continue;
		}
		switch (v.kind) {
		case WideVec::Kind::LOAD:
			++n_load;
			load_disp.push_back(v.disp);
			break;
		case WideVec::Kind::STORE:
			++n_store;
			store_disp.push_back(v.disp);
			break;
		case WideVec::Kind::ADD:
			++n_add;
			break;
		}
	}
	CHECK_EQ(n_wrong_width, 0u);
	CHECK_EQ(n_add, c.nchunks);
	CHECK_EQ(n_load, 2u * c.nchunks);
	CHECK_EQ(n_store, c.nchunks);

	std::vector<i64> want_loads, want_stores;
	for (u32 k = 0; k < c.nchunks; ++k) {
		want_loads.push_back((i64)M2CChunkOffs(VS2_REG, k, c.chunk_bytes));
		want_loads.push_back((i64)M2CChunkOffs(VS1_REG, k, c.chunk_bytes));
		want_stores.push_back((i64)M2CChunkOffs(VD_REG, k, c.chunk_bytes));
	}
	std::sort(load_disp.begin(), load_disp.end());
	std::sort(want_loads.begin(), want_loads.end());
	std::sort(store_disp.begin(), store_disp.end());
	std::sort(want_stores.begin(), want_stores.end());
	CHECK(load_disp == want_loads);
	CHECK(store_disp == want_stores);

	// REGISTER-DISJOINT CHAINS. At nchunks=2 the low and high halves are independent by
	// construction; if they shared any physical register the two host chains would serialize and
	// the "two independent 512-bit chains" property would be false in the bytes even though the
	// QIR said otherwise. Collect each add's three registers and require the sets be disjoint.
	unsigned add_i = 0;
	for (auto const &v : vecs) {
		if (v.kind != WideVec::Kind::ADD || v.reg_bits != want_bits)
			continue;
		if (add_i < c.nchunks) {
			chunk_regs[add_i] = {v.dst, v.src0, v.src1};
			// A chain must not be built out of one register aliased three ways either.
			CHECK(v.dst != v.src0 && v.dst != v.src1 && v.src0 != v.src1);
		}
		++add_i;
	}
	if (c.nchunks == 2) {
		bool disjoint = true;
		for (unsigned a : chunk_regs[0])
			for (unsigned b : chunk_regs[1])
				if (a == b)
					disjoint = false;
		CHECK(disjoint);
		printf("    chunk0 %s{%u,%u,%u} chunk1 %s{%u,%u,%u} disjoint=%d\n", c.reg,
		       chunk_regs[0][0], chunk_regs[0][1], chunk_regs[0][2], c.reg, chunk_regs[1][0],
		       chunk_regs[1][1], chunk_regs[1][2], (int)disjoint);
	} else {
		printf("    %u x %s add, %u loads / %u store, all %u-bit EVEX, displacements exact\n",
		       n_add, c.reg, n_load, n_store, want_bits);
	}
}

// MC4: post-boundary admission. No vsetvli in the block, so rvv_bb_vtype is unknown and the route
// runs on a translation-time CANDIDATE proved by the emitted runtime guard. It must admit at every
// width, otherwise a chain that crosses a TB boundary falls back to the helper mid-chain.
void M2C_CheckUnknownVtypeWidth(WidthCase const &c)
{
	MemArena arena(1u << 20);
	u32 words[1] = {INSN_VADD_VV};
	Region *region = TranslateSolo(arena, words, c.vlen, /*typed_enabled=*/true);
	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), c.nchunks);
	CHECK_EQ(CountOp(region, Op::_hcall), 0u);
	VType const want = M2CExpectType(c.chunk_bytes);
	for (auto *ins : g.body) {
		if (ins->GetOpcode() == Op::_vchunkadd)
			CHECK(ins->o(0).GetType() == want);
	}
	if (g.begin) {
		CHECK_EQ(g.begin->vlmax, c.vlmax);
	}
	printf("  M2C unknown-vtype vlen=%u: %u x %s chunk admitted, guard vlmax=%u, no helper\n",
	       c.vlen, c.nchunks, qir::vtype_names[to_underlying(want)], c.vlmax);
}

// MC5: the reversals. Each mutates ONE property of a well-formed frame and requires the
// representation to refuse it. Run in forked children because the refusal is a Panic (abort).
template <typename F>
void M2C_ExpectPanic(char const *what, F &&fn)
{
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		fn();
		_exit(0); // reached only if the malformed shape was accepted
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "  FAIL %s: waitpid\n", what);
		++g_failures;
		return;
	}
	bool const refused = WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
	if (!refused) {
		fprintf(stderr, "  FAIL %s: malformed shape was ACCEPTED (child exited %d)\n", what,
			WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		++g_failures;
		return;
	}
	printf("    refused: %s\n", what);
}

void M2C_CheckReversals()
{
	printf("  M2C reversals (each must be refused, not silently encoded)\n");

	// (a) MIXED WIDTHS in one lane operation. This is what a "just change the mnemonic" lowering
	// looks like from the inside: a 128-bit source feeding a 512-bit destination.
	M2C_ExpectPanic("vchunkadd with mixed host vector widths", [] {
		MemArena arena(1u << 20);
		StateInfo si{nullptr, 0};
		auto *region = arena.New<Region>(&arena, &si);
		qir::Builder qb(region->CreateBlock());
		auto d = VOperand::MakeVVPR(VType::V512, qb.CreateVGPR(VType::V512));
		auto a = VOperand::MakeVVPR(VType::V128, qb.CreateVGPR(VType::V128));
		auto b = VOperand::MakeVVPR(VType::V512, qb.CreateVGPR(VType::V512));
		qb.Create_vchunkadd(d, a, b, 4);
	});

	// (b) A SEW that does not tile the chunk: 8-byte lanes do divide 16, but a 16-byte chunk with
	// SEW=32 bytes cannot be a whole number of lanes.
	M2C_ExpectPanic("vchunkadd whose SEW does not tile the chunk width", [] {
		MemArena arena(1u << 20);
		StateInfo si{nullptr, 0};
		auto *region = arena.New<Region>(&arena, &si);
		qir::Builder qb(region->CreateBlock());
		auto mk = [&] { return VOperand::MakeVVPR(VType::V128, qb.CreateVGPR(VType::V128)); };
		qb.Create_vchunkadd(mk(), mk(), mk(), 32);
	});

	// (c) A scalar operand where a vector value is required -- the shape a lowering that "forgot"
	// the type would produce.
	M2C_ExpectPanic("vstatechunkstore of a non-vector value", [] {
		MemArena arena(1u << 20);
		StateInfo si{nullptr, 0};
		auto *region = arena.New<Region>(&arena, &si);
		qir::Builder qb(region->CreateBlock());
		auto s = VOperand::MakeVGPR(VType::I32, qb.CreateVGPR(VType::I32));
		qb.Create_vstatechunkstore(ST_VREG_BASE, s);
	});

	// (d) A width that has no host register form at all. VectorVTypeForBytes is the ONLY
	// byte-count-to-type mapping in the tree, so this is the single place an invented width can
	// be caught -- and it is, rather than being rounded to a neighbouring one.
	M2C_ExpectPanic("a chunk width that is not a host vector width", [] {
		(void)qir::VectorVTypeForBytes(48);
	});
}

// MC2: spill/fill coherence. A narrow value must occupy a slot of ITS OWN size and be moved by an
// access of its own width -- the allocator sizes the slot with VTypeToSize and the emitter sizes
// the move with the same function, so this checks they really are the same fact.
void M2C_CheckNarrowSpillSlot()
{
	printf("  M2C narrow spill slot sizing\n");
	struct Row {
		VType type;
		u16 bytes;
	} const rows[] = {{VType::V128, 16}, {VType::V256, 32}, {VType::V512, 64}};
	for (auto const &r : rows) {
		CHECK_EQ(VTypeToSize(r.type), (u8)r.bytes);
		CHECK(VTypeToRegClass(r.type) == RegClass::VPR);
		CHECK(qir::VectorVTypeForBytes(r.bytes) == r.type);
		CHECK(qir::IsVectorVType(r.type));
	}
	printf("    ok V128/V256/V512 -> 16/32/64 bytes, all RegClass::VPR, mapping is a bijection\n");
}

} // namespace

int main()
{
	printf("QCG typed vadd.vv route test (CompilerGenRegionIR, real translator)\n");
	printf("  ST_VREG_BASE=%u  sizeof(CPUState)=%zu  vs2=v%u vs1=v%u vd=v%u\n", ST_VREG_BASE,
	       sizeof(CPUState), VS2_REG, VS1_REG, VD_REG);

	CheckRoute("VLEN=512 regression control", 512u, 1u, 16u);
	CheckRoute("VLEN=1024 two-chunk", 1024u, 2u, 32u);

	CheckRoutePostQRA("VLEN=512 post-QRA", 512u, 1u, 16u);
	CheckRoutePostQRA("VLEN=1024 post-QRA two-chunk", 1024u, 2u, 32u);

	CheckRouteEmitted("VLEN=512 emitted", 512u, 1u, 16u);
	CheckRouteEmitted("VLEN=1024 emitted two-chunk", 1024u, 2u, 32u);

	// C3.1f: the vsetvli is in another translation block, so rvv_bb_vtype is unknown.
	CheckUnknownVtypeAdmitted("VLEN=512 unknown-vtype", 512u, 1u, 16u);
	CheckUnknownVtypeAdmitted("VLEN=1024 unknown-vtype two-chunk", 1024u, 2u, 32u);
	CheckUnknownVtypeDefaultOff("VLEN=512 unknown-vtype off", 512u);
	CheckUnknownVtypeDefaultOff("VLEN=1024 unknown-vtype off", 1024u);
	CheckObservedVtypePrecedence("VLEN=512 observed e64", 512u);
	CheckObservedVtypePrecedence("VLEN=1024 observed e64", 1024u);

	// C3.2a-fix1: the same unknown-vtype candidate now reaches the diagnostic control arm.
	CheckUnknownVtypeDiagAdmitted("VLEN=512 unknown-vtype diag", 512u, 1u, 16u);
	CheckUnknownVtypeDiagAdmitted("VLEN=1024 unknown-vtype diag two-chunk", 1024u, 2u, 32u);
	CheckUnknownVtypeBothArmsTypedWins("VLEN=512 both arms", 512u, 1u);
	CheckUnknownVtypeBothArmsTypedWins("VLEN=1024 both arms", 1024u, 2u);
	CheckUnknownVtypeHelperArm("VLEN=512 helper arm", 512u);
	CheckUnknownVtypeHelperArm("VLEN=1024 helper arm", 1024u);
	// e64 VLMAX at LMUL=1 is VLEN/64: 8 and 16, never the e32 candidate's 16 and 32.
	CheckObservedVtypePrecedenceDiag("VLEN=512 observed e64 diag", 512u, 1u, 8u);
	CheckObservedVtypePrecedenceDiag("VLEN=1024 observed e64 diag", 1024u, 2u, 16u);

	// C3.1f-fix11: K1's eight-group block. Last, because a regression here aborts the process.
	CheckManyGroups("VLEN=512 eight groups", 512u, 1u, 16u);
	CheckManyGroups("VLEN=1024 eight groups", 1024u, 2u, 32u);

	// M2C: the width-correct vertical slice, at all four widths the meeting record asks for.
	printf("--- M2C width-correct vadd.vv vertical slice ---\n");
	M2C_CheckNarrowSpillSlot();
	for (auto const &c : M2C_CASES)
		M2C_CheckQIRWidth(c);
	for (auto const &c : M2C_CASES)
		M2C_CheckEmittedWidth(c);
	for (auto const &c : M2C_CASES)
		M2C_CheckUnknownVtypeWidth(c);
	M2C_CheckReversals();

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK: all checks passed\n");
	return 0;
}
