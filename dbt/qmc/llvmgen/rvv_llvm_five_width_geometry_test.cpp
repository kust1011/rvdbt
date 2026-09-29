// W5 (2026-09-17). ONE HOST-CHUNK GEOMETRY FOR EVERY ADMITTED VLEN, ON THE LLVM/AOT ARM.
//
// WHAT CHANGED, AND WHY A TEST FILE IS NEEDED FOR IT
//
// Before W5 the LLVM typed-chunk routes were VLEN 512/1024, with one exception (`vadd.vv`, at
// 128..1024). That was not a property of the lowering: `TChunkAluLower`, `Emit_vstatechunkload` and
// `Emit_vstatechunkstore` have derived their widths from the value's own VType since P4, and
// `RvvHostChunkGeometry` has been able to describe 128..4096 since A1-review. It was a property of
// two constants -- `RvvSSAEnabled()`'s `{512, 1024}` and `RvvGenericChunkShapeAdmit`'s
// `vlen < 512` -- standing in for a width rule at gates that had no other one.
//
// W5 removes both. The substrate question (`RvvLLVMTypedSubstrate`) and the width question
// (`RvvRouteChunkShape` -> `RvvHostChunkGeometryForSew`) are now separate, and the FP and memory
// emitters take their lane counts and access widths from the chunk's own VType the way the integer
// ones already did.
//
// THIS FILE ASSERTS THE RESULT AS A GEOMETRY, NOT AS A LIST OF WIDTHS. Every expectation below is
// computed from `VLEN` by the same three lines the implementation uses -- width `min(VLEN/8, 64)`
// restricted to the three host vector widths, count `(VLEN/8)/width` -- so a build in which some
// route quietly kept a literal 64 fails here rather than passing at four of six widths.
//
//   [1] THE GEOMETRY ITSELF, as a truth table, at both element widths, including every refusal:
//       a register that is not a whole number of host chunks (VLEN 384 -> 48 bytes), one below the
//       smallest host vector (64), one above the guest's own limit (8192), and an element width no
//       lane op lowers.
//   [2] THE INTEGER `.vv` FAMILY (add/sub/mul/xor/or/and) at every admitted width: one typed frame,
//       `count` body ops, and every chunk value -- the state loads, the lane ops and the state
//       stores -- carrying the VType the geometry admitted. Asserting the TYPES is what
//       distinguishes "the width travelled" from "the count happened to be right".
//   [3] THE FP LANE FAMILY at every admitted width, at e32 AND e64: the frame's guard kind is still
//       the full-VL/RNE one, the body carries `count` lane ops per member at the admitted VType,
//       and the ordered per-member fallback is intact.
//   [4] THE FUSED FAMILY on the same terms.
//   [5] UNIT-STRIDE MEMORY at every admitted width, at EEW 32 and 64: `count` chunk accesses whose
//       displacements tile the register at the admitted width -- the rule that used to be
//       `disp % 64 == 0 && disp <= 64`.
//   [6] SAFE FALLBACK. At a width the geometry refuses, every family above builds NO typed frame
//       and the instruction still reaches a lowering (it is not dropped).
//   [7] THE BACKEND LOWERS WHAT THE FRONTEND ADMITTED, at every width. Every Panic named in the
//       emitters -- a chunk that is not a host vector width, one that is not a whole number of
//       elements, a displacement outside the node's rule -- aborts the process, so running
//       `QIRToLLVM::Run` at each width to completion IS the assertion.
//   [8] QCG ADMISSION IS UNCHANGED. The same words on the pure-QCG backend keep
//       `RvvGenericChunkShapeAdmit`'s rule: nothing at 128/256, `VLEN/512` chunks from 512 up. W5
//       widened one backend, and this is the row that says so.
//
// WHAT THIS FILE DOES NOT DO
//
//   * It never runs the code it builds. No object file is emitted and no PROT_EXEC page exists in
//     this process, so it needs no AVX-512 host and executes no vector instruction of any width.
//   * It makes no claim about VLENs 2048/4096 being architecturally VALIDATED. rv32_vector.h states
//     that the QEMU oracle covers [128, 1024] only; admitting a width here is a statement about
//     what this backend emits, not about what an oracle has confirmed.
//   * It asserts nothing about speed.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <cstdio>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

namespace rvv32 = dbt::rv32;

unsigned g_fail = 0;

#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto va_ = (long long)(a);                                                         \
		auto vb_ = (long long)(b);                                                         \
		if (va_ != vb_) {                                                                  \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, va_, vb_);                                                      \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

llvm::LLVMContext g_llvm_ctx;

// ---------------------------------------------------------------------------------------------
// The geometry, recomputed here from VLEN so an expectation is never a copied constant.
// ---------------------------------------------------------------------------------------------

struct Geom {
	u32 bytes = 0, count = 0;
	VType vtype = VType::UNDEF;
	explicit operator bool() const { return count != 0; }
};

Geom GeomFor(u32 vlen, u32 sew_bytes)
{
	Geom none;
	if (sew_bytes != 4 && sew_bytes != 8)
		return none;
	if (vlen < 128 || vlen > rvv32::VLEN_MAX_BITS || vlen % 8 != 0)
		return none;
	u32 const reg_bytes = vlen / 8;
	u32 const bytes = reg_bytes < 64 ? reg_bytes : 64;
	if (bytes != 16 && bytes != 32 && bytes != 64)
		return none;
	if (bytes % sew_bytes != 0 || reg_bytes % bytes != 0)
		return none;
	u32 const count = reg_bytes / bytes;
	if (count == 0 || count > rvv32::rvvrun::kMaxChunks)
		return none;
	Geom g;
	g.bytes = bytes;
	g.count = count;
	g.vtype = bytes == 16 ? VType::V128 : bytes == 32 ? VType::V256 : VType::V512;
	return g;
}

// The five widths this checkpoint is about, plus 4096 -- the width at which the geometry's own
// `count <= kMaxChunks` bound becomes the binding one at LMUL 1. Including it is what makes the
// bound asserted rather than assumed.
constexpr u32 WIDTHS[] = {128u, 256u, 512u, 1024u, 2048u, 4096u};
// The five widths this checkpoint assigns. Multi-member FP RUN frames are asserted over these: at
// 4096 one register group is eight chunks, so a three-member run over three groups is 24 chunk
// registers and a fourth group would exceed `rvvrun::kHostVectorRegs`. That bound is asserted in
// its own right by section 4b rather than worked around here.
constexpr u32 FRAME_WIDTHS[] = {128u, 256u, 512u, 1024u, 2048u};
// Widths with no chunk shape, for the fallback rows: not a whole number of host chunks, below the
// smallest host vector, above the guest's own VLEN limit.
constexpr u32 REFUSED_WIDTHS[] = {384u, 64u, 8192u};

// ---------------------------------------------------------------------------------------------
// Encodings.
// ---------------------------------------------------------------------------------------------

constexpr u32 OpIVV(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0b000u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 OpMVV(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0b010u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 OpFVV(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (0b001u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
// unit-stride `vle<EEW>.v vd, (rs1)` / `vse<EEW>.v vs3, (rs1)`: nf=0, mew=0, mop=00, vm=1,
// lumop/sumop=00000. width 0b110 is EEW 32 and 0b111 is EEW 64 (rv32_decode.h).
constexpr u32 VleV(u32 width3, u32 rs1, u32 vd)
{
	return (1u << 25) | (rs1 << 15) | (width3 << 12) | (vd << 7) | 0b0000111u;
}
constexpr u32 VseV(u32 width3, u32 rs1, u32 vs3)
{
	return (1u << 25) | (rs1 << 15) | (width3 << 12) | (vs3 << 7) | 0b0100111u;
}

constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kVT_E64M1 = 0xd8u;

constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u, F6_VAND = 0b001001u;
constexpr u32 F6_VOR = 0b001010u, F6_VXOR = 0b001011u, F6_VMUL = 0b100101u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u, F6_VFMUL = 0b100100u;
constexpr u32 F6_VFMACC = 0b101100u;
constexpr u32 kJalr = 0x00008067u;

// ---------------------------------------------------------------------------------------------
// Translation.
// ---------------------------------------------------------------------------------------------

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("w5", g_llvm_ctx) {}
};

// Every per-route switch this file's families need, at one place. `rvv_qcg_typed_chunk` (the
// umbrella, default true) is held OFF so no LLVM route can borrow it: each reads its own.
void ConfigureLLVM(u32 vlen, bool llvm_backend = true)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_vle = true;
	config::rvv_qcg_typed_chunk_vse = true;
	config::rvv_qcg_typed_chunk_mem_e64 = true;
	config::rvv_qcg_narrow_chunk_width = false;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_grouped_component_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_partial_vl = false;
}

void Translate(Built &b, bool run_backend)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!run_backend)
		return;
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

// What a region's typed frames look like, at the QIR level -- which is the level the width lives
// at, before any LLVM optimisation has run.
struct Frames {
	unsigned n_begin = 0;
	unsigned n_members = 0;
	unsigned guard_kind = ~0u;
	unsigned body_ops = 0;	 // lane ops of the op under test
	unsigned state_loads = 0, state_stores = 0;
	unsigned mem_loads = 0, mem_stores = 0;
	unsigned bad_type = 0;	 // any chunk value whose VType is not the admitted one
	unsigned bad_disp = 0;	 // any memory chunk whose disp does not tile at the admitted width
	unsigned fallback_stubs = 0;
};

Frames Scan(Region *region, Op body_op, Geom const &g)
{
	Frames f;
	auto typed = [&](VOperand v) {
		if (IsVectorVType(v.GetType()) && v.GetType() != g.vtype)
			++f.bad_type;
	};
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto const op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				auto *bgn = static_cast<InstRVVTypedChunkBegin *>(&ins);
				++f.n_begin;
				f.n_members = bgn->n_members;
				f.guard_kind = (unsigned)bgn->guard_kind;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				f.fallback_stubs += static_cast<InstRVVTypedChunkEnd *>(&ins)->n_members;
				continue;
			}
			if (op == body_op)
				++f.body_ops;
			if (op == Op::_vstatechunkload)
				++f.state_loads;
			if (op == Op::_vstatechunkstore)
				++f.state_stores;
			if (op == Op::_vchunkload) {
				++f.mem_loads;
				u32 const d = static_cast<InstVChunkLoad *>(&ins)->disp;
				if (g.bytes == 0 || d % g.bytes != 0 || d / g.bytes >= g.count)
					++f.bad_disp;
			}
			if (op == Op::_vchunkstore) {
				++f.mem_stores;
				u32 const d = static_cast<InstVChunkStore *>(&ins)->disp;
				if (g.bytes == 0 || d % g.bytes != 0 || d / g.bytes >= g.count)
					++f.bad_disp;
			}
			auto in = ins.inputs();
			for (u8 k = 0; k < in.size(); ++k)
				typed(in[k]);
			auto out = ins.outputs();
			for (u8 k = 0; k < out.size(); ++k)
				typed(out[k]);
		}
	}
	return f;
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

// ---------------------------------------------------------------------------------------------
// [1] The geometry truth table.
// ---------------------------------------------------------------------------------------------
void Section1_Geometry()
{
	printf("1. RvvHostChunkGeometryForSew truth table\n");
	using T = dbt::qir::rv32::RV32Translator;
	for (u32 sew : {4u, 8u}) {
		for (u32 vlen : WIDTHS) {
			auto const want = GeomFor(vlen, sew);
			auto const got = T::RvvHostChunkGeometryForSew(vlen, sew);
			CHECK_EQ((unsigned)got.bytes, want.bytes);
			CHECK_EQ((unsigned)got.count, want.count);
			CHECK(want.count != 0); // every width in WIDTHS must tile at both SEWs
		}
		for (u32 vlen : REFUSED_WIDTHS) {
			auto const got = T::RvvHostChunkGeometryForSew(vlen, sew);
			CHECK_EQ((unsigned)got.count, 0u);
		}
	}
	// An element width no lane op in this tree lowers.
	for (u32 vlen : WIDTHS)
		for (u32 sew : {1u, 2u, 16u})
			CHECK_EQ((unsigned)T::RvvHostChunkGeometryForSew(vlen, sew).count, 0u);
	// And the SEW-32 wrapper still refuses e64 -- the row whose removal admitted `vadd.vv` at e64
	// into an `<N x i32>` emitter.
	for (u32 vlen : WIDTHS) {
		CHECK_EQ((unsigned)T::RvvHostChunkGeometry(vlen, 8u).count, 0u);
		CHECK_EQ((unsigned)T::RvvHostChunkGeometry(vlen, 4u).count, GeomFor(vlen, 4).count);
	}
	printf("   ok  both SEWs at %zu widths, %zu refusals, e64 still refused by the SEW-32 wrapper\n",
	       sizeof(WIDTHS) / sizeof(WIDTHS[0]), sizeof(REFUSED_WIDTHS) / sizeof(REFUSED_WIDTHS[0]));
}

// ---------------------------------------------------------------------------------------------
// [2] The integer `.vv` family.
// ---------------------------------------------------------------------------------------------
struct IntRoute {
	char const *name;
	u32 word;
	Op body_op;
};
IntRoute const INT_ROUTES[] = {
    {"vadd.vv", OpIVV(F6_VADD, 9, 10, 8), Op::_vchunkadd},
    {"vsub.vv", OpIVV(F6_VSUB, 9, 10, 8), Op::_vchunksub},
    {"vand.vv", OpIVV(F6_VAND, 9, 10, 8), Op::_vchunkand},
    {"vor.vv", OpIVV(F6_VOR, 9, 10, 8), Op::_vchunkor},
    {"vxor.vv", OpIVV(F6_VXOR, 9, 10, 8), Op::_vchunkxor},
    {"vmul.vv", OpMVV(F6_VMUL, 9, 10, 8), Op::_vchunkmul},
};

void Section2_Integer()
{
	printf("2. integer .vv family: one frame, k body ops, chunk VType from the geometry\n");
	for (auto const &r : INT_ROUTES) {
		for (u32 vlen : WIDTHS) {
			auto const g = GeomFor(vlen, 4);
			ConfigureLLVM(vlen);
			Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
			Translate(b, /*run_backend=*/true);
			auto const f = Scan(b.region, r.body_op, g);
			CHECK_EQ(f.n_begin, 1u);
			CHECK_EQ(f.body_ops, g.count);
			// Two source chunks in and one destination chunk out, per host chunk.
			CHECK_EQ(f.state_loads, 2u * g.count);
			CHECK_EQ(f.state_stores, g.count);
			// THE WIDTH TRAVELLED: no chunk value anywhere carries a different VType.
			CHECK_EQ(f.bad_type, 0u);
			// The ordered fallback is still one stub for this single-instruction frame.
			CHECK_EQ(f.fallback_stubs, 1u);
			CHECK(b.fn != nullptr);
		}
		printf("   ok  %-8s at 128/256/512/1024/2048/4096\n", r.name);
	}
}

// ---------------------------------------------------------------------------------------------
// [3]+[4] FP lane and fused families, e32 and e64.
// ---------------------------------------------------------------------------------------------
// THE FP FIXTURE IS THREE ADJACENT MEMBERS OVER THREE REGISTER GROUPS, and the register count is
// part of the fixture rather than an accident. A run's peak live chunk count is bounded against
// `rvvrun::kHostVectorRegs` (30), and a chunk count is `groups * count` -- so at VLEN 4096, where
// one group is EIGHT chunks, a three-group run is 24 and a four-group run would be 32 and be cut.
// Section 4b asserts that cut directly; this function stays inside the bound so a width failure
// here is a width failure and not a pressure one.
void CheckFp(u32 vlen, u32 vtype, bool fused)
{
	u32 const sew = vtype == kVT_E32M1 ? 4u : 8u;
	auto const g = GeomFor(vlen, sew);
	ConfigureLLVM(vlen);
	u32 const a = fused ? OpFVV(F6_VFMACC, 10, 12, 8) : OpFVV(F6_VFADD, 10, 12, 8);
	u32 const m = fused ? OpFVV(F6_VFMACC, 12, 10, 8) : OpFVV(F6_VFMUL, 8, 10, 8);
	u32 const s = fused ? OpFVV(F6_VFMACC, 10, 12, 8) : OpFVV(F6_VFSUB, 8, 12, 8);
	Built b({Vsetvli(vtype), a, m, s, kJalr});
	Translate(b, /*run_backend=*/true);
	auto const f = Scan(b.region, fused ? Op::_vchunkfma : Op::_vchunkfalu, g);
	CHECK_EQ(f.n_begin, 1u);
	CHECK_EQ(f.n_members, 3u);
	// The guard kind does not relax with width: an LLVM FP run is always the full-VL/RNE kind.
	CHECK_EQ(f.guard_kind, (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE);
	CHECK(InstRVVTypedChunkBegin::GuardProvesFullVl(
	    (InstRVVTypedChunkBegin::GuardKind)f.guard_kind));
	CHECK_EQ(f.body_ops, 3u * g.count);
	CHECK_EQ(f.bad_type, 0u);
	// Three members replayed in order on the guard-miss arm.
	CHECK_EQ(f.fallback_stubs, 3u);
	CHECK(b.fn != nullptr);
}

// 4b. THE CHUNK-REGISTER CAPACITY BOUND, at the width where it becomes the binding one.
//
// This is the limit the checkpoint has to respect rather than remove: a frame names its chunks as
// QIR vector values, and the run scan refuses one whose peak live count exceeds
// `rvvrun::kHostVectorRegs`. The bound is `groups * chunks_per_group`, so it is reached by WIDTH as
// well as by member count -- four groups is 4 chunks at VLEN 512 and 32 at VLEN 4096.
//
// The assertion is the cut, not a frame: a run that would not fit keeps the per-instruction
// lowering, which for an FP `.vv` on this backend is the unchanged `rv32_vfalu` helper.
void Section4b_CapacityBound()
{
	printf("4b. peak-live bound: a four-group FP run is cut where groups*chunks > %u\n",
	       (unsigned)rvv32::rvvrun::kHostVectorRegs);
	// Four distinct source groups plus the destination.
	u32 const a = OpFVV(F6_VFADD, 10, 12, 8);
	u32 const m = OpFVV(F6_VFMUL, 8, 14, 8);
	u32 const sx = OpFVV(F6_VFSUB, 8, 16, 18);
	for (u32 vlen : WIDTHS) {
		auto const g = GeomFor(vlen, 4);
		ConfigureLLVM(vlen);
		Built b({Vsetvli(kVT_E32M1), a, m, sx, kJalr});
		Translate(b, /*run_backend=*/false);
		auto const f = Scan(b.region, Op::_vchunkfalu, g);
		unsigned multi = 0, single = 0;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
					if (static_cast<InstRVVTypedChunkBegin *>(&ins)->n_members >= 2)
						++multi;
					else
						++single;
				}
		// Five groups (v8, v10, v12, v14, v16, v18 minus overlaps) at `g.count` chunks each: the
		// run fits while that product is within the pool and is cut once it is not. The test
		// asserts only the direction that is structural -- at the widest width it must be cut --
		// so it does not encode the pressure model's exact arithmetic.
		//
		// W5D (2026-09-17) CHANGED WHAT THE CUT FALLS BACK TO, and this row records it. The RUN is
		// still cut -- no multi-member frame -- but its three `.vv` members now each build a
		// STANDALONE typed frame instead of taking the helper, because Family A does not admit
		// them at this width and W5D gives that case the existing typed FP body. So the assertion
		// moved from "no frame at all" to "no run, three single-instruction frames": the capacity
		// bound is unchanged and the coverage hole behind it is closed.
		if (g.count * 5u > (u32)rvv32::rvvrun::kHostVectorRegs) {
			CHECK_EQ(multi, 0u);
			CHECK_EQ(single, 3u);
			CHECK_EQ(f.body_ops, 3u * g.count);
			printf("   ok  vlen=%-5u run cut (> %u chunk registers), 3 standalone frame(s)\n",
			       vlen, (unsigned)rvv32::rvvrun::kHostVectorRegs);
		}
	}
}

void Section3_Fp()
{
	printf("3. FP lane family (e32 and e64) at the five assigned widths\n");
	for (u32 vtype : {kVT_E32M1, kVT_E64M1}) {
		for (u32 vlen : FRAME_WIDTHS)
			CheckFp(vlen, vtype, /*fused=*/false);
		printf("   ok  vfadd/vfmul/vfsub vtype=0x%02x at 128/256/512/1024/2048\n", vtype);
	}
	printf("4. fused family (e32 and e64) at the five assigned widths\n");
	for (u32 vtype : {kVT_E32M1, kVT_E64M1}) {
		for (u32 vlen : FRAME_WIDTHS)
			CheckFp(vlen, vtype, /*fused=*/true);
		printf("   ok  vfmacc x3 vtype=0x%02x at 128/256/512/1024/2048\n", vtype);
	}
}

// ---------------------------------------------------------------------------------------------
// [5] Unit-stride memory.
// ---------------------------------------------------------------------------------------------
void Section5_Memory()
{
	printf("5. unit-stride vle/vse at every admitted width, EEW 32 and 64\n");
	for (u32 eew : {4u, 8u}) {
		u32 const width3 = eew == 4 ? 0b110u : 0b111u;
		u32 const vtype = eew == 4 ? kVT_E32M1 : kVT_E64M1;
		for (u32 vlen : WIDTHS) {
			auto const g = GeomFor(vlen, eew);
			ConfigureLLVM(vlen);
			Built bl({Vsetvli(vtype), VleV(width3, /*rs1=*/11, /*vd=*/8), kJalr});
			Translate(bl, /*run_backend=*/true);
			auto const fl = Scan(bl.region, Op::_vchunkload, g);
			CHECK_EQ(fl.n_begin, 1u);
			CHECK_EQ(fl.mem_loads, g.count);
			CHECK_EQ(fl.state_stores, g.count);
			// Every chunk's displacement is a whole number of THIS width and lands inside the
			// register -- the rule that replaced `disp % 64 == 0 && disp <= 64`.
			CHECK_EQ(fl.bad_disp, 0u);
			CHECK_EQ(fl.bad_type, 0u);
			CHECK(bl.fn != nullptr);

			ConfigureLLVM(vlen);
			Built bs({Vsetvli(vtype), VseV(width3, /*rs1=*/11, /*vs3=*/8), kJalr});
			Translate(bs, /*run_backend=*/true);
			auto const fs = Scan(bs.region, Op::_vchunkstore, g);
			CHECK_EQ(fs.n_begin, 1u);
			CHECK_EQ(fs.mem_stores, g.count);
			CHECK_EQ(fs.state_loads, g.count);
			CHECK_EQ(fs.bad_disp, 0u);
			CHECK_EQ(fs.bad_type, 0u);
			CHECK(bs.fn != nullptr);
		}
		printf("   ok  EEW %u load and store at all six widths\n", eew * 8);
	}
}

// ---------------------------------------------------------------------------------------------
// [6] Safe fallback at a width the geometry refuses.
// ---------------------------------------------------------------------------------------------
void Section6_Fallback()
{
	printf("6. widths with no chunk shape: no typed frame, and the instruction still lowers\n");
	for (u32 vlen : REFUSED_WIDTHS) {
		if (!rvv32::vlen_supported(vlen)) {
			// 64 and 8192 are not guest-legal widths at all; the translator is still asked,
			// and must still refuse rather than build a frame from a shape it does not have.
		}
		for (auto const &r : INT_ROUTES) {
			ConfigureLLVM(vlen);
			Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
			Translate(b, /*run_backend=*/false);
			CHECK_EQ(CountOp(b.region, Op::_rvvtypedchunkbegin), 0u);
			CHECK_EQ(CountOp(b.region, r.body_op), 0u);
			// Not dropped: the instruction reached some other lowering.
			CHECK(CountOp(b.region, Op::_hcall) + CountOp(b.region, Op::_rvvaddv) > 0u);
		}
		// The FP run and the memory routes, on the same widths.
		ConfigureLLVM(vlen);
		Built fp({Vsetvli(kVT_E32M1), OpFVV(F6_VFADD, 10, 12, 8), OpFVV(F6_VFMUL, 8, 14, 8),
			  OpFVV(F6_VFSUB, 8, 10, 18), kJalr});
		Translate(fp, /*run_backend=*/false);
		CHECK_EQ(CountOp(fp.region, Op::_rvvtypedchunkbegin), 0u);
		CHECK_EQ(CountOp(fp.region, Op::_vchunkfalu), 0u);
		ConfigureLLVM(vlen);
		Built mem({Vsetvli(kVT_E32M1), VleV(0b110u, 11, 8), kJalr});
		Translate(mem, /*run_backend=*/false);
		CHECK_EQ(CountOp(mem.region, Op::_vchunkload), 0u);
		printf("   ok  vlen=%-5u every family falls back\n", vlen);
	}
}

// ---------------------------------------------------------------------------------------------
// [8] QCG admission is unchanged.
// ---------------------------------------------------------------------------------------------
void Section8_QcgUnchanged()
{
	printf("8. pure-QCG admission keeps RvvGenericChunkShapeAdmit's rule\n");
	for (auto const &r : INT_ROUTES) {
		for (u32 vlen : WIDTHS) {
			ConfigureLLVM(vlen, /*llvm_backend=*/false);
			// The QCG emitters probe the compiling host for AVX-512; this file must build the
			// same QIR anywhere and emits nothing.
			config::rvv_qcg_typed_chunk_force_emit = true;
			config::rvv_qcg_typed_chunk_sub_force_emit = true;
			config::rvv_qcg_typed_chunk_mul_force_emit = true;
			config::rvv_qcg_typed_chunk_and_force_emit = true;
			config::rvv_qcg_typed_chunk_or_force_emit = true;
			config::rvv_qcg_typed_chunk_xor_force_emit = true;
			config::rvv_qcg_typed_chunk = true; // the QCG umbrella IS this arm's switch
			Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
			Translate(b, /*run_backend=*/false);
			config::rvv_qcg_typed_chunk_force_emit = false;
			config::rvv_qcg_typed_chunk_sub_force_emit = false;
			config::rvv_qcg_typed_chunk_mul_force_emit = false;
			config::rvv_qcg_typed_chunk_and_force_emit = false;
			config::rvv_qcg_typed_chunk_or_force_emit = false;
			config::rvv_qcg_typed_chunk_xor_force_emit = false;
			// UNCHANGED BY W5, AND THE ASYMMETRY ON THIS SIDE IS PRE-EXISTING.
			//
			// `vadd.vv`'s QCG shape is RvvVaddChunkShape, which has asked RvvHostChunkGeometry
			// directly since M2C, so the pure-QCG arm has admitted 128/256 for that one opcode
			// since before this checkpoint. The other five ask RvvAluChunkShapeAdmit ->
			// RvvGenericChunkShapeAdmit, whose rule is `VLEN % 512 == 0`. W5 changed neither:
			// it added an LLVM arm to RvvRouteChunkShape, and the pure-QCG path does not reach
			// it. Encoding both rules here rather than one is what makes this row an assertion
			// about QCG instead of an assertion about the widening.
			bool const vadd = r.body_op == Op::_vchunkadd;
			unsigned const want = vadd ? GeomFor(vlen, 4).count
						   : (vlen % 512u == 0 ? vlen / 512u : 0u);
			CHECK_EQ(CountOp(b.region, r.body_op), want);
		}
		printf("   ok  %-8s QCG rule unchanged at all six widths\n", r.name);
	}
}

} // namespace

int main()
{
	printf("RVV_LLVM_FIVE_WIDTH_GEOMETRY: 128/256/512/1024/2048 (+4096 capacity edge)\n");
	Section1_Geometry();
	Section2_Integer();
	Section3_Fp();
	Section4b_CapacityBound();
	Section5_Memory();
	Section6_Fallback();
	Section8_QcgUnchanged();
	printf(g_fail ? "FAIL (%u failures)\n" : "PASS (%u failures)\n", g_fail);
	return g_fail ? 1 : 0;
}
