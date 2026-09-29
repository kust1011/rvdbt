#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cstdio>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvg = dbt::rv32;
namespace run = dbt::rv32::rvvrun;

namespace
{
int failures;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (0)
#define CHECK_EQ(a, b) do { auto av = (a); auto bv = (b); if (av != bv) { std::fprintf(stderr, "FAIL %s:%d: %s != %s (%lld != %lld)\n", __FILE__, __LINE__, #a, #b, (long long)av, (long long)bv); ++failures; } } while (0)

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

constexpr u32 Vsetvli(u32 sew_field, u32 lmul_field)
{
	return (((rvg::VTYPE_VTA_BIT | rvg::VTYPE_VMA_BIT | (sew_field << rvg::VTYPE_VSEW_SHIFT) |
		  lmul_field) & 0x7ffu) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 FpVv(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (1u << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 VlNre64(u32 nregs, u32 rs1, u32 vd)
{
	return 0b0000111u | (vd << 7) | (0b111u << 12) | (rs1 << 15) |
	       (0b01000u << 20) | (1u << 25) | ((nregs - 1) << 29);
}
constexpr u32 VsNr(u32 nregs, u32 rs1, u32 vs3)
{
	return 0b0100111u | (vs3 << 7) | (rs1 << 15) | (0b01000u << 20) |
	       (1u << 25) | ((nregs - 1) << 29);
}
constexpr u32 Add(u32 rd, u32 rs1, u32 rs2)
{
	return (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33u;
}
constexpr u32 VSET_E64_M2 = Vsetvli(3, 1);
constexpr u32 VFADD_V8_V10_V12 = FpVv(rvg::VF6_VFADD, 10, 12, 8);
constexpr u32 VFSUB_V14_V8_V10 = FpVv(rvg::VF6_VFSUB, 8, 10, 14);

void Configure(u32 vlen)
{
	config::vlen_bits = vlen;
	config::rvv_vector_run = true;
	// Every case in this file is about a run that spans scalar address/counter maintenance, so
	// the membership-rule ablation factor is pinned ON here rather than left at whatever the
	// process default or a previous section put in the global. `CheckScalarPassthroughOff`
	// drives the other arm explicitly and restores it.
	config::rvv_run_scalar_passthrough = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_whole_reg = true;
	config::rvv_qcg_whole_reg_force_emit = true;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_full_vl_fast_body = true;
	config::rvv_lane_census = false;
	config::rvv_lowering = 1;
}

u32 VregBase()
{
	return (u32)(offsetof(CPUState, vec) + offsetof(rvg::VectorState, vreg));
}

void CheckWidth(u32 vlen)
{
	Configure(vlen);
	std::vector<u32> words{VSET_E64_M2, VFADD_V8_V10_V12, VFSUB_V14_V8_V10};
	auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)(words.data() + 1), 0, 8, 2, 0xd9u, run::RunLimits{});
	u32 const chunks = 2u * (vlen / 512u);
	CHECK_EQ(d.n_members, 2);
	CHECK_EQ(d.lmul_log2, 1);
	CHECK_EQ(d.nchunks, chunks);
	CHECK_EQ(d.chunk_bytes, 64);
	CHECK_EQ(d.live_in_mask, (1u << 10) | (1u << 12));
	CHECK_EQ(d.live_out_mask, (1u << 8) | (1u << 14));

	MemArena arena{1u << 21};
	CompilerJob::IpRangesSet ranges{{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	unsigned frames = 0, members = 0, loads = 0, stores = 0, alus = 0;
	std::vector<u32> load_offsets, store_offsets;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				++frames;
				members = static_cast<InstRVVTypedChunkBegin *>(&ins)->n_members;
				break;
			case Op::_vstatechunkload:
				++loads;
				load_offsets.push_back(static_cast<InstVStateChunkLoad *>(&ins)->offs);
				break;
			case Op::_vstatechunkstore:
				++stores;
				store_offsets.push_back(static_cast<InstVStateChunkStore *>(&ins)->offs);
				break;
			case Op::_vchunkfalu:
				++alus;
				break;
			default:
				break;
			}
		}
	}
	CHECK_EQ(frames, 1);
	CHECK_EQ(members, 2);
	CHECK_EQ(loads, 2u * chunks);
	CHECK_EQ(stores, 2u * chunks);
	CHECK_EQ(alus, 2u * chunks);

	for (u32 c = 0; c < chunks; ++c) {
		u32 const a = rvg::group_chunk_state_offset(VregBase(), 10, vlen, 64, c);
		u32 const b = rvg::group_chunk_state_offset(VregBase(), 12, vlen, 64, c);
		u32 const x = rvg::group_chunk_state_offset(VregBase(), 8, vlen, 64, c);
		u32 const y = rvg::group_chunk_state_offset(VregBase(), 14, vlen, 64, c);
		CHECK((std::find(load_offsets.begin(), load_offsets.end(), a) != load_offsets.end()));
		CHECK((std::find(load_offsets.begin(), load_offsets.end(), b) != load_offsets.end()));
		CHECK((std::find(store_offsets.begin(), store_offsets.end(), x) != store_offsets.end()));
		CHECK((std::find(store_offsets.begin(), store_offsets.end(), y) != store_offsets.end()));
	}
	std::fprintf(stderr, "VLEN=%u LMUL=2: %u chunks, %u loads, %u FP ops, %u stores\n",
		vlen, chunks, loads, alus, stores);
}

void CheckMemoryFpIsland(u32 vlen)
{
	Configure(vlen);
	std::vector<u32> words{
		VSET_E64_M2,
		VlNre64(2, 15, 8),
		VlNre64(2, 14, 10),
		Add(14, 14, 26),
		FpVv(rvg::VF6_VFADD, 8, 10, 8),
		VsNr(2, 15, 8),
	};
	auto const admitted = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)(words.data() + 1), 0, 20, 5, 0xd9u, run::RunLimits{});
	CHECK_EQ(admitted.n_members, 5);
	CHECK_EQ(admitted.n_vector_members, 4);
	CHECK_EQ(admitted.n_scalar_members, 1);
	std::fprintf(stderr, "memory-fp admission: members=%u cut=%s cut_pc=%u\n",
		admitted.n_members, run::CutReasonName(admitted.cut), admitted.cut_pc);
	MemArena arena{1u << 21};
	CompilerJob::IpRangesSet ranges{{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);

	unsigned frames = 0, members = 0, mem_loads = 0, mem_stores = 0, scalars = 0;
	unsigned state_loads = 0, state_stores = 0, fp_ops = 0;
	u32 base_mask = 0;
	bool in_four_member_frame = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: {
				auto *b = static_cast<InstRVVTypedChunkBegin *>(&ins);
				in_four_member_frame = b->n_members == 5;
				if (!in_four_member_frame)
					break;
				++frames;
				members = b->n_members;
				base_mask = b->base_state_mask;
				CHECK(b->guard_kind ==
				      InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNEBaseMask);
				break;
			}
			case Op::_rvvtypedchunkend: in_four_member_frame = false; break;
			case Op::_vchunkload: mem_loads += in_four_member_frame; break;
			case Op::_vchunkstore: mem_stores += in_four_member_frame; break;
			case Op::_vstatechunkload: state_loads += in_four_member_frame; break;
			case Op::_vstatechunkstore: state_stores += in_four_member_frame; break;
			case Op::_vchunkfalu: fp_ops += in_four_member_frame; break;
			case Op::_rvvrunscalar: scalars += in_four_member_frame; break;
			default: break;
			}
		}
	u32 const chunks = 2u * (vlen / 512u);
	CHECK_EQ(frames, 1);
	CHECK_EQ(members, 5);
	CHECK_EQ(base_mask, (1u << 14) | (1u << 15));
	CHECK_EQ(mem_loads, 2u * chunks);
	CHECK_EQ(mem_stores, chunks);
	CHECK_EQ(fp_ops, chunks);
	CHECK_EQ(scalars, 1);
	CHECK_EQ(state_loads, 0);
	// v8 and v10 are architectural live-outs. Their values remain in SSA between memory and FP.
	CHECK_EQ(state_stores, 2u * chunks);
	TestCompilerRuntime cr;
	CodeSegment segment(0u, 0x1000u);
	auto const host = qcg::GenerateCode(&cr, &segment, region, 0);
	CHECK(!host.empty());

	// A scalar update may not be followed by a vector memory use of the updated base inside
	// the same frame: the frame-entry range guard observed the old value.
	std::vector<u32> unsafe{VlNre64(2, 14, 8), Add(14, 14, 26), VlNre64(2, 14, 10)};
	auto const refused = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)unsafe.data(), 0, 12, 3, 0xd9u, run::RunLimits{});
	// The scalar was admitted while the scan was still hoping to reach a second vector member;
	// the second load cut, so the scalar bridges nothing and is trimmed back out of the run.
	CHECK_EQ(refused.n_members, 1);
	CHECK_EQ(refused.n_vector_members, 1);
	CHECK_EQ(refused.n_scalar_members, 0);
	CHECK_EQ(refused.end_pc, 4u);
	CHECK_EQ(refused.scalar_written_mask, 0u);
	CHECK_EQ(refused.cut, run::CutReason::ScalarInsn);
	std::fprintf(stderr,
		"VLEN=%u load-load-add-store: %u memory loads, %u FP ops, %u memory stores, "
		"%u intermediate state loads\n",
		vlen, mem_loads, fp_ops, mem_stores, state_loads);
}
// A scalar passthrough member is admitted only to BRIDGE two vector members. FormRun therefore ends
// a run at its last VECTOR member and withdraws every frame-scope fact the trailing scalars
// contributed. Each case below is written so that the un-trimmed answer differs in a field the
// checks read, not only in `n_members`.
void CheckTrailingScalarTrim(u32 vlen)
{
	Configure(vlen);

	// (1) THE REAL SHAPE the Livermore kernels present: an island that loads, bridges over the
	// pointer bump, computes, stores -- and is then followed by more scalar maintenance that has
	// nothing to bridge. Exactly the first five instructions belong to the run.
	//
	// The trailing scalar writes x13 and the bridging one writes x14, so `scalar_written_mask`
	// distinguishes "trimmed" from "kept": an un-trimmed run reports both bits.
	std::vector<u32> shaped{
		VlNre64(2, 15, 8),   // 0  vector
		VlNre64(2, 14, 10),  // 4  vector
		Add(14, 14, 26),     // 8  scalar, bridges 4 -> 12
		FpVv(rvg::VF6_VFADD, 8, 10, 8), // 12 vector
		VsNr(2, 15, 8),	     // 16 vector
		Add(13, 13, 26),     // 20 scalar, bridges nothing
	};
	auto const trimmed = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)shaped.data(), 0, (u32)shaped.size() * 4u, (u32)shaped.size(), 0xd9u,
		run::RunLimits{});
	CHECK_EQ(trimmed.n_members, 5);
	CHECK_EQ(trimmed.n_vector_members, 4);
	CHECK_EQ(trimmed.n_scalar_members, 1);
	CHECK_EQ(trimmed.end_pc, 20u);
	CHECK_EQ(trimmed.scalar_written_mask, (1u << 14));
	CHECK(trimmed.members[2].op == run::RunOp::Scalar);
	CHECK(trimmed.members[4].op == run::RunOp::StoreWhole);
	CHECK(trimmed.members[4].pc == 16u);

	// (2) `partial_vl_ok` must be restored, not left at the value the trailing scalar forced.
	// Two FP members alone permit vl < VLMAX; a scalar member does not, and an un-trimmed run
	// would report false here and take the stricter guard for work it no longer contains.
	std::vector<u32> fp_tail{VFADD_V8_V10_V12, VFSUB_V14_V8_V10, Add(13, 13, 26)};
	auto const fp = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)fp_tail.data(), 0, (u32)fp_tail.size() * 4u, (u32)fp_tail.size(), 0xd9u,
		run::RunLimits{});
	CHECK_EQ(fp.n_members, 2);
	CHECK_EQ(fp.n_vector_members, 2);
	CHECK_EQ(fp.n_scalar_members, 0);
	CHECK_EQ(fp.end_pc, 8u);
	CHECK_EQ(fp.scalar_written_mask, 0u);
	CHECK(fp.partial_vl_ok);

	// (3) vector, scalar, scalar. There is no second vector member, so nothing is bridged and the
	// run collapses to the single vector instruction -- it must NOT come out as a multi-member
	// run, which is what the consumer's `n_members >= 2 && n_vector_members >= 2` gate reads.
	std::vector<u32> lone{VFADD_V8_V10_V12, Add(14, 14, 26), Add(13, 13, 26)};
	auto const one = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)lone.data(), 0, (u32)lone.size() * 4u, (u32)lone.size(), 0xd9u,
		run::RunLimits{});
	CHECK_EQ(one.n_members, 1);
	CHECK_EQ(one.n_vector_members, 1);
	CHECK_EQ(one.n_scalar_members, 0);
	CHECK_EQ(one.end_pc, 4u);
	CHECK_EQ(one.scalar_written_mask, 0u);
	CHECK(!one.IsMultiMember());

	std::fprintf(stderr,
		"VLEN=%u trailing-scalar trim: shaped=%u/%u fp_tail=%u lone=%u\n", vlen,
		trimmed.n_members, trimmed.n_vector_members, fp.n_members, one.n_members);
}

// THE OTHER ARM OF THE MEMBERSHIP ABLATION. With `rvv_run_scalar_passthrough` off, the three
// integer ALU forms are ordinary non-members: a scalar instruction between two vector members must
// CUT the run with CutReason::ScalarInsn, exactly as any other scalar instruction does, and the run
// must not span it. The inputs are the SAME word sequences the on-arm cases above use, so the only
// thing that differs between the two arms is the switch.
void CheckScalarPassthroughOff(u32 vlen)
{
	Configure(vlen);
	config::rvv_run_scalar_passthrough = false;

	// The real shape again: the run now stops at the scalar bump instead of bridging over it.
	std::vector<u32> shaped{
		VlNre64(2, 15, 8),   // 0  vector
		VlNre64(2, 14, 10),  // 4  vector
		Add(14, 14, 26),     // 8  scalar -- a BARRIER on this arm
		FpVv(rvg::VF6_VFADD, 8, 10, 8), // 12
		VsNr(2, 15, 8),	     // 16
		Add(13, 13, 26),     // 20
	};
	auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)shaped.data(), 0, (u32)shaped.size() * 4u, (u32)shaped.size(), 0xd9u,
		run::RunLimits{});
	CHECK_EQ(d.n_members, 2);
	CHECK_EQ(d.n_vector_members, 2);
	CHECK_EQ(d.n_scalar_members, 0);
	CHECK_EQ(d.end_pc, 8u);
	CHECK_EQ(d.cut, run::CutReason::ScalarInsn);
	CHECK_EQ(d.cut_pc, 8u);
	CHECK_EQ(d.scalar_written_mask, 0u);
	CHECK(d.members[0].op == run::RunOp::LoadWhole);
	CHECK(d.members[1].op == run::RunOp::LoadWhole);

	// A scalar at position 0 forms no run at all -- the same rule with nothing admitted before it.
	std::vector<u32> lead{Add(14, 14, 26), VFADD_V8_V10_V12, VFSUB_V14_V8_V10};
	auto const none = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)lead.data(), 0, (u32)lead.size() * 4u, (u32)lead.size(), 0xd9u,
		run::RunLimits{});
	CHECK_EQ(none.n_members, 0);
	CHECK_EQ(none.cut, run::CutReason::ScalarInsn);
	CHECK_EQ(none.cut_pc, 0u);

	// Two FP members with a trailing scalar: identical to the on-arm case (2), because the trim
	// and the switch reach the same answer from different directions. What must NOT differ is
	// `partial_vl_ok` -- the frame's guard kind is read from it.
	std::vector<u32> fp_tail{VFADD_V8_V10_V12, VFSUB_V14_V8_V10, Add(13, 13, 26)};
	auto const fp = qir::rv32::RV32Translator::RvvAdmitVectorRun(
		(uptr)fp_tail.data(), 0, (u32)fp_tail.size() * 4u, (u32)fp_tail.size(), 0xd9u,
		run::RunLimits{});
	CHECK_EQ(fp.n_members, 2);
	CHECK_EQ(fp.n_scalar_members, 0);
	CHECK_EQ(fp.end_pc, 8u);
	CHECK(fp.partial_vl_ok);
	CHECK_EQ(fp.cut, run::CutReason::ScalarInsn);

	// `addi` and `sub` are the other two forms the on-arm rule covers; both must cut here too.
	// Written as a loop over the three so that a future arm that re-admits only one of them is
	// caught rather than averaged away.
	u32 const scalar_forms[] = {
		Add(13, 13, 26),			     // add
		(26u << 20) | (13u << 15) | (13u << 7) | 0x13u,	     // addi x13, x13, 26
		(0b0100000u << 25) | (26u << 20) | (13u << 15) | (13u << 7) | 0x33u, // sub
	};
	for (u32 w : scalar_forms) {
		std::vector<u32> pair{VFADD_V8_V10_V12, w, VFSUB_V14_V8_V10};
		auto const cut = qir::rv32::RV32Translator::RvvAdmitVectorRun(
			(uptr)pair.data(), 0, (u32)pair.size() * 4u, (u32)pair.size(), 0xd9u,
			run::RunLimits{});
		CHECK_EQ(cut.n_members, 1);
		CHECK_EQ(cut.n_scalar_members, 0);
		CHECK_EQ(cut.end_pc, 4u);
		CHECK_EQ(cut.cut, run::CutReason::ScalarInsn);
	}

	std::fprintf(stderr, "VLEN=%u passthrough OFF: shaped=%u (cut=%s@%u), lead=%u, fp_tail=%u\n",
		vlen, d.n_members, run::CutReasonName(d.cut), d.cut_pc, none.n_members, fp.n_members);
	config::rvv_run_scalar_passthrough = true;
}
} // namespace

int main()
{
	static_assert(rvg::group_chunk_location(8, 512, 64, 0).reg == 8);
	static_assert(rvg::group_chunk_location(8, 512, 64, 1).reg == 9);
	static_assert(rvg::group_chunk_location(8, 1024, 64, 1).reg == 8);
	static_assert(rvg::group_chunk_location(8, 1024, 64, 2).reg == 9);
	CheckWidth(512);
	CheckWidth(1024);
	CheckMemoryFpIsland(512);
	CheckMemoryFpIsland(1024);
	CheckTrailingScalarTrim(512);
	CheckTrailingScalarTrim(1024);
	CheckScalarPassthroughOff(512);
	CheckScalarPassthroughOff(1024);
	if (failures) {
		std::fprintf(stderr, "FAILED: %d checks\n", failures);
		return 1;
	}
	std::fprintf(stderr, "ALL CHECKS PASSED\n");
	return 0;
}
