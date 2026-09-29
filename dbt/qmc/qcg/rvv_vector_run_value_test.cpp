// Execute the production M1 vector-run body and compare architectural post-state
// against an independent element-wise oracle. This complements the structural
// admission/code-generation tests: it specifically checks final publication and
// legal source/destination overlap on AVX-512 hardware.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/qcg/rvv_both_boundary_campaign_config.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sys/mman.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
namespace rv32 = dbt::rv32;
namespace rvvrun = dbt::rv32::rvvrun;
int g_checks = 0;
int g_failures = 0;
bool g_fp_batch_test = false, g_batch = false, g_both = false;

#define CHECK_MSG(cond, ...)                                                                         \
	do {                                                                                         \
		++g_checks;                                                                          \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                         \
			fprintf(stderr, __VA_ARGS__);                                                \
			fprintf(stderr, "\n");                                                       \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

constexpr u32 VTypeE32M1() { return 2u << 3; } // tail/mask undisturbed
constexpr u32 Vsetvli()
{
	return (VTypeE32M1() << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 OpV(u32 funct6, u32 vs2, u32 vs1, u32 vd)
{
	return (funct6 << 26) | (1u << 25) | (vs2 << 20) | (vs1 << 15) | (vd << 7) | 0x57u;
}
constexpr u32 Vadd(u32 vd, u32 vs2, u32 vs1) { return OpV(0u, vs2, vs1, vd); }
constexpr u32 Vsub(u32 vd, u32 vs2, u32 vs1) { return OpV(2u, vs2, vs1, vd); }
void ApplyConfig(u32 vlen, bool run)
{
	if (g_fp_batch_test) {
		if (g_both) campaign_config::ApplyCampaignArm_BOTH();
		else campaign_config::ApplyCampaignArm_M1();
		campaign_config::ForceEmitAll();
		config::vlen_bits = vlen;
		config::rvv_run_bounded_batches = g_batch;
		config::rvv_run_grouped_component_major = g_both;
		config::rvv_qcg_active_vl_run_bound = g_both;
		config::aot_use_llvm = false;
		return;
	}
	config::vlen_bits = vlen;
	config::aot_use_llvm = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = run;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_component_demand_placement = false;
	config::rvv_run_grouped_component_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_run_scalar_passthrough = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_partial_vl = true;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_active_vl_widen_bound = false;
	config::rvv_qcg_active_vl_narrow_bound = false;
	config::rvv_qcg_active_vl_run_bound = false;
	config::rvv_qcg_hit_counter = false;
	config::trace = false;
}

struct Runtime final : CompilerRuntime {
	~Runtime()
	{
		if (mem)
			munmap(mem, size);
	}
	void *AllocateCode(size_t n, uint) override
	{
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED)
			Panic("M1 value test: code mmap failed");
		last = static_cast<u8 *>(mem);
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	u8 *last{};
	size_t size{};
};

extern "C" __attribute__((noinline, naked)) void Enter(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void Enter(void *, void *, void *)
{
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Runtime runtime;
	Region *region{};
	u8 *code{};
	unsigned multi_member_frames{};
};

void Build(Built &b, std::vector<u32> words, u32 vlen, bool run, RvvEntryHint hint = {})
{
	ApplyConfig(vlen, run);
	b.words = std::move(words);
	CompilerJob::IpRangesSet ranges = {{0u, static_cast<u32>(b.words.size() * 4u)}};
	CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u),
			std::move(ranges), hint);
	b.region = CompilerGenRegionIR(&b.arena, job);
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvtypedchunkend &&
			    static_cast<InstRVVTypedChunkEnd &>(ins).n_members > 1)
				++b.multi_member_frames;

	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
	CHECK_MSG(!span.empty(), "generated region is empty");
	b.code = b.runtime.last;
	size_t n = span.size();
	if (b.code[0] == 0x51)
		b.code[n++] = 0x59;
	b.code[n] = 0xc3;
}

void Fill(rv32::VectorState &vec)
{
	for (u32 r = 0; r < 32; ++r)
		for (u32 i = 0; i < rv32::VLEN_MAX_BYTES / 4; ++i) {
			u32 const x = 0x1020304u * (r + 1u) + 0x11111111u * i;
			memcpy(vec.vreg[r].data() + 4u * i, &x, sizeof x);
		}
}

u32 Get(rv32::VectorState const &vec, u32 reg, u32 lane)
{
	u32 x;
	memcpy(&x, vec.vreg[reg].data() + 4u * lane, sizeof x);
	return x;
}

void Run(Built &b, u32 state_vlen, u32 avl, u32 a1, rv32::VectorState const &seed,
	rv32::VectorState *out, u64 *fallbacks, u32 initial_vtype = 0, u32 initial_vl = 0,
	u32 initial_vstart = 0, u32 *fcsr = nullptr)
{
	CPUState state(nullptr);
	memset(static_cast<void *>(&state), 0, sizeof state);
	state.vec = seed;
	state.vec.vlenb = static_cast<u16>(state_vlen / 8u);
	state.vec.vtype = initial_vtype;
	state.vec.vl = initial_vl;
	state.vec.vstart = initial_vstart;
	state.gpr[10] = avl;
	state.gpr[11] = a1;
	Enter(&state, nullptr, b.code);
	*out = state.vec;
	*fallbacks = state.rvv_direct_fallbacks;
	if (fcsr) *fcsr = state.fpu.fcsr;
}

void CheckChain(u32 vlen)
{
	std::vector<u32> const words = {Vsetvli(), Vadd(8, 2, 3), Vsub(9, 8, 4)};
	Built baseline, m1;
	Build(baseline, words, vlen, false);
	Build(m1, words, vlen, true);
	CHECK_MSG(baseline.multi_member_frames == 0, "VLEN=%u baseline formed an M1 frame", vlen);
	CHECK_MSG(m1.multi_member_frames == 1, "VLEN=%u M1 formed %u multi-member frames", vlen,
		  m1.multi_member_frames);

	rv32::VectorState seed{};
	Fill(seed);
	rv32::VectorState b_out{}, m1_out{};
	u64 b_fallbacks = 0, m1_fallbacks = 0;
	Run(baseline, vlen, vlen / 32u, 0, seed, &b_out, &b_fallbacks);
	Run(m1, vlen, vlen / 32u, 0, seed, &m1_out, &m1_fallbacks);
	CHECK_MSG(b_fallbacks == 0 && m1_fallbacks == 0,
		  "VLEN=%u fallback counts baseline=%llu M1=%llu", vlen,
		  (unsigned long long)b_fallbacks, (unsigned long long)m1_fallbacks);
	CHECK_MSG(b_out.vtype == m1_out.vtype && b_out.vl == m1_out.vl &&
			  b_out.vstart == m1_out.vstart && b_out.vlenb == m1_out.vlenb &&
			  b_out.vxrm == m1_out.vxrm && b_out.vxsat == m1_out.vxsat &&
			  b_out.fused_skip_pc == m1_out.fused_skip_pc &&
			  b_out.fused_skip_raw == m1_out.fused_skip_raw &&
			  b_out.fused_skip_valid == m1_out.fused_skip_valid,
		  "VLEN=%u baseline/M1 metadata differ: vtype=%08x/%08x vl=%u/%u "
		  "vstart=%u/%u vlenb=%u/%u fused=%u/%u",
		  vlen, b_out.vtype, m1_out.vtype, b_out.vl, m1_out.vl, b_out.vstart,
		  m1_out.vstart, b_out.vlenb, m1_out.vlenb, (unsigned)b_out.fused_skip_valid,
		  (unsigned)m1_out.fused_skip_valid);
	for (u32 r = 0; r < 32; ++r)
		CHECK_MSG(memcmp(b_out.vreg[r].data(), m1_out.vreg[r].data(),
				 rv32::VLEN_MAX_BYTES) == 0,
			  "VLEN=%u baseline and M1 differ in v%u", vlen, r);

	u32 const lanes = vlen / 32u;
	for (u32 i = 0; i < lanes; ++i) {
		u32 const intermediate = Get(seed, 2, i) + Get(seed, 3, i);
		u32 const final = intermediate - Get(seed, 4, i);
		CHECK_MSG(Get(m1_out, 8, i) == intermediate,
			  "VLEN=%u lane=%u intermediate v8 was not published", vlen, i);
		CHECK_MSG(Get(m1_out, 9, i) == final,
			  "VLEN=%u lane=%u final v9 mismatch", vlen, i);
	}
	for (u32 r = 0; r < 32; ++r)
		if (r != 8 && r != 9)
			CHECK_MSG(memcmp(seed.vreg[r].data(), m1_out.vreg[r].data(),
					 rv32::VLEN_MAX_BYTES) == 0,
				  "VLEN=%u unrelated v%u changed", vlen, r);
	printf("chain VLEN=%u: M1 frame=1 fallback=0 intermediate-and-final publication PASS\n",
	       vlen);
}

void CheckOverlap(u32 vlen)
{
	// The first instruction reads the old v3 before replacing it; the second reads
	// that newly produced v3. A wrong load/store ordering changes the final value.
	std::vector<u32> const words = {Vsetvli(), Vadd(3, 3, 2), Vsub(3, 3, 2)};
	Built m1;
	Build(m1, words, vlen, true);
	CHECK_MSG(m1.multi_member_frames == 1, "VLEN=%u overlap did not form one M1 frame", vlen);
	rv32::VectorState seed{};
	Fill(seed);
	rv32::VectorState out{};
	u64 fallbacks = 0;
	Run(m1, vlen, vlen / 32u, 0, seed, &out, &fallbacks);
	CHECK_MSG(fallbacks == 0, "VLEN=%u overlap unexpectedly used fallback", vlen);
	for (u32 i = 0; i < vlen / 32u; ++i)
		CHECK_MSG(Get(out, 3, i) == Get(seed, 3, i),
			  "VLEN=%u overlap lane=%u mismatch", vlen, i);
	printf("overlap VLEN=%u: old-source ordering and final publication PASS\n", vlen);
}

void CheckGeometryFallback()
{
	constexpr u32 compiled_vlen = 1024;
	constexpr u32 runtime_vlen = 512;
	Built m1;
	Build(m1, {Vadd(8, 2, 3), Vsub(9, 8, 4)}, compiled_vlen, true);
	CHECK_MSG(m1.multi_member_frames == 1, "geometry control did not form one M1 frame");
	rv32::VectorState seed{};
	Fill(seed);
	rv32::VectorState out{};
	u64 fallbacks = 0;
	Run(m1, runtime_vlen, runtime_vlen / 32u, 0, seed, &out, &fallbacks, VTypeE32M1(),
	    runtime_vlen / 32u, 0);
	CHECK_MSG(fallbacks == 1, "geometry mismatch fallback count=%llu, expected 1",
		  (unsigned long long)fallbacks);
	for (u32 i = 0; i < runtime_vlen / 32u; ++i) {
		u32 const intermediate = Get(seed, 2, i) + Get(seed, 3, i);
		CHECK_MSG(Get(out, 8, i) == intermediate, "geometry fallback v8 lane=%u mismatch", i);
		CHECK_MSG(Get(out, 9, i) == intermediate - Get(seed, 4, i),
			  "geometry fallback v9 lane=%u mismatch", i);
	}
	if (fallbacks == 1)
		printf("geometry mismatch: ordered fallback=1 and reference result PASS\n");
}

void CheckVstartFallback()
{
	constexpr u32 vlen = 1024;
	constexpr u32 start = 5;
	Built m1;
	Build(m1, {Vadd(8, 2, 3), Vsub(9, 8, 4)}, vlen, true);
	CHECK_MSG(m1.multi_member_frames == 1, "vstart control did not form one M1 frame");
	rv32::VectorState seed{};
	Fill(seed);
	rv32::VectorState out{};
	u64 fallbacks = 0;
	Run(m1, vlen, vlen / 32u, start, seed, &out, &fallbacks, VTypeE32M1(), vlen / 32u,
	    start);
	CHECK_MSG(fallbacks == 1, "nonzero-vstart fallback count=%llu, expected 1",
		  (unsigned long long)fallbacks);
	for (u32 i = 0; i < vlen / 32u; ++i) {
		u32 const intermediate = i < start ? Get(seed, 8, i)
						   : Get(seed, 2, i) + Get(seed, 3, i);
		CHECK_MSG(Get(out, 8, i) == intermediate, "vstart fallback v8 lane=%u mismatch", i);
		CHECK_MSG(Get(out, 9, i) == intermediate - Get(seed, 4, i),
			  "vstart fallback v9 lane=%u mismatch", i);
	}
	CHECK_MSG(out.vstart == 0, "vstart fallback did not clear vstart");
	if (fallbacks == 1)
		printf("nonzero vstart: ordered fallback=1, per-member restart semantics PASS\n");
}

template<class F>
void CheckBoundedFp(u32 vlen, bool both, bool chain, bool fused = false, bool copies = false)
{
	int const failures_before = g_failures;
	g_fp_batch_test = true;
	g_both = both;
	auto fp = [](u32 op, u32 d, u32 a, u32 b) { return OpV(op, a, b, d) | (1u << 12); };
	constexpr u32 fp_vtype = (sizeof(F) == 4 ? 2u : 3u) << 3 | 0xc0u;
	u32 const setup = (fp_vtype << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
	std::vector<u32> words{setup, fp(2, 9, 8, 10), fp(0, 11, 9, 12),
	    fp(2, 9, 11, 10), fp(0, 8, 9, 12), fp(2, 11, 8, 10)};
	if (chain) words = {setup, fp(2, 9, 9, 10), fp(2, 9, 9, 10),
	    fp(2, 9, 9, 10), fp(2, 9, 9, 10), fp(2, 9, 9, 10)};
	if (fused) for (size_t n = 1; n < words.size(); ++n) words[n] = fp(0x2c, 9, 8, 10);
	if (copies) {
		std::vector<u32> interleaved{setup};
		for (size_t n = 1; n < words.size(); ++n) {
			interleaved.push_back(words[n]);
			u32 const rd = (words[n] >> 7) & 31u;
			interleaved.push_back(OpV(0x17, 0, rd, 16)); // vmv.v.v v16,vd
			interleaved.push_back(OpV(0x17, 0, 16, rd)); // rename back; v16 remains live-out
		}
		words = std::move(interleaved);
	}
	Built control, candidate;
	g_batch = false;
	Build(control, words, vlen, true);
	g_batch = true;
	Build(candidate, words, vlen, true);
	auto d = dbt::qir::rv32::RV32Translator::RvvAdmitVectorRun(reinterpret_cast<uptr>(words.data()),
	    4, words.size() * 4, 64, fp_vtype);
	CHECK_MSG(candidate.multi_member_frames == 1,
	    "FP VLEN=%u both=%d frames=%u admitted=%u cut=%s batch=%u", vlen, both,
	    candidate.multi_member_frames, d.n_members, rvvrun::CutReasonName(d.cut), d.batch_chunks);
	if (vlen == 4096)
		CHECK_MSG(d.batch_chunks == 4, "eight chunks should form two balanced batches");
	u32 const maxvl = vlen / (8 * sizeof(F));
	for (bool special : {false, true})
	for (u32 vl : {0u, 1u, 15u, 16u, 17u, maxvl / 2, maxvl - 1, maxvl}) {
		if (vl > maxvl) continue;
		rv32::VectorState seed{}, old{}, out{};
		for (u32 r = 0; r < 32; ++r)
			for (u32 i = 0; i < rv32::VLEN_MAX_BYTES / sizeof(F); ++i) {
				F x = F(r * 4 + i);
				if (special && i % 3 == 0) x = std::numeric_limits<F>::infinity();
				if (special && i % 3 == 1) x = std::numeric_limits<F>::signaling_NaN();
				memcpy(seed.vreg[r].data() + sizeof(F) * i, &x, sizeof(F));
			}
		u64 fallback_old, fallback_new;
		u32 flags_old, flags_new;
		Run(control, vlen, vl, 0, seed, &old, &fallback_old, 0, 0, 0, &flags_old);
		Run(candidate, vlen, vl, 0, seed, &out, &fallback_new, 0, 0, 0, &flags_new);
		CHECK_MSG(flags_old == flags_new, "FP exception flags differ");
		CHECK_MSG(special ? (!vl || (fused && vl == 1) || (flags_new & 16)) : flags_new == 0,
		    "expected invalid exception only for active special-value lanes");
		for (u32 r = 0; r < 32; ++r)
			CHECK_MSG(!memcmp(old.vreg[r].data(), out.vreg[r].data(),
			    (r == 9 || (copies && r == 16) || (!chain && (r == 8 || r == 11)))
			        ? sizeof(F) * vl : rv32::VLEN_MAX_BYTES),
			    "FP VLEN=%u vl=%u both=%d v%u differs", vlen, vl, both, r);
		for (u32 r : {8u, 9u, 11u, 16u}) {
			if ((r == 16 && !copies) || (chain && r != 9 && r != 16)) continue;
			for (u32 i = vl; i < rv32::VLEN_MAX_BYTES / sizeof(F); ++i) {
				u64 bits = 0;
				memcpy(&bits, out.vreg[r].data() + sizeof(F) * i, sizeof(F));
				bool const unchanged = !memcmp(out.vreg[r].data() + sizeof(F) * i,
				    seed.vreg[r].data() + sizeof(F) * i, sizeof(F));
				u64 const ones = sizeof(F) == 4 ? 0xffffffffu : ~u64{0};
				CHECK_MSG(unchanged || (vl && i < maxvl && bits == ones),
				    "illegal tail/padding change VLEN=%u vl=%u reg=%u lane=%u", vlen, vl, r, i);
			}
		}
		CHECK_MSG(out.vl == vl && out.vstart == 0 && out.vtype == old.vtype,
		    "FP batch metadata mismatch");
		if (vl) CHECK_MSG(fallback_new == 0, "FP batch unexpectedly used fallback");
		for (u32 i = 0; !special && i < vl; ++i) {
			F a = F(8 * 4 + i), b = F(10 * 4 + i), c = F(12 * 4 + i);
			F v9 = (a - b + c) - b;
			F v8 = v9 + c, v11 = v8 - b;
			if (chain) { v9 = F(9 * 4 + i); for (int n = 0; n < 5; ++n) v9 -= b; }
			if (fused) v9 = F(9 * 4 + i) + F(5) * a * b;
			auto equal = [&](u32 reg, F value) {
			    return !memcmp(out.vreg[reg].data() + sizeof(F) * i, &value, sizeof(F));
			};
			CHECK_MSG(equal(9, v9) && (chain || (equal(8, v8) && equal(11, v11))),
			    "FP scalar oracle mismatch VLEN=%u vl=%u lane=%u", vlen, vl, i);
			if (copies) CHECK_MSG(equal(16, chain ? v9 : v11),
			    "renamed value must remain visible after the run");
		}
	}
	if (vlen == 4096 && chain && !fused) {
		words.erase(words.begin());
		Built restarted;
		Build(restarted, words, vlen, true, {fp_vtype, true});
		CHECK_MSG(restarted.multi_member_frames == 1, "restart test must have one FP run");
		rv32::VectorState seed{}, out{};
		for (u32 i = 0; i < maxvl; ++i) {
			F a = F(100 + i), b = F(1);
			memcpy(seed.vreg[9].data() + i * sizeof(F), &a, sizeof(F));
			memcpy(seed.vreg[10].data() + i * sizeof(F), &b, sizeof(F));
		}
		u64 fallbacks;
		Run(restarted, vlen, maxvl, 0, seed, &out, &fallbacks, fp_vtype, maxvl, 13);
		CHECK_MSG(fallbacks == 1 && out.vstart == 0, "restart must use ordered fallback");
		for (u32 i = 0; i < maxvl; ++i) {
			F expected = F(100 + i - (i < 13 ? 4 : 5));
			CHECK_MSG(!memcmp(out.vreg[9].data() + i * sizeof(F), &expected, sizeof(F)),
			    "restart per-member vstart reset mismatch lane=%u", i);
		}
	}
	printf("bounded FP%zu VLEN=%u both=%d chain=%d fused=%d copies=%d frames=%u batch=%u %s\n", sizeof(F) * 8, vlen, both, chain, fused, copies,
	    candidate.multi_member_frames, d.batch_chunks, failures_before == g_failures ? "PASS" : "FAIL");
	g_fp_batch_test = g_batch = g_both = false;
	config::rvv_run_bounded_batches = false;
}

void CheckLmulBatch(bool both)
{
	g_fp_batch_test = true;
	g_both = both;
	constexpr u32 width = 2048, vt = 0xd1; // e32,m2,ta,ma: eight physical chunks
	u32 const setup = (vt << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
	u32 const sub = OpV(2, 8, 10, 8) | (1u << 12);
	std::vector<u32> words{setup, sub, sub, sub, sub, sub};
	Built control, candidate;
	g_batch = false; Build(control, words, width, true);
	g_batch = true; Build(candidate, words, width, true);
	auto d = dbt::qir::rv32::RV32Translator::RvvAdmitVectorRun(
	    reinterpret_cast<uptr>(words.data()), 4, words.size() * 4, 64, vt);
	CHECK_MSG(candidate.multi_member_frames == 1 && d.batch_chunks == 4 && d.nchunks == 8,
	    "LMUL2 must execute the eight-chunk batch path");
	for (u32 vl : {0u, 1u, 63u, 64u, 65u, 127u, 128u}) {
		rv32::VectorState seed{}, old{}, out{};
		for (u32 r = 0; r < 32; ++r)
			for (u32 i = 0; i < width / 32; ++i) {
				float x = float(r * 4 + i);
				memcpy(seed.vreg[r].data() + i * 4, &x, 4);
			}
		u64 a, b;
		Run(control, width, vl, 0, seed, &old, &a);
		Run(candidate, width, vl, 0, seed, &out, &b);
		CHECK_MSG(!vl || b == 0, "LMUL2 unexpectedly fell back");
		for (u32 i = 0; i < vl; ++i) {
			u32 const group = i / 64, lane = i % 64;
			float expected = float((8 + group) * 4 + lane) -
			    5 * float((10 + group) * 4 + lane);
			CHECK_MSG(!memcmp(out.vreg[8 + group].data() + lane * 4, &expected, 4) &&
			    Get(out, 8 + group, lane) == Get(old, 8 + group, lane),
			    "LMUL2 group addressing mismatch at element %u", i);
		}
		for (u32 r = 0; r < 32; ++r)
			if (r != 8 && r != 9)
				CHECK_MSG(!memcmp(out.vreg[r].data(), seed.vreg[r].data(), rv32::VLEN_MAX_BYTES),
				    "LMUL2 clobbered unrelated register %u", r);
	}
	g_fp_batch_test = g_batch = g_both = false;
	config::rvv_run_bounded_batches = false;
}
} // namespace

int main()
{
	config::rvv_qcg_active_vl_mask_fusion = std::getenv("RVV_MASK_BOUND_FUSION") != nullptr;
#if defined(__x86_64__)
	__builtin_cpu_init();
	if (!__builtin_cpu_supports("avx512f") || !__builtin_cpu_supports("bmi2")) {
		printf("SKIP rvv_vector_run_value_test: AVX-512F and BMI2 required\n");
		return 0;
	}
#else
	printf("SKIP rvv_vector_run_value_test: x86-64 required\n");
	return 0;
#endif
	for (u32 vlen : {512u, 1024u}) {
		CheckChain(vlen);
		CheckOverlap(vlen);
	}
	CheckGeometryFallback();
	CheckVstartFallback();
	CheckLmulBatch(false);
	CheckLmulBatch(true);
	for (u32 vlen : {512u, 1024u, 2048u, 4096u})
		for (bool both : {false, true})
			for (bool chain : {false, true}) {
				CheckBoundedFp<float>(vlen, both, chain);
				CheckBoundedFp<double>(vlen, both, chain);
				CheckBoundedFp<float>(vlen, both, chain, false, true);
				if (chain) {
					CheckBoundedFp<float>(vlen, both, true, true);
					CheckBoundedFp<double>(vlen, both, true, true);
				}
			}
	printf("RVV_VECTOR_RUN_VALUE_TEST checks=%d failures=%d\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
