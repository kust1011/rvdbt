// Reuse the existing execution trampoline and configuration, not its oracle.
// This test compares complete vector/FPU state and census before/after fusion.
#define main ExistingBoundaryTestMain
#include "rvv_both_boundary_value_test.cpp"
#undef main

namespace {
struct FusionShape { char const *name; u32 f6, src1, f3, vsew; };
u32 Raw(FusionShape const &s, bool masked)
{
	u32 const vs2 = s.f6 == 20 && s.f3 == 2 ? 0 : 12;
	return (s.f6 << 26) | ((!masked) << 25) | (vs2 << 20) |
	       (s.src1 << 15) | (s.f3 << 12) | (8u << 7) | 0x57u;
}
size_t BuildRaw(Built &b, FusionShape const &s, bool masked, bool fusion, bool helper,
	      u32 width, bool census)
{
	ApplyArm(ArmBoth, width, census);
	config::rvv_qcg_active_vl_mask_fusion = fusion;
	config::rvv_direct = !helper;
	b.words = {Vsetvli(10, 10, s.vsew << 3), Raw(s, masked)};
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	for (auto &bb : b.region->GetBlocks())
		for (auto &i : bb.ilist)
			b.bound_nodes_total += i.GetOpcode() == Op::_vchunkactive;
	qir::CodeSegment segment(0u, 0x1000u);
	auto span = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
	b.code = b.runtime.last;
	size_t n = span.size();
	if (b.code[0] == 0x51) b.code[n++] = 0x59;
	b.code[n] = 0xc3;
	return span.size();
}
struct FusionOutcome {
	rv32::VectorState vec;
	rv32::FPUState fpu;
	u32 gpr[32];
	u64 available, executed, fallbacks;
};
void RunRaw(Built &b, u32 width, u32 avl, unsigned mask, FusionOutcome &out)
{
	CPUState st(nullptr);
	memset(static_cast<void *>(&st), 0, sizeof st);
	st.vec.vlenb = width / 8;
	st.vec.vtype = 2u << 3;
	st.vec.vstart = 3;
	st.vec.vxrm = 1;
	for (size_t i = 0; i < sizeof(st.vec.vreg); ++i)
		reinterpret_cast<u8 *>(st.vec.vreg.data())[i] = u8(i * 37u + mask * 13u + 19u);
	for (unsigned i = 0; i < sizeof(st.vec.vreg[0]); ++i)
		st.vec.vreg[0][i] = mask == 0 ? 0 : mask == 1 ? 0xff : 0x55;
	st.gpr[10] = avl;
	u64 a = rv32::g_rvv_chunks_available, e = rv32::g_rvv_chunks_executed;
	BothEnter(&st, nullptr, b.code);
	out.vec = st.vec; out.fpu = st.fpu;
	memcpy(out.gpr, st.gpr.data(), sizeof out.gpr);
	out.available = rv32::g_rvv_chunks_available - a;
	out.executed = rv32::g_rvv_chunks_executed - e;
	out.fallbacks = st.rvv_direct_fallbacks;
}
}

int main()
{
	__builtin_cpu_init();
	g_execute = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
	            __builtin_cpu_supports("avx512vl") && __builtin_cpu_supports("avx512dq") &&
	            __builtin_cpu_supports("bmi2");
	if (!g_execute) { fprintf(stderr, "AVX-512 execution required\n"); return 77; }
	FusionShape shapes[] = {
		{"integer add", 0, 14, 0, 2}, {"unsigned widen add", 48, 14, 2, 2},
		{"zero extend", 18, 6, 2, 2}, {"signed extend", 18, 7, 2, 3},
		{"narrow shift", 44, 14, 0, 2},
		{"float to signed integer", 18, 1, 1, 2},
		{"signed integer to float", 18, 3, 1, 2},
		{"float widening", 18, 12, 1, 2},
		{"float narrowing", 18, 20, 1, 2},
		{"float classification (excluded)", 19, 16, 1, 2},
		{"element index (excluded)", 20, 17, 2, 2},
	};
	unsigned executions = 0, changed = 0, bounded = 0;
	for (auto const &s : shapes)
	for (u32 width : {128u, 256u, 512u, 1024u, 2048u, 4096u})
	for (bool masked : {false, true})
	for (bool census : {false, true}) {
		Built off, on;
		auto off_bytes = BuildRaw(off, s, masked, false, false, width, census);
		auto on_bytes = BuildRaw(on, s, masked, true, false, width, census);
		CHECK_MSG(off.bound_nodes_total == on.bound_nodes_total, "bound count %s", s.name);
		bounded += off.bound_nodes_total != 0;
		changed += off_bytes != on_bytes;
		if (s.f6 == 19 || s.f6 == 20)
			CHECK_MSG(off_bytes == on_bytes, "excluded route changed %s", s.name);
		u32 vmax = (width / 8) / (1u << s.vsew);
		std::set<u32> lengths{0, 1, vmax - 1, vmax, vmax + 1};
		u32 step = 64u / (1u << s.vsew);
		for (u32 n = step; n < vmax; n += step) {
			lengths.insert(n - 1); lengths.insert(n); lengths.insert(n + 1);
		}
		for (u32 avl : lengths)
		for (unsigned mask = 0; mask < 3; ++mask) {
			FusionOutcome a{}, b{};
			RunRaw(off, width, avl, mask, a); RunRaw(on, width, avl, mask, b);
			CHECK_MSG(memcmp(&a.vec, &b.vec, sizeof a.vec) == 0, "vector %s width=%u avl=%u mask=%u", s.name, width, avl, mask);
			CHECK_MSG(memcmp(&a.fpu, &b.fpu, sizeof a.fpu) == 0, "FPU %s", s.name);
			CHECK_MSG(memcmp(a.gpr, b.gpr, sizeof a.gpr) == 0, "GPR %s", s.name);
			CHECK_MSG(a.available == b.available && a.executed == b.executed && a.fallbacks == b.fallbacks, "census/fallback %s", s.name);
			executions += 2;
		}
		printf("FUSION_SHAPE name=%s width=%u masked=%u census=%u bounds=%u cases=%zu\n", s.name, width, masked, census, off.bound_nodes_total, lengths.size() * 3);
	}
	CHECK_MSG(changed > 0, "test did not exercise any changed code shape");
	printf("MASK_BOUND_FUSION checks=%d failures=%d executions=%u bounded_shapes=%u code_size_changes=%u\n", g_checks, g_failures, executions, bounded, changed);
	return g_failures ? 1 : 0;
}
