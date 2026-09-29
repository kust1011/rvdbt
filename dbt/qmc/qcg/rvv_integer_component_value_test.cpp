#define main ExistingRunValueMain
#include "dbt/qmc/qcg/rvv_vector_run_value_test.cpp"
#undef main

static unsigned BuildInteger(Built &b, u32 width, bool bounded, bool chain, u32 start, bool accumulate)
{
    campaign_config::ApplyCampaignArm_BOTH();
    campaign_config::ForceEmitAll();
    config::aot_use_llvm = false;
    config::vlen_bits = width;
    config::rvv_run_grouped_component_major = false;
    config::rvv_qcg_active_vl_run_bound = false;
    config::rvv_qcg_active_vl_int_bound = bounded;
    config::rvv_run_bounded_batches = true;
    config::rvv_qcg_active_vl_mask_fusion = true;
    config::rvv_qcg_active_chunk_census = true;
    auto mulx = [](u32 vd, u32 vs) { return OpV(0x25, vs, 11, vd) | (6u << 12); };
    b.words = {Vsetvli()};
    if (start)
        b.words.push_back((8u << 20) | (start << 15) | (5u << 12) | 0x73u);
    b.words.push_back(mulx(8, 8));
    b.words.push_back(mulx(9, chain ? 8 : 9) | (accumulate ? 8u << 26 : 0u));
    CompilerJob::IpRangesSet ranges = {{0u, u32(b.words.size() * 4)}};
    CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u),
                    std::move(ranges));
    b.region = CompilerGenRegionIR(&b.arena, job);
    unsigned bounds = 0;
    for (auto &bb : b.region->GetBlocks())
        for (auto &ins : bb.ilist) {
            bounds += ins.GetOpcode() == Op::_vchunkactive;
            if (ins.GetOpcode() == Op::_rvvtypedchunkend &&
                static_cast<InstRVVTypedChunkEnd &>(ins).n_members > 1)
                ++b.multi_member_frames;
        }
    CodeSegment segment(0u, 0x1000u);
    auto span = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
    CHECK_MSG(!span.empty(), "empty integer component code");
    b.code = b.runtime.last;
    size_t n = span.size();
    if (b.code[0] == 0x51) b.code[n++] = 0x59;
    b.code[n] = 0xc3;
    return bounds;
}

int main()
{
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("avx512f") || !__builtin_cpu_supports("avx512dq") ||
        !__builtin_cpu_supports("avx512bw") || !__builtin_cpu_supports("avx512vl") ||
        !__builtin_cpu_supports("bmi2")) return 2;
    for (u32 width : {128u, 256u, 512u, 1024u, 2048u, 4096u})
        for (bool chain : {false, true})
          for (bool accumulate : {false, true})
            for (u32 start : {0u, 5u}) {
                Built control, candidate;
                BuildInteger(control, width, false, chain, start, accumulate);
                auto bounds = BuildInteger(candidate, width, true, chain, start, accumulate);
                // Admission still uses the existing member-major budget. A wide
                // multiply-accumulate pair may be refused before this schedule.
                bool const fits = dbt::rv32::rvvrun::RvvRunPeakLiveBound(
                    2, std::max(1u, width/512), 0, accumulate) <= dbt::rv32::rvvrun::kHostVectorRegs;
                CHECK_MSG((candidate.multi_member_frames != 0) == fits &&
                          candidate.multi_member_frames == control.multi_member_frames,
                          "integer run admission changed width=%u accumulate=%d", width, accumulate);
                CHECK_MSG((bounds != 0) == (fits && width > 512), "wrong bound population width=%u bounds=%u", width, bounds);
                for (u32 vl : {0u, 1u, 8u, 15u, 16u, 17u, 31u, 32u, 63u, 64u, 65u, width/32}) {
                    if (vl > width/32) continue;
                    dbt::rv32::VectorState seed{}, old{}, actual{};
                    Fill(seed);
                    u64 a, b;
                    Run(control, width, vl, 3, seed, &old, &a);
                    auto const before_available = dbt::rv32::g_rvv_chunks_available;
                    auto const before_executed = dbt::rv32::g_rvv_chunks_executed;
                    Run(candidate, width, vl, 3, seed, &actual, &b);
                    if (fits && width > 512 && !start) {
                        CHECK_MSG(dbt::rv32::g_rvv_chunks_available - before_available == width/512 &&
                                  dbt::rv32::g_rvv_chunks_executed - before_executed == (vl+15)/16,
                                  "active-work census mismatch width=%u vl=%u", width, vl);
                    }
                    CHECK_MSG(a == b && (start || b == 0), "fallback mismatch width=%u vl=%u", width, vl);
                    CHECK_MSG(actual.vstart == 0 && actual.vl == vl, "completion mismatch");
                    for (u32 r = 0; r < 32; ++r)
                        for (u32 i = 0; i < dbt::rv32::VLEN_MAX_BYTES/4; ++i) {
                            u32 expected = Get(seed, r, i);
                            u32 intermediate = i >= start && i < vl ? Get(seed, 8, i)*3u : Get(seed, 8, i);
                            if (r == 8) expected = intermediate;
                            if (r == 9 && i < vl) expected = (chain ? intermediate : Get(seed, 9, i))*3u +
                                (accumulate ? Get(seed, 9, i) : 0u);
                            CHECK_MSG(Get(actual,r,i) == expected && Get(old,r,i) == expected,
                                      "integer state width=%u vl=%u start=%u chain=%d v%u lane=%u", width, vl, start, chain, r, i);
                        }
                }
            }
    printf("INTEGER_COMPONENT checks=%d failures=%d\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
