#define main ExistingRunValueMain
#include "dbt/qmc/qcg/rvv_vector_run_value_test.cpp"
#undef main
#include "dbt/guest/rv32_frame_semantics.h"

static u32 Logic(u32 op, u32 dst)
{
    return ((24 + op) << 26) | (1u << 25) | (8u << 20) | (12u << 15) |
           (2u << 12) | (dst << 7) | 0x57u;
}

static void BuildLogic(Built &b, u32 width, u32 vt, u32 op, u32 dst, bool bounded)
{
    ApplyConfig(width, false);
    config::rvv_qcg_active_vl_int_bound = bounded;
    config::rvv_qcg_active_vl_mask_fusion = true;
    b.words = {(vt << 20) | (10u << 15) | (7u << 12) | (5u << 7) | 0x57u,
               (8u << 20) | (11u << 15) | (1u << 12) | 0x73u,
               Logic(op, dst), Logic(3, 2)};
    CompilerJob::IpRangesSet ranges = {{0u, u32(b.words.size() * 4)}};
    CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u),
                    std::move(ranges));
    b.region = CompilerGenRegionIR(&b.arena, job);
    u32 bounds = 0, bodies = 0, epilogues = 0;
    u32 const words = (dbt::rv32::compute_vlmax(dbt::rv32::VType{vt}, width) + 63) / 64;
    for (auto &bb : b.region->GetBlocks())
        for (auto &ins : bb.ilist) {
            if (ins.GetOpcode() == Op::_vchunkactive) {
                auto &bound = static_cast<InstVChunkActive &>(ins);
                ++bounds;
                CHECK_MSG(bound.element_base == u32(bound.chunk) * 64, "mask bound is not in bits");
            }
            if (ins.GetOpcode() == Op::_vmasklogic) ++bodies;
            if (ins.GetOpcode() == Op::_rvvtypedchunkend)
                epilogues += static_cast<InstRVVTypedChunkEnd &>(ins).frame_clears_vstart;
        }
    CHECK_MSG(bodies == 2 * words, "mask test did not reach native lowering");
    CHECK_MSG(bounds == (bounded ? 2 * (words - 1) : 0), "wrong bound count");
    CHECK_MSG(epilogues == (bounded && words > 1 ? 2u : 0u), "lost completion ownership");
    CodeSegment segment(0u, 0x1000u);
    auto code = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
    b.code = b.runtime.last;
    size_t n = code.size();
    if (b.code[0] == 0x51) b.code[n++] = 0x59;
    b.code[n] = 0xc3;
}

static void Oracle(dbt::rv32::VectorState &state, u32 op, u32 dst, u32 start, u32 vl)
{
    for (u32 e = start; e < vl; ++e) {
        bool const x = (state.vreg[8][e / 8] >> (e % 8)) & 1;
        bool const y = (state.vreg[12][e / 8] >> (e % 8)) & 1;
        bool value = false;
        switch (op) {
        case 0: value = x && !y; break;
        case 1: value = x && y; break;
        case 2: value = x || y; break;
        case 3: value = x != y; break;
        case 4: value = x || !y; break;
        case 5: value = !(x && y); break;
        case 6: value = !(x || y); break;
        case 7: value = x == y; break;
        }
        u32 const bit = 1u << (e % 8);
        state.vreg[dst][e / 8] = (state.vreg[dst][e / 8] & ~bit) | (value ? bit : 0);
    }
}

int main()
{
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("avx512bw") || !__builtin_cpu_supports("bmi2")) return 2;
    CHECK_MSG(dbt::rv32::rvvplan::ElementsPerUnit(8, 0, 1) == 64, "bit geometry");
    CHECK_MSG(dbt::rv32::rvvplan::ElementsPerUnit(64, 4) == 16, "byte geometry regressed");
    CHECK_MSG(dbt::rv32::rvvplan::ElementsPerUnit(8, 0) == 0, "unknown geometry must reject");
    for (u32 width : {128u, 256u, 512u, 1024u, 2048u, 4096u})
     for (u32 sew : {0u, 1u, 2u, 3u})
      for (int lm : {-1, 0, 1, 3}) {
        u32 const vt = (sew << 3) | u32(lm & 7);
        if (!dbt::rv32::vtype_supported(dbt::rv32::VType{vt}, width)) continue;
        u32 const vmax = dbt::rv32::compute_vlmax(dbt::rv32::VType{vt}, width);
        for (u32 op = 0; op < 8; ++op)
         for (u32 dst : {0u, 8u, 12u}) {
            Built old, candidate;
            BuildLogic(old, width, vt, op, dst, false);
            BuildLogic(candidate, width, vt, op, dst, true);
            std::vector<u32> lengths{0, 1, 16, 63, 64, 65, vmax};
            for (u32 vl : lengths) {
                if (vl > vmax) continue;
                for (u32 start : {0u, 5u, 64u, vl}) {
                    dbt::rv32::VectorState seed{}, expected{}, control{}, actual{};
                    Fill(seed);
                    seed.vxsat = 1;
                    seed.vxrm = 3;
                    expected = seed;
                    // The guest writes vstart through its WARL CSR, not directly to CPUState.
                    Oracle(expected, op, dst, start & (width - 1), vl);
                    Oracle(expected, 3, 2, 0, vl);
                    u64 fallback_old, fallback_new;
                    Run(old, width, vl, start, seed, &control, &fallback_old);
                    Run(candidate, width, vl, start, seed, &actual, &fallback_new);
                    CHECK_MSG(!fallback_old && !fallback_new, "unexpected helper fallback");
                    CHECK_MSG(actual.vl == vl && actual.vstart == 0 && actual.vtype == vt,
                              "bad vector completion");
                    CHECK_MSG(actual.vxsat == seed.vxsat && actual.vxrm == seed.vxrm, "changed flags");
                    CHECK_MSG(memcmp(actual.vreg.data(), expected.vreg.data(), sizeof(actual.vreg)) == 0,
                              "oracle width=%u sew=%u lm=%d op=%u dst=%u vl=%u start=%u",
                              width, sew, lm, op, dst, vl, start);
                    CHECK_MSG(memcmp(actual.vreg.data(), control.vreg.data(), sizeof(actual.vreg)) == 0,
                              "bounded/unbounded mismatch");
                }
            }
        }
    }
    config::rvv_qcg_active_chunk_census = true;
    for (bool bounded : {false, true}) {
        Built b;
        BuildLogic(b, 4096, (1u << 3) | 1u, 1, 0, bounded);
        dbt::rv32::VectorState seed{}, result{};
        Fill(seed);
        dbt::rv32::g_rvv_chunks_available = 0;
        dbt::rv32::g_rvv_chunks_executed = 0;
        u64 fallbacks;
        Run(b, 4096, 16, 0, seed, &result, &fallbacks);
        CHECK_MSG(dbt::rv32::g_rvv_chunks_available == 16, "incorrect mask-word census capacity");
        CHECK_MSG(dbt::rv32::g_rvv_chunks_executed == (bounded ? 2u : 16u),
                  "empty mask words actually executed");
        printf("MASK_WORD_CENSUS bounded=%d available=%llu executed=%llu\n", bounded,
               dbt::rv32::g_rvv_chunks_available, dbt::rv32::g_rvv_chunks_executed);
    }
    config::rvv_qcg_active_chunk_census = false;
    printf("MASK_LOGIC_BOUND checks=%d failures=%d\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
