#define main ExistingRunValueMain
#include "dbt/qmc/qcg/rvv_vector_run_value_test.cpp"
#undef main

static u32 WholeMove(u32 nregs, u32 src, u32 dst)
{
    return (0b100111u << 26) | (1u << 25) | (src << 20) |
           ((nregs - 1u) << 15) | (0b011u << 12) | (dst << 7) | 0x57u;
}

int main()
{
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("avx512f") || !__builtin_cpu_supports("avx512vl"))
        return 2;

    for (u32 width : {128u, 256u, 512u, 1024u, 2048u, 4096u})
        for (u32 nregs : {1u, 2u, 4u, 8u})
            for (u32 dst : {0u, 8u}) {
                Built b;
                ApplyConfig(width, false);
                config::rvv_qcg_whole_reg = true;
                Build(b, {WholeMove(nregs, 8u, dst)}, width, false);
                unsigned moves = 0;
                for (auto &bb : b.region->GetBlocks())
                    for (auto &ins : bb.ilist)
                        moves += ins.GetOpcode() == Op::_vwholemove;
                CHECK_MSG(moves == 1, "whole move did not take the QCG route");

                u32 const regbytes = width / 8u;
                for (u32 sew : {1u, 4u, 8u})
                    for (u32 start : {0u, 1u, regbytes / sew - 1u,
                                      regbytes / sew, nregs * regbytes / sew}) {
                        dbt::rv32::VectorState seed{}, expected{}, actual{};
                        Fill(seed);
                        expected = seed;
                        u32 const byte_start = start * sew;
                        if (dst != 8u)
                            for (u32 i = byte_start; i < nregs * regbytes; ++i)
                                expected.vreg[dst + i / regbytes][i % regbytes] =
                                    seed.vreg[8u + i / regbytes][i % regbytes];
                        u64 fallbacks = ~0ull;
                        Run(b, width, 0, 0, seed, &actual, &fallbacks,
                            (sew == 1 ? 0u : sew == 4 ? 2u << 3 : 3u << 3), 0u, start);
                        CHECK_MSG(fallbacks == 0, "unexpected whole move helper");
                        CHECK_MSG(actual.vstart == 0, "vstart not cleared");
                        CHECK_MSG(memcmp(actual.vreg.data(), expected.vreg.data(),
                                         sizeof(actual.vreg)) == 0,
                                  "move mismatch width=%u nregs=%u dst=%u sew=%u start=%u",
                                  width, nregs, dst, sew, start);
                    }
            }
    printf("rvv_wholemove_fastpath_test: %s (%d failures)\n",
           g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
