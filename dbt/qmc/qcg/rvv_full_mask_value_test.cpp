#define main ExistingRunValueMain
#include "dbt/qmc/qcg/rvv_vector_run_value_test.cpp"
#undef main

static void BuildMask(Built &b, u32 width, u32 sew, int lm, bool full,
                      bool bounded, bool masked, u32 start)
{
    ApplyConfig(width, false);
    config::rvv_qcg_active_vl_int_bound = bounded;
    u32 const vt = (sew << 3) | (lm & 7);
    u32 const op = (0x1au << 26) | (masked ? 0u : 1u << 25) | (16u << 20) | (24u << 15) | 0x57u;
    b.words = {(vt << 20) | (full ? 0u : 10u << 15) | (7u << 12) | (5u << 7) | 0x57u};
    if (start) b.words.push_back((8u << 20) | (start << 15) | (5u << 12) | 0x73u);
    b.words.push_back(op);
    CompilerJob::IpRangesSet ranges = {{0u, u32(b.words.size() * 4)}};
    CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u), std::move(ranges));
    b.region = CompilerGenRegionIR(&b.arena, job);
    unsigned full_guards = 0;
    for (auto &bb : b.region->GetBlocks())
        for (auto &ins : bb.ilist)
            if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
                auto &f = static_cast<InstRVVTypedChunkBegin &>(ins);
                full_guards += f.guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart;
            }
    CHECK_MSG(full_guards == unsigned(full && bounded), "wrong full-mask admission");
    CodeSegment segment(0u, 0x1000u);
    auto code = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
    b.code = b.runtime.last;
    size_t n = code.size();
    if (b.code[0] == 0x51) b.code[n++] = 0x59;
    b.code[n] = 0xc3;
}

int main()
{
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("avx512bw") || !__builtin_cpu_supports("avx512vl") ||
        !__builtin_cpu_supports("bmi2")) return 2;
    for (u32 width : {128u, 256u, 512u, 1024u, 2048u, 4096u})
      for (u32 sew : {0u, 1u, 2u, 3u})
       for (int lm : {-3, -2, -1, 0, 1, 2, 3})
        for (bool full : {false, true})
         for (bool masked : {false, true})
          for (u32 start : {0u, 5u}) {
            dbt::rv32::VType vt{(sew << 3) | u32(lm & 7)};
            if (!dbt::rv32::vtype_supported(vt, width)) continue;
            Built b, m;
            BuildMask(b, width, sew, lm, full, false, masked, start);
            BuildMask(m, width, sew, lm, full, true, masked, start);
            dbt::rv32::VectorState seed{}, old{}, actual{};
            Fill(seed);
            u32 const bytes = 1u << sew, rb = width / 8;
            u32 const vmax = dbt::rv32::compute_vlmax(vt, width);
            for (u32 avl : {0u, 1u, vmax / 2, vmax}) {
                u64 a, c;
                Run(b, width, avl, 0, seed, &old, &a);
                Run(m, width, avl, 0, seed, &actual, &c);
                CHECK_MSG(actual.vl == (full ? vmax : avl) && actual.vstart == 0, "bad completion");
                CHECK_MSG(memcmp(old.vreg.data(), actual.vreg.data(), sizeof(old.vreg)) == 0, "control mismatch");
                auto expected = seed;
                auto read = [&](u32 reg, u32 e) {
                    u32 const byte = e * bytes;
                    u64 v = 0;
                    memcpy(&v, seed.vreg[reg + byte / rb].data() + byte % rb, bytes);
                    return v;
                };
                for (u32 e = start; e < actual.vl; ++e) {
                    u32 const bit = 1u << (e % 8);
                    if (masked && !(seed.vreg[0][e / 8] & bit)) continue;
                    expected.vreg[0][e / 8] = (expected.vreg[0][e / 8] & ~bit) |
                        (read(16, e) < read(24, e) ? bit : 0);
                }
                CHECK_MSG(memcmp(expected.vreg.data(), actual.vreg.data(), sizeof(expected.vreg)) == 0,
                          "oracle mismatch width=%u sew=%u lm=%d full=%d masked=%d start=%u avl=%u",
                          width, sew, lm, full, masked, start, avl);
                CHECK_MSG(!a && c == unsigned(full && start != 0), "unexpected fallback count");
            }
          }
    printf("FULL_MASK checks=%d failures=%d\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
