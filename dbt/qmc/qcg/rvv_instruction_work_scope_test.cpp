#define main ExistingBoundaryMain
#include "dbt/qmc/qcg/rvv_both_boundary_value_test.cpp"
#undef main
#include "dbt/guest/rv32_frame_semantics.h"

// The inherited structure test specifies two resident groups only up to 2048.
// Check 4096 against architectural state without assuming the same grouping.
void CheckState(Scenario const &scenario, u32 width)
{
    Built built[ArmCount];
    for (int arm = 0; arm < ArmCount; ++arm) {
        ApplyArm(arm, width, false);
        Build(built[arm], scenario);
        printf("STATE_STRUCT %s width=%u batches=%d %s %s\n", scenario.name, width,
               config::rvv_run_bounded_batches, ArmName(arm), Signature(built[arm]).c_str());
    }
    auto const cases = Cases(scenario, width, &built[ArmB]);
    for (auto const &c : cases) {
        RefState expected = c.init;
        RefRun(scenario, width, expected, Bug::None);
        for (int arm = 0; arm < ArmCount; ++arm) {
            Outcome actual;
            Execute(built[arm], c.init, actual);
            std::string why;
            CHECK_MSG(SameState(actual.vec, actual.gpr, expected.vec, expected.gpr, &why),
                      "%u %s %s %s: %s", width, scenario.name, ArmName(arm), c.label.c_str(), why.c_str());
        }
    }
    printf("STATE_CASES %s width=%u batches=%d executions=%zu\n", scenario.name, width,
           config::rvv_run_bounded_batches, cases.size() * ArmCount);
}

int main()
{
    __builtin_cpu_init();
    g_execute = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
                __builtin_cpu_supports("avx512vl") && __builtin_cpu_supports("avx512dq") &&
                __builtin_cpu_supports("bmi2");
    if (!g_execute) {
        fprintf(stderr, "This execution test requires AVX-512F/BW/VL/DQ and BMI2.\n");
        return 2;
    }
    config::rvv_qcg_active_vl_mask_fusion = true;
    std::map<std::string, Totals> totals;
    for (auto const &scenario : {MakeS1(), MakeS2(), MakeS3(), MakeS4()}) {
        for (u32 width : {128u, 256u, 512u, 1024u, 2048u})
            RunScenario(scenario, width, totals);
        CheckState(scenario, 4096);
    }

    config::rvv_run_bounded_batches = true;
    for (auto const &scenario : {MakeS1(), MakeS2(), MakeS3(), MakeS4()})
        for (u32 width : {128u, 256u, 512u, 1024u, 2048u, 4096u})
            CheckState(scenario, width);

    config::rvv_run_bounded_batches = false;
    ApplyArm(ArmBoth, 4096, false);
    Built built;
    Build(built, MakeS1());
    unsigned scopes = 0;
    for (auto &block : built.region->GetBlocks()) {
        for (auto it = block.ilist.begin(); it != block.ilist.end(); ++it) {
            auto const scope = rv32::rvvfinal::PlanInstructionWorkScope(it, block.ilist.end());
            if (scope.units < 2)
                continue;
            ++scopes;
            auto *first = static_cast<InstVChunkPartialAlu *>(&*it);
            auto const old_base = scope.last->element_base;
            scope.last->element_base++;
            CHECK_MSG(rv32::rvvfinal::PlanInstructionWorkScope(it, block.ilist.end()).units == 0,
                      "noncontiguous element geometry must reject the scope");
            scope.last->element_base = old_base;
            first->architectural_mask = false;
            CHECK_MSG(rv32::rvvfinal::PlanInstructionWorkScope(it, block.ilist.end()).units == 0,
                      "a legacy shared mask must reject the scope");
            first->architectural_mask = true;
        }
    }
    CHECK_MSG(scopes > 0, "instruction-local scope test must not be vacuous");
    for (auto const &[key, total] : totals)
        printf("TOTAL %s executions=%u\n", key.c_str(), total.executions);
    printf("INSTRUCTION_WORK_SCOPE scopes=%u checks=%d failures=%d\n", scopes, g_checks, g_failures);
    return g_failures ? 1 : 0;
}
