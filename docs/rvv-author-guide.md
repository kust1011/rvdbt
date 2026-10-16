# RVV support and evidence guide

## Supported research scope

This continuation of upstream rvdbt adds RVV state/decoding, semantic helpers,
typed vector QIR and x86 emission to QCG. M1 retains eligible consecutive
instruction values; M2 omits eligible inactive high chunks using runtime `vl`.
See the [architecture and code map](rvv-qcg.md) for legality and fallback rules.
Inherited scalar translation, AOT and LLVM capabilities remain in the tree;
their presence is not acceptance of every optional combination for RVV.

The catalogue has **627 mnemonic/operand forms: 595 applicable to RV32/ELEN64,
32 ei64 indexed-memory forms excluded**. A helper is an implementation route,
not proof of either correctness or lack of support. VLEN128-4096 is a capability,
not an exhaustively tested Cartesian product.

## Build, run, check

Use the [public portable replay](rvv-validation/portable-external.md) for a
configurable build and checked execution without a research host. It covers one
complete adapted Ara source file and one retained RVVTS API-derived sequence.
It is not a 595-form regression suite or a performance recipe.

Source presence, compilation, static emission, executed instructions, checked
results and optimization admission are different evidence stages. A B/M1/M2/Both
label establishes configured options, not entry into an optimized body.
The portable ELF verifier and admission auditor check additional obligations.

Local tooling regressions can run without an RVV guest or AVX-512 execution:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_rvv_external.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_benchmark_checker.py
```

The benchmark-checker tests exercise expected return codes (zero by default,
explicit exception outcomes), requested stdout/file-content comparisons, failed
reference/setup/execution handling, score suppression and command exit status.
They test the checker and subprocess plumbing, not guest semantics, ISA coverage
or performance. The portable runner tests likewise check tooling contracts;
only the separate guest replay executes the two RVV fixtures.

## Find evidence for a form

| Question | Available entry | Limit |
| --- | --- | --- |
| Which forms and saved suite memberships? | [627-row scope](rvv-current-scope.md), [projection inputs/rebuild](rvv-validation/current-scope/README.md) | Offline rendering; static route labels and saved memberships, not fresh execution |
| Which original assertion, source and raw selector? | [Original-case navigation](rvv-validation/all-form-records/README.md) | Full joins need separately obtained packages/canonical data |
| Which directed dimensions and predicates? | [Case index and replay prerequisites](rvv-validation/delivery-task182/README.md) | Inspect each form's selected dimensions; some inputs/tools are archive-only |
| Which results on the frozen correctness executable? | [Fixed-build replay](rvv-validation/final-task197/README.md), [595-row results](rvv-validation/final-task197/PER_FORM_RESULTS.csv) | Compact receipts are committed; complete raw/runner archives have no public download |
| Which results on measured d252/79d0? | [Measured replay result and 595-form CSV](rvv-validation/delivery-task182/README.md#measured-d252-replay) | Actual receipt recount; diagnostic flags differ from formal timing; no full raw rehash |
| What can a third party execute now? | [Portable replay](rvv-validation/portable-external.md) | Two fixtures only, with new executable identity |

For example, from the repository root:

```sh
python3 scripts/rvv_verify.py show --form vadd.vv
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --form vsmul.vv --output /tmp/new-vsmul-records
```

The historical checked sets are CHIPS595, ACT590, RVV-ATG434, Ara422 and
SiFive RIF200; their union is 595, not their sum. RVVTS58 and RVISmith43 are
coupled endpoints, not independent checks of each static contributing opcode.
The original-case index preserves build-specific bindings and package selectors.
It does not upgrade old evidence to a rebuilt DUT. The historical fixed192 replay
records 12,069,048 ordinary comparisons, 2,256 focused positives, 592 denial
controls, 21,316 external calls and 9,888 sequence DUT checks. These are finite
observations against retained inputs/references, not full RVV conformance.

CHIPS/ACT [release packages](https://github.com/kust1011/rvdbt/releases/tag/rvv-validation-20261012)
and the [Ara inspection reader](rvv-validation/ara-review-task91/README.md)
provide selected historical source/assertion/raw access. Follow their licenses,
checksums and original predicates. The complete canonical evidence tree and
latest raw replay archives are not publicly obtainable through those packages.
Hashes and PASS tables cannot replace missing inputs, expected values or raw
outputs. Existing readers preserve original failures, source-reserved cases,
ACT reference blockers and scoped Ara exclusions; do not remove or relabel them.

## Configuration and ownership boundaries

This is an inventory of acceptance boundaries, not a claim that every default-off
option is supported or that a formal timing configuration has been certified.

| Class | Code/options | Acceptance boundary |
| --- | --- | --- |
| Evaluated RVV mechanisms | `dbt/guest/rv32_qir.cpp`, `rv32_vector_lower.h`, `dbt/qmc/qcg/{qcg,qra,qemit}.cpp`; QCG typed chunks, M1/M2 | Public correctness flags are frozen in `scripts/rvv/fixtures/external-flags.json`; AOT/LLVM and tier0 are disabled there |
| Maintained diagnostic checks | `--dump-tbcode`, `--dump-tbmap`, `--rvv-run-frame-census`, route/hit/stats counters, fault-state snapshots, focused regression targets | Establish particular emission/admission/state facts, not timing or new ISA form coverage |
| Semantics-changing diagnostic | CMake `RVDBT_FROUND_DIAG_NOP` | Produces incorrect FP behavior; must remain OFF for correctness and formal measurements |
| Profile-dependent ceiling oracles | `config.h` `subst_stable_loads`, `subst_stable_jalr`; private `guest/rv32_profiled_oracles.inc` maps/lookups and `profiled_oracle_setup.inc` environment loaders `DBT_STABLE_LOAD_FILE` / `DBT_STABLE_JALR_FILE` | Unguarded profiled constants/targets are measurement-only, not general semantics-preserving methods; leave these selectors unset for the supported replay |
| Trace-driven rounding ceiling | `--rvv-fround-oracle-mode=2` / `--rvv-fround-oracle-file`; `rv32_vector_fast.h` eligibility replay | Replays retained decisions instead of the live instruction scan; not the general rounding implementation, not enabled by the public fixture recipe. Runtime oracle mode is distinct from CMake `RVDBT_FROUND_IMPL=2` |
| Dispatch/target-set research | `aot_qir_known_targets_file`, `aot_order1_context_file`, `aot_static_table_file`, `aot_vtable_narrow_oracle`; frontend oracle loaders and RTTI/constructor analysis | Separate experimental mechanisms; not accepted by the public QCG fixture replay |
| Inherited and unevaluated combinations | `dbt/aot/`, LLVM lowering/tiering and other optional frontend variants | Preserve inherited capabilities; no blanket RVV or performance acceptance. Unreferenced/old variants require an ownership/test audit before retirement |

The public replay deliberately includes diagnostics for admission checking:
`RVDBT_BUILD_PROFILE=diagnostic` with `RVDBT_FAST_STATS`, `RVDBT_CENSUS` and
`RVDBT_RA_STATS` ON. It is not a formal timing binary.
The build owner's `RVDBT_BUILD_PROFILE=performance` policy requires Release,
those three counter switches OFF, FP contraction OFF, rounding implementation 2,
and no ASAN or rounding no-op oracle. RA spill/fill counters now have their own
`RVDBT_RA_STATS` gate; Release alone is still not a measurement configuration.
Keep `build-profile.txt`, the CMake cache and compiler commands to record effective
options. This build policy does not certify arbitrary runtime experiments or
zero framework overhead. Formal B/M1/M2/Both measurements need one common
source/build basis, effective build/runtime options, correctness on the measured
binary, and only the studied method switches differing between arms.

The profiled substitution maps and file-only oracle loaders are isolated in
`dbt/guest/rv32_profiled_oracles.inc`; their frontend environment setup is in
`dbt/profiled_oracle_setup.inc`. Both expand at their original locations, retaining
the same namespace, process-lifetime storage, lazy initialization and parsing.
This separates experimental data loading, not all research branches: structural
target resolution, RTTI analysis, inherited AOT and lowering gates remain intact.
No oracle is removed or made semantics-preserving by this extraction.
Expansion against the pre-extraction sources is byte-identical after removing
the two include-site comments; neither extracted block uses location macros or
relative includes. An isolated host512 review build compiled `elfaot` and passed
`rvv_vector_run_codegen_test`, `rvv_mem_e64_route_test` and
`rvv_active_chunk_census_test` (three PASS, no SKIP). This is a source-boundary
check, not a replacement for the measured executable's correctness replay.
Mechanism names and invariants belong in maintained code; task-local scripts and
session logs remain historical provenance, not the public execution driver.

## Review Status

The working-tree corrections address the review of `56eccf7`; they are not a
published replacement commit or acceptance of every research configuration.

| Item | Implemented / checked | Remaining boundary |
| --- | --- | --- |
| F1 | Expected outcomes, stdout/file-content checks, timeout, failure propagation and score suppression; 10 local checker tests pass | Tooling tests are not ISA execution |
| F2 | Separate profiles, effective-options record and RA gate; [measured configuration](build-profiles.md#measured-thesis-configuration) explicitly retains FAST_STATS/CENSUS and spill updates | Counter-off is a new build; its results cannot replace measured d252 or inherit complete197 correctness |
| F3 | Public two-fixture build/run/check ran successfully; 11 portable runner tests pass. Retained adapter has 13 tooling tests; measured d252/79d0 replay and actual 595-form receipt recount now complete, with separately classified supplements | Complete selected bundle is prepared privately; pending mixed-license/data grants prevent public download. Finite acceptance, not full conformance |
| F4 | CTest/Jenkins register eight structural and two native tests; isolated counter-off host512 build on xbd: ten PASS, zero SKIP; required-native negative controls also checked | Focused regression execution is not the complete same-build ISA matrix |
| F5 | Supported recipe and diagnostic/oracle boundaries documented; profiled maps/file loaders and environment setup extracted at their original same-TU locations | Limited data-loading separation, not complete research-branch isolation; inherited AOT and structural resolvers retained; other combinations are not supported by implication |
| F6 | The three stale RA comments and reader entry points are corrected | Historical records remain archived, not fresh-build evidence |

### Review And Staging Boundaries

The review working tree starts at branch `delivery/rvv-entry-task182`, HEAD
`56eccf765031704ed2e74b169925c7b09d4a60da`. Dirty changes are not a published
commit, and are not all changes made by this documentation/runner owner.
Review with `git diff -- PATH...` and `git diff --cached --stat`; stage only
explicit reviewed paths or hunks, never `git add .`. No staging or commit is
performed by this checklist. Each group below is an allowlist, not a command.

| Review group | Exact paths (relative to repository root) |
| --- | --- |
| Existing memory/runtime integration | `dbt/guest/rv32_interp.cpp`, `dbt/guest/rv32_memory_admission.h`, `dbt/guest/rv32_vector_lower.h`, `dbt/mmu.cpp`, `dbt/mmu.h`, `dbt/qmc/compile.h`, `dbt/qmc/runtime_stubs.h`, `dbt/rvv_host_copy.S`, `dbt/rvv_host_copy.cpp`, `dbt/rvv_native_fault.cpp`, `dbt/rvv_native_fault.h`, `dbt/ukernel.cpp` |
| Shared production emission / FP changes | `dbt/qmc/qcg/qcg.cpp`, `dbt/qmc/qcg/qemit.cpp`, `dbt/qmc/qcg/qemit.h`; keep runtime changes separate from F6 comment hunks |
| Existing memory / FP test maintenance | `dbt/rv32_host_copy_fault_test.cpp`, `dbt/rv32_native_memory_fault_test.cpp`, `dbt/rv32_permitted_bulk_fault_test.cpp`, `dbt/rv32_scalar_native_fault_test.cpp`, `dbt/guest/rv32_vector_fma_invalid_test.cpp`, `dbt/qmc/qcg/rvv_fp_environment_adjacency_test.cpp`, `dbt/qmc/qcg/qra_vpr_test.cpp`, `dbt/qmc/qcg/rvv_generic_width_route_test.cpp`, `dbt/qmc/qcg/rvv_vector_run_codegen_test.cpp` |
| F1 checker / private-path removal | `examples/benchmarks.py`, `scripts/test_benchmark_checker.py`, `scripts/test.sh` |
| F2 build profiles / counter gate | `CMakeLists.txt`, `CMakePresets.json`, `scripts/build.sh`, `dbt/qmc/qcg/qra.cpp`, `docs/build-profiles.md`; qra also contains F6 comment hunks |
| F4 focused fixtures / test wrapper | `dbt/qmc/qcg/rvv_fp_component_run_test.cpp`, `dbt/qmc/qcg/vfma_typedchunk_route_test.cpp`, `dbt/qmc/qcg/rvv_mem_e64_route_test.cpp`, `scripts/run-cpp-regression.py` |
| Shared build / CI registration | `dbt/CMakeLists.txt`, `Jenkinsfile`; review runtime-target, F1 checker and F4 registration hunks with their respective groups |
| F5 same-TU private loader extraction | `dbt/guest/rv32_qir.cpp`, `dbt/guest/rv32_profiled_oracles.inc`, `dbt/elfaot.cpp`, `dbt/profiled_oracle_setup.inc` |
| F3 portable / retained adapters and controls | `scripts/run_rvv_external.py`, `scripts/test_rvv_external.py`, `scripts/run_rvv_retained.py`, `scripts/test_rvv_retained.py`, `scripts/test_rvv_verify.py` |
| Stable public entry / F1-F6 boundaries | `README.md`, `docs/rvv-author-guide.md`, `docs/rvv-validation/portable-external.md`, `docs/rvv-validation/delivery-task182/README.md`, `docs/rvv-validation/final-task197/README.md` |

Exclude untracked `*-evidence/`, `*_RESULT.md`, all `__pycache__/`, raw outputs,
ELFs, caches and local campaign/bundle work directories. They are not source
staging candidates. Keep bulky licensed inputs/references in a separately
inventoried bundle; commit only selected compact, reviewed result receipts when
their owner approves. A source snapshot, measured d252 executable and new
counter-off profile have distinct identities; do not relabel one as another.

The measured ordinary key/receipt recount and external/focused/sequence joins
are complete in [this run's result](rvv-validation/delivery-task182/MEASURED_D252_RESULT.json).
The private bundle's final read-only verifier passed against its existing seal
without replacing data goldens or its sealed driver. Source diff review is
complete: production/archive correspondence and subsequent maintenance were
reviewed separately and published in `2c7464f`. Bundle publication/license
clearance remains separate.
The two `MEASURED_D252_*` result files in `docs/rvv-validation/delivery-task182/`
are published compact results, separate from runtime changes and raw.
No new performance run is required for bundle publication clearance.

### Retained Candidate Test Repairs

The complete197 executable is `908df235...`, not measured `d252ef99...`.
Later candidate evidence includes focused native memory/fault and FP checks,
the separate process-output matrix and final campaign output receipts; it is not
a replacement complete ISA replay. The original failed test logs remain intact:

| Test / original failures | What the retained log actually establishes | Status |
| --- | --- | --- |
| `vfma_typedchunk_route_test` / 13 | Software interpreter lacked emitted `vfpclassps/pd` zero/inf classification | Added exact encoding-based classification, signed-zero/inf/subnormal/NaN controls; value and flag assertions retained; PASS |
| `rvv_mem_e64_route_test` / 36 | Whole-function branch/arithmetic counts included new memory-admission code | Assert the base-limit compare/branch edge and arithmetic-free transfer body, retaining guard/QIR/width checks; PASS |
| `rvv_fp_component_run_test` / 80 | 72 widening refusals plus two aggregate assertions, four generic/family-switch expectations and two memory-barrier identity assertions | Exact widening classification and generic-or-family controls; memory row checks singleton boundaries without requiring identity or difference; other identity/positive-run tests retained; PASS |

The FP switch controls now cover the current `generic || family` condition.
In the memory-barrier row at VLEN512/1024, the observed disassembly difference
was only the external native-memory fault tail-jump relocation
(`QEmit`'s `kIdJmp` to `id_rv32_native_memory_fault`); the harness normalizes
calls, not jumps. It is not evidence that enabling runs must change this row.
Independent native FMA checks also pass with active-mask fusion off and on,
including the existing flags checks. No production semantics were changed by
these fixture repairs, and neither result closes the missing same-build matrix.

## Unverified behavior

Terminal fault observations, direct signal-frame interface calls and separately
initialized nonzero-`vstart` cases do not establish a guest handler repairing a
fault, returning to the same PC and completing the instruction. General precise
restart/repair-return remains unverified. The
[terminal illegal-instruction checks](rvv-validation/trap-task199/README.md)
cover a bounded exception dimension, not additional forms or a returning handler.

Also do not infer full intermediate state, arbitrary overlap/access suppression,
agnostic write history or per-PC M1/M2 admission from program success.
Ara source bounds/macro limitations and ACT reference blockers remain explicit
in their readers. Restricted datasets, missing toolchains and unavailable raw
archives remain prerequisites or blockers, never implicit PASS.
