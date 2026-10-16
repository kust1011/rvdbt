# RVV support and validation

## Implementation scope

This continuation of upstream rvdbt adds RVV state/decoding, semantic helpers,
typed vector QIR and x86 emission to the lightweight QCG JIT. Register promotion
(M1) retains eligible consecutive-instruction values; runtime chunk bounds (M2)
skip eligible high chunks outside `vl`. The [architecture guide](rvv-qcg.md)
explains their legality, allocator and fallback rules.

The catalogue contains **627 mnemonic/operand forms: 595 applicable to the
RV32/ELEN64 profile and 32 excluded ei64 indexed-memory forms**. These are forms,
not 627 distinct instruction names. Direct SIMD lowering and semantic helpers
are implementation routes; the per-form tests check architectural results
independently of that classification. VLEN ranges from 128 to 4096 in the test
catalogue; each form has its own selected legal configurations.

## What the tests check

Directed tests capture destination and preserved vector state, applicable scalar
results, vector/FP CSRs and memory results. The precise fields and allowed-value
rules are defined by each original checker. Retained Spike/Sail outputs and
specification predicates supply the expected behavior; rvdbt outputs are not
used to generate reference answers.

For a particular form:

```sh
python3 scripts/run_rvv_retained.py list
python3 scripts/run_rvv_retained.py show --form vadd.vv
```

The catalogue reports case counts, SEW/LMUL/VLEN, masks, partial lengths,
`vstart`, policies and original source/checker locations. Its dimension lists
are marginals, not every possible Cartesian combination. Use `preflight` with
the input corpus to inspect concrete selected cases, commands and ELF files.

| Material | Purpose |
| --- | --- |
| [Form catalogue](rvv-current-scope.md) | Applicable/excluded forms and recorded implementation routes |
| [Original-case navigation](rvv-validation/all-form-records/README.md) | External suite sources, assertions, adapters and selectors |
| [Measured-build results](rvv-validation/delivery-task182/README.md#measured-d252-replay) | Results tied to the measured executable, with per-form counts |
| [Replay instructions](rvv-validation/portable-external.md#retained-directed-corpus) | Acquire inputs, select cases, execute all four method configurations and audit results |
| [External fixture instructions](rvv-validation/portable-external.md) | Build Ara/RVVTS examples and execute fresh Spike and rvdbt comparisons |

The measured-build ordinary replay covers 595 forms, 95,242 ELF units,
380,968 B/M1/M2/Both executions and 12,069,048 selected checks. Focused tests,
external suites and instruction sequences are recorded separately in the
[measured result](rvv-validation/delivery-task182/MEASURED_D252_RESULT.json).
Do not add overlapping per-form execution counts to obtain campaign totals.

The historical external-case index records checked sets of CHIPS595, ACT590,
RVV-ATG434, Ara422 and SiFive RIF200; their union is 595, not their sum.
RVVTS58 and RVISmith43 describe coupled sequence endpoints, not independent
checks of every contributing opcode. Original failures, reference blockers and
source adaptations remain in those source-specific records.

## Reproduction

The corpus release supplies retained assembly/ELFs, reference packets,
commands, original checker snapshots and source/license notices separately from
the Git working tree. Follow the release manifest and commands in the
[replay guide](rvv-validation/portable-external.md#retained-directed-corpus).
Toolchains and the rvdbt executable are built separately.

A replay executes the original ELF and checks selected accepted cases under
B/M1/M2/Both. The checker identities and reference contents are verified before
use. Missing inputs, changed predicates, failed execution, timeout and result
mismatch fail the run. Downloading a corpus or listing its forms does not
execute a test. A new executable receives its own run identity and results.

Use `scripts/run_rvv_retained.py` for current replay, not the historical campaign
scripts in `scripts/rvv/directed/`. The [directed-script map](../scripts/rvv/directed/README.md)
explains why the original generators and snapshots remain available.
The release contains the ordinary directed inputs/references; it is not an
archive of every historical DUT output or every external-suite campaign.

## Configuration and ownership boundaries

See [build profiles](build-profiles.md) for effective options. The diagnostic
profile enables counters for route/admission checks. The performance profile
disables the three optional counter classes. The measured thesis executable
retained its documented counter configuration; it is not relabeled as a build
of the newer counter-off profile.

| Configuration | Treatment |
| --- | --- |
| Typed QIR, QCG chunks and M1/M2 | Supported replay uses recorded per-method flags; AOT and tier0 are disabled |
| Disassembly, route/hit counters, frame census and state snapshots | Diagnostic information; enabled options are recorded separately from timing |
| `RVDBT_FROUND_DIAG_NOP` | Must be OFF: the diagnostic no-op changes FP behavior |
| `DBT_STABLE_LOAD_FILE`, `DBT_STABLE_JALR_FILE` and unguarded profiled substitutions | Research ceiling oracles, not semantics-preserving execution; leave unset |
| `--rvv-fround-oracle-mode=2` and its file | Trace-driven diagnostic; not the runtime rounding implementation or CMake `RVDBT_FROUND_IMPL=2` |
| AOT target-set, RTTI and LLVM/tiering variants | Inherited/experimental paths; not validated by this QCG replay |

The profile/oracle file loaders are separated into
`dbt/guest/rv32_profiled_oracles.inc` and `dbt/profiled_oracle_setup.inc`.
Inherited AOT functionality remains in the repository.

## Regression tests

```sh
python3 -m unittest discover -s scripts -p 'test_rvv_*.py'
python3 -m unittest discover -s scripts -p test_benchmark_checker.py
cmake --build BUILD --target regression-focused
ctest --test-dir BUILD -L focused --output-on-failure --no-tests=error
```

Python tests exercise execution/checker contracts and rejection controls;
C++ regressions separately cover structural and native generated-code behavior.
Set `RVDBT_NATIVE_REQUIRED=ON` when configuring a native validation build:
missing required hardware must fail, not turn all native tests into skips.
Jenkins runs the registered tests. The benchmark checker rejects incorrect
outputs and execution/setup failures and suppresses speedups for failed runs.

## Interpretation boundaries

Finite selected cases do not establish every input or every legal configuration.
A configured M1/M2 flag does not alone establish that the optimized path was
entered; admission and generated-code checks are separate.

Terminal faults and initialized nonzero-`vstart` tests do not establish a
general guest-handler repair, return to the same PC and successful restart.
The [illegal-instruction checks](rvv-validation/trap-task199/README.md) cover
their documented exception cases. The original source-specific readers retain
other restrictions that affect those tests.
