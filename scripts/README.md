# Scritps
This directory collects the scripts to build, test, and benchmark, to avoid polluting the parent directory.
But to run these scripts, please be at parent diretory and specified llvm version like following examples. The CI/CD Jenkins also use these scripts.

## Build
Note that this only builds developing llvm version. There is no need to build earlier llvm version after building from forked repo.
```bash
~/rvdbt$ bash scripts/build.sh 19 
```

## Test
```bash
~/rvdbt$ bash scripts/test.sh 19
```

## Benchmark
```bash
~/rvdbt$ bash scripts/benchmark.sh 19
```

## RVV validation tools

Run from the repository root with Python3.10+. See
[validation](../docs/rvv-validation.md) for complete commands and dependencies.

| Command | Action | Required external inputs |
|---|---|---|
| `rvv_compact_scope.py --input ...` | Regenerate compact current 627-form table/CSV | committed projection; no raw archive or execution |
| `rvv_scope_report.py` | Render frozen per-form/suite stages and select bindings | scope archive CSV/JSON |
| `rvv_complete_inventory.py` | Recompute/check all ten canonical join outputs | complete retained evidence tree, metadata/ELFs |
| `rvv_coverage_report.py` | Rebuild historical FORM/supplement reports | original FORM CSV and optional supplement index |
| `verify_rvv_artifacts.py` | Verify archive sizes/digests | separately obtained named archives |
| `audit_rvv_results.py` | Check registered saved raw records | replay archive/results and inputs |
| `build_rvv_chips.py` | Compile retained CHIPS assembly | pinned CHIPS/environment, Clang/LLD20 |
| `run_rvv_smoke.py --build-only` | Rebuild/verify bundled fixture | same pinned headers/toolchain |
| `run_rvv_smoke.py` / `rvv_tests.py` | Execute registered guests, record a new DUT identity | engine/library, compatible host, fixture/manifest |

`python3 -m unittest discover -s scripts -p 'test_rvv*.py'` tests host tools,
including stage classification and failure controls. It supplies no ISA results.
Suite-specific historical adapters are not a portable all-suite runner.

Portable full Ara vredsum and retained RVVTS API sequence replay: see
[commands and dependency setup](../docs/rvv-validation/portable-external.md).
`fetch_rvv_external.py`, `run_rvv_external.py`, `verify_rvv_external_elf.py` and
`audit_rvv_external_admission.py` extend the existing RVV tooling; full-packet
controls use the pinned original MachineState comparator. They do not add ISA counts.

The [reviewer entry](../docs/rvv-validation/delivery-task182/README.md) uses
`rvv_verify.py list|show|command|smoke|preflight|export` and the existing directed executor/checkers. `rvv_reproduce.py preflight|run`
builds and checks one ordinary vadd unit with installed pinned reference/DUT tools.
