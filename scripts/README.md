# Build and validation scripts

Run commands from the repository root. Use the maintained entries below for
RVV development. Numbered campaign scripts reproduce historical experiments;
their paths remain stable because recorded manifests refer to them.

## Current entry points

| Task | Entry | Result |
|---|---|---|
| Build and focused C++ tests | [Build profiles](../docs/build-profiles.md) | Structural and hardware-dependent native checks |
| External guest tests | [Portable replay](../docs/rvv-validation/portable-external.md) | Documented Ara and RVVTS fixture results |
| Directed instruction tests | `run_rvv_retained.py` | Selected cases compared with retained independent references |
| Per-form external coverage | `rvv_scope_report.py` | Source cases, comparison sites and recorded outcomes |

Host-side runner and checker tests require no new performance campaign:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_rvv*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_legacy_*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/rvv/directed -p 'test_*.py'
```

These commands test host tools, not RVV execution. Catalogue `list` and `show`
commands likewise do not execute guest tests. Follow the portable replay guide
for dependencies and actual execution; diagnostic replay is not a timing recipe.

## Inherited build scripts

The scripts below are retained for the upstream scalar workflow. Prefer the
build profiles above for RVV configurations. The current Jenkins job uses LLVM 20.

### Build
```bash
bash scripts/build.sh 20
```

### Test
```bash
bash scripts/test.sh 20
```

### Benchmark
```bash
bash scripts/benchmark.sh 20
```

The inherited `hotspot.sh`, `test-rv32emu-im.sh`, `rv32emu-not-freq.sh`,
`spec2017/ref.sh`, `spec2017/ref-no-prop.sh` and `spec2017/train.sh` select
specific scalar experiment modes. They resolve paths from this checkout and
accept an optional LLVM major version (default 20), independent of the caller's
working directory. They require the corresponding build and prebuilt inputs;
SPEC inputs must be obtained under their own license.

`spec2017/test.sh` exits with an error: the inherited `SPEC2017RateTest` selector
has no workload definition. Reference and training inputs are not substitutes
for that missing test configuration. These scripts are not the thesis's RVV
performance matrix runner.

## Experimental AOT controller

`aot/sr_builder.sh` is the background compiler controller used by the experimental
in-run tiering path in `dbt/aot/aot_boot.cpp`. CMake supplies its path through
`DBT_SR_BUILDER_SH`; it is not a standalone build or test command. The runtime
passes the compiler, input ELF, cache directories, scheduling parameters, active
VLEN and RVV route options to the script.

The script was relocated from the dated `experiments/` directory without changing
its contents. Historical build manifests retain the original path. Reconfigure
and rebuild an existing build tree to embed the new location; previously built
executables still reference their original checkout. Keep measured snapshots
intact. AOT/tiering experiments are separate from the evaluated QCG path.

Check the runtime-to-compiler option contract without executing a guest:

```sh
python3 scripts/vlen_propagation_audit.py .
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
