# rvdbt: RISC-V Vector Dynamic Binary Translation

This repository continues [Wendell Lin's rvdbt](https://github.com/Wendell-Lin/rvdbt)
and retains its Git history and original MIT license. The RVV research snapshot
adds RISC-V Vector execution paths to the lightweight QCG JIT, consecutive-vector-
instruction value retention (M1), and runtime-`vl`-based omission of eligible
inactive high chunks (M2). The integration commit imports the implementation as
one snapshot; it does not reconstruct the chronological development history.

The evaluated thesis scope is **QCG**, not complete native lowering of every RVV
1.0 instruction and not a claim of completed online LLVM-AOT performance. Forms
outside a direct route may use a semantic helper. The repository contains
experimental AOT/tiering paths; their presence does not make them evaluated
thesis results. Benchmark guest binaries and restricted input datasets are not
redistributed here.

## Build, run and check RVV

Start with the [public portable replay](docs/rvv-validation/portable-external.md).
It provides configurable DUT, host/guest toolchains, dependency location, isolated
cache and output directories, then builds and checks one complete adapted Ara
file and one retained RVVTS sequence in B/M1/M2/BOTH against Spike. It requires
a compatible AVX-512 Linux host and the documented tools, not a private host.
The checked build includes diagnostics and is **not a performance recipe**.

For all 595 forms, use the [retained-corpus replay](docs/rvv-validation/portable-external.md#retained-directed-corpus).
Its separately downloadable corpus contains the test assembly/ELFs, original
checker snapshots, retained independent references and source/license notices.
The same entry supports listing forms, inspecting cases and running selected
configurations or the complete ordinary directed corpus.

The [documentation index](docs/README.md) groups the current architecture,
build and testing instructions separately from historical evidence. Start with:

- [Architecture and code map](docs/rvv-qcg.md): QCG translation, M1/M2 legality,
  helpers and allocator boundaries.
- [Support and evidence guide](docs/rvv-author-guide.md): accepted scope,
  formal/diagnostic/oracle inventory and missing evidence.
- [Public build/run/check](docs/rvv-validation/portable-external.md): fresh
  execution and explicit receipt reuse.
- [627-form scope](docs/rvv-current-scope.md) and
  [original-case navigation](docs/rvv-validation/all-form-records/README.md):
  per-form source/assertion/package selectors.

## Validation evidence

The [measured d252 replay](docs/rvv-validation/delivery-task182/README.md#measured-d252-replay)
has its own [result](docs/rvv-validation/delivery-task182/MEASURED_D252_RESULT.json)
and [595-form ordinary CSV](docs/rvv-validation/delivery-task182/MEASURED_D252_PER_FORM.csv):
95,242 units / 380,968 four-arm calls / 12,069,048 selected checks, plus separately
classified focused, external and sequence results. It uses the measured
executable/library with correctness diagnostics enabled, not identical timing
flags. Independent reference executions are retained, not regenerated.

The RV32/ELEN64 catalogue has **595 applicable mnemonic/operand forms** and
32 excluded ei64 indexed-memory forms. The
[frozen correctness replay](docs/rvv-validation/final-task197/README.md) records
B/M1/M2/Both results for all 595 applicable forms on its pinned executable:
12,069,048 ordinary comparisons, 2,256 focused positives, 592 denial controls,
21,316 external calls and 9,888 sequence DUT checks. The
[historical 595-row CSV](docs/rvv-validation/final-task197/PER_FORM_RESULTS.csv) joins those
compact results; it does not make the complete raw inputs/results public.

For a form's selected dimensions and original answer predicate, then its concrete
source/assertion/reference locators, run from the repository root:

```sh
python3 scripts/run_rvv_retained.py list
python3 scripts/run_rvv_retained.py show --form vadd.vv
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --form vadd.vv --output /absolute/path/to/new-form-records
```

`list/show` read the case catalogue, not a historical or fresh PASS. They expose
selected case counts, configuration dimensions and original checker/source pins;
the [same entry](docs/rvv-validation/portable-external.md#retained-directed-corpus)
provides per-form `preflight`, `run` and `audit` with a received local bundle.
Follow the per-form records to
the original oracle/checker; no universal synthetic expected-output generator is
provided. Research session logs, temporary builds and experiment queues are not
required by the public sample entry.

Retained-corpus replay executes the DUT against saved independent reference
outputs; the external fixture entry instead runs fresh Spike comparisons.
A new build receives its own identity and results. The corpus download contains
inputs/references for ordinary directed replay, not every historical DUT output
or every external-suite campaign.

Finite form counts are not full RVV conformance, a tested VLEN/SEW/LMUL Cartesian
product, or proof that M1/M2 admitted every target. General precise fault/retry
and guest-handler repair/return remain unverified. Older performance results
retain their original executable/configuration.

## Repository layout

| Directory | Contents |
|---|---|
| `dbt/` | RISC-V frontend, QIR, QCG, LLVM backend and runtime |
| `scripts/` | Build, validation and analysis entry points |
| `scripts/aot/` | Experimental background AOT controller |
| `docs/` | Architecture, build profiles, validation guides and retained evidence |
| `examples/` | Small example programs |
| `riscv-tests/`, `prebuilts/`, `patches/` | Upstream scalar tests, fixtures and adaptation patches |

See the [script guide](scripts/README.md) for supported entry points and the
[scalar examples](docs/scalar-examples.md) for the inherited scalar/AOT workflow.
Historical validation records remain under `docs/rvv-validation/` so their
source, checker and result references stay reproducible.

## Attribution and license

Based on [Wendell Lin's rvdbt](https://github.com/Wendell-Lin/rvdbt).
The inherited history is preserved, and the RVV implementation and subsequent
maintenance are recorded in this fork's commits. See [LICENSE](LICENSE).
External test sources and retained corpora have their own license notices.
