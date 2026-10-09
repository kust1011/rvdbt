# RVV validation

The validation has two separate responsibilities: external test programs check
instruction behavior, while the runner checks that the intended program ran and
that failures propagate. Passing the runner's unit tests is not ISA coverage.

## Registered test replay

`scripts/rvv_tests.py` runs self-checking RV32 ELFs from a registered manifest.
It requires both the registered exit status and exact stdout. A crash, timeout,
missing executable, mismatched input, or extra output fails the run. Negative
controls are reported separately from positive instruction tests. Existing output
directories cannot be reused.

Binary state packets use `expected_stdout_base64` instead of `expected_stdout`.
Exactly one representation is required, and comparison uses decoded bytes. The
registration must identify the external reference that produced the packet;
base64 encoding is only transport, not an oracle.

```sh
python3 scripts/rvv_tests.py \
  --manifest /path/to/bundle/manifest.json \
  --inputs /path/to/bundle/inputs \
  --engine /path/to/build/bin/elfrun \
  --library-dir /path/to/build/lib \
  --output /path/to/new-results --jobs 2
```

Each case retains its command, registration, stdout, stderr, and result. The
top-level invocation records executable identity, selected cases, runner identity,
and library search path. Elapsed values are timeout diagnostics, not benchmark
results. The runner does not establish whether a native, helper, M1, or M2 route
was entered; those observations need separate instrumentation.

The registered `candidate.build` binds an existing campaign to its executable and
runtime library. Rebuilding creates a separate executable identity, even when the
source is unchanged. Register that build separately and preserve the original
manifest; never replace old identities to make a historical campaign appear new.

## External source reconstruction

A complete external fixture is included under
`scripts/rvv/fixtures/chips-vsmul-vv`. With the pinned CHIPS checkout and its
environment submodule available, the following command rebuilds it, verifies
the registered ELF, and tests B/M1/M2/Both using a newly recorded DUT identity:

```sh
python3 scripts/run_rvv_smoke.py \
  --upstream /path/to/pinned/chips-checkout \
  --engine /path/to/build/bin/elfrun --library-dir /path/to/build/lib \
  --output /path/to/new-smoke-results
```

Use Clang/LLD 20 for the retained ELF identity. `--build-only` performs the
cross-build without requiring an AVX-512 execution host or a DUT; it reports
no ISA PASS. Obtain the upstream source with `git clone --recurse-submodules`,
checkout the revision in `sources.lock.json`, and run `git submodule update
--init --recursive`. The build rejects modified tracked headers/submodules.
Do not overwrite prior results when testing a new build.

`scripts/rvv/sources.lock.json` pins the CHIPS source and environment submodule.
`scripts/build_rvv_chips.py` rebuilds a registered stage2 assembly file without
changing its instruction body or expected values. The Linux-user adapter changes
only terminal reporting: successful completion prints `CHIPS_PASS` and exits 0;
failure prints `CHIPS_FAIL` and exits 1.

```sh
python3 scripts/build_rvv_chips.py \
  --upstream /path/to/pinned/chips-checkout \
  --source /path/to/registered-stage2.S \
  --source-sha256 REGISTERED_SOURCE_SHA256 \
  --expected-elf-sha256 REGISTERED_ELF_SHA256 \
  --compiler clang-20 --output /path/to/new-build
```

The stage2 fixture and its original oracle-generation record are required inputs.
This command rebuilds a fixture; it does not independently regenerate its golden
answers or certify their correctness. Do not replace expected values using rvdbt
output. Different upstream suites require their own documented adapters/checkers.

## Coverage records

```sh
python3 scripts/rvv_coverage_report.py \
  --forms /path/to/FORM_VERIFICATION_EVIDENCE.csv \
  --output /path/to/new-coverage-report
```

This exports existing per-form records, not new test results. The family summary
and `forms.json` preserve applicability, configurations, source/checker evidence,
actual-path observations, and unverified behavior. Instruction forms, executed
cells, assertions, and suites have different denominators.

The October 9 inventory contains 627 named forms: 595 applicable to the registered
RV32/ELEN64 scope and 32 marked not applicable. All 595 have a joined positive
record, but that does not mean all legal operand/configuration combinations were
tested. It is not a universal count of RVV instructions. Runtime geometry, masks,
tail policy, restart, overlap, floating-point flags, and method admission must be
reported independently.

Use `--supplements /path/to/supplements.json` to attach later scoped evidence to
existing instruction forms. Each record supplies `id`, `forms`, `candidate`,
`configuration`, `checker`, `result`, `evidence`, and `limitations`. Unknown forms
or duplicate record IDs are rejected. These observations remain separate from
historical records: they do not overwrite gaps, relabel an old build, or increase
the number of forms with historical positive results. The exporter validates the
index structure, not the underlying experimental evidence.

## Runner checks and CI

For an external self-checker that reports on stderr, a cell can additionally
register `expected_stderr_base64`. The runner then requires byte-exact stderr
as well as the registered exit code and stdout. Missing, extra or changed
stderr is a failure; the archive auditor applies the same rule. This is optional
for existing fixtures and does not reinterpret their historical results.
Diagnostic text must be kept separate from the source of numerical answers:
ACT answers come from the reference signature embedded in the guest, not from
a captured rvdbt diagnostic stream.

Archived runs can be checked without rerunning the guest:

```sh
python3 scripts/audit_rvv_results.py \
  --results /path/to/archived-results --inputs /path/to/registered-inputs
```

The audit checks the recorded build identity, selected cases, input files,
commands, raw stdout/stderr, exit/output classification, and aggregate counts.
It rejects a recorded PASS when the raw output disagrees with the registered
answer, even if the output digest was updated. It reports archive consistency,
not new ISA coverage or independent proof that the recorded execution occurred.
Historical timeout classification remains dependent on the runner record because
older archives lack a separate timeout flag. Source/checker provenance and actual
native-path admission still require the corresponding suite and method evidence.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts -p 'test_rvv_*.py' -v
```

These checks use synthetic host processes to test failure handling and reporting.
The Jenkins stage runs them before building rvdbt. It does not claim to run the
external ISA suites: those need registered fixtures, a compatible host, and a
separately recorded DUT build. No external suite result is inferred from CI being
green. Large raw results and third-party fixtures are separate artifacts; this
repository addition does not yet supply a public download of those artifacts.

## Review artifact inventory

`docs/rvv-validation-artifacts.json` identifies the local delivery archives by
filename, byte length, digest and purpose. Obtain the named archives separately;
the repository does not advertise an unavailable public download.

The registered replay bundles contain input ELFs, manifests, original logs and
the runner. Their README gives the command for the exact registered executable
and runtime library. The historical CHIPS bundle retains its original build;
the later supplements have their own registrations. Do not combine these as if
all were executed by one rebuilt binary.

`suite-evidence.tar.gz` is instead a review bundle. It contains the files
explicitly referenced by the ACT, Ara and RVVTS evidence index, including failed
and unexecuted records. A row can describe one target/checker binding within a
larger execution. Row counts must not be reported as test-execution counts.
The bundle retains original source and checker limitations; collecting a file
does not validate every textual anchor or make the toolchain reproducible.

The NF8 and fractional-source supplements keep original CHIPS inputs and
destination checks, but add local pre/post state observers. QEMU and Spike
provide the comparison packets. They test preservation of specifically observed
registers, CSRs and buffers, not all memory accesses or precise fault recovery.
Offline modified-output controls check that these observed bytes are actually
compared; those controls are harness checks, not additional external ISA tests.
