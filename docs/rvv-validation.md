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

## Runner checks and CI

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts -p test_rvv_runner.py -v
```

These checks use synthetic host processes to test failure handling and reporting.
The Jenkins stage runs them before building rvdbt. It does not claim to run the
external ISA suites: those need registered fixtures, a compatible host, and a
separately recorded DUT build. No external suite result is inferred from CI being
green. Large raw results and third-party fixtures are separate artifacts; this
repository addition does not yet supply a public download of those artifacts.
