# RVV validation

The validation has two separate responsibilities: external test programs check
instruction behavior, while the runner checks that the intended program ran and
that failures propagate. Passing the runner's unit tests is not ISA coverage.

## Current scope and reproducible index

Start with the [generated current 627-form table](rvv-current-scope.md), its
[compact inputs/source manifest and reproduction command](rvv-validation/current-scope/README.md),
the [CHIPS four-configuration smoke](rvv-validation/smoke-task80/README.md),
and the [complete Ara file and RVVTS sequence replay](rvv-validation/portable-external.md).
The table uses the accepted checked/endpoint membership, including the Ara
integration recorded in its input manifest, and already recorded
static route classes. It is a compact index, not raw evidence or new executions.
Its bundled projection renders without this machine; full bindings and unpublished
historical archives still require separately authorized retrieval. No public
reproduction of inaccessible historical archives is claimed.

The [licensed Ara inspection archive](rvv-validation/ara-review-task91/README.md)
packages the accepted Ara82–86/89 source, adapter, original parser and raw records,
including retained failures. Extract it into a fresh directory and run
`python3 tools/verify_rvv_ara_bundle.py .`; form-to-binding navigation and notices
are included. This offline predicate check is separate from live replay and
does not make the other historical suites portable.

The [primary CHIPS inspection guide](rvv-validation/chips-review-task93/README.md)
indexes retained source, reference-generation records, original assertions and
raw results for all 595 checked forms. Each candidate has 11,532 positive
executions and 212 failure-control executions, kept separate. The licensed
archive manifest and offline checks are committed; the approximately 627 MB
archive payload is prepared but its download location is still pending.
Do not mistake the committed manifest for a published data download.

The [suite execution accounting summary](rvv-validation/suite-execution-summary.md)
and its JSON separate distinct registered DUT/reference receipts, controls, source
dispositions and Ara overlays. These counts preserve candidate scopes and are
not original suite universes or exhaustive producer reference counts.

The [ACT primary inspection entry](rvv-validation/act-primary-task99/README.md)
links the retained Task53 source/signature/raw chain and offline acceptance
instructions. Python assertions must be enabled; optimized acceptance is
explicitly rejected. The Task100 checker refresh preserves original payload
bytes and evidence counts. Its archive remains staged on xbd, with payload
publication and a verified download still pending.

The [ACT db2 Task109/110 delivery](rvv-validation/act-db2-task110/README.md)
adds a separate exact output index and staged inspection/replay package:
1,916 new complete-file four-arm PASS, two preserved QEMU platform blockers,
and one separate Task104 join. Offline verification evaluates original raw
predicates and reprocesses frozen signatures without guest execution. The form
union remains 595; target reach does not establish optimized admission.

The current canonical stage index separates source presence, compilation/static
emission, program execution, target/result checking, coupled endpoints, diagnostics
and failures. Target-checked sets are CHIPS595, ACT590, RVV-ATG434, Ara422 and
SiFive RIF200, with union595. RVVTS58 and RVISmith43 are coupled
endpoints; the historical libriscv198 records are retained but excluded from
the current validation claim. An opcode in a successful program need not have executed or influenced
its output. The clean961 candidate has its own checked union595; historical2af5
and the performance binary remain distinct. See the [author guide](rvv-author-guide.md)
for provenance, implementation/checker/raw-result tracing and unresolved limits.

Obtain the immutable `scope-evidence.tar.gz` listed in the artifact manifest and
extract it into a new directory. It contains the frozen Task71 canonical outputs and
original per-form input, not new executions or a complete raw/source corpus.
From the code checkout, render a frozen index or select exact binding rows:

```sh
python3 scripts/rvv_scope_report.py \
  --forms "$SCOPE/FORM_VERIFICATION_EVIDENCE.csv" \
  --summary "$SCOPE/ACTUAL_FORM_VALIDATION_SUMMARY.json" \
  --bindings "$SCOPE/ACTUAL_FORM_VALIDATION_BINDINGS.csv" \
  --form vsmul.vv --output new-form-report
```

`SCOPE` is the extracted archive directory. This command uses Python3.10+ and
only reads saved index data; it reports input hashes, retains candidate scopes,
and never treats unknown stage membership as zero coverage. Bindings retain
original provenance paths; follow the archive's dependency record for raw data.

To recompute the complete joins, obtain the separately retained evidence tree
with its `artifacts/` layout and dependencies listed in the scope archive:

```sh
python3 scripts/rvv_complete_inventory.py --evidence-root "$EVIDENCE" --check
python3 scripts/rvv_complete_inventory.py --evidence-root "$EVIDENCE" \
  --output new-complete-report
```

`--check` compares all ten canonical outputs without writing. `--output` requires
a new directory and relocates Markdown evidence links. These commands rebuild
summaries from retained tables, metadata and ELFs; they do not execute tests or
certify raw-result truth. Missing inputs fail or remain explicit missing joins.
The full tree is still required; this archive does not silently supply it.
The older `rvv_coverage_report.py` regenerates the historical FORM/supplement
view and is not the current all-suite join. Task76 regenerates current joins from the separate evidence tree; the immutable scope archive keeps its earlier snapshot.

For artifact integrity, run `scripts/verify_rvv_artifacts.py --archive-root
"$ARCHIVES"`; the archive root may contain the named delivery subdirectories.
Digest/size verification proves transport identity, not ISA correctness.

`rvv_tests.py`, `run_rvv_smoke.py` and `run_rvv_external.py` execute guests.
The smoke and external runners also provide `--build-only`, without DUT execution. Original
suite-specific generation/campaign scripts are retained research evidence;
no portable all-suite execution runner is supplied. The source lock documents
pinned fetch entry points and licensing. Bundled runnable fixtures cover CHIPS,
an original complete Ara reduction file and a retained RVVTS API sequence;
RVV-ATG lacks a redistribution license in the pinned tree, and RVISmith restricts
redistribution/modification/use, so their fixtures are not copied into this repo.
Obtain any required permission before reuse. Pinned fetch instructions describe
source retrieval, not a promise of a working all-suite campaign.

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

`coverage-report.tar.gz` supplies the source CSV, scoped supplements, exporter
and generated per-form reports. Its README rebuilds all three report files from
a separate directory; this extracted rebuild was verified byte-identical.
This reproduces the evidence index, not the underlying ISA executions.

`remaining-supplements.tar.gz` contains eight scoped cases with 32 accepted
candidate records. Initial same-PC geometry launch errors remain in the raw
evidence but are not accepted test results. For widening and VLEN4096, eight
portable replay registrations relocate the recorded filesystem/cache/diagnostic
paths; these relocated command variants have not themselves been rerun.

`docs/rvv-validation-artifacts.json` identifies the local delivery archives by
filename, byte length, digest and purpose. Obtain the named archives separately;
the repository does not advertise an unavailable public download.

`oct10-evidence.tar.gz` is the incremental review archive in the delivery's
`oct10-evidence-bundle/` directory. Its 14 additions were selected by supplement
ID against the original coverage bundle, including additions prepended to the
index. It retains a 28-record coverage-v16 snapshot of the index, original CSV,
exporter and reports, plus the additions' actual evidence and correction history.
That later historical index is coverage-v21 with 41 records; this archive does not
contain that later index.
The archive contains 7,809 files, 60 accepted candidate executions and four
superseded candidate records; those counts are separate from its eight affected
instruction forms. `RESULT.json`, `SCOPE.json` and `CONTENTS.json` record the
completed fresh-extraction validation and exact scope.

Extract into a new directory and follow its README to run only the coverage
exporter and compare the three reports. For full payload/reference validation,
run `python3 tools/verify_oct10.py . /path/to/oct10-evidence-bundle/CONTENTS.json`
before creating additional files in the extraction. `REFERENCE_RESOLUTION.json`
maps original absolute paths, documents external historical/tool dependencies,
and resolves the index's `narrow-m4-overlap/runs` reference to the actual four
arm-specific results directories. Review dependencies support inspecting saved
evidence; this archive supplies no toolchains or turnkey build/replay and does
not reexecute ELFs. Frozen961 evidence remains separate from P4; packaging adds
no DUT, reference or generator execution. The seven earlier archives are unchanged.

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

`final-evidence.tar.gz` in the delivery's `final-evidence-bundle/` directory
packages the remaining 13 supplement IDs against the immutable 28-record
`oct10-evidence.tar.gz` snapshot. It contains the 41-record historical supplement index,
original source CSV, its exporter, and the readable coverage-v22 report
(627 forms, 595 applicable, 647 report files). Original report JSON regenerates
byte-identically in a fresh extraction. The eight earlier archives remain unchanged.

The archive has 6301 payload files and 60 saved raw-result bindings; the historical
ACT scalar join separately declares 13,720 lane-to-raw bindings. These units are
not new executions or instruction-form totals. Initial failures, adapters,
superseded attempts and original goldens/logs remain. Historical executable
2af5 is distinct from clean961. P3-38 retains two original whole-test FAIL
packets as bounded offline post-exit observation, with no new PASS; P4 is separate.

From a fresh extraction, before adding files, run
`python3 tools/verify_final_evidence.py . /path/to/final-evidence-bundle/CONTENTS.json`.
`RESULT.json` records payload integrity, declared raw bindings, local navigation
and report JSON regeneration. Transport Markdown relocates navigation; original
Markdown bytes remain in `original-markdown/`. `REFERENCE_RESOLUTION.json` and
`DEPENDENCIES.md` identify retained files, named prior archive members with hashes,
and unavailable remote/tool/source/output dependencies. Obtain prior archives
separately; original commands retain historical paths. The package includes no
caches, virtual environments, toolchains or turnkey build/replay promise, and
packaging performs no guest, reference, generator or build execution.
