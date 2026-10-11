# ACT primary inspection — Task99, Task100 checker fix

The compact archive is **staged on xbd**, at
`/home/vick/rvv-task99/act-primary-task100.tar.gz`. Publication and a verified
download remain pending. This page is not a payload download link.

Local review receipts: [archive manifest](MANIFEST.json),
[clean extraction](CLEAN_EXTRACTION.json),
[offline acceptance](OFFLINE_ACCEPTANCE.json),
[wrong-result rejection](REJECTION_CHECK.json),
[source-chain example](SOURCE_CHAIN_SAMPLE.json),
[license summary](LICENSE_SUMMARY.json), and
[existing archive review](EXISTING_ARCHIVE_REVIEW.json).

The package preserves clean961 Task53's 1,876 new all-arm PASS cases (7,504
DUT calls), two original reference-error cases, 3,756 primary reference receipts,
two diagnostic QEMU repeats, and 215 prelaunch adapter exclusions. These are
different units. The 41 exact-source aliases to 164 Task49 receipts carry source
and alias metadata only; Task49's earlier 416 receipts, other candidates and
other suites are outside this package. Original accepted sets and counts are
reused; packaging adds no instruction-form coverage or execution.

After obtaining the staged archive through an authorized Release upload, inspect
it in a fresh directory on a machine with Python 3.9+ and its standard library:

```sh
mkdir act-primary-inspection
tar xzf /path/to/act-primary-task100.tar.gz -C act-primary-inspection
cd act-primary-inspection
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_rvv_act_inspection.py .
PYTHONDONTWRITEBYTECODE=1 python3 tools/check_rvv_act_rejection.py .
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_rvv_act_inspection.py . --form vaadd.vv --case Vx8-vaadd.vv-00
```

Acceptance requires Python assertions enabled: do not use `python -O`,
`python -OO`, or a nonzero `PYTHONOPTIMIZE`. These modes remove required
host acceptance checks. Both the executable and imported `verify(root)` entry
explicitly reject when `__debug__` is false, before reading payload files or
reporting PASS. Normal checks and original source predicates are unchanged.
Task100 refreshes only the delivery verifier, this README and `FILES.json`;
all original source, signature and raw bytes remain identical. The previous
Task99 archive remains at `/home/vick/rvv-task99/act-primary-task99.tar.gz`.
Its previous identity is SHA256
`87d603fb1300cbe8331d5e28ddc48443d702ff1c7e31b892d69b0975bd0c557a`,
334,468,555 bytes; it is historical payload, not the current checker delivery.

`FORMS.json` selects indices into `CASES.json`. `NAVIGATION.json` joins the exact
form, case, arm, ledger row, checker, oracle and raw directory. The selected
original `SUITE_RUN_MANIFEST.csv` (15,364 rows) and
`ACTUAL_FORM_VALIDATION_BINDINGS.csv` (7,512 bindings) preserve all original
fields; eight bindings are unlaunched BLOCKED arms, not executed receipts.
`PATHS.json` translates historical source/raw locators to included files.
Unknown configuration dimensions remain unknown.

For a primary case, follow its unchanged `.S` to the retained capture `.sig`,
original `sig_modify.py`, processed `.results`, `ORACLE.json`,
`PRESERVATION.json`, `SCOPE_AUDIT.json`, original `signature.h`, and
`raw/{compile-reference,sail-signature,compile-user,qemu-selfcheck,DUT-*}/`.
Each raw directory retains its original command, exit/timeout, stdout/stderr and
engine identity records. `common/upstream/env/` preserves original headers;
`common/user_env/` and `user_link.ld` preserve the historical Linux-user adapter.
`ADAPTER_DELTAS.json` and `deltas/` expose differences without changing either.

Verification checks retained identities/navigation, runs the original signature
processor on a temporary copy of each frozen capture and compares it byte for
byte with the archived results, then applies the **original Task53 audit
predicates** to raw text and exit codes. Only those pure predicates are extracted
from `audit.py`; its runner is never imported or executed. The deliberately wrong
result controls alter raw text in memory and reject through the original
predicate, without invoking a hash gate or changing archived files.

This is offline evidence inspection. The original RVV `signature.h` assertions
ran inside the archived guest campaign; this host checker does not independently
recompute architectural results. BASE element0/bit0, LEN selected regions and
tail allowances, selected CSR/flags/scalar predicates, correlated target/checker
risk, static cross-owner read warnings and unobserved optimized-path admission
remain as recorded. `vfmv.f.s` QEMU SIGILL errors and eight unlaunched DUT arms
are retained. Four unresolved profile obligations and 228 grid exclusions are
preserved, with no new expected values or inferred coverage.

`DEPENDENCIES.json` distinguishes included inspection dependencies, outside prior
receipt chains and deliberate live-replay omissions. `EXCLUDED_IDENTITIES.json`
names the exact excluded original files and recorded hashes. Toolchains, Sail/QEMU/DUT
executables/libraries, all guest/capture ELFs/objects, full generation-only
packages, unrelated/restricted generator vectors and the historical full-ledger
snapshot are excluded. This archive does not support complete live replay.

Read `NOTICE.md`, `LICENSE_AUDIT.json` and `licenses/`. Original author/SPDX
notices and bytes remain intact: ACT Apache-2.0/BSD-3-Clause, upstream CC-BY-4.0
documentation/configuration/testplan terms, and UDB generated-header
[BSD-3-Clause-Clear](https://spdx.org/licenses/BSD-3-Clause-Clear.html) are retained
separately. Files without an individual SPDX marker retain upstream's licensing
statement and both code license texts; no entire-package relicensing is claimed.

Repo tools: [packager](../../../scripts/package_rvv_act_inspection.py),
[offline verifier](../../../scripts/verify_rvv_act_inspection.py),
[wrong-result controls](../../../scripts/check_rvv_act_rejection.py), and
[focused tests](../../../scripts/test_rvv_act_inspection.py).
Main owns thesis/status/email and publication. The launcher owns the completion
signal `rvv-act-safe-checks-20261012-100`.
