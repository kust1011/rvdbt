# Task120 — current-build external form regression

Completed the full retained sealed CHIPS queue on current production, starting
from clean `4ae749fb63c09a53d8e158b51ab97064c4226b40`. No prior commit amended,
production fix needed, push or issue closure. Launcher owns completion signaling.

| Actual configuration | Positive PASS | Control expectation PASS | Checked applicable forms |
|---|---:|---:|---:|
| B | 2,883 | 53 | 595 |
| M1 | 2,883 | 53 | 595 |
| M2 | 2,883 | 53 | 595 |
| BOTH | 2,883 | 53 | 595 |
| Unique call total / form union | 11,532 | 212 | 595 |

**11,744/11,744 calls PASS. Failed, crashed, timed-out, runner-error,
unattempted: 0/0/0/0/0.** No P4-04 or equivalent blocked repair/return/same-PC
retry case was present or executed. No reference run, generator, ELF compilation
or expected-answer regeneration occurred.

## Exact queue and current build

Derived the queue from campaign46 `TASK45_PENDING_FIXED.json` (11,732 calls:
11,528 positives/204 controls) and the original sealed `MANIFEST.json` (11,744).
Added its exact 12 prior sealed cells: four positives/eight controls. These were
new executions on the current build, not relabeled old results. Every executable
cell field matches the retained campaign46 selection; every complete cell in
the new manifest matches the original sealed manifest. Only candidate metadata
changes. Original source/ELF/input/oracle/predicate and complete flags remain.

Printed queue counts and the complete sorted intended union before launching.
[QUEUE.json](docs/rvv-validation/current-production-task120/QUEUE.json) retains exact
IDs, denominator and union. The two additional alias spellings `vmsgt.vv` and
`vmsgtu.vv` do not create new canonical forms; existing navigation/bindings
remain authoritative. Original manifest SHA256:
`ba3cd729f2683d8d9084df4c3e8750081570b1833ee1780de2d7aa47687b6573`.
Campaign46 fixed-selection SHA256:
`e52bb4428c234888005f6dde29d430ff6672be554b192f5b7c90bc6ea9f6a9dd`.

Compared retained Task118 source against tracked HEAD dbt/build inputs. The only
difference is Task119's `rvv_llvm_wholereg_mem_test.cpp`; production matches.
Retained build `ninja -C build -n elfrun` reports no work to do. Equality rows and
build receipt are retained in the [new evidence directory](docs/rvv-validation/current-production-task120/README.md).
Executable SHA256 is
`533443050f4d1ad4dc49ca74f3e5ac4ca1ccc576f2b107d3771412a218ac3e31`;
library SHA256 is
`1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d`.
Both remained unchanged through execution. The campaign46 runner is unchanged,
SHA256 `21f8f068b964c230fe965b1e08e12276f9f109238d3b089d7e22b17a3203c41c`.

Initial xbd load was 0.20/0.27/0.34. Used four workers, nice10, cores28–31,
fresh per-cell fs/cache and original 120-second timeouts/process-group cleanup.
Exact launcher command is retained. No performance testing or global CPU settings.
The entire queue continued through completion without routine permission stops.

## Raw and per-form receipt integration

Full remote raw: `xbd:/home/vick/chips-current120/raw/<cell-id>/`, including work
and cache. Local immutable raw:
`/home/user/research/materials/thesis_rvv_20260921/artifacts/rvv_validation_delivery_20261009/chips-current120/raw/`.
The same root retains manifest, original runner, source equality, launch command,
stdout/stderr, audit and transport receipt. Downloaded archive excludes work/cache:
8,926,032 bytes, SHA256
`928be4630c04d7a2a448c3c3b9d3056ecb5817a589b427a687dc47ce997d29c8`.
Transport attempts/failures: 1/0. Original measurements and old raw untouched.

Extended the existing `rvv_scope_report.py` with `--chips-replay`, rather than
creating another coverage framework. It authenticates the original complete
cells, timeout, invoked manifest/runner, before/after binary identities, each
case/result/stream hash and full argv; recomputes original exit/exact-stdout
classification; and joins original source navigation plus target/checker bindings.
All 11,744 receipts passed this audit. Existing bindings retain their original
configuration knowledge, observer limits and remaining statements.

[Per-form scope](docs/rvv-validation/current-production-task120/scope.json.gz) lists
627 rows, including every applicable form's actual source cases, tested arm/VLEN,
checker counts and new receipt paths. [Receipt CSV](docs/rvv-validation/current-production-task120/replay-receipts.csv.gz)
records full flags, source hashes/selectors and original bindings, with old
candidate/receipt explicitly labeled as prior. Actual checked union is exactly
595, and each arm's union is 595. There are 2,886 positive source-case aliases,
11,544 positive navigation rows and 11,920 total navigation rows; alias rows are
not calls. Actual VLEN settings span 128/256/512/1024/2048/4096. Other dimensions
remain source context or UNKNOWN where no dynamic observation exists.

Ten focused reporter tests pass, including changed-answer, tampered-stream and
candidate-identity rejection, and preservation of a failed checker result without
form credit. `git diff --check` passes. No DUT/reference/adapter execution failure
occurred, so no semantic fix/replay was necessary. One pre-execution setup
assertion stopped on campaign46's presentation-only omission of alias
`original_command`; retained in SETUP_ATTEMPTS.json. The corrected comparison
preserves full original cells and checks executable fields against campaign46.

## Remaining obligations

Task120 queue remaining: zero. Existing original allocation failures (two source
cases/eight arm records) remain excluded with their historical failures; retained
storage replacement fixtures do not close those originals. Supplements outside
this sealed cohort retain their existing dispositions.

595 passing forms do not validate every semantic obligation, full register/CSR/
memory state, memory-access suppression, agnostic history, all overlap cases,
all configuration combinations or per-PC M1/M2 admission. Concurrent mapping
changes, unexpected native host faults, complete guest handler/return/restart,
reordered CCRF precise faults and non-vector memory routes remain as recorded in
Tasks118/119. P4-04 restrictions remain. The 32 ei64 indexed forms are outside the
RV32/ELEN64 profile. Both issues remain open.

Next: main reviews this current-build receipt integration, then continues the
existing unresolved fault/restart and semantic obligations within those restrictions.
