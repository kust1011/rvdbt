# Task122 — current production original Ara regression

Completed the full retained accepted Ara scope from clean `3e7a336` on current
production. **1,904 eligible calls completed: 1,888 whole-file PASS and 16 MAC
scoped acceptances; checked union422 in every arm.** New eligible mismatch,
crash, timeout, runner error and unattempted: **0/0/0/0/0**. No production fix,
reference execution, compilation, golden regeneration, performance/global change,
push or issue closure. Launcher owns completion signaling.

| Original arm | Eligible calls | Whole-file PASS | MAC scoped acceptance | Checked forms |
|---|---:|---:|---:|---:|
| B | 476 | 472 | 4 | 422 |
| M1 | 476 | 472 | 4 | 422 |
| M2 | 476 | 472 | 4 | 422 |
| BOTH | 476 | 472 | 4 | 422 |
| Distinct eligible calls / union | 1,904 | 1,888 | 16 | 422 |

## Exact accepted queue and preserved failures

Derived the accepted queue from the retained Task90 navigation/bindings, original
Task48 CONFIGS/SELECTED/CASES, Task51/52 CASES/GROUPS/CONFIGS, reviewed Task82–86
and Task89 manifests, original receipts and original observers. Every final source,
adapter, ELF, selector, command, metadata and original predicate was authenticated.
The queue has **476 distinct ELF/VLEN groups × four arms**, with **no difference
from recorded422**. It reuses original flags and 120-second timeouts. Actual VLEN
call counts: 128=12, 256=20, 512=44, 1024=1,708, 2048=88, 4096=32.
These settings are not a claim of Cartesian source/runtime coverage.

| Original receipt producer | Eligible calls |
|---|---:|
| Task48 campaign | 368 |
| Task51 source scopes | 48 |
| Task52 remainder, including original reduction B and scoped MAC | 143 |
| Task82 missing reduction arms | 9 |
| Task83 reviewed legacy macro scopes | 16 |
| Task84 extracted FP32/64 blocks | 120 |
| Task85 accepted blocks | 980 |
| Task86 reviewed corrected-context blocks | 64 |
| Task89 extracted original blocks | 156 |

`context_original_vredsum`, `context_original_vwredsum` and
`context_original_vwredsumu` have B receipts in Task52 and M1/M2/BOTH receipts in
Task82. The canonical Task52 B rows have empty checked-form cells; their exact
accepted full-file form bindings come from the reviewed Task82 compact evidence.
All twelve slots were newly executed on current production.

`batch_vmacc`, `batch_vmadd`, `batch_vnmsac`, `batch_vnmsub` retain original
**TEST_CASE1/2 acceptance and TEST_CASE3/4 RESULT_MISMATCH**, including nonzero
original returncodes and incomplete original element comparisons. Their sixteen
calls are **SCOPED_PASS**, with whole_file_pass=false. The failed functions receive
no PASS credit; no source or expected values were repaired.

[Original dispositions](docs/rvv-validation/current-production-task122/ORIGINAL_DISPOSITIONS.json.gz)
preserve complete original reserved-input/no-oracle/source inventories,
invalid-context records, reference failures and review classifications separately.
The canonical excluded rows remain 86 clean961 original failures/blockers,
80 clean961 invalid-context rows and 14 other-candidate failures/blockers; these
are binding rows, not new calls. Task85's sixteen stale FP context programs remain
invalid; its `upstream_block_vfwadd_TEST_CASE5_e32_b2` and
`upstream_block_vfwadd_TEST_CASE6_e32_b2` remain failed/blocked. Task86's already
reviewed accepted artifacts were replayed unchanged.

The eight preliminary Task89 reference failures remain outside the queue:
`extracted_vmacc_TEST_CASE3/4`, `extracted_vmadd_TEST_CASE3/4`,
`extracted_vnmsac_TEST_CASE3/4`, `extracted_vnmsub_TEST_CASE3/4`. Their original
incompatible-e64 histories and raw identities are retained, with no new reference
or DUT retries of those failed builds. Source-only `vfwadd.wv`, `vnsra.wv`,
`vnsrl.wv`, `vssseg3e8.v`, `vssseg3e32.v` remain outside accepted422.
No P4-04 or equivalent blocked retry was executed.

## Launcher correction and all actual attempts

The first dispatch contained a queue-join error affecting four vaaddu slots.
Task48 RAW_MAPPING coalesces vaadd/vaaddu under the same vaadd output root; joining
CONFIGS by that root selected vaadd metadata/ELF for vaaddu. The first incorrectly
joined ELF hash was `ef78f431b278f70a24c6285c662c6a355a4b32d3dbe983334afc02ffc527510a`.
The original vaaddu ELF is
`3bef540040c9d436724cc4a99976189ea93f6cfcbc84675d508d42d42b67091c`.

Preserved the first queue and all four incorrect calls **without vaaddu credit**.
Corrected the CONFIGS join by original source case, required exact canonical ELF
binding equality for every final cell, rechecked every original receipt, then ran
only the four original missing vaaddu arms. All four pass. Therefore the exact
accounting is **1,908 actual guest attempts = 1,904 eligible calls + four retained
QUEUE_JOIN_ERROR calls**. Original tests/answers and production remain unchanged.
[QUEUE_CORRECTION.json](docs/rvv-validation/current-production-task122/QUEUE_CORRECTION.json)
contains the exact old cells, corrected ELF, affected IDs and preserved raw paths.
Both queue versions, launcher versions/content hashes and dispatch streams remain
in the raw root. This was a receipt/launcher correction, not a DUT defect.

Other prelaunch setup corrections had zero guest calls and are recorded in
[SETUP_ATTEMPTS.json](docs/rvv-validation/current-production-task122/SETUP_ATTEMPTS.json).
Remote preflight rejected a missing local orchestration script and a rounding
runner-copy case-filter difference before any dispatch. Staged exact hash-verified
retained original observer dependencies inside the new root, leaving original
remote files unchanged. Original parser acceptance code is reused.

## Production equality and execution

Compared 282 tracked dbt/build inputs at HEAD with retained Task118 source.
Only Task119's `dbt/qmc/llvmgen/rvv_llvm_wholereg_mem_test.cpp` differs; production
matches. `ninja -C build -n elfrun` reports no work to do. Used the existing
Task118 executable only after confirmation. Executable SHA256:
`533443050f4d1ad4dc49ca74f3e5ac4ca1ccc576f2b107d3771412a218ac3e31`;
library SHA256:
`1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d`.
Before/after pins match every actual attempt and the completed queue.

Load immediately before full dispatch: **0.14/0.24/0.57**; before affected-only
dispatch: **0.38/0.66/0.70**. Used bounded four workers, nice10, cores28–31,
fresh per-call FS/cache, original complete flags and **120-second timeouts**, with
process-group cleanup on timeout. No global settings or performance execution.

## Per-form assertions, receipts and verification

Extended the existing `rvv_scope_report.py` via `--ara-replay`, reusing original
producer observers. [Scope](docs/rvv-validation/current-production-task122/scope.json.gz)
joins all 627 navigation forms to actual current call/source/assertion locators;
[receipt CSV](docs/rvv-validation/current-production-task122/replay-receipts.csv.gz)
has exactly 1,904 eligible rows. Historical navigation remains separate.

[Comparison records](docs/rvv-validation/current-production-task122/comparison.json.gz)
retain original expected element literals, CSR/scalar checks, long-checker arrays,
and complete original source/compiled adapter text. [Runtime observations](docs/rvv-validation/current-production-task122/observations.json.gz)
retain original observed VL/vtype/assertion completion, actual/expected CSR/scalar
values where emitted, exact Ara89 initialization/configuration checks and MAC
function spans. Vector equality completion does not provide a separate complete
actual-element snapshot. Source setup remains context, not dynamic coverage or
optimized target admission. [Reader instructions](docs/rvv-validation/current-production-task122/README.md)
show concrete form selection and an offline audit command.

The final reader audit verifies every frozen original input, canonical case/ELF
binding, original assertion metadata, actual normalized command, timeout,
candidate pins, stream hashes and recomputed original predicate. Eight focused
controls reject changed candidate/assertion/ELF and tampered/missing streams,
preserve consistent failed-checker/timeout results without PASS credit, and retain
MAC whole-file failures as scoped acceptance. Ten existing reporter tests pass;
`git diff --check` passes. Controls execute no guests or references.

## Retention and remaining obligations

Full new remote raw: **`xbd:/home/vick/ara-current122/raw/<id>/`**.
Local retained raw: **`/home/user/research/materials/ara-current122-raw-20261012/`**.
Archive: **15,047,019 bytes**, SHA256
`301fdc011baf9be0f147d881128060f1c084f0df05ec85a572cf60cb8d4529ba`.
Transport attempts/failures: **1/0**. All 1,908 attempt receipts are retained;
work/cache and staged observers remain remote, with original observer archive
also retained locally. First `tar .` warned about root-directory change while
creating its archive; the final explicit-operand archive exited zero. No raw
mutation occurred. [Transport](docs/rvv-validation/current-production-task122/transport.attempt1.json)
and [local raw audit](docs/rvv-validation/current-production-task122/LOCAL_RAW_AUDIT.json)
bind the archive and every attempt stream/identity. Final local audit outputs and
concise committed receipts are retained separately from the transport snapshot.
Old raw, references and performance artifacts remain unchanged.

These original tested data validate current production's accepted Ara422 scope.
They do not establish complete architectural state, access suppression, agnostic
history, all overlaps/configurations, per-PC optimized admission, general precise
fault cause/address/restart, concurrent mappings, unexpected native host faults,
complete handler/return/restart, reordered CCRF faults or non-vector routes.
Original excluded/reserved/reference failures and RV32/ELEN64 profile exclusions
remain separate. Issues remain open. Main can review Task122 while continuing
its ACT audit and the existing unresolved semantic/fault obligations.
