# Task121 — current production ACT db2 regression

Completed the accepted original ACT db2 corpus on current production, from
`5952bf9` without waiting for Task120 review. **7,668/7,668 DUT calls PASS**;
failed, crashed, timed-out, runner-error and eligible-unattempted calls:
**0/0/0/0/0**. No production correction, reference execution, generator,
compilation, performance run, global setting change, push or issue closure.
Launcher owns the completion signal.

| Original accepted configuration | Files / calls | PASS | Fail / timeout / eligible-unattempted | Checked forms |
|---|---:|---:|---:|---:|
| B | 1,917 | 1,917 | 0 / 0 / 0 | 590 |
| M1 | 1,917 | 1,917 | 0 / 0 / 0 | 590 |
| M2 | 1,917 | 1,917 | 0 / 0 / 0 | 590 |
| BOTH | 1,917 | 1,917 | 0 / 0 / 0 | 590 |
| Total distinct new calls | 7,668 | 7,668 | 0 / 0 / 0 | 590 union |

## Exact denominator and fixed original answers

Derived the denominator from original `EXACT_QUEUE.json`, retained Task110/111
package/navigation and sealed Task104 records: **1,919 outputs = 1,916 Task109
accepted + one Task104 accepted reuse + two original reference blockers**.
`Vls32-vluxei32.v` is newly run in all four arms here, rather than relabeled old
acceptance. All 1,917 applicable accepted files ran; queue remaining is zero.
Accepted source-SEW file counts: e8=399, e16=437, e32=568, e64=513.
Actual settings retain XLEN32, ELEN64, VLEN1024 and complete original arm flags.
Source SEW/LMUL/VL/mask/tail context does not establish runtime Cartesian coverage.
Counts were printed in `queue-prelaunch.stdout` before launch and in launcher
stdout before dispatch; [QUEUE.json.gz](docs/rvv-validation/current-production-task121/QUEUE.json.gz)
retains every original command and binding.

`Vf32-vfmv.f.s` and `Vf64-vfmv.f.s` remain distinct whole-file reference-platform
blockers, originally QEMU SIGILL at `csrrc zero,mstatus,t1`, PCs `0x80005d20`
and `0x8000738c`. **Two blocked files / eight withheld arm slots; zero new calls**.
They are outside the 7,668 eligible-call denominator, and are neither PASS nor
unattempted eligible work. Their tested FS-state setup, checker, source and
original failed references remain intact. No P4-04 or equivalent blocked retry.

Original Sail captures, processed expected values, same-ELF QEMU receipts,
adapters, original `signature.h`, ELF bytes and original acceptance expressions
were reused as fixed evidence. No fresh reference execution or expected-answer
regeneration is claimed. Prelaunch checks verified all source/checker/capture/
expected hashes and every ELF's embedded signature bytes. Postrun audit matched
retained originals, package/full-raw hashes and Task104 seal again.

## Production equality and execution

Compared 282 tracked dbt/build inputs at HEAD with retained Task118 source.
Only Task119's `dbt/qmc/llvmgen/rvv_llvm_wholereg_mem_test.cpp` differs; production
matches. `ninja -C build -n elfrun` reports no work to do. The Task118 executable
was used only after this confirmation. Executable SHA256:
`533443050f4d1ad4dc49ca74f3e5ac4ca1ccc576f2b107d3771412a218ac3e31`;
library SHA256:
`1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d`.
Before/after pins match for every call and the completed queue.

Initial xbd load: **1.27/0.93/1.11**. Used bounded four workers, nice10, cores28–31,
fresh per-call FS/cache and original **300-second timeouts**, with process-group
cleanup on timeout. Only executable/library and fresh output/work paths change
from original commands; original flags and diagnostics remain. The task-specific
launcher wraps retained commands and original predicates, without a new test
framework or source-case changes. Exact command, launcher, stdout/stderr and
source/build receipts remain in the new raw directory.

One source-equality setup assertion used `qcg` instead of `llvmgen` for the sole
host-test difference. Corrected before executable use; zero guest calls in that
setup attempt. [SETUP_ATTEMPTS.json](docs/rvv-validation/current-production-task121/SETUP_ATTEMPTS.json)
retains the reason. No guest failure or semantic repair occurred.

## Per-form/source and exact comparison records

Extended existing `rvv_scope_report.py` with the ACT db2 receipt join. It
authenticates original package and Task104 seals, source/checker/oracle/ELF
identities, frozen signature words, original complete commands and timeouts,
current before/after candidate pins, stream hashes and original predicates.
All 7,668 receipts pass the audit. Historical Task104/109/110/111 and Task120
receipts retain their own build identities and totals.

[Scope](docs/rvv-validation/current-production-task121/scope.json.gz) retains
all 627 navigation rows, each actual source case, original selector, tested
arm/VLEN, checker counts, comparison and new raw path.
[Receipt CSV](docs/rvv-validation/current-production-task121/replay-receipts.csv.gz)
has exactly 7,668 rows with source/checker/ELF/signature hashes, actual flags,
original/current receipt paths and stream hashes. **Actual db2 tested union590**
is distinguished from the broader existing historical union595. This corpus does
not check `vfmv.f.s`, `vfwcvt.f.f.v`, `vsetivli`, `vsetvl` or `vsetvli`.

The raw root's `comparison.json.gz` preserves all exact frozen expected signature
words and original corrected checker scopes for all 1,919 outputs, with blockers
labeled separately by the queue. Tested files contain **52,804,952 expected words**,
including reserved/padding data; this is not a dynamic assertion count.
`comparison-sites.json.gz` preserves **1,393,130 literal source checker sites**
across the complete original inventory, with original line numbers and destination/
CSR arguments. Sites and signature words are authenticated against originals.
Original BASE checks selected destination elements/bits; LEN preserves original
active/masked/tail and allowed agnostic alternatives; FFLAGS/VXSAT retain original
CSR predicates. No fresh complete actual-state snapshot is claimed.

The original Task109 compiled macro counts remain 669,484 BASE, 114,729 LEN,
89,449 FFLAGS, 21,628 VXSAT and 1,494 scalar sites; Task104's separately retained
scope has 190 BASE and 25 LEN source sites. Static counts are not dynamic assertion
counts. The existing reader and all-form navigation now link the Task121 receipt
and comparison records; [reader instructions](docs/rvv-validation/current-production-task121/README.md)
show concrete form/source selection and the audit command.

Six focused controls reject changed candidate/answer, tampered stream and missing
raw, and preserve a consistent failed checker or timeout without PASS credit.
Ten existing reporter tests pass; `git diff --check` passes. Controls execute no
guests and do not alter the real receipts or expected values.

## Raw retention and remaining obligations

Full new remote raw: **`xbd:/home/vick/act-current121/raw/<source-case>/<arm>/`**.
Root includes queue, launcher, identities, load/build/equality receipts, exact
comparisons, audit outputs and controls. Local retained raw root:
**`/home/user/research/materials/act-current121-raw-20261012/`**.
Archive: `receipts.tar.gz`, **114,839,753 bytes**, SHA256
`b91c736021f499123082c8f6298b387dc04b5f63ba3a1008e404049df1c87e28`.
Transport attempts/failures: **1/0**. Downloaded archive retains command/result/
stream/identity files, TB diagnostics, comparisons and tooling; per-call work/cache
and control copies remain remote. Old raw and original performance untouched.
[Counts and identities](docs/rvv-validation/current-production-task121/COUNTS.json)
and [transport receipt](docs/rvv-validation/current-production-task121/transport.attempt1.json)
bind these paths and artifacts. [Local raw audit](docs/rvv-validation/current-production-task121/LOCAL_RAW_AUDIT.json)
verifies all 7,668 downloaded receipts and 30,672 stream/identity files.

Task121 validates original tested data on current production. General obligations
remain untested: complete register/CSR/memory state, access suppression, agnostic
history, all overlap/configurations, per-PC optimized admission, general fault
cause/address and restart, concurrent mappings, unexpected native host faults,
complete guest handler/return/restart, reordered CCRF faults and non-vector routes.
Both original FS/mstatus blockers, missing upstream EFFEW32 `vfwcvt.f.f.v`, privileged
vset and the RV32/ELEN64 ei64/optional FP16 profile exclusions remain separate.
No issue is closed. Main audit can review these receipts while Task120 review
continues, then proceed with existing unresolved semantic/fault obligations.
