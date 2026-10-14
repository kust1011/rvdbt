# Task197 fixed192 correctness replay

Completed finite-scope PASS:595 forms,102 directed entries,12,069,048 ordinary
checks,2,848 focused checks,21,316 external calls and9,888 sequence DUT checks.
There are no pending units or new DUT failures. Original external exclusions
remain unchanged. [Result](RESULT197.json), [per-form CSV](PER_FORM_RESULTS.csv),
[entry receipts](ENTRY_RECEIPTS.json.gz), and [retention index](RETENTION_VERIFIED197.json)
are the compact review packet; [SESSION0_RESULT_197](../../../SESSION0_RESULT_197.md)
records counts, limitations and setup/transport history.

Task197 starts at `4ad13da7a0a973623e8e51c683b2328bfba47f1b` and reuses
the accepted Task181 selection, Task179 focused trace matrix and Task180 full
sequence matrix. Historical DUT results receive no fixed192 credit.

The executable is `xbd:/home/vick/rvv-long-task192/build/bin/elfrun`, SHA256
`908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4`.
Its adjacent `lib/libdbtjitshared.so` is pinned to
`79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
Frozen ELFs, original independent references, selectors, flags and acceptance
predicates are reused. There are no builds, golden generations or reference
executions.

Raw execution and full adapted runner snapshots remain outside Git at
`xbd:/home/vick/rvv-task197`. Verified archives and full member/hash ledgers are
under `/home/user/research/materials/task197-fixed192-raw`. Closed successful
streams use the Task181 gzip capture and storage receipts, with stdout/packet
hardlinks. Archives receive tar member hashes, outer gzip CRC verification,
compressed storage-hash joins and archive SHA256 before remote removal.
Closed successful per-unit receipt files are separately archived to avoid
small-file allocation overhead. Original inputs and failures remain retained.

The initial budget records 18,686,681,088 remote free bytes, a 10 GiB reserve,
6 GiB conservative retention allowance and 512 MiB scratch allowance. Per-entry
offload reduces the live footprint; guest admission requires at least 11 GiB
free and stream capture enforces the 10 GiB reserve. All jobs inherit nice10
and affinity; no CPU pin is assigned. Shared admission caps own guests at eight.
Initially online/offline predicates shared two slots. After the external,
focused and sequence queues completed, a host with 32 logical CPUs at load4.46 with 34.97 GB
available memory justified eight directed checking workers under the user's
eight-worker authorization. Later directed stages use eight predicate slots
and at most eight worker processes, with unchanged predicates. Resource
sampling does not establish continuous occupancy.

The local entry is [replay197.py](../../../scripts/rvv/replay197.py).
`prepare` authenticates inputs and stages adaptations; `run` resumes directed
stages from receipts; `external-resume` checks existing Task197 captures before
launching pending calls; `stage-sequence` stages the original trace runner and
accepted180 input joins; `finish-supplements` performs missing audits;
`compact-metadata` retains closed receipts losslessly; `verify-retention`
rechecks all204 retained archive sizes/hashes after replay. Accepted raw181
runner snapshots are authenticated against [their pinned hashes](original-runner-pins.json).
The detached
[supervisor](../../../scripts/rvv/supervise197.py) persists command/start/exit
receipts so SSH disconnection cannot itself request another guest execution.
The [sequence entry](../../../scripts/rvv/sequence197.py) uses the original177
actual-path auditor and one-pass corruption controls.

The [collector](../../../scripts/rvv/collect197.py) distinguishes executed,
audited and pending unit/arm IDs. Its full ledgers stay outside Git. Compact
entry/form summaries and archive identities are the review packet; a completion
verdict requires every declared entry and supplement audit.

The initial focused launcher stopped at a build-identity assertion before any
guest because its H-relative path still selected179. Only that binding was
corrected. `SETUP_ATTEMPTS.json` discloses that the original focused log was
overwritten by the inherited launcher on resume; the error was transcribed from
the original tool response. A later SSH interruption stopped directed audit and
external controllers. Complete Task197 receipts were checked and reused once,
with no completed guest rerun. Interrupted runner/lineage snapshots and transport
logs remain in the raw evidence. Detached supervision was added afterward.

Scope retains the two ACT reference blockers and Ara's sixteen
TEST_CASE1/2-only calls, including their TEST_CASE3/4 exclusions, for session3.
Source-reserved declarations retain the original selectors. General precise
restart, service-blocked P4-04, handler repair-return and same-PC retry workflows
are excluded. No Linux/LLVM/performance work, thesis edits, publication or push
belongs to this replay. Finite matrices are not a complete RVV conformance proof.
