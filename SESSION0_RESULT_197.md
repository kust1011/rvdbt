# Task197 — fixed192 final-build correctness replay

**PASS_FINITE_SCOPE: the scoped fixed192 replay is complete.** All 102 directed
entries and every requested supplement passed execution and independent audit.
There are **zero pending units and zero new DUT failures**. The original external
exclusions remain unchanged.

Started at `4ad13da7a0a973623e8e51c683b2328bfba47f1b` in
`/home/user/research/materials/rvdbt-final197`. The only DUT is the unchanged
`xbd:/home/vick/rvv-long-task192/build/bin/elfrun`, SHA256
`908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4`.
Its adjacent library remains
`79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
No production build, ELF rebuild, reference execution or golden regeneration
has been performed. Historical DUT results receive no new-build credit.

Read delivery-task182 and accepted179/181/180 manifests and runners. The
original Task181 plan SHA256 is
`6a57de0fb7c149ea865a62a27055db1a438610336fa6bb34b9c185e91e6ad929`.
Only its build field changes; selectors, flags, original sources, frozen ELFs,
references and predicates remain unchanged. One complete existing unit passed
the initial pilot with eight checks across B/M1/M2/BOTH; the queue continued
without waiting for main. Later successful units are skipped from receipts.

The full ordinary queue completes **102 entries / 380,968 new DUT commands
/ 12,069,048 positive checks / 595 finite forms**. Every entry's actual audited
form counts equal its frozen selection; the combined 595-form result has 2,256
additional focused positive checks, with 592 focused denial controls separate.
The entire replay executes **407,816 unique new DUT commands**, including the
supplements below. No historical DUT result is relabeled as a new execution.

The [final result](docs/rvv-validation/final-task197/RESULT197.json),
[595-form CSV](docs/rvv-validation/final-task197/PER_FORM_RESULTS.csv),
[compact form data](docs/rvv-validation/final-task197/PER_FORM_RESULTS.json.gz),
[102 entry receipts](docs/rvv-validation/final-task197/ENTRY_RECEIPTS.json.gz),
and [exact plan join](docs/rvv-validation/final-task197/PLAN_JOIN197.json)
identify the new build and actual checked totals. The full exact unit/arm ledger
remains outside Git at both `xbd:/home/vick/rvv-task197/compact/` and
`/home/user/research/materials/task197-fixed192-raw/compact-final/` as
`DIRECTED_UNIT_STATUS.json.gz`: 380,968 execution PASS and 380,968 audit PASS,
with no pending units. The [final status](docs/rvv-validation/final-task197/STATUS.json)
contains the compact counts and runner identities.

The supplements are complete and independently audited on fixed192:

| Supplement | New DUT commands/checks | Result |
|---|---:|---|
| CHIPS | 11,744 calls | 11,532 positives +212 original controls |
| ACT | 7,668 calls | PASS; two original reference blockers excluded |
| Ara | 1,904 calls | 1,888 whole-file +16 TEST_CASE1/2-only scoped passes |
| Focused memory/configuration | 2,848 checks | 2,256 positives +592 original denial controls |
| Full original177/180 trace0 sequence matrix | 2,640 commands /9,672 DUT checks | PASS |
| Original179 focused trace1 sequence matrix | 44 commands /216 DUT checks | PASS |

The original177 v2 actual-path auditor passes **30,456 target-PC/arm rows,
1,824 multi frames /1,472 native-executed frames** for full trace0. Focused trace1
passes 680 rows / 94 frames / 90 native-executed frames. One-pass controls reject
543,840 mutations and accept 2,973 actually changed legal-tail outcomes over
12,360 acceptance observations, including 2,472 reference validation observations
over 2,418 distinct original reference cases. These are packet rereads, not new
reference executions or extra unique DUT checks. Full trace1 is not claimed.
All sixteen new Ara scoped stdout hashes equal
the retained179 failure-payload hashes; TEST_CASE3/4 exclusions remain unchanged
for session3. The ACT blockers remain `Vf32-vfmv.f.s` and `Vf64-vfmv.f.s`.
[Exact exclusion/payload joins](docs/rvv-validation/final-task197/EXTERNAL_EXCLUSIONS197.json)
retain their identities and explicitly deny whole-file credit for the 16 scoped calls.

Budget was calculated before execution: 18,686,681,088 remote free bytes, a
10 GiB reserve, 6 GiB conservative retention allowance and 512 MiB scratch
allowance; local free capacity exceeded 1.2 TB. New output uses the existing
Task181 lossless gzip capture/storage receipts and stdout/packet hardlinks.
Closed successful streams are archived to local capacity after member/storage
hash joins, outer gzip CRC and archive SHA256 verification. Closed per-unit
receipts are separately archived to recover small-file allocation overhead.
**102 stream archives / 1,268,481,031 bytes and 102 metadata archives
/ 1,822,408,989 bytes** pass final size/SHA256 re-verification. The
[retention index](docs/rvv-validation/final-task197/RETENTION_VERIFIED197.json)
maps every archive to its entry. Full member ledgers stay outside Git; no giant
duplicated packet directories or historical input copies are made.

Raw remains at `xbd:/home/vick/rvv-task197`; verified archives and full member
ledgers remain outside Git at
`/home/user/research/materials/task197-fixed192-raw`. Failed transfer captures,
interrupted snapshots and setup receipts remain retained. The first focused
launch stopped at a build-path assertion before any guest; only its H-relative
179 path binding was corrected. The inherited launcher overwrote that initial
focused log on resume; `SETUP_ATTEMPTS.json` transparently preserves the error
as a transcription of the original tool response. No DUT failure is inferred.

SSH interruptions stopped initial controllers and later packaging/polling.
Complete same197 receipts were rechecked without guest reruns. Detached
supervision now persists start/exit/log receipts, and an active matching
supervisor is reused on resume. Large receipt uploads use the accepted181
compressed-metadata receiver with bounded transport retries. Packaging retries
do not rerun guests, references or builds.

All jobs use nice10 and inherited affinity. Initially predicates shared two
slots; after all supplement queues finished, the 32-CPU host at load 4.46 with
34.97 GB available memory justified eight directed checking workers under the
user's eight-worker authorization. Predicates were not changed. The final
4,042 resource samples show own/shared guest peaks of 8/8, own nice10,
and minimum free space of 12,844,666,880 bytes (12.0 GiB). Sparse sampling is not continuous
occupancy proof. Guest admission and stream capture enforce the disk reserve.
The [final source/resource seal](docs/rvv-validation/final-task197/FINAL_SEAL197.json)
records the immutable binary/library, resource-journal and source hashes.
Retained accepted181 raw runner snapshots were used and pinned; they are not
assumed byte-identical to the checked-in orchestration wrappers. Their hashes
remain unchanged since preparation, and the external driver matches the
accepted181 tool receipt. Core directed checker/data pins are verified before
and after each stage. Sequence dependency hashes are additionally sealed
post-run, without claiming that this is a new execution.

The [replay entry](scripts/rvv/replay197.py),
[detached supervisor](scripts/rvv/supervise197.py),
[sequence entry](scripts/rvv/sequence197.py), and
[collector](scripts/rvv/collect197.py) retain the frozen checker machinery.
[Retention/replay notes](docs/rvv-validation/final-task197/README.md) describe
the exact namespaces and receipt protocol.

No service-blocked P4-04, handler repair-return, mapping repair or same-PC retry
workflow is attempted. No new recovery test, Linux/LLVM/performance project,
thesis edit or push belongs to this task. Reserved declarations and original
external exclusions remain intact. Finite matrices do not prove complete RVV
conformance or arbitrary per-target optimization admission.

The compact packet, replay scripts and this report are committed locally.
`tmux wait-for -S rvv-review197198` and `tmux wait-for -S rvv-final197` are sent
after that owned commit. No push is performed.
