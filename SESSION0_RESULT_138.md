# Task138 — complete retained corpus on exact successful Task137 final build

Continued **95e72f5** while main reviews135–137 and prepares delivery. This is a
separate evidence/tooling commit, with no production change, guest compilation,
new reference, expected-answer/checker edit, geometry or method-flag substitution.
No push, issue closure or direct message to main; the launcher signals main.

Every accepted original call receives **fresh Task138 credit** on Task137's final
successful executable **da5209ae488403f3eb2a15af8bf0376df4844eefb46b9525c8a0834f8e3f4d5e**.
Task128/129 executions receive **zero current-build credit**. Their navigation
bindings are reused as unchanged source/checker locators; historical nested
results retain their original attribution.

| Original suite / acceptance class | Fresh Task138 calls | Result |
|---|---:|---|
| CHIPS positive calls | 11,532 | PASS |
| CHIPS registered controls | 212 | PASS, separate from positive instruction credit |
| ACT accepted calls | 7,668 | PASS |
| Ara whole-file calls | 1,888 | PASS |
| Ara TEST_CASE1/2 scoped MAC calls | 16 | SCOPED_PASS, whole_file_pass=false |
| Total accepted queue | **21,316** | **21,316 accepted** |

Original Ara TEST_CASE3/4 failing outcomes and nonzero exits where applicable
remain in the actual streams/observers; none earns whole-file or failed-function
credit. ACT **Vf32-vfmv.f.s** and **Vf64-vfmv.f.s** remain the two original
reference blockers outside the 7,668 accepted calls, retaining original reference
receipts. Earlier excluded Ara/reference/invalid-context cases remain excluded.
No mismatches, crashes, timeouts, runner errors or unattempted accepted calls.

## Same-build pilots, original commands and bounded queue

Used the existing Task129 orchestration, original Task120 CHIPS runner,
Task121 execute109 DUT predicate and unchanged Task122 Ara observers. The only
execution adaptation selects the exact Task137 build and the complete retained
original accepted lists, then pilots one unchanged registered representative
from each suite. [Pilot calls](docs/rvv-validation/host512-task138/PILOT_CALLS.json)
retain complete original call objects. Their receipts earn current-build credit
once; the remaining **21,313** calls are disjoint by canonical sorted-key JSON
of the **full original call**, including ELF/source, flags, arm and acceptance
scope. [Partition](docs/rvv-validation/host512-task138/PARTITION.json) checks the
same-build union equals every original list; no opcode-name subtraction or
quiet corpus shrinkage occurs. The final reporter independently checks the
actual unique receipt union again.

Initial observed xbd load **0.14/0.22/0.33**, cores28–31 **100% idle**. Four total
workers, affinity28–31, nice10, original CHIPS/Ara120s and ACT300s timeouts,
fresh per-call FS/cache and disabled core dumps. No global setting changes.
The scheduler permits at most four in-flight calls and preserves/stops a failing
suite; none failed. Queue streams, original predicates, actual commands and
outputs are retained. All commands retain original guest VLEN and method flags.

| Method arm | CHIPS positives | CHIPS controls | ACT | Ara whole-file | Ara scoped | Total |
|---|---:|---:|---:|---:|---:|---:|
| B | 2,883 | 53 | 1,917 | 472 | 4 | 5,329 |
| M1 | 2,883 | 53 | 1,917 | 472 | 4 | 5,329 |
| M2 | 2,883 | 53 | 1,917 | 472 | 4 | 5,329 |
| BOTH | 2,883 | 53 | 1,917 | 472 | 4 | 5,329 |

B is the retained baseline; M1/M2/BOTH are the original vector-run,
active-VL-bound and combined arms. No arm is inferred from opcode names or
changed to force native/helper admission. [Machine summary](docs/rvv-validation/host512-task138/combined/SUMMARY.json)
retains suite/method counts and actual guest VLEN command settings.

## Exact build, configured widths and observed limits

Reused **xbd:/home/vick/rvdbt-goldens-task137/current/build/** without rebuilding.
Library **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**.
Prelaunch binary hashes and actual Release/host512 cache observations are retained
in [prelaunch notes](docs/rvv-validation/host512-task138/PRELAUNCH_CHECKS.md).
Before/after and per-call binary/library pins match. Input/runner hashes are
checked before dispatch and after collection; all original predicates and
expected values remain unchanged.

[DURING](docs/rvv-validation/host512-task138/CONFIGURATION_DURING.json) and
[AFTER](docs/rvv-validation/host512-task138/CONFIGURATION_AFTER.json) independently
check actual cache and **53 production/executable commands, 52 C++**, including
elfrun (Task137's 52/51 audit counted archive/shared commands only). Every
selected C++ command uses **-DRVV_HOST_CHUNK_BITS=512 -mavx512f -mavx512bw -O3
-DNDEBUG**. All **297 compiled-source inputs** authenticate against Task137's
source revision **58c9612**, and [current source equality](docs/rvv-validation/host512-task138/SOURCE_CURRENT_EQUALITY.json)
finds zero differences against **95e72f5**. Every one of **5,325 distinct guest ELFs**
is little-endian **RISC-V ELF32**. Actual rv32-engine inputs therefore establish
XLEN32; **ELEN64** is the authenticated compiled implementation constant, not a
new runtime tuple census. Actual `RVV_STATS` observations retain
**chunk_bytes=64** for all **7,668 ACT /1,904 Ara** receipts, separately from
cache/compile evidence. CHIPS prints no `RVV_STATS` in its unchanged calls; its
per-receipt observed width remains **UNKNOWN**, with host512 established by the
authenticated build configuration. Snapshot phases are
retained literally and never relabeled as prelaunch data.

Guest VLEN is an actual command setting, distinct from host chunk width. Source
SEW/LMUL/requested VL/mask/tail/vstart literals and assertion windows remain
source evidence; missing runtime dimensions remain **UNKNOWN**. Original checker
completion is not a complete architectural-state capture or proof that every
source opcode affected its endpoint. Enabled switches and aggregate counters
are not a current per-target native census. Task128's target-specific native,
scalar and helper observations remain historical evidence on their original
executable. Task135/136/137 focused checks retain their own build/receipt scope
and add no external call credit here.

## Final per-form/source/checker/result navigation

[Reader instructions](docs/rvv-validation/host512-task138/README.md),
[per-form table](docs/rvv-validation/host512-task138/combined/FORMS.md) and compressed
navigation resolve **one fresh receipt for every original call**, with current
commands/results/stream hashes, remote/local raw paths, original complete calls,
source/assertion/checker bindings and source vs observed configuration.
Checked forms: **CHIPS595, ACT590, Ara422; union595**. CHIPS controls receive no
positive form credit. All 16 scoped MAC acceptances remain explicitly scoped.

The reporter reuses the existing128/129 binding machinery. CHIPS geometry/setup/
assertion context files are unchanged authenticated literal copies. ACT retains
original literal signature-checker sites and frozen expected words. Ara retains
original metadata/assertions/adapter bindings and current stdout/observer bytes;
the reviewed three canonical reduction B joins with empty historical checked-form
fields remain unchanged. Two ACT original reference blockers remain accessible
through every selected navigation result.

[Original-predicate audit](docs/rvv-validation/host512-task138/AUDIT.json) verifies
complete original-call membership, normalized flags, executable identity, all
receipt/stream/file hashes, original CHIPS classification, original execute109
ACT DUT predicate and unchanged Ara observer details. The source audit freshly
authenticates **2,934 original CHIPS sources**, zero unresolved sources/differences.
No source, adapter or DUT failure required repair; no old-build credit was
promoted or needed invalidation. Existing four evidence-control and ten
scope-reporter tests pass. Current VADD, configuration-literal and scoped-MAC
selections resolve to fresh receipts. The first navigation spot-check had an
incorrect expectation about the arithmetic source belonging to the separate
configuration-literal supplement; [attempts](docs/rvv-validation/host512-task138/ATTEMPTS.md)
retain its disposition, with zero guest/reference executions and no reporter/oracle
change. Python syntax and `git diff --check` pass.

## Reproduction and retention

Exact invoked execution/collector scripts, launch output, actual per-call
commands, pilots, full original queues, same-build partition, configuration
snapshots, source/input pins, current streams/observers and TB dumps are retained.
Full work/cache and original observer dependencies remain remote unchanged.

```sh
# Original launch; a replay requires a new, nonexistent output root:
ssh xbd 'taskset -c 28-31 nice -n 10 python3 /home/vick/replay_retained_task138.py /home/vick/rvdbt-host512-task138'
# Read-only original-predicate audit:
ssh xbd 'python3 /home/vick/collect_retained_task138.py /home/vick/rvdbt-host512-task138'
# Offline navigation audit with the separately downloaded raw present:
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py --host512-corpus docs/rvv-validation --host512-task138-build --output /tmp/task138-audit
# Resolve exact form/source/checker/result records:
python3 scripts/rvv_scope_report.py --host512-corpus docs/rvv-validation/host512-task138/combined/navigation.json.gz --form vadd.vv --suite chips --arm B --output /tmp/task138-vadd
```

Remote raw: **xbd:/home/vick/rvdbt-host512-task138/**. Independent local raw:
**/home/user/research/materials/task138-host512-raw-20261013/**. Archive identity,
transport registry and complete local manifest audit are retained alongside the
navigation. Archive **100,514,028 bytes**, SHA256
**8aa6ddb625a3b4bf3c3687316239cae50d45b51d6d4c687290497e3eacc33307**.
[Independent local raw audit](docs/rvv-validation/host512-task138/LOCAL_RAW_AUDIT.json)
authenticates **137,509 files**, zero differences. One successful transfer,
zero transport failures. The exact invoked snapshots remain in raw; the repository
replay script subsequently clarifies only its inherited introductory build/task
labels. Its executable pin, call selection, original runners and predicates are unchanged.

This completes the finite retained normal corpus on the exact final executable.
It does not establish every ISA/state/suppression/agnostic-history/overlap geometry,
concurrent mapping/backing lifetime, arbitrary live/pinned-value recovery, native
unexpected-fault ownership for LLVM/optional gather/unannotated paths, or complete
SIMD publication/commit recovery. Task135/136's bounded signal-code/backing/fault
limits remain. No new fault/restart tests, performance campaign or optional-feature
expansion ran. No guest handler return, mapping repair, same-PC retry,
P4-04/equivalent or new reference. **Guest restart is NOT verified.**
