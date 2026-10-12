# Task142 — final host512 regression after signal-copy correction

Started **8111040faad84ded7f84fc5bd34d10461bfc50ca** on
`fix/rvv-memory-families-issue-1`, including reviewed **ad5e3c8** production/test
correction. This task changes only evidence and the existing reader's current-build
selection; production, tests, original inputs, predicates and expected values are
unchanged. Main's earlier checks and every prior build receive **zero current-build
credit**.

The fresh xbd final build and affected host regressions passed. All **21,316**
original Task138 accepted CHIPS/ACT/Ara calls passed their original predicates on
this new executable, including exactly three pilots credited once and the
**21,313** disjoint remainder. No queue was reduced or substituted.

| Acceptance class | Fresh Task142 calls | Result |
|---|---:|---|
| CHIPS positive | 11,532 | PASS |
| CHIPS registered controls | 212 | PASS, separate from positive instruction credit |
| ACT accepted | 7,668 | PASS |
| Ara whole-file | 1,888 | PASS |
| Ara TEST_CASE1/2-only MAC | 16 | SCOPED_PASS; whole_file_pass=false |
| Exact accepted queue | **21,316** | **21,316 accepted** |

ACT **Vf32-vfmv.f.s** and **Vf64-vfmv.f.s** retain the two original reference
blockers, separately outside the accepted queue. Ara's original TEST_CASE3/4
failures and applicable nonzero exits remain in current streams/observer details;
they earn no whole-file or failing-function credit. No mismatch, crash, timeout,
runner error or unattempted accepted call occurred.

Each original B/M1/M2/BOTH arm contains 2,883 CHIPS positives + 53 controls,
1,917 ACT, and 472 Ara whole-file + four scoped calls: **5,329 calls per arm**.
Actual flags/guest VLEN are unchanged. [Partition](docs/rvv-validation/host512-task142/PARTITION.json)
uses canonical sorted-key JSON of the complete original call, including ELF,
flags, arm and scope. The collector and existing navigation independently check
full original equality, uniqueness, pilots and complete receipt union.

## Actual final build and host checks

Fresh isolated source/build root:
**xbd:/home/vick/rvdbt-host512-task142-build/** (`source/`, `build/`, `receipts/`).
Source is exported from exact **8111040**. Build uses
actual Task137 successful **Release / RVV_HOST_CHUNK_BITS=512 / RV32 / ELEN64**
configuration and its pinned **Clang22/LLVM22.1.6** toolchain. No Task137/138
source, build or evidence root was overwritten.

[Source equality](docs/rvv-validation/host512-task142/SOURCE_EQUALITY.json)
authenticates **297** staged source/build inputs against 8111040.
[Dependency equality](docs/rvv-validation/host512-task142/DEPENDENCY_EQUALITY.json)
authenticates **442** retained asmjit/elfio files against successful Task137,
excluding `.git` metadata. [Configuration match](docs/rvv-validation/host512-task142/CONFIGURATION_MATCH_137.json)
checks **44** relevant actual cache options against Task137, zero differences,
and retains compiler executable hashes/version output.

Configure: 180s bound. Build: 900s bound, nice10, affinity28–31, **-j4**.
Initial observed xbd load was **0.08/0.24/0.28**; launch cores28–31 were **100% idle**.
Successful complete build gates all execution, and before/after complete binary
pins match. `ldd -r` for final elfrun succeeds. No configure/build/test failed. The sole early staging-upload failure and its successful pre-build retry are preserved in [prelaunch notes](docs/rvv-validation/host512-task142/PRELAUNCH_CHECKS.md).
Host checks use nice10/core28/60s and disabled core dumps.

| Final-build host regression | Actual result |
|---|---|
| `rv32_signal_interface_test` | rc0; 1,876 parent checks, input child101, output child86; both child statuses0; guest_calls=0 |
| `rv32_signal_frm_test` | rc0; 256 FRM/fflags roundtrips, 192 high-bit badframes; guest_calls=0 |
| `mmu_mapping_metadata_test` | rc0; 27/27 |
| Full `rvv_vector_run_codegen_test` | rc0; ALL CHECKS PASSED, including existing goldens/protocol/rejection checks |
| Existing `--memory-boundaries` | rc0; original 72 pairs /6 extended-family admission cases |
| `rvv_vector_run_admission_test` | rc0; PASS |
| Grouped memory `--normal-only` | rc0; 585 checks, terminal_cells=0 |
| Scalar native `--normal-only` | rc0; 1,919 checks, terminal_cells=0 |
| Whole native `--normal-only` | rc0; 13,330 checks, terminal_cells=0 |

[Host check gate](docs/rvv-validation/host512-task142/TEST_SUCCESS.json) and
[build identities](docs/rvv-validation/host512-task142/BUILD_SUCCESS.json) retain
all target pins. Interface parent/children are separate counts (2,063 combined).
The full codegen test's existing malformed-QIR panic children remain expected
checker tests. The affected host interface test exercises the reviewed direct
copy/syscall/delivery/codec boundary checks; it executes no guest handler.

Final identities:

```
e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b  build/bin/elfrun
79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af  build/lib/libdbtjitshared.so
2478ec5fb09e59b683bb96ac5686784ccef8a04ec52465693fd202737570cfff  build/bin/rvv_vector_run_codegen_test
82f277311ca7e37f9a71235797067a00dcfe94049069f35ca9c8e64f574e9c9a  build/bin/rv32_signal_interface_test
793744920f25a26d7b346322b41369e33506136f66eb7524c0374d33674c7e57  build/bin/rv32_signal_frm_test
295397c71cfcd9bba248e65099bccb5a824255fe526ed03e6457d37def333618  build/bin/mmu_mapping_metadata_test
```

The shared library hash is unchanged because the signal correction is in the
statically linked host interface/ukernel path; the fresh executable and affected
host binaries have their own new pins. Library identity alone earns no credit.

## Exact queue, independent acceptance and navigation

Used Task138's existing replay/collector with only final build/output paths and
new expected binary gate changed. Original Task120 CHIPS runner, Task121
execute109 predicate and Task122 Ara observers are unchanged. Original inputs,
checker/expected/observer bytes and runner hashes are authenticated before
execution and after independent collection. No guest compilation or reference
execution. Four total workers, affinity28–31, nice10, original CHIPS/Ara120s and
ACT300s timeouts, fresh per-call FS/cache, core dumps disabled. The scheduler
stops an affected failing suite and preserves output; no suite failed.

[DURING](docs/rvv-validation/host512-task142/CONFIGURATION_DURING.json) and
[AFTER](docs/rvv-validation/host512-task142/CONFIGURATION_AFTER.json) check actual
cache, **53 production/executable compile commands (52 C++)**, all relevant C++
using `-DRVV_HOST_CHUNK_BITS=512 -mavx512f -mavx512bw -O3 -DNDEBUG`.
All **5,325** retained guest ELF paths (**5,322** distinct SHA256 identities) are
little-endian RISC-V ELF32. ELEN64 is the
authenticated compiled implementation constant. ACT/Ara `RVV_STATS` independently
prints chunk_bytes=64; unchanged CHIPS calls print no stats and their observed
width stays UNKNOWN. Source SEW/LMUL/VL/mask/tail/vstart literals are source
evidence, not inferred runtime tuples.

[Original-predicate audit](docs/rvv-validation/host512-task142/AUDIT.json)
reapplies every original CHIPS classification, ACT execute109 expression and Ara
observer to current raw, checks complete original queue equality and normalized
flags, before/after/per-call pins, stream/result/file hashes and scoped outcomes.
A fresh source audit authenticates all **2,934** original CHIPS sources.
The independent local raw manifest audit, existing navigation audit and
[portable reader reapplication](docs/rvv-validation/host512-task142/PORTABLE_REAPPLICATION.json) are linked from
[reader instructions](docs/rvv-validation/host512-task142/README.md).

The existing Task128/129 binding schema provides
[per-form navigation](docs/rvv-validation/host512-task142/combined/FORMS.md),
current executable pins, complete original calls, actual commands/results,
current remote/local raw paths and literal source/assertion/checker joins.
Checked forms: CHIPS595, ACT590, Ara422, union595. Historical nested bindings
retain original attribution. Aggregate route counters and enabled method flags
are not per-target native admission or full architectural-state captures.
Only a small current-build identity/selection extension was added to the existing
reader; no coverage framework or package was created.

## Raw paths and concise reproduction

Remote current raw: **xbd:/home/vick/rvdbt-host512-task142/**.
Independent extracted local raw:
**/home/user/research/materials/task142-host512-raw-20261013/**.
Raw host receipts: `build-evidence/receipts/{configure,build,interface,frm,mmu,codegen-full,codegen-memory,admission,grouped-normal,scalar-normal,whole-normal}/{command.json,stdout,stderr,rc}`.
Corpus receipts: `chips/raw/ID/`, `act/raw/CASE/ARM/`, `ara/raw/ID/`.
Build/source/binaries and complete FS/cache/observer dependencies remain remote.
The direct-receipt archive preserves streams, observers, TB dumps, queues,
configuration, exact invoked scripts and build/test receipts.
[Transport identity](docs/rvv-validation/host512-task142/TRANSPORT.json) and
[local manifest audit](docs/rvv-validation/host512-task142/LOCAL_RAW_AUDIT.json)
authenticate **137,871 files**, zero differences. The archive is **100,532,961 bytes**, SHA256
**46cd12348780b6147308e8be961c029abd48a49e7fa56cacfaec8ea05ecec582**.
One successful archive transfer, zero archive transport failures.

```sh
# Read-only original-predicate audit on xbd:
ssh xbd 'taskset -c 28-31 nice -n 10 python3 /home/vick/collect142.py /home/vick/rvdbt-host512-task142'
# Offline exact-call/navigation/raw audit; output must be new:
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation --host512-task142-build \
  --host512-raw /home/user/research/materials/task142-host512-raw-20261013 \
  --output /tmp/task142-audit
```

The [short reader recipe](docs/rvv-validation/host512-task142/README.md) also
selects forms and resolves/reapplies original source/checker predicates through
the existing Task139 metadata plus licensed CHIPS94/ACT db2/Ara91 roots.
No new acquisition/packaging project or author-path fallback is needed.
The portable audit authenticates **7,409** source/checker/metadata files and
reapplies CHIPS11,744 /ACT7,668 /Ara1,904 predicates. A
[current `vle32.v` B selection](docs/rvv-validation/host512-task142/SELECTION_CHECK.json)
resolves all ten original records to Task142 raw and retains both ACT blockers.
Existing four evidence-control and ten scope-reader tests pass; Python syntax
and `git diff --check` pass.

No guest handler return/restart, repaired mapping, same-PC retry, P4-04 or
equivalent occurred. No performance/LLVM/optional-feature expansion, expected
value edit, publication, push or issue closure. **Guest restart is NOT verified.**
Main owns publication and thesis; the launcher sends the unique completion signal.
Existing unrelated `scripts/__pycache__/` remains untracked.
