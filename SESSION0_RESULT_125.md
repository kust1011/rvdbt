# Task125 — production integration and affected external memory regression

Continued from **d85d6f7**. Task123/124's checked-copy change passes the bounded
production integration requested here. Built actual **elfrun/libdbtjitshared**
from current source in fresh **xbd:/home/vick/rvdbt-production-task125/**,
using a fresh build directory. No production defect was found and no production
behavior change was needed. Test integration is committed separately as
**f5b32f4**; this report and receipts follow in a separate commit. No push or issue
closure. Launcher owns completion signaling.

Clang22 / LLVM22.1.6, Release, chunk128; configure and production build exit0.
Initial load **0.38/0.42/0.49**; recorded pre-replay load **0.67/0.56/0.54**.
Builds used nice10, cores28–31, -j4, timeout900 for production and timeout300/180
for focused integration targets. Replay used four workers total, nice10,
cores28–31, the original CHIPS/Ara120s and ACT300s per-process bounds, isolated
per-call work/cache, and disabled core dumps. No performance measurement or
global settings changed.

[Source equality](docs/rvv-validation/production-task125/SOURCE_EQUALITY.json)
checks **289 current tracked dbt/CMake inputs, zero differences**. Vendored
dependencies match the isolated Task124 source. New
[build identity](docs/rvv-validation/production-task125/BUILD_IDENTITY.json):
elfrun SHA256 **8220339e6d7443568d3918d884032d077183405bd5b6d16fd9cc48bb8bcb4bad**.
The freshly built library is byte-identical to the older library,
**1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d**;
the new executable identity distinguishes these calls. Executable `ldd -r`
reports no undefined symbols. Standalone library `ldd -r` lists its existing
`dbt::Panic` dependency, resolved by the executable. Executable symbols contain
HandleSignal and all eight width/direction leaf PCs. Actual production-object
disassembly confirms HandleSignal has no calls or TLS resolver calls.

The new **rv32_host_copy_linkage_test** links the production archive and includes
no implementation cpp. It calls normal public `MainThreadBoot` with a retained
original ELF, then reads installed SIGSEGV/SIGBUS actions: same production
callback, SA_SIGINFO, initialized masks and active CPUState. Through those
normally installed callbacks, **16 valid copies and 16 denied copies** pass at
1/2/4/8 bytes × read/write × anonymous protection/file truncation. Real kernel
codes remain SEGV_ACCERR and BUS_ADRERR. **142 checks, exit0, guest_calls=0**.
No denied guest instruction or guest handler executes in this probe. Full normal
guest execution is supplied by the external replay below.

The affected queue is derived from the retained Task120 manifest and Task121/122
queues by the exact memory-form selector in
[SELECTION.json](docs/rvv-validation/production-task125/SELECTION.json), with
complete selected calls retained in three compressed queue files. Only original
memory targets are selected; no unrelated arithmetic target suites or reference
blockers are scheduled. Every selected call retains its original ELF, flags,
timeout and acceptance predicate. CHIPS uses the unchanged registered exit/stdout
predicate; ACT reuses the original execute109 DUT predicate and unchanged guest
signature.h assertions; Ara imports unchanged original observers. No new oracle,
golden, original testcase or expected answer was generated or repaired.

| Retained suite | New-build calls | Per B/M1/M2/BOTH | Result |
|---|---:|---:|---|
| CHIPS | 1,948 | 487 each | all PASS |
| ACT db2 | 3,828 | 957 each | all PASS |
| Ara | 128 | 32 each | all PASS |
| Total | **5,904** | **1,476 each** | no mismatch/crash/timeout/runner error/unattempted call |

The checked memory union is **278 forms**, also 278 in each CHIPS and ACT arm;
Ara supplies 111 memory forms. Family union: unit 8, strided 8, indexed/segment 208,
mask 2, whole-register 20, FOF 32. These are finite original comparisons, not all
configurations or a full-state/fault oracle. Original source/adapter/ELF/checker
hashes were authenticated before execution. Remote receipt audit validates
original call membership, complete normalized flags, candidate identities and
stream hashes. Downloaded raw independently verifies **39,384 files**.

[form-bindings.json.gz](docs/rvv-validation/production-task125/form-bindings.json.gz)
contains **5,904 exact source/configuration/assertion joins**. Each record has
new command/result/build pins and an explicitly named `older_build_binding`:
CHIPS retains literal TEST_CASE line selectors, source-chain/configuration
selectors and original target/checker bindings; ACT retains source, signature,
literal comparison-site and checker links; Ara retains original source and
comparison/observation links. New Ara observations are in the new raw observer
records, not relabeled Task122 observations. Prior full Task120–122 results
remain older-build results; neither their files nor their denominators changed.

Admission evidence is separate from passing switches. In each arm, original ACT
**Vls8-vle32.v** passes with **62 vle32 handler entries**; **Vls32-vse32.v** passes
with **4 vse32 handler entries**. Thus normal valid helper execution is observed.
Original **Vls32-vle32.v** passes with **zero vle32 handler entries**, zero guard
fallbacks and positive aggregate direct hits (844 B/M2,815 M1/BOTH); its original
target assertions establish execution, supporting direct vle32 execution under
the existing route census contract. Aggregate hits alone are not target
admission. The `other-vector` bucket merges other families; no independent
per-target direct count is claimed for every strided/indexed/segment/mask/whole/
FOF case. Exact selected external counters are in
[ADMISSION.json](docs/rvv-validation/production-task125/ADMISSION.json).

Task119 executable LLVM/scanner checks are now reproducible from repository
sources using two small existing-CMake targets. Current source executes the
retained O3 MCJIT whole-memory body/observer fixture: **8 native, 4 denied, 4
forced successful fallback cells, 268 checks**, exit0. Actual scanner FormRun:
**13 rows, 0 failures**, exit0, with the original permissive shape callback and
separate production translator/route checks. Existing whole-register LLVM IR and
QCG route tests also exit0. The LLVM fixture still replaces GHC entry convention
with C and terminal dispatch with return; this is executable translated-body
evidence, not stock AOT dispatcher execution. No guest retry. Commands and limits
are retained in [commands.txt](docs/rvv-validation/production-task125/commands.txt)
and the [receipt README](docs/rvv-validation/production-task125/README.md).

Failures are preserved: admission attempt1 had no generated CMake target before
reconfiguration; attempt2 lacked explicit MCJIT execution-engine linkage, now
scoped to the new LLVM test target. Three replay preflights stopped before any
guest call while resolving absent remote Ara source/adapter files and an
unsuccessful source archive staging attempt; 43 distinct retained source/adapter
objects were then hash-verified and staged in the isolated root. The linked probe's
first invocation completed checks but timed out124 during static teardown:
it omitted the normal `fsmanager::Destroy()` shutdown. Its backtrace and streams
remain retained; the corrected focused probe exits0. No failed guest observation
was repaired or hidden, and no denied guest execution was retried.

Full raw stays at **xbd:/home/vick/rvdbt-production-task125/**; downloaded raw is
**/home/user/research/materials/task125-raw-20261013/**. The immutable archive is
**/home/user/research/materials/task125-receipts-20261013.tar.gz**, SHA256
**4560273f31960654fdeae2e3d27de41a63d60e656412b36ccda241ea7711950e**.
Work/cache and the full source/build stay remote; raw streams, commands, identities,
TB maps, observer/results, failed attempts and compressed logs/disassemblies are
preserved. [LOCAL_RAW_AUDIT.json](docs/rvv-validation/production-task125/LOCAL_RAW_AUDIT.json)
binds transport and the local audit. Repository `git diff --check` passes.

Remaining unexpected-host-fault limitations are explicit:

* **Native QCG/LLVM and optimized RVV/CCRF memory bodies** still lack host-PC
  ownership/recovery maps, lane/field coordinates, dirty/publication-state
  materialization and a safe dispatcher exit contract. Their permission admission
  does not pin mappings or prevent later host faults.
* **Unmasked permitted unit-stride bulk copies and permitted whole-register fixed
  copies** remain outside checked-leaf capture; valid external results do not
  prove unexpected-host-fault recovery there.
* **AVX2 gather and optional emitted gather routes** remain uncorrected for
  unexpected host faults after preflight.
* **Checked-leaf captures** still refuse HostCopy guest signal delivery; retained
  SIGBUS is not predicted SIGSEGV. Capture can lead to terminating dispatcher
  handling, not architectural guest handler/return/restart. The existing global
  dispatcher unwind/CPU ownership is not made concurrent by leaf TLS.

No native recovery, complete memory model, concurrent mapping contract, complete
guest fault delivery/restart, P4-04 or equivalent guest retry is accepted here.
