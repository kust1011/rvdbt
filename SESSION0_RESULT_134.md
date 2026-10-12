# Task134 — exact affected-memory replay on final Task133 host512

**5,904/5,904 original retained Task128 affected-memory calls PASS; failed0,
unattempted0.** Task134 newly executed **5,901**, and credited exactly **three**
authenticated Task133 original calls on the same final executable. No earlier-build
result receives credit. No regression or production change was required. Evidence
only; no push or closure. The existing `run134.sh` launcher signals main on exit.

## Final executable and independent identity

Reused isolated production: **xbd:/home/vick/rvdbt-whole-native-task133/build/**.
Source: **eaf45ab75c034c6135acb19b4897d9fe63859672**. Final identities:

* elfrun: **baac2151f634adb34132f5166e998b98c28b51616a50d7c55bbc829988ae6c98**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**

[Independent source audit](docs/rvv-validation/memory-task134/SOURCE_EQUALITY.pre.json)
compares **296** actual isolated source/build/test inputs against hashes generated
directly from `git show eaf45ab:<path>`, zero differences.
[Post audit](docs/rvv-validation/memory-task134/SOURCE_EQUALITY.post.json) agrees.
[Build files before](docs/rvv-validation/memory-task134/BUILD_FILES.pre.json) and
[after](docs/rvv-validation/memory-task134/BUILD_FILES.post.json) authenticate actual
production/focused binaries, cache and compile commands without changes.
[Flags audit](docs/rvv-validation/memory-task134/FLAGS_AUDIT.json) retains **53**
production commands: **52 C++** all carry `-DRVV_HOST_CHUNK_BITS=512 -mavx512f
-mavx512bw -O3 -DNDEBUG`, plus the separately retained assembly command.
Actual cache is Release/host512; original Task133 configure/final production/final
test build success receipts are checked. `ldd -r` has no unresolved symbols.

Real [xbd CPU](docs/rvv-validation/memory-task134/cpu.txt) is AMD Ryzen9 9950X3D,
with AVX512F/BW/BMI2. The existing normal fixture checks real AVX512F/BMI2 and
executes actual emitted SIMD. Host chunk is **512 bits/64 bytes**.
**XLEN32** is independently checked from every executed guest ELF's ELF32/LE
header. **ELEN64** is the implementation constant in authenticated
`dbt/guest/rv32_vector.h`, not a freely substituted option.

Original guest VLEN flags are preserved. The earlier Task128 report's blanket
VLEN1024 wording does not describe the entire retained queue:

| Guest VLEN | CHIPS calls | ACT calls | Ara calls |
|---:|---:|---:|---:|
| 128 | 1,860 | 0 | 8 |
| 256 | 4 | 0 | 20 |
| 512 | 4 | 0 | 16 |
| 1024 | 64 | 3,828 | 40 |
| 2048 | 4 | 0 | 16 |
| 4096 | 12 | 0 | 28 |

## Exact queue, subtraction and original acceptance

[Partition](docs/rvv-validation/memory-task134/PARTITION.json) compares complete
canonical original call objects against the retained Task128 queues and original
suite manifests. The new queue and credited calls are disjoint and their union
is exactly the retained **5,904** objects. No family filter is recomputed to expand
or shrink the retained selection.

Only Task133 ACT B **Vls8-vl1re8.v, Vls8-vl1re64.v, Vls8-vs1r.v** are
[credited](docs/rvv-validation/memory-task134/CREDITED.json). Full call equality,
before/after final production pins, original stream hashes, rc0/no timeout and the
original execute109 DUT predicate are checked again. Their raw evidence is copied
into Task134's `credited/` tree; Task133 originals remain untouched.

| Suite | Newly executed PASS | Credited final Task133 PASS | Completed/PASS | Failed | Unattempted | Each B/M1/M2/BOTH |
|---|---:|---:|---:|---:|---:|---:|
| CHIPS | 1,948 | 0 | 1,948 | 0 | 0 | 487 |
| ACT | 3,825 | 3 | 3,828 | 0 | 0 | 957 |
| Ara | 128 | 0 | 128 | 0 | 0 | 32 |
| Total | **5,901** | **3** | **5,904** | **0** | **0** | **1,476** |

[Exact queue/result index](docs/rvv-validation/memory-task134/QUEUE_RESULT_INDEX.json.gz)
joins **all5,904** full original calls, new/credited provenance, exact command,
result, binary pins, original raw acceptance predicate/observer, stream/file hashes
and route diagnostics. [Offline audit](docs/rvv-validation/memory-task134/AUDIT.json)
recomputes original predicates from the raw streams, normalizes only relocated
work/cache/dump paths, verifies guest ELF bytes and authenticates original tools
and inputs after execution. It executes zero guest instructions.

CHIPS keeps registered exact exit/stdout plus the original guest TEST_CASE checks;
[487 original sources](docs/rvv-validation/memory-task134/CHIPS_SOURCE_AUDIT.json)
and [1,948 source/assertion bindings](docs/rvv-validation/memory-task134/CHIPS_SOURCE_BINDINGS.json.gz)
match their retained hashes. ACT keeps source/ELF/answer/signature/checker hashes
and original execute109 whole-file DUT predicate. Ara keeps original source,
adapter, ELF and actual original observers. Earlier source/assertion selectors
remain provenance, not earlier-build result credit. No guest compilation,
reference engine, generator, oracle or answer/checker edit occurred.

Four workers maximum, nice10, cores28–31, isolated work/cache, core dumps disabled;
original CHIPS/Ara120s and ACT300s timeouts. Failure would stop scheduling that
suite while retaining initial results. No failure triggered. Final recorded host
load1.23/0.79/0.75; these are scheduling diagnostics, not performance measurements.

## Normal admission and remaining boundaries

Only two existing focused executables ran, sequentially core28/60s, using the
already successful isolated build and authenticated binary hashes:

* `rv32_whole_native_fault_test --normal-only`: **13,330 checks PASS,
  terminal_cells0**. Actual singleton emitted SIMD executes under ordinary
  admission with force emission off; 48 load geometries cover VLEN128/512/1024,
  nregs1/2/4/8 and encoded EEW8/16/32/64. The actual file-backed normal transfer
  selects checked fallback; the anonymous normal transfer selects SIMD, with
  fallback counters distinguishing them. The existing two-instruction grouped
  fixture publishes zero native sites, selects checked fallback and checks bytes.
* `rv32_llvm_memory_admission_test`: **292 checks PASS**, 16 existing cells;
  8 normal,4 checked denied,4 fixture-forced fallback. Actual whole native hit
  counters are zero. Existing fixture forcing is local admission coverage, not
  external production admission. No native fault is injected by this check.

[Focused identities/commands](docs/rvv-validation/memory-task134/FOCUSED_RESULTS.json)
and original [singleton/grouped](docs/rvv-validation/memory-task134/singleton-grouped.stdout)
and [LLVM](docs/rvv-validation/memory-task134/llvm.stdout) outputs are retained.
These establish the bounded final singleton/checked-grouped/checked-LLVM
classification. A singleton instruction transferring multiple architectural
registers remains distinct from a grouped frame containing multiple instructions.
The external queue's passing predicates and aggregate route counters do not
establish per-target SIMD admission. **Grouped QCG and LLVM whole-register SIMD
remain disabled; helper passes do not demonstrate restored grouped SIMD.**

No native fault campaign, guest handler return, repaired-mapping/same-PC retry,
P4-04/equivalent, new generated corpus, full suite or performance matrix ran.
**Guest restart remains NOT verified.** Other Task133 unowned/native/concurrency
boundaries remain unchanged.

## Retained attempts and evidence

[Attempts](docs/rvv-validation/memory-task134/ATTEMPTS.md) retain evidence-tool
assertion failures, a transport failure and an initial incomplete local extraction. No guest call failed, no original
failure was replaced, and no failed audit led to a dependent focused execution.
**Task134 runs no build**, so no executable runs after a build failure. Original
Task133 build/stale-fixture failures remain in its untouched report/archive.
The tracked replay script's header was corrected after execution; the exact
invoked bytes and tool hashes remain in raw receipts.

Raw root: **xbd:/home/vick/rvdbt-memory-validation-task134/**.
Local authenticated extraction:
**/home/user/research/materials/task134-memory-raw-20261013/**.
Archive: **/home/user/research/materials/task134-memory-receipts-20261013.tar.gz**,
SHA256 **20a2e39f9f57dcc70ca313ac514cf244db132eca522fb411d821dfdfe0116474**.
[Raw manifest](docs/rvv-validation/memory-task134/RAW_MANIFEST.json.gz) authenticates
**45,433 files**: commands, original results/streams/observers, guest ELF copies,
TB maps, focused emitted shapes and identities. Generated work/cache contents
are excluded from the archive; original input/answer/checker trees and the full
remote run remain retained. No prior evidence root was overwritten.

[Local extraction audit](docs/rvv-validation/memory-task134/LOCAL_RAW_AUDIT.json)
checks all **45,433** manifest files, zero differences, and exactly5,904 index
records after archive hash verification. The partial first extraction remains
separate and receives no credit. Python syntax checks and `git diff --check` pass.
