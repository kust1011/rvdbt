# Task132 — admitted helper bulk memory integration

Continued **98b57c3**, main audits130/131, on `fix/rvv-memory-families-issue-1`.
Implementation/test commit: **3912943**. Evidence is committed separately.
The permitted **ordinary unit-stride helper and whole-register memory bulk gap is
closed** through the existing checked-copy element frontier. No push or issue
closure; launcher signals main. This was one memory integration task, not a corpus
campaign. Guest continuation/restart is **not verified**.

## Access-entry audit and implemented boundary

Inspected every production caller of `dispatch_load_unit_stride`,
`dispatch_store_unit_stride`, `whole_reg_load/store`, the whole-register typed QCG
frame/run admission and LLVM whole-register guard, plus checked bulk leaf capture,
`QueueOrdinaryMemoryFault` and helper dispatcher cleanup.

| Previously permission-admitted access | Current route |
|---|---|
| H_vle/H_vse unmasked helper: reference scalar or chunked SSE copies, including diagnostic replay | Both dispatch functions return the checked loop's success/failure and denied address. Every unmasked invocation uses `unit_stride_checked`, including zero/nonzero vstart, either lowering option and verify mode. |
| Masked ordinary helper | Existing checked active-element path remains; suppressed lanes are never accessed. |
| SpecialMemory whole-register helper: per-register libc/fixed-size memcpy after `special_memory_safe` | Removed that bypass. Encoded EVL/EEW/nregs go directly to the shared checked slot loop. |
| Whole-register singleton QCG, multi-member typed QCG frames, and LLVM whole-register bodies | Shared `special_memory_safe` refuses the whole-register encoding before any body access. All these existing consumers take their checked helper fallback. These bodies have no Task131 exact-site/cold-exit/publication ABI; permission alone cannot justify retaining them. |
| Owned ordinary singleton QCG SIMD | Retains Task131 native page-contained user data #PF contract and actual emitted body. Native backing admission now requires anonymous mapping provenance; truncatable regular-file backing takes the checked helper before SIMD. |

Both dispatch functions have only the H_vle/H_vse production callers. Raw
`rvv_ref::whole_reg_load/store` byte-copy utilities now have **no production
caller**; retained semantic fixtures use host arrays and carry no host fault
ownership claim. They are explicitly documented as such. No runtime whole-register
bulk entry still calls them. The QCG emitter classifies all whole-register memory
members before its body; LLVM's dedicated guard and shared typed-frame guard
consume the same special admission. A refused multi-member whole-register frame
falls back from original state, including preceding arithmetic members.

The shared unmasked loop stops each batch at the actual architectural register
slot boundary (`VLEN/EEW` elements); smaller guest VLEN slots are not packed into
CPUState. It checks permissions per element, preserves a predicted first-denied
byte, and invokes existing `CopyElements` for the admitted batch. The aligned
assembly leaf updates R8 only after a completed element and load publication.
Unexpected host faults redirect only its armed, exact guest MOV site to its
frameless failure return. C++ publishes `vstart = batch_start + completed` and
queues the original fault before the existing normal cleanup/dispatcher unwind.
Misaligned/wrapping copies retain the existing checked decomposition. A split
load does not publish an incomplete element; an already written split-store byte
prefix remains observable, with the faulting element still reported in vstart.
There is no memory replay to reconstruct a prefix.

Whole loads retain encoded EEW8/16/32/64 and `EVL=nregs*VLEN/EEW`; whole stores
retain EEW8. nregs1/2/4/8, alignment/legality, vtype/vill independence, vl=0 transfer,
prestart prefix, tails and completion clearing remain unchanged. Ordinary helpers
retain their width-derived EMUL/group checks and masked suppression. FOF remains
its separate checked rule: absolute element zero traps; a later fault trims VL
without queuing an ordinary fault. No original signal/code is converted to a
permission prediction or swallowed.

Task131's idempotent ordinary-memory bit alone included regular files. A separate
always-maintained `native_copy_ram_pages` bitmap records **MAP_ANONYMOUS provenance**,
follows fixed replacement and clears on unmap/reset. Page permissions do not
establish backing safety: a file may truncate after the permission census. This
bitmap selects such backing away from the limited native #PF contract; it is not
a residency/lifetime pin or a SIGBUS recovery proof. Checked copies accept their
existing exact synchronous SIGSEGV/SIGBUS codes and provenance. Neither their
ownership nor Task131's ownership is extended to another family.

## Normal path cost and diagnostic behavior

* Ordinary anonymous, page-contained singleton QCG SIMD keeps the same emitted
  accesses/publications/cold exit. Its existing per-chunk bitmap lookup is replaced
  by the stronger backing bitmap lookup: **no extra per-chunk lookup or guest read**.
  Mapping lifecycle maintains an additional 128 KiB bitmap and sets/clears its bits.
* Helper ordinary/whole-register transfers now scan element permissions and use
  exact-width scalar MOVs in the existing bulk assembly loop. Capture setup and
  the C++ call are amortized per admitted register-slot batch, not per aligned
  element. Masks and misaligned/wrapping elements retain their existing narrower
  checked path. This is slower than unowned SSE/libc bulk copies; no speedup or
  measured overhead is claimed.
* Whole-register native frames now pay their existing guard plus helper fallback;
  file-backed ordinary singleton SIMD similarly falls back. Restoring whole SIMD
  requires an actual ownership/publication/exit contract. Unrelated arithmetic
  SIMD and the established ordinary anonymous SIMD path are retained.
* Ordinary memory `--rvv-verify` no longer performs an unowned second guest read,
  store snapshot/restore/replay or memory fault injection. It uses the checked
  result once. Arithmetic verification is unchanged. The removed verifier compared
  two paths that are no longer used for helper guest access; it supplied no fault
  contract. Existing diagnostic translation refusal remains.
* No runtime stub, CPUState layout or AOT ABI change: **a89957277993e0d9**.

## Actual isolated host512 build and bounded checks

Real build/source root: **xbd:/home/vick/rvdbt-permitted-bulk-task132/**.
Source: **/home/vick/rvdbt-permitted-bulk-task132/source/**.
Build: **/home/vick/rvdbt-permitted-bulk-task132/build/**.
Executables: **build/bin/elfrun**, **build/bin/rv32_permitted_bulk_fault_test** and
focused targets under that same actual bin directory; shared library:
**build/lib/libdbtjitshared.so**. No force-emission or simulated host512 credit.

Fresh source copied from Task131's retained dependencies/source, current tracked
production/build inputs overlaid, new isolated build directory. [Source equality](docs/rvv-validation/permitted-bulk-task132/SOURCE_EQUALITY.json):
**295** files equal3912943, zero differences. [Dependency equality](docs/rvv-validation/permitted-bulk-task132/DEPENDENCY_EQUALITY.json):
**443** files equal Task131, zero differences. Actual Clang22/LLVM22.1.6, Release,
**RVV_HOST_CHUNK_BITS=512, -mavx512f -mavx512bw**, real AVX512F/BMI2. [Actual cache/compiled flags](docs/rvv-validation/permitted-bulk-task132/FLAGS_AUDIT.json).
Configure/build exit0, `ldd -r` no unresolved symbols. Final production identities:

* elfrun: **d5e2c44470fef9c31090b2e880716ca690b68bd10147dea1ecf6491d45c62367**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**

Production hashes remained identical after final comments/test-only refinements;
the shared library's sole jitabi_shared input is unchanged. [Equality](docs/rvv-validation/permitted-bulk-task132/FINAL_PRODUCTION_EQUALITY.json).
Build nice10, cores28–31, -j4, configure180s/build900s; each focused check sequential
on core28, timeout60s, core dumps disabled. Observed load initially0.66/0.43/0.41,
finally0.24/0.49/0.45. No ctest/full suite or performance matrix.

| Check | Actual result |
|---|---|
| New permitted helper terminal checks | **266** bulk snapshots:133 actual SEGV_ACCERR,133 actual BUS_ADRERR; all register/memory/frontier checks pass |
| FOF distinction | 2 actual BUS_ADRERR observations: later VL trim, zero-element dispatcher event |
| Separate admission-only invocation | exit0,8 checks, **zero guest accesses**: permitted page-contained file refused, anonymous fixed replacement admitted, unmap clears backing bitmap |
| Task131 native fault-to-dispatcher test | exit0,6,142 checks,40 terminal cells; owned native #PF plus checked crossing fallback retained |
| Ordinary unit memory fixture | exit0,9,562 checks,1,248 cells |
| Special memory fixture | exit0,254,648 checks,26,290 local cells; actual QCG whole singleton and combined frames take fallback |
| LLVM whole-register executable admission | exit0,292 checks,16 independently initialized cells; all whole native hit counts zero, actual fallback/state/PC/prefix assertions pass |
| Ordinary load/store typed route tests | both exit0,PASS |
| Unchanged external ACT B calls | **9/9 PASS**, original whole-file DUT predicates |

The new terminal fixture enters real qcgstub handlers with permission-admitted
memory. Raw host mprotect or backing truncation after admission leaves MMU
permission metadata and MappingEpoch unchanged. The actual host callback delegates
to production `dbt_sigaction_memory`; checked leaf failure returns normally through
C++ scopes and traps to the existing dispatcher checkpoint. Capture terminates
that operation. No guest signal delivery/frame/handler/return is called.

Coverage includes ordinary EEW8/16/32/64, both lowering modes and verify mode,
masked/unmasked, vstart0/1; whole loads of every EEW, stores EEW8, nregs1/2/4/8,
guest VLEN128/512/1024 and vill/VL0; cross-register completed prefixes; additional
split-element/nonzero-vstart cells. Complete CPUState register arrays, original
VL/type, fault PC/raw/address/element/EEW/nf/field, older scalar state, accessible
memory and deliberately open older FP state/MXCSR cleanup are checked. Production
callback disassembly has zero calls for both checked and native handlers; representative
actual bulk leaf disassembly retains exact MOV, publication and R8 increment order.

[Offline terminal audit](docs/rvv-validation/permitted-bulk-task132/TERMINAL_AUDIT.json)
independently recomputes all266 active architectural register files and all4096
accessible memory bytes per cell from byte-array expectations, plus event/CSR/GPR
coordinates. It runs **zero guest instructions**, locally reproduces remote JSON
exactly, and finds zero differences. Test assertions also check unused CPUState
slot bytes beyond active guest VLEN.

Only nine frozen ACT calls selected by `scripts/replay_permitted_bulk_task132.py`:
Vls8-vle8.v, Vls16-vle16.v, Vls32-vle32.v, Vls64-vle64.v, Vls32-vse32.v,
Vls64-vse64.v, Vls8-vl1re8.v, Vls8-vl1re64.v, Vls8-vs1r.v. [External audit](docs/rvv-validation/permitted-bulk-task132/EXTERNAL_AUDIT.json)
authenticates exact original B call objects/flags, source/ELF/checker/answer/capture
hashes, original predicate and final production identity. No input/answer/checker
edit, new reference, guest recompilation, extra workload flag or fault credit for
normal external passes. No other external corpus ran.

## Attempts, receipts and remaining unowned accesses

The first135 terminal bulk cells passed. The next short whole load's fixture
prefix equaled EVL, placing the denied page immediately **after** its transfer;
it completed normally and hit the fixture's must-trap assertion (rc2). The prefix
was bounded below EVL. A resumed invocation skipped the135 captured cells without
mapping or executing them; it captured the remaining131 bulk cells and checked
both FOF cases. Original attempt/resume streams and exit codes remain separate.
The combined stream is explicitly an aggregate, not a claimed uninterrupted
exit0 run. The resumed summary's1507 checks/133 cells belongs to that invocation.
No faulting operation was repaired or reentered.

After captures, comments and the LLVM summary label were refined; its retained
`native=8` text means normal completions, with **zero** whole native hits asserted.
The final source labels it `normal=8`; no extra execution was made for that text
change. A later test refinement makes file rejection explicitly page-contained
and adds the separate admission-only invocation. Only that zero-access mode ran
afterward. Final production hashes equal those used by every terminal/external
check. No terminal cell was repeated. Remote rg was absent for one diagnostic;
used Python instead. Extraction showed remote-clock timestamp notices; all bytes
were independently authenticated. `git diff --check` passes.

[Receipt archive](docs/rvv-validation/permitted-bulk-task132/receipts.tar.gz): SHA256
**96b8ef469346b0c952c7ecfa48ef523ff132412ee787435250de4c1a4770e9df**.
[Raw audit](docs/rvv-validation/permitted-bulk-task132/LOCAL_RAW_AUDIT.json): **237**
manifest files, zero differences. Local raw:
**/home/user/research/materials/task132-permitted-bulk-raw-20261013/**.
Remote isolated source/build/receipts/external work remain at the real root above.
Archive contains all build attempts, CPU/compiler/cache/flags, source/dependency
identities, terminal snapshots/memory, Task13140 full snapshots/emitted receipts,
production disassembly, original external commands/results/streams/identities and
collection/audit/replay scripts.

Previously unowned accesses that remain:

* **Scalar-native unit loops, multi-member ordinary unit-memory native runs and
  LLVM-native ordinary unit memory:** separate emitted paths still use their
  permission preflights; they have no singleton exact-site/cold-exit ownership.
  Their helper fallback is now checked, but this task does not recover their
  native unexpected faults. No equivalent native ABI is inferred from the helper.
* **Owned ordinary anonymous SIMD's SIGBUS/machine-check/other nonaccepted host
  faults:** Task131 still accepts only its exact synchronous user data #PF codes
  and error bits. Anonymous provenance removes known truncatable backing admission;
  it does not prove recovery for every backing/hardware failure. Actual native
  MAPERR remains accepted but not newly actual-fault tested. Regular-file native
  singleton accesses now fall back; they are no longer a permitted SIMD entry.
* **Other native families:** mask memory, strided/indexed/segments, gathers and
  other backend/run memory have their existing distinct contracts. The unchanged
  mask branch of special admission remains permission-only. These have no new
  ownership here. Whole-register native body code remains compiled but admission
  refuses it, so it makes no guest access in current execution.
* **Concurrent mapping/backing replacement, general live RA/pinned-state recovery,
  unrelated CPUState/publication/spill faults and CCRF recovery:** not supplied
  by either checked guest-MOV ownership or the Task131 singleton ABI. Raw semantic
  fixture byte-copy utilities also carry no recovery ownership and are not runtime
  entries. Unrelated host faults retain existing fatal handling.

No guest handler execution/return, repaired mapping/same-PC retry, P4-04/equivalent,
suppressed required signal, skipped required element, full external suite or
performance campaign occurred. Captured prefixes and source contracts establish
this terminal integration boundary, not a guest restart claim.
