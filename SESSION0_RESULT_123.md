# Task123 — host faults after RVV admission

## Pre-edit route/state/design record

Starting HEAD: e2fadab. Correction committed separately as **f772ac1**.
No prior commits amended; Task122 external receipts remain untouched.

All guest host-memory instructions can still fault after permission admission:
ordinary checked element helpers; unmasked unit-stride chunk helpers;
whole-register fixed-copy helpers; FOF field copies; optional AVX2 gather;
QCG typed chunks/active loops/strided/indexed/segment/mask/whole-register bodies;
LLVM counterparts (including masked loads/stores); optimized RVV/CCRF runs.
Permission bitsets cover mmap/munmap/mprotect. PageInfo backing/private/shared
facts exist only when detailed metadata is enabled before Init. MappingEpoch
is an ordinary counter incremented by successful MMU changes, not a lock or a
pin; external file truncation and raw host mprotect do not change it.

The checked helper loop publishes vstart before each active element and knows
field, EEW, raw instruction and guest PC. Completed fields/elements are live;
load staging can keep a faulting field unpublished. Stores may have a byte
prefix written if a host fault occurs within a split field; no rollback or
atomic-field promise is sound. Helper body/census scopes must return before
FinishHelperMemoryFault closes FP state and invokes the existing dispatcher
longjmp. That process-global dispatcher environment is not a new per-thread
recovery contract.

Smallest proposed correction: Linux x86-64 byte-copy assembly leaf with exact
load/store PC labels, per-thread armed byte address, synchronous signal/code
filter, and a distinct failure-return PC. The handler only records scalar
signal metadata and changes RIP to that return path. It neither retries the
faulting instruction nor jumps across C++ objects. Loads stage up to eight
bytes before publication. Apply to existing checked helper fields and FOF;
retain native and bulk/gather routes as unverified. Host SIGBUS must remain
SIGBUS evidence and unsupported guest delivery, not become predicted SIGSEGV.
Unrelated host faults continue into the existing fatal diagnostic handler.

Native recovery needs emitted host-PC ownership, guest member PC/raw and lane/
field coordinates, publication/dirty-register maps (including spills and host
vector registers), and a safe exit/materialization ABI. Permission preflight
alone cannot supply these. No native recovery is claimed or global vector
execution disabled.

## Implemented correction and its boundary

Added `dbt/rvv_host_copy.{h,cpp,S}` and linked it into dbtstatic. Each copy is
bounded to one architectural field (1/2/4/8 bytes). Linux x86-64 SysV leaves
have no stack adjustment, callee-saved changes or live C++ objects. Their only
recoverable instructions are a byte read from RDI and a byte write to RDI.
The other pointer is accessed at a different PC. A matching synchronous fault
changes saved RIP to `rvv_copy_failed` (`xor eax,eax; ret`), consumes the
original leaf call's return address, and returns false through ordinary C++
control flow. It never resumes the faulting access or repairs a mapping.

The production SIGSEGV/SIGBUS callback checks this boundary before logging or
CPU/MMU lookup. Recognition requires an armed thread, exact leaf PC, matching
`si_addr` and saved RDI, and SEGV_MAPERR/SEGV_ACCERR or BUS_ADRERR/BUS_OBJERR.
State uses initial-exec TLS, volatile sig_atomic_t and a statically checked
lock-free pointer atomic. The accepted branch allocates nothing, takes no
lock, calls no libc or logging function and leaves errno/signal masks alone.
Compiled disassembly verifies direct TLS access and **no calls** in HandleSignal.
The assembly disassembly identifies offsets 0x4/0x14 for the read/write and
0x1c for the distinct failure path. Linux sigreturn restores the interrupted
mask; there is no signal-handler longjmp. Initialized the existing sigaction
mask, which previously filled an unused local while leaving sa_mask undefined.
The unmatched branch retains the old fatal diagnostics, including their
pre-existing non-async-safe logging/backtrace behavior; this task does not
rebuild that fatal subsystem or replace previously installed handlers.

`rvv_ref::memory_checked` and `load_fault_only_first` now use the leaf copy.
They still suppress masked/prestart accesses and predict guest permission
failures before copying. Loads stage a field before writing any destination
byte. Stores retain any completed byte prefix on a host fault; neither field
atomicity nor rollback is promised. Completed segment fields remain published.
FOF absolute element zero queues a fault; a later host fault trims VL as the
existing FOF path does. Resetting leaf metadata at checked-loop entry keeps a
later predicted denial from acquiring an earlier host-fault provenance.

MemoryFaultEvent adds HostCopy/HostFault and host signal/code, outside the baked
CPUState ABI. Queue validation keeps predicted and host-origin events distinct.
Snapshots retain the original PC/raw/address/element/field/EEW/NF plus actual
host signal/code. The dispatcher prints the capture and **terminates with 1**
when delivery is refused. DeliverHelperSignal explicitly refuses HostCopy;
SIGBUS is not mislabeled as predicted SIGSEGV. No guest handler, sigreturn or
retry is added. Updated the gather comment that incorrectly claimed permission
preflight proved host fault freedom; gather execution remains unchanged.

Exact corrected routes are checked unit-stride fallback (masked, nonzero
vstart, or permission-denied bulk preflight); strided, indexed/scatter and
segment checked helpers; mask helpers; whole-register checked fallback; and
FOF field copying. The permitted unmasked unit-stride dispatch bulk copy,
permitted whole-register fixed copy, AVX2 gather and all native QCG/LLVM arms
**remain uncorrected for unexpected host faults**. Their valid execution is
preserved. This is a helper boundary correction, not complete Issue1 closure.

## Authoritative design basis

Consulted QEMU **v9.2.0**, peeled commit
**ae35f033b874c627d81d51070187fbf55f0bf1a7** (annotated tag object
55162f76c8d6698c22d9e805f29b1faf15d9724a; verified by git ls-remote).
[linux-user/signal.c, lines 886–1007](https://github.com/qemu/qemu/blob/ae35f033b874c627d81d51070187fbf55f0bf1a7/linux-user/signal.c#L886)
checks code ownership, distinguishes synchronous signals, and uses a host PC
for CPU-state restoration before leaving translated execution. Its SIGBUS path
retains signal information. Its write-protection repair/restart branch at
900–906 is **not adopted**. Our leaf has an explicit failure-return PC and
needs no translated-state restoration. RVDBT lacks the equivalent native
restoration contract, so copying QEMU's escape into this handler would be unsound.

This design relies on Linux x86-64 ucontext and SysV ABI, not portable C++
signal recovery. Existing production handler already uses REG_RIP. The new
assembly rejects other architectures at build time. No scalar/atomic emulation,
global RVV disable, full signal subsystem replacement or original oracle edit.

## Actual bounded verification

New isolated root: **xbd:/home/vick/rvdbt-host-fault-task123/**; source copied
from retained Task118 with all current changes overlaid, including the current
Task119 LLVM test source. Final equality checks **287 files (tracked build/source inputs and four new
files)**, differences **0**. Vendored dependencies
were copied unchanged from the retained source. Built only the five focused
host-interface targets with **Clang 22 / LLVM 22.1.6, Release, chunk128,
-j4, nice10**. No elfrun/external-suite/performance execution or original reference.

Final verification used a sequential worker on core28, nice10, **90 seconds
per process**, core dumps disabled. Load before final five-target verification:
**1.51/0.93/0.67**. Load before the final changed-test-only assertion refinement:
**0.82/0.82/0.64**. Every final process exits **0**, with no timeout.

| Focused test | Actual final result |
|---|---|
| rv32_host_copy_fault_test | 118 checks, 11 helper cells PASS |
| rv32_unit_memory_fault_test | 9,562 checks, 1,248 cells PASS |
| rv32_family_memory_fault_test | 323,407 checks, 59,424 cells PASS |
| rv32_special_memory_fault_test | 254,648 checks, 26,290 cells PASS |
| rv32_signal_interface_test | 376 checks PASS |

These are bounded existing host tests, not reruns of the completed external
suites. ABI signature stays **ce212ddc4742de49** in all three memory regressions.
Final host-copy test covers eight strided load/store × SIGSEGV/SIGBUS × split/
non-split cells, one segment field-1 SIGBUS, and two FOF cells. It truncates a
two-page backing file **after admission**, without changing MappingEpoch.
It separately uses raw host mprotect to cause SIGSEGV despite allowed guest
permissions. It checks actual host signal/code, PC/raw/address/element/field,
full vector storage, VL/vstart, staged load publication and distinguishable
split-store byte prefixes. Census scopes run normally; an older FP run closes,
fflags are harvested and MXCSR restored. Two real leaf faults in separate
threads preserve parent TLS. Two forked negative controls (ordinary host fault
and invalid source buffer while armed) retain **SIGABRT from existing Panic**.
No faulting guest instruction is re-entered; each fixture initializes a new
host invocation and captures once. Existing signal-interface checks marshal
host frames but execute no guest handler/return/retry.

All setup and test attempts are retained, including failures: default GCC
configuration failed on pre-existing non-trivial designated initializers;
first Clang build failed because the new test called private InitSignals.
The test now installs the actual included production callback directly.
First strengthened FP fixture exited 2 after one host-helper capture because
its opener did not set fround_run_open; initialized that flag consistently
with the existing interface fixture. This was a test-setup error, not a
production repair. Preliminary passing runs, the failed run, segment and
unrelated-fault refinements, final five-target runs, and final store-prefix-only
run retain separate stdout/stderr/returncode/build files. No hidden retries of
blocked execution. Final binary hashes, source hashes/equality and disassembly
are in [retained receipts](docs/rvv-validation/host-fault-task123/).

Actual new-host-fault evidence is SEGV_ACCERR and BUS_ADRERR; new host
SEGV_MAPERR/BUS_OBJERR branches, asynchronous-signal injection, hardware poison,
BUS_ADRALN and other architectures receive no verification credit. Helper
capture does not validate guest delivery or architectural restart. The global
trap_unwind_env/CPU ownership still limits concurrent guest execution; only
the new leaf boundary and captures are thread-local. Tests deliberately avoid
that global dispatcher unwind in their worker threads.

## Exact remaining native interfaces and obligations

* **Host-PC ownership and lifetime:** CompilerRuntime::AnnounceRegion in
  `dbt/qmc/compile.h:18`, implemented at `dbt/execute.cpp:176`, publishes entry
  guest IP, code span and instruction count. It does not publish a signal-safe
  per-memory-PC recovery record. Need a bounded immutable lookup that survives
  code relocation, cache replacement/revocation and AOT load/unload.
* **QCG publication:** `dbt/qmc/qcg/qemit.cpp:1980` preflights all memory
  members, including arithmetic-first runs. Guest accesses in
  Emit_vgathernative:3001, Emit_vmemorynative:3250,
  Emit_vchunkload:4504 and Emit_vchunkstore:4907, plus active loops and
  whole-register bodies, need member PC/raw, lane/chunk/field and commit-point
  evidence at each emitted fault PC. Emit_vstatechunkstore:5015 and
  Emit_rvvtypedchunkend:2269 show that publication and completion occur at
  separate points. QRegAlloc's SIDEEFF spill synchronization at
  `qra.cpp:913` and guard-call synchronization are real safeguards, but do
  not identify partial vector publication or reconstruct all live host
  vector registers/spills at an arbitrary native fault.
* **LLVM publication and optimization:** `dbt/qmc/llvmgen/llvmgen.cpp:1727`
  preflights runs; Emit_vgathernative:3832, Emit_vmemorynative:4323,
  Emit_vchunkload:5933 and Emit_vchunkstore:6126 lower accesses that LLVM
  can legalize, split and schedule. Need final machine-PC records associated
  with guest members and their actual publication order, including masked
  operations and vector SSA values. RvvStoreGroup:1050 and
  Emit_rvvtypedchunkend:6165 are normal publication/completion, not fault
  materializers. Existing experimental stackmaps at :230 are disabled;
  `dbt/aot/llvmaot_stackmaps.cpp:189` consumes branch patchpoints, not RVV
  fault live-state maps. Neither supplies the missing recovery evidence.
* **Safe native exit:** `dbt/ukernel.cpp:424` still has only fatal handling
  outside these leaf PCs. Need a generated-code exit ABI that restores its
  stack/callee-saved context and materializes guest GPR/FPR/vector/CSR/IP,
  older FP flags and partially completed memory before dispatcher capture.
  `dbt/guest/rv32_interp.cpp:50` and helper wrappers :145 correctly close
  scopes/FP state for helpers; they cannot be called blindly from a signal
  while a native run is live.
* **Reordered runs/CCRF:** Mapping facts permit file backing
  (`dbt/ccrf_materializer.cpp:263,375`); snapshot memcpy :387 and epoch
  checks :423 do not pin backing or recover a reordered fault. Need member
  order/committed-frontier and join-state restoration evidence, including
  how an earlier uncommitted member's fault supersedes speculative later
  work. No CCRF native recovery or snapshot-copy repair is implemented.

Shared/file mappings, concurrent MMU mutation, unexpected faults in bulk/gather
helpers, native partial chunk/segment/gather state, native guest-IP publication,
and complete guest host-fault delivery/return/restart remain open. No P4-04,
mapping repair, returning to the same fault PC, global-disable workaround,
push or issue closure. Launcher owns completion signaling.
