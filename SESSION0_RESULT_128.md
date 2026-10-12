# Task128 — actual host512 validation after Task127

Continued `fix/rvv-memory-families-issue-1` at **a6c50facfac092c10fdfee2e8a8b4f34e86a22f8**
(Task127 implementation **ed833f4**). Fresh isolated production build and the exact
selected Task125 memory queue pass on **host512**. **No implementation fix or
expected-answer edit was needed.** This is validation evidence only; Task118/125/
126/127's original builds/results remain **host128** and are not relabeled.
No push, issue closure or completion signal; launcher owns signaling.

## Actual source, build and CPU identity

New root: **xbd:/home/vick/rvdbt-host512-task128/**. Task127 dependencies copied,
then current tracked source overlaid; all **289 dbt/CMake regular inputs match**
before and after execution, zero differences. Source/dependency hashes are in
[SOURCE_EQUALITY.json](docs/rvv-validation/host512-task128/SOURCE_EQUALITY.json) and
[DEPENDENCY_EQUALITY.json](docs/rvv-validation/host512-task128/DEPENDENCY_EQUALITY.json).
No production source, external source/ELF, checker, golden or original suite flag
was edited. Guest **VLEN1024**, original configuration arms and timeouts remain.

Clang/LLVM **22.1.6**, fresh **Release**, actual CMakeCache
**RVV_HOST_CHUNK_BITS:STRING=512**, **RVDBT_HOST_FMA:BOOL=OFF** as before.
[FLAGS_AUDIT.json.gz](docs/rvv-validation/host512-task128/FLAGS_AUDIT.json.gz)
checks **51 actual production C++ commands**: 49 archive TUs, elfrun and shared-JIT
TU all carry **-DRVV_HOST_CHUNK_BITS=512 -mavx512f -mavx512bw -O3 -DNDEBUG**.
The actual cache, compile_commands and flags.make are retained, not inferred
from a configure request. Runtime stderr also reports **chunk_bytes=64**.

xbd is AMD Ryzen9 9950X3D. Recorded CPUID7 EBX **f1bf97ab** confirms AVX512F/BW/
DQ/VL; XCR0 **0x2e7** enables the required vector state. A core28 probe actually
executes ZMM instructions, exit0. [CPU probe](docs/rvv-validation/host512-task128/cpu-probe.stdout)
and complete lscpu output are retained.

Production **elfrun/libdbtjitshared** and **14 focused targets** build successfully;
configure/build exit0. New identities:

* elfrun: **849e6dd0a11e78d19319a2d04b93a644f4dd04e9fbc86dd8b350288392d655a3**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**

[BUILD_IDENTITY.json](docs/rvv-validation/host512-task128/BUILD_IDENTITY.json)
records every built target; per-call identities and before/after hashes match.
Executable `ldd -r` has no undefined symbols. Standalone shared library retains
its existing `dbt::Panic` dependency, resolved by the executable. Actual compiled
HandleSignal disassembly has **zero calls**, including TLS resolver calls;
width-matched bulk-leaf disassembly is retained.

Build limits: configure180s/build900s, nice10, cores28–31, -j4. Focused checks
sequential core28/120s, linked probe90s. Queue: four workers total on cores28–31,
nice10, original CHIPS/Ara120s and ACT300s per call, isolated work/cache, core dumps
disabled. Initial/pre-replay/final loads: **0.58/0.43/0.45**, **0.70/0.79/0.61**,
**0.43/1.11/0.86**. No performance measurement or global setting change.

## Original pilot and actual target admission/code

Before the full queue, **32 original ACT calls** passed: these eight cases under
**B/M1/M2/BOTH**: `Vls32-vle32.v`, `Vls8-vle32.v`, `Vls32-vse32.v`,
`Vls32-vl1re32.v`, `Vls32-vlm.v`, `Vls32-vlse32.v`, `Vls32-vluxei32.v`,
`Vls32-vle32ff.v`. Each uses the original source/ELF/signature/checker and
execute109 DUT predicate, authenticated before execution. Exact commands and
original predicate results are in
[pilot-AUDITED_RESULTS.json.gz](docs/rvv-validation/host512-task128/pilot-AUDITED_RESULTS.json.gz).

Initial four-case code inspection preceded the queue; supplementary inspection
completed the other four. **32 passing diagnostic calls** use the same execution
options/predicate, adding only a missing exit-time code dump. Their results are
separate from the original-flags pilot/queue. One pre-guest bad-options diagnostic
failure is retained below. No switch was added to force helper/native admission.

[TARGET_CODE.json.gz](docs/rvv-validation/host512-task128/TARGET_CODE.json.gz)
has **36 case/target-PC/arm records**, independently decoded guest labels,
architectural PC MOV markers, host offsets/bytes hashes, executed TB maps,
actual host disassembly, and original pilot route counters. All four arms have
these concrete target bodies:

| Original target and sample guest PC | Actual emitted memory route |
|---|---|
| Vls32-vle32.v, 8000006c | Guarded ZMM guest reads and state publication; full and partial-VL arms. Original state e32/m1, VL1; zero vle32 helper entries throughout case. |
| Vls32-vse32.v, 8000006c | Guarded ZMM state reads and guest stores, including partial-VL masks. Four vse32 helper entries elsewhere in each case; no all-store-native claim. |
| Vls32-vse32.v masked target, 80001d2c | Emitted mask-bit test and active-element scalar store loop, with guarded helper fallback. No SIMD claim for this target. |
| Vls8-vle32.v, 80000078 | A ZMM candidate exists, but guard requires e32/m1 while original target runs e8/mf4. Correct helper fallback; 62 vle32 handler entries per arm. Candidate bytes do not prove this target takes native. |
| Vls32-vl1re32.v, 8000006c | Whole-register guard on vlenb128/vstart0 and two 64-byte ZMM guest reads/publication. Does not use a VL-dependent element-copy claim. |
| Vls32-vlm.v, 8000006c | Guarded byte-load/publication loop with ceil(VL/8) bound and helper fallback. |
| Vls32-vlse32.v, 80000070 | Guarded scalar element loop: stride multiplication, guest reads, register publication; helper fallback retained. |
| Vls32-vluxei32.v, 8000009c | Actual runtime helper call with original raw instruction 07c1e007. Indexed operation remains TranslateHelper on this QCG route; no target-native claim. |
| Vls32-vle32ff.v, 8000006c | Actual runtime helper call with original raw instruction 03096007. FOF retains its helper protocol and runtime VL publication; no target-native claim. |

Target guest assertions, original state, target-specific code and routes support
these bounded classifications. Aggregate inline counters and enabled switches
alone establish none of them. `other-vector` does not identify an individual
family/target. No per-target native census is claimed for the entire queue.

## Focused existing checks and exit-only signals

All **14** existing focused executables exit0; original output/check counts are
in [FOCUSED_RESULTS.json](docs/rvv-validation/host512-task128/FOCUSED_RESULTS.json).

| Existing check | Result |
|---|---|
| rv32_host_copy_fault_test | 3,789 checks, original 11 cells retained |
| rv32_unit_memory_fault_test | 9,562 checks, 1,248 cells |
| rv32_family_memory_fault_test | 323,407 checks, 59,424 cells |
| rv32_special_memory_fault_test | 254,648 checks, 26,290 cells |
| rv32_signal_interface_test | 1,792 checks, guest_calls=0 |
| rv32_signal_frm_test | 256 local roundtrips, 192 high-bit badframes, guest_calls=0 |
| rv32_host_copy_linkage_test | Normal production boot; 16 valid/16 denied, 142 checks, guest_calls=0 |
| rv32_llvm_memory_admission_test | 8 native/4 denied/4 fixture-forced successful fallback, 268 checks |
| rv32_memory_run_scanner_test | 13 rows, zero failures |
| rvv_llvm_wholereg_mem_test; rvv_whole_reg_mem_route_test | PASS |
| vle32v_typedchunk_route_test; vse32v_typedchunk_route_test | PASS, existing emitted-code fixtures |
| rvv_frame_finalizer_test | PASS |

The LLVM fixture's original forced-fallback cells and codegen fixtures' existing
force-emit controls are local fixture evidence; they are not external admission
or production execution claims. No new forcing was introduced. Signal/frame
codec restoration is host API coverage, not guest sigreturn instruction execution.

Additionally, the unchanged Task126 launcher replays the original Task113
**eight exit-only calls**, four first-fault handler exits and four later-FOF
controls under all arms. **8/8 PASS**, original checker and complete stdout bytes
match retained references, **zero guest sigreturn**. This establishes existing
predicted-helper delivery/control, not captured SIGBUS guest execution or retry.
[Exit-only summary](docs/rvv-validation/host512-task128/exit-only-SUMMARY.json.gz).

## Exact selected Task125 queue replay

Unchanged Task125 replay/collector and original suite runners/checkers executed
only the selected memory queue. [TASK125_QUEUE_EQUALITY.json](docs/rvv-validation/host512-task128/TASK125_QUEUE_EQUALITY.json)
checks exact call objects against all three retained Task125 queues.

| Suite | Completed/PASS | Each B/M1/M2/BOTH |
|---|---:|---:|
| CHIPS | 1,948/1,948 | 487 |
| ACT | 3,828/3,828 | 957 |
| Ara | 128/128 | 32 |
| Total | **5,904/5,904** | **1,476** |

**Zero queue mismatch/crash/timeout/runner error/unattempted call.** Each result
retains the actual original acceptance output: CHIPS registered exit/stdout,
ACT original DUT predicate plus guest signature assertions, Ara unchanged original
observers. No reference engine, guest compiler, generator or oracle rerun.
Complete normalized flags remain original; B is the retained baseline, M1 enables
the original bounded vector-run arm, M2 the original active-VL bounds, BOTH their
original combination. No guest VLEN/flag substitution was made.

[RECEIPTS.json.gz](docs/rvv-validation/host512-task128/RECEIPTS.json.gz) retains
**5,904 precise case/form/configuration/command/result joins**, raw hashes,
identities, route diagnostics and exact original calls.
[form-bindings-host512.json.gz](docs/rvv-validation/host512-task128/form-bindings-host512.json.gz)
retains all **5,904** original source/assertion/checker bindings plus these new
commands/predicate results; nested Task125 fields explicitly remain older host128
evidence. CHIPS/ACT each attribute 278 memory forms; the memory union is **278**.
Ara's raw 111 form labels include the setup label `vsetivli`, leaving 110 memory
labels; the raw all-label union is 279. Nothing is dropped from the selected calls.

## Evidence, all failures and remaining scope

Raw/source/build remain remote at the new root. Downloaded raw:
**/home/user/research/materials/task128-host512-raw-20261013/**.
Archive: **/home/user/research/materials/task128-host512-receipts-20261013.tar.gz**,
SHA256 **3f4283bfa310599df07decb2ed98b71cb8aa64fa62cb597fe4e3498603a01a23**.
[LOCAL_RAW_AUDIT.json](docs/rvv-validation/host512-task128/LOCAL_RAW_AUDIT.json)
independently validates **40,274 files**, zero differences. Build/cache flags,
streams, commands, target disassembly, per-call raw/TB maps, observers, identities,
failed diagnostic attempt and exit-only evidence are preserved. Existing host128
raw directories and reports were not overwritten.

All failures are described in [ATTEMPTS.md](docs/rvv-validation/host512-task128/ATTEMPTS.md).
There was **one supplementary diagnostic RESULT_MISMATCH**: indexed B exited1
before guest execution because duplicate dump options were supplied. It retains
original_predicate_pass=false and its original streams/command; corrected dump
launcher passes without source/checker changes. Evidence tooling also had an
incorrect exit-only staging path, preliminary PC-segment slicing error, audits
against absent supplementary dumps, and a linear disassembler alignment failure
across literal pools; final target decoding starts at the exact PC-store bytes.
An apport exception hook failed due to a temporary Python `inspect.py` name.
None was an implementation/guest failure. Host-copy fixtures' intentional fatal
unrelated-fault children remain expected SIGABRT negative controls. There are
**no code fixes to separate from this evidence**, and no expected edits or silent
helper forcing. Repository whitespace verification passes.

Remaining: this finite host512 normal regression/local fault validation does not
close unexpected-host-fault recovery for native QCG/LLVM/RVV/CCRF, permitted SIMD/
libc/fixed-copy bulk paths, gathers or snapshot/frame copies. Permission admission
still does not pin mappings/backing or prevent truncation. Task127's checked bulk
frontier passes locally but is not proof of owned SIMD publication/commit recovery.
Global dispatcher unwind/CPU ownership remains nonconcurrent. No architectural
guest handler return/restart or complete memory-model/mapping-race guarantee is
established. **No P4-04/equivalent, mapping repair/same-PC retry, unrelated full
suite or performance run** was performed.
