# Task127 — shared checked bulk frontier; SIMD bulk prerequisite remains open

Started at **0e163e0** on `fix/rvv-memory-families-issue-1`. Read
SESSION0_RESULT_123–126 and the actual ordinary/whole-register helper bodies.
Code/test commit: **ed833f4**. Evidence follows separately. No push or issue
closure. Launcher owns completion signaling.

**This is the requested prerequisite checkpoint, not closure of the permitted
SIMD/libc bulk host-fault gap.** A reusable width-preserving bulk boundary is
implemented and used by existing checked suffixes. Normal permitted SIMD/fixed
copy execution remains enabled. No native/gather recovery was attempted.

## Exact unchecked routes found

Current-source paths, after this commit:

* `dbt/guest/rv32_interp.cpp:639,660`: permitted, unmasked, zero-vstart ordinary
  unit-stride load/store call `dispatch_*_unit_stride` after FirstDenied.
  `dbt/guest/rv32_vector_lower.h:3607,3632` select the unchecked reference path
  when lowering is disabled/nonzero-vstart and the chunked path otherwise.
  The reference implementations at :672/:683 use `guest_*_elem` memcpy or
  wrapped byte accesses. Chunk implementations at :3442/:3478 use
  `copy_chunked` :3427 (chunk load/store plus memcpy remainder), or wrapped
  byte copies for RV32 wrap. All are outside owned leaf PCs. Optional verify
  load shadow access and store orig/want/save/restore memcpy also bypass capture.
  Nonzero-vstart dispatch is a utility possibility; production handlers route
  that case to checked memory instead.
* `dbt/guest/rv32_interp.cpp:606`: permitted, zero-vstart whole-register groups
  take `whole_reg_load/store` at `rv32_vector_lower.h:2732,2756`. Their
  `sized_copy` :2706 uses libc memcpy with fixed-copy off, compiler fixed-size
  16/32/64/128-byte copies with it on, and libc for other lengths. Those guest
  accesses have no owned PC/frontier. Utility nonzero-start/wrap arms use
  unchecked wrapped byte loops; normal SpecialMemory admission excludes those
  arms and uses the checked suffix instead.
* Register-only memcpy (whole-register moves and arithmetic) is not guest
  memory. AVX2 gather, its scalar tail, emitted QCG/LLVM memory and CCRF snapshot
  copies are separate unresolved boundaries, unchanged here.

Permission admission and MappingEpoch do not pin backing. Actual local tests
again demonstrate allowed page metadata and unchanged epoch with raw host
protection changes or backing-file truncation. Therefore no existing permission
check can justify declaring the unchecked bulk paths fault-free.

## Concrete prerequisite and implemented reusable part

Keeping normal SIMD guest-memory execution requires a helper-specific
**architectural publication/commit contract**: owned final access PCs, bounded
transfer geometry, and an observable completed-element frontier at each access,
with a justified element-width store/completion rule. Existing libc/compiler
copies expose none of that contract; an arbitrary internal SIMD/REP PC cannot
be assigned a sound vstart from helper entry state. Catching a helper address
range, setting vstart from si_addr, or escaping C++ from the callback would
invent a guarantee. A mapping lease alone also cannot prevent file truncation.
This prerequisite is about the bulk helper's own memory/commit ABI, separate
from translated native register/spill/guest-PC recovery maps.

Implemented its smallest reusable width-preserving part:

* `dbt/rvv_host_copy.h:17` / `.cpp:115`: `CopyElements` accepts EEW, count,
  direction and a contiguous register slice; returns completed elements and
  denied guest byte. Zero count accesses nothing. Misaligned/wrapping elements
  reuse the existing staged-field Copy and RV32 wrapping decomposition.
* `dbt/rvv_host_copy.S:113`: eight frameless bulk leaves, read/write ×
  1/2/4/8 bytes. Each guest operation is exactly one width-matched MOV, with
  a distinct owned PC. R8 counts fully completed elements. A load publishes
  its field after the guest read, before incrementing R8; a store increments
  only after its guest write. Source/publication PCs remain unowned host faults.
* `dbt/rvv_host_copy.cpp:46`: bulk-mode capture validates R8 against the armed
  count, derives the current element base, matches saved RDI, exact direction/
  width PC and bounded si_addr, then captures the frontier. The existing
  distinct failure-return PC returns through the original call. No retry,
  signal-handler longjmp, allocation, CPU lookup or logging is added.
* `dbt/guest/rv32_vector_lower.h:636`: checked unmasked ordinary, mask-byte and
  whole-register suffixes share register-slot-bounded admitted runs through
  CopyElements. Before a predicted denial, earlier admitted elements complete;
  host failure sets vstart to run start plus completed count. Register gaps,
  original EEW (whole-register store EEW8), prefix/tail and exact denied byte
  remain intact. Masked ordinary execution retains memory_checked's active-field
  loop; no inactive/prestart access is introduced. Existing queue/frame/FP
  cleanup remains on ordinary returned C++ control flow.

The new leaves are a bulk memory kernel, not an instruction interpreter. They
are used only on the existing checked paths. Replacing every normal SIMD copy
with them would violate the requested preservation of normal SIMD paths, so
that substitution was not made. Full bulk closure still requires the paired
SIMD access/publication contract above (particularly store partial completion),
or a supported backing-lifetime contract with explicitly bounded applicability.
No such contract is claimed by this checkpoint.

## Reviewed source, actual production build and bounded checks

Fresh isolated root: **xbd:/home/vick/rvdbt-bulk-boundary-task127/**. Copied
Task126 source/dependencies, overlaid current changes, configured a fresh build.
All **289 tracked dbt/CMake regular files match** current source, zero differences.
Source review checked register-slot limits, denial-before-copy handling, frontier
validation/publication order, source-PC exclusion, frameless return ABI, mask
suppression and unchanged normal fast-route selection. Production-object
HandleSignal disassembly has **zero calls**, including TLS resolver calls.
Bulk leaf disassembly is retained; all guest accesses are width-matched MOVs.

Clang22 / LLVM22.1.6, Release, chunk128; configure exit0. Actual **elfrun and
libdbtjitshared built successfully** before the initial aggregate build stopped
at the new test's unqualified VectorState type. Only the test qualifier changed
for the successful second build; production source was unchanged. Executable
`ldd -r` reports no undefined symbols. elfrun SHA256:
**1df792c48f9111cb24ca7ce9197d3c52027ccea7d68bccff4a5d20f9c4e72e26**.
Library SHA256 remains
**1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d**.

Build limits: configure180s, initial build900s, focused300s, test refinement180s;
nice10, cores28–31, -j4. Tests: sequential, core28, nice10, 60s each, core dumps
disabled. Initial/final load **0.05/0.29/0.46**, **0.98/0.68/0.59**.

| Focused affected check | Actual result |
|---|---|
| rv32_host_copy_fault_test, final refinement | exit0, 3,789 checks; original 11 helper cells retained |
| rv32_unit_memory_fault_test | exit0, 9,562 checks, 1,248 cells; ABI ce212ddc4742de49 |
| rv32_special_memory_fault_test | exit0, 254,648 checks, 26,290 cells; same ABI |
| Original ACT Vls8-vle32.v, B | PASS, exit0, unchanged original predicate |
| Original ACT Vls8-vl1re32.v, B | PASS, exit0, unchanged original predicate |
| Original ACT Vls8-vlm.v, B | PASS, exit0, unchanged original predicate |

The new bulk fixture covers all widths/directions × actual SEGV_ACCERR and
BUS_ADRERR: normal/zero-count transfers, three completed elements then one
captured fault, unpublished failing load and retained store prefix. Separate
checked-suffix invocations cover nonzero vstart and register-slot gaps, with
complete prefix/completed/fault/tail byte checks. Synthetic saved-R8 and opposite
PC negative controls reject invalid frontiers/directions before accepting the
original real signal once. RV32-wrap bulk success uses existing byte decomposition.
Misaligned bulk failure is not new independently measured coverage; existing
single-field split-fault checks remain. Existing two fatal unrelated-host-fault
children retain expected SIGABRT. No guest handler instruction/return/retry is
executed by these local capture fixtures.

Only **three original external normal calls**, one per ordinary/mask/whole-register
family, were executed using the retained adapter in
`scripts/replay_bulk_boundary_task127.py`. The initial two-call script and a
mask-only follow-up variant are retained; the final repository script reproduces
the three-call selection. The two prior passing calls were not repeated. Frozen
source, ELF, signature checker, expected results and retained capture hashes
were authenticated; original B flags, original300s timeout and Task109 DUT
predicate were reused. No reference engine, guest compiler, expected-answer
edit or extra workload flag. These establish normal regression only, not
admission of the new boundary or bulk host-fault recovery. Mask-byte behavior
shares the changed checked boundary; its one original normal case also passes.

## Retained evidence, failures and remaining limits

[Receipts](docs/rvv-validation/bulk-boundary-task127/receipts.tar.gz) contain build
streams/rcs, all preliminary/final test streams, executable identities, source
hash/equality, object disassembly, original three-call queues/inputs, commands,
results and raw external stdout/stderr/TB maps. Archive SHA256:
**557c9f8a70975b39d017e250a01e842ed4ea37143645891927ebc5ce8de10208**.
[Local raw audit](docs/rvv-validation/bulk-boundary-task127/LOCAL_RAW_AUDIT.json)
independently verifies **71 files**, zero differences. Full source/build and
external work/cache remain at the isolated remote root.

Failures remain: initial aggregate build rc2 at the new test's unqualified
VectorState (corrected to rv32::VectorState); preliminary passing host-copy run
3,772 checks preceded the final filter/wrap refinement. A first source-hash
script tried to read the asmjit gitlink directory as a file and failed before
hashing; regular-file filtering corrected the audit. Remote rg was unavailable;
grep retrieved the compiler error. Neither was a guest failure. Details are in
[attempt notes](docs/rvv-validation/bulk-boundary-task127/ATTEMPTS.md).

Unresolved: permitted unit-stride SIMD/libc/reference/verify copies and permitted
whole-register fixed/libc copies still lack owned SIMD commit capture, as listed
above. Native/gather/CCRF recovery remains separately open and untouched. Global
dispatcher unwind/CPU ownership is still not concurrent. No new signal code,
backing pin, device-memory contract, mapping-race guarantee, full RVWMO proof or
architectural restart is established. No guest signal-handler return, mapping
repair, same-PC guest retry, P4-04/equivalent blocked execution, full suite or
performance campaign was performed. `git diff --check` passes.
