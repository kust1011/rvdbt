# Task130 — ordinary QCG unit-memory publication/site prerequisite checkpoint

Started from **38d325b**, main audits129, on `fix/rvv-memory-families-issue-1`.
Implementation/test commit: **d86355b**. Evidence is committed separately.
**Native unexpected-fault recovery is not complete.** This checkpoint implements
exact ordinary SIMD guest-access identification and an earlier-chunk publication
fix. It demonstrates the remaining intra-chunk state prerequisite without retry.
No push or issue closure; launcher owns completion signaling.

## Exact implemented code and scope

* `dbt/guest/rv32_qir.cpp`, `RvvEmitTypedVleChunkGroup`: QCG full and partial
  arms now pair each `vchunkload` with its architectural `vstatechunkstore`
  before issuing the next guest load. Previously **all guest loads preceded all
  destination publications**; an unexpected second-chunk fault lost the first
  completed chunk from CPUState. These EMUL=1 chunks have disjoint destination
  windows and no vector input overlap. Width, guest displacement, active mask,
  fallback, guards and typed-node counts stay the same. LLVM retains its previous
  load-major SSA shape. There is no additional normal guest read or scalarization.
* Both ordinary singleton `vle` and `vse` producers annotate the typed begin with
  the actual translator `insn_ip`, using the new `native_memory_pc` field in
  `dbt/qmc/qir.h`. Block entry is not substituted for the instruction PC.
* `dbt/qmc/qcg/qemit.cpp`, `NoteNativeMemorySite`: immediately before the final
  indirect guest SIMD instruction, record its section offset, guest PC/raw,
  EEW, transfer bytes, displacement, CPUState base slot, actual allocated data
  VPR, address scratch register, mask register and direction. Full and partial
  arms use the same recorder. Mask setup/base-state reads and destination/source
  state accesses are **excluded**. Generic pointer nodes, unannotated producers
  and multi-member frames receive no attribution. Ordinary unmasked unit-stride
  encoding is checked; this is not a memory-family range catch.
* `dbt/qmc/compile.h` / `QEmit::EmitCode`: the runtime receives a borrowed site
  span after final relocation/copy and before execution. The default callback
  ignores it. `dbt/execute.cpp`'s actual JIT runtime copies these records through
  `tcache::RegisterNativeMemorySites`; offline/AOT runtimes gain no ownership.
* `dbt/tcache/tcache.{h,cpp}`: an exact-PC **host-stack inspection** table lives
  with the code pool. It survives guest target revocation because revocation
  unlinks lookups, not all extant executable bytes; old code can still be linked.
  Init, whole-cache Invalidate and Destroy clear it with physical code lifetime.
  Site offsets are checked against the allocated span. Lookup does not accept
  interior PCs. This unordered_map is **not signal safe and is never called by
  a production signal handler**. No signal ownership/escape behavior was added.
* `dbt/rv32_native_memory_site_test.cpp`: real guest translation, QSel, RA and
  QEmit, normal executable checks and terminal one-time native fault inspection.
  The existing route test now checks load/publication order in QIR and independently
  decoded actual JIT bytes, permitting physical VPR reuse after publication.

The shared implemented mechanism is final guest-access site publication through
CompilerRuntime, with JIT lifetime managed by the existing tcache. It is useful
inspection infrastructure, **not a complete architectural recovery descriptor**.
There is no progress field invented from an address and no unsupported RA map.

## Contract audit and concrete remaining prerequisite

Read qemit guards/full/partial bodies/publication, QRA CallOp/Spill/retirement/
block and region boundaries, tcache allocation/reset/revocation, Execute,
ukernel signal/dispatcher paths and the checked-copy boundary/FinishHelperMemoryFault.

| Required contract | Actual established boundary / missing prerequisite |
|---|---|
| Host PC and lifetime | Final SIMD access start only, tied to the actual code pool. Normal-context exact-PC inspection exists. Production async-safe lookup/capture is not implemented. |
| Guest PC/raw/EEW/access | Producer's actual singleton PC/raw plus emitted width/direction. Full/partial masks and displacements retained; not inferred from stale block entry or `si_addr`. |
| Earlier instruction state | PreSideeff writes the current instruction PC. Typed begin's HAS_CALLS invokes QRA CallOp(true) before the branched guard/body: dirty globals synchronize and call-clobbered locals spill. The fixture's preceding allocated `addi x6,x0,0x123` is present in CPUState at every native fault. This is not a general per-host-PC RA snapshot for arbitrary runs. |
| Completed load state | Completed earlier QCG chunks are now published before the next guest access. A faulting SIMD load has not supplied its earlier lanes to architectural destination storage. Full/partial one-time observations retain the entire first chunk and leave the second unchanged. |
| Store state | Earlier SIMD stores are retained. The faulting store exposes no architectural completed-lane frontier. Accessible bytes captured inside that chunk are observations, not an atomicity/ordering guarantee. |
| Precise `vstart` | **Unavailable inside a faulting SIMD chunk.** Existing bodies leave `vstart=0` until completion; these actual faults retain that value. A chunk address and `si_addr` do not establish which element completed. There is no claim that the observed zero is a correct trap frontier. |
| Host locations | R13 is CPUState; AX/RAX is the zero-extended guest base scratch. RBP supplies membase on nonzero-base builds. Actual allocated vector register and K7/none are recorded per final access. Loads hold new data in their allocated VPR until state publication; stores load source VPRs from state. Local receipts retain all 23 gregs and state slices; they do not decode XSAVE or recover other live locals. |
| C++/FP-safe dispatcher exit | Existing checked-copy leaves redirect only their exact armed guest MOV PC to a frameless failure return, allowing ordinary C++ body/census cleanup. FinishHelperMemoryFault closes deferred FP state/restores MXCSR before RaiseTrap to Execute's dispatcher boundary. **Native SIMD has no corresponding supported cold exit/state restoration contract.** No handler longjmp or jump into an ordinary success join/helper replay was added. |

The next implementation prerequisite is a paired **emitted-access completion and
publication ABI**: for every accepted synchronous fault it must preserve every
required element before an exact restart index, preserve prior guest instructions,
identify live host/spill locations and reach an emitted cold exit that tears down
the correct frame, queues the existing event and performs normal C++/FP cleanup.
The current SIMD body supplies no completed element values/frontier within its
faulting access. Reading the accessible prefix again, calling the whole guest
helper, or restarting at a chunk boundary would execute the operation again;
none was done. Catching a code range or borrowing QEMU's unwind would not create
the missing state contract. The scalar native loop's R8/current-element publication
is a different ABI and was not used to label SIMD progress.

The [pinned RVV 1.0 exception rules](https://github.com/riscvarchive/riscv-v-spec/blob/3570f998903f00352552b670f1f7b7334f0a144a/v-spec.adoc#exception-handling)
require prior instructions and results before `vstart` to be committed. They
permit some later updates when restart produces the right result; this checkpoint
neither establishes such a restart contract nor executes a restart.
[QEMU v9.2.0's pinned signal path](https://github.com/qemu/qemu/blob/ae35f033b874c627d81d51070187fbf55f0bf1a7/linux-user/signal.c)
checks translated code ownership and passes host PC into its CPU exit machinery.
Its protected-TB write repair/restart is not adopted.
[Linux v6.12 x86 sigcontext](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/arch/x86/include/uapi/asm/sigcontext.h)
supplies saved GPRs and an extended FP-state pointer; it supplies no guest-element
completion metadata. [Primary-source pins/hashes](docs/rvv-validation/native-memory-task130/AUTHORITATIVE_SOURCES.json)
are retained. No broad external research was needed.

## Isolated actual host512 production build and bounded validation

Fresh source/build root: **xbd:/home/vick/rvdbt-native-memory-task130/**.
Copied the actual Task128 dependency/source tree, overlaid current production
inputs and configured a new build directory. [Source equality](docs/rvv-validation/native-memory-task130/SOURCE_EQUALITY.json)
checks **290** tracked production/build regular files against d86355b, zero
differences. [Dependency equality](docs/rvv-validation/native-memory-task130/DEPENDENCY_EQUALITY.json)
checks the inherited third-party file contents against Task128, zero differences.
Actual compiled flags/cache, CPU probe and compiler output are in the archive:
Clang22/LLVM22.1.6, Release, **RVV_HOST_CHUNK_BITS=512, -mavx512f -mavx512bw**.
The local native test requires real AVX512F/BMI2, with force emission **off**.

Configure exit0; production elfrun/shared library and four focused targets built
exit0; `ldd -r` has no unresolved symbols. Final executable SHA256:
**c1a75778e29ee60dcc1b707628d5c1f6a85db60d2bcf9514b90d9d38f8f3baff**.
Shared library SHA256:
**79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**.
Final/first production hashes are equal; the three original external calls were
not repeated after the evidence-only test refinement.

Used nice10, cores28–31, -j4, configure180s/build900s; focused checks sequential
on core28, timeout60s each, core dumps disabled. Initial/final observed load:
**0.64/0.64/0.99**, **0.72/0.70/0.92**. No full suite or performance campaign.

| Check | Actual result |
|---|---|
| rv32_native_memory_site_test, final | exit0; 5,581 checks; 16 terminal native fault cells |
| vle32v_typedchunk_route_test | exit0, PASS; QIR/RA/actual JIT-byte order and exact site offsets |
| vse32v_typedchunk_route_test | exit0, PASS; unchanged normal emitted store shape |
| rv32_unit_memory_fault_test | exit0; 9,562 checks, 1,248 cells; ABI ce212ddc4742de49 |
| Original ACT B Vls32-vle32.v | PASS, original whole-file DUT predicate |
| Original ACT B Vls64-vle64.v | PASS, original whole-file DUT predicate |
| Original ACT B Vls32-vse32.v | PASS, original whole-file DUT predicate |

Local cells: load/store × EEW32/64 × full/partial VL × fault at the second chunk
start/one element inside it, guest VLEN1024, actual SIMD64-byte access. Each cell
has a separate normal invocation before its faulting invocation. In the child,
raw host mprotect makes the second page inaccessible while MMU metadata and
MappingEpoch remain unchanged; the real unit-memory preflight still returns1.
The callback accepts only the selected exact finalized guest access and bounded
fault footprint, captures saved registers/state, then **_exit(0)**. It never
returns to guest code. Only actual SEGV_ACCERR is demonstrated here; BUS handling
in the fixture is not new BUS coverage. Page-start addresses are fixture checks,
not a progress algorithm. State publications remain unrelated host accesses.

The standalone executable fixture replaces the final guest branch with a return
and undoes the normal nonleaf alignment push, using the existing Enter harness
and portable stub-table calls. It executes the real translated body and guards;
it is **not** a test of a production native fault-to-dispatcher exit. The existing
route test separately inspects actual JIT-mode bytes. The prior checked-helper
unit test covers its existing dispatcher boundary, not this native gap.

The [offline independent emitted/capture audit](docs/rvv-validation/native-memory-task130/EMITTED_CAPTURE_AUDIT.json)
checks **8 shapes, 24 exact final sites, 16 snapshots**: decoded instruction,
allocated VPR, address/displacement, K7/none, direction and load/publication order.
It recomputes full destination/earlier-memory observations from saved state.
A separate local copy reproduces the same JSON exactly, with zero guest executions.

Only three unchanged original external normal calls were selected by
`scripts/replay_native_memory_task130.py`. Original source/ELF/checker/expected/
capture hashes, complete B call objects/flags and original300s predicate are
retained/authenticated by the original adapter. [External audit](docs/rvv-validation/native-memory-task130/EXTERNAL_AUDIT.json)
confirms membership, unchanged inputs and identical final production identity.
No original source/answer/checker edit, new reference, compilation of guest tests,
extra workload flag or native-fault credit is assigned to these normal passes.

## Evidence, attempts and remaining limits

[Receipt archive](docs/rvv-validation/native-memory-task130/receipts.tar.gz):
SHA256 **e9544eaf143a624b8d2828cda1f44d0792abf6e66486ff18cf5926637cc50f5e**.
[Independent original-raw audit](docs/rvv-validation/native-memory-task130/LOCAL_RAW_AUDIT.json)
verifies **122** manifest files, zero differences. Local raw:
**/home/user/research/materials/task130-native-memory-raw-20261013/**.
Full isolated source/build, external work/cache and raw remain remote. The archive
retains configure/build streams, actual flags/cache, source/dependency identities,
first/final checks, emitted binaries/site lists/disassembly, 16 complete capture
records, original external queues/commands/results/streams/identities and scripts.

All guest checks passed. Preliminary checks preceded additional emitted-order
assertions and binary/capture retention; their streams remain separate. A second
build/check validated that refinement and formatting; production executable/library
hashes did not change. Setup-only mistakes: local `python` was absent (used python3);
the first tar put its exclusion after its file list and returned nonzero although
it produced the overlay (the local submodule directory was empty, so inherited
dependency contents remained intact); final overlay used the correct option order.
Two diagnostic tail/grep invocations had invalid options and were replaced by
explicit commands. The first local offline audit wrote derived disassembly into
the extracted raw directory; original raw was re-extracted and all122 hashes
reverified, then independent derivation ran in a separate copy. No guest failure
was repaired or relabeled, and no failing operation was reexecuted.

Still unresolved: precise intra-SIMD native fault state, signal-safe site/state
lookup and native C++/FP-safe cold exit; general runs/pinned-state snapshots,
scalar native recovery, LLVM memory faults, gathers, permitted helper bulk copies,
whole-register SIMD, concurrent mapping/backing lifetime and CCRF recovery remain
outside this implemented boundary. Exact-PC inspection and permission preflight
are not recovery. No guest handler execution/return, repair-mapping or same-PC
retry, P4-04/equivalent, suppressed signal, skipped required element, full external
corpus or performance run occurred. `git diff --check` passes.
