# Task135 — exact synchronous boundary for QCG scalar vector memory

Continued **4f24318** while main audits134. Implementation/test commit:
**93cb0c0**. Evidence is committed separately. No push or closure. The launcher
signals main after this bounded task finishes.

The actual **QCG `Emit_vmemorynative` scalar loop remains enabled**. Its singleton
producers now publish exact guest-memory MOV sites and use the existing emitted
terminal cold exit. Owned synchronous SIGSEGV and SIGBUS reach the normal pending
memory-fault dispatcher boundary and FP cleanup. This does not grant ownership to
SIMD gather, LLVM or grouped frames.

## Implementation and real state locations

Changed `dbt/guest/rv32_qir.cpp`, `dbt/qmc/qir.h`, `dbt/qmc/qcg/qemit.{h,cpp}`,
`dbt/qmc/compile.h`, `dbt/guest/rv32_interp.cpp`, `dbt/rvv_native_fault.cpp` and
`dbt/rv32_signal.inc`. Added `dbt/rv32_scalar_native_fault_test.cpp` and its CMake
executable. No original guest, answer, input, checker or acceptance predicate edit.

Explicit producer annotation covers only singleton frames containing this loop:
ordinary unit/strided/indexed load/store, their unit/strided/indexed segment forms,
mask-byte load/store, and scalar whole-register load/store. The frame emitter
requires **n_members==1**, separately from NF/nregs. Whole SIMD retains its existing
annotation, guard and codec. Fault-only-first and vector-register gather use other
nodes and receive no new sites.

The scalar loop has **fixed scratch registers**, not allocated vector operands:

* **R8D:** current element/restart counter, initialized from architectural vstart.
  **R9D:** live VL, mask-byte ceil(VL/8), or whole EVL=nregs*regbytes/encoded_EEW.
* **R10D:** base from synchronized architectural x[rs1], or zero for x0.
  **R11D:** scalar stride from synchronized x[rs2], or zero for x0.
* **EDI:** current field's actual RV32 address. Unit mode computes
  element*EEW*NF; stride mode uses low32(element*stride); indexed mode reads the
  offset at its index EEW from CPUState and takes its RV32 low32 value. Base and
  field additions use 32-bit arithmetic. A field can wrap independently.
* **RCX/ECX/CX/CL:** field data. Each completed load is immediately published into
  CPUState before the next field/element access. A field is **statically unrolled**,
  not a guessed dynamic counter: its site records field, NF and actual data EEW.
  Indexed data EEW comes from SEW, independently of encoded index EEW. Whole sites
  record encoded load EEW/store EEW1, nregs as event NF, and field0.

`stateaddr(width)` maps logical element bytes into fixed **512-byte physical
register slots** using the node's guest regbytes. Field bases use
`data + field*fieldregs`; neither consecutive fields nor a register group are
assumed physically contiguous at small guest VLEN. Mask testing/search and index
loads remain CPUState accesses. vstart is published from R8D before guest fields;
normal completion clears it. Masked-off elements perform no guest access, including
the existing active-mask search path, which rereads v0.

The enclosing `rvvtypedchunkbegin` already carries HAS_CALLS. Actual
`QRegAlloc::CallOp(true)` spills call-clobbered GPRs/VPRs and synchronizes dirty
guest globals **before** guard/body execution. The loop uses those call-clobbered
scratch registers and leaves surviving callee-saved locals alone. Existing pin
publication executes at the annotated begin; the requested-pin fixture verifies
actual region **n_pins=0** through HAS_CALLS exclusion. This is not evidence of
recovering arbitrary live/pinned allocations in other nodes. An older allocated
`addi x6,x0,0x123` is checked at every normal/terminal boundary.

Exact finalized instruction offsets cover only regular scalar guest MOVs. CPUState
base/index/mask reads, destination publication and spills have no site. Metadata
registration validates scalar width==EEW, EDI/RCX register IDs, zero displacement,
unmasked host access and field/NF bounds. Guest masking is enforced by the loop,
not an x86 opmask. The final offset registry/code-pool lifetime remains unchanged.

## Admission, split fields and signal exit

`qcgstub_rv32_scalar_memory_safe` is reached through the **existing**
`rv32_native_memory_safe` runtime slot with a private reserved-MEW call tag. The
stub removes the tag; all architectural, helper and site raw words stay unchanged.
No runtime table slot or CPUState layout was added. ABI remains
**a89957277993e0d9**.

The read-only scalar preflight checks runtime geometry/register legality, guest
permissions and ordinary anonymous/regular-file backing for **active fields from
vstart**. Nonzero vstart is admissible for this loop. It rejects any active
page-crossing field, which also catches an element crossing 2^32. A legal indexed
load whose destination overlaps its index group selects checked fallback: its
publication could change later offsets, so entry preflight must not claim to
predict that evolving loop. Masked-off addresses are skipped. Unsupported shapes,
backing and guard mismatches use each frame's original checked helper; scalar
fallback does not enter the unit-only raw arm of the terminal stub.

Thus page-contained admitted fields retain the original scalar-native MOV body.
Split/wrapping fields select the existing checked instruction before any native
access. Checked loads stage a complete field before publication. Permission
preflight prevents a predicted denied store from publishing any part of that field.
An **unexpected host fault during a checked misaligned store can retain completed
byte primitives inside the failed field**. The terminal split-store check explicitly
verifies that prefix. No all-or-none element claim is inferred from a scalar MOV.
Earlier fields of a failed segment element remain published; vstart identifies the
current element and the event separately identifies its field.

The signal callback requires exact registered RIP, TLS owner/R13 identity, actual
EDI footprint, address-space/page containment and si_addr within that field. SEGV
ownership retains the synchronous user data #PF, direction and accepted-error-bit
checks. Scalar sites additionally accept **BUS_ADRERR/BUS_OBJERR**; actual validation
injects BUS_ADRERR through a regular file truncated in a fresh terminal child.
Chunk sites retain their prior SEGV-only contract. Software signals, MCE/other BUS
codes, unrelated PCs/addresses and CPUState accesses remain unowned.

The callback reads only context/immutable site/TLS state, captures R8D and EDI,
field/EEW/NF and signal/code, and redirects RIP to the existing emitted cold block.
Actual disassembly has **zero calls** in the callback. Signal return enters that
block, which destroys the nonleaf frame and tail-enters the existing terminal stub.
The stub queues the precise event, publishes vstart, closes deferred FP state and
unwinds to the dispatcher. `HelperSiginfo` now accepts the validated native-origin
BUS event as well as checked-copy BUS. No guest handler runs, and the guest MOV is
never the signal-return target.

## Actual host512 build and bounded results

Isolated root: **xbd:/home/vick/rvdbt-scalar-native-task135/**; fresh **build/**,
source **source/** inherited from Task133 and overlaid with the committed changes.
[Source equality](docs/rvv-validation/scalar-native-task135/SOURCE_EQUALITY.json):
**297** inputs match hashes generated directly from `git show 93cb0c0:<path>`.
[Dependencies](docs/rvv-validation/scalar-native-task135/DEPENDENCY_EQUALITY.json):
**443** files equal the retained Task133 dependency tree. Zero differences.

Real Ryzen9 9950X3D with AVX512F/BW/BMI2, Clang22/LLVM22.1.6, Release,
**RVV_HOST_CHUNK_BITS=512**, actual **-mavx512f -mavx512bw -O3 -DNDEBUG**.
[Flags/cache audit](docs/rvv-validation/scalar-native-task135/FLAGS_AUDIT.json):
**53** production commands, including **52 C++** and one assembly command.
Configure180s/build900s; build nice10, cores28–31, -j4. Focused checks sequential
core28/60s; external batch core28/nice10/600s, original per-call300s. Core dumps
disabled. `ldd -r` has no unresolved symbols. Final load0.92/0.60/0.50 is a scheduling
diagnostic, not performance evidence.

Final [binary identities](docs/rvv-validation/scalar-native-task135/FINAL_IDENTITY.json):

* elfrun: **63748da4d0ed9588d78bc576919303796d9370b0605eeadf55e1a80da6343f20**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**
* scalar fixture: **e8124330a934c47beeed15a44bbf7085811d2d3c8f2f87abf95654955049557a**

[Final commands/results](docs/rvv-validation/scalar-native-task135/FOCUSED_RESULTS.json)
are gated on successful build and pinned before/after identities:

| Check | Result |
|---|---|
| Scalar normal-only | **1,919 parent checks PASS**, zero terminal children |
| Scalar reviewed terminal batch | **2,029 parent checks PASS**, **44 terminal cells** |
| Existing whole native normal-only | **13,330 checks PASS**, zero terminal children |
| Four unchanged ACT B original calls | **4/4 PASS**, original whole-file DUT predicate |

Focused scalar guest VLEN is512; XLEN32/ELEN64. Ordinary data EEW1/2/4/8,
unit/strided/indexed **two-field** load/store, indexed data64 with index32, sparse
mask/nonzero start with active-mask enumeration, mask EVL, scalar two-register whole
EVL (vill/VL-independent), negative stride, indexed wrapped address formation and
completed-vstart no-access are exercised. Normal code explicitly selects existing
scalar routes with dedicated unit/whole SIMD switches off; **no force-emission**.
This is supported scalar route selection, not disabling scalar native memory.

The final44 cells comprise **38 SIGSEGV**, **2 SIGBUS**, and **4 predicted checked
faults**. Of the host faults, **38 own scalar native sites** and **2 use checked split
copies**. The focused harness uses actual production translation, QRA, finalized site
registration and cold exit. It removes the final QIR gbr and appends a standalone
return for normal `Enter`; terminal children use the real production trampoline
and unwind checkpoint, with the cold block unchanged. Each child observes at most
one host fault, captures terminal dispatcher
state and exits. Both load/store segment field1 faults retain field0 of that same
element. Both split fields fail before load publication; an unexpected split-store
host fault retains its byte prefix. Both wrapped split fields predict denial at
address0 with unchanged field/top bytes; the actual zero-membase build cannot map
host page0 under host policy. Successful **wrapped address formation** is separately
executed through actual indexed scalar code into mapped ordinary RAM. Successful
split-across-2^32 copying with page0 mapped is not claimed.

The upstream cases are original **Vls32-vlseg2e32.v, Vls32-vlse32.v,
Vls32-vluxei32.v, Vls32-vlm.v**, armB, guest VLEN1024. [External audit](docs/rvv-validation/scalar-native-task135/EXTERNAL_AUDIT.json)
checks complete original call equality, original flags except relocated paths,
source/ELF/answer/checker/capture hashes, ELF32/LE, final pins and independently
recomputes the original predicate from raw streams. Original inputs are copied for
retention; no guest compilation, reference engine or generator ran. These normal
passes do not prove target-specific native fault ownership.

[Offline audit](docs/rvv-validation/scalar-native-task135/OFFLINE_AUDIT.json)
authenticates **1,174** receipt files, independently recomputes all **32 fixed
register slots** and retained completed memory bytes for42 scalar geometries,
checks both wrapped snapshots, events/PC/GPR6/vstart/VL/vtype, and decodes **38**
actual emitted shapes. Guest sites exclude CPUState operands; load publication
precedes the next normal guest MOV; cold blocks contain the real terminal tail jump.
The audit executes zero guest instructions. Zero differences.

## Retained attempts and remaining contracts

[Retained attempts](docs/rvv-validation/scalar-native-task135/ATTEMPTS.md) include
three failed builds: adding a runtime slot moved the asserted CPUState
layout; then incorrect ArchTraits register constant names; then a transport failure
prevented those fixes from reaching the source, so the same constant errors remained.
All were corrected. **No test executes after a failed build**, and final validation
runs only after successful builds plus final binary identity checks. Source transfers
were subsequently explicitly gated on success.

Earlier normal-only attempts caught fixture issues: standalone return into the
production trampoline's intentional INT3 (also inspected once under gdb), illegal
RV32 index64 encoding, incorrectly initialized index width, and attempted host page0
mapping. Those attempts receive no final credit. The normal Enter harness and the
real production terminal trampoline now have their appropriate separate uses.

The first terminal batch completed **33 fresh SEGV children**, then one fresh BUS
child reached the cold stub but was rejected by the old event formatter. Its panic
and failed parent are retained. Final reviewed validation uses the corrected event
contract and final executable. Physical totals across these attempts are **78 terminal
children, 74 memory host faults (71 SEGV/3 BUS)**; only the final44 cells receive final
coverage credit. There was no repaired mapping, guest handler return or reentry of
any faulting child/instruction. Offline audit also retained its initial wrong expected
shape-count assertion (38 shapes were present); it required no execution or production
change.

Remaining contracts: optional SIMD strided gather, LLVM, grouped QCG and other
unannotated/native nodes do **not** inherit this ownership. Arbitrary live/pinned
state recovery is not established. Scalar indexed-load overlap, split/wrapping
fields and unsupported backing keep checked fallback. Page provenance/permission
preflight is not mapping residency or concurrency/lifetime pinning. BUS_OBJERR is
accepted but not directly injected; nonaccepted #PF/BUS errors remain unowned.
Focused geometry does not exhaust VLEN/LMUL/fieldregs, ordered-indexed encoding or
all EEW split combinations. Existing whole/grouped/LLVM boundaries remain as in
Task134; no claim is inferred from the whole normal regression.

No full corpus, performance matrix, guest handler return, mapping repair/same-PC
retry, P4-04/equivalent, push or closure. **Guest restart is NOT verified.**

[Receipt archive](docs/rvv-validation/scalar-native-task135/receipts.tar.gz): SHA256
**121623f023dfe4685cd580b6056d4307c4a1f655b0a5565480d947e121955a18**.
Local raw: **/home/user/research/materials/task135-scalar-native-raw-20261013/**.
Remote isolated source/build/full raw remain at the root above. Extraction reported
approximately3s host-clock timestamp skew; all manifest bytes verify. Python syntax
checks and `git diff --check` pass. No preceding task evidence was overwritten.
