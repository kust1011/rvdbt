# Linux RV32 signal interface increment (Refs #1)

Checked helpers and admitted singleton QCG memory bodies have bounded fault
handling. The signal-copy correction below is included in the
[final host512 regression](../host512-task142/README.md). Complete guest
handler return/restart remains unverified; broad issue #1 is not closed.

## Task141 checked signal buffers (current bounded correction)

Production correction `ad5e3c8` replaces the raw guest `memcpy` in the common
`rv32_signal::CopyIn/CopyOut` boundary with owned `rvv_host_copy::CopyElements`
byte transfers after the existing nonwrapping, per-page permission checks.
Calls respect the checked leaf's signed count limit. Exact access-PC ownership
and the production SIGSEGV/SIGBUS callback return backing faults normally,
without a callback longjmp. This supersedes the **signal frame/action/mask copy**
part of the Task140 table below; general syscall marshalling remains open.

`rt_sigaction` and `rt_sigprocmask` return `-EFAULT` on failed output copies
before changing action/mask state, including queries. Guest output bytes can
retain a copied prefix after an unexpected backing fault. Delivery still refuses
a failed frame copy; restoration still stages and validates the frame before
architectural writeback. Signal layouts, flags, trampoline and existing
rejection rules are unchanged.

The existing production-interface regression now tests normal, denied,
nonwrapping, cross-page and truncated-file buffers through these wrappers and
the production callbacks. It checks EFAULT and unchanged actions/masks for
first-byte and crossing output faults, all three mask operations, permission
and overflow failures, and truncated delivery/restore rejection. File truncation
happens once per isolated child; no mapping repair or guest execution occurs.
The FRM test's obsolete host CPUState-size assertion is aligned with the already
pinned Task131 production size (42720); no ABI layout is changed.

Local engineering results: **1876 parent interface checks**, **101 input-child
and 86 output-child checks**, **256 FRM roundtrips / 192 badframes**, and
**27 MMU checks**, all passing. `elfrun` also builds but is not executed here.
These checks are distinct from external corpus coverage: no external fixtures
or corpus were rerun, and no external expected values changed. Raw builds,
original fatal witnesses, the copy-only EFAULT failure and final results are in
[Task141 receipt](../../../SESSION0_RESULT_141.md).

Generic scalar/atomic lowering, optional gather/LLVM ownership and general
syscall marshalling are outside this correction. Broad issue #1 remains open.
Guest handler-return/restart, repaired-mapping and same-PC retry execution,
including equivalents, remain prohibited and untested.

## Current issue #1 acceptance on QCG (Task140, source audit only)

This table supersedes the **current-work interpretation** of the historical
Tasks113–126 descriptions below and the 961f022 `FAULT_CONTRACT.md`; their
original build identities and results remain historical evidence. Audited source:
**47bc1be**, with **zero dbt/CMake source differences against merged 15618a8**.
Task139 publication and its pinned executable are unaffected.

Here QCG means the serialized RV32/ELEN64 execution profile with LLVM, CCRF,
helper AVX2 gather and emitted Z3 strided gather excluded. CLI defaults are explicit:
`elfrun.cpp:496` selects LLVM where applicable by default, so pure QCG requires
`--aot-use-llvm=0`; `:497` enables the common typed QCG route, while
`:575,583,617,640` leave dedicated unit/whole SIMD, CCRF and
helper gather off. `config.h:3067` leaves Z3 gather off. Stock pure QCG therefore
uses more checked helpers than the retained B/M1/M2/BOTH direct-route profiles.
The direct QCG paths below are also audited because those accepted profiles enable
them; enabled switches alone are not proof of dynamic admission.

**No new unhandled default RVV memory route was found. Broad default QCG still
has known unhandled non-vector memory and signal-buffer host-fault paths.**
Guest return/restart is implemented but execution acceptance remains blocked;
it must not be listed as missing codec implementation or as restart PASS.

| Acceptance item | Exact current implementation and existing evidence | Remaining action / disposition |
|---|---|---|
| Ordinary, strided, indexed, segment, mask and whole helpers | `rv32_interp.cpp::HBody_vle/HBody_vse` at727/748, `OrdinaryMemory` at714 and `SpecialMemory` at705 reach `rv32_vector_lower.h::memory_checked` at615 or `unit_stride_checked` at636. `dispatch_load/store_unit_stride` at3613/3620 always use the checked loop. `mmu.h::FirstDenied` at117 probes each complete field; masks/prestart skip before index/probe. `rvv_host_copy.cpp::Copy` at75 stages loads, preserves aligned width and decomposes misaligned/wrapped fields; `CopyElements` at115 exposes completed-element count. Task124 width checks, Task132's266 terminal bulk snapshots and existing unit/family/special tests establish bounded prefixes/frontiers. | No identified implementation work for these supported routes. Earlier permitted libc/SSE/fixed-copy helper bypasses were removed by132; do not reassign127's old gap. Unexpected split stores may retain byte prefixes. Finite tests are not exhaustive fault coverage. |
| FOF | `rv32_vector_lower.h::load_fault_only_first` at790 and `rv32_interp.cpp::HBody_vleff` at800 use checked field copies: absolute element0 queues, later failures trim VL. Tasks113/126/128 retain eight exit-only delivery/control calls;132 retains two BUS observations. | No new gap found. Exit-only delivery and manual incoming-vstart checks do not establish guest return/restart. |
| Singleton native QCG SIMD and scalar vector memory | `rv32_interp.cpp::qcgstub_rv32_native_memory_safe` at553 admits anonymous, page-contained active SIMD chunks; `qcgstub_rv32_scalar_memory_safe` at615 admits page-contained ordinary anonymous/regular-file active fields, rejecting evolving indexed-load overlap. `qemit.cpp::Emit_vmemorynative` at3274 records regular field MOV sites at3352; `NoteNativeMemorySite` at4537 records SIMD accesses. `rvv_native_fault.cpp::Register` at32 and `HandleSignal` at60 validate exact PCs/owner/footprint: SIMD owns accepted user data #PF only, scalar sites also ADRERR/OBJERR. `qcgstub_rv32_native_memory_fault` at111 queues after the emitted cold exit. Existing131:40 terminal cells,133:30 distinct whole geometries,135:44 terminal cells;135/136 audits independently decode sites/state. | No new gap in the accepted contract. File-backed SIMD, crossings, split/wrap, overlap and guard misses reach checked helpers before body access. Nonaccepted #PF/BUS/MCE remain unowned; actual OBJERR and broad geometry coverage are unverified. Provenance is not a mapping/backing lifetime pin. |
| Prior state, memory runs, registry lifetime and dispatcher | `qra.cpp::CallOp` at988 / `visitInstRVVTypedChunkBegin` at1164 synchronize globals before guards; scalar/site annotations come from actual instruction PC. `rv32_qir.cpp:9904` enables QCG memory cuts; `rv32_vrun.cpp::FormRun` at1132 cuts memory; `qemit.cpp::Emit_rvvtypedchunkbegin` at2005 rejects multi-member memory, and `Emit_rvvtypedchunkend` at2370 uses ordered helpers and at2386 builds the cold exit. `tcache.cpp:204,223,244,259` publishes/clears ownership with code lifetime. `rv32_interp.cpp::FinishHelperMemoryFault` at51 runs after scopes; `ukernel.cpp::CaptureHelperMemoryFault` at242 and `Execute` at301 capture/deliver after `execute.cpp::Execute` at226 unwinds. Task136:ten terminal children,585 normal checks;137 full codegen PASS resolves the22 old golden failures. | No grouped native implementation task on this profile: memory uses instruction boundaries, including with M1/component order enabled. Arbitrary live/pinned recovery, concurrent guest/cache/mapping lifecycle and reordered CCRF recovery are outside this established contract. |
| Guest signal return and instruction continuation | `rv32_signal.inc::DeliverHelperSignal` at121 builds frame/trampoline (`li a7,139; ecall`, at167); `RestoreSignalFrame` at187 validates before architectural writeback and restores PC/a0/FP/vector/mask. `SignalSyscall` at67 and `ukernel.cpp::SyscallLinux` at1267 bypass ordinary a0 writeback; dispatcher ECALL at323 advances PC before restoration. `rv32_signal_interface_test.cpp:153,163–167,202–208` and `rv32_signal_frm_test.cpp:39–61` directly call host APIs (Task126:1792 checks,256 roundtrips/192 badframes). | **Implemented; execution-blocked acceptance.** No guest sigreturn/return/restart PASS. P4-04 and equivalent repair-mapping/handler-return/same-PC-retry execution remain prohibited, including renamed/delegated variants. Retained source/codec evidence cannot discharge this row. |
| Generic scalar integer/FP/atomic guest memory | `rv32_qir.cpp::TranslateLoad/TranslateStore` at2357/2384 emit generic `vmload/vmstore`; `qemit.cpp::Emit_vmload/Emit_vmstore` at1394/1434 emit unowned direct MOVs. Interpreter `HANDLER_Load/Store` at180/189, `HBody_flw/fld/fsw/fsd` at2148–2158 and `HBody_lrw/scw/amoswapw/amoaddw` at2463–2497 likewise bypass checked capture. `ukernel.cpp::dbt_sigaction_memory` at417 falls through to `mmu.cpp::ReportGuestFault` at155 (Panic). This is the non-vector gap already recorded in118/119, not Task135's scalar **vector** loop. No existing dedicated scalar guest-delivery regression establishes acceptance; host-copy test at308–319 only establishes deliberate fatal handling of unrelated host PCs. | **Known default-path implementation work**, if broad issue1 includes these accesses. Preserve the source-only exit-handler witness in SESSION0_RESULT_140.md. Smallest common load/store correction: checked scalar runtime transfer with architectural publication at a call boundary, stage loads, queue actual PC/raw/direction/address after normal scope return; share across integer/FP widths. Atomic RMW needs its own exact-operation boundary, never load+store decomposition. Do not close broad issue1 from RVV receipts. |
| Signal frame/action/mask copies and syscall marshalling | `rv32_signal.inc::CopyIn/CopyOut` at41/46 check guest metadata then use unowned `memcpy`; delivery at156–174 and restore at196 consume them. `SignalSyscall` at98/108 also ignores output-copy failure. `ukernel.cpp::linux_writev/readv` at729/746 directly dereference guest iovec entries.118/126 explicitly retained frame/syscall-copy limits. Existing signal-interface test at23–48 tests predicted range/permission errors, not after-check backing loss;132's file-truncation capture tests belong to checked RVV copies only. | **Known default-path implementation boundary**, separate from missing guest-return execution. Shared signal copy can use the existing checked byte bulk leaf after range validation, returning failure normally; propagate every CopyOut failure before action/mask mutation, fail delivery/badframe cleanly. Preserve source-only truncated-buffer witness in140. General syscall marshalling needs checked guest buffers and syscall EFAULT handling, not conversion of every host syscall EFAULT into a guest signal. |
| Optional gather/LLVM | `rv32_interp.cpp:869` gates helper AVX2 gather; `rv32_vector_gather.cpp::rvv_gather_e32_avx2` at40 only preflights permissions. `qemit.cpp::EmitRvvStridedGather` at3167 is separately default-off. LLVM native ordinary/family accesses do not inherit QCG site ownership; shared whole admission at `rv32_interp.cpp:688` refuses unowned LLVM whole bodies. Existing117 gather value/permission tests and119/132 LLVM admission tests remain their bounded evidence. | Outside default QCG acceptance. Real recovery maps/publication/exit are needed before claiming these optional native routes recover unexpected faults. Do not invent a default-profile task to restore disabled grouped/LLVM whole SIMD. |

The retained **21,316 normal calls** (Task138, published by139) supply no new
fault/return/restart, concurrency or complete-state acceptance. No new execution,
coverage extrapolation or production correction was performed in140. Issue1 stays
open; the actionable implementation rows and blocked execution row are distinct.

## Historical Task113 increment

`rt_sigaction` now installs a guest SIGSEGV action instead of returning success
from a stub. The supported delivery ingress is a predicted element-zero FOF
load denial from `rvv_ref::load_fault_only_first`. General native load/store
fault materialization and precise restart remain separate obligations.

The design is adapted from the dirty P4 candidate at
`rvdbt-fault-delivery-20261009`, HEAD
`961f022d3be5fec26d64d5aaefc77346c921b652`. The candidate's fault record,
helper unwind, dispatcher and frame codec were reviewed as one dependency chain.
This increment does not change CPUState layout or its baked AOT ABI.

## Supported interface

- Syscall 134: a 16-byte little-endian RV32 action (handler at 0, flags at 4,
  64-bit mask at 8). SIGSEGV installations support flags 0 or SA_SIGINFO (4),
  and default disposition (handler 0). Queries support legal signals 1–64
  except SIGKILL/SIGSTOP. Other installations, SIG_IGN and unsupported flags
  return `-EOPNOTSUPP`; invalid signal/size returns `-EINVAL`.
- Syscall 135: exactly 8-byte guest masks, BLOCK/UNBLOCK/SETMASK. A null input
  queries the mask regardless of `how`. SIGKILL/SIGSTOP bits are cleared.
  Masks never alter the host signal mask.
- Syscall 139: restores the active frame's architectural state and PC. It returns
  before normal syscall a0 writeback. Malformed/unowned frames terminate the
  guest with a diagnostic, rather than returning success.
- Null optional pointers mean absent. Nonnull pointers are checked across every
  page and for RV32 overflow before copying. These checks use guest permissions,
  including write-only pages that the host might physically be able to read.
- `tgkill` returns `-ENOSYS`: asynchronous guest signal delivery is unsupported.
  It no longer routes guest signals into host diagnostic callbacks.

Blocked/default/ignored, nested, invalid-handler and unwritable-stack synchronous
faults terminate. Alternate stacks, SA_RESTART/SA_NODEFER/SA_RESETHAND, other
signal sources, relocated vector data and arbitrary user-created frames are
unsupported. The frame parser rejects alternate-stack edits instead of ignoring
them. Existing host SIGSEGV/SIGBUS callbacks retain diagnostic termination.

## Boundary contracts

1. **Record:** `QueueHelperMemoryFault` records value-only origin/access/reason,
   PC/raw/address/element/field/EEW/NF in the owning uthread, marks MEMORY_FAULT,
   and returns normally. The FOF helper leaves VL/vstart and committed bytes
   intact. It does not provoke a host fault.
2. **Unwind:** HBody returns on MEMORY_FAULT before advancing PC. Its census/body
   scopes end before `FinishHelperMemoryFault` closes the FP run, restores the
   per-run saved MXCSR in mode 0 or configured resting MXCSR in modes 1/2
   (including already closed deferred runs), and calls `RaiseTrap`. No helper-owned
   scope is crossed by this new longjmp.
3. **Dispatcher:** only after unwind does `CaptureHelperMemoryFault` copy live
   architectural state. The dispatcher consumes the pending record, then creates
   a frame on the ordinary dispatcher stack and transfers to the handler.
   Snapshot output records capture, not proof of handler completion or retry.
4. **Restoration:** read and validate the complete frame before architectural
   writeback; a bad frame may close host FP bookkeeping but does not partly
   restore registers/masks. Restore x1–x31, PC, D-register bits/fcsr (including
   all three frm bits), configured vector bytes and CSRs, guest mask and host
   MXCSR. Keep owner, caches, profile and bytes beyond configured VLEN intact.

## ABI rationale

The codec pins Linux **v6.12 native RV32 little-endian** layouts, independently
of host `unsigned long`, `sigaction`, `sigset_t` and `ucontext` sizes:

- [asm-generic signal.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal.h):
  64 signals, two RV32 mask words, no RISC-V SA_RESTORER field.
- [RISC-V ucontext.h](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/include/uapi/asm/ucontext.h),
  [ptrace.h](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/include/uapi/asm/ptrace.h),
  [sigcontext.h](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/include/uapi/asm/sigcontext.h):
  info=0, uc=128, mask=148, mcontext=288, FP=416, reserved=932,
  extension header=936, vector state=944, vector bytes=976.
- [signal.c](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/kernel/signal.c):
  16-byte frame alignment, vector magic 0x53465457, extension size
  `8 + aligned(6*4,16) + 32*vlenb = 40+32*vlenb`, and END magic/size zero.
  Handler arguments are signal/info/uc, and sigreturn restores a0.

## Tests and scope

Build `elfrun`, `rv32_signal_interface_test`, `rv32_signal_frm_test` and
`mmu_mapping_metadata_test` with CMake; run the three test executables with the
matching `build/lib` on LD_LIBRARY_PATH. The FRM source preserves the existing
P4-02 interface assertions (256 roundtrips, 192 high-bit badframes). The new test
checks syscall marshalling, guest permission metadata, host-mask isolation,
explicit unsupported cases, nested/badframe rejection and handler-edited PC/a0,
MXCSR modes 0/1/2 and VLEN 128/256/512/1024/2048/4096.
These are local host interface tests, **not external RVV conformance evidence**.

Task113 also replays P4-02's existing Ara `vl`, ACT positive `vfadd.vv`, and RVVTS
seed fixtures in B/M1/M2/BOTH with their original checkers and inputs. The result
receipt identifies this new executable separately from prior builds. No P4-04
execution is authorized or included. Frame roundtrips and helper delivery do not
establish general native fault recovery or complete instruction restart.

Final Task113 results: 376 focused checks, 27 MMU checks, 256 FRM roundtrips,
192 high-bit badframes, 12 normal-path configurations and eight existing exit-only
helper configurations passed. The latter execute no guest sigreturn. See
[RESULTS.json](RESULTS.json) for the exact build identity. Full commands, raw,
failed builds, candidate preservation and remaining obligations are retained in
Task113's workspace evidence and the thesis `SESSION0_RESULT_113.md` receipt.

## Task115 ordinary unit-stride design (base 032b5c4)

The historical FAULT_CONTRACT describes 961f022, not this base: Task113 now
provides `QueueHelperMemoryFault`, normal helper/census return followed by
`FinishHelperMemoryFault`, and dispatcher capture/delivery. Ordinary `vle/vse`
in `guest/rv32_interp.cpp` still select unchecked reference/chunked transfers;
QCG typed frames in `qmc/qcg/qemit.cpp::Emit_rvvtypedchunkbegin` guard vtype,
VL/vstart and address bounds but not guest permissions. Loads publish chunks
only after all memory reads, so native permission faults cannot preserve a prefix.

Reuse MMU's always-maintained readable/writable bitmaps (not optional observer
metadata). Add a wrapped range query returning the first denied byte. Before an
ordinary helper transfer, permit the existing chunked path only for an unmasked,
vstart-zero, wholly permitted active range. Otherwise execute active elements
in order, skipping masks/prestart before probing, setting vstart before each
probe, and checking the complete element before copying. On denial return a
value-only address to the handler; queue Load/Store, actual GET_GIP/raw, absolute
element, EEW, NF1/field0 and mapped/protection reason, then return normally.
Do not clear vstart or advance PC on fault. Normal completion clears vstart,
leaves VL unchanged and keeps inactive/tail bytes undisturbed. Element addresses
and permission probes wrap at RV32; a denied split element is not partially copied.

Every typed ordinary unit-stride frame in QCG and LLVM must call the same live
permission admission predicate before any native body access. HAS_CALLS already
publishes scalar state; the translators' existing RvvCommit/Reset publishes
vector SSA state. The guard reads the current base/VL and direction from raw,
checks the active byte range and reservation wrap, and sends unsafe mappings to
the precise helper. Existing shape/VL/vstart guards remain authoritative. This
retains SIMD on permitted mappings and does not specialize workloads or cache
permissions across mmap/mprotect. Guard calls occur before any frame temporaries.

FOF stays on its separate absolute-element-zero trap/later-element VL-trim
contract. Segment/indexed/whole-register precision, unexpected host SIGBUS,
concurrent mapping changes and full guest restart remain follow-ups. Local host
interface checks are not external ISA coverage; P4-04 and equivalent repair /
return / same-PC retry experiments are excluded. Historical suite/raw/build IDs
remain unchanged; candidate normal regressions get separate identities.

Task115 implementation also covers the general `RvvTryIntegerFamily` ordinary
unit-stride `vmemorynative` frames, through their existing vle/vse stub tag.
The permission guard conservatively probes the full active range even for a
masked native frame; denied inactive pages select the helper, whose mask check
precedes each probe and therefore queues no spurious fault. Nonzero vstart also
selects the helper. It verifies live VLEN against runtime configuration; AOT's
existing VLEN gate binds that configuration to the compiled artifact.

The admission stub is appended to `qmc/runtime_stubs.h`, preserving established
stub indices. The embedded table grows, changing later runtime/FP offsets and
`CPUStateAbiSignature` to `40cf59110e7e8839`. `ukernel.cpp` records the measured
layout tripwires. Old AOT artifacts are refused by the existing signature gate,
so their unchecked unit-stride bodies cannot survive through a stale cache.
Architectural GPR/vector/IP/trap offsets remain unchanged. Historical build/raw
results in RESULTS.json remain Task113 results; [UNIT_MEMORY_RESULTS.json](UNIT_MEMORY_RESULTS.json)
records the separate Task115 candidate and bounded validation.

## Task117 shared ordinary memory design (base cfa37bb; before implementation)

Use one checked element/field loop in `rv32_vector_lower.h` for ordinary
unit-stride, strided, indexed and segment helpers. Address selection is shared:
unit segments advance NF*data EEW, strided uses unsigned RV32 multiplication of
the signed scalar stride's bits, indexed reads unsigned byte offsets at index
EEW. Existing handler legality checks remain authoritative for independent
index/data EMUL, mask overlap, register bounds and segment field spacing.
Skip prestart/inactive elements before reading indices or probing permissions;
publish absolute element vstart, probe each complete field before copying, return
address/field values on denial. Completed elements and earlier fields of the
faulting segment remain committed; later fields/elements remain untouched.

Primary RVV 1.0 source: [v1.0 vector specification](https://github.com/riscvarchive/riscv-v-spec/blob/v1.0/v-spec.adoc),
sections 7.8 and 17: segment masking and vstart count whole segments; a faulting
segment may have a subset of fields accessed. This implementation chooses an
ascending field prefix, with no partial bytes within the denied field. This is
not segment-wide transactional rollback. Ordinary faults preserve VL and PC;
FOF's absolute-zero trap/later VL trim stays separate.

Extend typed-frame admission in QCG and LLVM for vlse/vsse, vlxei/vsxei and
vlseg/vsseg, including QCG's vmemorynative element/segment loops and Z3 AVX512
strided gather, LLVM C7/C8 masked gather/scatter, and the separate AVX2 indexed
helper gather. The guard scans live element/field addresses for guest permission
and rejects wrapping fields before native bodies; nonzero vstart uses checked
fallback. Conservative checks of inactive addresses may reject SIMD but the
helper never accesses inactive elements. Keep all existing safe shape routes.
Existing HAS_CALLS scalar publication and RvvCommit/Reset vector barriers apply;
add one admission call and O(VL*NF) permission probes per family frame, with index
reads for indexed forms. No measured performance claim. Append a runtime stub
so the changed table/layout signature rejects old unchecked AOT caches.

Validation is bounded local state/fault/native-route checks and retained external
original normal tests with original predicates on a new executable identity.
Unexpected host SIGBUS, concurrent remapping, native host-fault recovery and
complete restart are not solved by preflight. Whole-register/mask special EVL,
FOF expansion and external fault oracles remain follow-ups. P4-04/equivalent
repair/return/same-PC retry is excluded; neither issue is closed by this increment.

Task117 result: shared checked helpers now queue ordinary strided/indexed/segment
faults with absolute element and field coordinates. Every QCG/LLVM typed frame
for these families calls `rv32_family_memory_safe`; the separate AVX2 gather
checks read permission and refuses offsets above its positive signed-i32 range.
QCG Z3's own geometry/stride guards and LLVM's original shape guards remain.
Nonzero vstart selects the helper. Permission preflight is conservative for masks;
the checked helper suppresses inactive/prestart guest accesses. Unit-stride
fallback now delegates to the same loop. FOF and special EVL paths remain separate.

ABI is `b04553e010cbb4e9`; `CPUStateImpl` remains42688 bytes, `CPUState` becomes
42704, and fpu moves42264→42272. The old `40cf59110e7e8839` cache signature is
rejected by the actual AOT gate in a local host check. Architectural gpr/ip/vec/
trap offsets are unchanged. Pure QCG does not gain a new vector-SSA barrier;
existing HAS_CALLS publication applies. LLVM C7/C8 retain RvvCommit/Reset before
the frame. New cost is one admission call plus VL*NF field probes (with indices
read for indexed forms); no timing or performance result is claimed.

[Commands](FAMILY_MEMORY_COMMANDS.md) and [results](FAMILY_MEMORY_RESULTS.json)
record323410 family host checks/59424 cells,9562 unit checks/1248 cells,376 signal
checks, passing LLVM guard/value checks and88646 Z3 value checks. Twenty original
Ara normal calls pass1268 assertions/20052 comparisons; sixteen original CHIPS
indexed normal calls pass their original exit/stdout predicates. Actual local
native/fallback counters, Z3 fast completion and AVX2 admission are checked.
External Ara aggregate fallbacks belong to vmv.v.i, not target memory; CHIPS
original flags print helper census but omit RVV_DIRECT, so no native hit count
is invented. These results do not close issue #1 or transfer older full-suite or
performance results to this binary. Unexpected host faults/concurrent remapping,
complete restart, whole-register/mask EVL precision and additional FOF work remain.

## Task126 captured helper synchronous delivery

The current interface additionally installs SIGBUS (RV32 number 7) with the
same flags 0/SA_SIGINFO and default-disposition rules as SIGSEGV (11). It delivers
only existing predicted-helper events or owned checked-leaf HostCopy captures.
Queue validation and delivery share the explicit host-to-RV32 mapping:
SEGV_MAPERR→SIGSEGV/1, SEGV_ACCERR→SIGSEGV/2, BUS_ADRERR→SIGBUS/2,
BUS_OBJERR→SIGBUS/3. Predicted Unmapped/Protection remain SIGSEGV/1 or /2.
BUS_ADRALN, hardware poison, SI_USER/SI_KERNEL, unknown sources/codes and all
other signal installations remain unsupported. No new action flags are accepted.

The dispatcher uses the selected signal's action, mask bit, handler a0 and
siginfo number/code. Address is the already translated denied guest byte; PC,
GPR/FP/vector state, vstart and VL come from the existing clean snapshot. Linux
fault siginfo has no load/store field: direction and lane/field geometry stay in
the value-only event and snapshot; the delivery diagnostic also names direction.
Blocked/default/ignored faults, either kind of nested fault and invalid frames
retain the existing explicit termination behavior. A local API restore checks the
codec without executing a guest handler, sigreturn, repaired mapping or retry.

The callback still redirects only the owned leaf PC to its normal failed return.
Its kernel signal return restores the host mask before helper return/unwind;
Task126 adds no sigprocmask, allocation or longjmp to that callback. Frame
allocation remains on the normal dispatcher stack after helper scopes close.
Unrelated host faults remain fatal. Native, permitted bulk, gather, mapping-race
and guest restart limitations remain; this is no general OS signal subsystem.
See [Task126 report](../../../SESSION0_RESULT_126.md) for the new build/tests;
historical Task113–125 receipt identities and results above remain unchanged.
