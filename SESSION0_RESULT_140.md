# Task140 — remaining issue1 acceptance on default QCG

Docs-only audit from **47bc1be**. Main's accepted135–138/PR17 merge **15618a8**
has identical dbt/CMake inputs (`git diff 15618a8 HEAD -- dbt CMakeLists.txt`
is empty). No production edit, build, guest/reference/fault/performance execution,
push, merge or issue closure. Task139 publication retains its final executable.
The launcher signals main; this task sends no message or signal itself.

**No new gap was found in default RVV QCG memory under the serialized,
supported synchronous-fault contract. Yes, broader default QCG has known
unhandled paths: generic scalar integer/FP/atomic accesses and guest signal/
syscall buffer copies.** These were already left open in118/119/126. Task135's
scalar vector-memory loop does not cover generic scalar instructions. Optional
gather/LLVM recovery is separate. No new production fix is justified by this
audit's RVV route trace.

Reconciled the existing [fault/interface scope document](docs/rvv-validation/signal-issue-1/README.md#current-issue-1-acceptance-on-qcg-task140-source-audit-only)
into one current acceptance table with exact functions/lines, existing tests,
remaining implementation and blocked execution distinguished. Its old task
sections and result identities remain unchanged. The historical961f022
`FAULT_CONTRACT.md` must not be read as current missing sigaction/sigreturn code.
No replacement framework or coverage ledger was created.

Read the retained113,115–119 receipts in
`/home/user/research/materials/thesis_rvv_20260921/artifacts/rvv_validation_delivery_20261009/`,
their committed signal/unit/family/special scope documents, and120–137 receipts
in this repository. Prior audits were not reexecuted. Reviewed current helper
routes, permission/backing guards, scalar/SIMD sites, allocator publication,
memory run cuts, cache lifetime, signal callbacks, cold exits, dispatcher and
RV32 frame/syscall return code. Task138's21,316 normal results do not infer fault
or restart correctness. Existing actual terminal cells, synthetic metadata,
host codec calls and guest exit-only fixtures retain their distinct scopes.

The next implementation work, if broad issue1 is the acceptance target, is the
two known default-path rows in the table. For supported RVV routes the remaining
guest continuation acceptance is **execution-blocked**, rather than missing
frame/return code: syscall139 restores state/PC/a0, but no authorized guest
handler-return/restart witness exists. P4-04/repair-mapping/guest-handler-return/
same-PC-retry remains prohibited, including renamed, delegated or equivalent
execution. Neither source reasoning nor a codec roundtrip is restart PASS.

Preserved source-only witnesses below make the remaining implementation concrete.
They were **not assembled, built or executed** and have no new result/coverage
credit. Both avoid a returning guest handler or restart. They record old open
boundaries, not newly measured regressions.

```asm
# RV32 LE source-only generic scalar load witness; handler exits, never returns.
# Runtime supplies the ordinary initial stack. Guest address zero is unmapped
# by mmu::MIN_MMAP_ADDR (mmu.h:30). Pure QCG, no gather/LLVM/CCRF required.
.option norvc
.option norelax
.section .text
.globl _start
_start:
    li a0, 11
    la a1, action
    li a2, 0
    li a3, 8
    li a7, 134                 # rt_sigaction(SIGSEGV, action, NULL, 8)
    ecall
    bnez a0, setup_failed
fault_pc:
    .word 0x00002283           # lw t0, 0(x0)
    addi a0, t0, 78            # consume the result on unexpected normal completion
    j quit
setup_failed:
    li a0, 77
    j quit
handler:
    li a0, 0                  # delivery witness only, no rt_sigreturn
quit:
    li a7, 93
    ecall
.section .data
.balign 8
action:
    .word handler, 4          # handler, SA_SIGINFO
    .word 0, 0                # RV32 64-bit guest mask
```

Source determination: `RV32Translator::TranslateLoad` at
`dbt/guest/rv32_qir.cpp:2357` creates a generic vmload;
`QEmit::Emit_vmload` at `dbt/qmc/qcg/qemit.cpp:1394` emits an unowned MOV.
`dbt_sigaction_memory` at `dbt/ukernel.cpp:417` cannot match a registered RVV
site or armed checked leaf, and ends at `mmu::ReportGuestFault`
(`dbt/mmu.cpp:155`, Panic), bypassing pending-event delivery. This proves the
missing source interface; it does not claim an observed exit code or precise
scalar fault snapshot. No existing scalar-delivery test closes it.

Smallest general correction for this load/store class: use a shared checked
scalar runtime transfer at the normal HAS_CALLS publication boundary for every
generic integer/FP width, stage the load before register writeback, retain the
actual PC/raw/access/address and queue/finish through normal scope return. Keep
vector state and vstart intact for a scalar exception. Reuse checked-copy
ownership and the dispatcher/frame interface, not RVV loop progress inferred
from an arbitrary scalar host PC. Atomics need exact owned RMW operations and
reservation semantics separately; a pair of checked load/store calls is not
an atomic fix. No such production change was made here.

```cpp
// Source-only signal-buffer witness, in the existing host-interface setup:
// MMU initialized, production SIGBUS callback installed; no guest code runs.
int fd = memfd_create("signal-buffer-source-witness", 0);
check(fd >= 0, "backing file");
int rc = ftruncate(fd, 4096);
check(rc == 0, "initial backing length");
constexpr u32 a = 0x25000000;
void *mapping = mmu::mmap(a, 4096, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_SHARED, fd, 0);
check(mapping != MAP_FAILED, "guest buffer mapping");
rc = ftruncate(fd, 0);       // backing disappears; no repair or reentry
check(rc == 0, "remove backing");
check(mmu::CheckedRange(a, 16, PROT_READ), "permissions remain recorded");
u8 buffer[16];
bool ok = rv32_signal::CopyIn(buffer, a, sizeof buffer);
// Required bounded failure: ok == false. Current source reaches unowned memcpy
// and fatal host SIGBUS handling instead. No execution result is asserted here.
```

`CopyOut` has the corresponding write boundary. Smallest shared signal-buffer
correction: keep nonwrapping/per-page permission validation, use
`rvv_host_copy::CopyElements` with width1/count=size for the copy, return false on
capture, and check **every** CopyOut result before action/mask mutation
(`rv32_signal.inc:98,108`). Delivery already checks output failure; restoration
already stages the whole frame before architectural writeback. A failed syscall
copy should yield EFAULT, a failed delivery/restore should take existing refusal/
badframe handling. No callback longjmp, guest repair or restart is needed to
implement that boundary. The existing checked-file-truncation tests support the
leaf mechanism only; they are not evidence that current signal memcpy is owned.

Validation for this audit: source comparison against15618a8, static citation and
route review, Markdown/link review and `git diff --check`. No behavioral test was
run. Only this receipt and the existing scope README are committed; pre-existing
untracked `scripts/__pycache__/` is left untouched.
