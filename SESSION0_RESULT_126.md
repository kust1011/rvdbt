# Task126 — synchronous captured-helper SIGSEGV/SIGBUS delivery

Continued Task125 HEAD **041a616**. Code/tests commit **173fce8** delivers owned
checked-leaf HostCopy faults through the existing RV32 Linux frame/dispatcher.
Receipts are committed separately. No push or issue closure; launcher owns the
completion signal.

Queue validation and delivery now share one explicit mapping, rather than
rejecting HostCopy and hardcoding SIGSEGV. Predicted Unmapped/Protection remain
SIGSEGV/MAPERR or ACCERR. Captured mappings are:

| Host capture | RV32 signal | RV32 si_code |
|---|---:|---:|
| SIGSEGV / SEGV_MAPERR | 11 | 1 |
| SIGSEGV / SEGV_ACCERR | 11 | 2 |
| SIGBUS / BUS_ADRERR | 7 | 2 |
| SIGBUS / BUS_OBJERR | 7 | 3 |

The selected signal determines the action, guest mask bit, handler a0 and
siginfo number/code. The denied guest address, captured PC/GPR/FP/vector bytes,
vstart and VL are preserved. Load/store direction and element/field geometry
remain in the event/snapshot; the delivery diagnostic includes direction.
Linux fault siginfo has no load/store flag, so none is invented in the frame.
Syscall 134 additionally supports SIGBUS installation with flags 0/SA_SIGINFO;
no new flags, asynchronous sources, altstack or syscall semantics were added.
Default/blocked/ignored synchronous faults, invalid handlers/stacks, same- or
cross-signal nesting and badframes retain explicit refusal/termination.

ABI evidence: Linux v6.12 [signal.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal.h),
[siginfo.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/siginfo.h)
and [RISC-V signal.c](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/kernel/signal.c)
pin target numbers/codes, fault address union and frame convention. The pinned
[QEMU signal path](https://github.com/qemu/qemu/blob/ae35f033b874c627d81d51070187fbf55f0bf1a7/linux-user/signal.c)
was reviewed for separate host/target numbering, synchronous ownership,
PC/address/access materialization and unwind/mask distinctions. Source hashes
are in [AUTHORITATIVE_SOURCES.json](docs/rvv-validation/helper-signal-task126/AUTHORITATIVE_SOURCES.json).

No host callback behavior changed. The kernel returns from the callback to the
leaf failure return and restores the host mask before helper scopes finish.
Only the normal dispatcher stack builds/publishes the guest frame, after FP
closure and helper unwind. No callback allocation, logging or longjmp was
introduced. Actual production-object HandleSignal disassembly still contains
no calls or TLS resolver. The dispatcher does not restore a stale callback mask.

Fresh isolated **xbd:/home/vick/rvdbt-helper-signal-task126/** source/build:
Clang22/LLVM22.1.6, Release, chunk128; all **289 tracked dbt/CMake inputs match**
[SOURCE_IDENTITY.json](docs/rvv-validation/helper-signal-task126/SOURCE_IDENTITY.json).
Production elfrun/dbtjitshared builds pass, executable `ldd -r` has no unresolved
symbols. elfrun SHA256 **ed980270b6d6c659622cf5f519843ac2fb8a826d8b46cc6c31936e2ad70b5bf5**;
library remains **1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d**.
Builds used nice10, cores28–31, -j4, 900s initial/300s focused/180s final limits;
tests used core28 and 60s, replay 300s overall and original 30s per-call limits.
Core dumps disabled. Initial/final load **0.23/0.32/0.57**, **0.34/0.42/0.54**.
No global settings or other jobs changed.

| Focused check | Result |
|---|---|
| rv32_signal_interface_test | exit0; 1,792 checks; guest_calls=0 |
| rv32_signal_frm_test | exit0; 256 roundtrips; 192 high-bit badframes; guest_calls=0 |
| rv32_host_copy_fault_test | exit0; 1,048 checks, 11 captured helper cells; no guest handler/retry |
| Original exit-only delivery/control fixtures | 8/8 PASS; exact original stdout; zero guest sigreturn |

Interface tests cover all four supported host codes and both predicted reasons,
load/store, action flags 0/4, signal-specific handler/masks, PC/vstart/VL/vector
bytes, local codec restoration, nested/badframe atomicity, invalid stacks/actions
and explicit unsupported codes/sources/flags. Real kernel ACCERR/ADRERR helper
captures reach frame publication for both directions and aligned/split accesses;
host masks match across capture, normal helper unwind and delivery. MAPERR/OBJERR
coverage is synthetic metadata/interface coverage, not a real-kernel claim.
Host API frame restoration executes no guest instruction.

The unchanged Task113 first-fault exit-handler and later-FOF control fixtures run
B/M1/M2/BOTH: four delivery/handler exits plus four controls. Original ELF,
checker and retained reference hashes match the original preflight; all complete
stdout packets are byte-identical. No new oracle, source rewrite, reference run,
guest compilation or SIGBUS guest handler execution. These fixtures establish
retained predicted-helper guest delivery, not captured SIGBUS guest execution.

Failure preserved: initial aggregate build exit2 at the FRM test's stale
**42688** sizeof assertion; production already asserted current **42704**.
The test assertion now matches current layout without changing runtime ABI or
FRM/badframe oracle assertions. Failed build streams and the intermediate passing
interface run remain. The real host-copy test's two unrelated fault children
intentionally abort and are checked as fatal SIGABRT; their Panic streams remain.
No guest failure or reference byte was repaired or hidden.

[Commands](docs/rvv-validation/helper-signal-task126/COMMANDS.md),
[results](docs/rvv-validation/helper-signal-task126/SUMMARY.json) and
[175-file local raw audit](docs/rvv-validation/helper-signal-task126/LOCAL_RAW_AUDIT.json)
bind the new build, raw outputs and original bytes. Full raw/source/build stay
remote; downloaded raw is **/home/user/research/materials/task126-raw-20261013/**.
Immutable archive **/home/user/research/materials/task126-receipts-20261013.tar.gz**,
SHA256 **16d34fdf498bad0b29671ca98771409ec38f8d796c167866ba83acd058087452**.
Repository diff whitespace check passes; historical receipts remain unchanged.

Remaining limits: native QCG/LLVM/optimized RVV/CCRF bodies still lack owned
host-PC recovery maps, lane/field and publication materialization and safe exits.
Permitted unit-stride bulk/whole-register copies and AVX2/optional emitted gathers
remain outside checked-leaf capture. Permission preflight neither pins mappings
nor guarantees safety against later host faults. Global dispatcher unwind/CPU
ownership is not concurrent. Frame copy/trampoline operations remain the existing
normal-stack preflight/copy path without a mapping-race recovery contract.
BUS_ADRALN, poison and unsupported sources/flags remain refused. Complete guest
handler return/restart and native recovery are not established. No repaired
mapping followed by same-PC retry, P4-04 or equivalent blocked execution, broad
suite or performance run was performed. This closes only the bounded captured
helper synchronous delivery gap, not issue #1 as a whole or an OS signal subsystem.
