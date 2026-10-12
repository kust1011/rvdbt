# Linux RV32 signal interface increment (Refs #1)

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
