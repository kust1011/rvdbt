# Task124 — preserve element granularity at the helper host-fault boundary

Starting HEAD: f223a8f, including unaccepted Task123. This is a separate
correction; no Task123 commit or attempt receipt was changed. Launcher owns
completion signaling. No push or issue closure.

## Exact architectural source basis

Consulted the fixed **20240411** ratified manual, rather than a moving latest
redirect. RVV **1.0**, §30.8 permits successful misaligned element transfers or
an element alignment exception, independently of scalar misalignment support;
its misaligned atomicity follows scalar rules.
[§30.8, Vector Memory Alignment Constraints](https://docs.riscv.org/reference/isa/v20240411/unpriv/v-st-ext.html#30-8-vector-memory-alignment-constraints).
RVV §30.9 requires instruction-level RVWMO, leaves element operations unordered
except indexed-ordered transfers, and requires those transfers to obey element
order and element-level RVWMO. Unordered elements do not grant arbitrary
splitting of aligned elements.
[§30.9, Vector Memory Consistency Model](https://docs.riscv.org/reference/isa/v20240411/unpriv/v-st-ext.html#30-9-vector-memory-consistency-model).

RVWMO **2.0**, §16.1.1 defines primitive operations as single-copy atomic and
requires exactly one operation for aligned RV32GC/RV64GC memory instructions,
except unsuccessful SC and RV32 FLD/FSD. Misaligned loads/stores may decompose
at any granularity. RV32 FLD/FSD may also decompose because XLEN is below 64.
The chapter explicitly notes that the vector model is not fully formalized;
its aligned RV32GC sentence is not a blanket formal proof for every RVV
instruction.
[§16.1.1, Memory Model Primitives](https://docs.riscv.org/reference/isa/v20240411/unpriv/rvwmo.html#rvwmo-primitives).

XLEN32 determines address arithmetic here; EEW64 determines an eight-byte
vector field. The scalar RV32 FLD/FSD exception is not a justification for
unconditionally splitting all vector widths. We choose one eight-byte host
operation for aligned EEW64 too, satisfying the requested element granularity
without claiming that RVV formally guarantees all aligned EEW64 atomicity on
all RV32 implementations. Sequential helper traversal remains a permitted
choice for unordered elements and preserves indexed-ordered traversal.

## Implemented behavior

`dbt/rvv_host_copy.S` now has eight frameless SysV leaves: read/write ×
1/2/4/8 bytes. Each guest memory operation is exactly one MOV at its width,
with a distinct exact PC; staging/source memory uses RSI at a different PC.
The read/write opcode pairs are 8a/88, 66 8b/66 89, 8b/89, and 48 8b/48 89.
`Copy` validates architectural widths, selects the matching leaf once, and
makes one leaf call for a naturally aligned field. The guest address-space
base is page aligned. No aligned field silently takes the byte loop.

Misaligned fields retain byte decomposition, including explicit modulo-2^32
addressing for a field wrapping across the RV32 address space. A wrapping
2/4/8-byte field is necessarily misaligned. This is the allowed successful
misaligned path from the cited rules; completed store bytes may remain when a
later byte fails. It also avoids accessing host memory past the guest window.
Loads stage the entire field and publish only after all accesses succeed.
Aligned stores have one guest write instruction, rather than a byte prefix.

The armed thread records the exact expected PC, base and width. The synchronous
signal filter still accepts only SEGV_MAPERR/SEGV_ACCERR and
BUS_ADRERR/BUS_OBJERR. Recognition additionally requires saved RDI to match
and `si_addr - base < width`; this bounded subtraction accepts interior fault
addresses without an overflowing end calculation. A captured offset supplies
the denied guest byte. Direction, width, signal/code and exact PC must all
match this invocation. Fault provenance and helper guest coordinates remain
on the existing Task123 path.

Initial-exec TLS, volatile sig_atomic_t and statically lock-free pointer
atomics preserve per-thread state. The accepted callback branch performs only
scalar capture and RIP redirection to `xor eax,eax; ret`. Compiled HandleSignal
has **no calls**, including no TLS resolver. Leaves change no stack or
callee-saved register. Ordinary returns leave C++ scopes normally; no callback
longjmp crosses C++ objects. Existing dispatcher unwinding occurs after helper
scopes close, as in Task123. Unrelated host faults keep existing fatal handling.
Native execution remains enabled; Task123's uncorrected native/bulk/gather
host-fault limitations remain open. No workload special cases.

## Actual isolated bounded verification

New root: **xbd:/home/vick/rvdbt-host-fault-task124/**. Copied Task123's source
and vendored dependencies into a separate directory; configured a fresh build.
Final equality: **286 tracked dbt/CMake inputs, zero differences** from current
workspace. Task123 source/build/results were preserved.

Clang 22 / LLVM 22.1.6, Release, chunk128. Configure and all builds exit 0.
Build bounds: timeout600, nice10, cores28–31, -j4; final test-fixture rebuild
bound timeout180. Only these five targets were built. Tests ran sequentially,
core28, nice10, timeout90 per process, core dumps disabled. Initial test load
was **0.82/0.64/0.57**. No test timeout.

| Local test | Actual accepted result |
|---|---|
| rv32_host_copy_fault_test | exit0, 766 checks, 11 helper cells PASS |
| rv32_unit_memory_fault_test | exit0, 9,562 checks, 1,248 cells PASS |
| rv32_family_memory_fault_test | exit0, 323,407 checks, 59,424 cells PASS |
| rv32_special_memory_fault_test | exit0, 254,648 checks, 26,290 cells PASS |
| rv32_signal_interface_test | exit0, 376 checks, guest_calls=0 PASS |

The host-copy fixture now checks executable instruction bytes at all eight
labels, successful bounded transfers, and a real denied access at each aligned
width/direction. Its test callback checks the actual interrupted PC and one
signal per failing invocation. It rejects one-past/before-base addresses,
opposite-direction PCs, interior instruction PCs, changed RDI and SI_USER.
It then **synthetically substitutes the last byte address** before calling
the production callback, testing range acceptance and denied-byte offset.
This is synthetic interior-si_addr coverage, not evidence that the kernel
reported those interior addresses. Existing helper captures retain actual
kernel addresses/signals/codes without that substitution.

An accessible shared alias verifies that a denied aligned store writes none
of the field, without repairing/retrying the denied mapping. Width2/4/8
misaligned crossing fixtures verify byte-leaf PCs, one-time fault capture,
retained store prefixes and fully unpublished load destinations. A separate
4 GiB reservation verifies successful RV32 wrap load/store byte addresses.
Existing helper cells retain SIGSEGV/SIGBUS, segment denied-field publication,
FOF zero/later behavior, PC/raw/address/element/field/EEW, FP scope cleanup,
thread isolation and unrelated-host-fault SIGABRT controls. Existing memory
regressions retain ABI ce212ddc4742de49 and predicted denied-field behavior.

All attempts are retained in [Task124 receipts](docs/rvv-validation/host-fault-task124/),
including the first host-copy test exit2 at `wrap low page`: its MMU fixture
attempted the intentionally disallowed guest address zero. All preceding width
checks passed. Replaced that fixture with a separate host reservation; rebuilt
and ran only the changed host-copy test, exit0. The four unchanged passing
regressions were not rerun. Builds, stdout/stderr/rc, losslessly compressed
object disassemblies, source equality/hashes and tested binary hashes are
retained. Disassembly checks and `git diff --check` pass.

No external suite or performance run, guest handler/return/retry, P4-04 or
mapping repair. No full memory-model, native host-fault recovery or guest
restart validation is claimed.
