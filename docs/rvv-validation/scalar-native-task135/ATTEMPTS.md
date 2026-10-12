All attempts remain under the archived remote-root receipt names. No failed build
was followed by test execution. Earlier focused pins belong to their successful
builds, not the final source; only `normal-reviewed`, `terminal-reviewed`,
`whole-normal` and final upstream calls receive final credit.

- `build.initial`: runtime-stub table growth violated CPUState size/FPU offset
  assertions. Removed the slot; retained the existing guard ABI.
- `build.constants`: nonexistent ArchTraits DI/CX constants. Replaced with asmjit
  x86 register IDs.
- `build.transport`: SCP/banner timeout left those constants unfixed remotely;
  the subsequent build failed. No test followed. Future transfers gated on success.
- `normal-initial`: standalone return reached trampoline's intentional INT3.
  One gdb inspection showed `trampoline_to_jit+37: int3`; no guest memory fault.
- `normal-second`/`normal-third`: indexed data64 was encoded with illegal RV32
  index64. Added the raw/loop diagnostic and used index32 for data64.
- `normal-fourth`/`normal-fifth`: index storage still initialized at data width,
  producing r8 byte8=81 versus expected1. Corrected the index initializer.
- `normal-sixth`: zero-membase host page0 mapping refused. Replaced that assumption
  with a predicted wrapping-denial terminal case and actual normal wrapped address
  formation into mapped ordinary RAM.
- `normal-seventh`: successful earlier normal fixture (1,863 checks).
- `normal-final`: successful receipt-enhanced normal fixture (1,919 checks).
- `terminal-final`: 33 successful fresh SEGV children, then one BUS child reached
  the cold stub and panicked at `invalid helper-origin memory fault event`.
  Native BUS was still excluded by HelperSiginfo. Extended that runtime event
  validation and restricted scalar preflight to ordinary backing.
- `normal-reviewed`/`terminal-reviewed`: final successful executable, 1,919 normal
  checks and 2,029 parent checks/44 terminal cells. Every child is terminal;
  no repaired mapping, guest handler return or retry.
- Local offline audit first asserted 36 shapes and failed at
  `assert len(shapes)==36`. The retained actual site files number38. Corrected the
  audit count to38 and checked width32 load publication explicitly as well.
  No production change or execution followed that offline assertion failure.

Physical terminal totals: 78 children, 74 memory host faults (71 SEGV/3 BUS).
Final coverage: 44 cells, 40 host faults (38 SEGV/2 BUS), four predicted faults.
Earlier normal attempts and the gdb INT3 observation are not guest-memory faults.
