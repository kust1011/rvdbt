# Task141: checked signal-buffer copies

Completed on branch `fix/rvv-memory-families-issue-1`, starting
`bb2ac8520ddea319871adf98f01a9adce5ef8860`.
Production/test correction: **`ad5e3c8d151a1753578951d38f848aa347ebb95a`**.
This receipt and the signal scope README are committed separately from that
correction. No publication, merge or completion signal was sent; the launcher
handles completion automatically.

## Scope and original failure

No applicable AGENTS.md was found in the repository or its ancestor directories.
The investigation used Task140's signal-buffer finding and the actual signal,
MMU, checked-copy and existing interface/codec test APIs.

The original common boundary validated guest metadata then performed raw guest
`memcpy`. Both syscall paths ignored CopyOut's result before mutating their
private action/mask. The source-only Task140 truncation finding is now reproduced
with production callbacks: an 8192-byte shared memfd mapping at `0x25000000`
is truncated once to 4096 bytes, leaving the second page's guest read/write
permissions recorded. Direct CopyIn/CopyOut at `0x25001000` passed range checks
then reached unowned host faults and fatal handling. Each independent child
aborted (raw wait status **134**, SIGABRT); the parent test returned **2**.
The old diagnostic labels this `kind=protection`; it is not a new guest
permission oracle or evidence of owned fault capture.

With only the copy boundary corrected, both children got past direct first-byte
and crossing truncation checks (including owned SIGBUS/BUS_ADRERR checks), then
failed `action output failure EFAULT`. Each exited 2 (raw wait status **512**),
and the parent returned 2. This separately confirms that retaining the ignored
syscall CopyOut result is insufficient. Final copies and state gates pass.

## Correction and API requirements

`CopyBuffer` retains CheckedRange's null/zero-length rejection, RV32 overflow
rejection and complete per-page permission preflight. It supplies the actual
MMU address-space base, byte width 1, direction, and completed/denied outputs to
`rvv_host_copy::CopyElements`. Counts are bounded to `0x7fffffff` per call to
respect its signed signal-safe counter requirement while preserving the u32
buffer API. The const cast on CopyOut serves the existing mutable-pointer API;
the store leaf reads the local source only.

The existing ownership mechanism arms exact guest-access assembly PCs and
accepts only its matching footprint/direction and supported host fault codes.
The production callback redirects to the leaf's ordinary failed return, with no
allocation, MMU lookup or longjmp in that owned callback path. No mechanism or
callback was modified. Range checks still reject guest write-only reads even
where the host could physically read them. A backing fault may retain a byte
prefix in the caller's local destination or guest output; this is not an
all-or-nothing byte-copy guarantee.

Every syscall CopyOut result now gates mutation: failure returns `-EFAULT`,
including output-only queries, without changing the signal action or guest
mask. Existing input staging and validation precedence remain intact. Delivery
already checks CopyOut and refuses failed frame publication; restoration still
copies/validates the complete frame before architectural writeback. Its existing
FP cleanup on badframe is preserved. RV32 signal layouts, accepted flags, frame
codec, trampoline, delivery/restore rejection behavior and runtime ABI are
unchanged.

The existing FRM test had a stale `sizeof(CPUState)==42704` assertion. It is now
42720, matching the already-existing production assertions in ukernel.cpp and
Task131 layout; this is a local engineering test repair, not a production ABI
change or external expected-value edit.

## Actual build and regression results

A fresh local Release build uses Clang/LLVM **20.1.8**, host chunk **128**, default
CMake options otherwise. Only pinned asmjit/elfio build submodules were
initialized; riscv-tests was not initialized or run. Built targets:
`elfrun`, `rv32_signal_interface_test`, `rv32_signal_frm_test`,
`mmu_mapping_metadata_test`. `elfrun` was built but never executed.

| Stage | Actual rc and result |
|---|---|
| configure | 1: Clang/LLVM22 unavailable; no executable run |
| configure20 / configure20-ready | 1 / 1: asmjit absent, then initialization still pending; no executable run |
| submodules / configure20-complete | 0 / 0: pinned dependencies initialized, LLVM20 configuration succeeds |
| baseline-build | 2: new test incorrectly called private InitSignals; no executable run |
| baseline-build-ready | 2: existing FRM test's stale host-size assertion; no executable run, including the already-built interface binary |
| baseline-build-complete | 0: all four targets build after registering the actual production callback directly and aligning the local FRM assertion |
| baseline-interface | 2: both raw memcpy directions abort on truncated backing |
| copy-only-build / copy-only-interface | 0 / 2: checked copies capture normally; ignored syscall output failure still fails EFAULT assertion |
| fixed-build | 0: all four targets rebuild successfully; warnings retained in stderr |
| rv32_signal_interface_test | 0: 1876 parent checks; input child 101, output child 86; both child statuses 0 |
| rv32_signal_frm_test | 0: 256 frm/fflags roundtrips, 192 high-bit badframes |
| mmu_mapping_metadata_test | 0: 27/27 checks |

Every failed configure/build stopped execution. Only a later successful build
unlocked its matching test run; no stale binary was run after a failed build.
The final binaries match production/test commit ad5e3c8; only documentation
changes followed. `git diff --check` passes.

Focused additions test real production wrappers, private owner state and the
actual `dbt_sigaction_memory` callback, not a substitute leaf or fake codec:

- Normal cross-page copies, null/wrapping/unmapped crossings, denied cross-page
  reads/writes, untouched destinations/prefixes after preflight refusal, and
  guest write-only output permission.
- First-byte and crossing truncated-file transfers in both directions; owned
  BUS_ADRERR capture, copied six-byte prefixes and untouched input suffixes.
- Action output failure with a distinct incoming handler/flags/mask and unchanged
  old action; all BLOCK/UNBLOCK/SETMASK output failures with unchanged old mask.
  Outputs include first-byte/crossing backing faults, read-only and wrapping
  ranges. Truncated inputs and output-only queries return EFAULT too.
- Direct host delivery rejection without publishing PC/GPR/frame/mask, and
  direct codec restore rejection without changing PC/GPR/vector/mask/ownership
  after a truncated input fault. Existing normal delivery/codec/rejection and
  FRM regressions run unchanged apart from the local stale size assertion.

Parent and child counts are reported separately: 2063 combined interface
checks, plus the separate FRM and MMU results. These finite local checks do not
exhaust arbitrary large buffers, backing lifetime races or concurrent ownership.

## Raw evidence and reproduction paths

Raw root (outside the repository):
`/home/user/research/materials/task141-raw-20261013/`.
The exact command sequence and stage labels are in
[COMMANDS.txt](/home/user/research/materials/task141-raw-20261013/COMMANDS.txt).
Every stage named in the table has `.stdout`, `.stderr`, `.rc` under that root
(the configure20 variants retain their distinct stage prefixes).

Key raw paths:

- [Original failure stderr](/home/user/research/materials/task141-raw-20261013/baseline-interface.stderr),
  [rc](/home/user/research/materials/task141-raw-20261013/baseline-interface.rc),
  [original executable](/home/user/research/materials/task141-raw-20261013/baseline-interface.bin).
- [Copy-only failure stderr](/home/user/research/materials/task141-raw-20261013/copy-only-interface.stderr),
  [source delta](/home/user/research/materials/task141-raw-20261013/copy-only.patch).
  This intermediate executable was rebuilt in place; only the baseline binary
  and final binaries are preserved separately.
- [Baseline test delta](/home/user/research/materials/task141-raw-20261013/baseline-tests.patch),
  [final build stdout](/home/user/research/materials/task141-raw-20261013/fixed-build.stdout),
  [stderr](/home/user/research/materials/task141-raw-20261013/fixed-build.stderr),
  [rc](/home/user/research/materials/task141-raw-20261013/fixed-build.rc).
- [Final interface stdout](/home/user/research/materials/task141-raw-20261013/rv32_signal_interface_test.stdout),
  [stderr](/home/user/research/materials/task141-raw-20261013/rv32_signal_interface_test.stderr),
  [FRM stdout](/home/user/research/materials/task141-raw-20261013/rv32_signal_frm_test.stdout),
  [MMU stdout](/home/user/research/materials/task141-raw-20261013/mmu_mapping_metadata_test.stdout).
- Final build directory: `/home/user/research/materials/task141-raw-20261013/build20`;
  executables in `bin/`, matching shared library in `lib/`, CMake cache and
  compile_commands.json retained. [Final hashes](/home/user/research/materials/task141-raw-20261013/fixed.sha256)
  and [baseline hash](/home/user/research/materials/task141-raw-20261013/baseline.sha256).

SHA256 identities:

```
8df396894fbde72ea5c01a2e6d5238707062e3903cb27e9efac29a9bc00f9540  /home/user/research/materials/task141-raw-20261013/baseline-interface.bin
73ba59cf634428ea62d82a781c0bf13465aa7050f44830da9c0a5faccc3f9196  /home/user/research/materials/task141-raw-20261013/build20/bin/rv32_signal_interface_test
a72fa81574b2b2da140d134d992e24e466cbee91b0cd7eb56c603d08c747aa12  /home/user/research/materials/task141-raw-20261013/build20/bin/rv32_signal_frm_test
8f77c182924bcdcc75c1ec84f36656b8209ba4e99dd28fc87264283157e6470f  /home/user/research/materials/task141-raw-20261013/build20/bin/mmu_mapping_metadata_test
d550446d0414237ebdf48c28af3d0c253305d5aecf66cc7ed056c132b11f6aa6  /home/user/research/materials/task141-raw-20261013/build20/bin/elfrun
f001ab8dad25d7cdeba3fb3d9aa984194a6847b402dbd29206130623ac06f93f  /home/user/research/materials/task141-raw-20261013/build20/lib/libdbtjitshared.so
```

## Remaining scope

These are local host-interface/codec engineering regressions, with **zero guest
calls and zero external ISA tests**. No full external corpus or external fixture
was rerun. No guest handler-return/restart, repaired-mapping or same-PC retry
execution (including equivalents) occurred. File backing was truncated once and
not repaired. No new longjmp or jump across C++ scopes was introduced.

Generic scalar/atomic lowering, LLVM, performance and external expected values
were untouched. General syscall marshalling remains outside the common signal
copy correction. Broad issue #1 remains open; this bounded boundary fix is
complete. Existing unrelated `scripts/__pycache__/` is left untracked.
