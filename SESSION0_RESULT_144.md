# Task144 — generic scalar memory fault boundary design

Completed a source-only architecture-impact review on
`fix/rvv-memory-families-issue-1`, source base
`785253d7a224d883ea14fd7c56f91b7ddf06886b`. No applicable AGENTS.md was found
in repository/ancestor paths. Only this receipt and the existing
[signal issue #1 scope document](docs/rvv-validation/signal-issue-1/README.md#task144-generic-scalar-memory-boundary-design-only)
are changed. Production behavior is unchanged.

**Recommendation: one shared checked scalar transfer, one appended integer
memory dispatch stub, and the existing FP helper routes.** Cover LB/LBU/LH/LHU/LW,
SB/SH/SW and FLW/FLD/FSW/FSD, including integer rd=x0 accesses. Use complete-field
permission preflight followed by the existing owned width-matched copy leaf;
stage loads until full success. Queue the actual PC/raw/direction/denied byte,
return through the existing body wrapper, then finish at the established clean
FP/dispatcher boundary. Scalar faults must preserve vector registers and CSRs,
including vstart; scalar event coordinates are element0/field0/NF1.

Exact current source findings:

- Integer frontend: `dbt/guest/rv32_qir.cpp:2357–2400`, bindings15314–15321.
  Ordinary vmload/vmstore become unowned MOV/MOVSX/MOVZX at
  `dbt/qmc/qcg/qemit.cpp:1394–1447`. Stable-load and CCRF store-elision bypasses
  at2368–2373/2386–2389 must leave the ordinary fault contract when implementing
  the recommendation (recommended: remove those bypasses from these translators).
- FP frontend: `rv32_qir.cpp:15482–15485` already uses TranslateHelper; its
  commit/reset/hcall at2528–2532 publishes vector SSA. FP bodies at
  `dbt/guest/rv32_interp.cpp:2148–2158` still dereference guest memory directly.
  Integer bodies/macros at179–192/245–252 are likewise unchecked.
- Publication: translator MayTrap macro at `rv32_qir.cpp:14745–14763` invokes
  PreSideeff2198–2218 for actual PC. `dbt/qmc/qir_ops.h:6` marks hcall SIDEEFF
  and HAS_CALLS; `qcg/qra.cpp:988–1026,1108–1111` spills/releases globals and
  call-clobbered registers; `qcg/qemit.cpp:327–333` passes state/raw. PinSelect
  at `qra.cpp:645–709` refuses call-containing regions. Vector publication is
  separately explicit: `rv32_qir.cpp:6616–6620,14701–14736`.
- Transfer: `dbt/mmu.h:117–130` supplies RV32-wrapped first-denied-byte checks;
  `dbt/rvv_host_copy.cpp:46–113` owns exact leaf PCs and stages loads. ResetFault
  must precede preflight to avoid stale LastFault on predicted denial. Aligned
  fields use one width-matched access; split unexpected store faults may retain
  a byte prefix. No all-or-nothing store or concurrent mapping guarantee.
- Exit: `rv32_interp.cpp:93–162` stops PC advance on MEMORY_FAULT and calls
  Finish after body return; Finish51–69 closes deferred FP state before RaiseTrap.
  `dbt/ukernel.cpp:223–260,310–318` queues/captures/delivers; production callback
  at417–458 owns checked copies but terminates unrelated accesses.
  `dbt/rv32_signal.inc:15–35,134–191` accepts the existing scalar-compatible
  event and builds the frame. No dispatcher or codec rewrite is needed.
- Exact-site alternative: `dbt/qmc/compile.h:16–37`,
  `dbt/rvv_native_fault.cpp:32–109,111–138` are RVV-specific geometry/exit
  contracts; the latter writes vstart and raw fallback selects RVV. Ordinary
  scalar sites need a separate kind/exit and precise state publication or
  allocator reconstruction, plus crossing/wrapping handling. Existing relocation
  publication/lifetime is `qcg/qemit.cpp:78`, `dbt/execute.cpp:166–169`,
  `dbt/tcache/tcache.cpp:204–260`; offline default publication is empty.
- Newly generated LLVM scalar QIR can use the same hcall:
  `dbt/qmc/llvmgen/llvmgen.cpp:1178–1204,1505–1509`. Its ordinary native access
  emitters8084–8117 have no inherited scalar recovery. This recommendation does
  not establish ownership for other optional LLVM/RVV native routes.

Small implementable next step: edit `rv32_interp.cpp` to share a checked transfer
across all twelve bodies and define `qcgstub_rv32_scalar_memory` dispatching the
eight integer H handlers; append one entry in `dbt/qmc/runtime_stubs.h:27`;
route integer translators through hcall with explicit vector commit/reset.
Measure/update `dbt/ukernel.cpp:169–180` and test layout tripwires. Table growth
moves FPU/later offsets hashed by `dbt/guest/rv32_cpu.h:211–232`, enabling the
existing `dbt/aot/aot_boot.cpp:371–389` signature gate to reject old unchecked
integer AOT bodies. No new QIR opcode, allocator/emitter change or recovery map.

Estimated implementation and focused host/translation validation: **3–5
engineering days**, excluding corpus, packaging, performance campaigns and
prohibited execution. Conservative native QCG recovery: **8–12 days**, with
arbitrary-residency maps/native FP/offline ownership additional. Integer success
now incurs full call publication, helper/leaf calls, permission checks, TLS
arming and later reloads; FP already has a helper call. Integer memory regions
lose call-free pin/leaf eligibility. No measured slowdown or speedup is claimed.
Wrapping compatibility, partial-store behavior, compiled layout values and
actual hot-loop cost remain explicit uncertainties in the scope design.

Atomics are excluded. `rv32_interp.cpp:2440–2515` needs separate exact RMW,
reservation, alignment and aq/rl work; no split checked load/store implementation
is proposed. General syscall buffers and optional native routes remain open.

Validation for144: inspected current frontend/QIR publication, allocator,
emitter, checked leaf, native ownership, AOT gate and dispatcher source; reviewed
citations/Markdown and ran `git diff --check`. **No build or behavioral test was
run.** Main's accepted143, Task142 publication, independent21,316 original
predicate replay and public delivery05db3ca are handoff facts only; none was
repeated or repackaged. No P4-04, repaired-mapping, guest-handler return, same-PC
retry or equivalent restart execution occurred, directly or delegated. Host
codec checks are not guest restart proof. No push/publication/issue closure or
completion signal was sent; the launcher sends completion. Unrelated untracked
`scripts/__pycache__/` is untouched.
