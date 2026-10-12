# Reading the RVV implementation and validation

The inventory has 627 mnemonic/operand forms, with 595 applicable to RV32/ELEN64
and 32 ei64 indexed forms excluded by that profile. The current delivery has
separate host512 full-corpus and affected-memory regression builds, listed in
[the validation entry](rvv-validation.md). VLEN128–4096 is a capability, not a tested Cartesian product.
Direct chunk routes and shared semantic helpers both implement guest behavior.

Source presence, compiled source, static emission, program execution,
target/result checking and coupled endpoints are separate stages. Checked sets
are CHIPS595, ACT590, RVV-ATG434, Ara422 and SiFive RIF200; their union is595.
RVVTS58 and RVISmith43 are coupled endpoints: program success does not
independently check each contributing static opcode. Candidate-specific sets
and original/derivative provenance remain in the canonical bindings. Historical
libriscv records remain in the archive but are not used for this validation
claim. The immutable scope archive is the Task71 snapshot; the current scope
and Ara review package linked below supersede its aggregate counts.

The final current-build evidence is [Task142](rvv-validation/host512-task142/README.md):
source `8111040` with reviewed signal-copy correction `ad5e3c8`, executable
`e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b`.
Its 21,316 retained CHIPS/ACT/Ara calls reuse original inputs and predicates;
595 checked forms remain the same union. Earlier builds, including Task138,
retain historical attribution and earn no final-build credit. Use the explicit
Task142 raw root and already published source/checker packages in that reader;
the new raw asset is published, and reviewed source revision
`0d253a45ddce1b45f46c843e986b29410d04786f` contains its reader and manifest.

When writing about this result, distinguish four evidence classes:

- External predicates check the original program outputs: CHIPS controls and
  Ara scoped MAC failures remain separate; two ACT reference blockers stay excluded.
- Final-build local interface/FRM/MMU, codegen/admission and normal memory tests
  check engineering behavior. The signal interface test has `guest_calls=0`;
  these tests add no external instruction coverage.
- Actual cache/compile/command evidence establishes Release/host512/RV32/ELEN64
  settings and guest VLEN. Printed ACT/Ara chunks are observations; source
  geometry and unprinted runtime fields remain source-only or UNKNOWN. Enabled
  B/M1/M2/Both settings do not prove admission at each target instruction.
- Guest handler return/restart remains **NOT VERIFIED**. Host signal-copy checks
  do not establish mapping repair, same-PC retry or complete fault-state recovery.

## Explaining the support claim

- **What was implemented?** RVV decoding, vector architectural state, direct
  vector QIR and x86 emission, semantic helpers, and the M1/M2 optimizations in
  rvdbt's lightweight execution path. A helper is an implementation route,
  not evidence that the instruction is unsupported or correctly implemented.
- **What does 595 mean?** It counts applicable mnemonic/operand forms, not
  test programs or every combination of element width, grouping and vector
  state. The scope includes both direct and helper execution. The per-form
  index identifies the external checker and configuration behind each count.
- **How is a result checked?** The external assertion or separately identified
  reference supplies the expected result. The runner checks termination and
  output; source-to-checker bindings identify what that output actually tests.
  The example below follows one form through that chain. The expected result
  is not generated from the rvdbt execution being checked.
- **What do four configurations establish?** B/M1/M2/Both observations check
  those configured executions. An optimization may refuse a case and use a
  fallback; generated-code or runtime admission evidence is needed to say
  that the optimized body itself was exercised.
- **What remains incomplete?** Complete guest-handler return/retry is not established.
  Checked helpers and admitted singleton QCG memory bodies now have bounded
  fault-state handling, but this does not cover every generated memory path. Normal
  result checks, including manually supplied nonzero `vstart`, do not test
  an actual fault followed by repair and retry. Additional configuration and
  intermediate-state coverage is described below, not assumed from595 forms.

## Trace a direct body: `vadd.vv v10,v8,v9`

This is a source-derived example, not a new captured execution. Fix VLEN1024,
SEW32, LMUL1, unmasked, VL32 and vstart0, with the typed QCG route enabled and
M1 disabled. Read these functions in order:

1. [rv32_decode.h](../dbt/guest/rv32_decode.h) routes the unmasked ADD encoding
   to `vadd_vv`. `TRANSLATOR(vadd_vv)` in
   [rv32_qir.cpp](../dbt/guest/rv32_qir.cpp) checks the route's configuration
   and host-feature conditions. `RvvVaddChunkShape` derives two64-byte
   components for this example. A component is a QIR value, not a fixed ZMM.
2. `RvvEmitTypedChunkGroup` checks that the shape covers the architectural
   register. `RvvEmitTypedAluChunkGroupCore` constructs the guarded frame and
   calls `RvvEmitTypedAluChunkBody`. The body constructs all source loads,
   then both adds, then both destination stores. Its state address is
   `offsetof(CPUState,vec) + offsetof(VectorState,vreg) + r*VLEN_MAX_BYTES + c*64`.
   Here r is the architectural register number and c is0 or1. The slot stride
   is the maximum reserved register size, not the current128-byte logical size.

```text
a0 = vstatechunkload state(v8,0); a1 = vstatechunkload state(v9,0)
b0 = vstatechunkload state(v8,1); b1 = vstatechunkload state(v9,1)
x  = vchunkadd a0,a1,SEW32
y  = vchunkadd b0,b1,SEW32
vstatechunkstore state(v10,0),x
vstatechunkstore state(v10,1),y
```

3. [qra.cpp](../dbt/qmc/qcg/qra.cpp)'s `QRegAlloc` tracks vector values in a
   separate register class. It walks QIR in order, allocates operands and
   retires proven block-local values after their last use. `AllocPRegV`
   prefers free registers, then registers holding retired values, then a
   permitted spill candidate. This is the implemented allocation policy;
   calling it an interval-based linear-scan algorithm would be misleading.
4. [qemit.cpp](../dbt/qmc/qcg/qemit.cpp)'s `Emit_vstatechunkload` emits
   `vmovdqu64` from the CPU-state pointer. `Emit_vchunkadd` selects `vpaddd`
   for4-byte elements and obtains ZMM operands from the allocated512-bit
   values. `Emit_vstatechunkstore` emits the corresponding state write.
   This body has four state loads, two packed adds and two state stores,
   excluding guards and completion code. These stores are architectural
   state publication, not spills caused by register exhaustion.

`Emit_rvvtypedchunkbegin` emits runtime tests; the translator does not know
future VL values. With the integer two-arm path enabled, matching vtype,
VL32 and vstart0 enter the full body; a shorter VL or nonzero vstart selects
the partial body, and incompatible configuration selects the helper. The
partial body has separate lane-mask handling. Do not extend the full-store
example above to masked or partial updates. [rvv-qcg.md](rvv-qcg.md) explains
where cross-instruction promotion and active-component bounds modify this path.

## Trace a helper form: `vsmul.vv`

1. In [rv32_qir.cpp](../dbt/guest/rv32_qir.cpp), search
   `TRANSLATOR_Helper(vsmul)`; the QCG route retains the semantic helper.
   [rv32_vector_lower.h](../dbt/guest/rv32_vector_lower.h)'s `vsmul` multiplies
   signed SEW operands, rounds according to `vxrm`, saturates and updates `vxsat`.
   The fractional-multiply QIR/LLVM nodes elsewhere do not establish QCG native
   execution. Route admission needs its own observation.
2. [fixture.json](../scripts/rvv/fixtures/chips-vsmul-vv/fixture.json) pins
   `fixed1024/stage2/vsmul_vv-0.S`, CHIPS revision, environment, modified-Spike
   oracle, source hash and ELF hash. Decompress `test.S.gz` to inspect the actual
   input and original `TEST_CASE` checks. For example the first target has AVL0,
   e8/mf4/tu/mu; after storing the destination, `TEST_CASE(2, t0, 0xddb8bebc,
   lw t0, 0(a0); addi a0, a0, 4)` checks one preserved destination word.
   Later targets exercise arithmetic. This first assertion alone is not an
   arithmetic test. The upstream `macros/general/test_macros.h` defines the
   comparison and failure branch; the local `scripts/rvv/chips_user/riscv_test.h`
   changes terminal reporting, retaining the body and golden words.
3. In the separate registered-corpus archive, select manifest cells with ELF
   `94a1a592014d8d287fb17dc17fcd42e0c05e98f3fb694e253d5c87856f30440b`.
   The original alias table selects `batch=fixed1024,test=vsmul_vv-0`.
   An M2 example is cell
   `19a87e40a32aa13b90c1a51d463109a0d01a6c96b2b500c111f30763267a42cc`.
   Select that cell in `manifest.json`; open `historical/runs/<cell>/command.json`,
   `result.json`, `stdout` and `stderr`; check the historical candidate/library and complete
   flags, exit0 and exact `CHIPS_PASS\n`. The archive retains its `historical/AUDIT.json` and payload hashes.
   The repo auditor applies to saved runs in the portable replay schema; it
   does not directly reinterpret this historical directory layout. The self-check's words come from the retained
   modified-Spike/merger workflow, never from rvdbt output.
4. For current suite bindings, render `--form vsmul.vv --bindings ...` with
   `rvv_scope_report.py`. Each original row retains source/assertion/reference
   locators, candidate identity, adapter and raw-result paths. Follow those
   locators in the separately obtained evidence tree. Rebuilding a new DUT
   records a new identity; it cannot replace these historical results.

A fixture rebuild verifies source and ELF identity; the optional smoke execution
runs four configurations. Neither recreates the golden-generation campaign.
Passing four switches does not prove four optimized routes or full-state checks.
The thesis's complementary `vadd.vv` LMUL8 case is retained in the
`vadd-m8-1024-external/` evidence directory: 26 targets, 6656 original checker
words, same-ELF QEMU and clean DUT comparisons. Its `README.md`,
source, command/result records and checker audit explain that geometry.

## Trace external assertions

### CHIPS guest-side comparison

For the primary CHIPS corpus, the [inspection guide](rvv-validation/chips-review-task93/README.md)
provides the source/build/assertion/raw navigation and the actual width counts.
There are 11,532 positive executions and 212 failure controls per candidate,
not 595 forms multiplied by every VLEN/SEW/LMUL combination. The CHIPS macro
`TEST_CASE` loads each expected word, compares it with the observed word and
branches to `fail` on a mismatch. The retained build commands do not enable
`COSIM_TEST_CASE`, which would omit that comparison. Offline checking reapplies
the recorded exit/stdout predicate; it does not execute those guest comparisons
again. The [published archives](https://github.com/kust1011/rvdbt/releases/tag/rvv-validation-20261012)
include the sources, checks and retained outputs described in the guide.

### ACT indexed load: from expected signature to checked execution

The [ACT db2 reader](rvv-validation/act-db2-task110/README.md) provides a
1,919-file index. To inspect an indexed load, select `Vls8-vluxei8.v` in
`RESULT_INDEX.csv` and follow its source, signature and result paths:

1. Read the original generated assembly and its testplan entry. The target
   loads elements using vector indices; the surrounding code sets the operands,
   vector configuration and destination before executing it.
2. Sail executes the signature-producing program. The pinned upstream signature
   processor converts its capture into expected values for the self-checking
   executable. These values are not collected from rvdbt.
3. The upstream `signature.h` supplies the in-program comparisons. QEMU first
   runs the self-checking executable; B/M1/M2/Both then run that same executable.
   Check the selected BASE/LEN/CSR assertions, not just the target opcode name:
   different assertions observe different portions of the result.
4. Open each command, exit record and original output. Acceptance requires no
   timeout, exit zero, exactly one original PASS summary and no FAILED text.
   The portable replay interface creates new records without replacing the
   archived ones. The offline inspector only rechecks retained evidence.

This batch has 1,916 complete-file passes under all four configurations
(7,664 DUT executions), one previously accepted file, and two reference blockers.
The Linux environment replaces startup `csrs mstatus`, but retains the tested
`csrrc`/`csrrs mstatus` operations in both `vfmv.f.s` files. Those files stop in
QEMU before DUT execution; their original checks were not removed. The batch
does not add forms to the 595-form union, establish optimized-path admission,
or test general fault recovery.

### Ara `vfdiv.vv`

Ara revision `34bd3bc152421b4601a7bf3d6e8e91ffb545c99e` supplies
`apps/riscv-tests/isa/rv64uv/vfdiv.c`. Its first FP32 block sets VL16,
loads sixteen original hexadecimal operands into each source vector, executes
`vfdiv.vv v1, v2, v3`, and compares the result with sixteen literal expected
words through `VCMP_U32`. These expected words are upstream data, not outputs
captured from rvdbt. The original `main` selects `CHANGE_RM(RM_RTZ)` before
calling the test functions.

The RV32 adapter extracts the FP32/FP64 blocks from functions that also contain
FP16 operations. It preserves their operands, target instructions and assertions,
and carries the original rounding initialization into each wrapper. Before the
block, an observation reads `fcsr` and `vstart`: `fcsr=32` means `frm=1` (RTZ)
and zero initial exception flags; `vstart=0` starts at the first element.
The self-check compares the original result words. Spike and rvdbt execute the
same ELF; the runner also requires successful termination and complete checker
output. Final observed `fcsr` is compared with Spike separately from the
upstream result assertion.

This context check caught an adapter defect: wrappers initially omitted the
original RTZ initialization and ran in RNE. Those observations remain recorded
as invalid-context history, including one that happened to pass. Restoring only
the original initialization produced sixteen corrected blocks, each passing
Spike and B/M1/M2/Both, for eighty executions. The expected words were unchanged.
These are extracted-block results, not passes of complete mixed-FP16 files.

To explain the review, distinguish three checks: the original assertion checks
the calculated value; the adapter review checks that the intended input and
initial state reached the instruction; runner failure controls check that an
incorrect output or unsuccessful process cannot be reported as PASS. Enabling
M1 or M2 does not itself establish that the corresponding optimized path ran.
The retained `ara86/MAIN_REVIEW.json` records independent replay of all eighty
outputs and 160 parser rejection controls; source-initialization controls are
listed separately in `ara86/REGRESSION_CHECK.json`.

These source, adapter, raw and review records are included in the
[licensed Ara inspection archive](rvv-validation/ara-review-task91/README.md).
Follow `FORMS.json` into `BINDINGS.json` to find package-relative records, then
run its offline checker to replay the retained original predicates.

## Limits to keep in the answer

Original inputs, mechanical API derivatives, reporting adapters and added state
observers have different provenance. RIF's1500 final roots/6000 DUT calls stay
separate from543 O2 derivative ELFs/2172 diagnostic observations. The108 original reduction
producer failures remain. Task75 separately retains108 source-backed derivatives/108
same-ELF QEMU references/432 clean961 B/M1/M2/BOTH calls, all PASS with exit0/no timeout
and unchanged goldens. The host scalar evaluator reads uninitialized storage;24
absorbing-zero AND/unsigned-min checks lack target dependence. These derivatives receive
scalar endpoint evidence only, with no independent form or M1/M2 admission credit.
Task74 resolved218 mapping obligations as174 lowering absences,6 checked compound
sequences,8 genuine vmv.v.v checker gaps and30 parser false misses; the original872-row
CSV/views remain historical lineage. ATG's9 producer
contracts/2 reserved source-overlap outputs, Ara macro/store/profile gaps,
CHIPS8 unsafe store outputs, ACT profile/signature gaps and RVISmith34 compiler
errors remain visible alongside positive derivatives. RiESCUE/FORCE observer
contracts and CTK/Tenstorrent profile exclusions do not become ISA passes.
rv32emu retains whole-test FAIL (8 reached,7 passed,1 failed,296 unreached),
without data-vector result coverage.

Clean961 is a historical build, not the current fault-handling implementation.
The delivery branch integrates checked-helper fault delivery and exact host-PC
fault exits for admitted singleton QCG memory bodies. Memory instructions form
run boundaries; arithmetic promotion remains available on either side.
Local terminal-state checks inspect the instruction PC, memory address,
completed state and vstart. The retained guest signal fixtures exit from the
handler; they do not return and retry an instruction. Task142's checked signal
buffers do not establish guest return/restart, optional native-path recovery or
general non-vector fault handling. Historical P4 results remain separate.
Full/intermediate state, access suppression, agnostic write history, arbitrary
overlap/restart and per-PC M1/M2 admission remain unknown beyond scoped witnesses.
These results establish finite checked forms/configurations, not full RVV1.0
conformance or complete engineering.

## Explain a memory fault without conflating the tests

For an admitted singleton unit-stride load, the generated code publishes each
completed chunk to `CPUState` before the next guest-memory access. The compiler
records the exact host memory-instruction address and its emitted cold exit in
`NativeMemorySite` (`dbt/qmc/compile.h`). Registration binds those records to
the finalized code allocation, not a guessed instruction offset.

`dbt/rvv_native_fault.cpp` accepts only faults satisfying the site's ownership
and access conditions. The signal callback redirects execution to the cold
exit; the ordinary runtime then records the guest PC, address and restart
element and enters the dispatcher. CPUState loads, allocator spills and unrelated
host faults are not guest-memory sites. Page-crossing or unsupported backing
uses the checked helper instead of this SIMD fault path.

Three different observations answer three different questions:

1. An external normal-path test checks its original expected result. It does
   not test fault-state handling just because its opcode is a load or store.
2. A local one-time fault fixture captures the terminal dispatcher state and
   compares completed and unchanged elements. It does not repair memory or
   execute the faulting instruction again.
3. A guest-handler delivery test checks the delivered state and signal frame.
   Returning from that handler and correctly resuming the instruction would
   require a separate test; the exit-only fixtures do not establish it.

The implementation links and exact results are in the
[ordinary native contract](../SESSION0_RESULT_131.md),
[checked helper integration](../SESSION0_RESULT_132.md), and
[whole-register contract](../SESSION0_RESULT_133.md). These are implementation
regressions, not additional external instruction forms.
