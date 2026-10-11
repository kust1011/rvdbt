# Reading the RVV implementation and validation

The inventory has 627 mnemonic/operand forms, with 595 applicable to RV32/ELEN64
and 32 ei64 indexed forms excluded by that profile. The fixed correctness build
uses QCG host512; VLEN128–4096 is a capability, not a tested Cartesian product.
Direct chunk routes and shared semantic helpers both implement guest behavior.

Source presence, compiled source, static emission, program execution,
target/result checking and coupled endpoints are separate stages. Checked sets
are CHIPS595, ACT590, RVV-ATG434, Ara301 and SiFive RIF194; their union is595.
RVVTS58, RVISmith43 and libriscv194 are coupled endpoints: program success does
not independently check each contributing static opcode. Candidate-specific
sets and original/derivative provenance remain in the canonical bindings.

## Trace one form: `vsmul.vv`

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

## Limits to keep in the answer

Original inputs, mechanical API derivatives, reporting adapters and added state
observers have different provenance. RIF's1500 final roots/6000 DUT calls stay
separate from543 O2 derivative ELFs/2172 diagnostic observations. The108 reduction
producer errors and218 case/mapping obligations remain open. ATG's9 producer
contracts/2 reserved source-overlap outputs, Ara macro/store/profile gaps,
CHIPS8 unsafe store outputs, ACT profile/signature gaps and RVISmith34 compiler
errors remain visible alongside positive derivatives. RiESCUE/FORCE observer
contracts and CTK/Tenstorrent profile exclusions do not become ISA passes.
rv32emu retains whole-test FAIL (8 reached,7 passed,1 failed,296 unreached),
without data-vector result coverage.

Clean961 lacks guest signal-handler completion; general precise vector fault
restoration/retry and native fault-state proof remain incomplete. P4 is separate.
Full/intermediate state, access suppression, agnostic write history, arbitrary
overlap/restart and per-PC M1/M2 admission remain unknown beyond scoped witnesses.
These results establish finite checked forms/configurations, not full RVV1.0
conformance or complete engineering.
