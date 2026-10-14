# Task198 — external blockers and existing semantic dimensions

Reviewed `4ad13da7a0a973623e8e51c683b2328bfba47f1b`, current delivery/status/plan,
181 and193 evidence, original upstream sources/assertions and original outputs.
**No new DUT failure established. Two ACT blockers are reference/user-platform
problems; Ara's eight failing e64 function assertions are RV64-profile literals
inapplicable to RV32. One concrete non-recovery trap-testing gap is handed to
main.** No original test/predicate/result was changed or promoted to PASS.

| Item | Classification | Specific reason / credit |
|---|---|---|
| ACT db2 `Vf32-vfmv.f.s` | Reference/tool platform problem; privileged FS setup profile-inapplicable | Original `cp_custom_vfp_state` clears FS via mask0x6000 and sets Clean via0x4000 in machine `mstatus`. Original QEMU user selfcheck stops at PC0x80005d20/raw30033073, before the target. Sail capture exits0; QEMU SIGILL remains failure. Zero DUT calls; four withheld arm slots. |
| ACT db2 `Vf64-vfmv.f.s` | Same classification | Exact analogous original setup, QEMU PC0x8000738c/raw30033073. Sail capture exits0; original user QEMU stops before target. Zero DUT calls; four withheld arm slots. |
| Ara `vmacc`, `vmadd`, `vnmsac`, `vnmsub`, TEST_CASE3/4 e64 | Profile-inapplicable original RV64 scalar assertions; RV32 diagnostic-format problem | Scalar−598189234597999223 becomes the RV32 x-operand2069024137 before SEW64 sign extension. All16 unmasked and8 masked-active literals per form match the full RV64 scalar, and all24 active literals per form differ from the RV32 formula. `%x` receives uint64_t arguments; printed fields are not full64-bit observations. Original failures remain; whole-file PASS is false. |

The ACT generated source hashes match the original results; exact original
`signature.h` SHA is
`d4e7f032695ccd4bfb7dcf92687909aa20d4140e7f4ec7d999b829382f0ccacb`.
`RVTEST_SIGUPD_F` compares FP value words and `RVTEST_SIGUPD_FFLAGS` compares
flags; this coverpoint does **not** read/assert the post-instruction FS field.
Removing tested `mstatus` setup would change the original test. Neither an
unprivileged reference rerun nor an M-mode reference PASS could establish this
user DUT's whole-file PASS. FP32/64 `vfmv.f.s` itself remains applicable and has
separate accepted171 evidence; its mnemonic is not excluded.

Ara examples from unchanged source arithmetic: `vmacc`/`vmadd` TEST_CASE3 lane0
original literal `093861b79ac45352`, RV32 specified value `2da6692c9ac45352`;
TEST_CASE4 lane1 literal `fd3c909decf66b5b`, RV32 value `210df7dbecf66b5b`.
For `vnmsac`/`vnmsub`, corresponding pairs are
`60dd7609c833e03a` / `e47a12a7c833e03a` and
`79abe3a30a816ca0` / `af715fe90a816ca0`.
The printed low/high words are consistent with these RV32 values, but the
varargs format cannot prove the complete stored result. We do not infer full
DUT correctness from that diagnostic. Source proof decides applicability
without executing another reference or replacing the literals. `.vx` e64
operations remain required and have separate directed152 evidence.

[Supporting evidence](docs/rvv-validation/directed-task181/CLOSURE198_EVIDENCE.json)
retains source/adapter/header/stream hashes, exact ACT setup windows/results and
original diagnostic trace ends, all16 Ara arm-stream failure bindings, arithmetic
derivations for all eight e64 function blocks, and six exact accepted181 semantic
declaration joins. Four bounded downloads from Ara revision
`34bd3bc152421b4601a7bf3d6e8e91ffb545c99e` match the retained original sources
byte-for-byte; primary URLs/hashes are in the evidence. All four Ara
B/M1/M2/BOTH streams have two retained failed
assertions.181's fresh179 payload identity proof remains authoritative; no
historical external result is given a new-build identity.

[Semantic reconciliation](docs/rvv-validation/all-form-records/SEMANTIC_RECONCILIATION_198.md)
reuses the existing G/S/M/E dimensions and187–193 audits. Old even-retained
`vsmul.vx` ties, whole-move nonzero start, nonbyte mask-store length and mask-tail
allowed sets have later accepted exact declarations.190 already supplies the
specific inexact unordered-reduction category.193's86 reserved exclusions and86
legal neighbours are not reopened. No exhaustive-input demand or new survey is
created.

**Actual absent non-recovery obligation:** zero accepted181 architectural
nonzero-vstart illegal-instruction checks for the23 required-trap forms. Their
restriction declarations are `NOT_RUN`; the592 denials are memory faults, and
successful initialized nonzero starts cover the other572 forms. Smallest case
for main: `vcompress.vm v8,v16,v17` (`0x5f08a457`), VLEN128/e8/m1, VL0,
vstart1, disjoint operands; terminal `ILLEGAL_INSN` at exact PC/raw and preserved
state, with no handler return/retry. No test is authored/executed here, and no
source-confirmed DUT defect is inferred from absent execution evidence.

Unchanged denominators:627 inventory /595 applicable /32 RV32 ei64 exclusions;
3,017,262 ordinary cases/arm plus564 focused positives/arm =12,071,304 positive
DUT checks. External21,316 calls comprise CHIPS11,744 (212 controls), ACT7,668
accepted calls and Ara1,904 (1,888 whole-file,16 TEST_CASE1/2-only scoped).
The two ACT blocked files retain eight withheld arm slots outside7,668. Ara's
eight failing function blocks yield32 function/arm failure observations within
16 scoped calls; none becomes whole-file PASS.96 profile-mismatched active
source literals are an arithmetic audit count, not new ISA executions.

Undecided: actual forbidden-start trap execution for23 forms; full64-bit state
of the failed Ara assertions is unobserved in retained diagnostics; exact188
full fault-state observations remain limited. P4-04/equivalent recovery remains
**NOT EXECUTED / NOT VERIFIED**. New-build final replay belongs to Session0.

Validation: final read-only evidence generator completed at nice10 on xbd,
one worker/no affinity, RAM and disk>=10GiB gated. Zero compiler, guest or
reference calls; no production/shared prose/Linux/LLVM/performance/thesis edits,
full-matrix reruns or push. A preliminary local source join completed with a
disk gate only; after adding a RAM gate, its next attempt stopped before reading
the archive because available RAM was below10GiB. Final generation was moved to
the private `/home/vick/rvv-closure198-review` evidence directory with both gates;
no failed attempt earns execution credit. The
[generator](docs/rvv-validation/directed-task181/review198.py) and remote inputs
are retained; the separate bounded upstream identity check is recorded in the
JSON. Final generation gates observed34,667,409,408 available RAM bytes and
17,292,996,608 free disk bytes. No new test suite was created. Owned result/evidence committed
locally; completion signals `rvv-review197198` and `rvv-closure198` follow.
