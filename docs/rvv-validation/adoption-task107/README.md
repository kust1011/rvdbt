# Scoped adoption of Tasks103–106

These are accepted, named original predicates from four execution checkpoints.
Task107 adds **zero DUT executions**. Its RV64 precondition reference is
[blocked](reference/comparison.json): the existing Task106 installation has only
`qemu-riscv32`, and no `qemu-riscv64` was found in xbd PATH, `/usr`, `/usr/local`,
`/opt`, `/home/vick`, `/tmp` or `/var/tmp` searches. Zfh actual availability is
unobserved; this is an executable availability obstacle, not evidence that Zfh is
unsupported by a tested RV64 CPU. The [RV64/Zfh build](reference/build-command.json)
succeeded. [Identity](reference/identity.json) and [exact adapter diff](reference/original-to-user.diff)
identify the complete scalar/vector body retained for review.

| Checkpoint / explicit status | Actual predicate and profile | Accepted executions and limits |
|---|---|---|
| Task103: **Spike endpoint** | Original vector-sum prints 500500; RV32/VLEN1024/e32/m8 | One Spike + four Task88 fresh-build DUT arms PASS; accumulator tails must be preserved. No independent per-form/state check or M1/Both admission. [Receipt](receipts/EXECUTION_RESULTS_103.json) |
| Task104: **ACT original215 targets** | Complete db2 Vls32-vluxei32.v: 190 BASE + 25 LEN checks; RV32/ELEN64/VLEN1024 | Sail signature capture + QEMU selfcheck + four retained clean961 arms PASS. Added basic VL1 block checks element0; original signature checker uses vector comparisons. Aggregate mov setup admission does not establish indexed-target promotion. [Receipt](receipts/EXECUTION_RESULTS_104.json) |
| Task105: **Sail legal group no-trap** | Original e32/m8/VL2/ta/ma; `vrgatherei16.vv v8,v24,v4`, index EMUL4; RV32/ELEN64/VLEN256 | Final same ELF QEMU + four retained clean961 arms PASS. No lanes/flags/illegal-group checks. Original Sail RV32 ELEN32 profile differs. Initial compressed-scalar pretarget failure and its reference remain on xbd. [Receipt](receipts/EXECUTION_RESULTS_105.json) |
| Task106: **QEMU13 extracted no-trap** | Original enabled vector sequence and 13 `s3==s5` assertions; RV32/ELEN64/VLEN128, exact scalar-store byte replay | Same ELF QEMU + four retained clean961 arms PASS: 13 reference/52 DUT assertions. No vector byte/lane golden, disabled-profile exception checks or whole-file M-mode PASS. [Receipt](receipts/EXECUTION_RESULTS_106.json) |

Task103 used the [Task88 fresh-build identities](receipts/EXECUTION_INPUT_IDENTITIES.json):
elfrun `9bb171b61e1f8f75b1b2779fdf368fb9fa53613546659bc1403b6744ccb31d43`,
library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
Tasks104–106 used the separate [retained clean961 identities](receipts/EXECUTION_IDENTITIES.json):
elfrun `6fda0f9ab06c2c824b5301d1f302b76799842981b00a88fffa85fe43f1dbd84f`,
library `1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d`.
Neither cohort is silently merged with a newly built executable.

The [Task106 static dependency proof](receipts/DATA_DEPENDENCY_PROOF.json) remains
static: ten stores in original order, full 64-bit inputs, and 34 scalar value/byte
assertion calculations. Task107 has **no captured bytes and no equality result**. The
[offline review](reference/REVIEW_CHECKS.json) confirms literal body/macros/trap
handler preservation, emitted RV64/Zfh instructions and all five retained
Task106 13-marker receipts, without guest execution. Only the build and missing
executable path of the new tool have been exercised; its actual Zfh/reference
execution path remains untested.
The new [precondition checker](../../../scripts/check_rvv_qemu_preconditions.py)
builds the original RV64 body without replacing `ld/sd/flh/fsh` or scalar assertions.
Only privileged startup and semihost exit are adapted to Linux user, with a
256-byte write at vector entry. It saves/restores a0/a1/a2/a7/t0 and sp, writes no
buffer/vector/FP/CSR state, and leaves all original vector dependencies in place.
The unused M-mode trap handler remains visible. A separate actual `flh/fsh` probe
with `zfh=true` must succeed before the full reference is run once. Signals,
nonzero exit, timeout, short write or byte mismatch cannot pass. Missing RV64 or
failed Zfh probe is BLOCKED (exit2), never PASS. This validates extraction inputs;
even a future success would not add rvdbt coverage or original M-mode acceptance.

## Source, adapter, checker and raw access

Small copied receipts above are existing observations, not new executions. Full
source/adapters/build/disassembly/raw histories remain at the following xbd paths;
SSH access is required. These paths are not public download URLs. No new evidence
archive or upstream source bundle was created. Obtain upstream sources at the exact
pins below and retain their notices; source identity is stronger than a form name.

| Task | Pinned upstream original | xbd review root and exact access |
|---|---|---|
| 103 | [Spike vector-sum.c, 20feb9c](https://github.com/riscv-software-src/riscv-isa-sim/blob/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/ci-tests/vector-sum.c) | `/home/vick/rvv-task102/`: `source/spike/ci-tests/vector-sum.c`, `source/spike/ci-tests/test-spike`, `BUILD_COMMANDS.json`, `EXECUTION_INPUT_IDENTITIES.json`, `start.S`, `transport.c`, `build/`, `execute_first_batch.py`, `execution-first/runs/{Spike,B,M1,M2,BOTH}/` |
| 104 | [ACT producer, db2b9fd](https://github.com/riscv/riscv-arch-test/blob/db2b9fd7aa71a6e669417f711379988541f1464c/generators/testgen/scripts/vector-testgen-unpriv.py) | `/home/vick/rvv-task104/`: `generate104.py`, `GENERATED.json`, `signature.diff`, `CHECKER_SCOPE_104.json`, `TARGET_PRESERVATION.json`, `checker104.py`, `execute104.py`, `pilot/Vls32-vluxei32.v/{INPUT.json,ORACLE.json,PRESERVATION.json,*.S,*.sig,*.results,*.elf.dis,raw/}`; original `tests/env/signature.h` and `framework/src/act/sig_modify.py` under `riscv-arch-test-db2b9fd7aa71a6e669417f711379988541f1464c/` |
| 105 | [Sail legal gather, 549e723](https://github.com/riscv/sail-riscv/blob/549e723031b34b5ffea5bbb56367be15c7a38a9e/test/first_party/src/test_vrgatherei16_reg_group.S) | `/home/vick/rvv-task105/`: `source/test/first_party/src/test_vrgatherei16_reg_group.S`, `adapter/original-to-user.diff`, `profile/ORIGINAL_CI_PROFILE.json`, `build/`, `audit105.py`, `execute105.py`, `results/{QEMU,B,M1,M2,BOTH}/`, `results/qemu-trace.txt`, `attempt1-compressed/` |
| 106 | [QEMU zicclsm, f9587d4](https://github.com/qemu/qemu/blob/f9587d4045c67cd0d8d8bdcd5d0bb5b6b395b63c/tests/tcg/riscv64/test-zicclsm.S) | `/home/vick/rvv-task106/`: `source/test-zicclsm.S`, `adapter/original-to-extracted.diff`, `EXTRACTION_FROZEN.json`, `DATA_DEPENDENCY_PROOF.json`, `audit106.py`, `execute106.py`, `build/`, `results/{QEMU,B,M1,M2,BOTH}/`, `results/qemu-trace.txt`, `VLE32FF_REMAINING.json` |

For example, retrieve exact Task106 source/checker/results without executing guests:

```sh
mkdir task106-review
scp xbd:/home/vick/rvv-task106/source/test-zicclsm.S task106-review/
scp xbd:/home/vick/rvv-task106/audit106.py task106-review/
scp -r xbd:/home/vick/rvv-task106/adapter task106-review/
scp -r xbd:/home/vick/rvv-task106/results task106-review/
scp xbd:/home/vick/rvv-task106/SESSION0_RESULT_106.md task106-review/
```

Each task's `SESSION0_RESULT_*.md` gives retained build/runner commands and failure
history. The execute scripts are task-local drivers with fixed paths/dependencies;
they are not interchangeable portable fixtures for `run_rvv_external.py`.
Replay requires a new output/work directory, separately obtained pinned dependencies
and the exact recorded flags/compiler/ELF contract; do not overwrite accepted raw.
For Tasks104–106, recorded argv in the linked receipts identifies every engine call.
For Task103 use `EXECUTION_QUEUE.json` and `EXECUTION_INPUT_IDENTITIES.json` in its
review root. Fetching these files is inspection, not a new PASS claim.
The established [portable external runner](../portable-external.md) continues to
cover its two fixtures; this document exposes these four additional scoped drivers
and evidence without silently expanding that runner's acceptance contract.

To resolve only Task107's pending precondition using an existing RV64 binary:

```sh
python3 scripts/check_rvv_qemu_preconditions.py \
  --source /home/vick/rvv-task106/source/test-zicclsm.S \
  --proof /home/vick/rvv-task106/DATA_DEPENDENCY_PROOF.json \
  --qemu /actual/path/to/qemu-riscv64 \
  --output /home/vick/rvv-task107/new-reference-precondition
```

The command uses existing clang22 and produces raw build/probe/reference argv,
stdout/stderr/exit/timeout records, full adapter/diff/disassembly and comparison.
It never invokes elfrun. Current blocked preparation is at
`xbd:/home/vick/rvv-task107/reference-precondition-final/`.

Licensing inspected before integration: QEMU source explicitly GPL-2.0-or-later;
ACT generated source and signature.h explicitly Apache-2.0; Sail README identifies
BSD two-clause `LICENCE`; Spike source is obtained under its pinned BSD-style
repository license. The precondition tool contains our transformation/transport
code, not a bundled upstream body. Generated full QEMU adapter retains the source
SPDX header. No complete upstream fixture, binary or bulk raw is committed here.

## Ledger boundary and finite remaining gaps

Existing [scope renderer](../../../scripts/rvv_scope_report.py) stages include
`result_checked` and `coupled_endpoint`; the [compact projection](../current-scope/README.md)
retains only those form memberships. It has no scoped `no-trap` predicate/profile
field. Encoding Task105/106 as independent result-checked forms would assert more
than their checkers observe. Task103 is an endpoint, with a disclosed tail policy;
Task104 is an additional exact source/configuration identity for an already checked
form. A faithful new binding would require the full candidate/source/checker/raw
join and main review. No canonical ledger, generated table or historical counter
changes were made. See the existing [current scope](../../rvv-current-scope.md),
[ACT reader](../act-primary-task99/README.md) and
[Ara accepted bindings](../current-scope/ara-accepted-evidence.md) for those unchanged
claims. Main owns the external-suite summary and thesis/status prose.

Remaining bounded adoption gaps are: Task107's actual RV64/Zfh scalar buffer
capture; ACT's other 383 applicable db2 exact output identities, profile-excluded
64-bit-index truncation, EFFEW32 vfwcvt producer input and dedicated privileged
vset tests; Sail neighboring expected illegal-group/ELEN trap assertions; QEMU
`test-vle32ff.S` original cause5 plus unchanged-VL predicate and the disabled
Zicclsm exception/cause/address profile. Linux signal/precise fault/restart support
remains unresolved; clean961 and the independent P4 candidate must remain separate.
P4-04 remains blocked without retry. These gaps are not discharged by these four
accepted checkpoints, and no whole original QEMU/Sail M-mode PASS is claimed.
