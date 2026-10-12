# Scoped adoption of Tasks103–106

These are accepted, named original predicates from four execution checkpoints.
Tasks107–108 add **zero DUT executions**. Task108 completed the
[RV64 precondition comparison](reference/task108/comparison.json): the actual Zfh
`flh/fsh` probe and the complete original enabled body both exited0 without timeout;
all 256 captured bytes equal Task106's scalar-store replay. The
[Task107 blocked receipt](reference/comparison.json) is preserved as history.
The [new RV64 build identity](reference/task108/BUILD_IDENTITY.json) pins official
QEMU `f9587d4045c67cd0d8d8bdcd5d0bb5b6b395b63c`, built in isolated
`xbd:/home/vick/rvv-task108/build` with only `riscv64-linux-user` and two jobs.
The existing RV32 reference remains byte-identical and has a separate identity.
The [reference identity](reference/task108/identity.json) matches Task107's source,
proof, adapter, ELF and compiler; the [exact adapter diff](reference/original-to-user.diff)
remains unchanged.

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

The [Task106 dependency proof](receipts/DATA_DEPENDENCY_PROOF.json) replays ten
stores in original order with full 64-bit inputs. Task108 now validates its final
256-byte state by execution, immediately before the first vector `vsetvli`.
The [runtime review](reference/task108/RUNTIME_REVIEW.json) joins executed trace
blocks to all 23 scalar no-trap checks, 34 scalar value/byte checks and 13 vector
no-trap checks; the fail label and unused M-mode handler were not entered.
The [original offline review](reference/REVIEW_CHECKS.json) and all five accepted
Task106 receipts remain intact. No Task106 DUT was rerun.
The new [precondition checker](../../../scripts/check_rvv_qemu_preconditions.py)
builds the original RV64 body without replacing `ld/sd/flh/fsh` or scalar assertions.
Only privileged startup and semihost exit are adapted to Linux user, with a
256-byte write at vector entry. It saves/restores a0/a1/a2/a7/t0 and sp, writes no
buffer/vector/FP/CSR state, and leaves all original vector dependencies in place.
The unused M-mode trap handler remains visible. A separate actual `flh/fsh` probe
with `zfh=true` must succeed before the full reference is run once. Signals,
nonzero exit, timeout, short write or byte mismatch cannot pass. Missing RV64 or
failed Zfh probe is BLOCKED (exit2), never PASS. This validates extraction inputs;
the observed success adds no rvdbt coverage or original M-mode acceptance.

## Source, adapter, checker and raw access

Small copied receipts above are existing observations, not new executions. Full
source/adapters/build/disassembly/raw histories remain at the following xbd paths;
SSH access is required. These paths are not public download URLs. No distributable evidence
archive or full upstream source bundle is committed here. Obtain upstream sources at the exact
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

To replay only the validated precondition with Task108's separate RV64 binary:

```sh
python3 scripts/check_rvv_qemu_preconditions.py \
  --source /home/vick/rvv-task106/source/test-zicclsm.S \
  --proof /home/vick/rvv-task106/DATA_DEPENDENCY_PROOF.json \
  --qemu /home/vick/rvv-task108/build/qemu-riscv64 \
  --output /home/vick/rvv-task108/new-reference-precondition
```

The command uses existing clang22 and produces raw build/probe/reference argv,
stdout/stderr/exit/timeout records, full adapter/diff/disassembly and comparison.
It never invokes elfrun. Actual Task108 raw is at
`xbd:/home/vick/rvv-task108/reference-precondition/`; small
[probe](reference/task108/zfh-probe/result.json) and
[reference](reference/task108/reference/result.json) command/output/result receipts
are copied here. The 35,600-byte executed trace, full generated adapter and ELF,
source archive and build/dependency logs stay on xbd, with hashes in the build and
runtime reviews. The unchanged checker was invoked once for the probe and body.
Its availability receipt is a pre-execution snapshot; actual Zfh success is in the
probe and comparison receipts. The first incomplete source-stream configure failure
is retained in `reference/task108/configure-incomplete-transfer.{stdout,stderr}`;
the complete archive and all 11,404 archived files were verified before acceptance.
Historical blocked preparation remains at
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

The RV64/Zfh scalar buffer comparison gap is closed. Remaining bounded adoption
gaps are: ACT's other 383 applicable db2 exact output identities, profile-excluded
64-bit-index truncation, EFFEW32 vfwcvt producer input and dedicated privileged
vset tests; Sail neighboring expected illegal-group/ELEN trap assertions; QEMU
`test-vle32ff.S` original cause5 plus unchanged-VL predicate and the disabled
Zicclsm exception/cause/address profile. Linux signal/precise fault/restart support
remains unresolved; clean961 and the independent P4 candidate must remain separate.
P4-04 remains blocked without retry. These gaps are not discharged by these four
accepted checkpoints, and no whole original QEMU/Sail M-mode PASS is claimed.
