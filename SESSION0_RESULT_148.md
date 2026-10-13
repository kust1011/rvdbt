# Task148 — configuration delta and shift/minmax tests

On `test/rvv-directed-forms-20261013` after `a1e10b4`. Additive test/code/evidence;
no production changes, push, Task145–147 execution/repackaging, or new archive.
Read the active plan's 2026-10-13 efficiency update. Each pilot precedes its frozen
full background run/audit; shift development began while the delta ran.

Step 1 is complete. The immediate-vtype delta executes **7,008/7,008 cases** on
Reference and fixed e2559c5c host512 B/M1/M2/Both: **35,040/35,040 packet checks**,
**480/480 commands**, no missing/oracle/timeout/DUT failure. Full offline replay
checks every packet, source/target opcode and Sail adapter, rather than granting
credit from exit status. **156/156 formal-packet controls reject**; frozen scripts,
manifest and DUT/reference hashes match before/after. Execution 204.0541s, two
bounded workers. Pilot 292 cases/1,460 checks is separate.

| Delta opcode | Executed per arm | Unsupported profile result | Legal vill recovery |
|---|---:|---:|---:|
| vsetvli | 3,984 | 3,840 | 144 |
| vsetivli | 3,024 | 2,880 | 144 |

Each opcode directly covers its reserved vtype upper bits: vsetvli8–10,
vsetivli8–9. Opcode selectors earn no credit. Unsupported SEW/LMUL, six VLENs,
four policies, selected AVL, nonzero start, rd/x0 and prior vill/recovery cases
are explicit. Unsupported/reserved input results use PROFILE_UNSUPPORTED_VTYPE,
separate from legal PASS. No sibling-opcode result supplies an expected answer.

Step 2 implements **17 forms**: vsll/vsrl/vsra.vv/vx/vi and
vmin/vminu/vmax/vmaxu.vv/vx. **2,078-case/10,390-check pilot and complete replay
PASS; 457/457 targeted controls reject**. Full execution and complete raw replay verify
**102,785/102,785 cases / 513,925/513,925 checks / 22,440/22,440 commands**.
All five arms satisfy the declared predicates, with no packet failure, reference
blocker, missing result or timeout. **457/457 formal-packet controls reject**.
All 4,488 source/target batches and 2,244 Sail adapters are verified; snapshot and
fixed identities are unchanged. Execution 1,195.9203s with four bounded workers.
Compilation/development wall time was not separately instrumented. Per arm,
**98,365 ordinary PASS** and **4,420 PROFILE_RESERVED_START** are separate.

New ISA predicates were reviewed against frozen RVV1.0, fixed Spike20feb9c2 and
Sail0.14.1/e4b243f: signed/unsigned comparisons, SEW shift-count masks, unsigned
vi0–31 and RV32 scalar truncation/sign extension, including unsigned min/max.
The inherited geometry/mask/length/overlap/start obligations remain; targeted
operand/count boundaries, ties and all32 immediate encodings are additive.
Start>=VLMAX results receive PROFILE_RESERVED_START under the fixed accepting
profile. Controls cover new semantic mistakes and independent comparison, plus
active/preserved vector state, CSRs, scalar/pre-state and missing/crash/timeout.

First generator/routing/launch and control-witness mistakes are retained in
[FIRST_FAILURES.json](docs/rvv-validation/directed-task148/FIRST_FAILURES.json)
and the named remote logs/copies. All are resolved harness/control issues, with
no confirmed DUT diagnosis or production repair. Original147 manifests and the
145–147 finite declarations match; selected generated sources remain identical,
without rerunning their guests/checkers. Legacy 12 synthetic checks pass.

[Minimal reproduction/evidence](docs/rvv-validation/directed-task148/README.md)
links per-form manifests/results, fixed source-review hashes, commands, pilot,
freeze and identity receipts. Raw, generated source/ELFs, commands and frozen
script copies remain at **xbd:/home/vick/rvv-directed-task148/{delta,shift}/**.
No new transport archive or narrative attachment set. Load/disk were checked;
combined correctness workers never exceeded4 (delta2 + shift pilot2, then shift4
once delta/audit completed); affinity28–31 and nice10 only, no global change.

Progress: delta 2/2 opcodes complete; **shift 17/17 forms executed/audited**,
**109,793/109,793 total family cases**, **548,965/548,965 declared packet checks**,
**0 unresolved DUT/oracle failures**, **0 required family blocked/unexecuted
obligations**. **36/595 directed forms**, pending main review; remaining 559 forms
are outside this batch. Other host widths/RV64, per-target M1/M2 admission and
excluded Linux/scalar/atomic/LLVM, external full reruns, performance, guest
return/repair/retry/P4-04 equivalents remain outside scope. Finite predicate
acceptance is not a universal correctness proof. Launcher owns the unique
completion signal.
