# Task146 — directed integer subtraction and bitwise family

Completed on **test/rvv-directed-forms-20261013**, after **18d911e**.
Shared generator/checker/runner/auditor extended for **13 new forms** and all three
vadd regression forms. No production change or push. Existing Python caches,
Task145 manifest and Task145 raw remain untouched. Requested W/AGENTS.md is absent;
the active upstream delivery plan and THESIS_STATUS were read.

**70,696/70,696 planned cases executed**, each on independent reference and
host512 **B/M1/M2/Both**: **353,480/353,480 PASS checks**, **21,120/21,120 commands**.
Complete offline reapplication confirms every packet, source/target encoding and
all **2,112** Sail adapters. **128/128 formal-packet controls rejected**;
12/12 legacy synthetic checks passed. Pilot828 cases/4,140 checks and128 pilot
controls remain separately retained and earn no formal credit.

| Form | Planned = executed PASS per reference/B/M1/M2/Both arm |
|---|---:|
| vadd.vv | 4,237 |
| vadd.vx | 4,501 |
| vadd.vi | 4,501 |
| vsub.vv | 4,237 |
| vsub.vx | 4,501 |
| vrsub.vx | 4,501 |
| vrsub.vi | 4,501 |
| vand.vv | 4,237 |
| vand.vx | 4,501 |
| vand.vi | 4,501 |
| vor.vv | 4,237 |
| vor.vx | 4,501 |
| vor.vi | 4,501 |
| vxor.vv | 4,237 |
| vxor.vx | 4,501 |
| vxor.vi | 4,501 |
| **Total** | **70,696 per arm** |

New forms contribute57,457 cases; vadd regression contributes13,239.
Every form has all22 legal ELEN64 SEW/LMUL pairs × six VLENs128–4096.
Lengths, host chunk boundaries, masks/policies, operand edges, aligned equal-source
and destination/source overlap, and register-file endpoints reuse145 patterns.
New initialized nonzero-vstart cases cover partial/zero VL and start>=VL, with
partial chunk/mask/policy/overlap interactions. All starts are CSR-representable,
0..VLEN-1; e8/m8 full-VL equality cannot be represented and uses partial equality.
No setup instruction earns target-form credit.

Reference: fixed **Spike20feb9c2+RV32 pk** for42,184 zero-start cases using the same
ELF as DUT; fixed **Sail0.14.1/e4b243f** for28,512 nonzero-start cases, with verified
entry/exit-only adaptation and supported per-invocation configuration. Ordinary
nonzero-start cases number24,352. The other4,160 use CSR-representable starts>=VLMAX,
which the ISA marks reserved; Sail's supported Vstart_Ignore setting tests the
DUT's no-body profile behavior, not a universal ISA acceptance requirement.
Source review and the all-form pilot confirmed reference support before full run.

[Oracle review](docs/rvv-validation/directed-task146/REVIEW.md) explicitly checks
`vs2-operand` versus `operand-vs2`, simm5 -16..15, RV32 vx sign extension at SEW64,
and logical operations. No DUT algorithms/outputs supply expected answers.
ISA/profile predicates and independent-reference comparisons have separate
functions and receipt/CSV fields. All32 vector registers,10 CSRs and s0 have
observed pre/post state; target CSRs are captured before any vector dump.
Every preserved register/element is checked; no-body cases preserve even agnostic
tails. Reference agnostic choices are checked against allowed sets.

Correctness execution: **1,040.5402s**, four bounded workers after load check,
cores28–31/nice10, no global changes. Aggregate command elapsed time3,916.8293s.
Compilation/development wall time was not separately instrumented. No confirmed
DUT bug, missing case, reference blocker or unresolved semantic failure occurred;
therefore no DUT failure minimization/source diagnosis or production patch applies.
Stopped serial compilation, a failed scp destination and an early local transport
check of incomplete extraction are preserved as packaging/environment observations
in [PRELAUNCH](docs/rvv-validation/directed-task146/PRELAUNCH.md), separate from
formal tests. Original streams are retained; no semantic failure was retried.

[Delivery and commands](docs/rvv-validation/directed-task146/README.md) links the
finite declaration/manifest, per-form results, full observed state receipts,
compiled guest pins, build commands, full audit, rejection controls,80 concrete
source/state examples, reference/DUT identities and failure classification.
Formal raw: **xbd:/home/vick/rvv-directed-task146/corpus/**.
Local raw: **/home/user/research/materials/task146-directed-raw-20261013/**.
Archive: **xbd:/home/vick/task146-directed-final-raw.tar.gz**.
[Transport](docs/rvv-validation/directed-task146/TRANSPORT.json) authenticates the
archive and every extracted payload file. Old145 compatibility verifies identical
9,393-case default manifest and36 selected source batches; no old raw audit rerun.

Progress: **13/13 requested new forms complete**, **16/595 directed forms overall**;
**70,696/70,696 family cases**; **0 unresolved DUT failures**; **0 family blocked or
unexecuted obligations**. Remaining579 forms and other host widths/RV64, illegal
encodings, exhaustive interaction products, multi-instruction live-out/early-exit
and per-target M1/M2 admission remain outside this finite family. Reserved-value
profile tests are explicitly separated. No full external rerun, generic
Linux/scalar/atomic/LLVM work, performance/publication, guest handler return,
repair/retry/P4-04 or equivalent. Launcher owns the unique completion signal.
