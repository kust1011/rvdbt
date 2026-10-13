# Task154 — destructive multiply-accumulate execution

Eight MAC forms completed on unchanged e2559c5c host512: vmacc/vnmsac/vmadd/vnmsub, each vv/vx. **40,232/40,232 cases, 201,160/201,160 packet checks, 10,560/10,560 commands**; build/run/full offline audit/controls/summary all returned zero. There are **zero unresolved DUT failures, missing results, timeouts or reference blockers**. This is finite directed semantic evidence, not complete RVV conformance or per-target M1/M2 admission.

Read current THESIS_STATUS and its active RVV_UPSTREAM_TEST_DELIVERY_PLAN_20261012 before work. Branch remains `test/rvv-directed-forms-20261013`. Session3 worktree/raw and shared thesis status were not changed. No production edit, accepted-family rerun, exhaustive cache decompression, push, Linux/LLVM/performance expansion, or forbidden handler-return/repair-mapping/same-PC-retry/P4-04 execution.

The existing runner/capture/auditor now dispatch MAC initialization, assembler operand order, independent reference comparison and exact opcode checks. Captured old destination is the accumulator for vmacc/vnmsac and multiplicand for vmadd/vnmsub; legal same-width aliases consume captured old inputs. All six VLENs128/256/512/1024/2048/4096 and 132  legal SEW/LMUL geometries are covered, including fractional LMUL, group end, destination/source/both-source alias, masks, partial/zero VL, chunk boundaries, nonzero vstart, no-body preservation and RV32→SEW64 scalar extension. Full-state predicates cover 32  vector registers, ten CSRs and scalar s0. No DUT-generated golden: pinned Spike/pk supplies zero-start same-ELF packets; pinned Sail0.14.1 supplies nonzero-start packets through the unchanged adapter.

All five arms (Reference/B/M1/M2/BOTH) have identical full counts below. Every row has zero FAIL/blocked. Reserved starts remain profile observations, not ordinary ISA PASS; sixteen reserved encoding declarations remain NOT_RUN.

| Form | Cases per arm | Ordinary PASS | Reserved-start profile |
|---|---:|---:|---:|
| vmacc.vv | 4,897 | 4,637 | 260 |
| vmacc.vx | 5,161 | 4,901 | 260 |
| vnmsac.vv | 4,897 | 4,637 | 260 |
| vnmsac.vx | 5,161 | 4,901 | 260 |
| vmadd.vv | 4,897 | 4,637 | 260 |
| vmadd.vx | 5,161 | 4,901 | 260 |
| vnmsub.vv | 4,897 | 4,637 | 260 |
| vnmsub.vx | 5,161 | 4,901 | 260 |
| Total | 40,232 | 38,152 | 2,080 |

Pilot: 1,184 cases/5,920 checks/320 commands, all stages zero;1,152  ordinary and 32  profile cases per arm. All 64  actual-packet controls rejected. Additional260  retained-packet state/destructive-role mutations rejected, including all CSR/scalar pre/post fields, erased old destination, wrong destructive operand role, RV32 wrong extension, masked/prestart/tail/no-body and other-register corruption; no guest reruns. The full run independently rejected 64/64 mutations. [Actual witness packets](docs/rvv-validation/directed-task154/WITNESS_PACKETS.json) show source2=3/source1=5/old_vd=7 producing22,−8,38,−32 modulo2^64, respectively, in both forms and all five arms.

Full audit replays every packet and verifies 2,112  generated source/opcode units and 1,056 Sail adapters. Before/after frozen source checks and binary/reference identities match. Main MAC run time 788.1983 seconds with8 workers; pilot32.5261 seconds. Compact [full evidence](docs/rvv-validation/directed-task154/full-evidence/), [stage status](docs/rvv-validation/directed-task154/FULL_STAGE_STATUS.json), [final validation](docs/rvv-validation/directed-task154/FINAL_VALIDATION.json) and [commands](docs/rvv-validation/directed-task154/COMMANDS.json) retain exact denominators, per-form outcomes and identities. Current generators reproduce every frozen case declaration. The original full snapshot stays unchanged; later additive QEMU/widening dispatch lives in separately frozen snapshots and is not retroactively substituted for its source hashes.

QEMU RVV0.7.1 source was actually read in this task: all eight `tests/riscv/vector/case/{vmacc,vnmsac,vmadd,vnmsub}_{vv,vx}.c`, their64  matching wrappers in `rvv_ch12.inc`, plus `rvv_insn.S` include resolution and `rvv_insn.h` masks/pad/declarations, at romanheros/qemu commit 7a35c902707087c8e1b77a3c82c54b73ffa17703. Exact paths/hashes, borrowed scenarios and RVV1.0 adaptations are recorded in the [semantic note](docs/rvv-validation/directed-task154/SEMANTIC_REVIEW.md), linked from this family's existing Task152 note. The prepared40,232 case manifest predates the read and is not relabeled as previously QEMU-derived.

A separately frozen source-inspired MAC pilot adds96 cases/480 checks/160 commands: identifiable0x11 old destination, VLMAX−1 and complementary even/odd masks, adapted RV32 scalar0x55667788, generated vector inputs, all eight forms at four pilot geometries. All stages zero,80/80 controls rejected. This is project-directed testing inspired by external scenarios, not an unchanged external suite or adoption of old expected arrays/semantics. [Source-inspired evidence](docs/rvv-validation/directed-task154/qemu-pilot-evidence/) is separate from full MAC results.

Integer widening was developed while full MAC executed.22 forms: vwaddu/vwadd/vwsubu/vwsub vv/vx/wv/wx and vwmulu/vwmul/vwmulsu vv/vx. Full declaration 69,328 cases/3,960 units,65,236  ordinary and 4,092 reserved-start cases,90  legal geometries across all six VLENs;136 reserved encoding declarations NOT_RUN. Explicit destination/source EEW/EMUL, legal high-part narrow overlap (source EMUL>=1), equal-EEW wide-source overlap, fractional groups, group end, wide+narrow source distinction and current1.0 overlap-agnostic allowed sets are implemented. Different-EEW source-source overlap is reserved.22  additional QEMU case files and 132  matching wrappers were read and recorded; new qemu-* tags borrow partial/parity/padded-wide-destination scenarios, never their expected arrays.

Widening local checks: 1,248 checks,377  distinct compiled opcode matches,69,328 layouts and 360 geometry/form extents. Separately declared new-family pilot ran within task154's same eight-worker budget while the MAC full audit was active: **2,948 cases/14,740 checks/880 commands**, all stages zero;2,772  ordinary and 176  profile cases per arm,396/396 mutations rejected and 14/14  permitted overlap choices accepted. No unresolved widening DUT failures. Pilot guest time 55.2034 seconds. [Widening evidence](docs/rvv-validation/directed-task154/widen-pilot-evidence/) and [next-family declaration/entry](docs/rvv-validation/directed-task154/next-widen/README.md) are separate. Full widening is NOT_RUN;66,380  declared cases lie outside this pilot. Its first local preparation AssertionError (invalid low-part overlap in end-group layout) and correction are preserved in next-widen/PREPARATION_FAILURES.json; it was a generator defect before any guest, not a DUT failure.

Remote raw/source/compressed ELF/cache artifacts remain at `xbd:/home/vick/rvv-directed-task154/{pilot,full,qemu-pilot,widen-pilot}`. Build4/run8/nice10/no affinity throughout; task154 batches were sequential in guest execution, so together with session3's8 workers the combined guest limit stayed16. Disk was checked before launch and the shared compression runner enforced10GiB plus next-write reserve. No existing artifacts were deleted. Final measured free disk13,145,706,496B (12.24GiB), available memory recorded in [resources](docs/rvv-validation/directed-task154/FINAL_RESOURCES.json). The initial widening-full capacity preflight failed and remains retained; final capacity preflight passes the estimated2GiB batch allowance, so capacity must be checked again immediately before launch.

Next executable entry: separately frozen `xbd:/home/vick/rvv-directed-task154/widen-full/launch.sh`, complete finite69,328 case manifest, build4/run8 and same fixed references/DUT. Check live worker budget and free disk again, then execute:

```sh
ssh xbd 'cd /home/vick/rvv-directed-task154/widen-full; nohup nice -n 10 bash launch.sh /home/vick/rvv-directed-task154/widen-full > launcher.log 2>&1 < /dev/null &'
```

Its launcher refuses an existing corpus or less than10GiB reserve plus the estimated2GiB batch budget. Task154 only developed and piloted this next family; no full widening PASS is claimed. Main owns acceptance/integration and shared-status updates. Scoped local commit only; no push. Completion notifications: `rvv-directed-mac-20261013-154` and `rvv-review-parallel-20261013`.
