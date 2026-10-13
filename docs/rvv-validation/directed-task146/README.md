# Directed integer subtraction and bitwise forms — Task146

This project-authored family extends the reviewed Task145 framework with
**vsub.vv/vx, vrsub.vx/vi, vand/vor/vxor.vv/vx/vi**, plus three vadd regression forms.
[Oracle review](REVIEW.md) covers subtraction direction, simm5/vx sign extension,
initialized nonzero-vstart, independent answers and complete preserved state.
The shared implementation is `scripts/rvv/directed/{vadd,audit,reject}.py`.

All **353,480/353,480** checks PASS, independently reapplied to every retained
packet by the [complete audit](AUDIT.json). **21,120/21,120 commands**, zero missing,
blocked or unresolved test/reference/DUT failures. Correctness execution took
**1,040.5402s** with four workers; sum of command elapsed times3,916.8293s.
Compilation/development wall time was not separately instrumented. New13 forms:
57,457 cases; vadd regression:13,239 cases. Directed form progress is16/595 overall,
with13 new forms completed by this task; remaining579 forms are outside this batch.

| Form | Planned | Reference PASS | B PASS | M1 PASS | M2 PASS | Both PASS |
|---|---:|---:|---:|---:|---:|---:|
| vadd.vv | 4237 | 4237 | 4237 | 4237 | 4237 | 4237 |
| vadd.vx | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vadd.vi | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vsub.vv | 4237 | 4237 | 4237 | 4237 | 4237 | 4237 |
| vsub.vx | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vrsub.vx | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vrsub.vi | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vand.vv | 4237 | 4237 | 4237 | 4237 | 4237 | 4237 |
| vand.vx | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vand.vi | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vor.vv | 4237 | 4237 | 4237 | 4237 | 4237 | 4237 |
| vor.vx | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vor.vi | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vxor.vv | 4237 | 4237 | 4237 | 4237 | 4237 | 4237 |
| vxor.vx | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| vxor.vi | 4501 | 4501 | 4501 | 4501 | 4501 | 4501 |
| **Total** | **70,696** | **70,696** | **70,696** | **70,696** | **70,696** | **70,696** |

[Per-form executed results](PER_FORM_RESULTS.json), [summary](SUMMARY.json),
[observed checks](OBSERVED_CHECKS.csv.gz), [guest pins](GUEST_PINS.json.gz),
[build commands](BUILD_COMMANDS.json.gz), [adapter verification](ADAPTER_VERIFICATION.json.gz),
[identities](IDENTITIES.json), [first failure classification](FIRST_FAILURES.json),
and [128 formal-packet controls](REJECTIONS.json) are retained. All128 controls
were rejected;12 legacy synthetic checker tests passed. The independent comparison
passes282,784 DUT observations;70,696 reference packets satisfy separate ISA/profile
predicates. The complete audit verifies2,112 Sail-adapted batches. No per-target
M1/M2 admission claim is made. [Pilot](PILOT.json):828 cases/4,140 checks PASS,
5.7476s, plus128 separate pilot controls; excluded from formal case credit.

The [finite declaration](DECLARATION.json) and [manifest](MANIFEST.json.gz) precede
execution: **70,696 cases**, **353,480 checks**, **4,224 batches × 5 arms =21,120
commands**. Every form has all22 legal ELEN64 SEW/LMUL pairs and all six VLENs
128/256/512/1024/2048/4096. Full/partial/zero VL, chunk-adjacent lengths,
all/off/alternating/single-on/single-off masks, tu/ta and mu/ma, legal aligned
overlap and end-of-register-file groups follow the145 patterns. Additional
initialized vstart cases cover zero/partial VL, start>=VL and partial chunk
boundaries with masks, policies and overlap. [vstart classes](VSTART_CLASSES.json)
separate42,184 zero-start,24,352 ordinary nonzero-start, and4,160 reserved-start
profile cases. Reserved CSR-representable starts>=VLMAX are no-op profile evidence,
not a requirement that every conforming implementation accepts those values.

Fixed executable/library/reference identities are retained with the run. Spike
20feb9c2 plus RV32 pk executes the **same ELF** as DUT for zero starts. Fixed Sail
0.14.1/e4b243f handles nonzero starts with supported per-invocation configuration;
no reference algorithm/binary or global setting changes. All32 vector registers,
ten CSRs and scalar s0 have checked pre/post state. Post-CSRs precede any dump.
The audit checks each target opcode and Sail adapter, not setup opcodes as form
coverage. ISA predicates and independent-reference comparison have separate
receipt/CSV columns. Agnostic old/all-ones choices are checked as permitted sets.

[Legacy compatibility](LEGACY_COMPATIBILITY.json) confirms identical default
9,393-case manifest and36 selected original generated sources. Task145's manifest
and raw are untouched; its separate main raw audit is not repeated. The separate
828-case/4,140-check pilot and its128 rejection controls earn no formal case credit.
[Prelaunch notes](PRELAUNCH.md) preserve a stopped serial build and a transfer
error; neither is a guest/reference/DUT failure.

[Authenticated transport](TRANSPORT.json) verifies all193,371 payload files
(12,623,415,398 bytes), with zero missing/extra/hash differences. Archive SHA256:
`1f54b3e75418088c1a7f786378f52c0a43366081f26d9c0ec268c148510bffb8`.

Raw locations:

* Remote: `xbd:/home/vick/rvv-directed-task146/corpus/`.
* Local extraction: `/home/user/research/materials/task146-directed-raw-20261013/`.
* Archive: `xbd:/home/vick/task146-directed-final-raw.tar.gz`.

Each batch retains `test.S,test.elf`, nonzero-start `sail.elf,sail-config.json`,
and original build stderr. Each arm retains `command.json,execution.json,stdout,
stderr,packets.bin,checks.json,errors.json`; Sail adds `signature`, DUT adds `tbmap`.
No failure is overwritten or replaced by a retry. Archive excludes only disposable
work filesystem/cache copies and separately pinned reference binaries. Scripts,
source review copies, loads, manifests, commands, all raw, audits and corrupt
control copies are retained. [Commands](COMMANDS.json) gives exact launch arguments;
individual actual commands remain in raw. Launcher owns the completion signal.

To reproduce, use fresh paths and the existing dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/vadd.py build \
  --family integer146 --build-jobs 4 --compiler clang-20 \
  --output /tmp/task146-fresh \
  --link scripts/rvv/fixtures/rvvts-20261089/link.ld
# Transfer this corpus, shared scripts and external-flags.json to a fresh xbd root.
# Check load; <=4 workers, with process-local affinity/nice only.
taskset -c 28-31 nice -n 10 python3 vadd.py run --root /path/to/fresh-corpus \
  --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun \
  --spike /home/vick/rvv-directed-task145/deps/spike \
  --pk /home/vick/rvv-directed-task145/deps/pk \
  --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim \
  --flags external-flags.json --jobs 4
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/audit.py \
  /path/to/fresh-corpus /tmp/task146-audit-fresh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/reject.py \
  /path/to/fresh-corpus /tmp/task146-rejections-fresh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/test_vadd.py
```

The default `build` family remains `vadd145`; `--family integer146` selects this
additive manifest. `--units-file JSON` selects named finite units for a separately
labeled pilot; it retains full-family ordinals and records the selection.

Remaining finite gaps: other host widths/RV64, illegal encodings, exhaustive
interaction products, multi-instruction live-out/early-exit and per-target M1/M2
admission. This family does not complete all595 applicable forms. No production
change, external full rerun, generic Linux/scalar/atomic/LLVM work, performance,
publication, handler return, repair, retry or P4-04. Code commit is local; no push.
