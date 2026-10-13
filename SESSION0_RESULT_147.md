# Task147 — directed vector configuration forms

Worker delivery for main review, on **test/rvv-directed-forms-20261013** after
**2a9b36f**. Implements and executes **vsetvli, vsetivli, vsetvl** using the
existing generator/runner/packet/whole-register capture/independent-reference
infrastructure. No production change or push. Task145/146 raw, executions and
ongoing main audits are untouched; neither old family is rerun or repackaged.
Pre-existing untracked Python caches remain outside the commit.

**48,630/48,630 planned cases executed** on Reference and fixed host512
**B/M1/M2/Both**: **243,150/243,150 declared predicate checks**, **3,960/3,960
commands**, no packet failure, reference blocker, timeout or missing result.
Reserved observations have separate semantic counts; raw runner PASS is not a
claim of universally required behavior for reserved encodings/states.

| Form | Planned = executed per arm | Legal/profile PASS | Reserved vstart profile | Reserved transition observed | Failures |
|---|---:|---:|---:|---:|---:|
| vsetvli | 12,896 | 11,864 | 504 | 528 | 0 |
| vsetivli | 6,464 | 5,960 | 504 | 0 | 0 |
| vsetvl | 29,270 | 28,238 | 504 | 528 | 0 |
| **Total** | **48,630** | **46,062** | **1,512** | **1,056** | **0** |

The PASS column includes 30,750 supported configuration cases and 15,312
fixed-profile unsupported-vtype cases; the latter all belong to vsetvl and
check vill/VL/rd/start effects. Reserved ratio-changing x0/x0 transitions earn
only OBSERVED_RESERVED, with their actual target CSRs retained. Reserved
vstart>=old VLMAX cases earn PROFILE_PASS under the fixed accepting profile,
not universal acceptance credit. Each row applies independently to all five arms.

Complete offline reapplication confirms all 243,150 packet checks, every target
opcode and 396 Sail adapters. Determinism passes155,650 equal-input comparisons.
**293/293 independently corrupted formal controls rejected**, **12/12 permitted
VL endpoint controls accepted**;53 complete source/state examples retained.
Sail and DUT choose different legal VL values in1168 cases per DUT arm, accepted
by the declared set constraints, with actual rd matching each implementation's
VL. These differences are recorded rather than changed into exact-reference
failures. The auditor reuses the reviewed checker; it is not another independent
ISA implementation.

All three forms cover **six VLENs 128/256/512/1024/2048/4096**, all **22 legal
ELEN64 SEW/LMUL pairs**, and **four policies**. AVL0/1/VLMAX edges, both larger
AVL regions, XLEN32 maximum, immediate bounds0..31, x0 forms, legal equal-ratio
preserve-VL transitions, rd/rs1 overlap, vsetvl register-vtype/other overlaps,
every upper vtype input bit8..31, unsupported fields, pre-existing vill recovery,
and initialized nonzero vstart are included. Immediate AVL>31 and full VL when
VLMAX>31 are not encodable for vsetivli and are explicit ISA-based N/A.

Pinned RVV 1.0 and independent Spike/Sail implementations were read before
predicates. No DUT-derived expected answers. Spike 20feb9c2/pk executes the same
ELF as DUT for zero starts; fixed Sail 0.14.1/e4b243f executes shared entry/exit-only
adapted bodies for nonzero starts, with supported per-invocation vl_use_ceil=true.
Legal allowed VL intervals, deterministic equal-input constraints and rd==VL
are checked. The independent comparison never forces the DUT to adopt another
implementation's permitted middle-interval choice.

Actual **rd, vl/vtype/vlenb/vstart**, all **six other vector/FP CSRs** and all
**32 vector registers** are captured/checked. Target CSR/rd capture precedes
clearing start and restoring legal e8/m1 for whole-register output observation;
no vector instruction executes under vill before target capture. Input vectors
are dumped before pre-vill setup; output bytes follow the documented observer
boundary. [Review](docs/rvv-validation/directed-task147/REVIEW.md) gives precise
predicates, reserved scope and observation limits; the auditor verifies each
exact target configuration opcode, not setup as target-form credit.

Correctness execution: **750.2403 seconds**, **four bounded workers**, cores28–31,
nice10, after xbd load and disk checks. No global setting change. Compilation/
development time was not separately instrumented. No confirmed DUT failure,
so no original-failure minimization/common-source diagnosis or production repair
was needed. Original pilot harness findings and prelaunch classification correction
are retained in [PRELAUNCH](docs/rvv-validation/directed-task147/PRELAUNCH.md);
no expected VL set was changed to accommodate DUT output.

[Delivery and reproduction](docs/rvv-validation/directed-task147/README.md) links
finite declaration/manifest, per-form results, every observed receipt, guest/source
pins, build commands, exact method flags, complete audit, adapter verification,
controls, examples, identities and authenticated transport.

* Remote formal raw: **xbd:/home/vick/rvv-directed-task147/corpus/**.
* Local raw: **/home/user/research/materials/task147-directed-raw-20261013/task147/**.
* Archive: **xbd:/home/vick/task147-directed-final-v2-raw.tar.gz**.

Reproduce with fresh destinations and the existing pinned dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/vadd.py build \
  --family configuration147 --build-jobs 4 --compiler clang-20 \
  --output /tmp/task147-fresh \
  --link scripts/rvv/fixtures/rvvts-20261089/link.ld
# Transfer corpus, shared scripts and FLAGS.json to a fresh xbd root; check load/disk.
taskset -c 28-31 nice -n 10 python3 vadd.py run --root /path/to/fresh-corpus \
  --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun \
  --spike /home/vick/rvv-directed-task145/deps/spike \
  --pk /home/vick/rvv-directed-task145/deps/pk \
  --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim \
  --flags FLAGS.json --jobs 4
python3 audit.py /path/to/fresh-corpus /tmp/task147-audit
python3 reject_config.py /path/to/fresh-corpus /tmp/task147-controls
```

DUT exact **e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b**;
library and both references have the inherited fixed hashes, checked before/after.
Default145/146 manifests and 36 selected generated sources from each are identical
against2a9b36f; no old raw audit rerun. The 729-case/3645-check pilot is separate
and earns no formal credit. Legacy 12 synthetic checks pass.

Progress: **3/3 requested forms**, **19/595 directed forms overall** (worker
results pending main review), **48,630/48,630 family cases**, **0 unresolved DUT
failures**, **0 required family blocked/unexecuted obligations**. Remaining576
forms, other host widths/RV64, illegal-opcode trap paths, exhaustive products and
per-target M1/M2 admission remain outside this finite family. No production,
full external rerun, generic Linux/scalar/atomic/LLVM, performance/publication,
handler return/repair/retry/P4-04 equivalents. Launcher owns the unique completion
signal. Next step: main reviews Task147 checker and complete raw evidence.
