# Directed vector configuration forms — Task147

Project-authored **vsetvli, vsetivli and vsetvl** tests reuse the existing
builder, bounded runner, binary packet, whole-register observation, fixed
independent Spike/Sail references and complete offline auditor. New predicates
live in `scripts/rvv/directed/config.py`; `--family configuration147` selects
this finite manifest. [Oracle review](REVIEW.md) explains legal VL sets,
determinism, x0 special forms, unsupported vtype, and observer boundaries.

The [declaration](DECLARATION.json) and [manifest](MANIFEST.json.gz) precede formal
execution:48,630 cases, 792 units, 3,960 commands and 243,150 packet checks.
Every form covers six VLENs 128–4096, all 22 legal ELEN64 SEW/LMUL pairs and all
four tu/ta × mu/ma policies. vsetivli immediate0/1/15/16/30/31 and applicable
VLMAX edges are included; AVL>31 and full VL when VLMAX>31 are not encodable in
this form and are ISA-based N/A, not missing tests. Other forms include unsigned
XLEN32 maximum, both VLMAX stripmining regions, x0 forms, rd/rs1 overlap,
all legal equal-ratio preserve transitions, ordinary nonzero start and vill
recovery. vsetvl additionally tests rd/rs2 and rs1/rs2 overlap, x0 vtype source,
unsupported field values and each vtype upper bit8..31.

| Form | Planned/executed per arm | Legal/profile PASS | Reserved start profile | Reserved transition observed | Failures |
|---|---:|---:|---:|---:|---:|
| vsetvli | 12,896 | 11,864 | 504 | 528 | 0 |
| vsetivli | 6,464 | 5,960 | 504 | 0 | 0 |
| vsetvl | 29,270 | 28,238 | 504 | 528 | 0 |
| **Total** | **48,630** | **46,062** | **1,512** | **1,056** | **0** |

Counts above apply independently to Reference/B/M1/M2/Both. `PASS` here includes
supported configurations and fixed-profile unsupported-vtype rejection;1512
reserved-vstart-profile cases earn separate `PROFILE_PASS`, and 1056 reserved
ratio-changing x0/x0 transitions earn `OBSERVED_RESERVED` only. Raw runner
`PASS` labels mean the declared predicates succeeded; they do not turn reserved
observations into universal ISA obligations. [Per-form results](PER_FORM_RESULTS.json)
and the complete [observed receipts](OBSERVED_CHECKS.csv.gz) retain these classes.

All 243,150 declared checks pass, with zero failures/missing/reference blockers.
The complete offline reapplication verifies every packet, target opcode and 396
Sail adapters. Determinism: 155,650 equal-input comparisons, zero failures.
All 293 formal corruption controls are rejected;12 permitted VL endpoint controls
are accepted. [Allowed-choice evidence](VL_CHOICE_EVIDENCE.json) retains 1168
permitted Sail/DUT VL differences per DUT arm. There are 53 complete source/state
examples. Correctness execution took 750.2403s with four workers; aggregate
command elapsed time is recorded in AUDIT.json. Development/compilation timing
was not separately instrumented. New worker delivery awaits main review.

The checker observes actual rd and vl/vtype/vlenb/vstart, all six other vector/FP
CSRs and all 32 vector registers. Post-target CSR/rd stores occur before the
observer resets start and restores legal e8/m1 for the whole-register dump;
no vector instruction executes under vill before these captures. Input vector
bytes are observed before pre-vill setup; only scalar/configuration instructions
separate that snapshot from the target. Independent packets are checked against
ISA/profile constraints, then DUT invariants are compared with them. In the
nonunique middle AVL interval each packet must obey the allowed set and its
implementation's deterministic choice. Sail's supported `vl_use_ceil=true`
exercises a permitted result different from the fixed DUT/Spike choice.

[Complete audit](AUDIT.json), [determinism](DETERMINISM.json),
[formal corruption controls](REJECTIONS.json), [identities](IDENTITIES.json),
[guest pins](GUEST_PINS.json.gz), [build commands](BUILD_COMMANDS.json.gz),
[Sail adapter verification](ADAPTER_VERIFICATION.json.gz),
[source pins](SOURCE_PINS.json), [source/state examples](ORACLE_EXAMPLES.json.gz),
[original failure classification](FIRST_FAILURES.json), and
[commands](COMMANDS.json) support review. [Prelaunch observations](PRELAUNCH.md)
retain the pilot harness corrections and classification amendment. The pilot
729 cases/3645 packet checks earn no formal credit. [Legacy compatibility](LEGACY_COMPATIBILITY.json)
confirms identical145/146 manifests and 36 selected source batches from each;
old raw audits and executions were not repeated.

Raw locations:

* Remote:`xbd:/home/vick/rvv-directed-task147/` (formal `corpus/`, separate `pilot/`).
* Local:`/home/user/research/materials/task147-directed-raw-20261013/task147/`.
* Archive:`xbd:/home/vick/task147-directed-final-v2-raw.tar.gz`.
* [Transport authentication](TRANSPORT.json) checks every packaged payload.

Every unit retains source/ELF/build stderr; each arm retains exact command,
exit/timeout/time, stdout/stderr, extracted packets, checks/errors and DUT tbmap.
Sail adds signature and supported per-invocation config. Original controls and
prelaunch reports remain separate. Packaging excludes only disposable work
filesystem/cache copies and initial build-transfer archives, not original raw.
No old145/146 corpus is packaged. The existing pinned reference executables are
external dependencies whose hashes are checked before/after the formal run.

Reproduce in fresh paths with the pinned dependencies and a load/disk check:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/vadd.py build \
  --family configuration147 --build-jobs 4 --compiler clang-20 \
  --output /tmp/task147-fresh \
  --link scripts/rvv/fixtures/rvvts-20261089/link.ld
# Transfer corpus plus vadd.py/config.py/audit.py/reject_config.py and FLAGS.json
# to a fresh xbd root, keeping at most four correctness workers.
taskset -c 28-31 nice -n 10 python3 vadd.py run --root /path/to/fresh-corpus \
  --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun \
  --spike /home/vick/rvv-directed-task145/deps/spike \
  --pk /home/vick/rvv-directed-task145/deps/pk \
  --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim \
  --flags FLAGS.json --jobs 4
PYTHONDONTWRITEBYTECODE=1 python3 audit.py /path/to/fresh-corpus /tmp/task147-audit
PYTHONDONTWRITEBYTECODE=1 python3 reject_config.py /path/to/fresh-corpus /tmp/task147-controls
```

[Exact method flags](FLAGS.json) match the inherited B/M1/M2/Both configuration;
the runner substitutes each manifest VLEN. Method switches and aggregate stats
are not per-target M1/M2 path-admission proof. Host512/RV32 is the executed
profile. Other host widths/RV64, illegal opcode/trap paths, exhaustive interaction
products and multi-instruction method admission remain finite gaps. No
production change, external full rerun, performance/publication, generic Linux,
scalar/atomic/LLVM work, handler return, repair/retry/P4-04 or equivalent. This
family advances directed forms to19/595; it does not complete the whole plan.
Launcher owns the unique completion signal.
