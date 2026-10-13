# Task151 — merge/move execution and next integer family

Worked on existing `test/rvv-directed-forms-20261013`, preserving dirty files.
Accepted Task149/150 test/evidence work is saved in local scoped commit
`bb05b5a`; pycache and unrelated files were excluded. No push, production change,
149/150 guest rerun, unchanged framework-control rerun, or retained-cache sweep.
Main owns THESIS_STATUS; this report does not update its accepted-form count.

Merge/move is routed through shared `vadd.py` and `audit.py` as `mergemove151`.
vmerge treats v0 as selection data and compares every body lane; vmv permits
vector-source/destination v0. Ten synthetic checks passed before admission.
The fixed-reference pilot executed **900 cases / 4,500 checks / 180 commands**
in 36 units, with zero DUT/reference failures or blockers. Each pilot arm has
888 ordinary PASS and 12 reserved-start profile observations. Full offline replay
also passed and verified 18 Sail adapter units. Guest execution took 17.6345s.

The original pilot control utility failed: alternating bit0 is one, but its
polarity mutation assumed zero and produced an unchanged packet. Original
`controls.log`, stage status (controls1/summary1), and frozen scripts remain.
The corrected utility derives polarity from captured prestate and uses bit1
for spurious execution-mask mutations. **38/38 mutations rejected**, with no
new guests or changes to expected results. An additional **28/28 mutations**
reject prestart/no-body/undisturbed-tail and legal v0 move-data corruption.
See [preserved failure](docs/rvv-validation/directed-task151/FIRST_FAILURES.json).

The separately frozen full snapshot completed **38,214/38,214 cases,
191,070/191,070 checks and 7,920/7,920 commands**. Build/run/audit/controls/summary
all returned zero; 38/38 full actual-packet controls rejected. Complete replay
checked every packet, all 1,584 source/opcode units and 792 Sail adapters.
Each of Reference/B/M1/M2/BOTH has **36,654 ordinary PASS** and **1,560
PROFILE_RESERVED_START** outcomes. Six reserved encoding declarations remain
NOT_RUN and earn no PASS. No missing results, timeouts, reference blockers or
unresolved DUT failures. Full guest execution took 385.2055s; snapshot stages
ran 08:13:58–08:23:58 UTC. Audit remains single-process; this is not performance
or per-target M1/M2 admission evidence.

| Form | Cases per arm | Ordinary PASS | Reserved-start profile |
|---|---:|---:|---:|
| vmerge.vvm | 5,465 | 5,205 | 260 |
| vmerge.vxm | 5,729 | 5,469 | 260 |
| vmerge.vim | 9,425 | 9,165 | 260 |
| vmv.v.v | 4,633 | 4,373 | 260 |
| vmv.v.x | 4,633 | 4,373 | 260 |
| vmv.v.i | 8,329 | 8,069 | 260 |

DUT remains e2559c5c host512; fixed Spike/pk handles zero start and Sail0.14.1
handles nonzero start. Recorded DUT/library/reference identities match before
and after. Full frozen scripts/flags/link hashes pass before/after checks.
All 32 vector registers, 10 CSRs and scalar s0 receive pre/post predicates;
agnostic state uses permitted sets. No DUT-derived goldens.

Actual pilot/full commands, from each `xbd:/home/vick/rvv-directed-task151/`
batch directory:

```sh
nohup nice -n 10 bash launch.sh /home/vick/rvv-directed-task151/pilot > launcher.log 2>&1 < /dev/null &
nohup nice -n 10 bash launch.sh /home/vick/rvv-directed-task151/full > launcher.log 2>&1 < /dev/null &
# launch.sh exports PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1
python3 scripts/vadd.py build --family mergemove151 --output corpus --compiler clang-22 --build-jobs 8 --link ../user.ld
# pilot adds --units-file UNITS.json
python3 scripts/vadd.py run --root "$base/corpus" --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags ../FLAGS.json --jobs 12
python3 scripts/audit.py corpus audit
python3 scripts/reject_mergemove150_next.py corpus controls
python3 scripts/summarize148.py . evidence
# corrected/supplemental pilot controls only, no guest rerun:
PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 nice -n 10 python3 controls-fix-scripts/reject_mergemove150_next.py corpus controls-corrected
PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 nice -n 10 python3 controls-fix-scripts/reject_mergemove151_state.py corpus controls-state
```

See [command ledger](docs/rvv-validation/directed-task151/COMMANDS.json),
[launcher](docs/rvv-validation/directed-task151/launch.sh),
[full evidence](docs/rvv-validation/directed-task151/full-evidence/), and
[stage status](docs/rvv-validation/directed-task151/FULL_STAGE_STATUS.json).
Raw/source/compressed ELF records stay at xbd in `pilot` and `full`; compact
results were copied without archive packaging or exhaustive cache decompression.

Resource checks: xbd initial load0.39/1.15/3.18, available memory40,645,226,496B,
free disk25,055,301,632B; no active guest batch. Running checks found ample memory
and disk. Final load0.97/4.36/4.59, available memory40,660,443,136B, free
disk23,884,578,816B. No taskset; nice10, build8/run12, guest total <=12 throughout,
with >10GiB free disk. No global affinity or system changes.

While full tests ran, prepared the next independent integer comparison family:
**20 forms, 126,852 cases / 5,280 units**, including 121,652 ordinary and 5,200
reserved-start profile declarations; 20 reserved overlap declarations remain
unexecuted. Eight synthetic tests pass, including all 126,852 prestate extent
checks, signed/unsigned ordering, signed simm5 and RV32 scalar extension,
packed destination masks, legal masked v0 destination, overlap, preservation
and tail allowed sets. All **344 distinct target encodings** compile with
clang20 and match the encoder. These preparation checks earn zero guest credit.
The 120-unit pilot selector, finite manifest, source-reviewed predicates and
actual-packet corruption utility are ready under
[next-compare](docs/rvv-validation/directed-task151/next-compare/).
Next action: route `compare151_next.py` through the shared runner/auditor and
admit its independent fixed-reference pilot before full execution. No new
harness, Linux, LLVM implementation or performance work.

Task151 is a worker result pending main review; six new forms are ready for
acceptance, with no claim of complete RVV semantic coverage.
Completion signal: `tmux wait-for -S rvv-directed-mergemove-20261013-151`.
