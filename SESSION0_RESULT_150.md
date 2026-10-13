# Task150 — carry/borrow and next independent family

Working on existing `test/rvv-directed-forms-20261013`, preserving inherited
dirty files. Production and the fixed e2559c5c host512 DUT are unchanged.
No Linux, LLVM or performance expansion.

Task149 completion is separate in [SESSION0_RESULT_149.md](SESSION0_RESULT_149.md):
98,416 cases/492,080 checks from existing raw records; retained compressed ELF
alias repair is explicitly reported. No guests rerun and no main acceptance claimed.

Carry150 routes the prepared `carry149_next.py` through the existing build,
capture, independent reference, checker and full replay. The declaration has
15 forms, 116,559 cases and 3,960 units. Of these, 3,900 cases are inherited
reserved-start accepting-profile observations, separate from ordinary cases.
Thirty reserved encoding declarations remain unexecuted and earn no PASS credit.
The 2,796-case/90-unit pilot passed: 13,980/13,980 checks, 450/450 commands,
complete replay and 205/205 carry-specific mutations rejected; all stages zero.
Pilot execution took 56.2283s with 12 workers (not a performance measurement).
The separate full snapshot completed **116,559/116,559 cases,
582,795/582,795 packet checks and 19,800/19,800 commands**, with no missing result,
reference blocker, timeout or recorded DUT failure. Complete offline replay verifies
every packet plus all 3,960 source/opcode units and 1,980 Sail adapters.
**205/205 actual-packet carry controls reject**. Build/run/audit/controls/summary
all return zero; frozen scripts and DUT/reference identities remain unchanged.
Each arm has **112,659 ordinary PASS** and **3,900 PROFILE_RESERVED_START**
outcomes, kept separate. Execution took 1,101.7273s with 12 workers.
Twelve prepared synthetic carry checks pass separately and earn no guest credit.

New snapshots specify `--build-jobs 8`, `--jobs 12`, `nice -n 10`, and no taskset.
xbd SSH and the full runner inherit CPUs 0–31. Before launch: load 0.54/0.47/0.73,
37 GiB available memory, 28,125,659,136 bytes available disk; no active competing
guest batch. Launch and running checks found no resource pressure requiring a
reduction. Storage keeps >=10 GiB reserve and lossless compression. Total guest
workers are bounded at 12. Final disk availability is 25,057,427,456 bytes.
No global affinity/system setting was changed; old snapshots/batches are unchanged.

Actual commands, raw/source/ELF records and replay are retained under
`xbd:/home/vick/rvv-directed-task150/{pilot,full}/`;
[command ledger](docs/rvv-validation/directed-task150/COMMANDS.json) and
[launcher](docs/rvv-validation/directed-task150/launch.sh) reproduce the stages.
Fixed Spike/pk handles
zero start and fixed Sail0.14.1 handles nonzero start; every packet also receives
full vector-register/CSR/scalar predicate checks. Carry-specific controls mutate
actual packets; unchanged framework controls are not repeated.

Next-family preparation proceeded while full carry built and executed:
`mergemove150_next.py` declares six independent merge/move forms with
38,214 cases/1,584 units; 1,560 reserved-start profile cases are separately
declared. Ten synthetic tests pass, including source/destination v0 move cases,
RV32-to-SEW64 sign extension, all-body merge checking and overlap/no-body/tail
preservation. Guest executions are zero, all cases remain NOT_RUN, and runner
routing plus fixed-reference pilot admission are the next step.
All 38,214 prepared prestates pass exact vector-file extent checks. A 36-unit/900-case
pilot selector and actual-packet mutation utility are prepared; the utility
has no rejection credit until that independent pilot supplies packets.
[Declaration and reviewed predicates](docs/rvv-validation/directed-task150/next-mergemove/)
are retained; no packaging dependency delayed development.

New retained ELF aliases are healthy: 360 pilot and 15,840 full paths resolve to
the expected permanent compressed guests, with zero dangling paths or repairs.
Logical ELF identity is also verified through one alias in each batch. Checks add
zero guest executions.

[Final per-form evidence](docs/rvv-validation/directed-task150/FULL_PER_FORM_RESULTS.json),
[complete replay](docs/rvv-validation/directed-task150/FULL_AUDIT.json),
[controls](docs/rvv-validation/directed-task150/FULL_CONTROLS.json) and
[first failures](docs/rvv-validation/directed-task150/FIRST_FAILURES.json) are retained.
Two patch context rejections and a wrong-directory read-only freeze check were
corrected without changing guest records; no unresolved test/reference/DUT error.
The unchanged shared framework controls were reused, not repeated. This remains
a **worker result, not main acceptance** or per-target M1/M2 admission.
Next action: wire merge/move into the shared runner and run its independent pilot.
Completion command: `tmux wait-for -S rvv-directed-carry-20261013-150`.
