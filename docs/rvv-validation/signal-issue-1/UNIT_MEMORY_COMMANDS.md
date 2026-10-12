# Task116 formatter correction: final build and checks

Base `b0280831532748d4f76772c0585c2291a7199bf1`, branch
`fix/rvv-unit-memory-faults-issue-1`, worktree
`/home/user/research/materials/rvdbt-unit-memory-faults-20261012`.
Task115 commands/results remain byte-for-byte in `UNIT_MEMORY_COMMANDS_TASK115.md`
and `UNIT_MEMORY_RESULTS_TASK115.json`; its raw remains `task115-evidence/`.

The existing configured build root was reused on xbd:
`/home/vick/rvdbt-unit-memory-faults-20261012-task115`.
New logs, adapters, identities and raw are separately retained at
`/home/vick/rvdbt-unit-memory-faults-20261012-task116` and local
`task116-evidence/`. Only `source/dbt/ukernel.cpp` and
`source/dbt/rv32_unit_memory_fault_test.cpp` changed from the old source manifest;
all pinned dependencies remained identical. All 281 locally available build-source
files hash-match the final remote source. No old result is assigned to this build.

Checked `ssh xbd 'uptime; ps -eo user,pid,pcpu,comm --sort=-pcpu | head -12'`:
load 0.05/0.21/0.33, no competing CPU-heavy build observed. No host settings changed.

First build the new regression with the old formatter, then execute it:

```sh
root=/home/vick/rvdbt-unit-memory-faults-20261012-task115
receipt=/home/vick/rvdbt-unit-memory-faults-20261012-task116
nice -n 10 taskset -c 28,29 cmake --build "$root/build" --parallel 2 \
  --target rv32_unit_memory_fault_test > "$receipt/build-before-fix.log" 2>&1
cd "$root"
LD_LIBRARY_PATH=build/lib nice -n 10 taskset -c 28 \
  build/bin/rv32_unit_memory_fault_test \
  > "$receipt/before-fix.stdout" 2> "$receipt/before-fix.stderr"
```

Expected observed negative control: rc2,
`UNIT_MEMORY_FAIL formatter structured access direction`.
After correcting the formatter, the final build command was:

```sh
nice -n 10 taskset -c 28,29 cmake --build "$root/build" --parallel 2 \
  --target elfrun rv32_unit_memory_fault_test rv32_signal_interface_test \
  mmu_mapping_metadata_test vle32v_typedchunk_llvm_test vse32v_typedchunk_llvm_test \
  > "$receipt/build-final.log" 2>&1
cd "$receipt"
python3 run_focused.py > focused.stdout 2> focused.stderr
python3 normal_replay.py > normal.stdout 2> normal.stderr
python3 collect.py > collect.stdout 2> collect.stderr
```

`run_focused.py` runs the five tests sequentially, each with
`LD_LIBRARY_PATH=$root/build/lib nice -n 10 taskset -c 28 $root/build/bin/<test>`,
120-second timeout, retaining stdout/stderr/rc and exact argv in
`FOCUSED_RESULTS.json`. It also independently parses both emitted formatter
records using Python JSON; actual records are in `FORMATTER_RECORDS.json`.
The C++ regression invokes the production formatter on real captured load/store
faults, parses its JSON, and checks direction, schema, fault geometry, CSR state,
array shape and all serialized GPR/FPR/vector values. Existing checks remain intact.

`normal_replay.py` is the Task115 adapter with only its task comment changed;
its output root derives from the script directory. It uses the same final build
root and original fixture paths. Eight calls: Ara `vl` and `vs`, each B/M1/M2/BOTH,
sequential nice10/core28, timeout120, no core dumps. Original argv flags, retained
ELFs/source, observer and all success/failure predicates are preserved. Exact
original and launch argv are in `normal_final/<case>_<arm>/command.json`.
The final source/binaries/fixtures hash identically before and after those calls.
No reference run or guest compilation took place.

`collect.py` asserts five zero return codes, all eight original PASS results,
actual route counters, before/after identity equality, and exactly two source
changes against Task115. `SOURCE_IDENTITY.json` and `BUILD_IDENTITY.json` contain
final hashes; `UNIT_MEMORY_RESULTS.json` records actual final identities.
The static-linked elfrun changed; the shared library hash stayed identical.
The final source archive includes the pinned dependencies and configured source.

A first correction build (`build-attempt1.log`) had an added format argument
without the matching placeholder; diff inspection caught it before any test or
external call. The corrected build and all results above are separate from it.
No guest restart, full suite, performance, push, merge, issue closure, quota
change or completion signal was performed. The launcher owns completion.
