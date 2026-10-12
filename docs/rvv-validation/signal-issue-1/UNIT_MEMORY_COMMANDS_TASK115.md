# Task115 ordinary unit-stride build/check receipt

Isolated xbd root: `/home/vick/rvdbt-unit-memory-faults-20261012-task115`.
Source/worktree: `/home/user/research/materials/rvdbt-unit-memory-faults-20261012`.
Task113 pinned third_party source was copied into the new source tree; independent
file hashes confirm equality. Other jobs were checked with uptime and
`ps -eo user,pid,pcpu,comm --sort=-pcpu`; load was 0.86/0.54/0.39.
No machine settings or other jobs were changed.

```sh
cmake -S "$root/source" -B "$root/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/clang-22 \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++-22 -DLLVM_PATH=/usr/lib/llvm-22 \
  -DRVV_HOST_CHUNK_BITS=128 -DRVDBT_FP_CONTRACT_OFF=ON \
  -DRVDBT_FROUND_IMPL=2 -DRVDBT_HOST_FMA=OFF \
  -DRVDBT_FAST_STATS=ON -DRVDBT_CENSUS=ON
nice -n 10 taskset -c 28,29 cmake --build "$root/build" --parallel 2 \
  --target elfrun rv32_unit_memory_fault_test rv32_signal_interface_test \
  mmu_mapping_metadata_test vle32v_typedchunk_llvm_test vse32v_typedchunk_llvm_test
```

From the isolated root, each of the five test executables above was run with
`LD_LIBRARY_PATH=build/lib nice -n 10 taskset -c 28 build/bin/<test>`, separately
retaining stdout, stderr and rc. Local unit checks are not external ISA coverage.
The original LLVM tests now check the exact permission-call conjunct and retain
all four original guard-state comparisons with no unknown predicate allowed.

`python3 normal_replay.py` executed retained Ara `vl.elf` and `vs.elf` in
B/M1/M2/BOTH, sequentially on core28, nice10, timeout120 per call, core dumps off.
The adapter preserves original argv flags, inputs, expected observations, sequence
checks and all original success/failure predicates. Only executable/library and
fs/cache/output paths change. `original_observations.py` contains the exact retained
parser function with its required `import re`. No reference or guest compilation
was performed. Exact per-call commands are in `normal_final/*/command.json`.
`python3 collect.py` checks final identities, dependency equality and actual route
counts. These adapters and all raw are retained in workspace `task115-evidence/`.

The first successful external round used an earlier guard version; it stays in
`normal_pass/` with separate identity/results. Final results use `normal_final/`.
No historical full-suite build ID or raw was reassigned. Failed transfers,
builds, local harness attempts and LLVM expectation failures are described in
SESSION0_RESULT_115.md and retained separately. P4-04/equivalent guest restart,
full suites and performance campaigns were not executed.
