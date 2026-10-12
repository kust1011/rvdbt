# Task113 build and replay commands

Run on xbd in the isolated `/home/vick/rvdbt-signal-integration-20261012-task113`
directory. The source matches the Task113 workspace's retained source manifest,
including pinned asmjit and ELFIO submodules. Build flags are also in the result
JSON. No other user's jobs or machine settings were changed.

```sh
cmake -S "$root/source" -B "$root/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/clang-22 \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++-22 -DLLVM_PATH=/usr/lib/llvm-22 \
  -DRVV_HOST_CHUNK_BITS=128 -DRVDBT_FP_CONTRACT_OFF=ON \
  -DRVDBT_FROUND_IMPL=2 -DRVDBT_HOST_FMA=OFF \
  -DRVDBT_FAST_STATS=ON -DRVDBT_CENSUS=ON
nice -n 10 taskset -c 28,29 cmake --build "$root/build" \
  --target elfrun rv32_signal_frm_test rv32_signal_interface_test \
  mmu_mapping_metadata_test --parallel 2
LD_LIBRARY_PATH="$root/build/lib" nice -n 10 taskset -c 28 \
  "$root/build/bin/rv32_signal_interface_test"
LD_LIBRARY_PATH="$root/build/lib" nice -n 10 taskset -c 28 \
  "$root/build/bin/rv32_signal_frm_test"
LD_LIBRARY_PATH="$root/build/lib" nice -n 10 taskset -c 28 \
  "$root/build/bin/mmu_mapping_metadata_test"
python3 "$root/replay.py"
nice -n 10 taskset -c 28 python3 "$root/helper/run.py"
python3 "$root/admission_audit.py"
```

`root` above abbreviates the exact isolated directory. The retained replay
adapters are in the implementing workspace's `task113-evidence/` directory,
alongside their original versions, exact per-call argv/environment JSON, original
fixtures/oracles, raw results, failed builds and both execution rounds. They use
read-only P4 provenance on xbd; they are Task113 replay adapters, not a new public
standalone test package. The normal replay preserves all checker predicates and
flags and substitutes only executable/library/output/provenance locations. The
helper replay uses existing exit-only ELFs, checkers and retained reference
bytes; it does not compile or execute a returning fault handler.

Final interface results: 376/376 focused checks, 27/27 MMU checks, 256 FRM
roundtrips and 192 high-bit badframes. Final guest results: 12/12 normal and 8/8
exit-only helper configurations. The first implementation's passing runs are
retained separately under `pass1`; they are not substituted for the final build.
