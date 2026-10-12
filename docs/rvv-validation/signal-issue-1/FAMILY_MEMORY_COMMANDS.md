# Task117 bounded memory-family validation

New isolated xbd root: `/home/vick/rvdbt-memory-families-20261012-task117`.
Base `cfa37bb`, branch `fix/rvv-memory-families-issue-1`. No older build tree was
modified. Dependencies copied from Task115; all 443 dependency files hash-match.
Host initial load 0.24/0.17/0.24. Two build workers on cores28/29, nice10; tests
sequential on core28 with timeout120 and core dumps disabled for external replay.

```sh
root=/home/vick/rvdbt-memory-families-20261012-task117
cmake -S "$root/source" -B "$root/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/clang-22 \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++-22 -DLLVM_PATH=/usr/lib/llvm-22 \
  -DRVV_HOST_CHUNK_BITS=128 -DRVDBT_FP_CONTRACT_OFF=ON \
  -DRVDBT_FROUND_IMPL=2 -DRVDBT_HOST_FMA=OFF \
  -DRVDBT_FAST_STATS=ON -DRVDBT_CENSUS=ON
nice -n 10 taskset -c 28,29 cmake --build "$root/build" --parallel 2 \
  --target elfrun rv32_family_memory_fault_test rv32_unit_memory_fault_test \
  rv32_signal_interface_test rvv_llvm_vstrided_test rvv_vlse_gather_value_test
```

From that root, run the five tests sequentially with
`LD_LIBRARY_PATH=build/lib timeout 120 nice -n 10 taskset -c 28 build/bin/<name>`.
For the family test add `./abi-old.so ./abi-new.so`; their retained C sources are
compiled with `clang-22 -shared -fPIC <source> -o <so>`. The old/current host-only
fixtures exercise the production AOT ABI gate; no guest handler/retry is run.

`python3 normal_replay.py` replays original Ara vls/vss/vlsseg/vlseg/vsseg ELFs
in B/M1/M2/BOTH, preserving SELECTED.json commands except executable/fs/cache
paths. Original source, cases and observations function are retained; equality,
sequence, completed comparison and original PASSED/no-FAILED/no-ERROR predicates
are unchanged. Source VLENs are 512/1024/2048/256/256 respectively. This selection
excludes the original vssseg source with existing input/preflight qualifications;
no repair of external inputs or expected results is attempted here.

`python3 indexed_normal_replay.py` selects the existing CHIPS normal fixtures
vluxei32_v-1, vluxseg2ei32_v-1, vsuxei32_v-1, vsuxseg2ei32_v-1 at VLEN128,
B/M1/M2/BOTH. It uses retained campaign46 cell IDs, exact ELF hashes and original
commands, preserving return-code and exact `CHIPS_PASS\n` predicates. No guest
compilation, generator, reference or expected-answer construction occurs.

`python3 collect.py` checks final rc/results, binaries, complete build-source
snapshot and dependency equality. All commands, raw, earlier failures, observers,
fixtures and identities are in thesis artifact `task117-evidence/`; full source
archive and binaries remain in the new xbd root. The source snapshot predates
this final receipt documentation, with identical compiled dbt source.

These focused host checks are **local**, not external ISA fault conformance.
Normal external calls do not validate restart. P4-04/equivalent repair/return/
same-PC retry, whole suites and performance campaigns were not executed.
