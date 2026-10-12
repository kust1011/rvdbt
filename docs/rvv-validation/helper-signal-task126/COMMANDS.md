Task126 root: xbd:/home/vick/rvdbt-helper-signal-task126.
Copied Task125's isolated source/dependencies and overlaid the changed sources.
Source equality: all 289 tracked current dbt/CMake files match SOURCE_IDENTITY.json.
No changes to original fixture/oracle/checker bytes. Initial load 0.23/0.32/0.57;
final load 0.34/0.42/0.54. All build/test processes nice10 and pinned as below.

```sh
timeout 180 nice -n 10 taskset -c 28-31 cmake -S source -B build \
  -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-22/lib/cmake/llvm \
  -DRVV_HOST_CHUNK_BITS=128
timeout 900 nice -n 10 taskset -c 28-31 cmake --build build \
  --target elfrun dbtjitshared rv32_signal_interface_test rv32_signal_frm_test \
  rv32_host_copy_fault_test -j4
# Initial build rc2: stale FRM sizeof assertion (42688 vs current 42704).
# Corrected assertion; unchanged assertions for FRM, badframes and state restore.
timeout 300 nice -n 10 taskset -c 28-31 cmake --build build \
  --target rv32_signal_interface_test rv32_signal_frm_test rv32_host_copy_fault_test -j4
timeout 180 nice -n 10 taskset -c 28-31 cmake --build build --target elfrun dbtjitshared -j4
ulimit -c 0
for t in rv32_signal_interface_test rv32_signal_frm_test rv32_host_copy_fault_test; do
  LD_LIBRARY_PATH=build/lib timeout 60 nice -n 10 taskset -c 28 build/bin/$t
done
timeout 300 nice -n 10 taskset -c 28 python3 helper/run.py
```

Replay script is scripts/replay_helper_signal_task126.py, copied from the retained
Task113 adapter with only its candidate scope description updated. `helper/build`
and `helper/source` point to this isolated build/source. Original two fixture
ELFs, checkers, reference stdout, commands, specs and memory gates were copied
from Task113's helper directory. Exact eight argv/environment/result records
and raw comparisons are in the immutable raw archive; all retain the original
30-second bound, B/M1/M2/BOTH flags, VLEN1024, checker and byte-equality predicate.
No guest compiler/generator/reference call, handler return or repair/retry.

Initial build failure and passing interface attempt1 remain in raw. The final
host-copy test's two forked unrelated host faults intentionally abort and are
checked as fatal SIGABRT, not treated as recovered failures. Compiler warnings,
all stderr (including these expected Panic traces), raw snapshots and streams
are retained. No failed guest observation was edited or rescheduled.
