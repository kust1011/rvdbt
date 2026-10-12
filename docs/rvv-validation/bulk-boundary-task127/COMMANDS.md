Root: xbd:/home/vick/rvdbt-bulk-boundary-task127. Fresh source copied from Task126;
only five code/test files overlaid. Fresh build, retained vendored dependencies.

```sh
timeout 180 nice -n 10 taskset -c 28-31 cmake -S source -B build \
  -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-22/lib/cmake/llvm \
  -DRVV_HOST_CHUNK_BITS=128
timeout 900 nice -n 10 taskset -c 28-31 cmake --build build \
  --target elfrun dbtjitshared rv32_host_copy_fault_test \
  rv32_unit_memory_fault_test rv32_special_memory_fault_test -j4
# Initial aggregate rc2 at test type qualifier; production targets already built.
timeout 300 nice -n 10 taskset -c 28-31 cmake --build build \
  --target rv32_host_copy_fault_test rv32_unit_memory_fault_test \
  rv32_special_memory_fault_test -j4
ulimit -c 0
for t in rv32_host_copy_fault_test rv32_unit_memory_fault_test rv32_special_memory_fault_test; do
  LD_LIBRARY_PATH=build/lib timeout 60 nice -n 10 taskset -c 28 build/bin/$t
done
timeout 660 nice -n 10 taskset -c 28 python3 replay.py "$PWD"
# Final test-only R8/direction filter and successful wrap refinement:
timeout 180 nice -n 10 taskset -c 28-31 cmake --build build \
  --target rv32_host_copy_fault_test -j4
LD_LIBRARY_PATH=build/lib timeout 60 nice -n 10 taskset -c 28 \
  build/bin/rv32_host_copy_fault_test
objdump -drC build/dbt/CMakeFiles/dbtstatic.dir/rvv_host_copy.cpp.o
objdump -drC build/dbt/CMakeFiles/dbtstatic.dir/rvv_host_copy.S.o
ldd -r build/bin/elfrun
# Final review added the affected mask family; only its one call was run:
timeout 330 nice -n 10 taskset -c 28 python3 mask-replay.py "$PWD"
```

Each invocation's separate stdout/stderr/rc is in receipts.tar.gz. replay.py is
scripts/replay_bulk_boundary_task127.py, importing the unchanged retained ACT
adapter. Exact three external argv, original queue records, hashes and original
acceptance predicates are retained in external/ and external-mask/. No reference run.
