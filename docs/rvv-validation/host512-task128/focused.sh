#!/bin/bash
cd /home/vick/rvdbt-host512-task128
ulimit -c 0
for target in rv32_host_copy_fault_test rv32_unit_memory_fault_test rv32_family_memory_fault_test rv32_special_memory_fault_test rv32_signal_frm_test rv32_signal_interface_test rv32_llvm_memory_admission_test rv32_memory_run_scanner_test rvv_llvm_wholereg_mem_test rvv_whole_reg_mem_route_test vle32v_typedchunk_route_test vse32v_typedchunk_route_test rvv_frame_finalizer_test; do
 timeout 120 nice -n 10 taskset -c 28 build/bin/$target > "$target.stdout" 2> "$target.stderr"
 rc=$?; echo "$rc" > "$target.rc"
 if [ "$rc" != 0 ]; then exit "$rc"; fi
done
mkdir -p linkage-fixture
cp -a /home/vick/rvdbt-production-task125/linkage-fixture/fs linkage-fixture/fs
mkdir linkage-fixture/cache
timeout 90 nice -n 10 taskset -c 28 build/bin/rv32_host_copy_linkage_test "$PWD/linkage-fixture/fs" "$PWD/linkage-fixture/cache" > rv32_host_copy_linkage_test.stdout 2> rv32_host_copy_linkage_test.stderr
rc=$?; echo "$rc" > rv32_host_copy_linkage_test.rc
exit "$rc"
