#!/bin/bash
cd /home/vick/rvdbt-host512-task128
ulimit -c 0
tar -xzf overlay.tar.gz -C source
lscpu > cpu.txt
uptime > load.initial.txt
clang++-22 --version > compiler.txt
timeout 180 nice -n 10 taskset -c 28-31 cmake -S source -B build -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-22/lib/cmake/llvm -DRVV_HOST_CHUNK_BITS=512 > configure.stdout 2> configure.stderr
rc=$?; echo $rc > configure.rc
if [ "$rc" != 0 ]; then exit "$rc"; fi
timeout 900 nice -n 10 taskset -c 28-31 cmake --build build --target elfrun dbtjitshared rv32_host_copy_fault_test rv32_host_copy_linkage_test rv32_unit_memory_fault_test rv32_family_memory_fault_test rv32_special_memory_fault_test rv32_signal_frm_test rv32_signal_interface_test rv32_llvm_memory_admission_test rv32_memory_run_scanner_test rvv_llvm_wholereg_mem_test rvv_whole_reg_mem_route_test vle32v_typedchunk_route_test vse32v_typedchunk_route_test rvv_frame_finalizer_test -j4 > build.stdout 2> build.stderr
rc=$?; echo $rc > build.rc
exit "$rc"
