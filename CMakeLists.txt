cmake_minimum_required(VERSION 3.10)

project(rvdbt C CXX ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=gnu11")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=gnu++20")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}") # TODO: -fno-rtti
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c99-designator")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-invalid-offsetof")

option(DBT_ASAN "asan" OFF)
if(DBT_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
endif()

# RVV fixed-width lowering: the host chunk width in bits (128 = SSE2, 256 = AVX2, 512 = AVX-512).
# 128 is the default because it is the x86-64 baseline and is what the development host can
# execute. Building with 512 requires an AVX-512 host to RUN the result -- the binary will fault
# on a machine without it. See experiments/2026-08-17-rvv-scalable-fixed-local/docs/NLP_RUNBOOK.md.
set(RVV_HOST_CHUNK_BITS "128" CACHE STRING "RVV fixed-width host chunk width in bits (128/256/512)")
set_property(CACHE RVV_HOST_CHUNK_BITS PROPERTY STRINGS 128 256 512)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRVV_HOST_CHUNK_BITS=${RVV_HOST_CHUNK_BITS}")
# -mfma must be on the SAME translation units that evaluate the admission predicates, not only on
# the kernel TUs. fma_class_supported() in guest/rv32_vector_fast.h is compiled into
# guest/rv32_interp.cpp, and it returns false unconditionally when __FMA__ is undefined. The
# per-file COMPILE_OPTIONS below give -mfma to rv32_vector_run*.cpp (where the kernels live) but
# not to rv32_interp.cpp (where the gate lives), so the gate was testing the wrong TU's capability:
# try_fma refused every guest FMA and each one fell through to rvv_ref::vfma, which calls libm
# fma() per element. Measured effect of that fallback: rvv_ref::vfma 21-35% of cycles on
# linpack/pb_gemm/pb_syrk, with fma@plt and __fma_fma3 visible in the profile, and --rvv-fast
# buying those workloads nothing (1.00-1.008) while vfalu-dominated guests got 2.03-2.85x.
# Any host with AVX-512F or AVX2 has FMA3, so this widens no portability assumption.
if(RVV_HOST_CHUNK_BITS STREQUAL "512")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx512f -mavx512bw")
elseif(RVV_HOST_CHUNK_BITS STREQUAL "256")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx2")
endif()
# NOTE (P14 cycle 3, docs/P14_CYCLE3_FMA_GATE.md): fma_class_supported() in
# guest/rv32_vector_fast.h is `#ifndef __FMA__ return false`, and it is compiled into
# guest/rv32_interp.cpp, which gets NO -mfma at the default RVV_HOST_CHUNK_BITS=128 (neither
# branch above fires). Measured consequence: try_fma refuses 96-98% of guest vector FMAs on the
# FMA-dominated workloads and each one falls to rvv_ref::vfma, which calls libm fma() per element.
# Adding -mfma unconditionally here is NOT the fix -- it was tried and it makes the binary abort
# with SIGILL on an SSE2-only host. The gate is a HOST-CAPABILITY question and needs a runtime
# check plus the element kernel placed in an -mfma translation unit (guest/rv32_vector_run16fma.cpp
# already is one), not a compile-time flag on the interpreter TU.

# Guest FP emulation must round every guest operation individually. Compiler contraction of
# `a*b+c` into a single fused multiply-add would change the result of a two-instruction guest
# sequence, so it is switched off globally; an actual guest FMA reaches the host through an
# explicit std::fma / std::fmaf, which is unaffected.
option(RVDBT_FP_CONTRACT_OFF "forbid the compiler from fusing a*b+c (guest FP must round per operation)" ON)
if(RVDBT_FP_CONTRACT_OFF)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffp-contract=off")
endif()
# 0 = libc fenv (semantics reference), 1 = MXCSR intrinsics, 2 = MXCSR through volatile asm.
set(RVDBT_FROUND_IMPL "2" CACHE STRING "FRound implementation (0=libc fenv, 1=intrinsic, 2=asm)")
option(RVDBT_FROUND_DIAG_NOP "DIAGNOSTIC ONLY: make the FP rounding bracket a no-op to size its cost. Produces an INCORRECT binary; never ship or claim results from it." OFF)
if(RVDBT_FROUND_DIAG_NOP)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRVDBT_FROUND_DIAG_NOP=1")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRVDBT_FROUND_IMPL=${RVDBT_FROUND_IMPL}")

# P13: hardware FMA for the guest's fused multiply-add. Without it std::fma is a libm call with
# a full software implementation, and the census measured that as the dominant per-element cost
# of the FP class -- but it is a HOST CAPABILITY, not a free choice: on a machine without FMA3
# the software path is what correctness requires. Off by default so the build stays runnable on
# the development host (i7-3770, no FMA3); the evaluation host (Zen 5) sets it.
# Research instrumentation. A timing binary must carry NONE of it: the fast path's counters are
# one increment per host chunk and the control arm never pays them, so an instrumented binary
# cannot be used for an A/B against itself. Coverage and mechanism accounting use a separate
# build with these on.
option(RVDBT_FAST_STATS "collect RVV fast-path admission counters (OFF for timing binaries)" ON)
option(RVDBT_CENSUS "compile in the dynamic RVV census hook (OFF for timing binaries)" ON)
if(NOT RVDBT_FAST_STATS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRVDBT_FAST_STATS=0")
endif()
if(NOT RVDBT_CENSUS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRVDBT_CENSUS=0")
endif()

option(RVDBT_HOST_FMA "emit hardware FMA for guest fused multiply-add (requires an FMA3 host)" OFF)
if(RVDBT_HOST_FMA)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfma")
endif()
message(STATUS "RVV host chunk width: ${RVV_HOST_CHUNK_BITS} bits, host FMA: ${RVDBT_HOST_FMA}")

FIND_PACKAGE(Boost 1.71 COMPONENTS program_options REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

add_subdirectory(dbt)

file(GLOB_RECURSE CLANG_FORMAT_TARGETS dbt/*.h dbt/*.cpp)
list(FILTER CLANG_FORMAT_TARGETS EXCLUDE REGEX ".*third_party.*$")

add_custom_target(
    clang-format
    COMMAND /usr/bin/clang-format
    -i
    ${CLANG_FORMAT_TARGETS}
)
