cmake_minimum_required(VERSION 3.13)

project(rvdbt C CXX ASM)

include(CTest)
set(RVDBT_BUILD_PROFILE "custom" CACHE STRING "Build policy: custom, performance, diagnostic")
set_property(CACHE RVDBT_BUILD_PROFILE PROPERTY STRINGS custom performance diagnostic)
if(NOT RVDBT_BUILD_PROFILE MATCHES "^(custom|performance|diagnostic)$")
    message(FATAL_ERROR "Unknown RVDBT_BUILD_PROFILE=${RVDBT_BUILD_PROFILE}")
endif()

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
# These flags apply to the whole binary, which requires a matching host to execute.
set(RVV_HOST_CHUNK_BITS "128" CACHE STRING "RVV fixed-width host chunk width in bits (128/256/512)")
set_property(CACHE RVV_HOST_CHUNK_BITS PROPERTY STRINGS 128 256 512)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRVV_HOST_CHUNK_BITS=${RVV_HOST_CHUNK_BITS}")
# FMA is selected independently below, not inferred from vector width.
if(RVV_HOST_CHUNK_BITS STREQUAL "512")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx512f -mavx512bw")
elseif(RVV_HOST_CHUNK_BITS STREQUAL "256")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx2")
endif()

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

# Research instrumentation can add path-dependent updates that a control arm does not pay.
# Timing policy disables these counters; retained instrumented cohorts describe their own
# configuration, not the counter-free profile. Coverage uses a separate diagnostic build.
option(RVDBT_FAST_STATS "collect RVV fast-path admission counters (OFF for timing binaries)" OFF)
option(RVDBT_CENSUS "compile in the dynamic RVV census hook (OFF for timing binaries)" OFF)
option(RVDBT_RA_STATS "collect translation-time RA spill/fill counters" OFF)
foreach(_counter RVDBT_FAST_STATS RVDBT_CENSUS RVDBT_RA_STATS)
    if(RVDBT_BUILD_PROFILE STREQUAL "performance" AND ${_counter})
        message(FATAL_ERROR "performance profile requires ${_counter}=OFF")
    endif()
    add_compile_definitions(${_counter}=$<BOOL:${${_counter}}>)
endforeach()
if(RVDBT_BUILD_PROFILE STREQUAL "performance")
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Release" OR DBT_ASAN OR
       RVDBT_FROUND_DIAG_NOP OR NOT RVDBT_FP_CONTRACT_OFF OR
       NOT RVDBT_FROUND_IMPL STREQUAL "2")
        message(FATAL_ERROR "performance requires Release, FP_CONTRACT_OFF, FROUND_IMPL=2, no ASAN or rounding oracle")
    endif()
endif()

option(RVDBT_HOST_FMA "emit hardware FMA for guest fused multiply-add (requires an FMA3 host)" OFF)
if(RVDBT_HOST_FMA)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfma")
endif()
message(STATUS "RVV host chunk width: ${RVV_HOST_CHUNK_BITS} bits, host FMA: ${RVDBT_HOST_FMA}")

FIND_PACKAGE(Boost 1.71 COMPONENTS program_options REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

add_subdirectory(dbt)

# Keep the resolved policy beside the cache and actual compiler commands for provenance.
set(_profile_summary "profile=${RVDBT_BUILD_PROFILE}\nbuild_type=${CMAKE_BUILD_TYPE}\n")
foreach(_option RVV_HOST_CHUNK_BITS RVDBT_HOST_FMA RVDBT_FAST_STATS RVDBT_CENSUS
        RVDBT_RA_STATS RVDBT_FP_CONTRACT_OFF RVDBT_FROUND_IMPL RVDBT_FROUND_DIAG_NOP
        DBT_ASAN BUILD_TESTING RVDBT_NATIVE_REQUIRED CMAKE_CXX_COMPILER CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_RELEASE)
    string(APPEND _profile_summary "${_option}=${${_option}}\n")
endforeach()
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/build-profile.txt" CONTENT "${_profile_summary}")
message(STATUS "Resolved build policy:\n${_profile_summary}")

file(GLOB_RECURSE CLANG_FORMAT_TARGETS dbt/*.h dbt/*.cpp)
list(FILTER CLANG_FORMAT_TARGETS EXCLUDE REGEX ".*third_party.*$")

add_custom_target(
    clang-format
    COMMAND /usr/bin/clang-format
    -i
    ${CLANG_FORMAT_TARGETS}
)
