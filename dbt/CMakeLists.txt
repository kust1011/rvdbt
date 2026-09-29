add_subdirectory(third_party)

function(add_dbt_option option_name descr default)
    option(${option_name} "${descr}" ${default})
    if(${option_name})
        add_compile_definitions(${option_name})
    endif()
endfunction()

add_dbt_option(DBT_USE_INTERP "use interpreter for debugging" OFF)
add_dbt_option(DBT_DUMP_TRACE "" OFF)
add_dbt_option(DBT_DUMP_TRACE_VERBOSE "" OFF)

add_library(dbtstatic STATIC
	util/common.cpp
	util/fsmanager.cpp
	util/logger.cpp

	aot/aot.cpp
	aot/aot_module.cpp
	aot/aot_file.cpp
	aot/aot_boot.cpp
	aot/llvmaot_stackmaps.cpp
	aot/llvmaot.cpp
	aot/loop_region.cpp
	aot/loop_tier.cpp
	aot/loop_tier_load.cpp
	aot/loop_tier_install.cpp
	aot/loop_tier_route_census.cpp
	arena.cpp
	ccrf_materializer.cpp
	fault_snapshot.cpp
	mmu.cpp
	execute.cpp
	ukernel.cpp

	tcache/tcache.cpp
	tcache/objprof.cpp

	qmc/compile.cpp
	qmc/ngr.cpp
	qmc/qir.cpp
	qmc/qir_opt.cpp
	qmc/qir_printer.cpp
	qmc/runtime_stubs.cpp
	qmc/qcg/arch_traits.cpp
	qmc/qcg/jitabi.cpp
	qmc/qcg/qcg.cpp
	qmc/qcg/qemit.cpp
	qmc/qcg/qra.cpp
	qmc/qcg/qsel.cpp
	qmc/llvmgen/llvmgen.cpp

	guest/rv32_analyser.cpp
	guest/rv32_insn.cpp
	guest/rv32_interp.cpp
	guest/rv32_vector_run_flags.cpp
	guest/rv32_lane_region.cpp
	guest/rv32_lane_region_bridge.cpp
	guest/rv32_vrun.cpp
	guest/rv32_vector_run16.cpp
	guest/rv32_vector_run16fma.cpp
	guest/rv32_vector_run32.cpp
	guest/rv32_vector_gather.cpp
	guest/rv32_vector_run64.cpp
	guest/rv32_qir.cpp
)

# C2m. THE COMPILE-TIME HALF OF THE MATERIALIZE DISPATCHER'S FAIL-CLOSED RULE, MADE REAL.
#
# RvvMaterializeRunMember and RvvEmitPartialAluArm are closed-world switches over rvvrun::RunOp with
# no `default:`, and both state in their own comments that a route row added without a body there is
# a build failure. That sentence was FALSE as written: the project compiles with `-Wall` and no
# `-Werror` of any kind, so an unhandled enumerator was a warning in a 300-target build -- exactly
# the diagnostic a person adding a route row would scroll past -- and the new row would then reach
# the trailing run-time Panic instead. Promoting -Wswitch to an error for THIS ONE translation unit
# makes the stated guard the guard that actually runs.
#
# Scoped to the file rather than the project on purpose: other translation units (for instance
# qmc/qcg/rvv_vector_run_admission_test.cpp) contain deliberate partial switches whose warnings are
# accepted, and turning those into errors would be an unrelated change. guest/rv32_qir.cpp itself
# compiles with no -Wswitch diagnostic today, which is what makes this promotion free.
set_source_files_properties(guest/rv32_qir.cpp PROPERTIES COMPILE_OPTIONS "-Werror=switch")

add_library(dbtjitshared SHARED
	qmc/qcg/jitabi_shared.cpp
)

target_include_directories(dbtjitshared PUBLIC "${PROJECT_SOURCE_DIR}")
target_include_directories(dbtjitshared SYSTEM PUBLIC "${PROJECT_SOURCE_DIR}/dbt/third_party/asmjit/src")

target_include_directories(dbtstatic PUBLIC "${PROJECT_SOURCE_DIR}")
target_include_directories(dbtstatic SYSTEM PUBLIC "${PROJECT_SOURCE_DIR}/dbt/third_party/asmjit/src")
target_include_directories(dbtstatic SYSTEM PUBLIC "${PROJECT_SOURCE_DIR}/dbt/third_party/elfio")

target_link_libraries(dbtstatic PUBLIC dbtjitshared asmjit::asmjit ${Boost_LIBRARIES} m md ssl crypto)

# X4g1: the in-run single-run/descent builder script, baked from THIS source tree so a checkout is
# self-contained. aot_boot.cpp previously hardcoded an absolute path into a different working copy,
# which meant a branch could edit its own sr_builder.sh and change nothing about what ran. The
# script is tracked in this repository; aot_boot.cpp #errors if this definition is missing.
target_compile_definitions(dbtstatic PUBLIC
	DBT_SR_BUILDER_SH="${PROJECT_SOURCE_DIR}/experiments/2026-06-28-0840-spare-core-gate-pass/scripts/sr_builder.sh")

# if major version is defined, find the specific path
set(LLVM_DIR ${LLVM_PATH}/lib/cmake/llvm)
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# LLVM >= 21 ships a libc++abi <cxxabi.h> inside its own include dir. A plain -I puts that dir
# ahead of the standard system dirs, so any TU that pulls in <cxxabi.h> through libstdc++ (here:
# elfrun.cpp -> boost/any.hpp -> boost/core/demangle.hpp) gets libc++abi's declarations on top of
# libstdc++'s and fails to compile. -idirafter searches the dir AFTER the system dirs, which still
# resolves every llvm/... header (those names exist nowhere else) while leaving <cxxabi.h> to
# libstdc++. Kept version-guarded so the LLVM 20 build's command lines are unchanged.
# NB: CMAKE_CXX_FLAGS, not add_compile_options -- the latter only reaches targets created after the
# call, and dbtstatic/dbtjitshared are defined above, which would silently strip their LLVM includes.
if(LLVM_VERSION_MAJOR GREATER_EQUAL 21)
  foreach(_llvm_inc ${LLVM_INCLUDE_DIRS})
    string(APPEND CMAKE_CXX_FLAGS " -idirafter ${_llvm_inc}")
  endforeach()
else()
  include_directories(${LLVM_INCLUDE_DIRS})
endif()
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

llvm_map_components_to_libnames(llvm_libs support core irreader linker passes asmparser asmprinter target x86asmparser x86codegen x86desc x86disassembler x86info x86targetmca)
target_link_libraries(dbtstatic PUBLIC ${llvm_libs})


add_executable(elfrun elfrun.cpp)
target_include_directories(elfrun PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(elfrun PUBLIC dbtstatic)

add_executable(mmu_mapping_metadata_test mmu_mapping_metadata_test.cpp)
target_include_directories(mmu_mapping_metadata_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(mmu_mapping_metadata_test PUBLIC dbtstatic)

add_executable(arena_page_policy_test arena_page_policy_test.cpp)
target_include_directories(arena_page_policy_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(arena_page_policy_test PUBLIC dbtstatic)
target_link_options(arena_page_policy_test PRIVATE "-Wl,--wrap=mmap" "-Wl,--wrap=madvise")

add_executable(elfaot elfaot.cpp)
target_include_directories(elfaot PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(elfaot PUBLIC dbtstatic)

# Mechanism tests for the QCG vector register class. Hand-built QIR only: no guest program, no
# emitted code is executed, so this runs on a host without AVX-512.
add_executable(qra_vpr_test qmc/qcg/qra_vpr_test.cpp)
target_include_directories(qra_vpr_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(qra_vpr_test PUBLIC dbtstatic)

# Typed V512 chunk dataflow tests. The static half runs anywhere; the two native tests execute the
# emitted ZMM code and skip themselves via CPUID on a host without AVX-512. No -mavx512* flag here
# on purpose: the vector instructions are produced by asmjit at run time, not by the compiler, so
# this TU must stay buildable and runnable on a non-AVX-512 host.
add_executable(vchunk_dataflow_test qmc/qcg/vchunk_dataflow_test.cpp)
target_include_directories(vchunk_dataflow_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vchunk_dataflow_test PUBLIC dbtstatic)

# vstatechunkload: reads one 64-byte CPUState window into a typed V512 value. Same no--mavx512*
# rule as above, and for an additional reason: this test EXECUTES the emitted code on any host,
# emulating each ZMM instruction from its own emitted bytes through a SIGILL handler when the
# silicon cannot retire one. Compiling the TU for AVX-512 would put ZMM instructions in the
# handler itself, which would then fault on the host it exists to support.
add_executable(vstatechunkload_test qmc/qcg/vstatechunkload_test.cpp)
target_include_directories(vstatechunkload_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vstatechunkload_test PUBLIC dbtstatic)

# C2.1b1/C2.2a/C2.3a: routes a real encoded vsetvli+vadd.vv pair through the real RV32Translator via
# qir::CompilerGenRegionIR. CheckRoute inspects the constructed QIR only (no QSel/QRegAlloc/QEmit);
# CheckRoutePostQRA additionally runs QSelPass/QRegAllocPass by hand; CheckRouteEmitted additionally
# calls the real qcg::GenerateCode (QSel -> QRegAlloc -> QEmit -> QCodegen) and independently
# disassembles the returned host bytes with objdump -- so, unlike the other two, it DOES generate
# AVX-512 code, but its TestCompilerRuntime never mmaps that buffer (let alone PROT_EXEC), so nothing
# in this binary ever executes it. Runs on a host without AVX-512, same as qra_vpr_test above.
add_executable(vaddvv_typedchunk_route_test qmc/qcg/vaddvv_typedchunk_route_test.cpp)
target_include_directories(vaddvv_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vaddvv_typedchunk_route_test PUBLIC dbtstatic)

# P3.5a: the same four levels for exact unmasked vmul.vv -- decoder admission/exclusion, constructed
# QIR, post-QRegAlloc allocation, and objdump-decoded emitted bytes -- plus the forbidden-shape
# fallback table. Like the vadd test above it DOES generate AVX-512 (vpmulld), and like it its
# TestCompilerRuntime never mmaps that buffer, so nothing in this binary can execute it. Runs on a
# host without AVX-512.
add_executable(vmulvv_typedchunk_route_test qmc/qcg/vmulvv_typedchunk_route_test.cpp)
target_include_directories(vmulvv_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vmulvv_typedchunk_route_test PUBLIC dbtstatic)

# Native-3: the same four levels for unmasked e32/m1 `vmul.vx` and `vmacc.vx` -- decoder, constructed
# QIR, post-QRegAlloc allocation and objdump-decoded emitted bytes -- plus a fallback table that has
# to carry more weight than its siblings', because the decoder sends fourteen encodings to this one
# translator. Two checks are this route's own: the emitted `vpbroadcastd` reads the CPUState slot of
# the guest register the ENCODING names (checked at three rs1 values including x0), and vmacc.vx's
# accumulator is read before it is written at both widths. Like the tests above it DOES generate
# AVX-512, and like them its TestCompilerRuntime never mmaps that buffer, so nothing in this binary
# can execute it. Runs on a host without AVX-512.
add_executable(vxmulacc_typedchunk_route_test qmc/qcg/vxmulacc_typedchunk_route_test.cpp)
target_include_directories(vxmulacc_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vxmulacc_typedchunk_route_test PUBLIC dbtstatic)

# T7m: execute a frozen three-word direct RVV microkernel through the production CCRF QIR/QCG op,
# sequentially for its two 64-byte siblings, and compare with rvdbt's ordinary RVV substrate.
add_executable(ccrf_sequential_microkernel_test qmc/qcg/ccrf_sequential_microkernel_test.cpp)
target_include_directories(ccrf_sequential_microkernel_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(ccrf_sequential_microkernel_test PUBLIC dbtstatic)

# M6B: the two ccrf ops have fail-closed Panics in QIRToLLVM, and this proves they are unreachable
# -- both QCG admission predicates refuse under aot_use_llvm, checked against a control that shows
# the same word DOES take the route without it. Flipping either predicate makes it fail.
add_executable(ccrf_llvm_unreachable_test qmc/qcg/ccrf_llvm_unreachable_test.cpp)
target_include_directories(ccrf_llvm_unreachable_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(ccrf_llvm_unreachable_test PUBLIC dbtstatic)

# S2.1: the same four levels for exact unmasked vsub.vv (vpsubd), plus the forbidden-shape fallback
# table -- and one class of check the add/mul tests cannot have. Subtraction does not commute, so
# every place those tests compare an operand SET this one compares an ORDERED pair, and section [7]
# translates two guest words that differ only by exchanging vs2/vs1 to prove the order check is
# falsifiable rather than tautological. Like the two tests above it DOES generate AVX-512, and like
# them its TestCompilerRuntime never mmaps that buffer, so nothing in this binary can execute it.
# Runs on a host without AVX-512.
add_executable(vsubvv_typedchunk_route_test qmc/qcg/vsubvv_typedchunk_route_test.cpp)
target_include_directories(vsubvv_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vsubvv_typedchunk_route_test PUBLIC dbtstatic)

# P7E: the T7R floating-ALU typed chunk route generalized from LMUL=2 to LMUL in {1,2} on the
# OBSERVED-vtype path. Checks the shape rule, the three REAL miniWeather instruction words P7D
# measured, the two different 2-chunk tilings (one register at VLEN 1024 vs two at VLEN 512), that
# no LMUL=2 form regressed, that the unknown-vtype candidate still proposes m2, and that the opcode
# set did not move -- explicitly including the two OPFVF FMA forms, which are the NEXT checkpoint's
# work and must still take the helper. Inspects constructed QIR only: it never emits host bytes,
# never mmaps and never executes anything, so it runs on a host without AVX-512.
add_executable(vfalu_lmul1_typedchunk_route_test qmc/qcg/vfalu_lmul1_typedchunk_route_test.cpp)
target_include_directories(vfalu_lmul1_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vfalu_lmul1_typedchunk_route_test PUBLIC dbtstatic)

# P7G: the live-RVV-configuration entry hint. Checks that no hint (the 4-argument CompilerJob every
# AOT driver uses) leaves the constructed QIR byte-identical, that an e64,m1 hint specializes a
# block containing no vsetvli, that an in-block vsetvli/vsetivli overrides it, that a register-form
# vsetvl discards it, and that it is neither memoized nor leaked past the region entry. Inspects
# constructed QIR only: no host bytes are emitted, nothing is mmap'd and nothing is executed, so it
# runs on a host without AVX-512.
add_executable(rvv_entry_hint_test qmc/qcg/rvv_entry_hint_test.cpp)
target_include_directories(rvv_entry_hint_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_entry_hint_test PUBLIC dbtstatic)

# P7I-B: the OPFVF FUSED multiply-add typed chunk route (vfmadd.vf / vfnmsub.vf). Checks the shape
# rule, the two REAL miniWeather words operand by operand, funct6 fidelity, the load-major
# invariant under the legal vd==vs2 overlap, the fail-closed matrix (including the unobserved-vtype
# refusal that is STRICTER than the falu route's, and the other six FMA funct6 values), the real
# emitted host bytes disassembled by objdump -- where the x86 mnemonic for RVV's vfnmsub must be
# vfnmADD213pd -- and a VALUE differential in which the disassembly is interpreted over a real
# CPUState image and compared byte for byte against the rv32::vfma helper. It DOES emit AVX-512+FMA3
# code, but TestCompilerRuntime never mmaps that buffer (let alone PROT_EXEC), so nothing in this
# binary ever executes it; it runs on a host with none of those features.
add_executable(vfma_typedchunk_route_test qmc/qcg/vfma_typedchunk_route_test.cpp)
target_include_directories(vfma_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vfma_typedchunk_route_test PUBLIC dbtstatic)

# P7I-B N2: the SAME test source and the SAME translator source, rebuilt with -DRVV_FP_FORCE_SOFT.
# In that build fp_mode() forces the exact softfloat core, so the emitted host-FP route must not
# exist -- a property no runtime guard can express and therefore no ordinary test can check.
# guest/rv32_qir.cpp is listed explicitly so RvvQcgTypedFmaAdmit is really recompiled with the
# macro; the archive copy in dbtstatic is then never pulled in, because every symbol it defines is
# already resolved by this object.
add_executable(vfma_typedchunk_route_forcesoft_test
	qmc/qcg/vfma_typedchunk_route_test.cpp
	guest/rv32_qir.cpp)
target_include_directories(vfma_typedchunk_route_forcesoft_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vfma_typedchunk_route_forcesoft_test PRIVATE RVV_FP_FORCE_SOFT)
target_link_libraries(vfma_typedchunk_route_forcesoft_test PUBLIC dbtstatic)

# P7K-B: the three e64 floating-ALU forms that were miniWeather's entire remaining FP helper
# traffic (vfdiv.vv, vfadd.vf, vfsub.vf -- 7,200 executions at VLEN 512, all six PCs in one loop
# in output()). Checks the frame shape, the operand ORDER at both the QIR and the disassembled-byte
# level (vfsub and vfdiv do not commute, and the emitter has a deliberately reversed vfrdiv case
# next door), the load-major invariant under the real vd==vs1 word, and a fail-closed matrix whose
# first row is the `!dynamic_vtype` gate -- without it the unobserved-vtype path would propose a
# hard-coded e64,m2 candidate and turn 7,200 executions into guard misses. It DOES emit AVX-512
# code, but TestCompilerRuntime never mmaps that buffer, so nothing here is ever executed.
# A14: whole-register transfers under the guest-memory contract (base-range guard by transfer length).
add_executable(rvv_whole_reg_mem_route_test qmc/qcg/rvv_whole_reg_mem_route_test.cpp)
target_include_directories(rvv_whole_reg_mem_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_whole_reg_mem_route_test PUBLIC dbtstatic)

# Z3: the vlse32.v AVX-512 gather body -- route/emitted-code audit (any host, force-emit) and the
# executable value differential against rvv_ref::load_strided (skips itself without AVX-512F+BMI2).
add_executable(rvv_vlse_gather_route_test qmc/qcg/rvv_vlse_gather_route_test.cpp)
target_include_directories(rvv_vlse_gather_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_vlse_gather_route_test PUBLIC dbtstatic)

add_executable(rvv_vlse_gather_value_test qmc/qcg/rvv_vlse_gather_value_test.cpp)
target_include_directories(rvv_vlse_gather_value_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_vlse_gather_value_test PUBLIC dbtstatic)

# Z4B: the focused generated-code + value test for the gather route's default-off execution census.
add_executable(rvv_active_chunk_census_test qmc/qcg/rvv_active_chunk_census_test.cpp)
target_include_directories(rvv_active_chunk_census_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_chunk_census_test PUBLIC dbtstatic)

add_executable(rvv_vector_run_value_test qmc/qcg/rvv_vector_run_value_test.cpp)
target_include_directories(rvv_vector_run_value_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_vector_run_value_test PUBLIC dbtstatic)

add_executable(rvv_both_boundary_value_test qmc/qcg/rvv_both_boundary_value_test.cpp)
target_include_directories(rvv_both_boundary_value_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_both_boundary_value_test PUBLIC dbtstatic)

add_executable(rvv_instruction_work_scope_test qmc/qcg/rvv_instruction_work_scope_test.cpp)
target_include_directories(rvv_instruction_work_scope_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_instruction_work_scope_test PUBLIC dbtstatic)

add_executable(rvv_active_mask_memory_test qmc/qcg/rvv_active_mask_memory_test.cpp)
target_include_directories(rvv_active_mask_memory_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_mask_memory_test PUBLIC dbtstatic)

# F1: differential + translator-equivalence tests for the vector-run scan fast-reject.
add_executable(rvv_run_scan_fast_reject_test qmc/qcg/rvv_run_scan_fast_reject_test.cpp)
target_include_directories(rvv_run_scan_fast_reject_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_run_scan_fast_reject_test PUBLIC dbtstatic)

add_executable(rvv_run_fp_store_masked_partial_test qmc/qcg/rvv_run_fp_store_masked_partial_test.cpp)
target_include_directories(rvv_run_fp_store_masked_partial_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_run_fp_store_masked_partial_test PUBLIC dbtstatic)

add_executable(rvv_vlse_gather_census_test qmc/qcg/rvv_vlse_gather_census_test.cpp)
target_include_directories(rvv_vlse_gather_census_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_vlse_gather_census_test PUBLIC dbtstatic)

add_executable(rvv_run_mem_member_test qmc/qcg/rvv_run_mem_member_test.cpp)
target_include_directories(rvv_run_mem_member_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_run_mem_member_test PUBLIC dbtstatic)

add_executable(rvv_lmul2_run_test qmc/qcg/rvv_lmul2_run_test.cpp)
target_include_directories(rvv_lmul2_run_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_lmul2_run_test PUBLIC dbtstatic)

add_executable(rvv_run_move_member_test qmc/qcg/rvv_run_move_member_test.cpp)
target_include_directories(rvv_run_move_member_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_run_move_member_test PUBLIC dbtstatic)

# C2l: the materialize run body must be TOTAL over the member shapes the classifier admits, and
# its typed-op declaration must come from the same switch its emission does.
add_executable(rvv_materialize_run_body_test qmc/qcg/rvv_materialize_run_body_test.cpp)
target_include_directories(rvv_materialize_run_body_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_materialize_run_body_test PUBLIC dbtstatic)
# C2m: this file's EveryRunOpHasAShapeInThisTest is an enumerator pin with the same contract as the
# dispatcher's own switch, so it gets the same promotion for the same reason.
set_source_files_properties(qmc/qcg/rvv_materialize_run_body_test.cpp
			    PROPERTIES COMPILE_OPTIONS "-Werror=switch")

add_executable(rvv_run_move_split_test qmc/qcg/rvv_run_move_split_test.cpp)
target_include_directories(rvv_run_move_split_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_run_move_split_test PUBLIC dbtstatic)

# P7N-J: the value-epoch-aware, cost-weighted residency surrogate inside that same split body.
add_executable(rvv_split_value_weighted_test qmc/qcg/rvv_split_value_weighted_test.cpp)
target_include_directories(rvv_split_value_weighted_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_split_value_weighted_test PUBLIC dbtstatic)

# A13: EEW=64 unit-stride load/store through the shared width rule, plus the base-range guard.
add_executable(rvv_mem_e64_route_test qmc/qcg/rvv_mem_e64_route_test.cpp)
target_include_directories(rvv_mem_e64_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_mem_e64_route_test PUBLIC dbtstatic)

# A12: one active-element opmask per chunk per FP typed frame, shared by its lane ops.
add_executable(rvv_fp_shared_mask_test qmc/qcg/rvv_fp_shared_mask_test.cpp)
target_include_directories(rvv_fp_shared_mask_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_fp_shared_mask_test PUBLIC dbtstatic)

add_executable(rvv_full_vl_fast_body_test qmc/qcg/rvv_full_vl_fast_body_test.cpp)
target_include_directories(rvv_full_vl_fast_body_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_full_vl_fast_body_test PUBLIC dbtstatic)

add_executable(rvv_active_vl_bound_test qmc/qcg/rvv_active_vl_bound_test.cpp)
target_include_directories(rvv_active_vl_bound_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_bound_test PUBLIC dbtstatic)

add_executable(rvv_active_vl_bound_stage2a_test qmc/qcg/rvv_active_vl_bound_stage2a_test.cpp)
target_include_directories(rvv_active_vl_bound_stage2a_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_bound_stage2a_test PUBLIC dbtstatic)

add_executable(rvv_active_vl_bound_stage2d_fma_test qmc/qcg/rvv_active_vl_bound_stage2d_fma_test.cpp)
target_include_directories(rvv_active_vl_bound_stage2d_fma_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_bound_stage2d_fma_test PUBLIC dbtstatic)

# S1-3A: the same active-VL elimination on the equal-width same-EEW integer lane route.
add_executable(rvv_active_vl_int_bound_test qmc/qcg/rvv_active_vl_int_bound_test.cpp)
target_include_directories(rvv_active_vl_int_bound_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_int_bound_test PUBLIC dbtstatic)

# S1-3W: the same active-VL elimination on the widening integer route.
add_executable(rvv_active_vl_widen_bound_test qmc/qcg/rvv_active_vl_widen_bound_test.cpp)
target_include_directories(rvv_active_vl_widen_bound_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_widen_bound_test PUBLIC dbtstatic)

# W21: the static full-VL proof that lets the widening route emit no active-VL ladder at all.
add_executable(rvv_widen_static_fullvl_test qmc/qcg/rvv_widen_static_fullvl_test.cpp)
target_include_directories(rvv_widen_static_fullvl_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_widen_static_fullvl_test PUBLIC dbtstatic)

# W26: the SHARED active-chunk plan the FP, equal-width integer and widening integer producers now
# call, tested as a decision function -- including the shapes no accepted route reaches and the
# equivalence with each producer's own pre-W26 expression. W27 adds the narrowing geometry.
add_executable(rvv_active_chunk_plan_test qmc/qcg/rvv_active_chunk_plan_test.cpp)
target_include_directories(rvv_active_chunk_plan_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_chunk_plan_test PUBLIC dbtstatic)

# W27: the integer active-range policy switch on the NARROWING route (vnsrl/vnsra/vnclipu/vnclip),
# through the same shared planner -- ladder, vstart ownership, vnclip's sticky vxsat, legal overlap
# and switch-off inertness.
add_executable(rvv_active_vl_narrow_bound_test qmc/qcg/rvv_active_vl_narrow_bound_test.cpp)
target_include_directories(rvv_active_vl_narrow_bound_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_narrow_bound_test PUBLIC dbtstatic)

# W29: the five remaining already-eligible producers (vzext/vsext, vfmerge/vfmv.v.f, vfclass, vid
# under the integer policy; vfcvt under the FP policy) wired to the same shared planner -- switch-off
# inertness, the exact suffix ladder, splice equality, vstart/FP-epilogue ownership, policy
# separation, and single-unit / refused shapes.
add_executable(rvv_active_vl_family_closure_test qmc/qcg/rvv_active_vl_family_closure_test.cpp)
target_include_directories(rvv_active_vl_family_closure_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_active_vl_family_closure_test PUBLIC dbtstatic)

# QCG RVV LOWERING DECISION LAYER, phase 1 (dbt/guest/rv32_lowering_decision.h). The model, the
# three projections that join it to Ineligibility / GuardKind / CutReason, the scalar-lane
# predicate that mirrors Emit_vchunkpartialalu's arm, and the three acceptance witnesses
# (vadd.vv packed, vdiv.vv native-scalar, vle32ff.v helper-only) translated through
# CompilerGenRegionIR. Stops at QIR construction: no QEmit, no QCodegen, no guest program, so it
# runs on a host without AVX-512 exactly as the other route tests in this directory do.
add_executable(rvv_lowering_decision_test qmc/qcg/rvv_lowering_decision_test.cpp)
target_include_directories(rvv_lowering_decision_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_lowering_decision_test PUBLIC dbtstatic)

add_executable(rvv_frame_finalizer_test qmc/qcg/rvv_frame_finalizer_test.cpp)
target_include_directories(rvv_frame_finalizer_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_frame_finalizer_test PUBLIC dbtstatic)

add_executable(rvv_grouped_component_major_test qmc/qcg/rvv_grouped_component_major_test.cpp)
target_include_directories(rvv_grouped_component_major_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_grouped_component_major_test PUBLIC dbtstatic)

# C4k: the integral-LMUL half of the grouped component-major predicate. A separate binary from the
# one above on purpose -- that suite's numbers ARE the pre-C4k behaviour, so leaving it untouched is
# part of the evidence.
add_executable(rvv_lmul_group_component_major_test qmc/qcg/rvv_lmul_group_component_major_test.cpp)
target_include_directories(rvv_lmul_group_component_major_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_lmul_group_component_major_test PUBLIC dbtstatic)

add_executable(rvv_p1b_freeze_test qmc/qcg/rvv_p1b_freeze_test.cpp)
target_include_directories(rvv_p1b_freeze_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_p1b_freeze_test PUBLIC dbtstatic)

add_executable(rvv_p1c_freeze_test qmc/qcg/rvv_p1c_freeze_test.cpp)
target_include_directories(rvv_p1c_freeze_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_p1c_freeze_test PUBLIC dbtstatic)

add_executable(rvv_frame_close_coverage_test qmc/qcg/rvv_frame_close_coverage_test.cpp)
target_include_directories(rvv_frame_close_coverage_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(rvv_frame_close_coverage_test PRIVATE
    RVV_QIR_SOURCE="${PROJECT_SOURCE_DIR}/dbt/guest/rv32_qir.cpp"
    RVV_FINALIZER_SOURCE="${PROJECT_SOURCE_DIR}/dbt/guest/rv32_frame_semantics.h")

add_executable(vfalu_residual_e64_route_test qmc/qcg/vfalu_residual_e64_route_test.cpp)
target_include_directories(vfalu_residual_e64_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vfalu_residual_e64_route_test PUBLIC dbtstatic)

# A22: the floating add/subtract family on the observed-vtype path, as one semantic rule.
add_executable(vfaddsub_family_route_test qmc/qcg/vfaddsub_family_route_test.cpp)
target_include_directories(vfaddsub_family_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vfaddsub_family_route_test PUBLIC dbtstatic)
add_executable(rvv_integer_family_test qmc/qcg/rvv_integer_family_test.cpp)
target_link_libraries(rvv_integer_family_test PUBLIC dbtstatic)
add_executable(rvv_integer_family_route_test qmc/qcg/rvv_integer_family_route_test.cpp)
target_link_libraries(rvv_integer_family_route_test PUBLIC dbtstatic)
add_executable(rvv_scalar_operand_test qmc/qcg/rvv_scalar_operand_test.cpp)
target_link_libraries(rvv_scalar_operand_test PUBLIC dbtstatic)

# P7K-B soft gate: the SAME test source and the SAME translator source, rebuilt with
# -DRVV_FP_FORCE_SOFT. In that build fp_mode() forces the exact softfloat core, so the WHOLE
# floating-ALU direct route must be unreachable -- a property no runtime guard can express.
add_executable(vfalu_residual_e64_route_forcesoft_test
	qmc/qcg/vfalu_residual_e64_route_test.cpp
	guest/rv32_qir.cpp)
target_include_directories(vfalu_residual_e64_route_forcesoft_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vfalu_residual_e64_route_forcesoft_test PRIVATE RVV_FP_FORCE_SOFT)
target_link_libraries(vfalu_residual_e64_route_forcesoft_test PUBLIC dbtstatic)

# S2.2: the same levels for exact unmasked vxor.vv (vpxord), plus the class of check THIS route
# needs and its three siblings do not. vxor.vv shares the generic vialu decode family with vand.vv
# and vor.vv at adjacent funct6 values, so the hazard is not operand order (xor commutes) but
# SIBLING CAPTURE: a decoder predicate one bit too loose would route a guest AND or OR through an
# XOR emitter, structurally perfect and numerically wrong. Section [1] therefore sweeps the whole
# OP-V funct3 x funct6 x vm encoding space and requires exactly one encoding to reach Op::_vxor_vv,
# and section [7] gates that the emitted mnemonic is vpxord rather than a sibling bitwise op. Like
# the three tests above it DOES generate AVX-512 and its TestCompilerRuntime never mmaps that
# buffer, so nothing in this binary can execute it. Runs on a host without AVX-512.
add_executable(vxorvv_typedchunk_route_test qmc/qcg/vxorvv_typedchunk_route_test.cpp)
target_include_directories(vxorvv_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vxorvv_typedchunk_route_test PUBLIC dbtstatic)

# S2.3: the same levels for exact unmasked vor.vv (vpord), plus the one class of check that only
# becomes possible once TWO adjacent bitwise routes exist. vor.vv sits at funct6 001010, between the
# still-unrouted vand.vv (001001) and the ACCEPTED S2.2 vxor.vv route (001011), so its decoder hazard
# is asymmetric: a predicate one value too low mislowers a guest AND, while one value too high takes
# an already-accepted lowering AWAY from vxor.vv. Section [1] therefore sweeps the whole OP-V
# funct3 x funct6 x vm space and requires ALL FIVE splits to keep exactly one encoding each, and
# section [8] opens both bitwise switches in one process and requires vor.vv to emit vpord with zero
# vpxord and vxor.vv to emit vpxord with zero vpord. Like the four tests above it DOES generate
# AVX-512 and its TestCompilerRuntime never mmaps that buffer, so nothing in this binary can execute
# it. Runs on a host without AVX-512.
add_executable(vorvv_typedchunk_route_test qmc/qcg/vorvv_typedchunk_route_test.cpp)
target_include_directories(vorvv_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vorvv_typedchunk_route_test PUBLIC dbtstatic)

# S2.4: the same levels for exact unmasked vand.vv (vpandd), the LAST of the three adjacent bitwise
# funct6 values to be routed -- which changes what the sibling evidence can look like. vand.vv sits
# at 001001 with BOTH neighbours above it (vor.vv 001010, vxor.vv 001011) now accepted routes, so an
# upward decoder slip can only REMOVE accepted evidence, while 001000 below it is not an OPIVV
# encoding at all and a downward slip fails closed to `ill`. There is consequently no unrouted
# bitwise sibling left to prove non-capture by silence, so section [1] sweeps the whole OP-V space
# demanding ALL SIX splits keep exactly one encoding each, and section [8] opens all three bitwise
# switches in one process and requires each word to emit its own mnemonic and no other's. Section [1]
# additionally carries `vaadd.vv`, whose OPMVV funct6 is 0b001001 -- identical to vand.vv's -- as a
# named negative: only the funct3 group separates them. Like the five tests above it DOES generate
# AVX-512 and its TestCompilerRuntime never mmaps that buffer, so nothing in this binary can execute
# it. Runs on a host without AVX-512.
add_executable(vandvv_typedchunk_route_test qmc/qcg/vandvv_typedchunk_route_test.cpp)
target_include_directories(vandvv_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vandvv_typedchunk_route_test PUBLIC dbtstatic)

# S2.6: the exact unmasked unit-stride vle32.v typed chunk route. Same five levels as the six route
# tests above, plus three sections none of them could have: an EXHAUSTIVE 32768-word sweep of the
# LOAD-FP field space (the decoder does NOT narrow vm or the width field for this opcode, so the
# route's own predicate is the only gate), an operand-ROLE check that separates a load frame from a
# store frame built by copy-editing it, and the chunk-1 address-form gate that closes S2.5 4.3. Like
# the tests above it DOES generate AVX-512 and its TestCompilerRuntime never mmaps that buffer, so
# nothing in this binary can execute it. Runs on a host without AVX-512.
add_executable(vle32v_typedchunk_route_test qmc/qcg/vle32v_typedchunk_route_test.cpp)
target_include_directories(vle32v_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vle32v_typedchunk_route_test PUBLIC dbtstatic)

# S2.7: the exact unmasked unit-stride vse32.v typed chunk route. The mirror of the vle test above,
# with an exhaustive 32768-word sweep of the STORE-FP field space and the same operand-ROLE and
# chunk-1 address-form gates -- but read the other way round, because this is the first route that
# WRITES guest memory. Four sections have no analogue in any earlier route test: the direction gate
# now demands the guest address be the DESTINATION and forbids any guest-addressed load; the
# containment gate bounds what the frame may write to exactly nchunks*64 bytes at the base; the
# source window is a vs3 READ rather than a vd write, so the vd/vs3 field confusion the V format
# invites is checkable; and independent-base/alias rows drive the two guest-memory routes together.
# Like the tests above it DOES generate AVX-512 and its TestCompilerRuntime never mmaps that buffer,
# so nothing in this binary can execute it. Runs on a host without AVX-512.
add_executable(vse32v_typedchunk_route_test qmc/qcg/vse32v_typedchunk_route_test.cpp)
target_include_directories(vse32v_typedchunk_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vse32v_typedchunk_route_test PUBLIC dbtstatic)

# S2.9 + Native-1: the exact `vsetvli rd, rs1, e32,m1,ta,ma` DIRECT-STATE route, every (rd,rs1) pair
# except the reserved rd=x0 && rs1=x0 keep-vl form --
# decoder, an exhaustive 131072-word OPCFG admission sweep, the fallback matrix, constructed QIR,
# post-QRA allocation, the externally disassembled eight-instruction frame, whole-block containment,
# the same-TB accepted frames, the rvv_bb_vtype consumer gate and the frozen workload's own two
# words. UNLIKE the eight tests above it emits NO vector instruction at all -- the route is
# mov/cmp/cmovb -- so it needs no force-emit audit switch for its own frames; section [8] opens the
# add/vle/vse routes with theirs so their AVX-512 frames can be censused for non-disturbance. Its
# TestCompilerRuntime never mmaps, so nothing in this binary can execute what it emits either.
# R1A.3a: the vector-run (VRUN) descriptor and translation-time admission/cut substrate. Drives the
# REAL per-route admission predicates, the REAL shared decoder and the REAL translator; it emits
# host code only in the section that proves the emitted bytes are unchanged by the new switch, and
# never executes any of it. Runs on a host without AVX-512, same as the route tests above.
# R1A.3b: the QCG code generator for a multi-member vector run, and its correctness closure.
add_executable(rvv_vector_run_codegen_test qmc/qcg/rvv_vector_run_codegen_test.cpp)
target_include_directories(rvv_vector_run_codegen_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_vector_run_codegen_test PUBLIC dbtstatic)

# P7L-B1: the matched dependency probe, structural only (never executes what it emits).
add_executable(rvv_dep_probe_test qmc/qcg/rvv_dep_probe_test.cpp)
target_include_directories(rvv_dep_probe_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_dep_probe_test PUBLIC dbtstatic)

add_executable(rvv_shift_route_test qmc/qcg/rvv_shift_route_test.cpp)
target_include_directories(rvv_shift_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_shift_route_test PUBLIC dbtstatic)

# P7N-D: the VLEN-derived host chunk geometry (--rvv-qcg-narrow-chunk-width).
add_executable(rvv_narrow_width_route_test qmc/qcg/rvv_narrow_width_route_test.cpp)
target_include_directories(rvv_narrow_width_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_narrow_width_route_test PUBLIC dbtstatic)

# Reserved RVV encodings the decoder must refuse, each paired with the legal encoding one field
# away from it (the FP reductions' OPFVF twins, vid.v's vs2, and vmv.v.* against vmerge).
#
# NO LINK LIBRARIES, and that is this target's real dependency rather than an omission. What it
# tests is the header-only Decoder<> template, so the object references nothing in
# libdbtstatic.a -- and a static archive only yields the members that resolve something, so
# util/common.o (which defines dbt::Panic) is never extracted. libdbtjitshared.so, which dbtstatic
# links and which calls Panic, is then left with an unresolved symbol at the executable link.
# Linking dbtstatic "like the neighbouring tests" is what PRODUCES that failure here; those tests
# link cleanly only because their code pulls real objects out of the archive first.
add_executable(rvv_reserved_decode_test qmc/qcg/rvv_reserved_decode_test.cpp)
target_include_directories(rvv_reserved_decode_test PUBLIC "${PROJECT_SOURCE_DIR}")

# P7N-G: live-range splitting for the vector run's SSA body.
add_executable(rvv_run_live_range_split_test qmc/qcg/rvv_run_live_range_split_test.cpp)
target_include_directories(rvv_run_live_range_split_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_run_live_range_split_test PUBLIC dbtstatic)

# P7O-1 stage 1: the component-separable legality classifier and the component-resident liveness
# bound. Hand-built and translator-formed descriptors only; executes no emitted code, so it runs on
# a host without AVX-512 exactly as the neighbouring admission tests do.
add_executable(rvv_component_separable_stage1_test qmc/qcg/rvv_component_separable_stage1_test.cpp)
target_include_directories(rvv_component_separable_stage1_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_component_separable_stage1_test PUBLIC dbtstatic)

# P7O-1 stage 2: the component-resident admission bound and the component-major body, together.
# Builds QIR and host bytes and runs QSel/QRegAlloc, but never EXECUTES what it emits, so it runs on
# a host without AVX-512 exactly as the neighbouring run tests do.
add_executable(rvv_component_separable_stage2_test qmc/qcg/rvv_component_separable_stage2_test.cpp)
target_include_directories(rvv_component_separable_stage2_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_component_separable_stage2_test PUBLIC dbtstatic)

# P7O-2: demand-driven CPUState placement inside the component-major body. Same shape as the two
# above: builds QIR and host bytes and runs QSel/QRegAlloc, never EXECUTES what it emits.
add_executable(rvv_component_demand_placement_test qmc/qcg/rvv_component_demand_placement_test.cpp)
target_include_directories(rvv_component_demand_placement_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_component_demand_placement_test PUBLIC dbtstatic)

add_executable(rvv_vector_run_admission_test qmc/qcg/rvv_vector_run_admission_test.cpp)
target_include_directories(rvv_vector_run_admission_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_vector_run_admission_test PUBLIC dbtstatic)

# P7M-A: the cross-operation component-resident vector run generalized to the accepted FP lane
# routes. Checks that membership is still the single-instruction route's own admission predicate
# (swept over the whole 1024-word OP-V space against that route as the oracle), that a chain of FP
# operations becomes ONE frame whose CPUState traffic is exactly its live-ins and final live-outs,
# that the `.vf` scalar is a frame-scope live-in and never a vector one, that a fused member's old
# vd is read before it is written, that the host FP control/exception bracket is frame-scope and
# that the guard kind is the conjunction of the members' own guards. It DOES emit AVX-512 code, but
# TestCompilerRuntime never mmaps that buffer, so nothing here is ever executed; the audit
# force-emit switches bypass the host CPUID probes, so it runs on a machine without AVX-512.
add_executable(rvv_fp_component_run_test qmc/qcg/rvv_fp_component_run_test.cpp)
target_include_directories(rvv_fp_component_run_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_fp_component_run_test PUBLIC dbtstatic)

# P7M-A soft gate: the SAME test source and the SAME translator source, rebuilt with
# -DRVV_FP_FORCE_SOFT. In that build the exact softfloat core is the reference implementation, so
# both FP routes must be unreachable -- and therefore no FP run may form. A run substrate that
# re-derived admission instead of calling the route's predicate would still form one here.
add_executable(rvv_fp_component_run_forcesoft_test
	qmc/qcg/rvv_fp_component_run_test.cpp
	guest/rv32_qir.cpp)
target_include_directories(rvv_fp_component_run_forcesoft_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(rvv_fp_component_run_forcesoft_test PRIVATE RVV_FP_FORCE_SOFT)
target_link_libraries(rvv_fp_component_run_forcesoft_test PUBLIC dbtstatic)

# T7l-fix3: analysis-only exact QIR printer for caller-supplied guest basic-block ranges.  It
# translates but never selects, emits host code, installs a region, or executes guest instructions.
add_executable(qir_exact_region_dump qmc/qir_exact_region_dump.cpp)
target_include_directories(qir_exact_region_dump PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(qir_exact_region_dump PUBLIC dbtstatic)

# T7f: pure semantic analysis for the VLEN=1024 e32/m1/full-VL lane-region certificate.  The test
# executes no generated code and contains an independent scalar element oracle.
add_executable(rvv_lane_region_certificate_test
	qmc/qcg/rvv_lane_region_certificate_test.cpp
	guest/rv32_lane_region.cpp
	guest/rv32_vrun.cpp)
target_include_directories(rvv_lane_region_certificate_test PUBLIC "${PROJECT_SOURCE_DIR}")

# T7g: focused bridge tests.  This links the production translator-side bridge and detector but
# emits/executes no guest or host code.
add_executable(rvv_lane_region_bridge_test
	qmc/qcg/rvv_lane_region_bridge_test.cpp
	guest/rv32_lane_region_bridge.cpp
	guest/rv32_lane_region.cpp
	guest/rv32_vrun.cpp)
target_include_directories(rvv_lane_region_bridge_test PUBLIC "${PROJECT_SOURCE_DIR}")

add_executable(vsetvli_directstate_route_test qmc/qcg/vsetvli_directstate_route_test.cpp)
target_include_directories(vsetvli_directstate_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vsetvli_directstate_route_test PUBLIC dbtstatic)

# T6b: the FAMILY claim the nine per-opcode files above cannot make. It runs all nine element-wise
# QCG routes -- vsetvli, vle32.v, vse32.v and the six vv ALU operations -- at VLEN 512/1024/2048/4096
# and requires each to emit exactly k = VLEN/512 AVX-512 chunk operations with NO xmm or ymm operand
# anywhere in the region, which is the shape a silent return to the untyped SSE lowering would have
# (T6a measured exactly that at 2048/4096 before the widening). It re-runs every unsupported shape at
# all four widths, translates the real fourteen-word strip-mine body of the frozen T2g microkernel,
# and asserts the LLVM/AOT arm is unchanged in both directions. Emits AVX-512 and never mmaps it, so
# it runs on a host without AVX-512.
add_executable(rvv_generic_width_route_test qmc/qcg/rvv_generic_width_route_test.cpp)
target_include_directories(rvv_generic_width_route_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_generic_width_route_test PUBLIC dbtstatic)

# P4: the LLVM/AOT vadd.vv typed-chunk route at every host vector width (128/256/512/1024).
add_executable(rvv_llvm_narrow_width_test qmc/llvmgen/rvv_llvm_narrow_width_test.cpp)
target_include_directories(rvv_llvm_narrow_width_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_narrow_width_test PUBLIC dbtstatic)

# T5d-0: the QCG direct-backedge runtime safepoint. Unlike the route tests above, this one EXECUTES
# the code it emits -- on the real tcache code pool, through the real jitabi trampoline -- because
# the claim is about control flow and frame teardown, which emitted bytes alone cannot settle. It
# uses no vector instruction beyond one helper-routed `vsetvli` and so runs on any x86-64 host.
add_executable(backedge_safepoint_test qmc/qcg/backedge_safepoint_test.cpp)
target_include_directories(backedge_safepoint_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(backedge_safepoint_test PUBLIC dbtstatic)

# T5d2a1: the loop-tier crossing event, in the emitted bytes. Translates real RISC-V words through
# the real translator and the real QCG backend and inspects the produced machine code; nothing it
# emits is ever executed, so this runs on a host without AVX-512.
add_executable(loop_tier_event_test qmc/qcg/loop_tier_event_test.cpp)
target_include_directories(loop_tier_event_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_event_test PUBLIC dbtstatic)

# T5d2a3: the immediate service exit for an INTRA-REGION direct backedge. Reads emitted bytes AND
# executes real loops on the real code pool through the real trampoline -- the claim is about where
# control goes and what state it carries, which bytes alone cannot settle. Its guest instructions
# are one `addi`, one branch and (for the non-leaf case) a helper-routed `vsetvli`, so it runs on
# any x86-64 host.
# T5d2b1: the loop-tier load/validate primitive. Builds real ELF shared objects (some by hand, some
# with the host toolchain) and dlopens them for real, and measures the translation cache before and
# after every case -- so "loading installs nothing" is a measurement rather than a claim. No guest,
# no AVX-512, nothing executed from the artifact.
add_executable(loop_tier_load_test aot/loop_tier_load_test.cpp)
target_include_directories(loop_tier_load_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_load_test PUBLIC dbtstatic)

add_executable(loop_tier_install_test aot/loop_tier_install_test.cpp)
target_include_directories(loop_tier_install_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_install_test PUBLIC dbtstatic)

add_executable(loop_tier_route_census_test aot/loop_tier_route_census_test.cpp)
target_include_directories(loop_tier_route_census_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_route_census_test PUBLIC dbtstatic)

add_executable(promote_target_test tcache/promote_target_test.cpp)
target_include_directories(promote_target_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(promote_target_test PUBLIC dbtstatic)

add_executable(loop_tier_side_exit_test qmc/qcg/loop_tier_side_exit_test.cpp)
target_include_directories(loop_tier_side_exit_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_side_exit_test PUBLIC dbtstatic)

# T5d1a: the canonical hot-natural-loop candidate producer. Pure compiler analysis -- it builds
# module graphs from ModuleGraph's own Record* interface, computes dominators and reads the
# candidate set. No guest, no code generation, no host instruction of any width.
add_executable(loop_candidate_test aot/loop_candidate_test.cpp)
target_include_directories(loop_candidate_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_candidate_test PUBLIC dbtstatic)

# T5d1b: a selected hot natural loop compiled as a header-rooted region. Drives the REAL analyser,
# the REAL translator and the REAL LLVM backend over synthetic RISC-V words, and inspects the QIR
# and the llvm::Function in memory. No TargetMachine, no object file, no executable page.
add_executable(loop_region_test aot/loop_region_test.cpp)
target_include_directories(loop_region_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_region_test PUBLIC dbtstatic)

# T5d2a: the loop tier's state machine, artifact gate and publication step. Drives the REAL decision
# function, the REAL ELF reader and the REAL spawn site -- the argv/VLEN/route section forks the
# production builder with /bin/echo standing in for the compiler, so what it inspects is the argument
# vector execv would have received, not a copy of it. No guest, no compiler, no AVX-512, and every
# path it takes is decided by counts it supplies itself.
add_executable(loop_tier_test aot/loop_tier_test.cpp)
target_include_directories(loop_tier_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_test PUBLIC dbtstatic)

# C5.2b: the same real-translator route, taken all the way through the REAL LLVM backend
# (qir::QIRToLLVM::Run), with every check read off the generated llvm::Function. It is the AOT
# counterpart of the two route tests above, which stop at QIR/QRA/AsmJit bytes and therefore cannot
# see whether the LLVM tier admits the typed vadd.vv chunk group at all. No TargetMachine, no
# optimisation pipeline, no object file and no executable page: the IR is inspected in memory, so
# this runs on a host without AVX-512 and generates no host instruction of any width.
add_executable(vaddvv_typedchunk_llvm_test qmc/llvmgen/vaddvv_typedchunk_llvm_test.cpp)
target_include_directories(vaddvv_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vaddvv_typedchunk_llvm_test PUBLIC dbtstatic)

add_executable(rvv_integer_run_llvm_test qmc/llvmgen/rvv_integer_run_llvm_test.cpp)
target_include_directories(rvv_integer_run_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_integer_run_llvm_test PUBLIC dbtstatic)

add_executable(vsubvv_typedchunk_llvm_test qmc/llvmgen/vsubvv_typedchunk_llvm_test.cpp)
target_include_directories(vsubvv_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
# T1c: CheckAotPlumbing reads elfaot.cpp, aot_boot.cpp's route contract and the propagation audit's
# mirror from the source tree, because S3.10a's lowering was complete and tested while remaining
# unreachable from any artifact -- no elfaot option, no contract row. Same definition the T1b vmul
# test uses for the same check.
target_compile_definitions(vsubvv_typedchunk_llvm_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(vsubvv_typedchunk_llvm_test PUBLIC dbtstatic)

# T1b: focused test for the typed `vmul.vv` chunk frame as lowered by the LLVM/AOT backend. Same
# layer and discipline as the vadd/vsub LLVM tests above -- the real translator and the real
# QIRToLLVM, inspected in memory, no TargetMachine, no pass pipeline, no object file. Three classes
# of check are specific to this opcode. (1) LOW-HALF: vmul.vv writes the low SEW bits, so the test
# requires the multiply to be exactly <16 x i32> and the function to contain no vector sext/zext/
# trunc and no value wider than one 512-bit chunk -- a widening lowering would agree with the
# architecture on small inputs and disagree on large ones. (2) VLEN REACH IN BOTH DIRECTIONS: this
# route's shape half is RvvGenericChunkShapeAdmit (k=1/2/4/8) while T1b's scope is VLEN 512/1024, so
# the test pins that the LLVM arm produces no frame at 2048/4096 AND that the pure-QCG arm still
# produces k=4/k=8 there. (3) AOT REACHABILITY: it reads elfaot.cpp, aot_boot.cpp's route contract
# and the propagation audit's mirror from ${PROJECT_SOURCE_DIR}, because a complete lowering with no
# option and no contract row is exactly the unreachable-route defect T1a recorded for vsub.vv.
# Runs on any host.
# T1f: focused test for the typed `vand.vv` chunk frame as lowered by the LLVM/AOT backend, and the
# last of the family. Same layer and discipline as its four siblings, plus the two classes of check
# only the LAST-routed member of an adjacent funct6 triple can have. (1) BOTH neighbours are now
# accepted routes, so the risk has inverted: it is no longer "a neighbour leaks through" but "this
# checkpoint steals a neighbour's operation", which a purely negative check cannot see -- the
# neighbour table is therefore fully POSITIVE, requiring vor.vv and vxor.vv to still produce their
# own frames carrying their own nodes while this route's node appears zero times in them.
# (2) VF6_VAADD (OPMVV) is also 001001, so `vaadd.vv` shares this route's funct6 exactly and is
# separated only by its funct3 group; it is carried as a named negative row. Also checks live AOT
# reachability. Runs on any host.
add_executable(vandvv_typedchunk_llvm_test qmc/llvmgen/vandvv_typedchunk_llvm_test.cpp)
target_include_directories(vandvv_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vandvv_typedchunk_llvm_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(vandvv_typedchunk_llvm_test PUBLIC dbtstatic)

# T1e: focused test for the typed `vor.vv` chunk frame as lowered by the LLVM/AOT backend. Same
# layer and discipline as the vadd/vsub/vmul/vxor LLVM tests, plus the class of check only the
# SECOND-routed member of an adjacent funct6 triple needs. VF6_VAND (001001), VF6_VOR (001010) and
# VF6_VXOR (001011) are neighbours in one OPIVV group, and after T1d the two ways to get this route
# wrong differ in kind: `CreateXor` would STEAL the accepted T1d route's operation (a regression of a
# shipped route) while `CreateAnd` would use an operation with no LLVM lowering at all. The test
# therefore censuses all six family opcodes and requires everything but `or` to be zero, and checks
# both neighbours in their now-different directions -- vand.vv must produce no frame, vxor.vv must
# still produce exactly one carrying `vchunkxor`. It also checks live AOT reachability (elfaot
# option, contract row, audit mirror) and that vand.vv has acquired none of it. Runs on any host.
add_executable(vorvv_typedchunk_llvm_test qmc/llvmgen/vorvv_typedchunk_llvm_test.cpp)
target_include_directories(vorvv_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vorvv_typedchunk_llvm_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(vorvv_typedchunk_llvm_test PUBLIC dbtstatic)

# T1d: focused test for the typed `vxor.vv` chunk frame as lowered by the LLVM/AOT backend. Same
# layer and discipline as the vadd/vsub/vmul LLVM tests, plus the class of check only a BITWISE
# member needs: VF6_VAND/VF6_VOR/VF6_VXOR are adjacent funct6 values in one OPIVV group, so
# `CreateOr` or `CreateAnd` in place of `CreateXor` would emit a frame with the right blocks, chunk
# count, windows, guard and fallback and the wrong value in every lane. The test therefore censuses
# xor/or/and/add/sub/mul across the whole function and requires all but xor to be zero, drives the
# two neighbouring encodings with their own switches ON and requires no frame, and carries vsub/vmul
# as positive controls so those zeros cannot be satisfied by a harness that admits nothing. It also
# checks live AOT reachability (elfaot option, contract row, audit mirror) and that the two unrouted
# neighbours have acquired none of it. Runs on any host.
add_executable(vxorvv_typedchunk_llvm_test qmc/llvmgen/vxorvv_typedchunk_llvm_test.cpp)
target_include_directories(vxorvv_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vxorvv_typedchunk_llvm_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(vxorvv_typedchunk_llvm_test PUBLIC dbtstatic)

add_executable(vmulvv_typedchunk_llvm_test qmc/llvmgen/vmulvv_typedchunk_llvm_test.cpp)
target_include_directories(vmulvv_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vmulvv_typedchunk_llvm_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(vmulvv_typedchunk_llvm_test PUBLIC dbtstatic)

# Native-3, LLVM/AOT arm: the same admitted shape lowered by QIRToLLVM. Its own two obligations are
# that the scalar is an i32 load from the CPUState slot of the encoding's rs1 followed by a splat --
# not a per-lane load and not a constant -- and that a vmacc.vx frame's fast arm contains `mul` and
# `add` over <16 x i32> with ZERO calls, so no helper is hiding inside the direct arm. No
# TargetMachine, no pass pipeline, no object file; runs on any host.
add_executable(vxmulacc_typedchunk_llvm_test qmc/llvmgen/vxmulacc_typedchunk_llvm_test.cpp)
target_include_directories(vxmulacc_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_definitions(vxmulacc_typedchunk_llvm_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(vxmulacc_typedchunk_llvm_test PUBLIC dbtstatic)

# S3.4: focused test for the direct-state `vsetvli` route as lowered by the LLVM/AOT backend. Same
# layer and same discipline as the vadd test above -- the real translator and the real QIRToLLVM,
# inspected in memory. Its semantic core reads the emitted compare predicate and select arm order
# out of the IR and evaluates them over eight AVL values, so a signed compare or a swapped arm
# fails it. No TargetMachine, no pass pipeline, no object file; runs on any host.
add_executable(vsetvli_directstate_llvm_test qmc/llvmgen/vsetvli_directstate_llvm_test.cpp)
target_include_directories(vsetvli_directstate_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vsetvli_directstate_llvm_test PUBLIC dbtstatic)

# W30: the sibling of the test above, for `vsetivli`. Same layer and same discipline. It is a
# separate binary rather than more cases in that file because the two opcodes' admitted shapes
# differ in a way that must stay separately statable: vsetivli's AVL is a uimm5 in the same five
# bits that hold rs1 in vsetvli, so its `rd == x0 && field(19:15) == 0` encoding is LEGAL where
# vsetvli's is the reserved keep-VL form. Its semantic core is a uimm5 ladder straddling VLMAX,
# driven at VLENs where VLMAX falls inside and outside the 5-bit AVL domain. No TargetMachine, no
# pass pipeline, no object file; runs on any host.
add_executable(vsetivli_directstate_llvm_test qmc/llvmgen/vsetivli_directstate_llvm_test.cpp)
target_include_directories(vsetivli_directstate_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vsetivli_directstate_llvm_test PUBLIC dbtstatic)

# W31: the integer compare family on the LLVM arm. Two claims kept apart: that the LLVM route and
# the pure-QCG RvvTryIntegerFamily build node-for-node identical QIR for the same encoding (the
# anti-drift check that makes a separate admission function safe), and that the emitted IR computes
# the architectural answer -- the latter by pulling the real llvm::CmpInst::Predicate out of the
# generated function and evaluating it against rvv_ref::vicmp_apply over operand pairs that
# separate signed from unsigned. Also checks the three properties only a mask destination has: the
# destination is a blend and not a store, vstart is read by the body, and v0 is read iff vm == 0.
# No TargetMachine, no pass pipeline, no object file; runs on any host.
add_executable(rvv_llvm_icmp_test qmc/llvmgen/rvv_llvm_icmp_test.cpp)
target_include_directories(rvv_llvm_icmp_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_icmp_test PUBLIC dbtstatic)

# W32: the partial-VL arm of the LLVM/AOT unit-stride vector load. Pure IR assertions. Its central
# section takes the real llvm::CmpInst::Predicate and the real constant index vector out of the
# emitted mask and evaluates them for EVERY vl in [0, VLMAX], lane by lane, against the
# architectural predicate -- so vl = 0, every partial vl and vl = VLMAX are all covered by one
# check. It also requires that the guest-memory read is llvm.masked.load and that NO unmasked
# vector load survives, which is the page-boundary property: that intrinsic is specified not to
# access a lane whose mask bit is false, and rvdbt panics on SIGSEGV rather than delivering a guest
# trap. No TargetMachine, no pass pipeline, no object file; runs on any host.
add_executable(rvv_llvm_mem_partial_vl_test qmc/llvmgen/rvv_llvm_mem_partial_vl_test.cpp)
target_include_directories(rvv_llvm_mem_partial_vl_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_mem_partial_vl_test PUBLIC dbtstatic)

# S3.5: focused test for the typed `vle32.v` chunk frame as lowered by the LLVM/AOT backend. Same
# layer and same discipline as the two LLVM tests above, plus the three properties only a GUEST-
# MEMORY route has: the 64-byte load's address is reconstructed out of the IR and traced back to the
# CPUState slot of the guest GPR named by rs1; chunk 1's +64 is required to be a host-pointer byte
# displacement applied AFTER the zero-extension (never an i32 add, which would wrap at the top of the
# address space); and the guest load's alias scope and alignment are compared, as MDNode identities,
# against the frame's own CPUState accesses. No TargetMachine, no pass pipeline, no object file, no
# guest memory is actually mapped or dereferenced; runs on any host.
add_executable(vle32v_typedchunk_llvm_test qmc/llvmgen/vle32v_typedchunk_llvm_test.cpp)
target_include_directories(vle32v_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vle32v_typedchunk_llvm_test PUBLIC dbtstatic)

# S3.6: focused test for the typed `vse32.v` chunk frame as lowered by the LLVM/AOT backend. Same
# layer and discipline as the load test above, plus the property that only exists once BOTH memory
# routes are direct: a guest load and a guest store in one region may alias, so the test asserts the
# exact ScopedNoAliasAA containment relation -- neither direction provably-noalias between them,
# both provably disjoint from the frames' CPUState traffic -- which is what makes reordering
# illegal. It also pins the SOURCE window against vs3 (the V format keeps vs3 in the rd field) and
# the store's address, chunk displacement, alias scope and alignment. No TargetMachine, no pass
# pipeline, no object file, and no guest memory is mapped or written; runs on any host.
add_executable(vse32v_typedchunk_llvm_test qmc/llvmgen/vse32v_typedchunk_llvm_test.cpp)
target_include_directories(vse32v_typedchunk_llvm_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(vse32v_typedchunk_llvm_test PUBLIC dbtstatic)

# T6d: the fail-closed admission boundary of the four LLVM vector-SSA routes -- vfalu, vfma, vfcmp
# and vmerge. Unlike the ten routes above, these four are reached through decode Ops that carry a
# WHOLE encoding family (eleven, eight, six funct6 values, and OPIVV/OPIVX/OPIVI merge), so "this
# really is the instruction the frame was written for" is the translator's own inline funct3/funct6/
# vm test rather than a decoder-guaranteed type -- and none of the four had a test. It sweeps the
# entire funct3 x funct6 x vm space per route, requires exactly the declared encodings to be
# admitted and every other member of the same decode class to reach that route's pre-existing
# helper, then runs the shape (SEW/LMUL/group/mask-overlap) and gate (RvvSSAEnabled terms, host-fma,
# no observed vtype) rows. Translation-level only: no LLVM module, no TargetMachine, no emitted host
# instruction, nothing executed. Runs on any x86-64 host.
add_executable(rvv_ssa_fp_mask_admission_test qmc/llvmgen/rvv_ssa_fp_mask_admission_test.cpp)
target_include_directories(rvv_ssa_fp_mask_admission_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_ssa_fp_mask_admission_test PUBLIC dbtstatic)

# The other half of the vfalu route's obligation: what the ADMITTED encodings lower to. The file
# above pins WHICH funct6 values reach the typed node; this one runs the real LLVM backend on each
# of them, at e32 and e64 and at VLEN 512 and 1024, and requires the intended constrained intrinsic
# (matched by Intrinsic::ID), the round.dynamic/fpexcept.strict environment, the canonical-NaN
# select, `vd = vs2 OP vs1` operand order, two INDEPENDENT calls with no helper at VLEN 1024, and
# QIR active_chunks == emitted call count. Builds IR only: no TargetMachine, no object file, nothing
# executed, so it runs on any x86-64 host.
add_executable(rvv_llvm_falu_family_test qmc/llvmgen/rvv_llvm_falu_family_test.cpp)
target_include_directories(rvv_llvm_falu_family_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_falu_family_test PUBLIC dbtstatic)

# F1 (2026-09-16): the LLVM/AOT typed FP FRAME -- several admitted full-VL unmasked register-only
# `.vv` FP instructions under ONE guard and ONE MXCSR bracket. Complements the file above, which
# covers the per-instruction P-vector-SSA family's arithmetic. Real translator + real backend, no
# emitted object and no executed vector instruction, so it runs on any host.
add_executable(rvv_llvm_fp_run_test qmc/llvmgen/rvv_llvm_fp_run_test.cpp)
target_include_directories(rvv_llvm_fp_run_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fp_run_test PUBLIC dbtstatic)

# R1/R2 (2026-09-17): the CANDIDATE-VTYPE entry to the frame the file above covers. Multi-ip-range
# regions whose later ranges hold no `vsetvli`, the region-scoped candidate, its invalidation, the
# unchanged guard/ordered fallback, and the pure-QCG contrast. Same properties as above: real
# translator + real backend, no emitted object, no executed vector instruction, any host.
# W5 (2026-09-17): one host-chunk geometry for VLEN 128/256/512/1024/2048 (+4096) on the LLVM arm.
# Integer .vv, FP lane and fused, unit-stride memory; the refusal widths; and the unchanged pure-QCG
# admission. Real translator + real backend, no emitted object, no executed vector instruction.
add_executable(rvv_llvm_five_width_geometry_test qmc/llvmgen/rvv_llvm_five_width_geometry_test.cpp)
target_include_directories(rvv_llvm_five_width_geometry_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_five_width_geometry_test PUBLIC dbtstatic)

# 2026-09-17 exit-cancel: drives the real SpawnBuilder/ReportAtExit with /bin/sleep and /bin/echo
# standing in for the compiler, so the shipped lifecycle is what is measured.
add_executable(loop_tier_exit_cancel_test aot/loop_tier_exit_cancel_test.cpp)
target_include_directories(loop_tier_exit_cancel_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_exit_cancel_test PUBLIC dbtstatic)

add_executable(loop_tier_profile_snapshot_test aot/loop_tier_profile_snapshot_test.cpp)
target_include_directories(loop_tier_profile_snapshot_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(loop_tier_profile_snapshot_test PUBLIC dbtstatic)

# 2026-09-17: the gbr patch point's register ABI, asserted on EMITTED code. Takes an objdump of an
# artifact built the way the loop tier builds one and requires that a stack-spilled membase is
# reloaded BEFORE the rsp switch -- the ordering whose violation entered QCG with a garbage membase.
add_executable(gbr_patchpoint_abi_test qmc/llvmgen/gbr_patchpoint_abi_test.cpp)
target_include_directories(gbr_patchpoint_abi_test PUBLIC "${PROJECT_SOURCE_DIR}")
# Deliberately links nothing: the property is about EMITTED BYTES, so the checker reads a real
# objdump rather than re-deriving anything from the compiler it is meant to police.

add_executable(rvv_llvm_fp_candidate_vtype_test qmc/llvmgen/rvv_llvm_fp_candidate_vtype_test.cpp)
target_include_directories(rvv_llvm_fp_candidate_vtype_test PUBLIC "${PROJECT_SOURCE_DIR}")
# W5F [S21]: CheckSqrtAotPlumbing reads elfaot.cpp, aot_boot.cpp's route contract, the propagation
# audit's mirror and the gate itself from the source tree. [S18]-[S20] set the route's config flag by
# hand, so they all passed on the build where no command line could set it and no artifact could
# ever take the route -- the T1c defect, in the FP family. Same definition the T1b/T1c tests use.
target_compile_definitions(rvv_llvm_fp_candidate_vtype_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fp_candidate_vtype_test PUBLIC dbtstatic)

# W7: the whole-register move family on the LLVM arm.
#
# Section 8 reads elfrun/elfaot/aot_boot/the propagation audit from a SOURCE TREE, because every
# other section sets the route's config field by hand and would therefore pass on a build where no
# command line could turn the route on. `DBT_SOURCE_ROOT` is only the LAST-RESORT default for that
# tree: the test resolves the root at RUN TIME (argv, then $DBT_WHOLEMOVE_SOURCE_ROOT, then this
# compile-time path, then a walk up from the executable), so the binary is reproducible on a machine
# where the build-time path does not exist -- which is where it failed independent review.
#
# The generated `srcid` header carries the SHA256 of the test's own source and is a custom-command
# OUTPUT depending on that source, so ninja regenerates it on every edit. The binary prints it, which
# is what makes "this binary is stale with respect to its source" a visible fact rather than
# something inferred from failure line numbers.
set(WM_TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/qmc/llvmgen/rvv_llvm_wholemove_test.cpp)
set(WM_TEST_ID ${CMAKE_CURRENT_BINARY_DIR}/rvv_llvm_wholemove_srcid.h)
add_custom_command(OUTPUT ${WM_TEST_ID}
	COMMAND ${CMAKE_COMMAND} -DSRC=${WM_TEST_SRC} -DHDR=${WM_TEST_ID}
		-P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_source_id.cmake
	DEPENDS ${WM_TEST_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_source_id.cmake
	COMMENT "source id for rvv_llvm_wholemove_test")
add_executable(rvv_llvm_wholemove_test ${WM_TEST_SRC} ${WM_TEST_ID})
target_include_directories(rvv_llvm_wholemove_test
	PUBLIC "${PROJECT_SOURCE_DIR}" PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(rvv_llvm_wholemove_test PRIVATE
	DBT_SOURCE_ROOT="${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_wholemove_test PUBLIC dbtstatic)

# C1: whole-register MEMORY restart and address-window contract on the LLVM arm. Needs no source
# root -- every assertion is about emitted IR.
add_executable(rvv_llvm_wholereg_mem_test qmc/llvmgen/rvv_llvm_wholereg_mem_test.cpp)
target_include_directories(rvv_llvm_wholereg_mem_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_wholereg_mem_test PUBLIC dbtstatic)

# C2a: `vsetvl` with the vtype in a GPR, on the LLVM arm. Pure IR assertions; no source root.
add_executable(rvv_llvm_setvl_reg_test qmc/llvmgen/rvv_llvm_setvl_reg_test.cpp)
target_include_directories(rvv_llvm_setvl_reg_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_setvl_reg_test PUBLIC dbtstatic)

# C2b: the four scalar <-> vector element-0 transfers on the LLVM arm. Pure IR assertions.
add_executable(rvv_llvm_scalar_move_test qmc/llvmgen/rvv_llvm_scalar_move_test.cpp)
target_include_directories(rvv_llvm_scalar_move_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_scalar_move_test PUBLIC dbtstatic)

# C5: partial VL for the LLVM integer element-wise family. Pure IR assertions; C5_DUMP_IR=<path>
# additionally writes one frame's module so the report can run llc on it.
add_executable(rvv_llvm_partial_vl_test qmc/llvmgen/rvv_llvm_partial_vl_test.cpp)
target_include_directories(rvv_llvm_partial_vl_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_partial_vl_test PUBLIC dbtstatic)

# Order item 3: architectural-mask support for the masked OPIVV integer element-wise family. The
# central section folds each unit's mask to a constant and compares it element by element against
# the shared contract's own active predicate.
add_executable(rvv_llvm_masked_alu_test qmc/llvmgen/rvv_llvm_masked_alu_test.cpp)
target_include_directories(rvv_llvm_masked_alu_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_masked_alu_test PUBLIC dbtstatic)

# Order item 4: the carry/borrow family. The central section uses a NON-TRIVIAL v0 throughout,
# because v0 is a real operand here and an all-ones pattern would hide both ways of getting it wrong.
add_executable(rvv_llvm_adc_test qmc/llvmgen/rvv_llvm_adc_test.cpp)
target_include_directories(rvv_llvm_adc_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_adc_test PUBLIC dbtstatic)

add_executable(rvv_llvm_avg_test qmc/llvmgen/rvv_llvm_avg_test.cpp)
target_include_directories(rvv_llvm_avg_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_avg_test PUBLIC dbtstatic)

add_executable(rvv_llvm_smul_test qmc/llvmgen/rvv_llvm_smul_test.cpp)
target_include_directories(rvv_llvm_smul_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_smul_test PUBLIC dbtstatic)

add_executable(rvv_llvm_nclip_test qmc/llvmgen/rvv_llvm_nclip_test.cpp)
target_include_directories(rvv_llvm_nclip_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_nclip_test PUBLIC dbtstatic)

add_executable(rvv_llvm_ired_test qmc/llvmgen/rvv_llvm_ired_test.cpp)
target_include_directories(rvv_llvm_ired_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_ired_test PUBLIC dbtstatic)

add_executable(rvv_llvm_mlogic_test qmc/llvmgen/rvv_llvm_mlogic_test.cpp)
target_include_directories(rvv_llvm_mlogic_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_mlogic_test PUBLIC dbtstatic)

add_executable(rvv_llvm_vidcpop_test qmc/llvmgen/rvv_llvm_vidcpop_test.cpp)
target_include_directories(rvv_llvm_vidcpop_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_vidcpop_test PUBLIC dbtstatic)

add_executable(rvv_llvm_mprefix_test qmc/llvmgen/rvv_llvm_mprefix_test.cpp)
target_include_directories(rvv_llvm_mprefix_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_mprefix_test PUBLIC dbtstatic)

add_executable(rvv_llvm_viota_test qmc/llvmgen/rvv_llvm_viota_test.cpp)
target_include_directories(rvv_llvm_viota_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_viota_test PUBLIC dbtstatic)

add_executable(rvv_llvm_vcompress_test qmc/llvmgen/rvv_llvm_vcompress_test.cpp)
target_include_directories(rvv_llvm_vcompress_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_vcompress_test PUBLIC dbtstatic)

add_executable(rvv_llvm_gatherslide_test qmc/llvmgen/rvv_llvm_gatherslide_test.cpp)
target_include_directories(rvv_llvm_gatherslide_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_gatherslide_test PUBLIC dbtstatic)

add_executable(rvv_llvm_vstrided_test qmc/llvmgen/rvv_llvm_vstrided_test.cpp)
target_include_directories(rvv_llvm_vstrided_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_vstrided_test PUBLIC dbtstatic)

# Order item 4: the saturating integer add/sub family -- the FIRST of the five narrow nodes the
# fixed-point proposal names. The central section is a differential against rvv_ref::vsatadd driven
# through a real VectorState.
add_executable(rvv_llvm_satadd_test qmc/llvmgen/rvv_llvm_satadd_test.cpp)
target_include_directories(rvv_llvm_satadd_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_satadd_test PUBLIC dbtstatic)

# Order item 4: the widening FP arithmetic family. The delivery is ONE emitter (the widening
# convert) plus a guard kind, so this file checks those two and the envelope rather than re-pinning
# what the falu/fma tests already cover.
add_executable(rvv_llvm_fwiden_test qmc/llvmgen/rvv_llvm_fwiden_test.cpp)
target_include_directories(rvv_llvm_fwiden_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fwiden_test PUBLIC dbtstatic)

# Order item 4: vfmerge.vfm / vfmv.v.f. The central section folds every input and compares each
# published element against the architectural rule -- the mask is an OPERAND here, not a write
# enable, and that is what the oracle exists to pin.
add_executable(rvv_llvm_fmerge_test qmc/llvmgen/rvv_llvm_fmerge_test.cpp)
target_include_directories(rvv_llvm_fmerge_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fmerge_test PUBLIC dbtstatic)

# Order item 4: the 7-bit estimates vfrsqrt7.v / vfrec7.v. The central section is a DIFFERENTIAL of
# the folded emitted IR against rvv_ref::vfrsqrt7_elem / vfrec7_elem -- the repository's own
# reference -- including the five rounding modes vfrec7's overflow arm depends on.
add_executable(rvv_llvm_festimate_test qmc/llvmgen/rvv_llvm_festimate_test.cpp)
target_include_directories(rvv_llvm_festimate_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_festimate_test PUBLIC dbtstatic)

# Order item 4: vfncvt.rod.f.f.w in integer IR. The central section is a DIFFERENTIAL of the folded
# emitted IR against softfp::cvt_fmt(..., FRM_ROD, ...) -- the repository's own reference.
add_executable(rvv_llvm_fcvt_rod_test qmc/llvmgen/rvv_llvm_fcvt_rod_test.cpp)
target_include_directories(rvv_llvm_fcvt_rod_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fcvt_rod_test PUBLIC dbtstatic)

# Order item 3: FP predication -- the architectural mask for the typed FP lane family. The central
# section checks that the mask reaches the OPERANDS (not just the store) and is the SAME value.
add_executable(rvv_llvm_fp_masked_test qmc/llvmgen/rvv_llvm_fp_masked_test.cpp)
target_include_directories(rvv_llvm_fp_masked_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fp_masked_test PUBLIC dbtstatic)

# C3: the immediate-shift family on the LLVM arm. Pure IR assertions; C3_DUMP_IR=<path> also writes
# one frame's module so the report can run llc on it.
add_executable(rvv_llvm_shift_test qmc/llvmgen/rvv_llvm_shift_test.cpp)
target_include_directories(rvv_llvm_shift_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_shift_test PUBLIC dbtstatic)

# C3: the integer extension family on the LLVM arm. Pure IR assertions.
add_executable(rvv_llvm_extend_test qmc/llvmgen/rvv_llvm_extend_test.cpp)
target_include_directories(rvv_llvm_extend_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_extend_test PUBLIC dbtstatic)

# C3: the widening integer family on the LLVM arm. Pure IR assertions.
add_executable(rvv_llvm_widen_test qmc/llvmgen/rvv_llvm_widen_test.cpp)
target_include_directories(rvv_llvm_widen_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_widen_test PUBLIC dbtstatic)

# C3: the narrowing shifts on the LLVM arm. Pure IR assertions.
add_executable(rvv_llvm_narrow_shift_test qmc/llvmgen/rvv_llvm_narrow_shift_test.cpp)
target_include_directories(rvv_llvm_narrow_shift_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_narrow_shift_test PUBLIC dbtstatic)

# C5-FP: partial VL for the LLVM FP lane family via operand neutralisation.
add_executable(rvv_llvm_fp_partial_vl_test qmc/llvmgen/rvv_llvm_fp_partial_vl_test.cpp)
target_include_directories(rvv_llvm_fp_partial_vl_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fp_partial_vl_test PUBLIC dbtstatic)

# Strict Execution Order item 2: the shared RVV semantic contract (piece 1, geometry) and the
# check that every delivered conversion route actually agrees with it.
add_executable(rvv_rvv_contract_test guest/rv32_rvv_contract_test.cpp)
target_include_directories(rvv_rvv_contract_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_rvv_contract_test PUBLIC dbtstatic)

# C4: widening float-to-float on the LLVM arm. Value+NV oracle against softfp::cvt_fmt.
add_executable(rvv_llvm_fcvt_fwiden_test qmc/llvmgen/rvv_llvm_fcvt_fwiden_test.cpp)
target_include_directories(rvv_llvm_fcvt_fwiden_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fcvt_fwiden_test PUBLIC dbtstatic)

# C4: rtz float-to-integer on the LLVM arm. Value+NV oracle against softfp::cvt_to_int_width.
add_executable(rvv_llvm_fcvt_ftoi_test qmc/llvmgen/rvv_llvm_fcvt_ftoi_test.cpp)
target_include_directories(rvv_llvm_fcvt_ftoi_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fcvt_ftoi_test PUBLIC dbtstatic)

# C4: same-width integer-to-float on the LLVM arm. Asserts the CONSTRAINED intrinsic.
add_executable(rvv_llvm_fcvt_itof_test qmc/llvmgen/rvv_llvm_fcvt_itof_test.cpp)
target_include_directories(rvv_llvm_fcvt_itof_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fcvt_itof_test PUBLIC dbtstatic)

# C4: vfclass.v on the LLVM arm. Includes a constant-folding oracle against f32/f64_classify.
add_executable(rvv_llvm_fclass_test qmc/llvmgen/rvv_llvm_fclass_test.cpp)
target_include_directories(rvv_llvm_fclass_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fclass_test PUBLIC dbtstatic)

# C5-FP Family A: the same semantics on the P-vector-SSA route, which owns vfalu at VLEN 512/1024
# where no typed frame is built at all. Adds the destination merge, the bracket-guard widening and
# the fallback vd publication that the typed-chunk route does not need.
add_executable(rvv_llvm_fp_partial_vl_familya_test qmc/llvmgen/rvv_llvm_fp_partial_vl_familya_test.cpp)
target_include_directories(rvv_llvm_fp_partial_vl_familya_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_llvm_fp_partial_vl_familya_test PUBLIC dbtstatic)

# T5c-0: lifetime test for the direct-link escape ring. --inrun-escape-unlink records raw
# BranchSlot* into code_pool and the keeper later writes 12 bytes through each of them, so every
# boundary that resets, unmaps or re-initialises that pool must drop the ring first. Drives the real
# tcache (real arenas, real slot patching) across Invalidate/RevokeTarget/InvalidatePage/Init/Destroy
# and requires an empty ring after each. No guest, no emitted guest code; runs on any host.
add_executable(esc_link_ring_lifetime_test tcache/esc_link_ring_lifetime_test.cpp)
target_include_directories(esc_link_ring_lifetime_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(esc_link_ring_lifetime_test PUBLIC dbtstatic)

# X4g3: focused path test for VLEN-qualified artifact identity. Drives the real
# objprof::Init/Announce/GetCachePath and asserts both halves of the property: artifact paths
# separate by VLEN, and the .prof path does not move (one profile still serves every VLEN).
# No guest, no emitted code; runs on any host.
add_executable(objprof_vlen_cachepath_test tcache/objprof_vlen_cachepath_test.cpp)
target_include_directories(objprof_vlen_cachepath_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(objprof_vlen_cachepath_test PUBLIC dbtstatic)

# X4g1: source-level focused test for the in-run builder VLEN contract. Not a C++ test -- the thing
# it checks is the shape of the source itself (which spawn sites exist, and whether each carries the
# active --vlen), so a compiled test could not see it. Run it with `make vlen_propagation_audit`.
# Exit 0 = PASS. It reads files only: it builds nothing and runs nothing.
add_custom_target(vlen_propagation_audit
	COMMAND ${CMAKE_COMMAND} -E env python3
		"${PROJECT_SOURCE_DIR}/scripts/vlen_propagation_audit.py" "${PROJECT_SOURCE_DIR}"
	WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
	COMMENT "Auditing in-run elfaot builder VLEN propagation (source-only)"
	VERBATIM)

# P13 width cascade: one translation unit per host chunk width, each compiled with ONLY the ISA
# flags for its own width. The rest of the process is untouched, and the 256/512 kernels are only
# CALLED behind a runtime CPUID check, so an unsupported instruction is never reached.
set_source_files_properties(guest/rv32_vector_run16fma.cpp PROPERTIES COMPILE_OPTIONS "-mavx;-mfma")
set_source_files_properties(guest/rv32_vector_run32.cpp PROPERTIES COMPILE_OPTIONS "-mavx2;-mfma")
set_source_files_properties(guest/rv32_vector_gather.cpp PROPERTIES COMPILE_OPTIONS "-mavx2")
set_source_files_properties(guest/rv32_vector_run64.cpp PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512bw;-mavx512dq;-mavx512vl;-mfma")

# The CFG-edge commit invariant for dirty P-vector-SSA values. Builds QIR only (real translator, no
# backend, nothing executed), so it runs on any x86-64 host at any RVV_HOST_CHUNK_BITS. Pins the
# repair `96ff24bca` made to MakeGBr's intra-region arm and its sibling in TranslateBrcc, and prints
# fingerprints for the pure-QCG and both-gbr arms so a cross-build diff can confirm they did not
# move. Sections 8-10 cover the INDIRECT edge, including the three default-off guard rewrites
# whose hit path never reaches the `gbrind`. See
# experiments/2026-08-30-prof-hung-teacher-closure/RVV_EDGE_COMMIT_20260910-1132.md and
# RVV_INDIRECT_EDGE_20260910-1158.md.
add_executable(rvv_ssa_edge_commit_test qmc/qcg/rvv_ssa_edge_commit_test.cpp)
target_include_directories(rvv_ssa_edge_commit_test PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(rvv_ssa_edge_commit_test PUBLIC dbtstatic)
