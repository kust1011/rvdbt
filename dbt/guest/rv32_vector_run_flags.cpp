// Single definition of the chunk-run A/B flags shared by every host-width translation unit of
// rv32_vector_runs.inc. Kept in its own TU because that header is included once per width.
extern "C" unsigned rvv_run_hoist = 0;
// P14 G7: 2-chunk straight-line unroll in the run kernels. Off by default = the A/B control.
extern "C" unsigned rvv_run_unroll2 = 0;

// Counter for the RVDBT_CHECK_TBEXIT_MXCSR directed check (see guest/rv32_interp.cpp). Defined
// unconditionally so the check can be enabled without touching the link line.
extern "C" unsigned long long g_tbexit_mxcsr_violations = 0;
