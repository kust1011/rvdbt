// 128-bit kernels built with VEX encoding and FMA3 (-mavx -mfma). Capability is not a function of
// width: FMA3 provides 128-bit forms whenever AVX + FMA + the OS XCR0 state are available, so a
// short architectural extent can still use a fused multiply-add. Without this TU the cascade
// would drop every short-extent FMA to the element path and keep the very regressions it exists
// to remove. Symbols are tagged 16v ("16-bit-wide, VEX") so they cannot collide with the SSE2
// baseline TU, which stays available on hosts without AVX.
#define RVVRUN_W 16
#define RVVRUN_TAG 16v
#include "dbt/guest/rv32_vector_runs.inc"
