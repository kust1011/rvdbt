// Host-width translation unit for the P13 width cascade. See rv32_vector_runs.inc for why one
// TU per width is used instead of target-attribute multiversioning. This TU is compiled with
// only the ISA flags for its own width (see CMakeLists.txt); nothing else in the process is.
#define RVVRUN_W 16
#include "dbt/guest/rv32_vector_runs.inc"
