#pragma once

#include "dbt/util/common.h"

namespace dbt
{
struct CPUState;

namespace ccrf
{
enum class ComponentLowering : u8 { FunctionalXMM, AVX512ZMM, Unavailable };

// One selector is shared by production configuration and the focused missing-capability negative.
// `Unavailable` is never a lowering: Configure turns it into a fail-closed rejection.
ComponentLowering SelectComponentLowering(bool host_avx512f, bool require_avx512);
void Configure(char const *join_path, char const *affine_path, char const *elf_path,
	       char const *exact_qir_path, char const *output_path, bool sequential, bool concurrent,
	       bool precompiled_sequential, bool require_avx512, int worker_cpu0, int worker_cpu1);
bool Enabled();
bool Sequential();
ComponentLowering Lowering();
bool InScope(u32 pc);
bool IsScopeEntry(u32 pc);
bool IsExitInstruction(u32 pc);
bool IsScalarRemainderStore(u32 pc);
unsigned Component();
// Called only from Execute(), on the host stack. Returns true when it changed state->ip and the
// dispatcher must restart without executing the boundary target selected by the guest.
bool ObserveBoundary(CPUState *state);
void RejectUnsupported(u32 pc, u32 raw);
}
} // namespace dbt
