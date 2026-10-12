#pragma once
#include "dbt/qmc/compile.h"
#include <signal.h>
#include <ucontext.h>
#include "dbt/guest/rv32_cpu.h"
namespace dbt::rvv_native_fault {
// Serialized with physical code-pool lifetime, like the existing tcache itself.
void Register(std::span<u8> code, std::span<NativeMemorySite const> sites);
void Clear();
void Arm(CPUState *state);
bool HandleSignal(int signal, siginfo_t const *info, ucontext_t *context);
}
