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
// Initial-exec TLS displacements, never thread-specific absolute addresses.
// Only process-local x86-64 JIT code may embed these. Publish at EACH admitted
// memory instruction, base first and owner last, exactly like Arm; no hoisting.
struct PublicationOffsets { i32 membase, owner; };
PublicationOffsets GetPublicationOffsets();
bool HandleSignal(int signal, siginfo_t const *info, ucontext_t *context);
}
