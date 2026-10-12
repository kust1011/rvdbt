#pragma once
#include "dbt/util/common.h"
#include <signal.h>
#include <ucontext.h>

namespace dbt::rvv_host_copy {
// Linux x86-64 only. The callback recognizes exact leaf PCs, never a helper range.
struct Fault { int signal{}, code{}; };
void ResetFault();
Fault LastFault();
// memory is the page-aligned RV32 address-space base; bytes is 1/2/4/8.
// Aligned fields use one width-matched access; misaligned/wrapping fields split.
bool Copy(u8 *element, u8 *memory, u32 address, u32 bytes, bool store, u32 &denied);
bool HandleSignal(int signal, siginfo_t const *info, ucontext_t *context);
}
