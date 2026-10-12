#include "dbt/rvv_host_copy.h"
#include <atomic>
#include <cstring>

extern "C" {
int rvv_copy_read_byte(void *, void *);
int rvv_copy_write_byte(void *, void *);
extern char rvv_copy_read_pc[], rvv_copy_write_pc[], rvv_copy_failed[];
}
namespace dbt::rvv_host_copy {
// Initial-exec TLS avoids a lazy __tls_get_addr call inside the signal handler.
// No allocation, logging, MMU queries, CPU lookup or nonlocal jumps in the callback.
static thread_local volatile sig_atomic_t armed __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t signo __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t code __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<uptr> expected __attribute__((tls_model("initial-exec")));
static_assert(std::atomic<uptr>::is_always_lock_free);
void ResetFault() { signo = 0; code = 0; }
Fault LastFault() { return {signo, code}; }

bool HandleSignal(int signal, siginfo_t const *info, ucontext_t *context)
{
    if (!armed ||
        !((signal == SIGSEGV && (info->si_code == SEGV_MAPERR || info->si_code == SEGV_ACCERR)) ||
          (signal == SIGBUS && (info->si_code == BUS_ADRERR || info->si_code == BUS_OBJERR))))
        return false;
    uptr const pc = context->uc_mcontext.gregs[REG_RIP];
    // RDI must still be the one guest byte passed by this thread's wrapper.
    if ((pc != (uptr)rvv_copy_read_pc && pc != (uptr)rvv_copy_write_pc) ||
        (uptr)info->si_addr != expected.load(std::memory_order_relaxed) ||
        (uptr)context->uc_mcontext.gregs[REG_RDI] != expected.load(std::memory_order_relaxed))
        return false;
    signo = signal;
    code = info->si_code;
    armed = 0;
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)rvv_copy_failed;
    return true;
}

bool Copy(u8 *element, u8 *memory, u32 address, u32 bytes, bool store, u32 &denied)
{
    // Only architectural fields, never a bulk buffer. Nested use is a host bug.
    if (armed || !bytes || bytes > 8) __builtin_trap();
    u8 staging[8];
    ResetFault();
    for (u32 b = 0; b < bytes; ++b) {
        u8 *guest = memory + (u32)(address + b);
        expected.store((uptr)guest, std::memory_order_relaxed);
        armed = 1;
        std::atomic_signal_fence(std::memory_order_seq_cst);
        int const ok = store ? rvv_copy_write_byte(guest, element + b)
                             : rvv_copy_read_byte(guest, staging + b);
        std::atomic_signal_fence(std::memory_order_seq_cst);
        armed = 0;
        if (!ok) { denied = address + b; return false; }
    }
    if (!store) std::memcpy(element, staging, bytes);
    return true;
}
}
