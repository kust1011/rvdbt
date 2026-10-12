#include "dbt/rvv_host_copy.h"
#include <atomic>
#include <cstring>

extern "C" {
int rvv_copy_read_byte(void *, void *);
extern char rvv_copy_read_pc[];
int rvv_copy_write_byte(void *, void *);
extern char rvv_copy_write_pc[];
int rvv_copy_read_word(void *, void *);
extern char rvv_copy_read_pc_word[];
int rvv_copy_write_word(void *, void *);
extern char rvv_copy_write_pc_word[];
int rvv_copy_read_dword(void *, void *);
extern char rvv_copy_read_pc_dword[];
int rvv_copy_write_dword(void *, void *);
extern char rvv_copy_write_pc_dword[];
int rvv_copy_read_qword(void *, void *);
extern char rvv_copy_read_pc_qword[];
int rvv_copy_write_qword(void *, void *);
extern char rvv_copy_write_pc_qword[];
extern char rvv_copy_failed[];
#define BULK_DECL(n) \
int rvv_bulk_read_##n(void *, void *, u32); \
int rvv_bulk_write_##n(void *, void *, u32); \
extern char rvv_bulk_read_pc_##n[], rvv_bulk_write_pc_##n[];
BULK_DECL(byte) BULK_DECL(word) BULK_DECL(dword) BULK_DECL(qword)
#undef BULK_DECL
}
namespace dbt::rvv_host_copy {
// Initial-exec TLS avoids a lazy __tls_get_addr call inside the signal handler.
// No allocation, logging, MMU queries, CPU lookup or nonlocal jumps in the callback.
static thread_local volatile sig_atomic_t armed __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t signo __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t code __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<uptr> expected __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<uptr> expected_pc __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t width __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t fault_offset __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t bulk_count __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t bulk_completed __attribute__((tls_model("initial-exec")));
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
    uptr base = expected.load(std::memory_order_relaxed);
    uptr const completed = context->uc_mcontext.gregs[REG_R8];
    if (armed == 2) {
        if (completed >= (uptr)bulk_count) return false;
        base += completed * (uptr)width;
    }
    uptr const fault = (uptr)info->si_addr;
    // Linux may report any byte of a multi-byte access. Subtraction avoids
    // overflowing an end address. Match this invocation's direction and width.
    if (pc != expected_pc.load(std::memory_order_relaxed) ||
        fault - base >= (uptr)width ||
        (uptr)context->uc_mcontext.gregs[REG_RDI] != base)
        return false;
    if (armed == 2) bulk_completed = (sig_atomic_t)completed;
    fault_offset = (sig_atomic_t)(fault - base);
    signo = signal;
    code = info->si_code;
    armed = 0;
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)rvv_copy_failed;
    return true;
}

bool Copy(u8 *element, u8 *memory, u32 address, u32 bytes, bool store, u32 &denied)
{
    // Only architectural fields, never a bulk buffer. Nested use is a host bug.
    if (armed || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)) __builtin_trap();
    u8 staging[8];
    ResetFault();
    // Naturally aligned RV32 fields use one element-width memory operation,
    // including EEW64. Misaligned/wrapping fields retain byte decomposition
    // (RVV 1.0 alignment rules / RVWMO misaligned primitives).
    bool const aligned = !(address & (bytes - 1)) &&
                         (u64)address + bytes <= (u64{1} << 32);
    u32 const access_bytes = aligned ? bytes : 1;
    int (*leaf)(void *, void *);
    char *leaf_pc;
#define SELECT(n, suffix) \
    leaf = store ? rvv_copy_write_##n : rvv_copy_read_##n; \
    leaf_pc = store ? rvv_copy_write_pc##suffix : rvv_copy_read_pc##suffix
    switch (access_bytes) {
    case 1: SELECT(byte, ); break;
    case 2: SELECT(word, _word); break;
    case 4: SELECT(dword, _dword); break;
    default: SELECT(qword, _qword); break;
    }
#undef SELECT
    for (u32 b = 0; b < bytes; b += access_bytes) {
        u8 *guest = memory + (u32)(address + b);
        expected.store((uptr)guest, std::memory_order_relaxed);
        expected_pc.store((uptr)leaf_pc, std::memory_order_relaxed);
        width = access_bytes;
        armed = 1;
        std::atomic_signal_fence(std::memory_order_seq_cst);
        int const ok = leaf(guest, store ? element + b : staging + b);
        std::atomic_signal_fence(std::memory_order_seq_cst);
        armed = 0;
        if (!ok) { denied = address + b + (u32)fault_offset; return false; }
    }
    if (!store) std::memcpy(element, staging, bytes);
    return true;
}

bool CopyElements(u8 *elements, u8 *memory, u32 address, u32 bytes, u32 count,
                  bool store, u32 &completed, u32 &denied)
{
    if (armed || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
        count > 0x7fffffffu) __builtin_trap();
    completed = 0;
    ResetFault();
    if (!count) return true;
    if ((address & (bytes - 1)) || (u64)address + (u64)count * bytes > (u64{1} << 32)) {
        for (; completed < count; ++completed)
            if (!Copy(elements + (size_t)completed * bytes, memory,
                      address + completed * bytes, bytes, store, denied)) return false;
        return true;
    }
    int (*leaf)(void *, void *, u32);
    char *pc;
#define BULK_SELECT(n) \
    leaf = store ? rvv_bulk_write_##n : rvv_bulk_read_##n; \
    pc = store ? rvv_bulk_write_pc_##n : rvv_bulk_read_pc_##n
    switch (bytes) {
    case 1: BULK_SELECT(byte); break;
    case 2: BULK_SELECT(word); break;
    case 4: BULK_SELECT(dword); break;
    default: BULK_SELECT(qword); break;
    }
#undef BULK_SELECT
    expected.store((uptr)(memory + address), std::memory_order_relaxed);
    expected_pc.store((uptr)pc, std::memory_order_relaxed);
    width = bytes;
    bulk_count = count;
    bulk_completed = 0;
    armed = 2;
    std::atomic_signal_fence(std::memory_order_seq_cst);
    int const ok = leaf(memory + address, elements, count);
    std::atomic_signal_fence(std::memory_order_seq_cst);
    armed = 0;
    completed = ok ? count : (u32)bulk_completed;
    if (!ok) denied = address + completed * bytes + (u32)fault_offset;
    return ok;
}
}
