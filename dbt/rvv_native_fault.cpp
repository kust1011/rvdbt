#include "dbt/rvv_native_fault.h"
#include "dbt/config.h"
#include "dbt/mmu.h"
#include "dbt/guest/rv32_runtime.h"
#include "dbt/ukernel.h"
#include <atomic>

extern "C" void qcgstub_rv32_vlNre(dbt::CPUState *, u32);
extern "C" void qcgstub_rv32_vsNr(dbt::CPUState *, u32);
namespace dbt::rvv_native_fault {
struct Entry {
    Entry *next;
    uptr pc, cold;
    NativeMemorySite site;
};
static std::atomic<Entry *> head{};
static_assert(std::atomic<Entry *>::is_always_lock_free);
static_assert(std::atomic<uptr>::is_always_lock_free);
static thread_local std::atomic<uptr> owner __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<uptr> membase __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t pending __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<Entry const *> captured __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<uptr> address __attribute__((tls_model("initial-exec")));
static thread_local std::atomic<u32> element __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t fault_signal __attribute__((tls_model("initial-exec")));
static thread_local volatile sig_atomic_t fault_code __attribute__((tls_model("initial-exec")));

void Arm(CPUState *state) {
    membase.store((uptr)mmu::base, std::memory_order_relaxed);
    owner.store((uptr)state, std::memory_order_relaxed);
}
void Register(std::span<u8> code, std::span<NativeMemorySite const> sites)
{
    for (auto const &site : sites) {
        if (!site.cold_offset) continue;
        if (site.code_offset >= code.size() || site.cold_offset >= code.size() ||
            (site.eew_bytes != 1 && site.eew_bytes != 2 && site.eew_bytes != 4 && site.eew_bytes != 8) ||
            !site.bytes || site.bytes > 64 || site.displacement % site.eew_bytes ||
            (site.scalar_loop && (site.bytes != site.eew_bytes || site.displacement ||
                site.address_reg != 7 || site.data_reg != 1 || site.mask_reg != 0xff ||
                !site.nf || site.nf > 8 || site.field >= site.nf)) ||
            (site.mask_reg == 7 && site.eew_bytes < 4) ||
            (site.mask_reg != 7 && site.mask_reg != 0xff))
            Panic("native fault exit outside code allocation");
        auto *entry = new Entry{head.load(std::memory_order_relaxed),
            (uptr)code.data() + site.code_offset, (uptr)code.data() + site.cold_offset, site};
        head.store(entry, std::memory_order_release);
    }
}
void Clear()
{
    // Init/Invalidate/Destroy already require no executing JIT frame. No entry
    // dies merely because a guest target is revoked or a new entry is published.
    auto *entry = head.exchange(nullptr, std::memory_order_acq_rel);
    while (entry) { auto *next = entry->next; delete entry; entry = next; }
    owner.store(0, std::memory_order_relaxed);
    pending = 0;
}

bool HandleSignal(int signal, siginfo_t const *info, ucontext_t *context)
{
    // Scalar sites own synchronous SEGV data #PF and BUS backing errors.
    // Chunk sites retain their existing SEGV-only codec. No CPUState reads here.
    auto const *r = context->uc_mcontext.gregs;
    if (pending || !owner.load(std::memory_order_relaxed) ||
        (uptr)r[REG_R13] != owner.load(std::memory_order_relaxed)) return false;
    auto *entry = head.load(std::memory_order_acquire);
    while (entry && entry->pc != (uptr)r[REG_RIP]) entry = entry->next;
    if (!entry) return false;
    bool const page_fault = signal == SIGSEGV &&
        (info->si_code == SEGV_MAPERR || info->si_code == SEGV_ACCERR) &&
        r[REG_TRAPNO] == 14 && (r[REG_ERR] & 4) && !(r[REG_ERR] & ~greg_t(7)) &&
        bool(r[REG_ERR] & 2) == entry->site.store;
    bool const bus_fault = entry->site.scalar_loop && signal == SIGBUS &&
        (info->si_code == BUS_ADRERR || info->si_code == BUS_OBJERR);
    if (!page_fault && !bus_fault) return false;
    auto const &site = entry->site;
    uptr const memory = membase.load(std::memory_order_relaxed);
    uptr const guest = (uptr)r[site.scalar_loop ? REG_RDI : REG_RAX];
    if (guest > 0xffffffffu ||
        (!config::zero_membase && (uptr)r[REG_RBP] != memory)) return false;
    uptr const base = guest + site.displacement +
        (config::zero_membase ? 0 : (uptr)r[REG_RBP]);
    u32 bytes = site.bytes;
    if (site.mask_reg == 7) {
        // The partial arm loads K7 from EDX immediately before the access.
        // Its low-bit contiguous mask describes active lanes, never completion.
        u32 mask = (u32)r[REG_RDX] & ((1u << (site.bytes / site.eew_bytes)) - 1);
        if (!mask || (mask & (mask + 1))) return false;
        bytes = 0;
        while (mask) { bytes += site.eew_bytes; mask >>= 1; }
    }
    if (base - memory >= mmu::ASPACE_SIZE || bytes > mmu::ASPACE_SIZE - (base - memory) ||
        (base & (mmu::PAGE_SIZE - 1)) + bytes > mmu::PAGE_SIZE ||
        (uptr)info->si_addr - base >= bytes) return false;
    // No CPUState/MMU reads, allocation, logs, XSAVE interpretation or jumps out
    // of C++ here. Signal return enters emitted code, never the guest access.
    captured.store(entry, std::memory_order_relaxed);
    // Every active byte is on the denied page. Report the first byte of
    // the selected first denied element; si_addr only validates host ownership.
    address.store(base, std::memory_order_relaxed);
    element.store(site.scalar_loop ? (u32)r[REG_R8] : site.displacement / site.eew_bytes, std::memory_order_relaxed);
    fault_signal = signal;
    fault_code = info->si_code;
    pending = 1;
    owner.store(0, std::memory_order_relaxed);
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)entry->cold;
    return true;
}

extern "C" void qcgstub_rv32_native_memory_fault(CPUState *state, u32 raw)
{
    if (raw) {
        if (((raw >> 20) & 31u) == 8u) {
            if ((raw & 0x7f) == 0x27) qcgstub_rv32_vsNr(state, raw);
            else qcgstub_rv32_vlNre(state, raw);
        } else rv32::ExecuteCheckedUnitMemory(state, raw);
        return;
    }
    if (!pending || state != CPUState::Current()) Panic("unarmed native fault exit");
    auto const site = captured.load(std::memory_order_relaxed)->site;
    pending = 0;
    state->vec.vstart = element.load(std::memory_order_relaxed);
    MemoryFaultEvent event;
    event.origin = MemoryFaultEvent::Origin::NativeUnit;
    event.reason = MemoryFaultEvent::Reason::HostFault;
    event.access = site.store ? MemoryFaultEvent::Access::Store : MemoryFaultEvent::Access::Load;
    event.pc = site.guest_pc; event.raw = site.raw;
    event.address = mmu::h2g((void *)address.load(std::memory_order_relaxed));
    event.element = state->vec.vstart; event.eew_bytes = site.eew_bytes;
    event.field = site.scalar_loop ? site.field : 0;
    event.nf = site.scalar_loop ? site.nf : ((site.raw >> 20) & 31u) == 8u ? ((site.raw >> 29) & 7u) + 1u : 1u;
    event.host_signal = fault_signal; event.host_code = fault_code;
    ukernel::QueueHelperMemoryFault(state, event);
    // All automatic body scopes have ended before the established FP/unwind exit.
    rv32::FinishHelperMemoryFault(state);
    __builtin_unreachable();
}
}
