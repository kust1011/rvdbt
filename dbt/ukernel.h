#pragma once

#include "dbt/guest/rv32_cpu.h"
#include <cstdio>

namespace dbt
{

// TODO: add guardians for g2h
#define __user

using uabi_short = i32;
using uabi_ushort = u32;
using uabi_int = i32;
using uabi_uint = u32;
using uabi_long = i32;
using uabi_ulong = u32;
using uabi_llong = i64;
using uabi_ullong = u64;
using uabi_size_t = u32;

struct uthread;

// Value-only metadata, owned by uthread, never stored in the baked CPUState ABI.
// Queueing returns normally so helper-owned scopes end before the trap unwind.
struct MemoryFaultEvent {
	enum class Origin : u32 { PredictedHelper, HostCopy };
	enum class Access : u32 { Load, Store };
	enum class Reason : u32 { Unmapped, Protection, HostFault };
	Origin origin{Origin::PredictedHelper};
	Access access{Access::Load};
	Reason reason{};
	u32 pc{}, raw{}, address{}, element{}, field{}, eew_bytes{}, nf{};
	int host_signal{}, host_code{};
};

struct MemoryFaultSnapshot {
	MemoryFaultEvent event;
	u32 pc{}, vlenb{};
	std::array<u32, 32> gpr;
	std::array<u64, 32> fpr;
	// fflags, frm, fcsr, vstart, vxsat, vxrm, vcsr, vl, vtype, vlenb.
	std::array<u32, 10> csrs;
	decltype(rv32::VectorState::vreg) vreg;
};

struct ukernel {
	ukernel() = delete;

	struct ElfImage;
	struct Process;

	static void SetFSRoot(char const *fsroot_);

	static void MainThreadBoot(int argv_n, char **argv);
	static int MainThreadExecute();

	static void ReproduceElfMappings(char const *path);

	static void Execute();
	static void EnqueueTermination(int code);
	static void QueueHelperMemoryFault(CPUState *state, MemoryFaultEvent const &event);
	static MemoryFaultSnapshot CaptureHelperMemoryFault(CPUState const *state);
	static void WriteMemoryFaultSnapshot(FILE *out, MemoryFaultSnapshot const &snapshot);
	static bool DeliverHelperSignal(CPUState *state, MemoryFaultSnapshot const &snapshot);
	static bool RestoreSignalFrame(CPUState *state);
	static bool SignalSyscall(CPUState *state);

	static Process process;

private:
	static void InitElfMappings(char const *path, ElfImage *elf);
	static void InitAVectors(ElfImage *elf, int argv_n, char **argv);
	static void LoadElf(int elf_fd, ElfImage *elf);

	static void InitMainThread(CPUState *state, ElfImage *elf);
	static void InitSignals(CPUState *state);
	static void Syscall(CPUState *state);
	static void SyscallDemo(CPUState *state);
	static void SyscallLinux(CPUState *state);

	friend struct uthread;
};

} // namespace dbt
