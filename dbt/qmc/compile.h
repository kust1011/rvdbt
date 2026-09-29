#pragma once

#include "dbt/arena.h"
#include "dbt/util/common.h"
#include <span>
#include <sstream>
#include <vector>

namespace dbt
{
using IpRange = std::pair<u32, u32>;

struct CompilerRuntime {
	virtual void *AllocateCode(size_t sz, uint align) = 0;

	virtual bool AllowsRelocation() const = 0;

	virtual void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) = 0;
	// virtual void *AnnounceRegion(u32 ip, std::span<u8> const &code) = 0;
};

static constexpr std::string_view AOT_SYM_PREFIX = "_x";

inline std::string MakeAotSymbol(u32 ip)
{
	std::stringstream ss;
	ss << AOT_SYM_PREFIX << std::hex << ip;
	return ss.str();
}

} // namespace dbt

namespace dbt::qir
{

struct CodeSegment {
	explicit CodeSegment(u32 gip_base_, u32 size_) : gip_base(gip_base_), size(size_) {}

	bool InSegment(u32 gip) const
	{
		return (gip - gip_base) < size;
	}

	u32 gip_base;
	u32 size;
};

// P7F/P7G. THE LIVE RVV CONFIGURATION AT THIS JOB'S ENTRY IP, WHEN THERE IS ONE.
//
// A JIT job is created from Execute()'s host loop with the guest PAUSED at the ip about to be
// compiled, so the architectural vector configuration established by everything BEFORE that ip --
// including a `vsetvli` sitting in a loop preheader, in a different translation block -- is live
// and readable. An offline AOT job, and every unit test that builds a job directly, has no such
// state; that is why this is OPTIONAL and why `valid == false` must reproduce the previous
// behaviour exactly.
//
// DELIBERATELY DEPENDENCY-NEUTRAL. This header is included by the guest-independent compiler core
// and by every AOT driver, so it must not learn about CPUState or the RVV guest headers. The field
// is therefore the RAW vtype word plus an EXPLICIT validity bit, and it carries no meaning this
// header can interpret: whether the word is architecturally supported, non-vill, or usable at all
// is decided by the guest translator, which is the component that owns those rules.
//
// IT IS A HINT, NOT A FACT. It selects WHICH shape a typed frame is specialized for; the emitted
// frame still proves the architectural vtype/vl/vstart at run time and still falls back to the
// pre-existing helper on any mismatch. A wrong hint costs a guard miss, never a wrong answer.
//
// vl AND vstart ARE DELIBERATELY ABSENT. `vl` changes on the last strip of every loop, so a frame
// specialized on it would miss on exactly that iteration; and it does not need to be specialized
// on, because the emitted guard already admits any `vl <= VLMAX` and already requires `vstart == 0`.
struct RvvEntryHint {
	u32 vtype{0};
	bool valid{false};
};

struct CompilerJob {
	using IpRangesSet = std::vector<IpRange>;

	explicit CompilerJob(CompilerRuntime *cruntime_, uptr vmem_, CodeSegment segment_,
			     IpRangesSet &&iprange_, RvvEntryHint rvv_entry_hint_ = {})
	    : cruntime(cruntime_), vmem(vmem_), segment(segment_), iprange(iprange_),
	      rvv_entry_hint(rvv_entry_hint_)
	{
		assert(iprange.size());
	}

	CompilerRuntime *cruntime;

	uptr vmem;
	CodeSegment segment;
	IpRangesSet iprange;
	// Defaulted, so every pre-existing construction site -- the AOT drivers and the focused
	// tests -- keeps compiling unchanged and keeps getting `valid == false`.
	RvvEntryHint rvv_entry_hint{};
};

// Now qmc operates only in synchronous mode, so returns a value from runtime.AnnounceRegion
void *CompilerDoJob(CompilerJob &job);

struct Region;
// Just generate IR
Region *CompilerGenRegionIR(MemArena *arena, CompilerJob &job);

// NGR: generate host code for a job WITHOUT installing a TBlock (used for relocation discovery via a
// variant translation). Returns the freshly-emitted host code span (allocated in the code pool).
std::span<u8> CompilerGetCode(CompilerJob &job);

} // namespace dbt::qir
