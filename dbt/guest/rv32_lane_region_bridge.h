#pragma once

// T7g: analysis-only bridge from the real RV32 translator to the T7f detector.
//
// The bridge owns no admission policy.  A caller supplies the route predicate's actual result and
// the QIR/CFG facts it can prove.  Defaults remain Proof::Unknown, and BuildMember never turns an
// absent proof into a safe value.  Record/Dump are diagnostics only; neither is read by translation
// or execution.

#include "dbt/guest/rv32_lane_region.h"

#include <cstdio>
#include <span>
#include <vector>

namespace dbt::rv32::lane_region_bridge
{

namespace lr = lane_region;

struct QIRMemberFacts {
	lr::Proof ssa_defs_present{lr::Proof::Unknown};
	lr::Proof overlap_snapshot_proven{lr::Proof::Unknown};
};

// Derive decode/route facts from the shared default-absent TypedAluRoute table, while taking the
// actual route admission and QIR proofs from the caller.  Unsupported decodes intentionally retain
// UNKNOWN member metadata; Detect classifies their raw word on its rejection-only path.
lr::CandidateMember BuildMember(u32 pc, u32 raw, lr::Proof route_admitted,
				QIRMemberFacts const &qir);

lr::Input BuildInput(std::span<lr::CandidateMember const> members, lr::ShapeFacts const &shape,
		     lr::CFGFacts const &cfg, lr::Proof backend_can_hold_private);

struct Observation {
	std::vector<lr::CandidateMember> members;
	lr::ShapeFacts shape{};
	lr::CFGFacts cfg{};
	lr::Proof backend_can_hold_private{lr::Proof::Unknown};
	lr::Result result{lr::Reject::UNKNOWN_METADATA};
	lr::Reject first_cut{lr::Reject::UNKNOWN_DECODE_OR_ROUTE};
	u32 first_cut_pc{};
	bool has_first_cut{};
};

// Record one maximal, non-overlapping translator candidate. Exact repeats caused by translation
// cache replacement are deduplicated. A conflicting repeat remains visible as a separate row.
void Record(Observation observation);
void Reset();
bool Dump(char const *path);

// Rejection-only classification used for the first instruction after a maximal candidate.  The
// exact six admitted rows return UNKNOWN_METADATA and therefore must be extended, not cut.
lr::Reject ClassifyBoundaryRaw(u32 raw);

} // namespace dbt::rv32::lane_region_bridge
