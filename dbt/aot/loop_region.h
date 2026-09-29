#pragma once

// T5d1b: emitting a selected hot natural loop as a header-rooted LLVM function.
//
// This header exists so that the focused test drives the SAME emitter the compiler runs, rather than
// a copy of it. `llvmaot.cpp` owns the surrounding pipeline (profile -> whole-profile graph ->
// candidate set -> object -> link); everything specific to turning ONE candidate into ONE function
// lives here.

#include "dbt/aot/aot_module.h"
#include "dbt/arena.h"
#include "dbt/qmc/llvmgen/llvmgen.h"

#include <vector>

namespace dbt
{

// What emitting one candidate produced. Every field is read back off the artefacts themselves, so a
// caller reports what happened rather than what it intended.
struct LoopRegionResult {
	u32 header_ip{};
	llvm::Function *fn{};
	qir::Region *region{};
	unsigned qir_blocks{};
	std::vector<std::pair<u32, u32>> ranges;	 // header first, then ascending
	std::vector<ModuleGraph::LoopExit> exits;	 // every edge leaving the body
};

// Emit ONE candidate as a function whose external entry is its loop header and whose body is exactly
// the candidate's canonical `body_ips`.
//
// The header becomes the entry by construction, with no wrapper and no entry switch:
// `LoopCandidateIpRanges` puts it first, `RV32Translator::Translate` takes range 0 as the region
// entry and creates blocks in range order, and `QIRToLLVM::Run` takes block id 0 as `first_bb` --
// which, with `merge_entries` and `internal_dispatch_targets` both left empty, it simply branches
// to. Every branch target outside the body misses the translator's `ip2bb` and becomes a `gbr`
// carrying that guest PC, i.e. an explicit exit through the existing dispatcher contract.
//
// `arena` must outlive the returned `region`; `ctx` must outlive the returned `fn`.
LoopRegionResult EmitLoopRegion(qir::LLVMGenCtx *ctx, ModuleGraph &mg, MemArena *arena,
				ModuleGraph::LoopCandidate const &c, uptr vmem);

// Declare EVERY candidate's header before emitting ANY body, then emit each in candidate order.
//
// The two phases matter for the same reason `DeclareKnownRegionEntries` runs before the stock
// translate loop: an exit from one selected loop to another selected loop's header lowers as a
// direct AOT-to-AOT call only if the callee's `llvm::Function` already exists when the caller's
// `gbr` is lowered. Emitting as we go would make that depend on candidate order.
std::vector<LoopRegionResult> EmitLoopRegions(qir::LLVMGenCtx *ctx, ModuleGraph &mg, MemArena *arena,
					      std::vector<ModuleGraph::LoopCandidate> const &cands, uptr vmem);

} // namespace dbt
