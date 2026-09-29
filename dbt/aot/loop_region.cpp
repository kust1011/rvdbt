#include "dbt/aot/loop_region.h"
#include "dbt/qmc/compile.h"

namespace dbt
{

LoopRegionResult EmitLoopRegion(qir::LLVMGenCtx *ctx, ModuleGraph &mg, MemArena *arena,
				ModuleGraph::LoopCandidate const &c, uptr vmem)
{
	LoopRegionResult r;
	r.header_ip = c.header_ip;
	r.ranges = mg.LoopCandidateIpRanges(c);
	r.exits = mg.LoopCandidateExits(c);

	qir::CompilerJob::IpRangesSet ipranges(r.ranges.begin(), r.ranges.end());
	// `cruntime` is null on purpose. CompilerGenRegionIR only reads `job.iprange` and `job.vmem`;
	// the runtime is dereferenced by CompilerDoJob/CompilerGetCode (the JIT paths), and this path
	// calls neither -- it hands the QIR straight to the LLVM backend, exactly as the stock AOT
	// region loop does.
	qir::CompilerJob job(nullptr, vmem, mg.segment, std::move(ipranges));
	r.region = qir::CompilerGenRegionIR(arena, job);
	for ([[maybe_unused]] auto const &bb : r.region->GetBlocks())
		r.qir_blocks++;

	// merge_entries and internal_dispatch_targets are deliberately left empty: this function's
	// entry is the header itself, so there is no secondary entry to route to and no state->ip
	// switch to build. That is what makes the emitted entry a plain `br` into the header's block.
	qir::QIRToLLVM llvm_gen(*ctx, &mg.segment, r.region, c.header_ip);
	r.fn = llvm_gen.Run();
	return r;
}

std::vector<LoopRegionResult> EmitLoopRegions(qir::LLVMGenCtx *ctx, ModuleGraph &mg, MemArena *arena,
					      std::vector<ModuleGraph::LoopCandidate> const &cands, uptr vmem)
{
	for (auto const &c : cands)
		ctx->AddFunction(c.header_ip, mg.segment);
	std::vector<LoopRegionResult> out;
	out.reserve(cands.size());
	for (auto const &c : cands)
		out.push_back(EmitLoopRegion(ctx, mg, arena, c, vmem));
	return out;
}

} // namespace dbt
