#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/qemit.h"
#include "dbt/qmc/qir_printer.h"
#include "dbt/config.h"
#include <optional>
#include <time.h>

namespace dbt::qcg
{
static inline unsigned long long now_ns()
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (unsigned long long)t.tv_sec * 1000000000ull + t.tv_nsec;
}

struct QCodegen {
	QCodegen(qir::Region *region_, QEmit *ce_) : region(region_), ce(ce_) {}

	void Run(u32 ip);

private:
	qir::Region *region;
	QEmit *ce;

	friend struct QCodegenVisitor;
};

std::span<u8> GenerateCode(CompilerRuntime *cruntime, qir::CodeSegment *segment, qir::Region *r, u32 ip)
{
	ArchTraits::init();
	MachineRegionInfo mregion_info;

	bool prof = dbt::config::measure_translation;
	unsigned long long t0 = prof ? now_ns() : 0;
	QSelPass::run(r, &mregion_info);
	if (prof) { auto t = now_ns(); dbt::config::g_qsel_ns += t - t0; t0 = t; }
	qir::PrinterPass::run(log_qcg, "IR dump after QSelPass", r);

	QRegAllocPass::run(r);
	if (prof) { auto t = now_ns(); dbt::config::g_qra_ns += t - t0; t0 = t; }
	qir::PrinterPass::run(log_qcg, "IR dump after QRegAllocPass", r);

	log_qcg("Emit machine instructions: reloc=%u is_leaf=%u", !cruntime->AllowsRelocation(),
		!mregion_info.has_calls);
	QEmit ce(r, cruntime, segment, !mregion_info.has_calls);
	QCodegen cg(r, &ce);
	cg.Run(ip);

	auto code = ce.EmitCode();
	if (prof) dbt::config::g_emit_ns += now_ns() - t0;
	QEmit::DumpCode(code);
	return code;
}

struct QCodegenVisitor : qir::InstVisitor<QCodegenVisitor, void> {
public:
	QCodegenVisitor(QCodegen *cg_) : cg(cg_) {}

	void visitInst(qir::Inst *ins)
	{
		unreachable("");
	}

#define OP(name, cls, flags)                                                                                 \
	void visit_##name(qir::cls *ins)                                                                     \
	{                                                                                                    \
		cg->ce->Emit_##name(ins);                                                                    \
	}
	QIR_OPS_LIST(OP)
#undef OP

private:
	QCodegen *cg{};
};

// These offset-carrying nodes derive their body mask before any observable
// effect. Only the actual first-element field is read; geometry is not rebuilt.
static std::optional<u32> BodyMaskBase(qir::Inst *node)
{
	switch (node->GetOpcode()) {
	case qir::Op::_vchunkpartialalu: {
		auto *alu = static_cast<qir::InstVChunkPartialAlu *>(node);
		if (alu->architectural_mask) return alu->element_base;
		return std::nullopt;
	}
#define MASK_NODE(op, type) case qir::Op::_##op: return static_cast<qir::type *>(node)->base;
	MASK_NODE(vchunkwiden, InstVChunkWiden)
	MASK_NODE(vchunkextend, InstVChunkExtend)
	MASK_NODE(vchunknarrowshift, InstVChunkNarrowShift)
	MASK_NODE(vchunkftoi, InstVChunkFToI)
	MASK_NODE(vchunkitof, InstVChunkIToF)
	MASK_NODE(vchunkftof, InstVChunkFToF)
#undef MASK_NODE
	default: return std::nullopt;
	}
}

void QCodegen::Run(u32 ip)
{
	ce->Prologue(ip);
	ce->EmitInstrSeenIncr(region->num_insns);
	// 2026-06-21 --qcg-pin: load the pinned guest registers ONCE here. The prologue runs on region entry only; the
	// loop backedge jumps to a block label after this, so loop-carried pinned regs stay resident across iterations
	// without a separate preheader block. Region exits / SIDEEFFs sync them back to CPUState (qra).
	for (u8 i = 0; i < region->n_pins; ++i)
		ce->StateFill(region->pins[i].preg, region->pins[i].type, region->pins[i].offs);
	QCodegenVisitor vis(this);

	for (auto &bb : region->GetBlocks()) {
		ce->SetBlock(&bb);
		auto &ilist = bb.ilist;
		for (auto iit = ilist.begin(); iit != ilist.end(); ++iit) {
			if (dbt::config::rvv_qcg_active_vl_mask_fusion &&
			    iit->GetOpcode() == qir::Op::_vchunkactive) {
				auto next = iit;
				++next;
				if (next != ilist.end() && next->GetOpcode() == qir::Op::_vchunkmaskset) {
					auto *bound = static_cast<qir::InstVChunkActive *>(&*iit);
					auto *mask = static_cast<qir::InstVChunkMaskSet *>(&*next);
					if (bound->chunk == mask->chunk &&
					    bound->element_base == (u32)mask->chunk * mask->lanes) {
						ce->EmitActiveMaskPair(bound, mask);
						iit = next;
						continue;
					}
				}
				if (next != ilist.end()) {
					auto *bound = static_cast<qir::InstVChunkActive *>(&*iit);
					auto base = BodyMaskBase(&*next);
					if (base && *base == bound->element_base) {
						ce->BeginBodyMaskPair(bound);
						vis.visit(&*next);
						ce->EndBodyMaskPair();
						iit = next;
						continue;
					}
				}
			}
			vis.visit(&*iit);
		}
	}
	// T5d2a3 (--loop-tier-side-exit): the cold exit blocks an intra-region backedge's notification
	// jumps to, emitted HERE -- after every basic block -- so that they never sit on a fall-through
	// path and the in-region branch layout above is byte-for-byte what it was. Emits nothing when
	// the mode is off, which is every ordinary run.
	ce->EmitDeferredSideExits();
}

} // namespace dbt::qcg
