#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/qmc/qir_printer.h"
#include "dbt/execute.h"

namespace dbt::qcg
{

struct QSel {
	QSel(qir::Region *region_, MachineRegionInfo *region_info_)
	    : region(region_), region_info(region_info_)
	{
	}

	void Run();

	void SelectOperands(qir::Inst *ins);

	void merge_vmload2(qir::Block& bb);
	void merge_vmload4(qir::Block& bb);
	void merge_vmstore2(qir::Block& bb);
	void merge_vmstore4(qir::Block& bb);
	void merge_mov_store_mov_add_store(qir::Block& bb);

	qir::Region *region{};
	qir::Builder qb{nullptr};
	MachineRegionInfo *region_info{};
};

void QSel::SelectOperands(qir::Inst *ins)
{
	auto *op_ct = GetOpInfo(ins->GetOpcode()).ra_ct;
	assert(op_ct);
	auto srcl = ins->inputs();
	auto dstl = ins->outputs();
	auto src_n = srcl.size();
	auto dst_n = dstl.size();
	// satisfy aliases
	for (u8 i = 0; i < src_n; ++i) {
		auto &ct = op_ct[dst_n + i];
		if (!ct.has_alias) {
			continue;
		}
		auto *src = &srcl[i];
		auto *dst = &dstl[ct.alias];
		assert(dst->IsVGPR());
		if (src->IsVGPR() && src->GetVGPR() == dst->GetVGPR()) {
			continue;
		}

		bool live_input = false;
		for (u8 k = 0; k < src_n; ++k) {
			auto *src2 = &srcl[k];
			if (k != i && src2->IsVGPR() && src2->GetVGPR() == dst->GetVGPR()) {
				live_input = true;
				break;
			}
		}
		if (live_input) {
			auto tmp = qir::VOperand::MakeVGPR(dst->GetType(), qb.CreateVGPR(dst->GetType()));
			qb.Create_mov(tmp, *dst);
			for (u8 k = 0; k < src_n; ++k) {
				auto *src2 = &srcl[k];
				if (k != i && src2->IsVGPR() && src2->GetVGPR() == dst->GetVGPR()) {
					*src2 = tmp;
				}
			}
		}
		qb.Create_mov(*dst, *src);
		*src = *dst;
	}
	// lower constants
	for (u8 i = 0; i < src_n; ++i) {
		auto &ct = op_ct[dst_n + i];
		auto *src = &srcl[i];
		if (!src->IsConst()) {
			continue;
		}
		auto type = src->GetType();
		auto val = src->GetConst();
		if (ct.ci != RACtImm::NO && ArchTraits::match_gp_const(type, val, ct.ci)) {
			continue;
		}
		auto tmp = qir::VOperand::MakeVGPR(type, qb.CreateVGPR(type));
		qb.Create_mov(tmp, *src);
		*src = tmp;
	}
}

struct QSelVisitor : qir::InstVisitor<QSelVisitor, void> {
	using Base = qir::InstVisitor<QSelVisitor, void>;

public:
	QSelVisitor(QSel *sel_) : sel(sel_) {}

	void visitInst(qir::Inst *ins)
	{
		Panic(std::string("QSel: unhandled QIR instruction: ") +
		      qir::GetOpNameStr(ins->GetOpcode()));
	}

	void visitInstUnop(qir::InstUnop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstBinop(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstSetcc(qir::InstSetcc *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstBr(qir::InstBr *ins) {}

	void visitInstBrcc(qir::InstBrcc *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstGBr(qir::InstGBr *ins) {}

	void visitInstGBrind(qir::InstGBrind *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstVMLoad(qir::InstVMLoad *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstVMStore(qir::InstVMStore *ins)
	{
		sel->SelectOperands(ins);
	}
	
	void visitInstVMLoad2(qir::InstVMLoad2 *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstVMLoad4(qir::InstVMLoad4 *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstVMStore2(qir::InstVMStore2 *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstVMStore4(qir::InstVMStore4 *ins)
	{
		sel->SelectOperands(ins);
	}

	void visitInstHcall(qir::InstHcall *ins) {}

	// No QIR operands to select: every input is a translation-time constant and the vector data
	// is addressed directly off the state register.
	void visitInstRVVAddV(qir::InstRVVAddV *ins) {}
	void visitInstCCRFChunk(qir::InstCCRFChunk *ins) {}
	void visitInstCCRFComputeRegion(qir::InstCCRFComputeRegion *ins) {}

	// Same: the diagnostic chunk control arm carries only translation-time constants and has no
	// operands to select (see the block comment on InstRVVDiagChunkBegin in qir.h).
	void visitInstRVVDiagChunkBegin(qir::InstRVVDiagChunkBegin *ins) {}
	void visitInstRVVDiagChunkAdd(qir::InstRVVDiagChunkAdd *ins) {}
	void visitInstRVVDiagChunkEnd(qir::InstRVVDiagChunkEnd *ins) {}

	// Same for the typed group's frame: begin/end carry only translation-time constants. The
	// typed BODY between them does go through ordinary selection, above.
	void visitInstRVVTypedChunkBegin(qir::InstRVVTypedChunkBegin *ins) {}
	void visitInstRVVTypedChunkEnd(qir::InstRVVTypedChunkEnd *ins) {}

	// Typed V512 chunk ops, in contrast, DO carry operands and go through the ordinary selection.
	// Both of its jobs are well defined here: the alias loop is inert (none of the three tables
	// has an alias, because EVEX's destination is independent of its sources), and the constant
	// loop can only ever fire on the I32 address of a load/store -- a V512 operand has no constant
	// form to lower.
	void visitInstVChunkLoad(qir::InstVChunkLoad *ins)
	{
		sel->SelectOperands(ins);
	}
	void visitInstVChunkAdd(qir::InstVChunkAdd *ins)
	{
		sel->SelectOperands(ins);
	}
	void visitInstVChunkMul(qir::InstVChunkMul *ins)
	{
		sel->SelectOperands(ins);
	}
	// SelectOperands never permutes an instruction's inputs -- it only rewrites an operand in
	// place -- so routing the subtract through the same path cannot disturb the minuend/subtrahend
	// order the emitter depends on.
	void visitInstVChunkSub(qir::InstVChunkSub *ins)
	{
		sel->SelectOperands(ins);
	}
	// Same path again. Nothing here inspects the operation, so a bitwise body op is selected
	// exactly as the three arithmetic ones are.
	void visitInstVChunkXor(qir::InstVChunkXor *ins)
	{
		sel->SelectOperands(ins);
	}
	// And the second bitwise body op, on the same path. The visitor is per-opcode, so the only
	// thing keeping the or and the xor apart at this stage is that they ARE different opcodes.
	void visitInstVChunkOr(qir::InstVChunkOr *ins)
	{
		sel->SelectOperands(ins);
	}
	// And the third bitwise body op, on the same path. Three visitors with identical bodies is
	// exactly what "one opcode per host instruction" costs here, and it is the price of having the
	// operation be a NODE TYPE that dispatch can see rather than a field it cannot.
	void visitInstVChunkAnd(qir::InstVChunkAnd *ins)
	{
		sel->SelectOperands(ins);
	}
	// P7N-B. Same path once more. These two are the first chunk ALU ops with ONE source, and
	// nothing here notices: SelectOperands walks the operand arrays the node declares, and the
	// shift amount is a field rather than an operand, so there is nothing for it to select.
	void visitInstVChunkSll(qir::InstVChunkSll *ins)
	{
		sel->SelectOperands(ins);
	}
	void visitInstVChunkSrl(qir::InstVChunkSrl *ins)
	{
		sel->SelectOperands(ins);
	}
	void visitInstVChunkStore(qir::InstVChunkStore *ins)
	{
		sel->SelectOperands(ins);
	}

	// vstatechunkload has one output and no inputs, so both of SelectOperands' loops are empty for
	// it. It still goes through the ordinary path rather than being stubbed out: the call is what
	// asserts the op has a constraint table (arch_traits.cpp CT(r)), and a stub here would be a
	// second, silently diverging definition of "this op needs no selection".
	void visitInstVStateChunkLoad(qir::InstVStateChunkLoad *ins)
	{
		sel->SelectOperands(ins);
	}

	// Mirror image, and for the same reason: one V512 input, no output, so both of SelectOperands'
	// loops are empty -- the alias loop because CT(rin) declares none, the constant loop because a
	// V512 operand has no constant form. The call is still what asserts the op has a table.
	void visitInstVStateChunkStore(qir::InstVStateChunkStore *ins)
	{
		sel->SelectOperands(ins);
	}

	// Native-3. Same shape as vstatechunkload -- one V512 output, no inputs -- so both of
	// SelectOperands' loops are empty for it, and the call is here for that op's reason: it is
	// what asserts this opcode has a constraint table (arch_traits.cpp CT(r)).
	void visitInstVChunkBroadcast(qir::InstVChunkBroadcast *ins)
	{
		sel->SelectOperands(ins);
	}
	void visitInstVChunkFBroadcast(qir::InstVChunkFBroadcast *ins) { sel->SelectOperands(ins); }
	void visitInstVChunkFALU(qir::InstVChunkFALU *ins) { sel->SelectOperands(ins); }
	void visitInstVChunkDep(qir::InstVChunkDep *ins) { sel->SelectOperands(ins); }
	void visitInstVChunkMaskSet(qir::InstVChunkMaskSet *ins) {}
	// S1-1: no operands, so nothing to select -- the same entry vchunkmaskset has, and present for
	// the same reason: the visitor's default is a silent no-op, so an omission would not be a
	// compile error.
	void visitInstVChunkActive(qir::InstVChunkActive *ins) {}
	void visitInstVChunkPartialAlu(qir::InstVChunkPartialAlu *ins) {}
	void visitInstVMaskLogic(qir::InstVMaskLogic *) {}
	void visitInstVMaskScalar(qir::InstVMaskScalar *) {}
	void visitInstVMaskIota(qir::InstVMaskIota *) {}
	void visitInstVScalarMove(qir::InstVScalarMove *) {}
	void visitInstVCompress(qir::InstVCompress *) {}
	void visitInstVReduce(qir::InstVReduce *) {}
	void visitInstVChunkIndex(qir::InstVChunkIndex *) {}
	void visitInstVChunkFClass(qir::InstVChunkFClass *) {}
	void visitInstVChunkIToF(qir::InstVChunkIToF *) {}
	void visitInstVChunkFToI(qir::InstVChunkFToI *) {}
	void visitInstVChunkFToF(qir::InstVChunkFToF *) {}
	void visitInstVGather(qir::InstVGather *) {}
	void visitInstVFEstimate(qir::InstVFEstimate *) {}
	void visitInstVMemory(qir::InstVMemory *) {}
	void visitInstVWholeMove(qir::InstVWholeMove *) {}
	void visitInstVFReduce(qir::InstVFReduce *) {}
	void visitInstVMaskPrefix(qir::InstVMaskPrefix *) {}
	void visitInstVChunkExtend(qir::InstVChunkExtend *) {}
	void visitInstVChunkWiden(qir::InstVChunkWiden *) {}
	void visitInstVChunkNarrowShift(qir::InstVChunkNarrowShift *) {}
	void visitInstRVVTypedChunkPartial(qir::InstRVVTypedChunkPartial *ins) {}
	void visitInstRVVRunScalar(qir::InstRVVRunScalar *) {}
	// P7I. The fused three-input form takes the same ordinary path. It needs the visitor entry
	// as much as any other node: the base visitInst is `unreachable("")`, so a missing case is
	// not a compile error and not a Panic -- in a release build it is undefined behaviour that
	// crashes somewhere else entirely. Both of SelectOperands' loops are inert here for the
	// reason stated above the chunk ops: CT(vchunkfma, r_r_r_r) declares no alias, and a V512
	// operand has no constant form to lower.
	void visitInstVChunkFMA(qir::InstVChunkFMA *ins) { sel->SelectOperands(ins); }
	// P8. The one-source FP form, and it needs its entry for exactly the reason stated above the
	// fused one: the base visitInst is unreachable(), so a missing case is not a compile error --
	// it is a Panic here in a debug build and undefined behaviour elsewhere in a release build.
	// CT(vchunkfsqrt, r_r) declares no alias and a V512 operand has no constant form, so both of
	// SelectOperands' loops are inert; the call is what asserts the opcode has a table at all.
	void visitInstVChunkFSqrt(qir::InstVChunkFSqrt *ins) { sel->SelectOperands(ins); }
	// P9. The mask-producing compare. Zero outputs, so SelectOperands' alias loop has nothing to
	// do, and CT(vchunkfcmpstate, rin_r) declares no immediate form, so its constant loop is
	// inert as well; the call is what asserts the opcode has a table at all.
	void visitInstVChunkFCmpState(qir::InstVChunkFCmpState *ins) { sel->SelectOperands(ins); }
	// P10. The widening convert; required for the reason the entries above give (the base
	// visitInst is unreachable, so a missing case is undefined behaviour, not a diagnostic).
	void visitInstVChunkFWidenCvt(qir::InstVChunkFWidenCvt *ins) { sel->SelectOperands(ins); }
	void visitInstRVVQCGFPBegin(qir::InstRVVQCGFPBegin *) {}
	void visitInstRVVQCGFPEnd(qir::InstRVVQCGFPEnd *) {}

	// S2.9. Ordinary operand legalisation, and the call is doing real work here rather than being
	// a formality: CT(rvvsetvl, r_r) declares the input register-only, so THIS is the pass that
	// materialises a constant AVL into a register before the emitter -- whose `cmp`/`cmov` pair
	// has no immediate-source encoding -- can ever see one. The alias loop is empty because the
	// table declares no ALIAS: the output and the input are independent, which is what lets the
	// emitter own its own `rd == rs1` correctness rather than depending on allocator behaviour.
	void visitInstRVVSetVL(qir::InstRVVSetVL *ins)
	{
		sel->SelectOperands(ins);
	}
	void visitInstRVVSetVLReg(qir::InstRVVSetVLReg *ins) { sel->SelectOperands(ins); }

#define RVV_SSA_QSEL_VISITOR(cls) void visit##cls(qir::cls *ins) {}
	RVV_SSA_QSEL_VISITOR(InstRVVRead)
	RVV_SSA_QSEL_VISITOR(InstRVVWrite)
	RVV_SSA_QSEL_VISITOR(InstRVVSplatF)
	RVV_SSA_QSEL_VISITOR(InstRVVLoad)
	RVV_SSA_QSEL_VISITOR(InstRVVStore)
	RVV_SSA_QSEL_VISITOR(InstRVVFCmp)
	RVV_SSA_QSEL_VISITOR(InstRVVMerge)
	RVV_SSA_QSEL_VISITOR(InstRVVFALU)
	RVV_SSA_QSEL_VISITOR(InstRVVFMA)
	RVV_SSA_QSEL_VISITOR(InstRVVFPBegin)
	RVV_SSA_QSEL_VISITOR(InstRVVFPEnd)
#undef RVV_SSA_QSEL_VISITOR

	void visit_sll(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_srl(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_sra(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}
	// TODO: maybe remove these?
	void visit_mul(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_mulh(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_mulhsu(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_mulhu(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}
	
	void visit_div(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}
	
	void visit_divu(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_rem(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

	void visit_remu(qir::InstBinop *ins)
	{
		sel->SelectOperands(ins);
	}

private:
	QSel *sel{};
};

void QSel::Run()
{
	for (auto &bb : region->GetBlocks()) {
		// TODO: refactor below functions and impl them in llvm emit_vmload2, ..., etc.
		// 		However, below code is correct and works in jit mode
		if (dbt::config::merge_ls) {
			merge_vmload4(bb);
			merge_vmload2(bb);
			merge_vmstore4(bb);
			merge_vmstore2(bb); 
			merge_mov_store_mov_add_store(bb);
		}
		
		// Then proceed with normal instruction selection
		auto &ilist = bb.ilist;
		for (auto iit = ilist.begin(); iit != ilist.end(); ++iit) {
			qb = qir::Builder(&bb, iit);
			QSelVisitor(this).visit(&*iit);
			
			if (iit->GetFlags() & qir::Inst::HAS_CALLS) {
				region_info->has_calls = true;
			}
		}
	}
}
void QSel::merge_vmload4(qir::Block& bb) {
	log_qcg("merge_vmload4");
	for (auto iit = bb.ilist.begin(); iit != bb.ilist.end(); ++iit) {
		auto curr = iit;
		if (curr->GetOpcode() != qir::Op::_mov)
			continue;
		auto next = std::next(iit);
		if (next == bb.ilist.end() || next->GetOpcode() != qir::Op::_add)
			continue;
		auto next2 = std::next(next);
		if (next2 == bb.ilist.end() || next2->GetOpcode() != qir::Op::_vmload)
			continue;
		auto next3 = std::next(next2);
		if (next3 == bb.ilist.end() || next3->GetOpcode() != qir::Op::_mov)
			continue;
		auto next4 = std::next(next3);
		if (next4 == bb.ilist.end() || next4->GetOpcode() != qir::Op::_add)
			continue;
		auto next5 = std::next(next4);
		if (next5 == bb.ilist.end() || next5->GetOpcode() != qir::Op::_vmload)
			continue;
		auto next6 = std::next(next5);
		if (next6 == bb.ilist.end() || next6->GetOpcode() != qir::Op::_mov)
			continue;
		auto next7 = std::next(next6);
		if (next7 == bb.ilist.end() || next7->GetOpcode() != qir::Op::_add)
			continue;
		auto next8 = std::next(next7);
		if (next8 == bb.ilist.end() || next8->GetOpcode() != qir::Op::_vmload)
			continue;
		auto next9 = std::next(next8);
		if (next9 == bb.ilist.end() || next9->GetOpcode() != qir::Op::_mov)
			continue;
		auto next10 = std::next(next9);
		if (next10 == bb.ilist.end() || next10->GetOpcode() != qir::Op::_add)
			continue;
		auto next11 = std::next(next10);
		if (next11 == bb.ilist.end() || next11->GetOpcode() != qir::Op::_vmload)
			continue;
			
		// Check for mov+add+vmstore pattern
		auto* add1 = static_cast<qir::InstBinop*>(&*next);
		auto* load1 = static_cast<qir::InstVMLoad*>(&*next2);
		auto* mov2 = static_cast<qir::InstUnop*>(&*next3);
		auto* add2 = static_cast<qir::InstBinop*>(&*next4);
		auto* load2 = static_cast<qir::InstVMLoad*>(&*next5);
		auto* mov3 = static_cast<qir::InstUnop*>(&*next6);
		auto* add3 = static_cast<qir::InstBinop*>(&*next7);
		auto* load3 = static_cast<qir::InstVMLoad*>(&*next8);
		auto* mov4 = static_cast<qir::InstUnop*>(&*next9);
		auto* add4 = static_cast<qir::InstBinop*>(&*next10);
		auto* load4 = static_cast<qir::InstVMLoad*>(&*next11);
		// Verify patterns match and are consecutive stores
		if (add1->i(0).GetVGPR() == add2->i(0).GetVGPR() &&  // Same base register
			add2->i(0).GetVGPR() == add3->i(0).GetVGPR() &&
			add3->i(0).GetVGPR() == add4->i(0).GetVGPR() &&
			add1->i(1).IsConst() && add2->i(1).IsConst() && add3->i(1).IsConst() && add4->i(1).IsConst() &&
			add2->i(1).GetConst() == add1->i(1).GetConst() + 4 &&
			add3->i(1).GetConst() == add2->i(1).GetConst() + 4 &&
			add4->i(1).GetConst() == add3->i(1).GetConst() + 4) {  // Sequential offsets
			log_qcg("merge_vmload4: found pattern");
			// Remove original instructions
			qir::InstVMLoad4* vmload4 = bb.GetRegion()->Create<qir::InstVMLoad4>(
				qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
				qir::VType::I32,      // Then the rest of the arguments
				qir::VSign::U,
				load1->o(0),
				load2->o(0),
				load3->o(0),
				load4->o(0),
				add1->o(0)
			);
			bb.ilist.insert(load4, vmload4);
			bb.ilist.erase(load1);
			bb.ilist.erase(load2);
			bb.ilist.erase(load3);
			bb.ilist.erase(load4);
			bb.ilist.erase(add2);
			bb.ilist.erase(add3);
			bb.ilist.erase(add4);
			bb.ilist.erase(mov2);
			bb.ilist.erase(mov3);
			bb.ilist.erase(mov4);
		}
	}
}

void QSel::merge_vmload2(qir::Block& bb) {
	log_qcg("merge_vmload2");
	for (auto iit = bb.ilist.begin(); iit != bb.ilist.end(); ++iit) {
		auto curr = iit;
		if (curr->GetOpcode() != qir::Op::_mov)
			continue;
		auto next = std::next(iit);
		if (next == bb.ilist.end() || next->GetOpcode() != qir::Op::_add)
			continue;
		auto next2 = std::next(next);
		if (next2 == bb.ilist.end() || next2->GetOpcode() != qir::Op::_vmload)
			continue;
		auto next3 = std::next(next2);
		if (next3 == bb.ilist.end() || next3->GetOpcode() != qir::Op::_mov)
			continue;
		auto next4 = std::next(next3);
		if (next4 == bb.ilist.end() || next4->GetOpcode() != qir::Op::_add)
			continue;
		auto next5 = std::next(next4);
		if (next5 == bb.ilist.end() || next5->GetOpcode() != qir::Op::_vmload)
			continue;
		// Check for mov+add+vmstore pattern
		auto* add1 = static_cast<qir::InstBinop*>(&*next);
		auto* load1 = static_cast<qir::InstVMLoad*>(&*next2);
		auto* mov2 = static_cast<qir::InstUnop*>(&*next3);
		auto* add2 = static_cast<qir::InstBinop*>(&*next4);
		auto* load2 = static_cast<qir::InstVMLoad*>(&*next5);
		// Verify patterns match and are consecutive stores
		if (add1->i(0).GetVGPR() == add2->i(0).GetVGPR() &&  // Same base register
			add1->i(1).IsConst() && add2->i(1).IsConst() &&
			add2->i(1).GetConst() == add1->i(1).GetConst() + 4) {  // Sequential offsets
			log_qcg("merge_vmload2: found pattern");
			// Remove original instructions
			qir::InstVMLoad2* vmload2 = bb.GetRegion()->Create<qir::InstVMLoad2>(
				qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
				qir::VType::I32,      // Then the rest of the arguments
				qir::VSign::U,
				load1->o(0),
				load2->o(0),
				add1->o(0)
			);
			bb.ilist.insert(load2, vmload2);
			bb.ilist.erase(load1);
			bb.ilist.erase(load2);
			bb.ilist.erase(add2);
			bb.ilist.erase(mov2);
		}
	}
}

void QSel::merge_mov_store_mov_add_store(qir::Block& bb) {
	for (auto iit = bb.ilist.begin(); iit != bb.ilist.end(); ++iit) {
		auto curr = iit;
		if (curr->GetOpcode() != qir::Op::_mov)
			continue;
		auto next = std::next(iit);
		if (next == bb.ilist.end() || next->GetOpcode() != qir::Op::_vmstore)
			continue;
		auto next2 = std::next(next);
		if (next2 == bb.ilist.end() || next2->GetOpcode() != qir::Op::_mov)
			continue;
		auto next3 = std::next(next2);
		if (next3 == bb.ilist.end() || next3->GetOpcode() != qir::Op::_add)
			continue;
		auto next4 = std::next(next3);
		if (next4 == bb.ilist.end() || next4->GetOpcode() != qir::Op::_vmstore)
			continue;
		// Check for mov+add+vmstore pattern
		auto* store1 = static_cast<qir::InstVMStore*>(&*next);
		auto* mov2 = static_cast<qir::InstUnop*>(&*next2);
		auto* add2 = static_cast<qir::InstBinop*>(&*next3);
		auto* store2 = static_cast<qir::InstVMStore*>(&*next4);
		// Verify patterns match and are consecutive stores
		if (store1->sz == qir::VType::I32 && store2->sz == qir::VType::I32 &&
			store1->i(0).GetVGPR() == add2->i(0).GetVGPR() &&
			add2->i(1).IsConst() ){
			if (add2->i(1).GetConst() == -4) {  // Sequential offsets
				qir::InstVMStore2* vmstore2 = bb.GetRegion()->Create<qir::InstVMStore2>(
					qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
					qir::VType::I32,      // Then the rest of the arguments
					qir::VSign::U,
					store1->i(0), 
					store2->i(1),
					store1->i(1)
				);
				bb.ilist.insert(store2, vmstore2);
				bb.ilist.erase(store1);
				bb.ilist.erase(store2);
				bb.ilist.erase(add2);
				bb.ilist.erase(mov2);
			} else if (add2->i(1).GetConst() == 4) {
				qir::InstVMStore2* vmstore2 = bb.GetRegion()->Create<qir::InstVMStore2>(
					qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
					qir::VType::I32,      // Then the rest of the arguments
					qir::VSign::U,
					store1->i(0), 
					store1->i(1),
					store2->i(1)
				);
				bb.ilist.insert(store2, vmstore2);
				bb.ilist.erase(store1);
				bb.ilist.erase(store2);
				bb.ilist.erase(add2);
				bb.ilist.erase(mov2);
			}
		}
	}
}

void QSel::merge_vmstore2(qir::Block& bb) {
	for (auto iit = bb.ilist.begin(); iit != bb.ilist.end(); ++iit) {
		auto curr = iit;
		if (curr->GetOpcode() != qir::Op::_mov)
			continue;
		auto next = std::next(iit);
		if (next == bb.ilist.end() || next->GetOpcode() != qir::Op::_add)
			continue;
		auto next2 = std::next(next);
		if (next2 == bb.ilist.end() || next2->GetOpcode() != qir::Op::_vmstore)
			continue;
		auto next3 = std::next(next2);
		if (next3 == bb.ilist.end() || next3->GetOpcode() != qir::Op::_mov)
			continue;
		auto next4 = std::next(next3);
		if (next4 == bb.ilist.end() || next4->GetOpcode() != qir::Op::_add)
			continue;
		auto next5 = std::next(next4);
		if (next5 == bb.ilist.end() || next5->GetOpcode() != qir::Op::_vmstore)
			continue;
		// Check for mov+add+vmstore pattern
		auto* add1 = static_cast<qir::InstBinop*>(&*next);
		auto* store1 = static_cast<qir::InstVMStore*>(&*next2);
		auto* mov2 = static_cast<qir::InstUnop*>(&*next3);
		auto* add2 = static_cast<qir::InstBinop*>(&*next4);
		auto* store2 = static_cast<qir::InstVMStore*>(&*next5);
		// Verify patterns match and are consecutive stores
		if (store1->sz == qir::VType::I32 && store2->sz == qir::VType::I32 &&
			add1->i(0).GetVGPR() == add2->i(0).GetVGPR() &&  // Same base register
			add1->i(1).IsConst() && add2->i(1).IsConst() ){
			if (add2->i(1).GetConst() == add1->i(1).GetConst() - 4) {  // Sequential offsets
				qir::InstVMStore2* vmstore2 = bb.GetRegion()->Create<qir::InstVMStore2>(
					qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
					qir::VType::I32,      // Then the rest of the arguments
					qir::VSign::U,
					add2->o(0), 
					store2->i(1),
					store1->i(1)
				);
				bb.ilist.insert(store2, vmstore2);
				bb.ilist.erase(store1);
				bb.ilist.erase(store2);
				bb.ilist.erase(add1);
				bb.ilist.erase(mov2);
			} else if (add2->i(1).GetConst() == add1->i(1).GetConst() + 4) {  // Sequential offsets
				qir::InstVMStore2* vmstore2 = bb.GetRegion()->Create<qir::InstVMStore2>(
					qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
					qir::VType::I32,      // Then the rest of the arguments
					qir::VSign::U,
					add1->o(0), 
					store1->i(1),
					store2->i(1)
				);
				bb.ilist.insert(store2, vmstore2);
				bb.ilist.erase(store1);
				bb.ilist.erase(store2);
				bb.ilist.erase(add2);
				bb.ilist.erase(mov2);
			}
		}
	}
}

void QSel::merge_vmstore4(qir::Block& bb) {
	log_qcg("merge_vmstore4");
	for (auto iit = bb.ilist.begin(); iit != bb.ilist.end(); ++iit) {
		auto curr = iit;
		if (curr->GetOpcode() != qir::Op::_mov)
			continue;
		auto next = std::next(iit);
		if (next == bb.ilist.end() || next->GetOpcode() != qir::Op::_add)
			continue;
		auto next2 = std::next(next);
		if (next2 == bb.ilist.end() || next2->GetOpcode() != qir::Op::_vmstore)
			continue;
		auto next3 = std::next(next2);
		if (next3 == bb.ilist.end() || next3->GetOpcode() != qir::Op::_mov)
			continue;
		auto next4 = std::next(next3);
		if (next4 == bb.ilist.end() || next4->GetOpcode() != qir::Op::_add)
			continue;
		auto next5 = std::next(next4);
		if (next5 == bb.ilist.end() || next5->GetOpcode() != qir::Op::_vmstore)
			continue;
		auto next6 = std::next(next5);
		if (next6 == bb.ilist.end() || next6->GetOpcode() != qir::Op::_mov)
			continue;
		auto next7 = std::next(next6);
		if (next7 == bb.ilist.end() || next7->GetOpcode() != qir::Op::_add)
			continue;
		auto next8 = std::next(next7);
		if (next8 == bb.ilist.end() || next8->GetOpcode() != qir::Op::_vmstore)
			continue;
		auto next9 = std::next(next8);
		if (next9 != bb.ilist.end() && next9->GetOpcode() != qir::Op::_mov)
			continue;
		auto next10 = std::next(next9);
		if (next10 != bb.ilist.end() && next10->GetOpcode() != qir::Op::_add)
			continue;
		auto next11 = std::next(next10);
		if (next11 != bb.ilist.end() && next11->GetOpcode() != qir::Op::_vmstore)
			continue;
		// Check for mov+add+vmstore pattern
		auto* add1 = static_cast<qir::InstBinop*>(&*next);
		auto* store1 = static_cast<qir::InstVMStore*>(&*next2);
		auto* mov2 = static_cast<qir::InstUnop*>(&*next3);
		auto* add2 = static_cast<qir::InstBinop*>(&*next4);
		auto* store2 = static_cast<qir::InstVMStore*>(&*next5);
		auto* mov3 = static_cast<qir::InstUnop*>(&*next6);
		auto* add3 = static_cast<qir::InstBinop*>(&*next7);
		auto* store3 = static_cast<qir::InstVMStore*>(&*next8);
		auto* mov4 = static_cast<qir::InstUnop*>(&*next9);
		auto* add4 = static_cast<qir::InstBinop*>(&*next10);
		auto* store4 = static_cast<qir::InstVMStore*>(&*next11);
		// Verify patterns match and are consecutive stores
		if (store1->sz == qir::VType::I32 && store2->sz == qir::VType::I32 &&
			store2->sz == qir::VType::I32 && store3->sz == qir::VType::I32 &&
			add1->i(0).GetVGPR() == add2->i(0).GetVGPR() &&
			add2->i(0).GetVGPR() == add3->i(0).GetVGPR() &&
			add3->i(0).GetVGPR() == add4->i(0).GetVGPR() &&
			add1->i(1).IsConst() && add2->i(1).IsConst() && add3->i(1).IsConst() && add4->i(1).IsConst() &&
			add2->i(1).GetConst() == add1->i(1).GetConst() - 4 &&
			add3->i(1).GetConst() == add2->i(1).GetConst() - 4 &&
			add4->i(1).GetConst() == add3->i(1).GetConst() - 4) {
			log_qcg("merge_vmstore4: found negative pattern");
			// Remove original instructions
			qir::InstVMStore4* vmstore4 = bb.GetRegion()->Create<qir::InstVMStore4>(
				qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
				qir::VType::I32,      // Then the rest of the arguments
				qir::VSign::U,
				add4->o(0), 
				store4->i(1),
				store3->i(1),
				store2->i(1),
				store1->i(1)
			);
			bb.ilist.insert(store4, vmstore4);
			bb.ilist.erase(store1);
			bb.ilist.erase(store2);
			bb.ilist.erase(store3);
			bb.ilist.erase(store4);
			bb.ilist.erase(add1);
			bb.ilist.erase(add2);
			bb.ilist.erase(add3);
			bb.ilist.erase(mov2);
			bb.ilist.erase(mov3);
			bb.ilist.erase(mov4);
		} else if (store1->sz == qir::VType::I32 && store2->sz == qir::VType::I32 &&
			store2->sz == qir::VType::I32 && store3->sz == qir::VType::I32 &&
			add1->i(0).GetVGPR() == add2->i(0).GetVGPR() &&
			add2->i(0).GetVGPR() == add3->i(0).GetVGPR() &&
			add3->i(0).GetVGPR() == add4->i(0).GetVGPR() &&
			add1->i(1).IsConst() && add2->i(1).IsConst() && add3->i(1).IsConst() && add4->i(1).IsConst() &&
			add2->i(1).GetConst() == add1->i(1).GetConst() + 4 &&
			add3->i(1).GetConst() == add2->i(1).GetConst() + 4 &&
			add4->i(1).GetConst() == add3->i(1).GetConst() + 4) {
			log_qcg("merge_vmstore4: found positive pattern");
			// Remove original instructions
			qir::InstVMStore4* vmstore4 = bb.GetRegion()->Create<qir::InstVMStore4>(
				qir::Inst::Flags(qir::Inst::SIDEEFF),  // First argument must be flags
				qir::VType::I32,      // Then the rest of the arguments
				qir::VSign::U,
				add1->o(0), 
				store1->i(1),
				store2->i(1),
				store3->i(1),
				store4->i(1)
			);
			bb.ilist.insert(store4, vmstore4);
			bb.ilist.erase(store1);
			bb.ilist.erase(store2);
			bb.ilist.erase(store3);
			bb.ilist.erase(store4);
			bb.ilist.erase(add4);
			bb.ilist.erase(add2);
			bb.ilist.erase(add3);
			bb.ilist.erase(mov2);
			bb.ilist.erase(mov3);
			bb.ilist.erase(mov4);
		}
	}
}

void QSelPass::run(qir::Region *region, MachineRegionInfo *region_info)
{
	QSel sel(region, region_info);
	sel.Run();
}

} // namespace dbt::qcg
