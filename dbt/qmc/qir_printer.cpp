#include "dbt/qmc/qir_printer.h"
#include "dbt/config.h"
#include <sstream>

namespace dbt::qir
{

char const *const op_names[to_underlying(Op::Count)] = {
#define OP(name, cls, flags) [to_underlying(Op::_##name)] = #name,
    QIR_OPS_LIST(OP)
#undef OP
};

char const *const vtype_names[to_underlying(VType::Count)] = {
#define X(name, str) [to_underlying(VType::name)] = #str,
    X(UNDEF, invalid) X(I8, i8) X(I16, i16) X(I32, i32) X(V512, v512) X(MASK64, mask64)
		X(V128, v128) X(V256, v256)
#undef X
};

char const *const condcode_names[to_underlying(CondCode::Count)] = {
#define X(name, str) [to_underlying(CondCode::name)] = #str,
    X(EQ, eq) X(NE, ne) X(LE, le) X(LT, lt) X(GE, ge) X(GT, gt) X(LEU, leu) X(LTU, ltu) X(GEU, geu)
	X(GTU, gtu)
#undef X
};

char const *const runtime_stub_names[to_underlying(RuntimeStubId::Count)] = {
#define X(name) [to_underlying(RuntimeStubId::id_##name)] = #name,
    RUNTIME_STUBS(X)
#undef X
};

struct PrinterVisitor : InstVisitor<PrinterVisitor, void> {
private:
	void addsep()
	{
		ss << " ";
	}

	static constexpr char prop_sep = ':';

	void print(VType type)
	{
		ss << prop_sep;
		ss << GetVTypeNameStr(type);
	}

	void print(VSign sgn)
	{
		ss << prop_sep;
		ss << (sgn == VSign::U ? 'u' : 's');
	}

	void print(CondCode cc)
	{
		ss << prop_sep;
		ss << GetCondCodeNameStr(cc);
	}

	void print(VOperand o)
	{
		addsep();
		auto type = o.GetType();
		ss << "[";
		if (o.IsConst()) {
			ss << "$" << std::hex << o.GetConst() << std::dec;
		} else if (o.IsVGPR()) {
			auto vreg = o.GetVGPR();
			auto vinfo = region->GetVRegsInfo();
			if (vinfo->IsGlobal(vreg)) {
				ss << "@" << vinfo->GetGlobalInfo(vreg)->name;
			} else {
				ss << "%" << vreg;
			}
		} else if (o.IsPGPR()) {
			ss << "_" << o.GetPGPR();
		} else if (o.IsVVPR()) {
			// Vector vregs share the region's vreg index space with scalars but never its
			// physical file, so they are printed with a distinct sigil.
			ss << "%v" << o.GetVVPR();
		} else if (o.IsPVPR()) {
			ss << "_zmm" << o.GetPVPR();
		} else if (o.IsSlot()) {
			auto offs = o.GetSlotOffs();
			if (o.IsGSlot()) {
				ss << "g";
			} else {
				ss << "l";
			}
			ss << ":" << std::hex << offs << std::dec;
		} else if (o.IsBad()) {
			// The QIR dead-value pass clears unused fixed-shape RVV chunk
			// operands.  They are intentionally absent, not malformed IR.
			ss << "_";
		} else {
			unreachable("");
		}
		ss << "|" << GetVTypeNameStr(type) << "]";
	}

	void print(Block *b)
	{
		addsep();
		ss << "bb." << b->GetId();
	}

	void printName(Inst *ins)
	{
		ss << "    #" << ins->GetId() << " " << GetOpNameStr(ins->GetOpcode());
	}

	template <typename T>
	void printOperands(T *ins)
	{
		// TODO: iterators
		auto out = ins->outputs();
		for (u8 idx = 0; idx < out.size(); ++idx)
			print(out[idx]);
		auto in = ins->inputs();
		for (u8 idx = 0; idx < in.size(); ++idx)
			print(in[idx]);
	}

	Region *region;
	std::stringstream &ss;

public:
	PrinterVisitor(Region *region_, std::stringstream &ss_) : region(region_), ss(ss_) {}

	void visitInst(Inst *ins)
	{
		unreachable("");
	}

	void visitInstUnop(InstUnop *ins)
	{
		printName(ins);
		printOperands(ins);
	}

	void visitInstBinop(InstBinop *ins)
	{
		printName(ins);
		printOperands(ins);
	}

	void visitInstSetcc(InstSetcc *ins)
	{
		printName(ins);
		print(ins->cc);
		printOperands(ins);
	}

	void visitInstBr(InstBr *ins)
	{
		printName(ins);
	}

	void visitInstBrcc(InstBrcc *ins)
	{
		printName(ins);
		print(ins->cc);
		printOperands(ins);
	}

	void visitInstGBr(InstGBr *ins)
	{
		printName(ins);
		print(ins->tpc);
		// T5d-0: the backedge property is a decision made in the translator and consumed in the
		// emitter, with no other observable trace in QIR. Printing it is what lets a dumped region
		// be used as evidence for which edges a safepoint may appear on -- but ONLY on a run that
		// asked for the feature. With the flag off this token must not appear, because a dumped
		// region is output and "default off" means the output is the one a build without the
		// feature produced. Deleting every " backedge" token from a flag-on dump reproduces the
		// flag-off dump byte for byte; that is checked, not asserted.
		if (unlikely(dbt::config::qcg_backedge_safepoint) && ins->backedge) {
			ss << " backedge";
		}
	}

	void visitInstGBrind(InstGBrind *ins)
	{
		printName(ins);
		printOperands(ins);
	}

	void visitInstVMLoad(InstVMLoad *ins)
	{
		printName(ins);
		print(ins->sz);
		print(ins->sgn);
		printOperands(ins);
	}

	void visitInstVMStore(InstVMStore *ins)
	{
		printName(ins);
		print(ins->sz);
		print(ins->sgn);
		printOperands(ins);
	}

	void visitInstVMLoad2(InstVMLoad2 *ins)
	{
		printName(ins);
		print(ins->sz);
		print(ins->sgn);
		printOperands(ins);
	}

	void visitInstRVVAddV(InstRVVAddV *ins)
	{
		printName(ins);
		ss << "v" << (int)ins->vd << ", v" << (int)ins->vs2 << ", v" << (int)ins->vs1
		   << "  vtype=" << std::hex << ins->vtype << std::dec << " vlmax=" << ins->vlmax
		   << " sew=" << (int)ins->sew_bytes << "B emul=" << (int)ins->emul_regs
		   << " chunks/reg=" << (int)ins->chunks_per_reg
		   << " llvm-wide=" << (int)ins->llvm_wide;
	}

	void visitInstRVVWideAddSSA(InstRVVWideAddSSA *ins)
	{
		printName(ins);
		ss << "chunks=" << (int)ins->active_chunks << " sew=" << (int)ins->sew_bytes
		   << "B raw=0x" << std::hex << ins->raw << std::dec << " ";
		printOperands(ins);
	}

	// Diagnostic chunk control arm (see the block comment on InstRVVDiagChunkBegin in qir.h). The
	// chunk count is the number of rvvdiagchunkadd NODES rather than a field, so a dump shows one
	// line at VLEN=512 and two at VLEN=1024 -- but each line prints only translation-time
	// constants, because these nodes have no operands. The `zmm<i>` shown is the emitter's
	// hardcoded choice, not an allocated register.
	void visitInstRVVDiagChunkBegin(InstRVVDiagChunkBegin *ins)
	{
		printName(ins);
		ss << "vtype=" << std::hex << ins->vtype << std::dec << " vlmax=" << ins->vlmax;
	}

	void visitInstRVVDiagChunkAdd(InstRVVDiagChunkAdd *ins)
	{
		printName(ins);
		ss << "chunk" << (int)ins->index << " v" << (int)ins->vd << ", v" << (int)ins->vs2
		   << ", v" << (int)ins->vs1 << "  sew=" << (int)ins->sew_bytes << "B zmm"
		   << (int)ins->index;
	}

	void visitInstRVVDiagChunkEnd(InstRVVDiagChunkEnd *ins)
	{
		printName(ins);
	}

	void visitInstRVVTypedChunkBegin(InstRVVTypedChunkBegin *ins)
	{
		printName(ins);
		ss << prop_sep << "vtype=" << std::hex << ins->vtype << std::dec << " vlmax=" << ins->vlmax
		   << " body=" << (int)ins->n_typed;
		// R1A.3b: printed only for a real run, so every accepted single-instruction frame's
		// dump stays character-identical to its accepted form.
		if (ins->n_members != 1) {
			ss << " run=" << (int)ins->n_members;
		}
		if (ins->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit ||
		    ins->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlOrPartialVstartBaseLimit ||
		    ins->guard_kind == InstRVVTypedChunkBegin::GuardKind::VlenbVstartBaseLimit) {
			ss << " base_offs=" << ins->base_state_offs << " base_limit=0x" << std::hex
			   << ins->base_limit << std::dec;
		}
		if (ins->guard_kind ==
			InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNEBaseMask ||
		    ins->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseMask)
			ss << " base_mask=0x" << std::hex << ins->base_state_mask
			   << " base_limit=0x" << ins->base_limit << std::dec;
	}

	void visitInstRVVTypedChunkEnd(InstRVVTypedChunkEnd *ins)
	{
		printName(ins);
		if (ins->n_members != 1) {
			ss << prop_sep << "run=" << (int)ins->n_members;
			for (u8 i = 0; i < ins->n_members; ++i) {
				ss << " [pc=" << std::hex << ins->members[i].pc
				   << " raw=" << ins->members[i].raw << std::dec << "]";
			}
		}
	}
	void visitInstRVVRunScalar(InstRVVRunScalar *ins)
	{
		printName(ins);
		ss << prop_sep << "raw=0x" << std::hex << ins->raw << std::dec;
	}
	void visitInstVChunkFBroadcast(InstVChunkFBroadcast *ins)
	{
		printName(ins); ss << prop_sep << "offs=" << ins->offs << " sew=" << (int)ins->sew_bytes;
	}
	void visitInstVChunkFALU(InstVChunkFALU *ins)
	{
		printName(ins); ss << prop_sep << "f6=" << (int)ins->funct6 << " sew="
			<< (int)ins->sew_bytes << " chunk=" << (int)ins->chunk << " kmask=" << (int)ins->kmask;
	}
	void visitInstVChunkFMA(InstVChunkFMA *ins)
	{
		printName(ins); ss << prop_sep << "f6=" << (int)ins->funct6 << " sew="
			<< (int)ins->sew_bytes << " chunk=" << (int)ins->chunk << " kmask=" << (int)ins->kmask;
	}
	void visitInstVChunkDep(InstVChunkDep *ins) { printName(ins); }
	void visitInstVChunkMaskSet(InstVChunkMaskSet *ins)
	{
		printName(ins); ss << prop_sep << "chunk=" << (int)ins->chunk << " lanes=" << (int)ins->lanes;
	}
	// S1-3: `element_base` is the emitted `cmp`'s immediate itself, so the dump now prints exactly
	// what the compare holds instead of the two factors S1-1 multiplied. A dump is where a wrong
	// unit (bytes rather than elements) is first visible.
	void visitInstVChunkActive(InstVChunkActive *ins)
	{
		printName(ins); ss << prop_sep << "chunk=" << (int)ins->chunk
			<< " element_base=" << (unsigned)ins->element_base;
	}
	void visitInstVChunkPartialAlu(InstVChunkPartialAlu *ins) { printName(ins); }
	void visitInstVMaskLogic(InstVMaskLogic *ins) { printName(ins); }
	void visitInstVMaskScalar(InstVMaskScalar *ins) { printName(ins); }
	void visitInstVMaskIota(InstVMaskIota *ins) { printName(ins); }
	void visitInstVReduce(InstVReduce *ins) {
		printName(ins);ss<<prop_sep<<"vd="<<unsigned(ins->rd)<<" data="<<unsigned(ins->data)
			<<" seed="<<unsigned(ins->seed)<<" sew="<<unsigned(ins->sew)*8<<" op="<<unsigned(ins->op);
	}
	void visitInstVCompress(InstVCompress *ins) {
		printName(ins);ss<<prop_sep<<"vd="<<unsigned(ins->rd)<<" data="<<unsigned(ins->data)
			<<" mask="<<unsigned(ins->mask)<<" sew="<<unsigned(ins->sew)*8<<" vlmax="<<ins->vlmax;
	}
	void visitInstVScalarMove(InstVScalarMove *ins) {
		printName(ins);ss<<prop_sep<<"v"<<unsigned(ins->vreg)<<(ins->floating?" f":" x")<<unsigned(ins->greg)
			<<" sew="<<unsigned(ins->sew)*8<<" to_vector="<<ins->to_vector;
	}
	void visitInstVChunkIndex(InstVChunkIndex *ins) { printName(ins); }
	void visitInstVChunkFClass(InstVChunkFClass *ins) { printName(ins); }
	void visitInstVChunkIToF(InstVChunkIToF *ins) { printName(ins); }
	void visitInstVChunkFToI(InstVChunkFToI *ins) { printName(ins); }
	void visitInstVChunkFToF(InstVChunkFToF *ins) { printName(ins); }
	void visitInstVGather(InstVGather *ins) { printName(ins); }
	void visitInstVFEstimate(InstVFEstimate *ins) { printName(ins); }
	void visitInstVMemory(InstVMemory *ins) { printName(ins); }
	void visitInstVWholeMove(InstVWholeMove *ins) { printName(ins); }
	void visitInstVFReduce(InstVFReduce *ins) { printName(ins); }
	void visitInstVMaskPrefix(InstVMaskPrefix *ins) { printName(ins); }
	void visitInstVChunkExtend(InstVChunkExtend *ins) { printName(ins); }
	void visitInstVChunkWiden(InstVChunkWiden *ins) { printName(ins); }
	void visitInstVChunkNarrowShift(InstVChunkNarrowShift *ins) { printName(ins); }
	void visitInstRVVTypedChunkPartial(InstRVVTypedChunkPartial *ins) { printName(ins); }
	void visitInstRVVQCGFPBegin(InstRVVQCGFPBegin *ins) { printName(ins); }
	void visitInstRVVQCGFPEnd(InstRVVQCGFPEnd *ins) { printName(ins); }

	void visitInstCCRFChunk(InstCCRFChunk *ins)
	{
		printName(ins);
		static constexpr char const *kinds[] = {"whole_load", "whole_store", "vmul_vx", "vmacc_vx"};
		ss << prop_sep << "raw:0x" << std::hex << ins->raw << std::dec
		   << prop_sep << "kind:" << kinds[(unsigned)ins->kind]
		   << prop_sep << "component:chunk_" << (unsigned)ins->component
		   << prop_sep << "bytes:64" << prop_sep << "host_width:"
		   << (ins->host_width == InstCCRFChunk::HostWidth::AVX512ZMM ? "zmm512" : "xmm128_fallback");
	}

	void visitInstCCRFComputeRegion(InstCCRFComputeRegion *ins)
	{
		printName(ins);
		ss << prop_sep << "component:chunk_" << (unsigned)ins->component
		   << prop_sep << "iterations:" << ins->iterations
		   << prop_sep << "operations:" << ins->operation_count
		   << prop_sep << "read_mask:0x" << std::hex << ins->read_mask
		   << prop_sep << "write_mask:0x" << ins->write_mask << std::dec
		   << prop_sep << "host_width:zmm512";
	}

	// Typed V512 chunk ops: print the operands, since unlike the diagnostic arm above these HAVE
	// operands and the whole point of a dump is to show the chunk def-use chain.
	// The INDIRECT form's base and displacement are fields, not operands, and its operand slot is
	// a placeholder constant -- so without this a dump would show `vchunkload [%v32|v512] [$0|i32]`
	// and the whole addressing decision (which guest register, which chunk) would be invisible in
	// the one artifact that is supposed to show it. Printed in vstatechunkload's `state:<hex>+<n>`
	// style, plus the chunk displacement, so the two halves of a routed load frame read alike.
	void visitInstVChunkLoad(InstVChunkLoad *ins)
	{
		printName(ins);
		if (ins->base_state_offs != InstVChunkLoad::NO_STATE_BASE) {
			ss << prop_sep << "base:state:" << std::hex << ins->base_state_offs << std::dec
			   << prop_sep << "disp" << (int)ins->disp << "+"
			   << InstVChunkLoad::CHUNK_BYTES;
		}
		printOperands(ins);
	}

	void visitInstVChunkAdd(InstVChunkAdd *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}

	void visitInstVChunkMul(InstVChunkMul *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}

	// printOperands emits the inputs in slot order, which is what makes a dump readable as
	// "minuend, subtrahend" for this op rather than as an unordered pair.
	void visitInstVChunkSub(InstVChunkSub *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}

	// The SEW is printed for the xor too, even though its emitter does not select on it: it is
	// the only place a dump records WHICH guest width this frame was admitted under, and the
	// route's analyser gates that token rather than accepting a bare `vchunkxor`.
	void visitInstVChunkXor(InstVChunkXor *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}

	// Likewise for the or. printName emits the OPCODE name, so a dump distinguishes `vchunkor`
	// from `vchunkxor` by itself -- which is the property the route's analyser reads to decide
	// which guest instruction a frame belongs to, and the reason the two are separate opcodes
	// rather than one op with an operation field.
	void visitInstVChunkOr(InstVChunkOr *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}

	// And for the and, which completes the trio. With three bitwise chunk ops in the tree the
	// opcode name printed here is the only textual thing separating `vchunkand`, `vchunkor` and
	// `vchunkxor` in a dump -- their operand lists, types and properties are otherwise identical --
	// so this is what the routes' analysers read to decide which guest instruction a frame belongs
	// to, and the reason all three are separate opcodes rather than one op with an operation field.
	void visitInstVChunkAnd(InstVChunkAnd *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}
	// P7N-B. The SEW is printed for the same reason it is for the bitwise trio, and the SHIFT
	// AMOUNT is printed as well because it is the only thing that distinguishes two otherwise
	// identical frames -- a dump of `vsll.vi v8,v8,12` and one of `vsll.vi v8,v8,7` would
	// otherwise be textually the same, and the route's analyser reads this token to check that
	// the immediate reached the emitter reduced modulo SEW.
	void visitInstVChunkSll(InstVChunkSll *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		ss << prop_sep << "shamt" << (int)ins->shamt;
		printOperands(ins);
	}
	void visitInstVChunkSrl(InstVChunkSrl *ins)
	{
		printName(ins);
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		ss << prop_sep << "shamt" << (int)ins->shamt;
		printOperands(ins);
	}

	// Same treatment as vchunkload's, and for the same reason: in the INDIRECT form the base and
	// displacement are fields, not operands, and the address operand slot is a placeholder
	// constant -- so without this a dump would show `vchunkstore [$0|i32] [%v33|v512]` and the
	// whole addressing decision (which guest register holds the destination, which chunk of it)
	// would be invisible in the one artifact that is supposed to show it.
	void visitInstVChunkStore(InstVChunkStore *ins)
	{
		printName(ins);
		if (ins->base_state_offs != InstVChunkStore::NO_STATE_BASE) {
			ss << prop_sep << "base:state:" << std::hex << ins->base_state_offs << std::dec
			   << prop_sep << "disp" << (int)ins->disp << "+"
			   << InstVChunkStore::CHUNK_BYTES;
		}
		printOperands(ins);
	}

	// The state offset is a field, not an operand, so it has to be printed explicitly or a dump
	// would show a load with no source at all.
	void visitInstVStateChunkLoad(InstVStateChunkLoad *ins)
	{
		printName(ins);
		ss << prop_sep << "state:" << std::hex << ins->offs << std::dec << "+"
		   << InstVStateChunkLoad::CHUNK_BYTES;
		printOperands(ins);
	}

	// Native-3. The scalar's CPUState offset AND the lane width are both fields rather than
	// operands, so a dump would otherwise show a splat with neither a source nor a lane count.
	void visitInstVChunkBroadcast(InstVChunkBroadcast *ins)
	{
		printName(ins);
		if (ins->is_imm) // A6
			ss << prop_sep << "imm:" << (int)(i32)ins->imm;
		else
			ss << prop_sep << "state:" << std::hex << ins->offs << std::dec << "+"
			   << InstVChunkBroadcast::SCALAR_BYTES;
		ss << prop_sep << "sew" << (int)ins->sew_bytes;
		printOperands(ins);
	}

	// Same: the destination is a field, not an operand, so a dump would otherwise show a store
	// with no destination at all.
	void visitInstVStateChunkStore(InstVStateChunkStore *ins)
	{
		printName(ins);
		ss << prop_sep << "state:" << std::hex << ins->offs << std::dec << "+"
		   << ins->Bytes();
		if (ins->active_sew)
			ss << prop_sep << "active-sew:" << unsigned(ins->active_sew)
			   << " chunk:" << unsigned(ins->chunk);
		if (ins->kmask)
			ss << prop_sep << "kmask:k" << unsigned(ins->kmask);
		printOperands(ins);
	}

	// S2.9. vtype, vlmax and vlenb are node FIELDS, not operands, so a dump would otherwise show
	// `rvvsetvl [%vN|i32] [%vM|i32]` and the whole configuration this node was admitted under --
	// including the one value a wrong implementation is most likely to get wrong, a vlmax taken
	// from VLEN_MAX_BITS instead of config::vlen_bits -- would be invisible in the one artifact
	// that is supposed to show it. vlmax is printed in decimal because that is how the route's
	// gates state it (16 at VLEN=512, 32 at VLEN=1024); vtype stays hex because it is a bit field.
	void visitInstRVVSetVLReg(InstRVVSetVLReg *ins)
	{
		printName(ins);
		ss << prop_sep << "vlenb:" << ins->vlenb << prop_sep << "keep_vl:" << ins->keep_vl;
		printOperands(ins);
	}
	void visitInstRVVSetVL(InstRVVSetVL *ins)
	{
		printName(ins);
		ss << prop_sep << "vtype:" << std::hex << ins->vtype << std::dec << prop_sep
		   << "vlmax" << ins->vlmax << prop_sep << "vlenb" << ins->vlenb << prop_sep
		   << "keep_vl" << (ins->keep_vl ? 1 : 0);
		printOperands(ins);
	}

#define RVV_SSA_PRINT_VISITOR(cls)                                                                          \
	void visit##cls(cls *ins)                                                                              \
	{                                                                                                      \
		printName(ins);                                                                                  \
		printOperands(ins);                                                                              \
	}
	RVV_SSA_PRINT_VISITOR(InstRVVRead)
	RVV_SSA_PRINT_VISITOR(InstRVVWrite)
	RVV_SSA_PRINT_VISITOR(InstRVVSplatF)
	RVV_SSA_PRINT_VISITOR(InstRVVLoad)
	RVV_SSA_PRINT_VISITOR(InstRVVStore)
	RVV_SSA_PRINT_VISITOR(InstRVVFCmp)
	RVV_SSA_PRINT_VISITOR(InstRVVMerge)
	RVV_SSA_PRINT_VISITOR(InstRVVFALU)
	RVV_SSA_PRINT_VISITOR(InstRVVFMA)
	RVV_SSA_PRINT_VISITOR(InstRVVFPBegin)
	RVV_SSA_PRINT_VISITOR(InstRVVFPEnd)
#undef RVV_SSA_PRINT_VISITOR

	void visitInstVMLoad4(InstVMLoad4 *ins)
	{
		printName(ins);
		print(ins->sz);
		print(ins->sgn);
		printOperands(ins);
	}

	void visitInstVMStore2(InstVMStore2 *ins)
	{
		printName(ins);
		print(ins->sz);
		print(ins->sgn);
		printOperands(ins);
	}

	void visitInstVMStore4(InstVMStore4 *ins)
	{
		printName(ins);
		print(ins->sz);
		print(ins->sgn);
		printOperands(ins);
	}

	void visitInstHcall(InstHcall *ins)
	{
		printName(ins);
		ss << " [" << GetRuntimeStubName(ins->stub) << "]";
		printOperands(ins);
	}
};

std::string PrinterPass::run(Region *r)
{
	std::stringstream ss;

	ss << "region: n_glob=" << r->GetVRegsInfo()->NumAll() << " n_loc=" << r->GetVRegsInfo()->NumLocals();

	for (auto &bb : r->GetBlocks()) {
		ss << "\nbb." << bb.GetId() << ":";

		ss << " succs[ ";
		for (auto const &s : bb.GetSuccs()) {
			ss << s->GetId() << " ";
		}
		ss << "] preds[ ";
		for (auto const &p : bb.GetPreds()) {
			ss << p->GetId() << " ";
		}
		ss << "]";

		auto &ilist = bb.ilist;

		for (auto iit = ilist.begin(); iit != ilist.end(); ++iit) {
			ss << "\n";
			PrinterVisitor vis(r, ss);
			vis.visit(&*iit);
		}
	}

	return ss.str();
}

} // namespace dbt::qir
