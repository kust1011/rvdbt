#include "dbt/guest/rv32_analyser.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/tcache/cflow_dump.h"
#include "dbt/execute.h"

#include <sstream>

namespace dbt::rv32
{
LOG_STREAM(analyse)

RV32Analyser::RV32Analyser(ModuleGraph *mg_, u32 ip, uptr vmem) : vmem_base(vmem), bb_ip(ip), mg(mg_) {}

void RV32Analyser::Analyse(ModuleGraph *mg, u32 ip, u32 boundary_ip, uptr vmem, u64 &exec_count, std::map<u32, u64> &exec_count_map)
{
	log_analyse("RV32Analyser: [%08x:%08x]", ip, boundary_ip);
	RV32Analyser t(mg, ip, vmem);
	t.insn_ip = ip;
	t.ends_with_br = false;
	// mg->RecordEntry(ip);

	u32 num_insns = 0;
	while (true) {
		t.AnalyseInsn();
		num_insns++;
		if (t.control != Control::NEXT) {
			break;
		}
		if (num_insns == TB_MAX_INSNS || t.insn_ip >= boundary_ip) {
			t.control = Control::TB_OVF;
			mg->RecordGBr(t.bb_ip, t.insn_ip);
			break;
		}
	}
	if (dbt::config::propagate_exec_count) {
		for (auto it = exec_count_map.begin(); it != exec_count_map.end();) {
			if (it->first <= ip) {
				exec_count -= it->second;
				it = exec_count_map.erase(it);
			} else {
				break;
			}
		}
		auto curr_node = mg->GetNode(ip);
		if (curr_node && exec_count > 0) {
			log_dbt("propagate exec_count: %d to %08x", exec_count, ip);
			log_dbt("%llu becomes %llu", curr_node->flags.exec_count, curr_node->flags.exec_count + exec_count);
			if (curr_node->flags.exec_count < dbt::config::threshold && curr_node->flags.exec_count + exec_count >= dbt::config::threshold) {
				log_dbt("propagate exec_count: %08x has critical exec_count: %llu", curr_node->ip, curr_node->flags.exec_count);
				curr_node->flags.is_critical = true;
			}
			curr_node->flags.exec_count += exec_count;
		}
		if (curr_node->flags.exec_instr_count > num_insns) {
			exec_count += curr_node->flags.exec_count;
			exec_count_map[ip + curr_node->flags.exec_instr_count * 4] += curr_node->flags.exec_count;
		}
	}
	mg->GetNode(t.bb_ip)->ip_end = t.insn_ip;
	// log_dbt("RV32Analyser: stop at %08x", t.insn_ip);
}

void RV32Analyser::AnalyseInsn()
{
	auto *insn_ptr = (u32 *)(vmem_base + insn_ip);

	using decoder = insn::Decoder<RV32Analyser>;
	(this->*decoder::Decode(insn_ptr))(insn_ptr);
}

void RV32Analyser::AnalyseBrcc(rv32::insn::B i)
{
	mg->RecordGBr(bb_ip, insn_ip + 4);
	mg->RecordGBr(bb_ip, insn_ip + i.imm());
	ends_with_br = true;
}

template <typename IType>
static ALWAYS_INLINE void LogInsn(IType i, u32 ip)
{
	if (likely(!log_dbt.enabled())) {
		return;
	}
	std::stringstream ss;
	ss << i;
	const auto &res = ss.str();
	log_analyse("\t %08x: %-8s   %s", ip, IType::opcode_str, res.c_str());
}

#define Analyser(name)                                                                                       \
	void RV32Analyser::H_##name(void *insn)                                                              \
	{                                                                                                    \
		insn::Insn_##name i{*(u32 *)insn};                                                           \
		LogInsn(i, insn_ip);                                                                         \
		static constexpr auto flags = decltype(i)::flags;                                            \
		V_##name(i);                                                                                 \
		if constexpr (flags & insn::Flags::Branch || flags & insn::Flags::Trap) {                    \
			control = RV32Analyser::Control::BRANCH;                                             \
		}                                                                                            \
		insn_ip += 4;                                                                                \
	}                                                                                                    \
	ALWAYS_INLINE void RV32Analyser::V_##name(insn::Insn_##name i)

#define Analyser_Unimpl(name)                                                                                \
	Analyser(name)                                                                                       \
	{                                                                                                    \
		dbt::Panic("unimplemented insn " #name);                                                     \
	}

Analyser_Unimpl(ill);
// RVV: vector ops are straight-line for control-flow purposes (no branch, no trap edge);
// the analyser only needs to advance past them.
// Scalar FP is straight-line for control-flow purposes.
Analyser(flw) {}
Analyser(fld) {}
Analyser(fsw) {}
Analyser(fsd) {}
Analyser(fpop) {}
Analyser(fmadd) {}
Analyser(fmsub) {}
Analyser(fnmsub) {}
Analyser(fnmadd) {}
Analyser(vsetvli) {}
Analyser(vsetvl) {}
Analyser(vle) {}
Analyser(vse) {}
Analyser(vlse) {}
Analyser(vleff) {}
Analyser(vsse) {}
Analyser(vlxei) {}
Analyser(vsxei) {}
Analyser(vlseg) {}
Analyser(vsseg) {}
Analyser(vadd_vv) {}
Analyser(vsetivli) {}
Analyser(vialu) {}
Analyser(vicmp) {}
Analyser(vmlogic) {}
Analyser(vmerge) {}
Analyser(vid) {}
Analyser(vext) {}
Analyser(vslide) {}
Analyser(vrgather) {}
Analyser(vsatadd) {}
Analyser(vavg) {}
Analyser(vnshift) {}
Analyser(vadc) {}
Analyser(vsmul) {}
Analyser(vlm) {}
Analyser(vsm) {}
Analyser(vfwarith) {}
Analyser(vfwred) {}
Analyser(vsshift) {}
Analyser(vnclip) {}
Analyser(vwred) {}
Analyser(vmaskpop) {}
Analyser(vmunary) {}
Analyser(vcompress) {}
Analyser(vwint) {}
Analyser(vimul) {}
// Same empty body as every other vector op: the analyser models scalar dataflow only, and the
// P3.5a decoder split changes nothing it looks at.
Analyser(vmul_vv) {}
// Likewise for the S2.1 vsub.vv split: the analyser models scalar dataflow only.
Analyser(vsub_vv) {}
// Likewise for the S2.2 vxor.vv split.
Analyser(vxor_vv) {}
// Likewise for the S2.3 vor.vv split.
Analyser(vor_vv) {}
// Likewise for the S2.4 vand.vv split.
Analyser(vand_vv) {}
// P7N-B: likewise for the two OPIVI logical-shift splits. Like every other vector op the analyser
// has nothing to say about them -- they touch no scalar register and no memory.
Analyser(vsll_vi) {}
Analyser(vsrl_vi) {}
// A6: likewise for the vadd.vx / vadd.vi splits (vadd.vx READS a scalar GPR but, like every
// other .vx vector op that stays in `vialu`, the analyser records no scalar def/use for it).
Analyser(vadd_vx) {}
Analyser(vadd_vi) {}
Analyser(vred) {}
Analyser(vfalu) {}
Analyser(vfma) {}
Analyser(vfcmp) {}
Analyser(vfcvt) {}
Analyser(vfunary1) {}
Analyser(vfred) {}
Analyser(vfmerge) {}
Analyser(vfmvfs) {}
Analyser(vfmvsf) {}
Analyser(vmvsx) {}
Analyser(vmvxs) {}
Analyser(vmvNr) {}
Analyser(vlNre) {}
Analyser(vsNr) {}
Analyser(lui) {}
Analyser(auipc) {}
Analyser(jal)
{
	// TODO: check alignment
	mg->RecordGBr(bb_ip, insn_ip + i.imm());
	if (i.rd()) {
		mg->RecordLink(bb_ip, insn_ip + 4);
	}
	ends_with_br = true;
}
Analyser(jalr)
{
	// A-line SJR (2026-07-22): RISC-V toolchains emit `auipc rs1,HI20` immediately followed by
	// `jalr rd,LO12(rs1)` as a two-instruction long-range direct call/jump whenever the target is
	// too far for jal's +-1MiB reach -- the target is FULLY determined at static-analysis time, zero
	// runtime ambiguity, exactly like jal's own immediate-encoded target. Real-workload census
	// (xalan.elf, objdump-verified): of 4166 jr sites, 1286 (31%) are exactly this pattern. Currently
	// ALL jalr sources are treated as opaque (RecordGBrind, a dead is_brind_source marker downstream)
	// regardless of this -- give the statically-resolvable subset a REAL CFG edge instead, unifying
	// its treatment with jal/beq rather than special-casing jalr as inherently unpredictable.
	u32 auipc_ip = insn_ip - 4;
	insn::Insn_auipc ap{*(u32 *)(vmem_base + auipc_ip)};
	if (ap.opcode() == 0b0010111 && ap.rd() == i.rs1() && i.rs1() != 0) {
		u32 target = (auipc_ip + ap.imm() + i.imm()) & ~1u;
		mg->RecordGBr(bb_ip, target);
	} else {
		mg->RecordGBrind(bb_ip);
	}
	if (i.rd()) {
		mg->RecordLink(bb_ip, insn_ip + 4);
	}
	ends_with_br = true;
}
Analyser(beq)
{
	AnalyseBrcc(i);
}
Analyser(bne)
{
	AnalyseBrcc(i);
}
Analyser(blt)
{
	AnalyseBrcc(i);
}
Analyser(bge)
{
	AnalyseBrcc(i);
}
Analyser(bltu)
{
	AnalyseBrcc(i);
}
Analyser(bgeu)
{
	AnalyseBrcc(i);
}
Analyser(lb) {}
Analyser(lh) {}
Analyser(lw) {}
Analyser(lbu) {}
Analyser(lhu) {}
Analyser(sb) {}
Analyser(sh) {}
Analyser(sw) {}
Analyser(addi) {}
Analyser(slti) {}
Analyser(sltiu) {}
Analyser(xori) {}
Analyser(ori) {}
Analyser(andi) {}
Analyser(slli) {}
Analyser(srai) {}
Analyser(srli) {}
Analyser(sub) {}
Analyser(add) {}
Analyser(sll) {}
Analyser(slt) {}
Analyser(sltu) {}
Analyser(xor) {}
Analyser(sra) {}
Analyser(srl) {}
Analyser(or) {}
Analyser(and) {}
Analyser(fence) {}
Analyser(fencei) {}
Analyser(ecall)
{
	if (unlikely(dbt::config::analyser_ecall_edge)) {
		mg->RecordGBr(bb_ip, insn_ip + 4); // DC-4 pre-patch: true fallthrough edge
	}
}
Analyser(ebreak) {}

Analyser(lrw) {}
Analyser(scw) {}
Analyser(amoswapw) {}
Analyser(amoaddw) {}
Analyser(amoxorw) {}
Analyser(amoandw) {}
Analyser(amoorw) {}
Analyser(amominw) {}
Analyser(amomaxw) {}
Analyser(amominuw) {}
Analyser(amomaxuw) {}

Analyser(mul) {}
Analyser(mulh) {}
Analyser(mulhsu) {}
Analyser(mulhu) {}
Analyser(div) {}
Analyser(divu) {}
Analyser(rem) {}
Analyser(remu) {}
Analyser(csrrw) {}
Analyser(csrrs) {}
Analyser(csrrc) {}
Analyser(csrrwi) {}
Analyser(csrrsi) {}
Analyser(csrrci) {}
Analyser(mret) {}

} // namespace dbt::rv32
