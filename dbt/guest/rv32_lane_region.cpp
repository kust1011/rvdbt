#include "dbt/guest/rv32_lane_region.h"

#include "dbt/guest/rv32_decode.h"

#include <optional>

namespace dbt::rv32::lane_region
{

char const *RejectName(Reject r)
{
	switch (r) {
#define CASE(name)                                                                                             \
	case Reject::name:                                                                                      \
		return #name;
	CASE(UNKNOWN_DECODE_OR_ROUTE)
	CASE(ROUTE_NOT_ADMITTED)
	CASE(SHAPE_NOT_E32_M1_VLEN1024)
	CASE(MASKED)
	CASE(PARTIAL_VL)
	CASE(NONZERO_VSTART)
	CASE(VECTOR_CONFIG_WRITE)
	CASE(CROSS_CHUNK_DEF_USE)
	CASE(SCALAR_OR_CSR_EFFECT)
	CASE(VECTOR_TO_SCALAR)
	CASE(FP_OR_FFLAGS_EFFECT)
	CASE(MEMORY_READ_OR_WRITE)
	CASE(ATOMIC_MMIO_OR_UNKNOWN_PMA)
	CASE(MAY_TRAP_OR_HELPER)
	CASE(CONTROL_FLOW_OR_SIDE_EXIT)
	CASE(MULTI_ENTRY_OR_NONLOCAL_CFG)
	CASE(MISSING_SSA_DEF)
	CASE(OVERLAP_SNAPSHOT_UNPROVED)
	CASE(BACKEND_CANNOT_HOLD_PRIVATE)
	CASE(UNKNOWN_METADATA)
	CASE(NON_VECTOR_SOURCE_UNMODELED)
#undef CASE
	}
	return "UNKNOWN_REJECTION_VALUE";
}

namespace
{

struct OpProvider {
#define OP(name, format_, flags_) static constexpr insn::Op _##name = insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

insn::Op DecodeOp(u32 raw)
{
	u32 word = raw;
	return insn::Decoder<OpProvider>::Decode(&word);
}

bool Unknown(Proof p)
{
	return p == Proof::Unknown;
}

// Classify an unsupported decoded candidate into the semantic reason that prevents it from being
// certified.  This is rejection-only: no arm returns success.  Success is exclusively the shared
// six-row ClassifyTypedAluRoute table below.
Reject UnsupportedReason(u32 raw, insn::Op op)
{
	u32 const major = raw & 0x7f;
	if (major == 0b0101111)
		return Reject::ATOMIC_MMIO_OR_UNKNOWN_PMA;
	if (major == 0b1100011 || major == 0b1100111 || major == 0b1101111)
		return Reject::CONTROL_FLOW_OR_SIDE_EXIT;
	if (major == 0b0000111 || major == 0b0100111)
		return Reject::MEMORY_READ_OR_WRITE;
	if (major == 0b1110011 && op != insn::Op::_ill)
		return Reject::SCALAR_OR_CSR_EFFECT;
	if (major != 0b1010111)
		return Reject::UNKNOWN_DECODE_OR_ROUTE;
	if (((raw >> 12) & 0x7) == 0b111)
		return Reject::VECTOR_CONFIG_WRITE;

	switch (op) {
	case insn::Op::_vle:
	case insn::Op::_vse:
	case insn::Op::_vlse:
	case insn::Op::_vleff:
	case insn::Op::_vsse:
	case insn::Op::_vlxei:
	case insn::Op::_vsxei:
	case insn::Op::_vlseg:
	case insn::Op::_vsseg:
	case insn::Op::_vlNre:
	case insn::Op::_vsNr:
		return Reject::MEMORY_READ_OR_WRITE;
	case insn::Op::_vslide:
	case insn::Op::_vrgather:
	case insn::Op::_vcompress:
		return Reject::CROSS_CHUNK_DEF_USE;
	case insn::Op::_vmlogic:
	case insn::Op::_vicmp:
		return Reject::MASKED;
	case insn::Op::_vred:
	case insn::Op::_vwred:
	case insn::Op::_vfwred:
	case insn::Op::_vfred:
	case insn::Op::_vmaskpop:
	case insn::Op::_vfmvfs:
	case insn::Op::_vmvxs:
		return Reject::VECTOR_TO_SCALAR;
	case insn::Op::_vfalu:
	case insn::Op::_vfma:
	case insn::Op::_vfcmp:
	case insn::Op::_vfcvt:
	case insn::Op::_vfunary1:
	case insn::Op::_vfmerge:
	case insn::Op::_vfmvsf:
	case insn::Op::_vfwarith:
		return Reject::FP_OR_FFLAGS_EFFECT;
	case insn::Op::_vsetvli:
	case insn::Op::_vsetivli:
	case insn::Op::_vsetvl:
		return Reject::VECTOR_CONFIG_WRITE;
	case insn::Op::_ill:
		return Reject::UNKNOWN_DECODE_OR_ROUTE;
	default:
		return Reject::MAY_TRAP_OR_HELPER;
	}
}

std::optional<Reject> CheckKnownMemberFacts(CandidateMember const &m)
{
	Proof const facts[] = {m.route_admitted,
			       m.cross_chunk_def_use,
			       m.scalar_or_csr_effect,
			       m.vector_to_scalar,
			       m.fp_or_fflags_effect,
			       m.memory_read_or_write,
			       m.atomic_mmio_or_unknown_pma,
			       m.may_trap_or_helper,
			       m.control_or_side_exit,
			       m.ssa_defs_present,
			       m.overlap_snapshot_proven};
	for (Proof p : facts)
		if (Unknown(p))
			return Reject::UNKNOWN_METADATA;
	if (m.route_admitted == Proof::No)
		return Reject::ROUTE_NOT_ADMITTED;
	if (m.cross_chunk_def_use == Proof::Yes)
		return Reject::CROSS_CHUNK_DEF_USE;
	if (m.scalar_or_csr_effect == Proof::Yes)
		return Reject::SCALAR_OR_CSR_EFFECT;
	if (m.vector_to_scalar == Proof::Yes)
		return Reject::VECTOR_TO_SCALAR;
	if (m.fp_or_fflags_effect == Proof::Yes)
		return Reject::FP_OR_FFLAGS_EFFECT;
	if (m.memory_read_or_write == Proof::Yes)
		return Reject::MEMORY_READ_OR_WRITE;
	if (m.atomic_mmio_or_unknown_pma == Proof::Yes)
		return Reject::ATOMIC_MMIO_OR_UNKNOWN_PMA;
	if (m.may_trap_or_helper == Proof::Yes)
		return Reject::MAY_TRAP_OR_HELPER;
	if (m.control_or_side_exit == Proof::Yes)
		return Reject::CONTROL_FLOW_OR_SIDE_EXIT;
	if (m.ssa_defs_present == Proof::No)
		return Reject::MISSING_SSA_DEF;
	if (m.overlap_snapshot_proven == Proof::No)
		return Reject::OVERLAP_SNAPSHOT_UNPROVED;
	return std::nullopt;
}

} // namespace

Result Detect(Input const &in)
{
	if (in.members.empty() || in.route_table_version != rvvrun::kTypedAluRouteTableVersion)
		return Reject::UNKNOWN_METADATA;
	if (in.shape.complete != Proof::Yes)
		return Reject::UNKNOWN_METADATA;
	if (in.shape.vlen_bits != 1024 || in.shape.sew_bits != 32 || in.shape.lmul_log2 != 0 ||
	    in.shape.vlmax != 32)
		return Reject::SHAPE_NOT_E32_M1_VLEN1024;
	if (in.shape.vl != in.shape.vlmax)
		return Reject::PARTIAL_VL;
	if (in.shape.vstart != 0)
		return Reject::NONZERO_VSTART;
	if (in.cfg.complete != Proof::Yes)
		return Reject::UNKNOWN_METADATA;
	if (in.cfg.single_block == Proof::Unknown || in.cfg.single_entry == Proof::Unknown ||
	    in.cfg.normal_boundary_only == Proof::Unknown)
		return Reject::UNKNOWN_METADATA;
	if (in.cfg.single_block != Proof::Yes || in.cfg.single_entry != Proof::Yes)
		return Reject::MULTI_ENTRY_OR_NONLOCAL_CFG;
	if (in.cfg.normal_boundary_only != Proof::Yes)
		return Reject::CONTROL_FLOW_OR_SIDE_EXIT;
	if (in.backend_can_hold_private == Proof::Unknown)
		return Reject::UNKNOWN_METADATA;
	if (in.backend_can_hold_private != Proof::Yes)
		return Reject::BACKEND_CANNOT_HOLD_PRIVATE;
	if (in.cfg.boundary_pc != in.cfg.entry_pc + in.members.size() * 4u)
		return Reject::MULTI_ENTRY_OR_NONLOCAL_CFG;

	Certificate cert;
	cert.entry_pc = in.cfg.entry_pc;
	cert.boundary_pc = in.cfg.boundary_pc;
	cert.route_table_version = in.route_table_version;
	cert.shape = in.shape;
	for (auto &chunk_defs : cert.last_def)
		chunk_defs.fill(-1);
	std::array<std::array<i32, VREG_NUM>, 2> current_def{};
	for (auto &chunk_defs : current_def)
		chunk_defs.fill(-1);

	for (size_t idx = 0; idx < in.members.size(); ++idx) {
		CandidateMember const &m = in.members[idx];
		if (m.pc != in.cfg.entry_pc + idx * 4u)
			return Reject::MULTI_ENTRY_OR_NONLOCAL_CFG;
		if (m.metadata_complete != Proof::Yes)
			return Reject::UNKNOWN_METADATA;

		auto const route = rvvrun::ClassifyTypedAluRoute(m.raw);
		if (!route.present) {
			// A masked version of one of the six exact rows receives the stable MASKED reason,
			// while still deriving membership from the shared route table rather than a second
			// funct6 allow-list.
			if (((m.raw >> 25) & 1u) == 0 &&
			    rvvrun::ClassifyTypedAluRoute(m.raw | (1u << 25)).present)
				return Reject::MASKED;
			return UnsupportedReason(m.raw, DecodeOp(m.raw));
		}

		auto const facts = CheckKnownMemberFacts(m);
		if (facts)
			return *facts;
		// This certificate tracks vector definitions only. A GPR, FPR or immediate in rs1
		// cannot be represented by src1_def or the vector live-in bitmap.
		if (route.src1_is_xscalar || route.src1_is_fscalar || route.src1_is_imm5 ||
		    route.src1_is_simm5 || route.src1_is_xbase || !route.src2_is_vector ||
		    route.reads_vd)
			return Reject::NON_VECTOR_SOURCE_UNMODELED;
		// P7M-A: the same shared operand-kind rule the bridge builds the facts from, so the
		// two cannot disagree about whether an OPFVF rs1 is a vector use or whether a fused
		// form reads its old vd. A row whose facts do not match its route is still rejected.
		u32 const expected_uses = rvvrun::RouteVectorUses(route);
		u32 const expected_defs = 1u << route.rd;
		if (m.vector_uses != expected_uses || m.vector_defs != expected_defs ||
		    m.old_destination != rvvrun::RouteOldDestination(route))
			return Reject::UNKNOWN_METADATA;

		CertifiedMember cm;
		cm.pc = m.pc;
		cm.raw = m.raw;
		cm.op = route.op;
		cm.rd = route.rd;
		cm.rs1 = route.rs1;
		cm.rs2 = route.rs2;
		cm.vector_uses = m.vector_uses;
		cm.vector_defs = m.vector_defs;
		cm.old_destination = m.old_destination;
		for (size_t chunk = 0; chunk < 2; ++chunk) {
			cm.destination_def[chunk] = (i32)idx;
			cm.src1_def[chunk] = current_def[chunk][route.rs1];
			cm.src2_def[chunk] = current_def[chunk][route.rs2];
			if (cm.src1_def[chunk] < 0)
				cert.live_in[chunk] |= 1u << route.rs1;
			if (cm.src2_def[chunk] < 0)
				cert.live_in[chunk] |= 1u << route.rs2;
			current_def[chunk][route.rd] = (i32)idx;
			cert.last_def[chunk][route.rd] = (i32)idx;
			cert.live_out[chunk] |= 1u << route.rd;
		}
		cert.members.push_back(cm);
	}

	return cert;
}

} // namespace dbt::rv32::lane_region
