#pragma once

// T7f: fail-closed semantic certificate detector for a lane-separable RVV region.
//
// This module performs analysis only.  It creates no worker, emits no code, changes no execution
// path, and contains no member-count or profitability threshold.  Its authority is
// T7E_LANE_SEPARABILITY_CONTRACT.md section 6.

#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vrun.h"

#include <array>
#include <span>
#include <variant>
#include <vector>

namespace dbt::rv32::lane_region
{

enum class Proof : u8 {
	Unknown = 0,
	No,
	Yes,
};

// Stable rejection vocabulary.  Do not reorder or reuse values: logs and future cached analysis
// may persist the numeric value.  A successful result contains no rejection value at all.
enum class Reject : u8 {
	UNKNOWN_DECODE_OR_ROUTE = 1,
	ROUTE_NOT_ADMITTED = 2,
	SHAPE_NOT_E32_M1_VLEN1024 = 3,
	MASKED = 4,
	PARTIAL_VL = 5,
	NONZERO_VSTART = 6,
	VECTOR_CONFIG_WRITE = 7,
	CROSS_CHUNK_DEF_USE = 8,
	SCALAR_OR_CSR_EFFECT = 9,
	VECTOR_TO_SCALAR = 10,
	FP_OR_FFLAGS_EFFECT = 11,
	MEMORY_READ_OR_WRITE = 12,
	ATOMIC_MMIO_OR_UNKNOWN_PMA = 13,
	MAY_TRAP_OR_HELPER = 14,
	CONTROL_FLOW_OR_SIDE_EXIT = 15,
	MULTI_ENTRY_OR_NONLOCAL_CFG = 16,
	MISSING_SSA_DEF = 17,
	OVERLAP_SNAPSHOT_UNPROVED = 18,
	BACKEND_CANNOT_HOLD_PRIVATE = 19,
	UNKNOWN_METADATA = 20,
	NON_VECTOR_SOURCE_UNMODELED = 21,
};

char const *RejectName(Reject reject);

struct ShapeFacts {
	Proof complete{Proof::Unknown};
	u32 vlen_bits{};
	u32 sew_bits{};
	i8 lmul_log2{};
	u32 vl{};
	u32 vlmax{};
	u32 vstart{};
};

struct CFGFacts {
	Proof complete{Proof::Unknown};
	Proof single_block{Proof::Unknown};
	Proof single_entry{Proof::Unknown};
	Proof normal_boundary_only{Proof::Unknown};
	u32 entry_pc{};
	u32 boundary_pc{};
};

// Facts supplied by decode/translation/region formation.  Every proof field must be known for an
// accepted member.  `vector_uses/defs/old_destination` are independently checked against the exact
// decoded route, so a caller cannot omit or invent a vector edge and still obtain a certificate.
struct CandidateMember {
	u32 pc{};
	u32 raw{};
	Proof metadata_complete{Proof::Unknown};
	Proof route_admitted{Proof::Unknown};
	Proof cross_chunk_def_use{Proof::Unknown};
	Proof scalar_or_csr_effect{Proof::Unknown};
	Proof vector_to_scalar{Proof::Unknown};
	Proof fp_or_fflags_effect{Proof::Unknown};
	Proof memory_read_or_write{Proof::Unknown};
	Proof atomic_mmio_or_unknown_pma{Proof::Unknown};
	Proof may_trap_or_helper{Proof::Unknown};
	Proof control_or_side_exit{Proof::Unknown};
	Proof ssa_defs_present{Proof::Unknown};
	Proof overlap_snapshot_proven{Proof::Unknown};
	u32 vector_uses{};
	u32 vector_defs{};
	u32 old_destination{};
};

struct Input {
	std::span<CandidateMember const> members{};
	ShapeFacts shape{};
	CFGFacts cfg{};
	u32 route_table_version{};
	Proof backend_can_hold_private{Proof::Unknown};
};

struct ChunkRange {
	u8 first_element{};
	u8 end_element{};
};

struct CertifiedMember {
	u32 pc{};
	u32 raw{};
	rvvrun::RunOp op{rvvrun::RunOp::None};
	u8 rd{}, rs1{}, rs2{};
	u32 vector_uses{};
	u32 vector_defs{};
	u32 old_destination{};
	std::array<i32, 2> destination_def{{-1, -1}};
	// For each chunk, the earlier member defining the source, or -1 for a region live-in.
	std::array<i32, 2> src1_def{{-1, -1}};
	std::array<i32, 2> src2_def{{-1, -1}};
};

struct Certificate {
	u32 entry_pc{};
	u32 boundary_pc{};
	u32 route_table_version{};
	ShapeFacts shape{};
	bool unmasked{true};
	std::array<ChunkRange, 2> chunks{{{0, 16}, {16, 32}}};
	std::vector<CertifiedMember> members{};
	std::array<u32, 2> live_in{};
	std::array<u32, 2> live_out{};
	std::array<std::array<i32, VREG_NUM>, 2> last_def{};
	// The narrow certificate has no scalar/shared effects and exactly one normal publication point.
	bool immutable_scalar_inputs_empty{true};
	bool shared_effects_empty{true};
	bool normal_boundary_only{true};
	bool both_chunks_must_complete{true};
	bool publish_disjoint_vector_chunks{true};
	bool commit_pc_is_boundary{true};
};

using Result = std::variant<Certificate, Reject>;

Result Detect(Input const &input);

} // namespace dbt::rv32::lane_region
