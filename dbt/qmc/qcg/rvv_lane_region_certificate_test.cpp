// T7f focused test for the fail-closed lane-region certificate detector.
//
// This binary does not invoke a backend or execute generated code.  It independently evaluates
// accepted regions element by element, then evaluates the two certified chunks separately and
// compares the complete architectural test state.  Rejection checks require the exact stable enum.

#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_lane_region.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace dbt;
namespace lr = dbt::rv32::lane_region;
namespace rr = dbt::rv32::rvvrun;

namespace
{

int failures;

#define CHECK_TAG(tag, cond)                                                                                  \
	do {                                                                                                   \
		if (!(cond)) {                                                                                  \
			fprintf(stderr, "  FAIL [%s] %s:%d: %s\n", tag, __FILE__, __LINE__, #cond);             \
			++failures;                                                                                   \
		}                                                                                                  \
	} while (0)

constexpr u32 EncodeVV(u32 f6, u8 rd, u8 vs2, u8 vs1, bool unmasked = true)
{
	return (f6 << 26) | ((u32)unmasked << 25) | ((u32)vs2 << 20) | ((u32)vs1 << 15) |
	       ((u32)rd << 7) | 0b1010111u;
}

constexpr u32 EncodeMulVV(u8 rd, u8 vs2, u8 vs1)
{
	return (0b100101u << 26) | (1u << 25) | ((u32)vs2 << 20) | ((u32)vs1 << 15) |
	       (0b010u << 12) | ((u32)rd << 7) | 0b1010111u;
}

constexpr u32 F6_ADD = 0b000000;
constexpr u32 F6_SUB = 0b000010;
constexpr u32 F6_XOR = 0b001011;
constexpr u32 F6_OR = 0b001010;
constexpr u32 F6_AND = 0b001001;

constexpr u32 W_VSETVLI = 0x0d057557u;
constexpr u32 W_VLE32 = 0x0205e087u;
constexpr u32 W_VSLIDEUP = 0x3a10b1d7u;
constexpr u32 W_VREDSUM = 0x021121d7u;
constexpr u32 W_VFADD = 0x021111d7u;
constexpr u32 W_VMAND = 0x661121d7u;
constexpr u32 W_AMOADD = 0x00b526afu;
constexpr u32 W_BEQ = 0x00b50063u;

lr::CandidateMember SafeMember(u32 pc, u32 raw)
{
	lr::CandidateMember m;
	m.pc = pc;
	m.raw = raw;
	m.metadata_complete = lr::Proof::Yes;
	m.route_admitted = lr::Proof::Yes;
	m.cross_chunk_def_use = lr::Proof::No;
	m.scalar_or_csr_effect = lr::Proof::No;
	m.vector_to_scalar = lr::Proof::No;
	m.fp_or_fflags_effect = lr::Proof::No;
	m.memory_read_or_write = lr::Proof::No;
	m.atomic_mmio_or_unknown_pma = lr::Proof::No;
	m.may_trap_or_helper = lr::Proof::No;
	m.control_or_side_exit = lr::Proof::No;
	m.ssa_defs_present = lr::Proof::Yes;
	m.overlap_snapshot_proven = lr::Proof::Yes;
	auto const route = rr::ClassifyTypedAluRoute(raw);
	if (route.present) {
		// P7M-A: THE ONE FACT THIS HELPER MUST NOT FABRICATE.
		//
		// Everything above is a deliberately "safe" caller fact, so that a rejection this file
		// asserts is attributable to the DETECTOR rather than to a missing input. That was
		// harmless while every route row was integer. It is not harmless now: the route table
		// has two rows -- the `vfalu` and `vfma` decode classes -- that positively DECLARE an
		// FP/fflags effect, and asserting `No` for them would make this helper contradict the
		// route table and hand the detector a false premise. So this one fact is taken from
		// the table, exactly as the production bridge takes it (rv32_lane_region_bridge.cpp).
		// The FP words in the exhaustive sweep below are therefore refused with the accurate
		// FP_OR_FFLAGS_EFFECT, which is also what `reject-fp` asks for.
		m.fp_or_fflags_effect = route.fp_host_arith ? lr::Proof::Yes : lr::Proof::No;
		// P7M-A: the shared operand-kind rule, so an OPFVF rs1 is not counted as a vector use
		// and a fused form's old vd is.
		m.vector_uses = rr::RouteVectorUses(route);
		m.vector_defs = 1u << route.rd;
		m.old_destination = rr::RouteOldDestination(route);
	}
	return m;
}

lr::ShapeFacts GoodShape()
{
	return {lr::Proof::Yes, 1024, 32, 0, 32, 32, 0};
}

lr::CFGFacts GoodCFG(size_t members)
{
	return {lr::Proof::Yes, lr::Proof::Yes, lr::Proof::Yes, lr::Proof::Yes, 0,
		(u32)members * 4u};
}

lr::Result Detect(std::vector<lr::CandidateMember> const &members, lr::ShapeFacts shape = GoodShape(),
		  lr::CFGFacts cfg = {}, lr::Proof backend = lr::Proof::Yes,
		  u32 version = rr::kTypedAluRouteTableVersion)
{
	if (cfg.complete == lr::Proof::Unknown)
		cfg = GoodCFG(members.size());
	return lr::Detect({members, shape, cfg, version, backend});
}

lr::Certificate const *Accepted(lr::Result const &result)
{
	return std::get_if<lr::Certificate>(&result);
}

void ExpectReject(char const *tag, std::vector<lr::CandidateMember> const &members, lr::Reject want,
		  lr::ShapeFacts shape = GoodShape(), lr::CFGFacts cfg = {},
		  lr::Proof backend = lr::Proof::Yes, u32 version = rr::kTypedAluRouteTableVersion)
{
	auto const result = Detect(members, shape, cfg, backend, version);
	auto const *got = std::get_if<lr::Reject>(&result);
	if (!got || *got != want) {
		fprintf(stderr, "  FAIL [%s] expected %s, got %s\n", tag, lr::RejectName(want),
			got ? lr::RejectName(*got) : "CERTIFICATE");
		++failures;
	}
}

std::vector<lr::CandidateMember> Members(std::initializer_list<u32> words)
{
	std::vector<lr::CandidateMember> out;
	u32 pc = 0;
	for (u32 word : words) {
		out.push_back(SafeMember(pc, word));
		pc += 4;
	}
	return out;
}

struct TestState {
	std::array<std::array<u32, 32>, 32> v{};
	std::array<u32, 32> gpr{};
	std::array<u32, 16> csr{};
	std::array<u64, 32> fpr{};
	u32 pc{}, vl{32}, vtype{0x0d0}, vstart{};
	u32 fflags{0x15}, frm{3};
};

u32 Apply(rr::RunOp op, u32 a, u32 b)
{
	switch (op) {
	case rr::RunOp::Add:
		return a + b;
	case rr::RunOp::Sub:
		return a - b;
	case rr::RunOp::Mul:
		return a * b;
	case rr::RunOp::Xor:
		return a ^ b;
	case rr::RunOp::Or:
		return a | b;
	case rr::RunOp::And:
		return a & b;
	case rr::RunOp::None:
		break;
	}
	return 0;
}

void EvalElements(TestState &state, lr::Certificate const &cert, u32 first, u32 end)
{
	for (auto const &m : cert.members) {
		// Snapshot both sources before any destination element is published.  This is independent
		// of the detector's SSA-def indices and covers every legal operand overlap.
		auto const a = state.v[m.rs2];
		auto const b = state.v[m.rs1];
		for (u32 e = first; e < end; ++e)
			state.v[m.rd][e] = Apply(m.op, a[e], b[e]);
	}
}

u64 Next(u64 &s)
{
	s ^= s << 13;
	s ^= s >> 7;
	s ^= s << 17;
	return s;
}

TestState RandomState(u64 seed)
{
	TestState s;
	for (auto &reg : s.v)
		for (u32 &e : reg)
			e = (u32)Next(seed);
	for (u32 &v : s.gpr)
		v = (u32)Next(seed);
	for (u32 &v : s.csr)
		v = (u32)Next(seed);
	for (u64 &v : s.fpr)
		v = Next(seed);
	s.pc = 0;
	return s;
}

void CheckPositiveRegions()
{
	printf("[1] positive lengths 1/2/3/5, overlap, same-chunk def-use, and scalar oracle\n");
	std::vector<std::vector<lr::CandidateMember>> cases = {
	    Members({EncodeVV(F6_ADD, 3, 1, 2)}),
	    Members({EncodeVV(F6_ADD, 3, 1, 2), EncodeVV(F6_SUB, 4, 3, 2)}),
	    Members({EncodeVV(F6_ADD, 3, 3, 2), EncodeVV(F6_XOR, 3, 3, 3),
		     EncodeMulVV(5, 3, 4)}),
	    Members({EncodeVV(F6_ADD, 8, 1, 2), EncodeVV(F6_SUB, 9, 8, 3),
		     EncodeMulVV(10, 9, 4), EncodeVV(F6_OR, 10, 10, 5),
		     EncodeVV(F6_AND, 12, 10, 10)}),
	};
	unsigned const lengths[] = {1, 2, 3, 5};
	for (size_t ci = 0; ci < cases.size(); ++ci) {
		auto const result = Detect(cases[ci]);
		auto const *cert = Accepted(result);
		CHECK_TAG("positive-certificate", cert != nullptr);
		if (!cert) {
			fprintf(stderr, "    positive length=%u rejected as %s\n", lengths[ci],
				lr::RejectName(std::get<lr::Reject>(result)));
			continue;
		}
		CHECK_TAG("positive-length", cert->members.size() == lengths[ci]);
		CHECK_TAG("positive-shape", cert->shape.vlen_bits == 1024 && cert->shape.vl == 32);
		CHECK_TAG("positive-chunks", cert->chunks[0].first_element == 0 &&
					      cert->chunks[0].end_element == 16 &&
					      cert->chunks[1].first_element == 16 &&
					      cert->chunks[1].end_element == 32);
		CHECK_TAG("positive-commit", cert->normal_boundary_only && cert->both_chunks_must_complete &&
					      cert->publish_disjoint_vector_chunks && cert->commit_pc_is_boundary);
		CHECK_TAG("positive-unmasked", cert->unmasked);
		CHECK_TAG("positive-per-chunk-live", cert->live_in[0] == cert->live_in[1] &&
						      cert->live_out[0] == cert->live_out[1] &&
						      cert->last_def[0] == cert->last_def[1]);

		for (u64 seed = 1; seed <= 20; ++seed) {
			TestState initial = RandomState(seed * 0x9e3779b97f4a7c15ull + ci);
			TestState oracle = initial;
			TestState split = initial;
			EvalElements(oracle, *cert, 0, 32);
			oracle.pc = cert->boundary_pc;
			EvalElements(split, *cert, 0, 16);
			EvalElements(split, *cert, 16, 32);
			split.pc = cert->boundary_pc;
			CHECK_TAG("oracle-full-state", std::memcmp(&oracle, &split, sizeof(TestState)) == 0);
			// Explicitly pin untouched non-vector architectural state against the entry copy.
			CHECK_TAG("oracle-untouched-gpr", oracle.gpr == initial.gpr);
			CHECK_TAG("oracle-untouched-csr", oracle.csr == initial.csr);
			CHECK_TAG("oracle-untouched-fp", oracle.fpr == initial.fpr &&
						       oracle.fflags == initial.fflags && oracle.frm == initial.frm);
			CHECK_TAG("oracle-untouched-vector-csr", oracle.vl == initial.vl &&
							       oracle.vtype == initial.vtype &&
							       oracle.vstart == initial.vstart);
		}
		printf("    ok length=%u, 20 independent full-state oracle cases\n", lengths[ci]);
	}
	// The three-member overlap chain's second operation consumes member 0 in both chunks.
	auto const overlap_result = Detect(cases[2]);
	if (auto const *cert = Accepted(overlap_result))
		CHECK_TAG("same-chunk-def-use", cert->members[1].src1_def[0] == 0 &&
						 cert->members[1].src1_def[1] == 0 &&
						 cert->members[1].destination_def[0] == 1 &&
						 cert->members[1].destination_def[1] == 1);
	else
		CHECK_TAG("same-chunk-def-use-certificate", false);
}

struct OpProvider {
#define OP(name, format_, flags_) static constexpr dbt::rv32::insn::Op _##name = dbt::rv32::insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

dbt::rv32::insn::Op DecodeWord(u32 word)
{
	return dbt::rv32::insn::Decoder<OpProvider>::Decode(&word);
}

bool IsCertifiedRow(dbt::rv32::insn::Op op)
{
	using O = dbt::rv32::insn::Op;
	// The certificate represents vector-only dependencies; immediate and GPR source forms
	// remain on the ordinary route until the certificate can model their inputs.
	return op == O::_vadd_vv || op == O::_vsub_vv || op == O::_vmul_vv || op == O::_vxor_vv ||
	       op == O::_vor_vv || op == O::_vand_vv;
}

void CheckExhaustiveDecode()
{
	printf("[2] exhaustive OP-V funct6 x funct3 x vm audit\n");
	unsigned successes = 0, expected = 0, mismatch = 0;
	for (u32 f6 = 0; f6 < 64; ++f6) {
		for (u32 f3 = 0; f3 < 8; ++f3) {
			for (u32 vm = 0; vm < 2; ++vm) {
				u32 const raw = (f6 << 26) | (vm << 25) | (1u << 20) | (2u << 15) |
						(f3 << 12) | (3u << 7) | 0b1010111u;
				auto const result = Detect(Members({raw}));
				bool const got = Accepted(result) != nullptr;
				bool const want = IsCertifiedRow(DecodeWord(raw));
				successes += got;
				expected += want;
				if (got != want) {
					fprintf(stderr, "  FAIL [decode-sweep] raw=%08x want=%d got=%d\n", raw,
						(int)want, (int)got);
					++mismatch;
					++failures;
				}
			}
		}
	}
	CHECK_TAG("decode-certified-set-only",
		  successes == 6 && expected == 6 && mismatch == 0);
	printf("    ok 1024 encodings, exactly 6 vector-only certificates\n");
}

void CheckRejectFamilies()
{
	printf("[3] every stable rejection family\n");
	auto good = Members({EncodeVV(F6_ADD, 3, 1, 2)});
	auto const vx = rr::ClassifyTypedAluRoute(0x961161d7u);
	CHECK_TAG("vx-gpr-is-not-vector-use", vx.present && vx.src1_is_xscalar &&
					  rr::RouteVectorUses(vx) == (1u << vx.rs2));
	auto const maccx = rr::ClassifyTypedAluRoute(0xb61161d7u);
	CHECK_TAG("macc-vd-is-vector-use", maccx.present && maccx.reads_vd &&
					    rr::RouteVectorUses(maccx) ==
						((1u << maccx.rs2) | (1u << maccx.rd)));

	ExpectReject("reject-unknown-decode", Members({0}), lr::Reject::UNKNOWN_DECODE_OR_ROUTE);
	auto route_no = good;
	route_no[0].route_admitted = lr::Proof::No;
	ExpectReject("reject-route", route_no, lr::Reject::ROUTE_NOT_ADMITTED);
	auto shape = GoodShape();
	shape.vlen_bits = 512;
	ExpectReject("reject-shape", good, lr::Reject::SHAPE_NOT_E32_M1_VLEN1024, shape);
	ExpectReject("reject-mask", Members({EncodeVV(F6_ADD, 3, 1, 2, false)}), lr::Reject::MASKED);
	ExpectReject("reject-mask-op", Members({W_VMAND}), lr::Reject::MASKED);
	ExpectReject("reject-vx-source", Members({0x961161d7u}),
		     lr::Reject::NON_VECTOR_SOURCE_UNMODELED);
	u32 const shift_vi = (0b100101u << 26) | (1u << 25) | (1u << 20) |
			     (2u << 15) | (0b011u << 12) | (3u << 7) | 0b1010111u;
	auto const vi = rr::ClassifyTypedAluRoute(shift_vi);
	CHECK_TAG("vi-immediate-is-not-vector-use", vi.present && vi.src1_is_imm5 &&
						     rr::RouteVectorUses(vi) == (1u << vi.rs2));
	ExpectReject("reject-vi-source", Members({shift_vi}),
		     lr::Reject::NON_VECTOR_SOURCE_UNMODELED);
	shape = GoodShape();
	shape.vl = 31;
	ExpectReject("reject-partial-vl", good, lr::Reject::PARTIAL_VL, shape);
	shape = GoodShape();
	shape.vstart = 1;
	ExpectReject("reject-vstart", good, lr::Reject::NONZERO_VSTART, shape);
	ExpectReject("reject-config", Members({W_VSETVLI}), lr::Reject::VECTOR_CONFIG_WRITE);
	ExpectReject("reject-cross-chunk", Members({W_VSLIDEUP}), lr::Reject::CROSS_CHUNK_DEF_USE);
	auto scalar = good;
	scalar[0].scalar_or_csr_effect = lr::Proof::Yes;
	ExpectReject("reject-scalar-csr", scalar, lr::Reject::SCALAR_OR_CSR_EFFECT);
	ExpectReject("reject-vector-scalar", Members({W_VREDSUM}), lr::Reject::VECTOR_TO_SCALAR);
	ExpectReject("reject-fp", Members({W_VFADD}), lr::Reject::FP_OR_FFLAGS_EFFECT);
	ExpectReject("reject-memory", Members({W_VLE32}), lr::Reject::MEMORY_READ_OR_WRITE);
	ExpectReject("reject-atomic-mmio", Members({W_AMOADD}),
		     lr::Reject::ATOMIC_MMIO_OR_UNKNOWN_PMA);
	auto helper = good;
	helper[0].may_trap_or_helper = lr::Proof::Yes;
	ExpectReject("reject-helper", helper, lr::Reject::MAY_TRAP_OR_HELPER);
	ExpectReject("reject-control", Members({W_BEQ}), lr::Reject::CONTROL_FLOW_OR_SIDE_EXIT);
	auto cfg = GoodCFG(1);
	cfg.single_entry = lr::Proof::No;
	ExpectReject("reject-cfg", good, lr::Reject::MULTI_ENTRY_OR_NONLOCAL_CFG, GoodShape(), cfg);
	auto no_ssa = good;
	no_ssa[0].ssa_defs_present = lr::Proof::No;
	ExpectReject("reject-ssa", no_ssa, lr::Reject::MISSING_SSA_DEF);
	auto overlap = Members({EncodeVV(F6_ADD, 3, 3, 2)});
	overlap[0].overlap_snapshot_proven = lr::Proof::No;
	ExpectReject("reject-overlap", overlap, lr::Reject::OVERLAP_SNAPSHOT_UNPROVED);
	ExpectReject("reject-backend", good, lr::Reject::BACKEND_CANNOT_HOLD_PRIVATE, GoodShape(), {},
		     lr::Proof::No);
	auto unknown = good;
	unknown[0].memory_read_or_write = lr::Proof::Unknown;
	ExpectReject("reject-unknown-metadata", unknown, lr::Reject::UNKNOWN_METADATA);
	auto incomplete = good;
	incomplete[0].metadata_complete = lr::Proof::Unknown;
	ExpectReject("reject-incomplete-member", incomplete, lr::Reject::UNKNOWN_METADATA);
	auto bad_edges = good;
	bad_edges[0].old_destination = 1u << 3;
	ExpectReject("reject-old-dest-metadata", bad_edges, lr::Reject::UNKNOWN_METADATA);
	ExpectReject("reject-route-version", good, lr::Reject::UNKNOWN_METADATA, GoodShape(), {},
		     lr::Proof::Yes, rr::kTypedAluRouteTableVersion + 1);
	cfg = GoodCFG(1);
	cfg.boundary_pc = 8;
	ExpectReject("reject-boundary", good, lr::Reject::MULTI_ENTRY_OR_NONLOCAL_CFG, GoodShape(), cfg);
	printf("    ok 20 rejection enums plus old-destination/version metadata controls\n");
}

void CheckNamesStable()
{
	printf("[4] stable rejection names\n");
	CHECK_TAG("reject-name", std::string(lr::RejectName(lr::Reject::MASKED)) == "MASKED");
	CHECK_TAG("reject-name", std::string(lr::RejectName(lr::Reject::UNKNOWN_METADATA)) ==
				 "UNKNOWN_METADATA");
}

} // namespace

int main()
{
	printf("=== T7f lane-region certificate detector ===\n");
	CheckPositiveRegions();
	CheckExhaustiveDecode();
	CheckRejectFamilies();
	CheckNamesStable();
	if (failures) {
		fprintf(stderr, "T7F_CERTIFICATE_TEST: FAIL (%d explicit assertion failures)\n", failures);
		return 1;
	}
	printf("T7F_CERTIFICATE_TEST: PASS\n");
	return 0;
}
