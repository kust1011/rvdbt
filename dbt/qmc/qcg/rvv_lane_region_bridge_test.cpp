// T7g focused test: the production bridge must preserve UNKNOWN, side-effect and CFG negatives.
// No code generation or guest execution occurs here.

#include "dbt/guest/rv32_lane_region_bridge.h"

#include <cstdio>
#include <vector>

using namespace dbt;
namespace lb = dbt::rv32::lane_region_bridge;
namespace lr = dbt::rv32::lane_region;

namespace
{

int failures;

#define CHECK(tag, cond)                                                                                       \
	do {                                                                                                     \
		if (!(cond)) {                                                                                    \
			fprintf(stderr, "  FAIL [%s] %s:%d: %s\n", tag, __FILE__, __LINE__, #cond);              \
			++failures;                                                                                     \
		}                                                                                                    \
	} while (0)

constexpr u32 EncodeVV(u32 f6, u8 rd, u8 vs2, u8 vs1)
{
	return (f6 << 26) | (1u << 25) | ((u32)vs2 << 20) | ((u32)vs1 << 15) |
	       ((u32)rd << 7) | 0x57u;
}

lr::ShapeFacts GoodShape()
{
	return {lr::Proof::Yes, 1024, 32, 0, 32, 32, 0};
}

lr::CFGFacts GoodCFG(u32 entry, size_t n)
{
	return {lr::Proof::Yes, lr::Proof::Yes, lr::Proof::Yes, lr::Proof::Yes, entry,
		entry + (u32)n * 4u};
}

lr::Result Detect(std::vector<lr::CandidateMember> const &members, lr::CFGFacts cfg)
{
	return lr::Detect(lb::BuildInput(members, GoodShape(), cfg, lr::Proof::Yes));
}

void ExpectReject(char const *tag, std::vector<lr::CandidateMember> const &members,
		  lr::CFGFacts cfg, lr::Reject want)
{
	auto const result = Detect(members, cfg);
	auto const *reject = std::get_if<lr::Reject>(&result);
	CHECK(tag, reject && *reject == want);
}

} // namespace

int main()
{
	printf("T7g real-candidate bridge focused negatives\n");
	u32 const add = EncodeVV(0b000000, 8, 10, 12);
	u32 const sub = EncodeVV(0b000010, 14, 8, 16);

	// No QIR proof was supplied: BuildMember must not manufacture one from route membership.
	std::vector<lr::CandidateMember> unknown{
		lb::BuildMember(0x1000, add, lr::Proof::Yes, {})};
	CHECK("unknown_preserved",
	      unknown[0].metadata_complete == lr::Proof::Unknown &&
		      unknown[0].ssa_defs_present == lr::Proof::Unknown &&
		      unknown[0].overlap_snapshot_proven == lr::Proof::Unknown);
	ExpectReject("unknown_reject", unknown, GoodCFG(0x1000, 1), lr::Reject::UNKNOWN_METADATA);

	lb::QIRMemberFacts qir{lr::Proof::Yes, lr::Proof::Yes};
	std::vector<lr::CandidateMember> safe{
		lb::BuildMember(0x2000, add, lr::Proof::Yes, qir),
		lb::BuildMember(0x2004, sub, lr::Proof::Yes, qir)};
	auto const accepted = Detect(safe, GoodCFG(0x2000, safe.size()));
	auto const *cert = std::get_if<lr::Certificate>(&accepted);
	CHECK("real_facts_certify", cert && cert->members.size() == 2 &&
				      cert->members[0].pc == 0x2000 && cert->members[1].pc == 0x2004);

	// A negative mutation of a source fact must remain negative; the bridge cannot overwrite it.
	auto side_effect = safe;
	side_effect[0].memory_read_or_write = lr::Proof::Yes;
	ExpectReject("side_effect_reject", side_effect, GoodCFG(0x2000, side_effect.size()),
		     lr::Reject::MEMORY_READ_OR_WRITE);

	auto cfg = GoodCFG(0x2000, safe.size());
	cfg.single_block = lr::Proof::No;
	ExpectReject("cfg_boundary_reject", safe, cfg, lr::Reject::MULTI_ENTRY_OR_NONLOCAL_CFG);

	auto unknown_effect = safe;
	unknown_effect[0].scalar_or_csr_effect = lr::Proof::Unknown;
	unknown_effect[0].metadata_complete = lr::Proof::Unknown;
	ExpectReject("unknown_effect_reject", unknown_effect,
		     GoodCFG(0x2000, unknown_effect.size()), lr::Reject::UNKNOWN_METADATA);

	// An actual refused route is known No; absent QIR is known No, not a fabricated definition.
	lb::QIRMemberFacts no_qir{lr::Proof::No, lr::Proof::Yes};
	std::vector<lr::CandidateMember> refused{
		lb::BuildMember(0x3000, add, lr::Proof::No, no_qir)};
	ExpectReject("route_refused", refused, GoodCFG(0x3000, 1), lr::Reject::ROUTE_NOT_ADMITTED);

	CHECK("memory_boundary", lb::ClassifyBoundaryRaw(0x0205e087u) ==
				 lr::Reject::MEMORY_READ_OR_WRITE);
	CHECK("control_boundary", lb::ClassifyBoundaryRaw(0x00b50063u) ==
				  lr::Reject::CONTROL_FLOW_OR_SIDE_EXIT);

	if (failures) {
		fprintf(stderr, "T7G_BRIDGE_TEST: FAIL (%d)\n", failures);
		return 1;
	}
	printf("T7G_BRIDGE_TEST: PASS\n");
	return 0;
}
