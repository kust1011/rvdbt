#include "dbt/guest/rv32_lane_region_bridge.h"

#include "dbt/guest/rv32_vrun.h"

#include <algorithm>
#include <map>
#include <mutex>

namespace dbt::rv32::lane_region_bridge
{

namespace
{

lr::Proof NegativeWhen(bool proof)
{
	return proof ? lr::Proof::No : lr::Proof::Unknown;
}

std::mutex g_lock;
std::vector<Observation> g_observations;

bool SameObservation(Observation const &a, Observation const &b)
{
	if (a.cfg.entry_pc != b.cfg.entry_pc || a.cfg.boundary_pc != b.cfg.boundary_pc ||
	    a.members.size() != b.members.size() || a.result.index() != b.result.index() ||
	    a.has_first_cut != b.has_first_cut || a.first_cut != b.first_cut ||
	    a.first_cut_pc != b.first_cut_pc)
		return false;
	for (size_t i = 0; i < a.members.size(); ++i)
		if (a.members[i].pc != b.members[i].pc || a.members[i].raw != b.members[i].raw)
			return false;
	if (auto const *ar = std::get_if<lr::Reject>(&a.result)) {
		auto const *br = std::get_if<lr::Reject>(&b.result);
		return br && *ar == *br;
	}
	auto const *ac = std::get_if<lr::Certificate>(&a.result);
	auto const *bc = std::get_if<lr::Certificate>(&b.result);
	return ac && bc && ac->members.size() == bc->members.size();
}

void PrintHexList(FILE *f, char const *name, std::vector<lr::CandidateMember> const &members,
		  bool raw)
{
	fprintf(f, " %s=", name);
	for (size_t i = 0; i < members.size(); ++i)
		fprintf(f, "%s%08x", i ? "," : "", raw ? members[i].raw : members[i].pc);
}

} // namespace

lr::CandidateMember BuildMember(u32 pc, u32 raw, lr::Proof route_admitted,
				QIRMemberFacts const &qir)
{
	lr::CandidateMember out;
	out.pc = pc;
	out.raw = raw;
	out.route_admitted = route_admitted;
	auto const route = rvvrun::ClassifyTypedAluRoute(raw);
	if (!route.present)
		return out;

	// Each field comes from one named proof in the route table or the real QIR caller.  In
	// particular, none of these assignments uses a generic "present means everything is safe".
	//
	// P7M-A. THE TWO FP ROWS ANSWER SOME OF THESE POSITIVELY RATHER THAN LEAVING THEM UNKNOWN.
	// `vector_state_only` is FALSE on those rows (rv32_vrun.h says why: the integer sentence is
	// not true of a route that touches host FP control state and CPUState::fpu), so the four
	// derived facts below would all become UNKNOWN and the detector would report the generic
	// UNKNOWN_METADATA for an instruction whose disqualifying property is precisely known. What
	// the FP rows do establish -- `fp_vector_state_only` -- is the same "no guest memory, no
	// GPR, no control transfer, no vector-to-scalar" statement PLUS a named FP/fflags effect. So
	// the FP effect is asserted as a positive fact and the rest are derived from either
	// property. This detector is analysis-only and refuses these candidates either way; the
	// choice is between a precise reason and a generic one.
	//
	// THE ONE PLACE THE SPLIT NEEDS SPELLING OUT is `scalar_or_csr_effect`. An FP row DOES read
	// f[rs1] (the `.vf` broadcast) and DOES write the accrued bits of fcsr, and fcsr is a CSR.
	// Those two are exactly what `fp_or_fflags_effect` names, and it is asserted Yes below, so
	// reporting them a second time here would only decide which of two names the diagnostic
	// prints -- SCALAR_OR_CSR_EFFECT is checked first. `scalar_or_csr_effect` therefore keeps
	// its narrower meaning for these rows: no GPR effect, and no CSR effect OTHER than the
	// accrued fflags. Both facts are still positive and neither is Unknown, so the candidate is
	// refused with the accurate reason rather than the generic UNKNOWN_METADATA.
	bool const state_confined = route.vector_state_only || route.fp_vector_state_only;
	out.cross_chunk_def_use = NegativeWhen(route.lane_local);
	out.scalar_or_csr_effect = NegativeWhen(state_confined);
	out.vector_to_scalar = NegativeWhen(state_confined);
	out.fp_or_fflags_effect =
	    route.fp_host_arith ? lr::Proof::Yes : NegativeWhen(route.vector_state_only);
	out.memory_read_or_write = NegativeWhen(state_confined);
	out.atomic_mmio_or_unknown_pma = NegativeWhen(state_confined);
	out.control_or_side_exit = NegativeWhen(state_confined);
	out.may_trap_or_helper = NegativeWhen(route.nontrapping_fast_path);
	out.ssa_defs_present = route.chunk_ssa_present ? qir.ssa_defs_present : lr::Proof::Unknown;
	out.overlap_snapshot_proven = route.overlap_snapshot_proven
					  ? qir.overlap_snapshot_proven
					  : lr::Proof::Unknown;
	// P7M-A: the operand KINDS come from the shared route rule, not from `(1 << rs1) | (1 << rs2)`.
	// An OPFVF rs1 names an F register and is not a vector use; a fused form's vd is one, and is
	// also the old destination. The six integer rows are unchanged by both.
	out.vector_uses = rvvrun::RouteVectorUses(route);
	out.vector_defs = 1u << route.rd;
	out.old_destination = rvvrun::RouteOldDestination(route);

	lr::Proof const required[] = {
		out.route_admitted,
		out.cross_chunk_def_use,
		out.scalar_or_csr_effect,
		out.vector_to_scalar,
		out.fp_or_fflags_effect,
		out.memory_read_or_write,
		out.atomic_mmio_or_unknown_pma,
		out.may_trap_or_helper,
		out.control_or_side_exit,
		out.ssa_defs_present,
		out.overlap_snapshot_proven,
	};
	out.metadata_complete = lr::Proof::Yes;
	for (lr::Proof fact : required)
		if (fact == lr::Proof::Unknown)
			out.metadata_complete = lr::Proof::Unknown;
	return out;
}

lr::Input BuildInput(std::span<lr::CandidateMember const> members, lr::ShapeFacts const &shape,
		     lr::CFGFacts const &cfg, lr::Proof backend_can_hold_private)
{
	lr::Input in;
	in.members = members;
	in.shape = shape;
	in.cfg = cfg;
	in.route_table_version = rvvrun::kTypedAluRouteTableVersion;
	in.backend_can_hold_private = backend_can_hold_private;
	return in;
}

lr::Reject ClassifyBoundaryRaw(u32 raw)
{
	lr::CandidateMember member;
	member.pc = 0x1000;
	member.raw = raw;
	// This helper asks only the detector's rejection-only raw decoder. Marking the wrapper
	// record present is not a safety proof: unsupported raw words are classified before any
	// member fact is consulted, while an admitted row still reaches UNKNOWN_METADATA below.
	member.metadata_complete = lr::Proof::Yes;
	lr::ShapeFacts shape{lr::Proof::Yes, 1024, 32, 0, 32, 32, 0};
	lr::CFGFacts cfg{lr::Proof::Yes, lr::Proof::Yes, lr::Proof::Yes, lr::Proof::Yes, 0x1000,
			  0x1004};
	auto const result = lr::Detect(BuildInput(std::span(&member, 1), shape, cfg, lr::Proof::Yes));
	if (auto const *reject = std::get_if<lr::Reject>(&result))
		return *reject;
	return lr::Reject::UNKNOWN_METADATA;
}

void Record(Observation observation)
{
	std::lock_guard lock(g_lock);
	for (auto const &old : g_observations)
		if (SameObservation(old, observation))
			return;
	g_observations.push_back(std::move(observation));
}

void Reset()
{
	std::lock_guard lock(g_lock);
	g_observations.clear();
}

bool Dump(char const *path)
{
	std::lock_guard lock(g_lock);
	FILE *f = path && *path ? fopen(path, "w") : stderr;
	if (!f)
		return false;

	std::sort(g_observations.begin(), g_observations.end(), [](auto const &a, auto const &b) {
		if (a.cfg.entry_pc != b.cfg.entry_pc)
			return a.cfg.entry_pc < b.cfg.entry_pc;
		if (a.cfg.boundary_pc != b.cfg.boundary_pc)
			return a.cfg.boundary_pc < b.cfg.boundary_pc;
		return a.members.size() < b.members.size();
	});

	std::map<size_t, size_t> lengths;
	std::map<lr::Reject, size_t> rejects, cuts;
	std::map<u32, size_t> entries;
	std::map<u32, size_t> member_owners;
	size_t certified = 0;
	for (auto const &o : g_observations) {
		entries[o.cfg.entry_pc]++;
		for (auto const &m : o.members)
			member_owners[m.pc]++;
		fprintf(f, "T7G_CANDIDATE entry=%08x boundary=%08x", o.cfg.entry_pc,
			o.cfg.boundary_pc);
		PrintHexList(f, "pcs", o.members, false);
		PrintHexList(f, "raws", o.members, true);
		if (auto const *cert = std::get_if<lr::Certificate>(&o.result)) {
			fprintf(f, " result=CERTIFIED length=%zu", cert->members.size());
			lengths[cert->members.size()]++;
			certified++;
		} else {
			auto const reject = std::get<lr::Reject>(o.result);
			fprintf(f, " result=REJECT reason=%s", lr::RejectName(reject));
			rejects[reject]++;
		}
		if (o.has_first_cut) {
			fprintf(f, " first_cut=%s first_cut_pc=%08x", lr::RejectName(o.first_cut),
				o.first_cut_pc);
			cuts[o.first_cut]++;
		} else {
			fprintf(f, " first_cut=NONE first_cut_pc=%08x", o.first_cut_pc);
		}
		fputc('\n', f);
	}

	size_t conflicts = 0, overlaps = 0;
	for (auto const &[pc, count] : entries)
		if (count > 1)
			conflicts += count - 1;
	for (auto const &[pc, count] : member_owners)
		if (count > 1)
			overlaps += count - 1;
	fprintf(f,
		"T7G_SUMMARY candidates=%zu certified=%zu rejected=%zu unique_entries=%zu "
		"entry_conflicts=%zu member_overlaps=%zu\n",
		g_observations.size(), certified, g_observations.size() - certified, entries.size(),
		conflicts, overlaps);
	for (auto const &[length, count] : lengths)
		fprintf(f, "T7G_LENGTH length=%zu count=%zu\n", length, count);
	for (auto const &[reason, count] : rejects)
		fprintf(f, "T7G_REJECTION reason=%s count=%zu\n", lr::RejectName(reason), count);
	for (auto const &[reason, count] : cuts)
		fprintf(f, "T7G_FIRST_CUT reason=%s count=%zu\n", lr::RejectName(reason), count);

	bool ok = fflush(f) == 0;
	if (f != stderr)
		ok = fclose(f) == 0 && ok;
	return ok;
}

} // namespace dbt::rv32::lane_region_bridge
