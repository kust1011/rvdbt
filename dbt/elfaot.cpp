#include "dbt/aot/aot.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/tcache/objprof.h"
#include "dbt/tcache/tcache.h"
#include "dbt/ukernel.h"
#include "dbt/util/fsmanager.h"
#include <boost/any.hpp>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace bpo = boost::program_options;

namespace dbt { void add_stable_load(unsigned, unsigned); } // Family-A oracle, defined in rv32_qir.cpp
namespace dbt { void add_stable_jalr_target(unsigned, unsigned); } // C2 ceiling oracle, defined in rv32_qir.cpp

// A-line 2026-07-23 (--aot-edge-select-flow): FLOW-CERTAIN DOMINANCE region selection.
// Consumer-semantics derivation: h9's exclusive/acyclic answers TOPOLOGY questions from the edge
// SET alone; mass questions (which target dominates a source's dispatch) need weights the epoch
// SET does not provide and the falsified first-wins IC cannot provide. This rule derives edge
// weights from CONSERVATION INVARIANTS instead of new counting: per-source outflow equals the
// source block's (exact, per-block arrival) execution count, and per-target inflow equals the
// target's count WHEN the target is reachable only via dispatch (brind_target, not a segment
// entry, no static CFG predecessor -- checked against the ModuleGraph, not assumed). Leaf-peeling
// solves every edge in a forest-decomposable component EXACTLY; non-forest components stay
// UNDETERMINED and the rule abstains (poly-B's complete-bipartite shape lands here by
// construction). Decision: internalize t into s iff w(s,t) is determined, t is not its own
// selected source (h9's role filter), no direct (t,s) back-edge, and w(s,t) is a STRICT MAJORITY
// of s's dispatch mass ("dominant" = more than everything else combined -- a structural notion,
// not a corpus threshold). Distinct from the in-tree jserv-A A0-A5 ADMISSION-weighting matrix
// (aot.cpp), which scores per-target admission credit; this decides region MERGE topology.
// Runs after ReproduceElfMappings so objprof marginals are available (unlike the SetupConfig-time
// selections).
static void ComputeFlowSelection(std::string const &edge_path, u64 /*threshold*/)
{
	using namespace dbt;
	std::ifstream ef(edge_path);
	unsigned long s3, d3;
	unsigned long long ct3;
	std::set<std::pair<u32, u32>> eset;
	std::map<u32, std::vector<u32>> out, in;
	while (ef >> std::hex >> s3 >> d3 >> std::dec >> ct3) {
		if (s3 == d3)
			continue;
		if (eset.insert({(u32)s3, (u32)d3}).second) {
			out[(u32)s3].push_back((u32)d3);
			in[(u32)d3].push_back((u32)s3);
		}
	}
	if (eset.empty())
		return;
	// marginals + flags + static-inbound from the profile / ModuleGraph
	std::unordered_map<u32, u64> exec;
	std::unordered_set<u32> brt, seg, static_in;
	for (auto const &page : objprof::GetProfile()) {
		u32 pv = page.pageno << mmu::PAGE_BITS;
		for (u32 idx = 0; idx < page.executed.size(); ++idx) {
			if (!page.executed[idx])
				continue;
			u32 ip = pv + objprof::PageData::idx2po(idx);
			exec[ip] = page.exec_count[idx];
			if (page.brind_target[idx])
				brt.insert(ip);
			if (page.segment_entry[idx])
				seg.insert(ip);
		}
		auto mg = BuildModuleGraph(page);
		for (auto const &[ip, node] : mg.ip_map) {
			for (auto *succ : node->succs)
				static_in.insert(succ->ip);
			for (u32 cs : node->cross_succs)
				static_in.insert(cs);
		}
	}
	// leaf-peeling flow solve
	std::map<std::pair<u32, u32>, long long> w; // determined edge weights
	std::map<u32, long long> src_res, tgt_res;
	std::map<u32, unsigned> src_unk, tgt_unk;
	std::set<u32> tgt_eligible;
	for (auto const &[sp, ts] : out) {
		src_res[sp] = (long long)(exec.count(sp) ? exec[sp] : 0);
		src_unk[sp] = (unsigned)ts.size();
	}
	for (auto const &[t, ss] : in) {
		if (brt.count(t) && !seg.count(t) && !static_in.count(t)) {
			tgt_eligible.insert(t);
			tgt_res[t] = (long long)(exec.count(t) ? exec[t] : 0);
			tgt_unk[t] = (unsigned)ss.size();
		}
	}
	bool progress = true;
	auto settle = [&](u32 sp, u32 t, long long v) {
		if (v < 0)
			v = 0; // conservation slack from the known stock-lossy +-1 classes; clamp, never negative
		w[{sp, t}] = v;
		src_res[sp] -= v;
		src_unk[sp]--;
		if (tgt_eligible.count(t)) {
			tgt_res[t] -= v;
			tgt_unk[t]--;
		}
	};
	while (progress) {
		progress = false;
		for (auto const &[sp, ts] : out) {
			if (src_unk[sp] == 1) {
				for (u32 t : ts)
					if (!w.count({sp, t})) {
						settle(sp, t, src_res[sp]);
						progress = true;
						break;
					}
			}
		}
		for (u32 t : tgt_eligible) {
			if (tgt_unk[t] == 1) {
				for (u32 sp : in[t])
					if (!w.count({sp, t})) {
						settle(sp, t, tgt_res[t]);
						progress = true;
						break;
					}
			}
		}
	}
	// CONSERVATION-RESIDUAL CONSISTENCY CHECK (structural false-negative detector): if a fully-
	// settled eligible target still has |residual| far beyond the known stock-lossy +-1 slack, the
	// SET missed at least one of its inbound edges (poly-E witness: src1->h1 absorbed; residual
	// 12.5M exposed it) -- every solved weight in that component is untrustworthy. Abstain on any
	// source touching an inconsistent target rather than act on a wrong-but-plausible flow.
	std::unordered_set<u32> inconsistent;
	for (u32 t : tgt_eligible) {
		if (tgt_unk[t] == 0 && (tgt_res[t] > 1024 || tgt_res[t] < -1024)) {
			// slack bound: +-1 per L1-insert/collision event, orders below any real flow
			inconsistent.insert(t);
			fprintf(stderr, "FLOW_INCONSISTENT tgt=%08x residual=%lld -- SET incomplete, component abstains\n",
				t, tgt_res[t]);
		}
	}
	std::unordered_set<u32> tainted_sources;
	for (u32 t : inconsistent)
		for (u32 sp : in[t])
			tainted_sources.insert(sp);
	// decision: strict-majority determined edges, role-exclusive, no direct back-edge
	std::unordered_map<uint32_t, std::vector<uint32_t>> candidate;
	// DECISION RULE v2 (objective-derived; the v1 source-majority rule was NOT derivable from the
	// merge objective and is killed by the F/G counterexample witnesses -- see
	// docs/P8_OBJECTIVE_DERIVATION.md): under copy semantics the internal copy of t serves exactly
	// the (s->t) flow while all other arrivals keep using the standalone copy; per-arrival benefit
	// applies to internally-served traffic and duplication is wasted in proportion to the traffic
	// NOT served. With a uniform per-event cost model this reduces to TARGET-PRIMARY-FLOW:
	// internalize t into s iff w(s,t) > A(t) - w(s,t), i.e. s carries the strict majority of t's
	// arrivals. Corollary: at most ONE source can win any target (per-target uniqueness for free).
	// A(t) is trustworthy only for dispatch-only-reachable targets (tgt_eligible); otherwise
	// abstain (conservative under uncertain support).
	for (auto const &[sp, ts] : out) {
		if (tainted_sources.count(sp))
			continue; // conservation inconsistency in this source's component
		long long m = (long long)(exec.count(sp) ? exec[sp] : 0);
		if (m <= 0)
			continue;
		for (u32 t : ts) {
			auto it = w.find({sp, t});
			if (it == w.end())
				continue; // undetermined component: abstain
			if (!tgt_eligible.count(t))
				continue; // A(t) unknown (not dispatch-only-reachable): abstain
			long long At = (long long)(exec.count(t) ? exec[t] : 0);
			if (2 * it->second <= At)
				continue; // s does not carry the strict majority of t's arrivals
			if (eset.count({t, sp}))
				continue; // direct back-edge (h9's cyclic guard)
			candidate[sp].push_back(t);
			fprintf(stderr, "FLOW_EDGE src=%08x tgt=%08x w=%lld of_src=%lld of_tgt=%lld\n", sp, t,
				it->second, m, At);
		}
	}
	for (auto &[sp, ts] : candidate) { // h9's role-exclusivity filter
		std::vector<uint32_t> kept;
		for (uint32_t t : ts)
			if (!candidate.count(t))
				kept.push_back(t);
		ts = std::move(kept);
	}
	unsigned ns = 0, nt = 0;
	for (auto const &[sp, ts] : candidate) {
		if (ts.empty())
			continue;
		dbt::config::aot_region_merge_map[sp] = ts;
		ns++;
		nt += (unsigned)ts.size();
		fprintf(stderr, "FLOW_SELECT src=%08x targets=%zu\n", sp, ts.size());
	}
	dbt::config::aot_edge_region_merge = dbt::config::aot_edge_region_merge || ns > 0;
	fprintf(stderr, "FLOW_SELECT_SUMMARY sources=%u targets=%u determined_edges=%zu of %zu\n", ns, nt,
		w.size(), eset.size());
}

struct ElfAotOptions {
	std::string elf{};
	std::string cache{};
	bool use_llvm{};
	std::string logs{};
	std::string mgdump{};
	bool analyser_ecall_edge{};
	bool aot_freq_gated_seed{};
	bool aot_brind_seed_oracle_suppress{};
	bool aot_link_region_merge{};
	bool aot_link_multientry_merge{};
	bool aot_link_alias_merge{};
	bool aot_link_multientry_trace{};
	bool aot_function_closure{};
	bool aot_jumptable_closure{};
	bool aot_jumptable_multientry{};
	bool aot_return_closure{};
	bool aot_closure_cold_section{};
	bool aot_fdre_region{};
	bool aot_idf_fuse{};
	std::string aot_fdre_edges{};
	bool aot_fdre_lower{};
	bool aot_guardonly_lower{};
	std::string aot_guardonly_edges{};
	bool aot_multiguard_lower{};
	std::string aot_multiguard_edges{};
	bool aot_brcc_real_weights{};
	bool aot_gbrind_hitrate_weights{};
	std::string aot_gbrind_hitrate_file{};
	bool qcg_leaf_inline{};
	u64 threshold{};
	u64 threshold_max{};
	bool llvmopt{};
	bool cross_segment_branch{};
	bool propagate_exec_count{};
	u64 dispatch_admit_floor{};
	std::string dispatch_admit_list{};
	std::string dispatch_deny_list{};
	bool gbrind_hitrate_collect{};
	u64 return_admit_floor{};
	double return_admit_cost_ratio{};
	bool return_admit_optnone{};
	std::string aot_region_order_file{};
	std::string aot_indirect_succs_file{};
	bool aot_dump_indirect_succs{};
	std::string aot_diag_link_bitcode{};
	std::string aot_diag_direct_funcs{};
	std::string aot_diag_inline_funcs{};
	std::string aot_dump_llvm_ir{};
	std::string aot_dump_llvm_ir_preopt{};
	std::string aot_qir_known_targets_file{};
	bool aot_dump_qir_known_targets{};
	bool aot_gbrind_vp_metadata{};
	bool aot_log_icp{};
	bool aot_log_phase_timing{};
	int aot_optlevel{};
	bool dispatch_handler_optnone{};
	u64 aot_hot_floor{};
	bool aot_cpb_optnone{};
	unsigned aot_merge_max{};
	bool aot_heavy_final{};
	unsigned aot_heavy_last_n{};
	unsigned aot_heavy_min_regions{};
	int aot_final_expand_at{-1};
	int aot_phase1_optlevel{-1};
	bool aot_log_expand{};
	bool aot_log_gbrind_constfold{};
	bool aot_use_lld{};
	int aot_codegen_optlevel{-1};
	bool aot_log_irsize{};
	bool aot_reassoc_probe{};
	bool aot_edge_specialize{};
	bool aot_edge_oracle_unconditional{};
	bool aot_return_oracle_unconditional{};
	bool aot_log_gipv_shape{};
	bool aot_dump_gbrind_indegree{};
	bool aot_log_gbrind_site_identity{};
	bool aot_order1_context_oracle{};
	std::string aot_order1_context_file{};
	bool aot_marginal_context_oracle{};
	bool aot_static_table_oracle{};
	std::string aot_static_table_file{};
	bool aot_static_table_inline{};
	bool aot_static_table_alwaysinline{};
	bool aot_static_table_switch_noinline{};
	bool aot_static_table_target_optnone{};
	bool aot_indexed_dispatch_oracle{};
	bool aot_indexed_dispatch_require_full_coverage{};
	bool aot_vtable_narrow_oracle{};
	bool aot_vtable_narrow_inline{};
	bool aot_direct_call_fusion{};
	bool aot_return_directify{};
	bool aot_vtable_narrow_zeroguard_singleton{};
	bool aot_gbrind_context_replicate{};
	unsigned aot_edge_topk{};
	std::string aot_edge_profile{};
	std::string aot_indirect_edges{};
	bool aot_indirect_propagate{true};
	int aot_admit_mode{};
	bool aot_edge_underadmit_gate{};
	bool aot_edge_region_merge{};
	bool aot_edge_closure_merge{};
	bool aot_edge_select_exclusive{};
	bool aot_edge_select_acyclic{};
	bool aot_edge_move_not_copy{};
	bool aot_edge_select_flow{};
	unsigned repeat_compile{1};
	bool aot_count_gbrind{};
	bool aot_work_counter{};
	bool aot_region_cycle_count{};
	bool aot_region_hit_count{};
	std::string aot_region_hit_map_out{};
	bool sr_activation_invariant{};
	bool dry_page_floor{};
	bool aot_context_edge_specialize{};
	unsigned aot_context_edge_topk{};
	std::string aot_context_edge_profile{};
	std::string aot_pipeline{};
	int aot_shard_mod{};
	int aot_shard_idx{};
	int aot_shard_link{};
	bool dump_applicability{};
	bool dump_regions{};
	bool dump_regions_internal_edges{};
	bool dump_loop_vs_idf{};         // Cycle-13 Phase-0: measure loop-vs-IDF split surface (behavior-neutral)
	bool loop_structural_regions{};  // Cycle-13 Phase-1: loop-closed structural regions (default-off method)
	bool aot_loop_entry{};           // T5c-0: late-enterable loop entries (no per-loop hotness gate)
	bool aot_loop_regions{};         // T5d1b: compile selected hot natural loops as header-rooted regions
	std::string aot_loop_regions_qir_out{}; // T5d1b: QIR of every emitted loop region
	bool dump_loop_candidates{};     // T5d1a: canonical hot-natural-loop candidate dry-run dump
	std::string dump_loop_candidates_out{}; // T5d1a: where it goes ("" = stdout)
	bool dump_region_spill_exposure{}; // Cycle-14 SEGA Phase-0: per-region spill-exposure dump (behavior-neutral, PBA path)
	std::string return_headroom_edges_file{};
	unsigned vlen{128};
	bool rvv_vector_run{};
	bool rvv_run_scalar_passthrough{};
	bool rvv_run_component_separable{};
	bool rvv_run_component_demand_placement{};
	bool rvv_run_grouped_component_major{};
	bool rvv_qcg_active_vl_run_bound{};
	bool rvv_qcg_active_vl_bound_placebo{};
	std::string rvv_run_body{"ssa"};
	std::string rvv_run_order{"member"};
	bool rvv_qcg_hit_counter{true};
	bool rvv_vector_ssa{};
	bool rvv_llvm_wide_vadd{};
	bool rvv_llvm_wide_vadd_ssa{};
	bool rvv_vector_ssa_counters{};
	bool rvv_qcg_direct_setvl{};
	bool rvv_qcg_vx_mulacc{};
	bool rvv_qcg_typed_chunk_falu{};
	bool rvv_qcg_typed_chunk_fma{};
	bool rvv_qcg_typed_chunk_fsqrt{};
	bool rvv_qcg_typed_chunk_fredosum{};
	bool rvv_qcg_typed_chunk_wholemove{};
	bool rvv_llvm_setvl_reg{};
	bool rvv_llvm_scalar_move{};
	bool rvv_llvm_partial_vl{};
	bool rvv_llvm_shift{};
	bool rvv_llvm_extend{};
	bool rvv_llvm_fclass{};
	bool rvv_llvm_fcvt_itof{};
	bool rvv_llvm_fcvt_ftoi{};
	bool rvv_llvm_fcvt_fwiden{};
	bool rvv_llvm_fcvt_fnarrow{};
	bool rvv_llvm_fcvt_itof_widen{};
	bool rvv_llvm_fcvt_ftoi_widen{};
	bool rvv_llvm_fcvt_partial_vl{};
	bool rvv_llvm_masked{};
	bool rvv_llvm_fp_masked{};
	bool rvv_llvm_restart{};
	bool rvv_llvm_fcvt_rod{};
	bool rvv_llvm_festimate{};
	bool rvv_llvm_fmerge{};
	bool rvv_llvm_fwiden{};
	bool rvv_llvm_satadd{};
	bool rvv_llvm_adc{};
	bool rvv_llvm_avg{};
	bool rvv_llvm_smul{};
	bool rvv_llvm_nclip{};
	bool rvv_llvm_ired{};
	bool rvv_llvm_mlogic{};
	bool rvv_llvm_icmp{};
	bool rvv_llvm_mem_partial_vl{};
	bool rvv_llvm_vid{};
	bool rvv_llvm_mscalar{};
	bool rvv_llvm_mprefix{};
	bool rvv_llvm_viota{};
	bool rvv_llvm_vcompress{};
	bool rvv_llvm_vrgather{};
	bool rvv_llvm_vslide{};
	bool rvv_llvm_vstrided{};
	bool rvv_llvm_vindexed{};
	bool rvv_llvm_fixed_masked{};
	bool rvv_llvm_fp_cvt_masked{};
	bool rvv_llvm_fp_dynamic_frm{};
	bool rvv_llvm_fwiden_partial_vl{};
	bool rvv_llvm_fwiden_masked{};
	bool rvv_llvm_widen{};
	bool rvv_llvm_narrow{};
	bool rvv_llvm_fp_partial_vl{};
	bool rvv_qcg_typed_chunk_mem_e64{};
	bool rvv_qcg_partial_vl{};
	bool rvv_qcg_typed_chunk_vle{};
	bool rvv_qcg_typed_chunk_vse{};
	bool rvv_qcg_typed_chunk_sub{};
	bool rvv_qcg_typed_chunk_xor{};
	bool rvv_qcg_typed_chunk_or{};
	bool rvv_qcg_typed_chunk_and{};
	bool rvv_qcg_typed_chunk_mul{};
};

static void PrintHelp(bpo::options_description &adesc)
{
	std::cout << "usage: [options]\n";
	std::cout << adesc << "\n";
}

static bool ParseOptions(ElfAotOptions &o, int argc, char **argv)
{
	bpo::options_description adesc("options");
	// clang-format off
	adesc.add_options()
	    ("help",   "help")
	    ("logs",   bpo::value(&o.logs)->default_value(""), "enabled log streams separated by :")
	    ("elf", bpo::value(&o.elf)->required(), "elf file to translate")
	    ("cache",  bpo::value(&o.cache)->required(), "dbt cache path")
	    ("vlen", bpo::value(&o.vlen)->default_value(128), "specialized RVV VLEN in bits for typed LLVM-AOT vector SSA")
	    ("rvv-vector-run", bpo::value(&o.rvv_vector_run)->default_value(false), "R1A.3b/R1A.3d: form the vector-run (VRUN) descriptor at translation time and record it in the run counters. Scans forward from each instruction and applies the R1A.2 A1-A5 semantic membership predicates -- A1 by calling each operation's OWN typed-chunk admission predicate -- cutting at memory, helper-only, mask/cross-lane, branch/block boundary, vset{i}vl{i}, unsupported shape and the host vector-register pressure bound. With it on, a run of two or more admitted members is lowered as ONE guarded frame (R1A.3b); every other instruction is still translated by exactly the route it would take with this off. See --rvv-run-body for which body that frame emits. Default off")
	    ("rvv-run-scalar-passthrough", bpo::value(&o.rvv_run_scalar_passthrough)->default_value(false), "Pure ablation factor for the vector run's MEMBERSHIP rule: whether the three non-trapping RV32 integer ALU forms (add, addi, sub) may be carried through a run to BRIDGE two vector members, so that address/counter maintenance sitting between them does not cut the vector island. 0 (default) makes them ordinary non-members that cut the run with ScalarInsn, exactly as every other scalar instruction does -- no descriptor carries a RunOp::Scalar member, no frame emits an `rvvrunscalar` op and n_scalar_members is zero everywhere. 1 applies the bridging rule. Unlike --rvv-run-body and --rvv-run-order, which are BODY selectors that must never reach admission, this switch is read on the ADMISSION side only (rvvrun::Classify) and in no body, no emitter and no execution path: its subject IS which instructions are members, so its two arms are expected to form different runs. Requires --rvv-vector-run=1")
	    ("rvv-run-component-separable", bpo::value(&o.rvv_run_component_separable)->default_value(false), "P7O-1 component-separable vector runs. A run whose members are all provably lane-local can be executed one host component at a time -- pass-1 loads, the member body and pass-3 stores inside one component loop -- in which case only ONE component is live at a time and the admission liveness bound loses its nchunks factor. 0 (default) makes RunDescriptor::component_separable false on EVERY descriptor, so the predicate's answer is absent rather than merely unused, and no bound, body, host byte or counter differs from a build without this switch. 1 lets a run take the component-resident bound ONLY IF every member satisfies the conservative P1-P11 predicate AND that bound is not larger than the existing one for that run, so it can never cut a run the default arm admits; such a run is then emitted with the component-major load/body/store order selected by the SAME descriptor decision that chose the bound, while every other run keeps the existing bound and body. The frame-scope broadcasts and the single FP bracket stay outside the component loop and the typed-op accounting is unchanged. Like --rvv-run-scalar-passthrough and unlike the body selectors, this is an ADMISSION-side switch: its two arms are EXPECTED to form different runs, so any ablation using it must report runs_formed/multi_member_runs/members_admitted and the register_pressure cut alongside any timing. Requires --rvv-vector-run=1; refused with --rvv-run-body=materialize, --rvv-run-live-range-split=1 or --rvv-run-order=chunk, each of which manages pass 1/2/3 residency itself")
	    ("rvv-run-grouped-component-major", bpo::value(&o.rvv_run_grouped_component_major)->default_value(false), "C4e grouped component-major vector-run body, the ARM an active-suffix bound can be placed on and the CONTROL for it. 0 (default) leaves every run body exactly as it is -- not one node, host byte or counter differs from a build without this switch. 1 emits a run whose guard both bounds vec.vl by vlmax and does NOT prove vl == VLMAX (on the run path that is exactly the all-FP partial-vl kind) as nchunks contiguous COMPONENT SLICES: per component, its own active-lane mask node, pass-1 loads, every member's work for that component, pass-3 stores. That order is what makes a frame's entirely-inactive components a contiguous TAIL of the body for every member at once -- a run has ONE vtype and therefore ONE element-to-component map shared by all its members -- which the member-major order does not have. It is an EMISSION-side switch: the same runs are formed from the same descriptors under the same admission bound, so unlike --rvv-run-component-separable its arms do not have to report run-shape counters. A run is refused and keeps the existing body unless it has at least two components, one mask node per component, the P1-P11 lane-locality predicate holds, and the component-resident liveness bound fits the host pool. This switch does NOT insert any bound; --rvv-qcg-active-vl-run-bound does. Requires --rvv-vector-run=1; refused with --rvv-run-body=materialize, --rvv-run-live-range-split=1, --rvv-run-order=chunk, --rvv-run-component-separable=1 or --rvv-run-dep-probe-depth > 0")
	    ("rvv-qcg-active-vl-run-bound", bpo::value(&o.rvv_qcg_active_vl_run_bound)->default_value(false), "C4e active-VL bound on a grouped component-major run frame: the fourth member of the --rvv-qcg-active-vl-* policy family and the ONLY factor separating a bounded run arm from its control. 0 (default) emits the grouped body with no bound node in it. 1 lets the shared planner place one active-VL bound before each boundable component slice, so a runtime vl that leaves a component entirely in the tail set skips that component and every later one -- for every member of the run at once. The planner's own conjuncts decide which frames qualify (guard bounds vl by vlmax and does not prove vl == VLMAX, one mask node per unit, no partial arm, no forbidding per-unit effect, at most 64 components); nothing here names an opcode, a guest pc, a VLEN or a threshold. The two arms' bodies are identical node for node except for the bound nodes. Requires --rvv-run-grouped-component-major=1: on a member-major body the early exit would jump past LATER MEMBERS, which QEmit::Emit_vchunkactive Panics on")
	    ("rvv-qcg-active-vl-bound-placebo", bpo::value(&o.rvv_qcg_active_vl_bound_placebo)->default_value(false), "C4h EVALUATION-ONLY MEASUREMENT CONTROL (default off, QCG only). NOT a lowering, NOT a policy, NOT a method, and it must never be defaulted on or cited in any performance claim. It exists so a bounded arm can be compared against an arm carrying the SAME emitted code shape that never skips: it weakens the immediate each vchunkactive node compares vec.vl against, from that unit's own first element index to 0. The node is still created, by the same finalizer, at the same position, with the same chunk index, and QEmit emits the same `cmp [vec.vl], imm` + `jbe` to the same body-done label. `vl <= 0` is true only for the architecturally empty vector, which the real bound's own unit-0 immediate is already true for, so this arm skips a SUBSET of what the real arm skips and its results are correct on every path -- a smaller comparison value can only skip less, never more. It does NOT touch the planner's element_base, which the guarded unit's own lane mask also uses. Requires --rvv-qcg-active-vl-run-bound=1: with no bound node to weaken it would name an arm identical to its control")
	    ("rvv-run-component-demand-placement", bpo::value(&o.rvv_run_component_demand_placement)->default_value(false), "P7O-2 demand-driven CPUState placement inside the component-major body. 0 (default) emits the accepted P7O-1 body: per component, pass 1 loads every live-in chunk, the members run, pass 3 stores every live-out chunk -- not one node differs from a build without this switch. 1 keeps EXACTLY those nodes and moves only where the CPUState accesses sit: a live-in's chunk load is emitted immediately before the first member of that component that reads it (Rule L), and a live-out's chunk store immediately after the member RunDescriptor::last_def names has finished that component (Rule S, the earliest safe point -- before it the value is not final, after it it never changes). The arithmetic is untouched: same lane ops, same linear order, same SSA operands, same declared n_typed; the state accesses are untouched in COUNT (popcount(live_in_mask) loads and popcount(live_out_mask) stores per component, asserted per component), so only their POSITION differs. Register ASSIGNMENT is not claimed identical -- the allocator sees a different value order -- the same caveat --rvv-run-order carries. Unlike --rvv-run-component-separable this is an EMISSION-side switch read after admission, so both arms form the SAME runs from the SAME descriptors under the SAME bound; it cannot raise the peak, because Rule L only moves a birth later and Rule S only moves a last use earlier, making the live set at every arithmetic anchor a subset of the default arm's. A strict no-op at VLEN 512, where P1 (nchunks >= 2) admits no component-separable run at all. Requires --rvv-run-component-separable=1 and inherits its exclusions; additionally refused with --rvv-run-dep-probe-depth > 0, whose vchunkdep nodes would make Rule S anchor a store before the stored value stops changing")
    ("rvv-run-body", bpo::value(&o.rvv_run_body)->default_value("ssa"), "R1A.3d ablation body selector for a CONSUMED vector run: `ssa` (default) keeps the accepted R1A.3b component-SSA body -- each live-in chunk loaded once, the members run over SSA values, each final live-out chunk stored once; `materialize` emits the SAME body the single-instruction route emits, once per member, so the members still hand values to each other through CPUState. Both settings produce the same admission decision, the same descriptor, the same single guard, the same join and the same ordered fallback arm; the ONLY difference is the intermediate's CPUState reloads. Read in exactly one place (RV32Translator::RvvEmitVectorRunGroup) and never by admission. Ignored when --rvv-vector-run is 0")
	    ("rvv-run-order", bpo::value(&o.rvv_run_order)->default_value("member"), "P6C/P6A-Estimand-D issue-order selector for the vector-run SSA body: `member` (default) keeps the accepted order -- guest order outside, chunk inside -- so a guest op's sibling chunks are issued adjacently (L1,H1,L2,H2,...); `chunk` swaps the two loops so one whole independent chunk chain is issued before the next begins (L1,L2,...,Ln,H1,H2,...,Hn). The k chunks are k disjoint dataflow components (every read and write of a component value uses one fixed chunk index), so both are legal linear extensions of the SAME SSA value graph. THIS FLAG CHANGES EMISSION ORDER ONLY. Both settings produce the same admission decision, the same descriptor, the same nchunks/chunk_bytes/member list/n_typed, the same RVV_RUN/RVV_RUN_CUT counters, the same single guard, the same join, the same ordered fallback arm, the same pass-1 loads and pass-3 stores and the same emitted host instruction multiset; register ASSIGNMENT is not claimed identical, because the allocator sees a different order. Both orders are emitted by the SAME body (RvvEmitVectorRunGroup's shared per-member emitter, called over the whole chunk range for `member` and one component at a time for `chunk`), so every member kind the run substrate admits -- ALU, FP add/sub/mul/div, FMA, move/broadcast, whole-register load/store and the OPMVX multiply/accumulate -- is lowered identically in both. Read only on the emission side and NEVER by admission: no path reachable from rvvrun::FormRun or its MemberAdmit callback inspects it. Ignored when --rvv-vector-run is 0 or --rvv-run-body is materialize. ONE EXCLUSION REMAINS, and it is empty by default: a run carrying a --rvv-run-scalar-passthrough member is not lowered as a run in `chunk` order, because the scalar member is the one emitter arm that is not per-component and would otherwise execute k times. With that switch at its default 0 no descriptor carries such a member")
	    ("rvv-qcg-hit-counter", bpo::value(&o.rvv_qcg_hit_counter)->default_value(true), "R1A.3d: emit the QCG research hit counter (CPUState::rvv_direct_hits), one `inc` at the join of every typed frame, on the timed fast path. Default 1, which keeps every accepted pinned golden byte-identical. Set 0 for a counter-free timing arm: the frozen R1A.3c microkernel executes six typed frames per strip step with --rvv-vector-run 0 and five with it on, so this removes six and five instructions per strip step respectively. The guard-miss rvv_direct_fallbacks counter is deliberately NOT gated -- it is on the cold arm, costs a guard-hit arm nothing, and keeps guard_fallbacks==0 usable as a validity gate")
	    ("rvv-vector-ssa", bpo::value(&o.rvv_vector_ssa)->default_value(false), "enable typed fixed-512-bit RVV chunks, masks and EVL in QIR/LLVM AOT")
	    ("rvv-qcg-partial-vl", bpo::value(&o.rvv_qcg_partial_vl)->default_value(false), "allow partial VL in supported unmasked e32 integer SSA runs containing vmul.vx/vmacc.vx; preserve inactive destination lanes with LLVM masked stores. Requires --rvv-vector-run=1 and --rvv-vector-ssa=1; unsupported bodies retain their existing guard/fallback.")
	    ("rvv-qcg-typed-chunk-falu", bpo::value(&o.rvv_qcg_typed_chunk_falu)->default_value(false), "enable supported full-VL unmasked register-only floating-point sequence frames in LLVM; requires --llvm=1, --rvv-vector-ssa=1 and --rvv-vector-run=1. Unsupported forms keep their existing lowering/fallback.")
	    ("rvv-qcg-typed-chunk-fma", bpo::value(&o.rvv_qcg_typed_chunk_fma)->default_value(false), "enable supported full-VL unmasked fused floating-point sequence frames in LLVM; requires --llvm=1, --rvv-vector-ssa=1 and --rvv-vector-run=1. Unsupported forms retain their existing lowering/fallback.")
	    ("rvv-qcg-typed-chunk-fredosum", bpo::value(&o.rvv_qcg_typed_chunk_fredosum)->default_value(false), "W6: lower the exact unmasked full-VL ordered floating reduction `vfredosum.vs` (funct6=3) and `vfredusum.vs` (funct6=1) natively in the LLVM/AOT backend instead of the rv32_vfred helper. The body is a STRICT LEFT FOLD -- seed, then element 0, then element 1, ... -- emitted as a chain of llvm.experimental.constrained.fadd with round.dynamic and fpexcept.strict, so the accumulator dependence is preserved exactly; no vector reduce intrinsic, no partial sums recombined, no reassociation. Requires --llvm=1 and --rvv-vector-ssa=1. SEW 32/64 only. Masked reductions, a partial vl, nonzero vstart, non-RNE rounding, the widening vfwred forms and vfredmin/vfredmax all keep the unchanged rv32_vfred helper. Guarded at run time on vtype/vl/vstart/frm; any mismatch runs the helper. Read by RvvLLVMFredAdmit ALONE, never through an umbrella. Default off")
	    ("rvv-qcg-typed-chunk-wholemove", bpo::value(&o.rvv_qcg_typed_chunk_wholemove)->default_value(false), "W7: lower the whole-register move family `vmv1r.v`/`vmv2r.v`/`vmv4r.v`/`vmv8r.v` natively in the LLVM/AOT backend instead of the rv32_vmvNr helper. RVV 1.0 16.6: these copy NREG WHOLE registers and are independent of vl, LMUL, the mask and the tail/mask policy -- the frame guard is therefore vtype-independent (vlenb == VLEN/8 and vstart == 0), NOT a full-VL element-wise guard. Requires --llvm=1 and --rvv-vector-ssa=1. NREG must be 1/2/4/8 with both vd and vs2 aligned to NREG and inside the register file. NONZERO VSTART IS DELIBERATELY NOT ADMITTED and keeps the unchanged rv32_vmvNr helper: a register move's restart unit is the current SEW, and that restartable body is left to QCG and the helper, which are the recorded contract for it. Copies exactly VLEN/8 bytes per register and steps a whole VLEN_MAX_BYTES slot, so physical slot padding is never read or written. Read by RvvTryLLVMWholeMove ALONE, never through an umbrella. Default off")
	    ("rvv-llvm-setvl-reg", bpo::value(&o.rvv_llvm_setvl_reg)->default_value(false), "C2a: lower `vsetvl` (vtype from a GPR) natively in the LLVM/AOT backend instead of the rv32_vsetvl helper. The immediate forms vsetvli/vsetivli have been native since S3.4; this form differs only in that VLMAX is a run-time lookup in the same 256-entry table QCG indexes and the vtype may be ILLEGAL. Rules ported from QEmit::Emit_rvvsetvlreg: a vtype above 255 or with a zero table entry is illegal; the rd==x0,rs1==x0 keep-vl form is illegal when the new VLMAX cannot hold the current vl; illegal sets vtype:=vill, vl:=0, rd:=0; otherwise vl=min(AVL,VLMAX); every path clears vstart and both sources are read before rd is written. The table is emitted as a private module constant, never a host pointer baked at compile time. Requires --llvm=1 and --rvv-vector-ssa=1 and --rvv-qcg-direct-setvl=1. Read by the vsetvl route ALONE. Default off")
	    ("rvv-llvm-scalar-move", bpo::value(&o.rvv_llvm_scalar_move)->default_value(false), "C2b: lower the four scalar <-> vector element-0 transfers (vmv.s.x, vmv.x.s, vfmv.s.f, vfmv.f.s) natively in the LLVM/AOT backend instead of their helpers. Frame guard is VTypeInteger (exact vtype, vl <= VLMAX, vstart handled by the body), because the architectural rule for this family IS a vstart rule: the to-vector forms write vd[0] only when vstart < vl and leave it unchanged otherwise (including vl == 0), the from-vector forms ignore vl and vstart entirely, and both clear vstart. vmv.x.s sign-extends when SEW < XLEN and takes the low XLEN bits when SEW > XLEN; vmv.s.x sign-extends the GPR when SEW > XLEN and reads x0 as zero; vfmv.f.s NaN-boxes at SEW 32 and vfmv.s.f un-boxes an improperly boxed value to canonical qNaN using integer operations only (no FP compare, no rounding mode). SEW >= 32 for the floating forms. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMScalarMove ALONE. Default off")
	    ("rvv-llvm-partial-vl", bpo::value(&o.rvv_llvm_partial_vl)->default_value(false), "C5: admit PARTIAL VL (vl <= VLMAX) for the LLVM/AOT integer element-wise routes. Frame guard becomes VTypeIntegerNoRestart (exact vtype, vstart == 0, vl <= VLMAX) instead of the full-VL kind, and each destination store carries an ACTIVE-LANE predicate read from the live vec.vl, so active elements are written and inactive/tail elements are left UNDISTURBED (legal for vtu and vta); vl == 0 writes nothing. No second arm and no new QIR node. RESTRICTED to add/sub/mul/and/or/xor, the set whose lane operation cannot raise anything; division and the saturating/rounding families are excluded because their inactive lanes are observable. NOT applied to the FP routes: the FP bracket ORs host MXCSR sticky flags into guest fcsr, so an inactive FP lane's exception is architecturally visible, and LLVM 20's masked vp.fadd lowers to an unmasked vaddps on this target. The frame closes through FinalizeFrame with a derived geometry and policy_enabled explicitly false, so it never depends on --rvv-qcg-active-vl-bound and never emits vchunkactive. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-shift", bpo::value(&o.rvv_llvm_shift)->default_value(false), "C3: lower the immediate-shift forms `vsll.vi` and `vsrl.vi` natively in the LLVM/AOT backend instead of the rv32_vialu helper. Exactly the QCG typed shift route's envelope: SEW 32, LMUL 1, unmasked, legal single registers, immediate amount. `vsll` lowers to `shl` and `vsrl` to `lshr`; `vsra` (arithmetic right shift) has no node in this route and keeps its helper. The shift amount is reduced modulo SEW by the QIR node's constructor and RE-CHECKED, never re-masked, in the emitter. No nuw/nsw on shl and no exact on lshr, because RVV discards the bits shifted out. With --rvv-llvm-partial-vl the frame additionally takes the C5 partial-VL shape (guard VTypeIntegerNoRestart, active-lane masked stores). Requires --llvm=1, --rvv-vector-ssa=1 and --rvv-qcg-typed-chunk-shift=1. Setting this to 0 restores the previous unconditional refusal of the LLVM backend by the shift shape predicate. Default off")
	    ("rvv-llvm-extend", bpo::value(&o.rvv_llvm_extend)->default_value(false), "C3: lower the integer extension family `vzext.vf{2,4,8}` / `vsext.vf{2,4,8}` natively in the LLVM/AOT backend (Emit_vchunkextend) instead of the rv32_vext helper. `vsext` sign-extends and `vzext` zero-extends each source element to the vtype SEW; the element index is unchanged, so the active mask counts DESTINATION elements from this unit's element base against the live vec.vl. UNMASKED ONLY: this backend has no lowering for the architectural mask register, so masked extensions keep the unchanged helper. Same shape predicate as the QCG arm (VF6_VXUNARY0, funct3 2, vext_supported sub-encoding, SEW >= factor, emul_in_range, legal groups, RVV's lowest-part overlap rule) minus QCG's host CPUID probe, which is a property of QEmit's chosen instructions. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMExtend ALONE. Default off")
	    ("rvv-llvm-fclass", bpo::value(&o.rvv_llvm_fclass)->default_value(false), "C4: lower `vfclass.v` (VFUNARY1 with vs1==10000, funct3 OPFVV) natively in the LLVM/AOT backend (Emit_vchunkfclass) instead of the rv32_vfunary1 helper. RVV 1.0 13.14 makes it a 10-bit ONE-HOT classification of each element's bit pattern: it rounds nothing, raises no FP exception and ignores frm, so the lowering is ordinary integer vector IR with NO constrained intrinsic, NO MXCSR bracket and no frm conjunct in the guard -- unlike every other VFUNARY1 form. SEW 32/64 only (the reference implements f32_classify/f64_classify). UNMASKED ONLY: this backend has no architectural-mask lowering, so masked forms keep the unchanged helper. The frame carries GuardKind::VTypeIntegerNoRestart, so partial VL is admitted (per-unit masked store from the unit element base against the live vec.vl) while a nonzero vstart takes the helper -- the body has no prestart term and VTypeInteger would emit no vstart compare. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMFClass ALONE. Default off")
	    ("rvv-llvm-fcvt-itof", bpo::value(&o.rvv_llvm_fcvt_itof)->default_value(false), "C4: lower the SAME-WIDTH integer-to-float conversions `vfcvt.f.x.v` (signed) and `vfcvt.f.xu.v` (unsigned) natively in the LLVM/AOT backend (Emit_vchunkitof) instead of the rv32_vfcvt helper. Unlike --rvv-llvm-fclass these DO round and DO raise NX, so the frame keeps the FP bracket and the lane operation is llvm.experimental.constrained.{si,ui}tofp with round.dynamic + fpexcept.strict -- NEVER a plain sitofp/uitofp. That is a correctness requirement on this target, not a formality: measured on LLVM 20.1.8, an unconstrained uitofp <8 x i64> -> <8 x double> at -mattr=+avx512f lowers to the magic-constant trick (vporq then vsubpd), whose closing subtraction of two equal values yields -0.0 under roundTowardNegative -- the exact vfcvt.f.xu.v(0) == -0.0 defect rv32_vector_lower.h records for the host path. The constrained form emits vcvtuqq2pd with AVX512DQ and per-lane vcvtusi2sd without it, neither of which subtracts. SEW 32/64, FULL VL, unmasked, RNE, vstart == 0 (GuardKind::VTypeVlVstartFrmRNE). The widening vfwcvt.f.x* and narrowing vfncvt.f.x* forms and every float-source conversion keep the unchanged helper. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMIntToFloat ALONE. Default off")
	    ("rvv-llvm-fcvt-ftoi", bpo::value(&o.rvv_llvm_fcvt_ftoi)->default_value(false), "C4: lower the round-toward-zero same-width float-to-integer conversions `vfcvt.rtz.x.f.v` (signed, sub 7) and `vfcvt.rtz.xu.f.v` (unsigned, sub 6) natively in the LLVM/AOT backend (Emit_vchunkftoi) instead of the rv32_vfcvt helper. The frm-rounded pair (sub 0/1) is NOT admitted: LLVM fptosi/fptoui truncate by definition, so those need an explicit round step. The contract is softfp::cvt_to_int_width, which the vector reference uses unconditionally: NaN yields sat_max in BOTH directions, infinity is sign-directed, signed -2^(W-1) is IN range while +2^(W-1) is not, and for unsigned a negative value that truncates to magnitude zero (-0.5) is IN range and yields 0 with NX while -1.0 is invalid. Invalid lanes are NEUTRALISED to +0.0 BEFORE the conversion, so no lane is ever converted out of range: a plain fptosi of a NaN or out-of-range value is poison, and the host conversion instruction would otherwise raise the invalid flag into the FP bracket that ORs host MXCSR into guest fcsr. NV is then derived from the contract and OR-ed into fcsr explicitly, while NX comes from the hardware conversion of the genuinely in-range lanes -- which is what keeps NV and NX mutually exclusive as the architecture requires. The classification uses integer bit tests only, never fcmp, because an fcmp against a signalling NaN would raise a host invalid flag this route is supposed to derive itself. SEW 32/64, FULL VL, unmasked, vstart == 0, frm == RNE (conservative: rtz does not depend on frm). Widening, narrowing and masked forms keep the unchanged helper. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMFloatToInt ALONE. Default off")
	    ("rvv-llvm-fcvt-fwiden", bpo::value(&o.rvv_llvm_fcvt_fwiden)->default_value(false), "C4: lower the WIDENING float-to-float conversion `vfwcvt.f.f.v` (f32 source, f64 destination) natively in the LLVM/AOT backend (Emit_vchunkftof) instead of the rv32_vfcvt helper. A bare fpext is NOT correct and widening-a-finite-float-is-exact is not the contract: softfp::cvt_fmt canonicalises BOTH NaN kinds to the target format canonical quiet NaN and raises NV for a signalling NaN, and the host reference path agrees via f64_canon, whereas x86 vcvtps2pd quiets an sNaN while PRESERVING its payload and passes a qNaN through unchanged. NaN lanes are therefore selected to the canonical qNaN after the conversion and NV is derived for sNaN lanes from an integer bit test. No operand neutralisation is used here, unlike the float-to-integer routes, because fpext is total (no poison for any input) and the host flags already agree with the contract on every lane. SEW 32 source only, FULL VL, unmasked, vstart == 0, frm == RNE. The narrowing vfncvt.f.f.w and vfncvt.rod.f.f.w keep the unchanged helper: narrowing rounds, and round-to-odd is not an architectural rounding mode. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMFloatWiden ALONE. Default off")
	    ("rvv-llvm-fcvt-fnarrow", bpo::value(&o.rvv_llvm_fcvt_fnarrow)->default_value(false), "C4: lower the NARROWING float-to-float conversion `vfncvt.f.f.w` (f64 source, f32 destination) natively in the LLVM/AOT backend (Emit_vchunkftof) instead of the rv32_vfcvt helper. NOT the mirror of --rvv-llvm-fcvt-fwiden: narrowing ROUNDS, so beyond the NaN canonicalisation it can raise NX, OF|NX (with the saturated result depending on the rounding mode: RTZ gives the largest finite, RDN/RUP give an infinity only on the matching sign, RNE/RMM give the infinity) and UF|NX with tininess detected AFTER rounding. All three come from the hardware vcvtpd2ps, which agrees with softfp::round_pack on every one of them, so they are NOT re-derived; only the NaN VALUE differs, because x86 quiets a signalling NaN while preserving its payload while the contract canonicalises both NaN kinds to the target canonical quiet NaN. NaN lanes are therefore selected to the canonical f32 qNaN and NV is derived for signalling NaNs from an integer bit test. No operand neutralisation: fptrunc is total, the host flags agree with the contract on every lane, and a NaN input can neither overflow nor underflow. vfncvt.rod.f.f.w is NOT admitted -- round-to-odd is not one of the five architectural rounding modes, cannot be requested through frm and has no host equivalent. SEW 32 destination only, FULL VL, unmasked, vstart == 0, frm == RNE. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMFloatNarrow ALONE. Default off")
	    ("rvv-llvm-fcvt-itof-widen", bpo::value(&o.rvv_llvm_fcvt_itof_widen)->default_value(false), "C4: lower the WIDENING integer-to-float conversions `vfwcvt.f.x.v` (signed) and `vfwcvt.f.xu.v` (unsigned) natively in the LLVM/AOT backend (Emit_vchunkitof) instead of the rv32_vfcvt helper. Same flag logic as the same-width route: llvm.experimental.constrained.{si,ui}tofp with round.dynamic + fpexcept.strict, NEVER a plain sitofp/uitofp, because the unconstrained form lowers to the magic-constant trick whose closing subtraction yields -0.0 under roundTowardNegative. What is new is only the geometry: the destination element is twice the source, so the unit lane count comes from the destination window and the source window is half as wide. The shared predicate admits exactly two width pairs, vtype SEW 16 (i16 -> f32) and SEW 32 (i32 -> f64); SEW 8 and 64 are refused because the source must be 2 or 4 bytes and the destination 4 or 8. Both admitted pairs are exactly representable so NX cannot arise, which is a property of the admitted widths and is checked against softfp::cvt_from_int rather than assumed. FULL VL, unmasked, vstart == 0, frm == RNE. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMIntToFloatWiden ALONE. Default off")
	    ("rvv-llvm-fcvt-ftoi-widen", bpo::value(&o.rvv_llvm_fcvt_ftoi_widen)->default_value(false), "C4: lower the WIDENING float-to-integer conversions vfwcvt.xu.f.v, vfwcvt.x.f.v and the vfwcvt.rtz pair natively in the LLVM/AOT backend (Emit_vchunkftoi) instead of the rv32_vfcvt helper. Same body as the same-width route: integer bit-test classification (never fcmp, which would raise on a signalling NaN the route is classifying), invalid lanes NEUTRALISED to +0.0 BEFORE the conversion so the host cannot contribute a flag the contract forbids, NV derived from softfp::cvt_to_int_width and on the frm arm NX derived as well because constrained.nearbyint suppresses the host precision exception. The shared predicate admits exactly one width pair, f32 -> i64 (vtype SEW 32), because the source must be 4 or 8 bytes and the destination 4 or 8 while being twice the source; the range bounds are therefore 2^63 and 2^64 expressed as f32 exponents while every bit-layout constant stays in the SOURCE format. FULL VL, unmasked, vstart == 0, frm == RNE. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMFloatToIntWiden ALONE. Default off")
	    ("rvv-llvm-fcvt-partial-vl", bpo::value(&o.rvv_llvm_fcvt_partial_vl)->default_value(false), "Order item 3: PARTIAL VL for the LLVM conversion routes. The frame guard drops from vl == VLMAX to vl <= VLMAX (GuardKind::VTypePartialVlVstartFrmRNE) and the body then owes a tail policy, discharged the way the shared semantic contract (dbt/guest/rv32_rvv_contract.h) requires: an active-lane MASKED store from the unit own element base, so inactive elements are left UNDISTURBED, which is legal under both vta and vtu. For the integer-to-float direction the inactive lanes are additionally neutralised to integer 0 before the conversion: the conversion runs inside the FP bracket which ORs host MXCSR into guest fcsr, so an inactive lane whose integer is not exactly representable would raise NX and become architecturally visible; integer 0 converts to +0.0 exactly and raises nothing, which is why 0 is the right neutral here rather than the +1.0 the FP lane families use. vstart == 0 and frm == RNE are still proved by the guard. Requires --llvm=1 and --rvv-vector-ssa=1 and the per-route conversion switch. Default off")
	    ("rvv-llvm-masked", bpo::value(&o.rvv_llvm_masked)->default_value(false), "Order item 3: ARCHITECTURAL-MASK support for one integer family -- the masked OPIVV element-wise forms vadd/vsub/vand/vor/vxor with vm == 0, which both backends previously left to the rv32_vialu helper. It supplies the THIRD conjunct of the shared semantic contract's active predicate (dbt/guest/rv32_rvv_contract.h piece 2): each destination store's lane predicate becomes (e < vl) && v0[e] instead of (e < vl) alone, with vstart == 0 still proved by the frame guard (GuardKind::VTypeIntegerNoRestart). Masked-off and tail elements are simply NOT WRITTEN, so the destination is preserved, which is legal under all four of vta/vtu x vma/vmu. The LANE OPERATION is deliberately NOT masked: these five integer lane ops raise no exception and set no flag, so computing an inactive element is architecturally unobservable and only the commit needs the predicate -- the same argument partial VL uses, and one that does NOT carry to the FP families, whose lane emitters still refuse a masked node. REFUSED, each keeping the unchanged helper: vd == v0 (RVV 1.0 5.3, and the one read-after-write hazard the load-major order does not cover, since the mask is read inside each unit's store), vs1 == v0 or vs2 == v0 (5.2 once v0 is read at EEW 1), LMUL != 1, SEW != 32, an unobserved vtype, and every funct3 group but OPIVV. A masked frame is also a partial-VL frame by construction, so this route does not read --rvv-llvm-partial-vl. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-fp-masked", bpo::value(&o.rvv_llvm_fp_masked)->default_value(false), "Order item 3: FP PREDICATION -- architectural-mask support for the LLVM typed FP lane family (vfadd/vfsub/vfmul/vfdiv, .vv and .vf, SEW 32/64), which both LLVM route families previously refused at admission. A masked FP body needs MORE than the predicated destination store the integer family needs: the FP bracket ORs host MXCSR sticky bits into the guest fcsr, so a masked-off lane that raised OF/UF/NX/NV while being computed would become architecturally visible even though its result never reaches guest state. Emit_vchunkfalu therefore NEUTRALISES the operands of every inactive lane to +1.0, where inactive is now the FULL contract predicate (e < vl) && v0[e] rather than the vl bound alone -- +1.0 and not +0.0 because vfdiv is in the admitted set and (+0)/(+0) raises NV. The same mask value builds the destination store's predicate, from the same element base via the same RvvArchMaskForUnit, so the neutralised set and the published set cannot drift apart. The frame takes GuardKind::VTypePartialVlVstartFrmRNE whenever it is masked, so one body serves masked, partial-VL and both at once; vstart == 0 and frm == RNE are still proved by the guard. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-restart", bpo::value(&o.rvv_llvm_restart)->default_value(false), "Order item 3: RESTART -- admit a NONZERO vstart for the masked OPIVV integer element-wise family, supplying the last unemitted conjunct of the shared semantic contract's active predicate (dbt/guest/rv32_rvv_contract.h piece 2): the destination store's lane predicate becomes (vstart <= e) && (e < vl) && v0[e]. The frame guard drops from VTypeIntegerNoRestart to VTypeInteger (exact vtype, vl <= VLMAX, vstart left to the body), and the body's floor term is taken from the frame's own guard kind rather than from a node flag, so the guard's omission and the body's emission are one fact -- the pairing whose coming apart was the C4-FIX defect. The frame epilogue now also writes vec.vstart = 0 on the fast path, which RVV 1.0 3.7 requires of every vector instruction and which every earlier LLVM frame discharged only by proving the value was already 0; Emit_rvvtypedchunkend Panics on a restartable frame that neither declares the epilogue clear nor writes vstart in its body. Elements below vstart are left UNDISTURBED, which for a predicated store means simply not written. This family can restart because its lane operations are pure per-element functions with no cross-element state and no memory access; a memory family would additionally owe a partial-progress contract. Requires --llvm=1, --rvv-vector-ssa=1 and --rvv-llvm-masked. Default off")
	    ("rvv-llvm-fcvt-rod", bpo::value(&o.rvv_llvm_fcvt_rod)->default_value(false), "Order item 4: vfncvt.rod.f.f.w -- ROUND-TO-ODD narrowing (f64 -> f32) lowered natively instead of the rv32_vfcvt helper. It is NOT a host conversion with a requested rounding mode: measured on the installed LLVM 20.1.8, a constrained fptrunc carrying round.towardzero emits byte-identical x86 to one carrying round.dynamic, with no MXCSR write, so codegen would use the guest frm installed by the frame bracket and the result would be round_frm(x) with the low bit set rather than trunc(x) with the low bit set. The body is therefore INTEGER IR: truncate the significand and force its low bit whenever anything was discarded, which is what softfp::round_pack's FRM_ROD arms do. Overflow is E >= 128 and yields FLT_MAX, not an infinity (round-to-odd never produces one from a finite value); a nonzero input can never underflow to zero, which is the defining property; NX/OF/UF are derived by the body, and since no host floating-point operation runs there is no host flag that could contradict them and no inactive-lane neutralisation is needed. Requires --llvm=1, --rvv-vector-ssa=1 and --rvv-llvm-fcvt-fnarrow. Default off")
	    ("rvv-llvm-festimate", bpo::value(&o.rvv_llvm_festimate)->default_value(false), "Order item 4: the two 7-bit estimates `vfrsqrt7.v` and `vfrec7.v` lowered natively in the LLVM/AOT backend instead of the rv32_vfunary1 helper. THESE ARE NOT IEEE OPERATIONS: RVV 1.0 specifies them by an EXACT 128-entry lookup table, so two conforming implementations produce identical bits and substituting a host reciprocal or reciprocal-square-root would be a semantic replacement rather than a lowering. The body is therefore integer IR -- a table index on the normalised significand (with the subnormal normalisation done by llvm.ctlz rather than the reference's loop), a per-lane byte load from the table as a PRIVATE MODULE CONSTANT (never a host pointer: the artifact is built by elfaot and executed by elfrun, a different process), and a select tree for the special values. No constrained-FP call and no MXCSR bracket: the flags these raise (DZ for a zero operand, NV for a signalling NaN and for vfrsqrt7's negative operands, and OF|NX for vfrec7's two overflow paths) are ORed into fcsr from bits computed in the body. vfrec7's overflow direction depends on the guest frm, which the body READS from fcsr rather than pinning at the guard, so an RTZ/RDN/RUP execution is not sent to the helper for a mode this route handles. UNMASKED ONLY, SEW 32/64, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-fmerge", bpo::value(&o.rvv_llvm_fmerge)->default_value(false), "Order item 4: `vfmerge.vfm` / `vfmv.v.f` lowered natively in the LLVM/AOT backend instead of the rv32_vfmerge helper. THE MASK IS AN OPERAND HERE, NOT A WRITE ENABLE: vfmerge writes EVERY body element, vd[i] = v0[i] ? f[rs1] : vs2[i], so v0 feeds a select while the store carries the ordinary active-lane predicate. That is why this route is admitted while vm == 0 and the other FP routes are not -- a select raises nothing, so there is no inactive-lane flag to neutralise. It is a typed select and a broadcast: no rounding, no FP bracket, no constrained call. The SEW-32 NaN un-boxing uses integer operations only, so a signalling payload is moved unchanged rather than raising NV. vm == 1 is vfmv.v.f, whose encoding fixes vs2 = 0; a non-zero field there is reserved and keeps the helper, as do vd == v0 and vs2 == v0 for the merge form (RVV 1.0 5.3 and 5.2). SEW 32/64, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-fwiden", bpo::value(&o.rvv_llvm_fwiden)->default_value(false), "Order item 4: the WIDENING FP ARITHMETIC family (vfwadd/vfwsub/vfwmul and the four widening FMAs, .vv/.vf/.wv/.wf, f32 source and f64 destination) lowered natively in the LLVM/AOT backend instead of the rv32_vfwarith helper. The QCG route already decomposes this family into nodes this backend lowers -- vstatechunkload, vchunkfbroadcast, vchunkfalu, vchunkfma, vstatechunkstore -- and exactly one it did not, the widening convert, so the LLVM arm is that emitter plus a guard kind rather than a second copy of the frame. The reference's own definition survives intact: both operands are widened EXACTLY (fpext f32->f64 is exact, so it takes no rounding operand and can raise only NV for a signalling NaN) and then ONE operation is performed at the wide width, which is what emitting the convert separately means. RESTRICTED relative to the QCG twin by three rows, each stated: UNMASKED only (this backend's convert and lane emitters refuse a masked node); no shared opmask (--rvv-qcg-fp-shared-mask emits vchunkmaskset, which has no LLVM lowering, and is refused in admission rather than left to Panic); and no host CPUID probe, because the AVX-512F/BMI2/FMA3 tests are properties of the instructions QEmit selects and the LLVM backend picks encodings for its own target. The frame takes GuardKind::VTypeVlVstartFrmRNE -- the strictly stronger kind -- so a partial-vl, restarted or non-RNE execution reaches the unchanged helper. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-satadd", bpo::value(&o.rvv_llvm_satadd)->default_value(false), "Order item 4: the SATURATING integer add/sub family (vsaddu/vsadd/vssubu/vssub, .vv/.vx/.vi) lowered natively in the LLVM/AOT backend instead of the rv32_vsatadd helper. This is the FIRST of the five narrow nodes the fixed-point proposal names: QCG emits this family -- with the averaging, round-shift, clip and fractional-multiply ones -- through vchunkpartialalu, a 52-kind mega-node this backend does not lower, and the proposal was one node per semantic family so each is reviewable on its own saturation semantics. The four funct6 values map onto LLVM's uadd.sat / sadd.sat / usub.sat / ssub.sat bound for bound, so no saturation rule is approximated. vxsat is DERIVED rather than guessed -- a lane saturated exactly when the saturating result differs from the wrapping one, which is exact for all four operations -- and it is ORed into the sticky flag, never assigned, so a frame in which nothing saturates leaves a previously-set flag alone. Inactive and masked-off lanes are excluded from the flag by the unit's active-lane predicate. .vi has only the two ADDING forms, which is the ISA's rule (vsatadd_form_supported), not this route's. UNMASKED only, SEW 32, LMUL 1, vstart == 0, observed vtype; everything else keeps the unchanged helper. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-adc", bpo::value(&o.rvv_llvm_adc)->default_value(false), "Order item 4: the CARRY/BORROW family (vadc.vvm/.vxm and vsbc.vvm/.vxm -- the forms whose destination is a VECTOR register) lowered natively in the LLVM/AOT backend instead of the rv32_vadc helper. This is the second of the five narrow nodes the fixed-point proposal names, and the one whose entry flagged that its second operand is v0 as a REAL OPERAND rather than a mask: vadc computes vd[i] = vs2[i] + vs1[i] + v0[i] and writes EVERY body element, so v0's bits are fetched with the same shared window helper the masked routes use and then zero-extended into the lane type as an addend, never ANDed into a store predicate. The truncation to SEW is the lane type's, which is exactly the reference's & sew_mask. It raises nothing and sets no sticky flag, so the node is pure. vmadc/vmsbc are NOT admitted: their destination is a MASK register, a different shape with its own overlap rule, exactly as the FP compares are a different route from the FP arithmetic. .vim keeps the helper because the immediate form of vchunkbroadcast has no LLVM lowering (and vsbc has no immediate form in the ISA at all). vd == v0 is refused -- RVV 1.0 12.4 reserves it -- as is a v0 data source. SEW 32, LMUL 1, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-avg", bpo::value(&o.rvv_llvm_avg)->default_value(false), "Order item 4: the FIXED-POINT AVERAGING family (vaaddu/vaadd/vasubu/vasub, .vv and .vx) lowered natively in the LLVM/AOT backend instead of the rv32_vavg helper. Third of the five narrow nodes the fixed-point proposal names, and the one that brings vxrm into this backend: the result is roundoff(vs2 +/- vs1, 1) with the rounding rule selected by the vxrm CSR, which is a REAL ARCHITECTURAL INPUT -- the same encoding on the same operands gives four different answers across its four values, so all four are emitted and one is selected from live state. The rounding increment is emitted by a SHARED helper (RvvRoundoffIncrement) that vsmul and vnclip are meant to reuse, mirroring rounding_incr on the helper arm. The sum is formed in 2*SEW so the SEW+1 bit the spec requires is real and cannot overflow; the shift is ARITHMETIC even for the unsigned kinds, because vasubu can produce a negative difference and the spec's >> on it is a floor division. There is no .vi form to refuse -- this family is OPMVV/OPMVX and RVV 1.0 defines no immediate encoding for it -- so native support here is COMPLETE for every form the ISA defines. Pure: no saturation, no sticky flag. SEW 32, LMUL 1, unmasked, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-smul", bpo::value(&o.rvv_llvm_smul)->default_value(false), "Order item 4: the FRACTIONAL MULTIPLY vsmul.vv/.vx lowered natively in the LLVM/AOT backend instead of the rv32_vsmul helper. Fourth of the five narrow nodes the fixed-point proposal names, and the FIRST caller of the shared rounding helper at a shift greater than one: vaadd shifts by 1, where the spec's sticky v[d-2:0] term is an empty bit range, while vsmul shifts by SEW-1 and carries thirty bits through it. RVV 1.0 12.3 treats both operands as Q(SEW-1) SIGNED fractions -- there is no unsigned form -- multiplies into 2*SEW and keeps the high half after a rounding right shift of SEW-1; shifting by SEW would halve every result. The single saturating input pair is MIN*MIN, which is exactly +1.0 in that format and one ulp above the maximum; vxsat is ORed into the sticky flag, never assigned, and gated by the same active-lane predicate the saturating add/sub route uses. No .vi form exists in the ISA. SEW 32, LMUL 1, unmasked, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-nclip", bpo::value(&o.rvv_llvm_nclip)->default_value(false), "Order item 4: the NARROWING CLIP vnclipu.wv/.wx/.wi and vnclip.wv/.wx/.wi lowered natively in the LLVM/AOT backend instead of the rv32_vnclip helper. LAST of the five narrow nodes the fixed-point proposal names, and the only one that combines all three of the family's mechanisms: a 2*SEW source narrowed to SEW, a vxrm rounding right shift, and a saturating clip that sets vxsat. Its shift is a RUNTIME VECTOR rather than a constant -- .wv takes a per-element amount -- so the shared RvvRoundoffIncrement was GENERALISED to a value shift for it rather than duplicated. vnclipu reads the source unsigned and clips to [0, 2^SEW-1]; vnclip reads it signed and clips to [-2^(SEW-1), 2^(SEW-1)-1]. ALL THREE FORMS ARE NATIVE including .wi, because the immediate here is a shift amount carried on the node and not a broadcast operand -- so unlike vsatadd.vi and vadc.vim nothing is left to the helper. Destination SEW 8/16/32, unmasked, vstart == 0, standalone frame vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-ired", bpo::value(&o.rvv_llvm_ired)->default_value(false), "C6: the INTEGER REDUCTIONS vredsum/vredand/vredor/vredxor/vredminu/vredmin/vredmaxu/vredmax lowered natively in the LLVM/AOT backend instead of the rv32_vred helper. Reuses the QCG arm's own InstVReduce node -- the geometry the two backends already agree on -- and supplies the emitter that was the only missing half. All eight operations are ASSOCIATIVE AND COMMUTATIVE, including vredsum since modular addition is associative, so the group is folded chunk by chunk with one llvm.vector.reduce.* per chunk and the partial results combined in any order; that is exactly what is NOT legal for vfredosum, whose specified order is its purpose. Elements at or past vl are replaced by the operation's identity rather than skipped, using the same neutral table the QCG body broadcasts. vl == 0 writes NOTHING -- RVV 1.0 makes the reduction a no-op, not a seed store -- so the destination store is predicated. Unlike the QCG arm this route needs no AVX-512 CPUID probe, because LLVM selects encodings for the target it compiles for. Masked and widening (vwredsum) forms keep the helper. LMUL 1, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-mlogic", bpo::value(&o.rvv_llvm_mlogic)->default_value(false), "C6: the MASK LOGICAL operations vmand/vmnand/vmandn/vmxor/vmor/vmnor/vmorn/vmxnor lowered natively in the LLVM/AOT backend instead of the rv32_vmlogic helper. Reuses the QCG arm's own InstVMaskLogic node -- one 64-bit mask word with the destination, both sources and the word's first bit index -- and supplies the emitter that was the only missing half. A mask register is ONE register whatever the LMUL and these instructions are bit-wise over it, so SEW does not participate and there is no chunk geometry: the only element-indexed quantity is which bits the instruction may change. Bits at or beyond vl are UNDISTURBED, so the destination word is a blend and not a store of the computed value -- storing the whole word would clobber a mask still live above vl. The active-bit mask is built as <64 x i1> and bitcast, which matches the guest's own bit order (element 0 in the least significant bit, bit e%8 of byte e/8). Operand order is vs2 OP vs1: six of the eight are symmetric, so a swap shows up only in vmandn and vmorn. Unlike the QCG arm this route needs no BMI2 probe. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-icmp", bpo::value(&o.rvv_llvm_icmp)->default_value(false), "W31: the INTEGER COMPARE family vmseq/vmsne/vmsltu/vmslt/vmsleu/vmsle/vmsgtu/vmsgt lowered natively in the LLVM/AOT backend instead of the rv32_vicmp helper, in all three operand forms (.vv, .vx, .vi) that RVV 1.0 defines for each funct6. Reuses the QCG arm's own InstVChunkPartialAlu node with an architectural mask and one of its eight compare Kinds, so both backends consume ONE definition of the semantics; the emitter, which Panicked here for all fifty-two kinds, gains exactly those eight. The destination is a MASK register -- one bit per element, one register whatever the LMUL -- so each chunk does a 64-bit read-modify-write at vd + element_base/8 under the body mask rather than storing a computed word: bits before vstart, at or beyond vl, and at inactive elements stay UNDISTURBED, which is what makes vd == v0 legal and what rvv_ref::vicmp does. The body mask is [vstart, vl) intersected with v0 when vm == 0, computed in the scalar i64 domain exactly as QEmit computes it, which makes this the first route in this backend to read v0 as a body mask. Covers SEW 8/16/32/64 and every legal LMUL including fractional, at every supported VLEN; the frame's guard kind is VTypeInteger, so vstart is owned by the body and a restarted compare is handled rather than refused. The .vx scalar is sign-extended from XLEN then truncated to SEW, and .vi sign-extends the 5-bit immediate, both matching vialu_rhs. What keeps the helper: an unobserved block vtype, an illegal vtype, a mask destination that overlaps a non-low part of a source group (RVV 1.0 makes that encoding illegal and the helper raises the trap), and a chunk geometry the node cannot express. Unlike the QCG arm this route needs no AVX-512/BMI2 probe -- it emits IR, and the target's capability is the AOT triple's business. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-mem-partial-vl", bpo::value(&o.rvv_llvm_mem_partial_vl)->default_value(false), "W32: give the LLVM/AOT unit-stride vector LOAD (vle<EEW>.v) a partial-VL body, so it stops demanding vl == VLMAX. The LLVM arm of that frame carried GuardKind::VTypeVlVstart, which on the official ACT4 corpus missed its guard on 1591 of 1668 executions -- the frame was emitted and then called the helper anyway, paying a guard test for nothing. With this on the arm emits ONE body under the guard kind the QCG partial frames already use (VTypeVlOrPartialVstartBaseLimit): exact vtype, vl <= VLMAX, vstart == 0, and the guest base register <= 2^32 - VLEN/8. The base test is not optional: the body forms membase + zext(base) + disp with a HOST-pointer displacement that does not wrap at 2^32, while rvv_ref::load_unit_stride computes (u32)(base + e*eew), which does; the bound is what makes the two agree and it is the same constant and comparison QEmit emits for this kind. The guest-memory read is llvm.masked.load, which is a CORRECTNESS requirement rather than an optimisation -- at vl < VLMAX the bytes above vl*EEW may be on a page the guest never mapped, that intrinsic is specified not to access a lane whose mask bit is false, and rvdbt's SIGSEGV handler panics rather than delivering a guest trap, so a full-width load would kill the process on a legal program. The load's mask and its chunk's store mask are the same memoised llvm::Value, so they cannot drift. Tail and prestart elements are left undisturbed because neither is published, which is legal under all four of vta/vtu x vma/vmu and is what rvv_ref does. Covers EEW 32 and 64 (the widths the node's active-lane form accepts) at every supported VLEN; vse is NOT touched, and the pure-QCG arms are byte-identical either way. Requires --llvm=1, --rvv-vector-ssa=1 and --rvv-qcg-typed-chunk-vle=1. Default off")
	    ("rvv-llvm-vid", bpo::value(&o.rvv_llvm_vid)->default_value(false), "C6: `vid.v` (write each element's own index) lowered natively in the LLVM/AOT backend instead of the rv32_vid helper, reusing the QCG arm's own InstVChunkIndex node. Despite living in the cross-element chapter this instruction has no cross-lane dependency and no source register: element e gets the constant e, which makes the element index literally the datum and a wrong base or stride directly readable in the destination. Values TRUNCATE at small SEW, which is the architectural answer -- at SEW 8 element 256 holds 0 -- and elements at or beyond vl are UNDISTURBED. Unmasked only; no AVX512BW/VL/BMI2 probe, unlike the QCG arm. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-mscalar", bpo::value(&o.rvv_llvm_mscalar)->default_value(false), "C6: `vcpop.m` and `vfirst.m` lowered natively in the LLVM/AOT backend instead of the rv32_vmaskpop helper, reusing the QCG arm's own InstVMaskScalar node. These are the only two RVV instructions in this checkpoint whose destination is an INTEGER register, which is why they share a node and a frame closed with ScalarResult. vcpop counts the active set bits; vfirst returns the index of the lowest active set bit or -1. Both read [0, vl) rather than [vstart, vl) because RVV 1.0 requires vstart == 0 for them, so the frame's guard is the architectural precondition and not a narrowing. vfirst scans the words BACKWARDS so the lowest word with a set bit is the one left standing, which is branch-free. rd == x0 writes nothing. Unmasked only; no BMI2/POPCNT probe, unlike the QCG arm. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-mprefix", bpo::value(&o.rvv_llvm_mprefix)->default_value(false), "C6: the MASK PREFIX family vmsbf.m / vmsif.m / vmsof.m lowered natively in the LLVM/AOT backend instead of the rv32_vmunary helper, reusing the QCG arm's own InstVMaskPrefix node. All three are functions of ONE number -- the index f of the first ACTIVE set bit -- so once f is known each destination bit is a comparison against it: vmsbf is e < f, vmsif is e <= f, vmsof is e == f. That is the same function the reference's serial `seen` flag computes, in the form a vector unit can evaluate in parallel. f is computed exactly as vfirst.m computes it, and the no-active-set-bit answer is the same all-ones sentinel: read as UNSIGNED it exceeds every element index, so e < f and e <= f are true everywhere and e == f is false everywhere -- precisely the spec's answer for an empty mask, with no special case. Bits at or beyond vl are UNDISTURBED, so each word is a blend. Unmasked only; viota keeps the helper. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-viota", bpo::value(&o.rvv_llvm_viota)->default_value(false), "C6: `viota.m` (the prefix sum of a mask -- element e receives the number of active set bits STRICTLY BEFORE it) lowered natively in the LLVM/AOT backend instead of the rv32_vmunary helper, reusing the QCG arm's own InstVMaskIota node. It is the only genuinely CUMULATIVE cross-element computation in this checkpoint, and it is made parallel by splitting the count into a scalar prefix and a vector one: vd[base+i] = popcount(bits [0,base)) + popcount(bits [base,base+i)), where the first term is one scalar per chunk and the second is a single ctpop of splat(w) AND a constant per-lane mask vector, with no scan. The intermediate is always i64, never the element type: at SEW 8 a chunk holds 64 lanes and the lane-63 mask does not fit in an i8, so computing in the element type would truncate the MASK rather than the RESULT; the truncation to SEW happens once at the end, where the reference's elem_put puts it. The source needs no active-lane mask because every bit a STORED lane counts has index below that lane and hence below vl. Unmasked only. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-vcompress", bpo::value(&o.rvv_llvm_vcompress)->default_value(false), "C6: `vcompress.vm` (pack the elements selected by vs1 into the low end of vd) lowered natively in the LLVM/AOT backend instead of the rv32_vcompress helper, reusing the QCG arm's own InstVCompress node. It is the one C6 family that is not a per-element function of its inputs: the write index runs BEHIND the read index, so source element e lands at destination position viota(vs1)[e]. LLVM has the operation exactly -- llvm.masked.compressstore stores the selected lanes of a vector contiguously from a pointer -- so the emitter builds no scan, walking the source in chunks and carrying only the SCALAR count of elements already written. LMUL 1 ONLY, and the reason is ADDRESSING rather than semantics: the destination position is a runtime value, so the store address is vd_base + n*sew, which inside ONE register is a plain byte offset but across a register GROUP is not, because consecutive logical bytes jump a 512-byte slot every regbytes. LMUL > 1 keeps the helper. vs1 is the SELECTOR, not a mask, so there is no masked form; elements at or beyond the compressed count are UNDISTURBED. No AVX512F/VBMI2/BMI2/POPCNT probe, unlike the QCG arm. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-vrgather", bpo::value(&o.rvv_llvm_vrgather)->default_value(false), "C6: `vrgather.vv/.vx/.vi` and `vrgatherei16.vv` lowered natively in the LLVM/AOT backend instead of the rv32_vrgather helper, reusing the QCG arm's own InstVGather node. vd[e] = vs2[idx[e]] with the index taken from vs1[e] (at SEW, or at a fixed EEW of 16 for the ei16 form), from a GPR, or from an unsigned 5-bit immediate. An index at or beyond VLMAX reads ZERO -- not clamped, not wrapped -- which falls out of masked.gather's passthru operand rather than needing a branch. Index arithmetic is done in 64 bits because a GPR index can exceed 32 and the reference compares (u64)idx against VLMAX before reading. LMUL 1 ONLY: at LMUL 1 the source group is one register so element i is at src + i*sew and the address vector is a single scaled index, which is not true across a group where consecutive logical elements jump a 512-byte slot every regbytes. Unmasked only. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-vslide", bpo::value(&o.rvv_llvm_vslide)->default_value(false), "C6: `vslideup`, `vslidedown`, `vslide1up` and `vslide1down` (both .vx and the .vf twins of the slide1 forms) lowered natively in the LLVM/AOT backend instead of the rv32_vslide helper, reusing the QCG arm's own InstVGather node -- the same node and the same emitter as vrgather, because the five instructions differ only in WHICH source element each destination element reads. vslideup leaves elements below the offset UNDISTURBED rather than zeroing them; vslidedown past VLMAX reads zero; vslide1up puts the scalar at element 0 and vslide1down puts it at vl-1 -- NOT at VLMAX-1, which is a different bound from vslidedown's and is the one a shared implementation is most likely to get wrong. The vacated lane is exactly the lane whose source element does not exist, so the scalar arrives as masked.gather's passthru. Index arithmetic is 64-bit because e+off with off from a GPR can exceed 32 bits. LMUL 1 ONLY, for the addressing reason the gather flag records. Unmasked only. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-vstrided", bpo::value(&o.rvv_llvm_vstrided)->default_value(false), "C7: the STRIDED vector memory forms `vlse<EEW>.v` and `vsse<EEW>.v` lowered natively in the LLVM/AOT backend instead of the rv32_vlse / rv32_vsse helpers, reusing the QCG arm's own InstVMemory node. This is the first route in this backend whose addresses are GUEST addresses rather than CPUState offsets. What distinguishes strided from unit-stride is that consecutive elements are NOT contiguous: the progression is base + e*stride with the stride from a scalar register, so a NEGATIVE stride walks backwards and a ZERO stride makes every element touch the same address -- both legal and both exercised. The address is computed in 32 BITS and is allowed to WRAP, because the guest's address space is 32-bit and the reference computes base + e*(u32)stride in u32; the zero-extension to the host pointer width happens after the wrap. Each chunk is one masked.gather or masked.scatter whose mask is the active-element predicate, which is what keeps a lane at or beyond vl from touching memory at all -- for a memory operation 'compute it and discard it' is not available. Elements at or beyond vl are UNDISTURBED in the destination register. Unmasked, nf == 1, and a data group that fits one register. vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-vindexed", bpo::value(&o.rvv_llvm_vindexed)->default_value(false), "C7: the INDEXED vector memory forms `vluxei`/`vloxei` (loads) and `vsuxei` (the UNORDERED store) lowered natively in the LLVM/AOT backend instead of the rv32_vlxei / rv32_vsxei helpers, sharing InstVMemory and the SAME emitter as the strided forms -- the two modes differ only in the offset vector, which is computed from a scalar stride for strided and read from a vector register at the INDEX EEW for indexed. The index is a BYTE offset, zero-extended when narrower than 32 bits and truncated to its low half when wider, exactly as the reference's (u32)off cast; the sum base+offset wraps in 32 bits. ORDERED INDEXED STORES (vsoxei) ARE NOT ADMITTED, and that is a semantic limit rather than an effort one: vsoxei requires that when two indices name the same address the LAST element in order wins, and llvm.masked.scatter leaves the order among enabled lanes unspecified. vsuxei has exactly the scatter's guarantee and is admitted; both indexed LOADS are admitted because a load writes no memory and its order is unobservable. Index EEW <= SEW so the index group fits one register, LMUL 1, unmasked, nf == 1, vstart == 0, observed vtype. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-llvm-fixed-masked", bpo::value(&o.rvv_llvm_fixed_masked)->default_value(false), "C5-MASK (2026-09-20): admit the MASKED forms (vm == 0) of the fixed-point element-wise families -- vsatadd, vavg and vsmul -- on the LLVM arm. ONE SWITCH for three families because it is ONE mechanism: the architectural mask is ANDed into the destination's store predicate by the shared Emit_vstatechunkstore, which has carried that conjunct since order item 3, so no family needs mask code of its own. What is NOT shared, and is the reason this is a semantic change rather than an admission widening, is the STICKY FLAG: a masked-off lane that would saturate must not set vxsat, and unlike the destination -- which the store simply does not write -- the flag has no second chance to be corrected. So vsatadd's and vsmul's vxsat reductions are ANDed with the same architectural mask, through the same predicate helper the store uses, which is what keeps the two from disagreeing about which lanes are active. vavg needs none of that because it sets no flag. The destination may not be v0 (RVV 1.0 5.3) and no SEW-wide source may be v0 (the one-EEW-per-register rule), both asked of the shared predicates rather than restated. SEW 32, LMUL 1, vstart == 0. Requires --llvm=1 and --rvv-vector-ssa=1, plus each family's own route switch. Default off")
	    ("rvv-llvm-fp-cvt-masked", bpo::value(&o.rvv_llvm_fp_cvt_masked)->default_value(false), "C5-MASK-FP (2026-09-20): admit the MASKED forms (vm == 0) of the SAME-WIDTH FP element-wise families on the LLVM arm -- vfcvt float-to-integer and integer-to-float, vfclass, and the 7-bit estimates vfrsqrt7/vfrec7. ONE SWITCH for four families because it is ONE mechanism, and the same one --rvv-llvm-fixed-masked uses: the architectural mask is a conjunct of the shared RvvActiveLaneMask predicate, so admitting the masked form is a matter of asking that helper for it rather than writing mask code per family. These four are the right group because each already publishes its destination through an active-lane masked store AND already ANDs its flag predicates with the same mask -- they were built that way for partial VL, and an architectural mask is the same predicate with one more term. THE STICKY FLAG IS THE SEMANTIC CONTENT: an inactive lane holding a NaN must not raise NV, an inactive negative must not raise NV out of vfrsqrt7, and an inactive value must not contribute NX or OF -- the destination is merely not written, but fcsr has no second chance to be corrected. The destination may not be v0 and no SEW-wide source may be v0 (RVV 1.0 5.3 and the one-EEW-per-register rule), both asked of convert_registers_legal rather than restated. Requires --llvm=1 and --rvv-vector-ssa=1, plus each family's own route switch. Default off")
	    ("rvv-llvm-fp-dynamic-frm", bpo::value(&o.rvv_llvm_fp_dynamic_frm)->default_value(false), "C6-FRM (2026-09-20): widen the FP CONVERSION frame's rounding-mode admission from frm == RNE to frm <= FRM_RUP, so the four rounding modes the host MXCSR can express take the native arm instead of only round-to-nearest-even. The frame's bracket already installs the live guest frm into MXCSR.RC and every lane operation is a round.dynamic constrained intrinsic, so RNE/RTZ/RDN/RUP all execute in the mode the guest asked for; this switch only stops the guard from refusing three of them. It is NOT a removal of the guard: RMM (frm == 4, round to nearest with ties away from zero) still takes the fallback and must, because x86 has no such rounding mode and the bracket maps it onto RNE, which would be a wrong result rather than a slow one. Measured reason on official ACT4 at the frozen build: enabling a conversion route takes its ELF's guard_fallbacks from 0 to 189/183/143/134/96/73 while native gain stays at 0-9, and vfncvt.f.f.w loses every one of its admissions. Implemented as two NEW guard kinds rather than by widening the existing ones, because QEmit emits the frm == RNE test independently and moving the shared kind would make the two backends cover different executions from identical QIR. Requires --llvm=1 and --rvv-vector-ssa=1 plus the conversion routes' own switches. Default off")
	    ("rvv-llvm-fwiden-partial-vl", bpo::value(&o.rvv_llvm_fwiden_partial_vl)->default_value(false), "C7-FWPVL (2026-09-20): let the LLVM widening-FP body (vfwadd/vfwsub/vfwmul/vfwmacc and the .wv/.vf forms) run at a PARTIAL vl instead of requiring vl == VLMAX. Measured reason: on official ACT4 Vf32-vfwadd.vv the frame takes 662 guard fallbacks, and a one-variable control shows ALL of them are the vl term -- widening the rounding term instead moved the count by exactly 0 (662 -> 662). The body needed one change: the widening convert now neutralises inactive lanes to +1.0f before the fpext, because an f32->f64 widening is exact for every finite input but raises NV on a signalling NaN, and a tail lane must not set the guest fcsr. The destination already published through an active-lane masked store and the arithmetic nodes already neutralised their operands. Register overlap rules are unchanged -- admission still goes through RvvLLVMFWidenAdmit. The QCG arm is untouched: it keeps GuardKind::VTypePartialVlVstartFrmHost and its own body, which discharges mask, tail and rounding itself. Requires --llvm=1 and --rvv-vector-ssa=1 plus --rvv-llvm-fwiden. Default off")
	    ("rvv-llvm-fwiden-masked", bpo::value(&o.rvv_llvm_fwiden_masked)->default_value(false), "C7-FWMASK (2026-09-20): admit the MASKED forms (vm == 0, v0.t) of the LLVM widening-FP family -- vfwadd/vfwsub/vfwmul/vfwmacc and the .wv/.vf forms. This is a SEMANTIC lowering, not a looser admission: the architectural mask is a conjunct of the shared RvvActiveLaneMask predicate, and the SAME predicate value neutralises the widening convert's operand, neutralises the FALU/FMA operands and predicates the destination store, so the computed set and the published set cannot drift apart. The convert must be neutralised even though f32->f64 is exact for every finite input, because it raises NV on a signalling NaN and a predicated store cannot undo a sticky flag -- an inactive sNaN must not alter fflags. A masked frame always takes a PARTIAL guard kind, this backend's existing convention for masked frames. Register overlap is unchanged and is asked of vfw_registers_legal with the real vm, which enforces both that a masked op may not write v0 and that no SEW-wide source may be v0. UNCHANGED and still falling back to the helper: RMM rounding (x86 has no ties-away mode) and vstart != 0. The QCG arm is untouched. Requires --llvm=1, --rvv-vector-ssa=1 and --rvv-llvm-fwiden. Default off")
	    ("rvv-llvm-widen", bpo::value(&o.rvv_llvm_widen)->default_value(false), "C3: lower the widening integer family (vwadd/vwsub/vwmul/vwmacc and their unsigned, mixed-sign, .wv and .wx variants) natively in the LLVM/AOT backend (Emit_vchunkwiden) instead of the rv32_vwint helper. Destination element width is 2*SEW and the active mask counts DESTINATION elements from each unit's element base against the live vec.vl. The two sources are extended INDEPENDENTLY (sign2 for vs2, sign1 for vs1); the .wv/.wx forms load vs2 already-wide. A .vx scalar is the low SEW bits of the GPR, then sign- or zero-extended to 2*SEW. vwmacc reads the old vd and adds after the product; no nuw/nsw anywhere, because RVV wraps. UNMASKED ONLY: this backend has no architectural-mask lowering, so masked widening keeps the unchanged helper. Same vwint_form_supported / vwint_registers_legal predicates as the QCG arm, minus QCG's host CPUID probe. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMWiden ALONE. Default off")
	    ("rvv-llvm-narrow", bpo::value(&o.rvv_llvm_narrow)->default_value(false), "C3: lower the narrowing shifts `vnsrl` / `vnsra` natively in the LLVM/AOT backend (Emit_vchunknarrowshift) instead of the rv32_vnshift helper. The shift amount is reduced modulo 2*SEW (the SOURCE width, not the destination's) and the narrow store TRUNCATES. `vnsra` uses ashr, `vnsrl` lshr. UNMASKED ONLY. `vnclip` is NOT covered: QCG lowers saturating narrowing through the partial-arm node this backend cannot lower, so it keeps its helper and is listed as incomplete native support. Requires --llvm=1 and --rvv-vector-ssa=1. Read by RvvTryLLVMNarrowShift ALONE. Default off")
	    ("rvv-llvm-fp-partial-vl", bpo::value(&o.rvv_llvm_fp_partial_vl)->default_value(false), "C5-FP: admit PARTIAL VL (vl <= VLMAX) for the LLVM/AOT typed FP lane family vfadd/vfsub/vfmul/vfdiv. Unlike the integer families a masked store alone is NOT sufficient: the FP bracket ORs host MXCSR sticky flags into the guest fcsr, so an exception raised while computing an INACTIVE lane would be architecturally visible, and LLVM 20's masked vp.fadd lowers to an UNMASKED vaddps on x86 (measured) so VP intrinsics do not help. The operands of inactive lanes are therefore forced to +1.0 before the constrained operation -- +1.0 and not +0.0, because (+0)/(+0) raises NV and vfdiv IS admitted; (+1.0) op (+1.0) is exact and raises nothing for add, sub, mul, div, fma and sqrt alike. The frame takes GuardKind::VTypePartialVlVstartFrmRNE and the destination store is already active-lane predicated. policy_enabled is forced false on the LLVM arm so no vchunkactive can be planned. Requires --llvm=1 and --rvv-vector-ssa=1. Default off")
	    ("rvv-qcg-typed-chunk-fsqrt", bpo::value(&o.rvv_qcg_typed_chunk_fsqrt)->default_value(false), "W5F: admit the exact unmasked full-VL `vfsqrt.v` (VFUNARY1 with vs1==00000; SEW=32/64, integer LMUL 1/2/4/8, RNE, vstart=0) into the typed vchunkfsqrt route in the LLVM/AOT backend instead of the rv32_vfunary1 helper, emitting one constrained vector sqrt per chunk. Requires --llvm=1 and --rvv-vector-ssa=1; masked forms, partial VL, non-RNE rounding, nonzero vstart and the three other VFUNARY1 sub-opcodes (vfrsqrt7.v, vfrec7.v, vfclass.v) keep the unchanged helper. RvvLLVMSqrtChunkAdmit (rv32_qir.cpp) reads THIS switch alone and not the `rvv-qcg-typed-chunk` umbrella, so at 0 the route is off here no matter what the umbrella says -- which is why elfaot must carry the option: without it the flag is false in a freshly exec'd elfaot and no artifact can ever take the route. Same switch name and same envelope as elfrun's, so one flag means one thing in both. The separate --rvv-qcg-typed-chunk-fsqrt-force-emit host-feature bypass is AUDIT ONLY, is not offered here and is not carried by kRvvRouteContract. Default off")
	    ("rvv-qcg-typed-chunk-mem-e64", bpo::value(&o.rvv_qcg_typed_chunk_mem_e64)->default_value(false), "extend the enabled unit-stride vle/vse routes to EEW=SEW=64, LMUL=1, full VL, unmasked; requires the respective vle/vse switch and LLVM vector SSA. Partial VL, nonzero vstart and unsupported shapes retain their fallback.")
	    ("rvv-llvm-wide-vadd", bpo::value(&o.rvv_llvm_wide_vadd)->default_value(false), "T7a experimental representation: keep exact unmasked e32/m1/full-VL vadd.vv as one VLEN-wide LLVM integer-vector add at VLEN 512/1024; requires --rvv-vector-ssa and --llvm=1; default off keeps the accepted manually chunked baseline")
	    ("rvv-llvm-wide-vadd-ssa", bpo::value(&o.rvv_llvm_wide_vadd_ssa)->default_value(false), "T7b fair representation: form one VLEN-wide LLVM vadd.vv from the accepted V512 SSA operands and split its result back to that SSA path; default off, LLVM AOT only")
	    ("rvv-vector-ssa-counters", bpo::value(&o.rvv_vector_ssa_counters)->default_value(false), "diagnostic artifacts: count typed RVV direct and runtime-guard fallback executions")
	    ("rvv-qcg-direct-setvl", bpo::value(&o.rvv_qcg_direct_setvl)->default_value(false), "S3.4: admit the exact `vsetvli rd,rs1,e32,m1,ta,ma` (VLEN 512/1024; every register combination except the reserved rd=x0 && rs1=x0 keep-vl form) into the direct-state rvvsetvl route in the LLVM/AOT backend instead of the rv32_vsetvli helper. rs1=x0 supplies the architectural AVL=~0u so vl=VLMAX; rd=x0 writes no guest register. Requires --rvv-vector-ssa and --llvm=1; every other vsetvli, every vsetivli and every vsetvl keeps the unchanged helper. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("rvv-qcg-typed-chunk-vle", bpo::value(&o.rvv_qcg_typed_chunk_vle)->default_value(false), "S3.5: admit the exact unmasked unit-stride `vle32.v` (EEW=32 from the encoding, SEW=32/LMUL=1/EMUL=1 from vtype, base register != x0; VLEN 512/1024) into the typed vchunkload/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vle helper. Requires --rvv-vector-ssa and --llvm=1, and a non-Ref --rvv-lowering; masked vle32.v, vle8/16/64.v, EMUL!=1, strided/indexed/fault-only-first/whole-register/segment loads and EVERY vse form keep the unchanged helper. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch runs the existing rv32_vle helper unchanged. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("rvv-qcg-typed-chunk-vse", bpo::value(&o.rvv_qcg_typed_chunk_vse)->default_value(false), "S3.6: admit the exact unmasked unit-stride `vse32.v` (EEW=32 from the encoding, SEW=32/LMUL=1/EMUL=1 from vtype, base register != x0; VLEN 512/1024) into the typed vstatechunkload/vchunkstore route in the LLVM/AOT backend instead of the rv32_vse helper. Requires --rvv-vector-ssa and --llvm=1, and a non-Ref --rvv-lowering; masked vse32.v, vse8/16/64.v, EMUL!=1, strided/indexed/whole-register/segment/mask stores and EVERY vle form keep the unchanged helper. Own switch, independent of --rvv-qcg-typed-chunk-vle, so a wrong guest-memory byte stays attributable to the read route or the write route. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch runs the existing rv32_vse helper unchanged. Same switch name and same envelope as elfrun's. Default off")
	    ("rvv-qcg-typed-chunk-sub", bpo::value(&o.rvv_qcg_typed_chunk_sub)->default_value(false), "T1c: admit the exact unmasked `vsub.vv` (SEW=32/LMUL=1 from vtype, .vv form from the OPIVV decode; VLEN 512/1024) into the typed vstatechunkload/vchunksub/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vialu helper. Requires --rvv-vector-ssa and --llvm=1; masked vsub.vv, other SEW, LMUL!=1, fractional LMUL, vsub.vx, vrsub and the rest of the OPIVV vialu family keep the unchanged helper. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch -- including a partial vl -- runs the existing rv32_vialu helper unchanged. Own switch, independent of --rvv-qcg-typed-chunk-mul and of --rvv-vector-ssa's effect on vadd.vv, so an accepted evidence arm's flag keeps meaning what it meant. THE LOWERING IS S3.10a's AND IS UNCHANGED: this option only makes the existing route reachable from an artifact, which it was not before T1c. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("rvv-qcg-typed-chunk-and", bpo::value(&o.rvv_qcg_typed_chunk_and)->default_value(false), "T1f: admit the exact unmasked `vand.vv` (SEW=32/LMUL=1 from vtype, .vv form from the OPIVV decode; VLEN 512/1024) into the typed vstatechunkload/vchunkand/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vialu helper. Requires --rvv-vector-ssa and --llvm=1; masked vand.vv, other SEW, LMUL!=1, fractional LMUL, vand.vx/.vi and the rest of the OPIVV vialu family keep the unchanged helper. The funct6-identical OPMVV `vaadd.vv` is a different instruction in a different funct3 group and is untouched. ITS TWO FUNCT6 NEIGHBOURS ARE UNAFFECTED: vor.vv (001010) and vxor.vv (001011) have their own separate --rvv-qcg-typed-chunk-or / -xor routes and this switch does not change what those do. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch -- including a partial vl -- runs the existing rv32_vialu helper unchanged. Own switch, independent of every sibling. With this the typed integer element-wise family is complete on this backend. Same switch name and same envelope as elfrun's. Default off")
	    ("rvv-qcg-vx-mulacc", bpo::value(&o.rvv_qcg_vx_mulacc)->default_value(false), "Native-3: admit unmasked `vmul.vx` and `vmacc.vx` (SEW=32/LMUL=1 from vtype, OPMVX scalar form from the decode; full VL; VLEN 512/1024) into the typed vchunkbroadcast/vchunkmul(/vchunkadd)/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vimul helper. The scalar is x[rs1] read from the guest register the encoding names and splatted across the lanes; vmacc.vx additionally reads vd, and every source chunk -- including vd -- is read before any destination chunk is written, so the accumulator read-before-write and the legal vd==vs2 overlap are correct by construction. Requires --rvv-vector-ssa and --llvm=1; the rest of the OPMVX/OPMVV multiply family (vmulh/vmulhu/vmulhsu, vdivu/vdiv/vremu/vrem, vnmsac, vmadd, vnmsub), every .vv form, every masked form, other SEW, LMUL!=1 and fractional LMUL keep the unchanged helper. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch -- including a partial vl -- runs the existing rv32_vimul helper unchanged. Own switch, independent of every sibling. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("rvv-qcg-typed-chunk-or", bpo::value(&o.rvv_qcg_typed_chunk_or)->default_value(false), "T1e: admit the exact unmasked `vor.vv` (SEW=32/LMUL=1 from vtype, .vv form from the OPIVV decode; VLEN 512/1024) into the typed vstatechunkload/vchunkor/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vialu helper. Requires --rvv-vector-ssa and --llvm=1; masked vor.vv, other SEW, LMUL!=1, fractional LMUL, vor.vx/.vi and the rest of the OPIVV vialu family keep the unchanged helper. ITS TWO FUNCT6 NEIGHBOURS ARE UNAFFECTED: vxor.vv (001011) has its own separate --rvv-qcg-typed-chunk-xor route and this switch does not change what that does, while vand.vv (001001) has no LLVM route at all and keeps the helper whatever this switch says. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch -- including a partial vl -- runs the existing rv32_vialu helper unchanged. Own switch, independent of --rvv-qcg-typed-chunk-sub, --rvv-qcg-typed-chunk-mul and --rvv-qcg-typed-chunk-xor. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("rvv-qcg-typed-chunk-xor", bpo::value(&o.rvv_qcg_typed_chunk_xor)->default_value(false), "T1d: admit the exact unmasked `vxor.vv` (SEW=32/LMUL=1 from vtype, .vv form from the OPIVV decode; VLEN 512/1024) into the typed vstatechunkload/vchunkxor/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vialu helper. Requires --rvv-vector-ssa and --llvm=1; masked vxor.vv, other SEW, LMUL!=1, fractional LMUL, vxor.vx/.vi and the rest of the OPIVV vialu family keep the unchanged helper. ITS TWO FUNCT6 NEIGHBOURS ARE NOT AFFECTED: vor.vv (001010) and vand.vv (001001) have no LLVM route at all and keep the helper whatever this switch says. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch -- including a partial vl -- runs the existing rv32_vialu helper unchanged. Own switch, independent of --rvv-qcg-typed-chunk-sub and --rvv-qcg-typed-chunk-mul. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("rvv-qcg-typed-chunk-mul", bpo::value(&o.rvv_qcg_typed_chunk_mul)->default_value(false), "T1b: admit the exact unmasked `vmul.vv` (SEW=32/LMUL=1 from vtype, .vv form from the OPMVV decode; VLEN 512/1024) into the typed vstatechunkload/vchunkmul/vstatechunkstore route in the LLVM/AOT backend instead of the rv32_vimul helper. Requires --rvv-vector-ssa and --llvm=1; masked vmul.vv, other SEW, LMUL!=1, fractional LMUL, vmulh/vmulhu/vmulhsu, the whole VDIV/VREM/VMACC set and every .vx form keep the unchanged helper. Guarded at run time on vlenb/vtype/vl/vstart; any mismatch -- including a partial vl -- runs the existing rv32_vimul helper unchanged. Own switch, independent of --rvv-vector-ssa's effect on vadd.vv, so an accepted evidence arm's flag keeps meaning what it meant. Same switch name and same envelope as elfrun's, so one flag means one thing in both. Default off")
	    ("llvm",    bpo::value(&o.use_llvm)->default_value(true), "use llvm backend")
	    ("mgdump", bpo::value(&o.mgdump)->default_value(""), "module graphs dump dir, specify to enable")
	    ("analyser-ecall-edge", bpo::value(&o.analyser_ecall_edge)->default_value(false), "DC-4 pre-patch: record ecall fallthrough edge in module graph")
	    ("aot-freq-gated-seed", bpo::value(&o.aot_freq_gated_seed)->default_value(false), "P2: brind_target forces a region entry only if node exec_count>=threshold (de-shatter stale seeds)")
	    ("aot-brind-seed-oracle-suppress", bpo::value(&o.aot_brind_seed_oracle_suppress)->default_value(false), "A-line decision-regret-reset: DIAGNOSTIC ORACLE ONLY -- unconditionally removes is_brind_target from region-formation seeding regardless of exec_count, to measure the pure upper-bound cost of Wendell's always-root default. Not a deployment mechanism.")
	    ("aot-link-region-merge", bpo::value(&o.aot_link_region_merge)->default_value(false), "Design 8: a brind_target that is ALSO a recorded call-site return continuation (RecordLink, zero dynamic evidence) does not force an independent region entry -- swept into its caller's region instead")
	    ("aot-link-multientry-merge", bpo::value(&o.aot_link_multientry_merge)->default_value(false), "Design 8 multi-entry: requires --aot-link-region-merge. Exposes the merged return-continuation as a secondary externally-reachable entry (thin wrapper + state->ip check in the shared caller function) instead of silently losing its _aot_tab entry")
	    ("aot-link-alias-merge", bpo::value(&o.aot_link_alias_merge)->default_value(false), "EXPERIMENTALLY BROKEN, see DESIGN8_ALIAS_MULTIENTRY_OBSTRUCTION.md -- do not use for measurement. Design 8 alias multi-entry: requires --aot-link-region-merge. Zero-wrapper variant of --aot-link-multientry-merge: exposes the merged return-continuation's own symbol as an llvm::GlobalAlias for the same address as its caller's shared function, instead of a thin wrapper function")
	    ("aot-link-multientry-trace", bpo::value(&o.aot_link_multientry_trace)->default_value(false), "Design 8 multi-entry diagnostic: emit counting shims for switch-case/default/wrapper hits (CPUState dbg_* fields)")
	    ("aot-function-closure", bpo::value(&o.aot_function_closure)->default_value(false), "P6: once a function contains >=1 admitted region, statically admit every other block in that function (pre-empt cross-input exile at build time)")
	    ("aot-jumptable-closure", bpo::value(&o.aot_jumptable_closure)->default_value(false), "P7: narrower successor to P6 -- admit only a closure function's recovered jump-table entries")
	    ("aot-jumptable-multientry", bpo::value(&o.aot_jumptable_multientry)->default_value(false), "Jump-table pivot: requires --aot-jumptable-closure. Expose P7-discovered handlers via the validated Design 8 wrapper multi-entry mechanism instead of forcing an independent region per handler")
	    ("aot-return-closure", bpo::value(&o.aot_return_closure)->default_value(false), "P9: admit every call-return continuation (ip+4 of jal/jalr-with-rd) in a closure-triggered function -- statically exact")
	    ("aot-closure-cold-section", bpo::value(&o.aot_closure_cold_section)->default_value(false), "P10: place closure-admitted (P6/P7/P9) functions in a separate object section, away from hot-code layout")
	    ("aot-fdre-region", bpo::value(&o.aot_fdre_region)->default_value(false), "FDRE (A-line architecture reset): conservation-gated dominant-source region formation; requires --aot-fdre-edges")
	    ("aot-idf-fuse", bpo::value(&o.aot_idf_fuse)->default_value(false), "A-line 2026-07-25: zero-extra-evidence region defragmentation -- let ComputeRegionDomSets grow through IDF-propagation-only region boundaries (structural, needs only is_brind_target/is_segment_entry, no edge collection)")
	    ("aot-guardonly-lower", bpo::value(&o.aot_guardonly_lower)->default_value(false), "A-line 2026-07-25: source-local guard-only oracle (expat/Xerces-class) -- guard ONLY this source's own dominant target, target stays an independently-compiled function (no region fusion, no broadcast to other sites); requires --aot-guardonly-edges")
	    ("aot-guardonly-edges", bpo::value(&o.aot_guardonly_edges)->default_value(""), "source_ip target_ip [count] per line (hex ip, decimal count optional) -- one dominant target per source; highest-count line wins if a source repeats")
	    ("aot-multiguard-lower", bpo::value(&o.aot_multiguard_lower)->default_value(false), "A-line 2026-07-25 round 12: perfect-oracle probe for the UNFOLDED-FANOUT class -- guard against EVERY distinct observed target for a source (N-way compare chain, N = observed target count, no tuned cutoff), not just the majority one; requires --aot-multiguard-edges")
	    ("aot-multiguard-edges", bpo::value(&o.aot_multiguard_edges)->default_value(""), "source_ip target_ip count per line (hex ip, decimal count) -- ALL observed (source,target) pairs, one line each; every distinct target for a source is guarded, ordered by descending count")
	    ("aot-fdre-edges", bpo::value(&o.aot_fdre_edges)->default_value(""), "FDRE: path to a --brind-edges-out-format (source,target,count) edge file")
	    ("aot-fdre-lower", bpo::value(&o.aot_fdre_lower)->default_value(false), "FDRE stage 3: lower a dominant-source jalr to a guarded direct branch (requires --aot-fdre-region)")
	    ("aot-brcc-real-weights", bpo::value(&o.aot_brcc_real_weights)->default_value(false), "DC-9 fix: derive guest brcc LLVM branch-weight metadata from already-collected objprof exec_count instead of the blanket static 1:12 hint")
	    ("aot-gbrind-hitrate-weights", bpo::value(&o.aot_gbrind_hitrate_weights)->default_value(false), "A-line Round 48: derive the L1 gbrind-cache hit/miss CondBr's LLVM branch-weight metadata (Expand_gbrind_EdgeSpecializeAndSlowpath) from a --aot-gbrind-hitrate-file dump instead of the blanket static md_unlikely hint, per source. Requires --aot-gbrind-hitrate-file.")
	    ("aot-gbrind-hitrate-file", bpo::value(&o.aot_gbrind_hitrate_file)->default_value(""), "path to a --gbrind-hitrate-out dump (slot_hash hit miss per line, hex hash/decimal counts)")
	    ("qcg-leaf-inline", bpo::value(&o.qcg_leaf_inline)->default_value(false), "A-line round 16 (TRACK 1): wire the pre-existing M-INL leaf-return-elision mechanism (rv32_qir.cpp TRANSLATOR(jal)) into the AOT compile path -- previously elfrun-only, never testable under AOT single-run economics. Zero profiling cost (pure static scan of the callee body at translation time).")
	    ("threshold", bpo::value(&o.threshold)->default_value(0), "threshold of execution count to compile")
	    ("threshold-max", bpo::value(&o.threshold_max)->default_value(0), "banded delta: admit iff exec in [threshold, threshold-max); 0=off")
		("llvmopt", bpo::value(&o.llvmopt)->default_value(false), "enable llvm optimization")
		("cross-segment-branch", bpo::value(&o.cross_segment_branch)->default_value(false), "enable cross-segment branch")
		("propagate-exec-count", bpo::value(&o.propagate_exec_count)->default_value(true), "propagate execution count")
		("dispatch-admit-floor", bpo::value(&o.dispatch_admit_floor)->default_value(0), "V-next: if >0, admit executed brind_target dispatch-handler regions with exec_count >= this even below threshold")
		("dispatch-admit-list", bpo::value(&o.dispatch_admit_list)->default_value(""), "Round-15 DIA: admit exactly the brind-target regions whose entry ip is listed (hex, one per line) in this file")
		("dispatch-deny-list", bpo::value(&o.dispatch_deny_list)->default_value(""), "A-line 2026-07-27 fair-budget oracle tooling: unconditionally refuse admission for regions whose entry ip is listed (hex, one per line) in this file, checked before the threshold test -- topology (ComputeRegions()) is unaffected; combine with --dispatch-admit-list and a fixed --threshold/--aot-freq-gated-seed to build an arbitrary explicit admission set at fixed topology")
		("gbrind-hitrate-collect", bpo::value(&o.gbrind_hitrate_collect)->default_value(false), "A-line 2026-07-27: bake the AOT-tier per-source L1 gbrind-cache hit/miss counter (tcache::gbrind_hitrate_cache) into the compiled dispatch code at this compile, so a later --aot=1 elfrun with --gbrind-hitrate-collect=1 --gbrind-hitrate-out=<f> actually measures AOT-admitted sites (previously only QCG-tier codegen ever wrote to this counter -- see llvmgen.cpp's Expand_gbrind_EdgeSpecializeAndSlowpath comment)")
		("aot-return-admit-floor", bpo::value(&o.return_admit_floor)->default_value(0), "A-line Round 59: if >0, admit return-continuation regions with exec_count >= this even below threshold (dispatch-admit-floor deliberately excludes return targets for scope reasons; this is the cheap raw-floor A/B control, see config.h)")
		("aot-return-admit-cost-model", bpo::value(&o.return_admit_cost_ratio)->default_value(0.0), "A-line Round 59: if >0, admit a return-continuation region when its own execution density (dynmass/instr) exceeds this ratio times the naturally-admitted set's own average density (self-calibrating, not a fixed threshold)")
		("aot-return-admit-optnone", bpo::value(&o.return_admit_optnone)->default_value(false), "A-line Round 59: compile return_admit_floor/-cost-model's newly-admitted regions at O0/optnone instead of O3, to test whether cheap codegen rescues the compile-cost economics")
		("aot-region-order-file", bpo::value(&o.aot_region_order_file)->default_value(""), "Layout ceiling oracle: reorder ComputeRegions() output to match this file's ip sequence (hex, one per line) before codegen -- content/size unaffected, only emission order changes")
		("aot-indirect-succs-file", bpo::value(&o.aot_indirect_succs_file)->default_value(""), "A-line round 22 Gate 1 Row 1: load (source,target,count) edges into ModuleGraphNode::indirect_succs ONLY -- a typed relation isolated from succs/region-formation/merge/lowering/layout, read only by --aot-dump-indirect-succs's consistency check")
		("aot-dump-indirect-succs", bpo::value(&o.aot_dump_indirect_succs)->default_value(false), "dump INDIRECT_SUCCS_ORACLE matched-node/edge counts per page (requires --aot-indirect-succs-file)")
		("aot-diag-link-bitcode", bpo::value(&o.aot_diag_link_bitcode)->default_value(""), "OPAQUE_BOUNDARY diagnostic (default off, NOT a shipping mechanism): path to an LLVM bitcode/IR file whose defined functions replace matching external hcall-target declarations in cmodule before the optimization pipeline runs, so LLVM's own inliner can see across what is otherwise an opaque call")
		("aot-diag-direct-funcs", bpo::value(&o.aot_diag_direct_funcs)->default_value(""), "OPAQUE_BOUNDARY mechanism ladder (default off): colon-separated stub names for which Emit_hcall references a direct named LLVM function instead of loading a pointer from CPUState::stub_tab -- independent of --aot-diag-link-bitcode, so A1 (direct call, no linked body) is reachable on its own")
		("aot-diag-inline-funcs", bpo::value(&o.aot_diag_inline_funcs)->default_value(""), "colon-separated exact function names (present in --aot-diag-link-bitcode) to mark alwaysinline after linking, forcing inlining regardless of the standard cost model")
		("aot-dump-llvm-ir", bpo::value(&o.aot_dump_llvm_ir)->default_value(""), "write the final optimized LLVM IR (post-pipeline, pre-codegen) to this path as textual .ll")
		("aot-dump-llvm-ir-preopt", bpo::value(&o.aot_dump_llvm_ir_preopt)->default_value(""), "write the generated AOT LLVM IR before the optimization/legalization pipeline to this path")
		("aot-qir-known-targets-file", bpo::value(&o.aot_qir_known_targets_file)->default_value(""), "A-line round 22 Gate 1 Row 4: load (source,target,count) edges into InstGBrind::known_targets at the STOCK lowering path only -- Expand_gbrind never reads it, isolating whether QIR merely carrying this data changes codegen")
		("aot-dump-qir-known-targets", bpo::value(&o.aot_dump_qir_known_targets)->default_value(false), "dump QIR_KNOWN_TARGETS per attached gbrind site (requires --aot-qir-known-targets-file)")
		("aot-gbrind-vp-metadata", bpo::value(&o.aot_gbrind_vp_metadata)->default_value(false), "A-line round 23 Gate 1 Row 5: attach real LLVM !prof VP metadata to the gbrind intrinsic call (from known_targets/known_target_counts) and run llvm::PGOIndirectCallPromotionPass after final intrinsic expansion (requires --aot-qir-known-targets-file)")
		("aot-log-icp", bpo::value(&o.aot_log_icp)->default_value(false), "dump pre/post-ICP IR text stats for gbrind-derived indirect calls (requires --aot-gbrind-vp-metadata)")
		("aot-log-phase-timing", bpo::value(&o.aot_log_phase_timing)->default_value(false), "A-line round 23 Gate 3 pivot: dump coarse wall-clock breakdown of compile_wall (region/QIR/LLVM-IR construction vs optimize+expand loop vs object-emit+link)")
		("aot-optlevel", bpo::value(&o.aot_optlevel)->default_value(3), "V-next: AOT LLVM opt level 0..3 (lower = cheaper compile)")
		("dispatch-handler-optnone", bpo::value(&o.dispatch_handler_optnone)->default_value(false), "V-next: optnone the dispatch-admitted handler regions (cheap compile, keep hot regions O3)")
		("aot-hot-floor", bpo::value(&o.aot_hot_floor)->default_value(0), "Round-40 Route E: admitted regions with mx<this compile at optnone (cheap), hot regions (mx>=this) keep O3; coverage preserved")
		("aot-cpb-optnone", bpo::value(&o.aot_cpb_optnone)->default_value(false), "2026-07-20 CPB: indirect-admitted regions with indirect_confidence<0.5 compile at optnone (cheap); orthogonal to aot-hot-floor which gates on size not predictability")
		("aot-merge-max", bpo::value(&o.aot_merge_max)->default_value(1), "Round-41 region-merge: group up to N consecutive admitted regions into one O3 worker (entry switch on state->ip); cuts per-function compile overhead, preserves coverage+O3. 1=off")
		("aot-heavy-final", bpo::value(&o.aot_heavy_final)->default_value(false), "Round-42: run heavy O3 only on the final expand iteration; earlier iterations do expand+light cleanup")
		("aot-heavy-last-n", bpo::value(&o.aot_heavy_last_n)->default_value(0), "Round-42 frontier: run heavy O3 on the last N expand iterations (0=use aot-heavy-final; higher=closer to O3 quality, more compile)")
		("aot-heavy-min-regions", bpo::value(&o.aot_heavy_min_regions)->default_value(0), "Round-42 region-aware: if admitted region count < this, bump to >=2 heavy iterations (keep small/hot modules safe while large use aggressive K)")
		("aot-use-lld", bpo::value(&o.aot_use_lld)->default_value(false), "2026-07-28: link the .aot.so with LLVM's ld.lld instead of /usr/bin/ld (GNU BFD) -- objemit_link_ms is unchanged by any optimize/expand-side lever, this targets the link step itself")
		("aot-codegen-optlevel", bpo::value(&o.aot_codegen_optlevel)->default_value(-1), "2026-07-28: whole-module backend CodeGenOptLevel (0-3), separate from --aot-optlevel (middle-end only); -1 = unchanged CodeGenOptLevel::Aggressive")
		("aot-final-expand-at", bpo::value(&o.aot_final_expand_at)->default_value(-1), "Round-54: run the FINAL intrinsic expansion at this iteration (default -1 = last). Tests the expand-first / single-phase schedule")
		("aot-phase1-optlevel", bpo::value(&o.aot_phase1_optlevel)->default_value(-1), "Round-54: opt level (0-3) for heavy iterations BEFORE the final expansion (Phase-1 surroundings opt); -1 = same as aot-optlevel")
		("aot-log-expand", bpo::value(&o.aot_log_expand)->default_value(false), "Round-44 diagnostic: log intrinsic-expansion count per optimize iteration (shows the lowering fixpoint)")
		("aot-log-gbrind-constfold", bpo::value(&o.aot_log_gbrind_constfold)->default_value(false), "A-line round 7 diagnostic: log how many gbrind sites Expand_gbrind's existing constant-fold-to-gbr shortcut caught vs total (default-off, no stderr output when unset)")
		("aot-log-irsize", bpo::value(&o.aot_log_irsize)->default_value(false), "Round-54-fix: log module instruction count per optimize iteration (the O3 convergence signal for the K detector)")
		("aot-reassoc-probe", bpo::value(&o.aot_reassoc_probe)->default_value(false), "P2E static diagnostic probe (default off): after every optimize/expand iteration and before codegen, append exactly ONE llvm::ReassociatePass over the module. The default O3 pipeline is NOT replaced, no existing pass is reordered, and no InstCombine cleanup is added -- this exists so reassociation can be varied as a single factor, which --aot-pipeline cannot do because it replaces the default pipeline entirely. Off => the code never runs and the emitted object is byte-identical. Diagnostic only; not a method")
		("aot-edge-specialize", bpo::value(&o.aot_edge_specialize)->default_value(false), "Round-46: guarded direct-call fastpath for top-K profiled hot indirect targets (LLVM optimizes across edge)")
		("aot-edge-oracle-unconditional", bpo::value(&o.aot_edge_oracle_unconditional)->default_value(false), "ORACLE-ONLY (2026-07-22): unconditional direct call to aot-edge-targets[0], no guard. Breaks correctness by design -- measurement only, never deployable.")
		("aot-return-oracle-unconditional", bpo::value(&o.aot_return_oracle_unconditional)->default_value(false), "A-line round 25 Track A Treatment 1, ORACLE-ONLY: per-source unconditional direct call for RETURN-class gbrind sites with exactly one known_targets entry (requires --aot-qir-known-targets-file). Breaks correctness by design -- measures the perfect/free ceiling only, never deployable.")
		("aot-log-gipv-shape", bpo::value(&o.aot_log_gipv_shape)->default_value(false), "A-line round 25 Track B free-oracle test: classify each non-const-folded gbrind gipv's post-O3 IR shape (diagnostic only, no codegen change)")
		("aot-dump-gbrind-indegree", bpo::value(&o.aot_dump_gbrind_indegree)->default_value(false), "A-line round 25 Track C free-oracle test step 1: dump static in-degree of every gbrind source block (diagnostic only, no codegen change)")
		("aot-log-gbrind-site-identity", bpo::value(&o.aot_log_gbrind_site_identity)->default_value(false), "A-line round 26 Part A: tag each logical gbrind site with a unique id and count survivors in the final compiled module, to directly measure host-PC sharing across guest sources (diagnostic only, no codegen change)")
		("aot-order1-context-oracle", bpo::value(&o.aot_order1_context_oracle)->default_value(false), "A-line round 28 Gate 1 ORACLE (exhaustive-truth-for-the-measured-run, not deployable): per-SOURCE order-1 context guard, reading/updating this site's own tcache::gbrind_ctx1_slots entry -- never a global/shared context. Requires --aot-order1-context-file")
		("aot-order1-context-file", bpo::value(&o.aot_order1_context_file)->default_value(""), "A-line round 28 Gate 1: path to a .trans file (src prev target count) from --brind-edges-out --sr-record-returns=1")
		("aot-marginal-context-oracle", bpo::value(&o.aot_marginal_context_oracle)->default_value(false), "A-line round 29 Gate 1 ORACLE: per-SOURCE MARGINAL (context-free) target guard -- single compile-time-constant compare, zero runtime state. Reuses --aot-order1-context-file")
		("aot-static-table-oracle", bpo::value(&o.aot_static_table_oracle)->default_value(false), "A-line round 32 Gate 2 ORACLE: per-SOURCE PROVEN-COMPLETE static jump-table target set, read from the guest ELF's own read-only memory offline (r32_bootstrap_tool.py), lowered as a real llvm::SwitchInst. Requires --aot-static-table-file")
		("aot-static-table-file", bpo::value(&o.aot_static_table_file)->default_value(""), "A-line round 32 Gate 2: path to a static-table file (src target1 target2 ...) produced by r32_bootstrap_tool.py")
		("aot-static-table-inline", bpo::value(&o.aot_static_table_inline)->default_value(false), "A-line round 32 R32.9: TRUE in-process resolution, no file, no external disassembler -- reuses elfaot's own decode during normal translation. Requires --aot-static-table-oracle=1; ignores --aot-static-table-file if also set")
		("aot-static-table-alwaysinline", bpo::value(&o.aot_static_table_alwaysinline)->default_value(false), "A-line Round 50: use a non-musttail, AlwaysInline call (CreateInlinableQCGFnCall) instead of the generic musttail CreateQCGFnCall for static_table_md's SwitchInst hit cases, so LLVM's inliner can legally act on them. Requires --aot-static-table-oracle=1.")
		("aot-static-table-switch-noinline", bpo::value(&o.aot_static_table_switch_noinline)->default_value(false), "A-line Round 64: switch to static_table_resolve's proven candidates using ONLY ordinary musttail CreateQCGFnCall, never inlining -- isolates the switch consumer's own economics from Round 54's inlining-specific compile-cost tax. Requires --aot-static-table-oracle=1.")
		("aot-static-table-target-optnone", bpo::value(&o.aot_static_table_target_optnone)->default_value(false), "A-line Round 66: mark every static_table_resolve candidate TARGET function OptimizeNone+NoInline, cutting LLVM optimize-pass compile cost (the dominant compile-time component, 71-74% per Round 65's phase timing) for this structurally-identified function class -- independent of switch_noinline/alwaysinline (changes shared baseline compile cost, not the dispatch mechanism). Requires --aot-static-table-oracle=1.")
		("aot-indexed-dispatch-oracle", bpo::value(&o.aot_indexed_dispatch_oracle)->default_value(false), "A-line Round 44: index-preserving compact host dispatch table, O(1) IR regardless of table size (not an N-way SwitchInst). Independent of --aot-static-table-oracle/-inline (own dataflow resolver).")
		("aot-indexed-dispatch-require-full-coverage", bpo::value(&o.aot_indexed_dispatch_require_full_coverage)->default_value(false), "A-line Round 45: compile-time-only (zero profile) worst-case cost dominance gate -- only emit the compact dispatch for a site if EVERY proven table entry is independently AOT-admitted, so the fallback path is structurally unreachable and the extra overhead is never paid on top of the original path's own cost.")
		("aot-vtable-narrow-oracle", bpo::value(&o.aot_vtable_narrow_oracle)->default_value(false), "A-line Round 33 ORACLE: per-SOURCE C++ virtual-call target-set NARROWING (not proven-complete, guarded SwitchInst falls to the generic gbrind slowpath on a miss) via Itanium RTTI class-hierarchy descendant enumeration. Requires --aot-vtable-narrow-inline=1")
		("aot-vtable-narrow-inline", bpo::value(&o.aot_vtable_narrow_inline)->default_value(false), "A-line Round 33: TRUE in-process resolution, no file -- reuses elfaot's own decode + the guest ELF's symbol/RTTI data during normal translation. Requires --aot-vtable-narrow-oracle=1")
		("aot-direct-call-fusion", bpo::value(&o.aot_direct_call_fusion)->default_value(false), "A-line Round 34: AUIPC+JALR direct-call-sequence fusion -- recognizes the standard RISC-V psABI call/tail pseudo-instruction expansion as a compile-time-constant direct call (translator completeness fix, not a narrowing oracle) and lowers it like a genuinely-direct jal, zero guard")
		("aot-return-directify", bpo::value(&o.aot_return_directify)->default_value(false), "A-line Round 56: return-continuation directification -- when a region's own entry has a whole-binary-proven single static caller, lower its RISC-V 'ret' as a plain direct branch to that caller's continuation. Zero code duplication, zero region-membership change, zero guard.")
		("aot-vtable-narrow-zeroguard-singleton", bpo::value(&o.aot_vtable_narrow_zeroguard_singleton)->default_value(false), "A-line Round 36 Consumer A: when vtable_narrow's candidate set is PROVEN to have exactly one member, lower as a TRUE zero-guard direct edge (MakeGBr) instead of a guarded SwitchInst. Requires --aot-vtable-narrow-oracle=1 --aot-vtable-narrow-inline=1")
		("aot-gbrind-context-replicate", bpo::value(&o.aot_gbrind_context_replicate)->default_value(false), "A-line round 26 Part A/Track C ORACLE (known baseline: Ertl/Gregg dispatch replication -- not a claimed contribution): give each static predecessor of a shared gbrind dispatch its own host indirect-transfer site, same lookup/targets, no guard, no offline profile")
		("aot-edge-topk", bpo::value(&o.aot_edge_topk)->default_value(0), "Round-46: number of top hot targets to specialize+force-admit")
		("aot-edge-profile", bpo::value(&o.aot_edge_profile)->default_value(""), "Round-46: brind-edges profile (src dst count per line) to pick the top-K hot targets")
		("aot-indirect-edges", bpo::value(&o.aot_indirect_edges)->default_value(""), "2026-06-20 jserv-A: indirect-edge profile (src dst count) -> mark observed targets region entries w/ true dispatch mass + propagate hotness along direct succs to admit the warm dispatch component")
		("aot-indirect-propagate", bpo::value(&o.aot_indirect_propagate)->default_value(true), "Research ablation: propagate admitted indirect-target hotness through its direct CFG component")
		("aot-admit-mode", bpo::value(&o.aot_admit_mode)->default_value(0), "2026-07-20 A0-A5 attribution matrix: 0=A1 jserv-A pooled+floor (default) 1=A2 pooled-no-floor 2=A3 per-source-no-weight-control 3=A4 SCA(top1/total) 4=A5 Wilson-lower-bound 5=A6 (2026-07-22) per-SOURCE total-mass floor: if a source's summed outgoing indirect mass >= threshold, admit every target reachable from it regardless of individual target share")
		("aot-edge-underadmit-gate", bpo::value(&o.aot_edge_underadmit_gate)->default_value(false), "Round-46 P5: among the top-K hot targets, specialize ONLY those with in-count < threshold (under-admitted by the freq rule); skip already-admitted targets so specialization complements admission instead of duplicating it (auto-abstain when top-K are all admitted)")
		("aot-edge-region-merge", bpo::value(&o.aot_edge_region_merge)->default_value(false), "P3: merge majority-coverage dispatch targets INTO the top-source region as internal blocks; gbrind lowers to an internal switch (single entry -- avoids the Round-41 GHC-GHC merge wall)")
		("aot-edge-closure-merge", bpo::value(&o.aot_edge_closure_merge)->default_value(false), "ORACLE: co-compile the maximum-mass SCC of the dynamic indirect-edge graph; parameter-free structural ceiling test")
		("aot-edge-select-exclusive", bpo::value(&o.aot_edge_select_exclusive)->default_value(false), "Lane B 2026-07-23: PRINCIPLED (non-magic) selection -- for EVERY source s in the edge profile (not just the top-mass one), internalize target t iff indegree(t)==1 (s is t's ONLY observed predecessor in the whole profile) and no direct (t,s) back-edge exists. No mass ranking, no percentage cutoff. Multi-source (populates aot_region_merge_map with one entry per qualifying source). Reuses the existing --aot-edge-region-merge splice mechanism unchanged.")
		("aot-edge-select-flow", bpo::value(&o.aot_edge_select_flow)->default_value(false), "A-line 2026-07-23: FLOW-CERTAIN DOMINANCE selection -- edge weights derived from conservation invariants (per-source outflow = source block count; per-target inflow = target count when dispatch-only-reachable, ModuleGraph-checked), leaf-peeled; internalize only determined strict-majority edges; non-forest components abstain. Needs --aot-edge-profile (SET; counts ignored).")
		("aot-edge-move-not-copy", bpo::value(&o.aot_edge_move_not_copy)->default_value(false), "A-line 2026-07-23: internalized merge targets are MOVED, not copied -- the standalone body of a fired merge target is replaced by a 2-insn thunk (state->ip=T; musttail _xS) re-entering the source function's existing multi-entry switch. Removes the duplicate compile that made the candidate's compile phase ~+60% over Wendell.")
		("aot-edge-select-acyclic", bpo::value(&o.aot_edge_select_acyclic)->default_value(false), "Lane B 2026-07-23: PRINCIPLED (non-magic) selection -- Tarjan SCC over the whole edge profile; a source s qualifies only if s's own SCC is trivial (size 1, no observed cycle through s); its target set is every DIRECT successor t of s whose SCC is also trivial (targets MAY be shared/polymorphic, unlike --aot-edge-select-exclusive). Structural acyclicity safety boundary -- never selects a component containing an observed cycle. Multi-source, same splice mechanism.")
		("repeat-compile", bpo::value(&o.repeat_compile)->default_value(1), "2026-07-18 C-line: run LLVMAOTCompileELF() N times in the SAME process (same LLVM target-registry/static-init state) to separate process-spawn-only fixed cost from LLVM-object-lifecycle-inherent fixed cost; each iteration timed and printed separately")
		("aot-count-gbrind", bpo::value(&o.aot_count_gbrind)->default_value(false), "A-line: emit gbrind-execution counter in AOT dispatch path (measurement artifact)")
		("aot-work-counter", bpo::value(&o.aot_work_counter)->default_value(false), "DVET: emit a region-entry work counter (CPUState::work_counter++) in generated code -- trial artifacts only")
	    ("aot-region-hit-count", bpo::value(&o.aot_region_hit_count)->default_value(false), "2026-07-28: emit a per-region compile-time-assigned dense-slot entry counter (CPUState::region_entry_hits[slot]++) for causal ablation, independent of Wendell's exec_count")
	    ("aot-region-cycle-count", bpo::value(&o.aot_region_cycle_count)->default_value(false), "formal diagnostic: accumulate invariant-TSC execution time in each dense region slot (incompatible with --aot-region-hit-count)")
		("aot-region-hit-map-out", bpo::value(&o.aot_region_hit_map_out)->default_value(""), "2026-07-28: dump \"slot entry_ip\" lines (compile order) for --aot-region-hit-count's slot assignment")
		("sr-activation-invariant", bpo::value(&o.sr_activation_invariant)->default_value(false), "Line-B: emit exec_instr_seen increment (region->num_insns per entry) in AOT code, consistent with elfrun's QCG-side instrumentation")
		("dry-page-floor", bpo::value(&o.dry_page_floor)->default_value(false), "dry prefilter: skip pages whose max exec count < threshold -- dry cost becomes proportional to the rung's ambition (ski-shaped); admission output unchanged (region mx <= page max)")
		("aot-context-edge-specialize", bpo::value(&o.aot_context_edge_specialize)->default_value(false), "path-history exec-proof: CONTEXT-keyed (2-level) dispatch spec -- guard (prev_target,predicted_target) instead of site-local top-K")
		("aot-context-edge-topk", bpo::value(&o.aot_context_edge_topk)->default_value(0), "path-history: number of top hot (prev->predicted) contexts to specialize+force-admit")
		("aot-context-edge-profile", bpo::value(&o.aot_context_edge_profile)->default_value(""), "path-history: .trans profile (src prev target count per line) to pick the top contexts")
		("aot-pipeline", bpo::value(&o.aot_pipeline)->default_value(""), "Round-42: custom LLVM pass-pipeline string for the heavy iteration (e.g. function(sroa,early-cse<memssa>,instcombine,gvn,simplifycfg)); empty=default O-level")
		("aot-shard-mod", bpo::value(&o.aot_shard_mod)->default_value(1), "V-next Phase 2B: total shards for parallel compile (1=off)")
		("aot-shard-idx", bpo::value(&o.aot_shard_idx)->default_value(0), "V-next Phase 2B: this shard's index [0,mod) -- defines only regions with admitted-index%mod==idx")
		("aot-shard-link", bpo::value(&o.aot_shard_link)->default_value(0), "V-next R3: aggregation/link mode (=N) -- emit aottab-only object + link the N shard .o into one runnable .aot.so")
		("dump-applicability", bpo::value(&o.dump_applicability)->default_value(false), "V-next R4: dry-run admission analysis; print profile-derived applicability features (dispatch exec-mass fraction) for the build-time gate; no codegen")
		("return-headroom-edges-file", bpo::value(&o.return_headroom_edges_file)->default_value(""), "A-line Round 55: measurement-only -- run the whole-binary static single-caller certificate for return continuations and report what fraction of ACTUAL return-class dispatch mass (from a --shadow-edges2-all-jalr edge file) it would cover. No codegen change; exits after printing.")
		("dump-regions", bpo::value(&o.dump_regions)->default_value(false), "Round-8: with dump-applicability, also emit per-region REGIONDUMP lines (exec_count/instr/brind/ret/hot/handler) for the region-utility model")
		("dump-regions-internal-edges", bpo::value(&o.dump_regions_internal_edges)->default_value(false), "A-line 2026-07-27: with --dump-regions, also emit internal-successor REGIONEDGE (kind=internal) lines for edges whose destination is a member of the same region -- enables real reachability analysis of a region's own body, which the base --dump-regions output structurally cannot support (it only ever logs edges that exit a region)")
		("dump-loop-vs-idf", bpo::value(&o.dump_loop_vs_idf)->default_value(false), "Cycle-13 Phase-0: behavior-neutral; count natural loops whose body contains an actionable internal region_entry (split across >=2 IDF regions). Reports LOOP_TOTAL/LOOP_SPLIT/...")
		("aot-loop-entry", bpo::value(&o.aot_loop_entry)->default_value(false), "T5c-0 (default off): give every natural-loop header inside an admitted region its own entry symbol, via the existing multi-entry wrapper mechanism. Region formation, region membership and generated region code are unchanged; the artifact gains one entry wrapper and one _aot_tab slot per exposed header. This is what makes a region LATE-ENTERABLE: rvdbt seeds region entries only from segment entries and indirect-branch targets, so a loop header reached by direct branches has no entry symbol and BootOneArtifact's RelinkTo cannot redirect a loop that is already running. THERE IS NO PER-LOOP HOTNESS GATE: the candidates are the natural-loop headers of regions the compiler already selected, and selection is the only hotness filter applied. A --threshold gate was deliberately not added because it would be inert on the path this exists for -- sr_builder.sh runs admission separately and then invokes elfaot with --threshold=999999999 --dispatch-admit-list -- so cost scales with the number of natural loops in an admitted region (8 wrappers, +1.45% artifact size on the frozen T5c-0 guest; unmeasured on loop-dense code).")
		("loop-structural-regions", bpo::value(&o.loop_structural_regions)->default_value(false), "Cycle-13 Phase-1 method: form loop-closed regions by suppressing region_entry on header-dominated non-entry dom-frontier nodes inside natural loops")
		("aot-loop-regions", bpo::value(&o.aot_loop_regions)->default_value(false), "T5d1b (default off): build the AOT unit from T5d1a's SELECTED HOT NATURAL LOOPS instead of Wendell's per-page dominance regions. Each selected candidate becomes ONE real LLVM function whose external entry is the loop HEADER itself, containing exactly that candidate's canonical body -- which may span guest pages. Every CFG successor outside the body stays an explicit region exit through the existing QIR gbr/dispatcher contract, and a target the profile never executed exits through the same generic path (no target is ever invented). Nested candidates stay distinct functions and may duplicate blocks; the duplication is reported, not hidden. Admission is only T5d1a's header_exec_freq >= --threshold: no new threshold, ratio, timer or workload constant, and no promotion or OSR. Uses no multi-entry wrapper, alias or --aot-loop-entry exposure: the header is the entry. With the flag off nothing here runs.")
		("aot-loop-regions-qir-out", bpo::value(&o.aot_loop_regions_qir_out)->default_value(""), "T5d1b: with --aot-loop-regions, write the QIR of every emitted region to this file -- the translator's own output, before any LLVM pass. Empty (default) prints nothing.")
		("dump-loop-candidates", bpo::value(&o.dump_loop_candidates)->default_value(false), "T5d1a (default off): DRY RUN -- print the canonical hot-natural-loop candidate set of this profile and exit WITHOUT compiling. The analysis is over ONE STITCHED CFG spanning every profiled executable page, not one graph per 4 KiB page, so whether a loop is found does not depend on where the linker put its blocks; branch targets that the profile never executed are reported as LOOPUNRESOLVED rather than absorbed. One candidate per natural-loop HEADER, where a natural loop is a CFG edge latch->header whose header dominates its latch on the dominator tree the compiler itself builds (not an address comparison); the several latches of one header merge into one candidate whose body is the union of their bodies and may span pages, and nested loops stay distinct candidates because their headers differ. A candidate is HOT iff its header block's EXECUTION FREQUENCY IN THIS PROFILE reaches THIS invocation's --threshold, the same constant RegionAdmitted uses -- there is no second bar and no new number. That frequency is loop hotness evidence and NOT a trip count: it also counts every entry into the loop from outside, it is not a backedge-taken count, it says nothing about iteration cost, and --propagate-exec-count (default on) adds a carried sum to it; the report states this in its own LOOPCAND_EVIDENCE line. Every loop is printed with its disposition, and so is every raw back-edge, so the output cannot be confused with exposing all loop headers. Selection only: no node is marked, no region is chosen, no artifact is produced.")
		("dump-loop-candidates-out", bpo::value(&o.dump_loop_candidates_out)->default_value(""), "T5d1a: write --dump-loop-candidates output to this file instead of stdout. Read only when --dump-loop-candidates is set.")
		("dump-region-spill-exposure", bpo::value(&o.dump_region_spill_exposure)->default_value(false), "Cycle-14 SEGA Phase-0: behavior-neutral; on the PBA (--llvm=0) path dump per-region REGIONSPILL lines (ip/spills/exec/dyn_instr/instrs/exposure) to test spill-exposure vs exec-count admission ranking");
	// clang-format on

	try {
		bpo::variables_map vmap;
		bpo::store(bpo::parse_command_line(argc, argv, adesc), vmap);
		if (vmap.count("help")) {
			PrintHelp(adesc);
			return false;
		}
		bpo::notify(vmap);
	} catch (std::exception &e) {
		std::cerr << "Bad options: " << e.what() << "\n";
		PrintHelp(adesc);
		return false;
	}
	return true;
}

static void SetupLogger(std::string const &logopt)
{
	boost::char_separator sep(":");
	boost::tokenizer tok(logopt, sep);
	for (auto const &e : tok) {
		dbt::Logger::enable(e.c_str());
	}
}

static void SetupConfig(ElfAotOptions &opts)
{
	dbt::config::threshold = opts.threshold;
	if (!dbt::rv32::vlen_supported(opts.vlen)) {
		std::cerr << "invalid --vlen=" << opts.vlen << " (must be a supported RVV VLEN)\n";
		std::exit(1);
	}
	dbt::config::vlen_bits = opts.vlen;
	dbt::config::rvv_vector_run = opts.rvv_vector_run;
	// The membership-rule ablation factor. Fail closed on the one combination in which it cannot
	// mean anything: with --rvv-vector-run=0 no run is scanned at all, so an arm that asked for
	// scalar passthrough would silently be the same arm as one that did not.
	dbt::config::rvv_run_scalar_passthrough = opts.rvv_run_scalar_passthrough;
	if (dbt::config::rvv_run_scalar_passthrough && !dbt::config::rvv_vector_run) {
		std::cerr << "--rvv-run-scalar-passthrough requires --rvv-vector-run=1\n";
		std::exit(1);
	}
	// Fail closed on an unknown body mode rather than silently running the default: the two
	// modes are the single factor of the R1A.3d ablation, so a typo must not quietly become
	// "the other arm".
	if (opts.rvv_run_body == "ssa") {
		dbt::config::rvv_run_body_materialize = false;
	} else if (opts.rvv_run_body == "materialize") {
		dbt::config::rvv_run_body_materialize = true;
	} else {
		std::cerr << "--rvv-run-body must be 'ssa' or 'materialize', got '"
			  << opts.rvv_run_body << "'\n";
		std::exit(1);
	}
	// Same fail-closed discipline as --rvv-run-body: the two orders are the single factor of
	// the P6C ablation, so a typo must not quietly become "the other arm".
	if (opts.rvv_run_order == "member") {
		dbt::config::rvv_run_order_chunk_major = false;
	} else if (opts.rvv_run_order == "chunk") {
		dbt::config::rvv_run_order_chunk_major = true;
	} else {
		std::cerr << "--rvv-run-order must be 'member' or 'chunk', got '"
			  << opts.rvv_run_order << "'\n";
		std::exit(1);
	}
	// P7O-1. The component-separable classifier switch, refused loudly in every combination in
	// which it cannot mean what it says. Without runs there is no descriptor to classify. The
	// materialize body and the live-range-splitting body each rewrite pass 1/2/3 with their own
	// residency model, so "one component at a time" would be a claim about a body that is not
	// emitted; and inside a single component's sub-body member-major and chunk-major are the
	// same order, so keeping both knobs would stop the ablation being one-factor. Checked after
	// --rvv-run-body and --rvv-run-order have been parsed, so the test reads the resolved values.
	dbt::config::rvv_run_component_separable = opts.rvv_run_component_separable;
	if (dbt::config::rvv_run_component_separable) {
		if (!dbt::config::rvv_vector_run || dbt::config::rvv_run_body_materialize ||
		    dbt::config::rvv_run_live_range_split ||
		    dbt::config::rvv_run_order_chunk_major) {
			std::cerr << "--rvv-run-component-separable requires --rvv-vector-run=1, "
				     "--rvv-run-body=ssa, --rvv-run-order=member and "
				     "--rvv-run-live-range-split=0\n";
			std::exit(1);
		}
	}
	// P7O-2. The demand-placement switch, refused loudly in every combination in which it cannot
	// mean what it says. It is a placement rule INSIDE the component-major body, so without
	// --rvv-run-component-separable=1 no descriptor carries that decision, the component-major
	// arm is unreachable and an arm that asked for demand placement would silently be the same
	// arm as one that did not. Its remaining exclusions are inherited from that switch, which is
	// already validated above; the one it ADDS is the dependency probe, whose `vchunkdep` nodes
	// follow each lane op and make `cur[rd][c]` the probe's output rather than the member's, so
	// Rule S's anchor -- "the point after which this value never changes" -- would be wrong. The
	// probe has no elfaot option, so the global is read rather than an `opts` field, which keeps
	// this check true of a caller that set it directly.
	dbt::config::rvv_run_component_demand_placement = opts.rvv_run_component_demand_placement;
	if (dbt::config::rvv_run_component_demand_placement) {
		if (!dbt::config::rvv_run_component_separable ||
		    dbt::config::rvv_run_dep_probe_depth) {
			std::cerr << "--rvv-run-component-demand-placement requires "
				     "--rvv-run-component-separable=1 and "
				     "--rvv-run-dep-probe-depth=0\n";
			std::exit(1);
		}
	}
	// C4e. Resolved AFTER every other run switch so it reads their final values. Two fail-closed
	// rules, both refusing a combination in which the switch could not mean what it says:
	//
	//   * the grouped body needs the vector-run scan to produce a multi-member run at all, and it
	//     REPLACES the linear order the other four body selectors each rewrite with their own
	//     residency model. Silently resolving one of those would make an arm labelled "grouped"
	//     emit a different body.
	//   * the bound needs the grouped body. On a member-major body the early exit leaves the whole
	//     frame and would jump past LATER MEMBERS -- QEmit::Emit_vchunkactive Panics on exactly
	//     that, so without this check the failure would be a dead translation rather than a
	//     rejected command line.
	dbt::config::rvv_run_grouped_component_major = opts.rvv_run_grouped_component_major;
	if (dbt::config::rvv_run_grouped_component_major) {
		if (!dbt::config::rvv_vector_run || dbt::config::rvv_run_body_materialize ||
		    dbt::config::rvv_run_live_range_split ||
		    dbt::config::rvv_run_order_chunk_major ||
		    dbt::config::rvv_run_component_separable ||
		    dbt::config::rvv_run_dep_probe_depth) {
			std::cerr << "--rvv-run-grouped-component-major requires --rvv-vector-run=1, "
				     "--rvv-run-body=ssa, --rvv-run-order=member, "
				     "--rvv-run-live-range-split=0, "
				     "--rvv-run-component-separable=0 and "
				     "--rvv-run-dep-probe-depth=0\n";
			std::exit(1);
		}
	}
	dbt::config::rvv_qcg_active_vl_run_bound = opts.rvv_qcg_active_vl_run_bound;
	if (dbt::config::rvv_qcg_active_vl_run_bound &&
	    !dbt::config::rvv_run_grouped_component_major) {
		std::cerr << "--rvv-qcg-active-vl-run-bound requires "
			     "--rvv-run-grouped-component-major=1\n";
		std::exit(1);
	}
	// C4h. Resolved after the bound it weakens, so it reads that switch's final value. Fail-closed
	// for the reason the switch's own description gives: a placebo with no bound node to weaken is
	// byte-identical to its control, so an arm labelled "placebo" would silently be the control arm.
	dbt::config::rvv_qcg_active_vl_bound_placebo = opts.rvv_qcg_active_vl_bound_placebo;
	if (dbt::config::rvv_qcg_active_vl_bound_placebo &&
	    !dbt::config::rvv_qcg_active_vl_run_bound) {
		std::cerr << "--rvv-qcg-active-vl-bound-placebo requires "
			     "--rvv-qcg-active-vl-run-bound=1\n";
		std::exit(1);
	}
	dbt::config::rvv_qcg_hit_counter = opts.rvv_qcg_hit_counter;
	dbt::config::rvv_vector_ssa = opts.rvv_vector_ssa;
	dbt::config::rvv_llvm_wide_vadd = opts.rvv_llvm_wide_vadd;
	dbt::config::rvv_llvm_wide_vadd_ssa = opts.rvv_llvm_wide_vadd_ssa;
	dbt::config::rvv_vector_ssa_counters = opts.rvv_vector_ssa_counters;
	dbt::config::rvv_qcg_direct_setvl = opts.rvv_qcg_direct_setvl;
	dbt::config::rvv_qcg_vx_mulacc = opts.rvv_qcg_vx_mulacc;
	dbt::config::rvv_qcg_typed_chunk_falu = opts.rvv_qcg_typed_chunk_falu;
	dbt::config::rvv_qcg_typed_chunk_fma = opts.rvv_qcg_typed_chunk_fma;
	dbt::config::rvv_qcg_typed_chunk_fsqrt = opts.rvv_qcg_typed_chunk_fsqrt;
	dbt::config::rvv_qcg_typed_chunk_fredosum = opts.rvv_qcg_typed_chunk_fredosum;
	dbt::config::rvv_qcg_typed_chunk_wholemove = opts.rvv_qcg_typed_chunk_wholemove;
	dbt::config::rvv_llvm_setvl_reg = opts.rvv_llvm_setvl_reg;
	dbt::config::rvv_llvm_scalar_move = opts.rvv_llvm_scalar_move;
	dbt::config::rvv_llvm_partial_vl = opts.rvv_llvm_partial_vl;
	dbt::config::rvv_llvm_shift = opts.rvv_llvm_shift;
	dbt::config::rvv_llvm_extend = opts.rvv_llvm_extend;
	dbt::config::rvv_llvm_fclass = opts.rvv_llvm_fclass;
	dbt::config::rvv_llvm_fcvt_itof = opts.rvv_llvm_fcvt_itof;
	dbt::config::rvv_llvm_fcvt_ftoi = opts.rvv_llvm_fcvt_ftoi;
	dbt::config::rvv_llvm_fcvt_fwiden = opts.rvv_llvm_fcvt_fwiden;
	dbt::config::rvv_llvm_fcvt_fnarrow = opts.rvv_llvm_fcvt_fnarrow;
	dbt::config::rvv_llvm_fcvt_itof_widen = opts.rvv_llvm_fcvt_itof_widen;
	dbt::config::rvv_llvm_fcvt_ftoi_widen = opts.rvv_llvm_fcvt_ftoi_widen;
	dbt::config::rvv_llvm_fcvt_partial_vl = opts.rvv_llvm_fcvt_partial_vl;
	dbt::config::rvv_llvm_masked = opts.rvv_llvm_masked;
	dbt::config::rvv_llvm_fp_masked = opts.rvv_llvm_fp_masked;
	dbt::config::rvv_llvm_restart = opts.rvv_llvm_restart;
	dbt::config::rvv_llvm_fcvt_rod = opts.rvv_llvm_fcvt_rod;
	dbt::config::rvv_llvm_festimate = opts.rvv_llvm_festimate;
	dbt::config::rvv_llvm_fmerge = opts.rvv_llvm_fmerge;
	dbt::config::rvv_llvm_fwiden = opts.rvv_llvm_fwiden;
	dbt::config::rvv_llvm_satadd = opts.rvv_llvm_satadd;
	dbt::config::rvv_llvm_adc = opts.rvv_llvm_adc;
	dbt::config::rvv_llvm_avg = opts.rvv_llvm_avg;
	dbt::config::rvv_llvm_smul = opts.rvv_llvm_smul;
	dbt::config::rvv_llvm_nclip = opts.rvv_llvm_nclip;
	dbt::config::rvv_llvm_ired = opts.rvv_llvm_ired;
	dbt::config::rvv_llvm_mlogic = opts.rvv_llvm_mlogic;
	dbt::config::rvv_llvm_icmp = opts.rvv_llvm_icmp;
	dbt::config::rvv_llvm_mem_partial_vl = opts.rvv_llvm_mem_partial_vl;
	dbt::config::rvv_llvm_vid = opts.rvv_llvm_vid;
	dbt::config::rvv_llvm_mscalar = opts.rvv_llvm_mscalar;
	dbt::config::rvv_llvm_mprefix = opts.rvv_llvm_mprefix;
	dbt::config::rvv_llvm_viota = opts.rvv_llvm_viota;
	dbt::config::rvv_llvm_vcompress = opts.rvv_llvm_vcompress;
	dbt::config::rvv_llvm_vrgather = opts.rvv_llvm_vrgather;
	dbt::config::rvv_llvm_vslide = opts.rvv_llvm_vslide;
	dbt::config::rvv_llvm_vstrided = opts.rvv_llvm_vstrided;
	dbt::config::rvv_llvm_vindexed = opts.rvv_llvm_vindexed;
	dbt::config::rvv_llvm_fixed_masked = opts.rvv_llvm_fixed_masked;
	dbt::config::rvv_llvm_fp_cvt_masked = opts.rvv_llvm_fp_cvt_masked;
	dbt::config::rvv_llvm_fp_dynamic_frm = opts.rvv_llvm_fp_dynamic_frm;
	dbt::config::rvv_llvm_fwiden_partial_vl = opts.rvv_llvm_fwiden_partial_vl;
	dbt::config::rvv_llvm_fwiden_masked = opts.rvv_llvm_fwiden_masked;
	dbt::config::rvv_llvm_widen = opts.rvv_llvm_widen;
	dbt::config::rvv_llvm_narrow = opts.rvv_llvm_narrow;
	dbt::config::rvv_llvm_fp_partial_vl = opts.rvv_llvm_fp_partial_vl;
	dbt::config::rvv_qcg_typed_chunk_mem_e64 = opts.rvv_qcg_typed_chunk_mem_e64;
	dbt::config::rvv_qcg_partial_vl = opts.rvv_qcg_partial_vl;
	dbt::config::rvv_qcg_typed_chunk_vle = opts.rvv_qcg_typed_chunk_vle;
	dbt::config::rvv_qcg_typed_chunk_vse = opts.rvv_qcg_typed_chunk_vse;
	dbt::config::rvv_qcg_typed_chunk_sub = opts.rvv_qcg_typed_chunk_sub;
	dbt::config::rvv_qcg_typed_chunk_xor = opts.rvv_qcg_typed_chunk_xor;
	dbt::config::rvv_qcg_typed_chunk_or = opts.rvv_qcg_typed_chunk_or;
	dbt::config::rvv_qcg_typed_chunk_and = opts.rvv_qcg_typed_chunk_and;
	dbt::config::rvv_qcg_typed_chunk_mul = opts.rvv_qcg_typed_chunk_mul;
	if (opts.rvv_vector_ssa) {
#if defined(__x86_64__) || defined(__i386__)
		__builtin_cpu_init();
		dbt::config::rvv_vector_ssa_host_fma = __builtin_cpu_supports("fma");
#else
		dbt::config::rvv_vector_ssa_host_fma = false;
#endif
	}
	dbt::config::analyser_ecall_edge = opts.analyser_ecall_edge;
	dbt::config::aot_freq_gated_seed = opts.aot_freq_gated_seed;
	dbt::config::aot_brind_seed_oracle_suppress = opts.aot_brind_seed_oracle_suppress;
	dbt::config::aot_link_region_merge = opts.aot_link_region_merge;
	dbt::config::aot_link_multientry_merge = opts.aot_link_multientry_merge;
	dbt::config::aot_link_alias_merge = opts.aot_link_alias_merge;
	dbt::config::aot_link_multientry_trace = opts.aot_link_multientry_trace;
	dbt::config::aot_function_closure = opts.aot_function_closure;
	dbt::config::aot_jumptable_closure = opts.aot_jumptable_closure;
	dbt::config::aot_jumptable_multientry = opts.aot_jumptable_multientry;
	dbt::config::aot_return_closure = opts.aot_return_closure;
	dbt::config::aot_closure_cold_section = opts.aot_closure_cold_section;
	dbt::config::aot_fdre_region = opts.aot_fdre_region;
	dbt::config::aot_idf_fuse = opts.aot_idf_fuse;
	dbt::config::aot_fdre_edges_path = opts.aot_fdre_edges.c_str(); // opts outlives the whole compile
	dbt::config::aot_fdre_lower = opts.aot_fdre_lower;
	dbt::config::aot_guardonly_lower = opts.aot_guardonly_lower;
	if (opts.aot_guardonly_lower && !opts.aot_guardonly_edges.empty()) {
		std::ifstream gf(opts.aot_guardonly_edges);
		std::unordered_map<uint32_t, unsigned long long> best_weight;
		unsigned long s, t;
		unsigned long long ct;
		std::string line;
		while (std::getline(gf, line)) {
			if (line.empty())
				continue;
			std::istringstream ls(line);
			ct = 1;
			ls >> std::hex >> s >> t;
			ls >> std::dec >> ct; // count is optional; defaults to 1 if absent
			auto it = best_weight.find((uint32_t)s);
			if (it == best_weight.end() || ct > it->second) {
				best_weight[(uint32_t)s] = ct;
				dbt::config::aot_guardonly_target[(uint32_t)s] = (uint32_t)t;
			}
		}
	}
	dbt::config::aot_multiguard_lower = opts.aot_multiguard_lower;
	if (opts.aot_multiguard_lower && !opts.aot_multiguard_edges.empty()) {
		std::ifstream mgf(opts.aot_multiguard_edges);
		unsigned long s, t;
		unsigned long long ct;
		std::string line;
		std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, unsigned long long>>> collected;
		while (std::getline(mgf, line)) {
			if (line.empty())
				continue;
			std::istringstream ls(line);
			ct = 1;
			ls >> std::hex >> s >> t;
			ls >> std::dec >> ct; // count is optional; defaults to 1 if absent
			collected[(uint32_t)s].emplace_back((uint32_t)t, ct);
		}
		for (auto &[src, targets] : collected) {
			// perfect oracle: keep EVERY distinct target observed for this source, ordered by
			// descending weight (ties broken by target_ip, for determinism across runs) -- no
			// tuned cutoff, no top-K selection.
			std::sort(targets.begin(), targets.end(), [](auto const &a, auto const &b) {
				if (a.second != b.second)
					return a.second > b.second;
				return a.first < b.first;
			});
			auto &v = dbt::config::aot_multiguard_targets[src];
			for (auto &[t, c] : targets)
				v.push_back(t);
		}
	}
	dbt::config::aot_use_llvm = opts.use_llvm; // gates FDRE stage 3's lowering to the LLVM backend, see config.h
	dbt::config::aot_brcc_real_weights = opts.aot_brcc_real_weights;
	dbt::config::aot_gbrind_hitrate_weights = opts.aot_gbrind_hitrate_weights;
	static std::string gbrind_hitrate_file_path = opts.aot_gbrind_hitrate_file;
	dbt::config::aot_gbrind_hitrate_file = gbrind_hitrate_file_path.empty() ? nullptr : gbrind_hitrate_file_path.c_str();
	dbt::config::qcg_leaf_inline = opts.qcg_leaf_inline;
	dbt::config::aot_function_closure_elf = opts.elf.c_str(); // opts outlives the whole compile
	dbt::config::threshold_max = opts.threshold_max;
	dbt::config::llvmopt = opts.llvmopt;
	dbt::config::cross_segment_branch = opts.cross_segment_branch;
	dbt::config::propagate_exec_count = opts.propagate_exec_count;
	dbt::config::dispatch_admit_floor = opts.dispatch_admit_floor;
	dbt::config::return_admit_floor = opts.return_admit_floor;
	dbt::config::return_admit_cost_ratio = opts.return_admit_cost_ratio;
	dbt::config::return_admit_optnone = opts.return_admit_optnone;
	static std::string indirect_edges_path = opts.aot_indirect_edges;
	dbt::config::aot_indirect_edges = indirect_edges_path.empty() ? nullptr : indirect_edges_path.c_str();
	dbt::config::aot_indirect_propagate = opts.aot_indirect_propagate;
	dbt::config::aot_admit_mode = opts.aot_admit_mode;
	static std::string admit_list_storage = opts.dispatch_admit_list;
	if (!admit_list_storage.empty())
		dbt::config::dispatch_admit_list = admit_list_storage.c_str();
	static std::string deny_list_storage = opts.dispatch_deny_list;
	if (!deny_list_storage.empty())
		dbt::config::dispatch_deny_list = deny_list_storage.c_str();
	dbt::config::gbrind_hitrate_collect = opts.gbrind_hitrate_collect;
	static std::string region_order_storage = opts.aot_region_order_file;
	if (!region_order_storage.empty())
		dbt::config::aot_region_order_file = region_order_storage.c_str();
	static std::string indirect_succs_storage = opts.aot_indirect_succs_file;
	if (!indirect_succs_storage.empty())
		dbt::config::aot_indirect_succs_file = indirect_succs_storage.c_str();
	dbt::config::aot_dump_indirect_succs = opts.aot_dump_indirect_succs;
	static std::string diag_link_bitcode_storage = opts.aot_diag_link_bitcode;
	if (!diag_link_bitcode_storage.empty())
		dbt::config::aot_diag_link_bitcode = diag_link_bitcode_storage.c_str();
	static std::string diag_direct_funcs_storage = opts.aot_diag_direct_funcs;
	if (!diag_direct_funcs_storage.empty())
		dbt::config::aot_diag_direct_funcs = diag_direct_funcs_storage.c_str();
	static std::string diag_inline_funcs_storage = opts.aot_diag_inline_funcs;
	if (!diag_inline_funcs_storage.empty())
		dbt::config::aot_diag_inline_funcs = diag_inline_funcs_storage.c_str();
	static std::string dump_llvm_ir_storage = opts.aot_dump_llvm_ir;
	if (!dump_llvm_ir_storage.empty())
		dbt::config::aot_dump_llvm_ir = dump_llvm_ir_storage.c_str();
	static std::string dump_llvm_ir_preopt_storage = opts.aot_dump_llvm_ir_preopt;
	if (!dump_llvm_ir_preopt_storage.empty())
		dbt::config::aot_dump_llvm_ir_preopt = dump_llvm_ir_preopt_storage.c_str();
	static std::string qir_known_targets_storage = opts.aot_qir_known_targets_file;
	if (!qir_known_targets_storage.empty())
		dbt::config::aot_qir_known_targets_file = qir_known_targets_storage.c_str();
	dbt::config::aot_dump_qir_known_targets = opts.aot_dump_qir_known_targets;
	dbt::config::aot_gbrind_vp_metadata = opts.aot_gbrind_vp_metadata;
	dbt::config::aot_log_icp = opts.aot_log_icp;
	dbt::config::aot_log_phase_timing = opts.aot_log_phase_timing;
	dbt::config::aot_optlevel = opts.aot_optlevel;
	dbt::config::aot_hot_floor = opts.aot_hot_floor;
	dbt::config::aot_cpb_optnone = opts.aot_cpb_optnone;
	dbt::config::aot_merge_max = opts.aot_merge_max;
	dbt::config::dump_loop_vs_idf = opts.dump_loop_vs_idf;             // Cycle-13 Phase-0 diagnostic
	dbt::config::loop_structural_regions = opts.loop_structural_regions; // Cycle-13 Phase-1 method
	dbt::config::aot_loop_entry = opts.aot_loop_entry; // T5c-0 late-enterable loop entries
	dbt::config::aot_loop_regions = opts.aot_loop_regions;         // T5d1b loop-rooted AOT regions
	static std::string loop_regions_qir_storage = opts.aot_loop_regions_qir_out;
	if (!loop_regions_qir_storage.empty())
		dbt::config::aot_loop_regions_qir_out = loop_regions_qir_storage.c_str();
	dbt::config::dump_loop_candidates = opts.dump_loop_candidates; // T5d1a candidate dry-run dump
	static std::string loop_candidates_out_storage = opts.dump_loop_candidates_out;
	if (!loop_candidates_out_storage.empty())
		dbt::config::dump_loop_candidates_out = loop_candidates_out_storage.c_str();
	dbt::config::dump_region_spill_exposure = opts.dump_region_spill_exposure; // Cycle-14 SEGA Phase-0 diagnostic
	dbt::config::aot_heavy_final = opts.aot_heavy_final;
	dbt::config::aot_heavy_last_n = opts.aot_heavy_last_n;
	dbt::config::aot_heavy_min_regions = opts.aot_heavy_min_regions;
	dbt::config::aot_use_lld = opts.aot_use_lld;
	dbt::config::aot_codegen_optlevel = opts.aot_codegen_optlevel;
	dbt::config::aot_region_hit_count = opts.aot_region_hit_count;
	static std::string region_hit_map_out_storage = opts.aot_region_hit_map_out;
	dbt::config::aot_region_hit_map_out = region_hit_map_out_storage.empty() ? nullptr : region_hit_map_out_storage.c_str();
	dbt::config::aot_final_expand_at = opts.aot_final_expand_at;
	dbt::config::aot_phase1_optlevel = opts.aot_phase1_optlevel;
	dbt::config::aot_log_expand = opts.aot_log_expand;
	dbt::config::aot_log_gbrind_constfold = opts.aot_log_gbrind_constfold;
	dbt::config::aot_log_irsize = opts.aot_log_irsize;
	dbt::config::aot_reassoc_probe = opts.aot_reassoc_probe;
	dbt::config::aot_edge_specialize = opts.aot_edge_specialize;
	dbt::config::aot_edge_oracle_unconditional = opts.aot_edge_oracle_unconditional;
	dbt::config::aot_return_oracle_unconditional = opts.aot_return_oracle_unconditional;
	dbt::config::aot_log_gipv_shape = opts.aot_log_gipv_shape;
	dbt::config::aot_dump_gbrind_indegree = opts.aot_dump_gbrind_indegree;
	dbt::config::aot_log_gbrind_site_identity = opts.aot_log_gbrind_site_identity;
	dbt::config::aot_order1_context_oracle = opts.aot_order1_context_oracle;
	static std::string order1_context_storage = opts.aot_order1_context_file;
	if (!order1_context_storage.empty())
		dbt::config::aot_order1_context_file = order1_context_storage.c_str();
	dbt::config::aot_marginal_context_oracle = opts.aot_marginal_context_oracle;
	dbt::config::aot_static_table_oracle = opts.aot_static_table_oracle;
	static std::string static_table_storage = opts.aot_static_table_file;
	if (!static_table_storage.empty())
		dbt::config::aot_static_table_file = static_table_storage.c_str();
	dbt::config::aot_static_table_inline = opts.aot_static_table_inline;
	dbt::config::aot_static_table_alwaysinline = opts.aot_static_table_alwaysinline;
	dbt::config::aot_static_table_switch_noinline = opts.aot_static_table_switch_noinline;
	dbt::config::aot_static_table_target_optnone = opts.aot_static_table_target_optnone;
	dbt::config::aot_indexed_dispatch_oracle = opts.aot_indexed_dispatch_oracle;
	dbt::config::aot_indexed_dispatch_require_full_coverage = opts.aot_indexed_dispatch_require_full_coverage;
	dbt::config::aot_vtable_narrow_oracle = opts.aot_vtable_narrow_oracle;
	dbt::config::aot_vtable_narrow_inline = opts.aot_vtable_narrow_inline;
	dbt::config::aot_direct_call_fusion = opts.aot_direct_call_fusion;
	dbt::config::aot_return_directify = opts.aot_return_directify;
	dbt::config::aot_vtable_narrow_zeroguard_singleton = opts.aot_vtable_narrow_zeroguard_singleton;
	dbt::config::aot_gbrind_context_replicate = opts.aot_gbrind_context_replicate;
	dbt::config::aot_edge_topk = opts.aot_edge_topk;
	dbt::config::aot_edge_underadmit_gate = opts.aot_edge_underadmit_gate;
	dbt::config::aot_edge_region_merge = opts.aot_edge_region_merge || opts.aot_edge_closure_merge ||
		opts.aot_edge_select_exclusive || opts.aot_edge_select_acyclic;
	dbt::config::aot_edge_move_not_copy = opts.aot_edge_move_not_copy;
	dbt::config::aot_count_gbrind = opts.aot_count_gbrind;
	dbt::config::aot_work_counter = opts.aot_work_counter;
	if (opts.aot_region_hit_count && opts.aot_region_cycle_count) {
		std::cerr << "--aot-region-hit-count and --aot-region-cycle-count share slots\n";
		std::exit(2);
	}
	dbt::config::aot_region_cycle_count = opts.aot_region_cycle_count;
	dbt::config::sr_activation_invariant = opts.sr_activation_invariant;
	dbt::config::dry_page_floor = opts.dry_page_floor;
	if (opts.aot_edge_specialize && !opts.aot_edge_profile.empty() && opts.aot_edge_topk > 0) {
		// aggregate brind edges by target (in-count), take top-K targets; force-admit them via the admit-list.
		std::ifstream ef(opts.aot_edge_profile);
		std::unordered_map<uint32_t, unsigned long long> tin;
		unsigned long s, d; unsigned long long ct;
		while (ef >> std::hex >> s >> d >> std::dec >> ct) tin[(uint32_t)d] += ct;
		std::vector<std::pair<uint32_t, unsigned long long>> v(tin.begin(), tin.end());
		std::sort(v.begin(), v.end(), [](auto &a, auto &b){ return a.second > b.second; });
		static std::string edge_admit_path = opts.cache + "/.r46_edge_admit";
		std::ofstream af(edge_admit_path);
		// Select the GLOBAL top-K hottest indirect targets and force-admit ALL of them (so MakeAotSymbol(T)
		// exists for the guard). The under-admit GATE is applied later in Expand_gbrind against the prof
		// natural-admission set (aot_natural_admitted), NOT here against the edge-in-count: the brind-edge
		// profile and the admission *.prof are on different run scales, so an edge-count-vs-threshold filter
		// mis-fires (P5 raw: it skipped wasm3's under-admitted winners whose edge-in-count was >= threshold).
		for (unsigned i = 0; i < opts.aot_edge_topk && i < v.size(); ++i) {
			dbt::config::aot_edge_targets.push_back(v[i].first);
			char buf[16]; snprintf(buf, sizeof buf, "%08x\n", v[i].first); af << buf;
		}
		af.close();
		static std::string edge_admit_storage = edge_admit_path;
		if (!dbt::config::aot_edge_targets.empty() && !dbt::config::dispatch_admit_list)
			dbt::config::dispatch_admit_list = edge_admit_storage.c_str();
	}
	if ((opts.aot_edge_select_exclusive || opts.aot_edge_select_acyclic) && !opts.aot_edge_profile.empty()) {
		// Lane B 2026-07-23: two non-magic, purely topological selection principles, run on the
		// FULL real edge profile graph (not just the top-mass source). Both are scoped to DEPTH-1
		// (a source's own DIRECT successors only, no recursive/transitive closure) so that every
		// merged target has EXACTLY ONE real predecessor edge within the merge -- the same
		// single-site/internal-switch shape h9 already fixed and validated on the 2-target diamond
		// case (dbt/qmc/llvmgen/llvmgen.cpp:679-689); neither principle reuses the CLOSURE-merge's
		// cyclic-SCC selection (that mechanism is explicitly excluded here, see
		// --aot-edge-select-acyclic's rejection rule below). No force-admission is added for any
		// selected source: whether a candidate source's merge actually fires still passes through
		// the EXISTING, unmodified RegionAdmitted()/--threshold gate in llvmaot.cpp -- a cold,
		// low-mass source that would never be admitted on its own is left for that real gate to
		// filter, not re-implemented here as a second, invented mass cutoff.
		struct Edge { uint32_t src, dst; unsigned long long count; };
		std::ifstream ef(opts.aot_edge_profile);
		std::vector<Edge> edges;
		std::unordered_map<uint32_t, std::vector<uint32_t>> adj;
		std::unordered_map<uint32_t, unsigned> indeg;
		std::unordered_set<uint64_t> edge_seen; // (src<<32|dst) dedup, mirrors adjacency-set semantics
		std::unordered_set<uint32_t> nodes;
		unsigned long s3, d3; unsigned long long ct3;
		while (ef >> std::hex >> s3 >> d3 >> std::dec >> ct3) {
			edges.push_back({(uint32_t)s3, (uint32_t)d3, ct3});
			uint64_t key = ((uint64_t)(uint32_t)s3 << 32) | (uint32_t)d3;
			nodes.insert((uint32_t)s3);
			nodes.insert((uint32_t)d3);
			if (edge_seen.insert(key).second) {
				adj[(uint32_t)s3].push_back((uint32_t)d3);
				indeg[(uint32_t)d3]++;
			}
		}
		auto has_edge = [&](uint32_t a, uint32_t b) {
			return edge_seen.count(((uint64_t)a << 32) | b) != 0;
		};

		unsigned n_selected_sources = 0, n_selected_targets = 0;
		// Pre-role-exclusivity candidate map (both principles fill this, then a shared
		// structural filter below removes the ROLE-CONFLICT case found on real wasm3_swtable
		// data during this round's falsification, not part of either principle's original
		// design): a node that is ITSELF an independently-qualifying source (it has its own
		// non-empty candidate target set) is never accepted as anyone else's TARGET. Without
		// this, a node can end up simultaneously (a) spliced away as an internal block of a
		// neighbor's function and (b) retained as its own function head receiving its own
		// splice -- two mutually exclusive representations of the same node that the
		// underlying splice/expand pipeline (validated by h9 for one single-level, non-nested
		// merge only) cannot hold at once. Confirmed root cause via gdb of a real SIGSEGV in
		// Expand_gbrind's SwitchInst::addCase (llvmgen.cpp:686) on wasm3_swtable: node 0x115a8
		// was both an exclusive target of source 0x16998 AND an independent source of its own
		// (target 0x20e48) before this filter existed. This is a structural completeness fix
		// to the selection principle itself (Lane B's own mandate), not a Lane A correctness
		// patch to the splice/expand mechanism.
		std::unordered_map<uint32_t, std::vector<uint32_t>> candidate;
		if (opts.aot_edge_select_exclusive) {
			// Principle 1: EXCLUSIVE ACYCLIC CLOSURE. t qualifies iff s is t's ONLY real
			// predecessor anywhere in the profile (indegree(t)==1) and there is no direct
			// (t,s) back-edge. Not a mass ranking: a target with indegree==1 qualifies
			// regardless of its edge count, and a target with more mass than any exclusive
			// target but indegree>1 (shared/polymorphic) is rejected outright.
			for (auto const &[src, tgts] : adj) {
				std::vector<uint32_t> sel;
				for (uint32_t t : tgts) {
					if (t == src) continue;
					if (indeg[t] != 1) continue;
					if (has_edge(t, src)) continue; // direct 2-cycle back to the source
					sel.push_back(t);
				}
				if (!sel.empty()) {
					std::sort(sel.begin(), sel.end());
					candidate[src] = std::move(sel);
				}
			}
		} else {
			// Principle 2: ACYCLIC TRIVIAL-SCC NEIGHBORHOOD. Tarjan SCC over the WHOLE profiled
			// graph; a source only qualifies if its own SCC is trivial (size 1, not a self-loop
			// either) -- i.e. it does not participate in ANY observed cycle. Its target set is
			// every direct successor that is ALSO in a trivial SCC. Unlike Principle 1, targets
			// may be shared (indegree>1) -- this is the permissive/acyclic-only axis, and is the
			// structural inverse of the existing --aot-edge-closure-merge oracle, which requires
			// a NON-trivial (necessarily cyclic) SCC by construction and is exactly the class of
			// merge target this campaign's own cyclic-merge-crash investigation found still
			// crashes at runtime (5/5 SIGABRT) -- this principle never selects that class.
			std::unordered_map<uint32_t, int> index, low, component;
			std::unordered_set<uint32_t> on_stack;
			std::vector<uint32_t> stack;
			std::vector<std::vector<uint32_t>> components;
			int next_index = 0;
			std::function<void(uint32_t)> visit = [&](uint32_t v) {
				index[v] = low[v] = next_index++;
				stack.push_back(v);
				on_stack.insert(v);
				for (uint32_t w : adj[v]) {
					if (!index.count(w)) {
						visit(w);
						low[v] = std::min(low[v], low[w]);
					} else if (on_stack.count(w)) {
						low[v] = std::min(low[v], index[w]);
					}
				}
				if (low[v] != index[v])
					return;
				components.emplace_back();
				while (true) {
					uint32_t w = stack.back();
					stack.pop_back();
					on_stack.erase(w);
					component[w] = (int)components.size() - 1;
					components.back().push_back(w);
					if (w == v)
						break;
				}
			};
			for (uint32_t v : nodes)
				if (!index.count(v))
					visit(v);
			std::unordered_set<uint32_t> trivial;
			for (auto const &[v, cidx] : component)
				if (components[cidx].size() == 1 && !has_edge(v, v))
					trivial.insert(v);
			for (auto const &[src, tgts] : adj) {
				if (!trivial.count(src)) continue;
				std::vector<uint32_t> cand;
				for (uint32_t t : tgts)
					if (t != src && trivial.count(t))
						cand.push_back(t);
				// SAFETY PATCH (found during real-profile falsification on wasm3_swtable, not in
				// the original design): trivial-SCC membership alone is not sufficient. Two of
				// src's own direct successors can each individually sit in a trivial SCC while
				// still having a direct edge BETWEEN them; selecting both would put an edge other
				// than src's own dispatch edges inside the merged set -- the same
				// multi-predecessor-within-one-function shape the cyclic-merge-crash
				// investigation (h9 ledger) characterized as still-unresolved. Require the
				// induced subgraph on {src}+sel to be a pure star: no edge from/to src other than
				// (src,t) itself, and no edge between any two accepted siblings either direction.
				std::unordered_set<uint32_t> cand_set(cand.begin(), cand.end());
				std::vector<uint32_t> sel;
				for (uint32_t t : cand) {
					if (has_edge(t, src)) continue;
					bool bad = false;
					for (uint32_t u : cand_set) {
						if (u == t) continue;
						if (has_edge(t, u) || has_edge(u, t)) { bad = true; break; }
					}
					if (!bad) sel.push_back(t);
				}
				if (!sel.empty()) {
					std::sort(sel.begin(), sel.end());
					candidate[src] = std::move(sel);
				}
			}
		}
		// ROLE-EXCLUSIVITY FILTER (shared by both principles, see comment above `candidate`):
		// drop any candidate target that is itself a candidate source. Prefer preserving a
		// node's OWN independent merge (source role) over subsuming it into a neighbor's
		// (target role) -- this also makes the result invariant to map/hash iteration order,
		// since the source-set membership test does not depend on processing order.
		for (auto &[src, tgts] : candidate) {
			std::vector<uint32_t> kept;
			for (uint32_t t : tgts)
				if (!candidate.count(t))
					kept.push_back(t);
			tgts = std::move(kept);
		}
		for (auto const &[src, tgts] : candidate) {
			if (tgts.empty()) continue;
			dbt::config::aot_region_merge_map[src] = tgts;
			n_selected_sources++;
			n_selected_targets += (unsigned)tgts.size();
			fprintf(stderr, "EDGE_SELECT_%s src=%08x targets=%zu\n",
				opts.aot_edge_select_exclusive ? "EXCLUSIVE" : "ACYCLIC", src, tgts.size());
		}
		// DIAGNOSTIC ONLY (Lane B bisection tool, 2026-07-23): cap the number of simultaneously
		// merged sources, to isolate whether a crash is caused by the SELECTION PRINCIPLE itself
		// or by doing many independent single-source merges in the SAME compile at once (a scale
		// this campaign's prior single-source h9 validation never exercised). Not part of the
		// selection algorithm; unset by default (no cap).
		if (const char *capenv = getenv("LANEB_MAX_MERGE_SOURCES")) {
			unsigned cap = (unsigned)atoi(capenv);
			std::vector<uint32_t> srcs;
			for (auto const &[k, v] : dbt::config::aot_region_merge_map) srcs.push_back(k);
			std::sort(srcs.begin(), srcs.end());
			if (srcs.size() > cap) {
				for (unsigned i = cap; i < srcs.size(); ++i)
					dbt::config::aot_region_merge_map.erase(srcs[i]);
				fprintf(stderr, "EDGE_SELECT_CAPPED cap=%u kept=%u dropped=%zu\n", cap, cap, srcs.size() - cap);
			}
		}
		fprintf(stderr, "EDGE_SELECT_SUMMARY mode=%s sources=%u targets=%u\n",
			opts.aot_edge_select_exclusive ? "exclusive" : "acyclic", n_selected_sources, n_selected_targets);
	} else if (opts.aot_edge_closure_merge && !opts.aot_edge_profile.empty()) {
		struct Edge { uint32_t src, dst; unsigned long long count; };
		std::ifstream ef(opts.aot_edge_profile);
		std::vector<Edge> edges;
		std::unordered_map<uint32_t, std::vector<uint32_t>> adj;
		unsigned long s, d;
		unsigned long long count;
		while (ef >> std::hex >> s >> d >> std::dec >> count) {
			edges.push_back({(uint32_t)s, (uint32_t)d, count});
			adj[(uint32_t)s].push_back((uint32_t)d);
			adj.try_emplace((uint32_t)d);
		}

		std::unordered_map<uint32_t, int> index, low, component;
		std::unordered_set<uint32_t> on_stack;
		std::vector<uint32_t> stack;
		std::vector<std::vector<uint32_t>> components;
		int next_index = 0;
		std::function<void(uint32_t)> visit = [&](uint32_t v) {
			index[v] = low[v] = next_index++;
			stack.push_back(v);
			on_stack.insert(v);
			for (uint32_t w : adj[v]) {
				if (!index.count(w)) {
					visit(w);
					low[v] = std::min(low[v], low[w]);
				} else if (on_stack.count(w)) {
					low[v] = std::min(low[v], index[w]);
				}
			}
			if (low[v] != index[v])
				return;
			components.emplace_back();
			while (true) {
				uint32_t w = stack.back();
				stack.pop_back();
				on_stack.erase(w);
				component[w] = (int)components.size() - 1;
				components.back().push_back(w);
				if (w == v)
					break;
			}
		};
		for (auto const &[v, unused] : adj) {
			(void)unused;
			if (!index.count(v))
				visit(v);
		}

		std::vector<unsigned long long> internal_mass(components.size());
		for (auto const &e : edges)
			if (component[e.src] == component[e.dst])
				internal_mass[component[e.src]] += e.count;
		int best = -1;
		for (int i = 0; i < (int)components.size(); ++i)
			if (components[i].size() > 1 && (best < 0 || internal_mass[i] > internal_mass[best]))
				best = i;
		if (best >= 0) {
			std::unordered_map<uint32_t, unsigned long long> source_mass;
			std::unordered_set<uint32_t> target_set;
			for (auto const &e : edges) {
				if (component[e.src] != best || component[e.dst] != best)
					continue;
				source_mass[e.src] += e.count;
				target_set.insert(e.dst);
			}
			uint32_t primary_source = 0;
			unsigned long long primary_mass = 0;
			for (auto const &[src, mass] : source_mass)
				if (mass > primary_mass) {
					primary_source = src;
					primary_mass = mass;
				}
			// Cyclic-merge follow-up fix (2026-07-23, Lane A): target_set is built from EVERY
			// edge internal to the SCC, so for a genuinely cyclic component some edge necessarily
			// loops back INTO primary_source itself. That put primary_source in its own
			// internal_dispatch_targets list downstream, which Expand_gbrind's internal switch
			// (unlike QIRToLLVM::Run()'s entry switch) had no guard against -- a source is never
			// legitimately its own internal dispatch target.
			target_set.erase(primary_source);
			std::vector<uint32_t> targets(target_set.begin(), target_set.end());
			std::sort(targets.begin(), targets.end());
			dbt::config::aot_region_merge_map[primary_source] = targets;

			static std::string closure_admit_path = opts.cache + "/.edge_closure_admit";
			std::ofstream af(closure_admit_path);
			char buf[16];
			snprintf(buf, sizeof buf, "%08x\n", primary_source);
			af << buf;
			af.close();
			static std::string closure_admit_storage = closure_admit_path;
			if (!dbt::config::dispatch_admit_list)
				dbt::config::dispatch_admit_list = closure_admit_storage.c_str();
			fprintf(stderr,
				"EDGE_CLOSURE_MERGE source=%08x component_nodes=%zu targets=%zu internal_mass=%llu source_mass=%llu\n",
				primary_source, components[best].size(), targets.size(), internal_mass[best], primary_mass);
		}
	} else if (opts.aot_edge_region_merge && !opts.aot_edge_profile.empty()) {
		// P3: pick the TOP SOURCE by outgoing edge mass; its majority-coverage targets become internal
		// blocks of the source region (same doubling-family majority selection as everywhere else).
		std::ifstream ef2(opts.aot_edge_profile);
		std::unordered_map<uint32_t, unsigned long long> smass;
		std::unordered_map<uint32_t, std::unordered_map<uint32_t, unsigned long long>> stgt;
		unsigned long s2, d2; unsigned long long ct2;
		while (ef2 >> std::hex >> s2 >> d2 >> std::dec >> ct2) {
			smass[(uint32_t)s2] += ct2;
			stgt[(uint32_t)s2][(uint32_t)d2] += ct2;
		}
		uint32_t top_src = 0; unsigned long long top_m = 0;
		for (auto const &[sp, m] : smass)
			if (m > top_m) { top_m = m; top_src = sp; }
		if (top_src) {
			auto &tm = stgt[top_src];
			std::vector<std::pair<uint32_t, unsigned long long>> tv(tm.begin(), tm.end());
			std::sort(tv.begin(), tv.end(), [](auto &a, auto &b){ return a.second > b.second; });
			unsigned long long tot = 0, acc = 0;
			for (auto const &p : tv) tot += p.second;
			std::vector<uint32_t> tgts;
			for (auto const &p : tv) {
				tgts.push_back(p.first);
				acc += p.second;
				if (acc * 2 >= tot) break;
			}
			// keyed by the SOURCE ip; llvmaot resolves the owning region and its targets on this page
			dbt::config::aot_region_merge_map[top_src] = tgts;
			fprintf(stderr, "EDGE_REGION_MERGE src=%08x targets=%zu mass=%llu\n", top_src, tgts.size(), top_m);
		}
	}
	// path-history exec-proof: CONTEXT-keyed (2-level) edge specialization. Read .trans (src prev target count),
	// aggregate GLOBALLY by prev_target -> {target: count}; for each prev pick argmax target; take the top-K
	// hottest prev-contexts; emit (prev, predicted) pairs and force-admit the predicted targets (so the direct
	// call has a known AOT fn). This is the 2-level analogue of the 1-level top-K block above.
	dbt::config::aot_context_edge_specialize = opts.aot_context_edge_specialize;
	dbt::config::aot_context_edge_topk = opts.aot_context_edge_topk;
	if (opts.aot_context_edge_specialize && !opts.aot_context_edge_profile.empty() && opts.aot_context_edge_topk > 0) {
		std::ifstream ef(opts.aot_context_edge_profile);
		std::unordered_map<uint32_t, std::unordered_map<uint32_t, unsigned long long>> ctx; // prev -> target -> count
		std::unordered_map<uint32_t, unsigned long long> ctot;                              // prev -> total count
		unsigned long s, p, t; unsigned long long ct;
		while (ef >> std::hex >> s >> p >> t >> std::dec >> ct) {
			ctx[(uint32_t)p][(uint32_t)t] += ct;
			ctot[(uint32_t)p] += ct;
		}
		std::vector<std::pair<uint32_t, unsigned long long>> prevs(ctot.begin(), ctot.end());
		std::sort(prevs.begin(), prevs.end(), [](auto &a, auto &b){ return a.second > b.second; });
		static std::string ctx_admit_path = opts.cache + "/.ph_ctx_admit";
		std::ofstream af(ctx_admit_path);
		std::unordered_set<uint32_t> admitted_t;
		for (unsigned i = 0; i < opts.aot_context_edge_topk && i < prevs.size(); ++i) {
			uint32_t P = prevs[i].first;
			auto &tm = ctx[P];
			uint32_t T = std::max_element(tm.begin(), tm.end(),
				[](auto &a, auto &b){ return a.second < b.second; })->first; // argmax predicted target
			dbt::config::aot_context_edges.emplace_back(P, T);
			if (admitted_t.insert(T).second) {
				dbt::config::aot_edge_targets.push_back(T); // reuse force-admission machinery for the direct call
				char buf[16]; snprintf(buf, sizeof buf, "%08x\n", T); af << buf;
			}
		}
		af.close();
		static std::string ctx_admit_storage = ctx_admit_path;
		if (!dbt::config::aot_context_edges.empty() && !dbt::config::dispatch_admit_list)
			dbt::config::dispatch_admit_list = ctx_admit_storage.c_str();
	}
	static std::string aot_pipeline_storage = opts.aot_pipeline;
	if (!aot_pipeline_storage.empty())
		dbt::config::aot_pipeline = aot_pipeline_storage.c_str();
	dbt::config::dispatch_handler_optnone = opts.dispatch_handler_optnone;
	dbt::config::aot_shard_mod = opts.aot_shard_mod;
	dbt::config::aot_shard_idx = opts.aot_shard_idx;
	dbt::config::aot_shard_link = opts.aot_shard_link;
	dbt::config::dump_applicability = opts.dump_applicability;
	dbt::config::dump_regions = opts.dump_regions;
	dbt::config::dump_regions_internal_edges = opts.dump_regions_internal_edges;
}

int main(int argc, char **argv)
{
	ElfAotOptions opts;
	if (!ParseOptions(opts, argc, argv)) {
		return 1;
	}
	SetupConfig(opts);
	SetupLogger(opts.logs);
	if (!opts.mgdump.empty()) {
		dbt::InitModuleGraphDump(opts.mgdump.c_str());
	}

	dbt::fsmanager::Init(opts.cache.c_str());
	dbt::objprof::Init(opts.cache.c_str(), false);
	dbt::mmu::Init();

	dbt::ukernel::ReproduceElfMappings(opts.elf.c_str());

	// A-line Round 55: measurement-only headroom diagnostic -- runs the whole-binary static
	// single-caller certificate and exits, no compile. Placed here (right after the ELF mapping
	// is established, before any profile/config-dependent selection logic) since it only needs
	// vmem_base + g_elf_exec_ranges (both ready now) plus its own edges-file argument.
	if (!opts.return_headroom_edges_file.empty()) {
		dbt::return_target_resolve::RunReturnHeadroomDiagnostic((uptr)dbt::mmu::base,
									 opts.return_headroom_edges_file.c_str());
		return 0;
	}

	// T5d1a: the canonical hot-natural-loop candidate dump. Placed beside the return-headroom
	// diagnostic above and for the same reason -- it needs the profile and the guest's mapped
	// instructions (both ready now) and nothing else, and it exits before any selection,
	// region-formation or codegen path can be reached, which is what makes "the dump changed
	// nothing" structural instead of a claim.
	if (dbt::config::dump_loop_candidates) {
		dbt::DumpNaturalLoopCandidates();
		// The same teardown the normal exit path performs, and it is NOT optional: fsmanager::Init
		// (called above) starts a detached worker thread that parks on a condition variable, and
		// returning from main without releasing it leaves __run_exit_handlers destroying that
		// condition variable while a thread is still waiting on it -- the process then never
		// exits. Measured: an early return without this line hung after writing a complete,
		// correct dump.
		dbt::fsmanager::Destroy();
		return 0;
	}

	// A-line flow-certain selection: needs objprof marginals, so it runs here (after Announce),
	// not in SetupConfig like the SET-only selections.
	if (opts.aot_edge_select_flow && !opts.aot_edge_profile.empty())
		ComputeFlowSelection(opts.aot_edge_profile, opts.threshold);

	dbt::config::count_const_vmload = getenv("DBT_COUNT_CONST_VMLOAD") != nullptr;

	// 2026-06-23: skip runtime gen-code pages (not in the static ELF) during AOT to avoid SIGSEGV on
	// generated-code-workload profiles. Compiles only the static .text -> AOT-static + JIT/NGR-gencode.
	dbt::config::aot_skip_nonelf = getenv("DBT_AOT_SKIP_NONELF") != nullptr;

	// Family-A oracle: load profiled stable-load (PC,value) pairs and enable substitution.
	if (const char *slf = getenv("DBT_STABLE_LOAD_FILE")) {
		FILE *f = fopen(slf, "r");
		if (f) {
			unsigned pc, val; int n = 0;
			while (fscanf(f, "%x,%x\n", &pc, &val) == 2) { dbt::add_stable_load(pc, val); n++; }
			fclose(f);
			dbt::config::subst_stable_loads = (n > 0);
			fprintf(stderr, "STABLE_LOADS_LOADED=%d\n", n);
		}
	}
	// C2 ceiling oracle correction: load profiled (jalr_pc,target) pairs and skip Create_gbrind
	// entirely for those sites -- see config::subst_stable_jalr's comment.
	if (const char *sjf = getenv("DBT_STABLE_JALR_FILE")) {
		FILE *f = fopen(sjf, "r");
		if (f) {
			unsigned pc, tgt; int n = 0;
			while (fscanf(f, "%x,%x\n", &pc, &tgt) == 2) { dbt::add_stable_jalr_target(pc, tgt); n++; }
			fclose(f);
			dbt::config::subst_stable_jalr = (n > 0);
			fprintf(stderr, "STABLE_JALR_LOADED=%d\n", n);
		}
	}

	if (opts.use_llvm) {
		if (opts.repeat_compile > 1) {
			// C-line warm-vs-cold LLVM invocation probe (2026-07-18): repeat the SAME compile N times in
			// this process. Target registration / pass-pipeline construction / any lazy-initialized LLVM
			// global state is paid at most once (whichever iteration first touches it); everything after
			// that reuses the SAME process's already-initialized state. This isolates how much of the
			// measured ~90-140ms per-invocation fixed cost is PROCESS-SPAWN-only (would vanish here) vs
			// LLVM-OBJECT-LIFECYCLE-inherent (would persist on every iteration even in-process).
			for (unsigned i = 0; i < opts.repeat_compile; i++) {
				struct timespec t0, t1;
				clock_gettime(CLOCK_MONOTONIC, &t0);
				dbt::LLVMAOTCompileELF();
				clock_gettime(CLOCK_MONOTONIC, &t1);
				double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
				fprintf(stderr, "REPEAT_COMPILE iter=%u ms=%.2f\n", i, ms);
			}
		} else {
			dbt::LLVMAOTCompileELF();
		}
	} else {
		// 2026-06-22 cycle12-H3: QCG-codegen AOT (--llvm=0) must emit the inline L1 brind-cache fast-path. QEmit gates it
		// on !config::trace (qemit.cpp:317); elfaot otherwise leaves trace at its default (true) -> the fast-path is
		// omitted -> EVERY indirect dispatch hits the qcgstub_brind slowpath (measured: minivm 7,000,264 vs JIT's 82).
		// elfrun runs with trace=false by default, so compiling the AOT with trace=false matches the runtime and restores
		// the cache fast-path. AOT exec-count tracking is already skipped (qemit.cpp:347 !use_aot), so this is safe.
		dbt::config::trace = false;
		dbt::AOTCompileELF();
	}

	if (dbt::config::count_const_vmload)
		fprintf(stderr, "VMLOAD_TOTAL=%llu VMLOAD_CONST_ADDR=%llu\n",
			dbt::config::g_vmload_total, dbt::config::g_vmload_const_addr);

	if (getenv("DBT_REPORT_SPILLS")) // 2026-06-22 diag: static QCG spill-emission count (qra EmitSpill+EmitFill)
		fprintf(stderr, "SPILL_EMIT=%llu SPILL_STORE=%llu SPILL_FILL=%llu DYN_SPILL=%llu GLOBAL=%llu LOCAL=%llu\n", dbt::config::g_spill_emit, dbt::config::g_spill_store, dbt::config::g_spill_fill, dbt::config::g_dyn_spill, dbt::config::g_spill_global, dbt::config::g_spill_local);
	if (dbt::config::dump_loop_vs_idf || dbt::config::loop_structural_regions) // Cycle-13 loop-vs-IDF report
		fprintf(stderr, "LOOP_TOTAL=%llu LOOP_SPLIT=%llu LOOP_SPLIT_RAW=%llu LOOP_INTERNAL_RE=%llu LOOP_INTERNAL_RE_RAW=%llu LOOP_INTERNAL_RE_NODOM=%llu LOOP_BODY_NODES=%llu LOOP_BODY_MAX=%llu LOOP_BIG_TOTAL=%llu LOOP_BIG_SPLIT=%llu RE_TOTAL=%llu NODE_TOTAL=%llu RE_SUPPRESSED=%llu\n",
			dbt::config::g_loop_total, dbt::config::g_loop_split, dbt::config::g_loop_split_raw, dbt::config::g_loop_internal_re, dbt::config::g_loop_internal_re_raw, dbt::config::g_loop_internal_re_nodom, dbt::config::g_loop_body_nodes, dbt::config::g_loop_body_max, dbt::config::g_loop_big_total, dbt::config::g_loop_big_split, dbt::config::g_re_total, dbt::config::g_node_total, dbt::config::g_loop_re_suppressed);

	if (dbt::config::aot_static_table_oracle && dbt::config::aot_static_table_inline) {
		auto const &s = dbt::static_table_resolve::g_stats;
		fprintf(stderr,
			"STATICTABLE_INLINE sites_examined=%llu pattern_matched=%llu base_resolved=%llu "
			"bound_proven=%llu table_in_nonwritable=%llu table_read_ok=%llu\n",
			(unsigned long long)s.sites_examined, (unsigned long long)s.pattern_matched,
			(unsigned long long)s.base_resolved, (unsigned long long)s.bound_proven,
			(unsigned long long)s.table_in_nonwritable, (unsigned long long)s.table_read_ok);
	}

	if (dbt::config::aot_vtable_narrow_oracle && dbt::config::aot_vtable_narrow_inline) {
		auto const &s = dbt::vtable_narrow::g_stats;
		fprintf(stderr,
			"VTABLENARROW_INLINE sites_examined=%llu pattern_matched=%llu receiver_sound=%llu "
			"rtti_resolved=%llu candidates_found=%llu\n",
			(unsigned long long)s.sites_examined, (unsigned long long)s.pattern_matched,
			(unsigned long long)s.receiver_sound, (unsigned long long)s.rtti_resolved,
			(unsigned long long)s.candidates_found);
		fprintf(stderr,
			"VTABLENARROW_PROVENANCE reject_unrecognized=%llu reject_adjusted=%llu "
			"reject_liveend=%llu hops_total=%llu\n",
			(unsigned long long)s.provenance_reject_unrecognized,
			(unsigned long long)s.provenance_reject_adjusted,
			(unsigned long long)s.provenance_reject_liveend,
			(unsigned long long)s.provenance_hops_total);
		fprintf(stderr,
			"VTABLENARROW_RTTICOST symtab_parse_ns=%llu rtti_lazy_build_ns=%llu "
			"rtti_zti_total=%llu rtti_lazy_roots=%llu rtti_lazy_nodes_total=%llu "
			"provenance_scan_ns=%llu tryresolve_total_ns=%llu\n",
			(unsigned long long)s.symtab_parse_ns, (unsigned long long)s.rtti_lazy_build_ns,
			(unsigned long long)s.rtti_zti_total, (unsigned long long)s.rtti_lazy_roots,
			(unsigned long long)s.rtti_lazy_nodes_total, (unsigned long long)s.provenance_scan_ns,
			(unsigned long long)s.tryresolve_total_ns);
		fprintf(stderr, "VTABLENARROW_FIELDPROVENANCE field_provenance_resolved=%llu\n",
			(unsigned long long)s.field_provenance_resolved);
		fprintf(stderr,
			"VTABLENARROW_CONSUMERC candidate_total=%llu candidate_admitted=%llu\n",
			(unsigned long long)s.consumer_candidate_total,
			(unsigned long long)s.consumer_candidate_admitted);
	}

	if (dbt::config::aot_direct_call_fusion) {
		auto const &s = dbt::direct_call_resolve::g_stats;
		fprintf(stderr,
			"DIRECTCALLFUSION sites_examined=%llu pattern_matched=%llu target_verified=%llu\n",
			(unsigned long long)s.sites_examined, (unsigned long long)s.pattern_matched,
			(unsigned long long)s.target_verified);
	}

	dbt::fsmanager::Destroy();
	if constexpr (dbt::config::debug) {
		dbt::objprof::Destroy();
		dbt::mmu::Destroy();
	}
	return 0;
}
